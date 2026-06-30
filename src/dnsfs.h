/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef DNSFS_H
#define DNSFS_H

#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/rhashtable.h>
#include <linux/shrinker.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "parser.h"

#define DNSFS_MAGIC 0x444e5346
#define DNSFS_DEFAULT_PORT 53
#define DNSFS_DEFAULT_TIMEOUT_MS 1000
#define DNSFS_MAX_PACKET 512
#define DNSFS_TCP_MAX_PACKET 4096
#define DNSFS_MAX_RESOLVERS 4
#define DNSFS_MAX_TTL_SEC 3600
#define DNSFS_RECORD_TEXT_MAX 384
#define DNSFS_MAX_CACHE_ENTRIES 64
#define DNSFS_STORAGE_INDEX "index"
#define DNSFS_MAX_STORAGE_CHUNKS 64
#define DNSFS_MAX_STORAGE_SIZE (DNSFS_CHUNK_SIZE * DNSFS_MAX_STORAGE_CHUNKS)
/* Hash key for the TTL cache: a record is uniquely a {name, qtype} pair. */
struct dnsfs_cache_key {
    u16 qtype;
    char name[DNSFS_MAX_NAME + 1];
};

/* One cached DNS answer. Fields are immutable once published into the
 * rhashtable except via the query_lock writer, so the RCU read side may read
 * them locklessly (see dnsfs_cache_lookup_rcu). Freed through rcu to outlive
 * concurrent readers.
 */
struct dnsfs_cache_entry {
    struct rhash_head node; /* rhashtable linkage (lookup by key) */
    struct list_head list;  /* LRU order for the shrinker's reclaim */
    struct rcu_head rcu;    /* deferred free after a grace period */
    struct dnsfs_cache_key key;
    int err;              /* negative-cache errno (rcode map), else 0 */
    unsigned long expiry; /* jiffies deadline: TTL as object lifetime */
    size_t len;           /* valid bytes in text */
    bool refreshing;      /* an async TTL refresh is already in flight */
    char text[DNSFS_RECORD_TEXT_MAX]; /* presentation form served to readers */
};

/* Per-mount (per-superblock) state: resolver config, the TTL cache, and the
 * single query kthread that owns all wire I/O. One of these lives for the life
 * of the mount; sb->s_fs_info points at it.
 */
struct dnsfs_config {
    char *zone;       /* mount root zone, e.g. "example.org." */
    char *nameserver; /* raw nameserver= option string, for show */
    char *publisher;  /* absolute publisher path; NULL => read-only */
    __be32 nameservers[DNSFS_MAX_RESOLVERS]; /* parsed, in failover order */
    unsigned int nameserver_count;
    u32 port;
    u32 timeout_ms;
    u32 retries;
    bool dnssec;         /* set the EDNS DO bit (request signatures) */
    bool storage;        /* -o storage: reassemble files from TXT */
    bool publisher_set;  /* an explicit publisher= was given */
    bool writable;       /* storage && publisher_set && init_user_ns */
    atomic64_t next_ino; /* monotonic inode-number allocator */
    /* TTL cache: cache_ht for O(1) {name,qtype} lookup, cache list for LRU
     * reclaim order; both guarded by query_lock on the write side.
     */
    struct list_head cache;
    struct rhashtable cache_ht;
    unsigned int cache_entries;
    /* Query kthread queue: readers enqueue misses/refreshes here and either
     * wait or coalesce onto a request already on query_pending (in-flight
     * dedup).
     */
    struct list_head query_queue;
    struct list_head query_pending;
    spinlock_t query_queue_lock;      /* guards query_queue/query_pending */
    wait_queue_head_t query_wait;     /* kthread sleeps here for new work */
    struct task_struct *query_thread; /* sole owner of socket I/O */
    struct socket *sock;       /* shared UDP socket, used only by the kthread */
    struct mutex query_lock;   /* serializes cache writes + sync wire queries */
    struct shrinker *shrinker; /* registers the cache with memory reclaim */
};

/* One unit of work handed to the query kthread. Shared between the kthread and
 * any waiters that coalesced onto it, so it is refcounted and freed by the last
 * holder; a synchronous waiter blocks on 'done'.
 */
struct dnsfs_query_request {
    struct list_head queue;   /* link on query_queue (work to start) */
    struct list_head pending; /* link on query_pending (in-flight, dedup) */
    struct completion done;   /* signaled when the wire result is ready */
    refcount_t refs;          /* kthread + each coalesced waiter */
    char fqdn[DNSFS_MAX_NAME + 1];
    u16 qtype;
    int ret; /* result: byte count, or negative errno */
    size_t len;
    bool refresh;        /* fire-and-forget TTL refresh, nobody waits */
    struct inode *inode; /* igrab'd for a refresh, to invalidate pages */
    char text[DNSFS_RECORD_TEXT_MAX];
};

/* Per-open state for a storage file (file->private_data). Tracks the chunk set
 * the current epoch resolves to and buffers a pending write until commit.
 */
struct dnsfs_storage_file {
    struct dnsfs_file_meta meta; /* size/mode/mtime/chunk_count/epoch/crc */
    /* generation tag; bumped on each publish so a stale chunk is rejected */
    char epoch[DNSFS_MAX_LABEL + 1];
    char parent_fqdn[DNSFS_MAX_NAME + 1];
    char meta_fqdn[DNSFS_MAX_NAME + 1];
    bool dirty;        /* page cache holds unpublished writes */
    bool write_loaded; /* base file faulted in before first write */
    bool meta_stale;   /* meta must be re-fetched after a commit */
    int write_err;     /* deferred error to report at close */
    struct mutex lock; /* serializes write-cache load and commit on this open */
};

enum dnsfs_kind {
    DNSFS_DIR,
    DNSFS_RECORD,
    DNSFS_SYMLINK,
    DNSFS_STORAGE,
};

struct dnsfs_type {
    const char *name;
    u16 qtype;
    enum dnsfs_kind kind;
};

/* Module-wide wire-query counter (defined in main.c, bumped by the engine). */
extern atomic64_t dnsfs_wire_queries;

/* main.c */
const struct dnsfs_type *dnsfs_find_type(const struct qstr *name);

/* dns.c — resolver engine: wire client, presentation, TTL cache, query kthread.
 */
int dnsfs_cache_init(struct dnsfs_config *cfg);
u16 dnsfs_qtype(const struct qstr *name);
void dnsfs_free_config(struct dnsfs_config *cfg);
int dnsfs_parse_nameservers(struct dnsfs_config *cfg, const char *value);
int dnsfs_query_record(struct dnsfs_config *cfg,
                       const char *fqdn,
                       u16 qtype,
                       char *out,
                       size_t out_len,
                       struct address_space *mapping);
void dnsfs_cache_drop(struct dnsfs_config *cfg, const char *fqdn, u16 qtype);
void dnsfs_cache_drop_storage(struct dnsfs_config *cfg,
                              const char *parent,
                              const char *label,
                              size_t label_len);
int dnsfs_commit_put(struct dnsfs_config *cfg,
                     const char *label,
                     size_t label_len,
                     const u8 *data,
                     size_t data_len);
int dnsfs_commit_del(struct dnsfs_config *cfg, const char *label, size_t len);
long dnsfs_nr_cached_objects(struct super_block *sb, struct shrink_control *sc);
long dnsfs_free_cached_objects(struct super_block *sb,
                               struct shrink_control *sc);
int dnsfs_query_thread(void *data);

#endif
