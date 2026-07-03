/* SPDX-License-Identifier: GPL-2.0-only */

/* VFS glue plus storage layer.
 *
 * Thesis: a filesystem is a namespace, not storage. A path maps to a DNS FQDN
 * by reversing and lower-casing its labels under the mount's zone (zone nl.,
 * /miek/a -> a.miek.nl.); record types (A, TXT, MX, ...) are upper-case leaf
 * files, CNAME is a symlink, NXDOMAIN is a negative dentry. With -o storage a
 * directory also exposes regular files reassembled from chunked TXT records.
 *
 * Writes are gated hard: a mount is writable only when storage is on, an
 * absolute publisher= was given, and the mount lives in the initial user
 * namespace -- because publishing shells out via call_usermodehelper() as root.
 * All untrusted wire/storage decoding lives in src/parser.c; this TU is only
 * VFS plumbing and never parses raw input itself.
 */

#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/delayed_call.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/net.h>
#include <linux/nsproxy.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uio.h>
#include <linux/user_namespace.h>
#include <linux/wait.h>
#include <net/net_namespace.h>
#include <net/sock.h>

#include "dnsfs.h"

enum dnsfs_param {
    Opt_nameserver,
    Opt_publisher,
    Opt_port,
    Opt_timeout,
    Opt_retries,
    Opt_dnssec,
    Opt_storage,
};

#define DNSFS_TYPES(X)            \
    X("A", 1, DNSFS_RECORD)       \
    X("AAAA", 28, DNSFS_RECORD)   \
    X("TXT", 16, DNSFS_RECORD)    \
    X("MX", 15, DNSFS_RECORD)     \
    X("NS", 2, DNSFS_RECORD)      \
    X("SOA", 6, DNSFS_RECORD)     \
    X("DS", 43, DNSFS_RECORD)     \
    X("DNSKEY", 48, DNSFS_RECORD) \
    X("CNAME", 5, DNSFS_SYMLINK)

static const struct dnsfs_type dnsfs_types[] = {
#define DNSFS_TYPE_ENTRY(name, qtype, kind) {name, qtype, kind},
    DNSFS_TYPES(DNSFS_TYPE_ENTRY)
#undef DNSFS_TYPE_ENTRY
};

static const struct fs_parameter_spec dnsfs_param_specs[] = {
    fsparam_string("nameserver", Opt_nameserver),
    fsparam_string("publisher", Opt_publisher),
    fsparam_u32("port", Opt_port),
    fsparam_u32("timeout", Opt_timeout),
    fsparam_u32("retries", Opt_retries),
    fsparam_flag("dnssec", Opt_dnssec),
    fsparam_flag("storage", Opt_storage),
    {}};

static const struct inode_operations dnsfs_dir_inode_ops;
static const struct inode_operations dnsfs_storage_inode_ops;
static const struct file_operations dnsfs_dir_ops;
static struct inode *dnsfs_make_inode(struct super_block *sb,
                                      enum dnsfs_kind kind);
static struct proc_dir_entry *dnsfs_proc_dir;
atomic64_t dnsfs_wire_queries = ATOMIC64_INIT(0);

/* Counts how often a record file re-renders its page cache. Repeated small
 * reads of one open file must not bump this once the cache is fresh, which is
 * the whole point of the read_iter fast path; the test asserts on the delta.
 */
static atomic64_t dnsfs_record_refreshes = ATOMIC64_INIT(0);

struct dnsfs_record_file {
    char fqdn[DNSFS_MAX_NAME + 1];
    unsigned long cached_gen; /* cache generation this inode's pages reflect */
    u16 qtype;
};

static ssize_t dnsfs_proc_wire_queries_read(struct file *file,
                                            char __user *buf,
                                            size_t len,
                                            loff_t *ppos)
{
    char text[32];
    int text_len;

    text_len = scnprintf(text, sizeof(text), "%lld\n",
                         atomic64_read(&dnsfs_wire_queries));
    return simple_read_from_buffer(buf, len, ppos, text, text_len);
}

static const struct proc_ops dnsfs_proc_wire_queries_ops = {
    .proc_read = dnsfs_proc_wire_queries_read,
};

static bool dnsfs_proc_wire_queries;

static ssize_t dnsfs_proc_record_refreshes_read(struct file *file,
                                                char __user *buf,
                                                size_t len,
                                                loff_t *ppos)
{
    char text[32];
    int text_len;

    text_len = scnprintf(text, sizeof(text), "%lld\n",
                         atomic64_read(&dnsfs_record_refreshes));
    return simple_read_from_buffer(buf, len, ppos, text, text_len);
}

static const struct proc_ops dnsfs_proc_record_refreshes_ops = {
    .proc_read = dnsfs_proc_record_refreshes_read,
};

static bool dnsfs_proc_record_refreshes;

static bool dnsfs_is_lower_label(const struct qstr *name)
{
    unsigned int i;

    if (!name->len || name->len > DNSFS_MAX_LABEL)
        return false;

    for (i = 0; i < name->len; i++) {
        char c = name->name[i];

        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')
            continue;
        return false;
    }

    return name->name[0] != '-' && name->name[name->len - 1] != '-';
}

static bool dnsfs_is_mixed_case_label(const struct qstr *name)
{
    bool has_lower = false;
    bool has_upper = false;
    unsigned int i;

    if (!name->len || name->len > DNSFS_MAX_LABEL)
        return false;
    if (name->name[0] == '-' || name->name[name->len - 1] == '-')
        return false;

    for (i = 0; i < name->len; i++) {
        char c = name->name[i];

        if (c >= 'a' && c <= 'z') {
            has_lower = true;
            continue;
        }
        if (c >= 'A' && c <= 'Z') {
            has_upper = true;
            continue;
        }
        if ((c >= '0' && c <= '9') || c == '-')
            continue;
        return false;
    }

    return has_lower && has_upper;
}

const struct dnsfs_type *dnsfs_find_type(const struct qstr *name)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(dnsfs_types); i++) {
        if (name->len == strlen(dnsfs_types[i].name) &&
            !memcmp(name->name, dnsfs_types[i].name, name->len))
            return &dnsfs_types[i];
    }

    return NULL;
}

static char dnsfs_tolower(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A' + 'a';
    return c;
}

static int dnsfs_append_zone(char *buf,
                             size_t size,
                             size_t *pos,
                             const char *zone)
{
    size_t zone_len = strlen(zone);
    bool has_dot = zone_len && zone[zone_len - 1] == '.';

    if (*pos + zone_len + (has_dot ? 1 : 2) > size)
        return -ENAMETOOLONG;

    memcpy(buf + *pos, zone, zone_len);
    *pos += zone_len;
    if (!has_dot)
        buf[(*pos)++] = '.';
    buf[*pos] = '\0';
    return 0;
}

static int dnsfs_validate_zone_source(const char *zone)
{
    size_t len = strlen(zone);
    size_t label_len = 0;
    size_t i;

    if (!len)
        return -EINVAL;
    if (len > DNSFS_MAX_NAME || (len == DNSFS_MAX_NAME && zone[len - 1] != '.'))
        return -ENAMETOOLONG;

    for (i = 0; i < len; i++) {
        if (zone[i] == '.') {
            if (!label_len || zone[i - 1] == '-')
                return -EINVAL;
            label_len = 0;
            continue;
        }
        if (!label_len && zone[i] == '-')
            return -EINVAL;
        if (!((zone[i] >= 'a' && zone[i] <= 'z') ||
              (zone[i] >= '0' && zone[i] <= '9') || zone[i] == '-'))
            return -EINVAL;
        if (++label_len > DNSFS_MAX_LABEL)
            return -ENAMETOOLONG;
    }

    if (label_len && zone[len - 1] == '-')
        return -EINVAL;
    return label_len || zone[len - 1] == '.' ? 0 : -EINVAL;
}

/* Turn a VFS path into a DNS FQDN. Walking dentry up to the mount root collects
 * labels deepest-first, which reverses path order into DNS order, and each
 * label is lower-cased on the way out before the zone suffix is appended. Most
 * lookups are shallow, so keep the common dentry stack on the kernel stack and
 * allocate only for unusually deep paths. The stack bound and
 * per-label/total-length checks reject paths that cannot encode a legal DNS
 * name rather than overrun buf.
 */
static int dnsfs_path_to_fqdn(struct dentry *dentry, char *buf, size_t size)
{
    struct super_block *sb = dentry->d_sb;
    struct dnsfs_config *cfg = sb->s_fs_info;
    struct dentry *fast[16];
    struct dentry **stack = fast;
    struct dentry *cur;
    size_t pos = 0;
    int depth = 0;
    int i;
    int ret;

    cur = dget(dentry);
    while (cur != sb->s_root) {
        struct dentry *parent;

        if (cur->d_name.len > DNSFS_MAX_LABEL) {
            dput(cur);
            ret = -ENAMETOOLONG;
            goto out_put_stack;
        }
        if (depth == ARRAY_SIZE(fast)) {
            struct dentry **heap;

            heap = kcalloc(DNSFS_MAX_NAME / 2, sizeof(*heap), GFP_KERNEL);
            if (!heap) {
                dput(cur);
                ret = -ENOMEM;
                goto out_put_stack;
            }
            memcpy(heap, fast, sizeof(fast));
            stack = heap;
        }
        if (depth == DNSFS_MAX_NAME / 2) {
            dput(cur);
            ret = -ENAMETOOLONG;
            goto out_put_stack;
        }
        stack[depth++] = cur;
        parent = dget_parent(cur);
        cur = parent;
    }
    dput(cur);

    for (i = 0; i < depth; i++) {
        unsigned int j;

        if (pos + stack[i]->d_name.len + 1 > size) {
            ret = -ENAMETOOLONG;
            goto out_put_stack_from;
        }
        for (j = 0; j < stack[i]->d_name.len; j++)
            buf[pos++] = dnsfs_tolower(stack[i]->d_name.name[j]);
        buf[pos++] = '.';
        dput(stack[i]);
    }

    ret = dnsfs_append_zone(buf, size, &pos, cfg->zone);
    if (stack != fast)
        kfree(stack);
    return ret;

out_put_stack_from:
    while (i < depth)
        dput(stack[i++]);
    if (stack != fast)
        kfree(stack);
    return ret;
out_put_stack:
    while (--depth >= 0)
        dput(stack[depth]);
    if (stack != fast)
        kfree(stack);
    return ret;
}

/* Render a CNAME target as a path relative to the symlink's parent dir when the
 * target FQDN sits under that parent's subtree -- strip the shared suffix and
 * reverse the remaining labels back into mount path order.
 *
 * Returns -EINVAL when the target is not under parent, so dnsfs_get_link falls
 * back to emitting the raw FQDN and the link stays valid even when it escapes
 * the zone.
 */
static int dnsfs_fqdn_to_relative_child(const char *fqdn,
                                        const char *parent,
                                        char *buf,
                                        size_t size)
{
    size_t fqdn_len = strlen(fqdn);
    size_t parent_len = strlen(parent);
    size_t prefix_len;
    size_t pos = 0;

    if (fqdn_len <= parent_len ||
        strcasecmp(fqdn + fqdn_len - parent_len, parent))
        return -EINVAL;
    prefix_len = fqdn_len - parent_len;
    if (!prefix_len || fqdn[prefix_len - 1] != '.')
        return -EINVAL;
    prefix_len--;

    while (prefix_len) {
        size_t label_end = prefix_len;
        size_t label_start = label_end;

        while (label_start && fqdn[label_start - 1] != '.')
            label_start--;
        if (label_end - label_start > DNSFS_MAX_LABEL)
            return -ENAMETOOLONG;
        if (pos && pos + 1 >= size)
            return -ENAMETOOLONG;
        if (pos)
            buf[pos++] = '/';
        if (pos + label_end - label_start + 1 > size)
            return -ENAMETOOLONG;
        memcpy(buf + pos, fqdn + label_start, label_end - label_start);
        pos += label_end - label_start;
        if (!label_start)
            break;
        prefix_len = label_start - 1;
    }

    buf[pos] = '\0';
    return 0;
}

static int dnsfs_trim_query_line(char *line, int len)
{
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        line[--len] = '\0';
    return len;
}

static int dnsfs_child_fqdn(const char *label,
                            size_t label_len,
                            const char *parent,
                            char *out,
                            size_t out_len)
{
    size_t parent_len = strlen(parent);
    size_t i;

    if (!label_len || label_len > DNSFS_MAX_LABEL ||
        label_len + 1 + parent_len + 1 > out_len)
        return -ENAMETOOLONG;
    for (i = 0; i < label_len; i++)
        out[i] = dnsfs_tolower(label[i]);
    out[label_len] = '.';
    memcpy(out + label_len + 1, parent, parent_len + 1);
    return 0;
}

static int dnsfs_query_txt_child(struct dnsfs_config *cfg,
                                 const char *parent,
                                 const char *label,
                                 size_t label_len,
                                 char *out,
                                 size_t out_len)
{
    char fqdn[DNSFS_MAX_NAME + 1];
    int ret;

    ret = dnsfs_child_fqdn(label, label_len, parent, fqdn, sizeof(fqdn));
    if (ret)
        return ret;
    ret = dnsfs_query_record(cfg, fqdn, 16, out, out_len, NULL);
    if (ret > 0)
        ret = dnsfs_trim_query_line(out, ret);
    return ret;
}

static int dnsfs_split_chunk_text(char *line,
                                  size_t len,
                                  char **payload,
                                  size_t *payload_len,
                                  u32 *crc)
{
    char *space;
    int ret;

    space = memchr(line, ' ', len);
    if (!space)
        return -EINVAL;
    ret = dnsfs_parse_hex32(line, space - line, crc);
    if (ret)
        return ret;
    *payload = space + 1;
    *payload_len = len - (space + 1 - line);
    return *payload_len ? 0 : -EINVAL;
}

static int dnsfs_storage_validate_meta(const struct dnsfs_file_meta *meta);

static int dnsfs_storage_fetch_meta(struct dentry *dentry,
                                    struct dnsfs_file_meta *meta,
                                    char *line,
                                    size_t line_len)
{
    struct dentry *parent = dget_parent(dentry);
    struct dnsfs_config *cfg = dentry->d_sb->s_fs_info;
    char parent_fqdn[DNSFS_MAX_NAME + 1];
    int ret;

    ret = dnsfs_path_to_fqdn(parent, parent_fqdn, sizeof(parent_fqdn));
    dput(parent);
    if (ret)
        return ret;

    ret = dnsfs_query_txt_child(cfg, parent_fqdn, dentry->d_name.name,
                                dentry->d_name.len, line, line_len);
    if (ret < 0)
        return ret;
    ret = dnsfs_parse_file_meta(line, ret, meta);
    if (ret)
        return ret;
    return dnsfs_storage_validate_meta(meta);
}

static int dnsfs_storage_has_index(struct dnsfs_config *cfg, const char *fqdn)
{
    struct dnsfs_index_entry entries[DNSFS_MAX_INDEX_ENTRIES];
    char *line;
    size_t count = 0;
    int ret;

    line = kmalloc(DNSFS_RECORD_TEXT_MAX, GFP_KERNEL);
    if (!line)
        return -ENOMEM;
    ret = dnsfs_query_txt_child(cfg, fqdn, DNSFS_STORAGE_INDEX,
                                strlen(DNSFS_STORAGE_INDEX), line,
                                DNSFS_RECORD_TEXT_MAX);
    if (ret > 0)
        ret = dnsfs_parse_index_txt(line, ret, entries, ARRAY_SIZE(entries),
                                    &count);
    kfree(line);
    if (ret == -ENOENT)
        return 0;
    return ret < 0 ? ret : 1;
}

static int dnsfs_storage_validate_meta(const struct dnsfs_file_meta *meta)
{
    if ((meta->mode & S_IFMT) != S_IFREG)
        return -EINVAL;
    if (meta->mode & ~(S_IFMT | 0777))
        return -EINVAL;
    if (meta->mode & 0222)
        return -EINVAL;
    if (meta->chunk_count > DNSFS_MAX_STORAGE_CHUNKS ||
        meta->size > DNSFS_MAX_STORAGE_SIZE)
        return -EFBIG;
    return 0;
}

static int dnsfs_storage_copy_meta(struct dnsfs_storage_file *storage,
                                   const struct dnsfs_file_meta *meta)
{
    if (meta->epoch_len > DNSFS_MAX_LABEL)
        return -EINVAL;

    storage->meta = *meta;
    memcpy(storage->epoch, meta->epoch, meta->epoch_len);
    storage->epoch[meta->epoch_len] = '\0';
    storage->meta.epoch = storage->epoch;
    return 0;
}

static void dnsfs_storage_apply_inode_meta(struct inode *inode,
                                           const struct dnsfs_file_meta *meta)
{
    struct dnsfs_config *cfg = inode->i_sb->s_fs_info;

    inode->i_mode = S_IFREG | (meta->mode & 0777);
    if (cfg->writable)
        inode->i_mode |= 0200;
    /* Lockless i_size store, same call as dnsfs_record_refresh (TODO B5): a
     * plain aligned store on the 64-bit target. A 32-bit SMP target would need
     * inode_lock here and around the matching i_size_read in the read path.
     */
    i_size_write(inode, meta->size);
    inode_set_mtime_to_ts(inode, (struct timespec64) {.tv_sec = meta->mtime});
}

static int dnsfs_storage_pin_meta(struct file *file,
                                  struct dnsfs_storage_file *storage,
                                  bool drop_cache,
                                  bool refresh_inode)
{
    struct dentry *dentry = file_dentry(file);
    struct dnsfs_config *cfg = dentry->d_sb->s_fs_info;
    struct dnsfs_file_meta meta;
    char *line;
    int ret;

    if (drop_cache)
        dnsfs_cache_drop(cfg, storage->meta_fqdn, 16);

    line = kmalloc(DNSFS_RECORD_TEXT_MAX, GFP_KERNEL);
    if (!line)
        return -ENOMEM;
    ret =
        dnsfs_query_txt_child(cfg, storage->parent_fqdn, dentry->d_name.name,
                              dentry->d_name.len, line, DNSFS_RECORD_TEXT_MAX);
    if (ret < 0)
        goto out;
    ret = dnsfs_parse_file_meta(line, ret, &meta);
    if (ret)
        goto out;
    ret = dnsfs_storage_validate_meta(&meta);
    if (ret)
        goto out;
    ret = dnsfs_storage_copy_meta(storage, &meta);
    if (ret)
        goto out;

    if (refresh_inode) {
        dnsfs_storage_apply_inode_meta(file_inode(file), &storage->meta);
        invalidate_mapping_pages(file_inode(file)->i_mapping, 0, -1);
    }
out:
    kfree(line);
    return ret;
}

/* Reassemble the whole file from its chunk TXT records in a single pass. EOF is
 * defined by meta->chunk_count, so a chunk that has gone NXDOMAIN is a torn
 * read of a file that still claims those bytes, not a short file: -ENOENT
 * becomes -EIO (the storage-read exception) and dnsfs_storage_assemble()
 * retries once with re-pinned metadata.
 */
static int dnsfs_storage_assemble_once(struct file *file,
                                       struct dnsfs_storage_file *storage,
                                       u8 **out,
                                       size_t *out_len)
{
    struct dentry *dentry = file_dentry(file);
    struct dnsfs_config *cfg = dentry->d_sb->s_fs_info;
    struct dnsfs_file_meta *meta = &storage->meta;
    struct dnsfs_decoded_chunk *chunks = NULL;
    char (*labels)[DNSFS_MAX_LABEL + 1] = NULL;
    u8 *chunk_data = NULL;
    u8 *payload = NULL;
    char *line = NULL;
    int ret;
    u32 i;

    line = kmalloc(DNSFS_RECORD_TEXT_MAX, GFP_KERNEL);
    if (!line) {
        ret = -ENOMEM;
        goto out;
    }

    payload = kzalloc(meta->size ? meta->size : 1, GFP_KERNEL);
    chunks = kcalloc(meta->chunk_count, sizeof(*chunks), GFP_KERNEL);
    labels = kcalloc(meta->chunk_count, sizeof(*labels), GFP_KERNEL);
    chunk_data = kcalloc(meta->chunk_count, DNSFS_CHUNK_SIZE, GFP_KERNEL);
    if (!payload || (!chunks && meta->chunk_count) ||
        (!labels && meta->chunk_count) || (!chunk_data && meta->chunk_count)) {
        ret = -ENOMEM;
        goto out;
    }

    /* DNS storage is snapshot-ish, not transactional: index, metadata, and
     * chunks may come from different resolver cache generations. Epoch + CRC
     * catch mixed/stale chunks; callers retry once with fresh metadata.
     * Whole-file assembly is fine for the tiny teaching files.
     */
    for (i = 0; i < meta->chunk_count; i++) {
        char *chunk_payload;
        size_t chunk_payload_len;
        size_t decoded_len;
        u32 chunk_crc;
        u64 offset = (u64) i * DNSFS_CHUNK_SIZE;

        ret = dnsfs_build_chunk_label(meta, dentry->d_name.name,
                                      dentry->d_name.len, offset, labels[i],
                                      sizeof(labels[i]));
        if (ret < 0)
            goto out;
        ret = dnsfs_parse_chunk_name(labels[i], ret, &chunks[i].name);
        if (ret)
            goto out;
        ret = dnsfs_query_txt_child(cfg, storage->parent_fqdn, labels[i],
                                    strlen(labels[i]), line,
                                    DNSFS_RECORD_TEXT_MAX);
        if (ret == -ENOENT)
            ret = -EIO;
        if (ret < 0)
            goto out;
        ret = dnsfs_split_chunk_text(line, ret, &chunk_payload,
                                     &chunk_payload_len, &chunk_crc);
        if (ret) {
            ret = -EIO;
            goto out;
        }
        ret = dnsfs_decode_file_chunk(
            meta, &chunks[i].name, chunk_payload, chunk_payload_len, chunk_crc,
            chunk_data + i * DNSFS_CHUNK_SIZE, DNSFS_CHUNK_SIZE, &decoded_len);
        if (ret) {
            ret = -EIO;
            goto out;
        }
        chunks[i].data = chunk_data + i * DNSFS_CHUNK_SIZE;
        chunks[i].len = decoded_len;
    }

    ret = dnsfs_reassemble_file_payload(meta, chunks, meta->chunk_count,
                                        payload, meta->size);
    if (ret)
        goto out;
    *out = payload;
    *out_len = meta->size;
    payload = NULL;
    ret = 0;

out:
    kfree(chunk_data);
    kfree(labels);
    kfree(chunks);
    kfree(line);
    kfree(payload);
    return ret;
}

static int dnsfs_storage_assemble(struct file *file, u8 **out, size_t *out_len)
{
    struct dnsfs_storage_file *storage = file->private_data;
    int ret;
    int attempt;

    if (!storage)
        return -EIO;

    for (attempt = 0; attempt < 2; attempt++) {
        ret = dnsfs_storage_assemble_once(file, storage, out, out_len);
        if (ret != -EIO || attempt)
            return ret;
        ret = dnsfs_storage_pin_meta(file, storage, true, false);
        if (ret)
            return ret;
    }

    return ret;
}

/* Read [start, start+out_len) by fetching only the chunks that cover it. As in
 * assemble, a missing chunk is a hole in a file that still claims those bytes,
 * so -ENOENT is mapped to -EIO; the caller retries once with fresh meta. A read
 * that spans the whole file also re-checks the file-level CRC against the
 * reassembled bytes, since per-read coverage alone never validates the file.
 */
static int dnsfs_storage_read_range_once(struct file *file,
                                         struct dnsfs_storage_file *storage,
                                         loff_t start,
                                         u8 *out,
                                         size_t out_len)
{
    struct dentry *dentry = file_dentry(file);
    struct dnsfs_config *cfg = dentry->d_sb->s_fs_info;
    struct dnsfs_file_meta *meta = &storage->meta;
    u32 first = start / DNSFS_CHUNK_SIZE;
    u32 last = (start + out_len - 1) / DNSFS_CHUNK_SIZE;
    char label[DNSFS_MAX_LABEL + 1];
    u8 *chunk_data = NULL;
    u8 *full = NULL;
    char *line = NULL;
    int ret;
    u32 i;
    /* A read covering the whole file also gets a whole-file CRC check; pull the
     * decoded bytes into one buffer so dnsfs_crc32c_verify can validate them.
     * This second buffer (TODO B6) is bounded by DNSFS_MAX_STORAGE_SIZE, capped
     * in dnsfs_storage_validate_meta, so it can never exceed that ceiling.
     */
    bool verify_full = (start == 0 && out_len >= meta->size);

    if (!out_len)
        return 0;
    line = kmalloc(DNSFS_RECORD_TEXT_MAX, GFP_KERNEL);
    chunk_data = kmalloc(DNSFS_CHUNK_SIZE, GFP_KERNEL);
    if (verify_full)
        full = kzalloc(meta->size ? meta->size : 1, GFP_KERNEL);
    if (!line || !chunk_data || (verify_full && !full)) {
        ret = -ENOMEM;
        goto out;
    }

    for (i = first; i <= last; i++) {
        struct dnsfs_decoded_chunk chunk;
        char *chunk_payload;
        size_t chunk_payload_len;
        size_t decoded_len;
        size_t copy_start;
        size_t copy_end;
        u64 chunk_off = (u64) i * DNSFS_CHUNK_SIZE;
        u32 chunk_crc;

        ret = dnsfs_build_chunk_label(meta, dentry->d_name.name,
                                      dentry->d_name.len, chunk_off, label,
                                      sizeof(label));
        if (ret < 0)
            goto out;
        ret = dnsfs_parse_chunk_name(label, ret, &chunk.name);
        if (ret)
            goto out;
        ret = dnsfs_query_txt_child(cfg, storage->parent_fqdn, label,
                                    strlen(label), line, DNSFS_RECORD_TEXT_MAX);
        if (ret == -ENOENT)
            ret = -EIO;
        if (ret < 0)
            goto out;
        ret = dnsfs_split_chunk_text(line, ret, &chunk_payload,
                                     &chunk_payload_len, &chunk_crc);
        if (ret) {
            ret = -EIO;
            goto out;
        }
        ret = dnsfs_decode_file_chunk(meta, &chunk.name, chunk_payload,
                                      chunk_payload_len, chunk_crc, chunk_data,
                                      DNSFS_CHUNK_SIZE, &decoded_len);
        if (ret) {
            ret = -EIO;
            goto out;
        }
        copy_start = max_t(u64, start, chunk_off) - chunk_off;
        copy_end =
            min_t(u64, start + out_len, chunk_off + decoded_len) - chunk_off;
        if (copy_end > copy_start)
            memcpy(out + chunk_off + copy_start - start,
                   chunk_data + copy_start, copy_end - copy_start);
        if (full)
            memcpy(full + chunk_off, chunk_data, decoded_len);
    }
    ret = full ? dnsfs_crc32c_verify(full, meta->size, meta->file_crc) : 0;

out:
    kfree(full);
    kfree(chunk_data);
    kfree(line);
    return ret;
}

static int dnsfs_storage_read_range(struct file *file,
                                    loff_t start,
                                    u8 *out,
                                    size_t out_len)
{
    struct dnsfs_storage_file *storage = file->private_data;
    int ret;
    int attempt;

    if (!storage)
        return -EIO;

    for (attempt = 0; attempt < 2; attempt++) {
        ret = dnsfs_storage_read_range_once(file, storage, start, out, out_len);
        if (ret != -EIO || attempt)
            return ret;
        ret = dnsfs_storage_pin_meta(file, storage, true, false);
        if (ret)
            return ret;
    }

    return ret;
}

/* Fault the currently published file into the page cache before the first
 * write, so a write layers onto real data and the whole-file commit does not
 * publish zeros over untouched bytes. Re-pins stale metadata first; an empty
 * file needs no fetch. The per-folio comment below explains why the loaded
 * pages are deliberately pinned until commit.
 */
static int dnsfs_storage_load_write_cache(struct file *file,
                                          struct dnsfs_storage_file *storage)
{
    struct inode *inode = file_inode(file);
    u8 *payload = NULL;
    size_t payload_len = 0;
    size_t pos = 0;
    int ret;

    if (storage->write_loaded)
        return 0;
    if (storage->meta_stale) {
        ret = dnsfs_storage_pin_meta(file, storage, true, true);
        if (ret)
            return ret;
        storage->meta_stale = false;
    }
    if (!i_size_read(inode)) {
        storage->write_loaded = true;
        return 0;
    }

    ret = dnsfs_storage_assemble(file, &payload, &payload_len);
    if (ret)
        return ret;
    while (pos < payload_len) {
        struct folio *folio;
        char *addr;
        size_t off = pos & (PAGE_SIZE - 1);
        size_t len = min_t(size_t, payload_len - pos, PAGE_SIZE - off);

        folio = __filemap_get_folio(inode->i_mapping, pos >> PAGE_SHIFT,
                                    FGP_LOCK | FGP_CREAT, GFP_KERNEL);
        if (IS_ERR(folio)) {
            ret = PTR_ERR(folio);
            goto out;
        }
        addr = kmap_local_folio(folio, 0);
        if (!off && len < folio_size(folio))
            memset(addr, 0, folio_size(folio));
        memcpy(addr + off, payload + pos, len);
        kunmap_local(addr);
        flush_dcache_folio(folio);
        folio_mark_uptodate(folio);
        /* Whole-file commit needs every base page present at snapshot time.
         * These pages are clean (loaded, not yet modified) and would be
         * reclaimable under memory pressure; reclaiming one would make
         * dnsfs_storage_snapshot() commit zeros over unmodified data. Mark them
         * dirty: with no writeback path they stay resident until commit drops
         * them, so the snapshot always sees the full file. This pins the whole
         * base in cache; fine for capped teaching files, revisit if storage
         * grows past DNSFS_MAX_STORAGE_SIZE.
         */
        folio_mark_dirty(folio);
        folio_unlock(folio);
        folio_put(folio);
        pos += len;
    }
    storage->write_loaded = true;
out:
    kfree(payload);
    return ret;
}

/* Build the byte image to publish from the page cache. Pages reclaimed since
 * the write (returned -ENOENT here) are skipped and left zero; load_write_cache
 * dirties the base pages to keep them resident precisely so this snapshot never
 * writes a hole over data the user did not touch.
 */
static int dnsfs_storage_snapshot(struct inode *inode,
                                  u8 **out,
                                  size_t *out_len)
{
    loff_t size = i_size_read(inode);
    u8 *buf;
    size_t pos = 0;

    if (size < 0 || size > DNSFS_MAX_STORAGE_SIZE)
        return -EFBIG;
    buf = kzalloc(size ? size : 1, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;
    while (pos < size) {
        struct folio *folio;
        char *addr;
        size_t off = pos & (PAGE_SIZE - 1);
        size_t len = min_t(size_t, (size_t) size - pos, PAGE_SIZE - off);

        folio = __filemap_get_folio(inode->i_mapping, pos >> PAGE_SHIFT,
                                    FGP_LOCK, 0);
        if (IS_ERR(folio)) {
            if (PTR_ERR(folio) == -ENOENT) {
                pos += len;
                continue;
            }
            kfree(buf);
            return PTR_ERR(folio);
        }
        if (folio_test_uptodate(folio)) {
            addr = kmap_local_folio(folio, 0);
            memcpy(buf + pos, addr + off, len);
            kunmap_local(addr);
        }
        folio_unlock(folio);
        folio_put(folio);
        pos += len;
    }
    *out = buf;
    *out_len = size;
    return 0;
}

/* Publish the whole dirty file and reset write state. This runs only from
 * process context (fsync/flush/release), never an atomic, RCU, timer, or
 * reclaim section, because dnsfs_commit_put shells out and sleeps. After a
 * durable PUT it drops cached pages and marks metadata stale so the next access
 * re-pins the new epoch/size.
 */
static int dnsfs_storage_commit(struct file *file)
{
    struct dnsfs_storage_file *storage = file->private_data;
    struct inode *inode = file_inode(file);
    struct dnsfs_config *cfg = inode->i_sb->s_fs_info;
    u8 *payload = NULL;
    size_t payload_len = 0;
    int ret;

    if (!storage)
        return -EIO;
    mutex_lock(&storage->lock);
    if (!storage->dirty) {
        ret = storage->write_err;
        goto unlock;
    }
    ret = dnsfs_storage_snapshot(inode, &payload, &payload_len);
    if (!ret)
        ret = dnsfs_commit_put(cfg, file_dentry(file)->d_name.name,
                               file_dentry(file)->d_name.len, payload,
                               payload_len);
    if (!ret) {
        /* PUT succeeded: the publish is durable, so commit is successful even
         * if the post-publish metadata refresh below fails. Refresh meta so a
         * same-fd read/write sees the new epoch/size; on failure leave
         * meta_stale set and let load_write_cache (or assemble's retry) re-pin
         * later, never turn a successful publish into a sticky write_err.
         */
        storage->dirty = false;
        storage->write_err = 0;
        dnsfs_cache_drop_storage(cfg, storage->parent_fqdn,
                                 file_dentry(file)->d_name.name,
                                 file_dentry(file)->d_name.len);
        storage->meta_stale = true;
        if (!dnsfs_storage_pin_meta(file, storage, true, true))
            storage->meta_stale = false;
        truncate_inode_pages(inode->i_mapping, 0);
        storage->write_loaded = false;
    } else {
        storage->write_err = ret;
    }
    kfree(payload);
unlock:
    mutex_unlock(&storage->lock);
    return ret;
}

static struct inode *dnsfs_new_inode(struct super_block *sb, umode_t mode)
{
    struct dnsfs_config *cfg = sb->s_fs_info;
    struct inode *inode = new_inode(sb);

    if (!inode)
        return NULL;

    inode->i_ino = atomic64_inc_return(&cfg->next_ino);
    inode->i_mode = mode;
    inode->i_uid = current_fsuid();
    inode->i_gid = current_fsgid();
    simple_inode_init_ts(inode);
    return inode;
}

static int dnsfs_record_fill(struct file *file, char *line)
{
    struct dentry *dentry = file_dentry(file);
    struct dnsfs_config *cfg = dentry->d_sb->s_fs_info;
    struct dnsfs_record_file *record = file->private_data;
    char fqdn[DNSFS_MAX_NAME + 1];
    u16 qtype;
    int ret;

    if (record) {
        qtype = record->qtype;
        strscpy(fqdn, record->fqdn, sizeof(fqdn));
    } else {
        struct dentry *parent = dget_parent(dentry);

        ret = dnsfs_path_to_fqdn(parent, fqdn, sizeof(fqdn));
        dput(parent);
        if (ret)
            return ret;
        qtype = dnsfs_qtype(&dentry->d_name);
    }

    if (cfg->sock && qtype)
        return dnsfs_query_record(cfg, fqdn, qtype, line, DNSFS_RECORD_TEXT_MAX,
                                  dentry->d_inode->i_mapping);
    return scnprintf(line, DNSFS_RECORD_TEXT_MAX, "%.*s %s synthetic\n",
                     (int) dentry->d_name.len, dentry->d_name.name, fqdn);
}

static int dnsfs_record_refresh(struct inode *inode, struct file *file)
{
    struct dnsfs_record_file *record = file->private_data;
    char *line;
    int ret;

    line = kmalloc(DNSFS_RECORD_TEXT_MAX, GFP_KERNEL);
    if (!line)
        return -ENOMEM;
    atomic64_inc(&dnsfs_record_refreshes);
    ret = dnsfs_record_fill(file, line);
    if (ret >= 0) {
        /* Lockless i_size store (TODO B5): a plain aligned store on the 64-bit
         * target. A 32-bit SMP target would need inode_lock here and around the
         * matching i_size_read in the read path.
         */
        i_size_write(inode, ret);
        invalidate_mapping_pages(inode->i_mapping, 0, -1);
        /* Stamp the generation these freshly-filled pages now reflect, so a
         * later read can skip the refresh only while the cache hasn't moved.
         */
        if (record) {
            struct dnsfs_config *cfg = inode->i_sb->s_fs_info;

            /* WRITE_ONCE pairs with the READ_ONCE in read_iter: concurrent
             * reads on one fd may touch this field while we restamp it.
             */
            WRITE_ONCE(
                record->cached_gen,
                dnsfs_cache_generation(cfg, record->fqdn, record->qtype));
        }
        ret = 0;
    }
    kfree(line);
    return ret;
}

static int dnsfs_record_open(struct inode *inode, struct file *file)
{
    struct dentry *dentry = file_dentry(file);
    struct dnsfs_record_file *record;
    struct dentry *parent;
    int ret;

    record = kzalloc(sizeof(*record), GFP_KERNEL);
    if (!record)
        return -ENOMEM;
    parent = dget_parent(dentry);
    ret = dnsfs_path_to_fqdn(parent, record->fqdn, sizeof(record->fqdn));
    dput(parent);
    if (ret)
        goto out_free;
    record->qtype = dnsfs_qtype(&dentry->d_name);
    file->private_data = record;

    ret = dnsfs_record_refresh(inode, file);
    if (ret)
        goto out_clear;
    return 0;

out_clear:
    file->private_data = NULL;
out_free:
    kfree(record);
    return ret;
}

static ssize_t dnsfs_record_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
    struct file *file = iocb->ki_filp;
    struct dnsfs_config *cfg = file_inode(file)->i_sb->s_fs_info;
    struct dnsfs_record_file *record = file->private_data;
    unsigned long gen;
    int ret;

    /* Refresh unless the cache entry that filled our pages is still the live
     * one. dnsfs_cache_generation() returns 0 for absent/non-cacheable/expired
     * answers, which must never match an earlier stamp. Any non-zero value
     * other than what we last stamped means the answer moved, so our page cache
     * is stale.
     */
    if (cfg->sock && record && record->qtype) {
        gen = dnsfs_cache_generation(cfg, record->fqdn, record->qtype);
        if (!gen || gen != READ_ONCE(record->cached_gen)) {
            ret = dnsfs_record_refresh(file_inode(file), file);
            if (ret)
                return ret;
        }
    }
    return generic_file_read_iter(iocb, to);
}

static int dnsfs_record_release(struct inode *inode, struct file *file)
{
    kfree(file->private_data);
    file->private_data = NULL;
    return 0;
}

static int dnsfs_record_read_folio(struct file *file, struct folio *folio)
{
    char *line;
    char *addr;
    unsigned int nofs;
    loff_t start = folio_pos(folio);
    size_t offset = 0;
    size_t len = 0;
    int ret;

    /* This runs in the page-cache read path, which reclaim can enter; scope all
     * nested allocations to GFP_NOFS so they cannot recurse into the fs.
     */
    nofs = memalloc_nofs_save();
    line = kmalloc(DNSFS_RECORD_TEXT_MAX, GFP_KERNEL);
    if (!line) {
        memalloc_nofs_restore(nofs);
        folio_unlock(folio);
        return -ENOMEM;
    }

    ret = dnsfs_record_fill(file, line);
    if (ret < 0)
        goto out;
    if (start < ret) {
        offset = start;
        len = min_t(size_t, ret - offset, folio_size(folio));
    }
    addr = kmap_local_folio(folio, 0);
    memset(addr, 0, folio_size(folio));
    if (len)
        memcpy(addr, line + offset, len);
    kunmap_local(addr);
    flush_dcache_folio(folio);
    folio_mark_uptodate(folio);
    ret = 0;
out:
    memalloc_nofs_restore(nofs);
    kfree(line);
    folio_unlock(folio);
    return ret;
}

static void dnsfs_record_readahead(struct readahead_control *ractl)
{
    struct folio *folio;

    while ((folio = readahead_folio(ractl)))
        dnsfs_record_read_folio(ractl->file, folio);
}

static const struct address_space_operations dnsfs_record_aops = {
    .read_folio = dnsfs_record_read_folio,
    .readahead = dnsfs_record_readahead,
};

static const struct file_operations dnsfs_record_ops = {
    .open = dnsfs_record_open,
    .read_iter = dnsfs_record_read_iter,
    .release = dnsfs_record_release,
    .llseek = generic_file_llseek,
};

static int dnsfs_storage_open(struct inode *inode, struct file *file)
{
    struct dnsfs_storage_file *storage;
    struct dentry *parent;
    int ret;

    storage = kzalloc(sizeof(*storage), GFP_KERNEL);
    if (!storage)
        return -ENOMEM;
    mutex_init(&storage->lock);

    parent = dget_parent(file_dentry(file));
    ret = dnsfs_path_to_fqdn(parent, storage->parent_fqdn,
                             sizeof(storage->parent_fqdn));
    dput(parent);
    if (ret)
        goto out;
    ret = dnsfs_child_fqdn(file_dentry(file)->d_name.name,
                           file_dentry(file)->d_name.len, storage->parent_fqdn,
                           storage->meta_fqdn, sizeof(storage->meta_fqdn));
    if (ret)
        goto out;

    file->private_data = storage;
    ret = dnsfs_storage_pin_meta(file, storage, false, true);
    if (!ret) {
        if ((file->f_flags & O_TRUNC) && (file->f_mode & FMODE_WRITE)) {
            truncate_setsize(inode, 0);
            storage->dirty = true;
            storage->write_loaded = true;
        }
        return 0;
    }
    file->private_data = NULL;
out:
    kfree(storage);
    return ret;
}

static ssize_t dnsfs_storage_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
    return generic_file_read_iter(iocb, to);
}

static ssize_t dnsfs_storage_write_iter(struct kiocb *iocb,
                                        struct iov_iter *from)
{
    struct dnsfs_storage_file *storage = iocb->ki_filp->private_data;
    struct inode *inode = file_inode(iocb->ki_filp);
    struct dnsfs_config *cfg = inode->i_sb->s_fs_info;
    ssize_t ret;

    if (!storage)
        return -EIO;
    if (!cfg->writable)
        return -EROFS;
    /* Reject before the page cache grows. Subtraction form avoids the wrap of
     * ki_pos + count when a writer seeks near LLONG_MAX.
     */
    if (iocb->ki_pos < 0 || iocb->ki_pos > DNSFS_MAX_STORAGE_SIZE ||
        iov_iter_count(from) > DNSFS_MAX_STORAGE_SIZE - iocb->ki_pos)
        return -EFBIG;
    mutex_lock(&storage->lock);
    ret = dnsfs_storage_load_write_cache(iocb->ki_filp, storage);
    mutex_unlock(&storage->lock);
    if (ret)
        return ret;
    ret = generic_file_write_iter(iocb, from);
    if (ret > 0) {
        mutex_lock(&storage->lock);
        storage->dirty = true;
        mutex_unlock(&storage->lock);
    }
    return ret;
}

static int dnsfs_storage_fsync(struct file *file,
                               loff_t start,
                               loff_t end,
                               int datasync)
{
    return dnsfs_storage_commit(file);
}

static int dnsfs_storage_flush(struct file *file, fl_owner_t id)
{
    return dnsfs_storage_commit(file);
}

static int dnsfs_storage_release(struct inode *inode, struct file *file)
{
    struct dnsfs_storage_file *storage = file->private_data;
    bool need_commit = false;

    /* ->flush already committed on close(); only commit here if it never ran
     * (no explicit close) and didn't already fail, avoids a redundant socket
     * retry of a commit that just errored. Read dirty/write_err under the lock:
     * a dup'd fd's concurrent ->flush mutates them while this final fput runs.
     */
    if ((file->f_mode & FMODE_WRITE) && storage) {
        mutex_lock(&storage->lock);
        need_commit = storage->dirty && !storage->write_err;
        mutex_unlock(&storage->lock);
    }
    if (need_commit)
        dnsfs_storage_commit(file);
    kfree(storage);
    file->private_data = NULL;
    return 0;
}

static int dnsfs_storage_read_folio(struct file *file, struct folio *folio)
{
    char *addr;
    u8 *bounce = NULL;
    unsigned int nofs;
    loff_t size = i_size_read(file_inode(file));
    loff_t start = folio_pos(folio);
    size_t len = 0;
    int ret = 0;

    /* read_folio is entered with the folio locked, so it must not take
     * storage->lock: the write path holds storage->lock and then locks folios
     * (load_write_cache, commit's invalidate), which would be a lock-order
     * inversion. Stale post-commit metadata self-heals here via the range
     * reader's EIO retry, which re-pins meta on its own. Scope allocations to
     * GFP_NOFS since reclaim can enter this path.
     */
    nofs = memalloc_nofs_save();
    if (start < size)
        len = min_t(size_t, size - start, folio_size(folio));
    if (len) {
        /* Resolve into a bounce buffer, not the mapped folio: the range reader
         * sleeps on multi-second DNS queries and kmap_local pins a per-CPU
         * mapping slot that must not be held across that.
         */
        bounce = kmalloc(len, GFP_KERNEL);
        if (!bounce) {
            ret = -ENOMEM;
            goto out;
        }
        ret = dnsfs_storage_read_range(file, start, bounce, len);
        if (ret)
            goto out;
    }
    addr = kmap_local_folio(folio, 0);
    memset(addr, 0, folio_size(folio));
    if (len)
        memcpy(addr, bounce, len);
    kunmap_local(addr);
    flush_dcache_folio(folio);
    folio_mark_uptodate(folio);
out:
    memalloc_nofs_restore(nofs);
    kfree(bounce);
    folio_unlock(folio);
    return ret;
}

static int dnsfs_storage_write_end(const struct kiocb *iocb,
                                   struct address_space *mapping,
                                   loff_t pos,
                                   unsigned int len,
                                   unsigned int copied,
                                   struct folio *folio,
                                   void *fsdata)
{
    struct inode *inode = mapping->host;
    loff_t last = pos + copied;

    if (copied) {
        flush_dcache_folio(folio);
        folio_mark_uptodate(folio);
        folio_mark_dirty(folio);
        if (last > i_size_read(inode))
            i_size_write(inode, last);
    }
    folio_unlock(folio);
    folio_put(folio);
    return copied;
}

static void dnsfs_storage_readahead(struct readahead_control *ractl)
{
    struct folio *folio;

    while ((folio = readahead_folio(ractl)))
        dnsfs_storage_read_folio(ractl->file, folio);
}

static const struct address_space_operations dnsfs_storage_aops = {
    .read_folio = dnsfs_storage_read_folio,
    .readahead = dnsfs_storage_readahead,
    .write_begin = simple_write_begin,
    .write_end = dnsfs_storage_write_end,
    .dirty_folio = noop_dirty_folio,
};

static const struct file_operations dnsfs_storage_ops = {
    .open = dnsfs_storage_open,
    .flush = dnsfs_storage_flush,
    .fsync = dnsfs_storage_fsync,
    .release = dnsfs_storage_release,
    .read_iter = dnsfs_storage_read_iter,
    .write_iter = dnsfs_storage_write_iter,
    .llseek = generic_file_llseek,
};

static int dnsfs_create(struct mnt_idmap *idmap,
                        struct inode *dir,
                        struct dentry *dentry,
                        umode_t mode,
                        bool excl)
{
    struct dnsfs_config *cfg = dir->i_sb->s_fs_info;
    struct inode *inode;
    struct dentry *parent;
    char parent_fqdn[DNSFS_MAX_NAME + 1];
    int ret;

    if (!cfg->writable || !cfg->storage ||
        !dnsfs_is_lower_label(&dentry->d_name))
        return -EACCES;
    parent = dget_parent(dentry);
    ret = dnsfs_path_to_fqdn(parent, parent_fqdn, sizeof(parent_fqdn));
    dput(parent);
    if (ret)
        return ret;
    /* Allocate the inode first: if it fails after publishing, the remote file
     * is orphaned with no VFS object referencing it.
     */
    inode = dnsfs_make_inode(dir->i_sb, DNSFS_STORAGE);
    if (!inode)
        return -ENOMEM;
    inode->i_mode = S_IFREG | (mode & 0666);
    inode->i_op = &dnsfs_storage_inode_ops;
    ret =
        dnsfs_commit_put(cfg, dentry->d_name.name, dentry->d_name.len, NULL, 0);
    if (ret) {
        iput(inode);
        return ret;
    }
    dnsfs_cache_drop_storage(cfg, parent_fqdn, dentry->d_name.name,
                             dentry->d_name.len);
    d_instantiate(dentry, inode);
    return 0;
}

static int dnsfs_unlink(struct inode *dir, struct dentry *dentry)
{
    struct dnsfs_config *cfg = dir->i_sb->s_fs_info;
    struct dentry *parent;
    char parent_fqdn[DNSFS_MAX_NAME + 1];
    int ret;

    if (!cfg->writable || !cfg->storage ||
        !dnsfs_is_lower_label(&dentry->d_name))
        return -EACCES;
    parent = dget_parent(dentry);
    ret = dnsfs_path_to_fqdn(parent, parent_fqdn, sizeof(parent_fqdn));
    dput(parent);
    if (ret)
        return ret;
    ret = dnsfs_commit_del(cfg, dentry->d_name.name, dentry->d_name.len);
    if (ret)
        return ret;
    dnsfs_cache_drop_storage(cfg, parent_fqdn, dentry->d_name.name,
                             dentry->d_name.len);
    truncate_inode_pages(d_inode(dentry)->i_mapping, 0);
    drop_nlink(d_inode(dentry));
    return 0;
}

/* Resolve a CNAME live to its link target. Prefer an in-mount relative path
 * when the target lies under this zone (so the link stays inside the
 * namespace), otherwise emit the raw FQDN.
 *
 * Returns -ECHILD on the RCU walk so the VFS retries in ref-walk mode, since
 * resolving sleeps on a DNS query.
 */
static const char *dnsfs_get_link(struct dentry *dentry,
                                  struct inode *inode,
                                  struct delayed_call *done)
{
    struct dentry *parent;
    struct dnsfs_config *cfg;
    char *target;
    char *line;
    char fqdn[DNSFS_MAX_NAME + 1];
    int ret;

    if (!dentry)
        return ERR_PTR(-ECHILD);
    cfg = dentry->d_sb->s_fs_info;
    if (!cfg->sock)
        goto synthetic;

    line = kzalloc(DNSFS_RECORD_TEXT_MAX, GFP_KERNEL);
    if (!line)
        return ERR_PTR(-ENOMEM);
    parent = dget_parent(dentry);
    ret = dnsfs_path_to_fqdn(parent, fqdn, sizeof(fqdn));
    dput(parent);
    if (!ret)
        ret =
            dnsfs_query_record(cfg, fqdn, 5, line, DNSFS_RECORD_TEXT_MAX, NULL);
    if (ret > 0) {
        strim(line);
        target = kmalloc(DNSFS_MAX_NAME + 1, GFP_KERNEL);
        if (!target) {
            kfree(line);
            return ERR_PTR(-ENOMEM);
        }
        if (dnsfs_fqdn_to_relative_child(line, fqdn, target,
                                         DNSFS_MAX_NAME + 1)) {
            kfree(target);
            target = kstrdup(line, GFP_KERNEL);
        }
        kfree(line);
        if (!target)
            return ERR_PTR(-ENOMEM);
        set_delayed_call(done, kfree_link, target);
        return target;
    }
    kfree(line);
    if (ret == 0)      /* query succeeded but produced no link body */
        ret = -ENOENT; /* never return ERR_PTR(0) (NULL) to ->get_link */
    return ERR_PTR(ret);

synthetic:
    target = kstrdup("target", GFP_KERNEL);
    if (!target)
        return ERR_PTR(-ENOMEM);
    set_delayed_call(done, kfree_link, target);
    return target;
}

static const struct inode_operations dnsfs_symlink_ops = {
    .get_link = dnsfs_get_link,
};

static int dnsfs_storage_setattr(struct mnt_idmap *idmap,
                                 struct dentry *dentry,
                                 struct iattr *attr)
{
    struct inode *inode = d_inode(dentry);
    struct dnsfs_config *cfg = inode->i_sb->s_fs_info;
    int ret;

    if (!cfg->writable)
        return -EROFS;
    ret = setattr_prepare(idmap, dentry, attr);
    if (ret)
        return ret;

    if ((attr->ia_valid & ATTR_SIZE) && attr->ia_size != i_size_read(inode)) {
        char parent_fqdn[DNSFS_MAX_NAME + 1];
        struct dentry *parent;

        /* Whole-file publishing has no committed base to draw surviving bytes
         * from without an open storage context, so only truncate-to-zero (an
         * empty publish) is supported here. Resizes go through write().
         * Arbitrary truncate needs the open-file base load; add it only if
         * truncate(2) to non-zero sizes is ever needed.
         */
        if (attr->ia_size != 0)
            return -EOPNOTSUPP;
        parent = dget_parent(dentry);
        ret = dnsfs_path_to_fqdn(parent, parent_fqdn, sizeof(parent_fqdn));
        dput(parent);
        if (ret)
            return ret;
        ret = dnsfs_commit_put(cfg, dentry->d_name.name, dentry->d_name.len,
                               NULL, 0);
        if (ret)
            return ret;
        truncate_setsize(inode, 0);
        dnsfs_cache_drop_storage(cfg, parent_fqdn, dentry->d_name.name,
                                 dentry->d_name.len);
        truncate_inode_pages(inode->i_mapping, 0);
    }

    /* mode/owner/time live only in the local inode; the publisher derives
     * stored metadata from the file itself, so these are not pushed to DNS.
     */
    setattr_copy(idmap, inode, attr);
    return 0;
}

static const struct inode_operations dnsfs_storage_inode_ops = {
    .setattr = dnsfs_storage_setattr,
};

static struct inode *dnsfs_make_inode(struct super_block *sb,
                                      enum dnsfs_kind kind)
{
    struct dnsfs_config *cfg = sb->s_fs_info;
    struct inode *inode;

    switch (kind) {
    case DNSFS_DIR:
        inode = dnsfs_new_inode(sb, S_IFDIR | (cfg->writable ? 0755 : 0555));
        if (!inode)
            return NULL;
        inode->i_op = &dnsfs_dir_inode_ops;
        inode->i_fop = &dnsfs_dir_ops;
        set_nlink(inode, 2);
        return inode;
    case DNSFS_RECORD:
        inode = dnsfs_new_inode(sb, S_IFREG | 0444);
        if (!inode)
            return NULL;
        inode->i_fop = &dnsfs_record_ops;
        inode->i_mapping->a_ops = &dnsfs_record_aops;
        return inode;
    case DNSFS_STORAGE:
        inode = dnsfs_new_inode(sb, S_IFREG | (cfg->writable ? 0644 : 0444));
        if (!inode)
            return NULL;
        inode->i_op = &dnsfs_storage_inode_ops;
        inode->i_fop = &dnsfs_storage_ops;
        inode->i_mapping->a_ops = &dnsfs_storage_aops;
        return inode;
    case DNSFS_SYMLINK:
        inode = dnsfs_new_inode(sb, S_IFLNK | 0777);
        if (!inode)
            return NULL;
        inode->i_op = &dnsfs_symlink_ops;
        return inode;
    }

    return NULL;
}

/* Classify a name into the namespace without enumerating the zone. Upper-case
 * names match the fixed record-type table (CNAME -> symlink, the rest -> record
 * files); an all-upper-case name that is not a known type is rejected outright.
 * In storage mode a lower/mixed-case name becomes a regular file when it has
 * file metadata, else a directory when it has an index TXT, else a negative
 * dentry. Plain (non-storage) mounts treat any valid label as a directory and
 * defer existence to the record lookups performed under it.
 */
static struct dentry *dnsfs_lookup(struct inode *dir,
                                   struct dentry *dentry,
                                   unsigned int flags)
{
    const struct dnsfs_type *type;
    struct dnsfs_config *cfg = dir->i_sb->s_fs_info;
    struct inode *inode;
    struct dnsfs_file_meta storage_meta = {};
    bool have_storage_meta = false;
    char fqdn[DNSFS_MAX_NAME + 1];
    enum dnsfs_kind kind;
    int ret;

    if (dentry->d_name.len > DNSFS_MAX_LABEL)
        return ERR_PTR(-ENAMETOOLONG);

    ret = dnsfs_path_to_fqdn(dentry, fqdn, sizeof(fqdn));
    if (ret)
        return ERR_PTR(ret);

    type = dnsfs_find_type(&dentry->d_name);
    if (type) {
        kind = type->kind;
    } else if (dentry->d_name.name[0] >= 'A' && dentry->d_name.name[0] <= 'Z' &&
               !dnsfs_is_mixed_case_label(&dentry->d_name)) {
        return ERR_PTR(-ENOENT);
    } else if (cfg->storage && cfg->sock &&
               (dnsfs_is_lower_label(&dentry->d_name) ||
                dnsfs_is_mixed_case_label(&dentry->d_name))) {
        struct dnsfs_file_meta meta;
        char *line;

        line = kmalloc(DNSFS_RECORD_TEXT_MAX, GFP_KERNEL);
        if (!line)
            return ERR_PTR(-ENOMEM);
        ret = dnsfs_storage_fetch_meta(dentry, &meta, line,
                                       DNSFS_RECORD_TEXT_MAX);
        kfree(line);
        if (ret == -ENOENT) {
            ret = dnsfs_storage_has_index(cfg, fqdn);
            if (ret < 0)
                return ERR_PTR(ret);
            if (!ret) {
                d_add(dentry, NULL);
                return NULL;
            }
            kind = DNSFS_DIR;
        } else if (ret)
            return ERR_PTR(ret);
        else {
            storage_meta = meta;
            have_storage_meta = true;
            kind = DNSFS_STORAGE;
        }
    } else if (dnsfs_is_lower_label(&dentry->d_name) ||
               dnsfs_is_mixed_case_label(&dentry->d_name)) {
        kind = DNSFS_DIR;
    } else {
        return ERR_PTR(-ENOENT);
    }

    inode = dnsfs_make_inode(dir->i_sb, kind);
    if (!inode)
        return ERR_PTR(-ENOMEM);
    if (have_storage_meta)
        dnsfs_storage_apply_inode_meta(inode, &storage_meta);

    return d_splice_alias(inode, dentry);
}

/* Frozen view of a storage directory's index, taken once at opendir. The parsed
 * entries point into line, so the snapshot owns both. Pinning it keeps ctx->pos
 * offsets and positional inode numbers stable across a telldir/seekdir walk
 * even if the publisher rewrites the index mid-iteration.
 */
struct dnsfs_dir_snapshot {
    char line[DNSFS_RECORD_TEXT_MAX];
    struct dnsfs_index_entry entries[DNSFS_MAX_INDEX_ENTRIES];
    size_t count;
};

static int dnsfs_dir_open(struct inode *inode, struct file *file)
{
    struct dentry *dentry = file_dentry(file);
    struct dnsfs_config *cfg = dentry->d_sb->s_fs_info;
    struct dnsfs_dir_snapshot *snap;
    char fqdn[DNSFS_MAX_NAME + 1];
    int ret;

    /* Plain mounts have no index to snapshot; readdir emits only the fixed
     * record-type leaves, which need no per-open state.
     */
    if (!(cfg->storage && cfg->sock))
        return 0;

    snap = kzalloc(sizeof(*snap), GFP_KERNEL);
    if (!snap)
        return -ENOMEM;

    ret = dnsfs_path_to_fqdn(dentry, fqdn, sizeof(fqdn));
    if (!ret)
        ret = dnsfs_query_txt_child(cfg, fqdn, DNSFS_STORAGE_INDEX,
                                    strlen(DNSFS_STORAGE_INDEX), snap->line,
                                    sizeof(snap->line));
    if (ret > 0)
        ret = dnsfs_parse_index_txt(snap->line, ret, snap->entries,
                                    ARRAY_SIZE(snap->entries), &snap->count);
    if (ret == -ENOENT) /* no index TXT (NXDOMAIN or no match): empty dir */
        ret = 0;
    if (ret) {
        kfree(snap);
        return ret;
    }
    file->private_data = snap;
    return 0;
}

static int dnsfs_dir_release(struct inode *inode, struct file *file)
{
    kfree(file->private_data);
    file->private_data = NULL;
    return 0;
}

/* No AXFR, no zone walk. readdir emits only "." "..", the fixed record-type
 * leaf files, and -- in storage mode -- the children named by this directory's
 * index TXT snapshot. A plain mount therefore lists just the record-type files;
 * the actual records under a label only materialize when something looks them
 * up.
 */
static int dnsfs_iterate_shared(struct file *file, struct dir_context *ctx)
{
    struct dentry *dentry = file_dentry(file);
    struct dnsfs_config *cfg = dentry->d_sb->s_fs_info;
    loff_t base_pos = 2 + ARRAY_SIZE(dnsfs_types);

    if (!dir_emit_dots(file, ctx))
        return 0;

    /* ctx->pos is a 64-bit user-seekable offset; compare it as loff_t before
     * indexing so a wild seekdir() value cannot truncate back into the type
     * table or the index array and re-emit stale entries.
     */
    while (ctx->pos >= 2 && ctx->pos < base_pos) {
        unsigned int i = ctx->pos - 2;
        unsigned char type =
            dnsfs_types[i].kind == DNSFS_SYMLINK ? DT_LNK : DT_REG;

        if (!dir_emit(ctx, dnsfs_types[i].name, strlen(dnsfs_types[i].name),
                      i + 2, type))
            return 0;
        ctx->pos = i + 3;
    }

    if (cfg->storage && cfg->sock && ctx->pos >= base_pos) {
        struct dnsfs_dir_snapshot *snap = file->private_data;
        loff_t start = ctx->pos - base_pos;

        if (!snap) /* opendir raced a mount going read-only; nothing to list */
            return 0;
        for (; start < (loff_t) snap->count; start++) {
            if (!dir_emit(ctx, snap->entries[start].name,
                          snap->entries[start].name_len, base_pos + start,
                          DT_UNKNOWN))
                return 0;
            ctx->pos = base_pos + start + 1;
        }
    }

    return 0;
}

/* DNS state changes out from under the dcache: a name can begin resolving, go
 * NXDOMAIN, or (in storage mode) be published/removed by the publisher. The DNS
 * TTL cache is the real cache here, so rather than pin dentries past their TTL
 * we re-run lookup for the cases that can change and let that cache absorb the
 * cost -- staleness is then bounded by the record's TTL, not by dcache
 * eviction.
 *
 * A positive dentry on a plain (non-storage) mount is structural -- a label is
 * always a directory, a record-type leaf is always that type -- so it stays
 * valid and keeps the dcache fast path; content freshness lives in the read
 * path. The mount root, negative dentries, and every storage dentry re-resolve.
 */
static int dnsfs_d_revalidate(struct inode *dir,
                              const struct qstr *name,
                              struct dentry *dentry,
                              unsigned int flags)
{
    struct dnsfs_config *cfg = dentry->d_sb->s_fs_info;

    if (IS_ROOT(dentry) || (d_inode(dentry) && !cfg->storage))
        return 1;
    if (flags & LOOKUP_RCU)
        return -ECHILD; /* re-lookup sleeps on DNS; bail to ref-walk */
    return 0;
}

static const struct dentry_operations dnsfs_dentry_ops = {
    .d_revalidate = dnsfs_d_revalidate,
};

static const struct inode_operations dnsfs_dir_inode_ops = {
    .lookup = dnsfs_lookup,
    .create = dnsfs_create,
    .unlink = dnsfs_unlink,
};

static const struct file_operations dnsfs_dir_ops = {
    .open = dnsfs_dir_open,
    .release = dnsfs_dir_release,
    .iterate_shared = dnsfs_iterate_shared,
    .llseek = generic_file_llseek,
};

/* Reclaim hooks for the per-superblock DNS cache. scan_objects can be called
 * from a reclaim context, so the work in dns.c must stay non-sleeping; these
 * wrappers only forward the shrink_control to it.
 */
static unsigned long dnsfs_shrinker_count(struct shrinker *shrinker,
                                          struct shrink_control *sc)
{
    struct super_block *sb = shrinker->private_data;

    return dnsfs_nr_cached_objects(sb, sc);
}

static unsigned long dnsfs_shrinker_scan(struct shrinker *shrinker,
                                         struct shrink_control *sc)
{
    struct super_block *sb = shrinker->private_data;

    return dnsfs_free_cached_objects(sb, sc);
}

static const struct super_operations dnsfs_super_ops = {
    .statfs = simple_statfs,
    .drop_inode = generic_delete_inode,
};

/* fs_context superblock build. Beyond wiring the sb ops it computes
 * cfg->writable -- the mount-time write gate, the security boundary for the
 * whole TU -- then brings up the per-mount resolver socket, query kthread, and
 * cache shrinker, unwinding all of them in reverse on any later failure.
 */
static int dnsfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
    struct dnsfs_config *cfg = fc->fs_private;
    struct inode *root;
    int ret;

    sb->s_magic = DNSFS_MAGIC;
    sb->s_blocksize = PAGE_SIZE;
    sb->s_blocksize_bits = PAGE_SHIFT;
    sb->s_op = &dnsfs_super_ops;
    set_default_d_op(sb, &dnsfs_dentry_ops);
    sb->s_fs_info = cfg;

    /* Storage mode is useless without a resolver, so default to the local
     * resolver when no nameserver= was given; a plain mount with no nameservers
     * is allowed and just serves synthetic data.
     */
    if (cfg->storage && !cfg->nameserver_count) {
        ret = dnsfs_parse_nameservers(cfg, "127.0.0.1");
        if (ret)
            goto err_clear;
    }
    /* The write gate, all three conditions required. There is no default
     * publisher, so a bare -o storage mount stays read-only (publisher_set).
     * call_usermodehelper() runs the publisher as root in the initial
     * namespace, so only an initial-userns mount may publish even though the fs
     * sets FS_USERNS_MOUNT; an unprivileged userns mount stays read-only.
     */
    cfg->writable =
        cfg->storage && cfg->publisher_set && fc->user_ns == &init_user_ns;

    if (cfg->nameserver_count) {
        ret = sock_create_kern(current->nsproxy->net_ns, AF_INET, SOCK_DGRAM,
                               IPPROTO_UDP, &cfg->sock);
        if (ret)
            goto err_clear;
        cfg->query_thread = kthread_run(dnsfs_query_thread, cfg, "dnsfs-query");
        if (IS_ERR(cfg->query_thread)) {
            ret = PTR_ERR(cfg->query_thread);
            cfg->query_thread = NULL;
            goto err_sock;
        }
    }
    cfg->shrinker = shrinker_alloc(0, "dnsfs-%s", cfg->zone);
    if (!cfg->shrinker) {
        ret = -ENOMEM;
        goto err_sock;
    }
    if (IS_ERR(cfg->shrinker)) {
        ret = PTR_ERR(cfg->shrinker);
        cfg->shrinker = NULL;
        goto err_sock;
    }
    cfg->shrinker->count_objects = dnsfs_shrinker_count;
    cfg->shrinker->scan_objects = dnsfs_shrinker_scan;
    cfg->shrinker->seeks = DEFAULT_SEEKS;
    cfg->shrinker->private_data = sb;
    shrinker_register(cfg->shrinker);

    root = dnsfs_make_inode(sb, DNSFS_DIR);
    if (!root) {
        ret = -ENOMEM;
        goto err_shrinker;
    }
    sb->s_root = d_make_root(root);
    if (!sb->s_root) {
        ret = -ENOMEM;
        goto err_shrinker;
    }

    fc->fs_private = NULL;
    return 0;

err_shrinker:
    shrinker_free(cfg->shrinker);
    cfg->shrinker = NULL;
err_sock:
    if (cfg->query_thread) {
        kthread_stop(cfg->query_thread);
        cfg->query_thread = NULL;
    }
    if (cfg->sock) {
        sock_release(cfg->sock);
        cfg->sock = NULL;
    }
err_clear:
    sb->s_fs_info = NULL;
    return ret;
}

static int dnsfs_get_tree(struct fs_context *fc)
{
    struct dnsfs_config *cfg = fc->fs_private;
    int ret;

    if (!fc->source || !*fc->source)
        return -EINVAL;
    ret = dnsfs_validate_zone_source(fc->source);
    if (ret)
        return ret;

    cfg->zone = kstrdup(fc->source, GFP_KERNEL);
    if (!cfg->zone)
        return -ENOMEM;

    return get_tree_nodev(fc, dnsfs_fill_super);
}

static int dnsfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
    struct dnsfs_config *cfg = fc->fs_private;
    struct fs_parse_result result;
    int opt;
    int ret;

    opt = fs_parse(fc, dnsfs_param_specs, param, &result);
    if (opt < 0)
        return opt;

    switch (opt) {
    case Opt_nameserver:
        ret = dnsfs_parse_nameservers(cfg, param->string);
        if (ret)
            return ret;
        kfree(cfg->nameserver);
        cfg->nameserver = param->string;
        param->string = NULL;
        return 0;
    case Opt_publisher:
        if (!param->string || param->string[0] != '/')
            return -EINVAL;
        /* call_usermodehelper() runs this as root in the initial namespace, so
         * only a process with real CAP_SYS_ADMIN may name the executable.
         */
        if (!capable(CAP_SYS_ADMIN))
            return -EPERM;
        kfree(cfg->publisher);
        cfg->publisher = param->string;
        cfg->publisher_set = true;
        param->string = NULL;
        return 0;
    case Opt_port:
        if (!result.uint_32 || result.uint_32 > 65535)
            return -EINVAL;
        cfg->port = result.uint_32;
        return 0;
    case Opt_timeout:
        if (!result.uint_32)
            return -EINVAL;
        cfg->timeout_ms = result.uint_32;
        return 0;
    case Opt_retries:
        if (!result.uint_32)
            return -EINVAL;
        cfg->retries = result.uint_32;
        return 0;
    case Opt_dnssec:
        cfg->dnssec = true;
        return 0;
    case Opt_storage:
        cfg->storage = true;
        return 0;
    default:
        return -EINVAL;
    }
}

static void dnsfs_free_fc(struct fs_context *fc)
{
    dnsfs_free_config(fc->fs_private);
}

static const struct fs_context_operations dnsfs_context_ops = {
    .parse_param = dnsfs_parse_param,
    .get_tree = dnsfs_get_tree,
    .free = dnsfs_free_fc,
};

static int dnsfs_init_fs_context(struct fs_context *fc)
{
    struct dnsfs_config *cfg;
    int ret;

    cfg = kzalloc(sizeof(*cfg), GFP_KERNEL);
    if (!cfg)
        return -ENOMEM;

    cfg->port = DNSFS_DEFAULT_PORT;
    cfg->timeout_ms = DNSFS_DEFAULT_TIMEOUT_MS;
    mutex_init(&cfg->query_lock);
    INIT_LIST_HEAD(&cfg->query_queue);
    INIT_LIST_HEAD(&cfg->query_pending);
    spin_lock_init(&cfg->query_queue_lock);
    init_waitqueue_head(&cfg->query_wait);
    atomic64_set(&cfg->next_ino, 0);
    INIT_LIST_HEAD(&cfg->cache);
    ret = dnsfs_cache_init(cfg);
    if (ret) {
        kfree(cfg);
        return ret;
    }
    fc->fs_private = cfg;
    fc->ops = &dnsfs_context_ops;
    return 0;
}

static void dnsfs_kill_sb(struct super_block *sb)
{
    struct dnsfs_config *cfg = sb->s_fs_info;

    if (cfg && cfg->query_thread) {
        kthread_stop(cfg->query_thread);
        cfg->query_thread = NULL;
    }
    if (cfg && cfg->shrinker) {
        shrinker_free(cfg->shrinker);
        cfg->shrinker = NULL;
    }
    kill_anon_super(sb);
    dnsfs_free_config(cfg);
}

static struct file_system_type dnsfs_type = {
    .owner = THIS_MODULE,
    .name = "dnsfs",
    .init_fs_context = dnsfs_init_fs_context,
    .kill_sb = dnsfs_kill_sb,
    .fs_flags = FS_USERNS_MOUNT,
};

static int __init dnsfs_init(void)
{
    int ret;

    dnsfs_proc_dir = proc_mkdir("fs/dnsfs", NULL);
    if (dnsfs_proc_dir) {
        dnsfs_proc_wire_queries = !!proc_create(
            "wire_queries", 0444, dnsfs_proc_dir, &dnsfs_proc_wire_queries_ops);
        dnsfs_proc_record_refreshes =
            !!proc_create("record_refreshes", 0444, dnsfs_proc_dir,
                          &dnsfs_proc_record_refreshes_ops);
    }
    ret = register_filesystem(&dnsfs_type);
    if (ret) {
        if (dnsfs_proc_wire_queries)
            remove_proc_entry("wire_queries", dnsfs_proc_dir);
        if (dnsfs_proc_record_refreshes)
            remove_proc_entry("record_refreshes", dnsfs_proc_dir);
        if (dnsfs_proc_dir)
            remove_proc_entry("fs/dnsfs", NULL);
        dnsfs_proc_wire_queries = false;
        dnsfs_proc_record_refreshes = false;
        dnsfs_proc_dir = NULL;
    }
    return ret;
}

static void __exit dnsfs_exit(void)
{
    unregister_filesystem(&dnsfs_type);
    if (dnsfs_proc_wire_queries)
        remove_proc_entry("wire_queries", dnsfs_proc_dir);
    if (dnsfs_proc_record_refreshes)
        remove_proc_entry("record_refreshes", dnsfs_proc_dir);
    if (dnsfs_proc_dir)
        remove_proc_entry("fs/dnsfs", NULL);
    dnsfs_proc_wire_queries = false;
    dnsfs_proc_record_refreshes = false;
    dnsfs_proc_dir = NULL;
}

module_init(dnsfs_init);
module_exit(dnsfs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("National Cheng Kung University, Taiwan");
MODULE_DESCRIPTION("Teaching filesystem backed by DNS namespace concepts");
