/* SPDX-License-Identifier: GPL-2.0-only */

/* The resolver engine. Turns an {fqdn, qtype} request into record text: builds
 * DNS wire queries, runs the UDP/TCP kernel-socket client, parses and renders
 * responses, and fronts it all with an rhashtable + RCU TTL cache and a
 * per-mount query kthread. Entry point: dnsfs_query_record().
 *
 * Concurrency model. Unexpired cache hits are served from an RCU read side
 * (dnsfs_cache_lookup_rcu) that touches only immutable fields of an entry, so
 * the fast path takes no lock. Misses and stale-but-refreshable hits go through
 * query_lock (mutates the cache + LRU list) and then either join an
 * already-pending {fqdn, qtype} request or enqueue a new one under
 * query_queue_lock. The single per-mount kthread owns ALL resolver socket I/O,
 * so duplicate in-flight misses collapse to one wire query and the blocking
 * waiters are released together via each request's completion.
 *
 * Context rule: no socket I/O, allocation, or sleeping in a VFS atomic section,
 * an RCU read side, a timer, or reclaim. That is why every wire query is
 * deferred to the kthread (process context) and the shrinker helpers only
 * trylock and count/free, never resolve.
 */
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/inet.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/pagemap.h>
#include <linux/random.h>
#include <linux/refcount.h>
#include <linux/rhashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stdarg.h>
#include <linux/string.h>
#include <linux/uio.h>
#include <linux/umh.h>
#include <linux/wait.h>
#include <net/net_namespace.h>
#include <net/sock.h>

#include "dnsfs.h"

static const struct rhashtable_params dnsfs_cache_params = {
    .key_len = sizeof(struct dnsfs_cache_key),
    .key_offset = offsetof(struct dnsfs_cache_entry, key),
    .head_offset = offsetof(struct dnsfs_cache_entry, node),
    .automatic_shrinking = true,
};

/* Deferred free: an RCU reader (dnsfs_cache_lookup_rcu) may still be copying
 * this entry out after it leaves the hashtable, so reclaim waits for a grace
 * period. dnsfs_free_config drains pending callbacks with rcu_barrier().
 */
static void dnsfs_cache_free_rcu(struct rcu_head *rcu)
{
    kfree(container_of(rcu, struct dnsfs_cache_entry, rcu));
}

/* Unlink from both the hashtable and the LRU list, then free via call_rcu.
 * Caller must hold query_lock: this is the only writer side of the cache.
 */
static void dnsfs_cache_remove_entry(struct dnsfs_config *cfg,
                                     struct dnsfs_cache_entry *entry)
{
    rhashtable_remove_fast(&cfg->cache_ht, &entry->node, dnsfs_cache_params);
    list_del(&entry->list);
    cfg->cache_entries--;
    call_rcu(&entry->rcu, dnsfs_cache_free_rcu);
}

int dnsfs_cache_init(struct dnsfs_config *cfg)
{
    return rhashtable_init(&cfg->cache_ht, &dnsfs_cache_params);
}

/* Teardown order is load-bearing. Stop the kthread first so no resolver socket
 * I/O or queue activity can race the drain below; only then release the socket
 * it owned. Drain the cache, then rcu_barrier() to flush any in-flight
 * dnsfs_cache_free_rcu callbacks before the cfg they point into is freed.
 */
void dnsfs_free_config(struct dnsfs_config *cfg)
{
    if (!cfg)
        return;

    if (cfg->query_thread) {
        kthread_stop(cfg->query_thread);
        cfg->query_thread = NULL;
    }
    if (cfg->sock)
        sock_release(cfg->sock);
    while (!list_empty(&cfg->cache)) {
        struct dnsfs_cache_entry *entry;

        entry = list_first_entry(&cfg->cache, struct dnsfs_cache_entry, list);
        dnsfs_cache_remove_entry(cfg, entry);
    }
    rhashtable_destroy(&cfg->cache_ht);
    rcu_barrier();
    kfree(cfg->zone);
    kfree(cfg->nameserver);
    kfree(cfg->publisher);
    kfree(cfg);
}

int dnsfs_parse_nameservers(struct dnsfs_config *cfg, const char *value)
{
    char *copy;
    char *p;
    unsigned int count = 0;

    copy = kstrdup(value, GFP_KERNEL);
    if (!copy)
        return -ENOMEM;

    p = copy;
    while (p && *p) {
        char *next = strpbrk(p, ",;");

        if (next) {
            *next++ = '\0';
            if (!*next) {
                kfree(copy);
                return -EINVAL;
            }
        }
        if (count == DNSFS_MAX_RESOLVERS ||
            !in4_pton(p, -1, (u8 *) &cfg->nameservers[count], -1, NULL)) {
            kfree(copy);
            return -EINVAL;
        }
        count++;
        p = next;
    }
    kfree(copy);
    if (!count)
        return -EINVAL;
    cfg->nameserver_count = count;
    return 0;
}

u16 dnsfs_qtype(const struct qstr *name)
{
    const struct dnsfs_type *type = dnsfs_find_type(name);

    return type ? type->qtype : 0;
}

static int dnsfs_wire_name(const char *fqdn, u8 *buf, size_t size, size_t *pos)
{
    const char *label = fqdn;

    while (*label) {
        const char *dot = strchr(label, '.');
        size_t len;

        if (!dot)
            return -EINVAL;
        len = dot - label;
        if (len > DNSFS_MAX_LABEL || *pos + len + 1 >= size)
            return -ENAMETOOLONG;
        buf[(*pos)++] = len;
        memcpy(buf + *pos, label, len);
        *pos += len;
        label = dot + 1;
    }
    if (*pos >= size)
        return -ENAMETOOLONG;
    buf[(*pos)++] = 0;
    return 0;
}

static int dnsfs_build_query(const char *fqdn,
                             u16 qtype,
                             u16 txid,
                             u8 *buf,
                             size_t size,
                             bool dnssec)
{
    size_t pos = 0;
    int ret;

    if (size < 12)
        return -ENAMETOOLONG;
    memset(buf, 0, 12);
    buf[0] = txid >> 8;
    buf[1] = txid;
    buf[2] = 0x01;
    buf[5] = 0x01;
    if (dnssec)
        buf[11] = 0x01;
    pos = 12;
    ret = dnsfs_wire_name(fqdn, buf, size, &pos);
    if (ret)
        return ret;
    if (pos + 4 > size)
        return -ENAMETOOLONG;
    buf[pos++] = qtype >> 8;
    buf[pos++] = qtype;
    buf[pos++] = 0;
    buf[pos++] = 1;
    if (dnssec) {
        if (pos + 11 > size)
            return -ENAMETOOLONG;
        buf[pos++] = 0;
        buf[pos++] = 0;
        buf[pos++] = 41;
        buf[pos++] = 0x10;
        buf[pos++] = 0;
        buf[pos++] = 0;
        buf[pos++] = 0;
        buf[pos++] = 0x80;
        buf[pos++] = 0;
        memset(buf + pos, 0, 2);
        pos += 2;
    }
    return pos;
}

static u32 dnsfs_negative_ttl(struct dns_msg *msg);

static int dnsfs_wire_name_text_at(const u8 *buf,
                                   size_t len,
                                   size_t *off,
                                   char *out,
                                   size_t out_len)
{
    size_t pos = 0;

    while (*off < len && buf[*off]) {
        u8 label = buf[(*off)++];

        if (label > DNSFS_MAX_LABEL || *off + label > len)
            return -EIO;
        if (pos + label + 2 > out_len)
            return -ENOSPC;
        memcpy(out + pos, buf + *off, label);
        pos += label;
        out[pos++] = '.';
        *off += label;
    }
    if (*off >= len)
        return -EIO;
    (*off)++;
    if (!pos) {
        if (out_len < 2)
            return -ENOSPC;
        out[pos++] = '.';
    }
    out[pos] = '\0';
    return 0;
}

static int dnsfs_wire_name_text(const u8 *buf,
                                size_t len,
                                char *out,
                                size_t out_len)
{
    size_t off = 0;
    int ret;

    ret = dnsfs_wire_name_text_at(buf, len, &off, out, out_len);
    if (ret)
        return ret;
    if (off != len)
        return -EIO;
    return 0;
}

static int dnsfs_base64_append(char *out,
                               size_t out_len,
                               int pos,
                               const u8 *buf,
                               size_t len)
{
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i;

    for (i = 0; i < len; i += 3) {
        u32 v = (u32) buf[i] << 16;
        size_t remain = len - i;

        if (remain > 1)
            v |= (u32) buf[i + 1] << 8;
        if (remain > 2)
            v |= buf[i + 2];
        if (pos + 4 >= out_len)
            return -ENOSPC;
        out[pos++] = table[(v >> 18) & 0x3f];
        out[pos++] = table[(v >> 12) & 0x3f];
        out[pos++] = remain > 1 ? table[(v >> 6) & 0x3f] : '=';
        out[pos++] = remain > 2 ? table[v & 0x3f] : '=';
    }

    return pos;
}

/* Append a formatted record line at *pos, advancing it.
 *
 * Returns -ENOSPC if the output buffer would overflow (vsnprintf reports the
 * untruncated length).
 */
__printf(4, 5) static int dnsfs_append(char *out,
                                       size_t out_len,
                                       size_t *pos,
                                       const char *fmt,
                                       ...)
{
    va_list args;
    int len;

    va_start(args, fmt);
    len = vsnprintf(out + *pos, out_len - *pos, fmt, args);
    va_end(args);
    if (len < 0 || (size_t) len >= out_len - *pos)
        return -ENOSPC;
    *pos += len;
    return 0;
}

/* Render the matching answers of a parsed response into record text, returning
 * the byte count or a negative errno. The leading guard is the anti-spoofing
 * gate: a reply whose txid, question name, type, or class does not match what
 * we asked is rejected as -EAGAIN so the caller keeps waiting for the real one
 * rather than trusting a forged or stale datagram. The rcode switch is the
 * fixed rcode-to-errno mapping (NXDOMAIN->ENOENT, SERVFAIL->EIO,
 * REFUSED->EACCES, FORMERR->EINVAL); other rcodes degrade to -EIO.
 */
static int dnsfs_render_txt(struct dns_msg *msg,
                            u16 txid,
                            const char *fqdn,
                            u16 qtype,
                            char *out,
                            size_t out_len,
                            u32 *ttl)
{
    size_t pos = 0;
    unsigned int i;
    u32 min_ttl = DNSFS_MAX_TTL_SEC;

    if (msg->id != txid || msg->qtype != qtype || msg->qclass != 1 ||
        strcasecmp(msg->qname, fqdn))
        return -EAGAIN;

    switch (msg->flags & 0x000f) {
    case 0:
        break;
    case 3:
        *ttl = dnsfs_negative_ttl(msg);
        return -ENOENT;
    case 2:
        return -EIO;
    case 5:
        return -EACCES;
    case 1:
        return -EINVAL;
    default:
        return -EIO;
    }

    for (i = 0; i < msg->answer_count; i++) {
        struct dns_rr *rr = &msg->answers[i];
        size_t off = 0;
        int ret = 0;

        if (rr->type != qtype || rr->class != 1 || strcasecmp(rr->name, fqdn))
            continue;
        if (rr->ttl < min_ttl)
            min_ttl = rr->ttl;
        switch (qtype) {
        case 1: /* A */
            if (rr->rdlength != 4)
                return -EIO;
            ret =
                dnsfs_append(out, out_len, &pos, "%u.%u.%u.%u\n", rr->rdata[0],
                             rr->rdata[1], rr->rdata[2], rr->rdata[3]);
            break;
        case 28: /* AAAA */
            if (rr->rdlength != 16)
                return -EIO;
            ret = dnsfs_append(out, out_len, &pos, "%pI6c\n", rr->rdata);
            break;
        case 15: { /* MX */
            char exchange[DNSFS_MAX_NAME + 1];

            if (rr->rdlength < 3)
                return -EIO;
            if (dnsfs_wire_name_text(rr->rdata + 2, rr->rdlength - 2, exchange,
                                     sizeof(exchange)))
                return -EIO;
            ret = dnsfs_append(out, out_len, &pos, "%u %s\n",
                               dnsfs_get16(rr->rdata), exchange);
            break;
        }
        case 2: { /* NS */
            char ns[DNSFS_MAX_NAME + 1];

            if (dnsfs_wire_name_text(rr->rdata, rr->rdlength, ns, sizeof(ns)))
                return -EIO;
            ret = dnsfs_append(out, out_len, &pos, "%s\n", ns);
            break;
        }
        case 5: { /* CNAME */
            char target[DNSFS_MAX_NAME + 1];

            if (dnsfs_wire_name_text(rr->rdata, rr->rdlength, target,
                                     sizeof(target)))
                return -EIO;
            ret = dnsfs_append(out, out_len, &pos, "%s\n", target);
            if (ret)
                return ret;
            *ttl = min_ttl;
            return pos;
        }
        case 6: { /* SOA */
            char mname[DNSFS_MAX_NAME + 1];
            char rname[DNSFS_MAX_NAME + 1];

            if (dnsfs_wire_name_text_at(rr->rdata, rr->rdlength, &off, mname,
                                        sizeof(mname)))
                return -EIO;
            if (dnsfs_wire_name_text_at(rr->rdata, rr->rdlength, &off, rname,
                                        sizeof(rname)))
                return -EIO;
            if (off + 20 != rr->rdlength)
                return -EIO;
            ret = dnsfs_append(out, out_len, &pos, "%s %s %u %u %u %u %u\n",
                               mname, rname, dnsfs_get32(rr->rdata + off),
                               dnsfs_get32(rr->rdata + off + 4),
                               dnsfs_get32(rr->rdata + off + 8),
                               dnsfs_get32(rr->rdata + off + 12),
                               dnsfs_get32(rr->rdata + off + 16));
            break;
        }
        case 43: /* DS */
            if (rr->rdlength < 5)
                return -EIO;
            ret = dnsfs_append(out, out_len, &pos, "%u %u %u ",
                               dnsfs_get16(rr->rdata), rr->rdata[2],
                               rr->rdata[3]);
            for (off = 4; !ret && off < rr->rdlength; off++)
                ret = dnsfs_append(out, out_len, &pos, "%02X", rr->rdata[off]);
            if (!ret)
                ret = dnsfs_append(out, out_len, &pos, "\n");
            break;
        case 48: { /* DNSKEY */
            int len;

            if (rr->rdlength < 5)
                return -EIO;
            ret = dnsfs_append(out, out_len, &pos, "%u %u %u ",
                               dnsfs_get16(rr->rdata), rr->rdata[2],
                               rr->rdata[3]);
            if (ret)
                return ret;
            len = dnsfs_base64_append(out, out_len, pos, rr->rdata + 4,
                                      rr->rdlength - 4);
            if (len < 0)
                return len;
            pos = len;
            ret = dnsfs_append(out, out_len, &pos, "\n");
            break;
        }
        case 16: /* TXT */
            while (off < rr->rdlength) {
                u8 segment = rr->rdata[off++];

                if (off + segment > rr->rdlength)
                    return -EIO;
                if (pos + segment + 1 >= out_len)
                    return -ENOSPC;
                memcpy(out + pos, rr->rdata + off, segment);
                pos += segment;
                off += segment;
            }
            ret = dnsfs_append(out, out_len, &pos, "\n");
            break;
        default:
            ret = dnsfs_append(out, out_len, &pos, "%u %s\n", qtype, fqdn);
            if (ret)
                return ret;
            *ttl = min_ttl;
            return pos;
        }
        if (ret)
            return ret;
    }

    if (!pos)
        return -ENOENT;
    *ttl = min_ttl;
    return pos;
}

static size_t dnsfs_skip_wire_name(const u8 *buf, size_t len, size_t off)
{
    while (off < len && buf[off]) {
        u8 label = buf[off++];

        if (label > DNSFS_MAX_LABEL || off + label > len)
            return len + 1;
        off += label;
    }

    return off < len ? off + 1 : len + 1;
}

static u32 dnsfs_negative_ttl(struct dns_msg *msg)
{
    unsigned int i;

    for (i = 0; i < msg->authority_count; i++) {
        struct dns_rr *rr = &msg->authorities[i];
        size_t off;
        u32 minimum;

        if (rr->type != 6 || rr->class != 1)
            continue;
        off = dnsfs_skip_wire_name(rr->rdata, rr->rdlength, 0);
        if (off > rr->rdlength)
            continue;
        off = dnsfs_skip_wire_name(rr->rdata, rr->rdlength, off);
        if (off + 20 > rr->rdlength)
            continue;
        minimum = dnsfs_get32(rr->rdata + off + 16);
        return min_t(u32, minimum, rr->ttl);
    }

    return 0;
}

static int dnsfs_parse_response(const u8 *reply,
                                size_t reply_len,
                                u16 txid,
                                const char *fqdn,
                                u16 qtype,
                                char *out,
                                size_t out_len,
                                u32 *ttl)
{
    struct dns_msg *parsed;
    int ret;

    parsed = kzalloc(sizeof(*parsed), GFP_KERNEL);
    if (!parsed)
        return -ENOMEM;

    ret = dnsfs_parse(reply, reply_len, parsed);
    if (!ret)
        ret = dnsfs_render_txt(parsed, txid, fqdn, qtype, out, out_len, ttl);
    else
        ret = -EIO;
    kfree(parsed);
    return ret;
}

static int dnsfs_query_tcp(struct dnsfs_config *cfg,
                           __be32 resolver,
                           const u8 *query,
                           size_t query_len,
                           u16 txid,
                           const char *fqdn,
                           u16 qtype,
                           char *out,
                           size_t out_len,
                           u32 *ttl)
{
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(cfg->port),
        .sin_addr.s_addr = resolver,
    };
    struct socket *sock;
    u8 *request;
    u8 *reply;
    struct kvec vec;
    struct msghdr msg = {};
    int ret;
    u16 reply_len;

    request = kmalloc(query_len + 2, GFP_KERNEL);
    reply = kmalloc(DNSFS_TCP_MAX_PACKET, GFP_KERNEL);
    if (!request || !reply) {
        ret = -ENOMEM;
        goto out_free;
    }

    ret = sock_create_kern(sock_net(cfg->sock->sk), AF_INET, SOCK_STREAM,
                           IPPROTO_TCP, &sock);
    if (ret)
        goto out_free;
    sock->sk->sk_rcvtimeo = msecs_to_jiffies(cfg->timeout_ms);
    sock->sk->sk_sndtimeo = msecs_to_jiffies(cfg->timeout_ms);

    ret = kernel_connect(sock, (struct sockaddr *) &addr, sizeof(addr), 0);
    if (ret)
        goto out_sock;

    request[0] = query_len >> 8;
    request[1] = query_len;
    memcpy(request + 2, query, query_len);
    /* TCP is a byte stream, so one kernel_sendmsg can send fewer bytes than the
     * whole framed query. Loop until all of it goes out, and treat a
     * zero-length send as a stuck connection rather than spinning.
     */
    {
        size_t total_sent = 0;
        size_t to_send = query_len + 2;

        while (total_sent < to_send) {
            struct msghdr send_msg = {.msg_name = NULL};

            vec.iov_base = request + total_sent;
            vec.iov_len = to_send - total_sent;
            ret = kernel_sendmsg(sock, &send_msg, &vec, 1, vec.iov_len);
            if (ret < 0)
                goto out_sock;
            if (ret == 0) {
                ret = -EIO;
                goto out_sock;
            }
            total_sent += ret;
        }
    }
    atomic64_inc(&dnsfs_wire_queries);

    vec.iov_base = reply;
    vec.iov_len = 2;
    ret = kernel_recvmsg(sock, &msg, &vec, 1, 2, MSG_WAITALL);
    if (ret != 2) {
        ret = ret < 0 ? ret : -EIO;
        goto out_sock;
    }
    reply_len = ((u16) reply[0] << 8) | reply[1];
    if (!reply_len || reply_len > DNSFS_TCP_MAX_PACKET) {
        ret = -EIO;
        goto out_sock;
    }
    vec.iov_base = reply;
    vec.iov_len = reply_len;
    ret = kernel_recvmsg(sock, &msg, &vec, 1, reply_len, MSG_WAITALL);
    if (ret != reply_len) {
        ret = ret < 0 ? ret : -EIO;
        goto out_sock;
    }
    ret = dnsfs_parse_response(reply, reply_len, txid, fqdn, qtype, out,
                               out_len, ttl);
    if (ret == -EAGAIN)
        ret = -EIO;

out_sock:
    sock_release(sock);
out_free:
    kfree(reply);
    kfree(request);
    return ret;
}

/* Send one UDP query and read the reply. txid is freshly randomized per call so
 * a forged response must guess it. Datagrams not from the exact resolver
 * address+port, and replies the renderer rejects as -EAGAIN (wrong txid/name),
 * are off-path spoof attempts: we re-read up to 'invalid' times rather than
 * abort, since a real answer may still be queued behind them, but cap the retry
 * so a flood degrades to -ETIMEDOUT instead of looping. A set TC bit means the
 * answer was truncated, so retry the same query over TCP.
 */
static int dnsfs_query_udp_once(struct dnsfs_config *cfg,
                                __be32 resolver,
                                const char *fqdn,
                                u16 qtype,
                                char *out,
                                size_t out_len,
                                u32 *ttl)
{
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(cfg->port),
        .sin_addr.s_addr = resolver,
    };
    struct sockaddr_in from = {};
    u8 *query;
    u8 *reply;
    int ret;
    int query_len;
    u16 txid = get_random_u16();
    unsigned int invalid = 0;

    query = kmalloc(DNSFS_MAX_PACKET, GFP_KERNEL);
    reply = kmalloc(DNSFS_MAX_PACKET, GFP_KERNEL);
    if (!query || !reply) {
        ret = -ENOMEM;
        goto out_free;
    }

    ret = dnsfs_build_query(fqdn, qtype, txid, query, DNSFS_MAX_PACKET,
                            cfg->dnssec);
    if (ret < 0)
        goto out_free;
    query_len = ret;

    for (;;) {
        struct msghdr recv_msg = {
            .msg_name = &from,
            .msg_namelen = sizeof(from),
        };
        struct kvec recv_vec = {.iov_base = reply, .iov_len = DNSFS_MAX_PACKET};

        struct msghdr send_msg = {
            .msg_name = &addr,
            .msg_namelen = sizeof(addr),
        };
        struct kvec send_vec = {.iov_base = query, .iov_len = query_len};
        ret = kernel_sendmsg(cfg->sock, &send_msg, &send_vec, 1,
                             send_vec.iov_len);
        if (ret < 0)
            break;
        /* A UDP datagram sends whole or not at all; a short count means the
         * query never left intact, so fail rather than wait for a reply to it.
         */
        if (ret != send_vec.iov_len) {
            ret = -EIO;
            break;
        }
        atomic64_inc(&dnsfs_wire_queries);
        ret = kernel_recvmsg(cfg->sock, &recv_msg, &recv_vec, 1,
                             DNSFS_MAX_PACKET, 0);
        if (ret == -EAGAIN) {
            ret = -ETIMEDOUT;
            break;
        }
        if (ret < 0)
            break;
        if (from.sin_addr.s_addr != resolver ||
            from.sin_port != htons(cfg->port)) {
            ret = ++invalid > 4 ? -ETIMEDOUT : -EAGAIN;
            if (ret == -EAGAIN)
                continue;
            break;
        }
        if (ret >= 4 && (reply[2] & 0x02)) {
            ret = dnsfs_query_tcp(cfg, resolver, query, send_vec.iov_len, txid,
                                  fqdn, qtype, out, out_len, ttl);
            break;
        }
        ret = dnsfs_parse_response(reply, ret, txid, fqdn, qtype, out, out_len,
                                   ttl);
        if (ret == -EAGAIN && ++invalid <= 4)
            continue;
        if (ret == -EAGAIN)
            ret = -ETIMEDOUT;
        break;
    }

out_free:
    kfree(reply);
    kfree(query);
    return ret;
}

/* Copy a live entry's payload (or its negative-cache errno) out to the caller.
 * Shared by every lookup path so the copy-out rules live in one place.
 */
static int dnsfs_cache_copy(const struct dnsfs_cache_entry *entry,
                            char *out,
                            size_t out_len)
{
    if (entry->err)
        return entry->err;
    if (entry->len > out_len)
        return -ENOSPC;
    memcpy(out, entry->text, entry->len);
    return entry->len;
}

/* Slow-path lookup, run under query_lock. Unlike the RCU reader this may mutate
 * the cache: it promotes hits on the LRU list, and reaps expired entries. With
 * allow_stale it serves an expired entry once and, if no refresh is already in
 * flight, claims it by setting refreshing so exactly one caller drives the
 * background wire refresh (see *need_refresh).
 *
 * Returns -EAGAIN when the caller must go to the wire (true miss, or a
 * non-refreshable expiry that was reaped). Each reap invalidates the page cache
 * so a following read re-fetches.
 */
static int dnsfs_cache_lookup(struct dnsfs_config *cfg,
                              const char *fqdn,
                              u16 qtype,
                              char *out,
                              size_t out_len,
                              struct address_space *mapping,
                              bool allow_stale,
                              bool *need_refresh)
{
    struct dnsfs_cache_entry *entry;
    struct dnsfs_cache_entry *tmp;
    struct dnsfs_cache_key key = {.qtype = qtype};

    strscpy(key.name, fqdn, sizeof(key.name));
    if (need_refresh)
        *need_refresh = false;

    entry = rhashtable_lookup_fast(&cfg->cache_ht, &key, dnsfs_cache_params);
    if (entry && time_before(jiffies, entry->expiry)) {
        list_move(&entry->list, &cfg->cache);
        return dnsfs_cache_copy(entry, out, out_len);
    }
    if (entry && allow_stale) {
        if (!entry->refreshing && need_refresh) {
            entry->refreshing = true;
            *need_refresh = true;
        }
        list_move(&entry->list, &cfg->cache);
        if (mapping)
            invalidate_mapping_pages(mapping, 0, -1);
        return dnsfs_cache_copy(entry, out, out_len);
    }
    if (entry) {
        dnsfs_cache_remove_entry(cfg, entry);
        if (mapping)
            invalidate_mapping_pages(mapping, 0, -1);
        return -EAGAIN;
    }

    /* Opportunistic sweep of OTHER expired entries. The caller's own entry was
     * already handled above; mapping belongs to that file, not to these, so do
     * not touch it here -- invalidating it once per reaped entry would
     * needlessly blow away the current file's page cache N times.
     */
    list_for_each_entry_safe (entry, tmp, &cfg->cache, list) {
        if (time_after_eq(jiffies, entry->expiry) && !entry->refreshing)
            dnsfs_cache_remove_entry(cfg, entry);
    }
    return -EAGAIN;
}

/* Lockless fast path: serve an unexpired hit from the RCU read side. It only
 * reads immutable fields (key, expiry, text/len/err are never mutated in place;
 * a changed answer is published as a fresh entry and the old one freed via
 * call_rcu), so no lock is needed and the common read takes zero contention.
 * Anything else - miss, expired, or absent - returns -EAGAIN to fall back to
 * the locked path. The jiffies expiry check tolerates a wrap-driven false miss.
 */
static int dnsfs_cache_lookup_rcu(struct dnsfs_config *cfg,
                                  const char *fqdn,
                                  u16 qtype,
                                  char *out,
                                  size_t out_len)
{
    struct dnsfs_cache_key key = {.qtype = qtype};
    struct dnsfs_cache_entry *entry;
    int ret = -EAGAIN;

    strscpy(key.name, fqdn, sizeof(key.name));
    rcu_read_lock();
    entry = rhashtable_lookup_fast(&cfg->cache_ht, &key, dnsfs_cache_params);
    if (entry && time_before(jiffies, entry->expiry))
        ret = dnsfs_cache_copy(entry, out, out_len);
    rcu_read_unlock();
    return ret;
}

static void dnsfs_cache_evict_tail(struct dnsfs_config *cfg)
{
    while (cfg->cache_entries > DNSFS_MAX_CACHE_ENTRIES) {
        struct dnsfs_cache_entry *entry;

        entry = list_last_entry(&cfg->cache, struct dnsfs_cache_entry, list);
        dnsfs_cache_remove_entry(cfg, entry);
    }
}

static struct dnsfs_cache_entry *dnsfs_cache_alloc_entry(const char *fqdn,
                                                         u16 qtype)
{
    struct dnsfs_cache_entry *entry;

    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return NULL;
    strscpy(entry->key.name, fqdn, sizeof(entry->key.name));
    entry->key.qtype = qtype;
    return entry;
}

/* Publish a freshly built entry, replacing any existing one for the same key
 * (an updated answer is a new object, never an in-place edit, so RCU readers of
 * the old one stay valid). On rhashtable insert failure the new entry is handed
 * straight to call_rcu so the caller can treat it as consumed. Caller holds
 * query_lock.
 */
static bool dnsfs_cache_insert_entry(struct dnsfs_config *cfg,
                                     struct dnsfs_cache_entry *entry)
{
    struct dnsfs_cache_entry *old;

    old =
        rhashtable_lookup_fast(&cfg->cache_ht, &entry->key, dnsfs_cache_params);
    if (old)
        dnsfs_cache_remove_entry(cfg, old);
    if (rhashtable_insert_fast(&cfg->cache_ht, &entry->node,
                               dnsfs_cache_params)) {
        call_rcu(&entry->rcu, dnsfs_cache_free_rcu);
        return false;
    }
    list_add(&entry->list, &cfg->cache);
    cfg->cache_entries++;
    return true;
}

/* Cache a positive answer. TTL is the entry's whole lifetime (expiry = now +
 * ttl), clamped to DNSFS_MAX_TTL_SEC; a zero TTL is explicitly not cacheable,
 * so the caller must treat a false return as "answer not stored" and resolve
 * again next time.
 *
 * Returns whether the entry was installed.
 */
static bool dnsfs_cache_store(struct dnsfs_config *cfg,
                              const char *fqdn,
                              u16 qtype,
                              const char *text,
                              size_t len,
                              u32 ttl)
{
    struct dnsfs_cache_entry *entry;
    unsigned long ttl_sec = min_t(u32, ttl, DNSFS_MAX_TTL_SEC);
    bool stored;

    if (!ttl_sec || len > DNSFS_RECORD_TEXT_MAX)
        return false;
    entry = dnsfs_cache_alloc_entry(fqdn, qtype);
    if (!entry)
        return false;
    memcpy(entry->text, text, len);
    entry->err = 0;
    entry->len = len;
    entry->refreshing = false;
    entry->expiry = jiffies + ttl_sec * HZ;
    entry->generation = atomic_long_inc_return(&cfg->cache_generation);
    stored = dnsfs_cache_insert_entry(cfg, entry);
    dnsfs_cache_evict_tail(cfg);
    return stored;
}

/* Negative cache: remember an NXDOMAIN as a stored errno so repeated lookups of
 * a missing name don't hit the wire each time. ttl is the SOA-derived negative
 * TTL (see dnsfs_negative_ttl); a zero TTL is not cached, same rule as the
 * positive path.
 */
static bool dnsfs_cache_store_error(struct dnsfs_config *cfg,
                                    const char *fqdn,
                                    u16 qtype,
                                    int err,
                                    u32 ttl)
{
    struct dnsfs_cache_entry *entry;
    unsigned long ttl_sec = min_t(u32, ttl, DNSFS_MAX_TTL_SEC);
    bool stored;

    if (!ttl_sec)
        return false;
    entry = dnsfs_cache_alloc_entry(fqdn, qtype);
    if (!entry)
        return false;
    entry->err = err;
    entry->len = 0;
    entry->refreshing = false;
    entry->expiry = jiffies + ttl_sec * HZ;
    entry->generation = atomic_long_inc_return(&cfg->cache_generation);
    stored = dnsfs_cache_insert_entry(cfg, entry);
    dnsfs_cache_evict_tail(cfg);
    return stored;
}

/* A refresh did not install a cacheable replacement. Drop any stale entry
 * rather than clear its refreshing flag and keep serving it: TTL is the
 * object's lifetime, so the next read must hit the wire again.
 */
static void dnsfs_cache_refresh_done(struct dnsfs_config *cfg,
                                     const char *fqdn,
                                     u16 qtype)
{
    struct dnsfs_cache_entry *entry;
    struct dnsfs_cache_key key = {.qtype = qtype};

    strscpy(key.name, fqdn, sizeof(key.name));
    entry = rhashtable_lookup_fast(&cfg->cache_ht, &key, dnsfs_cache_params);
    if (entry && entry->refreshing)
        dnsfs_cache_remove_entry(cfg, entry);
}

/* The blocking resolve: cache check, then the actual wire query and cache
 * store. Sleeps on sockets, so it only runs in process context - the kthread,
 * or (when no kthread exists) directly from the caller. query_lock guards every
 * cache access here. The wire I/O between them is normally lockless because
 * only the single kthread reaches it; hold_wire_lock is the no-kthread fallback
 * that must keep query_lock held across the socket call to serialize the shared
 * cfg->sock. force_wire skips the cache read to drive a refresh.
 */
static int dnsfs_query_record_sync(struct dnsfs_config *cfg,
                                   const char *fqdn,
                                   u16 qtype,
                                   char *out,
                                   size_t out_len,
                                   struct address_space *mapping,
                                   bool force_wire)
{
    unsigned int attempts = cfg->retries ? cfg->retries : 1;
    int ret = -ETIMEDOUT;
    unsigned int i;
    unsigned int resolver;
    u32 ttl = 0;
    bool hold_wire_lock = !cfg->query_thread;
    bool stored;

    mutex_lock(&cfg->query_lock);
    cfg->sock->sk->sk_rcvtimeo = msecs_to_jiffies(cfg->timeout_ms);
    cfg->sock->sk->sk_sndtimeo = msecs_to_jiffies(cfg->timeout_ms);

    if (!force_wire) {
        ret = dnsfs_cache_lookup(cfg, fqdn, qtype, out, out_len, mapping, false,
                                 NULL);
        if (ret != -EAGAIN) {
            /* Cache hit: return it as-is. It must not fall into the store block
             * below, whose ttl==0 no-op would otherwise let refresh_done evict
             * the entry we just served.
             */
            mutex_unlock(&cfg->query_lock);
            return ret;
        }
    }
    if (!hold_wire_lock)
        mutex_unlock(&cfg->query_lock);

    for (i = 0; i < attempts; i++) {
        for (resolver = 0; resolver < cfg->nameserver_count; resolver++) {
            ret = dnsfs_query_udp_once(cfg, cfg->nameservers[resolver], fqdn,
                                       qtype, out, out_len, &ttl);
            /* Stop on a definitive disposition: a hit, an authoritative
             * NXDOMAIN (-ENOENT), a resolver refusal (-EACCES) or malformed
             * query error (-EINVAL) that another resolver would only repeat, or
             * a local resource error (-ENOMEM, -ENOSPC) that failover cannot
             * fix. Only transient resolver failures (timeout, SERVFAIL or a
             * junk reply as -EIO, and socket unreachability) fall through to
             * the next nameserver.
             */
            if (ret > 0 || ret == -ENOENT || ret == -EACCES || ret == -EINVAL ||
                ret == -ENOMEM || ret == -ENOSPC)
                goto out_store;
        }
    }

out_store:
    if (!hold_wire_lock)
        mutex_lock(&cfg->query_lock);
    /* Only wire results reach here. If the answer installed no cache entry
     * (ttl==0, alloc failure, or a SERVFAIL/timeout with no answer), drop any
     * stale entry left behind by a refresh so it cannot be served forever with
     * a stuck refreshing flag.
     */
    if (ret > 0)
        stored = dnsfs_cache_store(cfg, fqdn, qtype, out, ret, ttl);
    else if (ret == -ENOENT)
        stored = dnsfs_cache_store_error(cfg, fqdn, qtype, ret, ttl);
    else
        stored = false;
    if (!stored)
        dnsfs_cache_refresh_done(cfg, fqdn, qtype);
    mutex_unlock(&cfg->query_lock);
    return ret;
}

/* The per-mount resolver thread: the sole owner of wire socket I/O, which is
 * what lets duplicate misses coalesce onto one query. It pops one request at a
 * time off query_queue (under query_queue_lock), resolves it in sleepable
 * process context, then unlinks it from query_pending and wakes every coalesced
 * waiter with complete_all(). req->refs counts the kthread plus each blocking
 * waiter; whoever drops the last reference frees it, so a request outlives
 * whichever side exits first. A refresh request carries an igrab'd inode and no
 * waiter: the thread invalidates its page cache and iputs it here.
 *
 * The second loop is shutdown drain: after kthread_should_stop, fail every
 * still-queued request -EIO so no waiter is left blocked on a completion that
 * would never fire.
 */
int dnsfs_query_thread(void *data)
{
    struct dnsfs_config *cfg = data;

    for (;;) {
        struct dnsfs_query_request *req = NULL;

        wait_event_interruptible(
            cfg->query_wait,
            kthread_should_stop() || !list_empty(&cfg->query_queue));
        spin_lock(&cfg->query_queue_lock);
        if (!list_empty(&cfg->query_queue)) {
            req = list_first_entry(&cfg->query_queue,
                                   struct dnsfs_query_request, queue);
            list_del_init(&req->queue);
        } else if (kthread_should_stop()) {
            spin_unlock(&cfg->query_queue_lock);
            break;
        }
        spin_unlock(&cfg->query_queue_lock);
        if (!req)
            continue;

        req->ret =
            dnsfs_query_record_sync(cfg, req->fqdn, req->qtype, req->text,
                                    sizeof(req->text), NULL, req->refresh);
        if (req->ret > 0)
            req->len = req->ret;
        if (req->refresh && req->inode) {
            invalidate_mapping_pages(req->inode->i_mapping, 0, -1);
            iput(req->inode);
            req->inode = NULL;
        }
        spin_lock(&cfg->query_queue_lock);
        list_del_init(&req->pending);
        spin_unlock(&cfg->query_queue_lock);
        complete_all(&req->done);
        if (refcount_dec_and_test(&req->refs))
            kfree(req);
    }

    for (;;) {
        struct dnsfs_query_request *req;

        spin_lock(&cfg->query_queue_lock);
        if (list_empty(&cfg->query_queue)) {
            spin_unlock(&cfg->query_queue_lock);
            break;
        }
        req = list_first_entry(&cfg->query_queue, struct dnsfs_query_request,
                               queue);
        list_del_init(&req->queue);
        list_del_init(&req->pending);
        spin_unlock(&cfg->query_queue_lock);
        req->ret = -EIO;
        if (req->inode)
            iput(req->inode);
        complete_all(&req->done);
        if (refcount_dec_and_test(&req->refs))
            kfree(req);
    }

    return 0;
}

/* Public entry point. Tries the lockless RCU cache, then the locked cache
 * (which may serve a stale value and flag a background refresh). On a real miss
 * it builds a request and, under query_queue_lock, scans query_pending for an
 * identical {fqdn, qtype} already in flight: if found, a blocking caller just
 * takes a reference and waits on that request's completion instead of issuing a
 * second wire query; a refresh that collides drops its request entirely. This
 * is where in-flight coalescing happens. A miss blocks for the answer; a
 * refresh is fire-and-forget and returns the stale value immediately. refs is 2
 * for a blocking request (kthread + this waiter) and 1 for a refresh (kthread
 * only); the last dec frees it.
 */
int dnsfs_query_record(struct dnsfs_config *cfg,
                       const char *fqdn,
                       u16 qtype,
                       char *out,
                       size_t out_len,
                       struct address_space *mapping)
{
    struct dnsfs_query_request *req;
    struct dnsfs_query_request *pending;
    bool need_refresh = false;
    bool refresh;
    int wait_ret;
    int ret;

    if (!cfg->query_thread)
        return dnsfs_query_record_sync(cfg, fqdn, qtype, out, out_len, mapping,
                                       false);

    ret = dnsfs_cache_lookup_rcu(cfg, fqdn, qtype, out, out_len);
    if (ret != -EAGAIN)
        return ret;

    mutex_lock(&cfg->query_lock);
    ret = dnsfs_cache_lookup(cfg, fqdn, qtype, out, out_len, mapping, true,
                             &need_refresh);
    mutex_unlock(&cfg->query_lock);
    if (ret != -EAGAIN && !need_refresh)
        return ret;

    /* A served-stale lookup wants a background refresh; a miss (-EAGAIN) blocks
     * for the wire result. refresh tells the two apart from here on: a refresh
     * fires the request fire-and-forget and returns the stale value in ret.
     */
    refresh = ret != -EAGAIN;

    req = kzalloc(sizeof(*req), GFP_KERNEL);
    if (!req) {
        if (!refresh)
            return -ENOMEM;
        mutex_lock(&cfg->query_lock);
        dnsfs_cache_refresh_done(cfg, fqdn, qtype);
        mutex_unlock(&cfg->query_lock);
        return ret;
    }
    INIT_LIST_HEAD(&req->queue);
    INIT_LIST_HEAD(&req->pending);
    init_completion(&req->done);
    refcount_set(&req->refs, refresh ? 1 : 2);
    strscpy(req->fqdn, fqdn, sizeof(req->fqdn));
    req->qtype = qtype;
    req->refresh = refresh;
    if (refresh && mapping)
        req->inode = igrab(mapping->host);

    spin_lock(&cfg->query_queue_lock);
    list_for_each_entry (pending, &cfg->query_pending, pending) {
        if (pending->qtype == qtype && !strcmp(pending->fqdn, fqdn)) {
            if (!refresh)
                refcount_inc(&pending->refs);
            spin_unlock(&cfg->query_queue_lock);
            if (req->inode)
                iput(req->inode);
            kfree(req);
            if (refresh)
                return ret;
            req = pending;
            goto wait;
        }
    }
    list_add_tail(&req->pending, &cfg->query_pending);
    list_add_tail(&req->queue, &cfg->query_queue);
    spin_unlock(&cfg->query_queue_lock);
    wake_up(&cfg->query_wait);
    if (refresh)
        return ret;

wait:
    /* A signal aborts the wait immediately instead of blocking out the whole
     * query. The shared request stays queued, so the worker still resolves it,
     * fills the cache, and wakes the other coalesced waiters; this caller just
     * drops its reference and returns -ERESTARTSYS. Whoever drops the last
     * reference frees the request, so leaving early is use-after-free safe. Do
     * not read req->ret or req->text on the signal path: the worker may still
     * be writing them, and only a completed request has them stable.
     */
    wait_ret = wait_for_completion_interruptible(&req->done);
    if (wait_ret) {
        ret = -ERESTARTSYS;
    } else {
        ret = req->ret;
        if (ret > 0) {
            if (req->len > out_len)
                ret = -ENOSPC;
            else
                memcpy(out, req->text, req->len);
        }
    }
    if (refcount_dec_and_test(&req->refs))
        kfree(req);
    return ret;
}

void dnsfs_cache_drop(struct dnsfs_config *cfg, const char *fqdn, u16 qtype)
{
    struct dnsfs_cache_entry *entry;
    struct dnsfs_cache_key key = {.qtype = qtype};

    strscpy(key.name, fqdn, sizeof(key.name));
    mutex_lock(&cfg->query_lock);
    entry = rhashtable_lookup_fast(&cfg->cache_ht, &key, dnsfs_cache_params);
    if (entry)
        dnsfs_cache_remove_entry(cfg, entry);
    mutex_unlock(&cfg->query_lock);
}

unsigned long dnsfs_cache_generation(struct dnsfs_config *cfg,
                                     const char *fqdn,
                                     u16 qtype)
{
    struct dnsfs_cache_key key = {.qtype = qtype};
    struct dnsfs_cache_entry *entry;
    unsigned long gen = 0;

    strscpy(key.name, fqdn, sizeof(key.name));
    rcu_read_lock();
    entry = rhashtable_lookup_fast(&cfg->cache_ht, &key, dnsfs_cache_params);
    /* 0 is reserved to mean absent or expired. Non-zero values are assigned
     * when a cache entry is stored, so a caller can tell "still the same cached
     * answer I read" from "the cache changed under me".
     */
    if (entry && time_before(jiffies, entry->expiry))
        gen = entry->generation;
    rcu_read_unlock();
    return gen;
}

void dnsfs_cache_drop_storage(struct dnsfs_config *cfg,
                              const char *parent,
                              const char *label,
                              size_t label_len)
{
    struct dnsfs_cache_entry *entry;
    struct dnsfs_cache_entry *tmp;
    char meta[DNSFS_MAX_NAME + 1];
    char index[DNSFS_MAX_NAME + 1];
    size_t parent_len = strlen(parent);
    int meta_len;
    int index_len;

    meta_len =
        snprintf(meta, sizeof(meta), "%.*s.%s", (int) label_len, label, parent);
    index_len =
        snprintf(index, sizeof(index), "%s.%s", DNSFS_STORAGE_INDEX, parent);
    if (meta_len < 0 || (size_t) meta_len >= sizeof(meta) || index_len < 0 ||
        (size_t) index_len >= sizeof(index))
        return;

    mutex_lock(&cfg->query_lock);
    list_for_each_entry_safe (entry, tmp, &cfg->cache, list) {
        size_t name_len = strlen(entry->key.name);
        bool drop = false;

        if (entry->key.qtype != 16) /* storage records are all TXT */
            continue;
        if (!strcmp(entry->key.name, meta) || !strcmp(entry->key.name, index)) {
            drop = true;
        } else if (name_len > parent_len + 1 &&
                   entry->key.name[name_len - parent_len - 1] == '.' &&
                   !memcmp(entry->key.name + name_len - parent_len, parent,
                           parent_len)) {
            /* {epoch}-{offset}-{name}.{parent}: parse and match the exact file
             * name so "foo" does not also drop chunks of "bar-foo".
             */
            struct dnsfs_chunk_name cn;
            size_t label_part = name_len - parent_len - 1;

            if (!dnsfs_parse_chunk_name(entry->key.name, label_part, &cn) &&
                cn.name_len == label_len && !memcmp(cn.name, label, label_len))
                drop = true;
        }
        if (!drop)
            continue;
        dnsfs_cache_remove_entry(cfg, entry);
    }
    mutex_unlock(&cfg->query_lock);
}

static char *dnsfs_hex_payload(const u8 *data, size_t data_len)
{
    static const char hex[] = "0123456789abcdef";
    char *out;
    size_t i;

    /* data_len == 0 falls through: kmalloc(1) holds just the terminator. */
    out = kmalloc(data_len * 2 + 1, GFP_KERNEL);
    if (!out)
        return NULL;
    for (i = 0; i < data_len; i++) {
        out[i * 2] = hex[data[i] >> 4];
        out[i * 2 + 1] = hex[data[i] & 0xf];
    }
    out[data_len * 2] = '\0';
    return out;
}

/* Run the configured userspace publisher to commit a write. call_usermodehelper
 * with UMH_WAIT_PROC spawns it as root in the initial namespace and blocks for
 * exit, so this may only be called from sleepable process context. The payload
 * is hex-encoded into argv (binary-safe across the exec boundary). This routine
 * does NOT authorize the write: the security gate (init_user_ns + CAP_SYS_ADMIN
 * + an explicit publisher= mount option) is enforced in main.c before any
 * commit reaches here.
 *
 * Note: the hex payload rides in argv, so the file's bytes are visible in the
 * helper's /proc/<pid>/cmdline while it runs (only to the writer, who owns the
 * data) and the size is bounded by DNSFS_MAX_STORAGE_SIZE. If writes ever carry
 * secrets or grow past argv limits, hand the payload over stdin or a private
 * tmpfile instead.
 */
static int dnsfs_commit_publisher(struct dnsfs_config *cfg,
                                  const char *op,
                                  const char *label,
                                  size_t label_len,
                                  const u8 *data,
                                  size_t data_len)
{
    static char *envp[] = {
        "HOME=/",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
        NULL,
    };
    char *argv[5] = {};
    char *label_arg;
    char *hex_arg = NULL;
    int ret;

    label_arg = kmemdup_nul(label, label_len, GFP_KERNEL);
    if (!label_arg)
        return -ENOMEM;
    if (!strcmp(op, "put")) {
        hex_arg = dnsfs_hex_payload(data, data_len);
        if (!hex_arg) {
            kfree(label_arg);
            return -ENOMEM;
        }
    }
    argv[0] = cfg->publisher;
    argv[1] = (char *) op;
    argv[2] = label_arg;
    argv[3] = hex_arg;
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    kfree(hex_arg);
    kfree(label_arg);
    /* ret <= 0: helper could not run (e.g. -ENOENT, -EACCES) or it ran and
     * succeeded; pass it through. ret > 0: publisher ran but exited non-zero ->
     * generic write failure.
     */
    if (ret <= 0)
        return ret;
    return -EIO;
}

int dnsfs_commit_put(struct dnsfs_config *cfg,
                     const char *label,
                     size_t label_len,
                     const u8 *data,
                     size_t data_len)
{
    if (!cfg->writable || !cfg->sock || !cfg->publisher ||
        data_len > DNSFS_MAX_STORAGE_SIZE)
        return -EACCES;
    return dnsfs_commit_publisher(cfg, "put", label, label_len, data, data_len);
}

int dnsfs_commit_del(struct dnsfs_config *cfg, const char *label, size_t len)
{
    if (!cfg->writable || !cfg->sock || !cfg->publisher)
        return -EACCES;
    return dnsfs_commit_publisher(cfg, "del", label, len, NULL, 0);
}

/* Shrinker count/free callbacks run in reclaim context, so they never resolve,
 * allocate, or block: they mutex_trylock and bail to 0 on contention rather
 * than wait, and free only frees existing entries (LRU tail first).
 */
long dnsfs_nr_cached_objects(struct super_block *sb, struct shrink_control *sc)
{
    struct dnsfs_config *cfg = sb->s_fs_info;
    long count;

    if (!cfg || !mutex_trylock(&cfg->query_lock))
        return 0;
    count = cfg->cache_entries;
    mutex_unlock(&cfg->query_lock);
    return count;
}

long dnsfs_free_cached_objects(struct super_block *sb,
                               struct shrink_control *sc)
{
    struct dnsfs_config *cfg = sb->s_fs_info;
    long freed = 0;

    if (!cfg || !mutex_trylock(&cfg->query_lock))
        return 0;
    while (cfg->cache_entries && freed < sc->nr_to_scan) {
        struct dnsfs_cache_entry *entry;

        entry = list_last_entry(&cfg->cache, struct dnsfs_cache_entry, list);
        dnsfs_cache_remove_entry(cfg, entry);
        freed++;
    }
    mutex_unlock(&cfg->query_lock);
    return freed;
}
