/* SPDX-License-Identifier: GPL-2.0-only */

/* DNS wire + storage-encoding parser: the dnsfs trust boundary.
 *
 * Everything in this translation unit decodes UNTRUSTED bytes -- raw DNS
 * responses off the wire and the storage encoding layered on top (base36 chunk
 * names, file metadata, base64 + CRC32c chunk payloads, reassembly, index TXT).
 * It is pure and allocation-free, holds no kernel state, and compiles in
 * userspace via the parser.h __KERNEL__ shim, so the exact same code is fuzzed
 * under ASan/UBSan for millions of iterations before the socket layer is ever
 * allowed to feed it. Any change here is a change to the security gate: re-fuzz
 * before trusting it.
 *
 * The CRC32c used below is integrity only. It catches transport or cache
 * corruption, not a spoofed or cache-poisoned answer, which can forge a
 * matching checksum; EOF likewise comes from metadata chunk_count, never from
 * an NXDOMAIN that loss or poisoning can fake. Tamper resistance needs DNSSEC,
 * which lives above this layer.
 */

#ifdef __KERNEL__
#include <linux/crc32c.h>
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <stddef.h>
#include <string.h>
#endif

#include "parser.h"

/* Fixed DNS header: id, flags, and the four section counts (6 x u16). */
#define DNSFS_DNS_HDR_LEN 12
/* A length octet with both top bits set (0xc0) is a compression pointer. */
#define DNSFS_PTR_MASK 0xc0
#define DNSFS_PTR_TAG 0xc0
/* Cap compression-pointer jumps to bound work on a hostile packet. */
#define DNSFS_MAX_HOPS 16
/* Additional-section RRs are skipped, not stored; bound how many. */
#define DNSFS_MAX_SKIP_RR 32
/* RR types whose rdata embeds a domain name: NS (2) and CNAME (5). */
#define DNSFS_NAME_RDATA_TYPES(X) \
    X(2)                          \
    X(5)

static int dnsfs_decode_name(const u8 *buf,
                             size_t len,
                             size_t off,
                             char *out,
                             size_t out_len,
                             size_t *next)
{
    size_t pos = 0;
    size_t start = off;
    unsigned int hops = 0;
    int jumped = 0;

    for (;;) {
        u8 label;

        if (off >= len)
            return -EINVAL;

        label = buf[off++];
        if ((label & DNSFS_PTR_MASK) == DNSFS_PTR_TAG) {
            size_t ptr;

            if (off >= len)
                return -EINVAL;
            ptr = ((size_t) (label & 0x3f) << 8) | buf[off++];
            /* A pointer must target strictly before where this name began (ptr
             * < start), rejecting a self/forward jump into the name being
             * parsed. start stays fixed at the original offset, so this alone
             * still permits a chain bouncing among earlier offsets -- the hop
             * cap is what bounds the work and makes compression loops
             * impossible.
             */
            if (ptr >= start || ++hops > DNSFS_MAX_HOPS)
                return -EINVAL;
            /* The bytes the caller consumed end at the first pointer: record
             * that resume offset once, then chase the chain.
             */
            if (!jumped && next)
                *next = off;
            off = ptr;
            jumped = 1;
            continue;
        }
        /* 0x40 and 0x80 are reserved label types we never accept. */
        if (label & DNSFS_PTR_MASK)
            return -EINVAL;
        if (!label)
            break;
        /* Label must fit in 6 bits and stay inside the buffer. */
        if (label > 63 || off + label > len)
            return -EINVAL;
        /* Need room for the label, its '.' separator, and a final NUL. */
        if (pos + label + 2 > out_len)
            return -ENAMETOOLONG;
        memcpy(out + pos, buf + off, label);
        pos += label;
        out[pos++] = '.';
        off += label;
    }

    if (!jumped && next)
        *next = off;
    /* Total assembled name (with dots) must stay within the DNS limit. */
    if (pos > DNSFS_MAX_NAME)
        return -ENAMETOOLONG;
    /* An empty name is the DNS root; present it as ".". */
    if (!pos) {
        if (out_len < 2)
            return -ENAMETOOLONG;
        out[0] = '.';
        out[1] = '\0';
        return 0;
    }
    out[pos] = '\0';
    return 0;
}

/* Re-emit a dotted name back into uncompressed wire labels. Decoding then
 * re-encoding (see dnsfs_expand_rdata_name) strips compression pointers so
 * stored rdata is self-contained and keeps no dangling offsets into a packet we
 * no longer retain.
 */
static int dnsfs_encode_name(const char *name,
                             u8 *out,
                             size_t out_len,
                             size_t *written)
{
    size_t pos = 0;
    const char *label = name;

    if (!name || !out || !written)
        return -EINVAL;
    if (!strcmp(name, ".")) {
        if (!out_len)
            return -ENAMETOOLONG;
        out[0] = 0;
        *written = 1;
        return 0;
    }

    while (*label) {
        const char *dot = strchr(label, '.');
        size_t label_len;

        if (!dot)
            return -EINVAL;
        label_len = dot - label;
        if (!label_len || label_len > DNSFS_MAX_LABEL)
            return -EINVAL;
        /* One length byte precedes each label's bytes. */
        if (pos + label_len + 1 > out_len)
            return -ENAMETOOLONG;
        out[pos++] = label_len;
        memcpy(out + pos, label, label_len);
        pos += label_len;
        label = dot + 1;
    }

    /* The zero-length root label terminates the encoded name. */
    if (pos >= out_len)
        return -ENAMETOOLONG;
    out[pos++] = 0;
    *written = pos;
    return 0;
}

static int dnsfs_expand_rdata_name(const u8 *buf,
                                   size_t len,
                                   size_t off,
                                   u8 *out,
                                   size_t out_len,
                                   size_t *next,
                                   size_t *written)
{
    char name[DNSFS_MAX_NAME + 1];
    int ret;

    ret = dnsfs_decode_name(buf, len, off, name, sizeof(name), next);
    if (ret)
        return ret;
    return dnsfs_encode_name(name, out, out_len, written);
}

/* TXT rdata is a run of length-prefixed strings. Verify every segment stays
 * within len so later readers can walk it without overrunning.
 */
static int dnsfs_validate_txt(const u8 *rdata, size_t len)
{
    size_t off = 0;

    while (off < len) {
        u8 segment = rdata[off++];

        if (off + segment > len)
            return -EINVAL;
        off += segment;
    }

    return 0;
}

/* Rewrite rr->rdata in place for record types whose rdata embeds a domain name,
 * expanding any compression pointers into a self-contained copy. The "next must
 * equal rdata_off + rdlength" checks guarantee the embedded name(s) consumed
 * exactly the rdata -- no trailing slack and no overshoot past the declared
 * rdlength.
 * Returns 1 when rdata was rewritten, 0 to keep it verbatim.
 */
static int dnsfs_expand_name_rdata(const u8 *buf,
                                   size_t len,
                                   size_t rdata_off,
                                   struct dns_rr *rr)
{
    u8 expanded[DNSFS_MAX_RDATA];
    size_t expanded_len = 0;
    size_t name_len;
    size_t next;
    int ret;

    switch (rr->type) {
#define DNSFS_NAME_RDATA_CASE(type) case type:
        DNSFS_NAME_RDATA_TYPES(DNSFS_NAME_RDATA_CASE)
#undef DNSFS_NAME_RDATA_CASE
        ret = dnsfs_expand_rdata_name(buf, len, rdata_off, expanded,
                                      sizeof(expanded), &next, &expanded_len);
        if (ret)
            return ret;
        if (next != rdata_off + rr->rdlength)
            return -EINVAL;
        break;
    /* MX: a 2-byte preference precedes the exchange domain name. */
    case 15:
        if (rr->rdlength < 3)
            return -EINVAL;
        memcpy(expanded, buf + rdata_off, 2);
        ret = dnsfs_expand_rdata_name(buf, len, rdata_off + 2, expanded + 2,
                                      sizeof(expanded) - 2, &next, &name_len);
        if (ret)
            return ret;
        if (next != rdata_off + rr->rdlength)
            return -EINVAL;
        expanded_len = 2 + name_len;
        break;
    /* SOA: mname + rname, then 20 fixed bytes (serial, refresh, retry, expire,
     * minimum). Expand both names and copy the trailing block.
     */
    case 6:
        ret = dnsfs_expand_rdata_name(buf, len, rdata_off, expanded,
                                      sizeof(expanded), &next, &name_len);
        if (ret)
            return ret;
        expanded_len = name_len;
        ret = dnsfs_expand_rdata_name(buf, len, next, expanded + expanded_len,
                                      sizeof(expanded) - expanded_len, &next,
                                      &name_len);
        if (ret)
            return ret;
        expanded_len += name_len;
        if (next + 20 != rdata_off + rr->rdlength ||
            expanded_len + 20 > sizeof(expanded))
            return -EINVAL;
        memcpy(expanded + expanded_len, buf + next, 20);
        expanded_len += 20;
        break;
    default:
        /* Other types carry opaque rdata; leave it untouched. */
        return 0;
    }

    memcpy(rr->rdata, expanded, expanded_len);
    rr->rdlength = expanded_len;
    return 1;
}

static int dnsfs_read_rr(const u8 *buf,
                         size_t len,
                         size_t *off,
                         struct dns_rr *rr)
{
    size_t rdata_off;
    u16 wire_rdlength;
    int ret;

    ret = dnsfs_decode_name(buf, len, *off, rr->name, sizeof(rr->name), off);
    if (ret)
        return ret;
    /* Fixed RR header after the name: type+class+ttl+rdlength = 10. */
    if (*off + 10 > len)
        return -EINVAL;
    rr->type = dnsfs_get16(buf + *off);
    rr->class = dnsfs_get16(buf + *off + 2);
    rr->ttl = dnsfs_get32(buf + *off + 4);
    rr->rdlength = dnsfs_get16(buf + *off + 8);
    /* Keep the on-wire rdlength: name expansion below may rewrite rr->rdlength,
     * but *off must still advance by the original count.
     */
    wire_rdlength = rr->rdlength;
    *off += 10;
    /* Bound rdata both to our buffer and to the rdata[] field size. */
    if (wire_rdlength > DNSFS_MAX_RDATA || *off + wire_rdlength > len)
        return -EINVAL;
    rdata_off = *off;
    if (rr->type == 16 && dnsfs_validate_txt(buf + *off, wire_rdlength))
        return -EINVAL;
    ret = dnsfs_expand_name_rdata(buf, len, rdata_off, rr);
    if (ret < 0)
        return ret;
    if (!ret) {
        memcpy(rr->rdata, buf + *off, wire_rdlength);
        rr->rdlength = wire_rdlength;
    }
    *off += wire_rdlength;
    return 0;
}

static int dnsfs_skip_rr(const u8 *buf, size_t len, size_t *off)
{
    struct dns_rr rr;

    return dnsfs_read_rr(buf, len, off, &rr);
}

static int dnsfs_parse_rrs(const u8 *buf,
                           size_t len,
                           size_t *off,
                           u16 count,
                           struct dns_rr *rrs,
                           unsigned int *out_count)
{
    unsigned int i;

    for (i = 0; i < count; i++) {
        int ret = dnsfs_read_rr(buf, len, off, &rrs[i]);

        if (ret)
            return ret;
        (*out_count)++;
    }

    return 0;
}

int dnsfs_parse(const u8 *buf, size_t len, struct dns_msg *out)
{
    size_t off = DNSFS_DNS_HDR_LEN;
    u32 skip_count;
    unsigned int i;

    if (!buf || !out || len < DNSFS_DNS_HDR_LEN)
        return -EINVAL;

    memset(out, 0, sizeof(*out));
    out->id = dnsfs_get16(buf);
    out->flags = dnsfs_get16(buf + 2);
    out->qdcount = dnsfs_get16(buf + 4);
    out->ancount = dnsfs_get16(buf + 6);
    out->nscount = dnsfs_get16(buf + 8);
    out->arcount = dnsfs_get16(buf + 10);

    /* We always send exactly one question, so anything else is bogus. Answer
     * and authority counts must fit the fixed RR arrays.
     */
    if (out->qdcount != 1 || out->ancount > DNSFS_MAX_RR ||
        out->nscount > DNSFS_MAX_RR)
        return -EINVAL;
    /* Additional RRs are walked only to confirm framing, then dropped. */
    skip_count = out->arcount;
    if (skip_count > DNSFS_MAX_SKIP_RR)
        return -EINVAL;

    if (dnsfs_decode_name(buf, len, off, out->qname, sizeof(out->qname), &off))
        return -EINVAL;
    if (off + 4 > len)
        return -EINVAL;
    out->qtype = dnsfs_get16(buf + off);
    out->qclass = dnsfs_get16(buf + off + 2);
    off += 4;

    if (dnsfs_parse_rrs(buf, len, &off, out->ancount, out->answers,
                        &out->answer_count))
        return -EINVAL;
    if (dnsfs_parse_rrs(buf, len, &off, out->nscount, out->authorities,
                        &out->authority_count))
        return -EINVAL;
    for (i = 0; i < skip_count; i++) {
        int ret = dnsfs_skip_rr(buf, len, &off);

        if (ret)
            return ret;
    }

    /* Strict: question + RRs must consume the whole datagram exactly. */
    return off == len ? 0 : -EINVAL;
}

int dnsfs_base36_u64(const char *s, size_t len, u64 *out)
{
    u64 v = 0;
    size_t i;

    /* 13 base36 digits is the most a u64 can hold; longer is rejected cheaply
     * here, and the per-digit guard below catches the values in the 13-digit
     * range that would still overflow.
     */
    if (!s || !out || !len || len > 13)
        return -EINVAL;

    for (i = 0; i < len; i++) {
        u8 digit;

        if (s[i] >= '0' && s[i] <= '9')
            digit = s[i] - '0';
        else if (s[i] >= 'a' && s[i] <= 'z')
            digit = s[i] - 'a' + 10;
        else
            return -EINVAL;
        /* Reject before v*36 + digit could wrap past U64_MAX. */
        if (v > (~(u64) 0 - digit) / 36)
            return -EOVERFLOW;
        v = v * 36 + digit;
    }

    *out = v;
    return 0;
}

/* Split "{epoch}-{base36 offset}-{name}" in place. Rejects an empty epoch
 * (first == s), empty offset (second == first + 1), and empty name (second + 1
 * == s + len). The decoded offset must be chunk-aligned so it maps to a chunk
 * boundary.
 */
int dnsfs_parse_chunk_name(const char *s,
                           size_t len,
                           struct dnsfs_chunk_name *out)
{
    const char *first;
    const char *second;
    u64 offset;
    int ret;

    if (!s || !out || !len || len > 63)
        return -EINVAL;

    first = memchr(s, '-', len);
    if (!first || first == s)
        return -EINVAL;
    second = memchr(first + 1, '-', len - (first + 1 - s));
    if (!second || second == first + 1 || second + 1 == s + len)
        return -EINVAL;

    ret = dnsfs_base36_u64(first + 1, second - first - 1, &offset);
    if (ret)
        return ret;
    if (offset % DNSFS_CHUNK_SIZE)
        return -EINVAL;

    out->epoch = s;
    out->epoch_len = first - s;
    out->offset = offset;
    out->name = second + 1;
    out->name_len = s + len - out->name;
    return 0;
}

/* Emit base36 least-significant digit first, then reverse; tmp[13] holds the
 * longest u64.
 */
static size_t dnsfs_base36_write(u64 value, char *out)
{
    static const char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    char tmp[13];
    size_t len = 0;
    size_t i;

    do {
        tmp[len++] = digits[value % 36];
        value /= 36;
    } while (value);

    for (i = 0; i < len; i++)
        out[i] = tmp[len - i - 1];
    return len;
}

int dnsfs_build_chunk_label(const struct dnsfs_file_meta *meta,
                            const char *name,
                            size_t name_len,
                            u64 offset,
                            char *out,
                            size_t out_len)
{
    char off[13];
    size_t off_len;
    size_t need;

    if (!meta || !name || !out || !name_len || name_len > DNSFS_MAX_LABEL)
        return -EINVAL;
    if (meta->epoch_len == 0 || meta->epoch_len > DNSFS_MAX_LABEL)
        return -EINVAL;
    if (offset % DNSFS_CHUNK_SIZE)
        return -EINVAL;
    /* Offset must address a chunk that exists for this file. */
    if (offset / DNSFS_CHUNK_SIZE >= meta->chunk_count)
        return -EIO;
    off_len = dnsfs_base36_write(offset, off);
    need = meta->epoch_len + 1 + off_len + 1 + name_len;
    /* The whole "epoch-offset-name" must be one valid DNS label. */
    if (need > DNSFS_MAX_LABEL)
        return -ENAMETOOLONG;
    if (need + 1 > out_len)
        return -ENOSPC;

    memcpy(out, meta->epoch, meta->epoch_len);
    out[meta->epoch_len] = '-';
    memcpy(out + meta->epoch_len + 1, off, off_len);
    out[meta->epoch_len + 1 + off_len] = '-';
    memcpy(out + meta->epoch_len + off_len + 2, name, name_len);
    out[need] = '\0';
    return need;
}

static int dnsfs_parse_dec_u64(const char *s, size_t len, u64 *out)
{
    u64 v = 0;
    size_t i;

    if (!s || !out || !len)
        return -EINVAL;

    for (i = 0; i < len; i++) {
        u8 digit;

        if (s[i] < '0' || s[i] > '9')
            return -EINVAL;
        digit = s[i] - '0';
        /* Stop before v*10 + digit would exceed U64_MAX. */
        if (v > (~(u64) 0 - digit) / 10)
            return -EOVERFLOW;
        v = v * 10 + digit;
    }

    *out = v;
    return 0;
}

static int dnsfs_parse_dec_u32(const char *s, size_t len, u32 *out)
{
    u64 v;
    int ret;

    ret = dnsfs_parse_dec_u64(s, len, &v);
    if (ret)
        return ret;
    if (v > ~(u32) 0)
        return -EOVERFLOW;
    *out = v;
    return 0;
}

static int dnsfs_parse_oct_u32(const char *s, size_t len, u32 *out)
{
    u32 v = 0;
    size_t i;

    if (!s || !out || !len)
        return -EINVAL;

    for (i = 0; i < len; i++) {
        u8 digit;

        if (s[i] < '0' || s[i] > '7')
            return -EINVAL;
        digit = s[i] - '0';
        /* Stop before v*8 + digit would exceed U32_MAX. */
        if (v > (~(u32) 0 - digit) / 8)
            return -EOVERFLOW;
        v = v * 8 + digit;
    }

    *out = v;
    return 0;
}

static int dnsfs_hex_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -EINVAL;
}

int dnsfs_parse_hex32(const char *s, size_t len, u32 *out)
{
    u32 v = 0;
    size_t i;

    /* A u32 CRC field is exactly 8 hex digits -- no more, no less. */
    if (!s || !out || len != 8)
        return -EINVAL;

    for (i = 0; i < len; i++) {
        int digit = dnsfs_hex_value(s[i]);

        if (digit < 0)
            return digit;
        v = (v << 4) | digit;
    }

    *out = v;
    return 0;
}

/* Pull the next space-delimited field out of a metadata TXT string. */
static int dnsfs_next_field(const char *s,
                            size_t len,
                            size_t *pos,
                            const char **field,
                            size_t *field_len)
{
    size_t start = *pos;

    if (start >= len)
        return -EINVAL;
    while (*pos < len && s[*pos] != ' ')
        (*pos)++;
    if (*pos == start)
        return -EINVAL;
    *field = s + start;
    *field_len = *pos - start;
    if (*pos < len)
        (*pos)++;
    return 0;
}

/* Storage names reuse DNS label rules: lowercase letters, digits, and '-', no
 * leading or trailing '-', within the 63-octet label limit. This keeps an
 * attacker from smuggling '.', '/', or NUL into a path component once these
 * names become directory entries.
 */
static int dnsfs_validate_storage_label(const char *s, size_t len)
{
    size_t i;

    if (!s || !len || len > DNSFS_MAX_LABEL)
        return -EINVAL;
    if (s[0] == '-' || s[len - 1] == '-')
        return -EINVAL;

    for (i = 0; i < len; i++) {
        char c = s[i];

        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')
            continue;
        return -EINVAL;
    }

    return 0;
}

/* Decode "size mode(octal) mtime chunk_count epoch crc32c(hex8)" in field
 * order. Fields alias the source buffer; the last field must end exactly at the
 * input end so no trailing tokens slip through.
 */
int dnsfs_parse_file_meta(const char *s,
                          size_t len,
                          struct dnsfs_file_meta *out)
{
    const char *field;
    size_t field_len;
    size_t pos = 0;
    u64 expected_chunks;
    int ret;

    if (!s || !out || !len || len > DNSFS_MAX_TXT)
        return -EINVAL;

    ret = dnsfs_next_field(s, len, &pos, &field, &field_len);
    if (ret)
        return ret;
    ret = dnsfs_parse_dec_u64(field, field_len, &out->size);
    if (ret)
        return ret;

    ret = dnsfs_next_field(s, len, &pos, &field, &field_len);
    if (ret)
        return ret;
    ret = dnsfs_parse_oct_u32(field, field_len, &out->mode);
    if (ret)
        return ret;

    ret = dnsfs_next_field(s, len, &pos, &field, &field_len);
    if (ret)
        return ret;
    ret = dnsfs_parse_dec_u64(field, field_len, &out->mtime);
    if (ret)
        return ret;

    ret = dnsfs_next_field(s, len, &pos, &field, &field_len);
    if (ret)
        return ret;
    ret = dnsfs_parse_dec_u32(field, field_len, &out->chunk_count);
    if (ret)
        return ret;
    /* Recompute the chunk count from size and reject metadata that disagrees,
     * so a malformed line cannot promise more or fewer chunks than its declared
     * size implies.
     */
    expected_chunks = out->size / DNSFS_CHUNK_SIZE;
    if (out->size % DNSFS_CHUNK_SIZE)
        expected_chunks++;
    if (expected_chunks > ~(u32) 0)
        return -EOVERFLOW;
    if (out->chunk_count != expected_chunks)
        return -EINVAL;

    ret = dnsfs_next_field(s, len, &pos, &field, &field_len);
    if (ret)
        return ret;
    ret = dnsfs_validate_storage_label(field, field_len);
    if (ret)
        return ret;
    out->epoch = field;
    out->epoch_len = field_len;

    ret = dnsfs_next_field(s, len, &pos, &field, &field_len);
    if (ret)
        return ret;
    if (field + field_len != s + len)
        return -EINVAL;
    return dnsfs_parse_hex32(field, field_len, &out->file_crc);
}

int dnsfs_chunk_expected_len(const struct dnsfs_file_meta *meta,
                             const struct dnsfs_chunk_name *chunk,
                             size_t *expected_len)
{
    u64 remaining;

    if (!meta || !chunk || !expected_len)
        return -EINVAL;
    /* The chunk's epoch must match the file's: it ties this chunk to one
     * storage generation, so a leftover chunk from an earlier write can never
     * be reassembled into the current file.
     */
    if (chunk->epoch_len != meta->epoch_len ||
        memcmp(chunk->epoch, meta->epoch, meta->epoch_len))
        return -EIO;
    if (chunk->offset % DNSFS_CHUNK_SIZE)
        return -EINVAL;
    if (chunk->offset / DNSFS_CHUNK_SIZE >= meta->chunk_count)
        return -EIO;
    if (chunk->offset >= meta->size)
        return -EIO;

    /* Only the final chunk is short; earlier ones are full CHUNK_SIZE. */
    remaining = meta->size - chunk->offset;
    *expected_len = remaining < DNSFS_CHUNK_SIZE ? remaining : DNSFS_CHUNK_SIZE;
    return 0;
}

int dnsfs_validate_chunk_set(const struct dnsfs_file_meta *meta,
                             const struct dnsfs_chunk_name *chunks,
                             size_t count)
{
    size_t i;

    if (!meta || (!chunks && count))
        return -EINVAL;
    /* Exactly the declared set -- no missing and no extra chunks. */
    if (count != meta->chunk_count)
        return -EIO;

    for (i = 0; i < count; i++) {
        size_t expected_len;
        size_t j;
        int ret;

        ret = dnsfs_chunk_expected_len(meta, &chunks[i], &expected_len);
        if (ret)
            return ret;
        /* O(n^2) duplicate-offset scan; chunk_count is small. Two chunks at one
         * offset could otherwise mask a gap in coverage.
         */
        for (j = i + 1; j < count; j++) {
            if (chunks[i].offset == chunks[j].offset)
                return -EIO;
        }
    }

    return 0;
}

static int dnsfs_b64_value(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -EINVAL;
}

int dnsfs_base64_decode(const char *src,
                        size_t len,
                        u8 *dst,
                        size_t dst_len,
                        size_t *out_len)
{
    size_t i, pos = 0;

    /* Base64 is whole 4-symbol quartets; a partial group is malformed. */
    if (!src || !dst || !out_len || len % 4)
        return -EINVAL;

    for (i = 0; i < len; i += 4) {
        int a = dnsfs_b64_value(src[i]);
        int b = dnsfs_b64_value(src[i + 1]);
        int c = src[i + 2] == '=' ? -1 : dnsfs_b64_value(src[i + 2]);
        int d = src[i + 3] == '=' ? -1 : dnsfs_b64_value(src[i + 3]);

        if (a < 0 || b < 0 || (c < 0 && src[i + 2] != '=') ||
            (d < 0 && src[i + 3] != '='))
            return -EINVAL;
        /* Reject non-canonical encodings: '=' is only valid as trailing padding
         * in the final quartet, and the bits that padding throws away (b's low
         * 4, or c's low 2) must already be zero -- so each byte string has
         * exactly one base64 spelling.
         */
        if (src[i + 2] == '=' && (src[i + 3] != '=' || i + 4 != len))
            return -EINVAL;
        if (src[i + 3] == '=' && i + 4 != len)
            return -EINVAL;
        if (src[i + 2] == '=' && (b & 0x0f))
            return -EINVAL;
        if (src[i + 3] == '=' && c >= 0 && (c & 0x03))
            return -EINVAL;
        if (pos >= dst_len)
            return -ENOSPC;
        dst[pos++] = (a << 2) | (b >> 4);
        if (src[i + 2] == '=')
            break;
        if (pos >= dst_len)
            return -ENOSPC;
        dst[pos++] = (b << 4) | (c >> 2);
        if (src[i + 3] == '=')
            break;
        if (pos >= dst_len)
            return -ENOSPC;
        dst[pos++] = (c << 6) | d;
    }

    /* One chunk decodes to at most CHUNK_SIZE raw bytes. */
    if (pos > DNSFS_CHUNK_SIZE)
        return -EFBIG;
    *out_len = pos;
    return 0;
}

/* CRC32c (Castagnoli) over the payload. The kernel path uses the accelerated
 * crc32c(); userspace mirrors it bit-by-bit with the reflected polynomial so
 * the fuzzer computes identical values. This is integrity only: it detects
 * transport or cache corruption, NOT a spoofed or cache-poisoned answer, which
 * can carry a matching CRC. Real tamper resistance needs DNSSEC.
 */
int dnsfs_crc32c_verify(const u8 *buf, size_t len, u32 expected)
{
#ifdef __KERNEL__
    return (crc32c(~0U, buf, len) ^ ~0U) == expected ? 0 : -EIO;
#else
    u32 crc = ~0U;
    size_t i;

    for (i = 0; i < len; i++) {
        unsigned int bit;

        crc ^= buf[i];
        for (bit = 0; bit < 8; bit++)
            crc = (crc >> 1) ^ (0x82f63b78U & -(crc & 1));
    }

    return (~crc) == expected ? 0 : -EIO;
#endif
}

int dnsfs_decode_chunk_payload(const char *src,
                               size_t len,
                               u32 expected_crc,
                               u8 *dst,
                               size_t dst_len,
                               size_t *out_len)
{
    int ret;

    ret = dnsfs_base64_decode(src, len, dst, dst_len, out_len);
    if (ret)
        return ret;
    return dnsfs_crc32c_verify(dst, *out_len, expected_crc);
}

int dnsfs_decode_file_chunk(const struct dnsfs_file_meta *meta,
                            const struct dnsfs_chunk_name *chunk,
                            const char *src,
                            size_t len,
                            u32 expected_crc,
                            u8 *dst,
                            size_t dst_len,
                            size_t *out_len)
{
    size_t expected_len;
    int ret;

    ret = dnsfs_chunk_expected_len(meta, chunk, &expected_len);
    if (ret)
        return ret;
    ret = dnsfs_decode_chunk_payload(src, len, expected_crc, dst, dst_len,
                                     out_len);
    if (ret)
        return ret;
    /* Decoded size must equal what this offset is supposed to hold. */
    return *out_len == expected_len ? 0 : -EIO;
}

int dnsfs_verify_file_payload(const struct dnsfs_file_meta *meta,
                              const u8 *buf,
                              size_t len)
{
    if (!meta || (!buf && len))
        return -EINVAL;
    if (meta->size != len)
        return -EIO;
    return dnsfs_crc32c_verify(buf, len, meta->file_crc);
}

/* Copy each decoded chunk to its offset in dst, then verify the whole file CRC.
 * Requires the exact chunk_count, a matching per-chunk length, and no duplicate
 * offsets, so the assembled image has full coverage before the final integrity
 * check.
 */
int dnsfs_reassemble_file_payload(const struct dnsfs_file_meta *meta,
                                  const struct dnsfs_decoded_chunk *chunks,
                                  size_t count,
                                  u8 *dst,
                                  size_t dst_len)
{
    size_t i;

    if (!meta || (!chunks && count) || (!dst && meta && meta->size))
        return -EINVAL;
    if (meta->size > dst_len)
        return -ENOSPC;
    if (count != meta->chunk_count)
        return -EIO;

    for (i = 0; i < count; i++) {
        size_t expected_len;
        size_t j;
        int ret;

        ret = dnsfs_chunk_expected_len(meta, &chunks[i].name, &expected_len);
        if (ret)
            return ret;
        if (!chunks[i].data || chunks[i].len != expected_len)
            return -EIO;
        /* On 32-bit, a u64 offset may exceed size_t; guard the cast. */
        if (chunks[i].name.offset > ~(size_t) 0)
            return -EOVERFLOW;
        for (j = i + 1; j < count; j++) {
            if (chunks[i].name.offset == chunks[j].name.offset)
                return -EIO;
        }
        memcpy(dst + (size_t) chunks[i].name.offset, chunks[i].data,
               chunks[i].len);
    }

    return dnsfs_verify_file_payload(meta, dst, meta->size);
}

/* Parse a newline-separated list of storage labels from an index TXT. Each
 * label is validated and deduped, capped at max_entries. Entries alias the
 * source buffer, which must outlive them.
 */
int dnsfs_parse_index_txt(const char *src,
                          size_t len,
                          struct dnsfs_index_entry *entries,
                          size_t max_entries,
                          size_t *count)
{
    size_t pos = 0;
    size_t out = 0;

    if (!src || !entries || !count || len > DNSFS_MAX_TXT)
        return -EINVAL;

    while (pos < len) {
        size_t start = pos;
        size_t name_len;
        size_t i;
        int ret;

        while (pos < len && src[pos] != '\n')
            pos++;
        name_len = pos - start;
        if (pos < len)
            pos++;
        /* A trailing newline leaves an empty final line; stop there. */
        if (!name_len && pos == len)
            break;

        ret = dnsfs_validate_storage_label(src + start, name_len);
        if (ret)
            return ret;
        if (out == max_entries)
            return -ENOSPC;
        for (i = 0; i < out; i++) {
            if (entries[i].name_len == name_len &&
                !memcmp(entries[i].name, src + start, name_len))
                return -EIO;
        }
        entries[out].name = src + start;
        entries[out].name_len = name_len;
        out++;
    }

    *count = out;
    return 0;
}
