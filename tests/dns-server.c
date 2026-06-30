// SPDX-License-Identifier: GPL-2.0-only
/* Test DNS server for the dnsfs smoke suite. Faithful C port of the former
 * dns-server.py: synthesizes live records, malformed responses, and the DNS
 * storage layer (index/metadata/chunks) over UDP + TCP. No external deps.
 */
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#define PAYLOAD_LEN 1980
#define CHUNK_SIZE 180
#define MAX_STORAGE_SIZE (CHUNK_SIZE * 64)
#define TXT_STRING_MAX 255
#define MAX_PKT 4096
#define MAX_RESP 8192
#define PUT_HEADER_MAX 160

static unsigned long query_count;
static const char *count_file;
static const char *serve_dir;
static int storage_enabled;
static int bad_storage_index;
static int malformed_storage_index;
static int meta_count_epochflip;
static int meta_count_pin;
static uint8_t payload[PAYLOAD_LEN];

/* Storage files that carry chunk data (vs. metadata-only entries). */
static int is_chunk_file(const char *name)
{
    static const char *files[] = {
        "big",        "nested",     "private",      "badcrc",
        "badfilecrc", "shortchunk", "badchunktext", "badchunkb64",
        "missing",    "epochflip",  "pin",
    };
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++)
        if (!strcmp(name, files[i]))
            return 1;
    return 0;
}

static uint32_t crc32c(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFU;

    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ ((crc & 1) ? 0x82F63B78U : 0);
    }
    return crc ^ 0xFFFFFFFFU;
}

static size_t base64(const uint8_t *src, size_t n, char *out)
{
    static const char t[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;

    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t) src[i] << 16;
        size_t r = n - i;

        if (r > 1)
            v |= (uint32_t) src[i + 1] << 8;
        if (r > 2)
            v |= src[i + 2];
        out[o++] = t[(v >> 18) & 0x3f];
        out[o++] = t[(v >> 12) & 0x3f];
        out[o++] = r > 1 ? t[(v >> 6) & 0x3f] : '=';
        out[o++] = r > 2 ? t[v & 0x3f] : '=';
    }
    return o;
}

static void bump_count(void)
{
    FILE *f;

    query_count++;
    if (!count_file)
        return;
    f = fopen(count_file, "w");
    if (!f)
        return;
    fprintf(f, "%lu\n", query_count);
    fclose(f);
}

static int set_reuse_addr(int fd)
{
    int one = 1;

    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
}

/* Append a wire-encoded domain name; returns bytes written. */
static size_t wire_name(const char *name, uint8_t *out)
{
    size_t o = 0;

    while (*name) {
        const char *dot = strchr(name, '.');
        size_t len = dot ? (size_t) (dot - name) : strlen(name);

        if (!len) /* trailing dot terminates */
            break;
        out[o++] = (uint8_t) len;
        memcpy(out + o, name, len);
        o += len;
        name = dot ? dot + 1 : name + len;
    }
    out[o++] = 0;
    return o;
}

static void parse_qname(const uint8_t *p, size_t len, char *out, size_t out_len)
{
    size_t off = 12, o = 0;

    while (off < len && p[off]) {
        size_t size = p[off++];

        if (off + size > len || o + size + 1 >= out_len)
            break;
        memcpy(out + o, p + off, size);
        o += size;
        out[o++] = '.';
        off += size;
    }
    out[o] = '\0';
}

/* len(label) + label + pointer-to-qname (0xc00c). */
static size_t compressed_child(const char *label, uint8_t *out)
{
    size_t len = strlen(label);

    out[0] = (uint8_t) len;
    memcpy(out + 1, label, len);
    out[1 + len] = 0xc0;
    out[2 + len] = 0x0c;
    return len + 3;
}

static size_t put_u32(uint8_t *out, uint32_t v)
{
    out[0] = v >> 24;
    out[1] = v >> 16;
    out[2] = v >> 8;
    out[3] = v;
    return 4;
}

enum storage_kind { STORAGE_NONE, STORAGE_DATA, STORAGE_MISS };

/* A valid lowercase DNS label (and thus a publishable file name). */
static int is_label(const char *s, size_t n)
{
    if (!n || n > 63 || s[0] == '-' || s[n - 1] == '-')
        return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];

        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
            return 0;
    }
    return 1;
}

static int is_chunk_label(const char *s)
{
    const char *d1 = strchr(s, '-');
    const char *d2 = d1 ? strchr(d1 + 1, '-') : NULL;
    char *end;
    long off;

    /* {epoch}-{base36off}-{name}: epoch is "e" + hex (>=2 chars from
     * epoch_for_stat), so the first '-' is not fixed at index 1. Require a
     * non-empty 'e'-prefixed epoch, a non-empty offset, and a non-empty name.
     */
    if (!d1 || d1 < s + 1 || s[0] != 'e' || !d2 || d2 == d1 + 1 || !d2[1])
        return 0;
    off = strtol(d1 + 1, &end, 36);
    return end == d2 && off >= 0 && off % CHUNK_SIZE == 0;
}

static int is_published_label(const char *s, size_t n)
{
    return is_label(s, n) && strcmp(s, "index") && !is_chunk_label(s);
}

static void epoch_for_stat(const struct stat *st, char *out, size_t out_len)
{
    snprintf(out, out_len, "e%llx%lx", (unsigned long long) st->st_mtim.tv_sec,
             (unsigned long) st->st_mtim.tv_nsec);
}

/* Read serve_dir/name into *buf (caller frees). Returns size, or -1. */
static long read_published(const char *name, uint8_t **buf)
{
    char path[1024];
    FILE *f;
    long n;
    int rfd;

    *buf = NULL;
    if (snprintf(path, sizeof(path), "%s/%s", serve_dir, name) >=
        (int) sizeof(path))
        return -1;
    /* O_NOFOLLOW: a symlink planted in serve_dir must not leak its target. */
    rfd = open(path, O_RDONLY | O_NOFOLLOW);
    if (rfd < 0)
        return -1;
    f = fdopen(rfd, "rb");
    if (!f) {
        close(rfd);
        return -1;
    }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) {
        fclose(f);
        return -1;
    }
    *buf = malloc(n ? (size_t) n : 1);
    if (*buf && n)
        n = (long) fread(*buf, 1, (size_t) n, f);
    fclose(f);
    return *buf ? n : -1;
}

/* Serve storage queries from a real directory (--serve-dir): an index listing,
 * per-file metadata, and base64/CRC32c chunks, matching the kernel's storage
 * encoding. Writing a file into serve_dir is how you "publish" it to DNS.
 */
static enum storage_kind publish_txt(const char *qname,
                                     uint8_t *out,
                                     size_t out_cap,
                                     size_t *out_len)
{
    static const char suffix[] = ".example.org.";
    size_t qlen = strlen(qname), slen = sizeof(suffix) - 1;
    char label[256];
    size_t llen;
    struct stat st;
    char path[1024];

    if (qlen <= slen || strcmp(qname + qlen - slen, suffix))
        return STORAGE_MISS;
    llen = qlen - slen;
    if (llen >= sizeof(label))
        return STORAGE_MISS;
    memcpy(label, qname, llen);
    label[llen] = '\0';

    /* index.<zone> -> newline-separated listing of publishable files. */
    if (!strcmp(label, "index")) {
        DIR *d = opendir(serve_dir);
        struct dirent *e;
        size_t o = 0;

        if (!d)
            return STORAGE_MISS;
        while ((e = readdir(d))) {
            size_t nl = strlen(e->d_name);

            if (!is_published_label(e->d_name, nl))
                continue;
            if (snprintf(path, sizeof(path), "%s/%s", serve_dir, e->d_name) >=
                (int) sizeof(path))
                continue;
            if (lstat(path, &st) || !S_ISREG(st.st_mode))
                continue;
            if (o + nl + 1 > out_cap)
                break;
            memcpy(out + o, e->d_name, nl);
            o += nl;
            out[o++] = '\n';
        }
        closedir(d);
        *out_len = o;
        return STORAGE_DATA;
    }

    /* {epoch}-{base36off}-{file}.<zone> -> one chunk. */
    char *d1 = strchr(label, '-');
    char *d2 = d1 ? strchr(d1 + 1, '-') : NULL;

    if (d2 && d1 != label && d2 != d1 + 1) {
        char *end;
        char epoch[64];
        const char *name = d2 + 1;
        long off;

        *d2 = '\0';
        off = strtol(d1 + 1, &end, 36);
        *d2 = '-';
        if (end == d2 && off >= 0 && off % CHUNK_SIZE == 0 &&
            is_published_label(name, strlen(name)) &&
            snprintf(path, sizeof(path), "%s/%s", serve_dir, name) <
                (int) sizeof(path) &&
            !lstat(path, &st) && S_ISREG(st.st_mode)) {
            uint8_t *buf;
            long size = read_published(name, &buf);

            epoch_for_stat(&st, epoch, sizeof(epoch));
            *d1 = '\0';
            if (strcmp(label, epoch)) {
                *d1 = '-';
                free(buf);
                return STORAGE_MISS;
            }
            *d1 = '-';
            if (size >= 0 && off < size) {
                size_t clen = (size_t) (size - off);
                int n;

                if (clen > CHUNK_SIZE)
                    clen = CHUNK_SIZE;
                n = snprintf((char *) out, out_cap, "%08X ",
                             crc32c(buf + off, clen));
                *out_len = n + base64(buf + off, clen, (char *) out + n);
                free(buf);
                return STORAGE_DATA;
            }
            free(buf);
        }
    }

    /* <file>.<zone> -> metadata "size mode mtime chunk_count epoch crc". */
    if (is_published_label(label, llen) &&
        snprintf(path, sizeof(path), "%s/%s", serve_dir, label) <
            (int) sizeof(path) &&
        !stat(path, &st) && S_ISREG(st.st_mode)) {
        uint8_t *buf;
        long size = read_published(label, &buf);
        unsigned long count;
        char epoch[64];

        if (size < 0)
            return STORAGE_MISS;
        count = ((unsigned long) size + CHUNK_SIZE - 1) / CHUNK_SIZE;
        epoch_for_stat(&st, epoch, sizeof(epoch));
        *out_len = snprintf(
            (char *) out, out_cap, "%ld %lo %ld %lu %s %08X", size,
            (unsigned long) (0100000 | (st.st_mode & 0555)), (long) st.st_mtime,
            count, epoch, crc32c(buf, (size_t) size));
        free(buf);
        return STORAGE_DATA;
    }

    return STORAGE_MISS;
}

/* Build the TXT payload for a storage query. Returns the tri-state kind. */
static enum storage_kind storage_txt(const char *qname,
                                     uint8_t *out,
                                     size_t out_cap,
                                     size_t *out_len)
{
    if (!storage_enabled)
        return STORAGE_NONE;
    if (serve_dir)
        return publish_txt(qname, out, out_cap, out_len);

    if (!strcmp(qname, "index.example.org.")) {
        const char *s;

        if (bad_storage_index)
            s = "big\nbig\n";
        else if (malformed_storage_index)
            s = "Bad\n";
        else
            s = "big\nprivate\nempty\nsub\nhuge\nwritable\nspecialmode\n"
                "badmode\nbadmeta\nbadepoch\nbadcrc\nbadfilecrc\nshortchunk\n"
                "badchunktext\nbadchunkb64\nmissing\nepochflip\npin\n";
        *out_len = strlen(s);
        memcpy(out, s, *out_len);
        return STORAGE_DATA;
    }

    struct {
        const char *q;
        const char *meta;
    } statics[] = {
        {"index.sub.example.org.", "nested\n"},
        {"empty.example.org.", "0 100444 1700000000 0 e 00000000"},
        {"huge.example.org.", "11700 100444 1700000000 65 e 00000000"},
        {"writable.example.org.", "0 100644 1700000000 0 e 00000000"},
        {"specialmode.example.org.", "0 104444 1700000000 0 e 00000000"},
        {"badmode.example.org.", "0 40755 1700000000 0 e 00000000"},
        {"badmeta.example.org.", "180 100444 1700000000 2 e 00000000"},
        {"badepoch.example.org.", "0 100444 1700000000 0 E 00000000"},
    };
    for (size_t i = 0; i < sizeof(statics) / sizeof(statics[0]); i++)
        if (!strcmp(qname, statics[i].q)) {
            *out_len = strlen(statics[i].meta);
            memcpy(out, statics[i].meta, *out_len);
            return STORAGE_DATA;
        }
    if (!strcmp(qname, "sub.example.org."))
        return STORAGE_MISS;
    if (!strcmp(qname, "private.example.org.")) {
        *out_len =
            snprintf((char *) out, out_cap, "1980 100400 1700000000 11 e %08X",
                     crc32c(payload, PAYLOAD_LEN));
        return STORAGE_DATA;
    }

    /* File-metadata query for a chunk-bearing file: "<file>.example.org.". */
    char first[64];
    const char *dot = strchr(qname, '.');
    size_t flen = dot ? (size_t) (dot - qname) : 0;
    int suffix_org = 0;
    size_t qlen = strlen(qname);

    if (qlen >= 13 && !strcmp(qname + qlen - 13, ".example.org."))
        suffix_org = 1;
    if (flen && flen < sizeof(first)) {
        memcpy(first, qname, flen);
        first[flen] = '\0';
    } else {
        first[0] = '\0';
    }
    if (suffix_org && is_chunk_file(first) && strchr(qname, '-') == NULL) {
        uint32_t crc = crc32c(payload, PAYLOAD_LEN);
        const char *epoch = "e";

        if (!strcmp(qname, "badfilecrc.example.org."))
            crc ^= 1;
        if (!strcmp(qname, "epochflip.example.org.")) {
            meta_count_epochflip++;
            if (meta_count_epochflip > 1)
                epoch = "f";
        } else if (!strcmp(qname, "pin.example.org.")) {
            meta_count_pin++;
            if (meta_count_pin > 1)
                epoch = "f";
        }
        *out_len = snprintf((char *) out, out_cap,
                            "1980 100444 1700000000 11 %s %08X", epoch, crc);
        return STORAGE_DATA;
    }
    if (suffix_org && flen && is_label(first, flen) &&
        strchr(qname, '-') == NULL)
        return STORAGE_MISS;

    /* Chunk query: "{epoch}-{base36off}-{file}<suffix>". */
    size_t suffix_len;

    if (qlen >= 17 && !strcmp(qname + qlen - 17, ".sub.example.org.")) {
        suffix_len = 17;
    } else if (suffix_org) {
        suffix_len = 13;
    } else {
        return STORAGE_NONE;
    }

    char label[128];
    size_t llen = qlen - suffix_len;

    if (llen >= sizeof(label))
        return STORAGE_NONE;
    memcpy(label, qname, llen);
    label[llen] = '\0';

    /* split into epoch '-' off '-' file (file may not contain '-'). */
    char *d1 = strchr(label, '-');
    if (!d1)
        return STORAGE_NONE;
    *d1 = '\0';
    char *d2 = strchr(d1 + 1, '-');
    if (!d2)
        return STORAGE_NONE;
    *d2 = '\0';
    const char *epoch = label;
    const char *offstr = d1 + 1;
    const char *file = d2 + 1;

    if (strcmp(epoch, "e") && strcmp(epoch, "f"))
        return STORAGE_NONE;
    if (!is_chunk_file(file))
        return STORAGE_NONE;

    char *end;
    long offset = strtol(offstr, &end, 36);
    if (*end || offset < 0)
        return STORAGE_NONE;
    if (offset >= PAYLOAD_LEN)
        return STORAGE_NONE; /* empty chunk -> None */

    size_t chunk_len = PAYLOAD_LEN - offset;
    if (chunk_len > CHUNK_SIZE)
        chunk_len = CHUNK_SIZE;

    if (!strcmp(file, "missing") && offset == CHUNK_SIZE)
        return STORAGE_MISS;
    if (!strcmp(file, "epochflip") && !strcmp(epoch, "e"))
        return STORAGE_MISS;
    if (!strcmp(file, "pin") && !strcmp(epoch, "f"))
        return STORAGE_MISS;
    if (!strcmp(file, "badchunktext") && offset == 0) {
        *out_len = snprintf((char *) out, out_cap, "not-a-chunk");
        return STORAGE_DATA;
    }
    if (!strcmp(file, "badchunkb64") && offset == 0) {
        *out_len = snprintf((char *) out, out_cap, "00000000 !!!!");
        return STORAGE_DATA;
    }
    if (!strcmp(file, "shortchunk") && offset == CHUNK_SIZE)
        chunk_len--;

    uint32_t crc = crc32c(payload + offset, chunk_len);
    if (!strcmp(file, "badcrc") && offset == 0)
        crc ^= 1;
    int n = snprintf((char *) out, out_cap, "%08X ", crc);
    *out_len = n + base64(payload + offset, chunk_len, (char *) out + n);
    return STORAGE_DATA;
}

static int has_edns_do(const uint8_t *p, size_t len)
{
    size_t off = 12;

    if (len < 12 || p[10] != 0 || p[11] != 1)
        return 0;
    while (off < len && p[off])
        off += p[off] + 1;
    off += 5;
    return off + 11 <= len && p[off] == 0 && p[off + 1] == 0x00 &&
           p[off + 2] == 0x29 && p[off + 3] == 0x10 && p[off + 4] == 0x00 &&
           p[off + 7] == 0x80 && p[off + 8] == 0x00;
}

struct opts {
    int truncated, nxdomain, ttl, rcode, bad_txid;
    int delay_ms;
    unsigned long ttl0_after;
    int bad_qname, bad_qtype, bad_qclass;
    int bad_a, bad_aaaa, bad_mx, bad_ns, bad_soa, bad_ds, bad_dnskey, bad_txt,
        bad_cname;
    int multi_a, multi_aaaa, multi_mx, multi_ns, multi_ds, multi_dnskey,
        multi_soa;
};

/* SOA authority block shared by NXDOMAIN and missing-storage responses. */
static size_t build_nxdomain(const uint8_t *id,
                             const uint8_t *question,
                             size_t qlen,
                             int ttl,
                             uint8_t *out)
{
    uint8_t soa[256];
    size_t s = 0, o = 0;

    s += wire_name("ns.example.org.", soa + s);
    s += wire_name("hostmaster.example.org.", soa + s);
    s += put_u32(soa + s, 1);
    s += put_u32(soa + s, 3600);
    s += put_u32(soa + s, 600);
    s += put_u32(soa + s, 604800);
    s += put_u32(soa + s, ttl);

    out[o++] = id[0];
    out[o++] = id[1];
    memcpy(out + o, "\x81\x83\x00\x01\x00\x00\x00\x01\x00\x00", 10);
    o += 10;
    memcpy(out + o, question, qlen);
    o += qlen;
    o += wire_name("example.org.", out + o);
    memcpy(out + o, "\x00\x06\x00\x01", 4);
    o += 4;
    o += put_u32(out + o, ttl);
    out[o++] = s >> 8;
    out[o++] = s & 0xff;
    memcpy(out + o, soa, s);
    o += s;
    return o;
}

/* Append a second answer RR (compression pointer to qname) for multi-* tests.
 */
static size_t add_answer(uint8_t *out,
                         const uint8_t *qtype,
                         int ttl,
                         const uint8_t *rdata,
                         size_t rlen)
{
    size_t o = 0;

    out[o++] = 0xc0;
    out[o++] = 0x0c;
    out[o++] = qtype[0];
    out[o++] = qtype[1];
    out[o++] = 0x00;
    out[o++] = 0x01;
    o += put_u32(out + o, ttl);
    out[o++] = rlen >> 8;
    out[o++] = rlen & 0xff;
    memcpy(out + o, rdata, rlen);
    o += rlen;
    return o;
}

static size_t build_response(const uint8_t *p,
                             size_t len,
                             const struct opts *o,
                             uint8_t *out)
{
    char qname[256];
    uint8_t id[2];
    size_t off = 12;

    if (len < 12)
        return 0;
    parse_qname(p, len, qname, sizeof(qname));
    id[0] = o->bad_txid ? (p[0] ^ 1) : p[0];
    id[1] = p[1];
    while (off < len && p[off])
        off += p[off] + 1;
    if (off + 5 > len)
        return 0;

    uint8_t question[255 + 5]; /* max DNS name (255) + qtype + qclass */
    size_t qlen = off + 5 - 12;
    if (qlen > sizeof(question))
        return 0;
    memcpy(question, p + 12, qlen);
    if (o->bad_qname && qlen > 2)
        question[1] = question[1] != 'z' ? 'z' : 'y';
    if (o->bad_qtype) {
        if (question[qlen - 4] == 0x00 && question[qlen - 3] == 0x01) {
            question[qlen - 4] = 0x00;
            question[qlen - 3] = 0x10;
        } else {
            question[qlen - 4] = 0x00;
            question[qlen - 3] = 0x01;
        }
    }
    if (o->bad_qclass) {
        question[qlen - 2] = 0x00;
        question[qlen - 1] = 0x02;
    }
    uint8_t qtype[2] = {p[off + 1], p[off + 2]};

    if (o->nxdomain)
        return build_nxdomain(id, question, qlen, o->ttl, out);
    if (o->truncated) {
        size_t z = 0;

        out[z++] = id[0];
        out[z++] = id[1];
        memcpy(out + z, "\x83\x80\x00\x01\x00\x00\x00\x00\x00\x00", 10);
        z += 10;
        memcpy(out + z, question, qlen);
        return z + qlen;
    }
    if (o->rcode) {
        size_t z = 0;

        out[z++] = id[0];
        out[z++] = id[1];
        out[z++] = 0x81;
        out[z++] = 0x80 | o->rcode;
        memcpy(out + z, "\x00\x01\x00\x00\x00\x00\x00\x00", 8);
        z += 8;
        memcpy(out + z, question, qlen);
        return z + qlen;
    }

    int is_txt = qtype[0] == 0x00 && qtype[1] == 0x10;
    uint8_t storage[TXT_STRING_MAX];
    size_t storage_len = 0;
    enum storage_kind sk = STORAGE_NONE;

    if (is_txt)
        sk = storage_txt(qname, storage, sizeof(storage), &storage_len);
    if (sk == STORAGE_MISS)
        return build_nxdomain(id, question, qlen, o->ttl, out);

    uint8_t rdata[512];
    size_t rlen = 0;
    uint16_t qt = (qtype[0] << 8) | qtype[1];

    if (sk == STORAGE_DATA) {
        if (storage_len > TXT_STRING_MAX)
            return build_nxdomain(id, question, qlen, o->ttl, out);
        rdata[0] = (uint8_t) storage_len;
        memcpy(rdata + 1, storage, storage_len);
        rlen = storage_len + 1;
    } else if (qt == 0x0001) {
        if (o->bad_a) {
            memcpy(rdata, "\xc0\x00\x02", 3);
            rlen = 3;
        } else {
            memcpy(rdata, "\xc0\x00\x02\x01", 4);
            rlen = 4;
        }
    } else if (qt == 0x001c) {
        if (o->bad_aaaa) {
            memcpy(
                rdata,
                "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                15);
            rlen = 15;
        } else {
            memcpy(rdata,
                   "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                   "\x00\x01",
                   16);
            rlen = 16;
        }
    } else if (qt == 0x000f) {
        if (o->bad_mx) {
            memcpy(rdata, "\x00\x0a\x04ma", 5);
            rlen = 5;
        } else {
            memcpy(rdata, "\x00\x0a", 2);
            rlen = 2 + compressed_child("mail", rdata + 2);
        }
    } else if (qt == 0x0002) {
        if (o->bad_ns) {
            memcpy(rdata, "\x02n", 2);
            rlen = 2;
        } else {
            rlen = compressed_child("ns", rdata);
        }
    } else if (qt == 0x0005) {
        if (o->bad_cname) {
            memcpy(rdata, "\x06target", 7);
            rlen = 7;
        } else {
            rlen = compressed_child("target", rdata);
        }
    } else if (qt == 0x0006) {
        rlen = compressed_child("ns", rdata);
        rlen += compressed_child("hostmaster", rdata + rlen);
        rlen += put_u32(rdata + rlen, 1);
        if (!o->bad_soa) {
            rlen += put_u32(rdata + rlen, 3600);
            rlen += put_u32(rdata + rlen, 600);
            rlen += put_u32(rdata + rlen, 604800);
            rlen += put_u32(rdata + rlen, o->ttl);
        }
    } else if (qt == 0x002b) {
        if (o->bad_ds) {
            memcpy(rdata, "\x30\x39\x08\x02", 4);
            rlen = 4;
        } else {
            memcpy(rdata, "\x30\x39\x08\x02\xde\xad\xbe\xef", 8);
            rlen = 8;
        }
    } else if (qt == 0x0030) {
        if (o->bad_dnskey) {
            memcpy(rdata, "\x01\x01\x03\x08", 4);
            rlen = 4;
        } else {
            memcpy(rdata, "\x01\x01\x03\x08\xde\xad\xbe\xef", 8);
            rlen = 8;
        }
    } else if (o->bad_txt) {
        memcpy(rdata, "\x05hi", 3);
        rlen = 3;
    } else {
        rdata[0] = 10;
        memcpy(rdata + 1, "dnsfs live", 10);
        rlen = 11;
    }

    uint8_t answer[1024];
    size_t alen = add_answer(answer, qtype, o->ttl, rdata, rlen);
    int answers = 1;
    uint8_t r2[256];
    size_t r2len = 0;

    if (qt == 0x0001 && o->multi_a && !o->bad_a) {
        memcpy(r2, "\xc0\x00\x02\x02", 4);
        r2len = 4;
    } else if (qt == 0x001c && o->multi_aaaa && !o->bad_aaaa) {
        memcpy(
            r2,
            "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
            16);
        r2len = 16;
    } else if (qt == 0x000f && o->multi_mx && !o->bad_mx) {
        memcpy(r2, "\x00\x14", 2);
        r2len = 2 + wire_name("mail2.example.org.", r2 + 2);
    } else if (qt == 0x0002 && o->multi_ns && !o->bad_ns) {
        r2len = wire_name("ns2.example.org.", r2);
    } else if (qt == 0x002b && o->multi_ds && !o->bad_ds) {
        memcpy(r2, "\x30\x3a\x08\x02\xca\xfe\xba\xbe", 8);
        r2len = 8;
    } else if (qt == 0x0030 && o->multi_dnskey && !o->bad_dnskey) {
        memcpy(r2, "\x01\x00\x03\x08\xca\xfe\xba\xbe", 8);
        r2len = 8;
    } else if (qt == 0x0006 && o->multi_soa && !o->bad_soa) {
        r2len = wire_name("ns2.example.org.", r2);
        r2len += wire_name("hostmaster.example.org.", r2 + r2len);
        r2len += put_u32(r2 + r2len, 2);
        r2len += put_u32(r2 + r2len, 7200);
        r2len += put_u32(r2 + r2len, 1200);
        r2len += put_u32(r2 + r2len, 604800);
        r2len += put_u32(r2 + r2len, o->ttl);
    }
    if (r2len) {
        alen += add_answer(answer + alen, qtype, o->ttl, r2, r2len);
        answers = 2;
    }

    size_t z = 0;
    out[z++] = id[0];
    out[z++] = id[1];
    memcpy(out + z, "\x81\x80\x00\x01", 4);
    z += 4;
    out[z++] = 0x00;
    out[z++] = (uint8_t) answers;
    memcpy(out + z, "\x00\x00\x00\x00", 4);
    z += 4;
    memcpy(out + z, question, qlen);
    z += qlen;
    memcpy(out + z, answer, alen);
    z += alen;
    return z;
}

static ssize_t recv_exact(int fd, uint8_t *buf, size_t n)
{
    size_t got = 0;

    while (got < n) {
        ssize_t r = recv(fd, buf + got, n - got, 0);

        if (r <= 0)
            return got;
        got += r;
    }
    return got;
}

static int write_all(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;

    while (n) {
        ssize_t w = write(fd, p, n);

        if (w <= 0)
            return -1;
        p += w;
        n -= (size_t) w;
    }
    return 0;
}

static void put_status(int fd, const char *status)
{
    (void) write_all(fd, status, strlen(status));
}

static int peer_is_loopback(const struct sockaddr_in *peer)
{
    return (ntohl(peer->sin_addr.s_addr) >> 24) == 127;
}

static int handle_put(int conn, const struct sockaddr_in *peer)
{
    char header[PUT_HEADER_MAX];
    char label[64], path[1024], tmp[1024];
    unsigned long len;
    size_t hlen = 0, off = 0;
    uint8_t buf[MAX_STORAGE_SIZE];
    int fd = -1, dirfd = -1;
    int ret = -1;

    if (!serve_dir || !peer_is_loopback(peer)) {
        put_status(conn, "ERR EACCES\n");
        return -1;
    }
    while (hlen + 1 < sizeof(header)) {
        char c;

        if (recv_exact(conn, (uint8_t *) &c, 1) != 1) {
            put_status(conn, "ERR EINVAL\n");
            return -1;
        }
        header[hlen++] = c;
        if (c == '\n')
            break;
    }
    header[hlen] = '\0';
    if (sscanf(header, "PUT %63s %lu\n", label, &len) != 2 ||
        !is_published_label(label, strlen(label)) || len > sizeof(buf)) {
        put_status(conn, "ERR EINVAL\n");
        return -1;
    }
    while (off < len) {
        ssize_t r = recv(conn, buf + off, len - off, 0);

        if (r <= 0) {
            put_status(conn, "ERR EINVAL\n");
            return -1;
        }
        off += (size_t) r;
    }
    if (snprintf(path, sizeof(path), "%s/%s", serve_dir, label) >=
            (int) sizeof(path) ||
        snprintf(tmp, sizeof(tmp), "%s/.%s.tmp.%ld", serve_dir, label,
                 (long) getpid()) >= (int) sizeof(tmp)) {
        put_status(conn, "ERR ENAMETOOLONG\n");
        return -1;
    }

    /* O_EXCL | O_NOFOLLOW: refuse to write through a pre-planted symlink or a
     * leftover temp at this predictable name.
     */
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);
    if (fd < 0)
        goto out_errno;
    if (write_all(fd, buf, len) || fsync(fd))
        goto out_errno;
    ret = close(fd);
    fd = -1;
    if (ret)
        goto out_errno;
    if (rename(tmp, path))
        goto out_errno;
    dirfd = open(serve_dir, O_RDONLY | O_DIRECTORY);
    if (dirfd >= 0) {
        (void) fsync(dirfd);
        close(dirfd);
        dirfd = -1;
    }
    put_status(conn, "OK\n");
    ret = 0;
    goto out;

out_errno: {
    char status[32];

    snprintf(status, sizeof(status), "ERR E%d\n", errno ? errno : EIO);
    put_status(conn, status);
}
out:
    if (fd >= 0)
        close(fd);
    if (dirfd >= 0)
        close(dirfd);
    if (ret)
        unlink(tmp);
    return ret;
}

static int handle_del(int conn, const struct sockaddr_in *peer)
{
    char header[PUT_HEADER_MAX];
    char label[64], path[1024];
    size_t hlen = 0;

    if (!serve_dir || !peer_is_loopback(peer)) {
        put_status(conn, "ERR EACCES\n");
        return -1;
    }
    while (hlen + 1 < sizeof(header)) {
        char c;

        if (recv_exact(conn, (uint8_t *) &c, 1) != 1) {
            put_status(conn, "ERR EINVAL\n");
            return -1;
        }
        header[hlen++] = c;
        if (c == '\n')
            break;
    }
    header[hlen] = '\0';
    if (sscanf(header, "DEL %63s\n", label) != 1 ||
        !is_published_label(label, strlen(label))) {
        put_status(conn, "ERR EINVAL\n");
        return -1;
    }
    if (snprintf(path, sizeof(path), "%s/%s", serve_dir, label) >=
        (int) sizeof(path)) {
        put_status(conn, "ERR ENAMETOOLONG\n");
        return -1;
    }
    if (unlink(path) && errno != ENOENT) {
        char status[32];

        snprintf(status, sizeof(status), "ERR E%d\n", errno);
        put_status(conn, status);
        return -1;
    }
    put_status(conn, "OK\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s PORT [flags]\n", argv[0]);
        return 1;
    }
    int port = atoi(argv[1]);
    const char *bind_addr = "127.0.0.1";
    struct opts o = {0};
    int expect_do = -1; /* -1 = unset */
    int truncate_udp = 0, wrong_source_port = 0;

    o.ttl = 60;
    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];

        if (!strcmp(a, "--truncate-udp"))
            truncate_udp = 1;
        else if (!strcmp(a, "--nxdomain"))
            o.nxdomain = 1;
        else if (!strcmp(a, "--ttl1"))
            o.ttl = 1;
        else if (!strncmp(a, "--ttl0-after=", 13))
            o.ttl0_after = strtoul(a + 13, NULL, 10);
        else if (!strcmp(a, "--bad-txid"))
            o.bad_txid = 1;
        else if (!strcmp(a, "--bad-qname"))
            o.bad_qname = 1;
        else if (!strcmp(a, "--bad-qtype"))
            o.bad_qtype = 1;
        else if (!strcmp(a, "--bad-qclass"))
            o.bad_qclass = 1;
        else if (!strcmp(a, "--bad-a-rdlength"))
            o.bad_a = 1;
        else if (!strcmp(a, "--bad-aaaa-rdlength"))
            o.bad_aaaa = 1;
        else if (!strcmp(a, "--bad-mx-rdata"))
            o.bad_mx = 1;
        else if (!strcmp(a, "--bad-ns-rdata"))
            o.bad_ns = 1;
        else if (!strcmp(a, "--bad-soa-rdata"))
            o.bad_soa = 1;
        else if (!strcmp(a, "--bad-ds-rdata"))
            o.bad_ds = 1;
        else if (!strcmp(a, "--bad-dnskey-rdata"))
            o.bad_dnskey = 1;
        else if (!strcmp(a, "--bad-txt-rdata"))
            o.bad_txt = 1;
        else if (!strcmp(a, "--bad-cname-rdata"))
            o.bad_cname = 1;
        else if (!strcmp(a, "--multi-a"))
            o.multi_a = 1;
        else if (!strcmp(a, "--multi-aaaa"))
            o.multi_aaaa = 1;
        else if (!strcmp(a, "--multi-mx"))
            o.multi_mx = 1;
        else if (!strcmp(a, "--multi-ns"))
            o.multi_ns = 1;
        else if (!strcmp(a, "--multi-ds"))
            o.multi_ds = 1;
        else if (!strcmp(a, "--multi-dnskey"))
            o.multi_dnskey = 1;
        else if (!strcmp(a, "--multi-soa"))
            o.multi_soa = 1;
        else if (!strcmp(a, "--wrong-source-port"))
            wrong_source_port = 1;
        else if (!strcmp(a, "--storage"))
            storage_enabled = 1;
        else if (!strcmp(a, "--bad-storage-index"))
            bad_storage_index = 1;
        else if (!strcmp(a, "--malformed-storage-index"))
            malformed_storage_index = 1;
        else if (!strncmp(a, "--rcode=", 8))
            o.rcode = atoi(a + 8);
        else if (!strncmp(a, "--delay-ms=", 11))
            o.delay_ms = atoi(a + 11);
        else if (!strncmp(a, "--expect-do=", 12))
            expect_do = atoi(a + 12) == 1;
        else if (!strncmp(a, "--serve-dir=", 12)) {
            serve_dir = a + 12;
            storage_enabled = 1;
        } else if (!strncmp(a, "--bind=", 7))
            bind_addr = a + 7;
        else if (!strcmp(a, "--count-file") && i + 1 < argc)
            count_file = argv[++i];
    }

    for (int i = 0; i < PAYLOAD_LEN; i++)
        payload[i] = i % 251;

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(bind_addr);

    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    int tcp = socket(AF_INET, SOCK_STREAM, 0);

    if (udp < 0 || tcp < 0)
        return perror("socket"), 1;
    if (set_reuse_addr(udp) || set_reuse_addr(tcp))
        return perror("setsockopt"), 1;
    if (bind(udp, (struct sockaddr *) &addr, sizeof(addr)))
        return perror("udp bind"), 1;
    if (bind(tcp, (struct sockaddr *) &addr, sizeof(addr)) || listen(tcp, 8))
        return perror("tcp bind"), 1;

    for (;;) {
        fd_set rfds;
        int maxfd = udp > tcp ? udp : tcp;

        FD_ZERO(&rfds);
        FD_SET(udp, &rfds);
        FD_SET(tcp, &rfds);
        if (select(maxfd + 1, &rfds, NULL, NULL, NULL) < 0)
            continue;

        if (FD_ISSET(udp, &rfds)) {
            uint8_t pkt[MAX_PKT], resp[MAX_RESP];
            struct sockaddr_in peer;
            socklen_t plen = sizeof(peer);
            ssize_t n =
                recvfrom(udp, pkt, 512, 0, (struct sockaddr *) &peer, &plen);

            if (n <= 0)
                continue;
            bump_count();
            if (expect_do != -1 && has_edns_do(pkt, n) != expect_do)
                continue;
            struct opts ro = o;
            ro.truncated = truncate_udp;
            if (ro.ttl0_after && query_count > ro.ttl0_after)
                ro.ttl = 0;
            size_t rn = build_response(pkt, n, &ro, resp);
            if (!rn)
                continue;
            if (o.delay_ms > 0)
                usleep((useconds_t) o.delay_ms * 1000);
            if (wrong_source_port) {
                int s = socket(AF_INET, SOCK_DGRAM, 0);

                sendto(s, resp, rn, 0, (struct sockaddr *) &peer, plen);
                close(s);
            } else {
                sendto(udp, resp, rn, 0, (struct sockaddr *) &peer, plen);
            }
        }
        if (FD_ISSET(tcp, &rfds)) {
            struct sockaddr_in peer;
            socklen_t peer_len = sizeof(peer);
            int conn = accept(tcp, (struct sockaddr *) &peer, &peer_len);
            uint8_t lenbuf[2], pkt[MAX_PKT], resp[MAX_RESP];
            struct timeval rcvto = {.tv_sec = 5};
            char peek[4];

            if (conn < 0)
                continue;
            /* Bound the blocking recv so a connect-only client (e.g. a
             * readiness probe) can't starve UDP service.
             */
            setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &rcvto, sizeof(rcvto));
            /* MSG_PEEK leaves the bytes queued, so one peek dispatches both. */
            ssize_t pk = recv(conn, peek, sizeof(peek), MSG_PEEK);

            if (pk == sizeof(peek) && !memcmp(peek, "PUT ", 4)) {
                (void) handle_put(conn, &peer);
                close(conn);
                continue;
            }
            if (pk == sizeof(peek) && !memcmp(peek, "DEL ", 4)) {
                (void) handle_del(conn, &peer);
                close(conn);
                continue;
            }
            if (recv_exact(conn, lenbuf, 2) != 2) {
                close(conn);
                continue;
            }
            size_t want = (lenbuf[0] << 8) | lenbuf[1];
            if (want > sizeof(pkt) ||
                (size_t) recv_exact(conn, pkt, want) != want) {
                close(conn);
                continue;
            }
            bump_count();
            if (expect_do != -1 && has_edns_do(pkt, want) != expect_do) {
                close(conn);
                continue;
            }
            struct opts ro = o;
            ro.truncated = 0;
            if (ro.ttl0_after && query_count > ro.ttl0_after)
                ro.ttl = 0;
            size_t rn = build_response(pkt, want, &ro, resp);
            uint8_t frame[2 + MAX_RESP];

            if (o.delay_ms > 0)
                usleep((useconds_t) o.delay_ms * 1000);
            frame[0] = rn >> 8;
            frame[1] = rn & 0xff;
            memcpy(frame + 2, resp, rn);
            (void) write(conn, frame, rn + 2);
            close(conn);
        }
    }
    return 0;
}
