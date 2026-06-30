/* SPDX-License-Identifier: GPL-2.0-only */

/* Shared parser/wire definitions for the dnsfs trust boundary. The structs and
 * prototypes here describe the UNTRUSTED DNS and storage input decoded by
 * parser.c. This header also compiles in userspace: the __KERNEL__ shim below
 * supplies the u8/u16/u32/u64 types so the parser and its fuzzer build without
 * kernel headers.
 */

#ifndef DNSFS_PARSER_H
#define DNSFS_PARSER_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#include <stdint.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#endif

/* RFC 1035 caps: a domain name is <=255 octets, a single label <=63. */
#define DNSFS_MAX_NAME 255

/* Bounds the fixed answers[]/authorities[] arrays in struct dns_msg. */
#define DNSFS_MAX_RR 8
#define DNSFS_MAX_RDATA 255
#define DNSFS_MAX_TXT 255

/* Raw bytes per stored chunk. Chosen so base64 (4/3 growth) of one full chunk
 * still fits a single 255-byte DNS TXT string: 180 -> 240.
 */
#define DNSFS_CHUNK_SIZE 180

/* The top two bits of a label's length octet are reserved for the
 * compression-pointer tag, so a real label length maxes out at 63.
 */
#define DNSFS_MAX_LABEL 63
#define DNSFS_MAX_INDEX_ENTRIES 32

/* Big-endian wire accessors, shared by the parser and the kernel client. */
static inline u16 dnsfs_get16(const u8 *p)
{
    return ((u16) p[0] << 8) | p[1];
}

static inline u32 dnsfs_get32(const u8 *p)
{
    return ((u32) p[0] << 24) | ((u32) p[1] << 16) | ((u32) p[2] << 8) | p[3];
}

/* A chunk name "{epoch}-{base36 offset}-{name}" split in place: every pointer
 * aliases the source buffer (zero-copy), so the backing string must outlive
 * this struct. offset is the byte position within the file and is always a
 * multiple of DNSFS_CHUNK_SIZE.
 */
struct dnsfs_chunk_name {
    const char *epoch;
    size_t epoch_len;
    u64 offset;
    const char *name;
    size_t name_len;
};

/* Decoded index-TXT line "size mode mtime chunk_count epoch crc32c".
 * chunk_count is cross-checked against ceil(size/CHUNK_SIZE); epoch tags one
 * storage generation so stale chunks cannot be mixed into a fresh file;
 * file_crc covers the whole reassembled payload (integrity only, not
 * anti-poisoning). epoch aliases the source buffer.
 */
struct dnsfs_file_meta {
    u64 size;
    u32 mode;
    u64 mtime;
    u32 chunk_count;
    const char *epoch;
    size_t epoch_len;
    u32 file_crc;
};

struct dnsfs_decoded_chunk {
    struct dnsfs_chunk_name name;
    const u8 *data;
    size_t len;
};

struct dnsfs_index_entry {
    const char *name;
    size_t name_len;
};

struct dns_rr {
    char name[DNSFS_MAX_NAME + 1];
    u16 type;
    u16 class;
    u32 ttl;
    u16 rdlength;
    u8 rdata[DNSFS_MAX_RDATA];
};

struct dns_msg {
    u16 id;
    u16 flags;
    u16 qdcount;
    u16 ancount;
    u16 nscount;
    u16 arcount;
    char qname[DNSFS_MAX_NAME + 1];
    u16 qtype;
    u16 qclass;
    /* *_count are how many RRs were actually parsed and stored below; the wire
     * ancount/nscount above are only what the header claimed.
     */
    unsigned int answer_count;
    unsigned int authority_count;
    struct dns_rr answers[DNSFS_MAX_RR];
    struct dns_rr authorities[DNSFS_MAX_RR];
};

int dnsfs_parse(const u8 *buf, size_t len, struct dns_msg *out);
int dnsfs_base36_u64(const char *s, size_t len, u64 *out);
int dnsfs_parse_hex32(const char *s, size_t len, u32 *out);
int dnsfs_parse_chunk_name(const char *s,
                           size_t len,
                           struct dnsfs_chunk_name *out);
int dnsfs_parse_file_meta(const char *s,
                          size_t len,
                          struct dnsfs_file_meta *out);
int dnsfs_build_chunk_label(const struct dnsfs_file_meta *meta,
                            const char *name,
                            size_t name_len,
                            u64 offset,
                            char *out,
                            size_t out_len);
int dnsfs_chunk_expected_len(const struct dnsfs_file_meta *meta,
                             const struct dnsfs_chunk_name *chunk,
                             size_t *expected_len);
int dnsfs_validate_chunk_set(const struct dnsfs_file_meta *meta,
                             const struct dnsfs_chunk_name *chunks,
                             size_t count);
int dnsfs_base64_decode(const char *src,
                        size_t len,
                        u8 *dst,
                        size_t dst_len,
                        size_t *out_len);
int dnsfs_crc32c_verify(const u8 *buf, size_t len, u32 expected);
int dnsfs_decode_chunk_payload(const char *src,
                               size_t len,
                               u32 expected_crc,
                               u8 *dst,
                               size_t dst_len,
                               size_t *out_len);
int dnsfs_decode_file_chunk(const struct dnsfs_file_meta *meta,
                            const struct dnsfs_chunk_name *chunk,
                            const char *src,
                            size_t len,
                            u32 expected_crc,
                            u8 *dst,
                            size_t dst_len,
                            size_t *out_len);
int dnsfs_verify_file_payload(const struct dnsfs_file_meta *meta,
                              const u8 *buf,
                              size_t len);
int dnsfs_reassemble_file_payload(const struct dnsfs_file_meta *meta,
                                  const struct dnsfs_decoded_chunk *chunks,
                                  size_t count,
                                  u8 *dst,
                                  size_t dst_len);
int dnsfs_parse_index_txt(const char *src,
                          size_t len,
                          struct dnsfs_index_entry *entries,
                          size_t max_entries,
                          size_t *count);

#endif
