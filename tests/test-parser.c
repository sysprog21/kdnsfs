// SPDX-License-Identifier: GPL-2.0-only
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/parser.h"

#define DNSFS_TEST_CHUNKS 11

static void expect_parse_fail(const uint8_t *buf, size_t len)
{
    struct dns_msg msg;

    assert(dnsfs_parse(buf, len, &msg) < 0);
}

static void selftest(void)
{
    static const uint8_t ok_txt[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x01, 'a',  0x04, 'm',  'i',  'e',  'k',  0x02, 'n',  'l',  0x00, 0x00,
        0x10, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x3c, 0x00, 0x06, 0x05, 'h',  'e',  'l',  'l',  'o',
    };
    static const uint8_t pointer_loop[] = {
        0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c,
    };
    static uint8_t oversized_label[80] = {
        0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 64,
    };
    static const uint8_t lying_rdlength[] = {
        0, 0, 0x81, 0x80, 0, 1,  0, 1, 0, 0, 0, 0, 1, 'a', 0, 0,   16,
        0, 1, 0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 1, 0, 9,   5, 'h', 'e',
    };
    static const uint8_t truncated_rr_mid_name[] = {
        0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1, 3, 'b',
    };
    static const uint8_t empty_answer[] = {
        0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 16, 0, 1,
    };
    static const uint8_t trailing[] = {
        0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1, 0,
    };
    static const uint8_t nxdomain_soa[] = {
        0x12, 0x34, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x07, 'm',  'i',  's',  's',  'i',  'n',  'g',  0x00, 0x00, 0x10, 0x00,
        0x01, 0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03, 'o',  'r',
        'g',  0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x3c,
        0x02, 'n',  's',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03,
        'o',  'r',  'g',  0x00, 0x0a, 'h',  'o',  's',  't',  'm',  'a',  's',
        't',  'e',  'r',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03,
        'o',  'r',  'g',  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10,
        0x00, 0x00, 0x02, 0x58, 0x00, 0x09, 0x3a, 0x80, 0x00, 0x00, 0x00, 0x1e,
    };
    static const uint8_t compressed_mx[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',
        0x03, 'o',  'r',  'g',  0x00, 0x00, 0x0f, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00,
        0x09, 0x00, 0x0a, 0x04, 'm',  'a',  'i',  'l',  0xc0, 0x0c,
    };
    static const uint8_t expanded_mx_rdata[] = {
        0x00, 0x0a, 0x04, 'm', 'a', 'i',  'l', 0x07, 'e', 'x',
        'a',  'm',  'p',  'l', 'e', 0x03, 'o', 'r',  'g', 0x00,
    };
    struct dns_msg msg;
    uint64_t off;
    uint8_t raw[DNSFS_CHUNK_SIZE + 1];
    uint8_t chunk_a[DNSFS_CHUNK_SIZE];
    uint8_t chunk_b[1];
    uint8_t assembled[DNSFS_CHUNK_SIZE + 1];
    uint8_t big_payload[DNSFS_TEST_CHUNKS * DNSFS_CHUNK_SIZE];
    uint8_t big_assembled[DNSFS_TEST_CHUNKS * DNSFS_CHUNK_SIZE];
    char label[DNSFS_MAX_LABEL + 1];
    char big_labels[DNSFS_TEST_CHUNKS][DNSFS_MAX_LABEL + 1];
    size_t raw_len;
    size_t chunk_len;
    size_t i;
    struct dnsfs_chunk_name chunk;
    struct dnsfs_chunk_name chunks[2];
    struct dnsfs_decoded_chunk decoded[2];
    struct dnsfs_decoded_chunk big_decoded[DNSFS_TEST_CHUNKS];
    struct dnsfs_file_meta meta;
    struct dnsfs_index_entry index[2];
    size_t index_count;

    assert(dnsfs_parse(ok_txt, sizeof(ok_txt), &msg) == 0);
    assert(strcmp(msg.qname, "a.miek.nl.") == 0);
    assert(msg.answer_count == 1);
    assert(msg.answers[0].rdlength == 6);
    expect_parse_fail(pointer_loop, sizeof(pointer_loop));
    expect_parse_fail(oversized_label, sizeof(oversized_label));
    expect_parse_fail(lying_rdlength, sizeof(lying_rdlength));
    expect_parse_fail(truncated_rr_mid_name, sizeof(truncated_rr_mid_name));
    expect_parse_fail(trailing, sizeof(trailing));
    assert(dnsfs_parse(empty_answer, sizeof(empty_answer), &msg) == 0);
    assert(msg.answer_count == 0);
    assert(dnsfs_parse(nxdomain_soa, sizeof(nxdomain_soa), &msg) == 0);
    assert(msg.authority_count == 1);
    assert(msg.authorities[0].type == 6);
    assert(dnsfs_parse(compressed_mx, sizeof(compressed_mx), &msg) == 0);
    assert(msg.answers[0].type == 15);
    assert(msg.answers[0].rdlength == sizeof(expanded_mx_rdata));
    assert(!memcmp(msg.answers[0].rdata, expanded_mx_rdata,
                   sizeof(expanded_mx_rdata)));
    assert(dnsfs_base36_u64("zzzzzzzzzzzzzz", 14, &off) == -EINVAL);
    assert(dnsfs_base36_u64("1z", 2, &off) == 0 && off == 71);
    assert(dnsfs_parse_chunk_name("e-50-file", 9, &chunk) == 0);
    assert(chunk.epoch_len == 1 && memcmp(chunk.epoch, "e", 1) == 0);
    assert(chunk.offset == DNSFS_CHUNK_SIZE);
    assert(chunk.name_len == 4 && memcmp(chunk.name, "file", 4) == 0);
    assert(dnsfs_parse_chunk_name("e-1-file", 8, &chunk) == -EINVAL);
    assert(dnsfs_parse_chunk_name("e--file", 7, &chunk) == -EINVAL);
    assert(dnsfs_parse_file_meta("360 100444 1700000000 2 e DEADBEEF", 34,
                                 &meta) == 0);
    assert(meta.size == 360 && meta.mode == 0100444);
    assert(meta.mtime == 1700000000 && meta.chunk_count == 2);
    assert(meta.epoch_len == 1 && memcmp(meta.epoch, "e", 1) == 0);
    assert(meta.file_crc == 0xdeadbeefU);
    assert(dnsfs_parse_file_meta("0 100444 0 0 e 00000000", 23, &meta) == 0);
    assert(meta.size == 0 && meta.chunk_count == 0);
    assert(dnsfs_parse_file_meta("0 100444 0 0 E 00000000", 23, &meta) ==
           -EINVAL);
    assert(dnsfs_parse_file_meta("0 100444 0 0 bad- 00000000", 26, &meta) ==
           -EINVAL);
    assert(dnsfs_parse_file_meta("0 100444 0 0 bad_epoch 00000000", 31,
                                 &meta) == -EINVAL);
    assert(dnsfs_parse_file_meta("360 100444 1700000000 1 e DEADBEEF", 34,
                                 &meta) == -EINVAL);
    assert(dnsfs_parse_file_meta("773094113101 100444 0 4294967295 e 00000000",
                                 43, &meta) == -EOVERFLOW);
    assert(dnsfs_parse_file_meta("360 100444 1700000000 2 e DEADBEE", 33,
                                 &meta) == -EINVAL);
    assert(dnsfs_parse_file_meta("18446744073709551616 100444 0 0 e 00000000",
                                 42, &meta) == -EOVERFLOW);
    assert(dnsfs_parse_file_meta("0 100444 0 0 e 00000000 ", 24, &meta) ==
           -EINVAL);
    assert(dnsfs_parse_file_meta("181 100444 0 2 e 00000000", 25, &meta) == 0);
    assert(dnsfs_build_chunk_label(&meta, "file", 4, DNSFS_CHUNK_SIZE, label,
                                   sizeof(label)) == 9);
    assert(!strcmp(label, "e-50-file"));
    assert(dnsfs_build_chunk_label(&meta, "file", 4, DNSFS_CHUNK_SIZE, label,
                                   4) == -ENOSPC);
    assert(dnsfs_build_chunk_label(&meta, "file", 4, 2 * DNSFS_CHUNK_SIZE,
                                   label, sizeof(label)) == -EIO);
    /* B8 label-boundary audit: every synthesized label must be proven a valid
     * DNS label (<=63 bytes) before it can hit the wire, not just accepted when
     * parsed back. A name at the 63-byte cap is fine, one past it is EINVAL,
     * and a name that fits alone but pushes "epoch-offset-name" past 63 is
     * rejected with ENAMETOOLONG before the buffer-space check.
     */
    {
        char n63[DNSFS_MAX_LABEL];
        char n64[DNSFS_MAX_LABEL + 1];
        char wide[64];

        memset(n63, 'a', sizeof(n63));
        memset(n64, 'a', sizeof(n64));
        memset(wide, 'a', sizeof(wide));
        assert(dnsfs_build_chunk_label(&meta, n63, DNSFS_MAX_LABEL, 0, label,
                                       sizeof(label)) == -ENAMETOOLONG);
        assert(dnsfs_build_chunk_label(&meta, n64, DNSFS_MAX_LABEL + 1, 0,
                                       label, sizeof(label)) == -EINVAL);
        /* "e" + "-" + "0" + "-" + 60 chars == 64 > 63: the combined-length gate
         * fires even though the name alone (60) is a legal label.
         */
        assert(dnsfs_build_chunk_label(&meta, wide, 60, 0, label,
                                       sizeof(label)) == -ENAMETOOLONG);
    }
    /* B9 untrusted-metadata audit: storage metadata is DNS input, so an
     * overlong epoch label and non-hex CRC text must both be rejected by the
     * parser. The chunk-count overflow, size/chunk-count mismatch, and
     * short-CRC cases are already covered above.
     */
    {
        struct dnsfs_file_meta bad_meta;
        char meta_bad[DNSFS_MAX_TXT];
        int meta_len;
        char epoch64[DNSFS_MAX_LABEL + 1];

        memset(epoch64, 'a', sizeof(epoch64));
        meta_len =
            snprintf(meta_bad, sizeof(meta_bad), "0 100444 0 0 %.*s 00000000",
                     DNSFS_MAX_LABEL + 1, epoch64);
        assert(dnsfs_parse_file_meta(meta_bad, meta_len, &bad_meta) == -EINVAL);
        assert(dnsfs_parse_file_meta("0 100444 0 0 e zzzzzzzz", 23,
                                     &bad_meta) == -EINVAL);
    }
    assert(dnsfs_parse_chunk_name("e-0-file", 8, &chunk) == 0);
    assert(dnsfs_chunk_expected_len(&meta, &chunk, &chunk_len) == 0);
    assert(chunk_len == DNSFS_CHUNK_SIZE);
    assert(dnsfs_parse_chunk_name("e-50-file", 9, &chunk) == 0);
    assert(dnsfs_chunk_expected_len(&meta, &chunk, &chunk_len) == 0);
    assert(chunk_len == 1);
    assert(dnsfs_parse_chunk_name("e-a0-file", 9, &chunk) == 0);
    assert(dnsfs_chunk_expected_len(&meta, &chunk, &chunk_len) == -EIO);
    assert(dnsfs_parse_chunk_name("f-0-file", 8, &chunk) == 0);
    assert(dnsfs_chunk_expected_len(&meta, &chunk, &chunk_len) == -EIO);
    assert(dnsfs_parse_chunk_name("e-50-file", 9, &chunks[0]) == 0);
    assert(dnsfs_parse_chunk_name("e-0-file", 8, &chunks[1]) == 0);
    assert(dnsfs_validate_chunk_set(&meta, chunks, 2) == 0);
    assert(dnsfs_validate_chunk_set(&meta, chunks, 1) == -EIO);
    chunks[1] = chunks[0];
    assert(dnsfs_validate_chunk_set(&meta, chunks, 2) == -EIO);
    assert(dnsfs_base64_decode("aGVsbG8=", 8, raw, sizeof(raw), &raw_len) == 0);
    assert(raw_len == 5 && memcmp(raw, "hello", 5) == 0);
    assert(dnsfs_base64_decode("QUFB", 4, raw, 2, &raw_len) == -ENOSPC);
    assert(dnsfs_base64_decode("AA=A", 4, raw, sizeof(raw), &raw_len) ==
           -EINVAL);
    assert(dnsfs_base64_decode("AB==", 4, raw, sizeof(raw), &raw_len) ==
           -EINVAL);
    assert(dnsfs_base64_decode("AAB=", 4, raw, sizeof(raw), &raw_len) ==
           -EINVAL);
    assert(dnsfs_crc32c_verify((const uint8_t *) "123456789", 9, 0xe3069283U) ==
           0);
    assert(dnsfs_crc32c_verify((const uint8_t *) "123456789", 9, 0) == -EIO);
    assert(dnsfs_decode_chunk_payload("MTIzNDU2Nzg5", 12, 0xe3069283U, raw,
                                      sizeof(raw), &raw_len) == 0);
    assert(raw_len == 9 && memcmp(raw, "123456789", 9) == 0);
    assert(dnsfs_decode_chunk_payload("MTIzNDU2Nzg5", 12, 0, raw, sizeof(raw),
                                      &raw_len) == -EIO);
    assert(dnsfs_parse_file_meta("9 100444 0 1 e 00000000", 23, &meta) == 0);
    assert(dnsfs_parse_chunk_name("e-0-file", 8, &chunk) == 0);
    assert(dnsfs_decode_file_chunk(&meta, &chunk, "MTIzNDU2Nzg5", 12,
                                   0xe3069283U, raw, sizeof(raw),
                                   &raw_len) == 0);
    assert(raw_len == 9);
    assert(dnsfs_parse_file_meta("8 100444 0 1 e 00000000", 23, &meta) == 0);
    assert(dnsfs_decode_file_chunk(&meta, &chunk, "MTIzNDU2Nzg5", 12,
                                   0xe3069283U, raw, sizeof(raw),
                                   &raw_len) == -EIO);
    assert(dnsfs_parse_file_meta("9 100444 0 1 e E3069283", 23, &meta) == 0);
    assert(dnsfs_verify_file_payload(&meta, (const uint8_t *) "123456789", 9) ==
           0);
    assert(dnsfs_parse_file_meta("8 100444 0 1 e E3069283", 23, &meta) == 0);
    assert(dnsfs_verify_file_payload(&meta, (const uint8_t *) "123456789", 9) ==
           -EIO);
    assert(dnsfs_parse_file_meta("9 100444 0 1 e 00000000", 23, &meta) == 0);
    assert(dnsfs_verify_file_payload(&meta, (const uint8_t *) "123456789", 9) ==
           -EIO);
    memset(chunk_a, 'A', sizeof(chunk_a));
    chunk_b[0] = 'B';
    assert(dnsfs_parse_file_meta("181 100444 0 2 e 872BBD5F", 25, &meta) == 0);
    assert(dnsfs_parse_chunk_name("e-50-file", 9, &decoded[0].name) == 0);
    decoded[0].data = chunk_b;
    decoded[0].len = sizeof(chunk_b);
    assert(dnsfs_parse_chunk_name("e-0-file", 8, &decoded[1].name) == 0);
    decoded[1].data = chunk_a;
    decoded[1].len = sizeof(chunk_a);
    assert(dnsfs_reassemble_file_payload(&meta, decoded, 2, assembled,
                                         sizeof(assembled)) == 0);
    assert(!memcmp(assembled, chunk_a, sizeof(chunk_a)));
    assert(assembled[DNSFS_CHUNK_SIZE] == 'B');
    assert(dnsfs_reassemble_file_payload(&meta, decoded, 2, assembled,
                                         DNSFS_CHUNK_SIZE) == -ENOSPC);
    chunk_b[0] = 'C';
    assert(dnsfs_reassemble_file_payload(&meta, decoded, 2, assembled,
                                         sizeof(assembled)) == -EIO);
    for (i = 0; i < sizeof(big_payload); i++)
        big_payload[i] = (uint8_t) (i * 17 + 3);
    assert(dnsfs_parse_file_meta("1980 100444 0 11 e D14ED2DF", 27, &meta) ==
           0);
    for (i = 0; i < DNSFS_TEST_CHUNKS; i++) {
        size_t order = (i * 7) % DNSFS_TEST_CHUNKS;
        u64 offset = order * DNSFS_CHUNK_SIZE;
        int label_len;

        label_len = dnsfs_build_chunk_label(
            &meta, "big", 3, offset, big_labels[i], sizeof(big_labels[i]));
        assert(label_len > 0);
        assert(dnsfs_parse_chunk_name(big_labels[i], label_len,
                                      &big_decoded[i].name) == 0);
        big_decoded[i].data = big_payload + offset;
        big_decoded[i].len = DNSFS_CHUNK_SIZE;
    }
    assert(dnsfs_reassemble_file_payload(&meta, big_decoded, DNSFS_TEST_CHUNKS,
                                         big_assembled,
                                         sizeof(big_assembled)) == 0);
    assert(!memcmp(big_assembled, big_payload, sizeof(big_payload)));
    assert(dnsfs_parse_index_txt("alpha\nbeta-1\n", 13, index, 2,
                                 &index_count) == 0);
    assert(index_count == 2);
    assert(index[0].name_len == 5 && !memcmp(index[0].name, "alpha", 5));
    assert(index[1].name_len == 6 && !memcmp(index[1].name, "beta-1", 6));
    assert(dnsfs_parse_index_txt("alpha\nalpha", 11, index, 2, &index_count) ==
           -EIO);
    assert(dnsfs_parse_index_txt("Alpha", 5, index, 2, &index_count) ==
           -EINVAL);
    assert(dnsfs_parse_index_txt("-bad", 4, index, 2, &index_count) == -EINVAL);
    assert(dnsfs_parse_index_txt("bad-", 4, index, 2, &index_count) == -EINVAL);
    assert(dnsfs_parse_index_txt("alpha\n\nbeta", 11, index, 2, &index_count) ==
           -EINVAL);
    assert(dnsfs_parse_index_txt("alpha\nbeta", 10, index, 1, &index_count) ==
           -ENOSPC);
}

static uint32_t xorshift32(uint32_t *state)
{
    uint32_t x = *state;

    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static void fuzz_runs(unsigned long runs)
{
    uint8_t buf[512];
    struct dns_msg msg;
    uint32_t state = 0x12345678;
    unsigned long i;

    for (i = 0; i < runs; i++) {
        size_t j;
        size_t len = xorshift32(&state) % sizeof(buf);

        for (j = 0; j < len; j++)
            buf[j] = xorshift32(&state) & 0xff;
        (void) dnsfs_parse(buf, len, &msg);
    }
}

int main(int argc, char **argv)
{
    uint8_t buf[4096];
    size_t len = fread(buf, 1, sizeof(buf), stdin);
    struct dns_msg msg;

    if (len)
        (void) dnsfs_parse(buf, len, &msg);
    else if (argc > 1)
        fuzz_runs(strtoul(argv[1], NULL, 10));
    else
        selftest();
    return 0;
}
