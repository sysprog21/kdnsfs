// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef DNSFS_PUBLISHER_STORE
#define DNSFS_PUBLISHER_STORE "/tmp/kdnsfs-build/publisher-store"
#endif

#define CHUNK_SIZE 180
#define MAX_CHUNKS 64
#define MAX_LABEL 63
#define MAX_FILES 128
#define MAX_LINE 512
#ifndef DEFAULT_CONF
#define DEFAULT_CONF "/etc/dnsfs/nsupdate.conf"
#endif

extern char **environ;

struct config {
    char zone[256];
    char server[256];
    char key[512];
    char state[512];
    char nsupdate[256];
    unsigned int ttl;
};

struct entry {
    char label[MAX_LABEL + 1];
    char epoch[64];
    unsigned int chunks;
};

static uint32_t crc32c(const unsigned char *data, size_t len)
{
    uint32_t crc = 0xffffffffU;

    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ ((crc & 1) ? 0x82f63b78U : 0);
    }
    return crc ^ 0xffffffffU;
}

static int valid_label(const char *s)
{
    size_t n = strlen(s);
    const char *d1, *d2;
    char *end;
    long off;

    if (!n || n > MAX_LABEL || !strcmp(s, "index") || s[0] == '-' ||
        s[n - 1] == '-')
        return 0;
    for (size_t i = 0; i < n; i++)
        if (!islower((unsigned char) s[i]) && !isdigit((unsigned char) s[i]) &&
            s[i] != '-')
            return 0;
    d1 = strchr(s, '-');
    d2 = d1 ? strchr(d1 + 1, '-') : NULL;
    if (d1 && d1 >= s + 1 && s[0] == 'e' && d2 && d2 != d1 + 1 && d2[1]) {
        off = strtol(d1 + 1, &end, 36);
        if (end == d2 && off >= 0 && off % CHUNK_SIZE == 0)
            return 0;
    }
    return 1;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static unsigned char *decode_hex(const char *hex, size_t *out_len)
{
    size_t n = strlen(hex);
    unsigned char *out;

    if (n % 2)
        return NULL;
    out = malloc(n / 2 ? n / 2 : 1);
    if (!out)
        return NULL;
    for (size_t i = 0; i < n; i += 2) {
        int hi = hexval(hex[i]), lo = hexval(hex[i + 1]);

        if (hi < 0 || lo < 0) {
            free(out);
            return NULL;
        }
        out[i / 2] = (unsigned char) ((hi << 4) | lo);
    }
    *out_len = n / 2;
    return out;
}

static int local_put(const char *label, const char *hex)
{
    unsigned char *data;
    size_t len;
    char path[1024], tmp[1060];
    int fd, ret = 1;

    if (!valid_label(label))
        return 1;
    data = decode_hex(hex, &len);
    if (!data)
        return 1;
    if (mkdir(DNSFS_PUBLISHER_STORE, 0755) && errno != EEXIST)
        goto out;
    if (snprintf(path, sizeof(path), "%s/%s", DNSFS_PUBLISHER_STORE, label) >=
        (int) sizeof(path))
        goto out;
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int) sizeof(tmp))
        goto out;
    fd = open(tmp, O_CREAT | O_TRUNC | O_WRONLY | O_NOFOLLOW, 0644);
    if (fd < 0)
        goto out;
    if ((len && write(fd, data, len) != (ssize_t) len) || fsync(fd) ||
        close(fd)) {
        unlink(tmp);
        goto out;
    }
    if (rename(tmp, path))
        goto out;
    ret = 0;
out:
    free(data);
    return ret;
}

static int local_del(const char *label)
{
    char path[1024];

    if (!valid_label(label))
        return 1;
    if (snprintf(path, sizeof(path), "%s/%s", DNSFS_PUBLISHER_STORE, label) >=
        (int) sizeof(path))
        return 1;
    if (unlink(path) && errno != ENOENT)
        return 1;
    return 0;
}

static char *trim(char *s)
{
    char *end;

    while (isspace((unsigned char) *s))
        s++;
    end = s + strlen(s);
    while (end > s && isspace((unsigned char) end[-1]))
        *--end = '\0';
    return s;
}

static int read_config(const char *path, struct config *cfg)
{
    FILE *f = fopen(path, "r");
    char line[MAX_LINE];

    if (!f)
        return -1;
    memset(cfg, 0, sizeof(*cfg));
    cfg->ttl = 60;
    strcpy(cfg->state, "/var/lib/dnsfs-nsupdate/state.txt");
    strcpy(cfg->nsupdate, "nsupdate");
    while (fgets(line, sizeof(line), f)) {
        char *key, *value, *eq;

        key = trim(line);
        if (!*key || *key == '#')
            continue;
        eq = strchr(key, '=');
        if (!eq) {
            fclose(f);
            return -1;
        }
        *eq = '\0';
        value = trim(eq + 1);
        key = trim(key);
        if (!strcmp(key, "zone"))
            snprintf(cfg->zone, sizeof(cfg->zone), "%s", value);
        else if (!strcmp(key, "server"))
            snprintf(cfg->server, sizeof(cfg->server), "%s", value);
        else if (!strcmp(key, "key"))
            snprintf(cfg->key, sizeof(cfg->key), "%s", value);
        else if (!strcmp(key, "state"))
            snprintf(cfg->state, sizeof(cfg->state), "%s", value);
        else if (!strcmp(key, "nsupdate"))
            snprintf(cfg->nsupdate, sizeof(cfg->nsupdate), "%s", value);
        else if (!strcmp(key, "ttl"))
            cfg->ttl = (unsigned int) strtoul(value, NULL, 10);
    }
    fclose(f);
    if (!cfg->zone[0] || !cfg->server[0])
        return -1;
    if (cfg->zone[strlen(cfg->zone) - 1] != '.')
        strncat(cfg->zone, ".", sizeof(cfg->zone) - strlen(cfg->zone) - 1);
    return 0;
}

static int load_state(const char *path, struct entry *entries, size_t *count)
{
    FILE *f = fopen(path, "r");
    char line[MAX_LINE];

    *count = 0;
    if (!f)
        return errno == ENOENT ? 0 : -1;
    while (fgets(line, sizeof(line), f)) {
        struct entry *e = &entries[*count];

        if (*count >= MAX_FILES ||
            sscanf(line, "%63s %63s %u", e->label, e->epoch, &e->chunks) != 3 ||
            !valid_label(e->label) || e->chunks > MAX_CHUNKS) {
            fclose(f);
            return -1;
        }
        (*count)++;
    }
    fclose(f);
    return 0;
}

static int mkdir_p_parent(const char *path)
{
    char tmp[512];
    char *slash;

    snprintf(tmp, sizeof(tmp), "%s", path);
    slash = strrchr(tmp, '/');
    if (!slash)
        return 0;
    *slash = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) && errno != EEXIST)
        return -1;
    return 0;
}

static int save_state(const char *path,
                      const struct entry *entries,
                      size_t count)
{
    char tmp[560];
    FILE *f;

    if (mkdir_p_parent(path))
        return -1;
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    f = fopen(tmp, "w");
    if (!f)
        return -1;
    for (size_t i = 0; i < count; i++)
        fprintf(f, "%s %s %u\n", entries[i].label, entries[i].epoch,
                entries[i].chunks);
    if (fclose(f))
        return -1;
    return rename(tmp, path);
}

static int lock_state(const char *path)
{
    char lock[560];
    int fd;

    if (mkdir_p_parent(path))
        return -1;
    snprintf(lock, sizeof(lock), "%s.lock", path);
    fd = open(lock, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    if (flock(fd, LOCK_EX)) {
        close(fd);
        return -1;
    }
    return fd;
}

static int find_entry(const struct entry *entries,
                      size_t count,
                      const char *label)
{
    for (size_t i = 0; i < count; i++)
        if (!strcmp(entries[i].label, label))
            return (int) i;
    return -1;
}

static void base36(unsigned long n, char *out, size_t out_len)
{
    char tmp[32];
    const char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    size_t pos = 0, o = 0;

    if (!n)
        tmp[pos++] = '0';
    while (n && pos < sizeof(tmp)) {
        tmp[pos++] = digits[n % 36];
        n /= 36;
    }
    while (pos && o + 1 < out_len)
        out[o++] = tmp[--pos];
    out[o] = '\0';
}

static size_t b64(const unsigned char *src, size_t n, char *out)
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
    out[o] = '\0';
    return o;
}

static void txt(FILE *f, const char *s)
{
    fputc('"', f);
    for (; *s; s++) {
        unsigned char c = (unsigned char) *s;

        if (c == '"' || c == '\\')
            fprintf(f, "\\%c", c);
        else if (c < 32 || c >= 127)
            fprintf(f, "\\%03u", c);
        else
            fputc(c, f);
    }
    fputc('"', f);
}

static void fqdn(FILE *f, const char *label, const struct config *cfg)
{
    fprintf(f, "%s.%s", label, cfg->zone);
}

static void delete_existing(FILE *f,
                            const struct config *cfg,
                            const struct entry *entries,
                            size_t count,
                            const char *label)
{
    int idx = find_entry(entries, count, label);

    fputs("update delete ", f);
    fqdn(f, label, cfg);
    fputs(" TXT\n", f);
    if (idx >= 0) {
        for (unsigned int i = 0; i < entries[idx].chunks; i++) {
            char off[32], chunk[160];

            base36((unsigned long) i * CHUNK_SIZE, off, sizeof(off));
            snprintf(chunk, sizeof(chunk), "%s-%s-%s", entries[idx].epoch, off,
                     label);
            fputs("update delete ", f);
            fqdn(f, chunk, cfg);
            fputs(" TXT\n", f);
        }
    }
}

static int write_index(FILE *f,
                       const struct config *cfg,
                       const struct entry *entries,
                       size_t count)
{
    char index[256] = "";

    fputs("update delete ", f);
    fqdn(f, "index", cfg);
    fputs(" TXT\nupdate add ", f);
    fqdn(f, "index", cfg);
    fprintf(f, " %u TXT ", cfg->ttl);
    for (size_t i = 0; i < count; i++) {
        if (strlen(index) + strlen(entries[i].label) + 1 >= sizeof(index))
            return -1;
        strcat(index, entries[i].label);
        strcat(index, "\n");
    }
    txt(f, index);
    fputc('\n', f);
    return 0;
}

static int run_nsupdate(const struct config *cfg, FILE *script)
{
    char path[] = "/tmp/dnsfs-nsupdate.XXXXXX";
    posix_spawn_file_actions_t actions;
    pid_t pid;
    int fd, status;
    char *argv_key[] = {(char *) cfg->nsupdate, "-k", (char *) cfg->key, NULL};
    char *argv_plain[] = {(char *) cfg->nsupdate, NULL};

    fflush(script);
    rewind(script);
    fd = mkstemp(path);
    if (fd < 0)
        return -1;
    for (;;) {
        char buf[4096];
        size_t n = fread(buf, 1, sizeof(buf), script);

        if (n && write(fd, buf, n) != (ssize_t) n) {
            close(fd);
            unlink(path);
            return -1;
        }
        if (n < sizeof(buf))
            break;
    }
    lseek(fd, 0, SEEK_SET);
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, fd, STDIN_FILENO);
    if (posix_spawnp(&pid, cfg->nsupdate, &actions, NULL,
                     cfg->key[0] ? argv_key : argv_plain, environ)) {
        posix_spawn_file_actions_destroy(&actions);
        close(fd);
        unlink(path);
        return -1;
    }
    posix_spawn_file_actions_destroy(&actions);
    close(fd);
    unlink(path);
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int nsupdate_put(const struct config *cfg,
                        const char *label,
                        const char *hex)
{
    unsigned char *data;
    size_t len, count;
    struct entry entries[MAX_FILES];
    int idx, lock_fd, ret;
    FILE *script;
    char epoch[64], meta[256];
    struct timespec ts;

    if (!valid_label(label))
        return 1;
    data = decode_hex(hex, &len);
    if (!data)
        return 1;
    count = (len + CHUNK_SIZE - 1) / CHUNK_SIZE;
    if (count > MAX_CHUNKS) {
        free(data);
        return 1;
    }
    lock_fd = lock_state(cfg->state);
    if (lock_fd < 0) {
        free(data);
        return 1;
    }
    if (load_state(cfg->state, entries, &count)) {
        close(lock_fd);
        free(data);
        return 1;
    }
    script = tmpfile();
    if (!script) {
        close(lock_fd);
        free(data);
        return 1;
    }
    fprintf(script, "server %s\nzone %s\n", cfg->server, cfg->zone);
    delete_existing(script, cfg, entries, count, label);
    if (clock_gettime(CLOCK_REALTIME, &ts))
        ts.tv_sec = time(NULL), ts.tv_nsec = 0;
    snprintf(epoch, sizeof(epoch), "e%llx%lx", (unsigned long long) ts.tv_sec,
             (unsigned long) ts.tv_nsec);
    size_t chunks = (len + CHUNK_SIZE - 1) / CHUNK_SIZE;
    for (size_t i = 0; i < chunks; i++) {
        size_t off = i * CHUNK_SIZE;
        size_t clen = len - off;
        char off36[32], chunk_label[160], payload[320], encoded[256];

        if (clen > CHUNK_SIZE)
            clen = CHUNK_SIZE;
        base36(off, off36, sizeof(off36));
        b64(data + off, clen, encoded);
        snprintf(chunk_label, sizeof(chunk_label), "%s-%s-%s", epoch, off36,
                 label);
        snprintf(payload, sizeof(payload), "%08X %s", crc32c(data + off, clen),
                 encoded);
        fputs("update add ", script);
        fqdn(script, chunk_label, cfg);
        fprintf(script, " %u TXT ", cfg->ttl);
        txt(script, payload);
        fputc('\n', script);
    }
    snprintf(meta, sizeof(meta), "%zu 100444 %ld %zu %s %08X", len,
             (long) time(NULL), chunks, epoch, crc32c(data, len));
    fputs("update add ", script);
    fqdn(script, label, cfg);
    fprintf(script, " %u TXT ", cfg->ttl);
    txt(script, meta);
    fputc('\n', script);
    idx = find_entry(entries, count, label);
    if (idx < 0 && count < MAX_FILES)
        idx = (int) count++;
    else if (idx < 0) {
        fclose(script);
        close(lock_fd);
        free(data);
        return 1;
    }
    if (idx >= 0) {
        snprintf(entries[idx].label, sizeof(entries[idx].label), "%s", label);
        snprintf(entries[idx].epoch, sizeof(entries[idx].epoch), "%s", epoch);
        entries[idx].chunks = (unsigned int) chunks;
    }
    if (write_index(script, cfg, entries, count)) {
        fclose(script);
        close(lock_fd);
        free(data);
        return 1;
    }
    fputs("send\n", script);
    ret = run_nsupdate(cfg, script) || save_state(cfg->state, entries, count);
    fclose(script);
    close(lock_fd);
    free(data);
    return ret ? 1 : 0;
}

static int nsupdate_del(const struct config *cfg, const char *label)
{
    struct entry entries[MAX_FILES];
    size_t count;
    int idx, lock_fd, ret;
    FILE *script;

    if (!valid_label(label))
        return 1;
    lock_fd = lock_state(cfg->state);
    if (lock_fd < 0)
        return 1;
    if (load_state(cfg->state, entries, &count)) {
        close(lock_fd);
        return 1;
    }
    script = tmpfile();
    if (!script) {
        close(lock_fd);
        return 1;
    }
    fprintf(script, "server %s\nzone %s\n", cfg->server, cfg->zone);
    delete_existing(script, cfg, entries, count, label);
    idx = find_entry(entries, count, label);
    if (idx >= 0) {
        memmove(&entries[idx], &entries[idx + 1],
                (count - (size_t) idx - 1) * sizeof(entries[0]));
        count--;
    }
    if (write_index(script, cfg, entries, count)) {
        fclose(script);
        close(lock_fd);
        return 1;
    }
    fputs("send\n", script);
    ret = run_nsupdate(cfg, script) || save_state(cfg->state, entries, count);
    fclose(script);
    close(lock_fd);
    return ret ? 1 : 0;
}

static int self_test(void)
{
    unsigned char hello[] = "hello";
    char out[16];

    base36(180, out, sizeof(out));
    return !(valid_label("hello") && !valid_label("index") &&
             !strcmp(out, "50") && crc32c(hello, 5) == 0x9a71bb4cU);
}

int main(int argc, char **argv)
{
    const char *conf_path = getenv("DNSFS_NSUPDATE_CONF");
    int explicit_conf = !!conf_path;
    struct config cfg;

    if (argc == 2 && !strcmp(argv[1], "--self-test"))
        return self_test();
    if (!conf_path)
        conf_path = DEFAULT_CONF;
    if (argc < 3)
        return 1;
    if (!read_config(conf_path, &cfg)) {
        if (!strcmp(argv[1], "put") && argc == 4)
            return nsupdate_put(&cfg, argv[2], argv[3]);
        if (!strcmp(argv[1], "del") && argc == 3)
            return nsupdate_del(&cfg, argv[2]);
        return 1;
    }
    if (explicit_conf || access(conf_path, F_OK) == 0)
        return 1;
    if (!strcmp(argv[1], "put") && argc == 4)
        return local_put(argv[2], argv[3]);
    if (!strcmp(argv[1], "del") && argc == 3)
        return local_del(argv[2]);
    return 1;
}
