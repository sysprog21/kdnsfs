// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

struct linux_dirent64 {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

int main(int argc, char **argv)
{
    char buf[4096];
    const char *buf_env;
    size_t buf_len = sizeof(buf);
    int fd;
    int ret;
    int i;
    bool found[64] = {};

    if (argc < 3 || argc > 64)
        return 2;
    buf_env = getenv("DNSFS_GETDENTS_BUF");
    if (buf_env) {
        buf_len = strtoul(buf_env, NULL, 10);
        if (!buf_len || buf_len > sizeof(buf))
            return 2;
    }

    fd = open(argv[1], O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    for (;;) {
        ret = syscall(SYS_getdents64, fd, buf, buf_len);
        if (ret < 0) {
            perror("getdents64");
            close(fd);
            return 1;
        }
        if (!ret)
            break;

        for (int off = 0; off < ret;) {
            struct linux_dirent64 *d = (struct linux_dirent64 *) (buf + off);

            for (i = 2; i < argc; i++) {
                if (!strcmp(d->d_name, argv[i]) && d->d_type != DT_UNKNOWN) {
                    fprintf(stderr, "%s d_type=%u, want DT_UNKNOWN\n",
                            d->d_name, d->d_type);
                    close(fd);
                    return 1;
                }
                if (!strcmp(d->d_name, argv[i]))
                    found[i] = true;
            }
            off += d->d_reclen;
        }
    }

    for (i = 2; i < argc; i++) {
        if (!found[i]) {
            fprintf(stderr, "missing directory entry: %s\n", argv[i]);
            close(fd);
            return 1;
        }
    }

    close(fd);
    return 0;
}
