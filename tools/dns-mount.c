// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <linux/mount.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_fsopen
#define SYS_fsopen __NR_fsopen
#endif
#ifndef SYS_fsmount
#define SYS_fsmount __NR_fsmount
#endif

int main(void)
{
    int fsfd;
    int mfd;
    int saved;

    fsfd = syscall(SYS_fsopen, "dnsfs", 0);
    if (fsfd < 0) {
        perror("fsopen");
        return 2;
    }

    mfd = syscall(SYS_fsmount, fsfd, 0, 0);
    saved = errno;
    close(fsfd);
    if (mfd >= 0) {
        close(mfd);
        fputs("fsmount without source unexpectedly succeeded\n", stderr);
        return 1;
    }
    if (saved != EINVAL) {
        fprintf(stderr, "fsmount without source got %s, want EINVAL\n",
                strerror(saved));
        return 1;
    }

    return 0;
}
