#define _GNU_SOURCE

#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static void fail(const char *message) {
    dprintf(STDERR_FILENO, "prefilter-error:%s:%s\n", message, strerror(errno));
    _exit(74);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        errno = EINVAL;
        fail("usage");
    }
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(instructions) / sizeof(instructions[0])),
        .filter = instructions,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 ||
        syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) == -1) {
        fail("install");
    }
    execvp(argv[1], &argv[1]);
    fail("exec");
}
