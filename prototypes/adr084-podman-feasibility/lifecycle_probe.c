#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

static void fail(const char *message) {
    dprintf(STDERR_FILENO, "lifecycle-probe-error:%s:%d\n", message, errno);
    _exit(71);
}

int main(void) {
    pid_t child = fork();
    if (child == -1) {
        fail("fork");
    }
    if (child == 0) {
        for (;;) {
            pause();
        }
    }
    dprintf(STDERR_FILENO, "LIFECYCLE_PROBE parent=%ld child=%ld\n", (long)getpid(),
            (long)child);
    for (;;) {
        pause();
    }
}
