#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void fail(const char *message) {
    dprintf(STDERR_FILENO, "adapter-error:%s:%s\n", message, strerror(errno));
    _exit(71);
}

static void verify_boundary(void) {
    for (int fd = 3; fd < 64; ++fd) {
        errno = 0;
        if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) {
            errno = EPROTO;
            fail("extra-fd");
        }
    }
    if (environ[0] == NULL || strcmp(environ[0], "PIGLOROS_PROTOCOL=EAI1") != 0 ||
        environ[1] != NULL) {
        errno = EPROTO;
        fail("environment");
    }

    errno = 0;
    int denied = open("/denied", O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    if (denied != -1 || errno != EROFS) {
        if (denied != -1) {
            close(denied);
        }
        errno = EPROTO;
        fail("read-only-root");
    }

    errno = 0;
    int network = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (network != -1 || errno != EPERM) {
        if (network != -1) {
            close(network);
        }
        errno = EPROTO;
        fail("network-syscall");
    }
}

int main(void) {
    char input[64];
    ssize_t length = read(STDIN_FILENO, input, sizeof(input));
    if (length <= 0) {
        fail("input");
    }
    verify_boundary();

    if (length == 5 && memcmp(input, "HOLD\n", 5) == 0) {
        pid_t child = fork();
        if (child == -1) {
            fail("fork");
        }
        if (child == 0) {
            for (;;) {
                pause();
            }
        }
        dprintf(STDOUT_FILENO, "HOLDING child=%ld\n", (long)child);
        for (;;) {
            pause();
        }
    }

    static const char prefix[] = "EAO1:";
    if (write(STDOUT_FILENO, prefix, sizeof(prefix) - 1) != (ssize_t)(sizeof(prefix) - 1) ||
        write(STDOUT_FILENO, input, (size_t)length) != length) {
        fail("output");
    }
    return 0;
}
