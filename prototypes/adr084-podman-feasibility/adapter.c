#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "adapter_transport_vectors.h"

extern char **environ;

static void fail(const char *message) {
    dprintf(STDERR_FILENO, "adapter-error:%s:%s\n", message, strerror(errno));
    _exit(71);
}

static void write_all(const unsigned char *bytes, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(STDOUT_FILENO, bytes + offset, length - offset);
        if (written <= 0) {
            fail("output");
        }
        offset += (size_t)written;
    }
}

static void verify_boundary(void) {
    bool seen[3] = {false, false, false};
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) {
        fail("descriptor-directory");
    }
    int scan_fd = dirfd(directory);
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) {
                fail("descriptor-read");
            }
            break;
        }
        char *end = NULL;
        long fd = strtol(entry->d_name, &end, 10);
        if (end == entry->d_name || *end != '\0') {
            continue;
        }
        if (fd == scan_fd) {
            continue;
        }
        if (fd < 0 || fd > 2 || seen[fd]) {
            errno = EPROTO;
            fail("extra-fd");
        }
        seen[fd] = true;
    }
    if (closedir(directory) == -1) {
        fail("descriptor-close");
    }
    for (int fd = 0; fd <= 2; ++fd) {
        if (!seen[fd]) {
            errno = EPROTO;
            fail("descriptor-set");
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

    int network = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (network == -1) {
        fail("network-socket");
    }
    struct sockaddr_in unreachable = {
        .sin_family = AF_INET,
        .sin_port = htons(9),
        .sin_addr = {.s_addr = htonl(0xcb007101)},
    };
    errno = 0;
    int connected = connect(network, (struct sockaddr *)&unreachable,
                            sizeof(unreachable));
    int connect_errno = errno;
    if (close(network) == -1) {
        fail("network-close");
    }
    if (connected != -1 || connect_errno != ENETUNREACH) {
        errno = EPROTO;
        fail("network-egress");
    }
}

int main(void) {
    unsigned char input[4096];
    size_t length = 0;
    verify_boundary();
    for (;;) {
        if (length == sizeof(input)) {
            errno = EPROTO;
            fail("input-limit");
        }
        ssize_t received = read(STDIN_FILENO, input + length, sizeof(input) - length);
        if (received < 0) {
            fail("input-read");
        }
        if (received == 0) {
            break;
        }
        length += (size_t)received;
        bool hello_prefix = length <= eai1_hello_len &&
                            memcmp(input, eai1_hello, length) == 0;
        bool hold_prefix = length <= eai1_hold_len &&
                           memcmp(input, eai1_hold, length) == 0;
        bool memory_prefix = length <= eai1_memory_len &&
                             memcmp(input, eai1_memory, length) == 0;
        if (!hello_prefix && !hold_prefix && !memory_prefix) {
            errno = EPROTO;
            fail("input-authentication");
        }
    }

    if (length == eai1_hold_len && memcmp(input, eai1_hold, length) == 0) {
        pid_t child = fork();
        if (child == -1) {
            fail("fork");
        }
        if (child == 0) {
            for (;;) {
                pause();
            }
        }
        dprintf(STDERR_FILENO, "HOLDING child=%ld\n", (long)child);
        for (;;) {
            pause();
        }
    }
    if (length == eai1_memory_len && memcmp(input, eai1_memory, length) == 0) {
        const size_t allocation_size = 8U * 1024U * 1024U;
        for (;;) {
            volatile unsigned char *allocation = malloc(allocation_size);
            if (allocation == NULL) {
                fail("memory-allocation");
            }
            for (size_t offset = 0; offset < allocation_size; offset += 4096U) {
                allocation[offset] = (unsigned char)(offset >> 12);
            }
        }
    }
    if (length != eai1_hello_len || memcmp(input, eai1_hello, length) != 0) {
        errno = EPROTO;
        fail("input-selection");
    }
    write_all(eao1_hello, eao1_hello_len);
    return 0;
}
