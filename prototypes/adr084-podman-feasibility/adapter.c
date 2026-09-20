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
        bool tasks_prefix = length <= eai1_tasks_len &&
                            memcmp(input, eai1_tasks, length) == 0;
        bool cpu_prefix = length <= eai1_cpu_len &&
                          memcmp(input, eai1_cpu, length) == 0;
        bool file_prefix = length <= eai1_file_len &&
                           memcmp(input, eai1_file, length) == 0;
        bool work_prefix = length <= eai1_work_len &&
                           memcmp(input, eai1_work, length) == 0;
        bool watchdog_prefix = length <= eai1_watchdog_len &&
                               memcmp(input, eai1_watchdog, length) == 0;
        if (!hello_prefix && !hold_prefix && !memory_prefix && !tasks_prefix &&
            !cpu_prefix && !file_prefix && !work_prefix && !watchdog_prefix) {
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
        pid_t allocator = fork();
        if (allocator == -1) {
            fail("memory-fork");
        }
        if (allocator == 0) {
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
        int allocator_status = 0;
        if (waitpid(allocator, &allocator_status, 0) != allocator) {
            fail("memory-wait");
        }
        if (!WIFSIGNALED(allocator_status) || WTERMSIG(allocator_status) != SIGKILL) {
            errno = EPROTO;
            fail("memory-child-result");
        }
        dprintf(STDERR_FILENO, "MEMORY_OOM_CHILD signal=%d\n", SIGKILL);
        for (;;) {
            pause();
        }
    }
    if (length == eai1_tasks_len && memcmp(input, eai1_tasks, length) == 0) {
        size_t children = 0;
        for (;;) {
            pid_t child = fork();
            if (child == -1) {
                if (errno != EAGAIN) {
                    fail("task-fork");
                }
                dprintf(STDERR_FILENO, "TASK_LIMIT children=%zu errno=%d\n", children,
                        errno);
                for (;;) {
                    pause();
                }
            }
            if (child == 0) {
                for (;;) {
                    pause();
                }
            }
            children += 1;
        }
    }
    if (length == eai1_cpu_len && memcmp(input, eai1_cpu, length) == 0) {
        volatile unsigned long counter = 0;
        for (;;) {
            counter += 1;
        }
    }
    if (length == eai1_file_len && memcmp(input, eai1_file, length) == 0) {
        int file = open("/work/file-limit", O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
        if (file == -1) {
            fail("file-limit-open");
        }
        unsigned char block[4096] = {0};
        for (;;) {
            ssize_t written = write(file, block, sizeof(block));
            if (written != (ssize_t)sizeof(block)) {
                fail("file-limit-write-without-sigxfsz");
            }
        }
    }
    if (length == eai1_work_len && memcmp(input, eai1_work, length) == 0) {
        unsigned char block[4096] = {0};
        for (unsigned int file_index = 0;; ++file_index) {
            char path[64];
            int path_length = snprintf(path, sizeof(path), "/work/block-%u", file_index);
            if (path_length < 0 || (size_t)path_length >= sizeof(path)) {
                errno = EPROTO;
                fail("work-path");
            }
            int file = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
            if (file == -1) {
                if (errno != ENOSPC) {
                    fail("work-open");
                }
                dprintf(STDERR_FILENO, "WORK_LIMIT operation=open errno=%d\n", errno);
                for (;;) {
                    pause();
                }
            }
            for (unsigned int block_index = 0; block_index < 4; ++block_index) {
                ssize_t written = write(file, block, sizeof(block));
                if (written != (ssize_t)sizeof(block)) {
                    int write_errno = errno;
                    if (close(file) == -1) {
                        fail("work-close-after-write");
                    }
                    if (write_errno != ENOSPC) {
                        errno = write_errno;
                        fail("work-write");
                    }
                    dprintf(STDERR_FILENO, "WORK_LIMIT operation=write errno=%d\n",
                            write_errno);
                    for (;;) {
                        pause();
                    }
                }
            }
            if (close(file) == -1) {
                fail("work-close");
            }
        }
    }
    if (length == eai1_watchdog_len &&
        memcmp(input, eai1_watchdog, length) == 0) {
        for (;;) {
            pause();
        }
    }
    if (length != eai1_hello_len || memcmp(input, eai1_hello, length) != 0) {
        errno = EPROTO;
        fail("input-selection");
    }
    write_all(eao1_hello, eao1_hello_len);
    return 0;
}
