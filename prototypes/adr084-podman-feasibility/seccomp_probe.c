#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void fail(const char *message) {
    dprintf(STDERR_FILENO, "seccomp-probe-error:%s:%s\n", message,
            strerror(errno));
    _exit(73);
}

static uint64_t monotonic_nanoseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
        fail("clock");
    }
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

static void transfer_byte(int descriptor, bool write_byte, const char *message) {
    char byte = 'S';
    ssize_t amount;
    do {
        amount = write_byte ? write(descriptor, &byte, 1)
                            : read(descriptor, &byte, 1);
    } while (amount < 0 && errno == EINTR);
    if (amount != 1 || (!write_byte && byte != 'S')) {
        errno = EPROTO;
        fail(message);
    }
}

static void child_wait_for_start(int ready_write, int start_read) {
    transfer_byte(ready_write, true, "child-ready");
    close(ready_write);
    transfer_byte(start_read, false, "child-start");
    close(start_read);
}

static uint64_t parent_start_child(int ready_read, int start_write) {
    transfer_byte(ready_read, false, "parent-ready");
    close(ready_read);
    uint64_t deadline = monotonic_nanoseconds() + 100000000ULL;
    transfer_byte(start_write, true, "parent-start");
    close(start_write);
    return deadline;
}

static int wait_bounded(pid_t child, uint64_t deadline) {
    for (;;) {
        int status = 0;
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) {
            return status;
        }
        if (result == -1) {
            fail("wait");
        }
        if (monotonic_nanoseconds() >= deadline) {
            if (kill(child, SIGKILL) == -1 && errno != ESRCH) {
                fail("timeout-kill");
            }
            if (waitpid(child, &status, 0) != child) {
                fail("timeout-wait");
            }
            errno = ETIMEDOUT;
            fail("child-timeout");
        }
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
        if (nanosleep(&pause, NULL) == -1 && errno != EINTR) {
            fail("nanosleep");
        }
    }
}

static int expect_sigsys_exec(const char *path) {
    int ready_pipe[2];
    int start_pipe[2];
    if (pipe2(ready_pipe, O_CLOEXEC) == -1 ||
        pipe2(start_pipe, O_CLOEXEC) == -1) {
        fail("foreign-start-pipe");
    }
    pid_t child = fork();
    if (child == -1) {
        fail("foreign-fork");
    }
    if (child == 0) {
        close(ready_pipe[0]);
        close(start_pipe[1]);
        child_wait_for_start(ready_pipe[1], start_pipe[0]);
        char *const arguments[] = {(char *)path, NULL};
        char *const environment[] = {NULL};
        execve(path, arguments, environment);
        _exit(90);
    }
    close(ready_pipe[1]);
    close(start_pipe[0]);
    uint64_t deadline = parent_start_child(ready_pipe[0], start_pipe[1]);
    int status = wait_bounded(child, deadline);
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGSYS) {
        errno = EPROTO;
        fail("foreign-outcome");
    }
    return WTERMSIG(status);
}

#if defined(__x86_64__)
static long raw_syscall_number(uint64_t number) {
    register uint64_t accumulator __asm__("rax") = number;
    __asm__ volatile("syscall"
                     : "+a"(accumulator)
                     :
                     : "rcx", "r11", "memory");
    return (long)accumulator;
}

static int expect_high_bit_sigsys(void) {
    int ready_pipe[2];
    int start_pipe[2];
    if (pipe2(ready_pipe, O_CLOEXEC) == -1 ||
        pipe2(start_pipe, O_CLOEXEC) == -1) {
        fail("high-bit-start-pipe");
    }
    pid_t child = fork();
    if (child == -1) {
        fail("high-bit-fork");
    }
    if (child == 0) {
        close(ready_pipe[0]);
        close(start_pipe[1]);
        child_wait_for_start(ready_pipe[1], start_pipe[0]);
        (void)raw_syscall_number(0x40000000ULL);
        _exit(90);
    }
    close(ready_pipe[1]);
    close(start_pipe[0]);
    uint64_t deadline = parent_start_child(ready_pipe[0], start_pipe[1]);
    int status = wait_bounded(child, deadline);
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGSYS) {
        errno = EPROTO;
        fail("high-bit-outcome");
    }
    return WTERMSIG(status);
}

static long expect_sentinel_errno(void) {
    int result_pipe[2];
    int ready_pipe[2];
    int start_pipe[2];
    if (pipe2(result_pipe, O_CLOEXEC) == -1) {
        fail("sentinel-pipe");
    }
    if (pipe2(ready_pipe, O_CLOEXEC) == -1 ||
        pipe2(start_pipe, O_CLOEXEC) == -1) {
        fail("sentinel-start-pipe");
    }
    pid_t child = fork();
    if (child == -1) {
        fail("sentinel-fork");
    }
    if (child == 0) {
        close(ready_pipe[0]);
        close(start_pipe[1]);
        if (close(result_pipe[0]) == -1) {
            _exit(91);
        }
        child_wait_for_start(ready_pipe[1], start_pipe[0]);
        long result = raw_syscall_number(0xffffffffULL);
        if (write(result_pipe[1], &result, sizeof(result)) !=
            (ssize_t)sizeof(result)) {
            _exit(92);
        }
        _exit(0);
    }
    if (close(result_pipe[1]) == -1) {
        fail("sentinel-close-write");
    }
    close(ready_pipe[1]);
    close(start_pipe[0]);
    uint64_t deadline = parent_start_child(ready_pipe[0], start_pipe[1]);
    int status = wait_bounded(child, deadline);
    long result = 0;
    ssize_t amount = read(result_pipe[0], &result, sizeof(result));
    if (close(result_pipe[0]) == -1) {
        fail("sentinel-close-read");
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
        amount != (ssize_t)sizeof(result) || result != -4094) {
        errno = EPROTO;
        fail("sentinel-outcome");
    }
    return result;
}
#endif

int main(void) {
    int foreign_signal = expect_sigsys_exec("/foreign-probe");
#if defined(__x86_64__)
    int high_bit_signal = expect_high_bit_sigsys();
    long sentinel = expect_sentinel_errno();
    dprintf(STDOUT_FILENO,
            "{\"architecture\":\"x86_64\",\"foreign_signal\":%d,"
            "\"high_bit_signal\":%d,\"sentinel_raw\":%ld}\n",
            foreign_signal, high_bit_signal, sentinel);
#elif defined(__aarch64__)
    dprintf(STDOUT_FILENO,
            "{\"architecture\":\"aarch64\",\"foreign_signal\":%d}\n",
            foreign_signal);
#else
#error unsupported native architecture
#endif
    return 0;
}
