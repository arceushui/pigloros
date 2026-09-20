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

static int wait_bounded(pid_t child) {
    uint64_t deadline = monotonic_nanoseconds() + 100000000ULL;
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
    pid_t child = fork();
    if (child == -1) {
        fail("foreign-fork");
    }
    if (child == 0) {
        char *const arguments[] = {(char *)path, NULL};
        char *const environment[] = {NULL};
        execve(path, arguments, environment);
        _exit(90);
    }
    int status = wait_bounded(child);
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
    pid_t child = fork();
    if (child == -1) {
        fail("high-bit-fork");
    }
    if (child == 0) {
        (void)raw_syscall_number(0x40000000ULL);
        _exit(90);
    }
    int status = wait_bounded(child);
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGSYS) {
        errno = EPROTO;
        fail("high-bit-outcome");
    }
    return WTERMSIG(status);
}

static long expect_sentinel_errno(void) {
    int result_pipe[2];
    if (pipe2(result_pipe, O_CLOEXEC) == -1) {
        fail("sentinel-pipe");
    }
    pid_t child = fork();
    if (child == -1) {
        fail("sentinel-fork");
    }
    if (child == 0) {
        if (close(result_pipe[0]) == -1) {
            _exit(91);
        }
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
    int status = wait_bounded(child);
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
