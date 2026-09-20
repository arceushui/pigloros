/* Throwaway native syscall matrix; never production code. */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_SYSCALL_NUMBER 4096
#define MAX_NAME_LENGTH 63
#define DEADLINE_NANOSECONDS 100000000L

struct syscall_record {
    bool allowed;
    char name[MAX_NAME_LENGTH + 1];
};

static void fail(const char *message) {
    dprintf(STDERR_FILENO, "native-matrix-error:%s:%s\n", message,
            strerror(errno));
    _exit(74);
}

static int64_t monotonic_nanoseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        fail("clock");
    }
    return (int64_t)now.tv_sec * 1000000000LL + now.tv_nsec;
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

static long raw_syscall_six(long number) {
#if defined(__x86_64__)
    register long fourth __asm__("r10") = 0;
    register long fifth __asm__("r8") = 0;
    register long sixth __asm__("r9") = 0;
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(0L), "S"(0L), "d"(0L), "r"(fourth),
                       "r"(fifth), "r"(sixth)
                     : "rcx", "r11", "memory");
    return result;
#elif defined(__aarch64__)
    register long x0 __asm__("x0") = 0;
    register long x1 __asm__("x1") = 0;
    register long x2 __asm__("x2") = 0;
    register long x3 __asm__("x3") = 0;
    register long x4 __asm__("x4") = 0;
    register long x5 __asm__("x5") = 0;
    register long x8 __asm__("x8") = number;
    __asm__ volatile("svc 0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
                     : "memory");
    return x0;
#else
#error unsupported architecture
#endif
}

static int load_interface(struct syscall_record *records) {
    FILE *input = fopen("/libseccomp-interface-v1.txt", "re");
    if (input == NULL) {
        fail("interface-open");
    }
    char line[128];
    int maximum = -1;
    while (fgets(line, sizeof(line), input) != NULL) {
        size_t length = strlen(line);
        if (length < 4 || line[length - 1] != '\n') {
            errno = EPROTO;
            fail("interface-record");
        }
        line[length - 1] = '\0';
        char *separator = strchr(line, ':');
        if (separator == NULL || strchr(separator + 1, ':') != NULL) {
            errno = EPROTO;
            fail("interface-separator");
        }
        *separator = '\0';
        const char *name = separator + 1;
        if (strcmp(line, "PNR") == 0) {
            continue;
        }
        errno = 0;
        char *end = NULL;
        long number = strtol(line, &end, 10);
        if (errno != 0 || end == line || *end != '\0' || number < 0 ||
            number > MAX_SYSCALL_NUMBER || records[number].allowed ||
            strlen(name) > MAX_NAME_LENGTH) {
            errno = EPROTO;
            fail("interface-value");
        }
        records[number].allowed = true;
        strcpy(records[number].name, name);
        if (number > maximum) {
            maximum = (int)number;
        }
    }
    if (ferror(input) || fclose(input) != 0 || maximum < 0) {
        fail("interface-read");
    }
    return maximum;
}

static void kill_and_reap(pid_t child) {
    if (kill(-child, SIGKILL) != 0 && errno != ESRCH) {
        fail("group-kill");
    }
    if (kill(child, SIGKILL) != 0 && errno != ESRCH) {
        fail("child-kill");
    }
    for (;;) {
        pid_t waited = waitpid(-1, NULL, WNOHANG);
        if (waited > 0) {
            continue;
        }
        if (waited == 0) {
            struct timespec delay = {.tv_sec = 0, .tv_nsec = 100000};
            nanosleep(&delay, NULL);
            continue;
        }
        if (errno == ECHILD) {
            return;
        }
        if (errno != EINTR) {
            fail("cleanup-wait");
        }
    }
}

static void run_case(int number, const struct syscall_record *record) {
    int result_pipe[2];
    int ready_pipe[2];
    int start_pipe[2];
    if (pipe2(result_pipe, O_CLOEXEC | O_NONBLOCK) != 0) {
        fail("pipe");
    }
    if (pipe2(ready_pipe, O_CLOEXEC) != 0 ||
        pipe2(start_pipe, O_CLOEXEC) != 0) {
        fail("start-pipe");
    }
    pid_t child = fork();
    if (child < 0) {
        fail("fork");
    }
    if (child == 0) {
        close(result_pipe[0]);
        close(ready_pipe[0]);
        close(start_pipe[1]);
        if (setpgid(0, 0) != 0) {
            fail("child-process-group");
        }
        transfer_byte(ready_pipe[1], true, "child-ready");
        close(ready_pipe[1]);
        transfer_byte(start_pipe[0], false, "child-start");
        close(start_pipe[0]);
        long result = raw_syscall_six(number);
        ssize_t written = write(result_pipe[1], &result, sizeof(result));
        _exit(written == (ssize_t)sizeof(result) ? 0 : 75);
    }
    close(result_pipe[1]);
    close(ready_pipe[1]);
    close(start_pipe[0]);
    if (setpgid(child, child) != 0 && errno != EACCES && errno != ESRCH) {
        fail("parent-process-group");
    }

    transfer_byte(ready_pipe[0], false, "parent-ready");
    close(ready_pipe[0]);
    int64_t deadline = monotonic_nanoseconds() + DEADLINE_NANOSECONDS;
    transfer_byte(start_pipe[1], true, "parent-start");
    close(start_pipe[1]);

    int status = 0;
    bool finished = false;
    bool stopped = false;
    while (monotonic_nanoseconds() < deadline) {
        pid_t waited = waitpid(child, &status, WNOHANG | WUNTRACED);
        if (waited == child) {
            finished = true;
            stopped = WIFSTOPPED(status);
            break;
        }
        if (waited < 0 && errno != EINTR) {
            fail("case-wait");
        }
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 100000};
        nanosleep(&delay, NULL);
    }

    long raw_result = 0;
    ssize_t result_length = read(result_pipe[0], &raw_result, sizeof(raw_result));
    if (close(result_pipe[0]) != 0) {
        fail("pipe-close");
    }
    if (!finished) {
        dprintf(STDOUT_FILENO,
                "{\"nr\":%d,\"name\":\"%s\",\"allowed\":%s,"
                "\"outcome\":\"timeout\"}\n",
                number, record->name, record->allowed ? "true" : "false");
    } else if (stopped) {
        dprintf(STDOUT_FILENO,
                "{\"nr\":%d,\"name\":\"%s\",\"allowed\":%s,"
                "\"outcome\":\"signal\",\"signal\":%d}\n",
                number, record->name, record->allowed ? "true" : "false",
                WSTOPSIG(status));
    } else if (WIFSIGNALED(status)) {
        dprintf(STDOUT_FILENO,
                "{\"nr\":%d,\"name\":\"%s\",\"allowed\":%s,"
                "\"outcome\":\"signal\",\"signal\":%d}\n",
                number, record->name, record->allowed ? "true" : "false",
                WTERMSIG(status));
    } else if (result_length == (ssize_t)sizeof(raw_result)) {
        dprintf(STDOUT_FILENO,
                "{\"nr\":%d,\"name\":\"%s\",\"allowed\":%s,"
                "\"outcome\":\"return\",\"raw\":%ld}\n",
                number, record->name, record->allowed ? "true" : "false",
                raw_result);
    } else if (WIFEXITED(status)) {
        dprintf(STDOUT_FILENO,
                "{\"nr\":%d,\"name\":\"%s\",\"allowed\":%s,"
                "\"outcome\":\"exit\",\"status\":%d}\n",
                number, record->name, record->allowed ? "true" : "false",
                WEXITSTATUS(status));
    } else {
        errno = EPROTO;
        fail("case-outcome");
    }
    kill_and_reap(child);
}

int main(void) {
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) {
        fail("subreaper");
    }
    struct syscall_record *records =
        calloc(MAX_SYSCALL_NUMBER + 1, sizeof(*records));
    if (records == NULL) {
        fail("records");
    }
    int maximum = load_interface(records);
    for (int number = 0; number <= maximum + 1; ++number) {
        run_case(number, &records[number]);
    }
    dprintf(STDOUT_FILENO,
            "{\"summary\":true,\"case_count\":%d,"
            "\"maximum_interface_number\":%d,\"residual_children\":0}\n",
            maximum + 2, maximum);
    free(records);
    return 0;
}
