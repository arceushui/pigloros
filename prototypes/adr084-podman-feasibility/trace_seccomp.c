#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_TRACED 512
#define ADMITTED_SECCOMP_FLAGS SECCOMP_FILTER_FLAG_SPEC_ALLOW

struct traced_process {
    pid_t pid;
    bool awaiting_install_exit;
};

static struct traced_process traced[MAX_TRACED];
static size_t traced_count;

static void fail(const char *message) {
    dprintf(STDERR_FILENO, "seccomp-tracer-error:%s:%s\n", message,
            strerror(errno));
    _exit(72);
}

static void add_traced(pid_t pid) {
    for (size_t index = 0; index < traced_count; ++index) {
        if (traced[index].pid == pid) {
            return;
        }
    }
    if (traced_count == MAX_TRACED) {
        errno = E2BIG;
        fail("process-bound");
    }
    traced[traced_count++] =
        (struct traced_process){.pid = pid, .awaiting_install_exit = false};
}

static struct traced_process *find_traced(pid_t pid) {
    for (size_t index = 0; index < traced_count; ++index) {
        if (traced[index].pid == pid) {
            return &traced[index];
        }
    }
    errno = ESRCH;
    fail("unknown-tracee");
}

static void remove_traced(pid_t pid) {
    for (size_t index = 0; index < traced_count; ++index) {
        if (traced[index].pid == pid) {
            traced[index] = traced[traced_count - 1];
            --traced_count;
            return;
        }
    }
    errno = ESRCH;
    fail("remove-unknown-tracee");
}

static unsigned char *read_file(const char *path, size_t *length) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor == -1) {
        fail("expected-open");
    }
    struct stat metadata;
    if (fstat(descriptor, &metadata) == -1 || metadata.st_size <= 0 ||
        metadata.st_size > 1048576) {
        fail("expected-size");
    }
    *length = (size_t)metadata.st_size;
    unsigned char *bytes = malloc(*length);
    if (bytes == NULL) {
        fail("expected-allocate");
    }
    size_t offset = 0;
    while (offset < *length) {
        ssize_t amount = read(descriptor, bytes + offset, *length - offset);
        if (amount <= 0) {
            fail("expected-read");
        }
        offset += (size_t)amount;
    }
    if (close(descriptor) == -1) {
        fail("expected-close");
    }
    return bytes;
}

static void copy_tracee(pid_t pid, uintptr_t address, void *destination,
                        size_t length) {
    unsigned char *output = destination;
    size_t offset = 0;
    while (offset < length) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(address + offset), 0);
        if (word == -1 && errno != 0) {
            fail("tracee-read");
        }
        size_t remaining = length - offset;
        size_t amount = remaining < sizeof(word) ? remaining : sizeof(word);
        memcpy(output + offset, &word, amount);
        offset += amount;
    }
}

static void write_exact(const char *path, const unsigned char *bytes,
                        size_t length) {
    int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (descriptor == -1) {
        fail("installed-open");
    }
    size_t offset = 0;
    while (offset < length) {
        ssize_t amount = write(descriptor, bytes + offset, length - offset);
        if (amount <= 0) {
            fail("installed-write");
        }
        offset += (size_t)amount;
    }
    if (fsync(descriptor) == -1 || close(descriptor) == -1) {
        fail("installed-close");
    }
}

static void write_report(const char *path, pid_t installer, size_t length,
                         long result) {
    int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (descriptor == -1) {
        fail("report-open");
    }
    int written = dprintf(
        descriptor,
        "{\n  \"admitted_flags\": %u,\n  \"byte_length\": %zu,\n"
        "  \"equality\": true,\n  \"install_attempts\": 1,\n"
        "  \"installer_pid\": %ld,\n  \"syscall_return\": %ld\n}\n",
        ADMITTED_SECCOMP_FLAGS, length, (long)installer, result);
    if (written < 0 || fsync(descriptor) == -1 || close(descriptor) == -1) {
        fail("report-write");
    }
}

int main(int argc, char **argv) {
    if (argc < 6 || strcmp(argv[4], "--") != 0) {
        errno = EINVAL;
        fail("usage");
    }

    size_t expected_length = 0;
    unsigned char *expected = read_file(argv[1], &expected_length);
    pid_t child = fork();
    if (child == -1) {
        fail("fork");
    }
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1 || raise(SIGSTOP) != 0) {
            fail("trace-me");
        }
        execvp(argv[5], &argv[5]);
        fail("exec");
    }

    if (close(3) == -1 && errno != EBADF) {
        fail("control-close");
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) {
        errno = ECHILD;
        fail("initial-stop");
    }
    long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
                   PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                   PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL;
    if (ptrace(PTRACE_SETOPTIONS, child, 0, options) == -1) {
        fail("trace-options");
    }
    add_traced(child);
    if (ptrace(PTRACE_SYSCALL, child, 0, 0) == -1) {
        fail("initial-continue");
    }

    unsigned int install_attempts = 0;
    bool install_succeeded = false;
    pid_t installer = -1;
    int child_status = 0;
    bool child_reaped = false;
    while (traced_count != 0) {
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid == -1) {
            fail("wait");
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (pid == child) {
                child_status = status;
                child_reaped = true;
            }
            remove_traced(pid);
            continue;
        }
        if (!WIFSTOPPED(status)) {
            errno = EPROTO;
            fail("wait-state");
        }

        unsigned int event = (unsigned int)status >> 16;
        int signal = WSTOPSIG(status);
        if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
            event == PTRACE_EVENT_CLONE) {
            unsigned long new_pid = 0;
            if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &new_pid) == -1) {
                fail("fork-event");
            }
            add_traced((pid_t)new_pid);
        }

        struct traced_process *process = find_traced(pid);
        if (signal == (SIGTRAP | 0x80)) {
            struct ptrace_syscall_info information;
            memset(&information, 0, sizeof(information));
            long available = ptrace(PTRACE_GET_SYSCALL_INFO, pid,
                                    sizeof(information), &information);
            if (available < 0) {
                fail("syscall-info");
            }
            if (information.op == PTRACE_SYSCALL_INFO_ENTRY &&
                information.entry.nr == SYS_seccomp &&
                information.entry.args[0] == SECCOMP_SET_MODE_FILTER) {
                ++install_attempts;
                if (install_attempts != 1 ||
                    information.entry.args[1] != ADMITTED_SECCOMP_FLAGS) {
                    errno = EPROTO;
                    fail("install-attempt");
                }
                struct sock_fprog program;
                copy_tracee(pid, (uintptr_t)information.entry.args[2], &program,
                            sizeof(program));
                size_t installed_length =
                    (size_t)program.len * sizeof(struct sock_filter);
                if (installed_length != expected_length) {
                    errno = EPROTO;
                    fail("installed-length");
                }
                unsigned char *installed = malloc(installed_length);
                if (installed == NULL) {
                    fail("installed-allocate");
                }
                copy_tracee(pid, (uintptr_t)program.filter, installed,
                            installed_length);
                if (memcmp(installed, expected, installed_length) != 0) {
                    errno = EPROTO;
                    fail("installed-equality");
                }
                write_exact(argv[2], installed, installed_length);
                free(installed);
                process->awaiting_install_exit = true;
                installer = pid;
            } else if (information.op == PTRACE_SYSCALL_INFO_EXIT &&
                       process->awaiting_install_exit) {
                if (information.exit.rval != 0 || information.exit.is_error) {
                    errno = EPROTO;
                    fail("install-return");
                }
                process->awaiting_install_exit = false;
                install_succeeded = true;
                write_report(argv[3], installer, expected_length,
                             information.exit.rval);
            }
        }

        int deliver = 0;
        if (event == 0 && signal != (SIGTRAP | 0x80) && signal != SIGSTOP &&
            signal != SIGTRAP) {
            deliver = signal;
        }
        if (ptrace(PTRACE_SYSCALL, pid, 0, deliver) == -1 && errno != ESRCH) {
            fail("continue");
        }
    }

    free(expected);
    if (!child_reaped || install_attempts != 1 || !install_succeeded) {
        errno = EPROTO;
        fail("install-proof");
    }
    if (WIFEXITED(child_status)) {
        return WEXITSTATUS(child_status);
    }
    if (WIFSIGNALED(child_status)) {
        return 128 + WTERMSIG(child_status);
    }
    errno = EPROTO;
    fail("child-status");
}
