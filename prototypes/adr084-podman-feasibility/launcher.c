#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static void fail(const char *message) {
    dprintf(STDERR_FILENO, "launcher-error:%s:%s\n", message, strerror(errno));
    _exit(70);
}

static void verify_descriptors(void) {
    bool seen[4] = {false, false, false, false};
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
        if (fd < 0 || fd > 3 || seen[fd]) {
            errno = EPROTO;
            fail("descriptor-set");
        }
        seen[fd] = true;
    }
    if (closedir(directory) == -1) {
        fail("descriptor-close");
    }
    for (int fd = 0; fd <= 3; ++fd) {
        if (!seen[fd]) {
            errno = EPROTO;
            fail("descriptor-set");
        }
    }
}

int main(void) {
    static const char ready[] = "READY\n";
    static const char expected[] = "RELEASE\n";
    char release[sizeof(expected) - 1];
    struct stat adapter_stat;

    verify_descriptors();
    if (write(3, ready, sizeof(ready) - 1) != (ssize_t)(sizeof(ready) - 1)) {
        fail("ready-write");
    }
    if (read(3, release, sizeof(release)) != (ssize_t)sizeof(release)) {
        fail("release-read");
    }
    if (memcmp(release, expected, sizeof(release)) != 0) {
        errno = EPROTO;
        fail("release-value");
    }

    int adapter_fd = open("/adapter", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (adapter_fd == -1 || fstat(adapter_fd, &adapter_stat) == -1) {
        fail("adapter-open");
    }
    if (!S_ISREG(adapter_stat.st_mode)) {
        errno = EINVAL;
        fail("adapter-type");
    }
    if (close(3) == -1) {
        fail("control-close");
    }
    if (clearenv() != 0 || setenv("PIGLOROS_PROTOCOL", "EAI1", 1) != 0) {
        fail("environment");
    }

    char *const arguments[] = {"/adapter", NULL};
    char *const environment[] = {"PIGLOROS_PROTOCOL=EAI1", NULL};
    syscall(SYS_execveat, adapter_fd, "", arguments, environment, AT_EMPTY_PATH);
    fail("execveat");
}
