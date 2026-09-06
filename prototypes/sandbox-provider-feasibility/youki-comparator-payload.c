#include <errno.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return 0;
    }

    char *end = NULL;
    errno = 0;
    unsigned long seconds = strtoul(argv[1], &end, 10);
    if (errno != 0 || end == argv[1] || *end != '\0') {
        return 2;
    }

    struct timespec remaining = {
        .tv_sec = (time_t)seconds,
        .tv_nsec = 0,
    };
    while (nanosleep(&remaining, &remaining) == -1 && errno == EINTR) {
    }
    return 0;
}
