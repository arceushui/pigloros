/* Throwaway cache-bypass probe; never production code. */
#include <errno.h>
#include <stddef.h>
#include <unistd.h>

int main(void) {
  static const char output[] = "CACHE-OK\n";
  size_t offset = 0;

  while (offset < sizeof(output) - 1) {
    ssize_t written = write(STDOUT_FILENO, output + offset,
                            sizeof(output) - 1 - offset);
    if (written > 0) {
      offset += (size_t)written;
    } else if (written < 0 && errno == EINTR) {
      continue;
    } else {
      return 1;
    }
  }
  return 0;
}
