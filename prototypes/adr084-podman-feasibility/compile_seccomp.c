#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void fail(const char *message) {
    fprintf(stderr, "seccomp compiler: %s\n", message);
    exit(1);
}

static uint32_t architecture(const char *name) {
    if (strcmp(name, "x86_64") == 0) {
        return SCMP_ARCH_X86_64;
    }
    if (strcmp(name, "aarch64") == 0) {
        return SCMP_ARCH_AARCH64;
    }
    fail("unsupported architecture");
    return 0;
}

static void strip_newline(char *line, ssize_t length) {
    if (length < 1 || line[length - 1] != '\n') {
        fail("interface record lacks final newline");
    }
    line[length - 1] = '\0';
}

static void require_pnr_names(FILE *input, uint32_t arch) {
    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;
    while ((length = getline(&line, &capacity, input)) >= 0) {
        strip_newline(line, length);
        int resolved = seccomp_syscall_resolve_name_arch(arch, line);
        if (resolved == __NR_SCMP_ERROR || resolved >= 0) {
            fail("readback-only name did not resolve to PNR");
        }
    }
    if (ferror(input)) {
        fail("could not read readback-only PNR input");
    }
    free(line);
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fail("usage: compile_seccomp ARCH INTERFACE READBACK_PNR BPF METADATA");
    }
    uint32_t arch = architecture(argv[1]);
    if (seccomp_arch_native() != arch) {
        fail("selected architecture is not native");
    }
    FILE *interface = fopen(argv[2], "re");
    FILE *readback = fopen(argv[3], "re");
    if (interface == NULL || readback == NULL) {
        fail("could not open mapping inputs");
    }
    require_pnr_names(readback, arch);
    if (fclose(readback) != 0) {
        fail("could not close readback-only PNR input");
    }

    scmp_filter_ctx context = seccomp_init(SCMP_ACT_ERRNO(4094));
    if (context == NULL) {
        fail("seccomp_init failed");
    }
    uint32_t bad_arch = 0;
    if (seccomp_attr_get(context, SCMP_FLTATR_ACT_BADARCH, &bad_arch) != 0 ||
        bad_arch != SCMP_ACT_KILL) {
        fail("pinned bad-architecture action mismatch");
    }

    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;
    unsigned int numeric_rules = 0;
    unsigned int pnr_records = 0;
    while ((length = getline(&line, &capacity, interface)) >= 0) {
        strip_newline(line, length);
        char *separator = strchr(line, ':');
        if (separator == NULL || separator == line || separator[1] == '\0') {
            fail("malformed interface record");
        }
        *separator = '\0';
        const char *name = separator + 1;
        int resolved = seccomp_syscall_resolve_name_arch(arch, name);
        if (strcmp(line, "PNR") == 0) {
            if (arch != SCMP_ARCH_AARCH64 || strcmp(name, "poll") != 0 ||
                resolved == __NR_SCMP_ERROR || resolved >= 0) {
                fail("invalid PNR interface record");
            }
            pnr_records++;
            continue;
        }
        errno = 0;
        char *end = NULL;
        unsigned long parsed = strtoul(line, &end, 10);
        if (errno != 0 || end == line || *end != '\0' || parsed > INT32_MAX ||
            resolved < 0 || (unsigned long)resolved != parsed) {
            fail("numeric interface record does not match pinned resolver");
        }
        char *roundtrip = seccomp_syscall_resolve_num_arch(arch, resolved);
        if (roundtrip == NULL || strcmp(roundtrip, name) != 0) {
            free(roundtrip);
            fail("numeric interface record does not round-trip");
        }
        free(roundtrip);
        if (seccomp_rule_add_exact(context, SCMP_ACT_ALLOW, resolved, 0) != 0) {
            fail("could not insert exact allow rule");
        }
        numeric_rules++;
    }
    free(line);
    if (ferror(interface) || fclose(interface) != 0) {
        fail("could not read or close interface input");
    }
    if (numeric_rules == 0 ||
        pnr_records != (arch == SCMP_ARCH_AARCH64 ? 1U : 0U)) {
        fail("interface rule/PNR counts mismatch");
    }

    int output = open(argv[4], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (output < 0) {
        fail("could not create BPF output");
    }
    if (seccomp_export_bpf(context, output) != 0 || fsync(output) != 0 ||
        close(output) != 0) {
        fail("could not export BPF output");
    }
    FILE *metadata = fopen(argv[5], "wxe");
    if (metadata == NULL) {
        fail("could not create compiler metadata");
    }
    if (fprintf(metadata,
                "{\n  \"api_level\": %u,\n  \"architecture_token\": %u,\n"
                "  \"bad_arch_action\": %u,\n  \"default_action\": %u,\n"
                "  \"numeric_rule_count\": %u,\n  \"pnr_record_count\": %u\n}\n",
                seccomp_api_get(), arch, bad_arch, SCMP_ACT_ERRNO(4094),
                numeric_rules, pnr_records) < 0 ||
        fflush(metadata) != 0 || fsync(fileno(metadata)) != 0 ||
        fclose(metadata) != 0) {
        fail("could not write compiler metadata");
    }
    seccomp_release(context);
    return 0;
}
