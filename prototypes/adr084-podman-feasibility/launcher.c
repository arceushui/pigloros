#define _GNU_SOURCE

#include "blake3.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/stat.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef STATX_MNT_ID
#define STATX_MNT_ID 0x00001000U
#endif

#define CONTROL_FD 3
#define DIGEST_SIZE 32
#define ATTEMPT_SIZE 16
#define NONCE_SIZE 32
#define PACKET_MAX 4096
#define READY_MAX 1024
#define RELEASE_TIMEOUT_MS 30000

struct cursor {
    const uint8_t *next;
    const uint8_t *end;
};

struct buffer {
    uint8_t bytes[READY_MAX];
    size_t length;
};

struct identity {
    uint64_t mount;
    uint64_t inode;
};

struct launch_context {
    uint8_t attempt[ATTEMPT_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint8_t ois[DIGEST_SIZE];
    uint8_t ort[DIGEST_SIZE];
    uint8_t launcher[DIGEST_SIZE];
    uint8_t adapter[DIGEST_SIZE];
    uint8_t lpv[DIGEST_SIZE];
    uint8_t expected_fdl[DIGEST_SIZE];
};

_Noreturn static void fail(const char *message) {
    dprintf(STDERR_FILENO, "launcher-error:%s:%s\n", message, strerror(errno));
    _exit(70);
}

_Noreturn static void protocol_fail(const char *message) {
    errno = EPROTO;
    fail(message);
}

static bool checked_equal(const uint8_t *left, const uint8_t *right, size_t length) {
    uint8_t difference = 0;
    for (size_t index = 0; index < length; ++index) {
        difference |= left[index] ^ right[index];
    }
    return difference == 0;
}

static uint64_t read_head(struct cursor *cursor, uint8_t expected_major) {
    if (cursor->next == cursor->end) {
        protocol_fail("cbor-truncated");
    }
    uint8_t initial = *cursor->next++;
    if ((initial >> 5) != expected_major) {
        protocol_fail("cbor-major");
    }
    uint8_t additional = initial & 31U;
    if (additional < 24U) {
        return additional;
    }
    size_t width;
    uint64_t minimum;
    switch (additional) {
        case 24:
            width = 1;
            minimum = 24;
            break;
        case 25:
            width = 2;
            minimum = 256;
            break;
        case 26:
            width = 4;
            minimum = 65536;
            break;
        case 27:
            width = 8;
            minimum = UINT64_C(4294967296);
            break;
        default:
            protocol_fail("cbor-indefinite");
    }
    if ((size_t)(cursor->end - cursor->next) < width) {
        protocol_fail("cbor-truncated");
    }
    uint64_t value = 0;
    for (size_t index = 0; index < width; ++index) {
        value = (value << 8) | *cursor->next++;
    }
    if (value < minimum) {
        protocol_fail("cbor-noncanonical-integer");
    }
    return value;
}

static void expect_array(struct cursor *cursor, uint64_t length) {
    if (read_head(cursor, 4) != length) {
        protocol_fail("cbor-array-length");
    }
}

static uint64_t read_uint(struct cursor *cursor) {
    return read_head(cursor, 0);
}

static const uint8_t *read_bytes(struct cursor *cursor, size_t length) {
    if (read_head(cursor, 2) != length || (size_t)(cursor->end - cursor->next) < length) {
        protocol_fail("cbor-byte-string");
    }
    const uint8_t *value = cursor->next;
    cursor->next += length;
    return value;
}

static void expect_text(struct cursor *cursor, const char *expected) {
    size_t length = strlen(expected);
    if (read_head(cursor, 3) != length || (size_t)(cursor->end - cursor->next) < length ||
        memcmp(cursor->next, expected, length) != 0) {
        protocol_fail("cbor-text");
    }
    cursor->next += length;
}

static void skip_text(struct cursor *cursor) {
    uint64_t length = read_head(cursor, 3);
    if (length > (uint64_t)(cursor->end - cursor->next)) {
        protocol_fail("cbor-text");
    }
    cursor->next += (size_t)length;
}

static void append(struct buffer *buffer, const void *value, size_t length) {
    if (length > sizeof(buffer->bytes) - buffer->length) {
        errno = EOVERFLOW;
        fail("ready-size");
    }
    memcpy(buffer->bytes + buffer->length, value, length);
    buffer->length += length;
}

static void encode_head(struct buffer *buffer, uint8_t major, uint64_t value) {
    uint8_t encoded[9];
    size_t length;
    if (value < 24) {
        encoded[0] = (uint8_t)((major << 5) | value);
        length = 1;
    } else if (value <= UINT8_MAX) {
        encoded[0] = (uint8_t)((major << 5) | 24);
        encoded[1] = (uint8_t)value;
        length = 2;
    } else if (value <= UINT16_MAX) {
        encoded[0] = (uint8_t)((major << 5) | 25);
        length = 3;
    } else if (value <= UINT32_MAX) {
        encoded[0] = (uint8_t)((major << 5) | 26);
        length = 5;
    } else {
        encoded[0] = (uint8_t)((major << 5) | 27);
        length = 9;
    }
    for (size_t index = 1; index < length; ++index) {
        size_t shift = (length - 1 - index) * 8;
        encoded[index] = (uint8_t)(value >> shift);
    }
    append(buffer, encoded, length);
}

static void encode_array(struct buffer *buffer, uint64_t length) {
    encode_head(buffer, 4, length);
}

static void encode_uint(struct buffer *buffer, uint64_t value) {
    encode_head(buffer, 0, value);
}

static void encode_bytes(struct buffer *buffer, const uint8_t *value, size_t length) {
    encode_head(buffer, 2, length);
    append(buffer, value, length);
}

static void encode_text(struct buffer *buffer, const char *value) {
    size_t length = strlen(value);
    encode_head(buffer, 3, length);
    append(buffer, value, length);
}

static void digest_memory(const char *domain, const uint8_t *content, size_t length,
                          uint8_t output[DIGEST_SIZE]) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, domain, strlen(domain) + 1);
    blake3_hasher_update(&hasher, content, length);
    blake3_hasher_finalize(&hasher, output, DIGEST_SIZE);
}

static void digest_file(int fd, const char *domain, uint8_t output[DIGEST_SIZE]) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, domain, strlen(domain) + 1);
    uint8_t content[16384];
    off_t offset = 0;
    for (;;) {
        ssize_t count = pread(fd, content, sizeof(content), offset);
        if (count == 0) {
            break;
        }
        if (count < 0) {
            fail("executable-read");
        }
        blake3_hasher_update(&hasher, content, (size_t)count);
        offset += count;
    }
    blake3_hasher_finalize(&hasher, output, DIGEST_SIZE);
}

static struct identity descriptor_identity(int fd) {
    struct statx value;
    memset(&value, 0, sizeof(value));
    if (syscall(SYS_statx, fd, "", AT_EMPTY_PATH | AT_STATX_SYNC_AS_STAT,
                STATX_INO | STATX_MNT_ID, &value) == -1) {
        fail("descriptor-statx");
    }
    if ((value.stx_mask & (STATX_INO | STATX_MNT_ID)) != (STATX_INO | STATX_MNT_ID)) {
        protocol_fail("descriptor-statx-mask");
    }
    return (struct identity){.mount = value.stx_mnt_id, .inode = value.stx_ino};
}

static struct identity namespace_identity(void) {
    int fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
    struct stat value;
    if (fd == -1 || fstat(fd, &value) == -1) {
        fail("mount-namespace");
    }
    if (close(fd) == -1) {
        fail("mount-namespace-close");
    }
    return (struct identity){.mount = (uint64_t)value.st_dev, .inode = value.st_ino};
}

static void verify_control_socket(void) {
    int domain;
    int type;
    socklen_t length = sizeof(int);
    if (getsockopt(CONTROL_FD, SOL_SOCKET, SO_DOMAIN, &domain, &length) == -1 ||
        length != sizeof(int) || domain != AF_UNIX) {
        protocol_fail("control-domain");
    }
    length = sizeof(int);
    if (getsockopt(CONTROL_FD, SOL_SOCKET, SO_TYPE, &type, &length) == -1 ||
        length != sizeof(int) || type != SOCK_SEQPACKET) {
        protocol_fail("control-type");
    }
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
        if (end == entry->d_name || *end != '\0' || fd == scan_fd) {
            continue;
        }
        if (fd < 0 || fd > 3 || seen[fd]) {
            protocol_fail("descriptor-set");
        }
        seen[fd] = true;
    }
    if (closedir(directory) == -1) {
        fail("descriptor-close");
    }
    for (int fd = 0; fd <= 3; ++fd) {
        if (!seen[fd]) {
            protocol_fail("descriptor-set");
        }
    }
    verify_control_socket();
}

static size_t receive_packet(uint8_t packet[PACKET_MAX], int timeout_ms, const char *label) {
    struct pollfd descriptor = {.fd = CONTROL_FD, .events = POLLIN};
    int result;
    do {
        result = poll(&descriptor, 1, timeout_ms);
    } while (result == -1 && errno == EINTR);
    if (result == 0) {
        errno = ETIMEDOUT;
        fail(label);
    }
    if (result == -1) {
        fail(label);
    }
    ssize_t length = recv(CONTROL_FD, packet, PACKET_MAX, MSG_TRUNC);
    if (length <= 0 || length > PACKET_MAX) {
        protocol_fail(label);
    }
    return (size_t)length;
}

static void parse_context(const uint8_t *packet, size_t length, struct launch_context *context) {
    struct cursor cursor = {.next = packet, .end = packet + length};
    expect_array(&cursor, 6);
    expect_text(&cursor, "PBC1");
    if (read_uint(&cursor) != 1) {
        protocol_fail("context-version");
    }
    expect_array(&cursor, 2);
    const uint8_t *lpv_start = cursor.next;
    expect_array(&cursor, 8);
    expect_text(&cursor, "LPV2");
    if (read_uint(&cursor) != 2) {
        protocol_fail("lpv-version");
    }
    memcpy(context->attempt, read_bytes(&cursor, ATTEMPT_SIZE), ATTEMPT_SIZE);
    memcpy(context->nonce, read_bytes(&cursor, NONCE_SIZE), NONCE_SIZE);
    memcpy(context->ois, read_bytes(&cursor, DIGEST_SIZE), DIGEST_SIZE);
    expect_text(&cursor, "/adapter");
    expect_array(&cursor, 0);
    memcpy(context->expected_fdl, read_bytes(&cursor, DIGEST_SIZE), DIGEST_SIZE);
    const uint8_t *lpv_end = cursor.next;
    digest_memory("PiglorOS.LPV2.v2", lpv_start, (size_t)(lpv_end - lpv_start), context->lpv);
    if (!checked_equal(context->lpv, read_bytes(&cursor, DIGEST_SIZE), DIGEST_SIZE)) {
        protocol_fail("lpv-self-digest");
    }
    memcpy(context->ort, read_bytes(&cursor, DIGEST_SIZE), DIGEST_SIZE);
    memcpy(context->launcher, read_bytes(&cursor, DIGEST_SIZE), DIGEST_SIZE);
    memcpy(context->adapter, read_bytes(&cursor, DIGEST_SIZE), DIGEST_SIZE);
    if (cursor.next != cursor.end) {
        protocol_fail("context-trailing");
    }
}

static void observed_fdl_digest(uint8_t output[DIGEST_SIZE]) {
    struct buffer unsigned_record = {0};
    encode_array(&unsigned_record, 4);
    encode_text(&unsigned_record, "FDL1");
    encode_uint(&unsigned_record, 1);
    encode_uint(&unsigned_record, 1);
    encode_array(&unsigned_record, 1);
    encode_array(&unsigned_record, 2);
    encode_uint(&unsigned_record, CONTROL_FD);
    encode_uint(&unsigned_record, 1);
    digest_memory("PiglorOS.FDL1.v1", unsigned_record.bytes, unsigned_record.length, output);
}

static size_t build_ready(const struct launch_context *context, struct identity mount_namespace,
                          struct identity launcher_identity, struct identity adapter_identity,
                          uint8_t ready_digest[DIGEST_SIZE], uint8_t packet[READY_MAX]) {
    struct buffer unsigned_record = {0};
    encode_array(&unsigned_record, 14);
    encode_text(&unsigned_record, "RDY2");
    encode_uint(&unsigned_record, 2);
    encode_bytes(&unsigned_record, context->attempt, ATTEMPT_SIZE);
    encode_bytes(&unsigned_record, context->nonce, NONCE_SIZE);
    encode_array(&unsigned_record, 2);
    encode_uint(&unsigned_record, mount_namespace.mount);
    encode_uint(&unsigned_record, mount_namespace.inode);
    encode_bytes(&unsigned_record, context->launcher, DIGEST_SIZE);
    encode_array(&unsigned_record, 2);
    encode_uint(&unsigned_record, launcher_identity.mount);
    encode_uint(&unsigned_record, launcher_identity.inode);
    encode_bytes(&unsigned_record, context->ois, DIGEST_SIZE);
    encode_bytes(&unsigned_record, context->ort, DIGEST_SIZE);
    encode_bytes(&unsigned_record, context->adapter, DIGEST_SIZE);
    encode_array(&unsigned_record, 2);
    encode_uint(&unsigned_record, adapter_identity.mount);
    encode_uint(&unsigned_record, adapter_identity.inode);
    encode_bytes(&unsigned_record, context->lpv, DIGEST_SIZE);
    encode_bytes(&unsigned_record, context->expected_fdl, DIGEST_SIZE);
    encode_bytes(&unsigned_record, context->expected_fdl, DIGEST_SIZE);
    digest_memory("PiglorOS.RDY2.v2", unsigned_record.bytes, unsigned_record.length, ready_digest);

    struct buffer full_record = {0};
    encode_array(&full_record, 2);
    append(&full_record, unsigned_record.bytes, unsigned_record.length);
    encode_bytes(&full_record, ready_digest, DIGEST_SIZE);
    memcpy(packet, full_record.bytes, full_record.length);
    return full_record.length;
}

static uint64_t monotonic_now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) == -1 || value.tv_sec < 0) {
        fail("clock-monotonic");
    }
    uint64_t seconds = (uint64_t)value.tv_sec;
    if (seconds > (UINT64_MAX - (uint64_t)value.tv_nsec) / UINT64_C(1000000000)) {
        errno = EOVERFLOW;
        fail("clock-overflow");
    }
    return seconds * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static void parse_release(const uint8_t *packet, size_t length,
                          const struct launch_context *context,
                          const uint8_t ready_digest[DIGEST_SIZE]) {
    struct cursor cursor = {.next = packet, .end = packet + length};
    expect_array(&cursor, 3);
    const uint8_t *unsigned_start = cursor.next;
    expect_array(&cursor, 16);
    expect_text(&cursor, "RLS2");
    if (read_uint(&cursor) != 2) {
        protocol_fail("release-version");
    }
    if (!checked_equal(read_bytes(&cursor, ATTEMPT_SIZE), context->attempt, ATTEMPT_SIZE)) {
        protocol_fail("release-attempt");
    }
    if (!checked_equal(read_bytes(&cursor, NONCE_SIZE), context->nonce, NONCE_SIZE)) {
        protocol_fail("release-nonce");
    }
    if (!checked_equal(read_bytes(&cursor, DIGEST_SIZE), ready_digest, DIGEST_SIZE)) {
        protocol_fail("release-ready");
    }
    for (size_t index = 0; index < 3; ++index) {
        (void)read_bytes(&cursor, DIGEST_SIZE);
    }
    for (size_t index = 0; index < 3; ++index) {
        (void)read_uint(&cursor);
    }
    (void)read_bytes(&cursor, DIGEST_SIZE);
    (void)read_bytes(&cursor, DIGEST_SIZE);
    uint64_t anchor = read_uint(&cursor);
    uint64_t deadline = read_uint(&cursor);
    skip_text(&cursor);
    const uint8_t *unsigned_end = cursor.next;
    uint8_t observed[DIGEST_SIZE];
    digest_memory("PiglorOS.RLS2.v2", unsigned_start,
                  (size_t)(unsigned_end - unsigned_start), observed);
    if (!checked_equal(read_bytes(&cursor, DIGEST_SIZE), observed, DIGEST_SIZE)) {
        protocol_fail("release-self-digest");
    }
    (void)read_bytes(&cursor, 64);
    if (cursor.next != cursor.end) {
        protocol_fail("release-trailing");
    }
    if (anchor >= deadline || monotonic_now() >= deadline) {
        errno = ETIMEDOUT;
        fail("release-expired");
    }
}

static void require_identity(const struct identity expected, const struct identity observed,
                             const char *message) {
    if (expected.mount != observed.mount || expected.inode != observed.inode) {
        protocol_fail(message);
    }
}

int main(void) {
    verify_descriptors();

    uint8_t context_packet[PACKET_MAX];
    size_t context_length = receive_packet(context_packet, RELEASE_TIMEOUT_MS, "context-receive");
    struct launch_context context;
    memset(&context, 0, sizeof(context));
    parse_context(context_packet, context_length, &context);

    uint8_t fdl_digest[DIGEST_SIZE];
    observed_fdl_digest(fdl_digest);
    if (!checked_equal(fdl_digest, context.expected_fdl, DIGEST_SIZE)) {
        protocol_fail("fdl-mismatch");
    }

    int launcher_fd = open("/launcher", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int adapter_fd = open("/adapter", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat launcher_stat;
    struct stat adapter_stat;
    if (launcher_fd == -1 || adapter_fd == -1 || fstat(launcher_fd, &launcher_stat) == -1 ||
        fstat(adapter_fd, &adapter_stat) == -1) {
        fail("executable-open");
    }
    if (!S_ISREG(launcher_stat.st_mode) || !S_ISREG(adapter_stat.st_mode)) {
        protocol_fail("executable-type");
    }

    uint8_t launcher_digest[DIGEST_SIZE];
    uint8_t adapter_digest[DIGEST_SIZE];
    digest_file(launcher_fd, "PiglorOS.OciExecutable.v1", launcher_digest);
    digest_file(adapter_fd, "PiglorOS.OciExecutable.v1", adapter_digest);
    if (!checked_equal(launcher_digest, context.launcher, DIGEST_SIZE) ||
        !checked_equal(adapter_digest, context.adapter, DIGEST_SIZE)) {
        protocol_fail("executable-digest");
    }

    struct identity mount_namespace = namespace_identity();
    struct identity launcher_identity = descriptor_identity(launcher_fd);
    struct identity adapter_identity = descriptor_identity(adapter_fd);
    uint8_t ready_digest[DIGEST_SIZE];
    uint8_t ready_packet[READY_MAX];
    size_t ready_length = build_ready(&context, mount_namespace, launcher_identity,
                                      adapter_identity, ready_digest, ready_packet);
    if (send(CONTROL_FD, ready_packet, ready_length, MSG_NOSIGNAL) != (ssize_t)ready_length) {
        fail("ready-write");
    }

    uint8_t release_packet[PACKET_MAX];
    size_t release_length = receive_packet(release_packet, RELEASE_TIMEOUT_MS, "release-receive");
    parse_release(release_packet, release_length, &context, ready_digest);

    require_identity(mount_namespace, namespace_identity(), "mount-namespace-changed");
    require_identity(launcher_identity, descriptor_identity(launcher_fd), "launcher-identity-changed");
    require_identity(adapter_identity, descriptor_identity(adapter_fd), "adapter-identity-changed");
    digest_file(launcher_fd, "PiglorOS.OciExecutable.v1", launcher_digest);
    digest_file(adapter_fd, "PiglorOS.OciExecutable.v1", adapter_digest);
    if (!checked_equal(launcher_digest, context.launcher, DIGEST_SIZE) ||
        !checked_equal(adapter_digest, context.adapter, DIGEST_SIZE)) {
        protocol_fail("executable-digest-changed");
    }

    if (close(launcher_fd) == -1 || close(CONTROL_FD) == -1) {
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
