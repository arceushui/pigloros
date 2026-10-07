// C guest of the ADR-061 revisions 4 and 5 compatibility prototype (#539).
//
// It implements `pigloros:plugin/community-plugin@0.1.0` with no WASI import,
// using the bindings that `build-fixtures.sh` generates with the pinned
// wit-bindgen CLI. The Rust guest in `../rust-guest` implements the same
// behaviour, specified in `docs/evidence/adr-061-r4-prototype.md`.
//
// Ownership follows wit-bindgen's C conventions: an export owns its arguments
// and frees them, and the generated post-return functions free what an export
// returns. Every returned buffer is therefore a fresh allocation.

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "community_plugin.h"

#define FNV_OFFSET UINT64_C(0xcbf29ce484222325)
#define FNV_PRIME UINT64_C(0x00000100000001b3)
#define RANDOM_BYTES 16u

typedef pigloros_plugin_contract_v1_bytes_t bytes_t;
typedef pigloros_plugin_contract_v1_bounded_text_t bounded_text_t;
typedef pigloros_plugin_contract_v1_digest32_t digest32_t;
typedef pigloros_plugin_contract_v1_event_draft_t event_draft_t;
typedef pigloros_plugin_contract_v1_plugin_error_t plugin_error_t;
typedef pigloros_plugin_contract_v1_plugin_invocation_t plugin_invocation_t;
typedef pigloros_plugin_contract_v1_plugin_output_t plugin_output_t;

static void *checked_malloc(size_t size) {
  void *pointer = malloc(size);
  if (pointer == NULL) {
    abort();
  }
  return pointer;
}

static bytes_t copy_bytes(const uint8_t *data, size_t len) {
  bytes_t out = {NULL, len};
  if (len != 0) {
    out.ptr = checked_malloc(len);
    memcpy(out.ptr, data, len);
  }
  return out;
}

static bounded_text_t text(const char *value) {
  bounded_text_t out;
  out.utf8 = copy_bytes((const uint8_t *)value, strlen(value));
  return out;
}

static digest32_t filled_digest(uint8_t byte) {
  digest32_t out;
  out.value.len = 32;
  out.value.ptr = checked_malloc(32);
  memset(out.value.ptr, byte, 32);
  return out;
}

static uint64_t fnv1a(uint64_t hash, const uint8_t *data, size_t len) {
  for (size_t index = 0; index < len; ++index) {
    hash ^= data[index];
    hash *= FNV_PRIME;
  }
  return hash;
}

static void little_endian(uint64_t value, uint8_t out[8]) {
  for (unsigned index = 0; index < 8; ++index) {
    out[index] = (uint8_t)(value >> (8u * index));
  }
}

static bool is_trap_observation(const bytes_t *observation) {
  static const uint8_t trap[] = {'t', 'r', 'a', 'p'};
  return observation->len == sizeof trap &&
         memcmp(observation->ptr, trap, sizeof trap) == 0;
}

static bool log_message(uint16_t category, const char *message,
                        plugin_error_t *err) {
  bounded_text_t record = text(message);
  bool ok = pigloros_plugin_host_v1_record_operational_log(category, &record,
                                                            err);
  pigloros_plugin_contract_v1_bounded_text_free(&record);
  return ok;
}

static void fill_output(const plugin_invocation_t *input, uint64_t hash,
                        const char *event_type, plugin_output_t *ret) {
  uint8_t state[8];
  little_endian(hash, state);
  memset(ret, 0, sizeof *ret);
  ret->invocation_id =
      copy_bytes(input->invocation_id.ptr, input->invocation_id.len);
  ret->event_drafts.len = 1;
  ret->event_drafts.ptr = checked_malloc(sizeof(event_draft_t));
  event_draft_t *draft = &ret->event_drafts.ptr[0];
  memset(draft, 0, sizeof *draft);
  draft->event_schema_id = 1;
  draft->entity_id =
      copy_bytes(input->invocation_id.ptr, input->invocation_id.len);
  draft->event_type = text(event_type);
  draft->canonical_payload = copy_bytes(state, sizeof state);
  ret->next_state_schema.value = copy_bytes(
      input->prior_state_schema.value.ptr, input->prior_state_schema.value.len);
  ret->next_state_bytes = copy_bytes(state, sizeof state);
  ret->output_digest.value.len = 4 * sizeof state;
  ret->output_digest.value.ptr = checked_malloc(4 * sizeof state);
  for (unsigned copy = 0; copy < 4; ++copy) {
    memcpy(ret->output_digest.value.ptr + copy * sizeof state, state,
           sizeof state);
  }
}

static bool invoke(plugin_invocation_t *input, const char *message,
                   const char *event_type, plugin_output_t *ret,
                   plugin_error_t *err) {
  bool ok = false;
  if (is_trap_observation(&input->observation_bytes)) {
    if (log_message(2, "trapping", err)) {
      __builtin_trap();
    }
    goto done;
  }
  uint64_t now = pigloros_plugin_host_v1_simulation_time();
  bytes_t random;
  if (!pigloros_plugin_host_v1_deterministic_random(
          &input->deterministic_random_domain, input->timeline_position.seq,
          RANDOM_BYTES, &random, err)) {
    goto done;
  }
  if (log_message(1, message, err)) {
    uint8_t time_bytes[8];
    little_endian(now, time_bytes);
    uint64_t hash = fnv1a(FNV_OFFSET, input->prior_state_bytes.ptr,
                          input->prior_state_bytes.len);
    hash = fnv1a(hash, input->observation_bytes.ptr,
                 input->observation_bytes.len);
    hash = fnv1a(hash, time_bytes, sizeof time_bytes);
    hash = fnv1a(hash, random.ptr, random.len);
    fill_output(input, hash, event_type, ret);
    ok = true;
  }
  pigloros_plugin_contract_v1_bytes_free(&random);
done:
  pigloros_plugin_contract_v1_plugin_invocation_free(input);
  return ok;
}

bool exports_pigloros_plugin_guest_v1_describe(
    exports_pigloros_plugin_guest_v1_plugin_descriptor_t *ret,
    exports_pigloros_plugin_guest_v1_plugin_error_t *err) {
  (void)err;
  memset(ret, 0, sizeof *ret);
  ret->plugin_id = text("pigloros.compatibility-prototype");
  ret->release_semver = text("0.1.0");
  ret->world = text("pigloros:plugin/community-plugin@0.1.0");
  ret->abi_major = 0;
  ret->min_abi_minor = 1;
  ret->max_abi_minor = 1;
  ret->event_schema_digests.len = 1;
  ret->event_schema_digests.ptr = checked_malloc(sizeof(digest32_t));
  ret->event_schema_digests.ptr[0] = filled_digest(1);
  ret->state_schema_digest = filled_digest(2);
  ret->manifest_digest = filled_digest(0);
  ret->release_digest = filled_digest(0);
  return true;
}

bool exports_pigloros_plugin_guest_v1_reduce(
    exports_pigloros_plugin_guest_v1_plugin_invocation_t *input,
    exports_pigloros_plugin_guest_v1_plugin_output_t *ret,
    exports_pigloros_plugin_guest_v1_plugin_error_t *err) {
  return invoke(input, "reduce", "prototype.reduced", ret, err);
}

bool exports_pigloros_plugin_guest_v1_drive(
    exports_pigloros_plugin_guest_v1_plugin_invocation_t *input,
    exports_pigloros_plugin_guest_v1_plugin_output_t *ret,
    exports_pigloros_plugin_guest_v1_plugin_error_t *err) {
  return invoke(input, "drive", "prototype.driven", ret, err);
}

bool exports_pigloros_plugin_guest_v1_migrate_state(
    exports_pigloros_plugin_guest_v1_migration_request_t *input,
    exports_pigloros_plugin_guest_v1_migration_output_t *ret,
    exports_pigloros_plugin_guest_v1_plugin_error_t *err) {
  (void)ret;
  pigloros_plugin_contract_v1_migration_request_free(input);
  memset(err, 0, sizeof *err);
  err->code.tag = PIGLOROS_PLUGIN_CONTRACT_V1_PLUGIN_ERROR_CODE_GUEST_DECLARED_FAILURE;
  err->code.val.guest_declared_failure = 1;
  return false;
}
