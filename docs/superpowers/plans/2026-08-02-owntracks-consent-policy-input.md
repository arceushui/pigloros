# OwnTracks Consent Policy Input Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans task-by-task.

**Goal:** Enable real local OwnTracks pairing from an explicit one-shot consent-policy artifact.

**Architecture:** `owntracks.rs` strictly decodes one UTF-8 TOML artifact, computes its domain-separated consent hash, then creates the owner key/credential and calls only `OwnTracksEnrollmentStore::pair_owntracks_enrollment`. The artifact is not persisted or re-read by status, rotate, revoke, or admission.

**Tech Stack:** Rust 1.97.1, `toml`, BLAKE3, `pos-core`, SQLite enrollment store.

## Global Constraints

- ADR-054 and ADR-055 are Accepted.
- Pair syntax becomes `pair <sqlite-path> <owner-key-path> --consent-policy <path> <timeline-id> <entity-id>`.
- The TOML schema is exact: `schema_version = 1`; lower-hex `consent_identity`; non-zero `consent_revision`, `policy_version`, and `binding_revision`; `withdrawn = false`; `purpose = "local_pairing"`; `precision = "exact"`; `source_time_bucket = "minute"`; `visibility = "paired_devices_only"`.
- Compute, never accept, `BLAKE3("pigloros/owntracks/consent/v1\\0" || fixed-order canonical fields)`.
- Reject unknown, duplicate, malformed, missing, zero, withdrawn, or non-V1 values before owner-key or credential creation.
- No HTTP route, Basic verification, admission call, generic append, or `geo.location` event.

---

### Task 1: Strict consent-policy parser

**Files:**
- Modify: `apps/piglor-gateway/Cargo.toml`
- Modify: `apps/piglor-gateway/src/owntracks.rs`

- [x] Write tests for one valid TOML artifact, unknown fields, invalid lower hex, zero revisions, withdrawn consent, and all invalid V1 vocabulary values.
- [x] Add `toml` and a private typed parser that rejects every unsupported input and produces a private validated fence input.
- [x] Compute the fixed-order domain-separated BLAKE3 consent hash and test determinism plus one-field change sensitivity.
- [x] Re-run focused Gateway tests.

### Task 2: Pair command transition

**Files:**
- Modify: `apps/piglor-gateway/src/owntracks.rs`
- Modify: `apps/piglor-gateway/src/main.rs`

- [x] Write command tests proving valid pair creates an owner-only key, persists only the verifier through `OwnTracksEnrollmentStore`, prints credentials once, and exposes active status/policy version.
- [x] Add tests that invalid artifact input creates neither key nor enrollment, and active enrollment rejects a second pair without credential output.
- [x] Replace only the pair branch with parse → validate → create key/credential → construct `GeoLocationAdmissionFenceV1` with epoch `1` → narrow store pair.
- [x] Re-run Gateway tests.

### Task 3: Review and publish

- [x] Update ADR-055 and the CLI design document with the final artifact example and exact argument form.
- [x] Run formatter, non-privileged `cargo test --workspace --locked -- --include-ignored`, pedantic clippy, and `./scripts/ci.sh`.
- [x] Obtain CTO review and journal Redmine #146 and Notion.
- [x] Commit and push.
