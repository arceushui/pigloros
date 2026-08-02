# OwnTracks Enrollment CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver Redmine #146's accepted non-activating local OwnTracks enrollment commands: pair, status, rotate, and revoke.

**Architecture:** Build one private core/store enrollment-state capability beside #169's geographic-admission fence, with identical Memory and SQLite behaviour. The Gateway binary is the only local command consumer; it creates the owner key and plaintext credentials, persists only a keyed verifier, and never registers an OwnTracks HTTP route or appends a `geo.location` Event.

**Tech Stack:** Rust 1.97.1, `pos-core`, `pos-store` Memory/SQLite adapters, `piglor-gateway`, BLAKE3, deterministic CBOR, Rust Unix filesystem APIs.

## Global Constraints

- ADR-054 is Accepted; ADR-026 and ADR-053 remain authoritative for privacy and activation boundaries.
- Development SQLite databases may be replaced outright: no migration, backfill, dual write, upcast, or compatibility layer.
- Exactly one binding is `Absent`, `Active`, or `Revoked`; successful pair, rotate, and revoke advance a non-zero epoch.
- Persist no plaintext Basic handle, secret, or owner key; use a fresh independent 256-bit handle/secret pair for each successful pair/rotate.
- Keep the owner key in an owner-only Unix file created with create-new semantics, symlink rejection, file and directory sync, and fail-closed errors.
- No HTTP route, Basic-auth verification, rate limit, OwnTracks decoder, Timeline mutation, or `geo.location` append is allowed in this change.
- CI requires the project’s 99% line and region coverage floor and `cargo test --workspace --locked -- --include-ignored`; production `coverage(off)` remains prohibited.

---

### Task 1: Establish #169 as the #146 baseline

**Files:**
- Modify: branch history only by merging `583de05f3592c7d8e58c02f22f969e438c7d0bf0`
- Modify: `docs/superpowers/specs/2026-08-01-owntracks-cli-config-design.md`

**Produces:** #146 has the resolved geographic-admission types and a design document that names Accepted ADR-054 and the 99% CI policy.

- [ ] Verify `git status --short --branch` is clean and `git merge-tree` reports no conflict.
- [ ] Merge `583de05f3592c7d8e58c02f22f969e438c7d0bf0` with an explicit merge commit message `merge: incorporate geo admission baseline`.
- [ ] Update the design's activation prerequisite from Proposed ADR-053 to Accepted ADR-054/#169, and replace the obsolete exact-100% claim with the documented 99% policy.
- [ ] Run `cargo test -p pos-core --locked` and `cargo test -p pos-store --locked` to prove the baseline is sound.
- [ ] Commit only the baseline merge and design update.

### Task 2: Define the private enrollment contract in `pos-core`

**Files:**
- Create: `crates/pos-core/src/owntracks_enrollment.rs`
- Modify: `crates/pos-core/src/lib.rs`
- Modify: `crates/pos-core/src/error.rs`
- Test: unit tests in `crates/pos-core/src/owntracks_enrollment.rs`

**Produces:** `OwnTracksEnrollmentStateV1`, `OwnTracksEnrollmentFenceV1`, `OwnTracksCredentialVerifierV1`, and a narrow `OwnTracksEnrollmentStore` port. The port accepts only typed `pair`, `status`, `rotate`, and `revoke` requests and returns bounded state/outcome types.

- [ ] Write a failing core test that an absent state can pair once with a non-zero epoch, and a second pair is rejected.
- [ ] Run `cargo test -p pos-core owntracks_enrollment --locked`; confirm the test fails because the module and port are absent.
- [ ] Add private-field typed values containing the Timeline, EntityId, consent identity/revision/hash, policy version, withdrawal bit, binding revision, epoch, and 32-byte verifier; omit every plaintext credential field.
- [ ] Add tests for rotate, revoke, re-pair-after-revoke, stale/withdrawn policy rejection, epoch advancement, and bounded status display.
- [ ] Re-run the focused core tests and commit only the core contract and tests.

### Task 3: Implement Memory and SQLite enrollment parity

**Files:**
- Modify: `crates/pos-store/src/memory.rs`
- Modify: `crates/pos-store/src/sqlite.rs`
- Modify: `crates/pos-store/src/lib.rs`
- Create: `crates/pos-store/tests/owntracks_enrollment.rs`

**Produces:** both store adapters implement `OwnTracksEnrollmentStore`; SQLite creates the current pre-launch enrollment table directly and Memory maintains the same state transitions. The geographic-admission fence can be derived only from the same durable enrollment state.

- [ ] Write failing cross-adapter tests for pair/status/rotate/revoke/re-pair, verifier deletion on revoke, and unchanged state after each rejected transition.
- [ ] Run `cargo test -p pos-store --test owntracks_enrollment --locked`; confirm failure because no adapter capability exists.
- [ ] Implement the Memory state map and SQLite current-schema table/transaction without a migration path.
- [ ] Derive the `GeoLocationAdmissionFenceV1` from active enrollment only; missing, revoked, or withdrawn enrollment fails closed.
- [ ] Re-run the focused integration test, then `cargo test -p pos-store --locked`, and commit the parity implementation and tests.

### Task 4: Add owner-key and credential helpers in the Gateway binary

**Files:**
- Create: `apps/piglor-gateway/src/owntracks.rs`
- Modify: `apps/piglor-gateway/src/main.rs`
- Test: unit tests in `apps/piglor-gateway/src/owntracks.rs` and `apps/piglor-gateway/src/main.rs`

**Produces:** Unix-only owner-key creation/loading, random credential generation, domain-separated BLAKE3 verifier derivation, safe terminal formatting, and no plaintext persistence. Reuse the established `piglor-ledger` key-output safety pattern rather than creating a weaker file writer.

- [ ] Write a failing test that pair creates an owner-only 32-byte key at a new safe path and rejects an existing target or symlink.
- [ ] Run `cargo test -p piglor-gateway owntracks --locked`; confirm failure because the helper module is absent.
- [ ] Implement `create_or_load_owner_key`, `generate_pairing_credential`, and `derive_owntracks_verifier` with fixed application-specific BLAKE3 context strings; each credential comprises independent 32-byte handle and secret values.
- [ ] Add tests proving pair/rotate produce distinct verifiers, errors and status omit secret material, and unsupported platforms fail closed.
- [ ] Re-run focused Gateway tests and commit only the helper module/tests.

### Task 5: Wire the four local CLI commands without ingress activation

**Files:**
- Modify: `apps/piglor-gateway/src/main.rs`
- Modify: `apps/piglor-gateway/src/owntracks.rs`
- Test: `apps/piglor-gateway/src/main.rs`

**Produces:**
```text
piglor-gateway owntracks pair <sqlite-path> <owner-key-path> <timeline-id> <entity-id>
piglor-gateway owntracks status <sqlite-path>
piglor-gateway owntracks rotate <sqlite-path> <owner-key-path>
piglor-gateway owntracks revoke <sqlite-path>
```

- [ ] Write failing end-to-end command tests for all accepted argument forms and every malformed/missing argument form.
- [ ] Run the focused command tests and confirm the new subcommand is absent.
- [ ] Dispatch only the four accepted commands to the enrollment store; pair/rotate print a one-time local handle/secret, status prints state/policy only, revoke prints no credential data.
- [ ] Add a source-level boundary test that no OwnTracks route is registered and no CLI path invokes a geographic admission or generic append method.
- [ ] Run `cargo test -p piglor-gateway --locked`, then commit CLI wiring/tests.

### Task 6: Quality, review, and ticket evidence

**Files:**
- Modify: Redmine #146 journal and Notion work journal only

- [ ] Run formatter, `cargo test --workspace --locked -- --include-ignored`, pedantic clippy, and `./scripts/ci.sh` in a non-root test context.
- [ ] Record every command result in Redmine #146 and the Notion journal.
- [ ] Obtain CTO and independent code review; address all blocking findings in separate commits with focused re-tests.
- [ ] Push the verified non-activating CLI branch. Keep #146 In Progress because HTTP ingress remains separately gated.
