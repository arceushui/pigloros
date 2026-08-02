# OwnTracks V1 Ingress Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the explicit loopback-only OwnTracks V1 route that authenticates one active enrollment and atomically admits only the existing minimized `geo.location` Event.

**Architecture:** The HTTP adapter bounds and minimizes input, then sends credentials and canonical V1 bytes through a private executor command. The startup-loaded owner key remains in private executor state. That command alone verifies enrollment, rate-limits with opaque per-binding state, builds admission inputs, and invokes the existing geographic admission transaction.

**Tech Stack:** Rust 1.97.1, Axum 0.8, Tokio, BLAKE3, `pos-core`, `pos-store`, and `pos-plugin-geo`.

## Global Constraints

- Loopback `serve <addr> <sqlite-path> --owntracks-owner-key <path>` alone can register the route; omission leaves it absent and non-loopback stays spectator-only.
- Every request uses `axum::body::to_bytes(body, 65_536)`; the 65,537th byte maps to `413`, including chunked input.
- Only zero bytes yield unauthenticated `200 []`; every nonempty body requires JSON and Basic.
- Persist only current V1 0.1-degree/15-minute `geo.location` bytes from `_type = "location"`, finite WGS84 coordinates, and integer `tst`.
- Owner key, credentials, verifier, fence, raw body, exact location/time, opaque rate key, Timeline, EntityId, Event ID, sequence, and snapshot identity never reach logs, metrics, journals, or responses.
- Rate limit after authentication inside private executor state: one request per second, burst five per opaque binding key.
- No `geo.cell`, generic append, migration, backfill, dual-write, upcast, public/same-LAN route, TLS, MQTT, encryption, UI, export, or new dependency.
- Use capability-dropped full checks; the approved repository floor is at least 99% line and region coverage, with independent review and fresh activation approval mandatory.

---

### Task 1: Authenticated ingress capability

**Files:**
- Create: `crates/pos-core/src/owntracks_ingress.rs`
- Modify: `crates/pos-core/src/lib.rs`, `crates/pos-store/src/memory.rs`, `crates/pos-store/src/sqlite.rs`
- Test: `crates/pos-store/tests/owntracks_ingress.rs`

**Interfaces:** Produces `OwnTracksIngressStore::prepare_owntracks_ingress(OwnTracksIngressInputV1) -> Result<PreparedOwnTracksIngressV1, CoreError>`. The prepared value has private fields and exposes only `rate_key()` to the executor and `into_admission_request()` for same-turn geographic admission.

- [ ] **Step 1: Write failing Memory/SQLite contracts**

```rust
assert!(store.prepare_owntracks_ingress(valid_input()).is_ok());
assert!(store.prepare_owntracks_ingress(invalid_basic()).is_err());
store.revoke_owntracks_enrollment().unwrap();
assert!(store.prepare_owntracks_ingress(valid_input()).is_err());
```

- [ ] **Step 2: Confirm contracts fail**

Run: `cargo test -p pos-store --test owntracks_ingress --locked`

Expected: FAIL because the ingress trait and input do not exist.

- [ ] **Step 3: Implement opaque core input and adapters**

```rust
pub trait OwnTracksIngressStore {
    fn prepare_owntracks_ingress(&mut self, input: OwnTracksIngressInputV1)
        -> Result<PreparedOwnTracksIngressV1, CoreError>;
}
```

Adapters derive the candidate keyed verifier, compare constant-time, resolve active enrollment, domain-separate the opaque rate key and dedup input, and construct `GeoLocationAdmissionRequestV1`. Refuse invalid, missing, revoked, withdrawn, and mismatched state before producing a prepared value; the executor invokes existing admission after its rate decision.

- [ ] **Step 4: Verify and commit**

Run: `cargo test -p pos-store --test owntracks_ingress --locked && cargo clippy -p pos-core -p pos-store --all-targets -- -D warnings -W clippy::pedantic`

```bash
git add crates/pos-core/src/owntracks_ingress.rs crates/pos-core/src/lib.rs crates/pos-store/src/memory.rs crates/pos-store/src/sqlite.rs crates/pos-store/tests/owntracks_ingress.rs && git commit -m "feat: add authenticated OwnTracks ingress capability"
```

### Task 2: Executor-owned rate and notice semantics

**Files:**
- Modify: `apps/piglor-gateway/src/executor.rs`, `apps/piglor-gateway/src/lib.rs`
- Test: `apps/piglor-gateway/src/executor.rs`

**Interfaces:** Produces a private ingress command and a Gateway method that broadcasts only accepted commits.

- [ ] **Step 1: Write failing executor tests**

```rust
for _ in 0..5 { assert!(gateway.admit_owntracks_ingress(valid_input()).await.is_ok()); }
assert!(gateway.admit_owntracks_ingress(valid_input()).await.unwrap().is_rate_limited());
assert_no_notice_after_duplicate_or_denial(&mut notices).await;
```

- [ ] **Step 2: Confirm tests fail**

Run: `cargo test -p piglor-gateway owntracks_ingress --locked`

Expected: FAIL because no executor command or limiter exists.

- [ ] **Step 3: Implement private command and limiter**

```rust
OwnTracksIngress { input, reply }
```

Authenticate first, then use a cardinality-bounded private `HashMap<OpaqueBindingRateKey, TokenBucket>` with expired-entry eviction. Admit only after allowance succeeds; publish notice only for definite accepted results.

- [ ] **Step 4: Verify and commit**

Run: `cargo test -p piglor-gateway owntracks_ingress --locked && cargo clippy -p piglor-gateway --all-targets -- -D warnings -W clippy::pedantic`

```bash
git add apps/piglor-gateway/src/executor.rs apps/piglor-gateway/src/lib.rs && git commit -m "feat: route OwnTracks ingress through executor"
```

### Task 3: Strict HTTP decoding and opt-in loopback route

**Files:**
- Create: `apps/piglor-gateway/src/owntracks_http.rs`
- Modify: `apps/piglor-gateway/src/http.rs`, `apps/piglor-gateway/src/lib.rs`, `apps/piglor-gateway/Cargo.toml`
- Test: `apps/piglor-gateway/src/owntracks_http.rs`

**Interfaces:** Consumes cloned `Gateway`, startup-loaded owner key, request `Body`, and headers. Produces an opt-in loopback route and stable bounded responses.

- [ ] **Step 1: Write failing route contracts**

```rust
assert_response(empty_post(), StatusCode::OK, "[]").await;
assert_response(chunked_body(65_537), StatusCode::PAYLOAD_TOO_LARGE, "body_too_large").await;
assert_response(valid_basic_location(), StatusCode::OK, "[]").await;
assert_route_missing(spectator_router(state), "/v1/bridges/owntracks").await;
```

- [ ] **Step 2: Confirm route tests fail**

Run: `cargo test -p piglor-gateway owntracks_http --locked`

Expected: FAIL because the module and route do not exist.

- [ ] **Step 3: Implement bounded parse, minimize, and taxonomy**

```rust
let bytes = axum::body::to_bytes(body, 65_536).await.map_err(map_body_limit)?;
if bytes.is_empty() { return Ok(empty_owntracks_response()); }
require_json_content_type(&headers)?;
let basic = parse_basic(&headers)?;
let payload = parse_and_minimize_location(&bytes)?;
```

Allow-list only required fields, discard extra telemetry before creating the existing V1 canonical payload, and map: Basic `401`; fenced/conflict `403`; media `415`; semantic `422`; rate `429` plus `Retry-After`; unavailable/unknown/saturation `503`. Register the route only when the loopback router receives a key; leave spectator routes unchanged. Add a source-level guard against generic append, `geo.cell`, raw-body persistence, and sensitive logging.

- [ ] **Step 4: Verify and commit**

Run: `cargo test -p piglor-gateway --locked && cargo clippy -p piglor-gateway --all-targets -- -D warnings -W clippy::pedantic`

```bash
git add apps/piglor-gateway/src/owntracks_http.rs apps/piglor-gateway/src/http.rs apps/piglor-gateway/src/lib.rs apps/piglor-gateway/Cargo.toml && git commit -m "feat: add loopback OwnTracks ingress route"
```

### Task 4: Explicit serve activation and final evidence

**Files:**
- Modify: `apps/piglor-gateway/src/main.rs`, `apps/piglor-gateway/src/owntracks.rs`
- Test: `apps/piglor-gateway/src/main.rs`

**Interfaces:** Consumes `serve <addr> <sqlite-path> --owntracks-owner-key <path>` and existing owner-key validation. Produces route state only when a safe existing owner key and SQLite store are explicitly provided.

- [ ] **Step 1: Write failing startup configuration tests**

```rust
assert!(run_with_args(&serve_without_sqlite_and_key()).is_err());
assert_owntracks_route_absent(ordinary_loopback_serve()).await;
assert_owntracks_route_absent(non_loopback_serve_with_key()).await;
```

- [ ] **Step 2: Confirm startup tests fail**

Run: `cargo test -p piglor-gateway --bin piglor-gateway --locked`

Expected: FAIL because `serve` does not parse the opt-in key argument.

- [ ] **Step 3: Parse and validate activation**

```text
serve <addr> <sqlite-path> --owntracks-owner-key <path>
```

Reject absent SQLite, missing/unsafe/invalid key, repeated flag, and extra arguments with no-secret bounded errors. Load an existing key once; never create or rotate it while serving. Pass it only into private route/executor composition.

- [ ] **Step 4: Run full quality evidence**

Run: `capsh --drop=cap_dac_override,cap_dac_read_search -- -c 'cargo test --workspace --locked -- --include-ignored'`

Run: `capsh --drop=cap_dac_override,cap_dac_read_search -- -c './scripts/ci.sh'`

Run: `RUSTC_BOOTSTRAP=1 capsh --drop=cap_dac_override,cap_dac_read_search -- -c 'cargo llvm-cov --workspace --locked --summary-only --fail-under-lines 99 --fail-under-regions 99 -- --include-ignored'`

Expected: all checks pass and coverage meets the approved 99% line-and-region floor for the changed V1 path.

- [ ] **Step 5: Obtain reviews, record approval, commit, and push**

Record test evidence, independent/CTO review, and fresh route-activation approval in Redmine #146 and Notion. Then run:

```bash
git add apps/piglor-gateway/src/main.rs apps/piglor-gateway/src/owntracks.rs && git commit -m "feat: configure local OwnTracks ingress" && git push origin ticket-146-owntracks-ingress
```
