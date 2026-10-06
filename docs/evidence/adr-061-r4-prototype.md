# ADR-061 revision 4: Component compatibility prototype evidence

This is the compatibility gate evidence for ADR-061 revision 4 (Accepted
2026-10-06), produced by Redmine #539, slice 1 of the #538 community Plugin
Component host. ADR-061 revision 5 resolves findings F1, F2 and F6 below. As
revision 4 states, these gates apply to the #539 prototype evidence. They do
not re-accept the ADR.

The evidence is executable:

- `crates/pos-plugin-host` is the host engine.
- `crates/pos-plugin-host/tests/compatibility_gates.rs` runs the gates.
- `plugins/community/examples/compatibility-prototype` holds the guest sources,
  the negative variants and the committed Component fixtures.
- The `plugin-component-fixtures` CI job rebuilds every fixture from source
  with the pinned toolchains and requires identical bytes.

## Runtime pin

| Item | Value |
|---|---|
| Crate | `wasmtime` `=49.0.2` (newest stable release on 2026-10-06; MSRV 1.96) |
| Requested features | `default-features = false`, `component-model`, `cranelift`, `runtime` (ADR-061 revision 5, decision 2) |
| Resolved Wasmtime features | `component-model`, `cranelift`, `once_cell`, `runtime`, `std`, `wasmtime-jit-icache-coherence` |
| Rust toolchain | 1.97.1 (repository pin; the download is verified only by rustup's own checks) |
| Enforcement | `scripts/check_wasmtime_feature_pin.py` in the `dependency-policy` job |

`runtime` is the feature that lets the Component Model instantiate and call a
Component. Without it Wasmtime can only compile. `cranelift` implies `std`.
`std` enables two optional dependencies, which Cargo reports as the implicit
features `once_cell` and `wasmtime-jit-icache-coherence`.

The check reads `cargo metadata --locked --all-features`. It fails when:

- the version or source changes;
- the requirement is not exact;
- default features are enabled;
- the requested feature list changes;
- any other resolved package depends on Wasmtime;
- the resolved feature set differs from the table above.

`scripts/test_check_wasmtime_feature_pin.py` exercises each rejection.

The resolved feature set is recorded in two places: the pin checker
(`RESOLVED_FEATURES`) and this document. Recording it in the execution profile
and the ReproManifest is #540 and #541's work.

## Engine configuration

`engine_config()` sets each value below explicitly. Everything else keeps the
pinned Wasmtime 49.0.2 default and is fixed by the exact pin: Wasm proposal
flags, memory reservation and guard sizes, signals-based traps. #540 must
enumerate those defaults too when it records the Engine configuration in the
execution profile.

| Setting | Value | Reason |
|---|---|---|
| Strategy | Cranelift, `OptLevel::Speed` | Pinned compiler. Pulley is out of scope (non-goal). |
| `consume_fuel` | on | PMF1 fuel is Wasmtime fuel (decision 3). |
| `epoch_interruption` | on, deadline set per invocation | Operational watchdog only (decision 3). |
| `max_wasm_stack` | 524,288 bytes (`MAX_WASM_STACK_BYTES`) | `StackOverflow` maps to `stack-exhausted` (decision 6). |
| `cranelift_nan_canonicalization` | on | Deterministic NaN bit patterns. |
| `relaxed_simd_deterministic` | on | Deterministic relaxed-SIMD results. |
| `wasm_component_model` | on | The V1 world is a Component. |
| `wasm_backtrace_max_frames` | none | No backtraces are captured. |
| `wasm_backtrace_details` | `Disable` | Stops Wasmtime reading `WASMTIME_BACKTRACE_DETAILS` from the environment. |

The host also sets these limits:

- **Memory.** A store limiter charges every linear-memory reservation,
  instantiation included, against the negotiated effective `memory_bytes`.
  Denial is `MemoryLimitExceeded`.
- **Tables.** Each table is capped at 65,536 elements; growth beyond it is
  also `MemoryLimitExceeded`.
- **Store.** Every invocation runs in a fresh store and instance.

## Guest toolchains

All archives are fetched by `install-tools.sh` and checked against pinned
SHA-256 digests.

| Tool | Version | Use |
|---|---|---|
| Rust | 1.97.1, target `wasm32-unknown-unknown` | Rust guest (no WASI in the target). rustup installs it, verified only by rustup's own checks. |
| `wit-bindgen` crate | `=0.61.1`, `default-features = false`, `realloc` | Rust guest runtime support only |
| `wit-bindgen` CLI | 0.61.1 | Rust and C bindings |
| wasi-sdk | 34 (clang, wasi-libc `malloc`/`memcpy` only) | C guest |
| `wasm-tools` | 1.258.3 | `component new` (no WASI adapter), WAT variants, import check |
| BLAKE3 C sources | 1.8.7 (the workspace `blake3` release), portable implementation only | C guest `output-digest` |
| `blake3` crate | `=1.8.7`, `default-features = false` | Rust guest `output-digest` |

The `wit-bindgen` and `wasm-tools` versions are the ones Wasmtime 49.0.2 itself
builds and tests against (`wasmparser` 0.258).

Choice of the second language:

- **C.** Chosen. With wasi-sdk and wit-bindgen it links only `malloc` and
  `memcpy` from wasi-libc. `component new` runs without a WASI adapter, so a
  stray WASI import fails the build.
- **TinyGo.** Rejected. Its runtime imports WASI clocks, randomness and stdio.
  That violates default deny.

## Shared guest behaviour

Both guests implement this behaviour independently, and the host test checks it
against an in-test oracle.

- **`describe`** returns a fixed descriptor:
  - `plugin-id` is `pigloros.compatibility-prototype`, ABI 0.0–0.0 (the V1
    host's only minor, since #541 checks it against the negotiated release);
  - one event schema digest, `0x01` × 32; state schema digest `0x02` × 32;
  - manifest and release digests `0x00` × 32, which ADR-061 revision 6
    requires of every V1 guest (the host rejects any other value);
  - empty `capabilities`, `migrations`, `dependencies` and `required-features`.
- **`reduce` and `drive`**, in this order:
  1. If `observation-bytes` is `trap`, call `record-operational-log(2, "trapping")`,
     then trap with `unreachable`.
  2. Read `simulation-time`.
  3. Call `deterministic-random(deterministic-random-domain, timeline-position.seq, 16)`.
  4. Call `record-operational-log(1, "reduce" | "drive")`. A host error is
     returned as the guest error.
  5. Compute the FNV-1a 64-bit hash of `prior-state-bytes`,
     `observation-bytes`, the little-endian `simulation-time` and the random
     bytes.
  6. Return the hash `h` (little-endian, 8 bytes) as follows:
     - `next-state-bytes` is `h`, and `next-state-schema` echoes
       `prior-state-schema`;
     - one EventDraft: schema 1, `entity-id` set to the `invocation-id`,
       type `prototype.reduced` or `prototype.driven`, payload `h`;
     - `output-digest` is the V1 output digest of the other fields (see
       `plugin_output_digest_v1` in
       `crates/pos-runtime/src/community_plugin_host/contract.rs`, the
       ADR-061 revision 6 definition); `invocation-id` is echoed;
     - every other list is empty.
- **`migrate-state`** returns `guest-declared-failure(1)`. A V1 host never
  calls it, and `GuestExport` cannot name it.

The host serves `deterministic-random` as BLAKE3 extendable output keyed by the
32-byte domain and read from `offset`, up to 4,096 bytes per call.
`record-operational-log` accepts at most the effective `log_calls` (64 or
fewer) and `log_bytes`, each message at most 256 UTF-8 bytes. Every `host-v1`
call counts against `host_calls`.

## Budget measurements

The values below are exact. Fuel and memory are deterministic for the pinned
Wasmtime and the fixture bytes, and `budget_measurements_match_the_recorded_evidence`
asserts every value. They are the #541 fixtures (ABI 0.0 and the V1
`output-digest`), run through the engine under the default V1 profile; each
`reduce` makes 3 `host-v1` calls and `describe` none.

| Guest | Component bytes | Call | Startup fuel | Call fuel | Linear memory reserved |
|---|---:|---|---:|---:|---:|
| Rust | 51,947 | `describe` | 1 | 3,113 | 1,179,648 |
| Rust | | `reduce`, 11-byte observation | 1 | 21,112 | 1,179,648 |
| Rust | | `reduce`, 1 MiB observation | 1 | 16,798,314 | 2,293,760 |
| C | 88,893 | `describe` | 19 | 3,019 | 131,072 |
| C | | `reduce`, 11-byte observation | 19 | 20,744 | 131,072 |
| C | | `reduce`, 1 MiB observation | 19 | 9,982,361 | 1,179,648 |

The V1 output digest costs each guest about 12,000 fuel per `reduce`.

Observations:

- **Hashing cost.** The Rust guest spends about 16 fuel per hashed byte and the
  C guest about 9.5.
- **Fuel budgets.** A 1 MiB observation, the semantic maximum, therefore needs
  a PMF1 fuel budget well above 10⁷.
- **Rust memory baseline.** The Rust guest's 1,179,648-byte baseline is rustc's
  default 1 MiB shadow stack plus data. The C guest starts at two pages.
- **Exactness.** The memory limit is exact. Reserving the measured peak
  succeeds, and one page less fails with `MemoryLimitExceeded`.
- **Wall time.** Wall-clock startup and compilation time are not measured
  here. They are operational and nondeterministic, and they belong to the
  #542 worker watchdog.

## Gate status

| Gate (ADR-061 "Compatibility gates") | Status | Evidence or owner |
|---|---|---|
| The pinned Rust toolchain builds the host without weakening supply-chain gates | **Proven**, subject to green CI on PR #413 | Rust 1.97.1 builds Wasmtime 49.0.2. `cargo deny --locked check`, `cargo audit`, `cargo shear`, geiger and the pinned-Action policy run unchanged. `deny.toml` is unchanged. |
| At least two guest languages implement the same world | **Proven**; finding F1 resolved by revision 5 | The Rust and C guests produce identical results, equal to the oracle, over 3 repetitions, for `describe`, `reduce` and `drive`, and with a 1 MiB observation. |
| Startup, invocation, memory and artifact-size budgets are measured | **Proven** for fuel, memory and size | See the table above. Wall time is deferred to #542. |
| No ambient resource access | **Proven at load time** | A WASI import, an undeclared `host-v1` function, and a mistyped `simulation-time`, `deterministic-random` or `record-operational-log` are all rejected by `load` before execution (F3 resolved by #541). Both guests import only `host-v1` and the types-only `contract-v1`. The engine reads no environment variable. |
| Identical output under Local and Air-Gapped profiles | **Deferred** to #540 (profiles) and #542 (worker) | The engine has no mode-dependent input, and outputs are identical across guests and repetitions. The two host-owned profiles do not exist yet. **This gate is open:** "No P0 gate failed" does not cover it, and #540 and #542 must close it before ADR-061 is treated as gate-clean. |
| Traps and budget exhaustion cannot partially commit | **Proven in the engine (#541)** | A failure returns only the closed `CommunityPluginHostErrorV1`, which carries no guest data, and each store is dropped on failure. A trap after a successful `record-operational-log` returns nothing, and so does fuel exhaustion halfway through hashing a 1 MiB observation. The atomic Tick Boundary commit is #543. |
| Licence and MIT-distribution review | **Inventory done; no allow-list change** | See below. A formal legal review is for the owner. |

No P0 gate failed.

The #539 prototype's placeholder outcomes (`HostCallRejected`, `Rejected`,
`ComponentTrap(Trap)`, and the public `Trap` and `Val` re-exports) are gone.
#541 reports every failure as the closed `CommunityPluginHostErrorV1` of #540:
host-call bounds are `HostCallLimitExceeded`, log and output bounds
`OutputLimitExceeded`, malformed guest values and Canonical ABI lift failures
`InvalidGuestOutput`, and traps their pinned trap-table class.

## Licence inventory

The pin adds these crates to `Cargo.lock`. Every licence is already allowed by
`deny.toml`.

| Licence | Crates |
|---|---|
| Apache-2.0 WITH LLVM-exception | `wasmtime`, `wasmtime-environ`, `wasmtime-internal-*`, `cranelift-*`, `pulley-*`, `regalloc2`, `target-lexicon` |
| Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | `wasmparser`, `wasm-encoder`, `wasm-metadata`, `wasmprinter`, `wit-parser`, `wit-component` |
| MIT OR Apache-2.0 (any spelling) | `addr2line`, `anyhow`, `arbitrary`, `block-buffer`, `cobs`, `core_detect`, `cpp_demangle`, `cpufeatures`, `crypto-common`, `digest`, `embedded-io`, `futures`, `gimli`, `heck`, `id-arena`, `leb128fmt`, `memfd`, `multiversion_no_op`, `object`, `postcard`, `rustc-demangle`, `rustc-hash`, `sha2` 0.10 |
| BSD-2-Clause OR MIT OR Apache-2.0 | `mach2` (macOS only) |
| MIT | `generic-array` |
| (Apache-2.0 OR MIT) AND BSD-3-Clause | `encoding_rs` |

Notes for the owner's review:

- **Permissive licences.** Apache-2.0 WITH LLVM-exception is permissive and
  compatible with distributing PiglorOS under MIT.
- **Binary distributions.** They must carry the upstream licence texts and
  notices. No notice bundle is generated yet.
- **Guest-side tools.** The `wit-bindgen` crate, the wasi-sdk sysroot and
  `wasm-tools` are build-time only for test fixtures. They are not linked into
  the host. `wit-bindgen` is Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR
  MIT. wasi-libc is Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT, and
  its third-party parts include CC0 `dlmalloc` and MIT musl code. The C guest
  fixture statically contains those parts.
- **OCI, SLSA and SPDX terms.** They are not touched by this slice.

## Findings for later slices and the owner

### F1. The accepted WIT is not parseable as written

`plugins/community/wit/pigloros-plugin.wit` names two record fields `world`, in
`dependency-descriptor` and `plugin-descriptor`. `world` is a WIT keyword, so
`wit-parser` (all current `wit-bindgen` and `wasm-tools`) rejects the file:

```text
expected an identifier or string, found keyword `world`
```

The standard fix is the escape `%world`. It is lexical only: it names the same
field, `world`, so the component type, and therefore the world, is unchanged.

**Resolved by ADR-061 revision 5 (decision 1).** The owner amended the ADR's
WIT block in place to `%world: bounded-text`, and the canonical file is again
byte-identical to it, so it now parses. `build-fixtures.sh` builds from the
canonical file directly; the build-time escaped copy is gone. The committed
Components and `SHA256SUMS` are unchanged: they were built from the escaped
copy, which equals the new canonical file.

The WIT's BLAKE3 digest, which `pos-conformance::wave8_plugin_boundary()`
computes from the file, changed from
`688d4f69f958f2d1ebb56d02c58440235eb53180d8bf671cd7dd9128d9ea7cda` to
`fa661f549a9e9ad4383ac5d7ba457f073ca76644725e16f286a4dd0d0323a73b`. The
boundary's manifest and release digests are derived from it at run time. No
committed fixture, golden vector or evidence value carries any of them.

### F2. The trap table and the pinned Wasmtime trap codes

**Resolved by ADR-061 revision 5 (decision 3); #541 builds the pinned table.**

- **`AlwaysTrapAdapter`.** The revision 4 table lists it, but the `Trap` enum
  of Wasmtime 49.0.2 has no such code. The enum is defined in
  `wasmtime-environ` 49.0.2, `src/trap_encoding.rs`.
- **Unlisted codes.** 49.0.2 adds codes the table does not list. They fall
  under "other".
- **Lift codes.** `InvalidChar`, `StringOutOfBounds`, `ListOutOfBounds`,
  `InvalidDiscriminant` and `UnalignedPointer` are canonical-ABI lift
  failures. When they arise while lifting a guest return, decision 6 makes
  them `InvalidGuestOutput`, not `ComponentTrap`.

**Resolved by ADR-061 revision 5 (decision 3) and #541.** The engine builds
the pinned table from the 50 `wasmtime::Trap` codes of 49.0.2
(`crates/pos-plugin-host/src/runtime.rs`), so `AlwaysTrapAdapter` is absent
and every unlisted code is `other`. The lift codes are raised only by fused
adapters between Components inside one guest. The host's own lift of a guest
return reports a failure without a trap code, and the engine maps it to
`InvalidGuestOutput`.

### F3. Dynamic host functions are not type-checked at load

`simulation-time` is a typed definition, so a mistyped import fails at load.
`deterministic-random` and `record-operational-log` take record arguments.
They are defined with Wasmtime's dynamic `func_new`, because the typed
bindings (`bindgen!` and the `ComponentType` derives) emit `unsafe impl`,
which the workspace `unsafe_code = "forbid"` lint rejects.

A mistyped import of either function therefore linked, then failed closed at
call time.

**Resolved by #541.** `load` compares every imported function's type
structurally with the exact `host-v1` signature before linking
(`crates/pos-plugin-host/src/signatures.rs`). The same module checks the
`describe`, `reduce` and `drive` export types at load.

### F4. Guest memory baseline

A Rust guest's default 1 MiB shadow stack reserves 1.1 MiB before any work. An
execution profile ceiling below that rejects every unmodified Rust guest. The
V1 profile ceiling is 64 MiB, and the #541 compatibility gates run both guests
under it.

### F5. Fuel is checked at function entries and loop headers

Wasmtime charges fuel per operator, but traps only when a check finds the
budget spent. A budget slightly below the measured consumption can therefore
still complete when the overshoot is straight-line code after the last check.
For the pinned version and fixture bytes, the outcome at any given budget is
still deterministic.

The exhaustion edge is not "consumed fuel exceeds the budget by one". The #541
tests therefore assert only the outcome at the measured total and well below
it, never a budget-minus-one edge.

### F6. `runtime` is a third requested feature

**Resolved by ADR-061 revision 5 (decision 2).**

Decision 2 allows `component-model` and `cranelift` "plus only those features
Cargo requires them to imply". Neither feature implies `runtime`. Without it,
Wasmtime 49.0.2 can compile a Component but has no `Store` or `Linker`, so it
cannot instantiate or call one. The #539 brief anticipated it ("plus whatever
those strictly require to compile and run, for example `runtime`").

The owner should acknowledge `runtime` as part of the pinned feature set, or
amend decision 2's wording. The CI check pins it, so any change is visible.
