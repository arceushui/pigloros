# H3 Cell Codec Implementation Plan

> For agentic workers: REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Implement the accepted ADR-031 Wave 6 inert GeoCellV1 value codec and private H3 reference-cloaker adapter for Redmine #142.

**Architecture:** Add a feature-gated geo_cell module to the existing pos-plugin-geo crate. Keep the public value independent of h3o, validate all H3 identity at construction/decode, and use the existing pos-crypto::canonical encoder plus a strict ciborium::Value structural decoder. Do not add an Event writer, reader, capability, route, migration, dual-write, or activation path.

**Tech Stack:** Rust 1.97.1, h3o = "=0.10.0" with default-features = false, ciborium, serde, existing Wgs84Point, RFC 8949 canonical CBOR, Cargo feature h3 disabled by default.

## Global Constraints

- ADR-031/034/037 and CTO approval authorize only the inert Wave 6 value/adapter; #149 owns future geo.cell Event activation.
- H3 Core conformance baseline is v4.5.0 commit 1b536c34225191ba24a75a840f634d4a48c3b206; h3o is pinned to 0.10.0 with no enabled features.
- Public APIs must not expose h3o types, raw coordinate pairs, or arbitrary H3 index modes.
- GeoCellV1 bytes are exactly the four-field 61-byte canonical CBOR value specified in the approved spec.
- No historical migration, upcast, backfill, dual-write, schema registration, writer, reader, capability, route, or production configuration is added.
- Existing geo.location, Wgs84Point, SpatialCloaker, and reserved geo.cell boundary behavior remain unchanged.
- Every new production branch is covered by tests; repository gates remain at least 99% line and region coverage.
- Use CARGO_TARGET_DIR=/root/pigloros/target for local checks to avoid duplicating Rust build artifacts across worktrees.

---

### Task 1: Feature scaffolding and CI execution surface

**Files:**
- Modify: plugins/geo/Cargo.toml
- Modify: plugins/geo/src/lib.rs
- Modify: scripts/ci.sh
- Modify: .github/workflows/ci.yml
- Modify: .github/workflows/trunk-check.yml only if its Rust test command must match the feature-enabled policy

**Interfaces:**
- Produces the disabled-by-default h3 feature and optional pinned h3o dependency.
- Exports geo_cell only under cfg(feature = "h3").
- Makes test, clippy, and coverage gates run the feature-enabled workspace so the new seam is not unverified.

- [x] Step 1: Add exactly this dependency shape:

~~~toml
[features]
default = []
h3 = ["dep:h3o"]

[dependencies]
h3o = { version = "=0.10.0", default-features = false, optional = true }
~~~

Do not enable std, serde, geo, tools, or typed_floats.

- [x] Step 2: Add cfg(feature = "h3") pub mod geo_cell and feature-gated re-exports. Do not register geo.cell or change any existing Plugin capability.

- [x] Step 3: Make authoritative local and GitHub Rust test, clippy, and coverage commands include --all-features while preserving --workspace, --locked, --include-ignored, and the 99% line/region thresholds. Keep dependency policy behavior unchanged.

- [x] Step 4: Run:

~~~bash
CARGO_TARGET_DIR=/root/pigloros/target cargo check -p pos-plugin-geo --no-default-features --locked
CARGO_TARGET_DIR=/root/pigloros/target cargo check --workspace --all-targets --no-default-features --locked
CARGO_TARGET_DIR=/root/pigloros/target cargo tree -e features --locked --features h3 -i h3o
~~~

Expected: no-default check succeeds without the optional adapter; the feature tree shows h3o 0.10.0 with no std, serde, geo, tools, or typed_floats feature.

- [x] Step 5: Commit:

~~~bash
git add plugins/geo/Cargo.toml plugins/geo/src/lib.rs scripts/ci.sh .github/workflows/ci.yml .github/workflows/trunk-check.yml
git commit -m "build: gate h3 codec feature in geo plugin"
~~~

### Task 2: RED tests for the public value and strict wire contract

**Files:**
- Create: plugins/geo/src/geo_cell.rs
- Test: unit tests in the feature-gated module

**Interfaces:**
- Consumes Wgs84Point, CanonicalBytes, and h3o from Task 1.
- Produces failing tests defining H3Resolution, GeoCellV1, H3ReferenceCloaker, GeoCellError, exact bytes, and strict decode behavior.

- [x] Step 1: Add the known-answer contract:

~~~rust
let cloaker = H3ReferenceCloaker::new();
let cell = cloaker.parse("8928308280fffff").unwrap();
assert_eq!(cell.index(), "8928308280fffff");
assert_eq!(cell.resolution().value(), 9);
assert_eq!(cell.encode_v1().unwrap().as_slice(), EXPECTED_FIXTURE);
assert_eq!(GeoCellV1::decode_v1(&cell.encode_v1().unwrap()).unwrap(), cell);
~~~

- [x] Step 2: Add tests for repeated deterministic encodes, all resolutions 0–15, invalid resolution 16, invalid/non-cell/uppercase/prefixed/wrong-length indexes, missing/unknown/duplicate/wrong-type fields, trailing bytes, nonminimal CBOR, indefinite maps, resolution mismatch, unsupported format/system, and finer parent requests.

- [x] Step 3: Add ordinary H3 Core known answers, negative zero, +180 versus -180, both poles, points immediately around a captured boundary, equal parent, coarser parent, refusal to refine, and unchanged Wgs84Point validation.

- [x] Step 4: Run:

~~~bash
CARGO_TARGET_DIR=/root/pigloros/target cargo test -p pos-plugin-geo --all-features geo_cell --locked
~~~

Expected: compile or assertion failures because implementation does not yet exist.

- [x] Step 5: Commit the RED tests:

~~~bash
git add plugins/geo/src/geo_cell.rs
git commit -m "test: define h3 cell codec contract"
~~~

### Task 3: Implement validated value construction and strict codec

**Files:**
- Modify: plugins/geo/src/geo_cell.rs

**Interfaces:**
- Consumes the RED tests and existing canonical encoder.
- Produces validated public values, exact canonical bytes, strict one-item decoding, and stable typed errors.

- [x] Step 1: Implement H3Resolution and private validated address storage using a u8 resolution newtype and fixed [u8; 15] lowercase ASCII address buffer. Expose only index and resolution accessors.

- [x] Step 2: Implement the canonical wire representation with an internal serializable V1 wire struct containing cell_format, system, index, and resolution; use pos_crypto::canonical::encode and retain invariant-only failure handling for the fixed serializer shape per CTO review.

- [x] Step 3: Decode into ciborium::value::Value through a Cursor, require exactly one item and cursor position equal to input length, match exactly four text-keyed fields, reject duplicates and alternate types, validate the index and derived resolution, canonical re-encode, and compare bytes.

- [x] Step 4: Run focused tests and formatting:

~~~bash
CARGO_TARGET_DIR=/root/pigloros/target cargo test -p pos-plugin-geo --all-features geo_cell --locked
cargo fmt --all
~~~

Expected: all codec tests pass; remaining failures identify adapter or fixture behavior.

- [x] Step 5: Commit:

~~~bash
git add plugins/geo/src/geo_cell.rs
git commit -m "feat: add strict versioned geo cell codec"
~~~

### Task 4: Implement the private H3 reference-cloaker adapter

**Files:**
- Modify: plugins/geo/src/geo_cell.rs
- Modify: plugins/geo/src/lib.rs only if re-export organization requires it

**Interfaces:**
- Consumes validated Wgs84Point, H3Resolution, and private value constructors.
- Produces deterministic WGS84-to-H3 conversion, canonical parsing, and coarsening without leaking h3o types.

- [x] Step 1: Normalize only at the adapter boundary: -0.0 to 0.0, +180.0 to -180.0, and pole longitude to 0.0. Pass finite values to h3o::LatLng::new and convert with to_cell.

- [x] Step 2: Require exactly 15 lowercase ASCII hex characters before str::parse::<h3o::CellIndex>(); compare CellIndex::to_string() to the input and reject mismatch. Derive stored resolution from CellIndex::resolution.

- [x] Step 3: Map equal/coarser H3Resolution targets to h3o::Resolution, call CellIndex::parent, format the result, and construct a new value. Return a stable finer-parent error for a target above source resolution.

- [x] Step 4: Run:

~~~bash
CARGO_TARGET_DIR=/root/pigloros/target cargo test -p pos-plugin-geo --all-features --locked
CARGO_TARGET_DIR=/root/pigloros/target cargo tree -e features --locked --features h3 -i h3o
~~~

Expected: ordinary, boundary, parent, pentagon, and invalid-input tests pass; h3o optional features remain disabled.

- [x] Step 5: Commit:

~~~bash
git add plugins/geo/src/geo_cell.rs plugins/geo/src/lib.rs
git commit -m "feat: add private h3 reference cloaker"
~~~

### Task 5: Full quality gates and scope review

**Files:** none unless verification finds a defect.

- [x] Step 1: Run:

~~~bash
cd /root/pigloros-ticket-142-h3-cell-codec
CARGO_TARGET_DIR=/root/pigloros/target ./scripts/ci.sh 2>&1 | tee /tmp/pigloros-142-ci.log
~~~

Require CI gates OK, zero ignored tests, no policy violations, clean formatting, pedantic Clippy, and at least 99% line and region coverage. Record unavailable local tools separately; remote CI is authoritative.

- [x] Step 2: Verify scope:

~~~bash
git diff origin/main...HEAD --stat
git diff origin/main...HEAD -- crates/pos-core crates/pos-store apps plugins/geo scripts .github
rg -n 'geo.cell|EventStore|append|Capability|Gateway|migration|upcast|dual.?write' plugins/geo/src/geo_cell.rs plugins/geo/src/lib.rs
~~~

Confirm no Event admission or disclosure path and no changes to the reserved boundary outside feature-enabled CI execution.

- [x] Step 3: Commit any narrowly scoped verification correction and rerun focused plus full gates.

### Task 6: CTO review, rebase, publish, and merge

- [x] Step 1: Send Harvey the branch diff, exact gate output, feature-tree output, and inertness checklist. Do not publish or merge after REQUEST_CHANGES.

- [x] Step 2: For every finding, add or adjust a test first, implement the minimal correction, rerun focused gates, then rerun the full CI script.

- [ ] Step 3: Refresh and rebase the complete branch history:

~~~bash
git fetch origin
git rebase origin/main
git status --short --branch
~~~

Resolve conflicts without destructive reset commands; rerun full gates after the rebase.

- [ ] Step 4: Use the GitHub publishing workflow to push the intentionally committed branch and open a draft PR with the #142 link, ADR boundary, gate evidence, and no-activation statement.

- [ ] Step 5: After required remote checks and CTO approval are green, squash-merge the PR, fast-forward local main, push main, and verify post-merge checks on the merged SHA.

### Task 7: Reconcile tracking and clean worktrees

- [ ] Step 1: Update Redmine #142 with ADR/CTO approval, implementation commits, merged PR/SHA, gate result, and no-activation boundary; resolve and set 100% if accepted.

- [ ] Step 2: Reconcile parent #64 from its current child statuses without changing unrelated ADR or ticket records.

- [ ] Step 3: Append Notion closeout with approved scope, tests/gates, merged SHA, remote CI, tracker updates, and the next pending roadmap task. Tag the entry if a tracker or approval remains pending.

- [ ] Step 4: Verify the branch is merged and clean, remove only /root/pigloros-ticket-142-h3-cell-codec with git worktree remove, preserve active unmerged #169, then recheck worktrees, main status, and disk usage.

## Self-review

Every ADR-031 value/adapter requirement is covered by Tasks 2–4. Inertness and no-activation are covered by Tasks 1 and 5. The disabled-by-default feature is exercised by explicit all-feature gates. No task adds migration, Event admission, disclosure, or database migration. Every production behavior has focused tests and full-gate verification.
