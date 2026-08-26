# Public conformance fixture sources

These files are the public, deterministic inputs and expected-result records
for the seven CPF1 claim layers. Each directory under `profiles/` is a
separate public profile manifest and binds exactly one claim layer to all seven
required fixture families: positive, negative, malformed, resource, deletion,
downgrade, and independent evaluation. They contain no implementation-private
state, credentials, or signing material.

The immutable bundle boundary in `pos-conformance` accepts these bytes from a
caller, recomputes each BLAKE3 content address, binds the CPF1 profile digest,
and signs only the canonical manifest. Local and Air-Gapped manifests must be
materialized separately with the same expected-result records; the Air-Gapped
profile capability policy remains network-deny.

The scenario names intentionally cover positive, negative, malformed, resource
limit, deletion, downgrade, and independent-evaluation cases. A profile
manifest lists every family explicitly; no profile is represented by a single
input/result pair.

The seven public input/result records describe fixture families only; they do
not embed a claim-layer identity. Materialization binds each family once to
the enclosing claim layer for deterministic-local-v1 and once for
deterministic-air-gapped-v1, so every emitted descriptor has exactly one
ExecutionProfile while the paired bundles retain identical expected bytes.

`SHA256SUMS` is the independent byte inventory for all seven profile manifests,
seven input records, seven expected-result records, the ADR-059 matrix, and
seven required support artifacts. The #172 authority inventory is retained as
a Draft handoff with pending slots; no authority bytes are checked in or
bundled until the concrete handoff arrives.
The hosted verifier independently checks every available public digest before
bundle materialization.

The support SBOM is intentionally scoped to the published fixture artifact,
which contains public data and contract documents rather than compiled code or
its build environment. It therefore has no software components. The Rust
workspace and the materializer toolchain are outside that artifact boundary;
their dependency/advisory checks remain CI responsibilities (`cargo-deny`,
`cargo-audit`, and the pinned toolchain). The checked-in `SHA256SUMS` file is
the byte-integrity authority for this scoped support record.

The canonical architecture decisions for the CPF1 and authority workflow are
ADR-058 through ADR-062 on the [Redmine project wiki](https://redmine.piglor.com/projects/pigloros/wiki).

Repository settings must require the `ci-gate` check for protected branches;
adding a workflow job does not change GitHub branch-protection rules. The
mutation workflow has its own `diff mutation testing` fan-in check, which must
also remain required for changes that run that workflow.

The support directory contains the normative specification, schema, licence,
notice, SBOM, provenance, and limitations members that every immutable bundle
manifest must declare.

The Draft `matrix/execution-matrix.json` records all twelve accepted
non-interference rows and their 192 required Local/Air-Gapped/Replay/Fork
variant cases, with the row-specific AuthEq/PublicEq/OpEq predicates from
ADR-059. `expected-authority/inventory.json` records the eleven #172
handoff vectors as pending Draft slots with no asserted fixture or
expected-result digest. The matrix and authority inventory remain Draft until
the downstream authority/non-interference work supplies concrete bytes,
expected results, and independent review.

Every emitted Draft Local/Air-Gapped bundle includes the pending authority
inventory and the Draft execution matrix, but not nonexistent authority
fixture/result members. Candidate bundles are enabled only after the inventory
becomes Candidate and all concrete authority members are independently
verified. Materialized bytes are retained below
`published/<source-inventory-sha256>/`; that directory is immutable per source
inventory and includes its own `SHA256SUMS`.

Candidate materialization reads the eleven inventory fixture/result paths from
`PIGLOROS_CONFORMANCE_AUTHORITY_ROOT`, rejects traversal or digest mismatches,
binds each loaded JSON record back to its inventory `fixture_id`, and requires
each Candidate matrix coordinate to name its `authority_fixture_id` and match
that inventory entry's expected-result digest. CI keeps the checked-in Draft
inventory, so it cannot silently synthesize Candidate authority evidence.
