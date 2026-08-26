# Public conformance fixture sources

These files are the public, deterministic inputs and expected-result records
for the seven CPF1 claim layers. Each directory under `profiles/` is a
separate public profile manifest and binds exactly one claim layer to all seven
required fixture families: positive, negative, malformed, resource, deletion,
downgrade, and independent evaluation. The 49 records are layer-specific;
there is no shared generic fixture record. They contain no implementation-
private state, credentials, or signing material.

The immutable bundle boundary in `pos-conformance` accepts these bytes from a
caller, recomputes each BLAKE3 content address, binds the CPF1 profile digest,
and signs only the canonical manifest. Local and Air-Gapped manifests must be
materialized separately with the same expected-result records; the Air-Gapped
profile capability policy remains network-deny.

The scenario names intentionally cover positive, negative, malformed, resource
limit, deletion, downgrade, and independent-evaluation cases. A profile
manifest lists every family explicitly; no profile is represented by a single
input/result pair.

Each public input/result pair includes its claim-layer and case identity.
Materialization binds every family to deterministic-local-v1 or
deterministic-air-gapped-v1, so every emitted descriptor has exactly one
ExecutionProfile while the paired bundles retain identical expected bytes.

`SHA256SUMS` and `BLAKE3SUMS` are independent byte inventories for every public
profile, input, expected result, authority fixture/result, matrix, inventory,
and support artifact. The hosted verifier checks both inventories and rejects
any file not covered by the manifests before bundle materialization.

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

The Candidate `matrix/execution-matrix.json` records all twelve accepted
non-interference rows and their 192 required Local/Air-Gapped/Replay/Fork
variant cases, with the row-specific AuthEq/PublicEq/OpEq predicates from
ADR-059. Each executed coordinate names an authority fixture, binds its
authority-result digest, and carries a coordinate-specific expected-result
record whose BLAKE3 digest is checked independently. `expected-authority/inventory.json` records all
eleven #172 handoff vectors with concrete public fixture/result bytes and
independent BLAKE3 digests. The materializer bundles those typed authority
members into Candidate publications.

The checked-in Candidate inventory produces Candidate Local/Air-Gapped bundles
only. Materialized bytes are retained below
`published/<source-inventory-sha256>/`; that directory is immutable per source
inventory and includes `RETENTION.json` with the stable publication address,
`IMPACT-ANALYSIS.md`, its own
`SHA256SUMS`, the checked-in source inventory, and a source binding.

Candidate materialization reads the eleven inventory fixture/result paths from
the canonical checked-in `fixtures/conformance` root, rejects traversal or
digest mismatches, binds each loaded JSON record back to its inventory
`fixture_id`, and requires each Candidate matrix coordinate to name its
`authority_fixture_id`, match that inventory entry's authority-result digest,
and match the digest of its coordinate-specific expected-result record. The
publication script repeats verification from a clean Git checkout
and compares both materializations byte-for-byte.
