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
The `result` value in a checked-in expected record is descriptive fixture
metadata only; `status: "pending"` and the CPF1 unavailable outcome prevent it
from being interpreted as executed conformance evidence.
Each expected record also declares the exact Draft-unavailable typed result
(`ProvenanceMissing`) that the materializer encodes into the bundle, so the
packaged result cannot silently diverge from the public record.
Draft CPF1 bundles encode the exact checked-in expected-result record bytes;
the record's `status: "pending"` and `ProvenanceMissing` declaration keep those
bytes explicitly unavailable rather than executed evidence.

`SHA256SUMS` and `BLAKE3SUMS` are independent byte inventories for every
remaining public profile, input, expected result, matrix, inventory, and support
artifact. The hosted verifier checks both inventories and rejects any file not
covered by the manifests before bundle materialization.

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
ADR-059. Every coordinate is deliberately `executed: false` and has no result
digest until #193 supplies independently produced execution evidence.
`expected-authority/inventory.json` records the eleven #172 handoff slots as
pending. Its `expected_outcome` values are planned authority targets, not
observed results; the null paths/digests and pending materialization status are
the authoritative Draft state. #190 does not invent authority fixture/result
bytes.

The checked-in Draft inventory produces Draft Local/Air-Gapped bundles only.
Materialized bytes are CI transport artifacts, not Candidate evidence or a
retention authority. Candidate publication, trusted review, corrections, and
retention are owned by the #198 governance workflow after #193 supplies the
execution evidence.

The Draft materializer binds every layer-specific input/result pair to its
CPF1 profile, validates the authority handoff and matrix as open slots, checks
the Local/Air-Gapped pair before writing either archive, and independently
performs a structural cross-check of the resulting public archives. It does
not execute the matrix or claim that descriptive metadata is conformance
evidence; the independently produced execution evidence belongs to #193.

CI also independently regenerates the 49 input/result records from the public
input identities and fixture-family contract, reconstructs the Draft authority
inventory, and rebuilds both byte inventories before running the Rust
materializer. This check does not import the materializer or execute a claim;
it ensures the checked-in Draft handoff is reproducible by a separate, small
verifier.
