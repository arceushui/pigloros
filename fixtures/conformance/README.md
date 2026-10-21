# Public conformance fixture sources

These files are the public, deterministic inputs, provider-owned oracle records,
and pending execution-evidence records
for the seven CPF1 claim layers. Each directory under `profiles/` is a
separate public profile manifest and binds exactly one claim layer to all seven
required fixture families: positive, denied, malformed, resource exhaustion, deletion/redaction,
downgrade, and independent evaluation. The 49 records are layer-specific;
there is no shared generic fixture record. They contain no implementation-
private state, credentials, or signing material.

The seven profile manifests form the materializer's typed layer catalog. Each
manifest is the single semantic source for its profile identity, paired
claim-layer name and wire code, public subject adapter, fixture root, and
fixture identities. The build derives Rust's byte-embedding table directly
from those manifests; the materializer then parses and cross-checks identities
from the profile, provider, input, oracle, and evidence-status records instead of maintaining a
second fixture or layer inventory in source code.

`support/fixture-family-contract.json` is the shared source only for family
requirements and oracle kinds. Each provider manifest owns its exact public-adapter
payload templates, provider ID, contract version, ABI, subject adapter, operation
mapping, and artifact media types. CPF1 treats provider schema, payload, oracle,
and evidence-status bytes as opaque artifacts and binds their exact bytes and
declared media types. Evidence-status paths are extensionless, so the member name
does not impose a representation. The current provider adapter happens to generate
JSON and validates its JSON schemas in
`generate-conformance-fixture-records.sh`; neither the Rust catalog builder nor the
independent CPF1 verifier interprets those provider-owned bytes. A future provider
adapter may use another representation without changing the CPF1 verifier. No script
carries an adapter allowlist, provider version literal, generic payload template, or
second family catalog.

Each provider manifest also carries an `auxiliary` object that maps every family to
a list of `{ "path", "media_type" }` entries (a provider lists none unless its adapter renders
auxiliary members). A path
is a source file under `inputs/` that `SHA256SUMS` and `BLAKE3SUMS` cover; the build
embeds the verified bytes, and the materializer derives each bundle member path with
`fixture_input_member_path`. The `pigloros-json-v1` adapter accepts only empty lists.

The `plugin-signed-v1` adapter (`scripts/conformance-fixture-adapters/plugin-signed-v1.sh`) owns the
`plugin-conformance` layer (ADR-061 revision 8, #194). `scripts/generate_plugin_conformance_fixtures.py`
is the only writer of its payloads (`inputs/plugin-conformance/<family>.json`, JCS), its `PCW2`
composites (`inputs/plugin-conformance/<family>.pcw2`, one auxiliary member per family: the signed
release closures, trust epochs and anchor, addressed by BLAKE3 digest), its oracles and its
evidence-status records, and of the adapter's `src/schema_digests.rs`. It runs offline, calls no
Rust and uses fixed public fixture seeds ("repository-test-fixture-only"); `--check` reproduces the
PMF1, PTR1, PRV1, TPS1 and execution-profile vectors of the repository and the official BLAKE3
vectors (`scripts/data/blake3_test_vectors.json`) before it compares every output. The composites
carry every sub-case of the catalogue: `pos.1` to `pos.3`, `den.01` to `den.22`, `mal.1a` to
`mal.6`, `res.1` to `res.4`, `del.1`, `del.2`, `dgr.1` to `dgr.4` and `ind.1` to `ind.4`. Every
`expected/plugin-conformance/*.json` stays `pending` with a null result and a null time
(`scripts/check_plugin_conformance_expected.py` checks it).
Payloads are RFC 8785 canonical JSON and, like the oracles, end with one LF byte (the adapter reads
the payload with `serde_json`, which ignores it; the oracle LF is required by ADR-061 revision 8
decision 2). The `--check` validates every payload against its checked-in schema.

The immutable bundle boundary in `pos-conformance` accepts these bytes from a
caller, recomputes each BLAKE3 content address, binds the CPF1 profile digest,
and signs only the canonical manifest. Local and Air-Gapped manifests must be
materialized separately with the same oracle records; the Air-Gapped
profile capability policy remains network-deny.

The scenario names intentionally cover positive, denied, malformed, resource
exhaustion, deletion/redaction, downgrade, and independent-evaluation cases. A profile
manifest lists every family explicitly; no profile is represented by a single
input/result pair.

Each public input/oracle/evidence triple includes its claim-layer and case identity.
Materialization binds every family to deterministic-local-v1 or
deterministic-air-gapped-v1, so every emitted descriptor has exactly one
ExecutionProfile while the paired bundles retain identical oracle bytes.
Provider-owned records under `oracles/` define canonical outputs or namespaced
failures. Records under `expected/` bind the exact input digest but contain only
`status: "pending"`, null execution result, and null execution timestamp. The
materializer packages both artifacts separately using the provider-declared media
types, and only the oracle is bound as the manifest's expected result. Pending
evidence metadata is never used as
a canonical output or represented as an executed conformance claim.

`SHA256SUMS` and `BLAKE3SUMS` are independent byte inventories for every
remaining public profile, input, oracle, evidence-status, matrix, inventory, and support
artifact. The hosted verifier checks both inventories and rejects any file not
covered by the manifests before bundle materialization.

The support SBOM is intentionally scoped to the published fixture artifact,
which contains public data and contract documents rather than compiled code or
its build environment. It therefore has no software components. The Rust
workspace and the materializer toolchain are outside that artifact boundary;
their dependency/advisory checks remain CI responsibilities (`cargo-deny`,
`cargo-audit`, and the pinned toolchain). The checked-in `SHA256SUMS` file is
the byte-integrity authority for this scoped support record.

`support/package-manifest.json` is the single ordered inventory for support
artifacts, their media types, bundle roles, and provider-package membership.
Build-time generation and the independent shell verifier consume that manifest;
neither maintains a second support-artifact list.

The canonical architecture decisions for the CPF1 and authority workflow are
ADR-058 through ADR-068 on the [Redmine project wiki](https://redmine.piglor.com/projects/pigloros/wiki). ADR-068 owns the data-only FPR1/FPP1 provider contract used here.

Repository settings must require the `ci-gate` check for protected branches;
adding a workflow job does not change GitHub branch-protection rules. The
mutation workflow has its own `diff mutation testing` fan-in check, which must
also remain required for changes that run that workflow.

Each directory below `providers/` contains the seven public schemas owned by
that exact fixture provider. The `support/` directory contains the shared
normative specification, CPF1 CDDL, licence, notice, SBOM, separate source/build
provenance and publication-review records, and limitations members that every
immutable bundle manifest must declare.

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

The Draft materializer binds every layer-specific input/oracle/evidence triple to its
CPF1 profile, validates the authority handoff and matrix as open slots, checks
the Local/Air-Gapped pair before writing either archive, and independently
performs a structural cross-check of the resulting public archives. It does
not execute the matrix or claim that descriptive metadata is conformance
evidence; the independently produced execution evidence belongs to #193.
The publication script compares canonical in-memory tree fingerprints across
repeated and clean-checkout construction, then asks the Rust materializer to
publish the signed tree exactly once. It does not create temporary signed
bundle trees outside the descriptor-relative ADR-067 publication transaction.

CI also independently regenerates the 49 input/oracle/evidence triples from the public
input identities and fixture-family contract, reconstructs the Draft authority
inventory, and rebuilds both byte inventories before running the Rust
materializer. This check does not import the materializer or execute a claim;
it ensures the checked-in Draft handoff is reproducible by a separate, small
verifier.

`support/draft-execution-authority.json` is the checked public Draft authority
declaration for the authority closure required by ADR-058: two immutable EPF1
artifacts, a signed TPS1 snapshot, and signed RAD1 downgrade admissions. Its
authority key is a repository test-fixture authority, not a production
Deployment TrustPolicyRegistry root. The materializer emits only canonical
CBOR authority members and the independent verifier checks their digests,
sizes, signatures, and fixture relations.
EPF1 carries the complete selected execution semantics, including deterministic
budgets and evaluator compatibility. TPS1 carries a collection of versioned
trust roots plus revocation and minimum-version policy. Neither record relies
on an out-of-band singleton key or descriptive profile label.
