# Public conformance fixture sources

These files are the public, deterministic inputs, provider-owned oracle records,
and execution-evidence records
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
`mal.6`, `res.1` to `res.7`, `del.1`, `del.2`, `dgr.1` to `dgr.6` and `ind.1` to `ind.5`; `dgr.1`,
`dgr.2`, `dgr.5` and `dgr.6` roll back through the production entry (ADR-103 revision 7), and
`ind.5` is a `ComponentTrap` of the class `unreachable` at the probe guest's `drive`, which the
evaluator compares with its oracle entry (ADR-061 R13). Every
`expected/plugin-conformance/*.json` is `executed` (ADR-062 Revision 8 slice N6, #1234): the
independent evaluator dispatches the family through the adapter's exact `FixtureExecutorV1`
declaration and passes it in both the Local and the Air-Gapped ExecutionProfile run, which are
Local-relaxation engineering evidence, not hosted conformance. The result names each run's outcome
and the actual output digest (the BLAKE3 of the oracle member) or failure code (the oracle's), and
the time stays null; the generator derives the record from the oracle alone,
`scripts/check_plugin_conformance_expected.py` checks it, and
`apps/pos-plugin-worker/tests/provider_dispatch_public.rs` re-executes every family and requires
it.
Payloads are RFC 8785 canonical JSON and, like the oracles, end with one LF byte (the adapter reads
the payload with `serde_json`, which ignores it; the oracle LF is required by ADR-061 revision 8
decision 2). The `--check` validates every payload against its checked-in schema.

The `metric-cbor-v1` adapter (`scripts/conformance-fixture-adapters/metric-cbor-v1.sh`) owns the
`metric-conformance` layer (ADR-062 Revision 7, slice 1, #1211); provider
`pigloros.fixture.metric-conformance@2.0.0` replaces the Draft `fixture-ratio` placeholder with no
reader or alias. `scripts/generate_metric_conformance_fixtures.py` is the only writer of its seven
schemas, payloads (`inputs/metric-conformance/<family>.json`, JCS), `MCS1` composites
(`inputs/metric-conformance/<family>.mcs1`, one auxiliary member per family carrying the `MTI1`,
`MTQ1` and `MTR1` members of the sub-cases, addressed by BLAKE3 digest), oracles (`MTR1`/`MQR1`
bytes, or the closed `MetricErrorV1` and first coordinate) and evidence-status records. It runs
offline, calls no Rust and computes every oracle with exact integer and `fractions.Fraction`
arithmetic; `--check` reproduces the worked example and the quantization table of the profile,
recomputes every result by a second, definitional route, checks the strict decoder against every
failure expectation, and then compares every output. The profile text, including the record CDDL,
is `profiles/metric-conformance/normative-requirements.md`. Every
`expected/metric-conformance/*.json` stays `pending`. The generator also writes the pinned schema
digests of the plugins/eval subject adapter (`apps/pos-metric-conformance-adapter`, slice 4,
#1217), which outputs the exact canonical-output oracles; the oracle entry of the generator check
`ind.2` therefore names only the sub-case and its kind.

The `replay-cbor-v1` adapter (`scripts/conformance-fixture-adapters/replay-cbor-v1.sh`) owns the
`replay-conformance` layer (ADR-062 Revision 8 slice R4, #1222); provider
`pigloros.fixture.replay-conformance@2.0.0` replaces the 1.0.0 placeholder with no reader or alias.
`scripts/generate_replay_conformance_fixtures.py` is the only writer of its seven schemas, payloads
(`inputs/replay-conformance/<family>.json`, JCS, schema `pigloros.replay-conformance.case.v2`),
`RCS1` composites (`inputs/replay-conformance/<family>.rcs1`, one auxiliary member per family
carrying the closure members: exported Timelines, recomputation subjects and licences, addressed by
BLAKE3 digest), oracles and evidence-status records, and of the subject adapter's
`apps/pos-experiment/src/replay_conformance/schema_digests.rs`. It runs offline, calls no Rust and
derives every expected stream, authoritative result digest, closure digest and first divergence from
the closure members it writes, with the `PiglorOS.RecordedReplay*.v1` digests of the ADR-062
Revision 8 note "Recorded Replay Digests". The sub-cases carry all eleven entries of
`expected-authority/inventory.json`; each entry's fixture bytes and expected result are the payload
and oracle of one family, and its `materialization_status` is `materialized`. Every
`expected/replay-conformance/*.json` stays `pending`: materialized is not executed. The one exception
is `expected/replay-conformance/deletion-redaction.json` (ERA-001, degraded Replay; ADR-062 Revision 8,
#1296), which is `executed` with the record shape and fixed-point rule of the `plugin-conformance`
flip: the independent evaluator dispatches the family through the adapter's exact
`FixtureExecutorV1` declaration and passes it in both the Local and the Air-Gapped ExecutionProfile
run (Local-relaxation engineering evidence, not hosted conformance). The record names each run's
outcome and the actual output digest (the BLAKE3 of the oracle member) and the time stays null; the
generator derives it from the oracle alone, and
`apps/pos-experiment/tests/replay_provider_dispatch_public.rs` re-executes every family and requires
every record. The profile text is `profiles/replay-conformance/normative-requirements.md`.

The `erasure/` directory holds the ADR-060 erasure conformance cases (ADR-062 Revision 8 slice
N5, #1233; owner note `ADR-062_R8_Erasure_Cases` on the Redmine wiki). It is not a CPF1 claim
layer and is not a member of any bundle: `SHA256SUMS`, `BLAKE3SUMS` and the verify script cover
it, and `crates/pos-conformance/build.rs` leaves it out of the materialization closure.
`scripts/generate_erasure_conformance_fixtures.py` is the only writer of `erasure/cases.json` (the
case definitions and the independently derived expected projection of every case) and of the exact
`ERQ1` requests under `erasure/requests/`. It runs offline and calls no Rust. `erasure/executions.json`
and `erasure/records/` (the `ERS1`, `ERC1` and `ERRJ1` artifacts, each named by its BLAKE3) are the
recorded artifacts of one run of `apps/pos-experiment/tests/erasure_conformance.rs`, which executes
every case through the public `ErasureExecutionHostV1` over `MemoryStore` and `SQLite` and requires
byte equality with these files. The generator's `--check` decodes every recorded artifact,
recomputes its digests and links, derives the ERFP1/ERFA1 applicability matrix and the
ERAO1/ERPR1 provenance from the case inputs and compares them with the recorded bindings, compares
everything with the expected projection, scans the directory for the erased canary bytes and pins
that the erasure path writes no log. The cases cover every lifecycle terminal state, canonical
acknowledgement ordering, retry, legal hold and policy conflict, and replica, backup and rejoin
evidence of one host (not distributed). They are engineering evidence, make no ADR-059 mode claim
and do not change `expected/replay-conformance/deletion-redaction.json`.

The `gateway-http-v1` adapter (`scripts/conformance-fixture-adapters/gateway-http-v1.sh`) owns the
`gateway-client-conformance` layer (#1295); provider
`pigloros.fixture.gateway-client-conformance@2.0.0` replaces the 1.0.0 placeholder with no reader or
alias and declares no auxiliary member. `scripts/generate_gateway_conformance_fixtures.py` is the
only writer of its seven schemas, payloads (`inputs/gateway-client-conformance/<family>.json`, JCS,
schema `pigloros.gateway-client-conformance.case.v2`: ordered HTTP exchanges with their expected
normalized observations), oracles and evidence-status records, and of the subject adapter's
`apps/pos-gateway-conformance-adapter/src/subject/schema_digests.rs`. It runs offline, calls no Rust and
writes every expected exchange from the documented ADR-014 route table; `--check` decodes every
Society Signal payload a second time, checks the normalization rules, the routes and captures, the
capability set and step and Event usage of every family against the provider, and every payload
against its schema. The profile text is `profiles/gateway-client-conformance/normative-requirements.md`.
Every `expected/gateway-client-conformance/*.json` is `executed` under the same rule as the Plugin
records (ADR-062 R8 provider dispatch, section 10, as amended for #1295):
`apps/pos-gateway-conformance-adapter/tests/provider_dispatch_public.rs` re-executes every family
in both ExecutionProfile runs and requires it.

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
failures. Records under `expected/` bind the exact input digest; outside the
`plugin-conformance` layer and `expected/replay-conformance/deletion-redaction.json`
they contain only `status: "pending"`, null execution result, and null execution
timestamp. The
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
ADR-059. A coordinate stays `executed: false`, with no result digest, until #193
supplies execution evidence that the independent verifier accepts.

ADR-062 Revision 8 slice N1 (#1229, owner note `ADR-062_R8_NonInterference_Executions`)
flips the 24 cases of `NI-PUBLIC-006` and `NI-EVAL-007` in modes L, R and F.
- Each flipped case has one checked-in NIA1 at
  `non-interference/executions/<content address>.nia1`.
- The NIA1 are signed with the repository test-fixture-only executor key in
  `non-interference/executor.json`. They are engineering evidence, not an
  attestation.
- Each flipped case's `expected_result_digest` is its NIA1 result digest, derived
  independently by the row's oracle (for these rows
  `scripts/generate_non_interference_g_pub_fixtures.py`) and bound by
  `scripts/generate_non_interference_fixtures.py`. `executed: true` never implies a
  pass.
- The rows that may be flipped are declared once in
  `scripts/non_interference_executed_rows.json`, which the binder, the fixture
  verify script and the Plugin conformance checker read.
- Air-Gapped cases stay non-executed until N7 (#1235).

ADR-062 Revision 8 slice N4 (#1232, owner note `ADR-062_R8_NonInterference_Fork`)
flips the 12 cases of `NI-FORK-008` in modes L, R and F the same way, over the
ADR-064 Fork artifacts of slice R6. Their expected result digests are derived by
`scripts/generate_non_interference_g_fork_fixtures.py`, which rebuilds every
`INT1`, `CFP1`, `RCF1`, `SIV1`, `RCP1` and `CFR1` byte in pure Python. The F-mode
evidence is re-run when #1204 lands.

ADR-062 Revision 8 slice N2 (#1230, owner note `ADR-062_R8_NonInterference_Plugin`)
flips the 48 cases of `NI-TOOL-001`, `NI-STATE-003`, `NI-NET-010` and
`NI-SERVICE-011` in modes L, R and F the same way, derived by
`scripts/generate_non_interference_g_plug_fixtures.py`. The `NI-STATE-003` cases
cover its state members only; its migration surfaces and migration-only canary
stay non-executed until PMF1 v2 (#621, wiki `ADR-059_R9_State_Migration_Scoping`).

ADR-062 Revision 8 slice N3 (#1231, owner note `ADR-062_R8_NonInterference_Operations`)
flips the 48 cases of `NI-CACHE-002`, `NI-OBS-004`, `NI-TIME-005` and `NI-CRASH-012`
in modes L, R and F, under the same rules. Their oracle is
`scripts/generate_non_interference_g_ops_fixtures.py`; only each row's #181
operational normalization is applied, and their Air-Gapped cases stay non-executed
until N7.

ADR-062 Revision 8 slice N1b (#1284, wiki `ADR-127_Deterministic_Run_Evidence_Archive`)
flips the 12 cases of `NI-ARCHIVE-009` in modes L, R and F the same way, over the
canonical RVA1 run-evidence archive of the G-PUB subject's export. Their expected
result digests are derived by `scripts/generate_non_interference_g_archive_fixtures.py`,
which writes every archive byte with the shared ustar encoder `scripts/ustar.py`.
Archive bytes are not checked in: each NIA1 result digest binds them.
`expected-authority/inventory.json` records the eleven #172 handoff slots. Its
`expected_outcome` values are planned authority targets, not observed results.
Since ADR-062 Revision 8 slice R4 (#1222) every slot is `materialized`: its
fixture bytes and expected result are the replay-conformance payload and oracle
that carry it, bound by BLAKE3 digest. Materialized is not executed and claims
no conformance.

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
