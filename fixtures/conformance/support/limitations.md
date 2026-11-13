# Fixture limitations

These public fixtures establish only the claim coordinates, provider contract,
and strict oracle declared by CPF1. They do not establish safety, privacy,
causal truth, or predictive validity outside those coordinates.

For the plugin-conformance layer: migration graphs and failure rollback are not
covered; no sub-case, fixture, or oracle invokes `migrate-state`.

For the plugin-conformance layer: downgrade is release rollback through the
production entry (ADR-103 revision 7), with the refusals `NotActive` (a bind of
the release the rollback replaced), `ArtifactRevoked` (a rollback to a release
whose publisher key epoch is revoked), and `TrustStateUnavailable` (a rollback
to a release that was never installed or that is already active), and the
install refusals `IncompatibleAbi`, `InvalidManifest` (an ABI major other than
0, which the PMF1 decoder does not accept), and `TrustStateUnavailable` (a
broken release chain).

For the plugin-conformance layer: usage counters are measured after the
attempt; the resource family is bounded by the signed release's limits. One
execution step is one committed guest-v1 invocation.

For the plugin-conformance layer: Publisher signature proves attribution only.

For the plugin-conformance layer: results are Local-relaxation engineering
evidence, not hosted conformance.

For the replay-conformance layer: results are Local-relaxation engineering
evidence, not hosted conformance. The Experiment host binary is the replay
subject adapter; it exists only with the `test-support` feature, because it
needs the open fixture erasure gate and the generated Plugin registration.

For the replay-conformance layer: the `replay-v1` and `live-local-v1`
execution profiles are derived from `deterministic-local-v1`, each restricted
to one reproducibility class; the Draft authority declares neither.

For the replay-conformance layer: the recomputation host enforces only part of
the named execution profile. It refuses a manifest that enables network when
the profile denies network or the Execution Mode is Air-Gapped; this is an
input check, not runtime network denial. It builds its host in the manifest
Execution Mode, recomputes only in Local or Air-Gapped mode, and refuses a
composition that the Air-Gapped host refused. It caps the recomputed Event
count and the stepped Ticks at the profile's Event-count and execution-step
budgets. It does not enforce the scheduler and Driver order, the schema and
upcaster set, capability identifiers, numeric or architecture rules, or the
memory, fuel, host-call, output, storage and Simulation Time budgets, and it
claims no network or process isolation.

For the replay-conformance layer: the host asserts the trust evidence of the
bundled Draft trust policy snapshot instead of verifying it (the snapshot is
not signed with the operator domain); a passing run proves nothing about trust
roots.

For the replay-conformance layer: metering covers execution steps and the
Event count (every Event folded, replayed or recomputed); the other usage
counters are reported as 0. Each budget is the measured floor: the attempt's
measured usage, and 1 for a counter measured at 0. The watchdogs are 10 seconds
for CI shard latency.

For the replay-conformance layer: several expected-authority entries share one
family payload and oracle, keyed by their sub-case. A manifest's Execution Mode
is the attempt's mode, except for a cross-profile leg under
`deterministic-local-v1` or `deterministic-air-gapped-v1`, which is in that
profile's mode in every attempt.

For the replay-conformance layer: Air-Gapped results are Local-relaxation
engineering evidence, not hosted conformance. The host runs the `deterministic-air-gapped-v1`
semantics (no network, the bundled trust policy snapshot) in its own process,
not as a kernel-audited Air-Gapped execution under the Sandbox Provider.

For the gateway-client-conformance layer: results are Local-relaxation
engineering evidence, not hosted conformance. The subject is the in-process
Gateway router of `apps/pos-gateway-conformance-adapter`, whose `authorized`
composition is the production serve composition with a fixture Local Principal
document; no production authority is sourced from it.

For the gateway-client-conformance layer: the normative surface is the
documented ADR-014 route table only; there is no OpenAPI document, Golden Path
transition or public client action or authentication contract. Timeline and
Event IDs, cursors and error messages are normalized away.

For the gateway-client-conformance layer: deletion-redaction is redaction from
the public (spectator) listener, not ADR-060 deletion. The ADR-060 erasure
lifecycle cannot be reached through the Gateway until a Gateway erasure route
exists: once the Gateway owns its erasure host, no Gateway API or route runs an
erasure command.
