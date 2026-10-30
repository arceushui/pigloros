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
evidence, not hosted conformance; the subject adapter runs on the open fixture
erasure gate.

For the replay-conformance layer: the `replay-v1` and `live-local-v1`
execution profiles are `deterministic-local-v1` restricted to one
reproducibility class; the Draft authority declares neither.

For the replay-conformance layer: only execution steps are metered; the other
usage counters are reported as 0.
