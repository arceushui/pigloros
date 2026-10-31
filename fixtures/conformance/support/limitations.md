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

For the plugin-conformance layer: five usage counters are unmeasured and are
reported as 0.

For the plugin-conformance layer: Publisher signature proves attribution only.

For the plugin-conformance layer: results are Local-relaxation engineering
evidence, not hosted conformance.
