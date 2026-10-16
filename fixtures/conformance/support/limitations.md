# Fixture limitations

These public fixtures establish only the claim coordinates, provider contract,
and strict oracle declared by CPF1. They do not establish safety, privacy,
causal truth, or predictive validity outside those coordinates.

For the plugin-conformance layer: migration graphs and failure rollback are not
covered; no sub-case, fixture, or oracle invokes `migrate-state`.

For the plugin-conformance layer: downgrade is expressed only as `NotActive`,
`ArtifactRevoked`, and `IncompatibleAbi`.

For the plugin-conformance layer: five usage counters are unmeasured and are
reported as 0.

For the plugin-conformance layer: Publisher signature proves attribution only.

For the plugin-conformance layer: results are Local-relaxation engineering
evidence, not hosted conformance.
