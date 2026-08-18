# Agent plugin

The provider-backed path is an explicitly constructed, local-only alternative to
the unchanged deterministic `AgentDriver`. The host owns every durable identity
and provenance value; the provider receives one bounded request and returns one
bounded attempt. It cannot append Events.

## Local Live construction

```rust
use pos_core::ids::{EntityId, PluginId};
use pos_plugin_agent::{
    protocol::{
        ActionCatalogueV1, AgentProviderProvenanceV1, BoundedProviderBytes,
        ProviderAttempt,
    },
    FixtureAgentDecisionProvider, ProviderBackedAgentDriver,
};

let agent_id = EntityId::new(); // host-owned
let catalogue = ActionCatalogueV1::try_new(vec![
    "move".to_owned(),
    "wait".to_owned(),
])?;
let provenance = AgentProviderProvenanceV1::try_new(
    PluginId::new(),                 // host-owned plugin identity
    "1.0.0".to_owned(),
    [0x31; 32],                     // fixed plugin content hash
    "fixture-local".to_owned(),
    "fixture-v1".to_owned(),
    [0x32; 32],                     // fixed provider content hash
)?;

// Canonical PDP1 bytes for [h'PDP1', 1, accepted, action 0, 750_000 ppm].
let response = BoundedProviderBytes::try_from(vec![
    0x85, 0x44, b'P', b'D', b'P', b'1', 0x01, 0x00, 0x00,
    0x1a, 0x00, 0x0b, 0x71, 0xb0,
])?;
let provider = FixtureAgentDecisionProvider::new(vec![ProviderAttempt::Response(response)]);
let driver = ProviderBackedAgentDriver::new(
    agent_id,
    catalogue.clone(),
    provenance.clone(),
    Box::new(provider),
);

// Register `driver` with `AgentPlugin` and `AgentReducer` in the host's
// PluginRegistry or Experiment. A Live boundary records PDR1 first and, for an
// accepted decision, appends the host-derived PAA1 action second in one batch.
# Ok::<(), Box<dyn std::error::Error>>(())
```

`FixtureAgentDecisionProvider` is an in-memory test/local adapter. It performs no
network, file, process, environment, socket, or clock access. Exhausted fixture
attempts deterministically become `NoResponse`.

## Pure replay verification

Replay consumes a complete immutable source Event prefix; it never receives or
invokes a provider:

```rust
# use pos_core::{Event, clock::Seq, ids::{EntityId, TimelineId}};
# use pos_plugin_agent::{AgentDecisionReplayVerifier, protocol::{ActionCatalogueV1, AgentProviderProvenanceV1}};
# use pos_runtime::TimelineHistorySegment;
# fn verify(
#     timeline_id: TimelineId,
#     agent_id: EntityId,
#     provenance: AgentProviderProvenanceV1,
#     catalogue: ActionCatalogueV1,
#     source_events: Vec<Event>,
# ) -> Result<(), Box<dyn std::error::Error>> {
let through = Seq::from_u64(u64::try_from(source_events.len())?);
let verifier = AgentDecisionReplayVerifier::try_new_with_timeline_ancestry(
    vec![TimelineHistorySegment::new(timeline_id, through)],
    agent_id,
    provenance,
    catalogue,
)?;
let checkpoint = verifier.verify(&source_events, None)?;
assert_eq!(checkpoint.last_verified().as_u64(), source_events.len() as u64);
# Ok(())
# }
```

For `ExperimentSession`, `source_events()` returns the contiguous immutable
prefix through its last completed Tick Boundary. After a fault, construct fresh
runtime state and use `Experiment::resume_with_store` when the host supplied a
decorated store adapter.

## Boundary rules

- Agent IDs, Timeline IDs, action catalogues, plugin/provider IDs, versions, and
  content hashes are host-owned.
- The provider cannot choose an entity, Timeline, Event type, catalogue, or
  provenance and cannot persist anything directly.
- Raw provider responses, prompts, completions, credentials, and error text are
  never persisted. Live stores only bounded host fields, hashes, the normalized
  result, and an optional response digest.
- Replay takes immutable source Events and has no provider, store, append, or
  mutation authority.
- A remote provider, SDK, changed wire bound/schema, or new capability requires a
  new ADR. This module intentionally includes no network provider or external SDK.
