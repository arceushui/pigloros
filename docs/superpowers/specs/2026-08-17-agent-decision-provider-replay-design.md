# Redmine #62: Agent Decision Provider and Replay

**Status:** Approved by final `gpt-5.6-sol` CTO review on 2026-08-18
**ADR:** ADR-046 revision 7 (Accepted; canonical source of truth)
**Scope:** Local provider contract, bounded record/action wire formats, append-aware driver state, and immutable-Timeline replay verification

This implementation design is subordinate to the current Redmine ADR. Revisions
3–7 clarify bounded PAA1 classification, independent wire oracles, closed replay
prefixes and causal anchors, supplied-store recovery authority, complete-prefix
source validation, and restoration of append-committed Driver state from validated
Timeline ancestry, sequence-bounded lineage segments, host-filtered recovery
evidence, and atomic fresh-registry recovery. Historical review references to revision 2 describe only the
initial design checkpoint.

## Goal

Add one local, explicitly injected nondeterministic Agent decision seam without giving the provider authority over actors, Timelines, catalogues, Events, or persistence. Live execution records a bounded host-constructed decision before an optional derived action in one atomic append; replay verifies those immutable source Events byte-for-byte and never invokes a provider.

The existing deterministic `AgentDriver` and `AgentPolicy` implementations remain unchanged. The new path is inert unless a host explicitly constructs `ProviderBackedAgentDriver`.

## Non-goals

- No network or remote model provider, SDK, Rig, Kalosm, Candle, RL backend, sandbox, supervisor, passkey, Gateway, client, or human-interaction work.
- No ADR-021 feedback/refinement loop, world/physics change, new Timeline authority, or direct provider append.
- No migration, backfill, dual-write, upcast, or compatibility layer for the old `agent.action` payload. PiglorOS is not deployed; development fixture Timelines may be recreated.
- No V2 wire format. Any changed bound, schema, external provider, capability, or deployed-data requirement needs a new ADR.

## Authority and module seams

`pos-runtime` owns the Tick Boundary anchor and the append-aware Driver transaction. It exposes:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotAnchor {
    pub timeline_id: TimelineId,
    pub observed_through: Seq,
}

pub trait Driver: Send + Sync {
    fn step(
        &mut self,
        timeline: TimelineId,
        observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError>;
    fn commit_step(&mut self) { }
    fn abort_step(&mut self) { }
    fn requires_snapshot_anchor(&self) -> bool { false }
    // existing methods unchanged
}
```

`ObservationSnapshot` stores one host-created `SnapshotAnchor`; every `ObservationView` from it exposes the same anchor. Explicit anchored transactional registry entry points require the host to supply the folded cursor and construct the anchor internally.

Legacy `step_all` and `tick_cadenced` preserve their current immediate lifecycle for `TickScheduler` and direct deterministic callers. They preflight all registered Drivers and reject before eligibility calculation or mutation if any registered Driver requires an anchor, including an interval-gated provider Driver that is not due. They do not create a pending transaction, and legacy cadence still advances immediately after a successful deterministic-only step.

Only anchored registry entry points own a pending batch. They stage cadence `last_tick` values alongside provider-backed Driver state. `commit_step` advances staged Driver and cadence state only after successful schema validation and append; `abort_step` clears both on Driver, schema, or append failure. A second anchored step while pending fails before any Driver runs. Existing deterministic Drivers inherit no-op hooks, so they keep their current internal behavior; only provider-backed state and registry cadence are append-staged.

`pos-plugin-agent` owns a deep provider module: callers learn one bounded request/attempt seam while validation, normalization, hashes, record construction, action derivation, and exact codecs remain local.

```rust
pub trait AgentDecisionProvider: Send + Sync {
    fn decide(&mut self, request: &AgentDecisionRequestV1) -> ProviderAttempt;
}

pub enum ProviderAttempt {
    Response(BoundedProviderBytes),
    NoResponse,
    Failed(ProviderFailureCode),
    Oversized { response_digest: Option<[u8; 32]> },
}
```

The provider is called exactly once per eligible Live boundary and cannot access `EventStore`, `Recorder`, `PluginRegistry`, or construct an `EventDraft`.

## Snapshot and Live transaction

Both production append paths already fold one captured, contiguous prefix before running Drivers: `ExperimentSession::step_boundary` and `Experiment::run` through `advance_tick`/`append_driver_drafts`. Each passes `(timeline.id(), boundary.folded_through)` into an anchored registry entry point. Zero denotes an empty prefix.

The provider-backed Driver requires:

- the view anchor Timeline to equal the `timeline` step argument;
- a valid action catalogue and fixed provenance configuration;
- no already-staged step;
- request encoding to fit its bound before calling the provider.

It then calls the provider once, normalizes the attempt, constructs `DecisionRecordV1`, asks Live `Recorder` for the first `runtime.recorded_output` draft, and optionally derives the second `agent.action` draft. It stages only `driver_tick + 1`; no committed tick changes in `step`.

The host sequence is fixed:

```text
fold complete contiguous prefix
-> anchored shared ObservationSnapshot
-> registry steps selected Drivers
-> schema validation
-> one EventStore append for the whole draft vector
-> registry commit_step
-> post-append capture/fold
```

On Driver, schema, or append failure, each production path aborts staged state and retains its existing error/fault semantics. A successful zero-draft boundary commits. Partial Driver failure aborts every Driver staged earlier in that anchored selection. The accepted provider path itself always emits at least a decision record.

## Action catalogue and text validation

`ActionCatalogueV1` contains 1 through 64 identifiers in declaration order. Each identifier is 1 through 64 UTF-8 bytes, contains no Unicode General Category `Cc` control character, and is unique by exact UTF-8 bytes. Its exact CBOR value is:

```text
[h'50414331', 1, [action_id...]]
```

The encoded catalogue is at most 4,096 bytes.

`provider_id` is 1 through 64 ASCII bytes matching `[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?`. `plugin_version` is 1 through 32 printable ASCII bytes `0x21..=0x7e`; `provider_version` is 1 through 64 bytes under the same rule. All configured content hashes are exactly 32 bytes.

## Exact wire profile

All values use hand-checked, definite-length CBOR arrays. Decoders reject over-limit input before decode; require exactly one complete item; enforce exact array length, magic, version, type, width, range, and text rules; reject maps, tags, floats, indefinite values, unknown fields, and trailing bytes; and require deterministic re-encoding to equal the original bytes.

IDs are the 16-byte big-endian ULID representation. Integer fields use their shortest deterministic CBOR representation. The following schemas are exact.

```text
AgentDecisionRequestV1 = [
  h'50515231', 1,
  timeline_id_bstr16, observed_through_u64,
  agent_id_bstr16, driver_tick_u64,
  catalogue_hash_bstr32,
  plugin_id_bstr16, plugin_version_tstr, plugin_content_hash_bstr32,
  provider_id_tstr, provider_version_tstr, provider_content_hash_bstr32
]

ProviderDecisionV1 accepted  = [h'50445031', 1, 0, action_index_u8, confidence_ppm_u32]
ProviderDecisionV1 no_action = [h'50445031', 1, 1]

DecisionRecordV1 = [
  h'50445231', 1,
  timeline_id_bstr16, observed_through_u64,
  agent_id_bstr16, driver_tick_u64,
  catalogue_hash_bstr32,
  plugin_id_bstr16, plugin_version_tstr, plugin_content_hash_bstr32,
  provider_id_tstr, provider_version_tstr, provider_content_hash_bstr32,
  request_hash_bstr32,
  response_digest,
  result
]

response_digest_absent  = [0]
response_digest_present = [1, digest_bstr32]
accepted                 = [0, action_index_u8, confidence_ppm_u32]
no_action                = [1, code_u8]

AgentActionV1 = [
  h'50414131', 1,
  action_id_tstr, confidence_ppm_u32, driver_tick_u64,
  catalogue_hash_bstr32, decision_record_hash_bstr32
]
```

Limits are 4,096 encoded bytes for catalogue, request, provider response, and decision record; 512 encoded bytes for the action. Confidence is `0..=1_000_000`; no wire value is floating point.

Use BLAKE3 derive-key mode over exact encoded bytes with these contexts:

- `pigloros.agent.catalogue.v1`
- `pigloros.agent.request.v1`
- `pigloros.agent.response.v1`
- `pigloros.agent.record.v1`

## Normalization and persistence

No-action codes are exhaustive:

1. provider unavailable
2. provider timeout
3. provider rejected
4. provider rate limited
5. provider no action
6. response too large
7. response malformed
8. response version unsupported
9. response value invalid

Classification precedence is fixed:

1. adapter overflow -> code 6;
2. structurally readable protocol magic with version other than 1 -> code 8;
3. V1 shape, type, canonical, or trailing-byte failure -> code 7;
4. valid accepted response with invalid index or confidence -> code 9;
5. valid no-action response -> code 5;
6. valid accepted response -> accepted record plus action.

Provider failures map their fixed codes 1 through 4. `NoResponse` maps to code 5. Every `Response`, including valid no-action, carries the BLAKE3 digest of the exact raw response. Failures and `NoResponse` have no digest. `Oversized` carries only the adapter's optional already-computed digest; runtime never receives oversized bytes.

Provider response bytes, private observations, prompts, completions, credentials, error text, retry counts, transport bodies, and exception details are never persisted or emitted into errors, logs, traces, or metrics. The record stores only bounded host-controlled provenance, hashes, and normalized result.

## Replay verifier

`AgentDecisionReplayVerifier` is a pure module over immutable source `Event` values, not a Driver and not a destination append loop. It is configured with host-validated root-to-active sequence-bounded `TimelineHistorySegment`s, target Agent, plugin/provider provenance, and catalogue, then scans authoritative `Event.seq` order. Each PDR1 anchor and reconstructed request must match the Timeline segment that owns its `Event.seq`; a post-fork record therefore cannot claim an ancestor Timeline.

It recognizes PDR1 records only in `runtime.recorded_output` for the target entity. For an accepted record it derives exact PAA1 bytes and requires the immediately following Event to be `agent.action` for the same entity with byte-identical payload. A no-action record consumes only itself. An unexpected target action, missing or mismatched action, malformed or unsupported record, anchor/provenance/catalogue/request mismatch, duplicate/regressing/gapped source order, or unconsumed target record fails closed.

The returned checkpoint is the last verified source sequence and is returned only when no accepted record remains awaiting its adjacent action. Resume receives the checkpoint plus a complete contiguous source prefix beginning at sequence 1 and extending through the checkpoint and any suffix to verify. It revalidates the entire prefix through the checkpoint before accepting later Events. Re-verification after a crash is permitted; provider calls and source mutation are impossible by construction.

## Projection behavior

There are two active `agent.action` producers. The unchanged deterministic `AgentDriver` emits its existing CBOR map; `ProviderBackedAgentDriver` emits the strict PAA1 array. `AgentReducer` dispatches by protocol shape: a payload identified by PAA1 magic is decoded only by the strict PAA1 decoder, while a non-PAA1 payload uses the existing deterministic `ActionPayload` decoder. A malformed PAA1 payload never falls back to the map decoder.

Both valid formats increment `action_count` and update `last_action` from their validated action identifier. Existing malformed-payload semantics remain unchanged: the presence of an `agent.action` Event increments `action_count`, while decode failure leaves `last_action` unchanged. This is active dual-producer handling, not migration, backfill, historical upcasting, or authorization for a second provider wire format.

## File structure

- `crates/pos-runtime/src/driver.rs`: `SnapshotAnchor`, anchored views, Driver transaction hooks and anchor requirement declaration.
- `crates/pos-runtime/src/registry.rs`: anchored transactional stepping, staged cadence, pending-batch guard, commit/abort fan-out, and immediate deterministic legacy paths.
- `apps/pos-experiment/src/lib.rs`: update both `ExperimentSession::step_boundary` and `Experiment::run`/`append_driver_drafts` to pass the completed fold cursor, commit after successful append, and abort on Driver/validation/append failure.
- `plugins/agent/src/protocol.rs`: bounded value types, validation, exact CBOR codecs, domain-separated hashes, normalization, record/action derivation.
- `plugins/agent/src/provider.rs`: provider seam and fixture-backed local adapter only.
- `plugins/agent/src/provider_driver.rs`: Live orchestration and staged tick state.
- `plugins/agent/src/replay.rs`: pure immutable-source verifier and checkpoint handling.
- `plugins/agent/src/lib.rs`: preserve existing deterministic implementation, dispatch `AgentReducer` between strict PAA1 and the existing deterministic payload, and re-export the new public interface.

`blake3`, `ciborium`, and `ulid` are already workspace dependencies. Adding direct workspace references for `blake3` and `ulid` to `pos-plugin-agent` does not add a new external package.

## Verification

Implementation is test-first and must cover:

- exact golden bytes and hashes for PAC1/PQR1/PDP1/PDR1/PAA1;
- every size/count/text/range bound, wrong type/length/magic/version, noncanonical integer, indefinite item, map/tag/float, truncation, and trailing byte;
- every normalization code and precedence edge, response digest presence, and provider call count (zero before request validation, exactly one after it);
- host-owned actor/Timeline/catalogue/provenance and exact action lookup;
- record-before-action order and single atomic append;
- staged tick commit on success, abort on schema/append failure, zero-draft commit, and pending-step rejection;
- legacy deterministic immediate behavior, repeated `TickScheduler` use, and unanchored rejection whenever any anchor-requiring Driver is registered, even when it is not due;
- both production Experiment append paths, including zero-draft and partial-Driver failure transaction closure;
- reducer updates for valid deterministic and PAA1 actions, with malformed PAA1 never falling back;
- replay accepted/no-action paths, sequence-bounded lineage-segment enforcement, exact adjacency, every mismatch/failure, full-prefix checkpoint resume, no mutation, and compile-time absence of a provider from the verifier interface;
- fixture Live-to-Replay byte stability.

All workspace gates remain mandatory, including formatting, clippy with warnings denied, locked tests with ignored tests included, documentation, dependency/security checks, ASan, WASM/browser parity where configured, and at least 99% line and region coverage. No production coverage exclusions or skipped tests are added.

## Approval record

The user delegated routine design approval and review corrections to the CTO agent. Earlier accepted slices received explicit `gpt-5.6-sol` verdicts after correcting schemas, anchors, failure handling, transaction semantics, replay recovery, and text grammar. Revision 7 received a final clean `gpt-5.6-sol` CTO review on 2026-08-18 and is Accepted in Redmine. ADR-046 remains canonical if wording differs.
