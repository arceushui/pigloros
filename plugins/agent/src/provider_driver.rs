//! Host-owned Live orchestration for one local provider decision per boundary.

use crate::{
    protocol::{
        ActionCatalogueV1, AgentActionV1, AgentDecisionError, AgentDecisionRequestV1,
        AgentProviderProvenanceV1, DecisionNoActionCodeV1, DecisionRecordV1, DecisionResultV1,
        ProviderAttempt, ProviderDecisionV1,
    },
    provider::AgentDecisionProvider,
    replay::AgentDecisionReplayVerifier,
    EVENT_TYPE_ACTION,
};
use pos_core::{
    event::{CanonicalBytes, EventDraft, Kind},
    ids::{EntityId, TimelineId},
};
use pos_runtime::{
    recorder::RECORDER_EVENT_TYPE, Driver, DriverRecoveryEvidence, ObservationView, ProjectionKey,
    Recorder, RecoveryEventHeader, RuntimeError, SnapshotAnchor, StepOutput,
};
use std::time::Duration;

const DRIVER_NAME: &str = "provider-backed-agent-driver";
const RECORDER_ERROR: &str = "agent decision recorder unavailable";
const RECORD_ERROR: &str = "agent decision record invariant violated";
const HISTORY_ERROR: &str = "agent decision history does not match provider driver";

enum NormalizedAttempt {
    Accepted {
        action_id: String,
        confidence: u32,
        result: DecisionResultV1,
        response_digest: Option<[u8; 32]>,
    },
    NoAction {
        code: DecisionNoActionCodeV1,
        response_digest: Option<[u8; 32]>,
    },
}

impl NormalizedAttempt {
    const fn response_digest(&self) -> Option<[u8; 32]> {
        match self {
            Self::Accepted {
                response_digest, ..
            }
            | Self::NoAction {
                response_digest, ..
            } => *response_digest,
        }
    }

    const fn result(&self) -> DecisionResultV1 {
        match self {
            Self::Accepted { result, .. } => *result,
            Self::NoAction { code, .. } => DecisionResultV1::NoAction(*code),
        }
    }
}

/// Live driver that records every locally supplied provider decision before an
/// optional host-derived Agent action.
pub struct ProviderBackedAgentDriver {
    entity: EntityId,
    catalogue: ActionCatalogueV1,
    provenance: AgentProviderProvenanceV1,
    provider: Box<dyn AgentDecisionProvider>,
    recorder: Recorder,
    committed_tick: u64,
    staged_tick: Option<u64>,
    staged_restore_tick: Option<u64>,
    subscriptions: Vec<ProjectionKey>,
    tick_interval: Duration,
}

impl ProviderBackedAgentDriver {
    /// Creates a Live, host-configured provider-backed Agent driver.
    #[must_use]
    pub fn new(
        entity: EntityId,
        catalogue: ActionCatalogueV1,
        provenance: AgentProviderProvenanceV1,
        provider: Box<dyn AgentDecisionProvider>,
    ) -> Self {
        Self {
            entity,
            catalogue,
            provenance,
            provider,
            recorder: Recorder::new_live(entity),
            committed_tick: 0,
            staged_tick: None,
            staged_restore_tick: None,
            subscriptions: Vec::new(),
            tick_interval: Duration::from_millis(100),
        }
    }

    /// Overrides the host cadence for this driver.
    #[must_use]
    pub const fn with_tick_interval(mut self, tick_interval: Duration) -> Self {
        self.tick_interval = tick_interval;
        self
    }

    /// Declares the projection state observed by this driver.
    #[must_use]
    pub fn with_subscriptions(mut self, subscriptions: Vec<ProjectionKey>) -> Self {
        self.subscriptions = subscriptions;
        self
    }

    /// Returns the last append-committed decision tick.
    #[must_use]
    pub const fn committed_tick(&self) -> u64 {
        self.committed_tick
    }

    fn prepared_request(
        &self,
        timeline: TimelineId,
        anchor: SnapshotAnchor,
    ) -> Result<(AgentDecisionRequestV1, [u8; 32]), RuntimeError> {
        let catalogue_hash = self
            .catalogue
            .hash()
            .map_err(|_| invalid_payload(RECORDER_EVENT_TYPE, RECORD_ERROR))?;
        let request = AgentDecisionRequestV1::new(
            timeline,
            anchor.observed_through.as_u64(),
            self.entity,
            self.committed_tick,
            catalogue_hash,
            self.provenance.clone(),
        );
        let request_hash = request
            .hash()
            .map_err(|_| invalid_payload(RECORDER_EVENT_TYPE, RECORD_ERROR))?;
        Ok((request, request_hash))
    }

    fn record_draft(&mut self, record: &DecisionRecordV1) -> Result<EventDraft, RuntimeError> {
        let record_bytes = record
            .encode()
            .map_err(|_| invalid_payload(RECORDER_EVENT_TYPE, RECORD_ERROR))?;
        self.recorder
            .record(record_bytes)
            .map_err(|_| invalid_payload(RECORDER_EVENT_TYPE, RECORDER_ERROR))
            .and_then(|recorded| {
                self.recorder
                    .to_draft(&recorded)
                    .ok_or_else(|| invalid_payload(RECORDER_EVENT_TYPE, RECORDER_ERROR))
            })
    }

    fn action_draft(
        &self,
        action_id: String,
        confidence: u32,
        catalogue_hash: [u8; 32],
        record_hash: [u8; 32],
    ) -> Result<EventDraft, RuntimeError> {
        let action = AgentActionV1::try_new(
            action_id,
            confidence,
            self.committed_tick,
            catalogue_hash,
            record_hash,
        )
        .map_err(|_| invalid_payload(EVENT_TYPE_ACTION, RECORD_ERROR))?;
        let payload = action
            .encode()
            .map_err(|_| invalid_payload(EVENT_TYPE_ACTION, RECORD_ERROR))?;
        Ok(EventDraft::new(
            self.entity,
            Kind::new(EVENT_TYPE_ACTION),
            CanonicalBytes::from_vec(payload),
        ))
    }
}

impl Driver for ProviderBackedAgentDriver {
    fn step(
        &mut self,
        timeline: TimelineId,
        observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        if self.staged_tick.is_some() {
            return Err(RuntimeError::PendingDriverStep);
        }
        let staged_tick =
            self.committed_tick
                .checked_add(1)
                .ok_or_else(|| RuntimeError::DriverTickOverflow {
                    driver: DRIVER_NAME.to_owned(),
                })?;
        let anchor = validate_snapshot_anchor(timeline, observations.anchor())?;
        let (request, request_hash) = self.prepared_request(timeline, anchor)?;
        self.record_decision(request, request_hash, staged_tick)
    }

    fn name(&self) -> &'static str {
        DRIVER_NAME
    }

    fn tick_interval(&self) -> Duration {
        self.tick_interval
    }

    fn subscriptions(&self) -> &[ProjectionKey] {
        &self.subscriptions
    }

    fn requires_snapshot_anchor(&self) -> bool {
        true
    }

    fn commit_step(&mut self) {
        if let Some(staged_tick) = self.staged_tick.take() {
            self.committed_tick = staged_tick;
        }
    }

    fn abort_step(&mut self) {
        self.staged_tick = None;
    }

    fn needs_recovery_payload(&self, header: &RecoveryEventHeader) -> bool {
        header.entity() == self.entity
            && matches!(
                header.event_type().as_str(),
                RECORDER_EVENT_TYPE | EVENT_TYPE_ACTION
            )
    }

    fn stage_restore_from_history(
        &mut self,
        evidence: &DriverRecoveryEvidence,
    ) -> Result<(), RuntimeError> {
        if self.staged_restore_tick.is_some() || self.committed_tick != 0 {
            return Err(RuntimeError::DriverRecoveryNotFresh {
                driver: DRIVER_NAME.to_owned(),
            });
        }
        let checkpoint = AgentDecisionReplayVerifier::try_new_with_timeline_ancestry(
            evidence.timeline_segments().to_vec(),
            self.entity,
            self.provenance.clone(),
            self.catalogue.clone(),
        )
        .and_then(|verifier| verifier.verify_recovery(evidence))
        .map_err(|_| invalid_payload(RECORDER_EVENT_TYPE, HISTORY_ERROR))?;
        self.staged_restore_tick = Some(checkpoint.verified_decisions());
        Ok(())
    }

    fn commit_restore_from_history(&mut self) {
        self.committed_tick = self
            .staged_restore_tick
            .take()
            .unwrap_or(self.committed_tick);
    }

    fn abort_restore_from_history(&mut self) {
        self.staged_restore_tick = None;
    }
}

impl ProviderBackedAgentDriver {
    fn record_decision(
        &mut self,
        request: AgentDecisionRequestV1,
        request_hash: [u8; 32],
        staged_tick: u64,
    ) -> Result<StepOutput, RuntimeError> {
        let normalized = normalize_attempt(self.provider.decide(&request), &self.catalogue);
        let catalogue_hash = request.catalogue_hash();
        let response_digest = normalized.response_digest();
        let record =
            DecisionRecordV1::try_new(request, request_hash, response_digest, normalized.result())
                .map_err(|_| invalid_payload(RECORDER_EVENT_TYPE, RECORD_ERROR))?;
        let record_hash = record
            .hash()
            .map_err(|_| invalid_payload(RECORDER_EVENT_TYPE, RECORD_ERROR))?;
        let record_draft = self.record_draft(&record)?;
        let drafts =
            self.drafts_for_normalized(normalized, record_draft, catalogue_hash, record_hash)?;
        self.staged_tick = Some(staged_tick);
        Ok(StepOutput::new(drafts))
    }

    fn drafts_for_normalized(
        &self,
        normalized: NormalizedAttempt,
        record_draft: EventDraft,
        catalogue_hash: [u8; 32],
        record_hash: [u8; 32],
    ) -> Result<Vec<EventDraft>, RuntimeError> {
        match normalized {
            NormalizedAttempt::Accepted {
                action_id,
                confidence,
                ..
            } => Ok(vec![
                record_draft,
                self.action_draft(action_id, confidence, catalogue_hash, record_hash)?,
            ]),
            NormalizedAttempt::NoAction { .. } => Ok(vec![record_draft]),
        }
    }
}

fn invalid_payload(event_type: &str, reason: &str) -> RuntimeError {
    RuntimeError::InvalidPayload {
        event_type: event_type.to_owned(),
        reason: reason.to_owned(),
    }
}

fn validate_snapshot_anchor(
    timeline: TimelineId,
    anchor: Option<SnapshotAnchor>,
) -> Result<SnapshotAnchor, RuntimeError> {
    match anchor {
        None => Err(RuntimeError::MissingSnapshotAnchor {
            driver: DRIVER_NAME.to_owned(),
        }),
        Some(anchor) if anchor.timeline_id == timeline => Ok(anchor),
        Some(anchor) => Err(RuntimeError::SnapshotTimelineMismatch {
            expected: timeline,
            actual: anchor.timeline_id,
        }),
    }
}

fn normalize_attempt(attempt: ProviderAttempt, catalogue: &ActionCatalogueV1) -> NormalizedAttempt {
    match attempt {
        ProviderAttempt::Failed(failure) => NormalizedAttempt::NoAction {
            code: failure.into(),
            response_digest: None,
        },
        ProviderAttempt::NoResponse => NormalizedAttempt::NoAction {
            code: DecisionNoActionCodeV1::ProviderNoAction,
            response_digest: None,
        },
        ProviderAttempt::Oversized { response_digest } => NormalizedAttempt::NoAction {
            code: DecisionNoActionCodeV1::ResponseTooLarge,
            response_digest,
        },
        ProviderAttempt::Response(response) => {
            let response_digest = Some(ProviderDecisionV1::hash_response(response.as_slice()));
            match ProviderDecisionV1::decode(response.as_slice()) {
                Ok(ProviderDecisionV1::NoAction) => NormalizedAttempt::NoAction {
                    code: DecisionNoActionCodeV1::ProviderNoAction,
                    response_digest,
                },
                Ok(ProviderDecisionV1::Accepted {
                    action_index,
                    confidence,
                }) => catalogue.action(action_index.get()).map_or(
                    NormalizedAttempt::NoAction {
                        code: DecisionNoActionCodeV1::ResponseValueInvalid,
                        response_digest,
                    },
                    |action_id| NormalizedAttempt::Accepted {
                        action_id: action_id.to_owned(),
                        confidence: confidence.get(),
                        result: DecisionResultV1::Accepted {
                            action_index,
                            confidence,
                        },
                        response_digest,
                    },
                ),
                Err(AgentDecisionError::UnsupportedWireVersion) => NormalizedAttempt::NoAction {
                    code: DecisionNoActionCodeV1::ResponseVersionUnsupported,
                    response_digest,
                },
                Err(
                    AgentDecisionError::InvalidActionIndex | AgentDecisionError::InvalidConfidence,
                ) => NormalizedAttempt::NoAction {
                    code: DecisionNoActionCodeV1::ResponseValueInvalid,
                    response_digest,
                },
                Err(_) => NormalizedAttempt::NoAction {
                    code: DecisionNoActionCodeV1::ResponseMalformed,
                    response_digest,
                },
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {

    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!(
                    "unexpected provider driver fixture error: {error:?}"
                )))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing fixture value")))
        }
    }

    trait TestErrorExt<T, E> {
        fn test_err(self) -> E;
    }

    impl<T: std::fmt::Debug, E> TestErrorExt<T, E> for Result<T, E> {
        fn test_err(self) -> E {
            match self {
                Ok(value) => std::panic::resume_unwind(Box::new(format!(
                    "unexpected successful provider driver fixture value: {value:?}"
                ))),
                Err(error) => error,
            }
        }
    }

    use crate::{
        protocol::{
            ActionCatalogueV1, AgentActionV1, AgentDecisionError, AgentDecisionRequestV1,
            AgentProviderProvenanceV1, DecisionNoActionCodeV1, DecisionRecordV1, DecisionResultV1,
            ProviderAttempt, ProviderDecisionV1, ProviderFailureCode,
        },
        provider::{AgentDecisionProvider, FixtureAgentDecisionProvider, FixtureProviderCallCount},
        ProviderBackedAgentDriver, EVENT_TYPE_ACTION,
    };
    use pos_core::{
        clock::Seq,
        ids::{EntityId, PluginId, TimelineId},
    };
    use pos_runtime::recorder::RECORDER_EVENT_TYPE;
    use pos_runtime::{
        Driver, ObservationView, PluginRegistry, Recorder, RuntimeError, SnapshotAnchor,
        TimelineHistorySegment,
    };
    use std::time::Duration;

    const PLUGIN_HASH: [u8; 32] = [3; 32];
    const PROVIDER_HASH: [u8; 32] = [4; 32];

    struct HostConfigurationFixture {
        action_ids: [&'static str; 2],
        plugin_id: PluginId,
        plugin_version: &'static str,
        plugin_content_hash: [u8; 32],
        provider_id: &'static str,
        provider_version: &'static str,
        provider_content_hash: [u8; 32],
    }

    struct DriverFixture {
        registry: PluginRegistry,
        calls: FixtureProviderCallCount,
        timeline: TimelineId,
        entity: EntityId,
        host: HostConfigurationFixture,
    }

    fn provenance() -> AgentProviderProvenanceV1 {
        AgentProviderProvenanceV1::try_new(
            PluginId::new(),
            "1.0.0".to_owned(),
            PLUGIN_HASH,
            "local-provider".to_owned(),
            "2026.08".to_owned(),
            PROVIDER_HASH,
        )
        .test_ok()
    }

    fn provider_driver(attempts: Vec<ProviderAttempt>) -> DriverFixture {
        let provider = FixtureAgentDecisionProvider::new(attempts);
        let calls = provider.call_count_handle();
        let entity = EntityId::new();
        let host = HostConfigurationFixture {
            action_ids: ["left", "right"],
            plugin_id: PluginId::new(),
            plugin_version: "1.0.0",
            plugin_content_hash: PLUGIN_HASH,
            provider_id: "local-provider",
            provider_version: "2026.08",
            provider_content_hash: PROVIDER_HASH,
        };
        let catalogue = ActionCatalogueV1::try_new(
            host.action_ids
                .iter()
                .map(|action_id| (*action_id).to_owned())
                .collect(),
        )
        .test_ok();
        let provenance = AgentProviderProvenanceV1::try_new(
            host.plugin_id,
            host.plugin_version.to_owned(),
            host.plugin_content_hash,
            host.provider_id.to_owned(),
            host.provider_version.to_owned(),
            host.provider_content_hash,
        )
        .test_ok();
        let driver =
            ProviderBackedAgentDriver::new(entity, catalogue, provenance, Box::new(provider));
        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(driver));
        DriverFixture {
            registry,
            calls,
            timeline: TimelineId::new(),
            entity,
            host,
        }
    }

    fn response(decision: ProviderDecisionV1) -> Vec<u8> {
        decision.encode().test_ok()
    }

    fn record_from_drafts(drafts: &[pos_core::event::EventDraft]) -> DecisionRecordV1 {
        DecisionRecordV1::decode(drafts[0].payload.as_slice()).test_ok()
    }

    #[derive(Default)]
    struct IndependentCanonicalCbor(Vec<u8>);

    impl IndependentCanonicalCbor {
        fn array(&mut self, length: usize) {
            let length = u8::try_from(length).test_ok();
            assert!(length <= 23, "fixture arrays use direct CBOR lengths");
            self.0.push(0x80 | length);
        }

        fn bytes(&mut self, value: &[u8]) {
            let length = u8::try_from(value.len()).test_ok();
            if length <= 23 {
                self.0.push(0x40 | length);
            } else {
                self.0.extend([0x58, length]);
            }
            self.0.extend_from_slice(value);
        }

        fn text(&mut self, value: &str) {
            let length = u8::try_from(value.len()).test_ok();
            assert!(length <= 23, "fixture text uses direct CBOR lengths");
            self.0.push(0x60 | length);
            self.0.extend_from_slice(value.as_bytes());
        }

        fn uint(&mut self, value: u64) {
            if value > 23 {
                self.0.push(0x18);
            }
            self.0.push(u8::try_from(value).test_ok());
        }

        fn finish(self) -> Vec<u8> {
            self.0
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum ExpectedResult {
        Accepted { action_index: u8, confidence: u32 },
        NoAction { code: u8 },
    }

    fn write_fixture_request_fields(
        output: &mut IndependentCanonicalCbor,
        fixture: &DriverFixture,
        catalogue_hash: [u8; 32],
    ) {
        output.bytes(&fixture.timeline.inner().to_bytes());
        output.uint(7);
        output.bytes(&fixture.entity.inner().to_bytes());
        output.uint(0);
        output.bytes(&catalogue_hash);
        output.bytes(&fixture.host.plugin_id.inner().to_bytes());
        output.text(fixture.host.plugin_version);
        output.bytes(&fixture.host.plugin_content_hash);
        output.text(fixture.host.provider_id);
        output.text(fixture.host.provider_version);
        output.bytes(&fixture.host.provider_content_hash);
    }

    fn expected_catalogue_bytes(fixture: &DriverFixture) -> Vec<u8> {
        let mut output = IndependentCanonicalCbor::default();
        output.array(3);
        output.bytes(b"PAC1");
        output.uint(1);
        output.array(fixture.host.action_ids.len());
        for action_id in fixture.host.action_ids {
            output.text(action_id);
        }
        output.finish()
    }

    fn expected_request_bytes(fixture: &DriverFixture, catalogue_hash: [u8; 32]) -> Vec<u8> {
        let mut output = IndependentCanonicalCbor::default();
        output.array(13);
        output.bytes(b"PQR1");
        output.uint(1);
        write_fixture_request_fields(&mut output, fixture, catalogue_hash);
        output.finish()
    }

    fn write_expected_result(output: &mut IndependentCanonicalCbor, result: ExpectedResult) {
        match result {
            ExpectedResult::Accepted {
                action_index,
                confidence,
            } => {
                output.array(3);
                output.uint(0);
                output.uint(u64::from(action_index));
                output.uint(u64::from(confidence));
            }
            ExpectedResult::NoAction { code } => {
                output.array(2);
                output.uint(1);
                output.uint(u64::from(code));
            }
        }
    }

    fn expected_record_bytes(
        fixture: &DriverFixture,
        catalogue_hash: [u8; 32],
        request_hash: [u8; 32],
        response_digest: Option<[u8; 32]>,
        result: ExpectedResult,
    ) -> Vec<u8> {
        let mut output = IndependentCanonicalCbor::default();
        output.array(16);
        output.bytes(b"PDR1");
        output.uint(1);
        write_fixture_request_fields(&mut output, fixture, catalogue_hash);
        output.bytes(&request_hash);
        if let Some(response_digest) = response_digest {
            output.array(2);
            output.uint(1);
            output.bytes(&response_digest);
        } else {
            output.array(1);
            output.uint(0);
        }
        write_expected_result(&mut output, result);
        output.finish()
    }

    fn expected_action_bytes(
        action_id: &str,
        confidence: u32,
        catalogue_hash: [u8; 32],
        record_hash: [u8; 32],
    ) -> Vec<u8> {
        let mut output = IndependentCanonicalCbor::default();
        output.array(7);
        output.bytes(b"PAA1");
        output.uint(1);
        output.text(action_id);
        output.uint(u64::from(confidence));
        output.uint(0);
        output.bytes(&catalogue_hash);
        output.bytes(&record_hash);
        output.finish()
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_decoded_result(actual: DecisionResultV1, expected: ExpectedResult, case: usize) {
        match (actual, expected) {
            (
                DecisionResultV1::Accepted {
                    action_index,
                    confidence,
                },
                ExpectedResult::Accepted {
                    action_index: expected_index,
                    confidence: expected_confidence,
                },
            ) => {
                assert_eq!(
                    action_index.get(),
                    expected_index,
                    "normalization case {case}"
                );
                assert_eq!(
                    confidence.get(),
                    expected_confidence,
                    "normalization case {case}"
                );
            }
            (DecisionResultV1::NoAction(code), ExpectedResult::NoAction { code: expected }) => {
                assert_eq!(code.code(), expected, "normalization case {case}");
            }
            (actual, expected) => {
                std::panic::resume_unwind(Box::new(format!(
                    "normalization case {case}: decoded {actual:?}, expected {expected:?}"
                )));
            }
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_normalized_attempt(
        attempt: ProviderAttempt,
        expected_result: ExpectedResult,
        expected_digest: Option<[u8; 32]>,
        expected_action: Option<&str>,
        case: usize,
    ) {
        let mut fixture = provider_driver(vec![attempt]);
        let drafts = fixture
            .registry
            .step_all_anchored(fixture.timeline, Seq::from_u64(7))
            .test_ok();
        assert_eq!(fixture.calls.get(), 1);
        assert_eq!(drafts[0].event_type.as_str(), RECORDER_EVENT_TYPE);
        assert_eq!(drafts[0].entity, fixture.entity);
        let catalogue_hash = blake3::derive_key(
            "pigloros.agent.catalogue.v1",
            &expected_catalogue_bytes(&fixture),
        );
        let request_bytes = expected_request_bytes(&fixture, catalogue_hash);
        let request_hash = blake3::derive_key("pigloros.agent.request.v1", &request_bytes);
        let record_bytes = expected_record_bytes(
            &fixture,
            catalogue_hash,
            request_hash,
            expected_digest,
            expected_result,
        );
        assert_eq!(
            drafts[0].payload.as_slice(),
            record_bytes.as_slice(),
            "normalization case {case}"
        );
        let record = record_from_drafts(&drafts);
        let request = record.request();
        assert_eq!(request.timeline_id(), fixture.timeline);
        assert_eq!(request.observed_through(), 7);
        assert_eq!(request.agent_id(), fixture.entity);
        assert_eq!(request.driver_tick(), 0);
        assert_eq!(request.catalogue_hash(), catalogue_hash);
        assert_eq!(request.provenance().plugin_id(), fixture.host.plugin_id);
        assert_eq!(
            request.provenance().plugin_version(),
            fixture.host.plugin_version
        );
        assert_eq!(
            request.provenance().plugin_content_hash(),
            fixture.host.plugin_content_hash
        );
        assert_eq!(request.provenance().provider_id(), fixture.host.provider_id);
        assert_eq!(
            request.provenance().provider_version(),
            fixture.host.provider_version
        );
        assert_eq!(
            request.provenance().provider_content_hash(),
            fixture.host.provider_content_hash
        );
        assert_eq!(record.request_hash(), request_hash);
        assert_eq!(
            record.response_digest(),
            expected_digest,
            "normalization case {case}"
        );
        assert_decoded_result(record.result(), expected_result, case);

        if let Some(expected_action) = expected_action {
            assert_eq!(drafts.len(), 2);
            assert_eq!(drafts[1].event_type.as_str(), EVENT_TYPE_ACTION);
            assert_eq!(drafts[1].entity, fixture.entity);
            let ExpectedResult::Accepted { confidence, .. } = expected_result else {
                std::panic::resume_unwind(Box::new(format!(
                    "normalization case {case}: action requires accepted result"
                )));
            };
            let record_hash = blake3::derive_key("pigloros.agent.record.v1", &record_bytes);
            let action_bytes =
                expected_action_bytes(expected_action, confidence, catalogue_hash, record_hash);
            assert_eq!(
                drafts[1].payload.as_slice(),
                action_bytes.as_slice(),
                "normalization case {case}"
            );
            let action = AgentActionV1::decode(drafts[1].payload.as_slice()).test_ok();
            assert_eq!(action.action_id(), expected_action);
            assert_eq!(action.confidence().get(), confidence);
            assert_eq!(action.driver_tick(), 0);
            assert_eq!(action.catalogue_hash(), catalogue_hash);
            assert_eq!(action.decision_record_hash(), record_hash);
        } else {
            assert_eq!(drafts.len(), 1);
        }
        fixture.registry.abort_step();
    }

    #[test]
    fn fixture_provider_returns_configured_attempts_and_exposes_only_call_count() {
        let mut fixture = FixtureAgentDecisionProvider::new(vec![
            ProviderAttempt::NoResponse,
            ProviderAttempt::Failed(ProviderFailureCode::Timeout),
        ]);
        let request = AgentDecisionRequestV1::new(
            TimelineId::new(),
            0,
            EntityId::new(),
            0,
            [1; 32],
            provenance(),
        );

        assert_eq!(fixture.call_count(), 0);
        assert_eq!(fixture.decide(&request), ProviderAttempt::NoResponse);
        assert_eq!(fixture.call_count(), 1);
        assert_eq!(
            fixture.decide(&request),
            ProviderAttempt::Failed(ProviderFailureCode::Timeout)
        );
        assert_eq!(fixture.call_count(), 2);
        assert_eq!(fixture.decide(&request), ProviderAttempt::NoResponse);
        assert_eq!(fixture.call_count(), 3);
    }

    #[test]
    fn fixture_providers_keep_configured_attempts_and_counts_isolated() {
        let request = AgentDecisionRequestV1::new(
            TimelineId::new(),
            0,
            EntityId::new(),
            0,
            [1; 32],
            provenance(),
        );
        let mut first = FixtureAgentDecisionProvider::new(vec![ProviderAttempt::NoResponse]);
        let mut second = FixtureAgentDecisionProvider::new(vec![ProviderAttempt::Failed(
            ProviderFailureCode::Timeout,
        )]);

        assert_eq!(first.decide(&request), ProviderAttempt::NoResponse);
        assert_eq!(first.call_count(), 1);
        assert_eq!(second.call_count(), 0);
        assert_eq!(
            second.decide(&request),
            ProviderAttempt::Failed(ProviderFailureCode::Timeout)
        );
        assert_eq!(second.call_count(), 1);
    }

    #[test]
    fn provider_adapter_attempts_normalize_once_with_exact_digest_contract() {
        let overflow_digest = [9; 32];
        let cases = vec![
            (
                ProviderAttempt::Failed(ProviderFailureCode::Unavailable),
                ExpectedResult::NoAction { code: 1 },
                None,
                None,
            ),
            (
                ProviderAttempt::Failed(ProviderFailureCode::Timeout),
                ExpectedResult::NoAction { code: 2 },
                None,
                None,
            ),
            (
                ProviderAttempt::Failed(ProviderFailureCode::Rejected),
                ExpectedResult::NoAction { code: 3 },
                None,
                None,
            ),
            (
                ProviderAttempt::Failed(ProviderFailureCode::RateLimited),
                ExpectedResult::NoAction { code: 4 },
                None,
                None,
            ),
            (
                ProviderAttempt::NoResponse,
                ExpectedResult::NoAction { code: 5 },
                None,
                None,
            ),
            (
                ProviderAttempt::Oversized {
                    response_digest: Some(overflow_digest),
                },
                ExpectedResult::NoAction { code: 6 },
                Some(overflow_digest),
                None,
            ),
            (
                ProviderAttempt::Oversized {
                    response_digest: None,
                },
                ExpectedResult::NoAction { code: 6 },
                None,
                None,
            ),
        ];

        for (case, (attempt, expected_result, expected_digest, expected_action)) in
            cases.into_iter().enumerate()
        {
            assert_normalized_attempt(
                attempt,
                expected_result,
                expected_digest,
                expected_action,
                case,
            );
        }
    }

    #[test]
    fn provider_response_attempts_normalize_with_exact_output_contract() {
        let accepted = response(ProviderDecisionV1::accepted(1, 42).test_ok());
        let no_action = response(ProviderDecisionV1::no_action());
        let malformed = vec![0x83, 0x44, b'P', b'D', b'P', b'1', 0x01];
        let unsupported = vec![0x83, 0x44, b'P', b'D', b'P', b'1', 0x02, 0x00, 0xf6];
        let invalid_index = vec![
            0x85, 0x44, b'P', b'D', b'P', b'1', 0x01, 0x00, 0x18, 0x40, 0x00,
        ];
        let invalid_confidence = vec![
            0x85, 0x44, b'P', b'D', b'P', b'1', 0x01, 0x00, 0x00, 0x1a, 0x00, 0x0f, 0x42, 0x41,
        ];
        assert_eq!(
            ProviderDecisionV1::decode(&unsupported),
            Err(AgentDecisionError::UnsupportedWireVersion)
        );
        let cases = vec![
            (malformed, ExpectedResult::NoAction { code: 7 }, None),
            (unsupported, ExpectedResult::NoAction { code: 8 }, None),
            (invalid_index, ExpectedResult::NoAction { code: 9 }, None),
            (
                invalid_confidence,
                ExpectedResult::NoAction { code: 9 },
                None,
            ),
            (no_action, ExpectedResult::NoAction { code: 5 }, None),
            (
                accepted,
                ExpectedResult::Accepted {
                    action_index: 1,
                    confidence: 42,
                },
                Some("right"),
            ),
        ];

        for (case, (wire, expected_result, expected_action)) in cases.into_iter().enumerate() {
            let expected_digest = Some(blake3::derive_key("pigloros.agent.response.v1", &wire));
            assert_normalized_attempt(
                ProviderAttempt::Response(wire.try_into().test_ok()),
                expected_result,
                expected_digest,
                expected_action,
                case,
            );
        }
    }

    #[test]
    fn provider_response_normalization_enforces_precedence_and_catalogue_bounds() {
        let unsupported_with_invalid_shape =
            vec![0x85, 0x44, b'P', b'D', b'P', b'1', 0x02, 0xa0, 0xa0, 0xa0];
        let noncanonical_invalid_index = vec![
            0x85, 0x44, b'P', b'D', b'P', b'1', 0x01, 0x00, 0x19, 0x00, 0x40, 0x00,
        ];
        let noncanonical_no_action = vec![0x83, 0x44, b'P', b'D', b'P', b'1', 0x18, 0x01, 0x01];
        let catalogue_out_of_range = response(ProviderDecisionV1::accepted(2, 0).test_ok());
        let cases = [
            (
                unsupported_with_invalid_shape,
                DecisionResultV1::NoAction(DecisionNoActionCodeV1::ResponseVersionUnsupported),
            ),
            (
                noncanonical_invalid_index,
                DecisionResultV1::NoAction(DecisionNoActionCodeV1::ResponseMalformed),
            ),
            (
                noncanonical_no_action,
                DecisionResultV1::NoAction(DecisionNoActionCodeV1::ResponseMalformed),
            ),
            (
                catalogue_out_of_range,
                DecisionResultV1::NoAction(DecisionNoActionCodeV1::ResponseValueInvalid),
            ),
        ];

        for (wire, expected) in cases {
            let expected_digest = ProviderDecisionV1::hash_response(&wire);
            let mut fixture =
                provider_driver(vec![ProviderAttempt::Response(wire.try_into().test_ok())]);
            let drafts = fixture
                .registry
                .step_all_anchored(fixture.timeline, Seq::ZERO)
                .test_ok();
            let record = record_from_drafts(&drafts);
            assert_eq!(record.result(), expected);
            assert_eq!(record.response_digest(), Some(expected_digest));
            fixture.registry.abort_step();
        }
    }

    #[test]
    fn missing_or_mismatched_anchors_fail_with_stable_host_errors_before_provider_call() {
        let provider = FixtureAgentDecisionProvider::new(vec![ProviderAttempt::NoResponse]);
        let calls = provider.call_count_handle();
        let mut driver = ProviderBackedAgentDriver::new(
            EntityId::new(),
            ActionCatalogueV1::try_new(vec!["wait".to_owned()]).test_ok(),
            provenance(),
            Box::new(provider),
        );
        let timeline = TimelineId::new();
        let missing = driver.step(timeline, ObservationView::empty()).test_err();
        assert_eq!(
            missing.to_string(),
            "driver 'provider-backed-agent-driver' requires a snapshot anchor"
        );
        assert_eq!(calls.get(), 0);
        let actual = TimelineId::new();
        let mismatch = driver
            .step(
                timeline,
                ObservationView::anchored_empty(SnapshotAnchor::new(actual, Seq::ZERO)),
            )
            .test_err();
        assert_eq!(
            mismatch.to_string(),
            format!("snapshot Timeline mismatch: expected {timeline}, got {actual}")
        );
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn staged_steps_abort_and_commit_without_duplicate_provider_calls_or_tick_advancement() {
        let response = response(ProviderDecisionV1::accepted(0, 77).test_ok());
        let mut fixture = provider_driver(vec![
            ProviderAttempt::Response(response.clone().try_into().test_ok()),
            ProviderAttempt::Response(response.clone().try_into().test_ok()),
            ProviderAttempt::Response(response.try_into().test_ok()),
        ]);
        let first = fixture
            .registry
            .step_all_anchored(fixture.timeline, Seq::from_u64(4))
            .test_ok();
        assert_eq!(fixture.calls.get(), 1);
        let pending = fixture
            .registry
            .step_all_anchored(fixture.timeline, Seq::from_u64(4))
            .test_err();
        assert_eq!(
            pending.to_string(),
            "an anchored Driver step is already pending"
        );
        assert_eq!(fixture.calls.get(), 1);

        fixture.registry.abort_step();
        let retry = fixture
            .registry
            .step_all_anchored(fixture.timeline, Seq::from_u64(4))
            .test_ok();
        assert_eq!(fixture.calls.get(), 2);
        assert_eq!(first[0].payload, retry[0].payload);
        fixture.registry.commit_step_at(Seq::ZERO);
        fixture.registry.commit_step_at(Seq::ZERO);

        let next = fixture
            .registry
            .step_all_anchored(fixture.timeline, Seq::from_u64(5))
            .test_ok();
        let record = record_from_drafts(&next);
        assert_eq!(record.request().driver_tick(), 1);
        fixture.registry.abort_step();
    }

    #[test]
    fn provider_driver_declares_anchor_requirement_and_configured_cadence_and_subscriptions() {
        let entity = EntityId::new();
        let key = pos_runtime::ProjectionKey::new(EntityId::new());
        let driver = ProviderBackedAgentDriver::new(
            entity,
            ActionCatalogueV1::try_new(vec!["wait".to_owned()]).test_ok(),
            provenance(),
            Box::new(FixtureAgentDecisionProvider::new(vec![])),
        )
        .with_tick_interval(Duration::from_millis(250))
        .with_subscriptions(vec![key.clone()]);

        assert!(driver.requires_snapshot_anchor());
        assert_eq!(driver.tick_interval(), Duration::from_millis(250));
        assert_eq!(driver.subscriptions(), [key]);
        assert_eq!(driver.committed_tick(), 0);
    }

    #[test]
    fn driver_pending_steps_fail_before_provider_call() {
        let provider = FixtureAgentDecisionProvider::new(vec![ProviderAttempt::NoResponse]);
        let calls = provider.call_count_handle();
        let entity = EntityId::new();
        let mut driver = ProviderBackedAgentDriver::new(
            entity,
            ActionCatalogueV1::try_new(vec!["wait".to_owned()]).test_ok(),
            provenance(),
            Box::new(provider),
        );
        driver.commit_step();
        assert_eq!(driver.committed_tick(), 0);
        driver.staged_tick = Some(1);
        let pending = driver
            .step(TimelineId::new(), ObservationView::empty())
            .test_err();
        assert_eq!(
            pending.to_string(),
            "an anchored Driver step is already pending"
        );
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn recorder_error_paths_never_surface_record_bytes() {
        let entity = EntityId::new();
        let request =
            AgentDecisionRequestV1::new(TimelineId::new(), 0, entity, 0, [1; 32], provenance());
        let record = DecisionRecordV1::try_new(
            request,
            [2; 32],
            None,
            DecisionResultV1::NoAction(DecisionNoActionCodeV1::ProviderNoAction),
        )
        .test_ok();
        let mut driver = ProviderBackedAgentDriver::new(
            entity,
            ActionCatalogueV1::try_new(vec!["wait".to_owned()]).test_ok(),
            provenance(),
            Box::new(FixtureAgentDecisionProvider::new(vec![])),
        );
        driver.recorder = Recorder::new_replay(entity, vec![]);
        assert_eq!(
            driver.record_draft(&record).test_err().to_string(),
            "payload validation failed for event type 'runtime.recorded_output': agent decision recorder unavailable"
        );
        driver.recorder = Recorder::new_replay(entity, vec![vec![0]]);
        assert_eq!(
            driver.record_draft(&record).test_err().to_string(),
            "payload validation failed for event type 'runtime.recorded_output': agent decision recorder unavailable"
        );
    }

    #[test]
    fn driver_tick_overflow_fails_before_provider_call() {
        let provider = FixtureAgentDecisionProvider::new(vec![ProviderAttempt::NoResponse]);
        let calls = provider.call_count_handle();
        let mut driver = ProviderBackedAgentDriver::new(
            EntityId::new(),
            ActionCatalogueV1::try_new(vec!["wait".to_owned()]).test_ok(),
            provenance(),
            Box::new(provider),
        );
        driver.committed_tick = u64::MAX;
        let timeline = TimelineId::new();
        let error = driver
            .step(
                timeline,
                ObservationView::anchored_empty(SnapshotAnchor::new(timeline, Seq::ZERO)),
            )
            .test_err();
        assert!(matches!(error, RuntimeError::DriverTickOverflow { .. }));
        assert_eq!(calls.get(), 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn abort_restore_from_history_clears_staged_restore_tick_and_is_idempotent() {
        let mut driver = ProviderBackedAgentDriver::new(
            EntityId::new(),
            ActionCatalogueV1::try_new(vec!["wait".to_owned()]).test_ok(),
            provenance(),
            Box::new(FixtureAgentDecisionProvider::new(vec![])),
        );
        driver.staged_restore_tick = Some(7);
        driver.abort_restore_from_history();
        assert_eq!(driver.committed_tick(), 0);
        assert!(driver.staged_restore_tick.is_none());
        // Aborting when nothing is staged is also a no-op.
        driver.abort_restore_from_history();
        assert_eq!(driver.committed_tick(), 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn commit_restore_from_history_preserves_committed_tick_when_nothing_is_staged() {
        let mut driver = ProviderBackedAgentDriver::new(
            EntityId::new(),
            ActionCatalogueV1::try_new(vec!["wait".to_owned()]).test_ok(),
            provenance(),
            Box::new(FixtureAgentDecisionProvider::new(vec![])),
        );
        driver.committed_tick = 3;
        driver.commit_restore_from_history();
        assert_eq!(driver.committed_tick(), 3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn stage_restore_from_history_fails_when_a_driver_step_is_already_pending() {
        let mut fixture = provider_driver(vec![ProviderAttempt::NoResponse]);
        let _ = fixture
            .registry
            .step_all_anchored(fixture.timeline, Seq::ZERO)
            .test_ok();
        let segments = [TimelineHistorySegment::new(fixture.timeline, Seq::ZERO)];
        // The registry guards restore_driver_state with PendingDriverStep when
        // any driver has a staged step, so the error surfaces at registry level.
        let err = fixture
            .registry
            .restore_driver_state(&segments, &[])
            .test_err();
        assert!(matches!(err, RuntimeError::PendingDriverStep), "{err:?}");
        fixture.registry.abort_step();
    }

    #[test]
    fn stage_restore_from_history_fails_when_driver_has_committed_ticks() {
        let mut fixture = provider_driver(vec![
            ProviderAttempt::NoResponse,
            ProviderAttempt::NoResponse,
        ]);
        fixture
            .registry
            .step_all_anchored(fixture.timeline, Seq::ZERO)
            .test_ok();
        fixture.registry.commit_step_at(Seq::ZERO);
        // committed_tick is now 1; the guard fires before verifying evidence.
        let segments = [TimelineHistorySegment::new(fixture.timeline, Seq::ZERO)];
        let err = fixture
            .registry
            .restore_driver_state(&segments, &[])
            .test_err();
        assert!(
            matches!(err, RuntimeError::DriverRecoveryNotFresh { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn stage_restore_from_history_fails_when_a_restore_is_already_staged() {
        let mut driver = ProviderBackedAgentDriver::new(
            EntityId::new(),
            ActionCatalogueV1::try_new(vec!["wait".to_owned()]).test_ok(),
            provenance(),
            Box::new(FixtureAgentDecisionProvider::new(vec![])),
        );
        driver.staged_restore_tick = Some(5);
        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(driver));
        let timeline = TimelineId::new();
        let segments = [TimelineHistorySegment::new(timeline, Seq::ZERO)];
        let err = registry.restore_driver_state(&segments, &[]).test_err();
        assert!(
            matches!(err, RuntimeError::DriverRecoveryNotFresh { .. }),
            "{err:?}"
        );
    }
}
