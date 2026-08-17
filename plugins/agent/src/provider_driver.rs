//! Host-owned Live orchestration for one local provider decision per boundary.

use crate::{
    protocol::{
        ActionCatalogueV1, AgentActionV1, AgentDecisionError, AgentDecisionRequestV1,
        AgentProviderProvenanceV1, DecisionNoActionCodeV1, DecisionRecordV1, DecisionResultV1,
        ProviderAttempt, ProviderDecisionV1,
    },
    provider::AgentDecisionProvider,
    EVENT_TYPE_ACTION,
};
use pos_core::{
    event::{CanonicalBytes, EventDraft, Kind},
    ids::{EntityId, TimelineId},
};
use pos_runtime::{
    recorder::RECORDER_EVENT_TYPE, Driver, ObservationView, ProjectionKey, Recorder, RuntimeError,
    SnapshotAnchor, StepOutput,
};
use std::time::Duration;

const DRIVER_NAME: &str = "provider-backed-agent-driver";
const RECORDER_ERROR: &str = "agent decision recorder unavailable";

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
            subscriptions: Vec::new(),
            tick_interval: Duration::from_millis(100),
        }
    }

    /// Overrides the host cadence for this driver.
    #[must_use]
    pub fn with_tick_interval(mut self, tick_interval: Duration) -> Self {
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
    ) -> (AgentDecisionRequestV1, [u8; 32]) {
        let catalogue_hash = self
            .catalogue
            .hash()
            .expect("validated action catalogue must hash");
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
            .expect("validated agent decision request must hash");
        (request, request_hash)
    }

    fn record_draft(&mut self, record: &DecisionRecordV1) -> Result<EventDraft, RuntimeError> {
        let record_bytes = record
            .encode()
            .expect("validated agent decision record must encode");
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
    ) -> EventDraft {
        let action = AgentActionV1::try_new(
            action_id,
            confidence,
            self.committed_tick,
            catalogue_hash,
            record_hash,
        )
        .expect("catalogue action must create an agent action");
        let payload = action.encode().expect("validated agent action must encode");
        EventDraft::new(
            self.entity,
            Kind::new(EVENT_TYPE_ACTION),
            CanonicalBytes::from_vec(payload),
        )
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
        validate_snapshot_anchor(timeline, observations.anchor()).and_then(|anchor| {
            let (request, request_hash) = self.prepared_request(timeline, anchor);
            self.record_decision(request, request_hash)
        })
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
}

impl ProviderBackedAgentDriver {
    fn record_decision(
        &mut self,
        request: AgentDecisionRequestV1,
        request_hash: [u8; 32],
    ) -> Result<StepOutput, RuntimeError> {
        let normalized = normalize_attempt(self.provider.decide(&request), &self.catalogue);
        let catalogue_hash = request.catalogue_hash();
        let response_digest = normalized.response_digest();
        let record =
            DecisionRecordV1::new(request, request_hash, response_digest, normalized.result());
        let record_hash = record
            .hash()
            .expect("validated agent decision record must hash");
        self.record_draft(&record).map(|drafts| {
            let drafts =
                self.drafts_for_normalized(normalized, drafts, catalogue_hash, record_hash);
            self.staged_tick = Some(self.committed_tick.wrapping_add(1));
            StepOutput::new(drafts)
        })
    }

    fn drafts_for_normalized(
        &self,
        normalized: NormalizedAttempt,
        record_draft: EventDraft,
        catalogue_hash: [u8; 32],
        record_hash: [u8; 32],
    ) -> Vec<EventDraft> {
        match normalized {
            NormalizedAttempt::Accepted {
                action_id,
                confidence,
                ..
            } => vec![
                record_draft,
                self.action_draft(action_id, confidence, catalogue_hash, record_hash),
            ],
            NormalizedAttempt::NoAction { .. } => vec![record_draft],
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
                }) => match catalogue.action(action_index.get()) {
                    Some(action_id) => NormalizedAttempt::Accepted {
                        action_id: action_id.to_owned(),
                        confidence: confidence.get(),
                        result: DecisionResultV1::Accepted {
                            action_index,
                            confidence,
                        },
                        response_digest,
                    },
                    None => NormalizedAttempt::NoAction {
                        code: DecisionNoActionCodeV1::ResponseValueInvalid,
                        response_digest,
                    },
                },
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
mod tests {
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
    use pos_runtime::{Driver, ObservationView, PluginRegistry, Recorder, SnapshotAnchor};
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    const PLUGIN_HASH: [u8; 32] = [3; 32];
    const PROVIDER_HASH: [u8; 32] = [4; 32];

    struct DriverFixture {
        registry: PluginRegistry,
        calls: FixtureProviderCallCount,
        timeline: TimelineId,
        entity: EntityId,
        catalogue: ActionCatalogueV1,
        provenance: AgentProviderProvenanceV1,
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
        .unwrap()
    }

    fn provider_driver(attempts: Vec<ProviderAttempt>) -> DriverFixture {
        let provider = FixtureAgentDecisionProvider::new(attempts);
        let calls = provider.call_count_handle();
        let entity = EntityId::new();
        let catalogue =
            ActionCatalogueV1::try_new(vec!["left".to_owned(), "right".to_owned()]).unwrap();
        let provenance = provenance();
        let driver = ProviderBackedAgentDriver::new(
            entity,
            catalogue.clone(),
            provenance.clone(),
            Box::new(provider),
        );
        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(driver));
        DriverFixture {
            registry,
            calls,
            timeline: TimelineId::new(),
            entity,
            catalogue,
            provenance,
        }
    }

    fn response(decision: ProviderDecisionV1) -> Vec<u8> {
        decision.encode().unwrap()
    }

    fn record_from_drafts(drafts: &[pos_core::event::EventDraft]) -> DecisionRecordV1 {
        DecisionRecordV1::decode(drafts[0].payload.as_slice()).unwrap()
    }

    fn assert_normalized_attempt(
        attempt: ProviderAttempt,
        expected_result: DecisionResultV1,
        expected_digest: Option<[u8; 32]>,
        expected_action: Option<&str>,
        case: usize,
    ) {
        let mut fixture = provider_driver(vec![attempt]);
        let drafts = fixture
            .registry
            .step_all_anchored(fixture.timeline, Seq::from_u64(7))
            .unwrap();
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        assert_eq!(drafts[0].event_type.as_str(), RECORDER_EVENT_TYPE);
        assert_eq!(drafts[0].entity, fixture.entity);
        let catalogue_hash = fixture.catalogue.hash().unwrap();
        let expected_request = AgentDecisionRequestV1::new(
            fixture.timeline,
            7,
            fixture.entity,
            0,
            catalogue_hash,
            fixture.provenance.clone(),
        );
        let expected_request_hash = expected_request.hash().unwrap();
        let expected_record = DecisionRecordV1::new(
            expected_request,
            expected_request_hash,
            expected_digest,
            expected_result,
        );
        let expected_record_bytes = expected_record.encode().unwrap();
        assert_eq!(
            drafts[0].payload.as_slice(),
            expected_record_bytes.as_slice(),
            "normalization case {case}"
        );
        let record = record_from_drafts(&drafts);
        assert_eq!(
            record.result(),
            expected_result,
            "normalization case {case}"
        );
        assert_eq!(
            record.response_digest(),
            expected_digest,
            "normalization case {case}"
        );

        if let Some(expected_action) = expected_action {
            assert_eq!(drafts.len(), 2);
            assert_eq!(drafts[1].event_type.as_str(), EVENT_TYPE_ACTION);
            assert_eq!(drafts[1].entity, fixture.entity);
            let expected_action = AgentActionV1::try_new(
                expected_action.to_owned(),
                42,
                0,
                catalogue_hash,
                expected_record.hash().unwrap(),
            )
            .unwrap();
            assert_eq!(
                drafts[1].payload.as_slice(),
                expected_action.encode().unwrap().as_slice(),
                "normalization case {case}"
            );
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
                DecisionResultV1::NoAction(DecisionNoActionCodeV1::ProviderUnavailable),
                None,
                None,
            ),
            (
                ProviderAttempt::Failed(ProviderFailureCode::Timeout),
                DecisionResultV1::NoAction(DecisionNoActionCodeV1::ProviderTimeout),
                None,
                None,
            ),
            (
                ProviderAttempt::Failed(ProviderFailureCode::Rejected),
                DecisionResultV1::NoAction(DecisionNoActionCodeV1::ProviderRejected),
                None,
                None,
            ),
            (
                ProviderAttempt::Failed(ProviderFailureCode::RateLimited),
                DecisionResultV1::NoAction(DecisionNoActionCodeV1::ProviderRateLimited),
                None,
                None,
            ),
            (
                ProviderAttempt::NoResponse,
                DecisionResultV1::NoAction(DecisionNoActionCodeV1::ProviderNoAction),
                None,
                None,
            ),
            (
                ProviderAttempt::Oversized {
                    response_digest: Some(overflow_digest),
                },
                DecisionResultV1::NoAction(DecisionNoActionCodeV1::ResponseTooLarge),
                Some(overflow_digest),
                None,
            ),
            (
                ProviderAttempt::Oversized {
                    response_digest: None,
                },
                DecisionResultV1::NoAction(DecisionNoActionCodeV1::ResponseTooLarge),
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
        let accepted = response(ProviderDecisionV1::accepted(1, 42).unwrap());
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
            (
                malformed.clone(),
                DecisionResultV1::NoAction(DecisionNoActionCodeV1::ResponseMalformed),
                None,
            ),
            (
                unsupported.clone(),
                DecisionResultV1::NoAction(DecisionNoActionCodeV1::ResponseVersionUnsupported),
                None,
            ),
            (
                invalid_index.clone(),
                DecisionResultV1::NoAction(DecisionNoActionCodeV1::ResponseValueInvalid),
                None,
            ),
            (
                invalid_confidence.clone(),
                DecisionResultV1::NoAction(DecisionNoActionCodeV1::ResponseValueInvalid),
                None,
            ),
            (
                no_action.clone(),
                DecisionResultV1::NoAction(DecisionNoActionCodeV1::ProviderNoAction),
                None,
            ),
            (
                accepted.clone(),
                ProviderDecisionV1::accepted(1, 42).unwrap().into(),
                Some("right"),
            ),
        ];

        for (case, (wire, expected_result, expected_action)) in cases.into_iter().enumerate() {
            let expected_digest = Some(ProviderDecisionV1::hash_response(&wire));
            assert_normalized_attempt(
                ProviderAttempt::Response(wire.try_into().unwrap()),
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
        let catalogue_out_of_range = response(ProviderDecisionV1::accepted(2, 0).unwrap());
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
                provider_driver(vec![ProviderAttempt::Response(wire.try_into().unwrap())]);
            let drafts = fixture
                .registry
                .step_all_anchored(fixture.timeline, Seq::ZERO)
                .unwrap();
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
            ActionCatalogueV1::try_new(vec!["wait".to_owned()]).unwrap(),
            provenance(),
            Box::new(provider),
        );
        let timeline = TimelineId::new();
        let missing = driver.step(timeline, ObservationView::empty()).unwrap_err();
        assert_eq!(
            missing.to_string(),
            "driver 'provider-backed-agent-driver' requires a snapshot anchor"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let actual = TimelineId::new();
        let mismatch = driver
            .step(
                timeline,
                ObservationView::anchored_empty(SnapshotAnchor::new(actual, Seq::ZERO)),
            )
            .unwrap_err();
        assert_eq!(
            mismatch.to_string(),
            format!("snapshot Timeline mismatch: expected {timeline}, got {actual}")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn staged_steps_abort_and_commit_without_duplicate_provider_calls_or_tick_advancement() {
        let response = response(ProviderDecisionV1::accepted(0, 77).unwrap());
        let mut fixture = provider_driver(vec![
            ProviderAttempt::Response(response.clone().try_into().unwrap()),
            ProviderAttempt::Response(response.clone().try_into().unwrap()),
            ProviderAttempt::Response(response.try_into().unwrap()),
        ]);
        let first = fixture
            .registry
            .step_all_anchored(fixture.timeline, Seq::from_u64(4))
            .unwrap();
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        let pending = fixture
            .registry
            .step_all_anchored(fixture.timeline, Seq::from_u64(4))
            .unwrap_err();
        assert_eq!(
            pending.to_string(),
            "an anchored Driver step is already pending"
        );
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);

        fixture.registry.abort_step();
        let retry = fixture
            .registry
            .step_all_anchored(fixture.timeline, Seq::from_u64(4))
            .unwrap();
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
        assert_eq!(first[0].payload, retry[0].payload);
        fixture.registry.commit_step();
        fixture.registry.commit_step();

        let next = fixture
            .registry
            .step_all_anchored(fixture.timeline, Seq::from_u64(5))
            .unwrap();
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
            ActionCatalogueV1::try_new(vec!["wait".to_owned()]).unwrap(),
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
            ActionCatalogueV1::try_new(vec!["wait".to_owned()]).unwrap(),
            provenance(),
            Box::new(provider),
        );
        driver.commit_step();
        assert_eq!(driver.committed_tick(), 0);
        driver.staged_tick = Some(1);
        let pending = driver
            .step(TimelineId::new(), ObservationView::empty())
            .unwrap_err();
        assert_eq!(
            pending.to_string(),
            "an anchored Driver step is already pending"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn recorder_error_paths_never_surface_record_bytes() {
        let entity = EntityId::new();
        let request =
            AgentDecisionRequestV1::new(TimelineId::new(), 0, entity, 0, [1; 32], provenance());
        let record = DecisionRecordV1::new(
            request,
            [2; 32],
            None,
            DecisionResultV1::NoAction(DecisionNoActionCodeV1::ProviderNoAction),
        );
        let mut driver = ProviderBackedAgentDriver::new(
            entity,
            ActionCatalogueV1::try_new(vec!["wait".to_owned()]).unwrap(),
            provenance(),
            Box::new(FixtureAgentDecisionProvider::new(vec![])),
        );
        driver.recorder = Recorder::new_replay(entity, vec![]);
        assert_eq!(
            driver.record_draft(&record).unwrap_err().to_string(),
            "payload validation failed for event type 'runtime.recorded_output': agent decision recorder unavailable"
        );
        driver.recorder = Recorder::new_replay(entity, vec![vec![0]]);
        assert_eq!(
            driver.record_draft(&record).unwrap_err().to_string(),
            "payload validation failed for event type 'runtime.recorded_output': agent decision recorder unavailable"
        );
    }
}
