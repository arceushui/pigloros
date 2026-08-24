//! Pure verification of provider-backed Agent decisions in immutable source Events.

use crate::{
    protocol::{
        ActionCatalogueV1, AgentActionV1, AgentProviderProvenanceV1, DecisionRecordV1,
        DecisionResultV1,
    },
    EVENT_TYPE_ACTION,
};
use pos_core::{clock::Seq, event::Event, ids::EntityId};
use pos_runtime::{
    recorder::RECORDER_EVENT_TYPE, DriverRecoveryEvidence, RecoveryEvent, TimelineHistorySegment,
};

/// The verified end of one complete immutable source prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayCheckpoint {
    last_verified: Seq,
    verified_decisions: u64,
}

impl ReplayCheckpoint {
    #[must_use]
    pub const fn last_verified(self) -> Seq {
        self.last_verified
    }

    /// Returns the exact number of verified target decision records.
    #[must_use]
    pub const fn verified_decisions(self) -> u64 {
        self.verified_decisions
    }
}

/// A closed set of replay-verification failures containing no provider data.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReplayVerificationError {
    #[error("source Event sequence is not contiguous: expected {expected}, got {actual}")]
    NonContiguousSourceSequence { expected: u64, actual: u64 },
    #[error("resume checkpoint sequence {checkpoint} is absent from the source prefix")]
    MissingCheckpoint { checkpoint: u64 },
    #[error("target decision record is not an exact PDR1 value")]
    InvalidDecisionRecord,
    #[error("target decision record does not match replay configuration")]
    DecisionRecordMismatch,
    #[error("accepted target decision has no exact immediately adjacent PAA1 action")]
    MissingOrMismatchedAcceptedAction,
    #[error("target agent.action was not consumed by an adjacent accepted decision")]
    UnexpectedTargetAction,
    #[error("host-supplied Timeline ancestry is invalid")]
    InvalidTimelineAncestry,
    #[error("target decision count exceeds the V1 driver tick range")]
    DriverTickOverflow,
}

/// Verifies host-bound PDR1/PAA1 records without provider, store, or append authority.
pub struct AgentDecisionReplayVerifier {
    timeline_segments: Vec<TimelineHistorySegment>,
    target_agent: EntityId,
    provenance: AgentProviderProvenanceV1,
    catalogue: ActionCatalogueV1,
}

#[derive(Clone, Copy, Default)]
struct ReplayState {
    expected_driver_tick: u64,
    last_target_sequence: u64,
}

struct VerificationEvent<'a> {
    seq: Seq,
    entity: EntityId,
    event_type: &'a str,
    payload: Option<&'a [u8]>,
}

impl AgentDecisionReplayVerifier {
    /// Creates a verifier for host-validated root-to-active Timeline segments.
    ///
    /// Each record must name the Timeline segment that owns its source sequence.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayVerificationError::InvalidTimelineAncestry`] when the
    /// segments are empty, duplicate a Timeline, or have decreasing bounds.
    pub fn try_new_with_timeline_ancestry(
        timeline_segments: Vec<TimelineHistorySegment>,
        target_agent: EntityId,
        provenance: AgentProviderProvenanceV1,
        catalogue: ActionCatalogueV1,
    ) -> Result<Self, ReplayVerificationError> {
        let unique = timeline_segments
            .iter()
            .enumerate()
            .all(|(index, segment)| {
                !timeline_segments[..index]
                    .iter()
                    .any(|prior| prior.timeline_id() == segment.timeline_id())
            });
        let ordered = timeline_segments
            .windows(2)
            .all(|pair| pair[0].through() <= pair[1].through());
        if timeline_segments.is_empty() || !unique || !ordered {
            return Err(ReplayVerificationError::InvalidTimelineAncestry);
        }
        Ok(Self {
            timeline_segments,
            target_agent,
            provenance,
            catalogue,
        })
    }

    /// Verifies one complete contiguous immutable source range.
    ///
    /// When resuming, `events` must still begin at sequence one and include the
    /// complete prefix through `checkpoint`; that prefix is revalidated before
    /// any later Events are accepted.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayVerificationError`] for a non-contiguous source range,
    /// absent checkpoint, invalid or mismatched target PDR1, missing or
    /// mismatched adjacent PAA1, or any otherwise-unexpected target action.
    pub fn verify(
        &self,
        events: &[Event],
        checkpoint: Option<ReplayCheckpoint>,
    ) -> Result<ReplayCheckpoint, ReplayVerificationError> {
        let last_verified = validate_source_sequence(events)?;
        let verification_events = events
            .iter()
            .map(|event| VerificationEvent {
                seq: event.seq,
                entity: event.entity,
                event_type: event.event_type.as_str(),
                payload: Some(event.payload.as_slice()),
            })
            .collect::<Vec<_>>();
        let state = if let Some(checkpoint) = checkpoint {
            if checkpoint.last_verified > last_verified {
                return Err(ReplayVerificationError::MissingCheckpoint {
                    checkpoint: checkpoint.last_verified.as_u64(),
                });
            }
            let prefix_len = verification_events
                .iter()
                .take_while(|event| event.seq <= checkpoint.last_verified)
                .count();
            let state =
                self.verify_events(&verification_events[..prefix_len], ReplayState::default())?;
            self.verify_events(&verification_events[prefix_len..], state)?
        } else {
            self.verify_events(&verification_events, ReplayState::default())?
        };

        Ok(ReplayCheckpoint {
            last_verified,
            verified_decisions: state.expected_driver_tick,
        })
    }

    /// Verifies the bounded, host-filtered evidence used during Driver recovery.
    ///
    /// Source headers retain ordering and adjacency proof; only payloads selected
    /// by the Driver are visible. The host has already validated the complete
    /// immutable source prefix before constructing this evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayVerificationError`] for mismatched segments, unordered
    /// evidence headers, or invalid/mismatched target decisions and actions.
    ///
    pub fn verify_recovery(
        &self,
        evidence: &DriverRecoveryEvidence,
    ) -> Result<ReplayCheckpoint, ReplayVerificationError> {
        if evidence.timeline_segments() != self.timeline_segments.as_slice() {
            return Err(ReplayVerificationError::InvalidTimelineAncestry);
        }
        let events = evidence
            .events()
            .iter()
            .map(verification_event)
            .collect::<Vec<_>>();
        let Some(last_segment) = self.timeline_segments.last() else {
            return Err(ReplayVerificationError::InvalidTimelineAncestry);
        };
        validate_recovery_sequence(&events, last_segment.through())?;
        let state = self.verify_events(&events, ReplayState::default())?;
        Ok(ReplayCheckpoint {
            last_verified: last_segment.through(),
            verified_decisions: state.expected_driver_tick,
        })
    }

    fn verify_events(
        &self,
        events: &[VerificationEvent<'_>],
        mut state: ReplayState,
    ) -> Result<ReplayState, ReplayVerificationError> {
        let mut index = 0;
        while index < events.len() {
            let event = &events[index];
            if self.is_target_action(event) {
                return Err(ReplayVerificationError::UnexpectedTargetAction);
            }
            if !self.is_target_record(event) {
                index += 1;
                continue;
            }

            let record = DecisionRecordV1::decode(
                event
                    .payload
                    .ok_or(ReplayVerificationError::InvalidDecisionRecord)?,
            )
            .map_err(|_| ReplayVerificationError::InvalidDecisionRecord)?;
            self.verify_record(event, &record, state)?;
            state.expected_driver_tick = advance_driver_tick(state.expected_driver_tick)?;
            match record.result() {
                DecisionResultV1::Accepted {
                    action_index,
                    confidence,
                } => {
                    let action_id = self
                        .catalogue
                        .action(action_index.get())
                        .ok_or(ReplayVerificationError::DecisionRecordMismatch)?;
                    let next = events
                        .get(index + 1)
                        .ok_or(ReplayVerificationError::MissingOrMismatchedAcceptedAction)?;
                    self.verify_action(next, &record, action_id, confidence.get())?;
                    state.last_target_sequence = next.seq.as_u64();
                    index += 2;
                }
                DecisionResultV1::NoAction(_) => {
                    state.last_target_sequence = event.seq.as_u64();
                    index += 1;
                }
            }
        }
        Ok(state)
    }

    fn verify_record(
        &self,
        event: &VerificationEvent<'_>,
        record: &DecisionRecordV1,
        state: ReplayState,
    ) -> Result<(), ReplayVerificationError> {
        let request = record.request();
        let catalogue_hash = self
            .catalogue
            .hash()
            .map_err(|_| ReplayVerificationError::DecisionRecordMismatch)?;
        let expected_timeline = self
            .timeline_segments
            .iter()
            .find(|segment| event.seq <= segment.through())
            .map(|segment| segment.timeline_id());
        let matches_host = expected_timeline == Some(request.timeline_id())
            && request.observed_through() >= state.last_target_sequence
            && request.observed_through() < event.seq.as_u64()
            && request.agent_id() == self.target_agent
            && request.driver_tick() == state.expected_driver_tick
            && request.catalogue_hash() == catalogue_hash
            && request.provenance() == &self.provenance;
        let request_hash = request
            .hash()
            .map_err(|_| ReplayVerificationError::DecisionRecordMismatch)?;
        if matches_host && record.request_hash() == request_hash {
            Ok(())
        } else {
            Err(ReplayVerificationError::DecisionRecordMismatch)
        }
    }

    fn verify_action(
        &self,
        event: &VerificationEvent<'_>,
        record: &DecisionRecordV1,
        action_id: &str,
        confidence: u32,
    ) -> Result<(), ReplayVerificationError> {
        if !self.is_target_action(event) {
            return Err(ReplayVerificationError::MissingOrMismatchedAcceptedAction);
        }
        let record_hash = record
            .hash()
            .map_err(|_| ReplayVerificationError::DecisionRecordMismatch)?;
        let expected = AgentActionV1::try_new(
            action_id.to_owned(),
            confidence,
            record.request().driver_tick(),
            record.request().catalogue_hash(),
            record_hash,
        )
        .map_err(|_| ReplayVerificationError::MissingOrMismatchedAcceptedAction)?
        .encode()
        .map_err(|_| ReplayVerificationError::MissingOrMismatchedAcceptedAction)?;
        if event.payload != Some(expected.as_slice()) {
            return Err(ReplayVerificationError::MissingOrMismatchedAcceptedAction);
        }
        Ok(())
    }

    fn is_target_record(&self, event: &VerificationEvent<'_>) -> bool {
        event.entity == self.target_agent && event.event_type == RECORDER_EVENT_TYPE
    }

    fn is_target_action(&self, event: &VerificationEvent<'_>) -> bool {
        event.entity == self.target_agent && event.event_type == EVENT_TYPE_ACTION
    }
}

fn validate_recovery_sequence(
    events: &[VerificationEvent<'_>],
    expected_through: Seq,
) -> Result<(), ReplayVerificationError> {
    if events.is_empty() && expected_through == Seq::ZERO {
        return Ok(());
    }
    if events.first().map_or(Seq::ZERO, |event| event.seq) != Seq::from_u64(1) {
        return Err(ReplayVerificationError::NonContiguousSourceSequence {
            expected: 1,
            actual: events.first().map_or(0, |event| event.seq.as_u64()),
        });
    }
    for pair in events.windows(2) {
        let expected = pair[0].seq.as_u64().saturating_add(1);
        if pair[1].seq.as_u64() != expected {
            return Err(ReplayVerificationError::NonContiguousSourceSequence {
                expected,
                actual: pair[1].seq.as_u64(),
            });
        }
    }
    let actual = events.last().map_or(Seq::ZERO, |event| event.seq);
    if actual != expected_through {
        return Err(ReplayVerificationError::NonContiguousSourceSequence {
            expected: expected_through.as_u64(),
            actual: actual.as_u64(),
        });
    }
    Ok(())
}

fn verification_event(event: &RecoveryEvent) -> VerificationEvent<'_> {
    VerificationEvent {
        seq: event.header().seq(),
        entity: event.header().entity(),
        event_type: event.header().event_type().as_str(),
        payload: event
            .payload()
            .map(pos_core::event::CanonicalBytes::as_slice),
    }
}

fn validate_source_sequence(events: &[Event]) -> Result<Seq, ReplayVerificationError> {
    for (index, event) in events.iter().enumerate() {
        let expected = u64::try_from(index)
            .map_err(|_| ReplayVerificationError::DriverTickOverflow)?
            .checked_add(1)
            .ok_or(ReplayVerificationError::DriverTickOverflow)?;
        if event.seq.as_u64() != expected {
            return Err(ReplayVerificationError::NonContiguousSourceSequence {
                expected,
                actual: event.seq.as_u64(),
            });
        }
    }
    Ok(events.last().map_or(Seq::ZERO, |event| event.seq))
}

fn advance_driver_tick(current: u64) -> Result<u64, ReplayVerificationError> {
    current
        .checked_add(1)
        .ok_or(ReplayVerificationError::DriverTickOverflow)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        advance_driver_tick, validate_recovery_sequence, AgentDecisionReplayVerifier,
        ReplayVerificationError, VerificationEvent,
    };
    use crate::protocol::{
        ActionCatalogueV1, AgentActionV1, AgentDecisionRequestV1, AgentProviderProvenanceV1,
        DecisionRecordV1, DecisionResultV1, ProviderDecisionV1,
    };
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, Event, Kind, SchemaVersion},
        ids::{EntityId, EventId, PluginId, TimelineId},
    };
    use pos_runtime::TimelineHistorySegment;

    type VerifierFixture = (
        AgentDecisionReplayVerifier,
        TimelineId,
        EntityId,
        ActionCatalogueV1,
        AgentProviderProvenanceV1,
    );

    fn verifier_fixture() -> Result<VerifierFixture, Box<dyn std::error::Error>> {
        let timeline = TimelineId::new();
        let target_agent = EntityId::new();
        let catalogue = ActionCatalogueV1::try_new(vec!["move".to_owned()])?;
        let provenance = AgentProviderProvenanceV1::try_new(
            PluginId::new(),
            "1.0.0".to_owned(),
            [1; 32],
            "fixture-provider".to_owned(),
            "1.0.0".to_owned(),
            [2; 32],
        )?;
        let verifier = AgentDecisionReplayVerifier::try_new_with_timeline_ancestry(
            vec![TimelineHistorySegment::new(timeline, Seq::from_u64(2))],
            target_agent,
            provenance.clone(),
            catalogue.clone(),
        )?;
        Ok((verifier, timeline, target_agent, catalogue, provenance))
    }

    fn source_event(seq: u64, entity: EntityId, event_type: &str, payload: Vec<u8>) -> Event {
        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(event_type),
            payload: CanonicalBytes::from_vec(payload),
            wall_time: WallTime::from_micros(seq),
            seq: Seq::from_u64(seq),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0; 32]),
        }
    }

    fn accepted_events(
        target_agent: EntityId,
        catalogue: &ActionCatalogueV1,
        provenance: &AgentProviderProvenanceV1,
        timeline: TimelineId,
    ) -> Result<Vec<Event>, Box<dyn std::error::Error>> {
        let catalogue_hash = catalogue.hash()?;
        let request = AgentDecisionRequestV1::new(
            timeline,
            0,
            target_agent,
            0,
            catalogue_hash,
            provenance.clone(),
        );
        let request_hash = request.hash()?;
        let result = ProviderDecisionV1::accepted(0, 800_000)?;
        let record = DecisionRecordV1::try_new(
            request,
            request_hash,
            Some([3; 32]),
            DecisionResultV1::from(result),
        )?;
        let record_hash = record.hash()?;
        let action =
            AgentActionV1::try_new("move".to_owned(), 800_000, 0, catalogue_hash, record_hash)?;
        Ok(vec![
            source_event(
                1,
                target_agent,
                super::RECORDER_EVENT_TYPE,
                record.encode()?,
            ),
            source_event(2, target_agent, super::EVENT_TYPE_ACTION, action.encode()?),
        ])
    }

    fn event(seq: u64) -> VerificationEvent<'static> {
        VerificationEvent {
            seq: Seq::from_u64(seq),
            entity: EntityId::new(),
            event_type: "fixture",
            payload: None,
        }
    }

    #[test]
    fn driver_tick_advancement_fails_closed_at_the_v1_limit() {
        assert_eq!(advance_driver_tick(0), Ok(1));
        assert_eq!(
            advance_driver_tick(u64::MAX),
            Err(ReplayVerificationError::DriverTickOverflow)
        );
    }

    #[test]
    fn all_replay_verification_error_variants_have_non_empty_display_messages() {
        let variants = [
            ReplayVerificationError::NonContiguousSourceSequence {
                expected: 1,
                actual: 0,
            },
            ReplayVerificationError::MissingCheckpoint { checkpoint: 5 },
            ReplayVerificationError::InvalidDecisionRecord,
            ReplayVerificationError::DecisionRecordMismatch,
            ReplayVerificationError::MissingOrMismatchedAcceptedAction,
            ReplayVerificationError::UnexpectedTargetAction,
            ReplayVerificationError::InvalidTimelineAncestry,
            ReplayVerificationError::DriverTickOverflow,
        ];
        for variant in variants {
            let msg = variant.to_string();
            assert!(!msg.is_empty(), "{variant:?} must have a display message");
        }
    }

    #[test]
    fn recovery_sequence_validation_accepts_empty_zero_and_rejects_every_gap_shape() {
        assert_eq!(validate_recovery_sequence(&[], Seq::ZERO), Ok(()));
        assert_eq!(
            validate_recovery_sequence(&[], Seq::from_u64(1)),
            Err(ReplayVerificationError::NonContiguousSourceSequence {
                expected: 1,
                actual: 0,
            })
        );
        assert_eq!(
            validate_recovery_sequence(&[event(2)], Seq::from_u64(2)),
            Err(ReplayVerificationError::NonContiguousSourceSequence {
                expected: 1,
                actual: 2,
            })
        );
        assert_eq!(
            validate_recovery_sequence(&[event(1), event(3)], Seq::from_u64(3)),
            Err(ReplayVerificationError::NonContiguousSourceSequence {
                expected: 2,
                actual: 3,
            })
        );
        assert_eq!(
            validate_recovery_sequence(&[event(1)], Seq::from_u64(2)),
            Err(ReplayVerificationError::NonContiguousSourceSequence {
                expected: 2,
                actual: 1,
            })
        );
        assert_eq!(
            validate_recovery_sequence(&[event(1), event(2)], Seq::from_u64(2)),
            Ok(())
        );
    }

    #[test]
    fn verifier_accepts_adjacent_decisions_and_revalidates_checkpoints(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (verifier, timeline, target_agent, catalogue, provenance) = verifier_fixture()?;
        let events = accepted_events(target_agent, &catalogue, &provenance, timeline)?;
        let checkpoint = verifier.verify(&events, None)?;
        assert_eq!(checkpoint.last_verified(), Seq::from_u64(2));
        assert_eq!(checkpoint.verified_decisions(), 1);
        assert_eq!(verifier.verify(&events, Some(checkpoint))?, checkpoint);
        let mut malformed_suffix = events.clone();
        malformed_suffix.push(source_event(
            3,
            target_agent,
            super::RECORDER_EVENT_TYPE,
            b"bad".to_vec(),
        ));
        assert_eq!(
            verifier.verify(&malformed_suffix, Some(checkpoint)),
            Err(ReplayVerificationError::InvalidDecisionRecord)
        );
        assert_eq!(
            verifier.verify(
                &events,
                Some(super::ReplayCheckpoint {
                    last_verified: Seq::from_u64(3),
                    verified_decisions: 0,
                })
            ),
            Err(ReplayVerificationError::MissingCheckpoint { checkpoint: 3 })
        );
        Ok(())
    }

    #[test]
    fn verifier_rejects_malformed_and_unpaired_target_records(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (verifier, timeline, target_agent, catalogue, provenance) = verifier_fixture()?;
        let malformed = source_event(1, target_agent, super::RECORDER_EVENT_TYPE, b"bad".to_vec());
        assert_eq!(
            verifier.verify(&[malformed], None),
            Err(ReplayVerificationError::InvalidDecisionRecord)
        );

        let action = source_event(1, target_agent, super::EVENT_TYPE_ACTION, b"bad".to_vec());
        assert_eq!(
            verifier.verify(&[action], None),
            Err(ReplayVerificationError::UnexpectedTargetAction)
        );

        let events = accepted_events(target_agent, &catalogue, &provenance, timeline)?;
        assert_eq!(
            verifier.verify(&events[..1], None),
            Err(ReplayVerificationError::MissingOrMismatchedAcceptedAction)
        );
        let mut mismatched = events;
        mismatched[1].payload = CanonicalBytes::from_vec(b"wrong".to_vec());
        assert_eq!(
            verifier.verify(&mismatched, None),
            Err(ReplayVerificationError::MissingOrMismatchedAcceptedAction)
        );
        Ok(())
    }

    #[test]
    fn verifier_rejects_invalid_timeline_ancestry_and_source_sequence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (verifier, timeline, target_agent, _, provenance) = verifier_fixture()?;
        assert!(matches!(
            AgentDecisionReplayVerifier::try_new_with_timeline_ancestry(
                Vec::new(),
                target_agent,
                provenance.clone(),
                ActionCatalogueV1::try_new(vec!["move".to_owned()])?,
            ),
            Err(ReplayVerificationError::InvalidTimelineAncestry)
        ));
        let first = TimelineHistorySegment::new(timeline, Seq::from_u64(2));
        assert!(matches!(
            AgentDecisionReplayVerifier::try_new_with_timeline_ancestry(
                vec![first, first],
                target_agent,
                provenance,
                ActionCatalogueV1::try_new(vec!["move".to_owned()])?,
            ),
            Err(ReplayVerificationError::InvalidTimelineAncestry)
        ));
        let invalid = source_event(2, target_agent, "other", Vec::new());
        assert_eq!(
            verifier.verify(&[invalid], None),
            Err(ReplayVerificationError::NonContiguousSourceSequence {
                expected: 1,
                actual: 2,
            })
        );
        Ok(())
    }
}
