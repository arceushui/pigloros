//! Pure verification of provider-backed Agent decisions in immutable source Events.

use crate::{
    protocol::{
        ActionCatalogueV1, AgentActionV1, AgentProviderProvenanceV1, DecisionRecordV1,
        DecisionResultV1,
    },
    EVENT_TYPE_ACTION,
};
use pos_core::{
    clock::Seq,
    event::Event,
    ids::{EntityId, TimelineId},
};
use pos_runtime::recorder::RECORDER_EVENT_TYPE;

/// The verified end of one complete immutable source prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayCheckpoint {
    last_verified: Seq,
}

impl ReplayCheckpoint {
    #[must_use]
    pub const fn last_verified(self) -> Seq {
        self.last_verified
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
}

/// Verifies host-bound PDR1/PAA1 records without provider, store, or append authority.
pub struct AgentDecisionReplayVerifier {
    expected_timeline: TimelineId,
    target_agent: EntityId,
    provenance: AgentProviderProvenanceV1,
    catalogue: ActionCatalogueV1,
}

#[derive(Clone, Copy, Default)]
struct ReplayState {
    expected_driver_tick: u64,
    last_target_sequence: u64,
}

impl AgentDecisionReplayVerifier {
    /// Creates a verifier from host-owned identity, provenance, and catalogue values.
    #[must_use]
    pub fn new(
        expected_timeline: TimelineId,
        target_agent: EntityId,
        provenance: AgentProviderProvenanceV1,
        catalogue: ActionCatalogueV1,
    ) -> Self {
        Self {
            expected_timeline,
            target_agent,
            provenance,
            catalogue,
        }
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
        if let Some(checkpoint) = checkpoint {
            if checkpoint.last_verified > last_verified {
                return Err(ReplayVerificationError::MissingCheckpoint {
                    checkpoint: checkpoint.last_verified.as_u64(),
                });
            }
            let prefix_len = usize::try_from(checkpoint.last_verified.as_u64()).map_err(|_| {
                ReplayVerificationError::MissingCheckpoint {
                    checkpoint: checkpoint.last_verified.as_u64(),
                }
            })?;
            let state = self.verify_events(&events[..prefix_len], ReplayState::default())?;
            self.verify_events(&events[prefix_len..], state)?;
        } else {
            self.verify_events(events, ReplayState::default())?;
        }

        Ok(ReplayCheckpoint { last_verified })
    }

    fn verify_events(
        &self,
        events: &[Event],
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

            let record = DecisionRecordV1::decode(event.payload.as_slice())
                .map_err(|_| ReplayVerificationError::InvalidDecisionRecord)?;
            self.verify_record(event, &record, state)?;
            state.expected_driver_tick = state.expected_driver_tick.wrapping_add(1);
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
        event: &Event,
        record: &DecisionRecordV1,
        state: ReplayState,
    ) -> Result<(), ReplayVerificationError> {
        let request = record.request();
        let catalogue_hash = self
            .catalogue
            .hash()
            .map_err(|_| ReplayVerificationError::DecisionRecordMismatch)?;
        let matches_host = request.timeline_id() == self.expected_timeline
            && request.observed_through() >= state.last_target_sequence
            && request.observed_through() < event.seq.as_u64()
            && request.agent_id() == self.target_agent
            && request.driver_tick() == state.expected_driver_tick
            && request.catalogue_hash() == catalogue_hash
            && request.provenance() == &self.provenance;
        let request_hash = request
            .hash()
            .map_err(|_| ReplayVerificationError::InvalidDecisionRecord)?;
        if !matches_host || record.request_hash() != request_hash {
            return Err(ReplayVerificationError::DecisionRecordMismatch);
        }
        Ok(())
    }

    fn verify_action(
        &self,
        event: &Event,
        record: &DecisionRecordV1,
        action_id: &str,
        confidence: u32,
    ) -> Result<(), ReplayVerificationError> {
        if !self.is_target_action(event) {
            return Err(ReplayVerificationError::MissingOrMismatchedAcceptedAction);
        }
        let record_hash = record
            .hash()
            .map_err(|_| ReplayVerificationError::InvalidDecisionRecord)?;
        let expected = AgentActionV1::try_new(
            action_id.to_owned(),
            confidence,
            record.request().driver_tick(),
            record.request().catalogue_hash(),
            record_hash,
        )
        .map_err(|_| ReplayVerificationError::DecisionRecordMismatch)?
        .encode()
        .map_err(|_| ReplayVerificationError::DecisionRecordMismatch)?;
        if event.payload.as_slice() != expected {
            return Err(ReplayVerificationError::MissingOrMismatchedAcceptedAction);
        }
        Ok(())
    }

    fn is_target_record(&self, event: &Event) -> bool {
        event.entity == self.target_agent && event.event_type.as_str() == RECORDER_EVENT_TYPE
    }

    fn is_target_action(&self, event: &Event) -> bool {
        event.entity == self.target_agent && event.event_type.as_str() == EVENT_TYPE_ACTION
    }
}

fn validate_source_sequence(events: &[Event]) -> Result<Seq, ReplayVerificationError> {
    for (index, event) in events.iter().enumerate() {
        let expected =
            u64::try_from(index).expect("an in-memory Event slice length cannot exceed u64") + 1;
        if event.seq.as_u64() != expected {
            return Err(ReplayVerificationError::NonContiguousSourceSequence {
                expected,
                actual: event.seq.as_u64(),
            });
        }
    }
    Ok(events.last().map_or(Seq::ZERO, |event| event.seq))
}
