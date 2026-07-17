//! Recorded-decision determinism contract.
//!
//! Any nondeterministic plugin output (LLM call, sensor read, RNG) must go through
//! the `Recorder`. In `Live` mode the output is recorded as an event in the timeline.
//! In `Replay` mode the output is read back from the log — so every run is bit-exact.
//!
//! # Invariant
//! `Live(log) → Replay(same log)` always produces identical outputs.

use pos_core::{
    event::{CanonicalBytes, EventDraft, Kind},
    ids::{EntityId, TimelineId},
    store::EventStore,
};

use crate::error::RuntimeError;

/// Whether the runtime is producing new outputs or replaying recorded ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunMode {
    /// Produce outputs and record them as events.
    Live,
    /// Read outputs from the event log (bit-exact replay).
    Replay,
}

impl std::fmt::Display for RunMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Live => write!(f, "Live"),
            Self::Replay => write!(f, "Replay"),
        }
    }
}

/// A recorded nondeterministic output.
///
/// In `Live` mode the caller provides the output bytes and the Recorder stores them.
/// In `Replay` mode the Recorder reads back the bytes from the log.
#[derive(Clone, Debug)]
pub struct RecordedOutput {
    pub bytes: Vec<u8>,
    pub seq_hint: Option<u64>,
}

impl RecordedOutput {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            seq_hint: None,
        }
    }
}

/// The event type used by the Recorder when storing nondeterministic outputs.
pub const RECORDER_EVENT_TYPE: &str = "runtime.recorded_output";

/// The Recorder wires nondeterministic outputs into the event log.
///
/// In `Live` mode: caller provides bytes → Recorder appends them as an event.
/// In `Replay` mode: Recorder reads next `runtime.recorded_output` event → returns bytes.
pub struct Recorder {
    mode: RunMode,
    /// Entity used for recorder events (one per plugin instance).
    entity: EntityId,
    /// Replay cursor: index into the preloaded recorded events.
    replay_cursor: usize,
    /// Preloaded events for replay mode (populated on `prepare_replay`).
    replay_events: Vec<Vec<u8>>,
}

impl Recorder {
    /// Create a new Recorder in `Live` mode.
    #[must_use]
    pub fn new_live(entity: EntityId) -> Self {
        Self {
            mode: RunMode::Live,
            entity,
            replay_cursor: 0,
            replay_events: Vec::new(),
        }
    }

    /// Create a Recorder in `Replay` mode, preloaded with recorded events.
    #[must_use]
    pub fn new_replay(entity: EntityId, recorded: Vec<Vec<u8>>) -> Self {
        Self {
            mode: RunMode::Replay,
            entity,
            replay_cursor: 0,
            replay_events: recorded,
        }
    }

    /// Load replay events from the store for a given timeline.
    ///
    /// Reads all `runtime.recorded_output` events from `entity` and
    /// prepares the Recorder for replay.
    ///
    /// # Errors
    /// Returns [`RuntimeError::Store`] on store read failure.
    pub fn prepare_replay(
        entity: EntityId,
        store: &dyn EventStore,
        timeline: TimelineId,
    ) -> Result<Self, RuntimeError> {
        use pos_core::store::SeqRange;
        let all_events = store.read(timeline, SeqRange::all())?;
        let recorded: Vec<Vec<u8>> = all_events
            .into_iter()
            .filter(|e| e.entity == entity && e.event_type.as_str() == RECORDER_EVENT_TYPE)
            .map(|e| e.payload.as_slice().to_vec())
            .collect();
        Ok(Self::new_replay(entity, recorded))
    }

    /// Current run mode.
    #[must_use]
    pub fn mode(&self) -> RunMode {
        self.mode
    }

    /// Record or replay a nondeterministic output.
    ///
    /// - `Live`: `output_bytes` is the actual output. Returns a draft event to append.
    /// - `Replay`: reads the next recorded output. `output_bytes` is ignored.
    ///
    /// # Errors
    /// Returns [`RuntimeError::ModeMismatch`] if called in wrong mode.
    /// Returns [`RuntimeError::Store`] if replay cursor is exhausted.
    pub fn record(&mut self, output_bytes: Vec<u8>) -> Result<RecordedOutput, RuntimeError> {
        match self.mode {
            RunMode::Live => Ok(RecordedOutput::new(output_bytes)),
            RunMode::Replay => {
                if self.replay_cursor >= self.replay_events.len() {
                    return Err(RuntimeError::ModeMismatch {
                        expected: "more recorded outputs".to_owned(),
                        got: "replay cursor exhausted".to_owned(),
                    });
                }
                let bytes = self.replay_events[self.replay_cursor].clone();
                self.replay_cursor += 1;
                Ok(RecordedOutput {
                    bytes,
                    seq_hint: Some(self.replay_cursor as u64),
                })
            }
        }
    }

    /// Build an event draft to persist a recorded output in `Live` mode.
    ///
    /// Returns `None` in `Replay` mode (nothing to write).
    #[must_use]
    pub fn to_draft(&self, output: &RecordedOutput) -> Option<EventDraft> {
        if self.mode == RunMode::Live {
            Some(EventDraft::new(
                self.entity,
                Kind::new(RECORDER_EVENT_TYPE),
                CanonicalBytes::from_vec(output.bytes.clone()),
            ))
        } else {
            None
        }
    }

    /// How many replay events remain.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.replay_events.len().saturating_sub(self.replay_cursor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::ids::EntityId;
    use pos_store::{open_store, StoreConfig};

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn live_recorder_returns_provided_bytes() {
        let entity = EntityId::new();
        let mut rec = Recorder::new_live(entity);
        assert_eq!(rec.mode(), RunMode::Live);
        let out = rec.record(b"hello".to_vec()).unwrap();
        assert_eq!(out.bytes, b"hello");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn live_recorder_to_draft_returns_some() {
        let entity = EntityId::new();
        let rec = Recorder::new_live(entity);
        let output = RecordedOutput::new(b"data".to_vec());
        let draft = rec.to_draft(&output).unwrap();
        assert_eq!(draft.event_type.as_str(), RECORDER_EVENT_TYPE);
        assert_eq!(draft.payload.as_slice(), b"data");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn replay_recorder_returns_stored_bytes() {
        let entity = EntityId::new();
        let stored = vec![b"first".to_vec(), b"second".to_vec()];
        let mut rec = Recorder::new_replay(entity, stored);
        assert_eq!(rec.mode(), RunMode::Replay);
        assert_eq!(rec.remaining(), 2);

        let out1 = rec.record(b"ignored".to_vec()).unwrap();
        assert_eq!(out1.bytes, b"first");
        assert_eq!(rec.remaining(), 1);

        let out2 = rec.record(b"also_ignored".to_vec()).unwrap();
        assert_eq!(out2.bytes, b"second");
        assert_eq!(rec.remaining(), 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn replay_cursor_exhaustion_returns_error() {
        let entity = EntityId::new();
        let mut rec = Recorder::new_replay(entity, vec![b"only".to_vec()]);
        rec.record(vec![]).unwrap();
        let err = rec.record(vec![]).unwrap_err();
        assert!(matches!(err, RuntimeError::ModeMismatch { .. }));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn replay_to_draft_returns_none() {
        let entity = EntityId::new();
        let rec = Recorder::new_replay(entity, vec![]);
        let output = RecordedOutput::new(b"x".to_vec());
        assert!(rec.to_draft(&output).is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn prepare_replay_loads_recorder_events_from_store() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("t").unwrap();
        let entity = EntityId::new();

        // Write two recorded output events manually
        let drafts = vec![
            EventDraft::new(
                entity,
                Kind::new(RECORDER_EVENT_TYPE),
                CanonicalBytes::from_vec(b"r1".to_vec()),
            ),
            EventDraft::new(
                entity,
                Kind::new("other.event"),
                CanonicalBytes::from_vec(b"skip".to_vec()),
            ),
            EventDraft::new(
                entity,
                Kind::new(RECORDER_EVENT_TYPE),
                CanonicalBytes::from_vec(b"r2".to_vec()),
            ),
        ];
        store.append(tl.id(), &drafts).unwrap();

        let mut rec = Recorder::prepare_replay(entity, store.as_ref(), tl.id()).unwrap();
        assert_eq!(rec.remaining(), 2);
        assert_eq!(rec.record(vec![]).unwrap().bytes, b"r1");
        assert_eq!(rec.record(vec![]).unwrap().bytes, b"r2");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_mode_display() {
        assert_eq!(RunMode::Live.to_string(), "Live");
        assert_eq!(RunMode::Replay.to_string(), "Replay");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn prepare_replay_read_err_propagates() {
        struct ReadFailStore;

        #[cfg_attr(coverage_nightly, coverage(off))]
        impl pos_core::store::EventStore for ReadFailStore {
            fn create_timeline(
                &mut self,
                _: &str,
            ) -> Result<pos_core::Timeline, pos_core::CoreError> {
                Err(pos_core::CoreError::Storage("unused".to_owned()))
            }

            fn append(
                &mut self,
                _: pos_core::TimelineId,
                _: &[EventDraft],
            ) -> Result<Vec<pos_core::Event>, pos_core::CoreError> {
                Err(pos_core::CoreError::Storage("unused".to_owned()))
            }

            fn read(
                &self,
                _: pos_core::TimelineId,
                _: pos_core::store::SeqRange,
            ) -> Result<Vec<pos_core::Event>, pos_core::CoreError> {
                Err(pos_core::CoreError::Storage("read failed".to_owned()))
            }

            fn fork(
                &mut self,
                _: pos_core::TimelineId,
                _: pos_core::Seq,
                _: &str,
            ) -> Result<pos_core::Timeline, pos_core::CoreError> {
                Err(pos_core::CoreError::Storage("unused".to_owned()))
            }

            fn list_timelines(&self) -> Result<Vec<pos_core::Timeline>, pos_core::CoreError> {
                Ok(Vec::new())
            }

            fn get_timeline(
                &self,
                _: pos_core::TimelineId,
            ) -> Result<Option<pos_core::Timeline>, pos_core::CoreError> {
                Ok(None)
            }
        }

        let store = ReadFailStore;
        let result = Recorder::prepare_replay(EntityId::new(), &store, pos_core::TimelineId::new());
        assert!(matches!(result, Err(RuntimeError::Store(_))));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn live_replay_roundtrip() {
        // Simulate: live run records outputs, then replay reads them back identically.
        let entity = EntityId::new();
        let outputs = vec![b"llm_output_1".to_vec(), b"llm_output_2".to_vec()];

        // Live pass: collect drafts
        let mut live = Recorder::new_live(entity);
        let mut recorded_bytes: Vec<Vec<u8>> = Vec::new();
        for o in &outputs {
            let result = live.record(o.clone()).unwrap();
            recorded_bytes.push(result.bytes.clone());
        }

        // Replay pass: should get identical bytes regardless of what we pass
        let mut replay = Recorder::new_replay(entity, recorded_bytes);
        for expected in &outputs {
            let result = replay.record(b"ignored".to_vec()).unwrap();
            assert_eq!(&result.bytes, expected);
        }
    }
}
