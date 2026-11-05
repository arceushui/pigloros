//! The Replay and Fork runners over the Experiment host.
//!
//! Both runners take a [`NonInterferenceSessionSubjectV1`]: the host side of
//! one row that composes the subject's [`Experiment`] for a run (placing the
//! unauthorized value in the row's denied channel), supplies a fresh
//! Projection registry, and maps what the run observed to the row's raw
//! capture.
//!
//! - Replay records the subject's run to quiescence or its stop condition,
//!   then rebuilds Projection State from the recorded Events alone, in a
//!   fresh registry with no Driver. The capture observes the recorded Events
//!   and the replayed State.
//! - Fork advances the parent run by the runner's cut Ticks, forks the
//!   Timeline at that Tick Boundary (the Fork Cut), runs the Fork, and
//!   rebuilds Projection State from the Fork's stitched Events. The capture
//!   observes the Fork's Events and that State.
//!
//! Each runner binds its provenance (mode, recorded Event types and payloads,
//! and the canonical replayed State) into the capture.

use std::collections::HashMap;

use pos_conformance::{ExecutionModeV1, NonInterferenceHostRunV1, NonInterferenceRawCaptureV1};
use pos_core::{ids::TimelineId, Event, StateRegistry};
use pos_state::ProjectionRegistry;

use super::{
    NonInterferenceModeRunnerV1, NonInterferenceNonExecutedCauseV1, NonInterferencePreparationV1,
};
use crate::{Experiment, ExperimentError, ExperimentSession};

const PROVENANCE_DOMAIN_V1: &[u8] = b"PiglorOS.NonInterference.SessionProvenance.v1";
const FORK_NAME: &str = "non-interference-fork";

/// What one Replay or Fork run observed.
#[derive(Clone, Copy, Debug)]
pub struct NonInterferenceSessionObservationV1<'a> {
    /// The recorded (Replay) or stitched Fork (Fork) Events in Timeline
    /// Order.
    pub events: &'a [Event],
    /// Projection State rebuilt from `events` alone.
    pub snapshot: &'a HashMap<String, StateRegistry>,
}

/// The host side of one row for the Replay and Fork runners.
pub trait NonInterferenceSessionSubjectV1 {
    /// Reset the subject's host state before one case.
    ///
    /// # Errors
    /// Returns the cause when the subject cannot be prepared.
    fn prepare(
        &mut self,
        preparation: NonInterferencePreparationV1,
    ) -> Result<(), NonInterferenceNonExecutedCauseV1>;

    /// Compose the subject's Experiment for one run. A cold run must start
    /// from fresh host state; the Fork runner needs a Fork registry factory.
    ///
    /// # Errors
    /// Returns the cause when the run cannot be composed.
    fn compose(
        &mut self,
        run: &NonInterferenceHostRunV1<'_>,
        preparation: NonInterferencePreparationV1,
    ) -> Result<Experiment, NonInterferenceNonExecutedCauseV1>;

    /// A fresh Projection registry with the subject's Reducers and a bound
    /// erasure gate.
    fn projections(&self) -> ProjectionRegistry;

    /// Map one observation to the row's raw capture. Its provenance digest
    /// is replaced by the runner's.
    ///
    /// # Errors
    /// Returns the cause when the observation cannot be captured.
    fn capture(
        &mut self,
        run: &NonInterferenceHostRunV1<'_>,
        observation: &NonInterferenceSessionObservationV1<'_>,
    ) -> Result<NonInterferenceRawCaptureV1, NonInterferenceNonExecutedCauseV1>;
}

/// The Replay runner.
#[derive(Debug)]
pub struct NonInterferenceReplayRunnerV1<S> {
    subject: S,
}

impl<S> NonInterferenceReplayRunnerV1<S> {
    /// The Replay runner of `subject`.
    #[must_use]
    pub const fn new(subject: S) -> Self {
        Self { subject }
    }
}

impl<S: NonInterferenceSessionSubjectV1> NonInterferenceModeRunnerV1
    for NonInterferenceReplayRunnerV1<S>
{
    fn mode(&self) -> ExecutionModeV1 {
        ExecutionModeV1::Replay
    }

    fn prepare(
        &mut self,
        preparation: NonInterferencePreparationV1,
    ) -> Result<(), NonInterferenceNonExecutedCauseV1> {
        self.subject.prepare(preparation)
    }

    fn execute(
        &mut self,
        run: &NonInterferenceHostRunV1<'_>,
        preparation: NonInterferencePreparationV1,
    ) -> Result<NonInterferenceRawCaptureV1, NonInterferenceNonExecutedCauseV1> {
        self.subject
            .compose(run, preparation)
            .and_then(|experiment| {
                experiment
                    .start()
                    .map_err(NonInterferenceNonExecutedCauseV1::from)
            })
            .and_then(|mut session| recorded(&mut session))
            .and_then(|(timeline, events)| {
                observe(&mut self.subject, run, b"replay", timeline, &events)
            })
    }
}

/// The Fork runner.
#[derive(Debug)]
pub struct NonInterferenceForkRunnerV1<S> {
    subject: S,
    cut_ticks: u64,
}

impl<S> NonInterferenceForkRunnerV1<S> {
    /// The Fork runner of `subject`; the parent run advances `cut_ticks`
    /// Ticks before the Fork Cut.
    #[must_use]
    pub const fn new(subject: S, cut_ticks: u64) -> Self {
        Self { subject, cut_ticks }
    }
}

impl<S: NonInterferenceSessionSubjectV1> NonInterferenceModeRunnerV1
    for NonInterferenceForkRunnerV1<S>
{
    fn mode(&self) -> ExecutionModeV1 {
        ExecutionModeV1::Fork
    }

    fn prepare(
        &mut self,
        preparation: NonInterferencePreparationV1,
    ) -> Result<(), NonInterferenceNonExecutedCauseV1> {
        self.subject.prepare(preparation)
    }

    fn execute(
        &mut self,
        run: &NonInterferenceHostRunV1<'_>,
        preparation: NonInterferencePreparationV1,
    ) -> Result<NonInterferenceRawCaptureV1, NonInterferenceNonExecutedCauseV1> {
        let cut_ticks = self.cut_ticks;
        self.subject
            .compose(run, preparation)
            .and_then(|experiment| {
                experiment
                    .start()
                    .map_err(NonInterferenceNonExecutedCauseV1::from)
            })
            .and_then(|mut parent| {
                (0..cut_ticks)
                    .try_for_each(|_| parent.step().map(drop))
                    .and_then(|()| parent.fork(FORK_NAME))
                    .map_err(NonInterferenceNonExecutedCauseV1::from)
            })
            .and_then(|mut fork| recorded(&mut fork))
            .and_then(|(timeline, events)| {
                observe(&mut self.subject, run, b"fork", timeline, &events)
            })
    }
}

/// Step a session to quiescence or its stop condition and read its Events.
fn recorded(
    session: &mut ExperimentSession,
) -> Result<(TimelineId, Vec<Event>), NonInterferenceNonExecutedCauseV1> {
    while session.step()? {}
    session
        .source_events()
        .map(|events| (session.timeline().id(), events))
        .map_err(NonInterferenceNonExecutedCauseV1::from)
}

/// Rebuild Projection State from `events` alone, capture the observation and
/// bind the run's provenance.
fn observe<S: NonInterferenceSessionSubjectV1>(
    subject: &mut S,
    run: &NonInterferenceHostRunV1<'_>,
    mode: &[u8],
    timeline: TimelineId,
    events: &[Event],
) -> Result<NonInterferenceRawCaptureV1, NonInterferenceNonExecutedCauseV1> {
    let mut projections = subject.projections();
    projections.fold_events(timeline, events);
    projections
        .state_snapshot(timeline)
        .ok()
        .and_then(|snapshot| {
            pos_crypto::canonical::encode(&snapshot)
                .ok()
                .map(|state| (snapshot, state))
        })
        .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
        .and_then(|(snapshot, state)| {
            subject
                .capture(
                    run,
                    &NonInterferenceSessionObservationV1 {
                        events,
                        snapshot: &snapshot,
                    },
                )
                .map(|mut capture| {
                    capture.provenance_digest = provenance(mode, events, state.as_slice());
                    capture
                })
        })
}

fn provenance(mode: &[u8], events: &[Event], state: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROVENANCE_DOMAIN_V1);
    hasher.update(&[0]);
    hasher.update(&(mode.len() as u64).to_be_bytes());
    hasher.update(mode);
    for event in events {
        for value in [
            event.event_type.as_str().as_bytes(),
            event.payload.as_slice(),
        ] {
            hasher.update(&(value.len() as u64).to_be_bytes());
            hasher.update(value);
        }
    }
    hasher.update(&(state.len() as u64).to_be_bytes());
    hasher.update(state);
    *hasher.finalize().as_bytes()
}

/// A host failure of the Experiment leaves the run unavailable.
impl From<ExperimentError> for NonInterferenceNonExecutedCauseV1 {
    fn from(_: ExperimentError) -> Self {
        Self::Unavailable
    }
}
