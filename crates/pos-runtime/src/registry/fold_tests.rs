//! A quiet run of scheduled Ticks over the real adapters scans every Event
//! once (ADR-064 Revision 4, R4.2 and R4.6; conformance test 7).
//!
//! The Driver emits only drafts of an Ephemeral-declared type, so their nodes
//! are presentation only and no fold input. The plain Events appended between
//! the Ticks are reported as geographic Events by the counting port, because
//! the generic append refuses geographic drafts: the builder sees only the
//! type of a window Event, never its payload.
#![cfg(feature = "local-admission-host")]

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use pos_core::{
    AppendDedupKey, AppendDedupScope, AppendIdentity, CanonicalBytes, CoreError,
    DependencyNodeRecordV1, EntityId, ErasureContainmentGateV1, EventDraft, FactualCutV1,
    FactualFoldCursorV1, FactualFoldWindowV1, FactualHeadV1, FactualOwnerIdV1,
    FactualPrefixReadPortV1, Hash, Kind, PipelineAdmissionBasisV1, PipelineAdmissionPortV1,
    PipelineAttemptIdV1, PipelineEvidenceRefV1, PipelineOutcomeV1, PipelineReceiptLookupV1,
    PipelineSecurityRevisionsV1, RecordedSetCountsV1, Seq, TimelineId, TimelineMeta,
    GEOGRAPHIC_EVENT_TYPE,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};

use super::pass_state_tests::{ephemeral_policy, EPHEMERAL};
use super::test_ext::TestValueExt;
use super::*;
use crate::{driver::ObservationView, LocalScheduledAdmissionHostV1, ScheduledAdmissionStoreV1};

/// The Ticks of the quiet run.
const ROUNDS: u8 = 10;
/// The round whose Tick observes nothing new: its window is empty.
const EMPTY_ROUND: u8 = 5;

/// A Driver that emits one draft of the Ephemeral-declared type each step.
struct QuietDriver;

impl Driver for QuietDriver {
    fn name(&self) -> &'static str {
        "quiet"
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_nanos(10)
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        let payload = CanonicalBytes::from_static(b"quiet");
        let draft = EventDraft::new(EntityId::new(), Kind::new(EPHEMERAL), payload);
        Ok(StepOutput::new(vec![draft]))
    }
}

/// Port over a real store that keeps every basis it is offered, logs the
/// `seq`s of every fold window read, and reports the `geographic` Events as
/// geographic Events.
struct CountingPort<'a> {
    inner: &'a mut dyn ScheduledAdmissionStoreV1,
    geographic: &'a BTreeSet<u64>,
    reads: &'a RefCell<Vec<Vec<u64>>>,
    bases: Vec<PipelineAdmissionBasisV1>,
}

impl PipelineAdmissionPortV1 for CountingPort<'_> {
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        self.bases.push(basis.clone());
        self.inner.admit_pipeline_batch(basis)
    }

    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: NonZeroUsize,
    ) -> Result<pos_core::store::PurgeOutcome, CoreError> {
        self.inner.purge_expired_pipeline_receipts_bounded(limit)
    }

    fn lookup_pipeline_receipt(
        &mut self,
        timeline: TimelineId,
        key: AppendDedupKey,
        attempt_id: PipelineAttemptIdV1,
    ) -> Result<PipelineReceiptLookupV1, CoreError> {
        self.inner
            .lookup_pipeline_receipt(timeline, key, attempt_id)
    }
}

impl FactualPrefixReadPortV1 for CountingPort<'_> {
    fn last_committed_factual_tick(
        &self,
        timeline: TimelineId,
    ) -> Result<FactualHeadV1, CoreError> {
        self.inner.last_committed_factual_tick(timeline)
    }

    fn cut_tick_at(&self, timeline: TimelineId, seq: Seq) -> Result<FactualCutV1, CoreError> {
        self.inner.cut_tick_at(timeline, seq)
    }

    fn nodes_for_committed_events(
        &self,
        timeline: TimelineId,
        seqs: &[Seq],
    ) -> Result<Vec<Option<DependencyNodeRecordV1>>, CoreError> {
        self.inner.nodes_for_committed_events(timeline, seqs)
    }

    fn nodes_by_digest(
        &self,
        timeline: TimelineId,
        digests: &[Hash],
    ) -> Result<Vec<Option<pos_core::factual_dependency::BoundFactualNodeV1>>, CoreError> {
        self.inner.nodes_by_digest(timeline, digests)
    }

    fn last_step_node(
        &self,
        timeline: TimelineId,
        owner: &FactualOwnerIdV1,
    ) -> Result<Option<DependencyNodeRecordV1>, CoreError> {
        self.inner.last_step_node(timeline, owner)
    }

    fn factual_set_counts(&self, timeline: TimelineId) -> Result<RecordedSetCountsV1, CoreError> {
        self.inner.factual_set_counts(timeline)
    }

    fn fold_cursor(&self, timeline: TimelineId) -> Result<Option<FactualFoldCursorV1>, CoreError> {
        self.inner.fold_cursor(timeline)
    }

    fn fold_window(
        &self,
        timeline: TimelineId,
        after: Seq,
        through: Seq,
    ) -> Result<FactualFoldWindowV1, CoreError> {
        let mut window = self.inner.fold_window(timeline, after, through)?;
        for event in &mut window.events {
            if self.geographic.contains(&event.seq.as_u64()) {
                event.event_type = Kind::new(GEOGRAPHIC_EVENT_TYPE);
            }
        }
        let seqs = window.events.iter().map(|event| event.seq.as_u64());
        self.reads.borrow_mut().push(seqs.collect());
        Ok(window)
    }
}

/// Two plain Events, which the counting port reports as geographic.
fn plain_drafts() -> Vec<EventDraft> {
    (0..2_u8)
        .map(|index| {
            let payload = CanonicalBytes::from_vec(vec![index]);
            EventDraft::new(EntityId::new(), Kind::new("quiet.plain"), payload)
        })
        .collect()
}

/// The host inputs of one Tick, read after its pass.
fn admission(
    host: &LocalScheduledAdmissionHostV1,
    revisions: PipelineSecurityRevisionsV1,
    commit_head: Seq,
    key: u8,
) -> ScheduledPassAdmissionV1 {
    let evidence = Hash::from_bytes([60; 32]);
    ScheduledPassAdmissionV1 {
        attempt_id: PipelineAttemptIdV1::try_new([key; 16]).test_ok(),
        idempotency: AppendIdentity::new(
            AppendDedupKey::from_keyed_hash([key; 32]),
            AppendDedupScope::from_keyed_hash([62; 32]),
        ),
        provider_validation: PipelineEvidenceRefV1::try_new(evidence).test_ok(),
        security_revisions: revisions,
        authority_grant: host.authority_grant(),
        commit_head,
        commit_now_secs: 1,
    }
}

/// What the quiet run of one store observed.
struct QuietRun {
    reads: Vec<Vec<u64>>,
    bases: Vec<PipelineAdmissionBasisV1>,
    /// The fold cursor after each Tick, and the anchor of that Tick.
    cursors: Vec<(Option<FactualFoldCursorV1>, Seq)>,
}

/// A registry of the quiet Driver, composed non-participant.
fn quiet_registry(gate: Arc<ErasureContainmentGateV1>) -> PluginRegistry {
    let mut registry = PluginRegistry::new().with_erasure_gate(gate);
    let plugin_id = PluginId::new();
    let (policy, budget) = ephemeral_policy(plugin_id);
    let driver = Box::new(QuietDriver);
    registry
        .register_test_driver_with_output_policy(plugin_id, "test", policy, budget, driver)
        .test_ok();
    // The test registration records no schema; admission validates one.
    registry.schemas.register_claimed(EventTypeSchema {
        event_type: Kind::new(EPHEMERAL),
        description: "the quiet Driver's Ephemeral output".to_owned(),
        json_schema: None,
    });
    registry.compose_non_participant_drivers().test_ok();
    registry
}

/// Run `ROUNDS` scheduled Ticks of the quiet Driver. Every round but
/// `EMPTY_ROUND` first appends two plain Events and observes through the new
/// head; `EMPTY_ROUND` observes through the previous anchor.
fn quiet_run<S: ScheduledAdmissionStoreV1>(store: &mut S) -> QuietRun {
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    store.bind_erasure_gate(Arc::clone(&gate)).test_ok();
    let timeline = store.create_timeline("quiet-run").test_ok().id();
    let ancestry = [TimelineMeta {
        id: timeline,
        ..TimelineMeta::root("root")
    }];
    let host = LocalScheduledAdmissionHostV1::shared().test_ok();
    let mut registry = quiet_registry(gate);
    let (mut geographic, reads) = (BTreeSet::new(), RefCell::default());
    let (mut bases, mut cursors) = (Vec::new(), Vec::new());
    let mut through = Seq::ZERO;
    for round in 1..=ROUNDS {
        if round != EMPTY_ROUND {
            let appended = store.append(timeline, &plain_drafts()).test_ok();
            geographic.extend(appended.iter().map(|event| event.seq.as_u64()));
            through = store.logical_head(timeline).test_ok();
        }
        let revisions = host.observe(&registry, store, timeline).test_ok();
        registry
            .step_all_anchored(timeline, &ancestry, through)
            .test_ok();
        let head = store.logical_head(timeline).test_ok();
        let inputs = admission(host, revisions, head, round);
        let mut port = CountingPort {
            inner: &mut *store,
            geographic: &geographic,
            reads: &reads,
            bases: Vec::new(),
        };
        registry.admit_scheduled_pass(&mut port, &inputs).test_ok();
        bases.append(&mut port.bases);
        cursors.push((store.fold_cursor(timeline).test_ok(), through));
    }
    QuietRun {
        reads: reads.into_inner(),
        bases,
        cursors,
    }
}

/// ADR-064 R4.2 and R4.6: over a quiet run each Event is in exactly one
/// Tick's window, the Tick whose window is empty reads only the fold-head row,
/// no fold node is recorded, and every Tick writes a fold-head row through its
/// anchor that names no head.
#[test]
fn a_quiet_run_scans_every_event_once_and_records_no_fold_node() {
    let memory = quiet_run(&mut MemoryStore::new());
    let sqlite = quiet_run(&mut SqliteStore::open(":memory:").test_ok());
    for (name, run) in [("memory", memory), ("sqlite", sqlite)] {
        let rounds = usize::from(ROUNDS);
        assert_eq!(run.reads.len(), rounds - 1, "{name}");
        let scanned: Vec<u64> = run.reads.concat();
        let last = run.cursors.last().test_ok().1.as_u64();
        assert_eq!(scanned, (1..=last).collect::<Vec<_>>(), "{name}");
        assert_eq!(run.bases.len(), rounds, "{name}");
        for basis in &run.bases {
            let fold = basis.dependencies().fold();
            assert!(fold.checkpoints.is_empty(), "{name}");
            assert!(fold.history.is_empty(), "{name}");
        }
        for (cursor, through) in run.cursors {
            let expected = FactualFoldCursorV1 {
                scanned_through: through,
                head: None,
            };
            assert_eq!(cursor, Some(expected), "{name}");
        }
    }
}
