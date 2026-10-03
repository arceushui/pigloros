//! Recovery and duplicate receipt of a committed participant-authorized
//! scheduled pass (#507).
//!
//! ADR-021 Revision 3 makes recovery and duplicate receipt shared
//! obligations of both scheduled observation profiles. This test host
//! persists the participant's capability grant in each store and publishes
//! the Timeline's admission fence over it. The store fence is then the
//! recovery-time authority check for a participant-authorized pass, exactly
//! as it is for an anchored pass: recovery resubmits the retained basis and
//! never restages a Driver or releases a view again.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use pos_core::{
    pipeline_authority_revision_v1, pipeline_delegation_revision_v1, pipeline_erasure_revision_v1,
    AppendDedupKey, AppendDedupScope, AppendIdentity, CapabilityRevocationDraftV1,
    CapabilityRevocationV1, CoreError, EntityId, ErasureContainmentGateV1, EventDraft, Hash,
    PipelineAdmissionBasisV1, PipelineAdmissionFenceV1, PipelineAdmissionPortV1,
    PipelineAttemptIdV1, PipelineCommitReceiptV1, PipelineEvidenceRefV1, PipelineOutcomeV1,
    PipelineReceiptLookupV1, PipelineSecurityRevisionsDraftV1, PipelineSecurityRevisionsV1,
    PurgeOutcome, Seq, TimelineId,
};
use pos_runtime::{
    PluginRegistry, RuntimeError, ScheduledAdmissionStoreV1, ScheduledPassAdmissionV1,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};

use super::{
    harness::Capture,
    profiles::{
        bind_participants, observation_evaluation, participant_on, stage_authorized, Participant,
        CUT,
    },
    support::{draft, events, gated_registry, stage, FixturePlugin, ScriptedDriver, TestOk},
};

const PARTICIPANT_TYPE: &str = "participant.recovery";
const ANCHORED_TYPE: &str = "anchored.recovery";

type Admitted = Result<Option<PipelineCommitReceiptV1>, RuntimeError>;

/// Whether a port delivers the store's acknowledgement to the registry.
#[derive(Clone, Copy)]
enum Ack {
    Delivered,
    LostAfterCommit,
    LostBeforeCommit,
}

/// A port over a real store that records every store outcome and can lose
/// the acknowledgement after, or instead of, the commit.
struct AckPort<'a> {
    store: &'a mut dyn ScheduledAdmissionStoreV1,
    ack: Ack,
    outcomes: Vec<PipelineOutcomeV1>,
}

fn lost_acknowledgement() -> CoreError {
    CoreError::StorageOutcomeUnknown("injected lost acknowledgement".to_owned())
}

impl PipelineAdmissionPortV1 for AckPort<'_> {
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        if matches!(self.ack, Ack::LostBeforeCommit) {
            return Err(lost_acknowledgement());
        }
        let outcome = self.store.admit_pipeline_batch(basis).test_ok();
        self.outcomes.push(outcome.clone());
        if matches!(self.ack, Ack::LostAfterCommit) {
            return Err(lost_acknowledgement());
        }
        Ok(outcome)
    }

    fn lookup_pipeline_receipt(
        &mut self,
        timeline: TimelineId,
        key: AppendDedupKey,
        attempt_id: PipelineAttemptIdV1,
    ) -> Result<PipelineReceiptLookupV1, CoreError> {
        self.store
            .lookup_pipeline_receipt(timeline, key, attempt_id)
    }

    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: std::num::NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        self.store.purge_expired_pipeline_receipts_bounded(limit)
    }
}

/// One store whose Timeline holds the base cut, the participant's persisted
/// grant, and an admission fence published over that grant.
struct FencedStore {
    store: Box<dyn ScheduledAdmissionStoreV1>,
    participant: Participant,
    revisions: PipelineSecurityRevisionsV1,
}

const fn digest(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

fn fenced(mut store: Box<dyn ScheduledAdmissionStoreV1>) -> FencedStore {
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    store
        .bind_erasure_gate(Arc::<ErasureContainmentGateV1>::clone(&gate))
        .test_ok();
    let timeline = store.create_timeline("participant-recovery").test_ok().id();
    let prior: Vec<EventDraft> = (0..CUT)
        .map(|_| draft(EntityId::new(), "world.prior", b"prior"))
        .collect();
    store.append(timeline, &prior).test_ok();
    let participant = participant_on(timeline);
    store
        .bind_authority_persistence(participant.host.persistence_binding())
        .test_ok();
    store
        .issue_capability_grant(
            participant
                .host
                .authorize_grant(&participant.grant)
                .test_ok(),
            &participant.grant,
        )
        .test_ok();
    let grant_id = participant.grant.grant_id();
    let authority = store.load_authority(grant_id).test_ok();
    let revisions = PipelineSecurityRevisionsV1::try_from_draft(PipelineSecurityRevisionsDraftV1 {
        authority: pipeline_authority_revision_v1(&authority),
        consent: digest(51),
        capability: digest(52),
        delegation: pipeline_delegation_revision_v1(&authority),
        policy: digest(54),
        execution_profile: digest(55),
        erasure: pipeline_erasure_revision_v1(gate.inventory_generation().ok()),
    })
    .test_ok();
    store
        .set_pipeline_admission_fence(
            timeline,
            PipelineAdmissionFenceV1::try_new(grant_id, revisions, None, 100).test_ok(),
        )
        .test_ok();
    FencedStore {
        store,
        participant,
        revisions,
    }
}

impl FencedStore {
    /// Host admission inputs read after the pass finished.
    fn admission(&self, key: u8) -> ScheduledPassAdmissionV1 {
        ScheduledPassAdmissionV1 {
            attempt_id: PipelineAttemptIdV1::try_new([key; 16]).test_ok(),
            idempotency: AppendIdentity::new(
                AppendDedupKey::from_keyed_hash([key; 32]),
                AppendDedupScope::from_keyed_hash([62; 32]),
            ),
            provider_validation: PipelineEvidenceRefV1::try_new(digest(60)).test_ok(),
            security_revisions: self.revisions,
            commit_head: self
                .store
                .logical_head(self.participant.timeline_id)
                .test_ok(),
            commit_now_secs: 1,
        }
    }

    /// The number of Events committed after the base cut.
    fn committed(&self) -> usize {
        events(self.store.as_ref(), self.participant.timeline_id)
            .iter()
            .filter(|event| event.seq > Seq::from_u64(CUT))
            .count()
    }

    /// Persist a revocation of the participant's grant, which the admission
    /// fence names.
    fn revoke(&mut self) {
        let grant = &self.participant.grant;
        let revocation = CapabilityRevocationV1::try_from_draft(CapabilityRevocationDraftV1 {
            grant_id: grant.grant_id(),
            authority_timeline: grant.issuance_timeline(),
            fence_position: Seq::from_u64(11),
            revocation_epoch: 1,
            policy_revision: grant.policy_revision(),
            authority_registry_digest: grant.authority_registry_digest(),
        })
        .test_ok();
        let permit = self
            .participant
            .host
            .authorize_revocation(grant, &revocation)
            .test_ok();
        self.store
            .revoke_capability_grant(permit, &revocation)
            .test_ok();
    }

    /// Admit the staged participant pass under current view authority.
    fn admit_participant(
        &mut self,
        registry: &mut PluginRegistry,
        key: u8,
        ack: Ack,
    ) -> (Admitted, Vec<PipelineOutcomeV1>) {
        let admission = self.admission(key);
        let evaluation = observation_evaluation(&self.participant.observation);
        let current = self.participant.current_authority();
        let mut port = AckPort {
            store: self.store.as_mut(),
            ack,
            outcomes: Vec::new(),
        };
        let result = registry.admit_authorized_scheduled_pass(
            &mut port,
            &admission,
            &[self.participant.authority(&evaluation, &current)],
        );
        (result, port.outcomes)
    }

    /// Recover the registry's in-doubt pass through a delivering port.
    fn recover(&mut self, registry: &mut PluginRegistry) -> (Admitted, Vec<PipelineOutcomeV1>) {
        let mut port = AckPort {
            store: self.store.as_mut(),
            ack: Ack::Delivered,
            outcomes: Vec::new(),
        };
        let result = registry.recover_scheduled_pass(&mut port);
        (result, port.outcomes)
    }
}

/// A registry whose one Driver emits one draft of `event_type`; returns its
/// step and abort counters.
fn scripted_registry(
    plugin: &FixturePlugin,
    event_type: &'static str,
) -> (PluginRegistry, ScriptedCounters) {
    let mut registry = gated_registry(None);
    let driver = ScriptedDriver::new(plugin.name, vec![draft(EntityId::new(), event_type, b"1")]);
    let counters = ScriptedCounters {
        steps: Arc::clone(&driver.steps),
        aborts: Arc::clone(&driver.aborts),
    };
    registry
        .register_generated(plugin, None, Some(Box::new(driver)))
        .test_ok();
    (registry, counters)
}

struct ScriptedCounters {
    steps: Arc<AtomicUsize>,
    aborts: Arc<AtomicUsize>,
}

impl ScriptedCounters {
    fn steps(&self) -> usize {
        self.steps.load(Ordering::SeqCst)
    }

    fn aborts(&self) -> usize {
        self.aborts.load(Ordering::SeqCst)
    }
}

/// A registry with one participant Driver composed bound to the store's
/// Participant.
fn participant_registry(fenced: &FencedStore) -> (PluginRegistry, ScriptedCounters) {
    let (mut registry, counters) = scripted_registry(
        &FixturePlugin {
            id: fenced.participant.plugin_id,
            name: "participant-recovery",
            owned: vec![PARTICIPANT_TYPE],
            has_driver: true,
        },
        PARTICIPANT_TYPE,
    );
    bind_participants(&mut registry, &[&fenced.participant]);
    (registry, counters)
}

/// The outcome discriminants the store returned, in order.
fn names(outcomes: &[PipelineOutcomeV1]) -> String {
    outcomes
        .iter()
        .map(|outcome| match outcome {
            PipelineOutcomeV1::Committed(_) => "Committed".to_owned(),
            PipelineOutcomeV1::RecoveredDuplicate(_) => "RecoveredDuplicate".to_owned(),
            other => format!("{other:?}"),
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// The receipt the store returned for a committed or duplicate attempt.
fn receipt(outcomes: &[PipelineOutcomeV1]) -> Option<&PipelineCommitReceiptV1> {
    outcomes.iter().find_map(|outcome| match outcome {
        PipelineOutcomeV1::Committed(receipt) | PipelineOutcomeV1::RecoveredDuplicate(receipt) => {
            Some(receipt)
        }
        _ => None,
    })
}

fn error_text(result: Admitted) -> String {
    result.map_or_else(|error| error.to_string(), |_| "admitted".to_owned())
}

/// PCF-REC-004: a committed participant-authorized pass whose
/// acknowledgement was lost stays in doubt and recovers its committed
/// receipt without restaging; an exact retry returns the same receipt as a
/// `RecoveredDuplicate`; and a revocation between the attempt and recovery is
/// caught by the store fence on both observation profiles.
#[must_use]
pub fn participant_commit_recovery() -> Capture {
    let mut capture = Capture::default();
    let stores: [(&str, Box<dyn ScheduledAdmissionStoreV1>); 2] = [
        ("memory", Box::new(MemoryStore::new())),
        ("sqlite", Box::new(SqliteStore::open(":memory:").test_ok())),
    ];
    for (store, backend) in stores {
        let mut fenced = fenced(backend);
        recover_and_retry(&mut capture, store, &mut fenced);
        revoke_before_recovery(&mut capture, store, &mut fenced);
        capture.record(store, "committed", fenced.committed());
    }
    capture
}

/// Lose the acknowledgement of a committed pass, recover it, then retry it.
fn recover_and_retry(capture: &mut Capture, store: &str, fenced: &mut FencedStore) {
    let (mut registry, driver) = participant_registry(fenced);
    stage_authorized(&mut registry, &fenced.participant).test_ok();
    let (lost, attempted) = fenced.admit_participant(&mut registry, 1, Ack::LostAfterCommit);
    let original = receipt(&attempted).cloned();
    capture.record(store, "lost", error_text(lost));
    capture.record(store, "attempt.outcomes", names(&attempted));
    capture.record(store, "committed-before-recovery", fenced.committed());
    capture.record(
        store,
        "restage-while-in-doubt",
        stage_authorized(&mut registry, &fenced.participant)
            .map_or_else(|error| error.to_string(), |staged| staged.to_string()),
    );

    let (recovered, outcomes) = fenced.recover(&mut registry);
    capture.record(store, "recovery.outcomes", names(&outcomes));
    capture.record(
        store,
        "recovery.receipt-equal",
        original.is_some() && recovered.test_ok() == original,
    );
    capture.record(store, "recovery.driver-steps", driver.steps());
    capture.record(store, "recovery.driver-aborts", driver.aborts());
    let (again, _) = fenced.recover(&mut registry);
    capture.record(store, "second-recovery", error_text(again));

    stage_authorized(&mut registry, &fenced.participant).test_ok();
    let (retried, outcomes) = fenced.admit_participant(&mut registry, 1, Ack::Delivered);
    capture.record(store, "retry.outcomes", names(&outcomes));
    capture.record(
        store,
        "retry.receipt-equal",
        original.is_some() && retried.test_ok() == original,
    );
    capture.record(store, "retry.committed", fenced.committed());
}

/// Leave one committed and two uncommitted passes in doubt, revoke the
/// fenced grant, then recover each of them.
fn revoke_before_recovery(capture: &mut Capture, store: &str, fenced: &mut FencedStore) {
    let (mut committed, _) = participant_registry(fenced);
    stage_authorized(&mut committed, &fenced.participant).test_ok();
    let (_, attempted) = fenced.admit_participant(&mut committed, 2, Ack::LostAfterCommit);
    let original = receipt(&attempted).cloned();

    let (mut participant, participant_driver) = participant_registry(fenced);
    stage_authorized(&mut participant, &fenced.participant).test_ok();
    let (lost, _) = fenced.admit_participant(&mut participant, 3, Ack::LostBeforeCommit);
    capture.record(store, "uncommitted.lost", error_text(lost));

    let (mut anchored, anchored_driver) = scripted_registry(
        &FixturePlugin::new("anchored-recovery", &[ANCHORED_TYPE], true),
        ANCHORED_TYPE,
    );
    let timeline = fenced.participant.timeline_id;
    stage(&mut anchored, fenced.store.as_ref(), timeline, None).test_ok();
    let admission = fenced.admission(4);
    let mut port = AckPort {
        store: fenced.store.as_mut(),
        ack: Ack::LostBeforeCommit,
        outcomes: Vec::new(),
    };
    let lost = anchored.admit_scheduled_pass(&mut port, &admission);
    capture.record(store, "anchored.lost", error_text(lost));

    fenced.revoke();
    let (rejected, outcomes) = fenced.recover(&mut participant);
    capture.record(store, "revoked.participant", error_text(rejected));
    capture.record(store, "revoked.participant-outcomes", names(&outcomes));
    capture.record(
        store,
        "revoked.participant-driver",
        format!(
            "steps={},aborts={}",
            participant_driver.steps(),
            participant_driver.aborts()
        ),
    );
    let (rejected, outcomes) = fenced.recover(&mut anchored);
    capture.record(store, "revoked.anchored", error_text(rejected));
    capture.record(store, "revoked.anchored-outcomes", names(&outcomes));
    capture.record(
        store,
        "revoked.anchored-driver",
        format!(
            "steps={},aborts={}",
            anchored_driver.steps(),
            anchored_driver.aborts()
        ),
    );
    let (recovered, outcomes) = fenced.recover(&mut committed);
    capture.record(store, "revoked.committed-outcomes", names(&outcomes));
    capture.record(
        store,
        "revoked.committed-receipt-equal",
        original.is_some() && recovered.test_ok() == original,
    );
}
