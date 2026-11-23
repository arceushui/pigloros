//! The `getErasure` projection of one Local erasure request (ADR-136 §7;
//! ticket #1449).
//!
//! The projection reads only verified state: the request's ERS1 head and
//! history through the host-owned coordinator, its recorded progress
//! through the complete core recovery, and the ELADM1 its submission
//! retained, and the store's redaction generation (#1407). It never
//! discloses a Timeline, Fork, selector, target, owner or bundle content;
//! the acknowledgement classes are counts only.

use std::collections::BTreeMap;

use pos_core::{
    local_erasure_request_v1, local_erasure_subject_v1, EntityId, ErasureAcknowledgementOutcomeV1,
    ErasureHostErrorV1, ErasureRecordedProgressV1, ErasureReferenceV1, ErasureScopeV1,
    ErasureStateV1, LocalErasureAdmissionV1, LocalErasureOwnerRowV1, PrincipalRefV1,
};

use super::{
    local_principal_reference, map_erasure_error, ErasureCommandSenderV1, ErasureReadSenderV1,
};

/// The `generation` stride of one ERS1 state: 2^16, above the 16,384
/// acknowledgements of one attempt (ADR-136 §7). Every attempt closes with
/// a new ERS1 state, so closing one always advances the generation.
const STATE_STRIDE: u64 = 1 << 16;

/// The acknowledgement counts of one acknowledgement class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalErasureClassCountV1 {
    /// The ADR-136 acknowledgement class.
    pub class: String,
    /// The class's frozen obligations.
    pub required: u64,
    /// The class's positive acknowledgements in the effective inventory.
    pub positive: u64,
}

/// The projection `getErasure` answers for one Local erasure request
/// (ADR-136 §7).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalErasureProjectionV1 {
    /// The request's `erasure_id`.
    pub erasure_id: ulid::Ulid,
    /// The verified ERS1 head: its lifecycle, state digest and replay claim.
    pub state: ErasureStateV1,
    /// The scope class the ERQ1 names.
    pub scope: ErasureScopeV1,
    /// The monotonic generation: the head's ERS1 ordinal times 2^16 plus
    /// the acknowledgements committed in the active attempt.
    pub generation: u64,
    /// The ELADM1 its submission retained.
    pub admission: LocalErasureAdmissionV1,
    /// The frozen obligations, zero before the access freeze.
    pub required: u64,
    /// The positive acknowledgements in the effective inventory.
    pub positive: u64,
    /// The same counts per acknowledgement class, in class order.
    pub classes: Vec<LocalErasureClassCountV1>,
    /// The store's redaction generation (ADR-136 follow-up F2, #1407): how
    /// many ELCG1 cache generations the store has committed, across every
    /// request. It is store-wide, never decreases, and is 0 before the
    /// first commit.
    pub redaction_generation: u64,
}

/// The counts of `progress` per acknowledgement class: each obligation and
/// each positive acknowledgement counts for the class its owner row names.
fn class_counts(
    progress: &ErasureRecordedProgressV1,
    owners: &[LocalErasureOwnerRowV1],
) -> Vec<LocalErasureClassCountV1> {
    let class_of = |owner: ErasureReferenceV1| {
        owners
            .iter()
            .find(|row| row.owner_ref == owner)
            .map(|row| row.ack_class.as_str())
    };
    let mut classes = BTreeMap::<&str, (u64, u64)>::new();
    for class in progress
        .obligations
        .iter()
        .filter_map(|obligation| class_of(obligation.owner()))
    {
        classes.entry(class).or_default().0 += 1;
    }
    for class in positives(progress).filter_map(class_of) {
        classes.entry(class).or_default().1 += 1;
    }
    classes
        .into_iter()
        .map(|(class, (required, positive))| LocalErasureClassCountV1 {
            class: class.to_owned(),
            required,
            positive,
        })
        .collect()
}

/// The owners of the positive acknowledgements of `progress`'s effective
/// inventory.
fn positives(
    progress: &ErasureRecordedProgressV1,
) -> impl Iterator<Item = ErasureReferenceV1> + '_ {
    progress
        .effective
        .iter()
        .filter(|acknowledgement| {
            acknowledgement.outcome() == ErasureAcknowledgementOutcomeV1::Acknowledged
        })
        .map(pos_core::ErasureAcknowledgementProvenanceV1::owner)
}

/// The generation of a head at ERS1 `ordinal` with `progress`.
fn generation(ordinal: u64, progress: &ErasureRecordedProgressV1) -> u64 {
    let active = progress.active.as_ref().map_or(0, |attempt| {
        progress
            .effective
            .iter()
            .filter(|acknowledgement| acknowledgement.attempt() == attempt.reference())
            .count()
    });
    ordinal * STATE_STRIDE + u64::try_from(active).unwrap_or(u64::MAX)
}

impl ErasureCommandSenderV1<'_> {
    /// The `getErasure` projection of request `erasure_id` for the subject
    /// of `principal` acting as `actor` (ADR-136 §7).
    ///
    /// `Ok(None)` answers a host without a Local composition (owner
    /// decision D9 of 2026-11-18 on #1413), an `erasure_id` the host does
    /// not hold, and a request of another subject alike, so the answer
    /// never tells them apart.
    ///
    /// # Errors
    /// A payload-free stale-generation, recovery or store error; an
    /// installed request without its ELADM1 is
    /// [`ErasureHostErrorV1::RecoveryUnavailable`].
    pub fn local_erasure_projection(
        &mut self,
        principal: &PrincipalRefV1,
        actor: EntityId,
        erasure_id: ulid::Ulid,
    ) -> Result<Option<LocalErasureProjectionV1>, ErasureHostErrorV1> {
        let Some(owners) = self
            .host
            .local_submission
            .as_ref()
            .map(|binding| binding.owners.clone())
        else {
            return Ok(None);
        };
        let (subject, request) = local_principal_reference(principal)
            .and_then(|principal_ref| local_erasure_subject_v1(principal_ref, actor))
            .and_then(|subject| {
                local_erasure_request_v1(erasure_id).map(|request| (subject, request))
            })
            .map_err(map_erasure_error)?;
        let mut reads = ErasureReadSenderV1 {
            host: &mut *self.host,
            generation: self.generation,
        };
        let Some(verified) = reads
            .erasure_state(request)?
            .filter(|verified| verified.request().subject() == subject)
        else {
            return Ok(None);
        };
        // The history holds the head and each predecessor, so the head's
        // ordinal is one less than its length.
        let ordinal = reads.erasure_state_history(request)?.map_or(0, |history| {
            u64::try_from(history.len().saturating_sub(1)).unwrap_or(u64::MAX)
        });
        let progress = self.recorded_local_progress(request)?.unwrap_or_default();
        let admission = self
            .local_admission(request)?
            .ok_or(ErasureHostErrorV1::RecoveryUnavailable)?;
        let redaction_generation = self
            .host
            .store
            .host_store()
            .redaction_generation()
            .map_err(map_erasure_error)?;
        Ok(Some(LocalErasureProjectionV1 {
            erasure_id,
            state: verified.state().clone(),
            scope: verified.request().scope(),
            generation: generation(ordinal, &progress),
            admission,
            required: u64::try_from(progress.obligations.len()).unwrap_or(u64::MAX),
            positive: u64::try_from(positives(&progress).count()).unwrap_or(u64::MAX),
            classes: class_counts(&progress, &owners),
            redaction_generation,
        }))
    }
}
