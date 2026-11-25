//! The Decision Preview admission and read (ADR-140, Redmine #305).
//!
//! A Decision Preview binds one Preference revision, one `OptionSpec`
//! revision and one Scenario Room revision of the acting entity to the
//! `pigloros.match-score.v1` Recommendation, under one installed EPF1. This
//! module is the Gateway side of the ADR-140 section 6 admission and the
//! section 7 read: the acting Principal and entity of the operation permit,
//! the per-Principal in-flight slot (P35), the installed-profile port (P31),
//! the consent re-check with its ADN1 denial evidence (D6) and the typed
//! outcomes. Each store step runs as one command on the store worker
//! ([`crate::executor::decision_preview`]).
//!
//! The routes, the problem mapping and the JSON rendering belong to the
//! route layer (#305 C3); nothing here names an HTTP type.

use std::{
    collections::HashMap,
    num::NonZeroU64,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use pos_core::{CoreError, EntityId, EventId, GatewayRevisionErrorV1, Seq, TimelineId};
use pos_local_erasure_loader::local_principal::derived_timeline;
use pos_runtime::{
    ErasureExecutionHostV1, PreviewClaimKeyV1, PreviewClaimV1, PreviewFailureCodeV1,
    PreviewRequestV1, RecommendationV1,
};

use crate::{
    executor::decision_preview::{
        admit_inputs, commit_preview, lookup_claim, read_preview, AdmittedPreviewV1,
        ClaimedPreviewV1, FreshPreviewV1, PreviewCommitV1, PreviewLimitsV1, PreviewQuotaV1,
    },
    mode_profile::GatewayModeProfileIdV1,
    Gateway, GatewayError, GatewayOperationPermitV1,
};

/// The derivation context of the `decision-previews` Timeline identity.
const TIMELINE_CONTEXT: &str = "pigloros gateway decision previews timeline v1";
/// The name the `decision-previews` Timeline is opened with; it is never
/// looked up by this name (ADR-140 P9).
pub(crate) const DECISION_PREVIEWS_TIMELINE_NAME: &str = "decision-previews";
/// The most `createDecisionPreview` requests one Principal has in flight.
pub(crate) const MAX_IN_FLIGHT_PER_PRINCIPAL: usize = 4;

/// The identity of the host-owned `decision-previews` Timeline (ADR-140 P9).
pub(crate) fn decision_previews_timeline() -> TimelineId {
    derived_timeline(TIMELINE_CONTEXT)
}

/// Why a Decision Preview operation was not answered with its resource.
#[derive(Debug)]
pub enum DecisionPreviewErrorV1 {
    /// A failure every protected operation shares.
    ///
    /// An authority or consent denial (recorded as ADN1 evidence first), a
    /// permit without a decision, or a store command that never ran.
    Gateway(GatewayError),
    /// The Principal has its four `createDecisionPreview` requests in flight.
    InFlightLimit,
    /// No such preview or input, or one the caller may not use (`404`).
    NotFound,
    /// The `Idempotency-Key` was used for a different request.
    IdempotencyConflict,
    /// The profile is not servable in the bound mode or has no installed EPF1.
    IncompatibleProfile,
    /// The Principal used its per-minute admissions until the window closes.
    QuotaExceeded {
        /// The time left in the current window.
        retry_after: Duration,
    },
    /// The `decision-previews` Timeline holds no room for another preview.
    StoreFull,
    /// The Timeline cannot be opened under an active erasure request (P30).
    ///
    /// A store with an active erasure request opens a root only through the
    /// composed Local erasure authority; without it the refusal is not
    /// retryable.
    TopologyUnavailable,
    /// The store is not bound to an execution mode this Gateway knows.
    ModeUnavailable,
    /// The revision store refused or could not answer.
    Revisions(GatewayRevisionErrorV1),
    /// The store is inconsistent: the closed internal-failure arm (P29).
    Internal,
    /// The store refused or failed the operation.
    Store(CoreError),
}

impl From<GatewayError> for DecisionPreviewErrorV1 {
    fn from(error: GatewayError) -> Self {
        Self::Gateway(error)
    }
}

/// The `202` admission of one Decision Preview (ADR-140 P21).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionPreviewReceiptV1 {
    /// The preview ID: the claim Event's ID, the receipt's `request_id` and
    /// its `operation_id`.
    pub preview_id: EventId,
    /// BLAKE3 of the presented `Idempotency-Key` bytes.
    pub idempotency_key_digest: [u8; 32],
    /// The stored `PRQ1`, whose fields 4 to 6, 9 and 10 the receipt binds.
    pub claim: PreviewClaimV1,
}

/// The `preview.result.v1` Event a preview's `committed` member names (P23).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecisionPreviewResultEventV1 {
    /// The result Event's ID.
    pub event_id: EventId,
    /// Its sequence on the `decision-previews` Timeline.
    pub seq: Seq,
}

/// The GMP1 binding a preview's claim committed under (ADR-140 section 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecisionPreviewModeV1 {
    /// The bound execution-mode profile.
    pub profile: GatewayModeProfileIdV1,
    /// Its GMP1 digest, equal to `PRQ1` field 10.
    pub digest: [u8; 32],
    /// The binding epoch the claim's commit recorded.
    pub binding_epoch: NonZeroU64,
}

/// The lifecycle state of one preview (ADR-140 P17).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecisionPreviewStateV1 {
    /// The claim committed with no result yet.
    Admitted,
    /// The result is `computed` and every bound input is readable.
    Committed {
        /// The result Event.
        result: DecisionPreviewResultEventV1,
        /// The Recommendation, recomputed from the bound revisions.
        recommendation: RecommendationV1,
    },
    /// The result is `failed`.
    Failed {
        /// The typed failure code.
        code: PreviewFailureCodeV1,
    },
    /// The result is `computed`, and a bound input was erased afterwards.
    Degraded {
        /// The result Event.
        result: DecisionPreviewResultEventV1,
    },
}

impl DecisionPreviewStateV1 {
    /// The preview's `generation`: 1 while admitted, else 2 (D12).
    #[must_use]
    pub const fn generation(&self) -> u64 {
        if matches!(self, Self::Admitted) {
            1
        } else {
            2
        }
    }
}

/// One Decision Preview as `getDecisionPreview` reads it (ADR-140 section 7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionPreviewV1 {
    /// The preview ID.
    pub preview_id: EventId,
    /// The stored `PRQ1`: the bound inputs, consent and profiles.
    pub claim: PreviewClaimV1,
    /// The binding the claim's commit evidence records.
    pub mode_profile: DecisionPreviewModeV1,
    /// The `provenance.digest` of P24.
    pub provenance_digest: [u8; 32],
    /// The lifecycle state.
    pub state: DecisionPreviewStateV1,
}

/// The installed-profile port of ADR-140 P31.
///
/// It answers the installed EPF1 of one ADR-058 profile ID: that ID and the
/// raw EPF1 digest. #1364 and #461 own the real implementation over the #446
/// EPF1 lookup; until then the release composition answers `None`, so every
/// fresh request is `409 incompatible-profile`.
pub(crate) trait InstalledProfilesV1: Send + Sync {
    /// The installed EPF1 of `profile_id`, if any.
    fn installed_epf1(&self, profile_id: &str) -> Option<(String, [u8; 32])>;
}

/// The release port: no EPF1 is installed.
struct NoInstalledProfilesV1;

impl InstalledProfilesV1 for NoInstalledProfilesV1 {
    fn installed_epf1(&self, _profile_id: &str) -> Option<(String, [u8; 32])> {
        None
    }
}

/// The in-flight `createDecisionPreview` requests of each Principal.
type InFlightV1 = Arc<Mutex<HashMap<[u8; 16], usize>>>;

/// The Decision Preview state one Gateway holds in memory.
#[derive(Clone)]
pub(crate) struct DecisionPreviewsV1 {
    installed: Arc<dyn InstalledProfilesV1>,
    quota: Arc<Mutex<PreviewQuotaV1>>,
    in_flight: InFlightV1,
}

impl Default for DecisionPreviewsV1 {
    fn default() -> Self {
        Self {
            installed: Arc::new(NoInstalledProfilesV1),
            quota: Arc::default(),
            in_flight: Arc::default(),
        }
    }
}

/// One taken in-flight slot of a Principal, released when it is dropped.
struct InFlightSlotV1 {
    slots: InFlightV1,
    principal_id: [u8; 16],
}

impl InFlightSlotV1 {
    /// Take a slot for `principal_id`, unless its four slots are taken.
    fn take(slots: &InFlightV1, principal_id: [u8; 16]) -> Option<Self> {
        let mut taken = slots.lock().unwrap_or_else(PoisonError::into_inner);
        let held = taken.get(&principal_id).copied().unwrap_or(0);
        (held < MAX_IN_FLIGHT_PER_PRINCIPAL).then(|| {
            taken.insert(principal_id, held + 1);
            Self {
                slots: Arc::clone(slots),
                principal_id,
            }
        })
    }
}

impl Drop for InFlightSlotV1 {
    fn drop(&mut self) {
        let mut taken = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let count = taken.entry(self.principal_id).or_default();
        *count = count.saturating_sub(1);
        taken.retain(|_, count| *count > 0);
    }
}

/// The Principal and acting entity of the decision `permit` carries.
fn acting(
    permit: &GatewayOperationPermitV1,
) -> Result<([u8; 16], EntityId), DecisionPreviewErrorV1> {
    permit
        .decision()
        .map(|decision| {
            (
                *decision.principal().principal_id(),
                decision.actor_entity_id(),
            )
        })
        .ok_or(DecisionPreviewErrorV1::Gateway(
            GatewayError::AuthorizationUnavailable,
        ))
}

impl Gateway {
    /// Admit one `createDecisionPreview` request under its decision's `permit`.
    ///
    /// This is ADR-140 section 6 from step 4 on; the route answers steps 1
    /// to 3. The Principal's in-flight slot is held until the answer. A
    /// claim under the same key is an exact retry when its request digest is
    /// equal: its consent is re-checked, an interrupted attempt is finished,
    /// and the receipt is rebuilt from the stored `PRQ1`. A fresh request
    /// passes the profile gate, the room and binding checks, then the
    /// consent check, and commits in one store command. The permit is held
    /// until the last store command settles.
    ///
    /// # Errors
    /// [`DecisionPreviewErrorV1::InFlightLimit`] when the Principal's slots
    /// are taken; a recorded consent denial (`403`); the store refusals of
    /// ADR-140 section 6 as their [`DecisionPreviewErrorV1`] variants; and
    /// [`GatewayError::AuthorizationUnavailable`] for a permit without a
    /// decision.
    pub async fn create_decision_preview(
        &self,
        permit: GatewayOperationPermitV1,
        idempotency_key: &str,
        request: PreviewRequestV1,
    ) -> Result<DecisionPreviewReceiptV1, DecisionPreviewErrorV1> {
        let (principal_id, actor) = acting(&permit)?;
        let _slot = InFlightSlotV1::take(&self.decision_previews.in_flight, principal_id)
            .ok_or(DecisionPreviewErrorV1::InFlightLimit)?;
        let key = PreviewClaimKeyV1::derive(principal_id, actor, idempotency_key);
        let request_digest = request.digest();
        let found = self
            .preview_command(move |host| lookup_claim(host, &key, request_digest))
            .await?;
        let commit = PreviewCommitV1 {
            key,
            request_digest,
            fresh: None,
        };
        let admitted = match found {
            Some(claimed) => self.retry_preview(permit, commit, claimed).await,
            None => {
                self.admit_preview(permit, commit, (principal_id, actor), request)
                    .await
            }
        }?;
        Ok(DecisionPreviewReceiptV1 {
            preview_id: admitted.preview_id,
            idempotency_key_digest: *blake3::hash(idempotency_key.as_bytes()).as_bytes(),
            claim: admitted.claim,
        })
    }

    /// Read one Decision Preview under its decision's `permit`.
    ///
    /// This is ADR-140 section 7 from step 3 on: the claim must be the
    /// acting Principal's and entity's, its consent is re-checked, and the
    /// state is built, a computed result recomputed.
    ///
    /// # Errors
    /// [`DecisionPreviewErrorV1::NotFound`] for no claim or another caller's;
    /// a recorded consent denial (`403`); the internal-failure arm and the
    /// store failures; and [`GatewayError::AuthorizationUnavailable`] for a
    /// permit without a decision.
    pub async fn read_decision_preview(
        &self,
        permit: GatewayOperationPermitV1,
        preview_id: EventId,
    ) -> Result<DecisionPreviewV1, DecisionPreviewErrorV1> {
        let (principal_id, actor) = acting(&permit)?;
        let read = self
            .preview_command(move |host| read_preview(host, preview_id, principal_id, actor))
            .await?;
        drop(self.preview_consent(permit, read.consent_ref).await?);
        read.view
    }

    /// The exact retry of ADR-140 section 6 step 6.
    async fn retry_preview(
        &self,
        permit: GatewayOperationPermitV1,
        commit: PreviewCommitV1,
        claimed: ClaimedPreviewV1,
    ) -> Result<AdmittedPreviewV1, DecisionPreviewErrorV1> {
        let permit = self
            .preview_consent(permit, claimed.claim.consent_ref)
            .await?;
        let admitted = if claimed.is_finished() {
            Ok(claimed.admitted())
        } else {
            self.commit_preview(commit).await
        };
        drop(permit);
        admitted
    }

    /// Steps 7 to 12 of a fresh request by `actor` for `principal_id`.
    async fn admit_preview(
        &self,
        permit: GatewayOperationPermitV1,
        commit: PreviewCommitV1,
        (principal_id, actor): ([u8; 16], EntityId),
        request: PreviewRequestV1,
    ) -> Result<AdmittedPreviewV1, DecisionPreviewErrorV1> {
        let installed = self
            .decision_previews
            .installed
            .installed_epf1(&request.profile_id);
        let gated = request.clone();
        let (consent_ref, profile_digest) = self
            .preview_command(move |host| admit_inputs(host, actor, &gated, installed))
            .await?;
        let permit = self.preview_consent(permit, consent_ref).await?;
        let fresh = FreshPreviewV1 {
            principal_id,
            actor,
            request,
            profile_digest,
        };
        let admitted = self
            .commit_preview(PreviewCommitV1 {
                fresh: Some(fresh),
                ..commit
            })
            .await;
        drop(permit);
        admitted
    }

    /// The commit command of step 12, or the finish of step 6.2.
    async fn commit_preview(
        &self,
        commit: PreviewCommitV1,
    ) -> Result<AdmittedPreviewV1, DecisionPreviewErrorV1> {
        let limits = PreviewLimitsV1 {
            max_events: self.limits.max_events_per_timeline,
            quota: Arc::clone(&self.decision_previews.quota),
        };
        self.preview_command(move |host| commit_preview(host, commit, &limits, Instant::now()))
            .await
    }

    /// `permit` again when the consent `consent_ref` is held and unrevoked;
    /// otherwise the permit is released and the denial recorded and returned.
    async fn preview_consent(
        &self,
        permit: GatewayOperationPermitV1,
        consent_ref: EntityId,
    ) -> Result<GatewayOperationPermitV1, GatewayError> {
        let denial = self.consent_denial(&permit, consent_ref)?;
        let Some((authorization, pending)) = denial else {
            return Ok(permit);
        };
        drop(permit);
        let recorded = self.recorded_denial(&authorization, pending).await;
        Err(recorded)
    }

    /// Run one Decision Preview store operation on the store worker.
    async fn preview_command<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut ErasureExecutionHostV1) -> Result<T, DecisionPreviewErrorV1>
            + Send
            + 'static,
    ) -> Result<T, DecisionPreviewErrorV1> {
        self.store
            .decision_preview(operation)
            .await
            .unwrap_or_else(|error| Err(GatewayError::from(error).into()))
    }

    /// This Gateway with `installed` as its installed-profile port.
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[must_use]
    pub(crate) fn with_installed_profiles_for_test(
        mut self,
        installed: Arc<dyn InstalledProfilesV1>,
    ) -> Self {
        self.decision_previews.installed = installed;
        self
    }
}

/// The `#[cfg(test)]` installed-profile seam of ADR-140 P31.
///
/// It is never compiled into a release binary and adds no tuple to any
/// table: it answers one installed EPF1, `deterministic-local-v1` with a
/// fixture digest.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod test_seam {
    use super::InstalledProfilesV1;

    /// The one profile the seam reports installed.
    pub(crate) const SEAM_PROFILE_ID: &str = "deterministic-local-v1";
    /// The fixture EPF1 digest of [`SEAM_PROFILE_ID`].
    pub(crate) const SEAM_PROFILE_DIGEST: [u8; 32] = [0x01; 32];

    /// The seam port.
    pub(crate) struct SeamInstalledProfilesV1;

    impl InstalledProfilesV1 for SeamInstalledProfilesV1 {
        fn installed_epf1(&self, profile_id: &str) -> Option<(String, [u8; 32])> {
            (profile_id == SEAM_PROFILE_ID)
                .then(|| (SEAM_PROFILE_ID.to_owned(), SEAM_PROFILE_DIGEST))
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
