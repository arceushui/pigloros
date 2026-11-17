//! Freeze admission, scope partition and Fork scope extension of
//! `LocalErasureAuthorityV1` (ADR-136 §3, §5; amendment of 2026-11-16,
//! decisions 1B, 2A, 3A, 4A and 5A).
//!
//! Every value here is a pure function of the verified bundle, the compiled
//! ELP1 and the host-built view. The authority reads evidence and never
//! writes it: the driver signs the ERFA1-AUTH body the authority prepares,
//! and the authority verifies that signature with the bundle's pinned key.

use std::collections::{BTreeMap, BTreeSet};

use pos_core::{
    local_erasure_export_recipient_v1, local_erasure_fork_admission_v1,
    local_erasure_fork_scope_v1, local_erasure_key_digest_v1, local_erasure_owner_ref_v1,
    local_erasure_replica_id_v1, local_erasure_replica_set_v1, local_erasure_signature_message_v1,
    local_erasure_store_target_v1, local_erasure_timeline_payload_v1, ArtifactDataClassV1,
    ArtifactRegistrationCatalogRowV1, CanonicalBytes, EntityId, ErasureApplicabilityDecisionV1,
    ErasureArtifactClassV1, ErasureAtomicFreezeAdmissionInputV1, ErasureAtomicFreezeAdmissionV1,
    ErasureErrorV1, ErasureFreezeAdmissionEvidenceInputV1, ErasureFreezeAdmissionEvidenceV1,
    ErasureFreezeApplicabilityRowV1, ErasureFreezeAuthorizationEvidenceInputV1,
    ErasureFreezeAuthorizationEvidenceV1, ErasureFreezeFailureInputV1, ErasureFreezeFailureV1,
    ErasureInventoryCategoryV1, ErasureKeyRoleV1, ErasureObligationInputV1,
    ErasureObligationSetInputV1, ErasureObligationSetV1, ErasureObligationV1, ErasureReferenceV1,
    ErasureRequestV1, ErasureRequiredTargetV1, ErasureScopeCommitmentInputV1,
    ErasureScopeCommitmentV1, ErasureScopeExtensionV1, ErasureScopeV1,
    ErasureVerifiedTopologyObservationV1, KeyIdentityV1, KeyRoleV1, LocalErasureBundleV1,
    LocalErasureLineageRuleV1, LocalErasureSignaturePurposeV1, LocalErasureSignatureV1, OwnerIdV1,
    PublicKey, Signature, TimelineId, ERASURE_MAX_INVENTORY_TIMELINES, ERASURE_MAX_TARGETS,
};
use pos_crypto::key_roles::verify_for_role;
use pos_crypto::signing::verifying_key_from_public_key;

use super::authority::LocalErasureAuthorityV1;
use super::{
    LocalErasureClassificationRowV1, LOCAL_ERASURE_CLASSIFICATION_V1,
    LOCAL_ERASURE_POLICY_REFERENCE_V1,
};
use crate::{ErasureAuthorityReadViewV1, ErasureViewListErrorV1};

use ErasureArtifactClassV1::{CalibrationReport, ConformanceReport, Export, TimelineReplay};
use ErasureInventoryCategoryV1::{Artifact, Backup, Key, Replica};

/// The request-local freeze position (ADR-136 §6).
pub(super) const LOCAL_FREEZE_POSITION: u64 = 1;

/// The absent key or artifact component of a target (ADR-136 amendment,
/// target identity). Real ARD1 and key digests are domain hashes and are
/// never zero.
const NO_COMPONENT: ErasureReferenceV1 = ErasureReferenceV1::from_digest([0; 32]);

/// One applicable `(target, category, ack_class)` cell of the closure.
type ClosureCellV1 = (
    ErasureRequiredTargetV1,
    ErasureInventoryCategoryV1,
    &'static str,
);

/// The closure of one request: each target with its set of applicable
/// cells. A cell reached twice, for example through two ARD1 rows of one
/// artifact, is one cell.
pub(super) type ClosureV1 =
    BTreeMap<ErasureRequiredTargetV1, BTreeSet<(ErasureInventoryCategoryV1, &'static str)>>;

/// Why a freeze plan stops short of an admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ShortfallV1 {
    /// A bound overflow or an eligible cell without an ELP1 row: the
    /// freeze commits it as `Rejected(ScopeInvalid)`.
    Refused,
    /// Any other failure: returned, never committed.
    Failed(ErasureErrorV1),
}

impl From<ErasureErrorV1> for ShortfallV1 {
    fn from(error: ErasureErrorV1) -> Self {
        Self::Failed(error)
    }
}

/// A view list over its bound is a refusal; a failed read is a failure.
impl From<ErasureViewListErrorV1> for ShortfallV1 {
    fn from(error: ErasureViewListErrorV1) -> Self {
        match error {
            ErasureViewListErrorV1::OverBound => Self::Refused,
            ErasureViewListErrorV1::Read(error) => Self::Failed(error),
        }
    }
}

impl From<ShortfallV1> for ErasureErrorV1 {
    fn from(shortfall: ShortfallV1) -> Self {
        match shortfall {
            ShortfallV1::Refused => Self::ScopeInvalid,
            ShortfallV1::Failed(error) => error,
        }
    }
}

impl ShortfallV1 {
    /// A refusal resolves to `None`; a failure stays an error.
    pub(super) const fn resolved<T>(self) -> Result<Option<T>, ErasureErrorV1> {
        match self {
            Self::Refused => Ok(None),
            Self::Failed(error) => Err(error),
        }
    }
}

/// Add `cells` to `closure`, refused once it holds more than 4,096 targets
/// (adr060 :513). Each target holds at most one cell per category, so the
/// per-category bound follows from the total.
fn extend_bounded(closure: &mut ClosureV1, cells: Vec<ClosureCellV1>) -> Result<(), ShortfallV1> {
    for (target, category, ack_class) in cells {
        closure
            .entry(target)
            .or_default()
            .insert((category, ack_class));
    }
    (closure.len() <= ERASURE_MAX_TARGETS)
        .then_some(())
        .ok_or(ShortfallV1::Refused)
}

/// Whether every cell of `closure` is a row of `classification` for the
/// request's data class (the D1-a permit set).
pub(super) fn permitted(
    closure: &ClosureV1,
    class: ArtifactDataClassV1,
    classification: &[LocalErasureClassificationRowV1],
) -> bool {
    closure.iter().all(|(target, cells)| {
        cells.iter().all(|&(category, ack_class)| {
            classification.contains(&(target.artifact_class, class, category, ack_class))
        })
    })
}

/// Whether an ERSC1 of `[subject]` and `timelines` affected Timelines fits
/// the combined 65,536-entry reference cap (adr060 :1056).
pub(super) const fn scope_fits(timelines: usize) -> bool {
    timelines < ERASURE_MAX_INVENTORY_TIMELINES
}

/// The ELP1 data class a request scope selects. ERQ1 of a Local request
/// always names one of the two destruction-eligible classes.
fn data_class(scope: ErasureScopeV1) -> ArtifactDataClassV1 {
    if scope == ErasureScopeV1::PrivateSubjectData {
        ArtifactDataClassV1::PrivateSubjectData
    } else {
        ArtifactDataClassV1::ConsentedSharedData
    }
}

/// The Artifact acknowledgement class of an ARD1 artifact class (D5).
const fn artifact_ack_class(class: ErasureArtifactClassV1) -> &'static str {
    match class {
        CalibrationReport | ConformanceReport => "managed-report",
        _ => "artifact-store",
    }
}

/// Everything one freeze admission commits, before its ELS1 exists.
pub(super) struct FreezeDraftV1 {
    targets: Vec<ErasureRequiredTargetV1>,
    scope: ErasureScopeCommitmentInputV1,
    obligations: Vec<ErasureObligationV1>,
    obligation_set: ErasureObligationSetV1,
    admission: ErasureFreezeAdmissionEvidenceInputV1,
    /// `CA(ERFA1-AUTH)`, the digest a purpose-0 ELS1 signs.
    pub(super) body_digest: ErasureReferenceV1,
    /// ELB1 and ELLR1, retained before the freeze commits.
    pub(super) retained: Vec<Vec<u8>>,
}

impl LocalErasureAuthorityV1 {
    /// Every Timeline the actor owns in this snapshot, minus the bundle's
    /// host Timelines, plus every Fork descendant by `fork_point` lineage
    /// (ADR-136 §3, *Affected scope at freeze*), in increasing order.
    ///
    /// # Errors
    /// `ProvenanceMissing` when a topology entry has no Timeline row.
    pub(super) fn affected_timelines(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        actor: EntityId,
    ) -> Result<Vec<TimelineId>, ErasureErrorV1> {
        view.topology()
            .iter()
            .map(|timeline| {
                view.timeline_meta(*timeline)
                    .ok_or(ErasureErrorV1::ProvenanceMissing)
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|rows| {
                let rows = rows
                    .into_iter()
                    .filter(|row| !self.bundle.host_timelines.contains(&row.id))
                    .collect::<Vec<_>>();
                let mut children = BTreeMap::<TimelineId, Vec<TimelineId>>::new();
                for row in &rows {
                    if let Some((parent, _)) = row.fork_point {
                        children.entry(parent).or_default().push(row.id);
                    }
                }
                let mut affected = rows
                    .iter()
                    .filter(|row| row.owner == Some(actor))
                    .map(|row| row.id)
                    .collect::<BTreeSet<_>>();
                let mut pending = affected.iter().copied().collect::<Vec<_>>();
                while let Some(parent) = pending.pop() {
                    let fresh = children
                        .get(&parent)
                        .into_iter()
                        .flatten()
                        .filter(|child| affected.insert(**child))
                        .copied()
                        .collect::<Vec<_>>();
                    pending.extend(fresh);
                }
                affected.into_iter().collect()
            })
    }

    /// The closure of a request of `actor` for `scope` over `affected`, by
    /// the target table of decision 1B: one target per destructible thing,
    /// each carrying the single local replica. Reading stops as soon as the
    /// closure exceeds 4,096 targets.
    ///
    /// # Errors
    /// `Refused` above 4,096 targets or when a view list is over its bound;
    /// otherwise the closed read or encoding error.
    pub(super) fn closure(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        actor: EntityId,
        scope: ErasureScopeV1,
        affected: &[TimelineId],
    ) -> Result<ClosureV1, ShortfallV1> {
        let store = self.bundle.store_identity;
        let private = scope == ErasureScopeV1::PrivateSubjectData;
        let class = data_class(scope);
        let mut closure = ClosureV1::new();
        local_erasure_replica_set_v1(store)
            .and_then(|replica_set| {
                local_erasure_replica_id_v1(store).map(|replica_id| (replica_set, replica_id))
            })
            .and_then(|replicas| {
                local_erasure_store_target_v1(store).map(|digest| (replicas, digest))
            })
            .map_err(ShortfallV1::from)
            .and_then(|((replica_set, replica_id), store_digest)| {
                let target =
                    move |artifact_class, artifact_digest, key_digest| ErasureRequiredTargetV1 {
                        artifact_class,
                        artifact_digest,
                        key_role: ErasureKeyRoleV1::DataEncryption,
                        key_digest,
                        replica_set,
                        replica_id,
                    };
                let store_target = target(TimelineReplay, store_digest, NO_COMPONENT);
                extend_bounded(
                    &mut closure,
                    vec![
                        (store_target, Artifact, "client-cache-signal"),
                        (store_target, Replica, "local-replica"),
                    ],
                )
                .and_then(|()| {
                    affected
                        .iter()
                        .filter(|_| private)
                        .map(|timeline| {
                            local_erasure_timeline_payload_v1(*timeline).map(|digest| {
                                (
                                    target(TimelineReplay, digest, NO_COMPONENT),
                                    Artifact,
                                    "timeline-payload",
                                )
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(ShortfallV1::from)
                        .and_then(|cells| extend_bounded(&mut closure, cells))
                })
                .and_then(|()| {
                    Self::subject_keys(view, actor, private)
                        .map_err(ShortfallV1::from)
                        .and_then(|keys| {
                            keys.iter()
                                .map(|identity| {
                                    local_erasure_key_digest_v1(identity)
                                        .map(|digest| target(TimelineReplay, NO_COMPONENT, digest))
                                })
                                .collect::<Result<Vec<_>, _>>()
                                .map_err(ShortfallV1::from)
                        })
                        .and_then(|targets| {
                            extend_bounded(&mut closure, key_and_backup_cells(&targets))
                        })
                })
                .and_then(|()| {
                    affected.iter().try_for_each(|timeline| {
                        view.artifact_registrations(*timeline)
                            .map_err(ShortfallV1::from)
                            .and_then(|rows| {
                                let rows = rows
                                    .into_iter()
                                    .filter(|row| row.registration().fields().data_class == class)
                                    .collect::<Vec<_>>();
                                registration_cells(&rows, target).map_err(ShortfallV1::from)
                            })
                            .and_then(|cells| extend_bounded(&mut closure, cells))
                    })
                })
                .and_then(|()| {
                    Self::exports(view, private, affected, target)
                        .and_then(|cells| extend_bounded(&mut closure, cells))
                })
            })
            .map(|()| closure)
    }

    /// The role-0 keys of the ADR-091 `subject:<hex>` owner, every epoch,
    /// for a private-subject-data request; none for a consented one.
    fn subject_keys(
        view: &dyn ErasureAuthorityReadViewV1,
        actor: EntityId,
        private: bool,
    ) -> Result<Vec<KeyIdentityV1>, ErasureViewListErrorV1> {
        pos_crypto::subject_key::subject_owner_id(actor)
            .ok()
            .and_then(|owner| OwnerIdV1::new(owner).ok())
            .filter(|_| private)
            .map_or_else(
                || Ok(Vec::new()),
                |owner| {
                    view.key_identities(&owner).map(|identities| {
                        identities
                            .into_iter()
                            .filter(|identity| identity.role == KeyRoleV1::SubjectDataEncryption)
                            .collect()
                    })
                },
            )
    }

    /// One `export-recipient` cell per (publication, grantee) of an affected
    /// Timeline, for a consented-shared-data request.
    fn exports(
        view: &dyn ErasureAuthorityReadViewV1,
        private: bool,
        affected: &[TimelineId],
        target: impl Fn(
            ErasureArtifactClassV1,
            ErasureReferenceV1,
            ErasureReferenceV1,
        ) -> ErasureRequiredTargetV1,
    ) -> Result<Vec<ClosureCellV1>, ShortfallV1> {
        let timelines = if private { &[][..] } else { affected };
        view.recipient_export_publications(timelines)
            .map_err(ShortfallV1::from)
            .and_then(|publications| {
                publications
                    .iter()
                    .map(|publication| {
                        local_erasure_export_recipient_v1(
                            publication.export_id,
                            &publication.grantee_owner,
                        )
                        .map(|digest| {
                            (
                                target(Export, digest, NO_COMPONENT),
                                Artifact,
                                "export-recipient",
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(ShortfallV1::from)
            })
    }

    /// Whether the closure of a prospective request of `actor` for `scope`
    /// fits the 4,096-target bound, on the submission snapshot (ADR-136 Q10).
    ///
    /// # Errors
    /// The closed read or encoding error of the closure.
    pub(super) fn closure_fits(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        actor: EntityId,
        scope: ErasureScopeV1,
    ) -> Result<bool, ErasureErrorV1> {
        self.affected_timelines(view, actor)
            .map_err(ShortfallV1::from)
            .and_then(|affected| self.closure(view, actor, scope, &affected))
            .map(Some)
            .or_else(ShortfallV1::resolved)
            .map(|closure| closure.is_some())
    }

    /// The freeze `request` admits on this view, before its signature: the
    /// closure under the ELP1 permit set, ERSC1, EROS1 and ERFA1.
    ///
    /// # Errors
    /// `Refused` for a bound overflow or an eligible cell without an ELP1
    /// row, which the freeze commits as `Rejected`; otherwise `Failed`:
    /// `PolicyConflict` for a request the installed inventory does not
    /// hold, `Unauthorized` when its ERAZ1 no longer verifies.
    pub(super) fn freeze_draft(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        request: ErasureReferenceV1,
    ) -> Result<FreezeDraftV1, ShortfallV1> {
        view.verified_request(request)
            .map(|state| state.request().clone())
            .ok_or(ErasureErrorV1::PolicyConflict)
            .and_then(|erq1| {
                self.verified_authorization(view, &erq1, false)
                    .map(|(_, authorization)| (erq1, authorization.actor_entity))
            })
            .and_then(|(erq1, actor)| {
                self.affected_timelines(view, actor)
                    .map(|affected| (erq1, actor, affected))
            })
            .map_err(ShortfallV1::from)
            .and_then(|(erq1, actor, affected)| {
                self.closure(view, actor, erq1.scope(), &affected)
                    .and_then(|closure| {
                        permitted(
                            &closure,
                            data_class(erq1.scope()),
                            &LOCAL_ERASURE_CLASSIFICATION_V1,
                        )
                        .then_some(closure)
                        .filter(|_| scope_fits(affected.len()))
                        .ok_or(ShortfallV1::Refused)
                    })
                    .and_then(|closure| {
                        self.draft(&erq1, affected, &closure)
                            .map_err(ShortfallV1::from)
                    })
            })
    }

    /// Build ERSC1, the obligations, EROS1 and ERFA1 of one closure.
    fn draft(
        &self,
        erq1: &ErasureRequestV1,
        affected: Vec<TimelineId>,
        closure: &ClosureV1,
    ) -> Result<FreezeDraftV1, ErasureErrorV1> {
        let request = erq1.reference();
        let targets = closure.keys().copied().collect::<Vec<_>>();
        let lineage = LocalErasureLineageRuleV1 {
            subject: erq1.subject(),
        };
        self.bundle
            .to_canonical_cbor()
            .and_then(|bundle| {
                self.bundle.reference().and_then(|trust| {
                    lineage.to_canonical_cbor().and_then(|lineage_bytes| {
                        lineage
                            .reference()
                            .map(|lineage_rule| (trust, vec![bundle, lineage_bytes], lineage_rule))
                    })
                })
            })
            .and_then(|(trust, retained, lineage_rule)| {
                let scope = ErasureScopeCommitmentInputV1 {
                    request,
                    scope_members: vec![erq1.subject()],
                    scope_timeline_ids: affected,
                    target_closure: pos_core::erasure::target_closure_digest(&targets),
                    lineage_rule: Some(lineage_rule),
                };
                ErasureScopeCommitmentV1::new(scope.clone())
                    .and_then(|commitment| {
                        self.obligations(request, closure)
                            .map(|obligations| (commitment, obligations))
                    })
                    .and_then(|(commitment, obligations)| {
                        ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
                            request,
                            obligations: obligations
                                .iter()
                                .map(ErasureObligationV1::reference)
                                .collect(),
                            policy: LOCAL_ERASURE_POLICY_REFERENCE_V1,
                            trust,
                        })
                        .and_then(|obligation_set| {
                            applicability(&targets, &obligations)
                                .map(
                                    |applicability_matrix| ErasureFreezeAdmissionEvidenceInputV1 {
                                        request,
                                        scope_commitment: commitment.reference(),
                                        obligation_set: obligation_set.reference(),
                                        applicability_matrix,
                                        freeze_position: LOCAL_FREEZE_POSITION,
                                        policy: LOCAL_ERASURE_POLICY_REFERENCE_V1,
                                        trust,
                                        authorization_provenance: NO_COMPONENT,
                                    },
                                )
                                .map(|admission| (obligation_set, admission))
                        })
                        .and_then(|(obligation_set, admission)| {
                            ErasureFreezeAdmissionEvidenceV1::new(admission.clone())
                                .and_then(|provisional| provisional.authorization_body_digest())
                                .map(|body_digest| FreezeDraftV1 {
                                    targets,
                                    scope,
                                    obligations,
                                    obligation_set,
                                    admission,
                                    body_digest,
                                    retained,
                                })
                        })
                    })
            })
    }

    /// One obligation per applicable cell, owned by `ELOWN1` of the store,
    /// category and class, in increasing obligation-address order.
    fn obligations(
        &self,
        request: ErasureReferenceV1,
        closure: &ClosureV1,
    ) -> Result<Vec<ErasureObligationV1>, ErasureErrorV1> {
        closure
            .iter()
            .flat_map(|(target, cells)| cells.iter().map(move |cell| (*target, *cell)))
            .map(|(target, (category, ack_class))| {
                local_erasure_owner_ref_v1(
                    self.bundle.store_identity,
                    u64::from(category),
                    ack_class,
                )
                .and_then(|owner| {
                    ErasureObligationV1::new(ErasureObligationInputV1 {
                        category,
                        target,
                        owner,
                        command_identity: pos_core::destruction_command_reference(request, target),
                    })
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|mut obligations| {
                obligations.sort_unstable_by_key(ErasureObligationV1::reference);
                obligations
            })
    }

    /// Complete `draft` with the retained purpose-0 ELS1 named by
    /// `signature`, verified against the bundle's signer key.
    ///
    /// # Errors
    /// `Unauthorized` unless the ELS1 signs exactly the draft's body.
    pub(super) fn signed_admission(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        draft: FreezeDraftV1,
        signature: ErasureReferenceV1,
    ) -> Result<ErasureAtomicFreezeAdmissionV1, ErasureErrorV1> {
        view.retained_object(signature)
            .filter(|evidence| {
                verified_signature(
                    &self.bundle,
                    LocalErasureSignaturePurposeV1::FreezeAuthorization,
                    draft.body_digest,
                    evidence,
                )
            })
            .ok_or(ErasureErrorV1::Unauthorized)
            .and_then(|evidence| {
                ErasureFreezeAuthorizationEvidenceV1::new(
                    ErasureFreezeAuthorizationEvidenceInputV1 {
                        admission_body_digest: draft.body_digest,
                        policy: draft.admission.policy,
                        trust: draft.admission.trust,
                        evidence,
                    },
                )
            })
            .and_then(|authorization| {
                ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
                    authorization_provenance: authorization.reference(),
                    ..draft.admission
                })
                .and_then(|admission| {
                    ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
                        targets: draft.targets,
                        scope: draft.scope,
                        obligations: draft.obligations,
                        obligation_set: draft.obligation_set,
                        freeze_position: LOCAL_FREEZE_POSITION,
                        freeze_admission_evidence: admission,
                        freeze_authorization_evidence: authorization,
                    })
                })
            })
    }

    /// The committed `Rejected(ScopeInvalid)` of an over-bound or
    /// unclassified closure, under the request's own ERAZ1.
    ///
    /// # Errors
    /// `PolicyConflict` for a request the installed inventory does not hold.
    pub(super) fn freeze_refusal(
        view: &dyn ErasureAuthorityReadViewV1,
        request: ErasureReferenceV1,
    ) -> Result<ErasureFreezeFailureV1, ErasureErrorV1> {
        view.verified_request(request)
            .map(|state| state.request().authorization())
            .ok_or(ErasureErrorV1::PolicyConflict)
            .and_then(|authorization| {
                ErasureFreezeFailureV1::new(ErasureFreezeFailureInputV1 {
                    request,
                    error: ErasureErrorV1::ScopeInvalid,
                    authorization_provenance: authorization,
                    evidence: authorization,
                })
            })
    }

    /// The bundle a committed freeze or attempt pins by `CA(ELB1)`: the
    /// verified bundle, or after a rotation the retained ELB1 bytes.
    pub(super) fn pinned_bundle(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        trust: ErasureReferenceV1,
    ) -> Option<LocalErasureBundleV1> {
        (self.bundle.reference().ok() == Some(trust))
            .then(|| self.bundle.clone())
            .or_else(|| {
                view.retained_object(trust)
                    .and_then(|bytes| LocalErasureBundleV1::from_canonical_cbor(&bytes).ok())
                    .filter(|bundle| bundle.reference().ok() == Some(trust))
            })
    }

    /// Verify committed freeze evidence: ERFAA1 names the ERFA1 body, both
    /// pin the compiled ELP1 and one trust revision, and its evidence is a
    /// purpose-0 ELS1 over that body by the pinned bundle's signer.
    ///
    /// # Errors
    /// `Unauthorized` for any mismatch.
    pub(super) fn verified_freeze_evidence(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        admission: &ErasureFreezeAdmissionEvidenceV1,
        authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        authorization
            .verify_admission_body_binding(admission)
            .and_then(|()| {
                (admission.policy() == LOCAL_ERASURE_POLICY_REFERENCE_V1
                    && authorization.policy() == admission.policy()
                    && authorization.trust() == admission.trust())
                .then(|| self.pinned_bundle(view, admission.trust()))
                .flatten()
                .filter(|bundle| {
                    verified_signature(
                        bundle,
                        LocalErasureSignaturePurposeV1::FreezeAuthorization,
                        authorization.admission_body_digest(),
                        authorization.evidence(),
                    )
                })
                .map(drop)
                .ok_or(ErasureErrorV1::Unauthorized)
            })
    }
}

/// The Key and Backup cells of each key target: a key's `key-registry` and
/// `local-backup-inventory` obligations share its target (decision 1B).
fn key_and_backup_cells(targets: &[ErasureRequiredTargetV1]) -> Vec<ClosureCellV1> {
    targets
        .iter()
        .flat_map(|target| {
            [
                (*target, Key, "key-registry"),
                (*target, Backup, "local-backup-inventory"),
            ]
        })
        .collect()
}

/// The cells of ARD1 rows: each row's Artifact owner, and for each role-7
/// key it depends on a key target carrying the row's class and digest
/// (D2-a), with its Key and Backup cells.
fn registration_cells(
    rows: &[ArtifactRegistrationCatalogRowV1],
    target: impl Fn(
        ErasureArtifactClassV1,
        ErasureReferenceV1,
        ErasureReferenceV1,
    ) -> ErasureRequiredTargetV1,
) -> Result<Vec<ClosureCellV1>, ErasureErrorV1> {
    rows.iter()
        .map(|row| {
            let class = row.artifact_class();
            let digest = ErasureReferenceV1::from_digest(*row.artifact_digest().as_bytes());
            row.registration()
                .fields()
                .key_dependencies
                .iter()
                .filter(|dependency| {
                    dependency.identity.role == KeyRoleV1::CommunityArtifactEncryption
                })
                .map(|dependency| {
                    local_erasure_key_digest_v1(&dependency.identity)
                        .map(|key| target(class, digest, key))
                })
                .collect::<Result<Vec<_>, _>>()
                .map(|keys| {
                    let mut cells = vec![(
                        target(class, digest, NO_COMPONENT),
                        Artifact,
                        artifact_ack_class(class),
                    )];
                    cells.extend(key_and_backup_cells(&keys));
                    cells
                })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|cells| cells.into_iter().flatten().collect())
}

/// The complete category-major applicability matrix: a cell is Applicable
/// with its obligation's owner exactly when the closure holds it.
fn applicability(
    targets: &[ErasureRequiredTargetV1],
    obligations: &[ErasureObligationV1],
) -> Result<Vec<ErasureFreezeApplicabilityRowV1>, ErasureErrorV1> {
    let owners = obligations
        .iter()
        .map(|obligation| {
            (
                (obligation.category(), obligation.target()),
                obligation.owner(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    ErasureInventoryCategoryV1::CANONICAL
        .iter()
        .flat_map(|category| {
            targets
                .iter()
                .zip(0_u64..)
                .map(move |(target, index)| (*category, *target, index))
        })
        .map(|(category, target, index)| {
            let owner = owners.get(&(category, target)).copied();
            ErasureFreezeApplicabilityRowV1::new(
                category,
                index,
                if owner.is_some() {
                    ErasureApplicabilityDecisionV1::Applicable
                } else {
                    ErasureApplicabilityDecisionV1::Inapplicable
                },
                owner,
            )
        })
        .collect()
}

/// Whether `evidence` is an ELS1 of `purpose` over `digest` by `bundle`'s
/// signer, verified with the bundle's pinned public key over the
/// role-framed `["ELS1-SIG", 1, purpose, digest]` message.
pub(super) fn verified_signature(
    bundle: &LocalErasureBundleV1,
    purpose: LocalErasureSignaturePurposeV1,
    digest: ErasureReferenceV1,
    evidence: &[u8],
) -> bool {
    LocalErasureSignatureV1::from_canonical_cbor(evidence)
        .ok()
        // The message is built from the expected purpose and digest, and the
        // key from the bundle's signer, so a record whose own labels name
        // another purpose, digest or signer would still verify: this filter
        // is what refuses it, before any signature work.
        .filter(|signature| {
            signature.purpose == purpose
                && signature.signed_digest == digest
                && signature.signer_identity == bundle.signer_identity
        })
        .zip(
            String::from_utf8(bundle.signer_identity.owner_id.clone())
                .ok()
                .and_then(|owner| OwnerIdV1::new(owner).ok()),
        )
        .zip(local_erasure_signature_message_v1(purpose, digest).ok())
        .zip(verifying_key_from_public_key(&PublicKey::from_bytes(bundle.signer_public_key)).ok())
        .is_some_and(|(((signature, owner), message), key)| {
            verify_for_role(
                &key,
                KeyIdentityV1::from_parts(
                    owner,
                    KeyRoleV1::TimelineIntegritySigning,
                    bundle.signer_identity.epoch,
                ),
                &CanonicalBytes::from_vec(message),
                &Signature::from_bytes(signature.signature),
            )
            .is_ok()
        })
}

/// The bindings of every Timeline the request's committed scope names: each
/// ERSC1 Timeline to its subject member, each ERSE1 child to its Fork
/// scope. Partitioning uses only ERSC1 and ERSE1, never the current owner
/// (ADR-136 §3, *After freeze*).
pub(super) fn observation(
    view: &dyn ErasureAuthorityReadViewV1,
    request: ErasureReferenceV1,
    manifest_digest: ErasureReferenceV1,
    candidate: Option<TimelineId>,
) -> Result<ErasureVerifiedTopologyObservationV1, ErasureErrorV1> {
    view.recorded_scope(request).map(|recorded| {
        let bindings = recorded
            .map(|(scope, extensions)| {
                scope
                    .scope_members()
                    .first()
                    .into_iter()
                    .flat_map(|member| {
                        scope
                            .scope_timeline_ids()
                            .iter()
                            .map(move |timeline| (*timeline, *member))
                    })
                    .chain(
                        extensions
                            .iter()
                            .map(|extension| (extension.child_timeline(), extension.fork())),
                    )
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        let unaffected = view
            .topology()
            .iter()
            .copied()
            .chain(candidate)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|timeline| !bindings.contains_key(timeline))
            .collect();
        ErasureVerifiedTopologyObservationV1::new(
            manifest_digest,
            bindings.into_iter().collect(),
            unaffected,
        )
    })
}

/// Whether one ERSE1 is the Local extension of its child: its Fork scope is
/// `ELFS1(child)` and its admission provenance `ELFX1` over its request,
/// `parent`, child and lineage rule (decision 4A).
///
/// # Errors
/// `ProvenanceMissing` for any mismatch or an unknown parent.
pub(super) fn extension_admitted(
    extension: &ErasureScopeExtensionV1,
    parent: Option<TimelineId>,
) -> Result<(), ErasureErrorV1> {
    parent
        .and_then(|parent| {
            local_erasure_fork_admission_v1(
                extension.request(),
                parent,
                extension.child_timeline(),
                extension.lineage_rule(),
            )
            .ok()
        })
        .zip(local_erasure_fork_scope_v1(extension.child_timeline()).ok())
        .filter(|&(provenance, fork)| {
            provenance == extension.admission_provenance() && fork == extension.fork()
        })
        .map(drop)
        .ok_or(ErasureErrorV1::ProvenanceMissing)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_core::{
        ArtifactKeyDependencyV1, ArtifactOptionalityV1, ArtifactRegistrationFieldsV1,
        ArtifactRegistrationV1, ArtifactTransitionRuleV1, Hash,
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn target(
        artifact_class: ErasureArtifactClassV1,
        artifact_digest: ErasureReferenceV1,
        key_digest: ErasureReferenceV1,
    ) -> ErasureRequiredTargetV1 {
        ErasureRequiredTargetV1 {
            artifact_class,
            artifact_digest,
            key_role: ErasureKeyRoleV1::DataEncryption,
            key_digest,
            replica_set: ErasureReferenceV1::from_digest([0x01; 32]),
            replica_id: ErasureReferenceV1::from_digest([0x02; 32]),
        }
    }

    fn dependency(owner: &'static str, role: KeyRoleV1) -> ArtifactKeyDependencyV1 {
        ArtifactKeyDependencyV1 {
            identity: KeyIdentityV1::new(owner, role, 1),
            material_digest: Hash::from_bytes([0x03; 32]),
            private_material_required: true,
        }
    }

    /// A catalog row of `class` with `dependencies`, sorted by identity.
    fn row(
        class: ErasureArtifactClassV1,
        dependencies: Vec<ArtifactKeyDependencyV1>,
    ) -> TestResult<ArtifactRegistrationCatalogRowV1> {
        owned_row("community-owner", class, dependencies)
    }

    /// As [`row`], registered by `owner`: the same bytes under another owner
    /// are another registration of the same artifact.
    fn owned_row(
        owner: &'static str,
        class: ErasureArtifactClassV1,
        dependencies: Vec<ArtifactKeyDependencyV1>,
    ) -> TestResult<ArtifactRegistrationCatalogRowV1> {
        let owner = OwnerIdV1::from_static(owner);
        let bytes = format!("{class:?}").into_bytes();
        let digest = ArtifactRegistrationV1::artifact_digest(class, &bytes);
        let registration = ArtifactRegistrationV1::new(ArtifactRegistrationFieldsV1 {
            artifact_class: class,
            artifact_digest: digest,
            owner_reference: ArtifactRegistrationV1::owner_reference(&owner),
            data_class: ArtifactDataClassV1::PrivateSubjectData,
            optionality: ArtifactOptionalityV1::Required,
            transition_rule: ArtifactTransitionRuleV1::PreserveExact,
            required_key_roles: dependencies
                .iter()
                .map(|dependency| dependency.identity.role)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            key_dependencies: dependencies,
            child_artifacts: Vec::new(),
        })
        .map_err(|error| format!("{error:?}"))?;
        Ok(ArtifactRegistrationCatalogRowV1::from_persisted(
            owner,
            class,
            digest,
            registration.address(),
            bytes,
            registration.canonical_cbor(),
        )
        .map_err(|error| format!("{error:?}"))?)
    }

    #[test]
    fn an_ard1_row_is_an_owner_cell_and_one_key_target_per_role_7_dependency() -> TestResult {
        let community = dependency("community:x", KeyRoleV1::CommunityArtifactEncryption);
        // A role-0 dependency is reached through the subject's own keys,
        // never through ARD1 (ADR-136 §3, key mapping).
        let subject = dependency("subject:y", KeyRoleV1::SubjectDataEncryption);
        let report = row(CalibrationReport, vec![community, subject])?;
        let replay = row(TimelineReplay, Vec::new())?;
        let as_reference = |row: &ArtifactRegistrationCatalogRowV1| {
            ErasureReferenceV1::from_digest(*row.artifact_digest().as_bytes())
        };
        let key = local_erasure_key_digest_v1(&community.identity)?;
        assert_eq!(
            registration_cells(&[report.clone(), replay.clone()], target)?,
            vec![
                (
                    target(CalibrationReport, as_reference(&report), NO_COMPONENT),
                    Artifact,
                    "managed-report"
                ),
                (
                    target(CalibrationReport, as_reference(&report), key),
                    Key,
                    "key-registry"
                ),
                (
                    target(CalibrationReport, as_reference(&report), key),
                    Backup,
                    "local-backup-inventory"
                ),
                (
                    target(TimelineReplay, as_reference(&replay), NO_COMPONENT),
                    Artifact,
                    "artifact-store"
                ),
            ]
        );
        // D5: both report classes are managed reports.
        assert_eq!(artifact_ack_class(ConformanceReport), "managed-report");
        assert_eq!(artifact_ack_class(Export), "artifact-store");
        Ok(())
    }

    fn key_target(seed: u8) -> ErasureRequiredTargetV1 {
        target(
            TimelineReplay,
            NO_COMPONENT,
            ErasureReferenceV1::from_digest([seed; 32]),
        )
    }

    /// `count` distinct key targets with their Key and Backup cells.
    fn key_cells(count: usize) -> Vec<ClosureCellV1> {
        let targets = (0..count)
            .map(|index| {
                let mut digest = [0xaa; 32];
                digest[..8]
                    .copy_from_slice(&u64::try_from(index).unwrap_or_default().to_be_bytes());
                target(
                    TimelineReplay,
                    NO_COMPONENT,
                    ErasureReferenceV1::from_digest(digest),
                )
            })
            .collect::<Vec<_>>();
        key_and_backup_cells(&targets)
    }

    #[test]
    fn the_closure_holds_exactly_4096_targets_and_one_cell_per_reach() {
        let store = target(
            TimelineReplay,
            ErasureReferenceV1::from_digest([0x04; 32]),
            NO_COMPONENT,
        );
        let store_cells = vec![
            (store, Artifact, "client-cache-signal"),
            (store, Replica, "local-replica"),
        ];
        // 4,095 key targets and the store target: 4,095 Key and 4,095
        // Backup obligations, 4,096 targets.
        let mut closure = ClosureV1::new();
        assert_eq!(extend_bounded(&mut closure, store_cells.clone()), Ok(()));
        assert_eq!(extend_bounded(&mut closure, key_cells(4_095)), Ok(()));
        assert_eq!(closure.len(), 4_096);
        let mut over = ClosureV1::new();
        assert_eq!(extend_bounded(&mut over, store_cells), Ok(()));
        assert_eq!(
            extend_bounded(&mut over, key_cells(4_096)),
            Err(ShortfallV1::Refused)
        );
        // A cell reached twice is one cell.
        let mut twice = ClosureV1::new();
        let cells = key_and_backup_cells(&[key_target(0x05)]);
        assert_eq!(extend_bounded(&mut twice, cells.clone()), Ok(()));
        assert_eq!(extend_bounded(&mut twice, cells), Ok(()));
        assert_eq!(twice.get(&key_target(0x05)).map(BTreeSet::len), Some(2));
    }

    #[test]
    fn an_unclassified_cell_and_an_over_cap_scope_are_refused() {
        let mut closure = ClosureV1::new();
        assert_eq!(
            extend_bounded(&mut closure, key_and_backup_cells(&[key_target(0x06)])),
            Ok(())
        );
        let private = ArtifactDataClassV1::PrivateSubjectData;
        assert!(permitted(
            &closure,
            private,
            &LOCAL_ERASURE_CLASSIFICATION_V1
        ));
        // A table without the Backup row refuses the Backup cell.
        let pruned = LOCAL_ERASURE_CLASSIFICATION_V1
            .iter()
            .copied()
            .filter(|row| *row != (TimelineReplay, private, Backup, "local-backup-inventory"))
            .collect::<Vec<_>>();
        assert!(!permitted(&closure, private, &pruned));
        // The other data class has its own rows.
        assert!(permitted(
            &closure,
            ArtifactDataClassV1::ConsentedSharedData,
            &LOCAL_ERASURE_CLASSIFICATION_V1
        ));
        assert!(!permitted(
            &closure,
            ArtifactDataClassV1::PublicRecord,
            &LOCAL_ERASURE_CLASSIFICATION_V1
        ));
        // ERSC1 holds the subject and at most 65,535 Timelines.
        assert!(scope_fits(65_535));
        assert!(!scope_fits(65_536));
    }

    #[test]
    fn only_a_refusal_is_committed() {
        assert_eq!(
            ShortfallV1::from(ErasureViewListErrorV1::OverBound),
            ShortfallV1::Refused
        );
        // A store's own ScopeInvalid is a read failure, never a refusal.
        assert_eq!(
            ShortfallV1::from(ErasureViewListErrorV1::Read(ErasureErrorV1::ScopeInvalid)),
            ShortfallV1::Failed(ErasureErrorV1::ScopeInvalid)
        );
        assert_eq!(ShortfallV1::Refused.resolved::<()>(), Ok(None));
        assert_eq!(
            ShortfallV1::Failed(ErasureErrorV1::ScopeInvalid).resolved::<()>(),
            Err(ErasureErrorV1::ScopeInvalid)
        );
        assert_eq!(
            ErasureErrorV1::from(ShortfallV1::Refused),
            ErasureErrorV1::ScopeInvalid
        );
        assert_eq!(
            ErasureErrorV1::from(ShortfallV1::Failed(ErasureErrorV1::Unauthorized)),
            ErasureErrorV1::Unauthorized
        );
    }

    #[test]
    fn two_registrations_of_one_artifact_are_one_cell() -> TestResult {
        let first = owned_row("owner-a", TimelineReplay, Vec::new())?;
        let second = owned_row("owner-b", TimelineReplay, Vec::new())?;
        assert_ne!(first.registration_address(), second.registration_address());
        assert_eq!(first.artifact_digest(), second.artifact_digest());
        let mut closure = ClosureV1::new();
        assert_eq!(
            extend_bounded(&mut closure, registration_cells(&[first, second], target)?),
            Ok(())
        );
        assert_eq!(closure.len(), 1);
        assert_eq!(closure.values().map(BTreeSet::len).sum::<usize>(), 1);
        Ok(())
    }
}
