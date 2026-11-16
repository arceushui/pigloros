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
    PublicKey, Signature, TimelineId, ERASURE_MAX_TARGETS,
};
use pos_crypto::key_roles::verify_for_role;
use pos_crypto::signing::verifying_key_from_public_key;

use super::authority::LocalErasureAuthorityV1;
use super::{LOCAL_ERASURE_CLASSIFICATION_V1, LOCAL_ERASURE_POLICY_REFERENCE_V1};
use crate::ErasureAuthorityReadViewV1;

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

/// The closure of one request: each target with its applicable categories.
type ClosureV1 = BTreeMap<ErasureRequiredTargetV1, Vec<(ErasureInventoryCategoryV1, &'static str)>>;

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

/// Map a closure bound overflow to `T::default()`; any other error stays an
/// error. A bound overflow is every `ScopeInvalid` of the closure: the
/// target cap, a view list over its bound, and the ERSC1 cap.
pub(super) fn overflow<T: Default>(error: ErasureErrorV1) -> Result<T, ErasureErrorV1> {
    (error == ErasureErrorV1::ScopeInvalid)
        .then(T::default)
        .ok_or(error)
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

impl LocalErasureAuthorityV1 {
    /// Every Timeline the actor owns in this snapshot, minus the bundle's
    /// host Timelines, plus every Fork descendant by `fork_point` lineage
    /// (ADR-136 §3, *Affected scope at freeze*), in increasing order.
    pub(super) fn affected_timelines(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        actor: EntityId,
    ) -> Vec<TimelineId> {
        let rows = view
            .topology()
            .iter()
            .filter_map(|timeline| view.timeline_meta(*timeline))
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
    }

    /// The closure of a request of `actor` for `scope` over `affected`, by
    /// the target table of decision 1B: one target per destructible thing,
    /// each carrying the single local replica.
    ///
    /// # Errors
    /// `ScopeInvalid` above 4,096 targets or when a view list is over its
    /// bound, or the closed read or encoding error.
    pub(super) fn closure(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        actor: EntityId,
        scope: ErasureScopeV1,
        affected: &[TimelineId],
    ) -> Result<ClosureV1, ErasureErrorV1> {
        let store = self.bundle.store_identity;
        let private = scope == ErasureScopeV1::PrivateSubjectData;
        local_erasure_replica_set_v1(store)
            .and_then(|replica_set| {
                local_erasure_replica_id_v1(store).map(|replica_id| {
                    move |artifact_class, artifact_digest, key_digest| ErasureRequiredTargetV1 {
                        artifact_class,
                        artifact_digest,
                        key_role: ErasureKeyRoleV1::DataEncryption,
                        key_digest,
                        replica_set,
                        replica_id,
                    }
                })
            })
            .and_then(|target| {
                let store_cells = local_erasure_store_target_v1(store).map(|digest| {
                    let store_target = target(TimelineReplay, digest, NO_COMPONENT);
                    vec![
                        (store_target, Artifact, "client-cache-signal"),
                        (store_target, Replica, "local-replica"),
                    ]
                });
                let payload_cells = affected
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
                    .collect::<Result<Vec<_>, _>>();
                let key_cells = Self::subject_keys(view, actor, private).and_then(|keys| {
                    keys.iter()
                        .map(|identity| {
                            local_erasure_key_digest_v1(identity)
                                .map(|digest| target(TimelineReplay, NO_COMPONENT, digest))
                        })
                        .collect::<Result<Vec<_>, _>>()
                        .map(|targets| key_and_backup_cells(&targets))
                });
                let artifact_cells = Self::registrations(view, scope, affected)
                    .and_then(|rows| registration_cells(&rows, target));
                let export_cells = Self::exports(view, private, affected, target);
                [
                    store_cells,
                    payload_cells,
                    key_cells,
                    artifact_cells,
                    export_cells,
                ]
                .into_iter()
                .collect::<Result<Vec<_>, _>>()
            })
            .and_then(|cells| {
                let mut closure = ClosureV1::new();
                for (target, category, ack_class) in cells.into_iter().flatten() {
                    closure
                        .entry(target)
                        .or_default()
                        .push((category, ack_class));
                }
                (closure.len() <= ERASURE_MAX_TARGETS)
                    .then_some(closure)
                    .ok_or(ErasureErrorV1::ScopeInvalid)
            })
    }

    /// The role-0 keys of the ADR-091 `subject:<hex>` owner, every epoch,
    /// for a private-subject-data request; none for a consented one.
    fn subject_keys(
        view: &dyn ErasureAuthorityReadViewV1,
        actor: EntityId,
        private: bool,
    ) -> Result<Vec<KeyIdentityV1>, ErasureErrorV1> {
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

    /// Every ARD1 registration bound to an affected Timeline whose data
    /// class is the request's, once each by registration address.
    fn registrations(
        view: &dyn ErasureAuthorityReadViewV1,
        scope: ErasureScopeV1,
        affected: &[TimelineId],
    ) -> Result<Vec<ArtifactRegistrationCatalogRowV1>, ErasureErrorV1> {
        let class = data_class(scope);
        affected
            .iter()
            .map(|timeline| view.artifact_registrations(*timeline))
            .collect::<Result<Vec<_>, _>>()
            .map(|lists| {
                lists
                    .into_iter()
                    .flatten()
                    .filter(|row| row.registration().fields().data_class == class)
                    .map(|row| (row.registration_address(), row))
                    .collect::<BTreeMap<_, _>>()
                    .into_values()
                    .collect()
            })
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
    ) -> Result<Vec<ClosureCellV1>, ErasureErrorV1> {
        let timelines = if private { &[][..] } else { affected };
        view.recipient_export_publications(timelines)
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
                    .collect()
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
        let affected = self.affected_timelines(view, actor);
        self.closure(view, actor, scope, &affected)
            .map(|_| true)
            .or_else(overflow::<bool>)
    }

    /// The freeze `request` admits on this view, before its signature: the
    /// closure under the ELP1 permit set, ERSC1, EROS1 and ERFA1.
    ///
    /// # Errors
    /// `ScopeInvalid` for a bound overflow or an eligible cell without an
    /// ELP1 row, which the freeze commits as `Rejected`; `PolicyConflict`
    /// for a request the installed inventory does not hold; `Unauthorized`
    /// when its ERAZ1 no longer verifies.
    pub(super) fn freeze_draft(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        request: ErasureReferenceV1,
    ) -> Result<FreezeDraftV1, ErasureErrorV1> {
        view.verified_request(request)
            .map(|state| state.request().clone())
            .ok_or(ErasureErrorV1::PolicyConflict)
            .and_then(|erq1| {
                self.verified_authorization(view, &erq1, false)
                    .map(|(_, authorization)| (erq1, authorization.actor_entity))
            })
            .and_then(|(erq1, actor)| {
                let affected = self.affected_timelines(view, actor);
                self.closure(view, actor, erq1.scope(), &affected)
                    .and_then(|closure| self.draft(&erq1, affected, &closure))
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
        let class = data_class(erq1.scope());
        let permitted = closure.iter().all(|(target, cells)| {
            cells.iter().all(|&(category, ack_class)| {
                LOCAL_ERASURE_CLASSIFICATION_V1.contains(&(
                    target.artifact_class,
                    class,
                    category,
                    ack_class,
                ))
            })
        });
        let targets = closure.keys().copied().collect::<Vec<_>>();
        let lineage = LocalErasureLineageRuleV1 {
            subject: erq1.subject(),
        };
        permitted
            .then_some(())
            .ok_or(ErasureErrorV1::ScopeInvalid)
            .and_then(|()| self.bundle.to_canonical_cbor())
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
) -> ErasureVerifiedTopologyObservationV1 {
    let bindings = view
        .recorded_scope(request)
        .map(|(scope, extensions)| {
            scope
                .scope_members()
                .iter()
                .take(1)
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
