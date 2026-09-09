//! Public host/coordinator containment contract for both durable adapters.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use pos_core::erasure::target_closure_digest;
use pos_core::{
    ErasureAcknowledgementProvenanceV1, ErasureAdministrativeResolutionV1,
    ErasureAtomicFreezeAdmissionInputV1, ErasureAtomicFreezeAdmissionV1,
    ErasureAtomicFreezeResultV1, ErasureAttemptQuotaReservationV1, ErasureAuthorizationDecisionV1,
    ErasureDestructionCommandV1, ErasureErrorV1, ErasureForkAdmissionInputV1,
    ErasureForkScopeRequirementV1, ErasureFreezeAdmissionEvidenceV1,
    ErasureFreezeAuthorizationEvidenceV1, ErasureFreezeAuthorizationVerifierV1, ErasureHostErrorV1,
    ErasureLifecycleV1, ErasureObligationSetInputV1, ErasureObligationSetV1, ErasureObligationV1,
    ErasureReceiptInputV1, ErasureRecoveryAuthorizationVerifierV1, ErasureReferenceV1,
    ErasureReplayClaimV1, ErasureRequestV1, ErasureRetryAdmissionV1, ErasureScopeCommitmentInputV1,
    ErasureScopeCommitmentV1, ErasureScopeExtensionInputV1, ErasureScopeExtensionV1,
    ErasureStateTransitionV1, ErasureVerifiedTopologyObservationV1, TimelineId,
    ERASURE_MAX_INVENTORY_REQUESTS,
};
use pos_runtime::{ErasureCoordinatorAuthorityV1, ErasureExecutionHostV1};
use pos_store::StoreConfig;

#[path = "../../pos-core/tests/support/erasure.rs"]
pub mod erasure_support;

use erasure_support::{
    freeze_evidence_fixture, obligation, persistence_request, persistence_target, reference,
    FreezeEvidenceFixtureInput,
};

#[derive(Default)]
struct TestAuthority {
    timelines: Mutex<Vec<(TimelineId, ErasureReferenceV1)>>,
    frozen: AtomicBool,
}

impl TestAuthority {
    fn set_timeline(&self, timeline: TimelineId) -> Result<(), ErasureErrorV1> {
        self.timelines
            .lock()
            .map_err(|_| ErasureErrorV1::ProvenanceMissing)?
            .push((timeline, reference(9)));
        Ok(())
    }

    fn topology(
        &self,
        request: ErasureReferenceV1,
        manifest: ErasureReferenceV1,
    ) -> Result<ErasureVerifiedTopologyObservationV1, ErasureErrorV1> {
        let timelines = self
            .timelines
            .lock()
            .map_err(|_| ErasureErrorV1::ProvenanceMissing)?
            .clone();
        if self.frozen.load(Ordering::Acquire) {
            let scope = ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
                request,
                scope_members: vec![reference(9)],
                target_closure: target_closure_digest(&[persistence_target()]),
                lineage_rule: Some(reference(100)),
            })?;
            Ok(ErasureVerifiedTopologyObservationV1::new(
                manifest,
                timelines
                    .into_iter()
                    .map(|(timeline, child_scope)| {
                        let resolved_scope = if child_scope == reference(9) {
                            scope.reference()
                        } else {
                            child_scope
                        };
                        (timeline, resolved_scope)
                    })
                    .collect(),
                Vec::new(),
            ))
        } else {
            Ok(ErasureVerifiedTopologyObservationV1::new(
                manifest,
                Vec::new(),
                timelines
                    .into_iter()
                    .map(|(timeline, _)| timeline)
                    .collect(),
            ))
        }
    }
}

impl ErasureFreezeAuthorizationVerifierV1 for TestAuthority {
    fn validate_freeze_authorization(
        &self,
        admission: &ErasureFreezeAdmissionEvidenceV1,
        authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        authorization.verify_admission_body_binding(admission)
    }
}

impl ErasureRecoveryAuthorizationVerifierV1 for TestAuthority {
    fn validate_scope_extension(
        &self,
        _extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn validate_administrative_resolution(
        &self,
        _resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
}

impl ErasureCoordinatorAuthorityV1 for TestAuthority {
    fn verified_topology_observation(
        &self,
        request: ErasureReferenceV1,
        manifest_digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureVerifiedTopologyObservationV1>, ErasureErrorV1> {
        self.topology(request, manifest_digest).map(Some)
    }

    fn authenticate(&self, _request: &ErasureRequestV1) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_authorization(
        &self,
        _request: ErasureReferenceV1,
        _provenance: ErasureReferenceV1,
        decision: ErasureAuthorizationDecisionV1,
    ) -> Result<(), ErasureErrorV1> {
        (decision == ErasureAuthorizationDecisionV1::Authorized)
            .then_some(())
            .ok_or(ErasureErrorV1::Unauthorized)
    }

    fn admit_corrected_submission(
        &self,
        _request: &ErasureRequestV1,
        _correction: &pos_core::ErasureCorrectionProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::Unauthorized)
    }

    fn admit_atomic_freeze(
        &self,
        request: ErasureReferenceV1,
        requested: &ErasureStateTransitionV1,
    ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1> {
        let target = persistence_target();
        let targets = vec![target];
        let obligations = vec![obligation(request, target)?];
        let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
            request,
            obligations: obligations
                .iter()
                .map(ErasureObligationV1::reference)
                .collect(),
            policy: reference(6),
            trust: reference(8),
        })?;
        let scope = ErasureScopeCommitmentInputV1 {
            request,
            scope_members: vec![reference(9)],
            target_closure: target_closure_digest(&targets),
            lineage_rule: Some(reference(100)),
        };
        let scope_reference = ErasureScopeCommitmentV1::new(scope.clone())?.reference();
        let evidence = requested.provenance.digest();
        let freeze_position = requested
            .freeze_position
            .ok_or(ErasureErrorV1::ScopeInvalid)?;
        let (freeze_admission_evidence, freeze_authorization_evidence) =
            freeze_evidence_fixture(FreezeEvidenceFixtureInput {
                request,
                scope_commitment: scope_reference,
                obligation_set: &obligation_set,
                targets: &targets,
                obligations: &obligations,
                freeze_position,
                evidence: &evidence,
            })?;
        let admission = ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
            targets,
            scope,
            obligations,
            obligation_set,
            freeze_position,
            freeze_admission_evidence,
            freeze_authorization_evidence,
        })?;
        self.frozen.store(true, Ordering::Release);
        Ok(ErasureAtomicFreezeResultV1::Admitted(Box::new(admission)))
    }

    fn admit_scope_extension(
        &self,
        _extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::Unauthorized)
    }

    fn admit_fork_scope_extension(
        &self,
        _extension: &ErasureScopeExtensionV1,
        _input: &ErasureForkAdmissionInputV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn resolve_fork_child_scope(
        &self,
        _parent: TimelineId,
        child: &pos_core::TimelineMeta,
    ) -> Result<ErasureReferenceV1, ErasureErrorV1> {
        self.timelines
            .lock()
            .map_err(|_| ErasureErrorV1::ProvenanceMissing)?
            .push((child.id, reference(19)));
        Ok(reference(19))
    }

    fn resolve_fork_scope_extension(
        &self,
        requirement: ErasureForkScopeRequirementV1,
        input: &ErasureForkAdmissionInputV1,
    ) -> Result<ErasureScopeExtensionV1, ErasureErrorV1> {
        ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
            request: requirement.request(),
            scope_commitment: requirement.scope_commitment(),
            fork: input.child_scope,
            lineage_rule: requirement.lineage_rule(),
            predecessor_extension: requirement.predecessor_extension(),
            admission_provenance: reference(20),
        })
    }

    fn admit_administrative_resolution(
        &self,
        _resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::Unauthorized)
    }

    fn dispatch_destruction(
        &self,
        _request: ErasureReferenceV1,
        _commands: &[ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::Unauthorized)
    }

    fn admit_attempt(
        &self,
        _admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureAttemptQuotaReservationV1, ErasureErrorV1> {
        Err(ErasureErrorV1::Unauthorized)
    }

    fn admit_acknowledgement(
        &self,
        _acknowledgement: &ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::Unauthorized)
    }

    fn admit_receipt(&self, _input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1> {
        Err(ErasureErrorV1::Unauthorized)
    }
}

const fn freeze_transition() -> ErasureStateTransitionV1 {
    ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::AccessFrozen,
        freeze_position: Some(10),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: Vec::new(),
        replay_claim: ErasureReplayClaimV1::Exact,
        provenance: reference(11),
    }
}

fn assert_atomic_freeze_parity(config: StoreConfig) -> Result<(), Box<dyn std::error::Error>> {
    let authority = Arc::new(TestAuthority::default());
    let authority_plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority.clone();
    let mut host = ErasureExecutionHostV1::open_with_coordinator_authority(
        config,
        authority_plugin,
        reference(30),
        ERASURE_MAX_INVENTORY_REQUESTS,
    )?;
    let mut commands = host.command_sender()?;
    let timeline = commands.create_timeline("host-coordinator-freeze")?;
    authority.set_timeline(timeline.id())?;
    let request = persistence_request()?;
    let request_reference = request.reference();
    assert_eq!(
        commands
            .submit_erasure_request(request, reference(31))?
            .lifecycle(),
        ErasureLifecycleV1::Submitted
    );
    assert_eq!(
        commands
            .authorize_erasure_request(request_reference, reference(32))?
            .lifecycle(),
        ErasureLifecycleV1::Authorized
    );
    assert_eq!(
        commands
            .freeze_access(request_reference, &freeze_transition())?
            .lifecycle(),
        ErasureLifecycleV1::AccessFrozen
    );
    assert_eq!(
        commands.timeline(timeline.id()),
        Err(ErasureHostErrorV1::AccessFrozen)
    );
    let operation = reference(40);
    let child = commands.fork_timeline_identified(
        operation,
        timeline.id(),
        pos_core::Seq::ZERO,
        "frozen-child",
    )?;
    assert_eq!(
        commands.timeline(child.id()),
        Err(ErasureHostErrorV1::AccessFrozen)
    );
    assert_eq!(
        commands
            .fork_timeline_identified(
                operation,
                timeline.id(),
                pos_core::Seq::ZERO,
                "ignored-on-retry"
            )?
            .id(),
        child.id()
    );
    Ok(())
}

#[test]
fn memory_host_freezes_access_at_the_coordinator_cas_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_atomic_freeze_parity(StoreConfig::Memory)
}

#[test]
fn sqlite_host_freezes_access_at_the_coordinator_cas_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_atomic_freeze_parity(StoreConfig::SqliteInMemory)
}

#[test]
fn sqlite_host_recovers_nonempty_frozen_inventory_and_fork_scope(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "pigloros-erasure-host-{}.sqlite",
        TimelineId::new()
    ));
    let path_text = path.to_string_lossy().into_owned();
    let authority = Arc::new(TestAuthority::default());
    let (parent, child) = {
        let authority_plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority.clone();
        let mut host = ErasureExecutionHostV1::open_with_coordinator_authority(
            StoreConfig::Sqlite {
                path: path_text.clone(),
            },
            authority_plugin,
            reference(30),
            ERASURE_MAX_INVENTORY_REQUESTS,
        )?;
        let mut commands = host.command_sender()?;
        let parent = commands.create_timeline("restart-parent")?;
        authority.set_timeline(parent.id())?;
        let request = persistence_request()?;
        let request_reference = request.reference();
        commands.submit_erasure_request(request, reference(31))?;
        commands.authorize_erasure_request(request_reference, reference(32))?;
        commands.freeze_access(request_reference, &freeze_transition())?;
        let child = commands.fork_timeline_identified(
            reference(41),
            parent.id(),
            pos_core::Seq::ZERO,
            "restart-child",
        )?;
        (parent.id(), child.id())
    };
    {
        let authority_plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority;
        let mut recovered = ErasureExecutionHostV1::open_with_coordinator_authority(
            StoreConfig::Sqlite {
                path: path_text.clone(),
            },
            authority_plugin,
            reference(30),
            ERASURE_MAX_INVENTORY_REQUESTS,
        )?;
        let mut reads = recovered.read_sender()?;
        assert_eq!(
            reads.timeline(parent),
            Err(ErasureHostErrorV1::AccessFrozen)
        );
        assert_eq!(reads.timeline(child), Err(ErasureHostErrorV1::AccessFrozen));
    }
    for candidate in [
        path,
        std::path::PathBuf::from(format!("{path_text}-wal")),
        std::path::PathBuf::from(format!("{path_text}-shm")),
    ] {
        if candidate.exists() {
            std::fs::remove_file(candidate)?;
        }
    }
    Ok(())
}
