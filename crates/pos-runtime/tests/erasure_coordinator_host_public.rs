//! Public host/coordinator containment contract for both durable adapters.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use pos_core::erasure::target_closure_digest;
use pos_core::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceV1,
    ErasureAdministrativeResolutionV1, ErasureArtifactTransitionV1,
    ErasureAtomicFreezeAdmissionInputV1, ErasureAtomicFreezeAdmissionV1,
    ErasureAtomicFreezeResultV1, ErasureAttemptQuotaReservationV1, ErasureAuthorizationDecisionV1,
    ErasureDestructionCommandV1, ErasureErrorV1, ErasureForkAdmissionInputV1,
    ErasureForkScopeRequirementV1, ErasureFreezeAdmissionEvidenceV1,
    ErasureFreezeAuthorizationEvidenceV1, ErasureFreezeAuthorizationVerifierV1, ErasureHostErrorV1,
    ErasureInventoryCategoryV1, ErasureInventoryResultV1, ErasureLifecycleV1,
    ErasureObligationSetInputV1, ErasureObligationSetV1, ErasureObligationV1,
    ErasureReceiptInputV1, ErasureReceiptInventoriesV1, ErasureRecoveryAuthorizationVerifierV1,
    ErasureReferenceV1, ErasureReplayClaimV1, ErasureRequestV1, ErasureRetryAdmissionV1,
    ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1, ErasureScopeExtensionInputV1,
    ErasureScopeExtensionV1, ErasureStateTransitionV1, ErasureVerifiedTopologyObservationV1,
    TimelineId, ERASURE_MAX_INVENTORY_REQUESTS,
};
use pos_runtime::{ErasureCoordinatorAuthorityV1, ErasureExecutionHostV1};
use pos_store::StoreConfig;

#[path = "../../pos-core/tests/support/erasure.rs"]
pub mod erasure_support;

use erasure_support::{
    freeze_evidence_fixture, obligation, persistence_request, persistence_target, reference,
    retry_admission, FreezeEvidenceFixtureInput, RetryAdmissionFixture,
};

#[derive(Default)]
struct TestAuthority {
    timelines: Mutex<Vec<(TimelineId, ErasureReferenceV1)>>,
    frozen: AtomicBool,
    allow_post_freeze: AtomicBool,
    fail_fork_scope_extension: AtomicBool,
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
        _request: ErasureReferenceV1,
        manifest: ErasureReferenceV1,
    ) -> Result<ErasureVerifiedTopologyObservationV1, ErasureErrorV1> {
        let timelines = self
            .timelines
            .lock()
            .map_err(|_| ErasureErrorV1::ProvenanceMissing)?
            .clone();
        if self.frozen.load(Ordering::Acquire) {
            Ok(ErasureVerifiedTopologyObservationV1::new(
                manifest,
                timelines,
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
        if self.fail_fork_scope_extension.load(Ordering::Acquire) {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
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
        self.allow_post_freeze
            .load(Ordering::Acquire)
            .then_some(())
            .ok_or(ErasureErrorV1::Unauthorized)
    }

    fn admit_attempt(
        &self,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureAttemptQuotaReservationV1, ErasureErrorV1> {
        self.allow_post_freeze
            .load(Ordering::Acquire)
            .then_some(ErasureAttemptQuotaReservationV1::new(
                admission.reference(),
                reference(50),
            ))
            .ok_or(ErasureErrorV1::Unauthorized)
    }

    fn admit_acknowledgement(
        &self,
        _acknowledgement: &ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        self.allow_post_freeze
            .load(Ordering::Acquire)
            .then_some(())
            .ok_or(ErasureErrorV1::Unauthorized)
    }

    fn admit_receipt(&self, _input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1> {
        self.allow_post_freeze
            .load(Ordering::Acquire)
            .then_some(())
            .ok_or(ErasureErrorV1::Unauthorized)
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

const fn completed_inventory(
    target: pos_core::ErasureRequiredTargetV1,
) -> ErasureInventoryResultV1 {
    ErasureInventoryResultV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        transition: ErasureArtifactTransitionV1 {
            from: ErasureReplayClaimV1::Exact,
            to: ErasureReplayClaimV1::StructuralOnly,
            reason: reference(20),
            owner: target.replica_id,
            acknowledgements: reference(21),
            provenance: reference(22),
        },
        retained_disclosure: reference(23),
    }
}

fn test_stage<T, E: std::fmt::Debug>(
    stage: &str,
    result: Result<T, E>,
) -> Result<T, Box<dyn std::error::Error>> {
    result.map_err(|error| std::io::Error::other(format!("{stage}: {error:?}")).into())
}

fn assert_atomic_freeze_parity(config: StoreConfig) -> Result<(), Box<dyn std::error::Error>> {
    let authority = Arc::new(TestAuthority::default());
    let authority_plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority.clone();
    let mut host = test_stage(
        "open coordinator host",
        ErasureExecutionHostV1::open_with_coordinator_authority(
            config,
            authority_plugin,
            reference(30),
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
    )?;
    let mut commands = test_stage("open command sender", host.command_sender())?;
    let timeline = test_stage(
        "create parent timeline",
        commands.create_timeline("host-coordinator-freeze"),
    )?;
    test_stage(
        "publish authority topology",
        authority.set_timeline(timeline.id()),
    )?;
    let request = test_stage("construct erasure request", persistence_request())?;
    let request_reference = request.reference();
    let request_provenance = request.provenance();
    assert_eq!(
        test_stage(
            "submit erasure request",
            commands.submit_erasure_request(request, request_provenance),
        )?
        .lifecycle(),
        ErasureLifecycleV1::Submitted
    );
    assert_eq!(
        test_stage(
            "authorize erasure request",
            commands.authorize_erasure_request(request_reference, reference(32)),
        )?
        .lifecycle(),
        ErasureLifecycleV1::Authorized
    );
    assert_eq!(
        test_stage(
            "freeze erasure access",
            commands.freeze_access(request_reference, &freeze_transition()),
        )?
        .lifecycle(),
        ErasureLifecycleV1::AccessFrozen
    );
    assert_eq!(
        commands.timeline(timeline.id()),
        Err(ErasureHostErrorV1::AccessFrozen)
    );
    let operation = reference(40);
    let child = test_stage(
        "fork frozen timeline",
        commands.fork_timeline_identified(
            operation,
            timeline.id(),
            pos_core::Seq::ZERO,
            "frozen-child",
        ),
    )?;
    assert_eq!(
        commands.timeline(child.id()),
        Err(ErasureHostErrorV1::AccessFrozen)
    );
    assert_eq!(
        test_stage(
            "retry frozen timeline fork",
            commands.fork_timeline_identified(
                operation,
                timeline.id(),
                pos_core::Seq::ZERO,
                "ignored-on-retry",
            ),
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
fn memory_host_completes_post_freeze_lifecycle_through_public_sender(
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = Arc::new(TestAuthority::default());
    let authority_plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority.clone();
    let mut host = test_stage(
        "open lifecycle host",
        ErasureExecutionHostV1::open_with_coordinator_authority(
            StoreConfig::Memory,
            authority_plugin,
            reference(30),
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
    )?;
    let mut commands = test_stage("open lifecycle sender", host.command_sender())?;
    let request = test_stage("construct lifecycle request", persistence_request())?;
    let request_reference = request.reference();
    test_stage(
        "submit lifecycle request",
        commands.submit_erasure_request(request, request_reference),
    )?;
    test_stage(
        "authorize lifecycle request",
        commands.authorize_erasure_request(request_reference, reference(32)),
    )?;
    test_stage(
        "freeze lifecycle request",
        commands.freeze_access(request_reference, &freeze_transition()),
    )?;
    authority.allow_post_freeze.store(true, Ordering::Release);

    let target = persistence_target();
    let obligation = test_stage(
        "construct lifecycle obligation",
        obligation(request_reference, target),
    )?;
    let admission = test_stage(
        "construct lifecycle admission",
        retry_admission(RetryAdmissionFixture {
            request: request_reference,
            attempt_ordinal: 0,
            source_receipt: None,
            obligations: std::slice::from_ref(&obligation),
            policy: reference(6),
            trust: reference(8),
            admitted_position: 11,
            deadline_position: 20,
            authorization_provenance: reference(32),
        }),
    )?;
    assert_eq!(
        test_stage(
            "dispatch lifecycle destruction",
            commands.dispatch_erasure_destruction(request_reference, &admission),
        )?
        .lifecycle(),
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    test_stage(
        "acknowledge lifecycle destruction",
        commands.acknowledge_erasure(
            request_reference,
            pos_core::ErasureAcknowledgementV1 {
                obligation: obligation.reference(),
                target,
                owner: target.replica_id,
                evidence: reference(24),
                outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
            },
        ),
    )?;
    let receipt = test_stage(
        "finalize lifecycle request",
        commands.finalize_erasure_request(
            request_reference,
            ErasureReceiptInputV1 {
                request: reference(0),
                terminal_state: reference(0),
                coordinator: reference(0),
                lifecycle: ErasureLifecycleV1::Complete,
                freeze_position: 10,
                acknowledgements: Vec::new(),
                frozen_targets: Vec::new(),
                pending_owners: Vec::new(),
                failed_owners: Vec::new(),
                inventories: ErasureReceiptInventoriesV1 {
                    artifacts: vec![completed_inventory(target)],
                    keys: Vec::new(),
                    replicas: Vec::new(),
                    backups: Vec::new(),
                },
                replay_claim: ErasureReplayClaimV1::Exact,
                policy: reference(0),
                trust: reference(0),
                provenance: reference(0),
                issue_position: 21,
                signature: reference(25),
                receipt_digest: reference(0),
            },
        ),
    )?;
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::Complete);
    Ok(())
}

#[test]
fn memory_host_fails_closed_when_fork_scope_authority_rejects_an_active_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = Arc::new(TestAuthority::default());
    let authority_plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority.clone();
    let mut host = test_stage(
        "open fork failure host",
        ErasureExecutionHostV1::open_with_coordinator_authority(
            StoreConfig::Memory,
            authority_plugin,
            reference(30),
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
    )?;
    let mut commands = test_stage("open fork failure sender", host.command_sender())?;
    let parent = test_stage(
        "create fork failure parent",
        commands.create_timeline("fork-scope-authority-failure"),
    )?;
    test_stage(
        "publish fork failure topology",
        authority.set_timeline(parent.id()),
    )?;
    let request = test_stage("construct fork failure request", persistence_request())?;
    let request_reference = request.reference();
    let request_provenance = request.provenance();
    test_stage(
        "submit fork failure request",
        commands.submit_erasure_request(request, request_provenance),
    )?;
    test_stage(
        "authorize fork failure request",
        commands.authorize_erasure_request(request_reference, reference(32)),
    )?;
    test_stage(
        "freeze fork failure request",
        commands.freeze_access(request_reference, &freeze_transition()),
    )?;
    authority
        .fail_fork_scope_extension
        .store(true, Ordering::Release);

    assert_eq!(
        commands.fork_timeline_identified(
            reference(40),
            parent.id(),
            pos_core::Seq::ZERO,
            "rejected-fork-scope",
        ),
        Err(ErasureHostErrorV1::RecoveryUnavailable)
    );
    Ok(())
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
        let mut host = test_stage(
            "open persistent coordinator host",
            ErasureExecutionHostV1::open_with_coordinator_authority(
                StoreConfig::Sqlite {
                    path: path_text.clone(),
                },
                authority_plugin,
                reference(30),
                ERASURE_MAX_INVENTORY_REQUESTS,
            ),
        )?;
        let mut commands = test_stage("open persistent command sender", host.command_sender())?;
        let parent = test_stage(
            "create persistent parent",
            commands.create_timeline("restart-parent"),
        )?;
        test_stage(
            "publish persistent authority topology",
            authority.set_timeline(parent.id()),
        )?;
        let request = test_stage("construct persistent request", persistence_request())?;
        let request_reference = request.reference();
        let request_provenance = request.provenance();
        test_stage(
            "submit persistent request",
            commands.submit_erasure_request(request, request_provenance),
        )?;
        test_stage(
            "authorize persistent request",
            commands.authorize_erasure_request(request_reference, reference(32)),
        )?;
        test_stage(
            "freeze persistent request",
            commands.freeze_access(request_reference, &freeze_transition()),
        )?;
        let child = test_stage(
            "fork persistent frozen timeline",
            commands.fork_timeline_identified(
                reference(41),
                parent.id(),
                pos_core::Seq::ZERO,
                "restart-child",
            ),
        )?;
        (parent.id(), child.id())
    };
    {
        let authority_plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority;
        let mut recovered = test_stage(
            "reopen persistent coordinator host",
            ErasureExecutionHostV1::open_read_only_with_coordinator_authority(
                &path_text,
                authority_plugin,
                reference(30),
                ERASURE_MAX_INVENTORY_REQUESTS,
            ),
        )?;
        let mut reads = test_stage("open recovered read sender", recovered.read_sender())?;
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

#[test]
fn gateway_host_uses_the_same_coordinator_authority_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    let authority: Arc<dyn ErasureCoordinatorAuthorityV1> = Arc::new(TestAuthority::default());
    let mut host = test_stage(
        "open gateway coordinator host",
        ErasureExecutionHostV1::open_gateway_with_coordinator_authority(
            StoreConfig::Memory,
            authority,
            reference(30),
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
    )?;
    let mut commands = test_stage("open gateway command sender", host.command_sender())?;
    test_stage(
        "create gateway timeline",
        commands.create_timeline("gateway-coordinator-authority"),
    )?;
    Ok(())
}

#[test]
fn rejected_coordinator_command_closes_the_host_without_partial_publication(
) -> Result<(), Box<dyn std::error::Error>> {
    let authority: Arc<dyn ErasureCoordinatorAuthorityV1> = Arc::new(TestAuthority::default());
    let mut host = test_stage(
        "open rejected-command host",
        ErasureExecutionHostV1::open_with_coordinator_authority(
            StoreConfig::Memory,
            authority,
            reference(30),
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
    )?;
    let request = test_stage("construct rejected request", persistence_request())?;
    {
        let mut commands = test_stage("open rejected-command sender", host.command_sender())?;
        assert!(matches!(
            commands.submit_erasure_request(request, reference(99)),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        ));
    }
    assert!(matches!(
        host.command_sender(),
        Err(ErasureHostErrorV1::RecoveryUnavailable)
    ));
    Ok(())
}

#[test]
fn stale_durable_fork_retry_closes_the_host_without_republishing_old_inventory(
) -> Result<(), Box<dyn std::error::Error>> {
    let authority: Arc<dyn ErasureCoordinatorAuthorityV1> = Arc::new(TestAuthority::default());
    let mut host = test_stage(
        "open stale-fork host",
        ErasureExecutionHostV1::open_with_coordinator_authority(
            StoreConfig::Memory,
            authority,
            reference(30),
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
    )?;
    {
        let mut commands = test_stage("open stale-fork sender", host.command_sender())?;
        let parent = test_stage(
            "create stale-fork parent",
            commands.create_timeline("stale-fork-parent"),
        )?;
        let operation = reference(43);
        test_stage(
            "commit durable fork",
            commands.fork_timeline_identified(
                operation,
                parent.id(),
                pos_core::Seq::ZERO,
                "stale-fork-child",
            ),
        )?;
        test_stage(
            "advance inventory generation",
            commands.create_timeline("stale-fork-intervening"),
        )?;
        assert!(matches!(
            commands.fork_timeline_identified(
                operation,
                parent.id(),
                pos_core::Seq::ZERO,
                "ignored-stale-retry-name",
            ),
            Err(ErasureHostErrorV1::Conflict)
        ));
    }
    assert!(matches!(
        host.read_sender(),
        Err(ErasureHostErrorV1::RecoveryUnavailable)
    ));
    Ok(())
}
