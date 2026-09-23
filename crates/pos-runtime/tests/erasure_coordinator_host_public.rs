//! Public host/coordinator containment contract for both durable adapters.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use pos_core::erasure::target_closure_digest;
use pos_core::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceInputV1,
    ErasureAcknowledgementProvenanceV1, ErasureAdministrativeResolutionActionV1,
    ErasureAdministrativeResolutionInputV1, ErasureAdministrativeResolutionV1,
    ErasureArtifactTransitionV1, ErasureAtomicFreezeAdmissionInputV1,
    ErasureAtomicFreezeAdmissionV1, ErasureAtomicFreezeResultV1, ErasureAttemptQuotaReservationV1,
    ErasureAuthorizationDecisionV1, ErasureCorrectionProvenanceInputV1,
    ErasureDestructionCommandV1, ErasureErrorV1, ErasureForkAdmissionInputV1,
    ErasureForkScopeRequirementV1, ErasureFreezeAdmissionEvidenceV1,
    ErasureFreezeAuthorizationEvidenceV1, ErasureFreezeAuthorizationVerifierV1, ErasureHostErrorV1,
    ErasureInventoryCategoryV1, ErasureInventoryResultV1, ErasureLifecycleV1,
    ErasureObligationSetInputV1, ErasureObligationSetV1, ErasureObligationV1,
    ErasureReceiptInputV1, ErasureReceiptInventoriesV1, ErasureReceiptV1,
    ErasureRecoveryAuthorizationVerifierV1, ErasureRecoveryLimitsV1, ErasureReferenceV1,
    ErasureReplayClaimV1, ErasureRequestInputV1, ErasureRequestV1, ErasureRetryAdmissionV1,
    ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1, ErasureScopeExtensionInputV1,
    ErasureScopeExtensionV1, ErasureScopeV1, ErasureStateTransitionV1,
    ErasureVerifiedTopologyObservationV1, TimelineId, TimelineMeta, ERASURE_MAX_INVENTORY_REQUESTS,
};
use pos_runtime::{
    ClosedErasureCoordinatorAuthorityV1, ErasureCoordinatorAuthorityV1,
    ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, ErasureHostStatusV1,
};
use pos_store::StoreConfig;

#[path = "../../pos-core/tests/support/erasure.rs"]
pub mod erasure_support;

use erasure_support::{
    freeze_evidence_fixture, obligation, persistence_request, persistence_target, reference,
    retry_admission, FreezeEvidenceFixtureInput, RetryAdmissionFixture,
};

fn authority_composition(
    authority: Arc<dyn ErasureCoordinatorAuthorityV1>,
    coordinator: ErasureReferenceV1,
) -> Result<ErasureCoordinatorCompositionV1, ErasureHostErrorV1> {
    ErasureCoordinatorCompositionV1::new(authority, coordinator)
        .map_err(|_| ErasureHostErrorV1::RecoveryUnavailable)
}

fn open_with_authority(
    config: StoreConfig,
    authority: Arc<dyn ErasureCoordinatorAuthorityV1>,
    coordinator: ErasureReferenceV1,
    maximum_requests: usize,
) -> Result<ErasureExecutionHostV1, ErasureHostErrorV1> {
    let composition = authority_composition(authority, coordinator)?;
    let limits = ErasureRecoveryLimitsV1::from_maximum_requests(maximum_requests)
        .map_err(|_| ErasureHostErrorV1::RecoveryUnavailable)?;
    ErasureExecutionHostV1::open_with_authority(config, &composition, limits)
}

fn open_read_only_with_authority(
    path: &str,
    authority: Arc<dyn ErasureCoordinatorAuthorityV1>,
    coordinator: ErasureReferenceV1,
    maximum_requests: usize,
) -> Result<ErasureExecutionHostV1, ErasureHostErrorV1> {
    let composition = authority_composition(authority, coordinator)?;
    let limits = ErasureRecoveryLimitsV1::from_maximum_requests(maximum_requests)
        .map_err(|_| ErasureHostErrorV1::RecoveryUnavailable)?;
    ErasureExecutionHostV1::open_read_only_with_authority(path, &composition, limits)
}

fn open_gateway_with_authority(
    config: StoreConfig,
    authority: Arc<dyn ErasureCoordinatorAuthorityV1>,
    coordinator: ErasureReferenceV1,
    maximum_requests: usize,
) -> Result<ErasureExecutionHostV1, ErasureHostErrorV1> {
    let composition = authority_composition(authority, coordinator)?;
    let limits = ErasureRecoveryLimitsV1::from_maximum_requests(maximum_requests)
        .map_err(|_| ErasureHostErrorV1::RecoveryUnavailable)?;
    ErasureExecutionHostV1::open_gateway_with_authority(config, &composition, limits)
}

#[test]
fn coordinator_composition_rejects_zero_identity_at_every_public_entry() {
    let zero = ErasureReferenceV1::from_digest([0; 32]);
    let authority: Arc<dyn ErasureCoordinatorAuthorityV1> = Arc::new(TestAuthority::default());
    assert!(matches!(
        ErasureCoordinatorCompositionV1::new(Arc::clone(&authority), zero),
        Err(ErasureErrorV1::ProvenanceMissing)
    ));
    for result in [
        open_with_authority(
            StoreConfig::Memory,
            Arc::clone(&authority),
            zero,
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
        open_read_only_with_authority(
            "unused.db",
            Arc::clone(&authority),
            zero,
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
        open_gateway_with_authority(
            StoreConfig::Memory,
            Arc::clone(&authority),
            zero,
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
    ] {
        assert!(matches!(
            result,
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        ));
    }
}

struct TestAuthority {
    timelines: Mutex<Vec<(TimelineId, ErasureReferenceV1)>>,
    unaffected_timelines: Mutex<Vec<TimelineId>>,
    candidate_metadata: Mutex<Vec<TimelineMeta>>,
    frozen: AtomicBool,
    deny_authentication: AtomicBool,
    deny_topology: AtomicBool,
    deny_scope_extension: AtomicBool,
    allow_rejection: AtomicBool,
    allow_corrected: AtomicBool,
    allow_administrative_resolution: AtomicBool,
    allow_attempt: AtomicBool,
    allow_dispatch: AtomicBool,
    allow_ack: AtomicBool,
    allow_receipt: AtomicBool,
    fail_fork_child_scope: AtomicBool,
    fail_fork_scope_extension: AtomicBool,
    use_closed_scope_resolution: AtomicBool,
    fork_child_scope: std::sync::atomic::AtomicU8,
    fork_extension_provenance: std::sync::atomic::AtomicU8,
}

impl Default for TestAuthority {
    fn default() -> Self {
        Self {
            timelines: Mutex::new(Vec::new()),
            unaffected_timelines: Mutex::new(Vec::new()),
            candidate_metadata: Mutex::new(Vec::new()),
            frozen: AtomicBool::new(false),
            deny_authentication: AtomicBool::new(false),
            deny_topology: AtomicBool::new(false),
            deny_scope_extension: AtomicBool::new(false),
            allow_rejection: AtomicBool::new(false),
            allow_corrected: AtomicBool::new(false),
            allow_administrative_resolution: AtomicBool::new(false),
            allow_attempt: AtomicBool::new(false),
            allow_dispatch: AtomicBool::new(false),
            allow_ack: AtomicBool::new(false),
            allow_receipt: AtomicBool::new(false),
            fail_fork_child_scope: AtomicBool::new(false),
            fail_fork_scope_extension: AtomicBool::new(false),
            use_closed_scope_resolution: AtomicBool::new(false),
            fork_child_scope: std::sync::atomic::AtomicU8::new(19),
            fork_extension_provenance: std::sync::atomic::AtomicU8::new(20),
        }
    }
}

impl TestAuthority {
    fn set_timeline(&self, timeline: TimelineId) -> Result<(), ErasureErrorV1> {
        {
            let mut timelines = self
                .timelines
                .lock()
                .map_err(|_| ErasureErrorV1::ProvenanceMissing)?;
            if let Some((_, scope)) = timelines
                .iter_mut()
                .find(|(candidate, _)| *candidate == timeline)
            {
                *scope = reference(9);
            } else {
                timelines.push((timeline, reference(9)));
            }
        }
        Ok(())
    }

    fn set_timeline_unaffected(&self, timeline: TimelineId) -> Result<(), ErasureErrorV1> {
        self.set_timeline(timeline)?;
        {
            let mut unaffected = self
                .unaffected_timelines
                .lock()
                .map_err(|_| ErasureErrorV1::ProvenanceMissing)?;
            if !unaffected.contains(&timeline) {
                unaffected.push(timeline);
            }
        }
        Ok(())
    }

    fn allow_post_freeze(&self) {
        self.allow_attempt.store(true, Ordering::Release);
        self.allow_dispatch.store(true, Ordering::Release);
        self.allow_ack.store(true, Ordering::Release);
        self.allow_receipt.store(true, Ordering::Release);
    }

    fn set_fork_child_scope(&self, scope: u8) {
        self.fork_child_scope.store(scope, Ordering::Release);
    }

    fn set_fork_extension_provenance(&self, provenance: u8) {
        self.fork_extension_provenance
            .store(provenance, Ordering::Release);
    }

    fn topology(
        &self,
        _request: ErasureReferenceV1,
        manifest: ErasureReferenceV1,
        candidate: Option<TimelineId>,
    ) -> Result<ErasureVerifiedTopologyObservationV1, ErasureErrorV1> {
        if self.deny_topology.load(Ordering::Acquire) {
            return Err(ErasureErrorV1::TrustSnapshotInvalid);
        }
        let mut timelines = self
            .timelines
            .lock()
            .map_err(|_| ErasureErrorV1::ProvenanceMissing)?
            .clone();
        if let Some(candidate) = candidate {
            if !timelines.iter().any(|(timeline, _)| *timeline == candidate) {
                timelines.push((candidate, reference(9)));
            }
        }
        if self.frozen.load(Ordering::Acquire) {
            let unaffected = self
                .unaffected_timelines
                .lock()
                .map_err(|_| ErasureErrorV1::ProvenanceMissing)?
                .clone();
            let bindings = timelines
                .into_iter()
                .filter(|(timeline, _)| !unaffected.contains(timeline))
                .collect();
            Ok(ErasureVerifiedTopologyObservationV1::new(
                manifest, bindings, unaffected,
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
        (!self.deny_scope_extension.load(Ordering::Acquire))
            .then_some(())
            .ok_or(ErasureErrorV1::Unauthorized)
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
        self.topology(request, manifest_digest, None).map(Some)
    }

    fn verified_topology_observation_for_candidate(
        &self,
        request: ErasureReferenceV1,
        manifest_digest: ErasureReferenceV1,
        candidate: &TimelineMeta,
    ) -> Result<Option<ErasureVerifiedTopologyObservationV1>, ErasureErrorV1> {
        self.candidate_metadata
            .lock()
            .map_err(|_| ErasureErrorV1::ProvenanceMissing)?
            .push(candidate.clone());
        self.topology(request, manifest_digest, Some(candidate.id))
            .map(Some)
    }

    fn authenticate(&self, _request: &ErasureRequestV1) -> Result<(), ErasureErrorV1> {
        (!self.deny_authentication.load(Ordering::Acquire))
            .then_some(())
            .ok_or(ErasureErrorV1::Unauthorized)
    }

    fn admit_authorization(
        &self,
        _request: ErasureReferenceV1,
        _provenance: ErasureReferenceV1,
        decision: ErasureAuthorizationDecisionV1,
    ) -> Result<(), ErasureErrorV1> {
        (decision == ErasureAuthorizationDecisionV1::Authorized
            || (decision == ErasureAuthorizationDecisionV1::Rejected
                && self.allow_rejection.load(Ordering::Acquire)))
        .then_some(())
        .ok_or(ErasureErrorV1::Unauthorized)
    }

    fn admit_corrected_submission(
        &self,
        _request: &ErasureRequestV1,
        _correction: &pos_core::ErasureCorrectionProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        self.allow_corrected
            .load(Ordering::Acquire)
            .then_some(())
            .ok_or(ErasureErrorV1::Unauthorized)
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
        Ok(())
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
        if self.fail_fork_child_scope.load(Ordering::Acquire) {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        let mut timelines = self
            .timelines
            .lock()
            .map_err(|_| ErasureErrorV1::ProvenanceMissing)?;
        let scope = reference(self.fork_child_scope.load(Ordering::Acquire));
        if !timelines.iter().any(|(timeline, _)| *timeline == child.id) {
            timelines.push((child.id, scope));
        }
        drop(timelines);
        Ok(scope)
    }

    fn resolve_fork_scope_extension(
        &self,
        requirement: ErasureForkScopeRequirementV1,
        input: &ErasureForkAdmissionInputV1,
    ) -> Result<ErasureScopeExtensionV1, ErasureErrorV1> {
        if self.use_closed_scope_resolution.load(Ordering::Acquire) {
            return ClosedErasureCoordinatorAuthorityV1
                .resolve_fork_scope_extension(requirement, input);
        }
        if self.fail_fork_scope_extension.load(Ordering::Acquire) {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
            request: requirement.request(),
            scope_commitment: requirement.scope_commitment(),
            fork: input.child_scope,
            lineage_rule: requirement.lineage_rule(),
            predecessor_extension: requirement.predecessor_extension(),
            admission_provenance: reference(self.fork_extension_provenance.load(Ordering::Acquire)),
        })
    }

    fn admit_administrative_resolution(
        &self,
        _resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        self.allow_administrative_resolution
            .load(Ordering::Acquire)
            .then_some(())
            .ok_or(ErasureErrorV1::Unauthorized)
    }

    fn dispatch_destruction(
        &self,
        _request: ErasureReferenceV1,
        _commands: &[ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        self.allow_dispatch
            .load(Ordering::Acquire)
            .then_some(())
            .ok_or(ErasureErrorV1::Unauthorized)
    }

    fn admit_attempt(
        &self,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureAttemptQuotaReservationV1, ErasureErrorV1> {
        self.allow_attempt
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
        self.allow_ack
            .load(Ordering::Acquire)
            .then_some(())
            .ok_or(ErasureErrorV1::Unauthorized)
    }

    fn admit_receipt(&self, _input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1> {
        self.allow_receipt
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

fn frozen_scope_reference(
    request: ErasureReferenceV1,
) -> Result<ErasureReferenceV1, ErasureErrorV1> {
    let target = persistence_target();
    ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
        request,
        scope_members: vec![reference(9)],
        target_closure: target_closure_digest(&[target]),
        lineage_rule: Some(reference(100)),
    })
    .map(|scope| scope.reference())
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

fn receipt_input(
    target: pos_core::ErasureRequiredTargetV1,
    lifecycle: ErasureLifecycleV1,
    replay_claim: ErasureReplayClaimV1,
) -> ErasureReceiptInputV1 {
    ErasureReceiptInputV1 {
        request: reference(0),
        terminal_state: reference(0),
        coordinator: reference(0),
        lifecycle,
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
        replay_claim,
        policy: reference(0),
        trust: reference(0),
        provenance: reference(0),
        issue_position: 21,
        signature: reference(25),
        receipt_digest: reference(0),
    }
}

fn submit_authorize_freeze(
    host: &mut ErasureExecutionHostV1,
    request: ErasureRequestV1,
) -> Result<ErasureReferenceV1, Box<dyn std::error::Error>> {
    let request_reference = request.reference();
    let request_provenance = request.provenance();
    let mut commands = test_stage("open lifecycle sender", host.command_sender())?;
    test_stage(
        "submit lifecycle request",
        commands.submit_erasure_request(request, request_provenance),
    )?;
    test_stage(
        "authorize lifecycle request",
        commands.authorize_erasure_request(request_reference, reference(32)),
    )?;
    test_stage(
        "freeze lifecycle request",
        commands.freeze_access(request_reference, &freeze_transition()),
    )?;
    Ok(request_reference)
}

fn create_lifecycle_fork_parent(
    host: &mut ErasureExecutionHostV1,
    authority: &TestAuthority,
) -> Result<TimelineId, Box<dyn std::error::Error>> {
    let mut commands = test_stage("open topology sender", host.command_sender())?;
    let parent = test_stage(
        "create lifecycle fork parent",
        commands.create_timeline("lifecycle-fork-parent"),
    )?;
    test_stage(
        "publish lifecycle fork topology",
        authority.set_timeline(parent.id()),
    )?;
    Ok(parent.id())
}

fn add_lifecycle_fork_scope(
    host: &mut ErasureExecutionHostV1,
    parent: TimelineId,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut commands = test_stage("open fork scope sender", host.command_sender())?;
    test_stage(
        "fork lifecycle scope",
        commands.fork_timeline_identified(
            reference(45),
            parent,
            pos_core::Seq::ZERO,
            "lifecycle-fork-child",
        ),
    )?;
    Ok(())
}

fn assert_terminal_readback(
    reads: &mut pos_runtime::ErasureReadSenderV1<'_>,
    receipt: &ErasureReceiptV1,
    request: ErasureReferenceV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let history = test_stage(
        "read lifecycle history",
        reads.erasure_state_history(request),
    )?
    .ok_or("terminal lifecycle state missing")?;
    if history.len() < 3 {
        return Err("lifecycle history omitted a destruction predecessor".into());
    }
    let terminal = &history[0];
    let awaiting = &history[1];
    let dispatched = &history[2];
    assert_eq!(receipt.request(), request);
    assert_eq!(receipt.terminal_state(), terminal.state_digest());
    assert_eq!(receipt.coordinator(), terminal.coordinator());
    assert_eq!(receipt.lifecycle(), terminal.lifecycle());
    assert_eq!(
        awaiting.lifecycle(),
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    assert_eq!(
        dispatched.lifecycle(),
        ErasureLifecycleV1::DestructionDispatched
    );
    assert_eq!(terminal.previous_state(), Some(awaiting.state_digest()));
    assert_eq!(awaiting.previous_state(), Some(dispatched.state_digest()));
    test_stage(
        "validate terminal lifecycle predecessor",
        terminal.validate_predecessor(awaiting),
    )?;
    test_stage(
        "validate dispatched lifecycle predecessor",
        awaiting.validate_predecessor(dispatched),
    )?;
    Ok(())
}

fn test_stage<T, E: std::fmt::Debug>(
    stage: &str,
    result: Result<T, E>,
) -> Result<T, Box<dyn std::error::Error>> {
    result.map_err(|error| std::io::Error::other(format!("{stage}: {error:?}")).into())
}

fn assert_recovered_fork_is_frozen(
    host: &mut ErasureExecutionHostV1,
    parent: TimelineId,
    child: TimelineId,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut reads = test_stage("open recovered persistent read sender", host.read_sender())?;
    assert_eq!(
        reads.timeline(parent),
        Err(ErasureHostErrorV1::AccessFrozen)
    );
    assert_eq!(reads.timeline(child), Err(ErasureHostErrorV1::AccessFrozen));
    Ok(())
}

fn assert_frozen_fork_retries(
    commands: &mut pos_runtime::ErasureCommandSenderV1<'_>,
    authority: &TestAuthority,
    parent: TimelineId,
    child: TimelineId,
) -> Result<(), Box<dyn std::error::Error>> {
    let operation = reference(40);
    assert_eq!(
        test_stage(
            "exactly retry frozen timeline fork",
            commands.fork_timeline_identified(
                operation,
                parent,
                pos_core::Seq::ZERO,
                "frozen-child",
            ),
        )?
        .id(),
        child
    );
    authority.set_fork_child_scope(21);
    assert_eq!(
        commands.fork_timeline_identified(operation, parent, pos_core::Seq::ZERO, "frozen-child",),
        Err(ErasureHostErrorV1::Conflict)
    );
    authority.set_fork_child_scope(19);
    authority
        .fail_fork_child_scope
        .store(true, Ordering::Release);
    assert_eq!(
        commands.fork_timeline_identified(operation, parent, pos_core::Seq::ZERO, "frozen-child",),
        Err(ErasureHostErrorV1::RecoveryUnavailable)
    );
    authority
        .fail_fork_child_scope
        .store(false, Ordering::Release);
    assert_eq!(
        commands.fork_timeline_identified(
            operation,
            TimelineId::new(),
            pos_core::Seq::ZERO,
            "frozen-child",
        ),
        Err(ErasureHostErrorV1::Conflict)
    );
    assert_eq!(
        commands.fork_timeline_identified(
            operation,
            parent,
            pos_core::Seq::from_u64(1),
            "frozen-child",
        ),
        Err(ErasureHostErrorV1::Conflict)
    );
    assert_eq!(
        commands.fork_timeline_identified(
            operation,
            parent,
            pos_core::Seq::ZERO,
            "changed-on-retry",
        ),
        Err(ErasureHostErrorV1::Conflict)
    );
    authority.set_fork_extension_provenance(21);
    assert_eq!(
        commands.fork_timeline_identified(operation, parent, pos_core::Seq::ZERO, "frozen-child",),
        Err(ErasureHostErrorV1::Conflict)
    );
    authority.set_fork_extension_provenance(20);
    Ok(())
}

fn assert_atomic_freeze_parity(config: StoreConfig) -> Result<(), Box<dyn std::error::Error>> {
    let authority = Arc::new(TestAuthority::default());
    let authority_plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority.clone();
    let mut host = test_stage(
        "open coordinator host",
        open_with_authority(
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
    assert_eq!(
        commands.initialize_timeline_with_key_registry(
            "host-coordinator-freeze",
            &pos_core::KeyRegistryStateV1::new(),
        ),
        Err(ErasureHostErrorV1::Conflict)
    );
    assert_eq!(
        commands.fork_timeline(timeline.id(), pos_core::Seq::ZERO, "affected-ordinary-fork",),
        Err(ErasureHostErrorV1::Conflict)
    );
    let child = test_stage(
        "fork frozen timeline",
        commands.fork_timeline_identified(
            reference(40),
            timeline.id(),
            pos_core::Seq::ZERO,
            "frozen-child",
        ),
    )?;
    assert_eq!(
        commands.timeline(child.id()),
        Err(ErasureHostErrorV1::AccessFrozen)
    );
    assert_frozen_fork_retries(&mut commands, &authority, timeline.id(), child.id())?;
    let mut reader = test_stage("open read sender", host.read_sender())?;
    assert_eq!(reader.key_registry(), Ok(None));
    Ok(())
}

fn assert_active_unaffected_topology_parity(
    config: StoreConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = Arc::new(TestAuthority::default());
    let authority_plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority.clone();
    let mut host = test_stage(
        "open active topology host",
        open_with_authority(
            config,
            authority_plugin,
            reference(30),
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
    )?;
    let mut commands = test_stage("open active topology sender", host.command_sender())?;
    let parent = test_stage(
        "create active topology parent",
        commands.create_timeline("active-topology-parent"),
    )?;
    test_stage(
        "publish active topology parent",
        authority.set_timeline(parent.id()),
    )?;
    let request = test_stage("construct active topology request", persistence_request())?;
    let request_reference = request.reference();
    let request_provenance = request.provenance();
    test_stage(
        "submit active topology request",
        commands.submit_erasure_request(request, request_provenance),
    )?;
    test_stage(
        "authorize active topology request",
        commands.authorize_erasure_request(request_reference, reference(32)),
    )?;

    let root = test_stage(
        "create unaffected active root",
        commands.create_timeline("active-unaffected-root"),
    )?;
    test_stage(
        "publish unaffected active root",
        authority.set_timeline(root.id()),
    )?;
    let child = test_stage(
        "fork unaffected active parent",
        commands.fork_timeline(parent.id(), pos_core::Seq::ZERO, "active-unaffected-fork"),
    )?;
    assert_eq!(
        test_stage("read unaffected active root", commands.timeline(root.id()))?
            .map(|timeline| timeline.id()),
        Some(root.id())
    );
    assert_eq!(
        test_stage("read unaffected active fork", commands.timeline(child.id()))?
            .map(|timeline| timeline.id()),
        Some(child.id())
    );
    let candidates = test_stage(
        "read topology candidates passed to authority",
        authority
            .candidate_metadata
            .lock()
            .map(|candidates| candidates.clone()),
    )?;
    assert_eq!(candidates, vec![root.meta, child.meta]);
    assert_eq!(host.status(), ErasureHostStatusV1::Ready);
    Ok(())
}

#[test]
fn memory_host_admits_active_unaffected_roots_and_forks() -> Result<(), Box<dyn std::error::Error>>
{
    assert_active_unaffected_topology_parity(StoreConfig::Memory)
}

#[test]
fn sqlite_host_admits_active_unaffected_roots_and_forks() -> Result<(), Box<dyn std::error::Error>>
{
    assert_active_unaffected_topology_parity(StoreConfig::SqliteInMemory)
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
        open_with_authority(
            StoreConfig::Memory,
            authority_plugin,
            reference(30),
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
    )?;
    let parent = create_lifecycle_fork_parent(&mut host, &authority)?;
    let request = test_stage("construct lifecycle request", persistence_request())?;
    let request_reference = submit_authorize_freeze(&mut host, request)?;
    authority.allow_post_freeze();
    add_lifecycle_fork_scope(&mut host, parent)?;

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
    let receipt = {
        let mut commands = test_stage("open lifecycle sender", host.command_sender())?;
        let dispatched = test_stage(
            "dispatch lifecycle destruction",
            commands.dispatch_erasure_destruction(request_reference, &admission),
        )?;
        assert_eq!(
            dispatched.lifecycle(),
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
        test_stage(
            "finalize lifecycle request",
            commands.finalize_erasure_request(
                request_reference,
                &receipt_input(
                    target,
                    ErasureLifecycleV1::Complete,
                    ErasureReplayClaimV1::Exact,
                ),
            ),
        )?
    };
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::Complete);
    assert_ne!(receipt.terminal_state(), reference(0));
    assert_ne!(receipt.coordinator(), reference(0));
    assert_ne!(receipt.provenance(), reference(0));
    let mut reads = test_stage("open lifecycle reader", host.read_sender())?;
    assert_terminal_readback(&mut reads, &receipt, request_reference)?;
    authority
        .deny_scope_extension
        .store(true, Ordering::Release);
    assert_eq!(
        reads.erasure_state(request_reference),
        Err(ErasureHostErrorV1::AuthorizationDenied)
    );
    Ok(())
}

#[test]
fn delivery_denial_keeps_the_durable_attempt_retryable_without_poisoning_host(
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = Arc::new(TestAuthority::default());
    let authority_plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority.clone();
    let mut host = test_stage(
        "open retryable-denial host",
        open_with_authority(
            StoreConfig::Memory,
            authority_plugin,
            reference(30),
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
    )?;
    let request = test_stage("construct retryable-denial request", persistence_request())?;
    let request_reference = request.reference();
    let request_provenance = request.provenance();
    let target = persistence_target();
    let obligation = test_stage(
        "construct retryable-denial obligation",
        obligation(request_reference, target),
    )?;
    let admission = test_stage(
        "construct retryable-denial admission",
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
    {
        let mut commands = test_stage("open retryable-denial sender", host.command_sender())?;
        let timeline = test_stage(
            "create retryable-denial timeline",
            commands.create_timeline("retryable-denial-timeline"),
        )?;
        test_stage(
            "publish retryable-denial topology",
            authority.set_timeline(timeline.id()),
        )?;
        test_stage(
            "submit retryable-denial request",
            commands.submit_erasure_request(request, request_provenance),
        )?;
        test_stage(
            "authorize retryable-denial request",
            commands.authorize_erasure_request(request_reference, reference(32)),
        )?;
        test_stage(
            "freeze retryable-denial request",
            commands.freeze_access(request_reference, &freeze_transition()),
        )?;

        authority.allow_attempt.store(true, Ordering::Release);
        assert_eq!(
            commands.dispatch_erasure_destruction(request_reference, &admission),
            Err(ErasureHostErrorV1::AuthorizationDenied)
        );
    }
    assert_eq!(host.status(), ErasureHostStatusV1::Ready);

    authority.allow_dispatch.store(true, Ordering::Release);
    let mut retry = test_stage("reopen retryable-denial sender", host.command_sender())?;
    assert_eq!(
        test_stage(
            "retry durable destruction dispatch",
            retry.dispatch_erasure_destruction(request_reference, &admission),
        )?
        .lifecycle(),
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    Ok(())
}

#[test]
fn public_sender_reaches_rejected_lifecycle_before_containment(
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = Arc::new(TestAuthority::default());
    let authority_plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority.clone();
    let mut host = test_stage(
        "open rejected-lifecycle host",
        open_with_authority(
            StoreConfig::Memory,
            authority_plugin,
            reference(30),
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
    )?;
    let request = test_stage(
        "construct rejected-lifecycle request",
        persistence_request(),
    )?;
    let request_reference = request.reference();
    let request_provenance = request.provenance();
    authority.allow_rejection.store(true, Ordering::Release);
    let mut commands = test_stage("open rejected-lifecycle sender", host.command_sender())?;
    test_stage(
        "submit rejected-lifecycle request",
        commands.submit_erasure_request(request, request_provenance),
    )?;
    assert_eq!(
        test_stage(
            "reject rejected-lifecycle request",
            commands.reject_erasure_request(request_reference, reference(32)),
        )?
        .lifecycle(),
        ErasureLifecycleV1::Rejected
    );
    Ok(())
}

#[test]
fn public_sender_reaches_corrected_submission_after_rejection(
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = Arc::new(TestAuthority::default());
    let authority_plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority.clone();
    let mut host = test_stage(
        "open corrected-submission host",
        open_with_authority(
            StoreConfig::Memory,
            authority_plugin,
            reference(30),
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
    )?;
    let original = test_stage(
        "construct corrected-submission predecessor",
        persistence_request(),
    )?;
    let original_reference = original.reference();
    let original_provenance = original.provenance();
    authority.allow_rejection.store(true, Ordering::Release);
    let mut commands = test_stage("open corrected-submission sender", host.command_sender())?;
    test_stage(
        "submit corrected-submission predecessor",
        commands.submit_erasure_request(original, original_provenance),
    )?;
    let rejected = test_stage(
        "reject corrected-submission predecessor",
        commands.reject_erasure_request(original_reference, reference(32)),
    )?;
    let correction = test_stage(
        "construct corrected-submission provenance",
        pos_core::ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
            rejected_request: original_reference,
            rejected_terminal_state: rejected.state_digest(),
            correction_reason: reference(72),
            authorization_provenance: reference(73),
        }),
    )?;
    let corrected = test_stage(
        "construct corrected request",
        ErasureRequestV1::new(ErasureRequestInputV1 {
            request: reference(74),
            subject: reference(2),
            scope: ErasureScopeV1::PrivateSubjectData,
            selectors: vec![reference(3)],
            requester: reference(4),
            authorization: reference(5),
            policy: reference(6),
            request_position: 9,
            horizon_position: 20,
            provenance: correction.reference(),
        }),
    )?;
    authority.allow_corrected.store(true, Ordering::Release);
    assert_eq!(
        test_stage(
            "submit corrected request",
            commands.submit_corrected_erasure_request(corrected, correction),
        )?
        .lifecycle(),
        ErasureLifecycleV1::Submitted
    );
    Ok(())
}

#[test]
fn public_read_sender_reports_missing_request_and_missing_authority(
) -> Result<(), Box<dyn std::error::Error>> {
    let authority: Arc<dyn ErasureCoordinatorAuthorityV1> = Arc::new(TestAuthority::default());
    let mut host = test_stage(
        "open read-contract host",
        open_with_authority(
            StoreConfig::Memory,
            authority,
            reference(30),
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
    )?;
    let mut reads = test_stage("open read-contract sender", host.read_sender())?;
    assert_eq!(
        test_stage(
            "read missing request history",
            reads.erasure_state_history(reference(250)),
        )?,
        None
    );

    let mut empty_host = test_stage(
        "open authority-free read host",
        ErasureExecutionHostV1::open_verified_empty(
            StoreConfig::Memory,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        ),
    )?;
    let mut empty_reads = test_stage("open authority-free reader", empty_host.read_sender())?;
    assert_eq!(
        empty_reads.erasure_state_history(reference(250)),
        Err(ErasureHostErrorV1::AuthorizationDenied)
    );
    Ok(())
}

#[test]
fn public_sender_reaches_administrative_resolution() -> Result<(), Box<dyn std::error::Error>> {
    let authority = Arc::new(TestAuthority::default());
    let authority_plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority.clone();
    let mut host = test_stage(
        "open resolution host",
        open_with_authority(
            StoreConfig::Memory,
            authority_plugin,
            reference(30),
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
    )?;
    let request = test_stage("construct resolution request", persistence_request())?;
    let request_reference = request.reference();
    let request_provenance = request.provenance();
    {
        let mut commands = test_stage("open resolution sender", host.command_sender())?;
        test_stage(
            "submit resolution request",
            commands.submit_erasure_request(request, request_provenance),
        )?;
        test_stage(
            "authorize resolution request",
            commands.authorize_erasure_request(request_reference, reference(32)),
        )?;
        test_stage(
            "freeze resolution request",
            commands.freeze_access(request_reference, &freeze_transition()),
        )?;
    }
    let scope_commitment = test_stage(
        "derive frozen scope commitment",
        frozen_scope_reference(request_reference),
    )?;
    let before = {
        let mut reads = test_stage("open pre-resolution reader", host.read_sender())?;
        test_stage(
            "read pre-resolution state",
            reads.erasure_state(request_reference),
        )?
        .ok_or("pre-resolution state missing")?
        .manifest_digest()
    };
    authority
        .allow_administrative_resolution
        .store(true, Ordering::Release);
    let resolution = test_stage(
        "construct administrative resolution",
        ErasureAdministrativeResolutionV1::new(pos_core::ErasureAdministrativeResolutionInputV1 {
            request: request_reference,
            affected_digests: vec![reference(110)],
            action: ErasureAdministrativeResolutionActionV1::RecoverExactEvidence,
            scope_commitment,
            policy: reference(6),
            trust: reference(8),
            principal: reference(111),
            authorization_provenance: reference(112),
            reason: reference(113),
            issue_position: 12,
            predecessor_resolution: None,
        }),
    )?;
    {
        let mut commands = test_stage("open resolution sender", host.command_sender())?;
        assert_eq!(
            test_stage(
                "resolve administratively",
                commands.resolve_erasure_administratively(request_reference, &resolution),
            )?
            .lifecycle(),
            ErasureLifecycleV1::AccessFrozen
        );
    }
    let after = {
        let mut reads = test_stage("open post-resolution reader", host.read_sender())?;
        test_stage(
            "read post-resolution state",
            reads.erasure_state(request_reference),
        )?
        .ok_or("post-resolution state missing")?
        .manifest_digest()
    };
    assert_ne!(before, after);
    Ok(())
}

#[test]
fn public_sender_reaches_partial_failure_after_deadline_without_acknowledgement(
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = Arc::new(TestAuthority::default());
    let authority_plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority.clone();
    let mut host = test_stage(
        "open partial-failure host",
        open_with_authority(
            StoreConfig::SqliteInMemory,
            authority_plugin,
            reference(30),
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
    )?;
    let request = test_stage("construct partial-failure request", persistence_request())?;
    let request_reference = submit_authorize_freeze(&mut host, request)?;
    let target = persistence_target();
    let obligation = test_stage(
        "construct partial-failure obligation",
        obligation(request_reference, target),
    )?;
    let admission = test_stage(
        "construct partial-failure admission",
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
    authority.allow_post_freeze();
    let receipt = {
        let mut commands = test_stage("open partial-failure sender", host.command_sender())?;
        let dispatched = test_stage(
            "dispatch partial-failure destruction",
            commands.dispatch_erasure_destruction(request_reference, &admission),
        )?;
        assert_eq!(
            dispatched.lifecycle(),
            ErasureLifecycleV1::AwaitingAcknowledgements
        );
        test_stage(
            "finalize partial-failure request",
            commands.finalize_erasure_request(
                request_reference,
                &receipt_input(
                    target,
                    ErasureLifecycleV1::PartialFailure,
                    ErasureReplayClaimV1::StructuralOnly,
                ),
            ),
        )?
    };
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::PartialFailure);
    assert_ne!(receipt.terminal_state(), reference(0));
    assert_ne!(receipt.coordinator(), reference(0));
    assert_ne!(receipt.provenance(), reference(0));
    let mut reads = test_stage("open partial-failure reader", host.read_sender())?;
    assert_terminal_readback(&mut reads, &receipt, request_reference)?;
    Ok(())
}

fn assert_host_fails_closed_when_fork_scope_authority_rejects_an_active_request(
    config: StoreConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = Arc::new(TestAuthority::default());
    let authority_plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority.clone();
    let mut host = test_stage(
        "open fork failure host",
        open_with_authority(
            config,
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
        .use_closed_scope_resolution
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
    assert_eq!(host.status(), ErasureHostStatusV1::Ready);
    let mut reads = test_stage("open fork failure reader", host.read_sender())?;
    let timelines = test_stage("read fork failure timelines", reads.timelines())?;
    assert!(timelines.is_empty());
    assert_eq!(
        reads.timeline(parent.id()),
        Err(ErasureHostErrorV1::AccessFrozen)
    );
    Ok(())
}

#[test]
fn memory_host_fails_closed_when_fork_scope_authority_rejects_an_active_request(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_host_fails_closed_when_fork_scope_authority_rejects_an_active_request(
        StoreConfig::Memory,
    )
}

#[test]
fn sqlite_host_fails_closed_when_fork_scope_authority_rejects_an_active_request(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_host_fails_closed_when_fork_scope_authority_rejects_an_active_request(
        StoreConfig::SqliteInMemory,
    )
}

#[test]
fn sqlite_host_freezes_access_at_the_coordinator_cas_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_atomic_freeze_parity(StoreConfig::SqliteInMemory)
}

#[test]
fn sqlite_public_active_root_failure_rolls_back_before_poisoning(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "pigloros-erasure-root-rollback-{}.sqlite",
        TimelineId::new()
    ));
    let path = path.to_string_lossy().into_owned();
    let authority = Arc::new(TestAuthority::default());
    {
        let authority_plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority.clone();
        let mut host = test_stage(
            "open active-root rollback host",
            open_with_authority(
                StoreConfig::Sqlite { path: path.clone() },
                authority_plugin,
                reference(30),
                ERASURE_MAX_INVENTORY_REQUESTS,
            ),
        )?;
        let mut commands = test_stage("open active-root rollback sender", host.command_sender())?;
        let parent = test_stage(
            "create active-root rollback parent",
            commands.create_timeline("active-root-parent"),
        )?;
        test_stage(
            "publish active-root rollback topology",
            authority.set_timeline(parent.id()),
        )?;
        let request = test_stage(
            "construct active-root rollback request",
            persistence_request(),
        )?;
        let request_reference = request.reference();
        let request_provenance = request.provenance();
        test_stage(
            "submit active-root rollback request",
            commands.submit_erasure_request(request, request_provenance),
        )?;
        test_stage(
            "authorize active-root rollback request",
            commands.authorize_erasure_request(request_reference, reference(32)),
        )?;
        authority.deny_topology.store(true, Ordering::Release);
        assert_eq!(
            commands.create_timeline("rolled-back-root"),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        );
    }

    authority.deny_topology.store(false, Ordering::Release);
    let mut reopened = test_stage(
        "reopen active-root rollback host",
        open_read_only_with_authority(
            &path,
            authority,
            reference(30),
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
    )?;
    let mut reads = test_stage("open active-root rollback reader", reopened.read_sender())?;
    let timelines = test_stage("read active-root rollback timelines", reads.timelines())?;
    assert_eq!(timelines.len(), 1);
    assert_eq!(
        timelines[0].meta.name.as_deref(),
        Some("active-root-parent")
    );
    for candidate in [
        std::path::PathBuf::from(&path),
        std::path::PathBuf::from(format!("{path}-wal")),
        std::path::PathBuf::from(format!("{path}-shm")),
    ] {
        if candidate.exists() {
            std::fs::remove_file(candidate)?;
        }
    }
    Ok(())
}

fn create_persisted_frozen_fork(
    path_text: &str,
    authority: &Arc<TestAuthority>,
) -> Result<(TimelineId, TimelineId), Box<dyn std::error::Error>> {
    let authority_plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority.clone();
    let mut host = test_stage(
        "open persistent coordinator host",
        open_with_authority(
            StoreConfig::Sqlite {
                path: path_text.to_owned(),
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
    Ok((parent.id(), child.id()))
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
    let (parent, child) = create_persisted_frozen_fork(&path_text, &authority)?;
    let mut original_authority_recovery = test_stage(
        "reopen persistent coordinator host with the original authority",
        open_read_only_with_authority(
            &path_text,
            authority.clone(),
            reference(30),
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
    )?;
    assert_eq!(
        original_authority_recovery.status(),
        ErasureHostStatusV1::Ready
    );
    assert_recovered_fork_is_frozen(&mut original_authority_recovery, parent, child)?;
    {
        let mut commands = test_stage(
            "open persistent retry sender",
            original_authority_recovery.command_sender(),
        )?;
        let recovered_child = test_stage(
            "retry persistent fork after restart",
            commands.fork_timeline_identified(
                reference(41),
                parent,
                pos_core::Seq::ZERO,
                "restart-child",
            ),
        )?;
        assert_eq!(recovered_child.id(), child);
        authority.set_fork_child_scope(21);
        assert_eq!(
            commands.fork_timeline_identified(
                reference(41),
                parent,
                pos_core::Seq::ZERO,
                "restart-child",
            ),
            Err(ErasureHostErrorV1::Conflict)
        );
    }
    drop(original_authority_recovery);
    authority.deny_topology.store(true, Ordering::Release);
    let denied_recovery = open_read_only_with_authority(
        &path_text,
        authority,
        reference(30),
        ERASURE_MAX_INVENTORY_REQUESTS,
    );
    assert!(
        denied_recovery.is_err(),
        "topology denial must keep recovery closed"
    );
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
        open_gateway_with_authority(
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
fn closed_composition_proves_empty_but_rejects_non_empty_authority(
) -> Result<(), Box<dyn std::error::Error>> {
    let composition = ErasureCoordinatorCompositionV1::closed();
    let host = test_stage(
        "open explicitly closed composition",
        ErasureExecutionHostV1::open_with_authority(
            StoreConfig::Memory,
            &composition,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        ),
    )?;
    assert_eq!(host.status(), ErasureHostStatusV1::Ready);

    let path = std::env::temp_dir().join(format!(
        "pigloros-closed-composition-{}.sqlite",
        TimelineId::new()
    ));
    let path_text = path.to_string_lossy().into_owned();
    let authority = Arc::new(TestAuthority::default());
    {
        let authority_plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority.clone();
        let mut persistent_host = test_stage(
            "open non-empty host for closed-composition recovery",
            open_with_authority(
                StoreConfig::Sqlite {
                    path: path_text.clone(),
                },
                authority_plugin,
                reference(30),
                ERASURE_MAX_INVENTORY_REQUESTS,
            ),
        )?;
        let mut commands = test_stage(
            "open non-empty host command sender",
            persistent_host.command_sender(),
        )?;
        let timeline = test_stage(
            "create non-empty host timeline",
            commands.create_timeline("closed-composition-recovery"),
        )?;
        test_stage(
            "publish non-empty host topology",
            authority.set_timeline(timeline.id()),
        )?;
        let request = test_stage("construct non-empty host request", persistence_request())?;
        let request_reference = request.reference();
        let request_provenance = request.provenance();
        test_stage(
            "submit non-empty host request",
            commands.submit_erasure_request(request, request_provenance),
        )?;
        test_stage(
            "authorize non-empty host request",
            commands.authorize_erasure_request(request_reference, reference(32)),
        )?;
        test_stage(
            "freeze non-empty host request",
            commands.freeze_access(request_reference, &freeze_transition()),
        )?;
    }
    let closed_recovery = ErasureExecutionHostV1::open_read_only_with_authority(
        &path_text,
        &composition,
        pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
    );
    assert_eq!(
        closed_recovery.err(),
        Some(ErasureHostErrorV1::RecoveryUnavailable)
    );
    for candidate in [
        path,
        std::path::PathBuf::from(format!("{path_text}-wal")),
        std::path::PathBuf::from(format!("{path_text}-shm")),
    ] {
        if candidate.exists() {
            std::fs::remove_file(candidate)?;
        }
    }

    let authority = ClosedErasureCoordinatorAuthorityV1;
    assert_eq!(
        authority.verified_topology_observation(reference(1), reference(2)),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn closed_authority_rejects_request_operations() -> Result<(), Box<dyn std::error::Error>> {
    let authority = ClosedErasureCoordinatorAuthorityV1;
    let request = test_stage("construct closed-authority request", persistence_request())?;
    let request_reference = request.reference();
    assert_eq!(
        authority.authenticate(&request),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        authority.admit_authorization(
            request_reference,
            reference(230),
            ErasureAuthorizationDecisionV1::Authorized,
        ),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let correction = test_stage(
        "construct closed-authority correction",
        pos_core::ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
            rejected_request: request_reference,
            rejected_terminal_state: reference(231),
            correction_reason: reference(232),
            authorization_provenance: reference(233),
        }),
    )?;
    assert_eq!(
        authority.admit_corrected_submission(&request, &correction),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn closed_authority_rejects_freeze_and_scope_operations() -> Result<(), Box<dyn std::error::Error>>
{
    let authority = ClosedErasureCoordinatorAuthorityV1;
    let request = test_stage(
        "construct closed-authority freeze request",
        persistence_request(),
    )?;
    let request_reference = request.reference();
    let target = persistence_target();
    let obligation = test_stage(
        "construct closed-authority obligation",
        obligation(request_reference, target),
    )?;
    let obligations = vec![obligation];
    let targets = vec![target];
    let obligation_set = test_stage(
        "construct closed-authority obligation set",
        ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
            request: request_reference,
            obligations: obligations
                .iter()
                .map(ErasureObligationV1::reference)
                .collect(),
            policy: reference(201),
            trust: reference(202),
        }),
    )?;
    let (freeze_admission, freeze_authorization) = test_stage(
        "construct closed-authority freeze evidence",
        freeze_evidence_fixture(FreezeEvidenceFixtureInput {
            request: request_reference,
            scope_commitment: reference(203),
            obligation_set: &obligation_set,
            targets: &targets,
            obligations: &obligations,
            freeze_position: 1,
            evidence: b"closed-authority",
        }),
    )?;
    assert_eq!(
        authority.validate_freeze_authorization(&freeze_admission, &freeze_authorization),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let extension = test_stage(
        "construct closed-authority scope extension",
        ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
            request: request_reference,
            scope_commitment: reference(204),
            fork: reference(205),
            lineage_rule: reference(206),
            predecessor_extension: None,
            admission_provenance: reference(207),
        }),
    )?;
    let transition = ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::AccessFrozen,
        freeze_position: Some(1),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: Vec::new(),
        replay_claim: ErasureReplayClaimV1::Exact,
        provenance: reference(226),
    };
    let fork_input = ErasureForkAdmissionInputV1 {
        operation: reference(227),
        expected_inventory_generation: reference(228),
        child_scope: reference(229),
        child: pos_core::TimelineMeta::root("closed-authority-child"),
    };
    assert_eq!(
        authority.admit_atomic_freeze(request_reference, &transition),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        authority.admit_scope_extension(&extension),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        authority.admit_fork_scope_extension(&extension, &fork_input),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        authority.resolve_fork_child_scope(fork_input.child.id, &fork_input.child),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        authority.validate_scope_extension(&extension),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn closed_authority_rejects_retry_and_acknowledgement_operations(
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = ClosedErasureCoordinatorAuthorityV1;
    let request = test_stage(
        "construct closed-authority retry request",
        persistence_request(),
    )?;
    let request_reference = request.reference();
    let target = persistence_target();
    let obligation = test_stage(
        "construct closed-authority retry obligation",
        obligation(request_reference, target),
    )?;
    let obligations = vec![obligation];
    let retry = test_stage(
        "construct closed-authority retry admission",
        retry_admission(RetryAdmissionFixture {
            request: request_reference,
            attempt_ordinal: 0,
            source_receipt: None,
            obligations: &obligations,
            policy: reference(215),
            trust: reference(216),
            admitted_position: 1,
            deadline_position: 2,
            authorization_provenance: reference(217),
        }),
    )?;
    let acknowledgement = test_stage(
        "construct closed-authority acknowledgement",
        ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
            request: request_reference,
            command: reference(218),
            attempt: retry.reference(),
            obligation: obligation.reference(),
            owner: reference(219),
            scope: reference(220),
            outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
            evidence: reference(221),
            policy: reference(215),
            trust: reference(216),
        }),
    )?;
    assert_eq!(
        authority.admit_attempt(&retry),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        authority.admit_acknowledgement(&acknowledgement),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn closed_authority_rejects_receipt_and_administrative_operations(
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = ClosedErasureCoordinatorAuthorityV1;
    let request = test_stage(
        "construct closed-authority receipt request",
        persistence_request(),
    )?;
    let request_reference = request.reference();
    let resolution = test_stage(
        "construct closed-authority resolution",
        ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
            request: request_reference,
            affected_digests: vec![reference(208)],
            action: ErasureAdministrativeResolutionActionV1::RecoverExactEvidence,
            scope_commitment: reference(209),
            policy: reference(210),
            trust: reference(211),
            principal: reference(212),
            authorization_provenance: reference(213),
            reason: reference(214),
            issue_position: 1,
            predecessor_resolution: None,
        }),
    )?;
    let receipt = ErasureReceiptInputV1 {
        request: request_reference,
        terminal_state: reference(222),
        coordinator: reference(223),
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: 1,
        acknowledgements: Vec::new(),
        frozen_targets: Vec::new(),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        inventories: ErasureReceiptInventoriesV1 {
            artifacts: Vec::new(),
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        },
        replay_claim: ErasureReplayClaimV1::Exact,
        policy: reference(215),
        trust: reference(216),
        provenance: reference(224),
        issue_position: 2,
        signature: reference(225),
        receipt_digest: reference(0),
    };
    assert_eq!(
        authority.admit_receipt(&receipt),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        authority.admit_administrative_resolution(&resolution),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        authority.validate_administrative_resolution(&resolution),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        authority.dispatch_destruction(request_reference, &[]),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

#[test]
fn explicit_recovery_constructors_keep_empty_and_composed_paths_distinct(
) -> Result<(), Box<dyn std::error::Error>> {
    let host = test_stage(
        "open verified-empty host",
        ErasureExecutionHostV1::open_verified_empty(
            StoreConfig::Memory,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        ),
    )?;
    assert_eq!(host.status(), ErasureHostStatusV1::Ready);

    let gateway_host = test_stage(
        "open verified-empty gateway host",
        ErasureExecutionHostV1::open_gateway_verified_empty(
            StoreConfig::Memory,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        ),
    )?;
    assert_eq!(gateway_host.status(), ErasureHostStatusV1::Ready);
    let composition = ErasureCoordinatorCompositionV1::closed();
    let composed_gateway_host = test_stage(
        "open explicit composed gateway host",
        ErasureExecutionHostV1::open_gateway_with_authority(
            StoreConfig::Memory,
            &composition,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        ),
    )?;
    assert_eq!(composed_gateway_host.status(), ErasureHostStatusV1::Ready);

    let path = std::env::temp_dir().join(format!(
        "pigloros-runtime-recovery-{}.db",
        TimelineId::new()
    ));
    if path.exists() {
        return Err(format!("recovery fixture already exists: {}", path.display()).into());
    }
    let path_text = path.to_string_lossy().into_owned();
    drop(test_stage(
        "create compatibility read-only database",
        ErasureExecutionHostV1::open_verified_empty(
            StoreConfig::Sqlite {
                path: path_text.clone(),
            },
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        ),
    )?);
    let legacy_read_only_host = test_stage(
        "open legacy verified-empty read-only host",
        ErasureExecutionHostV1::open_read_only_verified_empty(
            &path_text,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        ),
    )?;
    assert_eq!(legacy_read_only_host.status(), ErasureHostStatusV1::Ready);
    let read_only_host = test_stage(
        "open explicit composed read-only host",
        ErasureExecutionHostV1::open_read_only_with_authority(
            &path_text,
            &composition,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        ),
    )?;
    assert_eq!(read_only_host.status(), ErasureHostStatusV1::Ready);
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn recovery_entrypoints_map_store_open_failures_to_adapter_failure() {
    let missing_path = std::env::temp_dir()
        .join(format!(
            "pigloros-erasure-recovery-missing-parent-{}",
            std::process::id()
        ))
        .join("store.db")
        .to_string_lossy()
        .into_owned();
    assert_eq!(
        ErasureExecutionHostV1::open_verified_empty(
            StoreConfig::Sqlite {
                path: missing_path.clone(),
            },
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )
        .map(|_| ()),
        Err(ErasureHostErrorV1::AdapterFailure)
    );
    assert_eq!(
        ErasureExecutionHostV1::open_gateway_verified_empty(
            StoreConfig::Sqlite { path: missing_path },
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )
        .map(|_| ()),
        Err(ErasureHostErrorV1::AdapterFailure)
    );
}

#[test]
fn authentication_denial_preserves_a_recovered_host() -> Result<(), Box<dyn std::error::Error>> {
    let authority = Arc::new(TestAuthority::default());
    let authority_plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority.clone();
    let mut host = test_stage(
        "open rejected-command host",
        open_with_authority(
            StoreConfig::Memory,
            authority_plugin,
            reference(30),
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
    )?;
    let request = test_stage("construct rejected request", persistence_request())?;
    let request_provenance = request.provenance();
    {
        let mut commands = test_stage("open rejected-command sender", host.command_sender())?;
        authority.deny_authentication.store(true, Ordering::Release);
        assert!(matches!(
            commands.submit_erasure_request(request, request_provenance),
            Err(ErasureHostErrorV1::AuthorizationDenied)
        ));
    }
    assert!(host.command_sender().is_ok());
    assert_eq!(host.status(), ErasureHostStatusV1::Ready);
    Ok(())
}

fn assert_exact_durable_fork_retry_preserves_current_inventory(
    config: StoreConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let authority: Arc<dyn ErasureCoordinatorAuthorityV1> = Arc::new(TestAuthority::default());
    let mut host = test_stage(
        "open stale-fork host",
        open_with_authority(
            config,
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
        let committed_child = test_stage(
            "commit durable fork",
            commands.fork_timeline_identified(
                operation,
                parent.id(),
                pos_core::Seq::ZERO,
                "stale-fork-child",
            ),
        )?;
        assert_eq!(
            commands.fork_timeline_identified(
                operation,
                TimelineId::new(),
                pos_core::Seq::ZERO,
                "stale-fork-child",
            ),
            Err(ErasureHostErrorV1::Conflict)
        );
        assert_eq!(
            test_stage(
                "retry durable fork after conflicting parent",
                commands.fork_timeline_identified(
                    operation,
                    parent.id(),
                    pos_core::Seq::ZERO,
                    "stale-fork-child",
                ),
            )?
            .id(),
            committed_child.id()
        );
        test_stage(
            "advance inventory generation",
            commands.create_timeline("stale-fork-intervening"),
        )?;
        let retried_child = test_stage(
            "retry durable fork after unrelated topology change",
            commands.fork_timeline_identified(
                operation,
                parent.id(),
                pos_core::Seq::ZERO,
                "stale-fork-child",
            ),
        )?;
        assert_eq!(retried_child.id(), committed_child.id());
    }
    assert_eq!(host.status(), ErasureHostStatusV1::Ready);
    let mut reads = test_stage("open stale-fork reader", host.read_sender())?;
    let timelines = test_stage("read stale-fork timelines", reads.timelines())?;
    assert_eq!(timelines.len(), 3);
    Ok(())
}

#[test]
fn exact_durable_fork_retry_preserves_current_inventory() -> Result<(), Box<dyn std::error::Error>>
{
    assert_exact_durable_fork_retry_preserves_current_inventory(StoreConfig::Memory)
}

#[test]
fn sqlite_exact_durable_fork_retry_preserves_current_inventory(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_exact_durable_fork_retry_preserves_current_inventory(StoreConfig::SqliteInMemory)
}

fn assert_exact_affected_fork_retry_after_later_scope_extension(
    config: StoreConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = Arc::new(TestAuthority::default());
    let authority_plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority.clone();
    let mut host = test_stage(
        "open affected-fork retry host",
        open_with_authority(
            config,
            authority_plugin,
            reference(30),
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
    )?;
    {
        let mut commands = test_stage("open affected-fork retry sender", host.command_sender())?;
        let parent = test_stage(
            "create affected-fork retry parent",
            commands.create_timeline("affected-fork-retry-parent"),
        )?;
        test_stage(
            "publish affected-fork retry parent",
            authority.set_timeline(parent.id()),
        )?;
        let request = test_stage(
            "construct affected-fork retry request",
            persistence_request(),
        )?;
        let request_reference = request.reference();
        let request_provenance = request.provenance();
        test_stage(
            "submit affected-fork retry request",
            commands.submit_erasure_request(request, request_provenance),
        )?;
        test_stage(
            "authorize affected-fork retry request",
            commands.authorize_erasure_request(request_reference, reference(32)),
        )?;
        test_stage(
            "freeze affected-fork retry request",
            commands.freeze_access(request_reference, &freeze_transition()),
        )?;

        let first_operation = reference(43);
        let first_child = test_stage(
            "commit first affected fork",
            commands.fork_timeline_identified(
                first_operation,
                parent.id(),
                pos_core::Seq::ZERO,
                "first-affected-child",
            ),
        )?;
        authority.set_fork_child_scope(21);
        let later_child = test_stage(
            "commit later affected fork in the same scope",
            commands.fork_timeline_identified(
                reference(44),
                first_child.id(),
                pos_core::Seq::ZERO,
                "later-affected-child",
            ),
        )?;
        authority.set_fork_child_scope(21);
        let retried_later_child = test_stage(
            "retry later affected fork with its original child binding",
            commands.fork_timeline_identified(
                reference(44),
                first_child.id(),
                pos_core::Seq::ZERO,
                "later-affected-child",
            ),
        )?;
        assert_eq!(retried_later_child.id(), later_child.id());
        authority.set_fork_child_scope(19);
        let retried_child = test_stage(
            "retry first affected fork after its scope advanced",
            commands.fork_timeline_identified(
                first_operation,
                parent.id(),
                pos_core::Seq::ZERO,
                "first-affected-child",
            ),
        )?;

        assert_eq!(retried_child.id(), first_child.id());
        assert_eq!(
            commands.timeline(first_child.id()),
            Err(ErasureHostErrorV1::AccessFrozen)
        );
        assert_eq!(
            commands.timeline(later_child.id()),
            Err(ErasureHostErrorV1::AccessFrozen)
        );
    }
    assert_eq!(host.status(), ErasureHostStatusV1::Ready);
    Ok(())
}

#[test]
fn exact_affected_fork_retry_survives_later_scope_extension(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_exact_affected_fork_retry_after_later_scope_extension(StoreConfig::Memory)
}

#[test]
fn sqlite_exact_affected_fork_retry_survives_later_scope_extension(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_exact_affected_fork_retry_after_later_scope_extension(StoreConfig::SqliteInMemory)
}

#[derive(Clone, Copy)]
enum LaterRequestChildMembership {
    Included,
    Unaffected,
}

fn assert_retried_fork_membership(
    commands: &mut pos_runtime::ErasureCommandSenderV1<'_>,
    authority: &TestAuthority,
    child_membership: LaterRequestChildMembership,
    operation: ErasureReferenceV1,
    parent: TimelineId,
    original_child: TimelineId,
    intervening: TimelineId,
) -> Result<(), Box<dyn std::error::Error>> {
    let later_child = if matches!(child_membership, LaterRequestChildMembership::Included) {
        // Reuse the original child's fork-scope reference to prove that a
        // later extension is not confused with the original receipt when this
        // request already included that child directly.
        authority.set_fork_child_scope(19);
        Some(test_stage(
            "admit a later Fork into the directly including scope",
            commands.fork_timeline_identified(
                reference(46),
                parent,
                pos_core::Seq::ZERO,
                "later-child-same-scope",
            ),
        )?)
    } else {
        None
    };

    let retried_child = test_stage(
        "retry original Fork after later request freeze",
        commands.fork_timeline_identified(
            operation,
            parent,
            pos_core::Seq::ZERO,
            "pre-freeze-child",
        ),
    )?;
    assert_eq!(retried_child.id(), original_child);
    if let Some(later_child) = later_child {
        assert_eq!(
            commands.timeline(later_child.id()),
            Err(ErasureHostErrorV1::AccessFrozen)
        );
    }
    assert_eq!(
        commands
            .timeline(intervening)?
            .map(|timeline| timeline.id()),
        Some(intervening)
    );
    if matches!(child_membership, LaterRequestChildMembership::Included) {
        assert_eq!(
            commands.timeline(original_child),
            Err(ErasureHostErrorV1::AccessFrozen)
        );
    } else {
        assert_eq!(
            commands
                .timeline(original_child)?
                .map(|timeline| timeline.id()),
            Some(original_child)
        );
    }
    Ok(())
}

fn assert_exact_fork_retry_after_later_request(
    config: StoreConfig,
    child_membership: LaterRequestChildMembership,
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = Arc::new(TestAuthority::default());
    let authority_plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority.clone();
    let mut host = test_stage(
        "open pre-freeze Fork retry host",
        open_with_authority(
            config,
            authority_plugin,
            reference(30),
            ERASURE_MAX_INVENTORY_REQUESTS,
        ),
    )?;
    {
        let mut commands = test_stage("open pre-freeze Fork retry sender", host.command_sender())?;
        let parent = test_stage(
            "create pre-freeze Fork parent",
            commands.create_timeline("pre-freeze-fork-parent"),
        )?;
        test_stage(
            "publish pre-freeze Fork parent",
            authority.set_timeline(parent.id()),
        )?;
        let operation = reference(45);
        let original_child = test_stage(
            "commit Fork before request submission",
            commands.fork_timeline_identified(
                operation,
                parent.id(),
                pos_core::Seq::ZERO,
                "pre-freeze-child",
            ),
        )?;
        let intervening = test_stage(
            "create an intervening unaffected timeline",
            commands.create_timeline("pre-freeze-intervening"),
        )?;
        test_stage(
            "classify intervening timeline as unaffected",
            authority.set_timeline_unaffected(intervening.id()),
        )?;
        match child_membership {
            LaterRequestChildMembership::Included => test_stage(
                "include pre-existing child in the later scope",
                authority.set_timeline(original_child.id()),
            )?,
            LaterRequestChildMembership::Unaffected => test_stage(
                "classify pre-existing child as unaffected",
                authority.set_timeline_unaffected(original_child.id()),
            )?,
        }

        let request = test_stage("construct request after Fork", persistence_request())?;
        let request_reference = request.reference();
        let request_provenance = request.provenance();
        test_stage(
            "submit request after Fork",
            commands.submit_erasure_request(request, request_provenance),
        )?;
        test_stage(
            "authorize request after Fork",
            commands.authorize_erasure_request(request_reference, reference(32)),
        )?;
        test_stage(
            "freeze parent while excluding pre-existing child",
            commands.freeze_access(request_reference, &freeze_transition()),
        )?;
        assert_retried_fork_membership(
            &mut commands,
            &authority,
            child_membership,
            operation,
            parent.id(),
            original_child.id(),
            intervening.id(),
        )?;
    }
    assert_eq!(host.status(), ErasureHostStatusV1::Ready);
    Ok(())
}

#[test]
fn exact_fork_retry_survives_later_request_excluding_child(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_exact_fork_retry_after_later_request(
        StoreConfig::Memory,
        LaterRequestChildMembership::Unaffected,
    )
}

#[test]
fn sqlite_exact_fork_retry_survives_later_request_excluding_child(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_exact_fork_retry_after_later_request(
        StoreConfig::SqliteInMemory,
        LaterRequestChildMembership::Unaffected,
    )
}

#[test]
fn exact_fork_retry_survives_later_request_including_child(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_exact_fork_retry_after_later_request(
        StoreConfig::Memory,
        LaterRequestChildMembership::Included,
    )
}

#[test]
fn sqlite_exact_fork_retry_survives_later_request_including_child(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_exact_fork_retry_after_later_request(
        StoreConfig::SqliteInMemory,
        LaterRequestChildMembership::Included,
    )
}
