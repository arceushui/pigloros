use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::IntoResponse,
};
use piglor_gateway::{router, AppState, Gateway, GatewayError, LedgerWriteMode, OwnTracksOwnerKey};
use pos_core::{
    target_closure_digest, CoreError, ErasureAcknowledgementProvenanceV1,
    ErasureAdministrativeResolutionV1, ErasureAtomicFreezeAdmissionInputV1,
    ErasureAtomicFreezeResultV1, ErasureAuthorizationDecisionV1, ErasureCorrectionProvenanceV1,
    ErasureDestructionCommandV1, ErasureErrorV1, ErasureForkAdmissionInputV1,
    ErasureForkScopeRequirementV1, ErasureFreezeAdmissionEvidenceV1,
    ErasureFreezeAuthorizationEvidenceV1, ErasureFreezeAuthorizationVerifierV1, ErasureLifecycleV1,
    ErasureObligationSetInputV1, ErasureObligationSetV1, ErasureReceiptInputV1,
    ErasureRecoveryAuthorizationVerifierV1, ErasureReferenceV1, ErasureRequestV1,
    ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1, ErasureScopeExtensionInputV1,
    ErasureScopeExtensionV1, ErasureStateTransitionV1, ErasureVerifiedTopologyObservationV1,
    TimelineId, ERASURE_MAX_INVENTORY_REQUESTS,
};
use pos_runtime::{
    ErasureCoordinatorAuthorityV1, ErasureCoordinatorCompositionV1, ErasureExecutionHostV1,
};
use pos_store::StoreConfig;
use std::sync::Arc;
use tower::ServiceExt;

#[path = "../../../crates/pos-core/tests/support/erasure.rs"]
mod erasure_support;

use erasure_support::{
    freeze_evidence_fixture, obligation, persistence_request, persistence_target, reference,
    FreezeEvidenceFixtureInput,
};

#[derive(Default)]
struct HealthAuthority;

impl ErasureFreezeAuthorizationVerifierV1 for HealthAuthority {
    fn validate_freeze_authorization(
        &self,
        admission: &ErasureFreezeAdmissionEvidenceV1,
        authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        authorization.verify_admission_body_binding(admission)
    }
}

impl ErasureRecoveryAuthorizationVerifierV1 for HealthAuthority {
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

impl ErasureCoordinatorAuthorityV1 for HealthAuthority {
    fn verified_topology_observation(
        &self,
        _request: ErasureReferenceV1,
        manifest_digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureVerifiedTopologyObservationV1>, ErasureErrorV1> {
        Ok(Some(ErasureVerifiedTopologyObservationV1::new(
            manifest_digest,
            Vec::new(),
            Vec::new(),
        )))
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
        _correction: &ErasureCorrectionProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
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
                .map(pos_core::ErasureObligationV1::reference)
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
        let scope_commitment = ErasureScopeCommitmentV1::new(scope.clone())?;
        let freeze_position = requested
            .freeze_position
            .ok_or(ErasureErrorV1::ScopeInvalid)?;
        let evidence = requested.provenance.digest();
        let (freeze_admission_evidence, freeze_authorization_evidence) =
            freeze_evidence_fixture(FreezeEvidenceFixtureInput {
                request,
                scope_commitment: scope_commitment.reference(),
                obligation_set: &obligation_set,
                targets: &targets,
                obligations: &obligations,
                freeze_position,
                evidence: &evidence,
            })?;
        ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
            targets,
            scope,
            obligations,
            obligation_set,
            freeze_position,
            freeze_admission_evidence,
            freeze_authorization_evidence,
        })
        .map(|admission| ErasureAtomicFreezeResultV1::Admitted(Box::new(admission)))
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
        _child: &pos_core::TimelineMeta,
    ) -> Result<ErasureReferenceV1, ErasureErrorV1> {
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
        Ok(())
    }

    fn dispatch_destruction(
        &self,
        _request: ErasureReferenceV1,
        _commands: &[ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_attempt(
        &self,
        admission: &pos_core::ErasureRetryAdmissionV1,
    ) -> Result<pos_core::ErasureAttemptQuotaReservationV1, ErasureErrorV1> {
        Ok(pos_core::ErasureAttemptQuotaReservationV1::new(
            admission.reference(),
            reference(50),
        ))
    }

    fn admit_acknowledgement(
        &self,
        _acknowledgement: &ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_receipt(&self, _input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
}

const fn freeze_transition() -> ErasureStateTransitionV1 {
    ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::AccessFrozen,
        freeze_position: Some(10),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: Vec::new(),
        replay_claim: pos_core::ErasureReplayClaimV1::Exact,
        provenance: reference(11),
    }
}

#[tokio::test]
async fn host_owned_gateway_covers_store_boundary(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let host = ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Memory,
        ERASURE_MAX_INVENTORY_REQUESTS,
    )?;
    let gateway = Gateway::new_with_erasure_host(host)?;
    let timeline = gateway.create_timeline("shared-gate").await?;
    assert!(gateway
        .read_events_page(&timeline.id().to_string(), 0, 1)
        .await?
        .events
        .is_empty());

    gateway.shutdown().await?;
    drop(gateway);
    Ok(())
}

#[tokio::test]
async fn recovered_access_frozen_gateway_health_is_payload_free(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("gateway.db");
    let config = || StoreConfig::Sqlite {
        path: path.to_string_lossy().into_owned(),
    };
    let authority: Arc<dyn ErasureCoordinatorAuthorityV1> = Arc::new(HealthAuthority);
    let composition = ErasureCoordinatorCompositionV1::new(authority, reference(30));
    let request = persistence_request()?;
    let mut initial = ErasureExecutionHostV1::open_gateway_with_authority(
        config(),
        &composition,
        ERASURE_MAX_INVENTORY_REQUESTS,
    )?;
    {
        let mut commands = initial.command_sender()?;
        commands.submit_erasure_request(request.clone(), request.provenance())?;
        commands.authorize_erasure_request(request.reference(), reference(32))?;
        commands.freeze_access(request.reference(), &freeze_transition())?;
    }
    {
        let mut reads = initial.read_sender()?;
        let history = reads
            .erasure_state_history(request.reference())?
            .ok_or("initial AccessFrozen state was not persisted")?;
        assert_eq!(history[0].lifecycle(), ErasureLifecycleV1::AccessFrozen);
    }
    drop(initial);

    let mut recovered = ErasureExecutionHostV1::open_gateway_with_authority(
        config(),
        &composition,
        ERASURE_MAX_INVENTORY_REQUESTS,
    )?;
    {
        let mut reads = recovered.read_sender()?;
        let history = reads
            .erasure_state_history(request.reference())?
            .ok_or("recovered AccessFrozen state was not persisted")?;
        assert_eq!(history[0].lifecycle(), ErasureLifecycleV1::AccessFrozen);
    }
    let gateway = Gateway::new_with_erasure_host(recovered)?;
    let response = router(AppState {
        gateway: gateway.clone(),
        ledger_view: piglor_ledger::LedgerView::default(),
        ledger_write: LedgerWriteMode::Disabled,
    })
    .oneshot(Request::builder().uri("/health").body(Body::empty())?)
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 4_096).await?;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body)?,
        serde_json::json!({"ok": true})
    );
    gateway.shutdown().await?;
    Ok(())
}

#[test]
fn gateway_maps_erasure_store_errors_to_http_statuses() {
    let cases = [
        (CoreError::ErasureAccessFrozen, StatusCode::FORBIDDEN),
        (
            CoreError::TimelineNotFound(TimelineId::new()),
            StatusCode::NOT_FOUND,
        ),
        (
            CoreError::ErasureContainmentUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            CoreError::Storage("storage failure".to_owned()),
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(
            GatewayError::Store(error).into_response().status(),
            expected
        );
    }
}

#[tokio::test]
async fn specialized_gate_gateway_constructors_bind_and_shutdown(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let geo_host = ErasureExecutionHostV1::open_gateway_verified_empty(
        StoreConfig::Memory,
        ERASURE_MAX_INVENTORY_REQUESTS,
    )?;
    let geo_gateway = Gateway::new_with_erasure_host(geo_host)?;
    geo_gateway.shutdown().await?;
    drop(geo_gateway);

    let directory = tempfile::tempdir()?;
    let owner_key_path = directory.path().join("owner.key");
    std::fs::write(&owner_key_path, [7_u8; 32])?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&owner_key_path, std::fs::Permissions::from_mode(0o600))?;
    }
    let owner_key = OwnTracksOwnerKey::load(&owner_key_path)?;

    assert!(ErasureExecutionHostV1::open_verified_empty(StoreConfig::Memory, 0).is_err());
    assert!(ErasureExecutionHostV1::open_gateway_verified_empty(StoreConfig::Memory, 0).is_err());

    let owntracks_host = ErasureExecutionHostV1::open_gateway_verified_empty(
        StoreConfig::SqliteInMemory,
        ERASURE_MAX_INVENTORY_REQUESTS,
    )?;
    let owntracks_gateway = Gateway::new_with_owntracks_erasure_host(owntracks_host, &owner_key)?;
    owntracks_gateway.shutdown().await?;
    drop(owntracks_gateway);
    Ok(())
}
