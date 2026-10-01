use piglor_gateway::{Gateway, GatewayError};
use pos_core::geo_admission::{GeoLocationAdmissionInputV1, GeoLocationAdmissionRequestV1};
use pos_core::{CanonicalBytes, ConsentGrantedV1, ConsentRevokedV1, EntityId};
use pos_runtime::ErasureExecutionHostV1;
use pos_store::StoreConfig;

trait TestResultExt<T, E> {
    fn test_ok(self) -> Result<T, Box<dyn std::error::Error + Send + Sync>>;
}

impl<T, E: std::fmt::Debug> TestResultExt<T, E> for Result<T, E> {
    fn test_ok(self) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
        self.map_err(|error| format!("unexpected error: {error:?}").into())
    }
}

trait TestOptionExt<T> {
    fn test_ok(self) -> Result<T, Box<dyn std::error::Error + Send + Sync>>;
}

impl<T> TestOptionExt<T> for Option<T> {
    fn test_ok(self) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
        self.ok_or_else(|| "expected a value".into())
    }
}

#[tokio::test]
async fn gateway_reloads_durable_consent_before_revocation(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let database = tempfile::NamedTempFile::new().test_ok()?;
    let path = database.path().to_str().test_ok()?.to_owned();
    let first_host = ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Sqlite { path: path.clone() },
        pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
    )
    .test_ok()?;
    let first_gateway = Gateway::new_with_erasure_host(first_host)?;
    let timeline = first_gateway
        .create_timeline("consent-recovery")
        .await
        .test_ok()?;
    let subject_id = EntityId::new();
    let grant = ConsentGrantedV1 {
        subject_id,
        grantee_id: EntityId::new(),
        purpose: "gateway-recovery".to_owned(),
        modalities: pos_core::MODALITY_LOCATION,
        min_geo_resolution: 1,
        fork_permitted: false,
        export_permitted: false,
        retention_days: 0,
        expiry_secs: 0,
        grant_seq: 1,
    };
    let (grant_event, token) = first_gateway
        .issue_consent_grant(&timeline.id().to_string(), grant)
        .await
        .test_ok()?;
    drop(first_gateway);

    let recovered_host = ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Sqlite { path },
        pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
    )
    .test_ok()?;
    let recovered_gateway = Gateway::new_with_erasure_host(recovered_host)?;
    let unknown_error = recovered_gateway
        .issue_consent_revocation(
            &timeline.id().to_string(),
            ConsentRevokedV1 {
                subject_id: EntityId::new(),
                grantee_id: token.grantee_id(),
                grant_seq: token.grant_seq(),
                fence_seq: grant_event.seq.as_u64().saturating_add(1),
            },
        )
        .await;
    assert!(matches!(
        unknown_error,
        Err(GatewayError::Store(pos_core::CoreError::Storage(message)))
            if message == "consent revocation did not name an active grant"
    ));

    let revocation = recovered_gateway
        .issue_consent_revocation(
            &timeline.id().to_string(),
            ConsentRevokedV1 {
                subject_id,
                grantee_id: token.grantee_id(),
                grant_seq: token.grant_seq(),
                fence_seq: grant_event.seq.as_u64().saturating_add(1),
            },
        )
        .await
        .test_ok()?;
    assert_eq!(
        revocation.seq.as_u64(),
        grant_event.seq.as_u64().saturating_add(1)
    );
    drop(recovered_gateway);
    Ok(())
}

#[tokio::test]
async fn gateway_rejects_geo_admission_after_consent_revocation(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let host = ErasureExecutionHostV1::open_gateway_verified_empty(
        StoreConfig::Memory,
        pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
    )
    .test_ok()?;
    let gateway = Gateway::new_with_erasure_host(host)?;
    let timeline = gateway
        .create_timeline("geo-revocation-fence")
        .await
        .test_ok()?;
    let subject = EntityId::new();
    let grant = ConsentGrantedV1 {
        subject_id: subject,
        grantee_id: EntityId::new(),
        purpose: "geo-revocation-fence".to_owned(),
        modalities: pos_core::MODALITY_LOCATION,
        min_geo_resolution: 1,
        fork_permitted: false,
        export_permitted: false,
        retention_days: 1,
        expiry_secs: 0,
        grant_seq: 1,
    };
    let (grant_event, token) = gateway
        .issue_consent_grant(&timeline.id().to_string(), grant)
        .await
        .test_ok()?;
    gateway
        .issue_consent_revocation(
            &timeline.id().to_string(),
            ConsentRevokedV1 {
                subject_id: subject,
                grantee_id: token.grantee_id(),
                grant_seq: token.grant_seq(),
                fence_seq: grant_event.seq.as_u64().saturating_add(1),
            },
        )
        .await
        .test_ok()?;
    let request = GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
        timeline.id(),
        subject,
        CanonicalBytes::from_static(b"revoked-geo-payload"),
        1,
        ([1; 32], 1, [2; 32]),
        (1, false, 0),
        ([4; 32], [5; 32]),
    ));
    assert!(matches!(
        gateway
            .admit_geo_location_with_consent(request, &token, 0)
            .await,
        Err(GatewayError::Consent(pos_core::ConsentError::Revoked))
    ));
    gateway.shutdown().await.test_ok()?;
    drop(gateway);
    Ok(())
}
