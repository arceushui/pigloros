use axum::{http::StatusCode, response::IntoResponse};
use piglor_gateway::{Gateway, GatewayError, OwnTracksOwnerKey};
use pos_core::{CoreError, TimelineId, ERASURE_MAX_INVENTORY_REQUESTS};
use pos_runtime::ErasureExecutionHostV1;
use pos_store::StoreConfig;

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
