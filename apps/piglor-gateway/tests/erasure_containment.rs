use axum::{http::StatusCode, response::IntoResponse};
use piglor_gateway::{Gateway, GatewayError, OwnTracksOwnerKey};
use pos_core::{
    CoreError, ErasureContainmentErrorV1, ErasureContainmentGateV1, ErasureGate,
    ErasureProtectedOperationV1, TimelineId,
};
use pos_store::{open_store, StoreConfig};
use std::sync::{Arc, Mutex};

struct SelectiveGate {
    blocked: Mutex<Vec<ErasureProtectedOperationV1>>,
}

impl SelectiveGate {
    fn block(&self, operation: ErasureProtectedOperationV1) {
        let mut blocked = self
            .blocked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !blocked.contains(&operation) {
            blocked.push(operation);
        }
    }

    fn authorize_operation(
        &self,
        operation: ErasureProtectedOperationV1,
    ) -> Result<(), ErasureContainmentErrorV1> {
        if self
            .blocked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&operation)
        {
            Err(ErasureContainmentErrorV1::AccessFrozen)
        } else {
            Ok(())
        }
    }
}

impl ErasureGate for SelectiveGate {
    fn authorize(
        &self,
        _timeline: TimelineId,
        operation: ErasureProtectedOperationV1,
    ) -> Result<(), ErasureContainmentErrorV1> {
        self.authorize_operation(operation)
    }

    fn with_fence(
        &self,
        timeline: TimelineId,
        operation: ErasureProtectedOperationV1,
        effect: &mut dyn FnMut(),
    ) -> Result<(), ErasureContainmentErrorV1> {
        self.authorize(timeline, operation)?;
        effect();
        Ok(())
    }
}

#[tokio::test]
async fn one_host_gate_covers_gateway_store_boundary(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let gate = Arc::new(SelectiveGate {
        blocked: Mutex::new(Vec::new()),
    });
    let gateway = Gateway::new_with_erasure_gate(
        open_store(StoreConfig::Memory)?,
        Arc::clone(&gate) as Arc<dyn ErasureGate>,
    )?;
    let timeline = gateway.create_timeline("shared-gate").await?;

    gate.block(ErasureProtectedOperationV1::Read);
    let Err(read_error) = gateway
        .read_events_page(&timeline.id().to_string(), 0, 1)
        .await
    else {
        return Err("the shared gate must fence EventStore reads".into());
    };
    assert!(matches!(
        read_error,
        GatewayError::Store(pos_core::CoreError::ErasureAccessFrozen)
    ));

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
    let geo_gateway = Gateway::new_with_geo_location_admission_and_erasure_gate(
        pos_store::memory::MemoryStore::default(),
        Arc::new(ErasureContainmentGateV1::new()),
    )?;
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
    let owntracks_gateway = Gateway::new_with_owntracks_ingress_and_erasure_gate(
        pos_store::sqlite::SqliteStore::open_in_memory()?,
        &owner_key,
        Arc::new(ErasureContainmentGateV1::new()),
    )?;
    owntracks_gateway.shutdown().await?;
    drop(owntracks_gateway);
    Ok(())
}
