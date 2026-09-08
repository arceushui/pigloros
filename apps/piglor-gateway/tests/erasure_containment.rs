use piglor_gateway::{Gateway, GatewayError};
use pos_core::{ErasureContainmentErrorV1, ErasureGate, ErasureProtectedOperationV1, TimelineId};
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
