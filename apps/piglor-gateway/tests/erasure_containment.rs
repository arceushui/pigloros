use piglor_gateway::{ActionPrincipal, Gateway, GatewayError};
use pos_core::{
    CanonicalBytes, EntityId, ErasureContainmentErrorV1, ErasureGate, ErasureProtectedOperationV1,
    Kind, ProposedAction, TimelineId,
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

    fn unblock(&self, operation: ErasureProtectedOperationV1) {
        self.blocked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|blocked| *blocked != operation);
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
async fn one_host_gate_covers_gateway_store_and_action_boundaries(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let actor = EntityId::new();
    let gate = Arc::new(SelectiveGate {
        blocked: Mutex::new(Vec::new()),
    });
    let gateway = Gateway::new_with_world_bodies_and_principal_and_erasure_gate(
        open_store(StoreConfig::Memory)?,
        [EntityId::new()],
        ActionPrincipal::new(actor, [Kind::new("world.action.submit")]),
        Arc::clone(&gate) as Arc<dyn ErasureGate>,
    )?;
    let timeline = gateway.create_timeline("shared-gate").await?;

    gate.block(ErasureProtectedOperationV1::Read);
    let read_error = gateway
        .read_events_page(&timeline.id().to_string(), 0, 1)
        .await
        .expect_err("the shared gate must fence EventStore reads");
    assert!(matches!(
        read_error,
        GatewayError::Store(pos_core::CoreError::ErasureAccessFrozen)
    ));

    gate.unblock(ErasureProtectedOperationV1::Read);
    gate.block(ErasureProtectedOperationV1::ProposedAction);
    let action_error = gateway
        .submit_proposed_action(
            &timeline.id().to_string(),
            ProposedAction::new(
                Kind::new("world.action"),
                actor,
                CanonicalBytes::from_static(b"payload"),
                Kind::new("world.action.submit"),
            ),
        )
        .await
        .expect_err("the shared gate must fence proposed actions");
    assert!(matches!(
        action_error,
        GatewayError::Store(pos_core::CoreError::ErasureAccessFrozen)
    ));

    gateway.shutdown().await?;
    Ok(())
}
