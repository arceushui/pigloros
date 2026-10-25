//! Public type/ownership witnesses, not protected-store adapter conformance.

use pos_core::{CanonicalBytes, EntityId, FieldStateV1, TimelineId};
use pos_crypto::subject_field_read::{
    SubjectFieldOwnerReadErrorV1 as OuterError, SubjectFieldOwnerReadPortV1,
    SubjectFieldReadCallbackErrorV1 as CallbackError, SubjectFieldReadError as FieldError,
    SubjectFieldReadResultV1, SubjectFieldSelectorV1 as Selector,
};

struct OutcomeWitness {
    outcome: SubjectFieldReadResultV1,
    requested: Option<(TimelineId, EntityId, Selector)>,
}

impl SubjectFieldOwnerReadPortV1 for OutcomeWitness {
    fn with_subject_field_read(
        &mut self,
        timeline_id: TimelineId,
        subject_id: EntityId,
        field: Selector,
        deliver: &mut dyn FnMut(SubjectFieldReadResultV1) -> Result<(), CallbackError>,
    ) -> Result<(), OuterError> {
        self.requested = Some((timeline_id, subject_id, field));
        let outcome = std::mem::replace(&mut self.outcome, Err(FieldError::NoValue));
        deliver(outcome).map_err(|CallbackError::Failed| OuterError::CallbackFailed)
    }
}

struct RefusalWitness(OuterError);

impl SubjectFieldOwnerReadPortV1 for RefusalWitness {
    fn with_subject_field_read(
        &mut self,
        _: TimelineId,
        _: EntityId,
        _: Selector,
        _: &mut dyn FnMut(SubjectFieldReadResultV1) -> Result<(), CallbackError>,
    ) -> Result<(), OuterError> {
        Err(self.0)
    }
}

// Exhaustive client handling proves the public closed names/classifications are
// expressible. It does not prove a real adapter's delivery or quarantine behavior.
fn delivery_occurred(error: OuterError) -> bool {
    match error {
        OuterError::ContextQuarantined
        | OuterError::OperationActive
        | OuterError::ErasureFenced
        | OuterError::ErasureFencedTransactionFinishFailed
        | OuterError::ReadUnavailableBeforeDelivery
        | OuterError::TransactionFinishFailedBeforeDelivery => false,
        OuterError::CallbackFailed | OuterError::TransactionFinishFailedAfterDelivery => true,
    }
}

#[test]
fn dyn_port_transfers_all_five_outcomes_and_exact_selection() {
    let timeline = TimelineId::new();
    let subject = EntityId::new();
    let outcomes = [
        Ok(FieldStateV1::Present(CanonicalBytes::from_vec(
            b"caller owned".to_vec(),
        ))),
        Ok(FieldStateV1::RedactedDestroyed),
        Err(FieldError::KeyUnavailable),
        Err(FieldError::Integrity),
        Err(FieldError::NoValue),
    ];
    for outcome in outcomes {
        // This expected clone is a test oracle, released before consuming wipe.
        let expected = outcome.clone();
        let mut witness = OutcomeWitness {
            outcome,
            requested: None,
        };
        let port: &mut dyn SubjectFieldOwnerReadPortV1 = &mut witness;
        let mut received = None;
        let mut calls = 0;
        assert_eq!(
            port.with_subject_field_read(
                timeline,
                subject,
                Selector::PersonaPreferenceWeights,
                &mut |value| {
                    calls += 1;
                    received = Some(value);
                    Ok(())
                }
            ),
            Ok(())
        );
        assert_eq!(calls, 1);
        assert_eq!(received.as_ref(), Some(&expected));
        assert_eq!(
            witness.requested,
            Some((timeline, subject, Selector::PersonaPreferenceWeights))
        );
        drop(expected);
        if let Some(Ok(FieldStateV1::Present(value))) = received {
            assert_eq!(value.as_slice(), b"caller owned");
            assert_eq!(value.try_zeroize_owned(), Ok(()));
        }
    }
}

#[test]
fn callback_failure_can_retain_the_owned_present_value() {
    let mut witness = OutcomeWitness {
        outcome: Ok(FieldStateV1::Present(CanonicalBytes::from_vec(
            b"retained".to_vec(),
        ))),
        requested: None,
    };
    let port: &mut dyn SubjectFieldOwnerReadPortV1 = &mut witness;
    let mut received = None;
    let mut calls = 0;
    let result = port.with_subject_field_read(
        TimelineId::new(),
        EntityId::new(),
        Selector::PersonaPreferenceWeights,
        &mut |value| {
            calls += 1;
            received = Some(value);
            Err(CallbackError::Failed)
        },
    );
    assert_eq!(result, Err(OuterError::CallbackFailed));
    assert_eq!(calls, 1);
    assert!(delivery_occurred(OuterError::CallbackFailed));
    let Some(Ok(FieldStateV1::Present(value))) = received else {
        std::panic::resume_unwind(Box::new("expected retained Present"));
    };
    assert_eq!(value.as_slice(), b"retained");
    assert_eq!(value.try_zeroize_owned(), Ok(()));
}

#[test]
fn closed_outer_refusals_do_not_become_a_sixth_field_outcome() {
    for error in [
        OuterError::ContextQuarantined,
        OuterError::OperationActive,
        OuterError::ErasureFenced,
        OuterError::ErasureFencedTransactionFinishFailed,
        OuterError::ReadUnavailableBeforeDelivery,
        OuterError::TransactionFinishFailedBeforeDelivery,
    ] {
        let mut witness = RefusalWitness(error);
        let port: &mut dyn SubjectFieldOwnerReadPortV1 = &mut witness;
        let mut calls = 0;
        assert_eq!(
            port.with_subject_field_read(
                TimelineId::new(),
                EntityId::new(),
                Selector::PersonaPreferenceWeights,
                &mut |_| {
                    calls += 1;
                    Ok(())
                }
            ),
            Err(error)
        );
        assert_eq!(calls, 0);
        assert!(!delivery_occurred(error));
    }
    assert!(delivery_occurred(
        OuterError::TransactionFinishFailedAfterDelivery
    ));
}
