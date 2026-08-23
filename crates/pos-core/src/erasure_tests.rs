fn test_uint(value: u64) -> Value {
    Value::Integer(value.into())
}
fn test_digest(reference: ErasureReferenceV1) -> Value {
    Value::Bytes(reference.digest().to_vec())
}
fn test_text(value: &str) -> Value {
    Value::Text(value.to_owned())
}
use super::*;
use ciborium::value::Value;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone)]
struct TestCoordinatorPort {
    accepted: bool,
    acknowledgement_admitted: bool,
    targets: Vec<ErasureRequiredTargetV1>,
    records: Rc<RefCell<Vec<ErasureCoordinatorRecordV1>>>,
}
struct TestResolver {
    states: Vec<ErasureStateV1>,
    unavailable: bool,
}
impl ErasureStateResolverV1 for TestResolver {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
        if self.unavailable {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        Ok(self
            .states
            .iter()
            .find(|state| state.state_digest() == digest)
            .cloned())
    }
}
impl ErasureCoordinatorPortV1 for TestCoordinatorPort {
    fn authenticate(&self, _request: &ErasureRequestV1) -> Result<(), ErasureErrorV1> {
        if self.accepted {
            Ok(())
        } else {
            Err(ErasureErrorV1::Unauthorized)
        }
    }
    fn required_targets(
        &self,
        _request: ErasureReferenceV1,
    ) -> Result<Vec<ErasureRequiredTargetV1>, ErasureErrorV1> {
        Ok(self.targets.clone())
    }
    fn dispatch_destruction(
        &self,
        _request: ErasureReferenceV1,
        _targets: &[ErasureRequiredTargetV1],
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
    fn admit_acknowledgement(
        &self,
        _request: ErasureReferenceV1,
        _acknowledgement: &ErasureAcknowledgementV1,
    ) -> Result<(), ErasureErrorV1> {
        if self.acknowledgement_admitted {
            Ok(())
        } else {
            Err(ErasureErrorV1::Unauthorized)
        }
    }
    fn admit_receipt(&self, _input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
    fn load_record(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<ErasureCoordinatorRecordV1>, ErasureErrorV1> {
        Ok(self
            .records
            .borrow()
            .iter()
            .find(|record| record.request.reference() == request)
            .cloned())
    }
    fn commit_record(&mut self, record: ErasureCoordinatorRecordV1) -> Result<(), ErasureErrorV1> {
        let mut records = self.records.borrow_mut();
        if let Some(existing) = records
            .iter_mut()
            .find(|existing| existing.request.reference() == record.request.reference())
        {
            *existing = record;
        } else {
            records.push(record);
        }
        Ok(())
    }
}
fn test_port(accepted: bool, targets: Vec<ErasureRequiredTargetV1>) -> TestCoordinatorPort {
    TestCoordinatorPort {
        accepted,
        acknowledgement_admitted: true,
        targets,
        records: Rc::new(RefCell::new(Vec::new())),
    }
}
fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}
fn indexed_reference(index: usize) -> ErasureReferenceV1 {
    let mut digest = [0; 32];
    let index = index.to_be_bytes();
    digest[32 - index.len()..].copy_from_slice(&index);
    ErasureReferenceV1::from_digest(digest)
}
fn references(count: usize) -> Vec<ErasureReferenceV1> {
    (0..count).map(indexed_reference).collect()
}
fn request_input(selectors: Vec<ErasureReferenceV1>) -> ErasureRequestInputV1 {
    ErasureRequestInputV1 {
        request: reference(1),
        subject: reference(2),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors,
        requester: reference(3),
        authorization: reference(4),
        policy: reference(5),
        request_position: 9,
        horizon_position: 10,
        provenance: reference(6),
    }
}
fn request() -> Result<ErasureRequestV1, ErasureErrorV1> {
    ErasureRequestV1::new(request_input(vec![reference(8), reference(7)]))
}
fn change(
    lifecycle: ErasureLifecycleV1,
    freeze_position: Option<u64>,
    pending_owners: Vec<ErasureReferenceV1>,
    failed_owners: Vec<ErasureReferenceV1>,
) -> ErasureStateTransitionV1 {
    ErasureStateTransitionV1 {
        lifecycle,
        freeze_position,
        pending_owners,
        failed_owners,
        acknowledged_targets: Vec::new(),
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        provenance: reference(9),
    }
}
fn acknowledgement(
    owner: u8,
    outcome: ErasureAcknowledgementOutcomeV1,
) -> ErasureAcknowledgementV1 {
    ErasureAcknowledgementV1 {
        target: ErasureRequiredTargetV1 {
            artifact_class: ErasureArtifactClassV1::TimelineReplay,
            artifact_digest: reference(owner),
            key_role: ErasureKeyRoleV1::DataEncryption,
            key_digest: reference(owner + 10),
            replica_set: reference(owner + 30),
            replica_id: reference(owner + 40),
        },
        owner: reference(owner + 40),
        evidence: reference(owner + 20),
        outcome,
    }
}
fn inventory_result(target: ErasureRequiredTargetV1) -> ErasureInventoryResultV1 {
    ErasureInventoryResultV1 {
        category: ErasureInventoryCategoryV1::Artifact,
        target,
        transition: ErasureArtifactTransitionV1 {
            from: ErasureReplayClaimV1::Exact,
            to: ErasureReplayClaimV1::StructuralOnly,
            reason: reference(50),
            owner: reference(51),
            acknowledgements: reference(52),
            provenance: reference(53),
        },
        retained_disclosure: reference(54),
    }
}
fn receipt_input(
    lifecycle: ErasureLifecycleV1,
    acknowledgements: Vec<ErasureAcknowledgementV1>,
    pending_owners: Vec<ErasureReferenceV1>,
    failed_owners: Vec<ErasureReferenceV1>,
) -> ErasureReceiptInputV1 {
    let required_targets = acknowledgements
        .iter()
        .map(|acknowledgement| acknowledgement.target)
        .collect();
    let artifacts = acknowledgements
        .iter()
        .map(|acknowledgement| inventory_result(acknowledgement.target))
        .collect();
    ErasureReceiptInputV1 {
        request: reference(1),
        terminal_state: reference(6),
        coordinator: reference(2),
        lifecycle,
        freeze_position: 10,
        required_targets,
        acknowledgements,
        pending_owners,
        failed_owners,
        inventories: ErasureReceiptInventoriesV1 {
            artifacts,
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        },
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        policy: reference(2),
        trust: reference(3),
        provenance: reference(4),
        issue_position: 11,
        signature: reference(5),
        receipt_digest: reference(0),
    }
}
fn receipt() -> Result<ErasureReceiptV1, ErasureErrorV1> {
    ErasureReceiptV1::new(receipt_input(
        ErasureLifecycleV1::Complete,
        vec![
            acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged),
            acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged),
        ],
        Vec::new(),
        Vec::new(),
    ))
}
fn dispatched() -> Result<ErasureStateV1, ErasureErrorV1> {
    ErasureStateV1::submitted(reference(1), reference(2), reference(3))?
        .transition(change(
            ErasureLifecycleV1::Authorized,
            None,
            Vec::new(),
            Vec::new(),
        ))?
        .transition(change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ))?
        .transition(change(
            ErasureLifecycleV1::DestructionDispatched,
            Some(10),
            Vec::new(),
            Vec::new(),
        ))
}
fn decode_request(value: &Value) -> Result<ErasureRequestV1, ErasureErrorV1> {
    ErasureRequestV1::from_canonical_cbor(&public_value_bytes(value)?)
}
fn decode_state(value: &Value) -> Result<ErasureStateV1, ErasureErrorV1> {
    ErasureStateV1::from_canonical_cbor(&public_value_bytes(value)?)
}
fn decode_receipt(value: &Value) -> Result<ErasureReceiptV1, ErasureErrorV1> {
    ErasureReceiptV1::from_canonical_cbor(&public_value_bytes(value)?)
}
fn public_value_bytes(value: &Value) -> Result<Vec<u8>, ErasureErrorV1> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    Ok(bytes)
}
fn public_request_value(request: &ErasureRequestV1) -> Result<Value, ErasureErrorV1> {
    ciborium::from_reader(request.to_canonical_cbor()?.as_slice())
        .map_err(|_| ErasureErrorV1::InvalidEncoding)
}
fn public_state_value(state: &ErasureStateV1) -> Result<Value, ErasureErrorV1> {
    ciborium::from_reader(state.to_canonical_cbor()?.as_slice())
        .map_err(|_| ErasureErrorV1::InvalidEncoding)
}
fn public_receipt_value(receipt: &ErasureReceiptV1) -> Result<Value, ErasureErrorV1> {
    ciborium::from_reader(receipt.to_canonical_cbor()?.as_slice())
        .map_err(|_| ErasureErrorV1::InvalidEncoding)
}
#[test]
fn coordinator_public_retries_reject_injection_and_query_existing() -> Result<(), ErasureErrorV1> {
    let acknowledgement = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![acknowledgement.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    let submitted = coordinator.submit(request()?, reference(3))?;
    assert_eq!(coordinator.submit(request()?, reference(3))?, submitted);
    assert_eq!(coordinator.existing(reference(1)), Some(&submitted));
    Ok(())
}
#[test]
fn coordinator_reloads_durable_identity_after_restart() -> Result<(), ErasureErrorV1> {
    let port = test_port(true, Vec::new());
    let restart_port = port.clone();
    let request = request()?;
    let mut first = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    let submitted = first.submit(request.clone(), reference(3))?;
    drop(first);
    let mut restarted = ErasureCoordinatorStateMachineV1::new(restart_port, reference(2));
    assert_eq!(restarted.submit(request, reference(99))?, submitted);
    Ok(())
}
#[test]
fn coordinator_freezes_closure_and_commits_only_derived_terminal_outcomes(
) -> Result<(), ErasureErrorV1> {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![ack.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    let frozen = coordinator.freeze_inventory(
        reference(1),
        change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            change(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        )?,
        frozen
    );
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    assert_eq!(
        coordinator.acknowledge(reference(1), ack)?,
        coordinator.acknowledge(reference(1), ack)?
    );
    let injected = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged);
    assert_eq!(
        coordinator.acknowledge(reference(1), injected),
        Err(ErasureErrorV1::Unauthorized)
    );
    let mut conflicting = ack;
    conflicting.outcome = ErasureAcknowledgementOutcomeV1::Negative;
    assert_eq!(
        coordinator.acknowledge(reference(1), conflicting),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let mut complete_input = receipt_input(
        ErasureLifecycleV1::PartialFailure,
        Vec::new(),
        vec![reference(9)],
        Vec::new(),
    );
    complete_input.inventories.artifacts = vec![inventory_result(ack.target)];
    complete_input.replay_claim = ErasureReplayClaimV1::Exact;
    let committed = coordinator.finalize(reference(1), complete_input.clone())?;
    assert_eq!(committed.lifecycle(), ErasureLifecycleV1::Complete);
    assert_eq!(
        committed.replay_claim(),
        ErasureReplayClaimV1::StructuralOnly
    );
    assert_eq!(
        coordinator.finalize(reference(1), complete_input)?,
        committed
    );
    assert_eq!(
        coordinator
            .existing(reference(1))
            .map(ErasureStateV1::lifecycle),
        Some(ErasureLifecycleV1::Complete)
    );
    Ok(())
}
#[test]
fn coordinator_derives_partial_failure_for_a_missing_frozen_target() -> Result<(), ErasureErrorV1> {
    let missing = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![missing.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    let mut input = receipt_input(
        ErasureLifecycleV1::Complete,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    input.inventories.artifacts = vec![inventory_result(missing.target)];
    assert_eq!(
        coordinator.finalize(reference(1), input)?.lifecycle(),
        ErasureLifecycleV1::PartialFailure
    );
    Ok(())
}
#[test]
fn coordinator_rejects_premature_finalize_and_preserves_awaiting_acknowledgements(
) -> Result<(), ErasureErrorV1> {
    let first = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut second = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged);
    second.owner = second.target.replica_id;
    let port = test_port(true, vec![first.target, second.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    assert_eq!(
        coordinator.finalize(
            reference(1),
            receipt_input(
                ErasureLifecycleV1::Complete,
                vec![first],
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    coordinator.acknowledge(reference(1), first)?;
    assert_eq!(
        coordinator.acknowledge(reference(1), second)?.lifecycle(),
        ErasureLifecycleV1::AwaitingAcknowledgements
    );
    Ok(())
}
#[test]
fn coordinator_rejects_unauthenticated_submission_and_unsupported_version(
) -> Result<(), ErasureErrorV1> {
    let port = test_port(false, Vec::new());
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    assert_eq!(
        coordinator.submit(request()?, reference(3)),
        Err(ErasureErrorV1::Unauthorized)
    );
    let mut value = public_receipt_value(&receipt()?)?;
    let Value::Array(fields) = &mut value else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    fields[1] = test_uint(2);
    assert_eq!(
        decode_receipt(&value),
        Err(ErasureErrorV1::UnsupportedVersion)
    );
    Ok(())
}
#[test]
fn receipt_history_requires_a_resolved_monotonic_terminal_chain() -> Result<(), ErasureErrorV1> {
    let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let authorized = submitted.transition(change(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let frozen = authorized.transition(change(
        ErasureLifecycleV1::AccessFrozen,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let dispatched = frozen.transition(change(
        ErasureLifecycleV1::DestructionDispatched,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let waiting = dispatched.transition(change(
        ErasureLifecycleV1::AwaitingAcknowledgements,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let terminal = waiting.transition(ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: Some(10),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: vec![
            acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target,
        ],
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        provenance: reference(9),
    })?;
    let mut input = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![acknowledgement(
            1,
            ErasureAcknowledgementOutcomeV1::Acknowledged,
        )],
        Vec::new(),
        Vec::new(),
    );
    input.terminal_state = terminal.state_digest();
    let receipt = ErasureReceiptV1::new(input)?;
    assert_eq!(
        receipt.verify_history(&TestResolver {
            states: vec![terminal.clone()],
            unavailable: false,
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let resolver = TestResolver {
        states: vec![submitted, authorized, frozen, dispatched, waiting, terminal],
        unavailable: false,
    };
    receipt.verify_history(&resolver)?;
    assert_eq!(
        receipt.verify_history(&TestResolver {
            states: Vec::new(),
            unavailable: false,
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        receipt.verify_history(&TestResolver {
            states: Vec::new(),
            unavailable: true,
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}
#[test]
fn receipt_inventory_codes_and_strict_decoder_paths_are_publicly_exercised(
) -> Result<(), ErasureErrorV1> {
    let mut acknowledgements = vec![
        acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged),
        acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged),
        acknowledgement(3, ErasureAcknowledgementOutcomeV1::Acknowledged),
        acknowledgement(4, ErasureAcknowledgementOutcomeV1::Acknowledged),
        acknowledgement(5, ErasureAcknowledgementOutcomeV1::Acknowledged),
        acknowledgement(6, ErasureAcknowledgementOutcomeV1::Acknowledged),
        acknowledgement(7, ErasureAcknowledgementOutcomeV1::Acknowledged),
    ];
    acknowledgements[1].target.artifact_class = ErasureArtifactClassV1::ReproManifest;
    acknowledgements[1].target.key_role = ErasureKeyRoleV1::Signing;
    acknowledgements[2].target.artifact_class = ErasureArtifactClassV1::CausalTrace;
    acknowledgements[2].target.key_role = ErasureKeyRoleV1::BackupEnvelope;
    acknowledgements[3].target.artifact_class = ErasureArtifactClassV1::ConformanceReport;
    acknowledgements[3].target.key_role = ErasureKeyRoleV1::ReplicaTransport;
    acknowledgements[4].target.artifact_class = ErasureArtifactClassV1::CalibrationReport;
    acknowledgements[5].target.artifact_class = ErasureArtifactClassV1::Export;
    acknowledgements[6].target.artifact_class = ErasureArtifactClassV1::ForkOrSnapshot;
    let mut input = receipt_input(
        ErasureLifecycleV1::Complete,
        acknowledgements.clone(),
        Vec::new(),
        Vec::new(),
    );
    input.inventories.artifacts = vec![
        inventory_result(acknowledgements[0].target),
        inventory_result(acknowledgements[4].target),
        inventory_result(acknowledgements[5].target),
        inventory_result(acknowledgements[6].target),
    ];
    input.inventories.keys = vec![inventory_result(acknowledgements[1].target)];
    input.inventories.keys[0].category = ErasureInventoryCategoryV1::Key;
    input.inventories.replicas = vec![inventory_result(acknowledgements[2].target)];
    input.inventories.replicas[0].category = ErasureInventoryCategoryV1::Replica;
    input.inventories.backups = vec![inventory_result(acknowledgements[3].target)];
    input.inventories.backups[0].category = ErasureInventoryCategoryV1::Backup;
    let expected = ErasureReceiptV1::new(input)?;
    let encoded = expected.to_canonical_cbor()?;
    assert_eq!(ErasureReceiptV1::from_canonical_cbor(&encoded)?, expected);
    let mut unknown_codes =
        public_receipt_value(&ErasureReceiptV1::from_canonical_cbor(&encoded)?)?;
    let mut tampered_digest = unknown_codes.clone();
    let Value::Array(fields) = &mut tampered_digest else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    fields[16] = test_digest(reference(99));
    assert_eq!(
        decode_receipt(&tampered_digest),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let Value::Array(fields) = &mut unknown_codes else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(targets) = &mut fields[6] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(target) = &mut targets[0] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    target[0] = test_uint(7);
    assert_eq!(
        decode_receipt(&unknown_codes),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let mut unknown_role = public_receipt_value(&ErasureReceiptV1::from_canonical_cbor(&encoded)?)?;
    let Value::Array(fields) = &mut unknown_role else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(targets) = &mut fields[6] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(target) = &mut targets[0] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    target[2] = test_uint(4);
    assert_eq!(
        decode_receipt(&unknown_role),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let mut unordered_targets =
        public_receipt_value(&ErasureReceiptV1::from_canonical_cbor(&encoded)?)?;
    let Value::Array(fields) = &mut unordered_targets else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(targets) = &mut fields[6] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    targets.swap(0, 1);
    assert_eq!(
        decode_receipt(&unordered_targets),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        ErasureReceiptV1::from_canonical_cbor(&trailing),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let noncanonical = [&[0x98, 18][..], &encoded[1..]].concat();
    assert_eq!(
        ErasureReceiptV1::from_canonical_cbor(&noncanonical),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    for invalid in [
        &[0x9f, 0xff][..],
        &[0xbf, 0xff][..],
        &[0x19, 0, 1][..],
        &[0x1b, 0, 0, 0, 0, 0, 0, 0, 1][..],
        &[0x9a, 0xff, 0xff, 0xff, 0xff][..],
        &[
            0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81,
            0x81, 0x81, 0x81, 0x00,
        ][..],
    ] {
        assert_eq!(
            ErasureReceiptV1::from_canonical_cbor(invalid),
            Err(ErasureErrorV1::InvalidEncoding)
        );
    }
    Ok(())
}
#[test]
fn coordinator_and_receipt_reject_each_public_injected_or_stale_seam() -> Result<(), ErasureErrorV1>
{
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![ack.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    assert_eq!(
        coordinator
            .authorize(reference(1), reference(9))?
            .lifecycle(),
        ErasureLifecycleV1::Authorized
    );
    let frozen = coordinator.freeze_inventory(
        reference(1),
        change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    assert_eq!(frozen.lifecycle(), ErasureLifecycleV1::AccessFrozen);
    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            change(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        )?,
        frozen
    );
    assert_eq!(
        coordinator.acknowledge(reference(1), ack),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        coordinator.finalize(
            reference(1),
            receipt_input(
                ErasureLifecycleV1::Complete,
                vec![ack],
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let mut stale_issue = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    stale_issue.issue_position = 9;
    assert_eq!(
        ErasureReceiptV1::new(stale_issue),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let mut invented_ack = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    invented_ack.acknowledgements[0].target =
        acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
    assert_eq!(
        ErasureReceiptV1::new(invented_ack),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut mismatched_owner = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    mismatched_owner.acknowledgements[0].owner = reference(99);
    assert_eq!(
        ErasureReceiptV1::new(mismatched_owner),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut missing_inventory = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    missing_inventory.inventories.artifacts.clear();
    assert_eq!(
        ErasureReceiptV1::new(missing_inventory),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut oversized = receipt_input(
        ErasureLifecycleV1::PartialFailure,
        Vec::new(),
        vec![reference(8)],
        Vec::new(),
    );
    oversized.acknowledgements = vec![ack; ERASURE_MAX_INVENTORY_RESULTS + 1];
    assert_eq!(
        ErasureReceiptV1::new(oversized),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut strengthened = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![ack],
        Vec::new(),
        Vec::new(),
    );
    strengthened.inventories.artifacts[0].transition.from = ErasureReplayClaimV1::StructuralOnly;
    strengthened.inventories.artifacts[0].transition.to = ErasureReplayClaimV1::Exact;
    assert_eq!(
        ErasureReceiptV1::new(strengthened),
        Err(ErasureErrorV1::PolicyConflict)
    );
    for invalid in [&[0x18, 0][..], &[0x1a, 0, 0, 0, 1][..], &[0x60, 0][..]] {
        assert_eq!(
            ErasureReceiptV1::from_canonical_cbor(invalid),
            Err(ErasureErrorV1::InvalidEncoding)
        );
    }
    Ok(())
}
#[test]
fn coordinator_requires_host_admission_for_acknowledgements() -> Result<(), ErasureErrorV1> {
    let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let mut port = test_port(true, vec![ack.target]);
    port.acknowledgement_admitted = false;
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    coordinator.freeze_inventory(
        reference(1),
        change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ),
    )?;
    coordinator.dispatch_destruction(reference(1), reference(9))?;
    assert_eq!(
        coordinator.acknowledge(reference(1), ack),
        Err(ErasureErrorV1::Unauthorized)
    );
    Ok(())
}
#[test]
fn public_erasure_failure_seams_cover_history_ordering_and_cbor_tails() -> Result<(), ErasureErrorV1>
{
    let receipt = receipt()?;
    assert_eq!(
        receipt.verify_history(&TestResolver {
            states: Vec::new(),
            unavailable: false,
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(
        receipt.verify_history(&TestResolver {
            states: Vec::new(),
            unavailable: true,
        }),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    let mut unordered = public_receipt_value(&receipt)?;
    let Value::Array(fields) = &mut unordered else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(inventories) = &mut fields[10] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    let Value::Array(artifacts) = &mut inventories[0] else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    artifacts.push(artifacts[0].clone());
    assert_eq!(
        decode_receipt(&unordered),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    for malformed in [
        &[0x58, 1][..],
        &[0x81, 0x58, 2, 0][..],
        &[0x81, 0x1a, 0, 0, 0][..],
        &[0x81, 0x58, 2, 0, 0][..],
        &[0x81, 0x1b, 0, 0, 0, 0, 0, 0, 0, 1][..],
        &[0x81, 0x78, 2, 0][..],
        &[0x81, 0x98, 24][..],
        &[0x81, 0x7f, 0xff][..],
    ] {
        assert_eq!(
            ErasureReceiptV1::from_canonical_cbor(malformed),
            Err(ErasureErrorV1::InvalidEncoding)
        );
    }
    Ok(())
}
#[test]
fn request_is_canonical_and_bounded() -> Result<(), ErasureErrorV1> {
    let first = request()?;
    let second = ErasureRequestV1::new(request_input(vec![reference(7), reference(8)]))?;
    let bytes = first.to_canonical_cbor()?;
    assert_eq!(bytes, second.to_canonical_cbor()?);
    assert_eq!(ErasureRequestV1::from_canonical_cbor(&bytes)?, first);
    assert_eq!(first.reference(), reference(1));
    assert_eq!(
        ErasureRequestV1::new(request_input(Vec::new())),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureRequestV1::new(request_input(vec![reference(7), reference(7)])),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut impossible = request_input(vec![reference(7)]);
    impossible.request_position = 11;
    assert_eq!(
        ErasureRequestV1::new(impossible),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}
#[test]
fn public_constants_display_and_state_digests_are_observable() -> Result<(), ErasureErrorV1> {
    assert_eq!(ERASURE_REQUEST_OR_STATE_MAX_BYTES, 1_048_576);
    assert_eq!(ERASURE_RECEIPT_MAX_BYTES, 16_777_216);
    assert_eq!(
        ErasureErrorV1::PolicyConflict.to_string(),
        "erasure contract error 4"
    );
    let first = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let second = ErasureStateV1::submitted(reference(4), reference(2), reference(3))?;
    assert_ne!(first.state_digest(), second.state_digest());
    Ok(())
}
#[test]
fn codecs_refuse_trailing_unknown_and_maps() -> Result<(), ErasureErrorV1> {
    let mut trailing = request()?.to_canonical_cbor()?;
    trailing.push(0);
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&trailing),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    let mut unsupported = public_request_value(&request()?)?;
    let Value::Array(fields) = &mut unsupported else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    fields[1] = test_uint(2);
    let mut bytes = Vec::new();
    ciborium::into_writer(&unsupported, &mut bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&bytes),
        Err(ErasureErrorV1::UnsupportedVersion)
    );
    let map = Value::Map(vec![(test_text("request"), test_digest(reference(1)))]);
    let mut map_bytes = Vec::new();
    ciborium::into_writer(&map, &mut map_bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&map_bytes),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}
#[test]
fn decoders_refuse_unknown_closed_codes() -> Result<(), ErasureErrorV1> {
    let mut invalid_scope = public_request_value(&request()?)?;
    {
        let Value::Array(fields) = &mut invalid_scope else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[4] = test_uint(5);
    }
    assert_eq!(
        decode_request(&invalid_scope),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let mut invalid_lifecycle = public_state_value(&submitted)?;
    {
        let Value::Array(fields) = &mut invalid_lifecycle else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[3] = test_uint(8);
    }
    assert_eq!(
        decode_state(&invalid_lifecycle),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let mut invalid_claim = public_state_value(&submitted)?;
    {
        let Value::Array(fields) = &mut invalid_claim else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[8] = test_uint(5);
    }
    assert_eq!(
        decode_state(&invalid_claim),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let canonical = receipt()?;
    let mut invalid_outcome = public_receipt_value(&canonical)?;
    {
        let Value::Array(fields) = &mut invalid_outcome else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        let Value::Array(acknowledgements) = &mut fields[7] else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        let Value::Array(acknowledgement) = &mut acknowledgements[0] else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        acknowledgement[3] = test_uint(3);
    }
    assert_eq!(
        decode_receipt(&invalid_outcome),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}
#[test]
fn request_decoder_refuses_noncanonical_and_wrong_shapes() -> Result<(), ErasureErrorV1> {
    let mut wrong_tag_type = public_request_value(&request()?)?;
    {
        let Value::Array(fields) = &mut wrong_tag_type else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[0] = Value::Bool(false);
    }
    assert_eq!(
        decode_request(&wrong_tag_type),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let mut wrong_scope_type = public_request_value(&request()?)?;
    {
        let Value::Array(fields) = &mut wrong_scope_type else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[4] = Value::Bool(false);
    }
    assert_eq!(
        decode_request(&wrong_scope_type),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let mut empty_selectors = public_request_value(&request()?)?;
    {
        let Value::Array(fields) = &mut empty_selectors else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[5] = Value::Array(Vec::new());
    }
    assert_eq!(
        decode_request(&empty_selectors),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    assert_eq!(
        decode_request(&Value::Array(vec![Value::Null; 13])),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        decode_request(&Value::Null),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert_eq!(
        decode_request(&Value::Array(Vec::new())),
        Err(ErasureErrorV1::InvalidEncoding)
    );

    let canonical = request()?.to_canonical_cbor()?;
    let noncanonical = [&[0x98, 12][..], &canonical[1..]].concat();
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&noncanonical),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}
#[test]
fn receipt_decoder_refuses_unsorted_acknowledgements() -> Result<(), ErasureErrorV1> {
    let canonical = receipt()?;
    let mut unsorted = public_receipt_value(&canonical)?;
    {
        let Value::Array(fields) = &mut unsorted else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        let Value::Array(acknowledgements) = &mut fields[7] else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        acknowledgements.swap(0, 1);
    }
    assert_eq!(decode_receipt(&unsorted), Err(ErasureErrorV1::ScopeInvalid));
    Ok(())
}
#[test]
fn receipt_constructor_bounds_acknowledgements() {
    assert_eq!(
        ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::PartialFailure,
            vec![
                acknowledgement(1, ErasureAcknowledgementOutcomeV1::Negative);
                ERASURE_MAX_REFERENCES + 1
            ],
            Vec::new(),
            Vec::new(),
        )),
        Err(ErasureErrorV1::ScopeInvalid)
    );
}
#[test]
fn lifecycle_public_edges_and_terminality_are_closed() {
    assert!(ErasureLifecycleV1::Submitted.permits(ErasureLifecycleV1::Authorized));
    assert!(ErasureLifecycleV1::Authorized.permits(ErasureLifecycleV1::AccessFrozen));
    assert!(ErasureLifecycleV1::AccessFrozen.permits(ErasureLifecycleV1::DestructionDispatched));
    assert!(ErasureLifecycleV1::DestructionDispatched
        .permits(ErasureLifecycleV1::AwaitingAcknowledgements));
    assert!(ErasureLifecycleV1::AwaitingAcknowledgements.permits(ErasureLifecycleV1::Complete));
    assert!(
        ErasureLifecycleV1::AwaitingAcknowledgements.permits(ErasureLifecycleV1::PartialFailure)
    );
    assert!(!ErasureLifecycleV1::Rejected.permits(ErasureLifecycleV1::Submitted));
    assert!(ErasureLifecycleV1::Complete.is_terminal());
    assert!(ErasureLifecycleV1::PartialFailure.is_terminal());
    assert!(ErasureLifecycleV1::Rejected.is_terminal());
    assert!(!ErasureLifecycleV1::Authorized.is_terminal());
}
#[test]
fn lifecycle_is_monotonic_and_digest_linked() -> Result<(), ErasureErrorV1> {
    let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    assert!(submitted
        .lifecycle()
        .permits(ErasureLifecycleV1::Authorized));
    assert!(submitted.lifecycle().permits(ErasureLifecycleV1::Rejected));
    assert!(!ErasureLifecycleV1::Complete.permits(ErasureLifecycleV1::Authorized));
    assert!(ErasureLifecycleV1::PartialFailure.is_terminal());
    assert_eq!(
        submitted.transition(change(
            ErasureLifecycleV1::Submitted,
            None,
            Vec::new(),
            Vec::new()
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        submitted.transition(change(
            ErasureLifecycleV1::Rejected,
            None,
            vec![reference(7)],
            Vec::new()
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let authorized = submitted.transition(change(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    assert_eq!(
        authorized.transition(change(
            ErasureLifecycleV1::AccessFrozen,
            None,
            Vec::new(),
            Vec::new()
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let frozen = authorized.transition(change(
        ErasureLifecycleV1::AccessFrozen,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    assert_eq!(
        frozen.transition(change(
            ErasureLifecycleV1::DestructionDispatched,
            Some(11),
            Vec::new(),
            Vec::new(),
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let dispatched = frozen.transition(change(
        ErasureLifecycleV1::DestructionDispatched,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let waiting = dispatched.transition(change(
        ErasureLifecycleV1::AwaitingAcknowledgements,
        Some(10),
        vec![reference(7)],
        Vec::new(),
    ))?;
    assert_eq!(
        waiting.transition(change(
            ErasureLifecycleV1::Complete,
            Some(10),
            vec![reference(7)],
            Vec::new()
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let partial = waiting.transition(change(
        ErasureLifecycleV1::PartialFailure,
        Some(10),
        Vec::new(),
        vec![reference(7)],
    ))?;
    let bytes = partial.to_canonical_cbor()?;
    assert_eq!(ErasureStateV1::from_canonical_cbor(&bytes)?, partial);
    let mut tampered = bytes;
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        ErasureStateV1::from_canonical_cbor(&tampered),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}
#[test]
fn owner_evidence_bounds_are_enforced_at_the_public_transition() -> Result<(), ErasureErrorV1> {
    let dispatched = dispatched()?;
    assert!(dispatched
        .transition(change(
            ErasureLifecycleV1::AwaitingAcknowledgements,
            Some(10),
            references(ERASURE_MAX_REFERENCES),
            Vec::new(),
        ))
        .is_ok());
    assert!(dispatched
        .transition(change(
            ErasureLifecycleV1::AwaitingAcknowledgements,
            Some(10),
            Vec::new(),
            references(ERASURE_MAX_REFERENCES),
        ))
        .is_ok());
    assert_eq!(
        dispatched.transition(change(
            ErasureLifecycleV1::AwaitingAcknowledgements,
            Some(10),
            references(ERASURE_MAX_REFERENCES + 1),
            Vec::new(),
        )),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        dispatched.transition(change(
            ErasureLifecycleV1::AwaitingAcknowledgements,
            Some(10),
            Vec::new(),
            references(ERASURE_MAX_REFERENCES + 1),
        )),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    Ok(())
}
#[test]
fn receipt_order_is_arrival_independent_and_completion_is_strict() -> Result<(), ErasureErrorV1> {
    let low = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let high = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let first = ErasureReceiptV1::new(receipt_input(
        ErasureLifecycleV1::Complete,
        vec![high, low],
        Vec::new(),
        Vec::new(),
    ))?;
    let second = ErasureReceiptV1::new(receipt_input(
        ErasureLifecycleV1::Complete,
        vec![low, high],
        Vec::new(),
        Vec::new(),
    ))?;
    let bytes = first.to_canonical_cbor()?;
    assert_eq!(bytes, second.to_canonical_cbor()?);
    assert_eq!(ErasureReceiptV1::from_canonical_cbor(&bytes)?, first);
    assert_eq!(
        ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::Complete,
            vec![acknowledgement(
                3,
                ErasureAcknowledgementOutcomeV1::Negative
            )],
            Vec::new(),
            Vec::new()
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::PartialFailure,
            vec![low],
            Vec::new(),
            Vec::new()
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert!(ErasureReceiptV1::new(receipt_input(
        ErasureLifecycleV1::PartialFailure,
        vec![low],
        vec![reference(9)],
        Vec::new()
    ))
    .is_ok());
    Ok(())
}
#[test]
fn safe_errors_are_closed_and_payload_free() {
    for code in 0..16 {
        assert_eq!(
            ErasureErrorV1::from_code(code).map(ErasureErrorV1::code),
            Ok(code)
        );
    }
    assert_eq!(
        ErasureErrorV1::from_code(16),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    assert!(!ErasureErrorV1::ArtifactDeletionFailed
        .to_string()
        .contains("payload"));
}

#[test]
fn every_closed_wire_enum_round_trips_at_its_public_seam() -> Result<(), ErasureErrorV1> {
    for scope in [
        ErasureScopeV1::PrivateSubjectData,
        ErasureScopeV1::ConsentedSharedData,
        ErasureScopeV1::PublicRecord,
        ErasureScopeV1::Aggregate,
        ErasureScopeV1::StructuralAuditMetadata,
    ] {
        let mut input = request_input(vec![reference(7)]);
        input.scope = scope;
        let request = ErasureRequestV1::new(input)?;
        assert_eq!(
            ErasureRequestV1::from_canonical_cbor(&request.to_canonical_cbor()?)?,
            request
        );
    }

    let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let authorized = submitted.transition(change(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let frozen = authorized.transition(change(
        ErasureLifecycleV1::AccessFrozen,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let dispatched = frozen.transition(change(
        ErasureLifecycleV1::DestructionDispatched,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let waiting = dispatched.transition(change(
        ErasureLifecycleV1::AwaitingAcknowledgements,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let complete = waiting.transition(ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: Some(10),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: vec![
            acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target,
        ],
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        provenance: reference(9),
    })?;
    let rejected = submitted.transition(change(
        ErasureLifecycleV1::Rejected,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    for state in [
        submitted, authorized, frozen, dispatched, waiting, complete, rejected,
    ] {
        assert_eq!(
            ErasureStateV1::from_canonical_cbor(&state.to_canonical_cbor()?)?,
            state
        );
        assert_ne!(state.state_digest(), reference(0));
    }

    for claim in [
        ErasureReplayClaimV1::Exact,
        ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews,
        ErasureReplayClaimV1::StructuralOnly,
        ErasureReplayClaimV1::UnverifiableArtifactsMissing,
        ErasureReplayClaimV1::IncompatibleProfile,
    ] {
        let mut transition = change(ErasureLifecycleV1::Authorized, None, Vec::new(), Vec::new());
        transition.replay_claim = claim;
        let state = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?
            .transition(transition)?;
        assert_eq!(
            ErasureStateV1::from_canonical_cbor(&state.to_canonical_cbor()?)?,
            state
        );
    }

    let receipt = ErasureReceiptV1::new(receipt_input(
        ErasureLifecycleV1::PartialFailure,
        vec![
            acknowledgement(1, ErasureAcknowledgementOutcomeV1::Negative),
            acknowledgement(2, ErasureAcknowledgementOutcomeV1::Stale),
        ],
        Vec::new(),
        vec![reference(9)],
    ))?;
    assert_eq!(
        ErasureReceiptV1::from_canonical_cbor(&receipt.to_canonical_cbor()?)?,
        receipt
    );
    Ok(())
}

#[test]
fn request_decoder_rejects_retained_wire_boundaries() -> Result<(), ErasureErrorV1> {
    let request = request()?;
    let mut malformed = public_request_value(&request)?;
    {
        let Value::Array(fields) = &mut malformed else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[0] = test_text("other-contract");
    }
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&public_value_bytes(&malformed)?),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    {
        let Value::Array(fields) = &mut malformed else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[0] = test_text("ERQ1");
        fields[2] = Value::Bool(false);
    }
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&public_value_bytes(&malformed)?),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    {
        let Value::Array(fields) = &mut malformed else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[2] = test_digest(reference(1));
        fields[5] = Value::Array(vec![test_digest(reference(9)), test_digest(reference(8))]);
    }
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&public_value_bytes(&malformed)?),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureRequestV1::new(request_input(vec![
            reference(7);
            ERASURE_MAX_REFERENCES + 1
        ])),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&vec![0; ERASURE_REQUEST_OR_STATE_MAX_BYTES + 1]),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    assert_eq!(
        ErasureRequestV1::from_canonical_cbor(&vec![0; ERASURE_REQUEST_OR_STATE_MAX_BYTES]),
        Err(ErasureErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn state_decoder_rejects_retained_wire_boundaries() -> Result<(), ErasureErrorV1> {
    let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    assert_eq!(
        submitted.transition(change(
            ErasureLifecycleV1::Authorized,
            None,
            vec![reference(7), reference(7)],
            Vec::new()
        )),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    let mut invalid_state = public_state_value(&submitted)?;
    {
        let Value::Array(state_fields) = &mut invalid_state else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        state_fields[6] = Value::Array(vec![test_digest(reference(7)), test_digest(reference(7))]);
    }
    assert_eq!(
        ErasureStateV1::from_canonical_cbor(&public_value_bytes(&invalid_state)?),
        Err(ErasureErrorV1::ScopeInvalid)
    );
    {
        let Value::Array(state_fields) = &mut invalid_state else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        state_fields[6] = Value::Array(Vec::new());
        state_fields[9] = test_digest(reference(8));
    }
    assert_eq!(
        ErasureStateV1::from_canonical_cbor(&public_value_bytes(&invalid_state)?),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    {
        let Value::Array(state_fields) = &mut invalid_state else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        state_fields[3] = test_uint(ErasureLifecycleV1::PartialFailure.code());
        state_fields[4] = test_uint(10);
    }
    assert_eq!(
        ErasureStateV1::from_canonical_cbor(&public_value_bytes(&invalid_state)?),
        Err(ErasureErrorV1::PolicyConflict)
    );
    Ok(())
}

#[test]
fn receipt_constructor_rejects_retained_wire_boundaries() {
    assert_eq!(
        ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::Authorized,
            Vec::new(),
            Vec::new(),
            Vec::new()
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::Complete,
            Vec::new(),
            Vec::new(),
            Vec::new()
        )),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::PartialFailure,
            vec![acknowledgement(1, ErasureAcknowledgementOutcomeV1::Stale)],
            vec![reference(8)],
            vec![reference(8)]
        )),
        Err(ErasureErrorV1::ScopeInvalid)
    );
}

#[test]
fn public_state_owner_accessors_and_freeze_rejection_remain_exact() -> Result<(), ErasureErrorV1> {
    let dispatched = dispatched()?;
    let pending = vec![reference(7)];
    let failed = vec![reference(8)];
    let awaiting = dispatched.transition(change(
        ErasureLifecycleV1::AwaitingAcknowledgements,
        Some(10),
        pending.clone(),
        failed.clone(),
    ))?;
    assert_eq!(awaiting.pending_owners(), pending);
    assert_eq!(awaiting.failed_owners(), failed);

    let acknowledgement = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let port = test_port(true, vec![acknowledgement.target, acknowledgement.target]);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            change(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );
    coordinator.authorize(reference(1), reference(9))?;
    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            change(ErasureLifecycleV1::Authorized, None, Vec::new(), Vec::new(),),
        ),
        Err(ErasureErrorV1::PolicyConflict)
    );
    assert_eq!(
        coordinator.freeze_inventory(
            reference(1),
            change(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ),
        ),
        Err(ErasureErrorV1::ScopeInvalid)
    );

    let targets = (0..ERASURE_MAX_INVENTORY_RESULTS)
        .map(|index| ErasureRequiredTargetV1 {
            artifact_class: ErasureArtifactClassV1::TimelineReplay,
            artifact_digest: indexed_reference(index),
            key_role: ErasureKeyRoleV1::DataEncryption,
            key_digest: indexed_reference(index + 1),
            replica_set: reference(30),
            replica_id: indexed_reference(index + 2),
        })
        .collect();
    let port = test_port(true, targets);
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request()?, reference(3))?;
    coordinator.authorize(reference(1), reference(9))?;
    assert_eq!(
        coordinator
            .freeze_inventory(
                reference(1),
                change(
                    ErasureLifecycleV1::AccessFrozen,
                    Some(10),
                    Vec::new(),
                    Vec::new(),
                ),
            )?
            .lifecycle(),
        ErasureLifecycleV1::AccessFrozen
    );
    Ok(())
}

#[test]
fn public_receipt_history_rejects_each_terminal_and_predecessor_mismatch(
) -> Result<(), ErasureErrorV1> {
    let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
    let authorized = submitted.transition(change(
        ErasureLifecycleV1::Authorized,
        None,
        Vec::new(),
        Vec::new(),
    ))?;
    let frozen = authorized.transition(change(
        ErasureLifecycleV1::AccessFrozen,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let dispatched = frozen.transition(change(
        ErasureLifecycleV1::DestructionDispatched,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let waiting = dispatched.transition(change(
        ErasureLifecycleV1::AwaitingAcknowledgements,
        Some(10),
        Vec::new(),
        Vec::new(),
    ))?;
    let acknowledgement = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
    let terminal = waiting.transition(ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: Some(10),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: vec![acknowledgement.target],
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        provenance: reference(9),
    })?;
    let mut input = receipt_input(
        ErasureLifecycleV1::Complete,
        vec![acknowledgement],
        Vec::new(),
        Vec::new(),
    );
    input.terminal_state = terminal.state_digest();
    let receipt = ErasureReceiptV1::new(input.clone())?;
    let resolver = TestResolver {
        states: vec![
            submitted.clone(),
            authorized.clone(),
            frozen.clone(),
            dispatched.clone(),
            waiting.clone(),
            terminal.clone(),
        ],
        unavailable: false,
    };
    receipt.verify_history(&resolver)?;

    for mismatch in 0..4 {
        let mut altered = input.clone();
        match mismatch {
            0 => altered.request = reference(99),
            1 => {
                altered.lifecycle = ErasureLifecycleV1::PartialFailure;
                altered.pending_owners = vec![reference(9)];
            }
            2 => {
                altered.freeze_position = 11;
                altered.issue_position = 11;
            }
            _ => altered.terminal_state = waiting.state_digest(),
        }
        assert_eq!(
            ErasureReceiptV1::new(altered)?.verify_history(&resolver),
            Err(ErasureErrorV1::PolicyConflict)
        );
    }

    struct ReplyResolver {
        terminal: ErasureStateV1,
        previous: ErasureStateV1,
    }
    impl ErasureStateResolverV1 for ReplyResolver {
        fn resolve_state(
            &self,
            digest: ErasureReferenceV1,
        ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
            if digest == self.terminal.state_digest() {
                Ok(Some(self.terminal.clone()))
            } else {
                Ok(Some(self.previous.clone()))
            }
        }
    }
    for previous in [
        submitted,
        authorized.clone(),
        frozen.clone(),
        dispatched.clone(),
    ] {
        assert_eq!(
            ErasureReceiptV1::new(input.clone())?.verify_history(&ReplyResolver {
                terminal: terminal.clone(),
                previous,
            }),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
    }
    Ok(())
}
