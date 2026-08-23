use super::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementV1, ErasureArtifactClassV1,
    ErasureArtifactTransitionV1, ErasureErrorV1, ErasureInventoryCategoryV1,
    ErasureInventoryResultV1, ErasureKeyRoleV1, ErasureLifecycleV1, ErasureReceiptInputV1,
    ErasureReceiptInventoriesV1, ErasureReceiptV1, ErasureReferenceV1, ErasureReplayClaimV1,
    ErasureRequestInputV1, ErasureRequestV1, ErasureRequiredTargetV1, ErasureScopeV1,
    ErasureStateV1, ERASURE_MAX_INVENTORY_RESULTS, ERASURE_MAX_REFERENCES, ERC1, ERQ1, ERS1,
    VERSION,
};
use ciborium::value::Value;
use std::io::Cursor;

pub(super) fn request_value(input: &ErasureRequestInputV1) -> Value {
    Value::Array(vec![
        text(ERQ1),
        uint(VERSION),
        digest(input.request),
        digest(input.subject),
        uint(input.scope.code()),
        references_value(&input.selectors),
        digest(input.requester),
        digest(input.authorization),
        digest(input.policy),
        uint(input.request_position),
        uint(input.horizon_position),
        digest(input.provenance),
    ])
}
pub(super) fn request_from_fields(fields: &[Value]) -> Result<ErasureRequestV1, ErasureErrorV1> {
    header(fields, ERQ1)
        .and_then(|()| request_identity(fields))
        .and_then(|(request, subject, scope, selectors)| {
            request_authority(fields).and_then(|(requester, authorization, policy)| {
                request_positions(fields).and_then(|(request_position, horizon_position, provenance)| {
                    ErasureRequestV1::new(ErasureRequestInputV1 {
                        request,
                        subject,
                        scope,
                        selectors,
                        requester,
                        authorization,
                        policy,
                        request_position,
                        horizon_position,
                        provenance,
                    })
                })
            })
        })
}
pub(super) fn request_identity(
    fields: &[Value],
) -> Result<
    (
        ErasureReferenceV1,
        ErasureReferenceV1,
        ErasureScopeV1,
        Vec<ErasureReferenceV1>,
    ),
    ErasureErrorV1,
> {
    bytes32(&fields[2]).and_then(|request| {
        bytes32(&fields[3]).and_then(|subject| {
            unsigned(&fields[4]).and_then(ErasureScopeV1::from_code).and_then(|scope| {
                references_from_value(&fields[5], true)
                    .map(|selectors| (request, subject, scope, selectors))
            })
        })
    })
}
pub(super) fn request_authority(
    fields: &[Value],
) -> Result<(ErasureReferenceV1, ErasureReferenceV1, ErasureReferenceV1), ErasureErrorV1> {
    bytes32(&fields[6]).and_then(|requester| {
        bytes32(&fields[7]).and_then(|authorization| {
            bytes32(&fields[8]).map(|policy| (requester, authorization, policy))
        })
    })
}
pub(super) fn request_positions(
    fields: &[Value],
) -> Result<(u64, u64, ErasureReferenceV1), ErasureErrorV1> {
    unsigned(&fields[9]).and_then(|request_position| {
        unsigned(&fields[10]).and_then(|horizon_position| {
            bytes32(&fields[11]).map(|provenance| {
                (request_position, horizon_position, provenance)
            })
        })
    })
}
pub(super) fn state_core_value(state: &ErasureStateV1) -> Value {
    Value::Array(vec![
        text(ERS1),
        uint(VERSION),
        digest(state.request),
        uint(state.lifecycle.code()),
        optional_uint(state.freeze_position),
        digest(state.coordinator),
        references_value(&state.pending_owners),
        references_value(&state.failed_owners),
        uint(state.replay_claim.code()),
        optional_digest(state.previous_state),
        digest(state.provenance),
    ])
}
pub(super) fn state_value(state: &ErasureStateV1) -> Value {
    Value::Array(vec![
        text(ERS1),
        uint(VERSION),
        digest(state.request),
        uint(state.lifecycle.code()),
        optional_uint(state.freeze_position),
        digest(state.coordinator),
        references_value(&state.pending_owners),
        references_value(&state.failed_owners),
        uint(state.replay_claim.code()),
        optional_digest(state.previous_state),
        digest(state.provenance),
        digest(state.state_digest),
    ])
}
pub(super) fn state_from_fields(fields: &[Value]) -> Result<ErasureStateV1, ErasureErrorV1> {
    header(fields, ERS1)
        .and_then(|()| state_identity(fields))
        .and_then(|(request, lifecycle, freeze_position, coordinator)| {
            state_owners(fields).and_then(|(pending_owners, failed_owners, replay_claim)| {
                state_provenance(fields).and_then(|(previous_state, provenance, state_digest)| {
                    let state = ErasureStateV1 {
                        request,
                        lifecycle,
                        freeze_position,
                        coordinator,
                        pending_owners,
                        failed_owners,
                        replay_claim,
                        previous_state,
                        provenance,
                        state_digest,
                    };
                    if matches!(
                        state.lifecycle,
                        ErasureLifecycleV1::Complete | ErasureLifecycleV1::PartialFailure
                    ) {
                        return Err(ErasureErrorV1::PolicyConflict);
                    }
                    state.validate().and_then(|()| state.clone().with_digest()).and_then(|expected| {
                        if expected.state_digest == state.state_digest {
                            Ok(state)
                        } else {
                            Err(ErasureErrorV1::ProvenanceMissing)
                        }
                    })
                })
            })
        })
}
pub(super) fn state_identity(
    fields: &[Value],
) -> Result<
    (
        ErasureReferenceV1,
        ErasureLifecycleV1,
        Option<u64>,
        ErasureReferenceV1,
    ),
    ErasureErrorV1,
> {
    bytes32(&fields[2]).and_then(|request| {
        unsigned(&fields[3]).and_then(ErasureLifecycleV1::from_code).and_then(|lifecycle| {
            optional_unsigned(&fields[4]).and_then(|freeze_position| {
                bytes32(&fields[5]).map(|coordinator| (request, lifecycle, freeze_position, coordinator))
            })
        })
    })
}
pub(super) fn state_owners(
    fields: &[Value],
) -> Result<
    (
        Vec<ErasureReferenceV1>,
        Vec<ErasureReferenceV1>,
        ErasureReplayClaimV1,
    ),
    ErasureErrorV1,
> {
    references_from_value(&fields[6], false).and_then(|pending_owners| {
        references_from_value(&fields[7], false).and_then(|failed_owners| {
            unsigned(&fields[8])
                .and_then(ErasureReplayClaimV1::from_code)
                .map(|replay_claim| (pending_owners, failed_owners, replay_claim))
        })
    })
}
pub(super) fn state_provenance(
    fields: &[Value],
) -> Result<
    (
        Option<ErasureReferenceV1>,
        ErasureReferenceV1,
        ErasureReferenceV1,
    ),
    ErasureErrorV1,
> {
    optional_bytes32(&fields[9]).and_then(|previous_state| {
        bytes32(&fields[10]).and_then(|provenance| {
            bytes32(&fields[11]).map(|state_digest| (previous_state, provenance, state_digest))
        })
    })
}
pub(super) fn receipt_fields(input: &ErasureReceiptInputV1) -> Vec<Value> {
    vec![
        text(ERC1),
        uint(VERSION),
        digest(input.request),
        digest(input.terminal_state),
        uint(input.lifecycle.code()),
        uint(input.freeze_position),
        targets_value(&input.required_targets),
        Value::Array(
            input
                .acknowledgements
                .iter()
                .copied()
                .map(acknowledgement_value)
                .collect(),
        ),
        references_value(&input.pending_owners),
        references_value(&input.failed_owners),
        inventories_value(&input.inventories),
        uint(input.replay_claim.code()),
        digest(input.policy),
        digest(input.trust),
        digest(input.provenance),
        uint(input.issue_position),
        digest(input.receipt_digest),
        digest(input.signature),
        digest(input.coordinator),
    ]
}
pub(super) fn receipt_value(input: &ErasureReceiptInputV1) -> Value {
    Value::Array(receipt_fields(input))
}
pub(super) fn receipt_core_value(input: &ErasureReceiptInputV1) -> Value {
    let mut fields = receipt_fields(input);
    fields.remove(16);
    Value::Array(fields)
}
pub(super) fn acknowledgement_value(ack: ErasureAcknowledgementV1) -> Value {
    Value::Array(vec![
        target_value(ack.target),
        digest(ack.owner),
        digest(ack.evidence),
        uint(ack.outcome.code()),
    ])
}
pub(super) fn receipt_from_fields(fields: &[Value]) -> Result<ErasureReceiptV1, ErasureErrorV1> {
    header(fields, ERC1).and_then(|()| {
        bytes32(&fields[2]).and_then(|request| {
            bytes32(&fields[3]).and_then(|terminal_state| {
                unsigned(&fields[4]).and_then(ErasureLifecycleV1::from_code).and_then(|lifecycle| {
                    unsigned(&fields[5]).and_then(|freeze_position| {
                        targets_from_value(&fields[6]).and_then(|required_targets| {
                            acknowledgements_from_value(&fields[7]).and_then(|acknowledgements| {
                                references_from_value(&fields[8], false).and_then(|pending_owners| {
                                    references_from_value(&fields[9], false).and_then(|failed_owners| {
                                        inventories_from_value(&fields[10]).and_then(|inventories| {
                                            unsigned(&fields[11]).and_then(ErasureReplayClaimV1::from_code).and_then(|replay_claim| {
                                                receipt_proof(&fields[12..18]).and_then(|(
                                                    policy,
                                                    trust,
                                                    provenance,
                                                    issue_position,
                                                    receipt_digest,
                                                    signature,
                                                )| {
                                                    bytes32(&fields[18]).and_then(|coordinator| {
                                                        let receipt = ErasureReceiptInputV1 {
                                                            request,
                                                            terminal_state,
                                                            coordinator,
                                                            lifecycle,
                                                            freeze_position,
                                                            acknowledgements,
                                                            required_targets,
                                                            pending_owners,
                                                            failed_owners,
                                                            inventories,
                                                            replay_claim,
                                                            policy,
                                                            trust,
                                                            provenance,
                                                            issue_position,
                                                            signature,
                                                            receipt_digest,
                                                        };
                                                        ErasureReceiptV1::new(receipt).and_then(|expected| {
                                                            if expected.receipt_digest() == receipt_digest {
                                                                Ok(expected)
                                                            } else {
                                                                Err(ErasureErrorV1::ProvenanceMissing)
                                                            }
                                                        })
                                                    })
                                                })
                                            })
                                        })
                                    })
                                })
                            })
                        })
                    })
                })
            })
        })
    })
}
pub(super) fn receipt_proof(
    fields: &[Value],
) -> Result<
    (
        ErasureReferenceV1,
        ErasureReferenceV1,
        ErasureReferenceV1,
        u64,
        ErasureReferenceV1,
        ErasureReferenceV1,
    ),
    ErasureErrorV1,
> {
    bytes32(&fields[0]).and_then(|policy| {
        bytes32(&fields[1]).and_then(|trust| {
            bytes32(&fields[2]).and_then(|provenance| {
                unsigned(&fields[3]).and_then(|issue_position| {
                    bytes32(&fields[4]).and_then(|receipt_digest| {
                        bytes32(&fields[5]).map(|signature| {
                            (policy, trust, provenance, issue_position, receipt_digest, signature)
                        })
                    })
                })
            })
        })
    })
}
pub(super) fn acknowledgements_from_value(
    value: &Value,
) -> Result<Vec<ErasureAcknowledgementV1>, ErasureErrorV1> {
    array(value, ERASURE_MAX_INVENTORY_RESULTS).and_then(|values| {
        values
            .iter()
            .map(|value| {
                exact_array(value, 4).and_then(|fields| {
                    target_from_value(&fields[0]).and_then(|target| {
                        bytes32(&fields[1]).and_then(|owner| {
                            bytes32(&fields[2]).and_then(|evidence| {
                                unsigned(&fields[3])
                                    .and_then(ErasureAcknowledgementOutcomeV1::from_code)
                                    .map(|outcome| ErasureAcknowledgementV1 {
                                        target,
                                        owner,
                                        evidence,
                                        outcome,
                                    })
                            })
                        })
                    })
                })
            })
            .collect::<Result<Vec<_>, ErasureErrorV1>>()
            .and_then(|acknowledgements| {
                if strictly_increasing(&acknowledgements) {
                    Ok(acknowledgements)
                } else {
                    Err(ErasureErrorV1::ScopeInvalid)
                }
            })
    })
}
pub(super) fn target_value(target: ErasureRequiredTargetV1) -> Value {
    Value::Array(vec![
        uint(target.artifact_class.code()),
        digest(target.artifact_digest),
        uint(target.key_role.code()),
        digest(target.key_digest),
        digest(target.replica_set),
        digest(target.replica_id),
    ])
}
pub(super) fn target_from_value(value: &Value) -> Result<ErasureRequiredTargetV1, ErasureErrorV1> {
    exact_array(value, 6).and_then(|fields| {
        unsigned(&fields[0]).and_then(ErasureArtifactClassV1::from_code).and_then(|artifact_class| {
            bytes32(&fields[1]).and_then(|artifact_digest| {
                unsigned(&fields[2]).and_then(ErasureKeyRoleV1::from_code).and_then(|key_role| {
                    bytes32(&fields[3]).and_then(|key_digest| {
                        bytes32(&fields[4]).and_then(|replica_set| {
                            bytes32(&fields[5]).map(|replica_id| ErasureRequiredTargetV1 {
                                artifact_class,
                                artifact_digest,
                                key_role,
                                key_digest,
                                replica_set,
                                replica_id,
                            })
                        })
                    })
                })
            })
        })
    })
}
pub(super) fn targets_value(targets: &[ErasureRequiredTargetV1]) -> Value {
    Value::Array(targets.iter().copied().map(target_value).collect())
}
pub(super) fn targets_from_value(
    value: &Value,
) -> Result<Vec<ErasureRequiredTargetV1>, ErasureErrorV1> {
    array(value, ERASURE_MAX_INVENTORY_RESULTS).and_then(|values| {
        values
            .iter()
            .map(target_from_value)
            .collect::<Result<Vec<_>, _>>()
            .and_then(|targets| {
                if strictly_increasing(&targets) {
                    Ok(targets)
                } else {
                    Err(ErasureErrorV1::ScopeInvalid)
                }
            })
    })
}
pub(super) fn transition_value(transition: ErasureArtifactTransitionV1) -> Value {
    Value::Array(vec![
        uint(transition.from.code()),
        uint(transition.to.code()),
        digest(transition.reason),
        digest(transition.owner),
        digest(transition.acknowledgements),
        digest(transition.provenance),
    ])
}
pub(super) fn transition_from_value(
    value: &Value,
) -> Result<ErasureArtifactTransitionV1, ErasureErrorV1> {
    exact_array(value, 6).and_then(|fields| {
        unsigned(&fields[0]).and_then(ErasureReplayClaimV1::from_code).and_then(|from| {
            unsigned(&fields[1]).and_then(ErasureReplayClaimV1::from_code).and_then(|to| {
                bytes32(&fields[2]).and_then(|reason| {
                    bytes32(&fields[3]).and_then(|owner| {
                        bytes32(&fields[4]).and_then(|acknowledgements| {
                            bytes32(&fields[5]).map(|provenance| ErasureArtifactTransitionV1 {
                                from,
                                to,
                                reason,
                                owner,
                                acknowledgements,
                                provenance,
                            })
                        })
                    })
                })
            })
        })
    })
}
pub(super) fn inventory_result_value(result: &ErasureInventoryResultV1) -> Value {
    Value::Array(vec![
        uint(result.category.code()),
        target_value(result.target),
        transition_value(result.transition),
        digest(result.retained_disclosure),
    ])
}
pub(super) fn inventory_result_from_value(
    value: &Value,
) -> Result<ErasureInventoryResultV1, ErasureErrorV1> {
    exact_array(value, 4).and_then(|fields| {
        unsigned(&fields[0]).and_then(ErasureInventoryCategoryV1::from_code).and_then(|category| {
            target_from_value(&fields[1]).and_then(|target| {
                transition_from_value(&fields[2]).and_then(|transition| {
                    bytes32(&fields[3]).map(|retained_disclosure| ErasureInventoryResultV1 {
                        category,
                        target,
                        transition,
                        retained_disclosure,
                    })
                })
            })
        })
    })
}
pub(super) fn inventory_value(inventory: &[ErasureInventoryResultV1]) -> Value {
    Value::Array(inventory.iter().map(inventory_result_value).collect())
}
pub(super) fn inventory_from_value(
    value: &Value,
) -> Result<Vec<ErasureInventoryResultV1>, ErasureErrorV1> {
    array(value, ERASURE_MAX_INVENTORY_RESULTS).and_then(|values| {
        values
            .iter()
            .map(inventory_result_from_value)
            .collect::<Result<Vec<_>, _>>()
            .and_then(|results| {
                if strictly_increasing(&results) {
                    Ok(results)
                } else {
                    Err(ErasureErrorV1::ScopeInvalid)
                }
            })
    })
}
pub(super) fn inventories_value(inventories: &ErasureReceiptInventoriesV1) -> Value {
    Value::Array(vec![
        inventory_value(&inventories.artifacts),
        inventory_value(&inventories.keys),
        inventory_value(&inventories.replicas),
        inventory_value(&inventories.backups),
    ])
}
pub(super) fn inventories_from_value(
    value: &Value,
) -> Result<ErasureReceiptInventoriesV1, ErasureErrorV1> {
    exact_array(value, 4).and_then(|fields| {
        inventory_from_value(&fields[0]).and_then(|artifacts| {
            inventory_from_value(&fields[1]).and_then(|keys| {
                inventory_from_value(&fields[2]).and_then(|replicas| {
                    inventory_from_value(&fields[3]).map(|backups| ErasureReceiptInventoriesV1 {
                        artifacts,
                        keys,
                        replicas,
                        backups,
                    })
                })
            })
        })
    })
}
pub(super) const fn inventories_exceed_bound(inventories: &ErasureReceiptInventoriesV1) -> bool {
    inventories.artifacts.len() > ERASURE_MAX_INVENTORY_RESULTS
        || inventories.keys.len() > ERASURE_MAX_INVENTORY_RESULTS
        || inventories.replicas.len() > ERASURE_MAX_INVENTORY_RESULTS
        || inventories.backups.len() > ERASURE_MAX_INVENTORY_RESULTS
}
pub(super) fn sort_inventories(inventories: &mut ErasureReceiptInventoriesV1) {
    inventories.artifacts.sort_unstable();
    inventories.keys.sort_unstable();
    inventories.replicas.sort_unstable();
    inventories.backups.sort_unstable();
}
pub(super) fn inventories_have_duplicate_targets(
    inventories: &ErasureReceiptInventoriesV1,
) -> bool {
    has_duplicate_by_inventory_target(&inventories.artifacts)
        || has_duplicate_by_inventory_target(&inventories.keys)
        || has_duplicate_by_inventory_target(&inventories.replicas)
        || has_duplicate_by_inventory_target(&inventories.backups)
}
pub(super) fn inventory_categories_match(inventories: &ErasureReceiptInventoriesV1) -> bool {
    inventories
        .artifacts
        .iter()
        .all(|entry| entry.category == ErasureInventoryCategoryV1::Artifact)
        && inventories
            .keys
            .iter()
            .all(|entry| entry.category == ErasureInventoryCategoryV1::Key)
        && inventories
            .replicas
            .iter()
            .all(|entry| entry.category == ErasureInventoryCategoryV1::Replica)
        && inventories
            .backups
            .iter()
            .all(|entry| entry.category == ErasureInventoryCategoryV1::Backup)
}
pub(super) fn has_duplicate_by_inventory_target(entries: &[ErasureInventoryResultV1]) -> bool {
    entries
        .windows(2)
        .any(|pair| pair[0].target == pair[1].target)
}
pub(super) fn inventory_transitions_preserve_or_weaken(
    inventories: &ErasureReceiptInventoriesV1,
) -> bool {
    [
        &inventories.artifacts,
        &inventories.keys,
        &inventories.replicas,
        &inventories.backups,
    ]
    .into_iter()
    .flatten()
    .all(|entry| {
        entry
            .transition
            .from
            .preserves_or_weakens(entry.transition.to)
    })
}
pub(super) fn weakest_inventory_claim(
    inventories: &ErasureReceiptInventoriesV1,
) -> ErasureReplayClaimV1 {
    [
        &inventories.artifacts,
        &inventories.keys,
        &inventories.replicas,
        &inventories.backups,
    ]
    .into_iter()
    .flatten()
    .map(|entry| entry.transition.to)
    .max_by_key(|claim| claim.rank())
    .unwrap_or(ErasureReplayClaimV1::UnverifiableArtifactsMissing)
}
pub(super) fn inventories_match_closure(
    required_targets: &[ErasureRequiredTargetV1],
    inventories: &ErasureReceiptInventoriesV1,
) -> bool {
    let mut targets = inventories
        .artifacts
        .iter()
        .chain(&inventories.keys)
        .chain(&inventories.replicas)
        .chain(&inventories.backups)
        .map(|entry| entry.target)
        .collect::<Vec<_>>();
    targets.sort_unstable();
    targets == required_targets
}
pub(super) fn has_duplicate_by_target(acknowledgements: &[ErasureAcknowledgementV1]) -> bool {
    acknowledgements
        .windows(2)
        .any(|pair| pair[0].target == pair[1].target)
}
pub(super) fn acknowledgements_match_closure(
    required_targets: &[ErasureRequiredTargetV1],
    acknowledgements: &[ErasureAcknowledgementV1],
) -> bool {
    required_targets.len() == acknowledgements.len()
        && required_targets
            .iter()
            .zip(acknowledgements)
            .all(|(target, acknowledgement)| target == &acknowledgement.target)
}
pub(super) fn acknowledgements_are_closure_subset(
    required_targets: &[ErasureRequiredTargetV1],
    acknowledgements: &[ErasureAcknowledgementV1],
) -> bool {
    acknowledgements.iter().all(|acknowledgement| {
        required_targets
            .binary_search(&acknowledgement.target)
            .is_ok()
    })
}
pub(super) fn references_value(references: &[ErasureReferenceV1]) -> Value {
    Value::Array(references.iter().copied().map(digest).collect())
}
pub(super) fn references_from_value(
    value: &Value,
    required: bool,
) -> Result<Vec<ErasureReferenceV1>, ErasureErrorV1> {
    array(value, ERASURE_MAX_REFERENCES).and_then(|values| {
        if required && values.is_empty() {
            Err(ErasureErrorV1::ScopeInvalid)
        } else {
            values
                .iter()
                .map(bytes32)
                .collect::<Result<Vec<_>, _>>()
                .and_then(|references| {
                    if strictly_increasing(&references) {
                        Ok(references)
                    } else {
                        Err(ErasureErrorV1::ScopeInvalid)
                    }
                })
        }
    })
}
pub(super) fn header(fields: &[Value], contract: &str) -> Result<(), ErasureErrorV1> {
    string(&fields[0]).and_then(|found_contract| {
        if found_contract == contract {
            unsigned(&fields[1]).and_then(|version| {
                if version == VERSION {
                    Ok(())
                } else {
                    Err(ErasureErrorV1::UnsupportedVersion)
                }
            })
        } else {
            Err(ErasureErrorV1::InvalidEncoding)
        }
    })
}
pub(super) fn invalid_owner_sets(
    pending: &[ErasureReferenceV1],
    failed: &[ErasureReferenceV1],
) -> bool {
    pending.len() > ERASURE_MAX_REFERENCES
        || failed.len() > ERASURE_MAX_REFERENCES
        || !strictly_increasing(pending)
        || !strictly_increasing(failed)
        || pending
            .iter()
            .any(|reference| failed.binary_search(reference).is_ok())
}
pub(super) fn has_duplicate<T: Eq>(values: &[T]) -> bool {
    values.windows(2).any(|pair| pair[0] == pair[1])
}
pub(super) fn strictly_increasing<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
pub(super) fn freeze_is_monotonic(previous: Option<u64>, next: Option<u64>) -> bool {
    previous.is_none() || previous == next
}
pub(super) const fn reference_zero() -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([0; 32])
}
pub(super) fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}
pub(super) fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
pub(super) fn digest(reference: ErasureReferenceV1) -> Value {
    Value::Bytes(reference.digest().to_vec())
}
pub(super) fn optional_digest(reference: Option<ErasureReferenceV1>) -> Value {
    reference.map_or(Value::Null, digest)
}
pub(super) fn optional_uint(value: Option<u64>) -> Value {
    value.map_or(Value::Null, uint)
}
pub(super) fn encode_canonical(value: &Value) -> Result<Vec<u8>, ErasureErrorV1> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map(|()| bytes)
        .map_err(|_| ErasureErrorV1::InvalidEncoding)
}
pub(super) fn encode_limited(value: &Value, maximum: usize) -> Result<Vec<u8>, ErasureErrorV1> {
    encode_canonical(value).and_then(|bytes| {
        if bytes.len() <= maximum {
            Ok(bytes)
        } else {
            Err(ErasureErrorV1::ScopeInvalid)
        }
    })
}
pub(super) fn decode_limited(
    bytes: &[u8],
    maximum: usize,
    maximum_array: usize,
) -> Result<Value, ErasureErrorV1> {
    if bytes.len() > maximum {
        return Err(ErasureErrorV1::ScopeInvalid);
    }
    cbor_shape_is_bounded(bytes, maximum_array).and_then(|()| {
        let mut cursor = Cursor::new(bytes);
        match ciborium::from_reader(&mut cursor) {
            Ok(value) => {
                if cursor.position() != bytes.len() as u64 {
                    return Err(ErasureErrorV1::InvalidEncoding);
                }
                encode_canonical(&value).and_then(|canonical| {
                    if canonical == bytes {
                        Ok(value)
                    } else {
                        Err(ErasureErrorV1::InvalidEncoding)
                    }
                })
            }
            Err(_) => Err(ErasureErrorV1::InvalidEncoding),
        }
    })
}
pub(super) fn cbor_shape_is_bounded(
    bytes: &[u8],
    maximum_array: usize,
) -> Result<(), ErasureErrorV1> {
    cbor_item_end(bytes, 0, 0, maximum_array).and_then(|end| {
        if end == bytes.len() {
            Ok(())
        } else {
            Err(ErasureErrorV1::InvalidEncoding)
        }
    })
}
pub(super) fn cbor_item_end(
    bytes: &[u8],
    offset: usize,
    depth: usize,
    maximum_array: usize,
) -> Result<usize, ErasureErrorV1> {
    if depth > 16 || offset >= bytes.len() {
        return Err(ErasureErrorV1::InvalidEncoding);
    }
    let initial = bytes[offset];
    let major = initial >> 5;
    cbor_argument(bytes, offset + 1, initial & 0x1f).and_then(|(argument, next)| match major {
        0 | 1 => Ok(next),
        2 | 3 => match usize::try_from(argument) {
            Ok(length) if length <= bytes.len().saturating_sub(next) => next
                .checked_add(length)
                .ok_or(ErasureErrorV1::InvalidEncoding),
            _ => Err(ErasureErrorV1::InvalidEncoding),
        },
        4 if argument <= maximum_array as u64 => cbor_array_end(
            bytes,
            next,
            depth.saturating_add(1),
            argument,
            maximum_array,
        ),
        7 if argument <= 22 => Ok(next),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    })
}
pub(super) fn cbor_array_end(
    bytes: &[u8],
    mut offset: usize,
    depth: usize,
    count: u64,
    maximum_array: usize,
) -> Result<usize, ErasureErrorV1> {
    for _ in 0..count {
        let Ok(next) = cbor_item_end(bytes, offset, depth, maximum_array) else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        offset = next;
    }
    Ok(offset)
}
pub(super) fn cbor_argument(
    bytes: &[u8],
    offset: usize,
    additional: u8,
) -> Result<(u64, usize), ErasureErrorV1> {
    match additional {
        0..=23 => Ok((u64::from(additional), offset)),
        24 => cbor_argument_bytes(bytes, offset, 1, 24),
        25 => cbor_argument_bytes(bytes, offset, 2, 256),
        26 => cbor_argument_bytes(bytes, offset, 4, 65_536),
        27 => cbor_argument_bytes(bytes, offset, 8, 4_294_967_296),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}
pub(super) fn cbor_argument_bytes(
    bytes: &[u8],
    offset: usize,
    width: usize,
    minimum: u64,
) -> Result<(u64, usize), ErasureErrorV1> {
    let end = offset.saturating_add(width);
    if end > bytes.len() {
        return Err(ErasureErrorV1::InvalidEncoding);
    }
    let mut encoded = [0_u8; 8];
    encoded[8 - width..].copy_from_slice(&bytes[offset..end]);
    let value = u64::from_be_bytes(encoded);
    if value < minimum {
        Err(ErasureErrorV1::InvalidEncoding)
    } else {
        Ok((value, end))
    }
}
pub(super) fn array(value: &Value, maximum: usize) -> Result<&[Value], ErasureErrorV1> {
    match value {
        Value::Array(values) if values.len() <= maximum => Ok(values),
        Value::Array(_) => Err(ErasureErrorV1::ScopeInvalid),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}
pub(super) fn exact_array(value: &Value, expected: usize) -> Result<&[Value], ErasureErrorV1> {
    match value {
        Value::Array(values) if values.len() == expected => Ok(values),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}
pub(super) fn string(value: &Value) -> Result<&str, ErasureErrorV1> {
    match value {
        Value::Text(value) => Ok(value),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}
pub(super) fn unsigned(value: &Value) -> Result<u64, ErasureErrorV1> {
    match value {
        Value::Integer(value) => u64::try_from(*value).map_err(|_| ErasureErrorV1::InvalidEncoding),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}
pub(super) fn optional_unsigned(value: &Value) -> Result<Option<u64>, ErasureErrorV1> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        unsigned(value).map(Some)
    }
}
pub(super) fn bytes32(value: &Value) -> Result<ErasureReferenceV1, ErasureErrorV1> {
    match value {
        Value::Bytes(bytes) => bytes
            .as_slice()
            .try_into()
            .map(ErasureReferenceV1::from_digest)
            .map_err(|_| ErasureErrorV1::InvalidEncoding),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}
pub(super) fn optional_bytes32(
    value: &Value,
) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        bytes32(value).map(Some)
    }
}
pub(super) fn domain_digest(domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(domain.len() + 1 + bytes.len());
    input.extend_from_slice(domain.as_bytes());
    input.push(0);
    input.extend_from_slice(bytes);
    *blake3::hash(&input).as_bytes()
}
