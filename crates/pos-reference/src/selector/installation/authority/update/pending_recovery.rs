//! Authentication of one durably pending SIR1 (ADR-069 R12 §4.1).
//!
//! A pending SIR1 is trusted only as far as the selector can rebuild it. The
//! loader reopens the previous and next SIC1 that SIR1 embeds from their
//! immutable objects, re-authenticates its RCU1 against the previous state,
//! rebinds the previous-provider binding to the previous state's admitted
//! provider, and re-encodes the whole record. Only a byte-identical rebuild is
//! accepted, so one comparison checks every field SIR1 carries, including its
//! self-digest.

use std::fs::File;
use std::os::unix::fs::MetadataExt as _;

use ciborium::value::Value;

use super::super::recovery_identity::{PendingRecoveryBinding, RecordedRecoveryRuntime};
use super::super::VerifiedPendingRecovery;
use super::durability::{read_bounded_immutable, sir1_envelope, sir1_unsigned, RECOVERY_LIMIT};
use super::{map_io_to_boundary_failure, map_protocol_to_artifact_invalid};
use crate::evaluator_protocol::{
    array, array_values, decode_canonical_with_limit, encode, fixed_bytes, uint, ProtocolError,
};
use crate::sandbox_provider_protocol::{RecoveryCancellationContext, RevocationUpdateRequest};
use crate::selector::installation::{InstalledSelectorState, RECOVERY_NAME};
use crate::selector::SelectorBoundaryError;

/// The SIR1 fields the loader cannot derive from the installed objects.
struct RecordedRecovery {
    previous: Vec<u8>,
    next: Vec<u8>,
    rcu1: Vec<u8>,
    runtime: RecordedRecoveryRuntime,
    previous_live_attempt_ids: Vec<[u8; 16]>,
    required_cancelled_attempt_ids: Vec<[u8; 16]>,
}

/// The previous state's view of one pending transaction.
struct RebuiltRecovery {
    previous_installation_digest: [u8; 32],
    revocation_update: RevocationUpdateRequest,
    binding: PendingRecoveryBinding,
}

impl VerifiedPendingRecovery {
    /// Loads the pending SIR1 beneath the installed state's root.
    ///
    /// The current SIC1 must equal SIR1's previous or next SIC1 byte for
    /// byte. Both embedded states are reopened and authenticated, RCU1 is
    /// re-authenticated against the previous state, and RCC1 is re-derived.
    ///
    /// # Errors
    /// Rejects an unsafe, oversized, malformed or altered SIR1, a third SIC1,
    /// any embedded record or object that fails authentication, and a SIR1
    /// whose rebuild differs from its exact bytes.
    pub(crate) fn load(installed: &InstalledSelectorState) -> Result<Self, SelectorBoundaryError> {
        let root = &installed.root;
        root.metadata()
            .map_err(map_io_to_boundary_failure)
            .and_then(|metadata| {
                read_bounded_immutable(root, RECOVERY_NAME, metadata.uid(), RECOVERY_LIMIT as u64)
                    .map(|bytes| (metadata.uid(), bytes))
            })
            .and_then(|(owner, bytes)| {
                RecordedRecovery::decode(&bytes)
                    .map_err(map_protocol_to_artifact_invalid)
                    .and_then(|recorded| {
                        let current = installed.manifest_bytes();
                        if current == recorded.previous || current == recorded.next {
                            Self::rebuild(root, owner, &bytes, &recorded)
                        } else {
                            Err(SelectorBoundaryError::ArtifactInvalid)
                        }
                    })
            })
    }

    fn rebuild(
        root: &File,
        owner: u32,
        bytes: &[u8],
        recorded: &RecordedRecovery,
    ) -> Result<Self, SelectorBoundaryError> {
        RebuiltRecovery::authenticate(root, owner, recorded).and_then(|rebuilt| {
            sir1_envelope(sir1_unsigned(
                [
                    recorded.previous.as_slice(),
                    recorded.next.as_slice(),
                    recorded.rcu1.as_slice(),
                ],
                rebuilt.binding.previous_provider_value(),
                rebuilt.binding.recovery_slot_value(),
                &recorded.previous_live_attempt_ids,
                &recorded.required_cancelled_attempt_ids,
            ))
            .and_then(|(rebuilt_bytes, sir1_digest)| {
                if rebuilt_bytes == bytes {
                    rebuilt
                        .binding
                        .previous_provider_digest()
                        .map(|binding_digest| (sir1_digest, binding_digest))
                } else {
                    Err(SelectorBoundaryError::ArtifactInvalid)
                }
            })
            .and_then(|(sir1_digest, previous_provider_binding_digest)| {
                RecoveryCancellationContext::for_committed_recovery(
                    sir1_digest,
                    previous_provider_binding_digest,
                    &rebuilt.revocation_update,
                    recorded.previous_live_attempt_ids.clone(),
                    recorded.required_cancelled_attempt_ids.clone(),
                )
                .map_err(map_protocol_to_artifact_invalid)
            })
            .and_then(|context| {
                pending_update(
                    rebuilt.previous_installation_digest,
                    &recorded.next,
                    &recorded.rcu1,
                )
                .map(|pending_update| Self {
                    sir1_digest: context.sir1_digest,
                    previous_provider_binding_digest: context.previous_provider_binding_digest,
                    previous_runtime_instance_id: recorded.runtime.runtime_instance_id,
                    previous_lifecycle_scope_id: recorded.runtime.lifecycle_scope_id,
                    previous_live_attempt_ids: context.previous_live_attempt_ids,
                    recovery_peer_slot: recorded.runtime.recovery_peer_slot,
                    previous_installation_digest: rebuilt.previous_installation_digest,
                    selector_nonce: rebuilt.revocation_update.selector_nonce,
                    pending_update,
                })
            })
        })
    }
}

impl RebuiltRecovery {
    /// Reopens and authenticates the next state, then the previous state, and
    /// re-authenticates RCU1 and the previous provider under the previous
    /// state. The next state is authenticated only as installed authority; its
    /// RVS1 may revoke the previous provider.
    fn authenticate(
        root: &File,
        owner: u32,
        recorded: &RecordedRecovery,
    ) -> Result<Self, SelectorBoundaryError> {
        InstalledSelectorState::open_recorded_at(root, recorded.next.clone(), owner)
            .and_then(InstalledSelectorState::authenticate_bootstrap)
            .and_then(|_next| {
                InstalledSelectorState::open_recorded_at(root, recorded.previous.clone(), owner)
            })
            .and_then(InstalledSelectorState::authenticate_bootstrap)
            .and_then(|previous| {
                previous
                    .authenticate_successor(&recorded.next, &recorded.rcu1)
                    .map(|successor| (previous, successor.revocation_update))
            })
            .and_then(|(previous, revocation_update)| {
                let previous_installation_digest = previous.installed().manifest().digest();
                previous
                    .admit_provider()
                    .and_then(|admitted| {
                        PendingRecoveryBinding::rebind(&admitted, recorded.runtime)
                    })
                    .map(|binding| Self {
                        previous_installation_digest,
                        revocation_update,
                        binding,
                    })
            })
    }
}

impl RecordedRecovery {
    /// Decodes the canonical SIR1 envelope and the fields the rebuild takes
    /// from it. The rebuild checks everything else.
    fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        decode_canonical_with_limit(bytes, RECOVERY_LIMIT).and_then(|document| {
            array(&document, 2)
                .and_then(|envelope| array(&envelope[0], 9))
                .and_then(|fields| {
                    match (
                        record_bytes(&fields[2]),
                        record_bytes(&fields[3]),
                        record_bytes(&fields[4]),
                        recorded_runtime(&fields[5], &fields[6]),
                        attempt_ids(&fields[7]),
                        attempt_ids(&fields[8]),
                    ) {
                        (
                            Ok(previous),
                            Ok(next),
                            Ok(rcu1),
                            Ok(runtime),
                            Ok(previous_live_attempt_ids),
                            Ok(required_cancelled_attempt_ids),
                        ) => Ok(Self {
                            previous,
                            next,
                            rcu1,
                            runtime,
                            previous_live_attempt_ids,
                            required_cancelled_attempt_ids,
                        }),
                        _ => Err(ProtocolError::InvalidEncoding),
                    }
                })
        })
    }
}

fn record_bytes(value: &Value) -> Result<Vec<u8>, ProtocolError> {
    match value {
        Value::Bytes(bytes) => Ok(bytes.clone()),
        _ => Err(ProtocolError::InvalidEncoding),
    }
}

fn recorded_runtime(
    binding: &Value,
    slot: &Value,
) -> Result<RecordedRecoveryRuntime, ProtocolError> {
    array(binding, 9).and_then(|binding| {
        array(slot, 3).and_then(|slot| {
            match (
                fixed_bytes::<16>(&binding[5]),
                fixed_bytes::<16>(&binding[6]),
                uint(&binding[7]),
                uint(&binding[8]),
                fixed_bytes::<16>(&slot[0]),
                fixed_bytes::<16>(&slot[1]),
                fixed_bytes::<16>(&slot[2]),
            ) {
                (
                    Ok(runtime_instance_id),
                    Ok(lifecycle_scope_id),
                    Ok(main_pid),
                    Ok(main_start_time_ticks),
                    Ok(slot_runtime),
                    Ok(slot_scope),
                    Ok(slot_endpoint),
                ) => Ok(RecordedRecoveryRuntime {
                    runtime_instance_id,
                    lifecycle_scope_id,
                    main_pid,
                    main_start_time_ticks,
                    recovery_peer_slot: [slot_runtime, slot_scope, slot_endpoint],
                }),
                _ => Err(ProtocolError::InvalidEncoding),
            }
        })
    })
}

fn attempt_ids(value: &Value) -> Result<Vec<[u8; 16]>, ProtocolError> {
    array_values(value).and_then(|values| values.iter().map(fixed_bytes::<16>).collect())
}

/// The exact SIU1 that committed a SIR1 with these previous-state digest,
/// next SIC1 and RCU1.
fn pending_update(
    previous_installation_digest: [u8; 32],
    next: &[u8],
    rcu1: &[u8],
) -> Result<Vec<u8>, SelectorBoundaryError> {
    encode(&Value::Array(vec![
        Value::Text("SIU1".to_owned()),
        Value::Integer(1_u64.into()),
        Value::Bytes(previous_installation_digest.to_vec()),
        Value::Bytes(next.to_vec()),
        Value::Bytes(rcu1.to_vec()),
    ]))
    .map_err(map_protocol_to_artifact_invalid)
}
