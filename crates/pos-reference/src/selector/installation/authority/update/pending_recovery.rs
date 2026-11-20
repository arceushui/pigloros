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
use ed25519_dalek::VerifyingKey;

use super::super::recovery_identity::{PendingRecoveryBinding, RecordedRecoveryRuntime};
use super::super::{
    AdmittedSelectorProvider, AuthenticatedSelectorBootstrap, PendingRecoveryRecords,
    VerifiedPendingRecovery,
};
use super::durability::{
    publish_successor, read_held_immutable, sir1_envelope, sir1_unsigned, RECOVERY_LIMIT,
};
use super::{map_io_to_boundary_failure, map_protocol_to_artifact_invalid};
use crate::evaluator_protocol::{
    array, array_values, decode_canonical_with_limit, encode, fixed_bytes, uint, ProtocolError,
};
use crate::provider_admission::admitted_provider_binary;
use crate::sandbox_provider_protocol::{
    AuthenticatedRevocationAcknowledgement, RecoveryCancellationContext, RevocationAcknowledgement,
    RevocationUpdateRequest,
};
use crate::selector::installation::{
    InstallationObjectKind, InstalledSelectorState, PositionalReader, RECOVERY_NAME,
};
use crate::selector::runtime_lifecycle::bounded_digest;
use crate::selector::SelectorBoundaryError;

const EMBEDDED_RECORD_LIMIT: usize = 16 * 1024 * 1024;

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
    previous: AdmittedSelectorProvider,
}

impl PendingRecoveryRecords {
    /// The previous provider's SPM1 provider ID.
    pub(crate) fn provider_id(&self) -> &str {
        &self.previous.provider().manifest().provider_id
    }

    /// The SIR1 previous-provider binary digest.
    pub(crate) const fn provider_binary_digest(&self) -> [u8; 32] {
        self.binary.digest()
    }

    /// The previous provider binary's exact byte length.
    pub(crate) const fn provider_binary_length(&self) -> u64 {
        self.binary.length()
    }

    /// The SIR1 previous main process: its PID and start-time ticks.
    pub(crate) const fn main_process(&self) -> (u64, u64) {
        (self.main_pid, self.main_start_time_ticks)
    }

    /// Re-hashes the previous provider binary through its retained
    /// descriptor and returns its path and digest, which must be the SIR1
    /// digest (R12 §6 step 6).
    ///
    /// # Errors
    /// Rejects a binary that is no longer held, cannot be read, or has
    /// another length or digest.
    pub(crate) fn verified_provider_binary(
        &self,
    ) -> Result<(String, [u8; 32]), SelectorBoundaryError> {
        let digest = self.binary.digest();
        self.previous
            .bootstrap()
            .installed()
            .artifact(InstallationObjectKind::PROVIDER_EXECUTABLE, digest)
            .and_then(|artifact| {
                bounded_digest(PositionalReader::new(artifact.file()), self.binary.length())
            })
            .and_then(|rehashed| {
                if rehashed == digest {
                    Ok((self.binary.path().to_owned(), digest))
                } else {
                    Err(SelectorBoundaryError::ArtifactInvalid)
                }
            })
    }

    /// The exact RCC1 bytes.
    ///
    /// # Errors
    /// Rejects an RCC1 that no longer encodes.
    pub(crate) fn context_bytes(&self) -> Result<Vec<u8>, SelectorBoundaryError> {
        self.context
            .to_canonical_cbor()
            .map_err(map_protocol_to_artifact_invalid)
    }

    /// The exact administrator-signed RCU1 bytes.
    pub(crate) fn revocation_update_bytes(&self) -> &[u8] {
        &self.rcu1
    }

    /// Authenticates one RCA1 under the previous runtime key against this
    /// RCC1, RCU1 request ID and next RVS1 digest.
    ///
    /// # Errors
    /// Rejects a malformed, forged or foreign-transaction RCA1.
    pub(crate) fn authenticate_acknowledgement(
        &self,
        bytes: &[u8],
    ) -> Result<AuthenticatedRevocationAcknowledgement, SelectorBoundaryError> {
        self.previous
            .runtime_attestation_key()
            .and_then(|key| {
                VerifyingKey::from_bytes(&key.public_key)
                    .map(|verifying| (key.key_id.as_str(), verifying))
                    .map_err(map_protocol_to_artifact_invalid)
            })
            .and_then(|(key_id, verifying)| {
                RevocationAcknowledgement::authenticate_for_context(
                    bytes,
                    key_id,
                    &verifying,
                    &self.context,
                    self.revocation_update.request_id,
                    self.revocation_update.next_revocation.snapshot_digest(),
                )
                .map_err(map_protocol_to_artifact_invalid)
            })
    }

    /// Whether an authenticated RCA1 matches this RCC1, RCU1 request ID and
    /// next RVS1 digest.
    pub(crate) fn acknowledgement_matches(
        &self,
        acknowledgement: &AuthenticatedRevocationAcknowledgement,
    ) -> bool {
        acknowledgement.matches_context(
            &self.context,
            self.revocation_update.request_id,
            self.revocation_update.next_revocation.snapshot_digest(),
        )
    }

    /// R12 §6 steps 15 to 17: verify the recovery floor (the retained SIR1
    /// unchanged, the current SIC1 previous or next), publish the next SIC1
    /// (or verify it when it is already current), remove SIR1 durably, and
    /// authenticate the next state.
    ///
    /// # Errors
    /// Rejects a changed floor and any failed durable step; SIR1 then stays.
    pub(crate) fn publish_successor(
        self,
    ) -> Result<AuthenticatedSelectorBootstrap, SelectorBoundaryError> {
        publish_successor(
            &self.root,
            self.owner,
            &self.previous_manifest,
            &self.next_manifest,
            &self.recovery_file,
            &self.recovery_bytes,
        )
        .and_then(InstalledSelectorState::authenticate_bootstrap)
    }
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
                read_recovery_record(root, metadata.uid())
                    .map(|(file, bytes)| (metadata.uid(), file, bytes))
            })
            .and_then(|(owner, file, bytes)| {
                RecordedRecovery::decode(&bytes)
                    .map_err(map_protocol_to_artifact_invalid)
                    .and_then(|recorded| {
                        let current = installed.manifest_bytes();
                        if current == recorded.previous || current == recorded.next {
                            root.try_clone()
                                .map_err(map_io_to_boundary_failure)
                                .and_then(|root| {
                                    Self::rebuild(
                                        Retained {
                                            root,
                                            owner,
                                            recovery_file: file,
                                        },
                                        bytes,
                                        recorded,
                                    )
                                })
                        } else {
                            Err(SelectorBoundaryError::ArtifactInvalid)
                        }
                    })
            })
    }

    fn rebuild(
        retained: Retained,
        bytes: Vec<u8>,
        recorded: RecordedRecovery,
    ) -> Result<Self, SelectorBoundaryError> {
        let Retained {
            root,
            owner,
            recovery_file,
        } = retained;
        RebuiltRecovery::authenticate(&root, owner, &recorded).and_then(|rebuilt| {
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
                if rebuilt_bytes == bytes.as_slice() {
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
                .and_then(|pending_update| {
                    admitted_provider_binary(&rebuilt.previous)
                        .map(|binary| (pending_update, binary))
                })
                .map(|(pending_update, binary)| Self {
                    sir1_digest: context.sir1_digest,
                    previous_provider_binding_digest: context.previous_provider_binding_digest,
                    previous_runtime_instance_id: recorded.runtime.runtime_instance_id,
                    previous_lifecycle_scope_id: recorded.runtime.lifecycle_scope_id,
                    previous_live_attempt_ids: context.previous_live_attempt_ids.clone(),
                    recovery_peer_slot: recorded.runtime.recovery_peer_slot,
                    previous_installation_digest: rebuilt.previous_installation_digest,
                    selector_nonce: rebuilt.revocation_update.selector_nonce,
                    pending_update,
                    records: PendingRecoveryRecords {
                        root,
                        owner,
                        recovery_file,
                        recovery_bytes: bytes,
                        previous_manifest: recorded.previous,
                        next_manifest: recorded.next,
                        rcu1: recorded.rcu1,
                        revocation_update: rebuilt.revocation_update,
                        context,
                        previous: rebuilt.previous,
                        binary,
                        main_pid: recorded.runtime.main_pid,
                        main_start_time_ticks: recorded.runtime.main_start_time_ticks,
                    },
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
                previous.admit_provider().and_then(|admitted| {
                    PendingRecoveryBinding::rebind(&admitted, recorded.runtime).map(|binding| {
                        Self {
                            previous_installation_digest,
                            revocation_update,
                            binding,
                            previous: admitted,
                        }
                    })
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

/// The SIR1 file as read: its installation root, owner and descriptor.
struct Retained {
    root: File,
    owner: u32,
    recovery_file: File,
}

/// Reads the fixed SIR1 file, refusing it by size before any byte is read
/// or decoded when it exceeds the 48 MiB SIR1 bound, and keeps the
/// descriptor whose identity completion rechecks.
fn read_recovery_record(root: &File, owner: u32) -> Result<(File, Vec<u8>), SelectorBoundaryError> {
    read_held_immutable(root, RECOVERY_NAME, owner, RECOVERY_LIMIT as u64)
}

/// One embedded SIC1 or RCU1: 1 byte to 16 MiB, independently of the
/// 48 MiB SIR1 bound (ADR-069 §4.1 CDDL).
fn record_bytes(value: &Value) -> Result<Vec<u8>, ProtocolError> {
    match value {
        Value::Bytes(bytes) if (1..=EMBEDDED_RECORD_LIMIT).contains(&bytes.len()) => {
            Ok(bytes.clone())
        }
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn an_embedded_record_holds_one_byte_to_exactly_16_mib() {
        // The ADR-069 §4.1 bound itself, independently of the constant.
        const SIXTEEN_MIB: usize = 16 << 20;
        assert_eq!(EMBEDDED_RECORD_LIMIT, SIXTEEN_MIB);
        for length in [1, SIXTEEN_MIB] {
            assert_eq!(
                record_bytes(&Value::Bytes(vec![7; length])).map(|bytes| bytes.len()),
                Ok(length)
            );
        }
        for length in [0, SIXTEEN_MIB + 1] {
            assert_eq!(
                record_bytes(&Value::Bytes(vec![7; length])),
                Err(ProtocolError::InvalidEncoding)
            );
        }
        assert_eq!(
            record_bytes(&Value::Null),
            Err(ProtocolError::InvalidEncoding)
        );
    }

    #[test]
    fn the_sir1_file_is_read_up_to_exactly_48_mib() -> TestResult {
        // The ADR-069 §4.1 bound itself, independently of the constant.
        const FORTY_EIGHT_MIB: usize = 48 << 20;
        let directory = tempfile::tempdir()?;
        let root = File::open(directory.path())?;
        let owner = root.metadata()?.uid();
        let path = directory.path().join(RECOVERY_NAME);
        assert_eq!(RECOVERY_LIMIT, FORTY_EIGHT_MIB);
        for length in [FORTY_EIGHT_MIB, FORTY_EIGHT_MIB + 1] {
            if path.exists() {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            }
            fs::write(&path, vec![0; length])?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
            let read = read_recovery_record(&root, owner).map(|(_, bytes)| bytes);
            if length == FORTY_EIGHT_MIB {
                assert_eq!(read?.len(), FORTY_EIGHT_MIB);
            } else {
                assert_eq!(read, Err(SelectorBoundaryError::ArtifactInvalid));
            }
        }
        Ok(())
    }
}
