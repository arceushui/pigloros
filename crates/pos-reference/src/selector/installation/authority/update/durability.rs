//! Durable SIR1 commit and live successor publication.

use std::fs::File;
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::sync::Arc;

use ciborium::value::Value;
use ed25519_dalek::VerifyingKey;
use rustix::fs::{
    fchmod, fsync, linkat, mkdirat, openat2, renameat_with, statat, unlinkat, AtFlags, Mode,
    OFlags, RenameFlags, ResolveFlags,
};

use super::ValidatedInstallationUpdate;
use crate::evaluator_protocol::encode_with_limit;
use crate::sandbox_provider_protocol::{
    attempt_values, AuthenticatedRevocationAcknowledgement, RecoveryCancellationContext,
    RevocationAcknowledgement,
};
use crate::selector::installation::authority::{
    fresh_selector_id, AdmittedSelectorProvider, InstallationRecoverySnapshot,
    InstallationUpdateCommitError,
};
use crate::selector::installation::{
    ensure_no_pending_recovery, hex_name, open_directory_chain, open_immutable_file,
    read_complete_file, InstallationObjectKind, InstalledSelectorState, MANIFEST_LIMIT,
    MANIFEST_NAME, RECOVERY_NAME,
};
use crate::selector::SelectorBoundaryError;

const STAGING_NAME: &str = ".installation-update-staging";
const RECOVERY_LIMIT: usize = 48 * 1024 * 1024;
const CONTROL_LIMIT: usize = 16 * 1024 * 1024;
const PRIVATE_DIRECTORY_MODE: Mode = Mode::RWXU;
const RECORD_MODE: Mode = Mode::RUSR;

/// One durably committed SIR1 awaiting the timely provider acknowledgement.
#[derive(Debug)]
pub struct CommittedInstallationUpdate {
    admitted: Arc<AdmittedSelectorProvider>,
    update: ValidatedInstallationUpdate,
    snapshot: InstallationRecoverySnapshot,
    sir1_digest: [u8; 32],
    recovery_file: File,
    recovery_bytes: Vec<u8>,
}

impl CommittedInstallationUpdate {
    /// Exact durable SIR1 bytes.
    #[must_use]
    pub fn recovery_bytes(&self) -> &[u8] {
        &self.recovery_bytes
    }

    /// Exact committed SIR1 self-digest.
    #[must_use]
    pub const fn sir1_digest(&self) -> [u8; 32] {
        self.sir1_digest
    }

    /// Exact administrator-signed RCU1 bytes.
    #[must_use]
    pub fn revocation_update_bytes(&self) -> &[u8] {
        self.update.revocation_update_bytes()
    }

    /// Construct the exact RCC1 paired with this SIR1 and RCU1.
    ///
    /// # Errors
    /// Rejects an internally inconsistent retained transaction.
    pub fn cancellation_context(
        &self,
    ) -> Result<RecoveryCancellationContext, SelectorBoundaryError> {
        self.snapshot
            .previous_provider_digest()
            .and_then(|previous_provider_binding_digest| {
                RecoveryCancellationContext::for_committed_recovery(
                    self.sir1_digest,
                    previous_provider_binding_digest,
                    self.update.revocation_update(),
                    self.snapshot.previous_live_attempt_ids().to_vec(),
                    self.snapshot.required_cancelled_attempt_ids().to_vec(),
                )
                .map_err(map_artifact_integrity_failure)
            })
    }

    /// Authenticate one RCA1 against this exact committed live transaction.
    ///
    /// Transport framing, EOF, and the absolute deadline must already have
    /// succeeded before this method is called.
    ///
    /// # Errors
    /// Rejects a forged runtime signature or any committed-identity mismatch.
    pub fn authenticate_live_acknowledgement(
        &self,
        bytes: &[u8],
    ) -> Result<AuthenticatedRevocationAcknowledgement, SelectorBoundaryError> {
        self.cancellation_context().and_then(|context| {
            let (runtime_key_id, runtime_public_key) = self.snapshot.runtime_key();
            VerifyingKey::from_bytes(&runtime_public_key)
                .map_err(map_artifact_integrity_failure)
                .and_then(|runtime_key| {
                    RevocationAcknowledgement::authenticate_for_context(
                        bytes,
                        runtime_key_id,
                        &runtime_key,
                        &context,
                        self.update.revocation_update().request_id,
                        self.update
                            .revocation_update()
                            .next_revocation
                            .snapshot_digest(),
                    )
                    .map_err(map_artifact_integrity_failure)
                })
        })
    }

    /// Recheck the retained SIR1 descriptor and current SIC1 recovery floor.
    ///
    /// # Errors
    /// Rejects replaced, unsafe, truncated, or altered durable state.
    pub fn verify_recovery_floor(&self) -> Result<(), SelectorBoundaryError> {
        let root = &self.admitted.bootstrap().installed().root;
        root.metadata()
            .map_err(map_io_to_boundary_failure)
            .map(|metadata| metadata.uid())
            .and_then(|owner| {
                read_bounded_immutable(root, MANIFEST_NAME, owner, MANIFEST_LIMIT)
                    .map(|current| (owner, current))
            })
            .and_then(|(owner, current)| {
                if current == self.update.previous_manifest_bytes()
                    || current == self.update.next_manifest_bytes()
                {
                    verify_recovery_identity(root, owner, &self.recovery_file, &self.recovery_bytes)
                } else {
                    Err(SelectorBoundaryError::ArtifactInvalid)
                }
            })
    }

    /// Publish successor SIC1, remove SIR1, and admit only the successor state.
    ///
    /// # Errors
    /// Rejects a foreign acknowledgement or changed recovery floor. Every
    /// failure after SIR1 commit leaves previous-state admission closed.
    pub fn complete_live_update(
        self,
        acknowledgement: &AuthenticatedRevocationAcknowledgement,
    ) -> Result<super::super::AuthenticatedSelectorBootstrap, SelectorBoundaryError> {
        self.verify_recovery_floor()
            .and_then(|()| self.cancellation_context())
            .and_then(|context| {
                if acknowledgement.matches_context(
                    &context,
                    self.update.revocation_update().request_id,
                    self.update
                        .revocation_update()
                        .next_revocation
                        .snapshot_digest(),
                ) {
                    Ok(())
                } else {
                    Err(SelectorBoundaryError::ArtifactInvalid)
                }
            })
            .and_then(|()| {
                let root = &self.admitted.bootstrap().installed().root;
                root.metadata()
                    .map_err(map_io_to_boundary_failure)
                    .and_then(|metadata| {
                        publish_successor(
                            root,
                            metadata.uid(),
                            self.update.previous_manifest_bytes(),
                            self.update.next_manifest_bytes(),
                            &self.recovery_file,
                            &self.recovery_bytes,
                        )
                    })
            })
            .and_then(InstalledSelectorState::authenticate_bootstrap)
    }
}

impl AdmittedSelectorProvider {
    /// Durably commit the exact fenced update snapshot as SIR1.
    ///
    /// This consumes previous-state admission authority. A successful commit
    /// can only proceed through live completion or #349 recovery.
    ///
    /// # Errors
    /// Rejects stale authority, pending recovery, unsafe staging state,
    /// changed successor records, oversized SIR1, or synchronization failure.
    pub(crate) fn commit_update(
        self: Arc<Self>,
        update: ValidatedInstallationUpdate,
        snapshot: InstallationRecoverySnapshot,
    ) -> Result<CommittedInstallationUpdate, InstallationUpdateCommitError> {
        let admitted = Arc::clone(&self);
        let installed = self.bootstrap().installed();
        if installed.manifest_bytes() != update.previous_manifest_bytes() {
            return Err(InstallationUpdateCommitError::BeforeRecovery(
                SelectorBoundaryError::ArtifactInvalid,
            ));
        }
        installed
            .root
            .metadata()
            .map_err(map_io_to_boundary_failure)
            .map(|metadata| metadata.uid())
            .and_then(|owner| {
                read_bounded_immutable(&installed.root, MANIFEST_NAME, owner, MANIFEST_LIMIT)
                    .and_then(|current| {
                        if current == update.previous_manifest_bytes() {
                            Ok(owner)
                        } else {
                            Err(SelectorBoundaryError::ArtifactInvalid)
                        }
                    })
            })
            .and_then(|owner| ensure_no_pending_recovery(&installed.root).map(|()| owner))
            .and_then(|owner| snapshot.verify_recovery_peer_reservation().map(|()| owner))
            .and_then(|owner| {
                recovery_bytes(&update, &snapshot).map(|(bytes, digest)| (owner, bytes, digest))
            })
            .and_then(|(owner, bytes, digest)| {
                synchronize_successor_records(installed, &update, owner)
                    .map(|()| (owner, bytes, digest))
            })
            .and_then(|(owner, bytes, digest)| {
                open_staging_directory(&installed.root, owner)
                    .map(|staging| (owner, bytes, digest, staging))
            })
            .map_err(InstallationUpdateCommitError::BeforeRecovery)
            .and_then(|(owner, bytes, digest, staging)| {
                write_recovery(&staging, &installed.root, owner, &bytes)
                    .map(|file| (bytes, digest, file))
            })
            .map(
                |(recovery_bytes, sir1_digest, recovery_file)| CommittedInstallationUpdate {
                    admitted,
                    update,
                    snapshot,
                    sir1_digest,
                    recovery_file,
                    recovery_bytes,
                },
            )
    }
}

fn recovery_bytes(
    update: &ValidatedInstallationUpdate,
    snapshot: &InstallationRecoverySnapshot,
) -> Result<(Vec<u8>, [u8; 32]), SelectorBoundaryError> {
    let records = [
        update.previous_manifest_bytes(),
        update.next_manifest_bytes(),
        update.revocation_update_bytes(),
    ];
    if records
        .iter()
        .any(|record| record.is_empty() || record.len() > CONTROL_LIMIT)
    {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    let unsigned = Value::Array(vec![
        Value::Text("SIR1".to_owned()),
        Value::Integer(1_u64.into()),
        Value::Bytes(records[0].to_vec()),
        Value::Bytes(records[1].to_vec()),
        Value::Bytes(records[2].to_vec()),
        snapshot.previous_provider_value(),
        snapshot.recovery_slot_value(),
        attempt_values(snapshot.previous_live_attempt_ids()),
        attempt_values(snapshot.required_cancelled_attempt_ids()),
    ]);
    encode_with_limit(&unsigned, RECOVERY_LIMIT)
        .map_err(map_artifact_integrity_failure)
        .and_then(|unsigned_bytes| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"PiglorOS.SIR1.v1\0");
            hasher.update(&unsigned_bytes);
            let sir1_digest = *hasher.finalize().as_bytes();
            encode_with_limit(
                &Value::Array(vec![unsigned, Value::Bytes(sir1_digest.to_vec())]),
                RECOVERY_LIMIT,
            )
            .map_err(map_artifact_integrity_failure)
            .map(|encoded| (encoded, sir1_digest))
        })
}

fn synchronize_successor_records(
    installed: &InstalledSelectorState,
    update: &ValidatedInstallationUpdate,
    owner: u32,
) -> Result<(), SelectorBoundaryError> {
    installed
        .root
        .try_clone()
        .map_err(map_io_to_boundary_failure)
        .and_then(|root| open_directory_chain(root, Path::new("authority"), owner))
        .and_then(|directory| {
            [
                (
                    InstallationObjectKind::ADMINISTRATOR_POLICY,
                    update.record_files()[0],
                ),
                (
                    InstallationObjectKind::REVOCATION_SNAPSHOT,
                    update.record_files()[1],
                ),
            ]
            .into_iter()
            .try_for_each(|(kind, held)| {
                let identity = update.next_manifest().authority_digests()[usize::from(kind.code())];
                update
                    .next_manifest()
                    .object(kind, identity)
                    .map_err(map_artifact_integrity_failure)
                    .and_then(|object| {
                        open_immutable_file(
                            &directory,
                            &hex_name(object.content_digest()),
                            kind.required_mode(),
                            object.byte_length(),
                            owner,
                        )
                    })
                    .and_then(|reopened| {
                        reopened
                            .metadata()
                            .map_err(map_io_to_boundary_failure)
                            .and_then(|reopened| {
                                held.metadata()
                                    .map_err(map_io_to_boundary_failure)
                                    .map(|held| (reopened, held))
                            })
                    })
                    .and_then(|(reopened, retained)| {
                        if reopened.dev() == retained.dev() && reopened.ino() == retained.ino() {
                            fsync(held).map_err(map_io_to_boundary_failure)
                        } else {
                            Err(SelectorBoundaryError::ArtifactInvalid)
                        }
                    })
            })
            .and_then(|()| fsync(&directory).map_err(map_io_to_boundary_failure))
        })
        .and_then(|()| fsync(&installed.root).map_err(map_io_to_boundary_failure))
}

fn open_staging_directory(root: &File, owner: u32) -> Result<File, SelectorBoundaryError> {
    let created = match mkdirat(root, STAGING_NAME, PRIVATE_DIRECTORY_MODE) {
        Ok(()) => true,
        Err(rustix::io::Errno::EXIST) => false,
        Err(_) => return Err(SelectorBoundaryError::Io),
    };
    openat2(
        root,
        STAGING_NAME,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(map_artifact_integrity_failure)
    .and_then(|staging| {
        if created {
            fchmod(&staging, PRIVATE_DIRECTORY_MODE)
                .map_err(map_io_to_boundary_failure)
                .and_then(|()| fsync(&staging).map_err(map_io_to_boundary_failure))
                .and_then(|()| fsync(root).map_err(map_io_to_boundary_failure))
                .map(|()| staging)
        } else {
            Ok(staging)
        }
    })
    .and_then(|staging| {
        staging
            .metadata()
            .map_err(map_io_to_boundary_failure)
            .and_then(|metadata| {
                root.metadata()
                    .map_err(map_io_to_boundary_failure)
                    .map(|root_metadata| (metadata, root_metadata))
            })
            .and_then(|(metadata, root_metadata)| {
                if metadata.is_dir()
                    && metadata.uid() == owner
                    && metadata.mode() & 0o7777 == 0o700
                    && metadata.dev() == root_metadata.dev()
                {
                    Ok(staging)
                } else {
                    Err(SelectorBoundaryError::ArtifactInvalid)
                }
            })
    })
}

fn write_recovery(
    staging: &File,
    root: &File,
    owner: u32,
    bytes: &[u8],
) -> Result<File, InstallationUpdateCommitError> {
    temporary_name("sir1")
        .and_then(|name| create_staging_file(staging, &name, owner).map(|file| (name, file)))
        .and_then(|(name, mut temporary)| {
            temporary
                .write_all(bytes)
                .map_err(map_io_to_boundary_failure)
                .and_then(|()| fsync(&temporary).map_err(map_io_to_boundary_failure))
                .map(|()| (name, temporary))
        })
        .map_err(InstallationUpdateCommitError::BeforeRecovery)
        .and_then(|(name, temporary)| {
            renameat_with(staging, &name, root, RECOVERY_NAME, RenameFlags::NOREPLACE)
                .map_err(map_artifact_integrity_failure)
                .map_err(InstallationUpdateCommitError::RecoveryPending)
                .map(|()| temporary)
        })
        .and_then(|temporary| {
            u64::try_from(bytes.len())
                .map_err(map_artifact_integrity_failure)
                .and_then(|length| open_immutable_file(root, RECOVERY_NAME, 0o400, length, owner))
                .map_err(InstallationUpdateCommitError::RecoveryPending)
                .map(|recovery| (temporary, recovery))
        })
        .and_then(|(temporary, recovery)| {
            verify_file_identity(&temporary, &recovery)
                .map_err(InstallationUpdateCommitError::RecoveryPending)
                .map(|()| recovery)
        })
        .and_then(|recovery| {
            fsync(root)
                .map_err(map_io_to_boundary_failure)
                .map_err(InstallationUpdateCommitError::RecoveryPending)
                .map(|()| recovery)
        })
}

fn publish_successor(
    root: &File,
    owner: u32,
    previous: &[u8],
    next: &[u8],
    retained_recovery: &File,
    recovery_bytes: &[u8],
) -> Result<InstalledSelectorState, SelectorBoundaryError> {
    read_bounded_immutable(root, MANIFEST_NAME, owner, MANIFEST_LIMIT)
        .and_then(|current| {
            if current == previous || current == next {
                Ok(current)
            } else {
                Err(SelectorBoundaryError::ArtifactInvalid)
            }
        })
        .and_then(|current| {
            verify_recovery_identity(root, owner, retained_recovery, recovery_bytes)
                .map(|()| current)
        })
        .and_then(|current| {
            if current == next {
                Ok(())
            } else {
                write_successor_manifest(root, owner, next)
            }
        })
        .and_then(|()| verify_recovery_identity(root, owner, retained_recovery, recovery_bytes))
        .and_then(|()| remove_recovery_durably(root, owner))
        .and_then(|()| InstalledSelectorState::open_at_for_owner(root, owner))
}

fn remove_recovery_durably(root: &File, owner: u32) -> Result<(), SelectorBoundaryError> {
    remove_recovery_durably_with(root, owner, |directory| {
        fsync(directory).map_err(map_io_to_boundary_failure)
    })
}

fn remove_recovery_durably_with(
    root: &File,
    owner: u32,
    mut synchronize: impl FnMut(&File) -> Result<(), SelectorBoundaryError>,
) -> Result<(), SelectorBoundaryError> {
    let staging = open_staging_directory(root, owner)?;
    let backup = temporary_name("completed-sir1")?;
    linkat(root, RECOVERY_NAME, &staging, &backup, AtFlags::empty())
        .map_err(map_io_to_boundary_failure)?;
    if let Err(error) = synchronize(&staging) {
        let _cleanup = unlinkat(&staging, &backup, AtFlags::empty());
        return Err(error);
    }
    if let Err(error) = unlinkat(root, RECOVERY_NAME, AtFlags::empty()) {
        let _cleanup = unlinkat(&staging, &backup, AtFlags::empty());
        return Err(map_io_to_boundary_failure(error));
    }
    if let Err(error) = synchronize(root) {
        restore_recovery_marker(root, &staging, &backup, &mut synchronize)?;
        return Err(error);
    }
    let _cleanup = unlinkat(&staging, &backup, AtFlags::empty())
        .map_err(map_io_to_boundary_failure)
        .and_then(|()| synchronize(&staging));
    Ok(())
}

fn restore_recovery_marker(
    root: &File,
    staging: &File,
    backup: &str,
    synchronize: &mut impl FnMut(&File) -> Result<(), SelectorBoundaryError>,
) -> Result<(), SelectorBoundaryError> {
    linkat(staging, backup, root, RECOVERY_NAME, AtFlags::empty())
        .map_err(map_io_to_boundary_failure)?;
    unlinkat(staging, backup, AtFlags::empty()).map_err(map_io_to_boundary_failure)?;
    synchronize(staging)?;
    synchronize(root)
}

fn write_successor_manifest(
    root: &File,
    owner: u32,
    next: &[u8],
) -> Result<(), SelectorBoundaryError> {
    open_staging_directory(root, owner)
        .and_then(|staging| temporary_name("sic1").map(|name| (staging, name)))
        .and_then(|(staging, name)| {
            create_staging_file(&staging, &name, owner).map(|temporary| (staging, name, temporary))
        })
        .and_then(|(staging, name, mut temporary)| {
            temporary
                .write_all(next)
                .map_err(map_io_to_boundary_failure)
                .and_then(|()| fsync(&temporary).map_err(map_io_to_boundary_failure))
                .map(|()| (staging, name))
        })
        .and_then(|(staging, name)| {
            renameat_with(&staging, &name, root, MANIFEST_NAME, RenameFlags::empty())
                .map_err(map_io_to_boundary_failure)
        })
        .and_then(|()| fsync(root).map_err(map_io_to_boundary_failure))
}

fn create_staging_file(
    staging: &File,
    name: &str,
    owner: u32,
) -> Result<File, SelectorBoundaryError> {
    openat2(
        staging,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        RECORD_MODE,
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map(File::from)
    .map_err(map_io_to_boundary_failure)
    .and_then(|file| {
        fchmod(&file, RECORD_MODE)
            .map_err(map_io_to_boundary_failure)
            .and_then(|()| file.metadata().map_err(map_io_to_boundary_failure))
            .and_then(|metadata| {
                if metadata.is_file()
                    && metadata.uid() == owner
                    && metadata.mode() & 0o7777 == 0o400
                    && metadata.nlink() == 1
                    && metadata.len() == 0
                {
                    Ok(file)
                } else {
                    Err(SelectorBoundaryError::ArtifactInvalid)
                }
            })
    })
}

fn read_bounded_immutable(
    root: &File,
    name: &str,
    owner: u32,
    limit: u64,
) -> Result<Vec<u8>, SelectorBoundaryError> {
    statat(root, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(map_io_to_boundary_failure)
        .and_then(|metadata| {
            u64::try_from(metadata.st_size).map_err(map_artifact_integrity_failure)
        })
        .and_then(|length| {
            if length == 0 || length > limit {
                Err(SelectorBoundaryError::ArtifactInvalid)
            } else {
                open_immutable_file(root, name, 0o400, length, owner)
            }
        })
        .and_then(|file| read_complete_file(&file, limit))
}

fn verify_recovery_identity(
    root: &File,
    owner: u32,
    retained: &File,
    expected_bytes: &[u8],
) -> Result<(), SelectorBoundaryError> {
    u64::try_from(expected_bytes.len())
        .map_err(map_artifact_integrity_failure)
        .and_then(|length| open_immutable_file(root, RECOVERY_NAME, 0o400, length, owner))
        .and_then(|current| verify_file_identity(retained, &current).map(|()| current))
        .and_then(|current| read_complete_file(&current, RECOVERY_LIMIT as u64))
        .and_then(|current| {
            if current == expected_bytes {
                Ok(())
            } else {
                Err(SelectorBoundaryError::ArtifactInvalid)
            }
        })
}

fn verify_file_identity(left: &File, right: &File) -> Result<(), SelectorBoundaryError> {
    left.metadata()
        .map_err(map_io_to_boundary_failure)
        .and_then(|left| {
            right
                .metadata()
                .map_err(map_io_to_boundary_failure)
                .map(|right| (left, right))
        })
        .and_then(|(left, right)| {
            if left.dev() == right.dev() && left.ino() == right.ino() {
                Ok(())
            } else {
                Err(SelectorBoundaryError::ArtifactInvalid)
            }
        })
}

fn temporary_name(prefix: &str) -> Result<String, SelectorBoundaryError> {
    fresh_selector_id().and_then(|id| {
        let mut name = String::with_capacity(prefix.len() + 39);
        name.push_str(prefix);
        name.push('-');
        id.into_iter()
            .try_for_each(|byte| {
                use std::fmt::Write as _;
                write!(name, "{byte:02x}").map_err(map_io_to_boundary_failure)
            })
            .map(|()| {
                name.push_str(".cbor");
                name
            })
    })
}

fn map_artifact_integrity_failure<T>(_: T) -> SelectorBoundaryError {
    SelectorBoundaryError::ArtifactInvalid
}

fn map_io_to_boundary_failure<T>(_: T) -> SelectorBoundaryError {
    SelectorBoundaryError::Io
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::selector::installation::tests::updates::pending_update_fixture;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn durable_root() -> Result<(tempfile::TempDir, File, u32), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let root = File::open(directory.path())?;
        let owner = root.metadata()?.uid();
        Ok((directory, root, owner))
    }

    #[test]
    fn staging_directory_and_files_are_private_and_exclusive() -> TestResult {
        let (_directory, root, owner) = durable_root()?;
        let staging = open_staging_directory(&root, owner)?;
        let metadata = staging.metadata()?;
        assert!(metadata.is_dir());
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        verify_file_identity(&staging, &open_staging_directory(&root, owner)?)?;

        let name = temporary_name("coverage")?;
        assert!(name.starts_with("coverage-"));
        assert_eq!(
            Path::new(&name).extension(),
            Some(std::ffi::OsStr::new("cbor"))
        );
        let file = create_staging_file(&staging, &name, owner)?;
        let metadata = file.metadata()?;
        assert!(metadata.is_file());
        assert_eq!(metadata.mode() & 0o7777, 0o400);
        assert!(matches!(
            create_staging_file(&staging, &name, owner),
            Err(SelectorBoundaryError::Io)
        ));
        Ok(())
    }

    #[test]
    fn failed_recovery_unlink_sync_restores_the_fixed_marker() -> TestResult {
        let (directory, root, owner) = durable_root()?;
        let recovery = directory.path().join(RECOVERY_NAME);
        fs::write(&recovery, b"sir1")?;
        fs::set_permissions(&recovery, fs::Permissions::from_mode(0o400))?;
        let calls = Cell::new(0_usize);

        let result = remove_recovery_durably_with(&root, owner, |_| {
            let call = calls.get();
            calls.set(call + 1);
            if call == 1 {
                Err(SelectorBoundaryError::Io)
            } else {
                Ok(())
            }
        });

        assert_eq!(result, Err(SelectorBoundaryError::Io));
        assert_eq!(fs::read(&recovery)?, b"sir1");
        assert_eq!(fs::metadata(recovery)?.nlink(), 1);
        Ok(())
    }

    #[test]
    fn recovery_removal_fails_closed_before_unlink_and_when_marker_disappears() -> TestResult {
        let (directory, root, owner) = durable_root()?;
        let recovery = directory.path().join(RECOVERY_NAME);
        fs::write(&recovery, b"sir1")?;
        fs::set_permissions(&recovery, fs::Permissions::from_mode(0o400))?;
        assert_eq!(
            remove_recovery_durably_with(&root, owner, |_| Err(SelectorBoundaryError::Io)),
            Err(SelectorBoundaryError::Io)
        );
        assert_eq!(fs::read(&recovery)?, b"sir1");

        let calls = Cell::new(0_usize);
        let result = remove_recovery_durably_with(&root, owner, |_| {
            if calls.replace(calls.get() + 1) == 0 {
                fs::remove_file(&recovery).map_err(|_| SelectorBoundaryError::Io)?;
            }
            Ok(())
        });
        assert_eq!(result, Err(SelectorBoundaryError::Io));
        assert!(!recovery.exists());
        Ok(())
    }

    #[test]
    fn recovery_restoration_propagates_each_directory_sync_failure() -> TestResult {
        for failed_call in [2_usize, 3] {
            let (directory, root, owner) = durable_root()?;
            let recovery = directory.path().join(RECOVERY_NAME);
            fs::write(&recovery, b"sir1")?;
            fs::set_permissions(&recovery, fs::Permissions::from_mode(0o400))?;
            let calls = Cell::new(0_usize);
            let result = remove_recovery_durably_with(&root, owner, |_| {
                let call = calls.replace(calls.get() + 1);
                if call == 1 || call == failed_call {
                    Err(SelectorBoundaryError::Io)
                } else {
                    Ok(())
                }
            });
            assert_eq!(result, Err(SelectorBoundaryError::Io));
        }
        Ok(())
    }

    #[test]
    fn recovery_removal_propagates_staging_and_missing_marker_failures() -> TestResult {
        let (_directory, root, owner) = durable_root()?;
        assert!(remove_recovery_durably_with(&root, owner ^ 1, |_| Ok(())).is_err());
        assert_eq!(
            remove_recovery_durably_with(&root, owner, |_| Ok(())),
            Err(SelectorBoundaryError::Io)
        );
        Ok(())
    }

    #[test]
    fn staging_directory_rejects_occupied_and_unsafe_entries() -> TestResult {
        let (occupied, root, owner) = durable_root()?;
        fs::write(occupied.path().join(STAGING_NAME), b"occupied")?;
        assert!(matches!(
            open_staging_directory(&root, owner),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));

        let (unsafe_directory, root, owner) = durable_root()?;
        let staging = unsafe_directory.path().join(STAGING_NAME);
        fs::create_dir(&staging)?;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o755))?;
        assert!(matches!(
            open_staging_directory(&root, owner),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));

        let regular = tempfile::NamedTempFile::new()?;
        assert!(matches!(
            open_staging_directory(regular.as_file(), owner),
            Err(SelectorBoundaryError::Io)
        ));

        let (_directory, root, owner) = durable_root()?;
        let staging = open_staging_directory(&root, owner)?;
        assert!(matches!(
            create_staging_file(&staging, "foreign-owner.cbor", owner.saturating_add(1)),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));

        let ordinary_file = tempfile::NamedTempFile::new()?;
        assert!(matches!(
            create_staging_file(ordinary_file.as_file(), "child", owner),
            Err(SelectorBoundaryError::Io)
        ));

        let (symlink_root, root, owner) = durable_root()?;
        std::os::unix::fs::symlink("missing", symlink_root.path().join(STAGING_NAME))?;
        assert!(matches!(
            open_staging_directory(&root, owner),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        Ok(())
    }

    #[test]
    fn bounded_immutable_reads_reject_missing_empty_and_oversized_files() -> TestResult {
        let (directory, root, owner) = durable_root()?;
        assert!(matches!(
            read_bounded_immutable(&root, "missing", owner, 8),
            Err(SelectorBoundaryError::Io)
        ));

        let empty = directory.path().join("empty");
        fs::write(&empty, [])?;
        fs::set_permissions(&empty, fs::Permissions::from_mode(0o400))?;
        assert!(matches!(
            read_bounded_immutable(&root, "empty", owner, 8),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));

        let record = directory.path().join("record");
        fs::write(&record, b"record")?;
        fs::set_permissions(&record, fs::Permissions::from_mode(0o400))?;
        assert_eq!(
            read_bounded_immutable(&root, "record", owner, 8)?,
            b"record"
        );
        assert!(matches!(
            read_bounded_immutable(&root, "record", owner, 5),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        Ok(())
    }

    #[test]
    fn recovery_write_and_identity_checks_fail_closed() -> TestResult {
        let (directory, root, owner) = durable_root()?;
        let staging = open_staging_directory(&root, owner)?;
        let recovery = write_recovery(&staging, &root, owner, b"recovery")?;
        verify_recovery_identity(&root, owner, &recovery, b"recovery")?;
        assert!(matches!(
            write_recovery(&staging, &root, owner, b"second"),
            Err(InstallationUpdateCommitError::RecoveryPending(_))
        ));

        fs::set_permissions(
            directory.path().join(RECOVERY_NAME),
            fs::Permissions::from_mode(0o600),
        )?;
        fs::write(directory.path().join(RECOVERY_NAME), b"changed!")?;
        fs::set_permissions(
            directory.path().join(RECOVERY_NAME),
            fs::Permissions::from_mode(0o400),
        )?;
        assert!(matches!(
            verify_recovery_identity(&root, owner, &recovery, b"recovery"),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));

        let other_path = directory.path().join("other");
        fs::write(&other_path, b"other")?;
        let other = File::open(other_path)?;
        assert!(matches!(
            verify_file_identity(&recovery, &other),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        Ok(())
    }

    #[test]
    fn recovery_encoding_rejects_each_invalid_control_record() -> TestResult {
        let (_fixture, _admitted, mut update, snapshot) = pending_update_fixture()?;
        update.replace_previous_manifest_for_test(Vec::new());
        assert!(recovery_bytes(&update, &snapshot).is_err());

        let (_fixture, _admitted, mut update, snapshot) = pending_update_fixture()?;
        update.replace_next_manifest_for_test(Vec::new());
        assert!(recovery_bytes(&update, &snapshot).is_err());

        let (_fixture, _admitted, mut update, snapshot) = pending_update_fixture()?;
        update.clear_revocation_update_for_test();
        assert!(recovery_bytes(&update, &snapshot).is_err());

        let oversized = vec![0; CONTROL_LIMIT + 1];
        let (_fixture, _admitted, mut update, snapshot) = pending_update_fixture()?;
        update.replace_previous_manifest_for_test(oversized.clone());
        assert!(recovery_bytes(&update, &snapshot).is_err());

        let (_fixture, _admitted, mut update, snapshot) = pending_update_fixture()?;
        update.replace_next_manifest_for_test(oversized.clone());
        assert!(recovery_bytes(&update, &snapshot).is_err());

        let (_fixture, _admitted, mut update, snapshot) = pending_update_fixture()?;
        update.replace_revocation_update_for_test(oversized);
        assert!(recovery_bytes(&update, &snapshot).is_err());
        Ok(())
    }

    #[test]
    fn successor_publication_rechecks_every_manifest_state() -> TestResult {
        assert_publication_transition(b"previous", b"previous", b"next")?;
        assert_publication_transition(b"next", b"previous", b"next")?;

        let (directory, root, owner) = durable_root()?;
        write_private_record(&directory.path().join(MANIFEST_NAME), b"third")?;
        assert!(matches!(
            publish_successor(&root, owner, b"previous", b"next", &root, b"recovery"),
            Err(SelectorBoundaryError::ArtifactInvalid)
        ));
        Ok(())
    }

    fn assert_publication_transition(current: &[u8], previous: &[u8], next: &[u8]) -> TestResult {
        let (directory, root, owner) = durable_root()?;
        write_private_record(&directory.path().join(MANIFEST_NAME), current)?;
        let staging = open_staging_directory(&root, owner)?;
        let recovery = write_recovery(&staging, &root, owner, b"recovery")?;
        assert!(publish_successor(&root, owner, previous, next, &recovery, b"recovery",).is_err());
        assert_eq!(fs::read(directory.path().join(MANIFEST_NAME))?, next);
        assert!(!directory.path().join(RECOVERY_NAME).exists());
        Ok(())
    }

    fn write_private_record(path: &Path, bytes: &[u8]) -> TestResult {
        fs::write(path, bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
        Ok(())
    }
}
