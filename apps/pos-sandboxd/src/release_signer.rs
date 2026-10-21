//! Runtime-attestation signing of `ReleaseV1` (ADR-069 section 6, #441).
//!
//! [`ReleaseSigner`] is the port the launch path signs through. The shipped
//! adapter, [`KeyFileReleaseSigner`], loads the provider's Ed25519 seed from a
//! root-owned key file. The key never leaves the process: callers receive only
//! signatures over the domain-separated `RLS1` message.
//!
//! Key file contract (recorded for owner review, not yet an ADR rule): a
//! regular, non-symlink file directly beneath a held, provider-owned
//! directory; owned by the provider uid; mode 0400 or 0600; exactly 32 raw
//! bytes holding the Ed25519 seed. The runtime-attestation key ID comes from
//! the admitted SPM1, never from the file.

use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;

use ed25519_dalek::{Signer, SigningKey};
use pos_reference::sandbox_provider_protocol::{
    ExecutionRelease, ExecutionReleaseFields, SandboxProviderProtocolError,
};
use rustix::fs::{openat2, Mode, OFlags, ResolveFlags};

const SEED_BYTES: u64 = 32;

/// The signing port for the provider runtime-attestation key.
pub trait ReleaseSigner {
    /// The SPM1-admitted runtime-attestation key ID this signer represents.
    fn runtime_attestation_key_id(&self) -> &str;

    /// Sign the exact domain-separated message and return the Ed25519 signature.
    fn sign(&self, message: &[u8]) -> [u8; 64];
}

/// Closed failures of the release-signing boundary.
#[derive(Debug, thiserror::Error)]
pub enum ReleaseSignerError {
    /// The key file is not a private, provider-owned, 32-byte regular file.
    #[error("release signing key file is unsafe")]
    UnsafeKeyFile,
    /// The release names a different key ID than the signer holds.
    #[error("release key id differs from the signer")]
    KeyIdMismatch,
    /// The release fields or signature are invalid.
    #[error(transparent)]
    Protocol(#[from] SandboxProviderProtocolError),
    /// An operating-system operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Ed25519 signer backed by a root-owned key file.
#[derive(Debug)]
pub struct KeyFileReleaseSigner {
    key: SigningKey,
    key_id: String,
}

impl KeyFileReleaseSigner {
    /// Load the seed from `file_name` beneath the held `directory`.
    ///
    /// # Errors
    /// `UnsafeKeyFile` for a symlink, non-regular file, another owner, any
    /// group/other or execute permission, or a length other than 32 bytes.
    pub fn open(
        directory: &File,
        file_name: &str,
        owner: u32,
        key_id: String,
    ) -> Result<Self, ReleaseSignerError> {
        let mut file = openat2(
            directory,
            file_name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map(File::from)
        .map_err(io::Error::from)?;
        file.metadata()
            .map_err(ReleaseSignerError::from)
            .and_then(|metadata| {
                if !metadata.is_file()
                    || metadata.uid() != owner
                    || metadata.mode() & 0o177 != 0
                    || metadata.len() != SEED_BYTES
                {
                    Err(ReleaseSignerError::UnsafeKeyFile)
                } else {
                    Ok(())
                }
            })
            .and_then(|()| {
                let mut seed = [0_u8; 32];
                file.read_exact(&mut seed)
                    .map(|()| Self {
                        key: SigningKey::from_bytes(&seed),
                        key_id,
                    })
                    .map_err(ReleaseSignerError::from)
            })
    }
}

impl ReleaseSigner for KeyFileReleaseSigner {
    fn runtime_attestation_key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }
}

/// Build and sign one `ReleaseV1` through `signer`.
///
/// # Errors
/// `KeyIdMismatch` if the fields name another key, and `Protocol` for invalid
/// fields or a zero signature.
pub fn issue_release(
    signer: &dyn ReleaseSigner,
    fields: ExecutionReleaseFields,
) -> Result<ExecutionRelease, ReleaseSignerError> {
    if fields.runtime_attestation_key_id != signer.runtime_attestation_key_id() {
        return Err(ReleaseSignerError::KeyIdMismatch);
    }
    ExecutionRelease::sign(fields, |message| signer.sign(message)).map_err(Into::into)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    use super::*;

    type TestResult = Result<(), Box<dyn Error>>;

    fn fields(key_id: &str) -> ExecutionReleaseFields {
        ExecutionReleaseFields {
            attempt_id: [1; 16],
            nonce: [2; 32],
            ready1_digest: [3; 32],
            trs1_digest: [4; 32],
            rvs1_digest: [5; 32],
            apt1_digest: [6; 32],
            trust_epoch: 1,
            revocation_epoch: 2,
            policy_epoch: 3,
            expected_readback_digest: [7; 32],
            observed_readback_digest: [8; 32],
            deadline_monotonic_ns: 9,
            runtime_attestation_key_id: key_id.to_owned(),
        }
    }

    fn fixture(mode: u32, bytes: &[u8]) -> Result<(tempfile::TempDir, File, u32), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let key = temporary.path().join("key");
        fs::write(&key, bytes)?;
        fs::set_permissions(&key, fs::Permissions::from_mode(mode))?;
        let directory = File::open(temporary.path())?;
        let owner = directory.metadata()?.uid();
        Ok((temporary, directory, owner))
    }

    #[test]
    fn a_private_key_file_signs_a_verifiable_release() -> TestResult {
        for mode in [0o400, 0o600] {
            let (_temporary, directory, owner) = fixture(mode, &[42; 32])?;
            let signer =
                KeyFileReleaseSigner::open(&directory, "key", owner, "runtime".to_owned())?;
            assert_eq!(signer.runtime_attestation_key_id(), "runtime");
            let release = issue_release(&signer, fields("runtime"))?;
            let public = SigningKey::from_bytes(&[42; 32]).verifying_key();
            release.verify_signature(&public)?;
            let decoded = ExecutionRelease::from_canonical_cbor(&release.to_canonical_cbor()?)?;
            assert_eq!(decoded, release);
        }
        Ok(())
    }

    #[test]
    fn an_unsafe_key_file_is_rejected() -> TestResult {
        for (mode, length) in [
            (0o640, 32),
            (0o604, 32),
            (0o700, 32),
            (0o600, 31),
            (0o600, 33),
        ] {
            let (_temporary, directory, owner) = fixture(mode, &vec![1; length])?;
            let result = KeyFileReleaseSigner::open(&directory, "key", owner, "k".to_owned());
            assert!(matches!(result, Err(ReleaseSignerError::UnsafeKeyFile)));
        }
        let (_temporary, directory, owner) = fixture(0o600, &[1; 32])?;
        let result = KeyFileReleaseSigner::open(&directory, "key", owner + 1, "k".to_owned());
        assert!(matches!(result, Err(ReleaseSignerError::UnsafeKeyFile)));
        Ok(())
    }

    #[test]
    fn missing_symlink_and_directory_key_entries_are_rejected() -> TestResult {
        let (temporary, directory, owner) = fixture(0o600, &[1; 32])?;
        symlink("key", temporary.path().join("link"))?;
        fs::create_dir(temporary.path().join("subdirectory"))?;
        for name in ["missing", "link", "subdirectory", "../key"] {
            let result = KeyFileReleaseSigner::open(&directory, name, owner, "k".to_owned());
            assert!(result.is_err());
        }
        Ok(())
    }

    #[test]
    fn a_release_naming_another_key_or_invalid_fields_is_not_signed() -> TestResult {
        let (_temporary, directory, owner) = fixture(0o600, &[42; 32])?;
        let signer = KeyFileReleaseSigner::open(&directory, "key", owner, "runtime".to_owned())?;
        assert!(matches!(
            issue_release(&signer, fields("other")),
            Err(ReleaseSignerError::KeyIdMismatch)
        ));
        let mut invalid = fields("runtime");
        invalid.deadline_monotonic_ns = 0;
        assert!(matches!(
            issue_release(&signer, invalid),
            Err(ReleaseSignerError::Protocol(_))
        ));
        Ok(())
    }
}
