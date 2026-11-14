//! The one runtime-attestation signer of the provider (ADR-069 R9 §5).
//!
//! [`RuntimeAttestationSigner`] is the only signing port. It accepts nothing
//! but a sealed [`SelfDigested`] record of a [`RuntimeSigned`] kind, built by
//! the `pos_reference` record encoders, and signs the message that record
//! derives: `PiglorOS.<M>.Signature.v1\0 || self_digest`. It is given no
//! bytes, digest or kind, so it is no signing oracle. [`sign_verified`]
//! verifies each signature under the admitted runtime key before it is
//! returned: a signature that does not verify is never emitted.
//!
//! The shipped adapter, [`KeyFileRuntimeSigner`], loads the provider's
//! Ed25519 seed from a root-owned key file. The key never leaves the process.
//!
//! Key file contract (recorded for owner review, not yet an ADR rule; R9 O1):
//! a regular, non-symlink file directly beneath a held directory that the
//! caller has verified as provider-owned and private; owned by the provider
//! uid; mode 0400 or 0600; exactly 32 raw bytes holding the Ed25519 seed. The
//! runtime-attestation key ID comes from the admitted SPM1, never from the
//! file.

use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use pos_reference::sandbox_provider_protocol::{
    ExecutionRelease, ExecutionReleaseFields, RuntimeSigned, SandboxProviderProtocolError,
    SelfDigested,
};
use rustix::fs::{openat2, Mode, OFlags, ResolveFlags};
use zeroize::Zeroizing;

const SEED_BYTES: u64 = 32;
// Read-only (`O_RDONLY` is zero), close-on-exec and non-blocking, so a FIFO
// cannot stall the open before the regular-file check. `RESOLVE_NO_SYMLINKS`
// also rejects a symlink in the final component.
const KEY_OPEN_FLAGS: OFlags = OFlags::CLOEXEC.union(OFlags::NONBLOCK);
const KEY_RESOLVE: ResolveFlags = ResolveFlags::BENEATH.union(ResolveFlags::NO_SYMLINKS);

/// The signing port for the provider's runtime-attestation key.
pub trait RuntimeAttestationSigner {
    /// The SPM1-named runtime-attestation key ID this signer holds.
    fn runtime_attestation_key_id(&self) -> &str;

    /// Sign the message `record` derives and return the Ed25519 signature.
    fn sign<M: RuntimeSigned>(&self, record: &SelfDigested<M>) -> [u8; 64];
}

/// The admitted runtime-attestation key: its SPM1 key ID and the public key
/// that TRS1 authorizes. Every emitted signature verifies under it.
#[derive(Clone, Copy, Debug)]
pub struct AdmittedRuntimeKey<'a> {
    key_id: &'a str,
    key: &'a VerifyingKey,
}

impl<'a> AdmittedRuntimeKey<'a> {
    /// The admitted key `key_id`, whose public key is `key`.
    #[must_use]
    pub const fn new(key_id: &'a str, key: &'a VerifyingKey) -> Self {
        Self { key_id, key }
    }

    /// The admitted key ID.
    #[must_use]
    pub const fn key_id(&self) -> &'a str {
        self.key_id
    }
}

/// Closed failures of the runtime-attestation signing boundary.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeSignerError {
    /// The key file is not a private, provider-owned, 32-byte regular file.
    #[error("runtime-attestation key file is unsafe")]
    UnsafeKeyFile,
    /// The signer or the record names another key than the admitted one.
    #[error("runtime-attestation key id differs from the admitted key")]
    KeyIdMismatch,
    /// The signature does not verify under the admitted key; nothing is
    /// emitted and the provider fault closes admission.
    #[error("the runtime-attestation signature does not verify")]
    Unverified,
    /// The record fields or signature are invalid.
    #[error(transparent)]
    Protocol(#[from] SandboxProviderProtocolError),
    /// An operating-system operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Sign `record` with `signer`, and return the signature only once it
/// verified under the admitted key (R9 §5, "verify before emission").
///
/// # Errors
/// `KeyIdMismatch` when the signer holds another key, and `Unverified` when
/// the signature does not verify.
pub fn sign_verified<S, M>(
    signer: &S,
    admitted: AdmittedRuntimeKey<'_>,
    record: &SelfDigested<M>,
) -> Result<[u8; 64], RuntimeSignerError>
where
    S: RuntimeAttestationSigner,
    M: RuntimeSigned,
{
    if signer.runtime_attestation_key_id() != admitted.key_id {
        return Err(RuntimeSignerError::KeyIdMismatch);
    }
    let signature = signer.sign(record);
    record
        .verify(&signature, admitted.key)
        .map(|()| signature)
        .map_err(|_| RuntimeSignerError::Unverified)
}

/// Ed25519 signer backed by a root-owned key file.
#[derive(Debug)]
pub struct KeyFileRuntimeSigner {
    key: SigningKey,
    key_id: String,
}

impl KeyFileRuntimeSigner {
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
    ) -> Result<Self, RuntimeSignerError> {
        let mut file = openat2(
            directory,
            file_name,
            KEY_OPEN_FLAGS,
            Mode::empty(),
            KEY_RESOLVE,
        )
        .map(File::from)
        .map_err(io::Error::from)?;
        file.metadata()
            .map_err(RuntimeSignerError::from)
            .and_then(|metadata| {
                if !metadata.is_file()
                    || metadata.uid() != owner
                    || !matches!(metadata.mode() & 0o7777, 0o400 | 0o600)
                    || metadata.len() != SEED_BYTES
                {
                    Err(RuntimeSignerError::UnsafeKeyFile)
                } else {
                    Ok(())
                }
            })
            .and_then(|()| {
                // The stack copy of the seed is wiped on drop, on every path;
                // `SigningKey` wipes its own copy.
                let mut seed = Zeroizing::new([0_u8; 32]);
                file.read_exact(&mut *seed)
                    .map(|()| Self {
                        key: SigningKey::from_bytes(&seed),
                        key_id,
                    })
                    .map_err(RuntimeSignerError::from)
            })
    }
}

impl RuntimeAttestationSigner for KeyFileRuntimeSigner {
    fn runtime_attestation_key_id(&self) -> &str {
        &self.key_id
    }

    fn sign<M: RuntimeSigned>(&self, record: &SelfDigested<M>) -> [u8; 64] {
        self.key.sign(&record.signature_message()).to_bytes()
    }
}

/// Build, sign and verify one `ReleaseV1` under the admitted key.
///
/// # Errors
/// `KeyIdMismatch` if the fields or the signer name another key than the
/// admitted one, `Protocol` for invalid fields, and `Unverified` for a
/// signature that does not verify.
pub fn issue_release<S>(
    signer: &S,
    admitted: AdmittedRuntimeKey<'_>,
    fields: ExecutionReleaseFields,
) -> Result<ExecutionRelease, RuntimeSignerError>
where
    S: RuntimeAttestationSigner,
{
    if fields.runtime_attestation_key_id != admitted.key_id {
        return Err(RuntimeSignerError::KeyIdMismatch);
    }
    let record = ExecutionRelease::self_digested(fields)?;
    sign_verified(signer, admitted, &record)
        .and_then(|signature| ExecutionRelease::new(record, signature).map_err(Into::into))
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
                KeyFileRuntimeSigner::open(&directory, "key", owner, "runtime".to_owned())?;
            assert_eq!(signer.runtime_attestation_key_id(), "runtime");
            let public = SigningKey::from_bytes(&[42; 32]).verifying_key();
            let admitted = AdmittedRuntimeKey::new("runtime", &public);
            assert_eq!(admitted.key_id(), "runtime");
            let release = issue_release(&signer, admitted, fields("runtime"))?;
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
            let result = KeyFileRuntimeSigner::open(&directory, "key", owner, "k".to_owned());
            assert!(matches!(result, Err(RuntimeSignerError::UnsafeKeyFile)));
        }
        // Unreadable modes fail at open (non-root) or at the mode check (root).
        for mode in [0o200, 0o000] {
            let (_temporary, directory, owner) = fixture(mode, &[1; 32])?;
            let result = KeyFileRuntimeSigner::open(&directory, "key", owner, "k".to_owned());
            assert!(result.is_err());
        }
        let (_temporary, directory, owner) = fixture(0o600, &[1; 32])?;
        let result = KeyFileRuntimeSigner::open(&directory, "key", owner + 1, "k".to_owned());
        assert!(matches!(result, Err(RuntimeSignerError::UnsafeKeyFile)));
        Ok(())
    }

    #[test]
    fn missing_symlink_and_directory_key_entries_are_rejected() -> TestResult {
        let (temporary, directory, owner) = fixture(0o600, &[1; 32])?;
        let nested = temporary.path().join("nested");
        fs::create_dir(&nested)?;
        let inner = File::open(&nested)?;
        // A valid key above the held directory must stay unreachable.
        let escaped = KeyFileRuntimeSigner::open(&inner, "../key", owner, "k".to_owned());
        assert!(escaped.is_err());
        symlink("key", temporary.path().join("link"))?;
        fs::create_dir(temporary.path().join("subdirectory"))?;
        for name in ["missing", "link", "subdirectory", "../key"] {
            let result = KeyFileRuntimeSigner::open(&directory, name, owner, "k".to_owned());
            assert!(result.is_err());
        }
        Ok(())
    }

    #[test]
    fn a_release_naming_another_key_or_invalid_fields_is_not_signed() -> TestResult {
        let (_temporary, directory, owner) = fixture(0o600, &[42; 32])?;
        let signer = KeyFileRuntimeSigner::open(&directory, "key", owner, "runtime".to_owned())?;
        let public = SigningKey::from_bytes(&[42; 32]).verifying_key();
        let admitted = AdmittedRuntimeKey::new("runtime", &public);
        assert!(matches!(
            issue_release(&signer, admitted, fields("other")),
            Err(RuntimeSignerError::KeyIdMismatch)
        ));
        let other = AdmittedRuntimeKey::new("other", &public);
        assert!(matches!(
            issue_release(&signer, other, fields("other")),
            Err(RuntimeSignerError::KeyIdMismatch)
        ));
        let mut invalid = fields("runtime");
        invalid.deadline_monotonic_ns = 0;
        assert!(matches!(
            issue_release(&signer, admitted, invalid),
            Err(RuntimeSignerError::Protocol(_))
        ));
        Ok(())
    }

    #[test]
    fn a_signature_that_does_not_verify_under_the_admitted_key_is_never_emitted() -> TestResult {
        let (_temporary, directory, owner) = fixture(0o600, &[42; 32])?;
        let signer = KeyFileRuntimeSigner::open(&directory, "key", owner, "runtime".to_owned())?;
        let foreign = SigningKey::from_bytes(&[43; 32]).verifying_key();
        let admitted = AdmittedRuntimeKey::new("runtime", &foreign);
        assert!(matches!(
            issue_release(&signer, admitted, fields("runtime")),
            Err(RuntimeSignerError::Unverified)
        ));
        let record = ExecutionRelease::self_digested(fields("runtime"))?;
        assert!(matches!(
            sign_verified(&signer, admitted, &record),
            Err(RuntimeSignerError::Unverified)
        ));
        let public = SigningKey::from_bytes(&[42; 32]).verifying_key();
        let signature = sign_verified(
            &signer,
            AdmittedRuntimeKey::new("runtime", &public),
            &record,
        )?;
        record.verify(&signature, &public)?;
        Ok(())
    }
}
