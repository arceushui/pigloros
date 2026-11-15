//! The SPI1 provider installation file and the runtime-attestation key file
//! (ADR-069 R11 §4, #1358).
//!
//! SPI1 holds only the provider-host values: the attempt address range, the
//! egress-probe /30 and port, the aggregate staging cap, the cleanup phases
//! and the name of the runtime-attestation key file. It is local
//! installation data, not authority: it is closed deterministic CBOR with a
//! BLAKE3 self-digest that detects inconsistent bytes and authenticates
//! nothing, and its bytes and digest never enter an emitted record.
//!
//! [`ProviderInstallation::open`] reads it once from the one fixed path,
//! `/var/lib/pigloros/sandbox/provider-installation.cbor`, beneath the held
//! SIC1 artifact root. No argument, environment variable or descriptor can
//! name another file or override a value. Every rule of R11 §4.3 is checked,
//! in order, and the first failure wins.
//!
//! [`RuntimeKey::open`] opens the key file SPI1 names beneath the same held
//! root, under `provider-keys/` (R11 §4.4).

mod codec;
mod files;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;

use std::fs::File;

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::{CleanupBudget, EgressProbe, InvalidEgressProbe, NetworkRange, StagingLimits};

/// Why the provider installation or its key file was refused. Each refusal
/// keeps the provider from binding any socket.
///
/// The variants follow the R11 §4.3 rules in their order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProviderInstallationError {
    /// Rule 1: the file or an ancestor is missing, unreadable, or breaks the
    /// file rules.
    #[error("the provider installation file is missing or unsafe")]
    UnsafeFile,
    /// Rule 2: the bytes are not canonical SPI1 within its bounds.
    #[error("the provider installation is not canonical SPI1")]
    InvalidEncoding,
    /// Rule 3: the self-digest does not match the bytes.
    #[error("the provider installation digest does not match")]
    DigestMismatch,
    /// Rule 4: the attempt IPv4 range is not an aligned RFC 1918 network.
    #[error("the attempt IPv4 range is not an aligned private network")]
    AttemptIpv4Range,
    /// Rule 5: the attempt IPv6 range is not an aligned `fc00::/7` network.
    #[error("the attempt IPv6 range is not an aligned unique local network")]
    AttemptIpv6Range,
    /// Rule 6: the egress probe is refused by [`EgressProbe::new`].
    #[error(transparent)]
    EgressProbe(#[from] InvalidEgressProbe),
    /// Rule 6b: the egress probe's /30 lies outside RFC 1918 space.
    #[error("the egress probe's /30 is not a private network")]
    EgressProbeNotPrivate,
    /// Rule 7: the egress probe's /30 lies inside the attempt IPv4 range.
    #[error("the egress probe's /30 lies inside the attempt range")]
    EgressProbeInAttemptRange,
    /// Rule 9: the cleanup phases are not strictly increasing.
    #[error("the cleanup phases are not strictly increasing")]
    CleanupBudget,
    /// Rule 10: the key directory is missing or not a root-owned `0700`
    /// directory.
    #[error("the provider key directory is missing or unsafe")]
    UnsafeKeyDirectory,
    /// Rule 10: the key file is missing or breaks the key-file rules.
    #[error("the runtime-attestation key file is missing or unsafe")]
    UnsafeKeyFile,
    /// The key file's public key is not the admitted runtime key.
    #[error("the runtime-attestation key differs from the admitted key")]
    KeyMismatch,
}

/// One validated SPI1 provider installation.
///
/// It retains the SIC1 artifact root it was read beneath, so its key file is
/// opened beneath the very same directory.
#[derive(Debug)]
pub struct ProviderInstallation {
    artifact_root: File,
    owner: u32,
    attempt_range: NetworkRange,
    egress_probe: EgressProbe,
    staging_limits: StagingLimits,
    cleanup_budget: CleanupBudget,
    runtime_key_file: String,
}

impl ProviderInstallation {
    /// Read and validate the one fixed SPI1 file.
    ///
    /// The artifact root `/var/lib/pigloros/sandbox` is opened from `/`
    /// through root-owned directories that no group or other may write,
    /// without following a symlink or magic link. The file is opened beneath
    /// it and read once through its descriptor, which is then closed.
    ///
    /// # Errors
    /// The first R11 §4.3 rule, in order, that the file breaks.
    pub fn open() -> Result<Self, ProviderInstallationError> {
        files::open_artifact_root().and_then(|root| Self::open_beneath(root, 0))
    }

    /// Read and validate SPI1 beneath the held `artifact_root`, whose
    /// directories and files `owner` must own.
    fn open_beneath(artifact_root: File, owner: u32) -> Result<Self, ProviderInstallationError> {
        files::read_installation(&artifact_root, owner)
            .and_then(|bytes| codec::decode(&bytes))
            .map(|fields| Self {
                artifact_root,
                owner,
                attempt_range: fields.attempt_range,
                egress_probe: fields.egress_probe,
                staging_limits: StagingLimits {
                    aggregate_bytes: fields.staging_aggregate_bytes,
                },
                cleanup_budget: fields.cleanup_budget,
                runtime_key_file: fields.runtime_key_file,
            })
    }

    /// The address range reserved for attempt namespaces.
    #[must_use]
    pub const fn attempt_range(&self) -> NetworkRange {
        self.attempt_range
    }

    /// The egress probe's /30 and target port.
    #[must_use]
    pub const fn egress_probe(&self) -> EgressProbe {
        self.egress_probe
    }

    /// The owner-set aggregate staging cap (Q9.7).
    #[must_use]
    pub const fn staging_limits(&self) -> StagingLimits {
        self.staging_limits
    }

    /// The per-attempt cleanup phases.
    #[must_use]
    pub const fn cleanup_budget(&self) -> CleanupBudget {
        self.cleanup_budget
    }

    /// The name of the runtime-attestation key file in `provider-keys/`.
    #[must_use]
    pub fn runtime_key_file(&self) -> &str {
        &self.runtime_key_file
    }
}

/// The runtime-attestation key, loaded from the key file SPI1 names.
///
/// The seed is read once into wiped memory; the key wipes itself when
/// dropped and is never printed.
pub struct RuntimeKey {
    key: SigningKey,
}

impl std::fmt::Debug for RuntimeKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RuntimeKey")
    }
}

impl RuntimeKey {
    /// Load the key file `installation` names from `provider-keys/`.
    ///
    /// The directory must be a `0700` directory and the file a singly linked
    /// regular file of mode `0400` or `0600` holding exactly the 32-byte
    /// Ed25519 seed, both owned by root. Neither is reached through a
    /// symlink or magic link.
    ///
    /// # Errors
    /// [`ProviderInstallationError::UnsafeKeyDirectory`] or
    /// [`ProviderInstallationError::UnsafeKeyFile`].
    pub fn open(installation: &ProviderInstallation) -> Result<Self, ProviderInstallationError> {
        files::read_runtime_key(
            &installation.artifact_root,
            &installation.runtime_key_file,
            installation.owner,
        )
        .map(|seed| Self {
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// The public key of this seed.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Keep this key only if its public key is `admitted`: the TRS1 role-3
    /// key bound to the SPM1 runtime-attestation key ID.
    ///
    /// # Errors
    /// [`ProviderInstallationError::KeyMismatch`] for any other public key.
    pub fn require_admitted(
        self,
        admitted: &VerifyingKey,
    ) -> Result<Self, ProviderInstallationError> {
        if self.verifying_key() == *admitted {
            Ok(self)
        } else {
            Err(ProviderInstallationError::KeyMismatch)
        }
    }

    /// The one R9 runtime-attestation signer of this key, for the
    /// SPM1-admitted `key_id`.
    pub(crate) fn into_signer(self, key_id: String) -> crate::KeyFileReleaseSigner {
        crate::KeyFileReleaseSigner::from_signing_key(self.key, key_id)
    }
}
