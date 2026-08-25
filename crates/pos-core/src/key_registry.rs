//! Role-separated key-registry and irreversible-destruction contracts.
//!
//! The core boundary deliberately carries no private key bytes.  A registry
//! records a role/epoch identity, a fingerprint of the private material, and
//! (for signing roles) the public verification key.  Destruction clears the
//! private-material fingerprint from the live record and leaves an immutable
//! tombstone so that the identity cannot be restored or reused.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Hash, PublicKey};

/// The five independent key roles required by the Wave 8 boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum KeyRoleV1 {
    /// Encrypts subject data at rest.
    SubjectDataEncryption,
    /// Signs subject-attribution records.
    SubjectAttributionSigning,
    /// Signs Timeline integrity evidence.
    TimelineIntegritySigning,
    /// Signs Plugin releases.
    PluginReleaseSigning,
    /// Encrypts exported data for recipients.
    ExportRecipientEncryption,
}

impl KeyRoleV1 {
    /// Return the stable wire code for this role.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::SubjectDataEncryption => 0,
            Self::SubjectAttributionSigning => 1,
            Self::TimelineIntegritySigning => 2,
            Self::PluginReleaseSigning => 3,
            Self::ExportRecipientEncryption => 4,
        }
    }

    /// Decode a stable role code.
    ///
    /// # Errors
    ///
    /// Returns [`KeyRegistryErrorV1::InvalidRoleCode`] for an unknown code.
    pub const fn from_code(code: u8) -> Result<Self, KeyRegistryErrorV1> {
        match code {
            0 => Ok(Self::SubjectDataEncryption),
            1 => Ok(Self::SubjectAttributionSigning),
            2 => Ok(Self::TimelineIntegritySigning),
            3 => Ok(Self::PluginReleaseSigning),
            4 => Ok(Self::ExportRecipientEncryption),
            _ => Err(KeyRegistryErrorV1::InvalidRoleCode),
        }
    }

    /// Whether this role carries a signing key and therefore needs a public
    /// verification key in its registry record.
    #[must_use]
    pub const fn is_signing(self) -> bool {
        matches!(
            self,
            Self::SubjectAttributionSigning
                | Self::TimelineIntegritySigning
                | Self::PluginReleaseSigning
        )
    }

    /// Whether this role carries encryption key material rather than a
    /// verification key.
    #[must_use]
    pub const fn is_encryption(self) -> bool {
        matches!(
            self,
            Self::SubjectDataEncryption | Self::ExportRecipientEncryption
        )
    }
}

/// Security disposition for signatures emitted by the pre-#183
/// subject-data-key path described by ADR-041.
///
/// This is a policy marker, not a compatibility implementation: the current
/// product has no legacy signer, migration path, or `ReplayClaim` upgrade
/// path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacySubjectDataSignatureDispositionV1 {
    /// Existing signatures may be verified with their recorded public key,
    /// but cannot be reissued, migrated, or used to upgrade a replay claim.
    VerifyOnlyNoReplayUpgrade,
}

impl LegacySubjectDataSignatureDispositionV1 {
    /// Return the only permitted disposition.
    #[must_use]
    pub const fn current() -> Self {
        Self::VerifyOnlyNoReplayUpgrade
    }
}

/// A role and monotonically increasing key epoch.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct KeyIdentityV1 {
    /// Independent cryptographic role.
    pub role: KeyRoleV1,
    /// Monotonically increasing epoch within `role`; zero is reserved.
    pub epoch: u64,
}

impl KeyIdentityV1 {
    /// Construct a role/epoch identity.
    #[must_use]
    pub const fn new(role: KeyRoleV1, epoch: u64) -> Self {
        Self { role, epoch }
    }
}

/// A registry input.  `private_material_digest` is a fingerprint, never the
/// private material itself.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyRegistrationV1 {
    /// Role/epoch being registered.
    pub identity: KeyIdentityV1,
    /// Digest of the private material held by an adapter.
    pub private_material_digest: Hash,
    /// Public verification material for signing roles only.
    pub public_verification_key: Option<PublicKey>,
}

impl KeyRegistrationV1 {
    /// Construct a registry input.
    #[must_use]
    pub const fn new(
        identity: KeyIdentityV1,
        private_material_digest: Hash,
        public_verification_key: Option<PublicKey>,
    ) -> Self {
        Self {
            identity,
            private_material_digest,
            public_verification_key,
        }
    }
}

/// The live public view of one registered key.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyRecordV1 {
    /// Role/epoch identity.
    pub identity: KeyIdentityV1,
    /// `None` after irreversible destruction.
    pub private_material_digest: Option<Hash>,
    /// Retained after destruction for signature verification.
    pub public_verification_key: Option<PublicKey>,
}

/// A durable proof that a key identity was destroyed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyTombstoneV1 {
    /// Destroyed role/epoch identity.
    pub identity: KeyIdentityV1,
    /// Fingerprint retained to prohibit material reuse.
    pub destroyed_material_digest: Hash,
    /// Digest binding the destruction request to this tombstone.
    pub destruction_digest: Hash,
}

/// A destruction request.  The authorization is already reduced to a digest
/// before it reaches this boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyDestructionRequestV1 {
    /// Identity to destroy.
    pub identity: KeyIdentityV1,
    /// Expected currently registered private-material fingerprint.
    pub expected_material_digest: Hash,
    /// Authorization/provenance digest for the destruction request.
    pub authorization_digest: Hash,
}

impl KeyDestructionRequestV1 {
    /// Construct a destruction request.
    #[must_use]
    pub const fn new(
        identity: KeyIdentityV1,
        expected_material_digest: Hash,
        authorization_digest: Hash,
    ) -> Self {
        Self {
            identity,
            expected_material_digest,
            authorization_digest,
        }
    }
}

/// Result of a destruction command.  Repeating the exact command is safe and
/// returns the original tombstone rather than attempting restoration or reuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyDestructionOutcomeV1 {
    /// Private material was destroyed and a tombstone was committed.
    Destroyed(KeyTombstoneV1),
    /// The identity was already destroyed; the original tombstone is stable.
    AlreadyDestroyed(KeyTombstoneV1),
}

impl KeyDestructionOutcomeV1 {
    /// Return the durable tombstone for either outcome.
    #[must_use]
    pub const fn tombstone(self) -> KeyTombstoneV1 {
        match self {
            Self::Destroyed(tombstone) | Self::AlreadyDestroyed(tombstone) => tombstone,
        }
    }
}

/// Idempotent registration result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyRegistrationOutcomeV1 {
    /// A new live record was inserted.
    Registered,
    /// The exact same live record already existed.
    AlreadyRegistered,
}

/// Closed failures for the key-registry and destruction ports.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum KeyRegistryErrorV1 {
    /// Key epochs start at one.
    #[error("key epoch zero is reserved")]
    InvalidEpoch,
    /// Unknown role code while decoding a stable representation.
    #[error("invalid key role code")]
    InvalidRoleCode,
    /// The requested epoch is behind the highest accepted role epoch.
    #[error("stale key epoch for {role:?}: requested {requested}, highest {active}")]
    StaleEpoch {
        /// Role being rotated.
        role: KeyRoleV1,
        /// Requested epoch.
        requested: u64,
        /// Highest epoch previously accepted for the role.
        active: u64,
    },
    /// One identity cannot be registered with two different materials.
    #[error("key identity is already registered with different material")]
    IdentityConflict,
    /// The same private material fingerprint was used for another identity.
    #[error("private key material cannot be reused across roles or epochs")]
    MaterialReuse,
    /// A signing role omitted its public verification key.
    #[error("signing role requires public verification material")]
    MissingPublicVerificationKey,
    /// An encryption role supplied signing verification material.
    #[error("encryption role cannot carry public verification material")]
    UnexpectedPublicVerificationKey,
    /// A signing operation was requested for an encryption role.
    #[error("only signing roles may create role-bound signatures")]
    SigningRoleRequired,
    /// An encryption operation was requested for a signing role.
    #[error("only encryption roles may authorize protected material use")]
    EncryptionRoleRequired,
    /// The identity is permanently tombstoned.
    #[error("key identity has been irreversibly destroyed")]
    Destroyed,
    /// No live record exists for the identity.
    #[error("key identity is not registered")]
    NotFound,
    /// The identity is registered but is no longer the active role epoch.
    #[error("key identity is not the active epoch for its role")]
    InactiveKey,
    /// The supplied signer does not match the registered key material.
    #[error("signing key does not match the registered identity")]
    SigningKeyMismatch,
    /// The supplied encryption material does not match the registered identity.
    #[error("encryption key does not match the registered identity")]
    EncryptionKeyMismatch,
    /// The registry adapter could not provide its atomic signing boundary.
    #[error("key registry is unavailable for authorized signing")]
    RegistryUnavailable,
    /// A decoded durable snapshot violates the registry invariants.
    #[error("key registry state is invalid")]
    InvalidState,
    /// The destruction request does not match the live record.
    #[error("destruction request has the wrong material fingerprint")]
    MaterialDigestMismatch,
    /// A repeated destruction request does not match the durable tombstone.
    #[error("destruction request authorization does not match the tombstone")]
    DestructionAuthorizationMismatch,
}

/// Registry operations needed by the core and its storage adapters.
pub trait KeyRegistryPortV1 {
    /// Register one role/epoch record.
    ///
    /// # Errors
    ///
    /// Returns a closed [`KeyRegistryErrorV1`] when the epoch, role material,
    /// or identity conflicts with registry state.
    fn register_key(
        &mut self,
        registration: KeyRegistrationV1,
    ) -> Result<KeyRegistrationOutcomeV1, KeyRegistryErrorV1>;
    /// Return the active epoch for a role.
    fn active_key(&self, role: KeyRoleV1) -> Option<KeyRecordV1>;
    /// Return a live or destroyed record by identity.
    fn key_record(&self, identity: KeyIdentityV1) -> Option<KeyRecordV1>;
    /// Return the immutable tombstone for an identity.
    fn tombstone(&self, identity: KeyIdentityV1) -> Option<KeyTombstoneV1>;
}

/// Atomic signing boundary supplied by a key-registry adapter.
///
/// The adapter must validate the supplied identity, private-material digest,
/// and public verification key, then hold its transaction/lock through
/// `operation`.  This makes the callback the linearization point: destruction
/// that wins before authorization prevents the callback, while destruction
/// that follows the callback cannot be observed as preceding the signature.
/// The callback receives no bearer token that can outlive the operation.
pub trait KeyRegistrySigningPortV1 {
    /// Run one signing operation while its registry authorization is held.
    ///
    /// # Errors
    ///
    /// Returns a closed [`KeyRegistryErrorV1`] when the identity is absent,
    /// destroyed, inactive, mismatched, or the adapter cannot provide the
    /// authorization boundary.  The callback is not invoked on failure.
    fn with_signing_authorization<T, F>(
        &mut self,
        identity: KeyIdentityV1,
        private_material_digest: Hash,
        public_verification_key: PublicKey,
        operation: F,
    ) -> Result<T, KeyRegistryErrorV1>
    where
        F: FnOnce() -> T;
}

/// Atomic protected-material boundary for encryption-role adapters.
///
/// The core never receives private bytes. An adapter supplies the digest and
/// keeps its transaction/lock through the non-escaping callback, just as the
/// signing boundary does. Encryption and signing therefore share no
/// authorization path or role identity.
pub trait KeyRegistryEncryptionPortV1 {
    /// Run one operation while an encryption identity is authorized.
    ///
    /// # Errors
    ///
    /// Returns a closed [`KeyRegistryErrorV1`] when the identity is absent,
    /// destroyed, inactive, mismatched, or the adapter cannot provide the
    /// authorization boundary.
    fn with_encryption_authorization<T, F>(
        &mut self,
        identity: KeyIdentityV1,
        private_material_digest: Hash,
        operation: F,
    ) -> Result<T, KeyRegistryErrorV1>
    where
        F: FnOnce() -> T;
}

/// The irreversible destruction operation is kept separate from registration
/// so adapters can place it behind their own durable transaction boundary.
pub trait KeyDestructionPortV1 {
    /// Destroy private material and commit an immutable tombstone.
    ///
    /// # Errors
    ///
    /// Returns a closed [`KeyRegistryErrorV1`] when the identity is missing,
    /// the expected material fingerprint does not match, or a repeated request
    /// does not exactly match the durable tombstone.
    fn destroy_key(
        &mut self,
        request: KeyDestructionRequestV1,
    ) -> Result<KeyDestructionOutcomeV1, KeyRegistryErrorV1>;
}

/// Reference state machine for adapters and public-interface tests.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyRegistryStateV1 {
    records: BTreeMap<KeyIdentityV1, KeyRecordV1>,
    active: BTreeMap<KeyRoleV1, KeyIdentityV1>,
    tombstones: BTreeMap<KeyIdentityV1, KeyTombstoneV1>,
    highest_epoch: BTreeMap<KeyRoleV1, u64>,
}

impl KeyRegistryStateV1 {
    /// Construct an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: BTreeMap::new(),
            active: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            highest_epoch: BTreeMap::new(),
        }
    }

    /// Validate a decoded or adapter-provided registry snapshot.
    ///
    /// This is a public load-boundary contract because `Deserialize` can
    /// construct states that the mutation methods would never produce. A
    /// caller must reject an invalid snapshot before using it for signing or
    /// destruction authorization.
    ///
    /// # Errors
    ///
    /// Returns [`KeyRegistryErrorV1::InvalidState`] when a durable snapshot
    /// violates tombstone, active/high-water, or material-uniqueness rules.
    pub fn validate(&self) -> Result<(), KeyRegistryErrorV1> {
        let mut reserved_material = HashSet::new();
        for (identity, record) in &self.records {
            if record.identity != *identity {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
            if identity.epoch == 0 {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
            if identity.role.is_signing() != record.public_verification_key.is_some() {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
            if !self.highest_epoch.contains_key(&identity.role) {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
            if let Some(private_material_digest) = record.private_material_digest {
                if !reserved_material.insert(private_material_digest) {
                    return Err(KeyRegistryErrorV1::InvalidState);
                }
            }
            if record.private_material_digest.is_none() && !self.tombstones.contains_key(identity) {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
        }
        for (role, highest_epoch) in &self.highest_epoch {
            let Some(maximum) = self
                .records
                .keys()
                .filter(|identity| identity.role == *role)
                .map(|identity| identity.epoch)
                .max()
            else {
                return Err(KeyRegistryErrorV1::InvalidState);
            };
            if maximum != *highest_epoch {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
        }
        for (role, identity) in &self.active {
            if identity.role != *role {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
            if self.tombstones.contains_key(identity) {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
            if !self.records.contains_key(identity) {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
            if self.highest_epoch.get(role) != Some(&identity.epoch) {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
        }
        for (role, highest_epoch) in &self.highest_epoch {
            let identity = KeyIdentityV1::new(*role, *highest_epoch);
            if !self.tombstones.contains_key(&identity) && self.active.get(role) != Some(&identity)
            {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
        }
        for (identity, tombstone) in &self.tombstones {
            let Some(record) = self.records.get(identity) else {
                return Err(KeyRegistryErrorV1::InvalidState);
            };
            if tombstone.identity != *identity {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
            if record.private_material_digest.is_some() {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
            if !reserved_material.insert(tombstone.destroyed_material_digest) {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
        }
        Ok(())
    }

    /// Validate a durable replacement without permitting history rollback.
    ///
    /// A backend may append an epoch above the prior role high-water mark or
    /// transition one live record into its tombstoned form, but it may not drop
    /// records, backfill stale identities, restore private-material fingerprints,
    /// rewrite public verification material, or lower a role's high-water mark.
    ///
    /// # Errors
    ///
    /// Returns [`KeyRegistryErrorV1::InvalidState`] when next would erase durable destruction or alter
    /// an already accepted identity.
    pub fn validate_replacement(&self, next: &Self) -> Result<(), KeyRegistryErrorV1> {
        self.validate()?;
        next.validate()?;

        for identity in next.records.keys() {
            if self.records.contains_key(identity) {
                continue;
            }
            if self
                .highest_epoch
                .get(&identity.role)
                .is_some_and(|highest| identity.epoch <= *highest)
            {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
        }
        for (identity, previous) in &self.records {
            let Some(current) = next.records.get(identity) else {
                return Err(KeyRegistryErrorV1::InvalidState);
            };
            if current.identity != previous.identity
                || current.public_verification_key != previous.public_verification_key
            {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
            match (
                previous.private_material_digest,
                current.private_material_digest,
            ) {
                (Some(previous_digest), Some(current_digest))
                    if previous_digest != current_digest =>
                {
                    return Err(KeyRegistryErrorV1::InvalidState);
                }
                (Some(_), Some(_)) => {}
                (Some(previous_digest), None) => {
                    let Some(tombstone) = next.tombstones.get(identity) else {
                        return Err(KeyRegistryErrorV1::InvalidState);
                    };
                    if tombstone.destroyed_material_digest != previous_digest {
                        return Err(KeyRegistryErrorV1::InvalidState);
                    }
                }
                (None, None) => {
                    if next.tombstones.get(identity) != self.tombstones.get(identity) {
                        return Err(KeyRegistryErrorV1::InvalidState);
                    }
                }
                (None, Some(_)) => return Err(KeyRegistryErrorV1::InvalidState),
            }
        }

        for (role, previous_epoch) in &self.highest_epoch {
            if next.highest_epoch.get(role).copied().unwrap_or(0) < *previous_epoch {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
        }
        Ok(())
    }

    /// Register one role/epoch record.
    ///
    /// # Errors
    ///
    /// Returns a closed [`KeyRegistryErrorV1`] when the epoch, role material,
    /// or identity conflicts with registry state.
    pub fn register_key(
        &mut self,
        registration: KeyRegistrationV1,
    ) -> Result<KeyRegistrationOutcomeV1, KeyRegistryErrorV1> {
        self.validate()?;
        validate_registration(registration)?;
        let identity = registration.identity;
        if self.tombstones.contains_key(&identity) {
            return Err(KeyRegistryErrorV1::Destroyed);
        }
        if let Some(highest) = self.highest_epoch.get(&identity.role) {
            if *highest > identity.epoch {
                return Err(KeyRegistryErrorV1::StaleEpoch {
                    role: identity.role,
                    requested: identity.epoch,
                    active: *highest,
                });
            }
        }
        if let Some(existing) = self.records.get(&identity) {
            if existing.private_material_digest == Some(registration.private_material_digest)
                && existing.public_verification_key == registration.public_verification_key
            {
                return Ok(KeyRegistrationOutcomeV1::AlreadyRegistered);
            }
            return Err(KeyRegistryErrorV1::IdentityConflict);
        }
        if self.material_is_reserved(registration.private_material_digest) {
            return Err(KeyRegistryErrorV1::MaterialReuse);
        }
        self.records.insert(
            identity,
            KeyRecordV1 {
                identity,
                private_material_digest: Some(registration.private_material_digest),
                public_verification_key: registration.public_verification_key,
            },
        );
        self.active.insert(identity.role, identity);
        self.highest_epoch.insert(identity.role, identity.epoch);
        Ok(KeyRegistrationOutcomeV1::Registered)
    }

    /// Return the active record for `role`.
    #[must_use]
    pub fn active_key(&self, role: KeyRoleV1) -> Option<KeyRecordV1> {
        self.active
            .get(&role)
            .and_then(|identity| self.records.get(identity))
            .copied()
    }

    /// Return the record for an identity, including a destroyed record whose
    /// public verification key remains available.
    #[must_use]
    pub fn key_record(&self, identity: KeyIdentityV1) -> Option<KeyRecordV1> {
        self.records.get(&identity).copied()
    }

    /// Return the immutable tombstone for an identity.
    #[must_use]
    pub fn tombstone(&self, identity: KeyIdentityV1) -> Option<KeyTombstoneV1> {
        self.tombstones.get(&identity).copied()
    }

    /// Run one signing operation under the active registry authorization.
    ///
    /// The reference state machine is synchronous, so its mutable borrow
    /// covers validation and the callback as one operation.  Durable adapters
    /// must provide the equivalent transaction or lock boundary.
    ///
    /// # Errors
    ///
    /// Returns a closed [`KeyRegistryErrorV1`] when the identity is invalid,
    /// inactive, destroyed, or does not match the registered key material.
    pub fn with_signing_authorization<T, F>(
        &mut self,
        identity: KeyIdentityV1,
        private_material_digest: Hash,
        public_verification_key: PublicKey,
        operation: F,
    ) -> Result<T, KeyRegistryErrorV1>
    where
        F: FnOnce() -> T,
    {
        self.validate()
            .map_err(|_| KeyRegistryErrorV1::RegistryUnavailable)?;
        if identity.epoch == 0 {
            return Err(KeyRegistryErrorV1::InvalidEpoch);
        }
        if !identity.role.is_signing() {
            return Err(KeyRegistryErrorV1::SigningRoleRequired);
        }
        let record = self
            .records
            .get(&identity)
            .copied()
            .ok_or(KeyRegistryErrorV1::NotFound)?;
        if self.tombstones.contains_key(&identity) {
            return Err(KeyRegistryErrorV1::Destroyed);
        }
        let Some(active) = self.active_key(identity.role) else {
            return Err(KeyRegistryErrorV1::InactiveKey);
        };
        if active.identity != identity {
            return Err(KeyRegistryErrorV1::InactiveKey);
        }
        if record.private_material_digest != Some(private_material_digest)
            || record.public_verification_key != Some(public_verification_key)
        {
            return Err(KeyRegistryErrorV1::SigningKeyMismatch);
        }
        Ok(operation())
    }

    /// Run one protected-material operation under an active encryption key.
    ///
    /// # Errors
    ///
    /// Returns a closed [`KeyRegistryErrorV1`] when the identity is invalid,
    /// inactive, destroyed, absent, or does not match the registered
    /// encryption material.
    pub fn with_encryption_authorization<T, F>(
        &mut self,
        identity: KeyIdentityV1,
        private_material_digest: Hash,
        operation: F,
    ) -> Result<T, KeyRegistryErrorV1>
    where
        F: FnOnce() -> T,
    {
        self.validate()
            .map_err(|_| KeyRegistryErrorV1::RegistryUnavailable)?;
        if identity.epoch == 0 {
            return Err(KeyRegistryErrorV1::InvalidEpoch);
        }
        if !identity.role.is_encryption() {
            return Err(KeyRegistryErrorV1::EncryptionRoleRequired);
        }
        let record = self
            .records
            .get(&identity)
            .copied()
            .ok_or(KeyRegistryErrorV1::NotFound)?;
        if self.tombstones.contains_key(&identity) {
            return Err(KeyRegistryErrorV1::Destroyed);
        }
        let Some(active) = self.active_key(identity.role) else {
            return Err(KeyRegistryErrorV1::InactiveKey);
        };
        if active.identity != identity {
            return Err(KeyRegistryErrorV1::InactiveKey);
        }
        if record.private_material_digest != Some(private_material_digest) {
            return Err(KeyRegistryErrorV1::EncryptionKeyMismatch);
        }
        Ok(operation())
    }

    /// Destroy private material and retain the public record plus tombstone.
    ///
    /// # Errors
    ///
    /// Returns a closed [`KeyRegistryErrorV1`] when the identity is missing,
    /// the expected material fingerprint does not match, or a repeated request
    /// does not exactly match the durable tombstone.
    pub fn destroy_key(
        &mut self,
        request: KeyDestructionRequestV1,
    ) -> Result<KeyDestructionOutcomeV1, KeyRegistryErrorV1> {
        self.validate()?;
        if let Some(tombstone) = self.tombstones.get(&request.identity).copied() {
            if tombstone.destroyed_material_digest != request.expected_material_digest {
                return Err(KeyRegistryErrorV1::MaterialDigestMismatch);
            }
            if tombstone.destruction_digest != destruction_digest(&request) {
                return Err(KeyRegistryErrorV1::DestructionAuthorizationMismatch);
            }
            return Ok(KeyDestructionOutcomeV1::AlreadyDestroyed(tombstone));
        }
        let Some(record) = self.records.get_mut(&request.identity) else {
            return Err(KeyRegistryErrorV1::NotFound);
        };
        if record.private_material_digest != Some(request.expected_material_digest) {
            return Err(KeyRegistryErrorV1::MaterialDigestMismatch);
        }
        record.private_material_digest = None;
        let destruction_digest = destruction_digest(&request);
        let tombstone = KeyTombstoneV1 {
            identity: request.identity,
            destroyed_material_digest: request.expected_material_digest,
            destruction_digest,
        };
        self.tombstones.insert(request.identity, tombstone);
        if self.active.get(&request.identity.role) == Some(&request.identity) {
            self.active.remove(&request.identity.role);
        }
        Ok(KeyDestructionOutcomeV1::Destroyed(tombstone))
    }

    fn material_is_reserved(&self, digest: Hash) -> bool {
        self.records
            .values()
            .any(|record| record.private_material_digest == Some(digest))
            || self
                .tombstones
                .values()
                .any(|tombstone| tombstone.destroyed_material_digest == digest)
    }
}

impl KeyRegistryPortV1 for KeyRegistryStateV1 {
    fn register_key(
        &mut self,
        registration: KeyRegistrationV1,
    ) -> Result<KeyRegistrationOutcomeV1, KeyRegistryErrorV1> {
        Self::register_key(self, registration)
    }

    fn active_key(&self, role: KeyRoleV1) -> Option<KeyRecordV1> {
        Self::active_key(self, role)
    }

    fn key_record(&self, identity: KeyIdentityV1) -> Option<KeyRecordV1> {
        Self::key_record(self, identity)
    }

    fn tombstone(&self, identity: KeyIdentityV1) -> Option<KeyTombstoneV1> {
        Self::tombstone(self, identity)
    }
}

impl KeyDestructionPortV1 for KeyRegistryStateV1 {
    fn destroy_key(
        &mut self,
        request: KeyDestructionRequestV1,
    ) -> Result<KeyDestructionOutcomeV1, KeyRegistryErrorV1> {
        Self::destroy_key(self, request)
    }
}

impl KeyRegistrySigningPortV1 for KeyRegistryStateV1 {
    fn with_signing_authorization<T, F>(
        &mut self,
        identity: KeyIdentityV1,
        private_material_digest: Hash,
        public_verification_key: PublicKey,
        operation: F,
    ) -> Result<T, KeyRegistryErrorV1>
    where
        F: FnOnce() -> T,
    {
        Self::with_signing_authorization(
            self,
            identity,
            private_material_digest,
            public_verification_key,
            operation,
        )
    }
}

impl KeyRegistryEncryptionPortV1 for KeyRegistryStateV1 {
    fn with_encryption_authorization<T, F>(
        &mut self,
        identity: KeyIdentityV1,
        private_material_digest: Hash,
        operation: F,
    ) -> Result<T, KeyRegistryErrorV1>
    where
        F: FnOnce() -> T,
    {
        Self::with_encryption_authorization(self, identity, private_material_digest, operation)
    }
}

const fn validate_registration(registration: KeyRegistrationV1) -> Result<(), KeyRegistryErrorV1> {
    if registration.identity.epoch == 0 {
        return Err(KeyRegistryErrorV1::InvalidEpoch);
    }
    if registration.identity.role.is_signing() && registration.public_verification_key.is_none() {
        return Err(KeyRegistryErrorV1::MissingPublicVerificationKey);
    }
    if registration.identity.role.is_encryption() && registration.public_verification_key.is_some()
    {
        return Err(KeyRegistryErrorV1::UnexpectedPublicVerificationKey);
    }
    Ok(())
}

fn destruction_digest(request: &KeyDestructionRequestV1) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros/key-destruction/v1");
    hasher.update(&[request.identity.role.code()]);
    hasher.update(&request.identity.epoch.to_be_bytes());
    hasher.update(request.expected_material_digest.as_bytes());
    hasher.update(request.authorization_digest.as_bytes());
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    const DATA: KeyIdentityV1 = KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 1);
    const ATTRIBUTION: KeyIdentityV1 = KeyIdentityV1::new(KeyRoleV1::SubjectAttributionSigning, 1);

    fn digest(value: u8) -> Hash {
        Hash::from_bytes([value; 32])
    }

    fn signing_registration(identity: KeyIdentityV1, material: u8) -> KeyRegistrationV1 {
        KeyRegistrationV1::new(
            identity,
            digest(material),
            Some(PublicKey::from_bytes([material; 32])),
        )
    }

    fn assert_signing_error(
        registry: &mut KeyRegistryStateV1,
        identity: KeyIdentityV1,
        material: u8,
        public_key: u8,
        expected: KeyRegistryErrorV1,
    ) {
        assert_eq!(
            KeyRegistrySigningPortV1::with_signing_authorization(
                registry,
                identity,
                digest(material),
                PublicKey::from_bytes([public_key; 32]),
                || (),
            ),
            Err(expected)
        );
    }

    #[test]
    fn role_codes_are_closed_and_distinct() {
        for role in [
            KeyRoleV1::SubjectDataEncryption,
            KeyRoleV1::SubjectAttributionSigning,
            KeyRoleV1::TimelineIntegritySigning,
            KeyRoleV1::PluginReleaseSigning,
            KeyRoleV1::ExportRecipientEncryption,
        ] {
            assert_eq!(KeyRoleV1::from_code(role.code()), Ok(role));
        }
        assert_eq!(
            KeyRoleV1::from_code(99),
            Err(KeyRegistryErrorV1::InvalidRoleCode)
        );
    }

    #[test]
    fn legacy_subject_signatures_are_verify_only() {
        let disposition = LegacySubjectDataSignatureDispositionV1::current();
        assert_eq!(
            disposition,
            LegacySubjectDataSignatureDispositionV1::VerifyOnlyNoReplayUpgrade
        );
    }

    #[test]
    fn signing_authorization_is_fail_closed_and_scoped() -> Result<(), KeyRegistryErrorV1> {
        let mut registry = KeyRegistryStateV1::new();
        registry.register_key(signing_registration(ATTRIBUTION, 2))?;
        let mut called = false;
        assert_eq!(
            KeyRegistrySigningPortV1::with_signing_authorization(
                &mut registry,
                ATTRIBUTION,
                digest(2),
                PublicKey::from_bytes([2; 32]),
                || {
                    called = true;
                    7_u8
                },
            ),
            Ok(7)
        );
        assert!(called);

        let before_mismatch = registry.clone();
        called = false;
        assert_eq!(
            KeyRegistrySigningPortV1::with_signing_authorization(
                &mut registry,
                ATTRIBUTION,
                digest(9),
                PublicKey::from_bytes([2; 32]),
                || {
                    called = true;
                },
            ),
            Err(KeyRegistryErrorV1::SigningKeyMismatch)
        );
        assert!(!called);
        assert_eq!(registry, before_mismatch);

        assert_signing_error(
            &mut registry,
            ATTRIBUTION,
            2,
            9,
            KeyRegistryErrorV1::SigningKeyMismatch,
        );
        assert_signing_error(
            &mut registry,
            KeyIdentityV1::new(KeyRoleV1::SubjectAttributionSigning, 0),
            2,
            2,
            KeyRegistryErrorV1::InvalidEpoch,
        );
        assert_signing_error(
            &mut registry,
            DATA,
            2,
            2,
            KeyRegistryErrorV1::SigningRoleRequired,
        );
        assert_signing_error(
            &mut registry,
            KeyIdentityV1::new(KeyRoleV1::SubjectAttributionSigning, 9),
            2,
            2,
            KeyRegistryErrorV1::NotFound,
        );

        let next = KeyIdentityV1::new(KeyRoleV1::SubjectAttributionSigning, 2);
        registry.register_key(signing_registration(next, 4))?;
        assert_signing_error(
            &mut registry,
            ATTRIBUTION,
            2,
            2,
            KeyRegistryErrorV1::InactiveKey,
        );

        registry.destroy_key(KeyDestructionRequestV1::new(next, digest(4), digest(5)))?;
        assert_signing_error(&mut registry, next, 4, 4, KeyRegistryErrorV1::Destroyed);
        assert_signing_error(
            &mut registry,
            ATTRIBUTION,
            2,
            2,
            KeyRegistryErrorV1::InactiveKey,
        );
        Ok(())
    }

    #[test]
    fn encryption_authorization_is_fail_closed_and_scoped() -> Result<(), KeyRegistryErrorV1> {
        let mut registry = KeyRegistryStateV1::new();
        registry.register_key(KeyRegistrationV1::new(DATA, digest(1), None))?;
        let mut called = false;
        assert_eq!(
            registry.with_encryption_authorization(DATA, digest(1), || {
                called = true;
                11_u8
            }),
            Ok(11)
        );
        assert!(called);

        called = false;
        assert_eq!(
            registry.with_encryption_authorization(DATA, digest(9), || {
                called = true;
            }),
            Err(KeyRegistryErrorV1::EncryptionKeyMismatch)
        );
        assert!(!called);

        assert_eq!(
            registry.with_encryption_authorization(ATTRIBUTION, digest(1), || ()),
            Err(KeyRegistryErrorV1::EncryptionRoleRequired)
        );
        assert_eq!(
            registry.with_encryption_authorization(
                KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 0),
                digest(1),
                || (),
            ),
            Err(KeyRegistryErrorV1::InvalidEpoch)
        );

        let next = KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 2);
        registry.register_key(KeyRegistrationV1::new(next, digest(2), None))?;
        assert_eq!(
            registry.with_encryption_authorization(DATA, digest(1), || ()),
            Err(KeyRegistryErrorV1::InactiveKey)
        );
        registry.destroy_key(KeyDestructionRequestV1::new(next, digest(2), digest(3)))?;
        assert_eq!(
            registry.with_encryption_authorization(next, digest(2), || ()),
            Err(KeyRegistryErrorV1::Destroyed)
        );
        Ok(())
    }

    #[test]
    fn registration_rejects_cross_role_material_reuse() -> Result<(), KeyRegistryErrorV1> {
        let mut registry = KeyRegistryStateV1::new();
        registry.register_key(KeyRegistrationV1::new(DATA, digest(1), None))?;
        assert_eq!(
            registry.register_key(signing_registration(ATTRIBUTION, 1)),
            Err(KeyRegistryErrorV1::MaterialReuse)
        );
        Ok(())
    }

    #[test]
    fn destruction_is_irreversible_idempotent_and_keeps_public_key(
    ) -> Result<(), KeyRegistryErrorV1> {
        let mut registry = KeyRegistryStateV1::new();
        registry.register_key(signing_registration(ATTRIBUTION, 2))?;
        let request = KeyDestructionRequestV1::new(ATTRIBUTION, digest(2), digest(3));
        let first = registry.destroy_key(request)?;
        let second = registry.destroy_key(request)?;
        assert!(matches!(first, KeyDestructionOutcomeV1::Destroyed(_)));
        assert!(matches!(
            second,
            KeyDestructionOutcomeV1::AlreadyDestroyed(_)
        ));
        assert_eq!(first.tombstone(), second.tombstone());
        assert_eq!(
            registry.destroy_key(KeyDestructionRequestV1::new(
                ATTRIBUTION,
                digest(99),
                digest(3),
            )),
            Err(KeyRegistryErrorV1::MaterialDigestMismatch)
        );
        assert_eq!(
            registry.destroy_key(KeyDestructionRequestV1::new(
                ATTRIBUTION,
                digest(2),
                digest(99),
            )),
            Err(KeyRegistryErrorV1::DestructionAuthorizationMismatch)
        );
        assert_eq!(
            registry.key_record(ATTRIBUTION),
            Some(KeyRecordV1 {
                identity: ATTRIBUTION,
                private_material_digest: None,
                public_verification_key: Some(PublicKey::from_bytes([2; 32])),
            })
        );
        assert_eq!(
            registry.active_key(KeyRoleV1::SubjectAttributionSigning),
            None
        );
        assert_eq!(
            registry.register_key(signing_registration(ATTRIBUTION, 2)),
            Err(KeyRegistryErrorV1::Destroyed)
        );
        Ok(())
    }

    fn state_value(
        state: &KeyRegistryStateV1,
    ) -> Result<ciborium::value::Value, Box<dyn std::error::Error>> {
        let mut bytes = Vec::new();
        ciborium::into_writer(state, &mut bytes)?;
        Ok(ciborium::from_reader(bytes.as_slice())?)
    }

    fn state_from_value(
        value: &ciborium::value::Value,
    ) -> Result<KeyRegistryStateV1, Box<dyn std::error::Error>> {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes)?;
        Ok(ciborium::from_reader(bytes.as_slice())?)
    }

    fn edit_state<F>(
        state: &KeyRegistryStateV1,
        edit: F,
    ) -> Result<KeyRegistryStateV1, Box<dyn std::error::Error>>
    where
        F: FnOnce(&mut ciborium::value::Value) -> Result<(), Box<dyn std::error::Error>>,
    {
        let mut value = state_value(state)?;
        edit(&mut value)?;
        state_from_value(&value)
    }

    fn top_level_field<'a>(
        value: &'a mut ciborium::value::Value,
        name: &str,
    ) -> Result<&'a mut ciborium::value::Value, Box<dyn std::error::Error>> {
        let ciborium::value::Value::Map(entries) = value else {
            return Err("registry state is not a CBOR map".into());
        };
        entries
            .iter_mut()
            .find_map(|(key, value)| match key {
                ciborium::value::Value::Text(key) if key == name => Some(value),
                _ => None,
            })
            .ok_or_else(|| format!("missing registry field {name}").into())
    }

    fn replace_first_bytes(
        value: &mut ciborium::value::Value,
        from: &[u8; 32],
        to: ciborium::value::Value,
    ) -> bool {
        match value {
            ciborium::value::Value::Bytes(bytes) if bytes.as_slice() == from => {
                *value = to;
                true
            }
            ciborium::value::Value::Array(values) => values
                .iter_mut()
                .any(|value| replace_first_bytes(value, from, to.clone())),
            ciborium::value::Value::Map(entries) => entries.iter_mut().any(|(key, value)| {
                replace_first_bytes(key, from, to.clone())
                    || replace_first_bytes(value, from, to.clone())
            }),
            ciborium::value::Value::Tag(_, value) => replace_first_bytes(value, from, to),
            _ => false,
        }
    }

    fn replace_first_integer(value: &mut ciborium::value::Value, from: u64, to: u64) -> bool {
        match value {
            ciborium::value::Value::Integer(integer) if *integer == from.into() => {
                *integer = to.into();
                true
            }
            ciborium::value::Value::Array(values) => values
                .iter_mut()
                .any(|value| replace_first_integer(value, from, to)),
            ciborium::value::Value::Map(entries) => entries.iter_mut().any(|(key, value)| {
                replace_first_integer(key, from, to) || replace_first_integer(value, from, to)
            }),
            ciborium::value::Value::Tag(_, value) => replace_first_integer(value, from, to),
            _ => false,
        }
    }

    fn replace_first_null(
        value: &mut ciborium::value::Value,
        replacement: ciborium::value::Value,
    ) -> bool {
        match value {
            ciborium::value::Value::Null => {
                *value = replacement;
                true
            }
            ciborium::value::Value::Array(values) => values
                .iter_mut()
                .any(|value| replace_first_null(value, replacement.clone())),
            ciborium::value::Value::Map(entries) => entries.iter_mut().any(|(key, value)| {
                replace_first_null(key, replacement.clone())
                    || replace_first_null(value, replacement.clone())
            }),
            ciborium::value::Value::Tag(_, value) => replace_first_null(value, replacement),
            _ => false,
        }
    }

    #[test]
    fn malformed_state_without_tombstone_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let mut state = KeyRegistryStateV1::new();
        state.register_key(signing_registration(ATTRIBUTION, 19))?;
        let state = edit_state(&state, |value| {
            if replace_first_bytes(value, &[19; 32], ciborium::value::Value::Null) {
                Ok(())
            } else {
                Err("private-material digest was not encoded".into())
            }
        })?;
        assert_eq!(state.validate(), Err(KeyRegistryErrorV1::InvalidState));
        Ok(())
    }

    #[test]
    fn malformed_state_with_active_record_missing_is_rejected() {
        let mut state = KeyRegistryStateV1::new();
        state.active.insert(ATTRIBUTION.role, ATTRIBUTION);
        assert_eq!(state.validate(), Err(KeyRegistryErrorV1::InvalidState));
    }

    #[test]
    fn malformed_state_without_high_water_entry_is_rejected(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut state = KeyRegistryStateV1::new();
        state.register_key(signing_registration(ATTRIBUTION, 23))?;
        let state = edit_state(&state, |value| {
            let highest_epoch = top_level_field(value, "highest_epoch")?;
            let ciborium::value::Value::Map(entries) = highest_epoch else {
                return Err("highest_epoch is not a CBOR map".into());
            };
            entries.clear();
            Ok(())
        })?;
        assert_eq!(state.validate(), Err(KeyRegistryErrorV1::InvalidState));
        Ok(())
    }

    #[test]
    fn malformed_state_with_mismatched_record_identity_is_rejected(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut state = KeyRegistryStateV1::new();
        state.register_key(signing_registration(ATTRIBUTION, 24))?;
        let state = edit_state(&state, |value| {
            if replace_first_integer(value, 1, 2) {
                Ok(())
            } else {
                Err("record identity epoch was not encoded".into())
            }
        })?;
        assert_eq!(state.validate(), Err(KeyRegistryErrorV1::InvalidState));
        Ok(())
    }

    #[test]
    fn malformed_state_rejects_each_snapshot_cross_reference(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut mismatched_record = KeyRegistryStateV1::new();
        mismatched_record.register_key(signing_registration(ATTRIBUTION, 32))?;
        mismatched_record
            .records
            .get_mut(&ATTRIBUTION)
            .ok_or("missing record")?
            .identity = KeyIdentityV1::new(ATTRIBUTION.role, 2);
        assert_eq!(
            mismatched_record.validate(),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut zero_epoch = KeyRegistryStateV1::new();
        let zero = KeyIdentityV1::new(ATTRIBUTION.role, 0);
        zero_epoch.records.insert(
            zero,
            KeyRecordV1 {
                identity: zero,
                private_material_digest: Some(digest(33)),
                public_verification_key: Some(PublicKey::from_bytes([33; 32])),
            },
        );
        zero_epoch.active.insert(zero.role, zero);
        zero_epoch.highest_epoch.insert(zero.role, 0);
        assert_eq!(zero_epoch.validate(), Err(KeyRegistryErrorV1::InvalidState));

        let mut high_water_mismatch = KeyRegistryStateV1::new();
        high_water_mismatch.register_key(signing_registration(ATTRIBUTION, 34))?;
        high_water_mismatch
            .highest_epoch
            .insert(ATTRIBUTION.role, 2);
        assert_eq!(
            high_water_mismatch.validate(),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut orphaned_tombstone = KeyRegistryStateV1::new();
        orphaned_tombstone.register_key(signing_registration(ATTRIBUTION, 35))?;
        orphaned_tombstone.destroy_key(KeyDestructionRequestV1::new(
            ATTRIBUTION,
            digest(35),
            digest(36),
        ))?;
        orphaned_tombstone.records.remove(&ATTRIBUTION);
        orphaned_tombstone.active.remove(&ATTRIBUTION.role);
        orphaned_tombstone.highest_epoch.remove(&ATTRIBUTION.role);
        assert_eq!(
            orphaned_tombstone.validate(),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut mismatched_tombstone = KeyRegistryStateV1::new();
        mismatched_tombstone.register_key(signing_registration(ATTRIBUTION, 37))?;
        mismatched_tombstone.destroy_key(KeyDestructionRequestV1::new(
            ATTRIBUTION,
            digest(37),
            digest(38),
        ))?;
        mismatched_tombstone
            .tombstones
            .get_mut(&ATTRIBUTION)
            .ok_or("missing tombstone")?
            .identity = KeyIdentityV1::new(ATTRIBUTION.role, 2);
        assert_eq!(
            mismatched_tombstone.validate(),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut restored_material = KeyRegistryStateV1::new();
        restored_material.register_key(signing_registration(ATTRIBUTION, 39))?;
        restored_material.destroy_key(KeyDestructionRequestV1::new(
            ATTRIBUTION,
            digest(39),
            digest(40),
        ))?;
        restored_material
            .records
            .get_mut(&ATTRIBUTION)
            .ok_or("missing destroyed record")?
            .private_material_digest = Some(digest(39));
        assert_eq!(
            restored_material.validate(),
            Err(KeyRegistryErrorV1::InvalidState)
        );
        Ok(())
    }

    #[test]
    fn malformed_state_rejects_zero_epoch_and_role_material_mismatch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut zero_epoch = KeyRegistryStateV1::new();
        zero_epoch.register_key(signing_registration(ATTRIBUTION, 25))?;
        let zero_epoch = edit_state(&zero_epoch, |value| {
            if replace_first_integer(value, 1, 0) {
                Ok(())
            } else {
                Err("record epoch was not encoded".into())
            }
        })?;
        assert_eq!(zero_epoch.validate(), Err(KeyRegistryErrorV1::InvalidState));

        let mut missing_signing_key = KeyRegistryStateV1::new();
        missing_signing_key.register_key(KeyRegistrationV1::new(
            ATTRIBUTION,
            digest(26),
            Some(PublicKey::from_bytes([27; 32])),
        ))?;
        let missing_signing_key = edit_state(&missing_signing_key, |value| {
            if replace_first_bytes(value, &[27; 32], ciborium::value::Value::Null) {
                Ok(())
            } else {
                Err("signing public key was not encoded".into())
            }
        })?;
        assert_eq!(
            missing_signing_key.validate(),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut unexpected_encryption_key = KeyRegistryStateV1::new();
        unexpected_encryption_key.register_key(KeyRegistrationV1::new(DATA, digest(28), None))?;
        let unexpected_encryption_key = edit_state(&unexpected_encryption_key, |value| {
            if replace_first_null(value, ciborium::value::Value::Bytes(vec![29; 32])) {
                Ok(())
            } else {
                Err("encryption public-key slot was not encoded".into())
            }
        })?;
        assert_eq!(
            unexpected_encryption_key.validate(),
            Err(KeyRegistryErrorV1::InvalidState)
        );
        Ok(())
    }

    #[test]
    fn malformed_state_without_record_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let mut state = KeyRegistryStateV1::new();
        state.register_key(signing_registration(ATTRIBUTION, 18))?;
        state.destroy_key(KeyDestructionRequestV1::new(
            ATTRIBUTION,
            digest(18),
            digest(17),
        ))?;
        let state = edit_state(&state, |value| {
            let records = top_level_field(value, "records")?;
            let ciborium::value::Value::Map(entries) = records else {
                return Err("registry records are not a CBOR map".into());
            };
            entries.clear();
            Ok(())
        })?;
        assert_eq!(state.validate(), Err(KeyRegistryErrorV1::InvalidState));
        Ok(())
    }

    #[test]
    fn malformed_destroyed_state_cannot_authorize_signing() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut destroyed = KeyRegistryStateV1::new();
        destroyed.register_key(signing_registration(ATTRIBUTION, 20))?;
        destroyed.destroy_key(KeyDestructionRequestV1::new(
            ATTRIBUTION,
            digest(20),
            digest(21),
        ))?;
        let mut live = KeyRegistryStateV1::new();
        live.register_key(signing_registration(ATTRIBUTION, 22))?;
        let mut live_value = state_value(&live)?;
        let active = top_level_field(&mut live_value, "active")?.clone();
        let mut state = edit_state(&destroyed, |value| {
            *top_level_field(value, "active")? = active;
            Ok(())
        })?;
        assert_eq!(state.validate(), Err(KeyRegistryErrorV1::InvalidState));
        assert_eq!(
            state.with_signing_authorization(
                ATTRIBUTION,
                digest(20),
                PublicKey::from_bytes([20; 32]),
                || (),
            ),
            Err(KeyRegistryErrorV1::RegistryUnavailable)
        );
        Ok(())
    }

    #[test]
    fn malformed_state_rejects_epoch_rollback_and_material_reuse(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let first = KeyIdentityV1::new(KeyRoleV1::SubjectAttributionSigning, 1);
        let second = KeyIdentityV1::new(KeyRoleV1::SubjectAttributionSigning, 2);
        let mut first_state = KeyRegistryStateV1::new();
        first_state.register_key(signing_registration(first, 30))?;
        let mut both = first_state.clone();
        both.register_key(signing_registration(second, 31))?;

        let mut first_value = state_value(&first_state)?;
        let rollback = edit_state(&both, |value| {
            let first_active = top_level_field(&mut first_value, "active")?.clone();
            *top_level_field(value, "active")? = first_active;
            Ok(())
        })?;
        assert_eq!(rollback.validate(), Err(KeyRegistryErrorV1::InvalidState));

        let no_active = edit_state(&both, |value| {
            let active = top_level_field(value, "active")?;
            let ciborium::value::Value::Map(entries) = active else {
                return Err("active is not a CBOR map".into());
            };
            entries.clear();
            Ok(())
        })?;
        assert_eq!(no_active.validate(), Err(KeyRegistryErrorV1::InvalidState));

        let reused = edit_state(&both, |value| {
            if replace_first_bytes(
                value,
                &[31; 32],
                ciborium::value::Value::Bytes(vec![30; 32]),
            ) {
                Ok(())
            } else {
                Err("second private-material digest was not encoded".into())
            }
        })?;
        assert_eq!(reused.validate(), Err(KeyRegistryErrorV1::InvalidState));

        let mut wrong_active_role = both.clone();
        wrong_active_role
            .active
            .insert(KeyRoleV1::SubjectDataEncryption, second);
        assert_eq!(
            wrong_active_role.validate(),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut destroyed = first_state;
        destroyed.destroy_key(KeyDestructionRequestV1::new(first, digest(30), digest(32)))?;
        destroyed.register_key(signing_registration(second, 33))?;
        let tombstone_reuse = edit_state(&destroyed, |value| {
            if replace_first_bytes(
                value,
                &[33; 32],
                ciborium::value::Value::Bytes(vec![30; 32]),
            ) {
                Ok(())
            } else {
                Err("live private-material digest was not encoded".into())
            }
        })?;
        assert_eq!(
            tombstone_reuse.validate(),
            Err(KeyRegistryErrorV1::InvalidState)
        );
        Ok(())
    }

    #[test]
    fn encryption_authorization_rejects_missing_active_role() -> Result<(), KeyRegistryErrorV1> {
        let mut state = KeyRegistryStateV1::new();
        state.register_key(KeyRegistrationV1::new(DATA, digest(57), None))?;
        state.active.remove(&DATA.role);
        assert_eq!(
            state.with_encryption_authorization(DATA, digest(57), || ()),
            Err(KeyRegistryErrorV1::RegistryUnavailable)
        );
        Ok(())
    }

    #[test]
    fn durable_replacement_rejects_backfilled_stale_epoch() -> Result<(), KeyRegistryErrorV1> {
        let latest = KeyIdentityV1::new(KeyRoleV1::SubjectAttributionSigning, 2);
        let stale = KeyIdentityV1::new(KeyRoleV1::SubjectAttributionSigning, 1);
        let mut previous = KeyRegistryStateV1::new();
        previous.register_key(signing_registration(latest, 40))?;

        let mut next = previous.clone();
        next.records.insert(
            stale,
            KeyRecordV1 {
                identity: stale,
                private_material_digest: Some(digest(41)),
                public_verification_key: Some(PublicKey::from_bytes([41; 32])),
            },
        );
        assert_eq!(
            previous.validate_replacement(&next),
            Err(KeyRegistryErrorV1::InvalidState)
        );
        Ok(())
    }

    #[test]
    fn durable_replacement_preserves_identity_material_and_tombstone_history(
    ) -> Result<(), KeyRegistryErrorV1> {
        let mut previous = KeyRegistryStateV1::new();
        previous.register_key(signing_registration(ATTRIBUTION, 50))?;

        assert_eq!(previous.validate_replacement(&previous), Ok(()));

        let mut public_key_changed = previous.clone();
        public_key_changed
            .records
            .get_mut(&ATTRIBUTION)
            .ok_or(KeyRegistryErrorV1::NotFound)?
            .public_verification_key = Some(PublicKey::from_bytes([51; 32]));
        assert_eq!(
            previous.validate_replacement(&public_key_changed),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut material_changed = previous.clone();
        material_changed
            .records
            .get_mut(&ATTRIBUTION)
            .ok_or(KeyRegistryErrorV1::NotFound)?
            .private_material_digest = Some(digest(52));
        assert_eq!(
            previous.validate_replacement(&material_changed),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut destroyed = previous.clone();
        destroyed.destroy_key(KeyDestructionRequestV1::new(
            ATTRIBUTION,
            digest(50),
            digest(53),
        ))?;
        assert_eq!(previous.validate_replacement(&destroyed), Ok(()));

        let mut tombstone_changed = destroyed.clone();
        tombstone_changed
            .tombstones
            .get_mut(&ATTRIBUTION)
            .ok_or(KeyRegistryErrorV1::NotFound)?
            .destroyed_material_digest = digest(54);
        assert_eq!(
            previous.validate_replacement(&tombstone_changed),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let next = KeyIdentityV1::new(KeyRoleV1::SubjectAttributionSigning, 2);
        let mut advanced = previous.clone();
        advanced.register_key(signing_registration(next, 55))?;
        assert_eq!(previous.validate_replacement(&advanced), Ok(()));
        Ok(())
    }

    #[test]
    fn data_destruction_does_not_remove_other_role_verification_material(
    ) -> Result<(), KeyRegistryErrorV1> {
        let mut registry = KeyRegistryStateV1::new();
        registry.register_key(KeyRegistrationV1::new(DATA, digest(4), None))?;
        registry.register_key(signing_registration(ATTRIBUTION, 5))?;
        registry.destroy_key(KeyDestructionRequestV1::new(DATA, digest(4), digest(6)))?;
        let signing_record = registry
            .key_record(ATTRIBUTION)
            .ok_or(KeyRegistryErrorV1::NotFound)?;
        assert_eq!(
            signing_record.public_verification_key,
            Some(PublicKey::from_bytes([5; 32]))
        );
        Ok(())
    }

    #[test]
    fn destruction_does_not_allow_epoch_rollback() -> Result<(), KeyRegistryErrorV1> {
        let mut registry = KeyRegistryStateV1::new();
        let latest = KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 3);
        registry.register_key(KeyRegistrationV1::new(latest, digest(30), None))?;
        registry.destroy_key(KeyDestructionRequestV1::new(latest, digest(30), digest(31)))?;

        assert_eq!(
            registry.register_key(KeyRegistrationV1::new(
                KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 2),
                digest(32),
                None,
            )),
            Err(KeyRegistryErrorV1::StaleEpoch {
                role: KeyRoleV1::SubjectDataEncryption,
                requested: 2,
                active: 3,
            })
        );
        assert_eq!(registry.active_key(KeyRoleV1::SubjectDataEncryption), None);

        let next = KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 4);
        assert_eq!(
            registry.register_key(KeyRegistrationV1::new(next, digest(33), None)),
            Ok(KeyRegistrationOutcomeV1::Registered)
        );
        assert_eq!(
            registry
                .active_key(KeyRoleV1::SubjectDataEncryption)
                .map(|key| key.identity),
            Some(next)
        );
        Ok(())
    }

    #[test]
    fn destroying_an_inactive_epoch_keeps_the_newer_epoch_active() -> Result<(), KeyRegistryErrorV1>
    {
        let mut registry = KeyRegistryStateV1::new();
        let first = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
        let latest = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 2);
        registry.register_key(signing_registration(first, 40))?;
        registry.register_key(signing_registration(latest, 41))?;

        registry.destroy_key(KeyDestructionRequestV1::new(first, digest(40), digest(42)))?;

        assert_eq!(
            registry.active_key(first.role).map(|key| key.identity),
            Some(latest)
        );
        assert_eq!(
            registry
                .key_record(first)
                .and_then(|record| record.private_material_digest),
            None
        );
        assert!(registry.tombstone(first).is_some());
        Ok(())
    }

    #[test]
    fn stale_epoch_and_wrong_digest_are_rejected() -> Result<(), KeyRegistryErrorV1> {
        let mut registry = KeyRegistryStateV1::new();
        registry.register_key(KeyRegistrationV1::new(DATA, digest(7), None))?;
        registry.register_key(KeyRegistrationV1::new(
            KeyIdentityV1::new(DATA.role, 2),
            digest(8),
            None,
        ))?;
        assert!(matches!(
            registry.register_key(KeyRegistrationV1::new(DATA, digest(9), None)),
            Err(KeyRegistryErrorV1::StaleEpoch { .. })
        ));
        let identity = KeyIdentityV1::new(DATA.role, 2);
        let record_before = registry.key_record(identity);
        let active_before = registry.active_key(DATA.role);
        assert_eq!(
            registry.destroy_key(KeyDestructionRequestV1::new(
                identity,
                digest(99),
                digest(10),
            )),
            Err(KeyRegistryErrorV1::MaterialDigestMismatch)
        );
        assert_eq!(registry.key_record(identity), record_before);
        assert_eq!(registry.active_key(DATA.role), active_before);
        Ok(())
    }

    #[test]
    fn registration_validation_and_idempotency_are_closed() {
        let mut registry = KeyRegistryStateV1::new();
        assert_eq!(
            registry.register_key(KeyRegistrationV1::new(
                KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 0),
                digest(11),
                None,
            )),
            Err(KeyRegistryErrorV1::InvalidEpoch)
        );
        assert_eq!(
            registry.register_key(KeyRegistrationV1::new(ATTRIBUTION, digest(12), None)),
            Err(KeyRegistryErrorV1::MissingPublicVerificationKey)
        );
        assert_eq!(
            registry.register_key(KeyRegistrationV1::new(
                DATA,
                digest(13),
                Some(PublicKey::from_bytes([13; 32])),
            )),
            Err(KeyRegistryErrorV1::UnexpectedPublicVerificationKey)
        );

        let registration = KeyRegistrationV1::new(DATA, digest(14), None);
        assert_eq!(
            registry.register_key(registration),
            Ok(KeyRegistrationOutcomeV1::Registered)
        );
        assert_eq!(
            registry.register_key(registration),
            Ok(KeyRegistrationOutcomeV1::AlreadyRegistered)
        );
        assert_eq!(
            registry.register_key(KeyRegistrationV1::new(DATA, digest(15), None)),
            Err(KeyRegistryErrorV1::IdentityConflict)
        );
        assert_eq!(
            registry.active_key(KeyRoleV1::SubjectDataEncryption),
            Some(KeyRecordV1 {
                identity: DATA,
                private_material_digest: Some(digest(14)),
                public_verification_key: None,
            })
        );
        assert_eq!(registry.tombstone(DATA), None);
    }

    #[test]
    fn missing_keys_and_destroyed_material_are_not_reusable() -> Result<(), KeyRegistryErrorV1> {
        let mut registry = KeyRegistryStateV1::new();
        assert_eq!(
            registry.destroy_key(KeyDestructionRequestV1::new(DATA, digest(16), digest(17),)),
            Err(KeyRegistryErrorV1::NotFound)
        );
        registry.register_key(KeyRegistrationV1::new(DATA, digest(18), None))?;
        registry.destroy_key(KeyDestructionRequestV1::new(DATA, digest(18), digest(19)))?;
        assert_eq!(
            registry.register_key(KeyRegistrationV1::new(
                KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 2),
                digest(18),
                None,
            )),
            Err(KeyRegistryErrorV1::MaterialReuse)
        );
        assert!(registry.key_record(DATA).is_some());
        assert!(registry.tombstone(DATA).is_some());
        Ok(())
    }

    #[test]
    fn ports_expose_the_same_irreversible_contract() -> Result<(), KeyRegistryErrorV1> {
        let mut registry = KeyRegistryStateV1::new();
        let registration = KeyRegistrationV1::new(DATA, digest(20), None);
        assert_eq!(
            KeyRegistryPortV1::register_key(&mut registry, registration),
            Ok(KeyRegistrationOutcomeV1::Registered)
        );
        assert_eq!(
            KeyRegistryPortV1::key_record(&registry, DATA),
            Some(KeyRecordV1 {
                identity: DATA,
                private_material_digest: Some(digest(20)),
                public_verification_key: None,
            })
        );
        assert_eq!(
            KeyRegistryPortV1::active_key(&registry, KeyRoleV1::SubjectDataEncryption),
            Some(KeyRecordV1 {
                identity: DATA,
                private_material_digest: Some(digest(20)),
                public_verification_key: None,
            })
        );
        assert_eq!(KeyRegistryPortV1::tombstone(&registry, DATA), None);
        let outcome = KeyDestructionPortV1::destroy_key(
            &mut registry,
            KeyDestructionRequestV1::new(DATA, digest(20), digest(21)),
        )?;
        assert!(matches!(outcome, KeyDestructionOutcomeV1::Destroyed(_)));
        assert_eq!(
            KeyRegistryPortV1::tombstone(&registry, DATA),
            Some(outcome.tombstone())
        );
        Ok(())
    }
}
