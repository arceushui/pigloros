//! Role-separated key-registry and irreversible-destruction contracts.
//!
//! The core boundary deliberately carries no private key bytes.  A registry
//! records an owner/role/epoch identity, a fingerprint of the private material, and
//! (for signing roles) the public verification key. Destruction removes the
//! material from the live authorization record and leaves an immutable
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

/// A canonical owner identifier for a key identity.
///
/// Owner bytes are part of every identity and signed representation. The
/// value is intentionally exact: callers must not trim, normalize, or fold
/// case before constructing it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OwnerIdV1 {
    bytes: [u8; 128],
    length: usize,
}

impl OwnerIdV1 {
    /// Construct and validate an owner identifier.
    ///
    /// # Errors
    ///
    /// Returns [`KeyRegistryErrorV1::InvalidOwnerId`] for an empty identifier
    /// or one longer than 128 UTF-8 bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, KeyRegistryErrorV1> {
        let value = value.into();
        let length = value.len();
        if !(1..=128).contains(&length) {
            return Err(KeyRegistryErrorV1::InvalidOwnerId);
        }
        let mut bytes = [0; 128];
        bytes[..length].copy_from_slice(value.as_bytes());
        Ok(Self { bytes, length })
    }

    /// Construct an owner identifier from a source-controlled literal.
    ///
    /// # Panics
    ///
    /// Panics when `value` is empty or longer than 128 UTF-8 bytes. Source
    /// controlled literals should use a valid owner identifier.
    #[must_use]
    pub fn from_static(value: &'static str) -> Self {
        let bytes = value.as_bytes();
        assert!(!bytes.is_empty() && bytes.len() <= 128);
        let mut storage = [0; 128];
        storage[..bytes.len()].copy_from_slice(bytes);
        Self {
            bytes: storage,
            length: bytes.len(),
        }
    }

    /// Return the exact owner identifier bytes as UTF-8 text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.length]).unwrap_or_default()
    }
}

impl Serialize for OwnerIdV1 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for OwnerIdV1 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl From<&'static str> for OwnerIdV1 {
    fn from(value: &'static str) -> Self {
        Self::from_static(value)
    }
}

/// An owner-scoped role and monotonically increasing key epoch.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct KeyIdentityV1 {
    /// Principal that owns the key material and signed identity.
    pub owner_id: OwnerIdV1,
    /// Independent cryptographic role.
    pub role: KeyRoleV1,
    /// Monotonically increasing epoch within `role`; zero is reserved.
    pub epoch: u64,
}

impl KeyIdentityV1 {
    /// Construct an identity in a const context from an already validated owner.
    #[must_use]
    pub const fn from_parts(owner_id: OwnerIdV1, role: KeyRoleV1, epoch: u64) -> Self {
        Self {
            owner_id,
            role,
            epoch,
        }
    }

    /// Construct an owner-scoped role/epoch identity.
    #[must_use]
    pub fn new(owner_id: impl Into<OwnerIdV1>, role: KeyRoleV1, epoch: u64) -> Self {
        Self::from_parts(owner_id.into(), role, epoch)
    }
}

/// A registry input.  `private_material_digest` is a fingerprint, never the
/// private material itself.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyRegistrationV1 {
    /// Owner/role/epoch identity being registered.
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
    /// Owner/role/epoch identity.
    pub identity: KeyIdentityV1,
    /// `None` after irreversible destruction.
    pub private_material_digest: Option<Hash>,
    /// Retained after destruction for signature verification.
    pub public_verification_key: Option<PublicKey>,
}

/// A durable proof that a key identity was destroyed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyTombstoneV1 {
    /// Destroyed owner/role/epoch identity.
    pub identity: KeyIdentityV1,
    /// Fingerprint retained to prohibit material reuse.
    pub destroyed_material_digest: Hash,
    /// Digest binding the destruction request to this tombstone.
    pub destruction_digest: Hash,
    /// Request-bound lifecycle receipt retained with this tombstone.
    pub deletion_receipt: Hash,
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

/// Derive the deterministic lifecycle receipt bound to a destruction request.
///
/// This receipt binds the registry transition to its request. It is not
/// evidence that an adapter durably deleted owned private material.
#[must_use]
pub fn deletion_receipt(request: &KeyDestructionRequestV1) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros/key-deletion-receipt/v1");
    hasher.update(request.identity.owner_id.as_str().as_bytes());
    hasher.update(&[request.identity.role.code()]);
    hasher.update(&request.identity.epoch.to_be_bytes());
    hasher.update(request.expected_material_digest.as_bytes());
    hasher.update(request.authorization_digest.as_bytes());
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// Result of recording a destruction request before private material is deleted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyDestructionBeginOutcomeV1 {
    /// The request was recorded and the identity is now pending destruction.
    Started,
    /// The exact request was already recorded and still awaits finalization.
    AlreadyPending,
    /// The identity was already finalized; the original tombstone is stable.
    AlreadyDestroyed(Box<KeyTombstoneV1>),
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
    /// Owner identifiers must be non-empty and at most 128 UTF-8 bytes.
    #[error("owner identifier must contain 1 through 128 UTF-8 bytes")]
    InvalidOwnerId,
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
    /// The identity is awaiting a deletion receipt before finalization.
    #[error("key identity is pending private-material destruction")]
    DestructionPending,
    /// The request was not recorded as pending destruction.
    #[error("key identity has no pending destruction request")]
    DestructionNotPending,
    /// The deletion receipt does not match the pending material and request.
    #[error("private-material deletion receipt is invalid")]
    DeletionReceiptMismatch,
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
    /// Return the active epoch for an owner-scoped role.
    fn active_key(&self, owner_id: &OwnerIdV1, role: KeyRoleV1) -> Option<KeyRecordV1>;
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
    /// Record a destruction request and revoke authorization without yet
    /// claiming that private material has been deleted.
    ///
    /// # Errors
    ///
    /// Returns a closed [`KeyRegistryErrorV1`] when the identity is missing,
    /// the expected material fingerprint does not match, or a repeated request
    /// does not exactly match the durable tombstone.
    fn begin_key_destruction(
        &mut self,
        request: KeyDestructionRequestV1,
    ) -> Result<KeyDestructionBeginOutcomeV1, KeyRegistryErrorV1>;

    /// Finalize a pending destruction after the owned-material adapter has
    /// returned a deletion receipt.
    ///
    /// # Errors
    ///
    /// Returns a closed [`KeyRegistryErrorV1`] when the request is not
    /// pending, does not match, or the receipt is invalid.
    fn complete_key_destruction(
        &mut self,
        request: KeyDestructionRequestV1,
        deletion_receipt: Hash,
    ) -> Result<KeyDestructionOutcomeV1, KeyRegistryErrorV1>;
}

/// Reference state machine for adapters and public-interface tests.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyRegistryStateV1 {
    records: BTreeMap<KeyIdentityV1, KeyRecordV1>,
    active: BTreeMap<(OwnerIdV1, KeyRoleV1), KeyIdentityV1>,
    tombstones: BTreeMap<KeyIdentityV1, KeyTombstoneV1>,
    highest_epoch: BTreeMap<(OwnerIdV1, KeyRoleV1), u64>,
    pending_destructions: BTreeMap<KeyIdentityV1, KeyDestructionRequestV1>,
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
            pending_destructions: BTreeMap::new(),
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
            if OwnerIdV1::new(identity.owner_id.as_str()).is_err() || identity.epoch == 0 {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
            if identity.role.is_signing() != record.public_verification_key.is_some() {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
            if !self
                .highest_epoch
                .contains_key(&(identity.owner_id, identity.role))
            {
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
        self.validate_pending_destructions()?;
        for ((owner_id, role), highest_epoch) in &self.highest_epoch {
            let Some(maximum) = self
                .records
                .keys()
                .filter(|identity| {
                    identity.owner_id.as_str() == owner_id.as_str() && identity.role == *role
                })
                .map(|identity| identity.epoch)
                .max()
            else {
                return Err(KeyRegistryErrorV1::InvalidState);
            };
            if maximum != *highest_epoch {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
        }
        for ((owner_id, role), identity) in &self.active {
            if OwnerIdV1::new(owner_id.as_str()).is_err() {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
            if identity.role != *role {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
            if identity.owner_id.as_str() != owner_id.as_str() {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
            if self.tombstones.contains_key(identity) {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
            if !self.records.contains_key(identity) {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
            if self.highest_epoch.get(&(*owner_id, *role)) != Some(&identity.epoch) {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
        }
        for ((owner_id, role), highest_epoch) in &self.highest_epoch {
            let identity = KeyIdentityV1::new(*owner_id, *role, *highest_epoch);
            if !self.tombstones.contains_key(&identity)
                && !self.pending_destructions.contains_key(&identity)
                && self.active.get(&(*owner_id, *role)) != Some(&identity)
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
            if next.tombstones.contains_key(identity)
                || next.pending_destructions.contains_key(identity)
            {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
            if self
                .highest_epoch
                .get(&(identity.owner_id, identity.role))
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
                (None, Some(_)) => {
                    return Err(KeyRegistryErrorV1::InvalidState);
                }
                (Some(_), None) => {
                    if !self.pending_destructions.contains_key(identity) {
                        return Err(KeyRegistryErrorV1::InvalidState);
                    }
                }
                (None, None) if next.tombstones.get(identity) != self.tombstones.get(identity) => {
                    return Err(KeyRegistryErrorV1::InvalidState);
                }
                (Some(_), Some(_)) | (None, None) => {}
            }
        }
        for (identity, request) in &self.pending_destructions {
            if next.pending_destructions.get(identity) == Some(request) {
                continue;
            }
            let Some(tombstone) = next.tombstones.get(identity) else {
                return Err(KeyRegistryErrorV1::InvalidState);
            };
            if tombstone.destroyed_material_digest != request.expected_material_digest
                || tombstone.destruction_digest != destruction_digest(request)
                || tombstone.deletion_receipt != deletion_receipt(request)
            {
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
        validate_registration(&registration)?;
        let identity = registration.identity;
        if self.tombstones.contains_key(&identity) {
            return Err(KeyRegistryErrorV1::Destroyed);
        }
        if self.pending_destructions.contains_key(&identity) {
            return Err(KeyRegistryErrorV1::DestructionPending);
        }
        if let Some(highest) = self.highest_epoch.get(&(identity.owner_id, identity.role)) {
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
        self.active
            .insert((identity.owner_id, identity.role), identity);
        self.highest_epoch
            .insert((identity.owner_id, identity.role), identity.epoch);
        Ok(KeyRegistrationOutcomeV1::Registered)
    }

    /// Return the active record for an owner-scoped `role`.
    #[must_use]
    pub fn active_key(&self, owner_id: &OwnerIdV1, role: KeyRoleV1) -> Option<KeyRecordV1> {
        self.active
            .get(&(*owner_id, role))
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
        if identity.epoch == 0 {
            return Err(KeyRegistryErrorV1::InvalidEpoch);
        }
        if !identity.role.is_signing() {
            return Err(KeyRegistryErrorV1::SigningRoleRequired);
        }
        self.validate()
            .map_err(|_| KeyRegistryErrorV1::RegistryUnavailable)?;
        let record = self
            .records
            .get(&identity)
            .copied()
            .ok_or(KeyRegistryErrorV1::NotFound)?;
        if self.tombstones.contains_key(&identity) {
            return Err(KeyRegistryErrorV1::Destroyed);
        }
        if self.pending_destructions.contains_key(&identity) {
            return Err(KeyRegistryErrorV1::DestructionPending);
        }
        let active_identity = self
            .active
            .get(&(identity.owner_id, identity.role))
            .copied()
            .ok_or(KeyRegistryErrorV1::InactiveKey)?;
        if active_identity != identity {
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
        if identity.epoch == 0 {
            return Err(KeyRegistryErrorV1::InvalidEpoch);
        }
        if !identity.role.is_encryption() {
            return Err(KeyRegistryErrorV1::EncryptionRoleRequired);
        }
        self.validate()
            .map_err(|_| KeyRegistryErrorV1::RegistryUnavailable)?;
        let record = self
            .records
            .get(&identity)
            .copied()
            .ok_or(KeyRegistryErrorV1::NotFound)?;
        if self.tombstones.contains_key(&identity) {
            return Err(KeyRegistryErrorV1::Destroyed);
        }
        if self.pending_destructions.contains_key(&identity) {
            return Err(KeyRegistryErrorV1::DestructionPending);
        }
        let active_identity = self
            .active
            .get(&(identity.owner_id, identity.role))
            .copied()
            .ok_or(KeyRegistryErrorV1::InactiveKey)?;
        if active_identity != identity {
            return Err(KeyRegistryErrorV1::InactiveKey);
        }
        if record.private_material_digest != Some(private_material_digest) {
            return Err(KeyRegistryErrorV1::EncryptionKeyMismatch);
        }
        Ok(operation())
    }

    /// Record a destruction request and revoke active authorization.
    ///
    /// # Errors
    ///
    /// Returns a closed [`KeyRegistryErrorV1`] when the identity is missing,
    /// the expected material fingerprint does not match, or a repeated request
    /// does not exactly match the durable tombstone.
    pub fn begin_key_destruction(
        &mut self,
        request: KeyDestructionRequestV1,
    ) -> Result<KeyDestructionBeginOutcomeV1, KeyRegistryErrorV1> {
        if request.identity.epoch == 0 {
            return Err(KeyRegistryErrorV1::InvalidEpoch);
        }
        self.validate()?;
        if let Some(tombstone) = self.tombstones.get(&request.identity).copied() {
            if tombstone.destroyed_material_digest != request.expected_material_digest {
                return Err(KeyRegistryErrorV1::MaterialDigestMismatch);
            }
            if tombstone.destruction_digest != destruction_digest(&request) {
                return Err(KeyRegistryErrorV1::DestructionAuthorizationMismatch);
            }
            if tombstone.deletion_receipt != deletion_receipt(&request) {
                return Err(KeyRegistryErrorV1::DeletionReceiptMismatch);
            }
            return Ok(KeyDestructionBeginOutcomeV1::AlreadyDestroyed(Box::new(
                tombstone,
            )));
        }
        if let Some(pending) = self.pending_destructions.get(&request.identity) {
            if pending != &request {
                return Err(KeyRegistryErrorV1::DestructionAuthorizationMismatch);
            }
            return Ok(KeyDestructionBeginOutcomeV1::AlreadyPending);
        }
        let Some(record) = self.records.get(&request.identity) else {
            return Err(KeyRegistryErrorV1::NotFound);
        };
        if record.private_material_digest != Some(request.expected_material_digest) {
            return Err(KeyRegistryErrorV1::MaterialDigestMismatch);
        }
        let identity = request.identity;
        self.pending_destructions.insert(identity, request);
        if self.active.get(&(identity.owner_id, identity.role)) == Some(&identity) {
            self.active.remove(&(identity.owner_id, identity.role));
        }
        Ok(KeyDestructionBeginOutcomeV1::Started)
    }

    /// Finalize a pending destruction after the owned-material adapter has
    /// returned a request-bound deletion receipt.
    ///
    /// # Errors
    ///
    /// Returns a closed [`KeyRegistryErrorV1`] when the request is not
    /// pending, does not match, or the receipt is invalid.
    pub fn complete_key_destruction(
        &mut self,
        request: KeyDestructionRequestV1,
        receipt: Hash,
    ) -> Result<KeyDestructionOutcomeV1, KeyRegistryErrorV1> {
        if request.identity.epoch == 0 {
            return Err(KeyRegistryErrorV1::InvalidEpoch);
        }
        self.validate()?;
        if let Some(tombstone) = self.tombstones.get(&request.identity).copied() {
            if tombstone.destroyed_material_digest != request.expected_material_digest {
                return Err(KeyRegistryErrorV1::MaterialDigestMismatch);
            }
            if tombstone.destruction_digest != destruction_digest(&request)
                || tombstone.deletion_receipt != receipt
            {
                return Err(KeyRegistryErrorV1::DestructionAuthorizationMismatch);
            }
            return Ok(KeyDestructionOutcomeV1::AlreadyDestroyed(tombstone));
        }
        if self.pending_destructions.get(&request.identity) != Some(&request) {
            return if self.pending_destructions.contains_key(&request.identity) {
                Err(KeyRegistryErrorV1::DestructionAuthorizationMismatch)
            } else {
                Err(KeyRegistryErrorV1::DestructionNotPending)
            };
        }
        if receipt != deletion_receipt(&request) {
            return Err(KeyRegistryErrorV1::DeletionReceiptMismatch);
        }
        // `validate` proves that every pending request has a record.
        let Some(record) = self.records.get_mut(&request.identity) else {
            return Err(KeyRegistryErrorV1::InvalidState);
        };
        record.private_material_digest = None;
        let destruction_digest = destruction_digest(&request);
        let identity = request.identity;
        let tombstone = KeyTombstoneV1 {
            identity,
            destroyed_material_digest: request.expected_material_digest,
            destruction_digest,
            deletion_receipt: receipt,
        };
        self.pending_destructions.remove(&request.identity);
        self.tombstones.insert(request.identity, tombstone);
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

    fn validate_pending_destructions(&self) -> Result<(), KeyRegistryErrorV1> {
        for (identity, request) in &self.pending_destructions {
            let Some(record) = self.records.get(identity) else {
                return Err(KeyRegistryErrorV1::InvalidState);
            };
            if request.identity != *identity
                || request.expected_material_digest
                    != record
                        .private_material_digest
                        .ok_or(KeyRegistryErrorV1::InvalidState)?
                || self.tombstones.contains_key(identity)
                || self.active.get(&(identity.owner_id, identity.role)) == Some(identity)
            {
                return Err(KeyRegistryErrorV1::InvalidState);
            }
        }
        Ok(())
    }
}

impl KeyRegistryPortV1 for KeyRegistryStateV1 {
    fn register_key(
        &mut self,
        registration: KeyRegistrationV1,
    ) -> Result<KeyRegistrationOutcomeV1, KeyRegistryErrorV1> {
        Self::register_key(self, registration)
    }

    fn active_key(&self, owner_id: &OwnerIdV1, role: KeyRoleV1) -> Option<KeyRecordV1> {
        Self::active_key(self, owner_id, role)
    }

    fn key_record(&self, identity: KeyIdentityV1) -> Option<KeyRecordV1> {
        Self::key_record(self, identity)
    }

    fn tombstone(&self, identity: KeyIdentityV1) -> Option<KeyTombstoneV1> {
        Self::tombstone(self, identity)
    }
}

impl KeyDestructionPortV1 for KeyRegistryStateV1 {
    fn begin_key_destruction(
        &mut self,
        request: KeyDestructionRequestV1,
    ) -> Result<KeyDestructionBeginOutcomeV1, KeyRegistryErrorV1> {
        Self::begin_key_destruction(self, request)
    }

    fn complete_key_destruction(
        &mut self,
        request: KeyDestructionRequestV1,
        deletion_receipt: Hash,
    ) -> Result<KeyDestructionOutcomeV1, KeyRegistryErrorV1> {
        Self::complete_key_destruction(self, request, deletion_receipt)
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

const fn validate_registration(registration: &KeyRegistrationV1) -> Result<(), KeyRegistryErrorV1> {
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
    let owner_bytes = request.identity.owner_id.as_str().as_bytes();
    hasher.update(
        &u32::try_from(owner_bytes.len())
            .unwrap_or_default()
            .to_be_bytes(),
    );
    hasher.update(owner_bytes);
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

    const TEST_OWNER: OwnerIdV1 = OwnerIdV1 {
        bytes: {
            let mut bytes = [0; 128];
            bytes[0] = b't';
            bytes[1] = b'e';
            bytes[2] = b's';
            bytes[3] = b't';
            bytes[4] = b'-';
            bytes[5] = b'o';
            bytes[6] = b'w';
            bytes[7] = b'n';
            bytes[8] = b'e';
            bytes[9] = b'r';
            bytes
        },
        length: 10,
    };
    const DATA: KeyIdentityV1 =
        KeyIdentityV1::from_parts(TEST_OWNER, KeyRoleV1::SubjectDataEncryption, 1);
    const ATTRIBUTION: KeyIdentityV1 =
        KeyIdentityV1::from_parts(TEST_OWNER, KeyRoleV1::SubjectAttributionSigning, 1);

    fn digest(value: u8) -> Hash {
        Hash::from_bytes([value; 32])
    }

    fn destroy(
        registry: &mut KeyRegistryStateV1,
        request: KeyDestructionRequestV1,
    ) -> Result<KeyDestructionOutcomeV1, KeyRegistryErrorV1> {
        registry.begin_key_destruction(request)?;
        registry.complete_key_destruction(request, deletion_receipt(&request))
    }

    fn assert_pending_transition_binds_every_tombstone_field(
        pending: &KeyRegistryStateV1,
        request: KeyDestructionRequestV1,
    ) -> Result<(), KeyRegistryErrorV1> {
        let mut completed = pending.clone();
        completed.complete_key_destruction(request, deletion_receipt(&request))?;
        assert_eq!(pending.validate_replacement(&completed), Ok(()));

        let mut wrong_material = completed.clone();
        wrong_material
            .tombstones
            .get_mut(&request.identity)
            .ok_or(KeyRegistryErrorV1::NotFound)?
            .destroyed_material_digest = digest(70);
        assert_eq!(
            pending.validate_replacement(&wrong_material),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut wrong_destruction = completed.clone();
        wrong_destruction
            .tombstones
            .get_mut(&request.identity)
            .ok_or(KeyRegistryErrorV1::NotFound)?
            .destruction_digest = digest(71);
        assert_eq!(
            pending.validate_replacement(&wrong_destruction),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut wrong_receipt = completed;
        wrong_receipt
            .tombstones
            .get_mut(&request.identity)
            .ok_or(KeyRegistryErrorV1::NotFound)?
            .deletion_receipt = digest(72);
        assert_eq!(
            pending.validate_replacement(&wrong_receipt),
            Err(KeyRegistryErrorV1::InvalidState)
        );
        Ok(())
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
            KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectAttributionSigning, 0),
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
            KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectAttributionSigning, 9),
            2,
            2,
            KeyRegistryErrorV1::NotFound,
        );

        let next = KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectAttributionSigning, 2);
        registry.register_key(signing_registration(next, 4))?;
        assert_signing_error(
            &mut registry,
            ATTRIBUTION,
            2,
            2,
            KeyRegistryErrorV1::InactiveKey,
        );

        destroy(
            &mut registry,
            KeyDestructionRequestV1::new(next, digest(4), digest(5)),
        )?;
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
                KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectDataEncryption, 0),
                digest(1),
                || (),
            ),
            Err(KeyRegistryErrorV1::InvalidEpoch)
        );

        let next = KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectDataEncryption, 2);
        registry.register_key(KeyRegistrationV1::new(next, digest(2), None))?;
        assert_eq!(
            registry.with_encryption_authorization(DATA, digest(1), || ()),
            Err(KeyRegistryErrorV1::InactiveKey)
        );
        let request = KeyDestructionRequestV1::new(next, digest(2), digest(3));
        assert_eq!(
            registry.begin_key_destruction(request)?,
            KeyDestructionBeginOutcomeV1::Started
        );
        assert_eq!(
            registry.with_encryption_authorization(next, digest(2), || ()),
            Err(KeyRegistryErrorV1::DestructionPending)
        );
        assert!(matches!(
            registry.complete_key_destruction(request, deletion_receipt(&request))?,
            KeyDestructionOutcomeV1::Destroyed(_)
        ));
        assert_eq!(
            registry.with_encryption_authorization(next, digest(2), || ()),
            Err(KeyRegistryErrorV1::Destroyed)
        );
        assert_eq!(
            registry.with_encryption_authorization(DATA, digest(1), || ()),
            Err(KeyRegistryErrorV1::InactiveKey)
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
        let first = destroy(&mut registry, request)?;
        let second = destroy(&mut registry, request)?;
        assert!(matches!(first, KeyDestructionOutcomeV1::Destroyed(_)));
        assert!(matches!(
            second,
            KeyDestructionOutcomeV1::AlreadyDestroyed(_)
        ));
        assert_eq!(first.tombstone(), second.tombstone());
        assert_eq!(
            destroy(
                &mut registry,
                KeyDestructionRequestV1::new(ATTRIBUTION, digest(99), digest(3),)
            ),
            Err(KeyRegistryErrorV1::MaterialDigestMismatch)
        );
        assert_eq!(
            registry.begin_key_destruction(KeyDestructionRequestV1::new(
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
            registry.active_key(
                &OwnerIdV1::from_static("test-owner"),
                KeyRoleV1::SubjectAttributionSigning,
            ),
            None
        );
        assert_eq!(
            registry.register_key(signing_registration(ATTRIBUTION, 2)),
            Err(KeyRegistryErrorV1::Destroyed)
        );
        Ok(())
    }

    #[test]
    fn owners_have_independent_role_epochs() -> Result<(), KeyRegistryErrorV1> {
        let mut registry = KeyRegistryStateV1::new();
        let first_owner = KeyIdentityV1::new(TEST_OWNER, KeyRoleV1::TimelineIntegritySigning, 1);
        let second_owner = KeyIdentityV1::new(
            OwnerIdV1::from_static("other-owner"),
            KeyRoleV1::TimelineIntegritySigning,
            1,
        );

        assert_eq!(
            registry.register_key(signing_registration(first_owner, 43))?,
            KeyRegistrationOutcomeV1::Registered
        );
        assert_eq!(
            registry.register_key(signing_registration(second_owner, 44))?,
            KeyRegistrationOutcomeV1::Registered
        );
        assert_eq!(
            registry
                .active_key(&first_owner.owner_id, first_owner.role)
                .map(|record| record.identity),
            Some(first_owner)
        );
        assert_eq!(
            registry
                .active_key(&second_owner.owner_id, second_owner.role)
                .map(|record| record.identity),
            Some(second_owner)
        );
        assert_eq!(registry.validate(), Ok(()));
        Ok(())
    }

    #[test]
    fn pending_destruction_requires_matching_receipt_before_finalization(
    ) -> Result<(), KeyRegistryErrorV1> {
        let mut registry = KeyRegistryStateV1::new();
        registry.register_key(signing_registration(ATTRIBUTION, 45))?;
        let request = KeyDestructionRequestV1::new(ATTRIBUTION, digest(45), digest(46));

        assert_eq!(
            registry.begin_key_destruction(request)?,
            KeyDestructionBeginOutcomeV1::Started
        );
        assert_eq!(
            registry.begin_key_destruction(request)?,
            KeyDestructionBeginOutcomeV1::AlreadyPending
        );
        assert_eq!(
            registry.with_signing_authorization(
                ATTRIBUTION,
                digest(45),
                PublicKey::from_bytes([45; 32]),
                || (),
            ),
            Err(KeyRegistryErrorV1::DestructionPending)
        );
        assert_eq!(
            registry.complete_key_destruction(request, digest(47)),
            Err(KeyRegistryErrorV1::DeletionReceiptMismatch)
        );
        let outcome = registry.complete_key_destruction(request, deletion_receipt(&request))?;
        assert!(matches!(outcome, KeyDestructionOutcomeV1::Destroyed(_)));
        assert_eq!(registry.validate(), Ok(()));
        Ok(())
    }

    #[test]
    fn malformed_active_and_pending_indexes_are_rejected() -> Result<(), KeyRegistryErrorV1> {
        let invalid_owner = OwnerIdV1 {
            bytes: [0; 128],
            length: 0,
        };
        let invalid_owner_identity =
            KeyIdentityV1::from_parts(invalid_owner, KeyRoleV1::TimelineIntegritySigning, 1);
        let mut invalid_owner_state = KeyRegistryStateV1::new();
        invalid_owner_state.active.insert(
            (invalid_owner, invalid_owner_identity.role),
            invalid_owner_identity,
        );
        assert_eq!(
            invalid_owner_state.validate(),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let other_owner = OwnerIdV1::from_static("other-owner");
        let other_identity =
            KeyIdentityV1::from_parts(other_owner, KeyRoleV1::TimelineIntegritySigning, 1);
        let mut mismatched_owner = KeyRegistryStateV1::new();
        mismatched_owner
            .active
            .insert((TEST_OWNER, other_identity.role), other_identity);
        assert_eq!(
            mismatched_owner.validate(),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut mismatched_role = KeyRegistryStateV1::new();
        mismatched_role
            .active
            .insert((TEST_OWNER, KeyRoleV1::SubjectDataEncryption), ATTRIBUTION);
        assert_eq!(
            mismatched_role.validate(),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let request = KeyDestructionRequestV1::new(ATTRIBUTION, digest(61), digest(62));
        let mut missing_record = KeyRegistryStateV1::new();
        missing_record
            .pending_destructions
            .insert(ATTRIBUTION, request);
        assert_eq!(
            missing_record.validate(),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut missing_material = KeyRegistryStateV1::new();
        missing_material.records.insert(
            ATTRIBUTION,
            KeyRecordV1 {
                identity: ATTRIBUTION,
                private_material_digest: None,
                public_verification_key: Some(PublicKey::from_bytes([63; 32])),
            },
        );
        missing_material.tombstones.insert(
            ATTRIBUTION,
            KeyTombstoneV1 {
                identity: ATTRIBUTION,
                destroyed_material_digest: digest(63),
                destruction_digest: digest(64),
                deletion_receipt: digest(65),
            },
        );
        missing_material
            .highest_epoch
            .insert((ATTRIBUTION.owner_id, ATTRIBUTION.role), ATTRIBUTION.epoch);
        missing_material
            .pending_destructions
            .insert(ATTRIBUTION, request);
        assert_eq!(
            missing_material.validate(),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut active_pending = KeyRegistryStateV1::new();
        active_pending.register_key(signing_registration(ATTRIBUTION, 66))?;
        active_pending.pending_destructions.insert(
            ATTRIBUTION,
            KeyDestructionRequestV1::new(ATTRIBUTION, digest(66), digest(67)),
        );
        assert_eq!(
            active_pending.validate(),
            Err(KeyRegistryErrorV1::InvalidState)
        );
        Ok(())
    }

    #[test]
    fn pending_destruction_guards_cover_remaining_transitions() -> Result<(), KeyRegistryErrorV1> {
        let mut pending = KeyRegistryStateV1::new();
        pending.register_key(signing_registration(ATTRIBUTION, 60))?;
        let request = KeyDestructionRequestV1::new(ATTRIBUTION, digest(60), digest(61));
        assert_eq!(
            pending.begin_key_destruction(request)?,
            KeyDestructionBeginOutcomeV1::Started
        );
        assert_eq!(
            pending.begin_key_destruction(request)?,
            KeyDestructionBeginOutcomeV1::AlreadyPending
        );
        assert_eq!(pending.validate_replacement(&pending), Ok(()));
        assert_eq!(
            pending.register_key(signing_registration(ATTRIBUTION, 60)),
            Err(KeyRegistryErrorV1::DestructionPending)
        );
        assert_eq!(
            pending.begin_key_destruction(KeyDestructionRequestV1::new(
                ATTRIBUTION,
                digest(60),
                digest(62),
            )),
            Err(KeyRegistryErrorV1::DestructionAuthorizationMismatch)
        );
        assert_eq!(
            pending.complete_key_destruction(
                KeyDestructionRequestV1::new(ATTRIBUTION, digest(60), digest(62),),
                deletion_receipt(&request)
            ),
            Err(KeyRegistryErrorV1::DestructionAuthorizationMismatch)
        );
        assert_eq!(
            pending.complete_key_destruction(
                KeyDestructionRequestV1::new(DATA, digest(68), digest(69)),
                digest(70),
            ),
            Err(KeyRegistryErrorV1::DestructionNotPending)
        );

        let mut restored_active = pending.clone();
        restored_active
            .active
            .insert((ATTRIBUTION.owner_id, ATTRIBUTION.role), ATTRIBUTION);
        restored_active.pending_destructions.remove(&ATTRIBUTION);
        assert_eq!(
            pending.validate_replacement(&restored_active),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        assert_pending_transition_binds_every_tombstone_field(&pending, request)?;

        Ok(())
    }

    #[test]
    fn destruction_rejects_zero_epoch_and_direct_tombstoning() -> Result<(), KeyRegistryErrorV1> {
        let zero_epoch_request = KeyDestructionRequestV1::new(
            KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectAttributionSigning, 0),
            digest(59),
            digest(60),
        );
        let mut zero_epoch_registry = KeyRegistryStateV1::new();
        assert_eq!(
            zero_epoch_registry.begin_key_destruction(zero_epoch_request),
            Err(KeyRegistryErrorV1::InvalidEpoch)
        );
        assert_eq!(
            zero_epoch_registry.complete_key_destruction(
                zero_epoch_request,
                deletion_receipt(&zero_epoch_request),
            ),
            Err(KeyRegistryErrorV1::InvalidEpoch)
        );

        let mut live = KeyRegistryStateV1::new();
        live.register_key(signing_registration(ATTRIBUTION, 72))?;
        let direct_request = KeyDestructionRequestV1::new(ATTRIBUTION, digest(72), digest(73));
        let mut direct_tombstone = live.clone();
        direct_tombstone
            .records
            .get_mut(&ATTRIBUTION)
            .ok_or(KeyRegistryErrorV1::NotFound)?
            .private_material_digest = None;
        direct_tombstone
            .active
            .remove(&(ATTRIBUTION.owner_id, ATTRIBUTION.role));
        direct_tombstone.tombstones.insert(
            ATTRIBUTION,
            KeyTombstoneV1 {
                identity: ATTRIBUTION,
                destroyed_material_digest: digest(72),
                destruction_digest: destruction_digest(&direct_request),
                deletion_receipt: deletion_receipt(&direct_request),
            },
        );
        assert_eq!(
            live.validate_replacement(&direct_tombstone),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut pending_initial_snapshot = live.clone();
        pending_initial_snapshot.begin_key_destruction(direct_request)?;
        assert_eq!(
            KeyRegistryStateV1::new().validate_replacement(&pending_initial_snapshot),
            Err(KeyRegistryErrorV1::InvalidState)
        );
        let mut destroyed_initial_snapshot = pending_initial_snapshot.clone();
        destroyed_initial_snapshot
            .complete_key_destruction(direct_request, deletion_receipt(&direct_request))?;
        assert_eq!(
            KeyRegistryStateV1::new().validate_replacement(&destroyed_initial_snapshot),
            Err(KeyRegistryErrorV1::InvalidState)
        );
        Ok(())
    }

    #[test]
    fn destroyed_destruction_guards_cover_remaining_transitions() -> Result<(), KeyRegistryErrorV1>
    {
        let mut stale = KeyRegistryStateV1::new();
        let latest = KeyIdentityV1::new(TEST_OWNER, KeyRoleV1::SubjectAttributionSigning, 2);
        stale.register_key(signing_registration(latest, 72))?;
        assert!(matches!(
            stale.register_key(signing_registration(ATTRIBUTION, 73)),
            Err(KeyRegistryErrorV1::StaleEpoch { .. })
        ));

        let mut destroyed = KeyRegistryStateV1::new();
        destroyed.register_key(signing_registration(ATTRIBUTION, 74))?;
        let destroyed_request = KeyDestructionRequestV1::new(ATTRIBUTION, digest(74), digest(75));
        destroy(&mut destroyed, destroyed_request)?;
        assert_eq!(
            destroyed.complete_key_destruction(
                KeyDestructionRequestV1::new(ATTRIBUTION, digest(76), digest(75)),
                digest(77),
            ),
            Err(KeyRegistryErrorV1::MaterialDigestMismatch)
        );
        let wrong_authorization = KeyDestructionRequestV1::new(ATTRIBUTION, digest(74), digest(78));
        assert_eq!(
            destroyed.complete_key_destruction(
                wrong_authorization,
                deletion_receipt(&wrong_authorization),
            ),
            Err(KeyRegistryErrorV1::DestructionAuthorizationMismatch)
        );
        let mut wrong_receipt = destroyed.clone();
        wrong_receipt
            .tombstones
            .get_mut(&ATTRIBUTION)
            .ok_or(KeyRegistryErrorV1::NotFound)?
            .deletion_receipt = digest(79);
        assert_eq!(
            wrong_receipt.begin_key_destruction(destroyed_request),
            Err(KeyRegistryErrorV1::DeletionReceiptMismatch)
        );
        Ok(())
    }

    #[test]
    fn owner_identifier_validation_preserves_exact_utf8_bytes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            OwnerIdV1::new(String::new()),
            Err(KeyRegistryErrorV1::InvalidOwnerId)
        );
        assert_eq!(
            OwnerIdV1::new("x".repeat(129)),
            Err(KeyRegistryErrorV1::InvalidOwnerId)
        );
        let unicode = "é".repeat(64);
        let owner = OwnerIdV1::new(unicode.clone())?;
        assert_eq!(owner.as_str(), unicode);
        let exact = OwnerIdV1::new("Case-Sensitive")?;
        assert_eq!(exact.as_str(), "Case-Sensitive");
        assert_ne!(exact, OwnerIdV1::new("case-sensitive")?);

        let encoded = serde_json::to_string(&unicode)?;
        let decoded: OwnerIdV1 = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, owner);
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
        state
            .active
            .insert((ATTRIBUTION.owner_id, ATTRIBUTION.role), ATTRIBUTION);
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
            .identity = KeyIdentityV1::new("test-owner", ATTRIBUTION.role, 2);
        assert_eq!(
            mismatched_record.validate(),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut zero_epoch = KeyRegistryStateV1::new();
        let zero = KeyIdentityV1::new("test-owner", ATTRIBUTION.role, 0);
        zero_epoch.records.insert(
            zero,
            KeyRecordV1 {
                identity: zero,
                private_material_digest: Some(digest(33)),
                public_verification_key: Some(PublicKey::from_bytes([33; 32])),
            },
        );
        zero_epoch.active.insert((zero.owner_id, zero.role), zero);
        zero_epoch
            .highest_epoch
            .insert((zero.owner_id, zero.role), 0);
        assert_eq!(zero_epoch.validate(), Err(KeyRegistryErrorV1::InvalidState));

        let mut high_water_mismatch = KeyRegistryStateV1::new();
        high_water_mismatch.register_key(signing_registration(ATTRIBUTION, 34))?;
        high_water_mismatch
            .highest_epoch
            .insert((ATTRIBUTION.owner_id, ATTRIBUTION.role), 2);
        assert_eq!(
            high_water_mismatch.validate(),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut orphaned_tombstone = KeyRegistryStateV1::new();
        orphaned_tombstone.register_key(signing_registration(ATTRIBUTION, 35))?;
        destroy(
            &mut orphaned_tombstone,
            KeyDestructionRequestV1::new(ATTRIBUTION, digest(35), digest(36)),
        )?;
        orphaned_tombstone.records.remove(&ATTRIBUTION);
        orphaned_tombstone
            .active
            .remove(&(ATTRIBUTION.owner_id, ATTRIBUTION.role));
        orphaned_tombstone
            .highest_epoch
            .remove(&(ATTRIBUTION.owner_id, ATTRIBUTION.role));
        assert_eq!(
            orphaned_tombstone.validate(),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut mismatched_tombstone = KeyRegistryStateV1::new();
        mismatched_tombstone.register_key(signing_registration(ATTRIBUTION, 37))?;
        destroy(
            &mut mismatched_tombstone,
            KeyDestructionRequestV1::new(ATTRIBUTION, digest(37), digest(38)),
        )?;
        mismatched_tombstone
            .tombstones
            .get_mut(&ATTRIBUTION)
            .ok_or("missing tombstone")?
            .identity = KeyIdentityV1::new("test-owner", ATTRIBUTION.role, 2);
        assert_eq!(
            mismatched_tombstone.validate(),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut restored_material = KeyRegistryStateV1::new();
        restored_material.register_key(signing_registration(ATTRIBUTION, 39))?;
        destroy(
            &mut restored_material,
            KeyDestructionRequestV1::new(ATTRIBUTION, digest(39), digest(40)),
        )?;
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
        destroy(
            &mut state,
            KeyDestructionRequestV1::new(ATTRIBUTION, digest(18), digest(17)),
        )?;
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
        destroy(
            &mut destroyed,
            KeyDestructionRequestV1::new(ATTRIBUTION, digest(20), digest(21)),
        )?;
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
        let first = KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectAttributionSigning, 1);
        let second = KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectAttributionSigning, 2);
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
            .insert((second.owner_id, KeyRoleV1::SubjectDataEncryption), second);
        assert_eq!(
            wrong_active_role.validate(),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut destroyed = first_state;
        destroy(
            &mut destroyed,
            KeyDestructionRequestV1::new(first, digest(30), digest(32)),
        )?;
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
        state.active.remove(&(DATA.owner_id, DATA.role));
        assert_eq!(
            state.with_encryption_authorization(DATA, digest(57), || ()),
            Err(KeyRegistryErrorV1::RegistryUnavailable)
        );
        Ok(())
    }

    #[test]
    fn durable_replacement_rejects_backfilled_stale_epoch() -> Result<(), KeyRegistryErrorV1> {
        let latest = KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectAttributionSigning, 2);
        let stale = KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectAttributionSigning, 1);
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
    fn registry_mutators_fail_closed_for_invalid_snapshots_and_missing_records(
    ) -> Result<(), KeyRegistryErrorV1> {
        let mut invalid = KeyRegistryStateV1::new();
        invalid.records.insert(
            DATA,
            KeyRecordV1 {
                identity: DATA,
                private_material_digest: Some(digest(58)),
                public_verification_key: None,
            },
        );
        let mut valid = KeyRegistryStateV1::new();
        valid.register_key(KeyRegistrationV1::new(DATA, digest(59), None))?;

        assert_eq!(
            invalid.validate_replacement(&valid),
            Err(KeyRegistryErrorV1::InvalidState)
        );
        assert_eq!(
            invalid.with_signing_authorization(
                KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectAttributionSigning, 0),
                digest(58),
                PublicKey::from_bytes([58; 32]),
                || (),
            ),
            Err(KeyRegistryErrorV1::InvalidEpoch)
        );
        assert_eq!(
            invalid.with_encryption_authorization(ATTRIBUTION, digest(58), || ()),
            Err(KeyRegistryErrorV1::EncryptionRoleRequired)
        );
        let mut invalid_next = valid.clone();
        invalid_next.active.clear();
        assert_eq!(
            valid.validate_replacement(&invalid_next),
            Err(KeyRegistryErrorV1::InvalidState)
        );
        assert_eq!(
            invalid.register_key(KeyRegistrationV1::new(DATA, digest(60), None)),
            Err(KeyRegistryErrorV1::InvalidState)
        );
        assert_eq!(
            KeyRegistryStateV1::new().with_encryption_authorization(DATA, digest(59), || ()),
            Err(KeyRegistryErrorV1::NotFound)
        );
        assert_eq!(
            invalid.begin_key_destruction(KeyDestructionRequestV1::new(
                DATA,
                digest(58),
                digest(61)
            )),
            Err(KeyRegistryErrorV1::InvalidState)
        );
        assert_eq!(
            invalid.complete_key_destruction(
                KeyDestructionRequestV1::new(DATA, digest(58), digest(61)),
                digest(62),
            ),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        destroy(
            &mut valid,
            KeyDestructionRequestV1::new(DATA, digest(59), digest(62)),
        )?;
        let mut changed_tombstone = valid.clone();
        changed_tombstone
            .tombstones
            .get_mut(&DATA)
            .ok_or(KeyRegistryErrorV1::NotFound)?
            .destroyed_material_digest = digest(63);
        assert_eq!(
            valid.validate_replacement(&changed_tombstone),
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

        let request = KeyDestructionRequestV1::new(ATTRIBUTION, digest(50), digest(53));
        let mut pending = previous.clone();
        assert_eq!(
            pending.begin_key_destruction(request)?,
            KeyDestructionBeginOutcomeV1::Started
        );
        let mut destroyed = pending.clone();
        assert!(matches!(
            destroyed.complete_key_destruction(request, deletion_receipt(&request))?,
            KeyDestructionOutcomeV1::Destroyed(_)
        ));
        assert_eq!(
            previous.validate_replacement(&destroyed),
            Err(KeyRegistryErrorV1::InvalidState)
        );
        assert_eq!(pending.validate_replacement(&destroyed), Ok(()));

        let mut restored = destroyed.clone();
        restored
            .records
            .get_mut(&ATTRIBUTION)
            .ok_or(KeyRegistryErrorV1::NotFound)?
            .private_material_digest = Some(digest(50));
        restored
            .active
            .insert((ATTRIBUTION.owner_id, ATTRIBUTION.role), ATTRIBUTION);
        restored.tombstones.remove(&ATTRIBUTION);
        assert_eq!(
            destroyed.validate_replacement(&restored),
            Err(KeyRegistryErrorV1::InvalidState)
        );

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

        let mut destroyed_tombstone_changed = destroyed.clone();
        destroyed_tombstone_changed
            .tombstones
            .get_mut(&ATTRIBUTION)
            .ok_or(KeyRegistryErrorV1::NotFound)?
            .destroyed_material_digest = digest(56);
        assert_eq!(
            destroyed.validate_replacement(&destroyed_tombstone_changed),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let next = KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectAttributionSigning, 2);
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
        destroy(
            &mut registry,
            KeyDestructionRequestV1::new(DATA, digest(4), digest(6)),
        )?;
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
        let latest = KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectDataEncryption, 3);
        registry.register_key(KeyRegistrationV1::new(latest, digest(30), None))?;
        destroy(
            &mut registry,
            KeyDestructionRequestV1::new(latest, digest(30), digest(31)),
        )?;

        assert_eq!(
            registry.register_key(KeyRegistrationV1::new(
                KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectDataEncryption, 2),
                digest(32),
                None,
            )),
            Err(KeyRegistryErrorV1::StaleEpoch {
                role: KeyRoleV1::SubjectDataEncryption,
                requested: 2,
                active: 3,
            })
        );
        assert_eq!(
            registry.active_key(
                &OwnerIdV1::from_static("test-owner"),
                KeyRoleV1::SubjectDataEncryption,
            ),
            None
        );

        let next = KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectDataEncryption, 4);
        assert_eq!(
            registry.register_key(KeyRegistrationV1::new(next, digest(33), None)),
            Ok(KeyRegistrationOutcomeV1::Registered)
        );
        assert_eq!(
            registry
                .active_key(
                    &OwnerIdV1::from_static("test-owner"),
                    KeyRoleV1::SubjectDataEncryption,
                )
                .map(|key| key.identity),
            Some(next)
        );
        Ok(())
    }

    #[test]
    fn destroying_an_inactive_epoch_keeps_the_newer_epoch_active() -> Result<(), KeyRegistryErrorV1>
    {
        let mut registry = KeyRegistryStateV1::new();
        let first = KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1);
        let latest = KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 2);
        registry.register_key(signing_registration(first, 40))?;
        registry.register_key(signing_registration(latest, 41))?;

        destroy(
            &mut registry,
            KeyDestructionRequestV1::new(first, digest(40), digest(42)),
        )?;

        assert_eq!(
            registry
                .active_key(&first.owner_id, first.role)
                .map(|key| key.identity),
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
            KeyIdentityV1::new("test-owner", DATA.role, 2),
            digest(8),
            None,
        ))?;
        assert!(matches!(
            registry.register_key(KeyRegistrationV1::new(DATA, digest(9), None)),
            Err(KeyRegistryErrorV1::StaleEpoch { .. })
        ));
        let identity = KeyIdentityV1::new("test-owner", DATA.role, 2);
        let record_before = registry.key_record(identity);
        let active_before = registry.active_key(&DATA.owner_id, DATA.role);
        assert_eq!(
            destroy(
                &mut registry,
                KeyDestructionRequestV1::new(identity, digest(99), digest(10),)
            ),
            Err(KeyRegistryErrorV1::MaterialDigestMismatch)
        );
        assert_eq!(registry.key_record(identity), record_before);
        assert_eq!(
            registry.active_key(&DATA.owner_id, DATA.role),
            active_before
        );
        Ok(())
    }

    #[test]
    fn registration_validation_and_idempotency_are_closed() {
        let mut registry = KeyRegistryStateV1::new();
        assert_eq!(
            registry.register_key(KeyRegistrationV1::new(
                KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectDataEncryption, 0),
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
            registry.active_key(
                &OwnerIdV1::from_static("test-owner"),
                KeyRoleV1::SubjectDataEncryption,
            ),
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
            registry.begin_key_destruction(KeyDestructionRequestV1::new(
                DATA,
                digest(16),
                digest(17),
            )),
            Err(KeyRegistryErrorV1::NotFound)
        );
        registry.register_key(KeyRegistrationV1::new(DATA, digest(18), None))?;
        destroy(
            &mut registry,
            KeyDestructionRequestV1::new(DATA, digest(18), digest(19)),
        )?;
        assert_eq!(
            registry.register_key(KeyRegistrationV1::new(
                KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectDataEncryption, 2),
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
            KeyRegistryPortV1::active_key(
                &registry,
                &OwnerIdV1::from_static("test-owner"),
                KeyRoleV1::SubjectDataEncryption,
            ),
            Some(KeyRecordV1 {
                identity: DATA,
                private_material_digest: Some(digest(20)),
                public_verification_key: None,
            })
        );
        assert_eq!(KeyRegistryPortV1::tombstone(&registry, DATA), None);
        let request = KeyDestructionRequestV1::new(DATA, digest(20), digest(21));
        let begin = KeyDestructionPortV1::begin_key_destruction(&mut registry, request)?;
        assert_eq!(begin, KeyDestructionBeginOutcomeV1::Started);
        let outcome = KeyDestructionPortV1::complete_key_destruction(
            &mut registry,
            request,
            deletion_receipt(&request),
        )?;
        assert!(matches!(outcome, KeyDestructionOutcomeV1::Destroyed(_)));
        assert_eq!(
            KeyRegistryPortV1::tombstone(&registry, DATA),
            Some(outcome.tombstone())
        );
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod coverage_entrypoints {
    use super::*;

    fn record(identity: KeyIdentityV1, material: u8) -> KeyRecordV1 {
        KeyRecordV1 {
            identity,
            private_material_digest: Some(Hash::from_bytes([material; 32])),
            public_verification_key: Some(PublicKey::from_bytes([material; 32])),
        }
    }

    fn destroyed_record(identity: KeyIdentityV1, material: u8) -> KeyRecordV1 {
        KeyRecordV1 {
            identity,
            private_material_digest: None,
            public_verification_key: Some(PublicKey::from_bytes([material; 32])),
        }
    }

    fn active_state(identity: KeyIdentityV1, material: u8) -> KeyRegistryStateV1 {
        let mut state = KeyRegistryStateV1::new();
        state.records.insert(identity, record(identity, material));
        state
            .active
            .insert((identity.owner_id, identity.role), identity);
        state
            .highest_epoch
            .insert((identity.owner_id, identity.role), identity.epoch);
        state
    }

    #[test]
    fn validation_entrypoints_cover_record_invariants() {
        let signing = KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectAttributionSigning, 1);
        let next_signing =
            KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectAttributionSigning, 2);

        let mut zero_epoch = KeyRegistryStateV1::new();
        let zero = KeyIdentityV1::new("test-owner", signing.role, 0);
        zero_epoch.records.insert(zero, record(zero, 1));
        assert_invalid_state(&zero_epoch);

        let mut missing_public_key = KeyRegistryStateV1::new();
        missing_public_key.records.insert(
            signing,
            KeyRecordV1 {
                identity: signing,
                private_material_digest: Some(Hash::from_bytes([2; 32])),
                public_verification_key: None,
            },
        );
        assert_invalid_state(&missing_public_key);

        let mut missing_highest_epoch = KeyRegistryStateV1::new();
        missing_highest_epoch
            .records
            .insert(signing, record(signing, 3));
        assert_invalid_state(&missing_highest_epoch);

        let mut duplicate_material = active_state(signing, 4);
        duplicate_material
            .records
            .insert(next_signing, record(next_signing, 4));
        duplicate_material
            .active
            .insert((next_signing.owner_id, next_signing.role), next_signing);
        duplicate_material.highest_epoch.insert(
            (next_signing.owner_id, next_signing.role),
            next_signing.epoch,
        );
        assert_invalid_state(&duplicate_material);

        let mut missing_tombstone = KeyRegistryStateV1::new();
        missing_tombstone
            .records
            .insert(signing, destroyed_record(signing, 5));
        assert_invalid_state(&missing_tombstone);

        let mut mismatched_record_identity = active_state(signing, 26);
        mismatched_record_identity
            .records
            .insert(signing, record(next_signing, 26));
        assert_invalid_state(&mismatched_record_identity);

        let encryption = KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectDataEncryption, 1);
        let encryption_with_public_key = active_state(encryption, 27);
        assert_invalid_state(&encryption_with_public_key);
    }

    #[test]
    fn validation_entrypoints_cover_index_invariants() {
        let signing = KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectAttributionSigning, 1);

        let mut orphaned_highest_epoch = KeyRegistryStateV1::new();
        orphaned_highest_epoch
            .highest_epoch
            .insert((signing.owner_id, signing.role), 1);
        assert_invalid_state(&orphaned_highest_epoch);

        let mut mismatched_highest_epoch = active_state(signing, 6);
        mismatched_highest_epoch
            .highest_epoch
            .insert((signing.owner_id, signing.role), 2);
        assert_invalid_state(&mismatched_highest_epoch);

        let mut wrong_active_role = active_state(signing, 7);
        wrong_active_role.active.insert(
            (signing.owner_id, KeyRoleV1::SubjectDataEncryption),
            signing,
        );
        assert_invalid_state(&wrong_active_role);

        let mut active_tombstone = KeyRegistryStateV1::new();
        active_tombstone
            .records
            .insert(signing, destroyed_record(signing, 8));
        active_tombstone.tombstones.insert(
            signing,
            KeyTombstoneV1 {
                identity: signing,
                destroyed_material_digest: Hash::from_bytes([8; 32]),
                destruction_digest: Hash::from_bytes([9; 32]),
                deletion_receipt: Hash::from_bytes([10; 32]),
            },
        );
        active_tombstone
            .active
            .insert((signing.owner_id, signing.role), signing);
        active_tombstone
            .highest_epoch
            .insert((signing.owner_id, signing.role), 1);
        assert_invalid_state(&active_tombstone);

        let mut missing_active_record = KeyRegistryStateV1::new();
        missing_active_record
            .active
            .insert((signing.owner_id, signing.role), signing);
        assert_invalid_state(&missing_active_record);
    }

    #[test]
    fn validation_entrypoints_cover_active_history_invariants() {
        let signing = KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectAttributionSigning, 1);
        let next_signing =
            KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectAttributionSigning, 2);

        let mut inactive_active_record = active_state(signing, 10);
        inactive_active_record
            .records
            .insert(next_signing, record(next_signing, 11));
        inactive_active_record
            .highest_epoch
            .insert((signing.owner_id, next_signing.role), next_signing.epoch);
        assert_invalid_state(&inactive_active_record);

        let mut missing_active_for_highest = active_state(signing, 12);
        missing_active_for_highest.active.clear();
        assert_invalid_state(&missing_active_for_highest);
    }

    #[test]
    fn validation_entrypoints_cover_tombstone_invariants() {
        let signing = KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectAttributionSigning, 1);
        let next_signing =
            KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectAttributionSigning, 2);

        let mut orphaned_tombstone = KeyRegistryStateV1::new();
        orphaned_tombstone.tombstones.insert(
            signing,
            KeyTombstoneV1 {
                identity: signing,
                destroyed_material_digest: Hash::from_bytes([13; 32]),
                destruction_digest: Hash::from_bytes([14; 32]),
                deletion_receipt: Hash::from_bytes([15; 32]),
            },
        );
        assert_invalid_state(&orphaned_tombstone);

        let mut mismatched_tombstone_identity = KeyRegistryStateV1::new();
        mismatched_tombstone_identity
            .records
            .insert(signing, destroyed_record(signing, 15));
        mismatched_tombstone_identity.tombstones.insert(
            signing,
            KeyTombstoneV1 {
                identity: next_signing,
                destroyed_material_digest: Hash::from_bytes([15; 32]),
                destruction_digest: Hash::from_bytes([16; 32]),
                deletion_receipt: Hash::from_bytes([17; 32]),
            },
        );
        mismatched_tombstone_identity
            .highest_epoch
            .insert((signing.owner_id, signing.role), signing.epoch);
        assert_invalid_state(&mismatched_tombstone_identity);

        let mut live_record_with_tombstone = active_state(signing, 17);
        live_record_with_tombstone.tombstones.insert(
            signing,
            KeyTombstoneV1 {
                identity: signing,
                destroyed_material_digest: Hash::from_bytes([17; 32]),
                destruction_digest: Hash::from_bytes([18; 32]),
                deletion_receipt: Hash::from_bytes([19; 32]),
            },
        );
        live_record_with_tombstone.active.clear();
        assert_invalid_state(&live_record_with_tombstone);

        let mut duplicate_tombstone_material = KeyRegistryStateV1::new();
        duplicate_tombstone_material
            .records
            .insert(signing, destroyed_record(signing, 19));
        duplicate_tombstone_material
            .records
            .insert(next_signing, record(next_signing, 19));
        duplicate_tombstone_material.tombstones.insert(
            signing,
            KeyTombstoneV1 {
                identity: signing,
                destroyed_material_digest: Hash::from_bytes([19; 32]),
                destruction_digest: Hash::from_bytes([20; 32]),
                deletion_receipt: Hash::from_bytes([21; 32]),
            },
        );
        duplicate_tombstone_material
            .active
            .insert((next_signing.owner_id, next_signing.role), next_signing);
        duplicate_tombstone_material.highest_epoch.insert(
            (next_signing.owner_id, next_signing.role),
            next_signing.epoch,
        );
        assert_invalid_state(&duplicate_tombstone_material);
    }

    fn assert_invalid_state(state: &KeyRegistryStateV1) {
        assert_eq!(state.validate(), Err(KeyRegistryErrorV1::InvalidState));
    }

    #[test]
    fn replacement_entrypoints_cover_snapshot_and_history_guards() {
        let signing = KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectAttributionSigning, 1);
        let next_signing =
            KeyIdentityV1::new("test-owner", KeyRoleV1::SubjectAttributionSigning, 2);
        let valid = active_state(signing, 21);

        let mut invalid_previous = KeyRegistryStateV1::new();
        invalid_previous
            .records
            .insert(signing, destroyed_record(signing, 22));
        assert_eq!(
            invalid_previous.validate_replacement(&valid),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut invalid_next = valid.clone();
        invalid_next.active.clear();
        assert_eq!(
            valid.validate_replacement(&invalid_next),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let previous_latest = active_state(next_signing, 23);
        let mut stale_next = previous_latest.clone();
        stale_next.records.insert(signing, record(signing, 24));
        assert_eq!(
            previous_latest.validate_replacement(&stale_next),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut wrong_tombstone = valid.clone();
        wrong_tombstone
            .records
            .insert(signing, destroyed_record(signing, 25));
        wrong_tombstone.tombstones.insert(
            signing,
            KeyTombstoneV1 {
                identity: signing,
                destroyed_material_digest: Hash::from_bytes([25; 32]),
                destruction_digest: Hash::from_bytes([26; 32]),
                deletion_receipt: Hash::from_bytes([27; 32]),
            },
        );
        wrong_tombstone.active.clear();
        assert_eq!(
            valid.validate_replacement(&wrong_tombstone),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        replacement_entrypoints_cover_material_and_history_guards(&valid, signing, next_signing);
    }

    fn replacement_entrypoints_cover_material_and_history_guards(
        valid: &KeyRegistryStateV1,
        signing: KeyIdentityV1,
        next_signing: KeyIdentityV1,
    ) {
        let mut changed_public_key = valid.clone();
        changed_public_key.records.insert(
            signing,
            KeyRecordV1 {
                identity: signing,
                private_material_digest: Some(Hash::from_bytes([21; 32])),
                public_verification_key: Some(PublicKey::from_bytes([28; 32])),
            },
        );
        assert_eq!(
            valid.validate_replacement(&changed_public_key),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut changed_material = valid.clone();
        changed_material.records.insert(
            signing,
            KeyRecordV1 {
                identity: signing,
                private_material_digest: Some(Hash::from_bytes([29; 32])),
                public_verification_key: Some(PublicKey::from_bytes([21; 32])),
            },
        );
        assert_eq!(
            valid.validate_replacement(&changed_material),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let previous_destroyed = destroyed_state(signing, 30, 31);
        let restored = active_state(signing, 32);
        assert_eq!(
            previous_destroyed.validate_replacement(&restored),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut changed_tombstone = previous_destroyed.clone();
        if let Some(tombstone) = changed_tombstone.tombstones.get_mut(&signing) {
            tombstone.destruction_digest = Hash::from_bytes([33; 32]);
        }
        assert_eq!(
            previous_destroyed.validate_replacement(&changed_tombstone),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut new_tombstoned_identity = valid.clone();
        new_tombstoned_identity
            .records
            .insert(next_signing, destroyed_record(next_signing, 34));
        new_tombstoned_identity.tombstones.insert(
            next_signing,
            KeyTombstoneV1 {
                identity: next_signing,
                destroyed_material_digest: Hash::from_bytes([34; 32]),
                destruction_digest: Hash::from_bytes([35; 32]),
                deletion_receipt: Hash::from_bytes([36; 32]),
            },
        );
        new_tombstoned_identity.active.clear();
        new_tombstoned_identity
            .highest_epoch
            .insert((signing.owner_id, next_signing.role), next_signing.epoch);
        assert_eq!(
            valid.validate_replacement(&new_tombstoned_identity),
            Err(KeyRegistryErrorV1::InvalidState)
        );
    }

    fn destroyed_state(
        identity: KeyIdentityV1,
        material: u8,
        destruction: u8,
    ) -> KeyRegistryStateV1 {
        let mut state = KeyRegistryStateV1::new();
        state
            .records
            .insert(identity, destroyed_record(identity, material));
        state.tombstones.insert(
            identity,
            KeyTombstoneV1 {
                identity,
                destroyed_material_digest: Hash::from_bytes([material; 32]),
                destruction_digest: Hash::from_bytes([destruction; 32]),
                deletion_receipt: Hash::from_bytes([destruction.wrapping_add(1); 32]),
            },
        );
        state
            .highest_epoch
            .insert((identity.owner_id, identity.role), identity.epoch);
        state
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod key_registry_coverage {
    use super::*;

    fn digest(value: u8) -> Hash {
        Hash::from_bytes([value; 32])
    }

    #[test]
    fn owner_deserialization_rejects_non_text_and_invalid_text() {
        assert!(serde_json::from_str::<OwnerIdV1>("null").is_err());
        assert!(serde_json::from_str::<OwnerIdV1>("\"\"").is_err());
    }

    #[test]
    fn replacement_accepts_only_the_exact_pending_to_tombstone_transition(
    ) -> Result<(), KeyRegistryErrorV1> {
        let identity = KeyIdentityV1::new(
            OwnerIdV1::from_static("coverage-owner"),
            KeyRoleV1::SubjectAttributionSigning,
            1,
        );
        let registration =
            KeyRegistrationV1::new(identity, digest(1), Some(PublicKey::from_bytes([2; 32])));
        let mut pending = KeyRegistryStateV1::new();
        pending.register_key(registration)?;
        let request = KeyDestructionRequestV1::new(identity, digest(1), digest(3));
        assert_eq!(
            pending.begin_key_destruction(request)?,
            KeyDestructionBeginOutcomeV1::Started
        );
        assert_eq!(pending.validate_replacement(&pending), Ok(()));

        let mut finalized = pending.clone();
        finalized.pending_destructions.remove(&identity);
        finalized
            .records
            .get_mut(&identity)
            .ok_or(KeyRegistryErrorV1::NotFound)?
            .private_material_digest = None;
        finalized.tombstones.insert(
            identity,
            KeyTombstoneV1 {
                identity,
                destroyed_material_digest: request.expected_material_digest,
                destruction_digest: destruction_digest(&request),
                deletion_receipt: deletion_receipt(&request),
            },
        );
        assert_eq!(pending.validate_replacement(&finalized), Ok(()));

        let mut wrong_material = finalized.clone();
        wrong_material
            .tombstones
            .get_mut(&identity)
            .ok_or(KeyRegistryErrorV1::NotFound)?
            .destroyed_material_digest = digest(4);
        assert_eq!(
            pending.validate_replacement(&wrong_material),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut wrong_destruction = finalized.clone();
        wrong_destruction
            .tombstones
            .get_mut(&identity)
            .ok_or(KeyRegistryErrorV1::NotFound)?
            .destruction_digest = digest(5);
        assert_eq!(
            pending.validate_replacement(&wrong_destruction),
            Err(KeyRegistryErrorV1::InvalidState)
        );

        let mut wrong_receipt = finalized;
        wrong_receipt
            .tombstones
            .get_mut(&identity)
            .ok_or(KeyRegistryErrorV1::NotFound)?
            .deletion_receipt = digest(6);
        assert_eq!(
            pending.validate_replacement(&wrong_receipt),
            Err(KeyRegistryErrorV1::InvalidState)
        );
        Ok(())
    }
}
