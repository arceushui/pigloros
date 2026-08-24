//! Role-separated key-registry and irreversible-destruction contracts.
//!
//! The core boundary deliberately carries no private key bytes.  A registry
//! records a role/epoch identity, a fingerprint of the private material, and
//! (for signing roles) the public verification key.  Destruction clears the
//! private-material fingerprint from the live record and leaves an immutable
//! tombstone so that the identity cannot be restored or reused.

use std::collections::BTreeMap;

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

/// Compatibility policy for signatures emitted by the pre-#183 subject-data
/// key path described by ADR-041.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacySubjectDataSignatureDispositionV1 {
    /// Existing signatures may be verified with their recorded public key,
    /// but cannot be reissued, migrated, or used to upgrade a replay claim.
    VerifyOnlyNoReplayUpgrade,
}

impl LegacySubjectDataSignatureDispositionV1 {
    /// Return the fixed compatibility disposition.
    #[must_use]
    pub const fn current() -> Self {
        Self::VerifyOnlyNoReplayUpgrade
    }
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
    /// The requested epoch is behind the active role epoch.
    #[error("stale key epoch for {role:?}: requested {requested}, active {active}")]
    StaleEpoch {
        /// Role being rotated.
        role: KeyRoleV1,
        /// Requested epoch.
        requested: u64,
        /// Current active epoch.
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
    /// The identity is permanently tombstoned.
    #[error("key identity has been irreversibly destroyed")]
    Destroyed,
    /// No live record exists for the identity.
    #[error("key identity is not registered")]
    NotFound,
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
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KeyRegistryStateV1 {
    records: BTreeMap<KeyIdentityV1, KeyRecordV1>,
    active: BTreeMap<KeyRoleV1, KeyIdentityV1>,
    tombstones: BTreeMap<KeyIdentityV1, KeyTombstoneV1>,
}

impl KeyRegistryStateV1 {
    /// Construct an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: BTreeMap::new(),
            active: BTreeMap::new(),
            tombstones: BTreeMap::new(),
        }
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
        validate_registration(registration)?;
        let identity = registration.identity;
        if self.tombstones.contains_key(&identity) {
            return Err(KeyRegistryErrorV1::Destroyed);
        }
        if let Some(active) = self.active.get(&identity.role) {
            if active.epoch > identity.epoch {
                return Err(KeyRegistryErrorV1::StaleEpoch {
                    role: identity.role,
                    requested: identity.epoch,
                    active: active.epoch,
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
        assert_eq!(
            registry.destroy_key(KeyDestructionRequestV1::new(
                KeyIdentityV1::new(DATA.role, 2),
                digest(99),
                digest(10),
            )),
            Err(KeyRegistryErrorV1::MaterialDigestMismatch)
        );
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
