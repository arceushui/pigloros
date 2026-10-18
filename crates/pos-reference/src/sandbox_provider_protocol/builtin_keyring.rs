//! Provider startup check of the kernel's built-in trusted keyring.
//!
//! The release certificate that signs SIM1 root hashes is compiled into the
//! appliance kernel's `.builtin_trusted_keys`. Before admission the provider
//! requires that keyring to hold exactly one key with each TRS1 certificate's
//! kernel key description, and that key must be asymmetric.
//!
//! A listing is one `(serial, type, description)` member per key serial that
//! `KEYCTL_READ` returns for the keyring, with type and description from
//! `KEYCTL_DESCRIBE` of that serial. Only the provider's keyctl reader may
//! supply a listing that admission trusts; this module checks it and has no
//! kernel bypass of its own.

use super::SandboxTrustSnapshot;

const ASYMMETRIC_KEY_TYPE: &str = "asymmetric";

/// Bounded failures of the built-in keyring check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BuiltinKeyringError {
    /// A member has a non-positive or repeated serial, or an empty type or
    /// description.
    #[error("malformed built-in keyring member")]
    Malformed,
    /// No member carries a TRS1 certificate's key description.
    #[error("built-in keyring lacks a TRS1 release key")]
    Missing,
    /// The only member carrying a TRS1 key description is not asymmetric.
    #[error("built-in keyring release key has the wrong key type")]
    WrongType,
    /// More than one member carries the same TRS1 key description.
    #[error("built-in keyring holds a TRS1 release key more than once")]
    Duplicate,
}

/// One `.builtin_trusted_keys` member.
#[derive(Clone, Debug, Eq, PartialEq)]
struct BuiltinKeyringMember {
    serial: i32,
    key_type: String,
    description: String,
}

/// Every `.builtin_trusted_keys` member, by serial, type and description.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltinKeyringListing {
    members: Vec<BuiltinKeyringMember>,
}

impl BuiltinKeyringListing {
    /// Collect `(serial, type, description)` for every keyring member.
    ///
    /// # Errors
    /// Rejects a non-positive or repeated serial, or an empty type or
    /// description.
    pub fn from_members<'a>(
        members: impl IntoIterator<Item = (i32, &'a str, &'a str)>,
    ) -> Result<Self, BuiltinKeyringError> {
        let mut listing = Self {
            members: Vec::new(),
        };
        for (serial, key_type, description) in members {
            if serial <= 0
                || key_type.is_empty()
                || description.is_empty()
                || listing.members.iter().any(|member| member.serial == serial)
            {
                return Err(BuiltinKeyringError::Malformed);
            }
            listing.members.push(BuiltinKeyringMember {
                serial,
                key_type: key_type.to_owned(),
                description: description.to_owned(),
            });
        }
        Ok(listing)
    }

    fn release_key(&self, description: &str) -> Result<(), BuiltinKeyringError> {
        let mut matching = self
            .members
            .iter()
            .filter(|member| member.description == description);
        match (matching.next(), matching.next()) {
            (None, _) => Err(BuiltinKeyringError::Missing),
            (Some(_), Some(_)) => Err(BuiltinKeyringError::Duplicate),
            (Some(member), None) if member.key_type != ASYMMETRIC_KEY_TYPE => {
                Err(BuiltinKeyringError::WrongType)
            }
            (Some(_), None) => Ok(()),
        }
    }
}

/// TRS1 release keys proven present exactly once in the built-in keyring.
///
/// Only [`verify_builtin_release_keys`] constructs this value, and it binds the
/// exact TRS1 snapshot it checked. Provider admission requires it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltinReleaseKeys {
    trust_digest: [u8; 32],
}

impl BuiltinReleaseKeys {
    /// Whether this check covered exactly this authenticated TRS1 snapshot.
    #[must_use]
    pub fn covers(&self, trust: &SandboxTrustSnapshot) -> bool {
        self.trust_digest == trust.snapshot_digest()
    }
}

/// Require exactly one asymmetric built-in key for every TRS1 certificate.
///
/// # Errors
/// Returns [`BuiltinKeyringError::Missing`], [`BuiltinKeyringError::WrongType`]
/// or [`BuiltinKeyringError::Duplicate`] for the first TRS1 certificate whose
/// key description is not held by exactly one asymmetric key.
pub fn verify_builtin_release_keys(
    trust: &SandboxTrustSnapshot,
    listing: &BuiltinKeyringListing,
) -> Result<BuiltinReleaseKeys, BuiltinKeyringError> {
    trust
        .certificates()
        .iter()
        .try_for_each(|certificate| listing.release_key(&certificate.key_description))
        .map(|()| BuiltinReleaseKeys {
            trust_digest: trust.snapshot_digest(),
        })
}
