//! Per-admission check of the kernel's built-in trusted keyring.
//!
//! The release certificate that signs SIM1 root hashes is compiled into the
//! appliance kernel's `.builtin_trusted_keys`. At every provider admission
//! the keyring must hold exactly one key with the kernel key description of
//! the TRS1 certificate that matched the image's SIM1, and that key must be
//! asymmetric.
//!
//! A listing is one member per key serial that `KEYCTL_READ` returns for the
//! keyring, carrying the full raw `KEYCTL_DESCRIBE` result for that serial:
//! `type;uid;gid;perm;description`. The type is the text before the first `;`
//! and the description is everything after the fourth `;`, so a certificate
//! subject containing `;` is preserved. Only the provider's keyctl reader may
//! supply a listing that admission trusts; this module checks it and has no
//! kernel bypass of its own.

use super::AdmittedSandboxImage;

const ASYMMETRIC_KEY_TYPE: &str = "asymmetric";

/// Bounded failures of the built-in keyring check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BuiltinKeyringError {
    /// A member has a non-positive or repeated serial, or a raw describe
    /// result without four `;` separators, a type or a description.
    #[error("malformed built-in keyring member")]
    Malformed,
    /// No member carries the image's release key description.
    #[error("built-in keyring lacks the image release key")]
    Missing,
    /// The only member carrying the description is not asymmetric.
    #[error("built-in keyring release key has the wrong key type")]
    WrongType,
    /// More than one member carries the description.
    #[error("built-in keyring holds the image release key more than once")]
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
    /// Collect `(serial, raw KEYCTL_DESCRIBE result)` for every keyring member.
    ///
    /// # Errors
    /// Rejects a non-positive or repeated serial, or a describe result without
    /// a type, four `;` separators and a description.
    pub fn from_members<S: AsRef<str>>(
        members: impl IntoIterator<Item = (i32, S)>,
    ) -> Result<Self, BuiltinKeyringError> {
        let mut listing = Self {
            members: Vec::new(),
        };
        for (serial, describe) in members {
            let (key_type, description) =
                parse_describe(describe.as_ref()).ok_or(BuiltinKeyringError::Malformed)?;
            if serial <= 0 || listing.members.iter().any(|member| member.serial == serial) {
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

    fn require_release_key(&self, description: &str) -> Result<(), BuiltinKeyringError> {
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

    /// Require this admitted image's release key in the built-in keyring.
    ///
    /// Admission already matched the image's SIM1 signer fingerprint, epoch
    /// and kernel key description to one authenticated TRS1 certificate.
    /// Exactly one keyring member, of any type, must carry that description,
    /// and it must be asymmetric. Other TRS1 certificates are not consulted.
    ///
    /// # Errors
    /// Returns [`BuiltinKeyringError::Missing`],
    /// [`BuiltinKeyringError::WrongType`] or
    /// [`BuiltinKeyringError::Duplicate`] when that is not the case.
    pub fn verify_release_key(
        &self,
        image: &AdmittedSandboxImage,
    ) -> Result<(), BuiltinKeyringError> {
        self.require_release_key(&image.manifest().kernel_key_description)
    }
}

/// Split `type;uid;gid;perm;description` at its first and fourth `;`.
fn parse_describe(describe: &str) -> Option<(&str, &str)> {
    describe.split_once(';').and_then(|(key_type, rest)| {
        rest.splitn(4, ';')
            .nth(3)
            .filter(|description| !key_type.is_empty() && !description.is_empty())
            .map(|description| (key_type, description))
    })
}
