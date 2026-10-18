//! Provider startup check of the kernel's built-in trusted keyring.
//!
//! The release certificate that signs SIM1 root hashes is compiled into the
//! appliance kernel's `.builtin_trusted_keys`. Before admission the provider
//! requires that keyring to hold exactly one asymmetric key with each TRS1
//! certificate's kernel key description. A listing is the exact
//! `KEYCTL_DESCRIBE` text of every keyring member; reading it from the kernel
//! is the separate keyctl reader's job, so this check has no kernel bypass.

use super::SandboxTrustSnapshot;

const ASYMMETRIC_KEY_TYPE: &str = "asymmetric";

/// Bounded failures of the built-in keyring check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BuiltinKeyringError {
    /// A member is not exact `type;uid;gid;perm;description` text.
    #[error("malformed built-in keyring member description")]
    Malformed,
    /// No asymmetric member carries a TRS1 certificate's key description.
    #[error("built-in keyring lacks a TRS1 release key")]
    Missing,
    /// More than one asymmetric member carries the same TRS1 key description.
    #[error("built-in keyring holds a TRS1 release key more than once")]
    Duplicate,
}

/// Type and description of every `.builtin_trusted_keys` member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltinKeyringListing {
    members: Vec<(String, String)>,
}

impl BuiltinKeyringListing {
    /// Parse each member's exact `KEYCTL_DESCRIBE` result.
    ///
    /// The kernel formats it as `type;uid;gid;perm;description`, where `perm`
    /// is eight lowercase hexadecimal digits and the description may itself
    /// contain `;`.
    ///
    /// # Errors
    /// Rejects any member that does not have that exact shape.
    pub fn from_describe_records<'a>(
        records: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, BuiltinKeyringError> {
        records
            .into_iter()
            .map(parse_record)
            .collect::<Result<Vec<_>, _>>()
            .map(|members| Self { members })
    }

    fn asymmetric_count(&self, description: &str) -> usize {
        self.members
            .iter()
            .filter(|(key_type, member)| key_type == ASYMMETRIC_KEY_TYPE && member == description)
            .count()
    }
}

fn parse_record(record: &str) -> Result<(String, String), BuiltinKeyringError> {
    let fields = record.splitn(5, ';').collect::<Vec<_>>();
    let [key_type, uid, gid, permissions, description] = fields.as_slice() else {
        return Err(BuiltinKeyringError::Malformed);
    };
    if key_type.is_empty()
        || description.is_empty()
        || uid.parse::<i64>().is_err()
        || gid.parse::<i64>().is_err()
        || permissions.len() != 8
        || !permissions
            .bytes()
            .all(|digit| matches!(digit, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(BuiltinKeyringError::Malformed);
    }
    Ok(((*key_type).to_owned(), (*description).to_owned()))
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
/// Returns [`BuiltinKeyringError::Missing`] or
/// [`BuiltinKeyringError::Duplicate`] for the first TRS1 certificate whose
/// key description is not present exactly once.
pub fn verify_builtin_release_keys(
    trust: &SandboxTrustSnapshot,
    listing: &BuiltinKeyringListing,
) -> Result<BuiltinReleaseKeys, BuiltinKeyringError> {
    trust
        .certificates()
        .iter()
        .map(
            |certificate| match listing.asymmetric_count(&certificate.key_description) {
                0 => Err(BuiltinKeyringError::Missing),
                1 => Ok(()),
                _ => Err(BuiltinKeyringError::Duplicate),
            },
        )
        .collect::<Result<(), _>>()
        .map(|()| BuiltinReleaseKeys {
            trust_digest: trust.snapshot_digest(),
        })
}
