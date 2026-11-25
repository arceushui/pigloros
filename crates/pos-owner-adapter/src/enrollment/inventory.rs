#![cfg(any(test, feature = "test-support"))]
//! The bounded `subject-keys.v1` inventory pass that enrollment reads.
//!
//! It lists the P4 directory with the ADR-137 D2 bounds (4,096 entries, the
//! first 4,097 bytes of each regular file) and parses every regular file with
//! the `SubjectKeyWrapV1` and `SubjectCredentialBindingV1` codecs, whatever its
//! name. It classifies entries exactly as the D2 destruction inventory does:
//! an entry that is not a regular file, or a reserved-name file that parses as
//! neither codec, is unrecognized and refuses the whole pass; a file with
//! another name that parses as neither codec belongs to no subject key and is
//! ignored.

use pos_crypto::subject_key::SubjectKeyWrapV1;
use pos_owner_bridge::encryptor_lock::linux::{
    SubjectEncryptorLock, SubjectKeyArtifactContent, SubjectKeyArtifactEntry,
    SubjectKeyArtifactName,
};
use pos_owner_bridge::{OwnerError, OwnerErrorKind};
use pos_owner_bridge_codec::decode_subject_credential_binding;

const REGISTRY: OwnerError = OwnerError::new(OwnerErrorKind::Registry);

/// One `(owner, epoch)` that an artifact's name or contents names.
struct Named {
    owner_id: String,
    epoch: u64,
    /// The credential ID of a parsed wrap or binding; a name carries none.
    credential_id: Option<Vec<u8>>,
}

/// Every `(owner, epoch)` and credential ID the P4 directory names.
pub(super) struct Inventory {
    named: Vec<Named>,
}

impl Inventory {
    /// Run one bounded pass over `subject-keys.v1`.
    ///
    /// # Errors
    /// Returns `Registry` when the directory cannot be admitted or read within
    /// the D2 bounds, or when any entry is unrecognized.
    pub(super) fn read(lock: &SubjectEncryptorLock) -> Result<Self, OwnerError> {
        lock.list_and_read_subject_key_artifacts()
            .or(Err(REGISTRY))
            .and_then(|entries| entries.into_iter().map(classify).collect())
            .map(|named: Vec<Vec<Named>>| Self {
                named: named.into_iter().flatten().collect(),
            })
    }

    /// `false` when any parsed wrap or binding, of any owner or epoch, holds
    /// `credential_id`.
    ///
    /// ADR-110 §8 E1 names bindings only. A wrap names its credential too, so
    /// an unregistered staged wrap of the same credential also counts as
    /// holding it (the fail-closed reading).
    pub(super) fn credential_unbound(&self, credential_id: &[u8]) -> bool {
        self.named
            .iter()
            .all(|named| named.credential_id.as_deref() != Some(credential_id))
    }

    /// The highest epoch any artifact names for `owner_id`, or zero.
    ///
    /// ADR-137 P3 step 2 counts both a reserved name (canonical or `.tmp`) and
    /// the parsed contents of a file of any name.
    pub(super) fn epoch_ceiling(&self, owner_id: &str) -> u64 {
        self.named
            .iter()
            .filter(|named| named.owner_id == owner_id)
            .map(|named| named.epoch)
            .max()
            .unwrap_or_default()
    }
}

fn classify(entry: SubjectKeyArtifactEntry) -> Result<Vec<Named>, OwnerError> {
    let reserved = SubjectKeyArtifactName::parse(&entry.name).map(|(name, _)| Named {
        owner_id: name.owner_id(),
        epoch: name.epoch(),
        credential_id: None,
    });
    match entry.content {
        SubjectKeyArtifactContent::Regular { bytes, .. } => match (parse(&bytes), reserved) {
            (None, Some(_)) => Err(REGISTRY),
            (parsed, reserved) => Ok(parsed.into_iter().chain(reserved).collect()),
        },
        SubjectKeyArtifactContent::NonRegular => Err(REGISTRY),
    }
}

fn parse(bytes: &[u8]) -> Option<Named> {
    SubjectKeyWrapV1::from_bytes(bytes)
        .ok()
        .map(|wrap| Named {
            owner_id: wrap.owner_id(),
            epoch: wrap.params().epoch,
            credential_id: Some(wrap.params().credential_id.clone()),
        })
        .or_else(|| {
            decode_subject_credential_binding(bytes)
                .ok()
                .map(|binding| Named {
                    owner_id: binding.owner_id().to_owned(),
                    epoch: binding.epoch(),
                    credential_id: Some(binding.credential_id().to_vec()),
                })
        })
}
