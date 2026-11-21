#![cfg(any(test, feature = "test-support"))]
//! The bounded `subject-keys.v1` inventory pass that enrollment and unlock
//! read.
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
    SubjectKeyArtifactKind, SubjectKeyArtifactName,
};
use pos_owner_bridge::{OwnerError, OwnerErrorKind};
use pos_owner_bridge_codec::decode_subject_credential_binding;

const REGISTRY: OwnerError = OwnerError::new(OwnerErrorKind::Registry);

/// One `(owner, epoch)` that an artifact's name or contents names.
struct Named {
    owner_id: String,
    epoch: u64,
    /// The parsed file; a reserved name alone carries none.
    artifact: Option<Artifact>,
}

/// One regular file whose contents parsed as a wrap or a binding.
pub(crate) struct Artifact {
    /// Which codec parsed the contents, whatever the file's name.
    pub(crate) kind: SubjectKeyArtifactKind,
    /// The raw directory entry name.
    pub(crate) name: Vec<u8>,
    /// The credential ID that the wrap or binding names.
    pub(crate) credential_id: Vec<u8>,
    /// The exact bytes read.
    pub(crate) bytes: Vec<u8>,
}

/// Every `(owner, epoch)` and parsed artifact the P4 directory names.
pub(crate) struct Inventory {
    named: Vec<Named>,
}

impl Inventory {
    /// Run one bounded pass over `subject-keys.v1`.
    ///
    /// # Errors
    /// Returns `Registry` when the directory cannot be admitted or read within
    /// the D2 bounds, or when any entry is unrecognized.
    pub(crate) fn read(lock: &SubjectEncryptorLock) -> Result<Self, OwnerError> {
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
    pub(crate) fn credential_unbound(&self, credential_id: &[u8]) -> bool {
        self.named.iter().all(|named| {
            named
                .artifact
                .as_ref()
                .map(|artifact| artifact.credential_id.as_slice())
                != Some(credential_id)
        })
    }

    /// The highest epoch any artifact names for `owner_id`, or zero.
    ///
    /// ADR-137 P3 step 2 counts both a reserved name (canonical or `.tmp`) and
    /// the parsed contents of a file of any name.
    pub(crate) fn epoch_ceiling(&self, owner_id: &str) -> u64 {
        self.named
            .iter()
            .filter(|named| named.owner_id == owner_id)
            .map(|named| named.epoch)
            .max()
            .unwrap_or_default()
    }

    /// Every file, of any name, whose parsed contents name `(owner_id, epoch)`.
    pub(crate) fn artifacts<'a>(
        &'a self,
        owner_id: &'a str,
        epoch: u64,
    ) -> impl Iterator<Item = &'a Artifact> + 'a {
        self.named
            .iter()
            .filter(move |named| named.owner_id == owner_id && named.epoch == epoch)
            .filter_map(|named| named.artifact.as_ref())
    }
}

fn classify(entry: SubjectKeyArtifactEntry) -> Result<Vec<Named>, OwnerError> {
    let SubjectKeyArtifactEntry { name, content } = entry;
    let reserved = SubjectKeyArtifactName::parse(&name).map(|(reserved, _)| Named {
        owner_id: reserved.owner_id(),
        epoch: reserved.epoch(),
        artifact: None,
    });
    match content {
        SubjectKeyArtifactContent::Regular { bytes, .. } => match (parse(name, bytes), reserved) {
            (None, Some(_)) => Err(REGISTRY),
            (parsed, reserved) => Ok(parsed.into_iter().chain(reserved).collect()),
        },
        SubjectKeyArtifactContent::NonRegular => Err(REGISTRY),
    }
}

fn parse(name: Vec<u8>, bytes: Vec<u8>) -> Option<Named> {
    let parsed = SubjectKeyWrapV1::from_bytes(&bytes)
        .ok()
        .map(|wrap| {
            (
                wrap.owner_id(),
                wrap.params().epoch,
                SubjectKeyArtifactKind::Wrap,
                wrap.params().credential_id.clone(),
            )
        })
        .or_else(|| {
            decode_subject_credential_binding(&bytes)
                .ok()
                .map(|binding| {
                    (
                        binding.owner_id().to_owned(),
                        binding.epoch(),
                        SubjectKeyArtifactKind::Binding,
                        binding.credential_id().to_vec(),
                    )
                })
        });
    parsed.map(|(owner_id, epoch, kind, credential_id)| Named {
        owner_id,
        epoch,
        artifact: Some(Artifact {
            kind,
            name,
            credential_id,
            bytes,
        }),
    })
}
