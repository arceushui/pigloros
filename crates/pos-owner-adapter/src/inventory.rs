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
//!
//! The pass covers the whole directory while only the calling owner's lock is
//! held, so another owner's in-flight `.tmp` file would refuse it spuriously.
//! ADR-110 §1a keeps one owner thread, and the adapters rely on that: it is
//! load-bearing, not incidental.

use pos_crypto::subject_key::SubjectKeyWrapV1;
use pos_owner_bridge::encryptor_lock::linux::{
    SubjectEncryptorLock, SubjectKeyArtifactContent, SubjectKeyArtifactEntry,
    SubjectKeyArtifactName,
};
use pos_owner_bridge::{OwnerError, OwnerErrorKind};
use pos_owner_bridge_codec::{
    decode_subject_credential_binding, CoseEs256PublicKey, OwnerUserHandle,
    SubjectCredentialBindingInputV1, SubjectCredentialBindingV1, SubjectId, TransportCodes,
};

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
    /// The raw directory entry name.
    pub(crate) name: Vec<u8>,
    /// What the contents parsed as, whatever the file's name.
    pub(crate) parsed: Parsed,
}

/// The parsed contents of one artifact.
pub(crate) enum Parsed {
    /// A `SubjectKeyWrapV1`.
    Wrap(SubjectKeyWrapV1),
    /// A `SubjectCredentialBindingV1`, with its fields owned.
    Binding(StoredBinding),
}

impl Parsed {
    /// The wrap, when these contents are one.
    pub(crate) const fn wrap(&self) -> Option<&SubjectKeyWrapV1> {
        match self {
            Self::Wrap(wrap) => Some(wrap),
            Self::Binding(_) => None,
        }
    }

    /// The binding, when these contents are one.
    pub(crate) const fn binding(&self) -> Option<&StoredBinding> {
        match self {
            Self::Wrap(_) => None,
            Self::Binding(binding) => Some(binding),
        }
    }

    fn credential_id(&self) -> &[u8] {
        match self {
            Self::Wrap(wrap) => &wrap.params().credential_id,
            Self::Binding(binding) => &binding.credential_id,
        }
    }
}

/// The fields of one decoded `SubjectCredentialBindingV1`, owned.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct StoredBinding {
    pub(crate) owner_id: String,
    pub(crate) subject_id: SubjectId,
    pub(crate) epoch: u64,
    pub(crate) credential_id: Vec<u8>,
    pub(crate) user_handle: OwnerUserHandle,
    pub(crate) public_key: CoseEs256PublicKey,
    pub(crate) backup_eligible: bool,
    pub(crate) backup_state: bool,
    pub(crate) sign_count: u32,
    pub(crate) transports: TransportCodes,
}

impl StoredBinding {
    /// Own the fields of a validated binding.
    pub(crate) fn new(binding: SubjectCredentialBindingV1<'_>) -> Self {
        Self {
            owner_id: binding.owner_id().to_owned(),
            subject_id: binding.subject_id(),
            epoch: binding.epoch(),
            credential_id: binding.credential_id().to_vec(),
            user_handle: binding.user_handle(),
            public_key: binding.public_key(),
            backup_eligible: binding.backup_eligible(),
            backup_state: binding.backup_state(),
            sign_count: binding.sign_count(),
            transports: binding.transports(),
        }
    }

    /// The codec input that rebuilds this binding.
    pub(crate) fn input(&self) -> SubjectCredentialBindingInputV1<'_> {
        SubjectCredentialBindingInputV1 {
            owner_id: &self.owner_id,
            subject_id: self.subject_id,
            epoch: self.epoch,
            credential_id: &self.credential_id,
            user_handle: self.user_handle,
            public_key: self.public_key,
            backup_eligible: self.backup_eligible,
            backup_state: self.backup_state,
            sign_count: self.sign_count,
            transports: self.transports,
        }
    }
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
                .map(|artifact| artifact.parsed.credential_id())
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
        SubjectKeyArtifactContent::Regular { bytes, .. } => match (parse(name, &bytes), reserved) {
            (None, Some(_)) => Err(REGISTRY),
            (parsed, reserved) => Ok(parsed.into_iter().chain(reserved).collect()),
        },
        SubjectKeyArtifactContent::NonRegular => Err(REGISTRY),
    }
}

fn parse(name: Vec<u8>, bytes: &[u8]) -> Option<Named> {
    let parsed = SubjectKeyWrapV1::from_bytes(bytes)
        .ok()
        .map(|wrap| (wrap.owner_id(), wrap.params().epoch, Parsed::Wrap(wrap)))
        .or_else(|| {
            decode_subject_credential_binding(bytes)
                .ok()
                .map(StoredBinding::new)
                .map(|binding| {
                    (
                        binding.owner_id.clone(),
                        binding.epoch,
                        Parsed::Binding(binding),
                    )
                })
        });
    parsed.map(|(owner_id, epoch, parsed)| Named {
        owner_id,
        epoch,
        artifact: Some(Artifact { name, parsed }),
    })
}
