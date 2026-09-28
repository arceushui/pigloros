//! ADR-101 MRM1 structural root bytes for one selected World run.
//!
//! This record does not authenticate a cut, roster, adapter transcript, owner
//! operation, or guarded `ReproManifest` release.

use crate::{encode_head, Hash, WorldReplayHandleV1};

/// Maximum canonical size of one MRM1 root.
pub const MAX_REPRO_MANIFEST_ROOT_BYTES_V1: usize = 1_024;
/// Maximum UTF-8 byte length of an MRM1 display label.
pub const MAX_REPRO_MANIFEST_LABEL_BYTES_V1: usize = 256;

/// Structural MRM1 failures; none grant owner or use authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReproManifestRootErrorV1 {
    /// Wrong CBOR shape, field type, magic, version, or truncated input.
    #[error("invalid MRM1 encoding")]
    InvalidEncoding,
    /// Nonpreferred CBOR width or trailing bytes.
    #[error("noncanonical MRM1 encoding")]
    NonCanonical,
    /// Whole record or label exceeds its accepted byte bound.
    #[error("MRM1 field exceeds its byte bound")]
    FieldOutOfBounds,
    /// A required digest is zero or the handle names another owner.
    #[error("invalid MRM1 identity")]
    InvalidIdentity,
}

/// Untrusted exact MRM1 fields, subject to installed owner verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReproManifestRootInputV1 {
    pub owner_reference: Hash,
    pub world_handle: WorldReplayHandleV1,
    pub run_operation_id: Hash,
    pub plugin_roster_digest: Hash,
    pub adapter_transcript_digest: Hash,
    pub created_at_micros: u64,
    pub label: Option<String>,
}

/// Preferred-CBOR MRM1 root without a catalog or protected-use claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReproManifestRootV1(ReproManifestRootInputV1);

impl ReproManifestRootV1 {
    /// Check structural identities and label length.
    ///
    /// # Errors
    /// Rejects zero required digests, mismatched owner, or long labels.
    pub fn new(input: ReproManifestRootInputV1) -> Result<Self, ReproManifestRootErrorV1> {
        if input.owner_reference == Hash::zero()
            || input.run_operation_id == Hash::zero()
            || input.plugin_roster_digest == Hash::zero()
            || input.adapter_transcript_digest == Hash::zero()
            || input.owner_reference != input.world_handle.as_input().owner_reference
        {
            return Err(ReproManifestRootErrorV1::InvalidIdentity);
        }
        if input
            .label
            .as_ref()
            .is_some_and(|label| label.len() > MAX_REPRO_MANIFEST_LABEL_BYTES_V1)
        {
            return Err(ReproManifestRootErrorV1::FieldOutOfBounds);
        }
        Ok(Self(input))
    }

    /// Borrow the structurally checked fields without granting owner authority.
    #[must_use]
    pub const fn as_input(&self) -> &ReproManifestRootInputV1 {
        &self.0
    }

    /// Encode the unique preferred definite nine-field MRM1 record.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(309);
        bytes.extend_from_slice(&[0x89, 0x44]);
        bytes.extend_from_slice(b"MRM1");
        bytes.push(1);
        encode_hash(&mut bytes, self.0.owner_reference);
        encode_bytes(&mut bytes, &self.0.world_handle.to_canonical_cbor(), 2);
        for digest in [
            self.0.run_operation_id,
            self.0.plugin_roster_digest,
            self.0.adapter_transcript_digest,
        ] {
            encode_hash(&mut bytes, digest);
        }
        encode_head(&mut bytes, 0, self.0.created_at_micros);
        match &self.0.label {
            Some(label) => encode_bytes(&mut bytes, label.as_bytes(), 3),
            None => bytes.push(0xf6),
        }
        bytes
    }

    /// Native MRM1 identity; distinct from its ADR-093 class-1 artifact digest.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"pigloros.repro.manifest-root.v1\0");
        hasher.update(&self.to_canonical_cbor());
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Decode bounded preferred MRM1 bytes and recheck their canonical form.
    ///
    /// # Errors
    /// Rejects malformed, oversized, nonpreferred, mismatched or trailing data.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ReproManifestRootErrorV1> {
        if bytes.len() > MAX_REPRO_MANIFEST_ROOT_BYTES_V1 {
            return Err(ReproManifestRootErrorV1::FieldOutOfBounds);
        }
        let mut reader = Reader { bytes, offset: 0 };
        reader.root().and_then(|root| {
            if reader.offset != bytes.len() || root.to_canonical_cbor() != bytes {
                Err(ReproManifestRootErrorV1::NonCanonical)
            } else {
                Ok(root)
            }
        })
    }
}

fn encode_hash(bytes: &mut Vec<u8>, value: Hash) {
    bytes.extend_from_slice(&[0x58, 0x20]);
    bytes.extend_from_slice(value.as_bytes());
}

fn encode_bytes(bytes: &mut Vec<u8>, value: &[u8], major: u8) {
    encode_head(bytes, major, value.len() as u64);
    bytes.extend_from_slice(value);
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn root(&mut self) -> Result<ReproManifestRootV1, ReproManifestRootErrorV1> {
        self.fixed(&[0x89, 0x44, b'M', b'R', b'M', b'1', 1])
            .and_then(|()| self.hash())
            .and_then(|owner_reference| {
                self.bounded_blob(2, 256).and_then(|handle_bytes| {
                    WorldReplayHandleV1::from_canonical_cbor(handle_bytes)
                        .map(|world_handle| (owner_reference, world_handle))
                        .map_err(|_| ReproManifestRootErrorV1::InvalidEncoding)
                })
            })
            .and_then(|(owner_reference, world_handle)| {
                self.hash()
                    .map(|run_operation_id| (owner_reference, world_handle, run_operation_id))
            })
            .and_then(|(owner_reference, world_handle, run_operation_id)| {
                self.hash().map(|plugin_roster_digest| {
                    (
                        owner_reference,
                        world_handle,
                        run_operation_id,
                        plugin_roster_digest,
                    )
                })
            })
            .and_then(
                |(owner_reference, world_handle, run_operation_id, plugin_roster_digest)| {
                    self.hash()
                        .map(|adapter_transcript_digest| ReproManifestRootInputV1 {
                            owner_reference,
                            world_handle,
                            run_operation_id,
                            plugin_roster_digest,
                            adapter_transcript_digest,
                            created_at_micros: 0,
                            label: None,
                        })
                },
            )
            .and_then(|mut input| {
                self.unsigned().map(|created_at_micros| {
                    input.created_at_micros = created_at_micros;
                    input
                })
            })
            .and_then(|mut input| {
                self.label().map(|label| {
                    input.label = label;
                    input
                })
            })
            .and_then(ReproManifestRootV1::new)
    }

    fn fixed(&mut self, expected: &[u8]) -> Result<(), ReproManifestRootErrorV1> {
        self.take(expected.len()).and_then(|actual| {
            if actual == expected {
                Ok(())
            } else {
                Err(ReproManifestRootErrorV1::InvalidEncoding)
            }
        })
    }

    fn hash(&mut self) -> Result<Hash, ReproManifestRootErrorV1> {
        self.fixed(&[0x58, 0x20]).and_then(|()| {
            self.take(32).map(|value| {
                let mut bytes = [0; 32];
                bytes.copy_from_slice(value);
                Hash::from_bytes(bytes)
            })
        })
    }

    fn unsigned(&mut self) -> Result<u64, ReproManifestRootErrorV1> {
        self.head(0)
    }

    fn bounded_blob(
        &mut self,
        major: u8,
        maximum: usize,
    ) -> Result<&[u8], ReproManifestRootErrorV1> {
        self.head(major)
            .and_then(|length| {
                u16::try_from(length).map_err(|_| ReproManifestRootErrorV1::FieldOutOfBounds)
            })
            .and_then(|length| {
                let length = usize::from(length);
                if length > maximum {
                    Err(ReproManifestRootErrorV1::FieldOutOfBounds)
                } else {
                    self.take(length)
                }
            })
    }

    fn label(&mut self) -> Result<Option<String>, ReproManifestRootErrorV1> {
        if self.bytes.get(self.offset) == Some(&0xf6) {
            self.offset += 1;
            Ok(None)
        } else {
            self.bounded_blob(3, MAX_REPRO_MANIFEST_LABEL_BYTES_V1)
                .and_then(|value| {
                    std::str::from_utf8(value)
                        .map(|text| Some(text.to_owned()))
                        .map_err(|_| ReproManifestRootErrorV1::InvalidEncoding)
                })
        }
    }

    fn head(&mut self, major: u8) -> Result<u64, ReproManifestRootErrorV1> {
        self.take(1).map(|value| value[0]).and_then(|tag| {
            if tag >> 5 != major {
                return Err(ReproManifestRootErrorV1::InvalidEncoding);
            }
            match tag & 0x1f {
                small @ 0..=23 => Ok(u64::from(small)),
                24 => self.number::<1>(),
                25 => self.number::<2>(),
                26 => self.number::<4>(),
                27 => self.number::<8>(),
                _ => Err(ReproManifestRootErrorV1::InvalidEncoding),
            }
        })
    }

    fn number<const N: usize>(&mut self) -> Result<u64, ReproManifestRootErrorV1> {
        self.take(N).map(|bytes| {
            bytes
                .iter()
                .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte))
        })
    }

    fn take(&mut self, length: usize) -> Result<&[u8], ReproManifestRootErrorV1> {
        let end = self.offset.saturating_add(length);
        match self.bytes.get(self.offset..end) {
            Some(value) => {
                self.offset = end;
                Ok(value)
            }
            None => Err(ReproManifestRootErrorV1::InvalidEncoding),
        }
    }
}
