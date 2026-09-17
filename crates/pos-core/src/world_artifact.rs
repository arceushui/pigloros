//! Immutable ADR-081 WAL1 structural records, without native verification,
//! retrieval authority, owner disposition or a Replay claim.

use crate::{
    ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactTransitionRuleV1, Hash, KeyRoleV1,
};

/// Whole-input WAL1 bound, checked before decoding any field.
pub const MAX_WORLD_ARTIFACT_LEAF_BYTES_V1: usize = 16_384;
/// Maximum explicit key dependency triples in one leaf.
pub const MAX_WORLD_ARTIFACT_KEYS_V1: usize = 16;
/// Maximum complete native dependency node addresses in one leaf.
pub const MAX_WORLD_ARTIFACT_CHILDREN_V1: usize = 256;

/// Closed native artifact meanings from accepted ADR-081 Revision 1.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum WorldArtifactKindV1 {
    /// Canonical Plugin output declaration.
    OutputPolicy,
    /// Executable admission budget policy.
    ExecutableBudgetPolicy,
    /// Finite retention policy.
    RetentionPolicy,
    /// Concrete native retention lease.
    RetentionLease,
    /// Recorded base configuration.
    BaseConfiguration,
    /// Recorded execution profile.
    ExecutionProfile,
    /// Admitted audience policy.
    AudiencePolicy,
    /// Recorded payload or reducer schema.
    Schema,
    /// Recorded consumer reducer implementation.
    ReducerImplementation,
    /// Recorded host runtime identity.
    RuntimeIdentity,
    /// Host-admitted Plugin implementation identity.
    PluginImplementationIdentity,
    /// Non-secret native key dependency evidence.
    KeyDependencyEvidence,
    /// Source Event canonical payload.
    TimelinePayload,
    /// Separately admitted optional derived view.
    OptionalView,
}

impl WorldArtifactKindV1 {
    /// Exact accepted wire code, independent of native owner verification.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Decode only the accepted closed artifact kinds.
    ///
    /// # Errors
    /// Rejects unknown kind codes, including unapproved proposed extensions.
    pub fn from_code(code: u8) -> Result<Self, WorldArtifactErrorV1> {
        const KINDS: [WorldArtifactKindV1; 14] = [
            WorldArtifactKindV1::OutputPolicy,
            WorldArtifactKindV1::ExecutableBudgetPolicy,
            WorldArtifactKindV1::RetentionPolicy,
            WorldArtifactKindV1::RetentionLease,
            WorldArtifactKindV1::BaseConfiguration,
            WorldArtifactKindV1::ExecutionProfile,
            WorldArtifactKindV1::AudiencePolicy,
            WorldArtifactKindV1::Schema,
            WorldArtifactKindV1::ReducerImplementation,
            WorldArtifactKindV1::RuntimeIdentity,
            WorldArtifactKindV1::PluginImplementationIdentity,
            WorldArtifactKindV1::KeyDependencyEvidence,
            WorldArtifactKindV1::TimelinePayload,
            WorldArtifactKindV1::OptionalView,
        ];
        KINDS
            .get(usize::from(code))
            .copied()
            .ok_or(WorldArtifactErrorV1::UnsupportedValue)
    }
}

/// Structural failures do not report native availability or authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WorldArtifactErrorV1 {
    #[error("invalid artifact encoding")]
    InvalidEncoding,
    #[error("noncanonical artifact encoding")]
    NonCanonical,
    #[error("unsupported artifact value")]
    UnsupportedValue,
    #[error("artifact field out of bounds")]
    FieldOutOfBounds,
    #[error("artifact dependencies are not strictly ordered")]
    InvalidDependencyOrder,
}

/// Untrusted exact key triple; no secret material or key-use capability.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WorldArtifactKeyDependencyV1 {
    /// Existing registry role, not the coarser erasure receipt role.
    pub role: KeyRoleV1,
    /// Native key identity evidence address.
    pub identity_digest: Hash,
    /// Exact native key owner identifier.
    pub owner: [u8; 32],
}

/// Untrusted portable leaf fields; native ownership is checked elsewhere.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldArtifactLeafInputV1 {
    pub scope: Hash,
    pub kind: WorldArtifactKindV1,
    pub native_digest: Hash,
    pub native_byte_length: u64,
    pub owner: [u8; 32],
    pub data_class: ArtifactDataClassV1,
    pub optionality: ArtifactOptionalityV1,
    pub transition: ArtifactTransitionRuleV1,
    pub source_lease_hash: Hash,
    pub key_dependencies: Vec<WorldArtifactKeyDependencyV1>,
    pub child_node_hashes: Vec<Hash>,
}

/// Immutable structurally validated WAL1; it does not prove native edges,
/// key-child bijection, current source rights or requested-use eligibility.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldArtifactLeafV1(WorldArtifactLeafInputV1);

impl WorldArtifactLeafV1 {
    /// Validate fixed content addresses and bounded, strictly ordered lists.
    ///
    /// # Errors
    /// Rejects zero content addresses, excessive counts and duplicate/unsorted lists.
    pub fn new(input: WorldArtifactLeafInputV1) -> Result<Self, WorldArtifactErrorV1> {
        if input.scope == Hash::zero()
            || input.native_digest == Hash::zero()
            || input.source_lease_hash == Hash::zero()
            || input.key_dependencies.len() > MAX_WORLD_ARTIFACT_KEYS_V1
            || input.child_node_hashes.len() > MAX_WORLD_ARTIFACT_CHILDREN_V1
            || input
                .key_dependencies
                .iter()
                .any(|key| key.identity_digest == Hash::zero())
            || input.child_node_hashes.contains(&Hash::zero())
        {
            return Err(WorldArtifactErrorV1::FieldOutOfBounds);
        }
        if input
            .key_dependencies
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
            || input
                .child_node_hashes
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(WorldArtifactErrorV1::InvalidDependencyOrder);
        }
        Ok(Self(input))
    }

    /// Borrow validated fields without changing their immutable registration.
    #[must_use]
    pub const fn as_input(&self) -> &WorldArtifactLeafInputV1 {
        &self.0
    }

    /// Encode the exact13-field preferred definite WAL1 representation.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let input = &self.0;
        let mut out = vec![0x8d, 0x44];
        out.extend_from_slice(b"WAL1");
        out.push(1);
        encode_blob(&mut out, input.scope.as_bytes());
        encode_head(&mut out, 0, u64::from(input.kind.code()));
        encode_blob(&mut out, input.native_digest.as_bytes());
        encode_head(&mut out, 0, input.native_byte_length);
        encode_blob(&mut out, &input.owner);
        out.extend_from_slice(&[
            data_class_code(input.data_class),
            optionality_code(input.optionality),
            transition_code(input.transition),
        ]);
        encode_blob(&mut out, input.source_lease_hash.as_bytes());
        encode_head(&mut out, 4, input.key_dependencies.len() as u64);
        for key in &input.key_dependencies {
            out.extend_from_slice(&[0x83, key.role.code()]);
            encode_blob(&mut out, key.identity_digest.as_bytes());
            encode_blob(&mut out, &key.owner);
        }
        encode_head(&mut out, 4, input.child_node_hashes.len() as u64);
        for hash in &input.child_node_hashes {
            encode_blob(&mut out, hash.as_bytes());
        }
        out
    }

    /// Ordinary BLAKE3 of the exact ADR-081 domain, NUL and preferred bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"pigloros.world-evidence.artifact-leaf.v1\0");
        hasher.update(&self.to_canonical_cbor());
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Decode only bounded structural bytes; no native owner is invoked.
    ///
    /// # Errors
    /// Rejects malformed, oversized, unknown, nonpreferred and trailing bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, WorldArtifactErrorV1> {
        if bytes.len() > MAX_WORLD_ARTIFACT_LEAF_BYTES_V1 {
            return Err(WorldArtifactErrorV1::FieldOutOfBounds);
        }
        let mut reader = Reader { bytes, offset: 0 };
        reader
            .array(13)
            .and_then(|()| reader.magic())
            .and_then(|()| reader.version())
            .and_then(|()| reader.native_header())
            .and_then(|header| reader.policy_lease().map(|policy| (header, policy)))
            .and_then(|(header, policy)| {
                reader
                    .key_dependencies()
                    .map(|key_dependencies| (header, policy, key_dependencies))
            })
            .and_then(|(header, policy, key_dependencies)| {
                reader
                    .child_node_hashes()
                    .map(|child_node_hashes| WorldArtifactLeafInputV1 {
                        scope: header.scope,
                        kind: header.kind,
                        native_digest: header.native_digest,
                        native_byte_length: header.native_byte_length,
                        owner: header.owner,
                        data_class: policy.data_class,
                        optionality: policy.optionality,
                        transition: policy.transition,
                        source_lease_hash: policy.source_lease_hash,
                        key_dependencies,
                        child_node_hashes,
                    })
            })
            .and_then(Self::new)
            .and_then(|leaf| {
                if bytes == leaf.to_canonical_cbor() {
                    Ok(leaf)
                } else {
                    Err(WorldArtifactErrorV1::NonCanonical)
                }
            })
    }
}

const fn data_class_code(value: ArtifactDataClassV1) -> u8 {
    match value {
        ArtifactDataClassV1::PrivateSubjectData => 0,
        ArtifactDataClassV1::ConsentedSharedData => 1,
        ArtifactDataClassV1::PublicRecord => 2,
        ArtifactDataClassV1::AggregateData => 3,
        ArtifactDataClassV1::StructuralAuditMetadata => 4,
    }
}

const fn optionality_code(value: ArtifactOptionalityV1) -> u8 {
    match value {
        ArtifactOptionalityV1::Required => 0,
        ArtifactOptionalityV1::Optional => 1,
    }
}

const fn transition_code(value: ArtifactTransitionRuleV1) -> u8 {
    match value {
        ArtifactTransitionRuleV1::PreserveExact => 0,
        ArtifactTransitionRuleV1::RedactViews => 1,
        ArtifactTransitionRuleV1::RetainStructure => 2,
        ArtifactTransitionRuleV1::Remove => 3,
    }
}

fn decode_code<T: Copy>(code: u8, values: &[T]) -> Result<T, WorldArtifactErrorV1> {
    values
        .get(usize::from(code))
        .copied()
        .ok_or(WorldArtifactErrorV1::UnsupportedValue)
}

fn encode_blob(out: &mut Vec<u8>, bytes: &[u8]) {
    // Only fixed native widths4 and32 are encoded by this module.
    encode_head(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn encode_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let bytes = value.to_be_bytes();
    let tag = major << 5;
    match value {
        0..=23 => out.push(tag | bytes[7]),
        24..=255 => out.extend_from_slice(&[tag | 0x18, bytes[7]]),
        256..=65_535 => {
            out.push(tag | 0x19);
            out.extend_from_slice(&bytes[6..]);
        }
        65_536..=4_294_967_295 => {
            out.push(tag | 0x1a);
            out.extend_from_slice(&bytes[4..]);
        }
        _ => {
            out.push(tag | 0x1b);
            out.extend_from_slice(&bytes);
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

struct NativeHeaderV1 {
    scope: Hash,
    kind: WorldArtifactKindV1,
    native_digest: Hash,
    native_byte_length: u64,
    owner: [u8; 32],
}

struct PolicyLeaseV1 {
    data_class: ArtifactDataClassV1,
    optionality: ArtifactOptionalityV1,
    transition: ArtifactTransitionRuleV1,
    source_lease_hash: Hash,
}

impl<'a> Reader<'a> {
    fn magic(&mut self) -> Result<(), WorldArtifactErrorV1> {
        self.blob::<4>().and_then(|magic| {
            if magic == *b"WAL1" {
                Ok(())
            } else {
                Err(WorldArtifactErrorV1::InvalidEncoding)
            }
        })
    }

    fn version(&mut self) -> Result<(), WorldArtifactErrorV1> {
        self.head(0).and_then(|version| {
            if version == 1 {
                Ok(())
            } else {
                Err(WorldArtifactErrorV1::UnsupportedValue)
            }
        })
    }

    fn native_header(&mut self) -> Result<NativeHeaderV1, WorldArtifactErrorV1> {
        self.blob()
            .map(Hash::from_bytes)
            .and_then(|scope| {
                self.code()
                    .and_then(WorldArtifactKindV1::from_code)
                    .map(|kind| (scope, kind))
            })
            .and_then(|(scope, kind)| {
                self.blob()
                    .map(Hash::from_bytes)
                    .map(|native_digest| (scope, kind, native_digest))
            })
            .and_then(|(scope, kind, native_digest)| {
                self.head(0)
                    .map(|native_byte_length| (scope, kind, native_digest, native_byte_length))
            })
            .and_then(|(scope, kind, native_digest, native_byte_length)| {
                self.blob().map(|owner| NativeHeaderV1 {
                    scope,
                    kind,
                    native_digest,
                    native_byte_length,
                    owner,
                })
            })
    }

    fn policy_lease(&mut self) -> Result<PolicyLeaseV1, WorldArtifactErrorV1> {
        self.code()
            .and_then(|code| {
                decode_code(
                    code,
                    &[
                        ArtifactDataClassV1::PrivateSubjectData,
                        ArtifactDataClassV1::ConsentedSharedData,
                        ArtifactDataClassV1::PublicRecord,
                        ArtifactDataClassV1::AggregateData,
                        ArtifactDataClassV1::StructuralAuditMetadata,
                    ],
                )
            })
            .and_then(|data_class| {
                self.code()
                    .and_then(|code| {
                        decode_code(
                            code,
                            &[
                                ArtifactOptionalityV1::Required,
                                ArtifactOptionalityV1::Optional,
                            ],
                        )
                    })
                    .map(|optionality| (data_class, optionality))
            })
            .and_then(|(data_class, optionality)| {
                self.code()
                    .and_then(|code| {
                        decode_code(
                            code,
                            &[
                                ArtifactTransitionRuleV1::PreserveExact,
                                ArtifactTransitionRuleV1::RedactViews,
                                ArtifactTransitionRuleV1::RetainStructure,
                                ArtifactTransitionRuleV1::Remove,
                            ],
                        )
                    })
                    .map(|transition| (data_class, optionality, transition))
            })
            .and_then(|(data_class, optionality, transition)| {
                self.blob()
                    .map(Hash::from_bytes)
                    .map(|source_lease_hash| PolicyLeaseV1 {
                        data_class,
                        optionality,
                        transition,
                        source_lease_hash,
                    })
            })
    }

    fn key_dependencies(
        &mut self,
    ) -> Result<Vec<WorldArtifactKeyDependencyV1>, WorldArtifactErrorV1> {
        self.bounded_count(MAX_WORLD_ARTIFACT_KEYS_V1 as u64)
            .and_then(|count| {
                (0..count)
                    .map(|_| self.key_dependency())
                    .collect::<Result<Vec<_>, WorldArtifactErrorV1>>()
            })
    }

    fn key_dependency(&mut self) -> Result<WorldArtifactKeyDependencyV1, WorldArtifactErrorV1> {
        self.array(3)
            .and_then(|()| self.code())
            .and_then(|code| {
                KeyRoleV1::from_code(code).map_err(|_| WorldArtifactErrorV1::UnsupportedValue)
            })
            .and_then(|role| {
                self.blob()
                    .map(Hash::from_bytes)
                    .and_then(|identity_digest| {
                        self.blob().map(|owner| WorldArtifactKeyDependencyV1 {
                            role,
                            identity_digest,
                            owner,
                        })
                    })
            })
    }

    fn child_node_hashes(&mut self) -> Result<Vec<Hash>, WorldArtifactErrorV1> {
        self.bounded_count(MAX_WORLD_ARTIFACT_CHILDREN_V1 as u64)
            .and_then(|count| {
                (0..count)
                    .map(|_| self.blob().map(Hash::from_bytes))
                    .collect::<Result<Vec<_>, WorldArtifactErrorV1>>()
            })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], WorldArtifactErrorV1> {
        // offset<=16384; requested fixed native widths are at most32.
        let end = self.offset + length;
        self.bytes
            .get(self.offset..end)
            .ok_or(WorldArtifactErrorV1::InvalidEncoding)
            .inspect(|_| self.offset = end)
    }

    fn head(&mut self, major: u8) -> Result<u64, WorldArtifactErrorV1> {
        self.take(1).and_then(|bytes| {
            let initial = bytes[0];
            if initial >> 5 != major {
                return Err(WorldArtifactErrorV1::InvalidEncoding);
            }
            match initial & 31 {
                value @ 0..=23 => Ok(u64::from(value)),
                argument @ 24..=27 => self.take(1usize << (argument - 24)).map(|bytes| {
                    bytes
                        .iter()
                        .fold(0, |value, byte| (value << 8) | u64::from(*byte))
                }),
                _ => Err(WorldArtifactErrorV1::InvalidEncoding),
            }
        })
    }

    fn code(&mut self) -> Result<u8, WorldArtifactErrorV1> {
        self.head(0).and_then(|value| {
            u8::try_from(value).map_err(|_| WorldArtifactErrorV1::FieldOutOfBounds)
        })
    }

    fn array(&mut self, count: u64) -> Result<(), WorldArtifactErrorV1> {
        self.head(4).and_then(|actual| {
            if actual == count {
                Ok(())
            } else {
                Err(WorldArtifactErrorV1::InvalidEncoding)
            }
        })
    }

    fn bounded_count(&mut self, maximum: u64) -> Result<u64, WorldArtifactErrorV1> {
        self.head(4).and_then(|count| {
            if count > maximum {
                Err(WorldArtifactErrorV1::FieldOutOfBounds)
            } else {
                Ok(count)
            }
        })
    }

    fn blob<const N: usize>(&mut self) -> Result<[u8; N], WorldArtifactErrorV1> {
        self.head(2).and_then(|length| {
            if length != N as u64 {
                return Err(WorldArtifactErrorV1::InvalidEncoding);
            }
            self.take(N).map(|bytes| {
                let mut out = [0; N];
                out.copy_from_slice(bytes);
                out
            })
        })
    }
}
