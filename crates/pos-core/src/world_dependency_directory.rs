//! Immutable structural WDB1 dependency-directory branches.
//!
//! The codec records bounded ordered key ranges and child summaries. It does
//! not establish that a referenced WAL1/WDB1 object exists, that its native
//! dependencies are complete, or that a World Replay claim is justified.

use crate::{CanonicalBytes, Hash, WorldArtifactKindV1};
use std::cmp::Ordering;
use std::fmt;

/// Maximum encoded size of one WDB1 node.
pub const MAX_WORLD_DEPENDENCY_DIRECTORY_BYTES_V1: usize = 65_536;
/// Maximum number of child references in one WDB1 branch.
pub const MAX_WORLD_DEPENDENCY_DIRECTORY_CHILDREN_V1: usize = 256;
/// Maximum supported height of one WDB1 branch.
pub const MAX_WORLD_DEPENDENCY_DIRECTORY_HEIGHT_V1: u8 = 31;

const MAGIC: &[u8; 4] = b"WDB1";
const VERSION: u8 = 1;
const DOMAIN: &[u8] = b"pigloros.world-evidence.dependency-branch.v1\0";

/// Closed errors returned by the structural WDB1 codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorldDependencyDirectoryErrorV1 {
    /// The CBOR item is malformed or has a field with the wrong type or width.
    InvalidEncoding,
    /// The record does not use the WDB1 magic.
    WrongMagic,
    /// The record version is not supported.
    UnsupportedVersion,
    /// A kind code is not part of the closed World artifact vocabulary.
    UnsupportedKind,
    /// A bounded field or cardinality is outside the WDB1 contract.
    FieldOutOfBounds,
    /// A scope, child, or native content address is zero.
    ZeroContentAddress,
    /// A child range or leaf count is invalid.
    InvalidRange,
    /// Child ranges are not strictly ordered and non-overlapping.
    NonCanonicalOrder,
    /// The checked sum of child leaf counts overflowed.
    LeafCountOverflow,
    /// The input is valid CBOR but not the unique preferred WDB1 encoding.
    NonCanonicalEncoding,
}

impl fmt::Display for WorldDependencyDirectoryErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "invalid WDB1 encoding",
            Self::WrongMagic => "wrong WDB1 magic",
            Self::UnsupportedVersion => "unsupported WDB1 version",
            Self::UnsupportedKind => "unsupported WDB1 artifact kind",
            Self::FieldOutOfBounds => "WDB1 field is out of bounds",
            Self::ZeroContentAddress => "WDB1 content address is zero",
            Self::InvalidRange => "invalid WDB1 key range or leaf count",
            Self::NonCanonicalOrder => "WDB1 child ranges are not in canonical order",
            Self::LeafCountOverflow => "WDB1 leaf count overflow",
            Self::NonCanonicalEncoding => "WDB1 encoding is not preferred",
        })
    }
}

impl std::error::Error for WorldDependencyDirectoryErrorV1 {}

/// One immutable WDB1 key, ordered by artifact kind code then raw digest bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorldDependencyKeyV1 {
    kind: WorldArtifactKindV1,
    native_digest: Hash,
}

impl WorldDependencyKeyV1 {
    /// Construct one key from its native artifact kind and content digest.
    ///
    /// # Errors
    /// Rejects a zero native content digest.
    pub fn new(
        kind: WorldArtifactKindV1,
        native_digest: Hash,
    ) -> Result<Self, WorldDependencyDirectoryErrorV1> {
        if native_digest == Hash::zero() {
            return Err(WorldDependencyDirectoryErrorV1::ZeroContentAddress);
        }
        Ok(Self {
            kind,
            native_digest,
        })
    }

    /// Return the closed native artifact kind.
    #[must_use]
    pub const fn kind(self) -> WorldArtifactKindV1 {
        self.kind
    }

    /// Return the native content digest.
    #[must_use]
    pub const fn native_digest(self) -> Hash {
        self.native_digest
    }
}

/// One immutable summary of a WDB1 child node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorldDependencyDirectoryChildV1 {
    first_key: WorldDependencyKeyV1,
    last_key: WorldDependencyKeyV1,
    leaf_count: u64,
    node_hash: Hash,
}

impl WorldDependencyDirectoryChildV1 {
    /// Construct one child summary with a positive, internally consistent range.
    ///
    /// # Errors
    /// Rejects zero leaf counts, impossible one-key/count combinations,
    /// reversed ranges, and zero child content addresses.
    pub fn new(
        first_key: WorldDependencyKeyV1,
        last_key: WorldDependencyKeyV1,
        leaf_count: u64,
        node_hash: Hash,
    ) -> Result<Self, WorldDependencyDirectoryErrorV1> {
        let order = compare_keys(first_key, last_key);
        if leaf_count == 0
            || order == Ordering::Greater
            || (order == Ordering::Equal && leaf_count != 1)
            || (order == Ordering::Less && leaf_count < 2)
        {
            return Err(WorldDependencyDirectoryErrorV1::InvalidRange);
        }
        if node_hash == Hash::zero() {
            return Err(WorldDependencyDirectoryErrorV1::ZeroContentAddress);
        }
        Ok(Self {
            first_key,
            last_key,
            leaf_count,
            node_hash,
        })
    }

    /// Return the first key covered by this child.
    #[must_use]
    pub const fn first_key(self) -> WorldDependencyKeyV1 {
        self.first_key
    }

    /// Return the last key covered by this child.
    #[must_use]
    pub const fn last_key(self) -> WorldDependencyKeyV1 {
        self.last_key
    }

    /// Return the exact number of WAL1 leaves claimed by this child.
    #[must_use]
    pub const fn leaf_count(self) -> u64 {
        self.leaf_count
    }

    /// Return the content address of the referenced WAL1 or WDB1 child.
    #[must_use]
    pub const fn node_hash(self) -> Hash {
        self.node_hash
    }
}

/// Unvalidated fields supplied to construct one WDB1 branch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldDependencyDirectoryInputV1 {
    /// Owner scope for this directory node.
    pub scope: Hash,
    /// One for WAL1 leaf references, increasing toward the root.
    pub height: u8,
    /// Ordered child summaries. The node derives its endpoints and leaf count.
    pub children: Vec<WorldDependencyDirectoryChildV1>,
}

/// Immutable structurally validated WDB1 branch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldDependencyDirectoryV1 {
    scope: Hash,
    height: u8,
    first_key: WorldDependencyKeyV1,
    last_key: WorldDependencyKeyV1,
    leaf_count: u64,
    children: Vec<WorldDependencyDirectoryChildV1>,
}

impl WorldDependencyDirectoryV1 {
    /// Validate scope, height, ordered ranges, packed child counts, and the
    /// checked leaf-count sum.
    ///
    /// Height-one children must each summarize exactly one WAL1 key. At greater
    /// heights, each non-final child must be full for its level and the final
    /// child may be partial. Referenced lower-level WDB1 records must still be
    /// checked by the native verifier; this constructor validates summaries.
    ///
    /// # Errors
    /// Rejects zero scope, unsupported height, empty or oversized branches,
    /// invalid child summaries, unordered ranges, or an overflowing sum.
    pub fn new(
        input: WorldDependencyDirectoryInputV1,
    ) -> Result<Self, WorldDependencyDirectoryErrorV1> {
        if input.scope == Hash::zero() {
            return Err(WorldDependencyDirectoryErrorV1::ZeroContentAddress);
        }
        if input.height == 0 || input.height > MAX_WORLD_DEPENDENCY_DIRECTORY_HEIGHT_V1 {
            return Err(WorldDependencyDirectoryErrorV1::FieldOutOfBounds);
        }
        if input.children.is_empty()
            || input.children.len() > MAX_WORLD_DEPENDENCY_DIRECTORY_CHILDREN_V1
        {
            return Err(WorldDependencyDirectoryErrorV1::FieldOutOfBounds);
        }
        if input
            .children
            .windows(2)
            .any(|pair| compare_keys(pair[0].last_key, pair[1].first_key) != Ordering::Less)
        {
            return Err(WorldDependencyDirectoryErrorV1::NonCanonicalOrder);
        }
        let child_capacity = subtree_capacity(input.height - 1);
        for (index, child) in input.children.iter().enumerate() {
            match child_capacity {
                Some(capacity) if child.leaf_count > capacity => {
                    return Err(WorldDependencyDirectoryErrorV1::InvalidRange);
                }
                Some(capacity)
                    if index + 1 < input.children.len() && child.leaf_count != capacity =>
                {
                    return Err(WorldDependencyDirectoryErrorV1::InvalidRange);
                }
                None if index + 1 < input.children.len() => {
                    return Err(WorldDependencyDirectoryErrorV1::InvalidRange);
                }
                _ => {}
            }
        }
        let first_key = input.children[0].first_key;
        let last_key = input.children[input.children.len() - 1].last_key;
        let leaf_count = match input
            .children
            .iter()
            .try_fold(0_u64, |total, child| total.checked_add(child.leaf_count))
        {
            Some(total) => total,
            None => return Err(WorldDependencyDirectoryErrorV1::LeafCountOverflow),
        };
        Ok(Self {
            scope: input.scope,
            height: input.height,
            first_key,
            last_key,
            leaf_count,
            children: input.children,
        })
    }

    /// Decode and validate one complete preferred WDB1 representation.
    ///
    /// # Errors
    /// Rejects malformed, non-preferred, trailing, unsupported, or oversized
    /// records before allocating child storage beyond the fixed fanout bound.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, WorldDependencyDirectoryErrorV1> {
        if bytes.as_slice().len() > MAX_WORLD_DEPENDENCY_DIRECTORY_BYTES_V1 {
            return Err(WorldDependencyDirectoryErrorV1::FieldOutOfBounds);
        }
        let mut reader = Reader {
            bytes: bytes.as_slice(),
            offset: 0,
        };
        let directory = match reader.directory() {
            Ok(directory) => directory,
            Err(error) => return Err(error),
        };
        if let Err(error) = reader.finish() {
            return Err(error);
        }
        if directory.encode().as_slice() != bytes.as_slice() {
            return Err(WorldDependencyDirectoryErrorV1::NonCanonicalEncoding);
        }
        Ok(directory)
    }

    /// Encode the exact eight-field preferred definite WDB1 representation.
    #[must_use]
    pub fn encode(&self) -> CanonicalBytes {
        let mut output = Vec::with_capacity(MAX_WORLD_DEPENDENCY_DIRECTORY_BYTES_V1.min(256));
        encode_array(&mut output, 8);
        encode_bytes(&mut output, MAGIC);
        encode_uint(&mut output, u64::from(VERSION));
        encode_bytes(&mut output, self.scope.as_bytes());
        encode_uint(&mut output, u64::from(self.height));
        encode_key(&mut output, self.first_key);
        encode_key(&mut output, self.last_key);
        encode_uint(&mut output, self.leaf_count);
        encode_array(&mut output, self.children.len());
        for child in &self.children {
            encode_array(&mut output, 4);
            encode_key(&mut output, child.first_key);
            encode_key(&mut output, child.last_key);
            encode_uint(&mut output, child.leaf_count);
            encode_bytes(&mut output, child.node_hash.as_bytes());
        }
        CanonicalBytes::from_vec(output)
    }

    /// Return the domain-separated WDB1 content address.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let encoded = self.encode();
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN);
        hasher.update(encoded.as_slice());
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Return the owner scope recorded in this node.
    #[must_use]
    pub const fn scope(&self) -> Hash {
        self.scope
    }

    /// Return this node's height above WAL1 leaf references.
    #[must_use]
    pub const fn height(&self) -> u8 {
        self.height
    }

    /// Return the first key covered by this node.
    #[must_use]
    pub const fn first_key(&self) -> WorldDependencyKeyV1 {
        self.first_key
    }

    /// Return the last key covered by this node.
    #[must_use]
    pub const fn last_key(&self) -> WorldDependencyKeyV1 {
        self.last_key
    }

    /// Return the checked number of WAL1 leaves summarized by this node.
    #[must_use]
    pub const fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Borrow the ordered child summaries.
    #[must_use]
    pub fn children(&self) -> &[WorldDependencyDirectoryChildV1] {
        &self.children
    }
}

fn compare_keys(left: WorldDependencyKeyV1, right: WorldDependencyKeyV1) -> Ordering {
    left.kind.code().cmp(&right.kind.code()).then_with(|| {
        left.native_digest
            .as_bytes()
            .cmp(right.native_digest.as_bytes())
    })
}

fn subtree_capacity(height: u8) -> Option<u64> {
    let bit_shift = u32::from(height) * 8;
    if bit_shift < u64::BITS {
        Some(1_u64 << bit_shift)
    } else {
        None
    }
}

fn encode_key(output: &mut Vec<u8>, key: WorldDependencyKeyV1) {
    encode_array(output, 2);
    encode_uint(output, u64::from(key.kind.code()));
    encode_bytes(output, key.native_digest.as_bytes());
}

fn encode_array(output: &mut Vec<u8>, length: usize) {
    encode_head(output, 4, length as u64);
}

fn encode_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    encode_head(output, 2, bytes.len() as u64);
    output.extend_from_slice(bytes);
}

fn encode_uint(output: &mut Vec<u8>, value: u64) {
    encode_head(output, 0, value);
}

fn encode_head(output: &mut Vec<u8>, major: u8, value: u64) {
    let bytes = value.to_be_bytes();
    let tag = major << 5;
    match value {
        0..=23 => output.push(tag | bytes[7]),
        24..=255 => output.extend_from_slice(&[tag | 0x18, bytes[7]]),
        256..=65_535 => {
            output.push(tag | 0x19);
            output.extend_from_slice(&bytes[6..]);
        }
        65_536..=4_294_967_295 => {
            output.push(tag | 0x1a);
            output.extend_from_slice(&bytes[4..]);
        }
        _ => {
            output.push(tag | 0x1b);
            output.extend_from_slice(&bytes);
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn directory(&mut self) -> Result<WorldDependencyDirectoryV1, WorldDependencyDirectoryErrorV1> {
        self.array(8)
            .and_then(|()| self.magic())
            .and_then(|()| self.version())
            .and_then(|()| self.blob::<32>())
            .map(Hash::from_bytes)
            .and_then(|scope| self.code().map(|height| (scope, height)))
            .and_then(|(scope, height)| self.key().map(|first_key| (scope, height, first_key)))
            .and_then(|(scope, height, first_key)| {
                self.key()
                    .map(|last_key| (scope, height, first_key, last_key))
            })
            .and_then(|(scope, height, first_key, last_key)| {
                self.head(0)
                    .map(|leaf_count| (scope, height, first_key, last_key, leaf_count))
            })
            .and_then(|(scope, height, first_key, last_key, leaf_count)| {
                self.children().and_then(|children| {
                    WorldDependencyDirectoryV1::new(WorldDependencyDirectoryInputV1 {
                        scope,
                        height,
                        children,
                    })
                    .and_then(|directory| {
                        if directory.first_key == first_key
                            && directory.last_key == last_key
                            && directory.leaf_count == leaf_count
                        {
                            Ok(directory)
                        } else {
                            Err(WorldDependencyDirectoryErrorV1::InvalidRange)
                        }
                    })
                })
            })
    }

    fn magic(&mut self) -> Result<(), WorldDependencyDirectoryErrorV1> {
        self.blob::<4>().and_then(|magic| {
            if magic == *MAGIC {
                Ok(())
            } else {
                Err(WorldDependencyDirectoryErrorV1::WrongMagic)
            }
        })
    }

    fn version(&mut self) -> Result<(), WorldDependencyDirectoryErrorV1> {
        self.head(0).and_then(|version| {
            if version == u64::from(VERSION) {
                Ok(())
            } else {
                Err(WorldDependencyDirectoryErrorV1::UnsupportedVersion)
            }
        })
    }

    fn key(&mut self) -> Result<WorldDependencyKeyV1, WorldDependencyDirectoryErrorV1> {
        self.array(2)
            .and_then(|()| self.code())
            .and_then(|code| {
                WorldArtifactKindV1::from_code(code)
                    .map_err(|_| WorldDependencyDirectoryErrorV1::UnsupportedKind)
            })
            .and_then(|kind| {
                self.blob()
                    .and_then(|digest| WorldDependencyKeyV1::new(kind, Hash::from_bytes(digest)))
            })
    }

    fn children(
        &mut self,
    ) -> Result<Vec<WorldDependencyDirectoryChildV1>, WorldDependencyDirectoryErrorV1> {
        self.bounded_count(1, MAX_WORLD_DEPENDENCY_DIRECTORY_CHILDREN_V1 as u64)
            .and_then(|count| {
                (0..count)
                    .map(|_| self.child())
                    .collect::<Result<Vec<_>, WorldDependencyDirectoryErrorV1>>()
            })
    }

    fn child(
        &mut self,
    ) -> Result<WorldDependencyDirectoryChildV1, WorldDependencyDirectoryErrorV1> {
        self.array(4)
            .and_then(|()| self.key())
            .and_then(|first_key| self.key().map(|last_key| (first_key, last_key)))
            .and_then(|(first_key, last_key)| {
                self.head(0)
                    .map(|leaf_count| (first_key, last_key, leaf_count))
            })
            .and_then(|(first_key, last_key, leaf_count)| {
                self.blob().and_then(|node_hash| {
                    WorldDependencyDirectoryChildV1::new(
                        first_key,
                        last_key,
                        leaf_count,
                        Hash::from_bytes(node_hash),
                    )
                })
            })
    }

    fn finish(&self) -> Result<(), WorldDependencyDirectoryErrorV1> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(WorldDependencyDirectoryErrorV1::InvalidEncoding)
        }
    }

    fn take(&mut self, length: usize) -> Result<&[u8], WorldDependencyDirectoryErrorV1> {
        // The caller reads only fixed 1/8/32-byte fields after the complete
        // input has been capped at 65,536 bytes, so this addition is bounded.
        let end = self.offset + length;
        match self.bytes.get(self.offset..end) {
            Some(bytes) => {
                self.offset = end;
                Ok(bytes)
            }
            None => Err(WorldDependencyDirectoryErrorV1::InvalidEncoding),
        }
    }

    fn head(&mut self, expected_major: u8) -> Result<u64, WorldDependencyDirectoryErrorV1> {
        let initial = match self.take(1) {
            Ok(bytes) => bytes[0],
            Err(error) => return Err(error),
        };
        if initial >> 5 != expected_major {
            return Err(WorldDependencyDirectoryErrorV1::InvalidEncoding);
        }
        match initial & 31 {
            value @ 0..=23 => Ok(u64::from(value)),
            argument @ 24..=27 => self.take(1usize << (argument - 24)).map(|bytes| {
                bytes
                    .iter()
                    .fold(0, |value, byte| (value << 8) | u64::from(*byte))
            }),
            _ => Err(WorldDependencyDirectoryErrorV1::InvalidEncoding),
        }
    }

    fn code(&mut self) -> Result<u8, WorldDependencyDirectoryErrorV1> {
        self.head(0).and_then(|value| {
            u8::try_from(value).map_err(|_| WorldDependencyDirectoryErrorV1::FieldOutOfBounds)
        })
    }

    fn array(&mut self, expected_count: u64) -> Result<(), WorldDependencyDirectoryErrorV1> {
        self.head(4).and_then(|actual_count| {
            if actual_count == expected_count {
                Ok(())
            } else {
                Err(WorldDependencyDirectoryErrorV1::InvalidEncoding)
            }
        })
    }

    fn bounded_count(
        &mut self,
        minimum: u64,
        maximum: u64,
    ) -> Result<u64, WorldDependencyDirectoryErrorV1> {
        self.head(4).and_then(|count| {
            if count < minimum || count > maximum {
                Err(WorldDependencyDirectoryErrorV1::FieldOutOfBounds)
            } else {
                Ok(count)
            }
        })
    }

    fn blob<const N: usize>(&mut self) -> Result<[u8; N], WorldDependencyDirectoryErrorV1> {
        self.head(2).and_then(|length| {
            if length != N as u64 {
                return Err(WorldDependencyDirectoryErrorV1::InvalidEncoding);
            }
            self.take(N).map(|bytes| {
                let mut output = [0; N];
                output.copy_from_slice(bytes);
                output
            })
        })
    }
}
