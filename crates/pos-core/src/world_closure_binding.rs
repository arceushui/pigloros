//! Immutable ADR-081 WCB1 structural binding records.
//!
//! A content address is not proof of the recorded cut, its owner, or an Exact
//! Replay claim. The installed recording and verification hosts own those checks.

use crate::{Hash, TimelineId};
use ulid::Ulid;

/// Maximum encoded size of one WCB1 record.
pub const MAX_WORLD_CLOSURE_BINDING_BYTES_V1: usize = 1024;

const DOMAIN: &[u8] = b"pigloros.world-evidence.binding.v1\0";

/// Structural WCB1 failures; none imply a native owner decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WorldClosureBindingErrorV1 {
    /// Malformed CBOR, wrong field type or width, or incomplete input.
    #[error("invalid WCB1 encoding")]
    InvalidEncoding,
    /// An unsupported record version was supplied.
    #[error("unsupported WCB1 version")]
    UnsupportedVersion,
    /// A fixed integer, read limit or record size is out of bounds.
    #[error("WCB1 field is out of bounds")]
    FieldOutOfBounds,
    /// The history root does not match the logical head's empty/nonempty state.
    #[error("WCB1 history root does not match logical head")]
    InvalidHistoryRelation,
    /// A required or present optional content address is zero.
    #[error("WCB1 content address is zero")]
    ZeroContentAddress,
    /// The input is not its unique preferred definite CBOR representation.
    #[error("noncanonical WCB1 encoding")]
    NonCanonicalEncoding,
}

/// Recorded precommit cut coordinate supplied by the authenticated cut owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorldClosureCutCoordinateV1 {
    pub cut_id: u64,
    pub partition_id: u16,
    pub reservation_identity: [u8; 32],
}

/// Finite traversal limits recorded from the admitted profile, not defaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorldClosureReadLimitsV1 {
    pub max_node_visits: u64,
    pub max_native_bytes: u64,
    pub max_combined_depth: u8,
}

/// Untrusted WCB1 fields. Supplying them does not authenticate their owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorldClosureBindingInputV1 {
    pub timeline_id: TimelineId,
    pub operation_id: Hash,
    pub cut_coordinate: WorldClosureCutCoordinateV1,
    pub logical_head: u64,
    pub stitched_head_hash: Hash,
    pub retention_lease_leaf_hash: Hash,
    pub consumer_set_hash: Hash,
    pub dependency_root_hash: Hash,
    pub history_root_hash: Option<Hash>,
    pub predecessor_binding_hash: Option<Hash>,
    pub parent_lineage_reference: Option<Hash>,
    pub read_limits: WorldClosureReadLimitsV1,
}

/// Validated immutable structural WCB1 record; not a verified Replay closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorldClosureBindingV1(WorldClosureBindingInputV1);

impl WorldClosureBindingV1 {
    /// Validate the structural binding fields without consulting any owner.
    ///
    /// # Errors
    /// Rejects invalid content addresses, history-root relation or read limits.
    pub fn new(input: WorldClosureBindingInputV1) -> Result<Self, WorldClosureBindingErrorV1> {
        if input.retention_lease_leaf_hash == Hash::zero()
            || input.consumer_set_hash == Hash::zero()
            || input.dependency_root_hash == Hash::zero()
            || [
                input.history_root_hash,
                input.predecessor_binding_hash,
                input.parent_lineage_reference,
            ]
            .into_iter()
            .flatten()
            .any(|address| address == Hash::zero())
        {
            return Err(WorldClosureBindingErrorV1::ZeroContentAddress);
        }
        if (input.logical_head == 0) != input.history_root_hash.is_none() {
            return Err(WorldClosureBindingErrorV1::InvalidHistoryRelation);
        }
        if input.read_limits.max_node_visits == 0
            || input.read_limits.max_native_bytes == 0
            || !(1..=32).contains(&input.read_limits.max_combined_depth)
        {
            return Err(WorldClosureBindingErrorV1::FieldOutOfBounds);
        }
        Ok(Self(input))
    }

    /// Borrow the exact validated structural fields.
    #[must_use]
    pub const fn as_input(&self) -> &WorldClosureBindingInputV1 {
        &self.0
    }

    /// Encode the unique preferred definite 14-field WCB1 CBOR record.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let input = &self.0;
        let mut out = Vec::with_capacity(384);
        encode_head(&mut out, 4, 14);
        encode_blob(&mut out, b"WCB1");
        encode_head(&mut out, 0, 1);
        encode_blob(&mut out, &input.timeline_id.inner().to_bytes());
        encode_blob(&mut out, input.operation_id.as_bytes());
        encode_head(&mut out, 4, 3);
        encode_head(&mut out, 0, input.cut_coordinate.cut_id);
        encode_head(&mut out, 0, u64::from(input.cut_coordinate.partition_id));
        encode_blob(&mut out, &input.cut_coordinate.reservation_identity);
        encode_head(&mut out, 0, input.logical_head);
        encode_blob(&mut out, input.stitched_head_hash.as_bytes());
        encode_blob(&mut out, input.retention_lease_leaf_hash.as_bytes());
        encode_blob(&mut out, input.consumer_set_hash.as_bytes());
        encode_blob(&mut out, input.dependency_root_hash.as_bytes());
        encode_optional_hash(&mut out, input.history_root_hash);
        encode_optional_hash(&mut out, input.predecessor_binding_hash);
        encode_optional_hash(&mut out, input.parent_lineage_reference);
        encode_head(&mut out, 4, 3);
        encode_head(&mut out, 0, input.read_limits.max_node_visits);
        encode_head(&mut out, 0, input.read_limits.max_native_bytes);
        encode_head(&mut out, 0, u64::from(input.read_limits.max_combined_depth));
        out
    }

    /// Ordinary BLAKE3 of the accepted domain, NUL and canonical WCB1 bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN);
        hasher.update(&self.to_canonical_cbor());
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Decode only one complete, bounded, preferred WCB1 record.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, oversized or structurally invalid bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, WorldClosureBindingErrorV1> {
        if bytes.len() > MAX_WORLD_CLOSURE_BINDING_BYTES_V1 {
            return Err(WorldClosureBindingErrorV1::FieldOutOfBounds);
        }
        let mut reader = Reader { bytes, offset: 0 };
        reader.record().and_then(|input| {
            if reader.offset != bytes.len() {
                return Err(WorldClosureBindingErrorV1::InvalidEncoding);
            }
            Self::new(input).and_then(|binding| {
                if binding.to_canonical_cbor().as_slice() == bytes {
                    Ok(binding)
                } else {
                    Err(WorldClosureBindingErrorV1::NonCanonicalEncoding)
                }
            })
        })
    }
}

fn encode_optional_hash(out: &mut Vec<u8>, address: Option<Hash>) {
    if let Some(address) = address {
        encode_blob(out, address.as_bytes());
    } else {
        out.push(0xf6);
    }
}

fn encode_blob(out: &mut Vec<u8>, bytes: &[u8]) {
    encode_head(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn encode_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let tag = major << 5;
    let bytes = value.to_be_bytes();
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

impl Reader<'_> {
    fn record(&mut self) -> Result<WorldClosureBindingInputV1, WorldClosureBindingErrorV1> {
        self.array(14)
            .and_then(|()| self.blob::<4>())
            .and_then(|magic| {
                if magic == *b"WCB1" {
                    Ok(())
                } else {
                    Err(WorldClosureBindingErrorV1::InvalidEncoding)
                }
            })
            .and_then(|()| self.unsigned())
            .and_then(|version| {
                if version == 1 {
                    Ok(())
                } else {
                    Err(WorldClosureBindingErrorV1::UnsupportedVersion)
                }
            })
            .and_then(|()| self.identity_and_logical_head())
            .and_then(
                |(timeline_id, operation_id, cut_coordinate, logical_head)| {
                    self.addresses().and_then(|addresses| {
                        self.read_limits()
                            .map(|read_limits| WorldClosureBindingInputV1 {
                                timeline_id,
                                operation_id,
                                cut_coordinate,
                                logical_head,
                                stitched_head_hash: addresses.stitched_head_hash,
                                retention_lease_leaf_hash: addresses.retention_lease_leaf_hash,
                                consumer_set_hash: addresses.consumer_set_hash,
                                dependency_root_hash: addresses.dependency_root_hash,
                                history_root_hash: addresses.history_root_hash,
                                predecessor_binding_hash: addresses.predecessor_binding_hash,
                                parent_lineage_reference: addresses.parent_lineage_reference,
                                read_limits,
                            })
                    })
                },
            )
    }

    fn identity_and_logical_head(
        &mut self,
    ) -> Result<(TimelineId, Hash, WorldClosureCutCoordinateV1, u64), WorldClosureBindingErrorV1>
    {
        self.blob::<16>()
            .map(|bytes| TimelineId::from_ulid(Ulid::from(u128::from_be_bytes(bytes))))
            .and_then(|timeline_id| {
                self.hash().and_then(|operation_id| {
                    self.cut_coordinate().and_then(|cut_coordinate| {
                        self.unsigned().map(|logical_head| {
                            (timeline_id, operation_id, cut_coordinate, logical_head)
                        })
                    })
                })
            })
    }

    fn cut_coordinate(
        &mut self,
    ) -> Result<WorldClosureCutCoordinateV1, WorldClosureBindingErrorV1> {
        self.array(3)
            .and_then(|()| self.unsigned())
            .and_then(|cut_id| {
                self.unsigned().and_then(|partition| {
                    u16::try_from(partition)
                        .map_err(|_| WorldClosureBindingErrorV1::FieldOutOfBounds)
                        .and_then(|partition_id| {
                            self.blob()
                                .map(|reservation_identity| WorldClosureCutCoordinateV1 {
                                    cut_id,
                                    partition_id,
                                    reservation_identity,
                                })
                        })
                })
            })
    }

    fn addresses(&mut self) -> Result<Addresses, WorldClosureBindingErrorV1> {
        self.hash().and_then(|stitched_head_hash| {
            self.hash().and_then(|retention_lease_leaf_hash| {
                self.hash().and_then(|consumer_set_hash| {
                    self.hash().and_then(|dependency_root_hash| {
                        self.optional_hash().and_then(|history_root_hash| {
                            self.optional_hash().and_then(|predecessor_binding_hash| {
                                self.optional_hash()
                                    .map(|parent_lineage_reference| Addresses {
                                        stitched_head_hash,
                                        retention_lease_leaf_hash,
                                        consumer_set_hash,
                                        dependency_root_hash,
                                        history_root_hash,
                                        predecessor_binding_hash,
                                        parent_lineage_reference,
                                    })
                            })
                        })
                    })
                })
            })
        })
    }

    fn read_limits(&mut self) -> Result<WorldClosureReadLimitsV1, WorldClosureBindingErrorV1> {
        self.array(3)
            .and_then(|()| self.unsigned())
            .and_then(|max_node_visits| {
                self.unsigned().and_then(|max_native_bytes| {
                    self.unsigned().and_then(|depth| {
                        u8::try_from(depth)
                            .map_err(|_| WorldClosureBindingErrorV1::FieldOutOfBounds)
                            .map(|max_combined_depth| WorldClosureReadLimitsV1 {
                                max_node_visits,
                                max_native_bytes,
                                max_combined_depth,
                            })
                    })
                })
            })
    }

    fn optional_hash(&mut self) -> Result<Option<Hash>, WorldClosureBindingErrorV1> {
        match self.bytes.get(self.offset) {
            Some(&0xf6) => {
                self.offset += 1;
                Ok(None)
            }
            Some(_) => self.hash().map(Some),
            None => Err(WorldClosureBindingErrorV1::InvalidEncoding),
        }
    }

    fn hash(&mut self) -> Result<Hash, WorldClosureBindingErrorV1> {
        self.blob().map(Hash::from_bytes)
    }

    fn blob<const N: usize>(&mut self) -> Result<[u8; N], WorldClosureBindingErrorV1> {
        self.head(2).and_then(|length| {
            if length != N as u64 {
                return Err(WorldClosureBindingErrorV1::InvalidEncoding);
            }
            self.take(N).map(|bytes| {
                let mut out = [0; N];
                out.copy_from_slice(bytes);
                out
            })
        })
    }

    fn array(&mut self, count: u64) -> Result<(), WorldClosureBindingErrorV1> {
        self.head(4).and_then(|actual| {
            if actual == count {
                Ok(())
            } else {
                Err(WorldClosureBindingErrorV1::InvalidEncoding)
            }
        })
    }

    fn unsigned(&mut self) -> Result<u64, WorldClosureBindingErrorV1> {
        self.head(0)
    }

    fn head(&mut self, major: u8) -> Result<u64, WorldClosureBindingErrorV1> {
        self.take(1).map(|bytes| bytes[0]).and_then(|initial| {
            if initial >> 5 != major {
                return Err(WorldClosureBindingErrorV1::InvalidEncoding);
            }
            match initial & 31 {
                value @ 0..=23 => Ok(u64::from(value)),
                argument @ 24..=27 => self.take(1usize << (argument - 24)).map(|bytes| {
                    bytes
                        .iter()
                        .fold(0, |value, byte| (value << 8) | u64::from(*byte))
                }),
                _ => Err(WorldClosureBindingErrorV1::InvalidEncoding),
            }
        })
    }

    fn take(&mut self, length: usize) -> Result<&[u8], WorldClosureBindingErrorV1> {
        self.bytes
            .get(self.offset..)
            .and_then(|remaining| remaining.get(..length))
            .ok_or(WorldClosureBindingErrorV1::InvalidEncoding)
            .inspect(|_| self.offset += length)
    }
}

struct Addresses {
    stitched_head_hash: Hash,
    retention_lease_leaf_hash: Hash,
    consumer_set_hash: Hash,
    dependency_root_hash: Hash,
    history_root_hash: Option<Hash>,
    predecessor_binding_hash: Option<Hash>,
    parent_lineage_reference: Option<Hash>,
}
