//! ADR-129 §4 native node references and typed direct input references.
//!
//! A reference only names an input. The concrete native owner must resolve
//! the exact committed node, IDP1 edge, source artifact or encrypted
//! metadata record, derive its scope and check current authority. Decoding a
//! reference establishes none of those facts.

use super::member_progress::{
    encode_factual_node, node_bytes, read_factual_node, valid_factual_node,
};
use super::{
    bounded_bytes, canonical_end, encode_coordinates, fixed_bytes, head_len, read_coordinates,
    read_hash, read_head, validate_coordinates, CommunityFactualNodeReferenceV1,
    CommunityLifecycleErrorV1 as Error, CommunityMetadataSchemaV1, Result,
};
use crate::{
    encode_bytes, encode_hash, encode_head, CborCursor, ErasureArtifactClassV1, Hash, TimelineId,
};
use zeroize::Zeroizing;

// Array head (1), Timeline and generation (2 x 17), kind (1), the larger
// producer form, a 16-byte control ID (17), and u16 role and slot (2 x 3).
const MAX_LOCATOR_BYTES: usize = 59;

/// `[store_incarnation, producer_ordinal, node_ordinal, CPN1_digest]`.
///
/// The derived order is the ADR's lexicographic tuple order. A reference is
/// not proof that the node exists, precedes its consumer or is current.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct CommunityNativeNodeReferenceV1 {
    /// Nonzero store incarnation; inputs from another incarnation are unsupported.
    pub store_incarnation: [u8; 16],
    /// Positive non-reusable native producer ordinal.
    pub producer_ordinal: u64,
    /// Node ordinal within that producer.
    pub node_ordinal: u32,
    /// Exact CPN1 identity.
    pub node_digest: Hash,
}

impl CommunityNativeNodeReferenceV1 {
    pub(super) fn validate(self) -> Result<()> {
        if self.store_incarnation == [0; 16]
            || self.producer_ordinal == 0
            || self.node_digest == Hash::zero()
        {
            Err(Error::InvalidBinding)
        } else {
            Ok(())
        }
    }

    /// The native coordinate, without the node digest.
    const fn coordinate(self) -> ([u8; 16], u64, u32) {
        (
            self.store_incarnation,
            self.producer_ordinal,
            self.node_ordinal,
        )
    }

    /// Whether this reference strictly precedes the native coordinate.
    pub(super) const fn precedes(self, producer_ordinal: u64, node_ordinal: u32) -> bool {
        self.producer_ordinal < producer_ordinal
            || (self.producer_ordinal == producer_ordinal && self.node_ordinal < node_ordinal)
    }

    /// Exact length of [`Self::encode`]: array head, incarnation, the two
    /// ordinals and the node digest.
    fn encoded_len(self) -> usize {
        1 + 17 + head_len(self.producer_ordinal) + head_len(u64::from(self.node_ordinal)) + 34
    }

    pub(super) fn encode(self, out: &mut Vec<u8>) {
        out.push(0x84);
        encode_bytes(out, &self.store_incarnation, 2);
        encode_head(out, 0, self.producer_ordinal);
        encode_head(out, 0, u64::from(self.node_ordinal));
        encode_hash(out, self.node_digest);
    }

    pub(super) fn read(cursor: &mut CborCursor<'_>) -> Result<Self> {
        cursor.fixed(&[0x84]).map_err(Error::from).and_then(|()| {
            fixed_bytes(cursor).and_then(|store_incarnation| {
                read_head(cursor, 0).and_then(|producer_ordinal| {
                    read_u32(cursor).and_then(|node_ordinal| {
                        read_hash(cursor).map(|node_digest| Self {
                            store_incarnation,
                            producer_ordinal,
                            node_ordinal,
                            node_digest,
                        })
                    })
                })
            })
        })
    }
}

/// Native node references in strictly ascending tuple order.
#[derive(Clone, Copy)]
pub struct CommunityNativeNodeReferencesV1<'a>(NodeRows<'a>);

#[derive(Clone, Copy)]
enum NodeRows<'a> {
    Typed(&'a [CommunityNativeNodeReferenceV1]),
    Canonical { bytes: &'a [u8], count: usize },
}

impl<'a> CommunityNativeNodeReferencesV1<'a> {
    /// Borrow caller references; the owning record validates them.
    #[must_use]
    pub const fn from_references(references: &'a [CommunityNativeNodeReferenceV1]) -> Self {
        Self(NodeRows::Typed(references))
    }

    /// Number of references.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self.0 {
            NodeRows::Typed(rows) => rows.len(),
            NodeRows::Canonical { count, .. } => count,
        }
    }

    /// Whether the list is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate references; decoded rows are re-read from validated bytes.
    pub fn iter(&self) -> impl Iterator<Item = Result<CommunityNativeNodeReferenceV1>> + '_ {
        let rows = self.0;
        let mut cursor = match rows {
            NodeRows::Typed(_) => CborCursor::new(&[]),
            NodeRows::Canonical { bytes, .. } => CborCursor::new(bytes),
        };
        (0..self.len()).map(move |index| match rows {
            NodeRows::Typed(references) => Ok(references[index]),
            NodeRows::Canonical { .. } => CommunityNativeNodeReferenceV1::read(&mut cursor),
        })
    }

    /// Check the count, every reference and strictly ascending native
    /// coordinates: one coordinate under two digests is a conflicting alias.
    pub(super) fn validate(self, minimum: usize, maximum: usize) -> Result<()> {
        if self.len() < minimum || self.len() > maximum {
            return Err(Error::BoundsExceeded);
        }
        let mut previous = None;
        self.iter().try_for_each(|row| {
            row.and_then(|reference| {
                reference.validate().and_then(|()| {
                    if previous.is_some_and(|prior: CommunityNativeNodeReferenceV1| {
                        prior.coordinate() >= reference.coordinate()
                    }) {
                        Err(Error::InvalidBinding)
                    } else {
                        previous = Some(reference);
                        Ok(())
                    }
                })
            })
        })
    }

    pub(super) fn encode(self, out: &mut Vec<u8>) {
        encode_head(out, 4, self.len() as u64);
        match self.0 {
            NodeRows::Typed(rows) => rows.iter().for_each(|reference| reference.encode(out)),
            NodeRows::Canonical { bytes, .. } => out.extend_from_slice(bytes),
        }
    }

    pub(super) fn read(cursor: &mut CborCursor<'a>, maximum: usize) -> Result<Self> {
        read_rows(cursor, maximum, |cursor| {
            CommunityNativeNodeReferenceV1::read(cursor).map(drop)
        })
        .map(|(bytes, count)| Self(NodeRows::Canonical { bytes, count }))
    }
}

impl PartialEq for CommunityNativeNodeReferencesV1<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}
impl Eq for CommunityNativeNodeReferencesV1<'_> {}

/// Native producer or closed control identity of a metadata locator.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityLocatorProducerV1 {
    /// Kind 0: the allocated positive native producer ordinal.
    Native(u64),
    /// Kind 1: the nonzero 16-byte control identity.
    Control([u8; 16]),
}

/// `[T, G, producer_or_control_kind, ordinal_or_control_id, record_role, slot]`.
///
/// Qualified-store metadata, not a caller-selected path or key.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityMetadataLocatorV1 {
    /// Admitted Timeline.
    pub timeline: TimelineId,
    /// Admitted generation.
    pub generation: [u8; 16],
    /// Producing native producer or control operation.
    pub producer: CommunityLocatorProducerV1,
    /// Record role.
    pub record_role: u16,
    /// Record slot.
    pub slot: u16,
}

impl CommunityMetadataLocatorV1 {
    fn validate(self) -> Result<()> {
        validate_coordinates(self.timeline, self.generation).and_then(|()| {
            require(match self.producer {
                CommunityLocatorProducerV1::Native(ordinal) => ordinal != 0,
                CommunityLocatorProducerV1::Control(id) => id != [0; 16],
            })
        })
    }

    /// Exact length of [`Self::encode`]'s byte string: its head, then the
    /// array head, T and G, the producer form, role and slot.
    fn encoded_len(self) -> usize {
        let producer = match self.producer {
            CommunityLocatorProducerV1::Native(ordinal) => 1 + head_len(ordinal),
            CommunityLocatorProducerV1::Control(_) => 1 + 17,
        };
        let inner = 1
            + 34
            + producer
            + head_len(u64::from(self.record_role))
            + head_len(u64::from(self.slot));
        head_len(inner as u64) + inner
    }

    fn encode(self, out: &mut Vec<u8>) {
        let mut inner = Zeroizing::new(Vec::with_capacity(MAX_LOCATOR_BYTES));
        inner.push(0x86);
        encode_coordinates(&mut inner, self.timeline, self.generation);
        match self.producer {
            CommunityLocatorProducerV1::Native(ordinal) => {
                encode_head(&mut inner, 0, 0);
                encode_head(&mut inner, 0, ordinal);
            }
            CommunityLocatorProducerV1::Control(id) => {
                encode_head(&mut inner, 0, 1);
                encode_bytes(&mut inner, &id, 2);
            }
        }
        encode_head(&mut inner, 0, u64::from(self.record_role));
        encode_head(&mut inner, 0, u64::from(self.slot));
        encode_bytes(out, &inner, 2);
    }

    fn read(cursor: &mut CborCursor<'_>) -> Result<Self> {
        bounded_bytes(cursor, MAX_LOCATOR_BYTES).and_then(|bytes| {
            let mut cursor = CborCursor::new(bytes);
            cursor
                .fixed(&[0x86])
                .map_err(Error::from)
                .and_then(|()| read_coordinates(&mut cursor))
                .and_then(|(timeline, generation)| {
                    read_locator_producer(&mut cursor).and_then(|producer| {
                        read_u16(&mut cursor).and_then(|record_role| {
                            read_u16(&mut cursor).map(|slot| Self {
                                timeline,
                                generation,
                                producer,
                                record_role,
                                slot,
                            })
                        })
                    })
                })
                .and_then(|locator| canonical_end(&cursor).map(|()| locator))
        })
    }
}

/// One ADR-129 typed direct input reference.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityTypedInputRefV1<'a> {
    /// `[0, native_node_ref]`.
    Native(CommunityNativeNodeReferenceV1),
    /// `[1, source_T, canonical_IDP1_node_bytes, record_digest]`.
    Factual {
        /// Source Timeline.
        timeline: TimelineId,
        /// Existing six-field IDP1 node.
        node: CommunityFactualNodeReferenceV1<'a>,
        /// Exact committed record identity.
        record_digest: Hash,
    },
    /// `[2, owner_reference, artifact_class, artifact_digest,
    /// registration_address, source_scope_binding_digest]`.
    Artifact {
        /// Independent owner reference.
        owner_reference: Hash,
        /// Existing ARD1 artifact class.
        artifact_class: ErasureArtifactClassV1,
        /// Exact source artifact identity.
        artifact_digest: Hash,
        /// Exact registration address.
        registration_address: Hash,
        /// Source scope binding.
        source_scope_binding_digest: Hash,
    },
    /// `[3, metadata_schema_magic, locator_bytes, CNE1_physical_address,
    /// private_record_digest]`; only CDP1, CNT1, CMB1 and CMS1 are admitted.
    Metadata {
        /// Admitted immutable policy or progress schema.
        schema: CommunityMetadataSchemaV1,
        /// Exact qualified-store locator.
        locator: CommunityMetadataLocatorV1,
        /// CNE1 physical address.
        envelope_address: Hash,
        /// Private owner record commitment.
        private_record_digest: Hash,
    },
}

impl CommunityTypedInputRefV1<'_> {
    fn validate(self) -> Result<()> {
        match self {
            Self::Native(reference) => reference.validate(),
            Self::Factual {
                timeline,
                node,
                record_digest,
            } => require(
                timeline.inner().to_bytes() != [0; 16]
                    && valid_factual_node(node)
                    && record_digest != Hash::zero(),
            ),
            Self::Artifact {
                owner_reference,
                artifact_digest,
                registration_address,
                source_scope_binding_digest,
                ..
            } => require(
                ![
                    owner_reference,
                    artifact_digest,
                    registration_address,
                    source_scope_binding_digest,
                ]
                .contains(&Hash::zero()),
            ),
            Self::Metadata {
                schema,
                locator,
                envelope_address,
                private_record_digest,
            } => require(
                matches!(
                    schema,
                    CommunityMetadataSchemaV1::Cdp1
                        | CommunityMetadataSchemaV1::Cnt1
                        | CommunityMetadataSchemaV1::Cmb1
                        | CommunityMetadataSchemaV1::Cms1
                ) && envelope_address != Hash::zero()
                    && private_record_digest != Hash::zero(),
            )
            .and_then(|()| locator.validate()),
        }
    }

    /// Exact length of [`Self::encode`]: array head and tag (2), then the
    /// variant's fields.
    fn encoded_len(self) -> usize {
        match self {
            Self::Native(reference) => 2 + reference.encoded_len(),
            Self::Factual { node, .. } => {
                let node_len = node_bytes(node);
                2 + 17 + head_len(node_len as u64) + node_len + 34
            }
            Self::Artifact { artifact_class, .. } => {
                2 + 34 + head_len(artifact_class.code()) + 3 * 34
            }
            Self::Metadata { locator, .. } => 2 + 5 + locator.encoded_len() + 2 * 34,
        }
    }

    fn encode(self, out: &mut Vec<u8>) {
        match self {
            Self::Native(reference) => {
                out.extend_from_slice(&[0x82, 0]);
                reference.encode(out);
            }
            Self::Factual {
                timeline,
                node,
                record_digest,
            } => {
                out.extend_from_slice(&[0x84, 1]);
                encode_bytes(out, &timeline.inner().to_bytes(), 2);
                encode_factual_node(out, node);
                encode_hash(out, record_digest);
            }
            Self::Artifact {
                owner_reference,
                artifact_class,
                artifact_digest,
                registration_address,
                source_scope_binding_digest,
            } => {
                out.extend_from_slice(&[0x86, 2]);
                encode_hash(out, owner_reference);
                encode_head(out, 0, artifact_class.code());
                encode_hash(out, artifact_digest);
                encode_hash(out, registration_address);
                encode_hash(out, source_scope_binding_digest);
            }
            Self::Metadata {
                schema,
                locator,
                envelope_address,
                private_record_digest,
            } => {
                out.extend_from_slice(&[0x85, 3]);
                encode_bytes(out, &schema.magic(), 2);
                locator.encode(out);
                encode_hash(out, envelope_address);
                encode_hash(out, private_record_digest);
            }
        }
    }
}

fn read_typed_ref<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunityTypedInputRefV1<'a>> {
    read_head(cursor, 4).and_then(|fields| {
        read_head(cursor, 0).and_then(|tag| match (fields, tag) {
            (2, 0) => {
                CommunityNativeNodeReferenceV1::read(cursor).map(CommunityTypedInputRefV1::Native)
            }
            (4, 1) => fixed_bytes(cursor).and_then(|timeline| {
                read_factual_node(cursor).and_then(|node| {
                    read_hash(cursor).map(|record_digest| CommunityTypedInputRefV1::Factual {
                        timeline: TimelineId::from_ulid(ulid::Ulid::from_bytes(timeline)),
                        node,
                        record_digest,
                    })
                })
            }),
            (6, 2) => read_artifact_ref(cursor),
            (5, 3) => read_metadata_ref(cursor),
            _ => Err(Error::InvalidEncoding),
        })
    })
}

fn read_artifact_ref<'a>(cursor: &mut CborCursor<'_>) -> Result<CommunityTypedInputRefV1<'a>> {
    read_hash(cursor).and_then(|owner_reference| {
        read_head(cursor, 0)
            .and_then(|code| {
                ErasureArtifactClassV1::from_code(code).map_err(|_| Error::InvalidEncoding)
            })
            .and_then(|artifact_class| {
                super::read_hashes(cursor).map(
                    |[artifact_digest, registration_address, source_scope_binding_digest]| {
                        CommunityTypedInputRefV1::Artifact {
                            owner_reference,
                            artifact_class,
                            artifact_digest,
                            registration_address,
                            source_scope_binding_digest,
                        }
                    },
                )
            })
    })
}

fn read_metadata_ref<'a>(cursor: &mut CborCursor<'_>) -> Result<CommunityTypedInputRefV1<'a>> {
    fixed_bytes(cursor)
        .and_then(|magic| {
            CommunityMetadataSchemaV1::from_magic(magic).ok_or(Error::InvalidEncoding)
        })
        .and_then(|schema| {
            CommunityMetadataLocatorV1::read(cursor).and_then(|locator| {
                super::read_hashes(cursor).map(|[envelope_address, private_record_digest]| {
                    CommunityTypedInputRefV1::Metadata {
                        schema,
                        locator,
                        envelope_address,
                        private_record_digest,
                    }
                })
            })
        })
}

/// Typed direct input references in canonical order: variant code first,
/// then the lexicographic canonical encoding of the remaining fields.
#[derive(Clone, Copy)]
pub struct CommunityTypedInputRefsV1<'a>(RefRows<'a>);

#[derive(Clone, Copy)]
enum RefRows<'a> {
    Typed(&'a [CommunityTypedInputRefV1<'a>]),
    Canonical { bytes: &'a [u8], count: usize },
}

impl<'a> CommunityTypedInputRefsV1<'a> {
    /// Borrow caller references; the owning record validates them.
    #[must_use]
    pub const fn from_references(references: &'a [CommunityTypedInputRefV1<'a>]) -> Self {
        Self(RefRows::Typed(references))
    }

    /// Number of references.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self.0 {
            RefRows::Typed(rows) => rows.len(),
            RefRows::Canonical { count, .. } => count,
        }
    }

    /// Whether the list is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate references; decoded rows are re-read from validated bytes.
    pub fn iter(&self) -> impl Iterator<Item = Result<CommunityTypedInputRefV1<'a>>> + '_ {
        let rows = self.0;
        let mut cursor = match rows {
            RefRows::Typed(_) => CborCursor::new(&[]),
            RefRows::Canonical { bytes, .. } => CborCursor::new(bytes),
        };
        (0..self.len()).map(move |index| match rows {
            RefRows::Typed(references) => Ok(references[index]),
            RefRows::Canonical { .. } => read_typed_ref(&mut cursor),
        })
    }

    /// Check the count, every reference and strict canonical order. Two
    /// native references to one coordinate under different digests are a
    /// conflicting alias; they sort adjacently, since only the digest differs.
    pub(super) fn validate(self, minimum: usize, maximum: usize) -> Result<()> {
        if self.len() < minimum || self.len() > maximum {
            return Err(Error::BoundsExceeded);
        }
        let mut previous: Option<Zeroizing<Vec<u8>>> = None;
        let mut previous_native = None;
        // A named iterator is dropped before `previous`, in either edition.
        let mut rows = self.iter();
        rows.try_for_each(|row| {
            row.and_then(|reference| {
                reference.validate().and_then(|()| {
                    if let CommunityTypedInputRefV1::Native(native) = reference {
                        if previous_native == Some(native.coordinate()) {
                            return Err(Error::InvalidBinding);
                        }
                        previous_native = Some(native.coordinate());
                    }
                    let mut encoded = Zeroizing::new(Vec::with_capacity(256));
                    reference.encode(&mut encoded);
                    // Byte 0 is the array head; ordering starts at the code.
                    if previous
                        .as_ref()
                        .is_some_and(|prior| prior[1..] >= encoded[1..])
                    {
                        Err(Error::InvalidBinding)
                    } else {
                        previous = Some(encoded);
                        Ok(())
                    }
                })
            })
        })
    }

    /// Exact length of [`Self::encode`]'s array, computed without encoding.
    pub(super) fn encoded_len(self) -> usize {
        head_len(self.len() as u64)
            + match self.0 {
                RefRows::Typed(rows) => rows
                    .iter()
                    .copied()
                    .map(CommunityTypedInputRefV1::encoded_len)
                    .sum::<usize>(),
                RefRows::Canonical { bytes, .. } => bytes.len(),
            }
    }

    pub(super) fn encode(self, out: &mut Vec<u8>) {
        encode_head(out, 4, self.len() as u64);
        match self.0 {
            RefRows::Typed(rows) => rows.iter().for_each(|reference| reference.encode(out)),
            RefRows::Canonical { bytes, .. } => out.extend_from_slice(bytes),
        }
    }

    pub(super) fn read(cursor: &mut CborCursor<'a>, maximum: usize) -> Result<Self> {
        read_rows(cursor, maximum, |cursor| read_typed_ref(cursor).map(drop))
            .map(|(bytes, count)| Self(RefRows::Canonical { bytes, count }))
    }
}

impl PartialEq for CommunityTypedInputRefsV1<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}
impl Eq for CommunityTypedInputRefsV1<'_> {}

/// Read a bounded definite array, returning its exact row bytes and count.
fn read_rows<'a>(
    cursor: &mut CborCursor<'a>,
    maximum: usize,
    mut read_row: impl FnMut(&mut CborCursor<'a>) -> Result<()>,
) -> Result<(&'a [u8], usize)> {
    read_head(cursor, 4).and_then(|count| {
        if count > maximum as u64 {
            return Err(Error::BoundsExceeded);
        }
        let count = usize::try_from(count).unwrap_or(usize::MAX);
        let start = cursor.position();
        let mut original = cursor.clone();
        (0..count)
            .try_for_each(|_| read_row(cursor))
            .and_then(|()| {
                original
                    .take(cursor.position() - start)
                    .map_err(Error::from)
                    .map(|bytes| (bytes, count))
            })
    })
}

const fn require(valid: bool) -> Result<()> {
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidBinding)
    }
}

fn read_locator_producer(cursor: &mut CborCursor<'_>) -> Result<CommunityLocatorProducerV1> {
    read_head(cursor, 0).and_then(|kind| match kind {
        0 => read_head(cursor, 0).map(CommunityLocatorProducerV1::Native),
        1 => fixed_bytes(cursor).map(CommunityLocatorProducerV1::Control),
        _ => Err(Error::InvalidEncoding),
    })
}

fn read_u16(cursor: &mut CborCursor<'_>) -> Result<u16> {
    read_head(cursor, 0).and_then(|value| u16::try_from(value).map_err(|_| Error::BoundsExceeded))
}

fn read_u32(cursor: &mut CborCursor<'_>) -> Result<u32> {
    read_head(cursor, 0).and_then(|value| u32::try_from(value).map_err(|_| Error::BoundsExceeded))
}
