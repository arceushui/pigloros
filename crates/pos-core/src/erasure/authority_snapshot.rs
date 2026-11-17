//! The single-host erasure authority's adapter inputs (ADR-136 §2.5 and §4a).
//!
//! [`ErasureAuthoritySnapshotV1`] is the read-only, same-snapshot evidence a
//! host turns into the authority's read view: the complete erasure inventory,
//! the owner and Fork relation of every Timeline in that inventory's topology,
//! and the write-once erasure store identity. It is evidence, never a trust
//! root.
//!
//! [`ErasureRetainedObjectV1`] is one canonical object an adapter retains in
//! the shared content-addressed erasure object store before any committed
//! record references it. It is non-authoritative until a committed record
//! references its address (ADR-060).
//!
//! [`LocalOwnerEffectV1`] is one durable single-host owner effect that an
//! adapter commits in the same transaction as its owner-result object.

use super::{
    decode_limited, domain_digest, ErasureErrorV1, ErasurePersistenceInventorySnapshotV1,
    ErasureReferenceV1,
};
use crate::{
    clock::Seq,
    ids::{EntityId, TimelineId},
    Hash, KeyDestructionRequestV1,
};
use ciborium::value::Value;

/// The largest canonical object an adapter retains for the erasure authority.
///
/// It equals the largest retained record, the bound TPS1 snapshot.
pub const ERASURE_RETAINED_OBJECT_MAX_BYTES_V1: usize = 1024 * 1024;

/// The largest definite array inside a retained object.
///
/// It equals the TPS1 nested-array ceiling (`MAX_NESTED_ARRAY_ITEMS` in
/// `pos-conformance`): the V1 per-category maximum of 4,096 entries
/// ([`super::ERASURE_MAX_OBLIGATIONS_PER_CATEGORY`]) plus one, so the largest
/// retained record, a bound TPS1 snapshot, always decodes.
const RETAINED_OBJECT_MAX_ARRAY: usize = super::ERASURE_MAX_OBLIGATIONS_PER_CATEGORY + 1;

/// The shortest record tag of a retained object, in bytes.
pub const ERASURE_RECORD_TAG_MIN_BYTES_V1: usize = 2;

/// The longest record tag of a retained object, in bytes.
pub const ERASURE_RECORD_TAG_MAX_BYTES_V1: usize = 8;

/// The largest ELAD1, ELCG1 or ELNEG1 owner-effect record (ADR-136 §4a).
pub const LOCAL_OWNER_EFFECT_MAX_BYTES_V1: usize = 1024;

/// The largest ELO1 owner-result record (ADR-136 §4).
pub const LOCAL_OWNER_RESULT_MAX_BYTES_V1: usize = 4 * 1024;

/// The owner and Fork relation of one Timeline in an authority snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureAuthorityTimelineRowV1 {
    /// The Timeline or Fork identity.
    pub id: TimelineId,
    /// The durable owner recorded for the Timeline, if any.
    pub owner: Option<EntityId>,
    /// The parent Timeline and sequence of a Fork.
    pub fork_point: Option<(TimelineId, Seq)>,
}

/// One same-snapshot read of everything the single-host authority may
/// evaluate as evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureAuthoritySnapshotV1 {
    inventory: ErasurePersistenceInventorySnapshotV1,
    timelines: Vec<ErasureAuthorityTimelineRowV1>,
    store_identity: Option<Hash>,
}

impl ErasureAuthoritySnapshotV1 {
    /// Package one adapter read.
    ///
    /// # Errors
    /// Returns [`ErasureErrorV1::ProvenanceMissing`] unless the Timeline rows
    /// name exactly the inventory topology, in the same strictly increasing
    /// order.
    pub fn new(
        inventory: ErasurePersistenceInventorySnapshotV1,
        timelines: Vec<ErasureAuthorityTimelineRowV1>,
        store_identity: Option<Hash>,
    ) -> Result<Self, ErasureErrorV1> {
        if timelines
            .iter()
            .map(|row| row.id)
            .eq(inventory.topology().iter().copied())
        {
            Ok(Self {
                inventory,
                timelines,
                store_identity,
            })
        } else {
            Err(ErasureErrorV1::ProvenanceMissing)
        }
    }

    /// The complete erasure inventory read in this snapshot.
    #[must_use]
    pub const fn inventory(&self) -> &ErasurePersistenceInventorySnapshotV1 {
        &self.inventory
    }

    /// Every Timeline row, in strictly increasing identity order.
    #[must_use]
    pub fn timelines(&self) -> &[ErasureAuthorityTimelineRowV1] {
        &self.timelines
    }

    /// The row of one Timeline in this snapshot.
    #[must_use]
    pub fn timeline(&self, id: TimelineId) -> Option<&ErasureAuthorityTimelineRowV1> {
        self.timelines
            .binary_search_by_key(&id, |row| row.id)
            .ok()
            .and_then(|index| self.timelines.get(index))
    }

    /// The write-once erasure store identity, when it has been written.
    #[must_use]
    pub const fn store_identity(&self) -> Option<Hash> {
        self.store_identity
    }
}

/// One canonical object retained in the shared erasure object store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureRetainedObjectV1 {
    tag: String,
    reference: ErasureReferenceV1,
    canonical_cbor: Vec<u8>,
}

impl ErasureRetainedObjectV1 {
    /// Validate one canonical record and derive its content address.
    ///
    /// The record must be a bounded, canonical, definite CBOR array whose
    /// first element is its record tag: an ASCII upper-case letter followed
    /// by one to seven upper-case letters or digits. Its address is the
    /// ADR-060 V1 domain-separated BLAKE3 digest under that tag.
    ///
    /// # Errors
    /// Returns [`ErasureErrorV1::ScopeInvalid`] when the record exceeds
    /// `max_bytes` or [`ERASURE_RETAINED_OBJECT_MAX_BYTES_V1`], and
    /// [`ErasureErrorV1::InvalidEncoding`] for any other malformed record.
    pub fn new(canonical: &[u8], max_bytes: usize) -> Result<Self, ErasureErrorV1> {
        Self::from_owned(canonical.to_vec(), max_bytes)
    }

    fn from_owned(canonical_cbor: Vec<u8>, max_bytes: usize) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            &canonical_cbor,
            max_bytes.min(ERASURE_RETAINED_OBJECT_MAX_BYTES_V1),
            RETAINED_OBJECT_MAX_ARRAY,
        )
        .and_then(|value| record_tag(&value))
        .map(|tag| Self {
            reference: ErasureReferenceV1::from_digest(domain_digest(&tag, &canonical_cbor)),
            tag,
            canonical_cbor,
        })
    }

    /// The record tag that domain-separates the content address.
    #[must_use]
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// The content address of the record.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.reference
    }

    /// The exact canonical record bytes.
    #[must_use]
    pub fn canonical_cbor(&self) -> &[u8] {
        &self.canonical_cbor
    }
}

fn record_tag(value: &Value) -> Result<String, ErasureErrorV1> {
    match value {
        Value::Array(items) => match items.first() {
            Some(Value::Text(tag)) if is_record_tag(tag) => Ok(tag.clone()),
            _ => Err(ErasureErrorV1::InvalidEncoding),
        },
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}

fn is_record_tag(tag: &str) -> bool {
    let bytes = tag.as_bytes();
    (ERASURE_RECORD_TAG_MIN_BYTES_V1..=ERASURE_RECORD_TAG_MAX_BYTES_V1).contains(&bytes.len())
        && bytes[0].is_ascii_uppercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

/// One durable single-host owner effect (ADR-136 §4a).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalOwnerEffectV1 {
    /// The final key-registry tombstone of one key destruction.
    KeyTombstone {
        /// The key destruction whose pending phase is already durable.
        ///
        /// Boxed only to keep the variants of this enum a similar size
        /// (`clippy::large_enum_variant`); the value is ADR-136's unboxed
        /// `KeyDestructionRequestV1`.
        request: Box<KeyDestructionRequestV1>,
        /// The tombstone's deletion receipt.
        deletion_receipt: Hash,
    },
    /// One canonical ELAD1 artifact disposition.
    ArtifactDisposition(Vec<u8>),
    /// One canonical ELCG1 cache generation.
    CacheGeneration(Vec<u8>),
    /// One canonical ELNEG1 negative owner result.
    Negative(Vec<u8>),
}

/// One owner effect and its owner-result object, validated for one adapter
/// transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedLocalOwnerEffectV1 {
    key_tombstone: Option<(KeyDestructionRequestV1, Hash)>,
    effect_object: Option<ErasureRetainedObjectV1>,
    owner_result: ErasureRetainedObjectV1,
}

impl PreparedLocalOwnerEffectV1 {
    /// Validate one effect and its canonical ELO1 owner result.
    ///
    /// A record effect must carry its own record tag (ELAD1, ELCG1 or
    /// ELNEG1) and the owner result must be an ELO1 record.
    ///
    /// # Errors
    /// Returns [`ErasureErrorV1::InvalidEncoding`] when a record is malformed
    /// or carries another tag, and [`ErasureErrorV1::ScopeInvalid`] when one
    /// is over the retained-object bound.
    pub fn new(effect: LocalOwnerEffectV1, elo1: &[u8]) -> Result<Self, ErasureErrorV1> {
        let (key_tombstone, effect_object) = match effect {
            LocalOwnerEffectV1::KeyTombstone {
                request,
                deletion_receipt,
            } => (Some((*request, deletion_receipt)), Ok(None)),
            LocalOwnerEffectV1::ArtifactDisposition(record) => (
                None,
                tagged_object(record, "ELAD1", LOCAL_OWNER_EFFECT_MAX_BYTES_V1).map(Some),
            ),
            LocalOwnerEffectV1::CacheGeneration(record) => (
                None,
                tagged_object(record, "ELCG1", LOCAL_OWNER_EFFECT_MAX_BYTES_V1).map(Some),
            ),
            LocalOwnerEffectV1::Negative(record) => (
                None,
                tagged_object(record, "ELNEG1", LOCAL_OWNER_EFFECT_MAX_BYTES_V1).map(Some),
            ),
        };
        effect_object
            .and_then(|effect_object| {
                tagged_object(elo1.to_vec(), "ELO1", LOCAL_OWNER_RESULT_MAX_BYTES_V1)
                    .map(|owner_result| (effect_object, owner_result))
            })
            .map(|(effect_object, owner_result)| Self {
                key_tombstone,
                effect_object,
                owner_result,
            })
    }

    /// The key destruction to complete, for a key tombstone effect.
    #[must_use]
    pub const fn key_tombstone(&self) -> Option<(KeyDestructionRequestV1, Hash)> {
        self.key_tombstone
    }

    /// The effect record to retain, for a record effect.
    #[must_use]
    pub const fn effect_object(&self) -> Option<&ErasureRetainedObjectV1> {
        self.effect_object.as_ref()
    }

    /// The ELO1 owner-result object to retain.
    #[must_use]
    pub const fn owner_result(&self) -> &ErasureRetainedObjectV1 {
        &self.owner_result
    }
}

fn tagged_object(
    record: Vec<u8>,
    tag: &str,
    max_bytes: usize,
) -> Result<ErasureRetainedObjectV1, ErasureErrorV1> {
    ErasureRetainedObjectV1::from_owned(record, max_bytes).and_then(|object| {
        if object.tag() == tag {
            Ok(object)
        } else {
            Err(ErasureErrorV1::InvalidEncoding)
        }
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{KeyIdentityV1, KeyRoleV1};

    fn record(tag: &str, payload: Vec<u8>) -> Result<Vec<u8>, ErasureErrorV1> {
        super::super::encode_canonical(&Value::Array(vec![
            Value::Text(tag.to_owned()),
            Value::Bytes(payload),
        ]))
    }

    fn timeline(seed: u128) -> TimelineId {
        TimelineId::from_ulid(ulid::Ulid::from(seed))
    }

    #[test]
    fn bounds_hold_their_adr_values() {
        assert_eq!(ERASURE_RETAINED_OBJECT_MAX_BYTES_V1, 1_048_576);
        assert_eq!(RETAINED_OBJECT_MAX_ARRAY, 4_097);
        assert_eq!(LOCAL_OWNER_EFFECT_MAX_BYTES_V1, 1_024);
        assert_eq!(LOCAL_OWNER_RESULT_MAX_BYTES_V1, 4_096);
    }

    /// A record of exactly the retained-object bound is admitted under any
    /// caller bound, and one byte more is refused.
    #[test]
    fn retained_object_admits_exactly_its_byte_bound() -> Result<(), ErasureErrorV1> {
        // Array head, "ERS1" text and a four-byte byte-string head.
        let largest = record("ERS1", vec![0; ERASURE_RETAINED_OBJECT_MAX_BYTES_V1 - 11])?;
        assert_eq!(largest.len(), ERASURE_RETAINED_OBJECT_MAX_BYTES_V1);
        assert_eq!(
            ErasureRetainedObjectV1::new(&largest, usize::MAX)?.canonical_cbor(),
            largest.as_slice()
        );
        let over = record("ERS1", vec![0; ERASURE_RETAINED_OBJECT_MAX_BYTES_V1 - 10])?;
        assert_eq!(
            ErasureRetainedObjectV1::new(&over, usize::MAX),
            Err(ErasureErrorV1::ScopeInvalid)
        );
        Ok(())
    }

    /// The tag plus 4,096 entries, the largest TPS1 array, decodes; one more
    /// entry is refused.
    #[test]
    fn retained_object_admits_exactly_its_array_bound() -> Result<(), ErasureErrorV1> {
        let array = |entries: usize| {
            let mut items = vec![Value::Text("ERA1".to_owned())];
            items.resize(entries + 1, Value::Integer(0.into()));
            super::super::encode_canonical(&Value::Array(items))
        };
        let largest = array(super::super::ERASURE_MAX_OBLIGATIONS_PER_CATEGORY)?;
        assert_eq!(
            ErasureRetainedObjectV1::new(&largest, usize::MAX)?.tag(),
            "ERA1"
        );
        let over = array(super::super::ERASURE_MAX_OBLIGATIONS_PER_CATEGORY + 1)?;
        assert_eq!(
            ErasureRetainedObjectV1::new(&over, usize::MAX),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        Ok(())
    }

    #[test]
    fn retained_object_keeps_its_tag_bytes_and_tagged_address() -> Result<(), ErasureErrorV1> {
        let bytes = record("ELO1", vec![7])?;
        let object = ErasureRetainedObjectV1::new(&bytes, LOCAL_OWNER_RESULT_MAX_BYTES_V1)?;
        assert_eq!(object.tag(), "ELO1");
        assert_eq!(object.canonical_cbor(), bytes.as_slice());
        let mut preimage = b"ELO1\0".to_vec();
        preimage.extend_from_slice(&bytes);
        assert_eq!(
            object.reference(),
            ErasureReferenceV1::from_digest(*blake3::hash(&preimage).as_bytes())
        );
        assert_eq!(
            ErasureRetainedObjectV1::new(&bytes, bytes.len() - 1),
            Err(ErasureErrorV1::ScopeInvalid)
        );
        Ok(())
    }

    #[test]
    fn record_tag_is_an_upper_case_letter_then_upper_case_letters_or_digits(
    ) -> Result<(), ErasureErrorV1> {
        for tag in ["AB", "E1", "ELO1", "ELNEG1", "ABCDEFGH", "A1234567"] {
            let object = ErasureRetainedObjectV1::new(&record(tag, Vec::new())?, 1_024)?;
            assert_eq!(object.tag(), tag);
        }
        for tag in ["", "A", "ABCDEFGHI", "1A", "aB", "Ab", "A-", "ÄB"] {
            assert_eq!(
                ErasureRetainedObjectV1::new(&record(tag, Vec::new())?, 1_024),
                Err(ErasureErrorV1::InvalidEncoding),
                "{tag:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn retained_object_must_be_an_array_led_by_its_tag() -> Result<(), ErasureErrorV1> {
        for value in [
            Value::Text("ELO1".to_owned()),
            Value::Array(Vec::new()),
            Value::Array(vec![
                Value::Integer(1.into()),
                Value::Text("ELO1".to_owned()),
            ]),
            Value::Array(vec![Value::Bytes(b"ELO1".to_vec())]),
        ] {
            assert_eq!(
                ErasureRetainedObjectV1::new(&super::super::encode_canonical(&value)?, 1_024),
                Err(ErasureErrorV1::InvalidEncoding)
            );
        }
        Ok(())
    }

    #[test]
    fn snapshot_reads_back_its_rows_and_store_identity() -> Result<(), ErasureErrorV1> {
        let (first, second) = (timeline(1), timeline(2));
        let inventory =
            ErasurePersistenceInventorySnapshotV1::new(Vec::new(), vec![first, second], 4)?;
        let rows = vec![
            ErasureAuthorityTimelineRowV1 {
                id: first,
                owner: Some(EntityId::from_ulid(ulid::Ulid::from(9_u128))),
                fork_point: None,
            },
            ErasureAuthorityTimelineRowV1 {
                id: second,
                owner: None,
                fork_point: Some((first, Seq::from_u64(3))),
            },
        ];
        let identity = Hash::from_bytes([5; 32]);
        let snapshot =
            ErasureAuthoritySnapshotV1::new(inventory.clone(), rows.clone(), Some(identity))?;
        assert_eq!(snapshot.inventory(), &inventory);
        assert_eq!(snapshot.timelines(), rows.as_slice());
        assert_eq!(snapshot.timeline(first), Some(&rows[0]));
        assert_eq!(snapshot.timeline(second), Some(&rows[1]));
        assert_eq!(snapshot.timeline(timeline(3)), None);
        assert_eq!(snapshot.store_identity(), Some(identity));
        assert_eq!(
            ErasureAuthoritySnapshotV1::new(inventory, rows[..1].to_vec(), None),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
        Ok(())
    }

    #[test]
    fn prepared_effect_exposes_its_tombstone_or_effect_record() -> Result<(), ErasureErrorV1> {
        let elo1 = record("ELO1", vec![1])?;
        let request = KeyDestructionRequestV1::new(
            KeyIdentityV1::new("owner", KeyRoleV1::SubjectDataEncryption, 1),
            Hash::from_bytes([2; 32]),
            Hash::from_bytes([3; 32]),
        );
        let receipt = Hash::from_bytes([4; 32]);
        let tombstone = PreparedLocalOwnerEffectV1::new(
            LocalOwnerEffectV1::KeyTombstone {
                request: Box::new(request),
                deletion_receipt: receipt,
            },
            &elo1,
        )?;
        assert_eq!(tombstone.key_tombstone(), Some((request, receipt)));
        assert_eq!(tombstone.effect_object(), None);
        assert_eq!(tombstone.owner_result().canonical_cbor(), elo1.as_slice());

        for (effect, tag) in [
            (
                LocalOwnerEffectV1::ArtifactDisposition(record("ELAD1", vec![1])?),
                "ELAD1",
            ),
            (
                LocalOwnerEffectV1::CacheGeneration(record("ELCG1", vec![1])?),
                "ELCG1",
            ),
            (
                LocalOwnerEffectV1::Negative(record("ELNEG1", vec![1])?),
                "ELNEG1",
            ),
        ] {
            let prepared = PreparedLocalOwnerEffectV1::new(effect, &elo1)?;
            assert_eq!(prepared.key_tombstone(), None);
            assert_eq!(
                prepared.effect_object().map(ErasureRetainedObjectV1::tag),
                Some(tag)
            );
            assert_eq!(prepared.owner_result().tag(), "ELO1");
        }
        Ok(())
    }

    #[test]
    fn prepared_effect_refuses_other_tags_and_oversized_owner_results() -> Result<(), ErasureErrorV1>
    {
        let elo1 = record("ELO1", vec![1])?;
        assert_eq!(
            PreparedLocalOwnerEffectV1::new(
                LocalOwnerEffectV1::Negative(record("ELCG1", vec![1])?),
                &elo1
            ),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        let negative = || record("ELNEG1", vec![1]).map(LocalOwnerEffectV1::Negative);
        assert_eq!(
            PreparedLocalOwnerEffectV1::new(negative()?, &record("ELNEG1", vec![1])?),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        // Array head, "ELO1" text and a two-byte byte-string head.
        let largest = record("ELO1", vec![0; LOCAL_OWNER_RESULT_MAX_BYTES_V1 - 9])?;
        assert_eq!(largest.len(), LOCAL_OWNER_RESULT_MAX_BYTES_V1);
        assert_eq!(
            PreparedLocalOwnerEffectV1::new(negative()?, &largest)?
                .owner_result()
                .canonical_cbor(),
            largest.as_slice()
        );
        let over = record("ELO1", vec![0; LOCAL_OWNER_RESULT_MAX_BYTES_V1 - 8])?;
        assert_eq!(
            PreparedLocalOwnerEffectV1::new(negative()?, &over),
            Err(ErasureErrorV1::ScopeInvalid)
        );
        Ok(())
    }
}
