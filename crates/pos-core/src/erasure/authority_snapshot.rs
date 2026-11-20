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
//!
//! [`RecipientExportWithdrawalRowV1`] and
//! [`RecipientExportWithdrawalBindingV1`] carry ADR-138's recipient-export
//! withdrawal state into the snapshot and the owner-effect commit.

use super::{
    decode_limited, domain_digest, ErasureErrorV1, ErasurePersistenceInventorySnapshotV1,
    ErasureReferenceV1, LocalErasureNegativeResultV1, LocalErasureOwnerResultV1,
    LocalErasureRecipientExportWithdrawalV1,
};
use crate::{
    clock::Seq,
    ids::{EntityId, TimelineId},
    Hash, KeyDestructionRequestV1, KeyTombstoneV1, OwnerIdV1,
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

/// The largest ELAD1, ELCG1, ELNEG1, ELRP1 or ELXW1 owner-effect record
/// (ADR-136 §4a, ADR-138 §5).
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

/// The recipient-export withdrawal row of one requested `ELXR1` target
/// (ADR-138 §3 and §5).
///
/// A row without a `disposition` is retracted: its publication is no longer
/// served but is not yet withdrawn. A withdrawn row carries `CA(ELXW1)` and
/// the address of the ELO1 that first committed it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecipientExportWithdrawalRowV1 {
    /// `CA("ELXR1", [export_id, grantee_owner])`.
    pub target: ErasureReferenceV1,
    /// The 16-byte export identity.
    pub export_id: [u8; 16],
    /// `CA(ELXW1)` once withdrawn.
    pub disposition: Option<ErasureReferenceV1>,
    /// `CA(ELO1)` of the first commit, once withdrawn.
    pub committed_elo1: Option<ErasureReferenceV1>,
}

/// One same-snapshot read of everything the single-host authority may
/// evaluate as evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureAuthoritySnapshotV1 {
    inventory: ErasurePersistenceInventorySnapshotV1,
    timelines: Vec<ErasureAuthorityTimelineRowV1>,
    store_identity: Option<Hash>,
    recipient_export_withdrawals: Vec<RecipientExportWithdrawalRowV1>,
}

impl ErasureAuthoritySnapshotV1 {
    /// Package one adapter read.
    ///
    /// `recipient_export_withdrawals` holds the withdrawal rows of the
    /// requested `export_targets` that exist (ADR-138 §5).
    ///
    /// # Errors
    /// Returns [`ErasureErrorV1::ProvenanceMissing`] unless the Timeline rows
    /// name exactly the inventory topology, in the same strictly increasing
    /// order.
    pub fn new(
        inventory: ErasurePersistenceInventorySnapshotV1,
        timelines: Vec<ErasureAuthorityTimelineRowV1>,
        store_identity: Option<Hash>,
        recipient_export_withdrawals: Vec<RecipientExportWithdrawalRowV1>,
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
                recipient_export_withdrawals,
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

    /// The withdrawal rows of the requested `export_targets`, one per target
    /// that has one, in increasing target order.
    #[must_use]
    pub fn recipient_export_withdrawals(&self) -> &[RecipientExportWithdrawalRowV1] {
        &self.recipient_export_withdrawals
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
    /// A key tombstone the registry already holds, whatever authorization
    /// committed it (owner decision Q5 on #1430): an owner command over an
    /// already destroyed key binds its ELO1 to this tombstone's existing
    /// deletion receipt. The adapter commits nothing but the ELO1, and only
    /// while the registry holds exactly this tombstone. Boxed like
    /// [`Self::KeyTombstone`].
    ExistingTombstone(Box<KeyTombstoneV1>),
    /// One canonical ELAD1 artifact disposition.
    ArtifactDisposition(Vec<u8>),
    /// One canonical ELCG1 cache generation.
    CacheGeneration(Vec<u8>),
    /// One canonical ELNEG1 negative owner result, bound only by an ELO1
    /// that names it as its `effect_digest` and carries its command, owner
    /// reference and closed error code.
    Negative(Vec<u8>),
    /// One canonical ELRP1 local-replica purge, committed after the purge.
    ReplicaPurge(Vec<u8>),
    /// One canonical ELXW1 recipient-export withdrawal (ADR-138 §5),
    /// committed after its owner step deleted the captured objects.
    RecipientExportWithdrawal(Vec<u8>),
}

/// The fields of one ELXW1 that its first commit compares with the
/// withdrawal row (ADR-138 §5, T3), parsed once by
/// [`PreparedLocalOwnerEffectV1::new`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecipientExportWithdrawalBindingV1 {
    /// The 16-byte export identity.
    pub export_id: [u8; 16],
    /// The Timeline the export was published from.
    pub timeline_id: TimelineId,
    /// The recipient owner of the grantee the export was encrypted for.
    pub grantee_owner: OwnerIdV1,
    /// The BLAKE3 digest of the complete stored ciphertext.
    pub ciphertext_digest: Hash,
    /// The stored ciphertext length in bytes.
    pub ciphertext_length: u64,
    /// The custody directory's big-endian `(device, inode)`.
    pub directory_identity: [u8; 16],
    /// The deleted final object's big-endian `(device, inode, uid)`.
    pub final_identity: [u8; 20],
}

impl From<&LocalErasureRecipientExportWithdrawalV1> for RecipientExportWithdrawalBindingV1 {
    fn from(record: &LocalErasureRecipientExportWithdrawalV1) -> Self {
        Self {
            export_id: record.export_id,
            timeline_id: record.timeline_id,
            grantee_owner: record.grantee_owner,
            ciphertext_digest: record.ciphertext_digest,
            ciphertext_length: record.ciphertext_length,
            directory_identity: record.directory_identity,
            final_identity: record.final_identity,
        }
    }
}

/// The fields of one ELO1 owner result except its `effect_digest`.
///
/// [`PreparedLocalOwnerEffectV1::new`] derives that digest from the effect
/// the ELO1 binds, so a committed ELO1 can never name another effect
/// (owner decision of 2026-11-18 on #1430).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalOwnerResultBindingV1 {
    /// The ERQ1 request.
    pub request: ErasureReferenceV1,
    /// The attempt.
    pub attempt: ErasureReferenceV1,
    /// The obligation.
    pub obligation: ErasureReferenceV1,
    /// The destruction command.
    pub command: ErasureReferenceV1,
    /// The owner reference.
    pub owner_ref: ErasureReferenceV1,
    /// `None` for a positive result, else the negative result's closed code.
    pub error: Option<ErasureErrorV1>,
}

/// One owner effect and the ELO1 owner result that binds it, validated for
/// one adapter transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedLocalOwnerEffectV1 {
    key_tombstone: Option<(KeyDestructionRequestV1, Hash)>,
    existing_tombstone: Option<KeyTombstoneV1>,
    recipient_export_withdrawal: Option<RecipientExportWithdrawalBindingV1>,
    effect_object: Option<ErasureRetainedObjectV1>,
    owner_result: ErasureRetainedObjectV1,
}

impl PreparedLocalOwnerEffectV1 {
    /// Validate one effect and assemble the canonical ELO1 of `binding` that
    /// binds it.
    ///
    /// The ELO1 `effect_digest` is derived here, never supplied: the new or
    /// existing key tombstone's deletion receipt, or the content address `CA(effect)` of
    /// the ELAD1, ELCG1, ELNEG1, ELRP1 or ELXW1 record (ADR-136 §4a). A record
    /// effect must carry its own record tag. An ELNEG1 must be canonical and
    /// carry the binding's command, owner reference and closed error code. An
    /// ELXW1 must be canonical, and its fields are kept for the adapter's
    /// row checks (ADR-138 §5, T3).
    ///
    /// # Errors
    /// Returns [`ErasureErrorV1::InvalidEncoding`] when a record is malformed
    /// or carries another tag, [`ErasureErrorV1::ScopeInvalid`] when one is
    /// over the retained-object bound, and
    /// [`ErasureErrorV1::ProvenanceMissing`] when the binding does not carry
    /// its ELNEG1's command, owner reference and code.
    pub fn new(
        effect: LocalOwnerEffectV1,
        binding: LocalOwnerResultBindingV1,
    ) -> Result<Self, ErasureErrorV1> {
        let (key_tombstone, existing_tombstone, recipient_export_withdrawal, effect) =
            effect_parts(effect, &binding);
        effect
            .and_then(|(effect_digest, effect_object)| {
                owner_result_object(&binding, effect_digest)
                    .map(|owner_result| (effect_object, owner_result))
            })
            .map(|(effect_object, owner_result)| Self {
                key_tombstone,
                existing_tombstone,
                recipient_export_withdrawal,
                effect_object,
                owner_result,
            })
    }

    /// The key destruction to complete, for a key tombstone effect.
    #[must_use]
    pub const fn key_tombstone(&self) -> Option<(KeyDestructionRequestV1, Hash)> {
        self.key_tombstone
    }

    /// The tombstone the registry must already hold, for an existing
    /// tombstone effect.
    #[must_use]
    pub const fn existing_tombstone(&self) -> Option<KeyTombstoneV1> {
        self.existing_tombstone
    }

    /// The parsed ELXW1 fields, for a recipient-export withdrawal effect
    /// (ADR-138 §5, T3); [`Self::effect_object`] is then the ELXW1 itself.
    #[must_use]
    pub const fn recipient_export_withdrawal(&self) -> Option<RecipientExportWithdrawalBindingV1> {
        self.recipient_export_withdrawal
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

/// The tombstones, the recipient-export withdrawal binding and the ELO1
/// effect digest and object of one owner effect, with an ELNEG1 checked
/// against `binding`.
fn effect_parts(effect: LocalOwnerEffectV1, binding: &LocalOwnerResultBindingV1) -> EffectPartsV1 {
    let tag = effect_tag(&effect);
    match effect {
        LocalOwnerEffectV1::KeyTombstone {
            request,
            deletion_receipt,
        } => (
            Some((*request, deletion_receipt)),
            None,
            None,
            Ok((receipt_digest(deletion_receipt), None)),
        ),
        LocalOwnerEffectV1::ExistingTombstone(tombstone) => (
            None,
            Some(*tombstone),
            None,
            Ok((receipt_digest(tombstone.deletion_receipt), None)),
        ),
        LocalOwnerEffectV1::Negative(record) => (
            None,
            None,
            None,
            negative_bound_by(&record, binding).and_then(|()| record_effect(record, tag)),
        ),
        LocalOwnerEffectV1::RecipientExportWithdrawal(record) => {
            let withdrawal = LocalErasureRecipientExportWithdrawalV1::from_canonical_cbor(&record)
                .map(|elxw1| RecipientExportWithdrawalBindingV1::from(&elxw1));
            (
                None,
                None,
                withdrawal.as_ref().ok().copied(),
                withdrawal.and_then(|_| record_effect(record, tag)),
            )
        }
        LocalOwnerEffectV1::ArtifactDisposition(record)
        | LocalOwnerEffectV1::CacheGeneration(record)
        | LocalOwnerEffectV1::ReplicaPurge(record) => {
            (None, None, None, record_effect(record, tag))
        }
    }
}

/// The tag of the record `effect` commits beside its ELO1; a tombstone
/// commits none.
const fn effect_tag(effect: &LocalOwnerEffectV1) -> &'static str {
    match effect {
        LocalOwnerEffectV1::KeyTombstone { .. } | LocalOwnerEffectV1::ExistingTombstone(_) => "",
        LocalOwnerEffectV1::ArtifactDisposition(_) => "ELAD1",
        LocalOwnerEffectV1::CacheGeneration(_) => "ELCG1",
        LocalOwnerEffectV1::Negative(_) => "ELNEG1",
        LocalOwnerEffectV1::ReplicaPurge(_) => "ELRP1",
        LocalOwnerEffectV1::RecipientExportWithdrawal(_) => "ELXW1",
    }
}

/// The parts [`effect_parts`] splits one owner effect into.
type EffectPartsV1 = (
    Option<(KeyDestructionRequestV1, Hash)>,
    Option<KeyTombstoneV1>,
    Option<RecipientExportWithdrawalBindingV1>,
    Result<(ErasureReferenceV1, Option<ErasureRetainedObjectV1>), ErasureErrorV1>,
);

/// The canonical ELO1 of `binding` over `effect_digest`.
fn owner_result_object(
    binding: &LocalOwnerResultBindingV1,
    effect_digest: ErasureReferenceV1,
) -> Result<ErasureRetainedObjectV1, ErasureErrorV1> {
    LocalErasureOwnerResultV1 {
        request: binding.request,
        attempt: binding.attempt,
        obligation: binding.obligation,
        command: binding.command,
        owner_ref: binding.owner_ref,
        error: binding.error,
        effect_digest,
    }
    .to_canonical_cbor()
    .and_then(|elo1| tagged_object(elo1, "ELO1", LOCAL_OWNER_RESULT_MAX_BYTES_V1))
}

/// A deletion receipt as the ELO1 effect digest of its tombstone.
const fn receipt_digest(receipt: Hash) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest(*receipt.as_bytes())
}

/// One record effect of `tag`: its content address and its object.
fn record_effect(
    record: Vec<u8>,
    tag: &str,
) -> Result<(ErasureReferenceV1, Option<ErasureRetainedObjectV1>), ErasureErrorV1> {
    tagged_object(record, tag, LOCAL_OWNER_EFFECT_MAX_BYTES_V1)
        .map(|object| (object.reference(), Some(object)))
}

/// Whether `binding` carries the command, owner reference and closed error
/// code of canonical ELNEG1 `elneg1` (ADR-136 §4a).
fn negative_bound_by(
    elneg1: &[u8],
    binding: &LocalOwnerResultBindingV1,
) -> Result<(), ErasureErrorV1> {
    LocalErasureNegativeResultV1::from_canonical_cbor(elneg1).and_then(|negative| {
        if binding.command == negative.command
            && binding.owner_ref == negative.owner_ref
            && binding.error == Some(negative.error)
        {
            Ok(())
        } else {
            Err(ErasureErrorV1::ProvenanceMissing)
        }
    })
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

    /// A canonical ELNEG1 and the negative binding that carries it.
    fn negative_pair() -> Result<(Vec<u8>, LocalOwnerResultBindingV1), ErasureErrorV1> {
        let negative = LocalErasureNegativeResultV1 {
            command: ErasureReferenceV1::from_digest([1; 32]),
            owner_ref: ErasureReferenceV1::from_digest([2; 32]),
            error: ErasureErrorV1::ArtifactDeletionFailed,
        };
        Ok((
            negative.to_canonical_cbor()?,
            LocalOwnerResultBindingV1 {
                request: ErasureReferenceV1::from_digest([3; 32]),
                attempt: ErasureReferenceV1::from_digest([4; 32]),
                obligation: ErasureReferenceV1::from_digest([5; 32]),
                command: negative.command,
                owner_ref: negative.owner_ref,
                error: Some(negative.error),
            },
        ))
    }

    /// The ELO1 a prepared effect assembled.
    fn elo1(
        prepared: &PreparedLocalOwnerEffectV1,
    ) -> Result<LocalErasureOwnerResultV1, ErasureErrorV1> {
        LocalErasureOwnerResultV1::from_canonical_cbor(prepared.owner_result().canonical_cbor())
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
        let withdrawals = vec![RecipientExportWithdrawalRowV1 {
            target: ErasureReferenceV1::from_digest([6; 32]),
            export_id: [7; 16],
            disposition: None,
            committed_elo1: None,
        }];
        let snapshot = ErasureAuthoritySnapshotV1::new(
            inventory.clone(),
            rows.clone(),
            Some(identity),
            withdrawals.clone(),
        )?;
        assert_eq!(snapshot.inventory(), &inventory);
        assert_eq!(
            snapshot.recipient_export_withdrawals(),
            withdrawals.as_slice()
        );
        assert_eq!(snapshot.timelines(), rows.as_slice());
        assert_eq!(snapshot.timeline(first), Some(&rows[0]));
        assert_eq!(snapshot.timeline(second), Some(&rows[1]));
        assert_eq!(snapshot.timeline(timeline(3)), None);
        assert_eq!(snapshot.store_identity(), Some(identity));
        assert_eq!(
            ErasureAuthoritySnapshotV1::new(inventory, rows[..1].to_vec(), None, Vec::new()),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
        Ok(())
    }

    #[test]
    fn prepared_effect_derives_its_elo1_effect_digest() -> Result<(), ErasureErrorV1> {
        let (elneg1, binding) = negative_pair()?;
        let request = KeyDestructionRequestV1::new(
            KeyIdentityV1::new("owner", KeyRoleV1::SubjectDataEncryption, 1),
            Hash::from_bytes([2; 32]),
            Hash::from_bytes([3; 32]),
        );
        let receipt = Hash::from_bytes([4; 32]);
        let positive = LocalOwnerResultBindingV1 {
            error: None,
            ..binding
        };
        let tombstone = PreparedLocalOwnerEffectV1::new(
            LocalOwnerEffectV1::KeyTombstone {
                request: Box::new(request),
                deletion_receipt: receipt,
            },
            positive,
        )?;
        assert_eq!(tombstone.key_tombstone(), Some((request, receipt)));
        assert_eq!(tombstone.existing_tombstone(), None);
        assert_eq!(tombstone.effect_object(), None);
        assert_eq!(
            elo1(&tombstone)?,
            LocalErasureOwnerResultV1 {
                request: binding.request,
                attempt: binding.attempt,
                obligation: binding.obligation,
                command: binding.command,
                owner_ref: binding.owner_ref,
                error: None,
                effect_digest: ErasureReferenceV1::from_digest([4; 32]),
            }
        );

        let held = KeyTombstoneV1 {
            identity: request.identity,
            destroyed_material_digest: Hash::from_bytes([2; 32]),
            destruction_digest: Hash::from_bytes([6; 32]),
            deletion_receipt: Hash::from_bytes([7; 32]),
        };
        let existing = PreparedLocalOwnerEffectV1::new(
            LocalOwnerEffectV1::ExistingTombstone(Box::new(held)),
            positive,
        )?;
        assert_eq!(existing.existing_tombstone(), Some(held));
        assert_eq!(existing.key_tombstone(), None);
        assert_eq!(existing.effect_object(), None);
        assert_eq!(
            elo1(&existing)?.effect_digest,
            ErasureReferenceV1::from_digest([7; 32])
        );

        for (effect, tag, owner) in [
            (
                LocalOwnerEffectV1::ArtifactDisposition(record("ELAD1", vec![1])?),
                "ELAD1",
                positive,
            ),
            (
                LocalOwnerEffectV1::CacheGeneration(record("ELCG1", vec![1])?),
                "ELCG1",
                positive,
            ),
            (LocalOwnerEffectV1::Negative(elneg1), "ELNEG1", binding),
            (
                LocalOwnerEffectV1::ReplicaPurge(record("ELRP1", vec![1])?),
                "ELRP1",
                positive,
            ),
        ] {
            let prepared = PreparedLocalOwnerEffectV1::new(effect, owner)?;
            let object = prepared
                .effect_object()
                .ok_or(ErasureErrorV1::ProvenanceMissing)?;
            assert_eq!(prepared.key_tombstone(), None);
            assert_eq!(object.tag(), tag);
            assert_eq!(prepared.owner_result().tag(), "ELO1");
            assert_eq!(elo1(&prepared)?.effect_digest, object.reference());
            assert_eq!(elo1(&prepared)?.error, owner.error);
        }
        Ok(())
    }

    #[test]
    fn prepared_effect_refuses_other_tags_oversized_effects_and_unbound_negatives(
    ) -> Result<(), ErasureErrorV1> {
        let (elneg1, binding) = negative_pair()?;
        assert_eq!(
            PreparedLocalOwnerEffectV1::new(
                LocalOwnerEffectV1::ReplicaPurge(record("ELCG1", vec![1])?),
                binding
            ),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        // Only a canonical ELNEG1 is a negative effect.
        assert_eq!(
            PreparedLocalOwnerEffectV1::new(
                LocalOwnerEffectV1::Negative(record("ELNEG1", vec![1])?),
                binding
            ),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        // The binding must carry the ELNEG1's command, owner and code.
        for unbound in [
            LocalOwnerResultBindingV1 {
                command: ErasureReferenceV1::from_digest([9; 32]),
                ..binding
            },
            LocalOwnerResultBindingV1 {
                owner_ref: ErasureReferenceV1::from_digest([9; 32]),
                ..binding
            },
            LocalOwnerResultBindingV1 {
                error: Some(ErasureErrorV1::ReplicaTimeout),
                ..binding
            },
            LocalOwnerResultBindingV1 {
                error: None,
                ..binding
            },
        ] {
            assert_eq!(
                PreparedLocalOwnerEffectV1::new(
                    LocalOwnerEffectV1::Negative(elneg1.clone()),
                    unbound
                ),
                Err(ErasureErrorV1::ProvenanceMissing)
            );
        }
        // Array head, "ELRP1" text and a two-byte byte-string head.
        let largest_effect = record("ELRP1", vec![0; LOCAL_OWNER_EFFECT_MAX_BYTES_V1 - 10])?;
        assert_eq!(largest_effect.len(), LOCAL_OWNER_EFFECT_MAX_BYTES_V1);
        assert_eq!(
            PreparedLocalOwnerEffectV1::new(
                LocalOwnerEffectV1::ReplicaPurge(largest_effect.clone()),
                binding
            )?
            .effect_object()
            .map(ErasureRetainedObjectV1::canonical_cbor),
            Some(largest_effect.as_slice())
        );
        let over_effect = record("ELRP1", vec![0; LOCAL_OWNER_EFFECT_MAX_BYTES_V1 - 9])?;
        assert_eq!(over_effect.len(), LOCAL_OWNER_EFFECT_MAX_BYTES_V1 + 1);
        assert_eq!(
            PreparedLocalOwnerEffectV1::new(LocalOwnerEffectV1::ReplicaPurge(over_effect), binding),
            Err(ErasureErrorV1::ScopeInvalid)
        );
        Ok(())
    }
}
