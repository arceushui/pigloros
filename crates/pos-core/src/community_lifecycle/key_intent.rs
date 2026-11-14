//! Clear CKP1 key-creation intent and CKU1 encryption-credit counter.
//!
//! Neither record carries private material, plaintext State identities or a
//! data value. A decoded intent cannot create, import or reopen a key: the
//! qualified owner must still match its own vault material, fingerprint,
//! inventory and current authority before any use.

use super::envelope::{
    derive_key_owner, encode_operation, read_kind, read_operation, read_owner, read_purpose,
    validate_operation,
};
use super::{
    canonical_end, digest, encode_coordinates, fixed_bytes, read_coordinates, read_hash, read_head,
    record_cursor, record_prefix, validate_coordinates, validate_horizon, CommunityArtifactKindV1,
    CommunityArtifactOperationV1, CommunityArtifactPurposeV1, CommunityLifecycleErrorV1 as Error,
    Result, MAX_COMMUNITY_MEMBERS_V1,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash, OwnerIdV1, TimelineId};
use zeroize::Zeroizing;

/// Maximum primitive encryptions one operation/purpose key may ever record.
pub const MAX_COMMUNITY_KEY_ENCRYPTION_ORDINAL_V1: u32 = 65_536;
const MAX_INTENT: usize = 65_536;
const MAX_USE: usize = 512;
const KINDS: [CommunityArtifactKindV1; 9] = [
    CommunityArtifactKindV1::StateContent,
    CommunityArtifactKindV1::StateRevisionOrHead,
    CommunityArtifactKindV1::PreparedInvocation,
    CommunityArtifactKindV1::ExecutionProvenance,
    CommunityArtifactKindV1::TraceAnnotation,
    CommunityArtifactKindV1::ReplayReceiptOrRoot,
    CommunityArtifactKindV1::LifecycleControl,
    CommunityArtifactKindV1::BoundedRecordBundle,
    CommunityArtifactKindV1::ClassificationProof,
];

/// Closed set of COH1 record kinds one key intent admits, in code order.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityRecordKindsV1(u16);

impl CommunityRecordKindsV1 {
    /// The empty set; an intent refuses it.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Return this set with one more closed record kind.
    #[must_use]
    pub const fn with(self, kind: CommunityArtifactKindV1) -> Self {
        Self(self.0 | (1 << kind.code()))
    }

    /// Whether the set admits `kind`.
    #[must_use]
    pub const fn contains(self, kind: CommunityArtifactKindV1) -> bool {
        self.0 & (1 << kind.code()) != 0
    }

    /// Iterate admitted kinds in strictly ascending code order.
    pub fn iter(self) -> impl Iterator<Item = CommunityArtifactKindV1> {
        KINDS.into_iter().filter(move |kind| self.contains(*kind))
    }
}

/// Unique admitted-roster slot indices below 64, kept in ascending order.
///
/// These are roster positions, not plaintext CMB1 or State identities.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityMemberSlotsV1(u64);

impl CommunityMemberSlotsV1 {
    /// The empty slot set, used by member-independent control keys.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Validate strictly ascending slot indices within the 64-member roster.
    ///
    /// # Errors
    /// Returns `BoundsExceeded` for a slot outside the roster and
    /// `InvalidBinding` for a duplicate or unordered slot.
    pub fn new(slots: &[u16]) -> Result<Self> {
        slots
            .iter()
            .try_fold(Self::empty(), |set, slot| set.push(*slot))
    }

    fn push(self, slot: u16) -> Result<Self> {
        if usize::from(slot) >= MAX_COMMUNITY_MEMBERS_V1 {
            Err(Error::BoundsExceeded)
        } else if self.0 >> slot != 0 {
            Err(Error::InvalidBinding)
        } else {
            // Every bit at or above `slot` is clear, so adding sets exactly it.
            Ok(Self(self.0 + (1 << slot)))
        }
    }

    /// Iterate admitted slots in strictly ascending order.
    pub fn iter(self) -> impl Iterator<Item = u16> {
        (0..64_u16).filter(move |slot| self.0 & (1 << *slot) != 0)
    }
}

/// Untrusted CKP1 fields; the qualified owner supplies the real fingerprint.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityKeyIntentInputV1 {
    /// Nonzero protection Control identity, allocated once.
    pub protection_operation_id: [u8; 16],
    /// Original pass, initialization or Control parent, in ADR-128 form.
    pub parent_operation: CommunityArtifactOperationV1,
    /// Key Timeline.
    pub timeline: TimelineId,
    /// Key generation.
    pub generation: [u8; 16],
    /// Separate key purpose partition.
    pub purpose: CommunityArtifactPurposeV1,
    /// Exact `ScopeSet` digest of the prepared scope members.
    pub scope_set_digest: Hash,
    /// Original finite horizon, never extended by a retry.
    pub evidence_not_after_micros: u64,
    /// Nonempty kinds, each admitted by `purpose`.
    pub allowed_record_kinds: CommunityRecordKindsV1,
    /// Admitted roster slots this key may protect.
    pub member_slots: CommunityMemberSlotsV1,
    /// Existing key-material fingerprint of the generated material.
    pub material_fingerprint: Hash,
    /// Exact current-authority request digest that admitted the intent.
    pub authority_request_digest: Hash,
}

/// CKP1 intent with its derived role7 key owner spelling.
///
/// No `Debug`, `Clone` or Serde form: the record names potentially personal
/// Timeline/generation metadata and is stored only by the qualified owner.
pub struct CommunityKeyIntentV1 {
    input: CommunityKeyIntentInputV1,
    owner: OwnerIdV1,
}

impl CommunityKeyIntentV1 {
    /// Validate local bindings and derive the exact Control key owner.
    ///
    /// # Errors
    /// Rejects zero identities, a foreign parent pass, an empty or
    /// purpose-incompatible kind set and an invalid horizon.
    pub fn new(input: CommunityKeyIntentInputV1) -> Result<Self> {
        if input.protection_operation_id == [0; 16]
            || [
                input.scope_set_digest,
                input.material_fingerprint,
                input.authority_request_digest,
            ]
            .contains(&Hash::zero())
            || input.allowed_record_kinds == CommunityRecordKindsV1::empty()
            || input
                .allowed_record_kinds
                .iter()
                .any(|kind| !input.purpose.admits(kind))
        {
            return Err(Error::InvalidBinding);
        }
        validate_coordinates(input.timeline, input.generation)
            .and_then(|()| {
                validate_operation(input.parent_operation, input.timeline, input.generation)
            })
            .and_then(|()| validate_horizon(input.evidence_not_after_micros))
            .and_then(|()| {
                derive_key_owner(
                    input.timeline,
                    input.generation,
                    input.purpose,
                    CommunityArtifactOperationV1::Control(input.protection_operation_id),
                )
            })
            .map(|owner| Self { input, owner })
    }

    /// Borrow the exact original intent fields; they grant no key use.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityKeyIntentInputV1 {
        &self.input
    }

    /// Exact `community:<T>:<G>:<purpose>:c:<id>` role7 key owner text.
    #[must_use]
    pub fn key_owner_text(&self) -> &str {
        self.owner.as_str()
    }

    /// Encode the exact fourteen-field CKP1 into a zeroizing buffer.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(512));
        record_prefix(&mut out, 14, *b"CKP1");
        encode_bytes(&mut out, &input.protection_operation_id, 2);
        encode_operation(&mut out, input.parent_operation);
        encode_coordinates(&mut out, input.timeline, input.generation);
        encode_head(&mut out, 0, u64::from(input.purpose.code()));
        encode_hash(&mut out, input.scope_set_digest);
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        encode_head(
            &mut out,
            4,
            input.allowed_record_kinds.iter().count() as u64,
        );
        for kind in input.allowed_record_kinds.iter() {
            encode_head(&mut out, 0, u64::from(kind.code()));
        }
        encode_head(&mut out, 4, input.member_slots.iter().count() as u64);
        for slot in input.member_slots.iter() {
            encode_head(&mut out, 0, u64::from(slot));
        }
        encode_hash(&mut out, input.material_fingerprint);
        encode_hash(&mut out, input.authority_request_digest);
        out
    }

    /// Clear intent identity `BLAKE3("PiglorOS.Community.CKP1.v1\0" || CKP1)`.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CKP1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode one complete preferred CKP1 without creating any key.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, versioned, oversized or trailing
    /// records, unordered kinds or slots and every invalid local binding.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, MAX_INTENT, 14, *b"CKP1").and_then(|mut cursor| {
            read_intent(&mut cursor)
                .and_then(|input| canonical_end(&cursor).and_then(|()| Self::new(input)))
        })
    }
}

/// CKU1 highest burned encryption ordinal for one exact key intent.
pub struct CommunityKeyUseV1 {
    protection_operation_id: [u8; 16],
    owner: OwnerIdV1,
    highest_encryption_ordinal: u32,
}

impl CommunityKeyUseV1 {
    /// Bind a burned-credit counter to its exact intent and epoch1 owner.
    ///
    /// # Errors
    /// Returns `BoundsExceeded` above the 65536-encryption key budget.
    pub const fn new(
        intent: &CommunityKeyIntentV1,
        highest_encryption_ordinal: u32,
    ) -> Result<Self> {
        if highest_encryption_ordinal > MAX_COMMUNITY_KEY_ENCRYPTION_ORDINAL_V1 {
            Err(Error::BoundsExceeded)
        } else {
            Ok(Self {
                protection_operation_id: intent.input.protection_operation_id,
                owner: intent.owner,
                highest_encryption_ordinal,
            })
        }
    }

    /// Burn the next credit before its primitive call; credits never reset.
    ///
    /// # Errors
    /// Returns `CapacityExhausted` once the key budget is spent.
    pub const fn next_credit(&self) -> Result<Self> {
        if self.highest_encryption_ordinal >= MAX_COMMUNITY_KEY_ENCRYPTION_ORDINAL_V1 {
            Err(Error::CapacityExhausted)
        } else {
            Ok(Self {
                protection_operation_id: self.protection_operation_id,
                owner: self.owner,
                highest_encryption_ordinal: self.highest_encryption_ordinal + 1,
            })
        }
    }

    /// Highest committed encryption ordinal; zero before the first call.
    #[must_use]
    pub const fn highest_encryption_ordinal(&self) -> u32 {
        self.highest_encryption_ordinal
    }

    /// Encode the exact six-field CKU1.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(MAX_USE));
        record_prefix(&mut out, 6, *b"CKU1");
        encode_bytes(&mut out, &self.protection_operation_id, 2);
        encode_bytes(&mut out, self.owner.as_str().as_bytes(), 3);
        out.push(1);
        encode_head(&mut out, 0, u64::from(self.highest_encryption_ordinal));
        out
    }

    /// Decode CKU1 against its independently retained exact intent.
    ///
    /// # Errors
    /// Rejects malformed records, another intent's identity or owner, an
    /// epoch other than 1 and an ordinal above the key budget.
    pub fn from_canonical_cbor(bytes: &[u8], intent: &CommunityKeyIntentV1) -> Result<Self> {
        record_cursor(bytes, MAX_USE, 6, *b"CKU1").and_then(|mut cursor| {
            fixed_bytes::<16>(&mut cursor).and_then(|id| {
                read_owner(&mut cursor).and_then(|owner| {
                    read_head(&mut cursor, 0).and_then(|epoch| {
                        read_head(&mut cursor, 0).and_then(|ordinal| {
                            canonical_end(&cursor).and_then(|()| {
                                if id != intent.input.protection_operation_id
                                    || owner != intent.owner
                                    || epoch != 1
                                {
                                    return Err(Error::InvalidBinding);
                                }
                                u32::try_from(ordinal)
                                    .map_err(|_| Error::BoundsExceeded)
                                    .and_then(|ordinal| Self::new(intent, ordinal))
                            })
                        })
                    })
                })
            })
        })
    }
}

fn read_intent(cursor: &mut CborCursor<'_>) -> Result<CommunityKeyIntentInputV1> {
    fixed_bytes(cursor).and_then(|protection_operation_id| {
        read_operation(cursor).and_then(|parent_operation| {
            read_coordinates(cursor).and_then(|(timeline, generation)| {
                read_purpose(cursor).and_then(|purpose| {
                    read_hash(cursor).and_then(|scope_set_digest| {
                        read_head(cursor, 0).and_then(|evidence_not_after_micros| {
                            read_kinds(cursor).and_then(|allowed_record_kinds| {
                                read_slots(cursor).and_then(|member_slots| {
                                    read_hash(cursor).and_then(|material_fingerprint| {
                                        read_hash(cursor).map(|authority_request_digest| {
                                            CommunityKeyIntentInputV1 {
                                                protection_operation_id,
                                                parent_operation,
                                                timeline,
                                                generation,
                                                purpose,
                                                scope_set_digest,
                                                evidence_not_after_micros,
                                                allowed_record_kinds,
                                                member_slots,
                                                material_fingerprint,
                                                authority_request_digest,
                                            }
                                        })
                                    })
                                })
                            })
                        })
                    })
                })
            })
        })
    })
}

fn read_kinds(cursor: &mut CborCursor<'_>) -> Result<CommunityRecordKindsV1> {
    read_head(cursor, 4).and_then(|count| {
        if count > KINDS.len() as u64 {
            return Err(Error::BoundsExceeded);
        }
        (0..count).try_fold(CommunityRecordKindsV1::empty(), |kinds, _| {
            read_kind(cursor).and_then(|kind| {
                if kinds.0 >> kind.code() == 0 {
                    Ok(kinds.with(kind))
                } else {
                    Err(Error::InvalidBinding)
                }
            })
        })
    })
}

fn read_slots(cursor: &mut CborCursor<'_>) -> Result<CommunityMemberSlotsV1> {
    read_head(cursor, 4).and_then(|count| {
        if count > MAX_COMMUNITY_MEMBERS_V1 as u64 {
            return Err(Error::BoundsExceeded);
        }
        (0..count).try_fold(CommunityMemberSlotsV1::empty(), |slots, _| {
            read_head(cursor, 0).and_then(|slot| {
                u16::try_from(slot)
                    .map_err(|_| Error::BoundsExceeded)
                    .and_then(|slot| slots.push(slot))
            })
        })
    })
}
