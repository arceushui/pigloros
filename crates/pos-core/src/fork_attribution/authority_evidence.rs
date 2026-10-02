//! ADR-105 evidence records carried inside `FAE1`.
//!
//! `IKR1`/`IKT1` are verification-only projections of a source key record and
//! tombstone; they never enter local `KeyRegistryStateV1`. `FEE1` carries one
//! exact #202 Event, and `FTI1` projects the exact #202 `TimelineExport`
//! metadata. None of these values is creator or publication authority.

use super::{
    array, authority_wire, bytes, canonical, hash, text, timeline, uint,
    ForkAttributionCodecErrorV1 as Error, Reader,
};
use crate::{
    CanonicalBytes, EntityId, Event, EventOriginV1, Hash, KeyIdentityV1, KeyRecordV1, KeyRoleV1,
    KeyTombstoneV1, PublicKey, SchemaVersion, Seq, Signature, Timeline,
    TimelineEventEnvelopeErrorV1, TimelineEventEnvelopeV1, TimelineExport, TimelineId,
    TimelineMeta, TimelineMode, MAX_TIMELINE_EVENT_ENVELOPE_BYTES_V1,
    MAX_TIMELINE_EVENT_PAYLOAD_BYTES_V1,
};

/// Maximum accepted canonical `IKR1` bytes, as carried by `FAE1` field 14.
pub const MAX_IMPORTED_KEY_RECORD_BYTES_V1: usize = 512;
/// Maximum accepted canonical `IKT1` bytes, as carried by `FAE1` field 15.
pub const MAX_IMPORTED_KEY_TOMBSTONE_BYTES_V1: usize = 512;
/// Maximum accepted canonical `FTI1` bytes, as carried by `FAE1` field 17.
pub const MAX_FORK_TIMELINE_IMPORT_BYTES_V1: usize = 1_024;
/// Maximum exact UTF-8 bytes of the optional `FTI1` Timeline name.
pub const MAX_FORK_TIMELINE_IMPORT_NAME_BYTES_V1: usize = 256;
/// Largest canonical `FEE1`, derived from its field bounds.
///
/// The sum is the array head (1), marker (5), version (1), a 512-byte
/// envelope with its 3-byte head, a 16 MiB payload with its 5-byte head, and
/// a 64-byte signature with its 2-byte head.
pub const MAX_FORK_EVENT_EVIDENCE_BYTES_V1: usize = 1
    + 5
    + 1
    + 3
    + MAX_TIMELINE_EVENT_ENVELOPE_BYTES_V1
    + 5
    + MAX_TIMELINE_EVENT_PAYLOAD_BYTES_V1
    + 2
    + 64;

/// Verification-only `IKR1` projection of a source `KeyRecordV1`.
///
/// It never registers, activates, or authorizes a local key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportedKeyRecordV1 {
    identity: KeyIdentityV1,
    private_material_digest: Option<Hash>,
    public_verification_key: PublicKey,
}

impl ImportedKeyRecordV1 {
    /// Construct one source attribution-signing key projection.
    ///
    /// A `None` material digest means the source key was destroyed.
    ///
    /// # Errors
    /// Rejects a role other than `SubjectAttributionSigning`, a zero epoch,
    /// or a zero material digest.
    pub fn new(
        identity: KeyIdentityV1,
        private_material_digest: Option<Hash>,
        public_verification_key: PublicKey,
    ) -> Result<Self, Error> {
        attribution_identity(identity)?;
        if private_material_digest == Some(Hash::zero()) {
            return Err(Error::FieldOutOfBounds);
        }
        Ok(Self {
            identity,
            private_material_digest,
            public_verification_key,
        })
    }

    /// Project the exact retained source `KeyRecordV1`.
    ///
    /// # Errors
    /// Rejects a record without a retained public verification key, or any
    /// identity or digest that [`Self::new`] rejects.
    pub fn from_key_record(record: &KeyRecordV1) -> Result<Self, Error> {
        record
            .public_verification_key
            .ok_or(Error::FieldOutOfBounds)
            .and_then(|key| Self::new(record.identity, record.private_material_digest, key))
    }

    #[must_use]
    pub const fn identity(&self) -> KeyIdentityV1 {
        self.identity
    }

    #[must_use]
    pub const fn private_material_digest(&self) -> Option<Hash> {
        self.private_material_digest
    }

    #[must_use]
    pub const fn public_verification_key(&self) -> PublicKey {
        self.public_verification_key
    }

    /// Require the source lifecycle shape: a live key has no tombstone, and a
    /// destroyed key has exactly one tombstone for the same identity.
    ///
    /// # Errors
    /// Returns `FieldMismatch` for any other combination.
    pub fn validate_tombstone(
        &self,
        tombstone: Option<&ImportedKeyTombstoneV1>,
    ) -> Result<(), Error> {
        let consistent = match (self.private_material_digest, tombstone) {
            (Some(_), None) => true,
            (None, Some(tombstone)) => tombstone.identity == self.identity,
            _ => false,
        };
        if consistent {
            Ok(())
        } else {
            Err(Error::FieldMismatch)
        }
    }

    /// Encode the exact seven-field deterministic-CBOR `IKR1` array.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        array(&mut out, 7);
        text(&mut out, "IKR1");
        uint(&mut out, 1);
        encode_identity(&mut out, self.identity);
        authority_wire::optional_hash(&mut out, self.private_material_digest);
        bytes(&mut out, self.public_verification_key.as_bytes());
        out
    }

    /// Decode exact canonical `IKR1` bytes.
    ///
    /// # Errors
    /// Rejects malformed, out-of-bounds, unsupported-version, or noncanonical bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, Error> {
        let mut wire = Reader::new(bytes_in, MAX_IMPORTED_KEY_RECORD_BYTES_V1)?;
        wire.array(7)?;
        wire.magic("IKR1")?;
        wire.version()?;
        let identity = read_identity(&mut wire)?;
        let private_material_digest = wire.optional_hash()?;
        let public_verification_key = PublicKey::from_bytes(wire.fixed()?);
        wire.finish()?;
        let record = Self::new(identity, private_material_digest, public_verification_key)?;
        canonical(bytes_in, &record.to_canonical_cbor())?;
        Ok(record)
    }
}

/// Verification-only `IKT1` projection of a source `KeyTombstoneV1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportedKeyTombstoneV1 {
    identity: KeyIdentityV1,
    destroyed_material_digest: Hash,
    destruction_digest: Hash,
    deletion_receipt: Hash,
}

impl ImportedKeyTombstoneV1 {
    /// Construct one source attribution-signing tombstone projection.
    ///
    /// # Errors
    /// Rejects a role other than `SubjectAttributionSigning`, a zero epoch,
    /// or any zero digest.
    pub fn new(
        identity: KeyIdentityV1,
        destroyed_material_digest: Hash,
        destruction_digest: Hash,
        deletion_receipt: Hash,
    ) -> Result<Self, Error> {
        attribution_identity(identity)?;
        if [
            destroyed_material_digest,
            destruction_digest,
            deletion_receipt,
        ]
        .contains(&Hash::zero())
        {
            return Err(Error::FieldOutOfBounds);
        }
        Ok(Self {
            identity,
            destroyed_material_digest,
            destruction_digest,
            deletion_receipt,
        })
    }

    /// Project the exact source `KeyTombstoneV1`.
    ///
    /// # Errors
    /// Rejects any identity or digest that [`Self::new`] rejects.
    pub fn from_tombstone(tombstone: &KeyTombstoneV1) -> Result<Self, Error> {
        Self::new(
            tombstone.identity,
            tombstone.destroyed_material_digest,
            tombstone.destruction_digest,
            tombstone.deletion_receipt,
        )
    }

    #[must_use]
    pub const fn identity(&self) -> KeyIdentityV1 {
        self.identity
    }

    #[must_use]
    pub const fn destroyed_material_digest(&self) -> Hash {
        self.destroyed_material_digest
    }

    #[must_use]
    pub const fn destruction_digest(&self) -> Hash {
        self.destruction_digest
    }

    #[must_use]
    pub const fn deletion_receipt(&self) -> Hash {
        self.deletion_receipt
    }

    /// Encode the exact eight-field deterministic-CBOR `IKT1` array.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        array(&mut out, 8);
        text(&mut out, "IKT1");
        uint(&mut out, 1);
        encode_identity(&mut out, self.identity);
        hash(&mut out, self.destroyed_material_digest);
        hash(&mut out, self.destruction_digest);
        hash(&mut out, self.deletion_receipt);
        out
    }

    /// Decode exact canonical `IKT1` bytes.
    ///
    /// # Errors
    /// Rejects malformed, out-of-bounds, unsupported-version, or noncanonical bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, Error> {
        let mut wire = Reader::new(bytes_in, MAX_IMPORTED_KEY_TOMBSTONE_BYTES_V1)?;
        wire.array(8)?;
        wire.magic("IKT1")?;
        wire.version()?;
        let identity = read_identity(&mut wire)?;
        let destroyed_material_digest = wire.hash()?;
        let destruction_digest = wire.hash()?;
        let deletion_receipt = wire.hash()?;
        wire.finish()?;
        let record = Self::new(
            identity,
            destroyed_material_digest,
            destruction_digest,
            deletion_receipt,
        )?;
        canonical(bytes_in, &record.to_canonical_cbor())?;
        Ok(record)
    }
}

/// One `FEE1` evidence carrier for an exact #202 child-segment Event.
///
/// It is not a new Event signature format: the envelope, payload, and
/// `TimelineIntegritySigning` signature are carried exactly. Construction
/// checks only payload binding, never the signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkEventEvidenceV1 {
    envelope: TimelineEventEnvelopeV1,
    payload: CanonicalBytes,
    signature: Signature,
}

impl ForkEventEvidenceV1 {
    /// Bind one exact envelope to its exact payload and signature bytes.
    ///
    /// # Errors
    /// Returns `FieldOutOfBounds` for an oversized payload and
    /// `FieldMismatch` for a payload-hash mismatch or a schema
    /// version that no V1 Event can carry.
    pub fn new(
        envelope: TimelineEventEnvelopeV1,
        payload: CanonicalBytes,
        signature: Signature,
    ) -> Result<Self, Error> {
        envelope.validate_payload(&payload).map_err(|error| {
            if error == TimelineEventEnvelopeErrorV1::FieldOutOfBounds {
                Error::FieldOutOfBounds
            } else {
                Error::FieldMismatch
            }
        })?;
        if envelope.input().schema_version != SchemaVersion::V1.as_u32() {
            return Err(Error::FieldMismatch);
        }
        Ok(Self {
            envelope,
            payload,
            signature,
        })
    }

    /// Project one exported, signed, own-segment Event.
    ///
    /// # Errors
    /// Returns `FieldMismatch` for an Event without its first-commit
    /// envelope context or signature, or whose payload hash disagrees.
    pub fn from_event(event: &Event) -> Result<Self, Error> {
        let envelope = TimelineEventEnvelopeV1::from_committed_event(event)
            .map_err(|_| Error::FieldMismatch)?;
        let signature = event.signature.ok_or(Error::FieldMismatch)?;
        Self::new(envelope, event.payload.clone(), signature)
    }

    #[must_use]
    pub const fn envelope(&self) -> &TimelineEventEnvelopeV1 {
        &self.envelope
    }

    #[must_use]
    pub const fn payload(&self) -> &CanonicalBytes {
        &self.payload
    }

    #[must_use]
    pub const fn signature(&self) -> Signature {
        self.signature
    }

    /// Encode the exact five-field deterministic-CBOR `FEE1` array.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.payload.len() + 640);
        self.encode(&mut out);
        out
    }

    /// Decode exact canonical `FEE1` bytes.
    ///
    /// # Errors
    /// Rejects malformed, out-of-bounds, unsupported-version, mismatched, or
    /// noncanonical bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, Error> {
        let mut wire = Reader::new(bytes_in, MAX_FORK_EVENT_EVIDENCE_BYTES_V1)?;
        let record = Self::read(&mut wire)?;
        wire.finish()?;
        canonical(bytes_in, &record.to_canonical_cbor())?;
        Ok(record)
    }

    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        array(out, 5);
        text(out, "FEE1");
        uint(out, 1);
        bytes(out, self.envelope.canonical_bytes());
        bytes(out, self.payload.as_slice());
        bytes(out, self.signature.as_bytes());
    }

    /// Read one inline `FEE1`; the caller owns the outer canonical check.
    pub(super) fn read(wire: &mut Reader<'_>) -> Result<Self, Error> {
        wire.array(5)?;
        wire.magic("FEE1")?;
        wire.version()?;
        let envelope = TimelineEventEnvelopeV1::from_canonical_bytes(
            wire.record(MAX_TIMELINE_EVENT_ENVELOPE_BYTES_V1)?,
        )
        .map_err(|_| Error::InvalidEncoding)?;
        let payload =
            CanonicalBytes::from_vec(wire.bytes(MAX_TIMELINE_EVENT_PAYLOAD_BYTES_V1)?.to_vec());
        let signature = Signature::from_bytes(wire.fixed()?);
        Self::new(envelope, payload, signature)
    }

    /// Reconstruct the exported own-segment Event at one child-local sequence.
    fn to_child_event(
        &self,
        fork: &ForkTimelineImportInputV1,
        local_seq: u64,
    ) -> Result<Event, Error> {
        let input = self.envelope.input();
        let origin_seq = input.origin_logical_seq.as_u64();
        if input.origin_timeline_id != fork.child_timeline_id
            || fork.parent_cut.checked_add(local_seq) != Some(origin_seq)
        {
            return Err(Error::FieldMismatch);
        }
        Ok(Event {
            id: input.event_id,
            entity: input.entity_id,
            event_type: input.event_type.clone(),
            payload: self.payload.clone(),
            wall_time: input.wall_time,
            seq: Seq::from_u64(local_seq),
            causation_id: input.causation_id,
            correlation_id: input.correlation_id,
            schema_version: SchemaVersion::V1,
            signature: Some(self.signature),
            signature_identity: Some(input.identity),
            origin: Some(EventOriginV1 {
                origin_timeline_id: input.origin_timeline_id,
                origin_logical_seq: input.origin_logical_seq,
            }),
            payload_hash: self.envelope.payload_hash(),
        })
    }
}

/// Construction fields for one `FTI1` child-segment Timeline projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkTimelineImportInputV1 {
    pub child_timeline_id: TimelineId,
    /// Transport metadata only; it grants no authority.
    pub name: Option<String>,
    /// Must equal the trusted parent owner at import; it cannot claim ownership.
    pub owner: Option<EntityId>,
    pub parent_timeline_id: TimelineId,
    pub parent_cut: u64,
    /// Child-segment-local `Timeline.head`.
    pub local_head: u64,
    pub parent_chain_hash: Hash,
}

/// Strict portable `FTI1` bytes: the exact #202 `TimelineExport` metadata of
/// one `Historical` child segment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkTimelineImportV1(ForkTimelineImportInputV1);

impl ForkTimelineImportV1 {
    /// Validate one child-segment projection.
    ///
    /// # Errors
    /// Rejects an oversized name, equal parent and child IDs, or a final
    /// logical head that overflows.
    pub fn new(input: ForkTimelineImportInputV1) -> Result<Self, Error> {
        if input
            .name
            .as_ref()
            .is_some_and(|name| name.len() > MAX_FORK_TIMELINE_IMPORT_NAME_BYTES_V1)
            || input.parent_timeline_id == input.child_timeline_id
            || input.parent_cut.checked_add(input.local_head).is_none()
        {
            return Err(Error::FieldOutOfBounds);
        }
        Ok(Self(input))
    }

    #[must_use]
    pub const fn input(&self) -> &ForkTimelineImportInputV1 {
        &self.0
    }

    /// Return `parent_cut + local_head`, which [`Self::new`] proved cannot overflow.
    #[must_use]
    pub const fn final_logical_head(&self) -> u64 {
        self.0.parent_cut + self.0.local_head
    }

    /// Project an exact own-segment #202 export of one `Historical` child.
    ///
    /// The projection is accepted only when [`Self::to_timeline_export`]
    /// reconstructs exactly the same Timeline and Events.
    ///
    /// # Errors
    /// Returns `FieldMismatch` for a root, missing parent hash,
    /// non-`Historical` mode, unsigned Event, or any Event or head that the
    /// projection cannot reproduce exactly.
    pub fn from_export(export: &TimelineExport) -> Result<(Self, Vec<ForkEventEvidenceV1>), Error> {
        let meta = &export.timeline.meta;
        let (parent_timeline_id, parent_cut) = meta.fork_point.ok_or(Error::FieldMismatch)?;
        let parent_chain_hash = export.parent_fork_hash.ok_or(Error::FieldMismatch)?;
        let projection = Self::new(ForkTimelineImportInputV1 {
            child_timeline_id: meta.id,
            name: meta.name.clone(),
            owner: meta.owner,
            parent_timeline_id,
            parent_cut: parent_cut.as_u64(),
            local_head: export.timeline.head.as_u64(),
            parent_chain_hash,
        })?;
        let evidence = export
            .events
            .iter()
            .map(ForkEventEvidenceV1::from_event)
            .collect::<Result<Vec<_>, _>>()?;
        let rebuilt = projection.to_timeline_export(&evidence)?;
        if rebuilt.timeline != export.timeline || rebuilt.events != export.events {
            return Err(Error::FieldMismatch);
        }
        Ok((projection, evidence))
    }

    /// Reconstruct the exact #202 own-segment `TimelineExport`.
    ///
    /// Local Event sequences must be exactly `1..=local_head`, each Event's
    /// origin must be the child, and its origin logical sequence must equal
    /// `parent_cut + local_seq`.
    ///
    /// # Errors
    /// Returns `FieldMismatch` for any count, order, origin, or
    /// sequence mismatch.
    pub fn to_timeline_export(
        &self,
        evidence: &[ForkEventEvidenceV1],
    ) -> Result<TimelineExport, Error> {
        let value = &self.0;
        if evidence.len() as u64 != value.local_head {
            return Err(Error::FieldMismatch);
        }
        let events = evidence
            .iter()
            .zip(1_u64..)
            .map(|(item, local_seq)| item.to_child_event(value, local_seq))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(TimelineExport {
            timeline: Timeline {
                meta: TimelineMeta {
                    id: value.child_timeline_id,
                    mode: TimelineMode::Historical,
                    name: value.name.clone(),
                    owner: value.owner,
                    fork_point: Some((value.parent_timeline_id, Seq::from_u64(value.parent_cut))),
                },
                head: Seq::from_u64(value.local_head),
            },
            events,
            parent_fork_hash: Some(value.parent_chain_hash),
        })
    }

    /// Encode the exact ten-field deterministic-CBOR `FTI1` array.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let value = &self.0;
        let mut out = Vec::with_capacity(160);
        array(&mut out, 10);
        text(&mut out, "FTI1");
        uint(&mut out, 1);
        timeline(&mut out, value.child_timeline_id);
        uint(&mut out, HISTORICAL_MODE);
        if let Some(name) = &value.name {
            text(&mut out, name);
        } else {
            out.push(authority_wire::NULL);
        }
        if let Some(owner) = value.owner {
            bytes(&mut out, &owner.inner().to_bytes());
        } else {
            out.push(authority_wire::NULL);
        }
        timeline(&mut out, value.parent_timeline_id);
        uint(&mut out, value.parent_cut);
        uint(&mut out, value.local_head);
        hash(&mut out, value.parent_chain_hash);
        out
    }

    /// Decode exact canonical `FTI1` bytes.
    ///
    /// # Errors
    /// Rejects malformed, out-of-bounds, unsupported-version, non-`Historical`,
    /// or noncanonical bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, Error> {
        let mut wire = Reader::new(bytes_in, MAX_FORK_TIMELINE_IMPORT_BYTES_V1)?;
        wire.array(10)?;
        wire.magic("FTI1")?;
        wire.version()?;
        let child_timeline_id = wire.timeline()?;
        if wire.uint()? != HISTORICAL_MODE {
            return Err(Error::InvalidEncoding);
        }
        let name = read_optional_name(&mut wire)?;
        let owner = read_optional_owner(&mut wire)?;
        let record = Self::new(ForkTimelineImportInputV1 {
            child_timeline_id,
            name,
            owner,
            parent_timeline_id: wire.timeline()?,
            parent_cut: wire.uint()?,
            local_head: wire.uint()?,
            parent_chain_hash: wire.hash()?,
        })?;
        wire.finish()?;
        canonical(bytes_in, &record.to_canonical_cbor())?;
        Ok(record)
    }
}

/// The only V1 `FTI1` mode code, `TimelineMode::Historical`.
const HISTORICAL_MODE: u64 = 0;

fn read_optional_name(wire: &mut Reader<'_>) -> Result<Option<String>, Error> {
    if wire.null() {
        Ok(None)
    } else {
        wire.bounded_text(MAX_FORK_TIMELINE_IMPORT_NAME_BYTES_V1)
            .map(Some)
    }
}

fn read_optional_owner(wire: &mut Reader<'_>) -> Result<Option<EntityId>, Error> {
    if wire.null() {
        Ok(None)
    } else {
        wire.fixed()
            .map(|owner| Some(EntityId::from_ulid(ulid::Ulid::from_bytes(owner))))
    }
}

/// Imported key evidence names only the ADR-065 attribution-signing role.
fn attribution_identity(identity: KeyIdentityV1) -> Result<(), Error> {
    if identity.role == KeyRoleV1::SubjectAttributionSigning && identity.epoch != 0 {
        Ok(())
    } else {
        Err(Error::FieldOutOfBounds)
    }
}

fn encode_identity(out: &mut Vec<u8>, identity: KeyIdentityV1) {
    text(out, identity.owner_id.as_str());
    uint(out, u64::from(identity.role.code()));
    uint(out, identity.epoch);
}

fn read_identity(wire: &mut Reader<'_>) -> Result<KeyIdentityV1, Error> {
    let owner_id = wire.owner()?;
    let role = wire.role()?;
    let epoch = wire.uint()?;
    Ok(KeyIdentityV1::from_parts(owner_id, role, epoch))
}
