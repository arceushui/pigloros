//! ADR-105 revision 6 `ForkAttributionAuthorityEnvelopeV1` (`FAE1`).
//!
//! This module owns the exact wire profile, every conjunctive byte and count
//! bound, the closed `closure_leaf` and `closure_root`, the primitive `FAO1`
//! code-2 origin digest, the issuer signature message, and the full
//! signed-envelope digest. It is pure: it installs nothing, consults no issuer
//! policy, and validates no cross-record graph against a store. The carried
//! ADR-099 records stay opaque bounded bytes here, so their authority-origin
//! code 2 remains fail closed in every existing decoder; their typed strict
//! decode runs first in the import validator, per ADR-105 r6 erratum E1.

use super::authority_evidence::{
    ForkEventEvidenceV1, ForkTimelineImportV1, ImportedKeyRecordV1, ImportedKeyTombstoneV1,
    MAX_FORK_EVENT_EVIDENCE_BYTES_V1, MAX_FORK_TIMELINE_IMPORT_BYTES_V1,
    MAX_IMPORTED_KEY_RECORD_BYTES_V1, MAX_IMPORTED_KEY_TOMBSTONE_BYTES_V1,
};
use super::authority_issuer::MAX_FORK_ATTRIBUTION_ISSUER_BYTES_V1;
use super::{
    array, authority_issuer::ForkAttributionIssuerV1, authority_wire, bytes, canonical,
    domain_digest, hash, text, timeline, uint, ForkAttributionCodecErrorV1 as Error, Reader,
    MAX_FORK_ADMISSION_RECORD_BYTES_V1, MAX_FORK_PUBLICATION_ARTIFACT_BYTES_V1,
    MAX_FORK_PUBLICATION_BINDING_BYTES_V1, MAX_FORK_PUBLICATION_OPERATION_BYTES_V1,
};
use crate::{
    Hash, Signature, TimelineId, MAX_EVENT_ORIGIN_RECORD_BYTES_V1,
    MAX_FORK_EVENT_APPEND_OPERATION_BYTES_V1, MAX_FORK_EVENT_CLASSIFIER_REGISTRATION_BYTES_V1,
    MAX_FORK_EVENT_CLASSIFIER_TABLE_BYTES_V1, MAX_FORK_INTERVENTION_ADMISSION_BYTES_V1,
    MAX_FORK_MANIFEST_INTERVENTIONS_V1, MAX_PRINCIPAL_OWNER_BINDING_BYTES_V1,
};

/// Maximum complete signed `FAE1` bytes (64 MiB).
pub const MAX_FORK_ATTRIBUTION_AUTHORITY_ENVELOPE_BYTES_V1: usize = 67_108_864;
/// Maximum child-segment Events, and so `EOR1`, `FEE1`, and `FOP1` entries.
pub const MAX_FORK_ATTRIBUTION_AUTHORITY_EVENTS_V1: usize = 10_000;
/// Maximum `FIA1` entries, preserving ADR-099's manifest bound.
pub const MAX_FORK_ATTRIBUTION_AUTHORITY_INTERVENTIONS_V1: usize =
    MAX_FORK_MANIFEST_INTERVENTIONS_V1;
/// Maximum sum of all carried Event payload bytes (60 MiB).
pub const MAX_FORK_ATTRIBUTION_AUTHORITY_PAYLOAD_BYTES_V1: usize = 62_914_560;
/// Maximum code-2 `POB1` bytes carried by `FAE1` field 7, per ADR-105 r6
/// erratum E2.
///
/// This is the local `POB1` maximum plus 34 bytes for the code-2 origin
/// `[2, bstr32]` in place of `[1]`: 207 + 34 = 241.
pub const MAX_IMPORTED_PRINCIPAL_OWNER_BINDING_BYTES_V1: usize =
    MAX_PRINCIPAL_OWNER_BINDING_BYTES_V1 + 34;

const LEAF_DOMAIN: &[u8] = b"pigloros/fork-attribution-closure-leaf/v1";
const ROOT_DOMAIN: &[u8] = b"pigloros/fork-attribution-final-closure/v1";
const ORIGIN_DOMAIN: &[u8] = b"pigloros/fork-attribution-authority-origin/v1";
const SIGNATURE_DOMAIN: &[u8] = b"pigloros/fork-attribution-authority-envelope/signature/v1";
const ENVELOPE_DOMAIN: &[u8] = b"pigloros/fork-attribution-authority-envelope/v1";

/// Fields 0–21 form the signed preimage; field 22 is the signature.
const UNSIGNED_FIELDS: u64 = 22;
const SIGNED_FIELDS: u64 = 23;
/// Both array heads (22 and 23 elements) are exactly one byte.
///
/// Each count is below 24, so the unsigned and signed encodings share every
/// byte after the head.
const ARRAY_HEAD_BYTES: usize = 1;
/// A 64-byte signature adds its 2-byte `bstr` head.
const SIGNATURE_ITEM_BYTES: usize = 2 + 64;
/// The `bstr .size 32` head that precedes the closure root in field 5.
const DIGEST_HEAD_BYTES: usize = 2;

/// Closed `closure_leaf` type codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkAttributionClosureLeafTypeV1 {
    /// 1: `POB1`.
    PrincipalOwnerBinding,
    /// 2: `FAR1`.
    ForkAdmission,
    /// 3: `EOR1`.
    EventOrigin,
    /// 4: `FIA1`.
    InterventionAdmission,
    /// 5: `FPO1`.
    PublicationOperation,
    /// 6: `FPB1`.
    PublicationBinding,
    /// 7: `FPA1`, committing its nested `FSM1` and `FRM1`.
    PublicationArtifact,
    /// 8: `IKR1`.
    ImportedKeyRecord,
    /// 9: `IKT1`, or the typed empty leaf when absent.
    ImportedKeyTombstone,
    /// 10: `FEE1`.
    EventEvidence,
    /// 11: `FTI1`.
    TimelineImport,
    /// 12: `FCS1`, or the typed empty leaf when absent.
    ClassifierSource,
    /// 13: `FCT1`, or the typed empty leaf when absent.
    ClassifierTable,
    /// 14: `FCR1`, or the typed empty leaf when absent.
    ClassifierRegistration,
    /// 15: `FOP1`.
    AppendOperation,
}

impl ForkAttributionClosureLeafTypeV1 {
    /// Return the closed wire type code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::PrincipalOwnerBinding => 1,
            Self::ForkAdmission => 2,
            Self::EventOrigin => 3,
            Self::InterventionAdmission => 4,
            Self::PublicationOperation => 5,
            Self::PublicationBinding => 6,
            Self::PublicationArtifact => 7,
            Self::ImportedKeyRecord => 8,
            Self::ImportedKeyTombstone => 9,
            Self::EventEvidence => 10,
            Self::TimelineImport => 11,
            Self::ClassifierSource => 12,
            Self::ClassifierTable => 13,
            Self::ClassifierRegistration => 14,
            Self::AppendOperation => 15,
        }
    }

    /// Return the exact record bound that a present leaf must satisfy.
    const fn maximum_bytes(self) -> usize {
        match self {
            Self::PrincipalOwnerBinding => MAX_IMPORTED_PRINCIPAL_OWNER_BINDING_BYTES_V1,
            Self::ForkAdmission => MAX_FORK_ADMISSION_RECORD_BYTES_V1,
            Self::EventOrigin => MAX_EVENT_ORIGIN_RECORD_BYTES_V1,
            Self::InterventionAdmission => MAX_FORK_INTERVENTION_ADMISSION_BYTES_V1,
            Self::PublicationOperation => MAX_FORK_PUBLICATION_OPERATION_BYTES_V1,
            Self::PublicationBinding => MAX_FORK_PUBLICATION_BINDING_BYTES_V1,
            Self::PublicationArtifact => MAX_FORK_PUBLICATION_ARTIFACT_BYTES_V1,
            Self::ImportedKeyRecord => MAX_IMPORTED_KEY_RECORD_BYTES_V1,
            Self::ImportedKeyTombstone => MAX_IMPORTED_KEY_TOMBSTONE_BYTES_V1,
            Self::EventEvidence => MAX_FORK_EVENT_EVIDENCE_BYTES_V1,
            Self::TimelineImport => MAX_FORK_TIMELINE_IMPORT_BYTES_V1,
            Self::ClassifierSource | Self::ClassifierTable => {
                MAX_FORK_EVENT_CLASSIFIER_TABLE_BYTES_V1
            }
            Self::ClassifierRegistration => MAX_FORK_EVENT_CLASSIFIER_REGISTRATION_BYTES_V1,
            Self::AppendOperation => MAX_FORK_EVENT_APPEND_OPERATION_BYTES_V1,
        }
    }

    /// Whether the record may be absent, hashing as the typed empty leaf.
    const fn may_be_absent(self) -> bool {
        matches!(
            self,
            Self::ImportedKeyTombstone
                | Self::ClassifierSource
                | Self::ClassifierTable
                | Self::ClassifierRegistration
        )
    }

    /// Require a present record to be nonempty and within its bound.
    const fn check_present(self, record: &[u8]) -> Result<(), Error> {
        if record.is_empty() || record.len() > self.maximum_bytes() {
            Err(Error::FieldOutOfBounds)
        } else {
            Ok(())
        }
    }

    /// Accept the empty absent form only where the type permits it; any other
    /// record must satisfy [`Self::check_present`].
    const fn check(self, record: &[u8]) -> Result<(), Error> {
        if record.is_empty() && self.may_be_absent() {
            Ok(())
        } else {
            self.check_present(record)
        }
    }

    /// Read one carried record of this type, bounded before allocation.
    fn read(self, wire: &mut Reader<'_>) -> Result<Vec<u8>, Error> {
        wire.record(self.maximum_bytes()).map(<[u8]>::to_vec)
    }
}

/// Compute one typed ADR-105 closure leaf.
///
/// The leaf is `BLAKE3(domain || u8(type) || u64be(length) || bytes)`. Empty
/// bytes are the absent form and are accepted only for `IKT1`, `FCS1`,
/// `FCT1`, and `FCR1`.
///
/// # Errors
/// Returns `FieldOutOfBounds` for a present record above its bound
/// or an empty record whose type cannot be absent.
pub fn fork_attribution_closure_leaf_v1(
    leaf: ForkAttributionClosureLeafTypeV1,
    record: &[u8],
) -> Result<Hash, Error> {
    leaf.check(record).map(|()| leaf_digest(leaf, record))
}

/// Derive the primitive `FAO1` code-2 authority-origin digest.
///
/// Its inputs are only the import operation ID, the exact `FAI1` bytes, the
/// issuer-policy digest, and the primitive parent and child Timeline IDs
/// (`FAR1` fields 5 and 6), so it depends on no closure member digest.
#[must_use]
pub fn fork_attribution_authority_origin_digest_v1(
    import_operation_id: Hash,
    issuer: &ForkAttributionIssuerV1,
    issuer_policy_digest: Hash,
    parent_timeline_id: TimelineId,
    child_timeline_id: TimelineId,
) -> Hash {
    origin_digest(
        import_operation_id,
        &issuer.to_canonical_cbor(),
        issuer_policy_digest,
        parent_timeline_id,
        child_timeline_id,
    )
}

fn origin_digest(
    import_operation_id: Hash,
    issuer: &[u8],
    issuer_policy_digest: Hash,
    parent_timeline_id: TimelineId,
    child_timeline_id: TimelineId,
) -> Hash {
    let mut out = Vec::with_capacity(320);
    array(&mut out, 7);
    text(&mut out, "FAO1");
    uint(&mut out, 1);
    hash(&mut out, import_operation_id);
    bytes(&mut out, issuer);
    hash(&mut out, issuer_policy_digest);
    timeline(&mut out, parent_timeline_id);
    timeline(&mut out, child_timeline_id);
    domain_digest(ORIGIN_DOMAIN, &out)
}

/// `FAE1` fields 7–13: the carried ADR-099 authority and publication records.
///
/// Every record is its complete canonical bytes. Their typed decoding and
/// graph validation belong to the import seam, after code 2 is enabled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAttributionAuthorityRecordsV1 {
    /// Field 7: `POB1`.
    pub principal_owner_binding: Vec<u8>,
    /// Field 8: `FAR1`.
    pub fork_admission: Vec<u8>,
    /// Field 9: every `EOR1`, in logical-sequence order.
    pub event_origins: Vec<Vec<u8>>,
    /// Field 10: exactly the implied `FIA1` set, in logical-sequence order.
    pub intervention_admissions: Vec<Vec<u8>>,
    /// Field 11: `FPO1`.
    pub publication_operation: Vec<u8>,
    /// Field 12: `FPB1`.
    pub publication_binding: Vec<u8>,
    /// Field 13: `FPA1`, embedding the only `FSM1` and `FRM1` copy.
    pub publication_artifact: Vec<u8>,
}

/// `FAE1` fields 18–20, which are all present or all `null`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAttributionClassifierRecordsV1 {
    /// Field 18: `FCS1`.
    pub source: Vec<u8>,
    /// Field 19: `FCT1`.
    pub table: Vec<u8>,
    /// Field 20: `FCR1`.
    pub registration: Vec<u8>,
}

/// Construction fields for one unsigned `FAE1`.
///
/// `closure_root` (field 5) and `authority_origin_digest` (field 6) are
/// derived, never supplied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAttributionAuthorityEnvelopeInputV1 {
    /// Field 2: the independent, nonzero import operation ID.
    pub import_operation_id: Hash,
    /// Field 3: the exact `FAI1` issuer identity.
    pub issuer: ForkAttributionIssuerV1,
    /// Field 4: the locally pinned `FIP1` digest.
    pub issuer_policy_digest: Hash,
    /// Fields 7–13.
    pub records: ForkAttributionAuthorityRecordsV1,
    /// Field 14.
    pub key_record: ImportedKeyRecordV1,
    /// Field 15: present exactly when the source key was destroyed.
    pub key_tombstone: Option<ImportedKeyTombstoneV1>,
    /// Field 16: the child-segment Events, in origin-logical-sequence order.
    pub event_evidence: Vec<ForkEventEvidenceV1>,
    /// Field 17.
    pub timeline_import: ForkTimelineImportV1,
    /// Fields 18–20.
    pub classifier: Option<ForkAttributionClassifierRecordsV1>,
    /// Field 21: one `FOP1` per child-segment Event, in logical-sequence order.
    pub append_operations: Vec<Vec<u8>>,
}

/// One bounded `FAE1` without its signature: the exact signed preimage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAttributionAuthorityUnsignedEnvelopeV1 {
    input: ForkAttributionAuthorityEnvelopeInputV1,
    closure_root: Hash,
    authority_origin_digest: Hash,
    canonical_bytes: Vec<u8>,
}

impl ForkAttributionAuthorityUnsignedEnvelopeV1 {
    /// Validate every conjunctive bound and structural rule, then derive the
    /// closure root and the primitive code-2 origin digest.
    ///
    /// The origin digest uses the `FTI1` parent and child IDs, per ADR-105 r6
    /// erratum E4; the import seam must still prove they equal `FAR1` fields
    /// 5 and 6. Every record
    /// is encoded exactly once, and each closure leaf is hashed as it is
    /// written.
    ///
    /// # Errors
    /// Returns `FieldOutOfBounds` for a zero required digest, any record,
    /// count, aggregate-payload, or complete-envelope bound, and
    /// `FieldMismatch` for an Event count that `EOR1` or `FOP1` does not
    /// match, Events that are not exactly the `FTI1` child segment, a
    /// classifier triple absent for a nonempty segment or beside any Event
    /// record, or an inconsistent key tombstone.
    pub fn new(input: ForkAttributionAuthorityEnvelopeInputV1) -> Result<Self, Error> {
        validate_counts(&input)?;
        validate_structure(&input)?;
        let issuer = input.issuer.to_canonical_cbor();
        let fork = input.timeline_import.input();
        let authority_origin_digest = origin_digest(
            input.import_operation_id,
            &issuer,
            input.issuer_policy_digest,
            fork.parent_timeline_id,
            fork.child_timeline_id,
        );
        let mut writer = ClosureWriter::new();
        let root_at = writer.header(&input, &issuer, authority_origin_digest);
        writer.closure(&input);
        let (canonical_bytes, closure_root) = writer.finish(root_at)?;
        if canonical_bytes.len() + SIGNATURE_ITEM_BYTES
            > MAX_FORK_ATTRIBUTION_AUTHORITY_ENVELOPE_BYTES_V1
        {
            return Err(Error::FieldOutOfBounds);
        }
        Ok(Self {
            input,
            closure_root,
            authority_origin_digest,
            canonical_bytes,
        })
    }

    /// Return the validated input fields.
    #[must_use]
    pub const fn input(&self) -> &ForkAttributionAuthorityEnvelopeInputV1 {
        &self.input
    }

    /// Field 5: the final closure root.
    #[must_use]
    pub const fn closure_root(&self) -> Hash {
        self.closure_root
    }

    /// Field 6: the primitive `FAO1` code-2 origin digest.
    #[must_use]
    pub const fn authority_origin_digest(&self) -> Hash {
        self.authority_origin_digest
    }

    /// Return the exact canonical 22-element array of fields 0–21.
    #[must_use]
    pub const fn canonical_bytes(&self) -> &[u8] {
        self.canonical_bytes.as_slice()
    }

    /// Fields 0–21 without the one-byte array head.
    fn body(&self) -> &[u8] {
        &self.canonical_bytes[ARRAY_HEAD_BYTES..]
    }

    /// Return the exact Ed25519 issuer signature message:
    /// `domain || u64be(unsigned length) || unsigned bytes`.
    #[must_use]
    pub fn signature_message(&self) -> Vec<u8> {
        let mut message =
            Vec::with_capacity(SIGNATURE_DOMAIN.len() + 8 + self.canonical_bytes.len());
        message.extend_from_slice(SIGNATURE_DOMAIN);
        message.extend_from_slice(&(self.canonical_bytes.len() as u64).to_be_bytes());
        message.extend_from_slice(&self.canonical_bytes);
        message
    }
}

/// One complete signed `FAE1`.
///
/// Decoding proves only exact structure and derived digests. The issuer
/// signature is verified by `pos-crypto`, and issuer trust by the pinned
/// issuer policy; neither is implied by this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAttributionAuthorityEnvelopeV1 {
    unsigned: ForkAttributionAuthorityUnsignedEnvelopeV1,
    signature: Signature,
}

impl ForkAttributionAuthorityEnvelopeV1 {
    /// Attach field 22 to an exact unsigned envelope; the signature is not
    /// verified here.
    #[must_use]
    pub const fn new(
        unsigned: ForkAttributionAuthorityUnsignedEnvelopeV1,
        signature: Signature,
    ) -> Self {
        Self {
            unsigned,
            signature,
        }
    }

    /// Fields 0–21: the exact signed preimage.
    #[must_use]
    pub const fn unsigned(&self) -> &ForkAttributionAuthorityUnsignedEnvelopeV1 {
        &self.unsigned
    }

    /// Field 22: the issuer signature, not verified here.
    #[must_use]
    pub const fn signature(&self) -> Signature {
        self.signature
    }

    /// Encode the exact canonical 23-element `FAE1`.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(self.unsigned.canonical_bytes.len() + SIGNATURE_ITEM_BYTES);
        self.for_each_part(|part| out.extend_from_slice(part));
        out
    }

    /// Return the full signed-envelope content address, hashing the encoding
    /// in place without materializing it.
    #[must_use]
    pub fn full_envelope_digest(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ENVELOPE_DOMAIN);
        self.for_each_part(|part| {
            hasher.update(part);
        });
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Feed the canonical signed encoding, in order, to `sink`: the signed
    /// array head, the unsigned body, and the signature item.
    fn for_each_part(&self, mut sink: impl FnMut(&[u8])) {
        let mut head = Vec::with_capacity(ARRAY_HEAD_BYTES);
        array(&mut head, SIGNED_FIELDS);
        let mut signature = Vec::with_capacity(SIGNATURE_ITEM_BYTES);
        bytes(&mut signature, self.signature.as_bytes());
        sink(&head);
        sink(self.unsigned.body());
        sink(&signature);
    }

    /// Decode exact canonical `FAE1` bytes.
    ///
    /// # Errors
    /// Rejects input above 64 MiB, any other violated bound, a wrong arity
    /// (including a 19-element revision 5 array), an unsupported version,
    /// malformed or noncanonical bytes, any structural rule that
    /// [`ForkAttributionAuthorityUnsignedEnvelopeV1::new`] enforces, and a
    /// closure root or origin digest that differs from its derivation.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, Error> {
        let mut wire = Reader::new(bytes_in, MAX_FORK_ATTRIBUTION_AUTHORITY_ENVELOPE_BYTES_V1)?;
        wire.array(SIGNED_FIELDS)?;
        wire.magic("FAE1")?;
        wire.version()?;
        let import_operation_id = wire.hash()?;
        let issuer = ForkAttributionIssuerV1::from_canonical_cbor(
            wire.record(MAX_FORK_ATTRIBUTION_ISSUER_BYTES_V1)?,
        )?;
        let issuer_policy_digest = wire.hash()?;
        let closure_root = wire.hash()?;
        let authority_origin_digest = wire.hash()?;
        let records = read_records(&mut wire)?;
        let input = read_evidence(
            &mut wire,
            import_operation_id,
            issuer,
            issuer_policy_digest,
            records,
        )?;
        let signature = Signature::from_bytes(wire.fixed()?);
        wire.finish()?;
        let unsigned = ForkAttributionAuthorityUnsignedEnvelopeV1::new(input)?;
        if unsigned.closure_root != closure_root
            || unsigned.authority_origin_digest != authority_origin_digest
        {
            return Err(Error::FieldMismatch);
        }
        let envelope = Self::new(unsigned, signature);
        canonical(bytes_in, &envelope.to_canonical_cbor())?;
        Ok(envelope)
    }
}

fn read_records(wire: &mut Reader<'_>) -> Result<ForkAttributionAuthorityRecordsV1, Error> {
    use ForkAttributionClosureLeafTypeV1 as Leaf;
    Ok(ForkAttributionAuthorityRecordsV1 {
        principal_owner_binding: Leaf::PrincipalOwnerBinding.read(wire)?,
        fork_admission: Leaf::ForkAdmission.read(wire)?,
        event_origins: wire.records(
            MAX_FORK_ATTRIBUTION_AUTHORITY_EVENTS_V1,
            Leaf::EventOrigin.maximum_bytes(),
        )?,
        intervention_admissions: wire.records(
            MAX_FORK_ATTRIBUTION_AUTHORITY_INTERVENTIONS_V1,
            Leaf::InterventionAdmission.maximum_bytes(),
        )?,
        publication_operation: Leaf::PublicationOperation.read(wire)?,
        publication_binding: Leaf::PublicationBinding.read(wire)?,
        publication_artifact: Leaf::PublicationArtifact.read(wire)?,
    })
}

/// Read fields 14–21 after the carried ADR-099 records.
fn read_evidence(
    wire: &mut Reader<'_>,
    import_operation_id: Hash,
    issuer: ForkAttributionIssuerV1,
    issuer_policy_digest: Hash,
    records: ForkAttributionAuthorityRecordsV1,
) -> Result<ForkAttributionAuthorityEnvelopeInputV1, Error> {
    use ForkAttributionClosureLeafTypeV1 as Leaf;
    Ok(ForkAttributionAuthorityEnvelopeInputV1 {
        import_operation_id,
        issuer,
        issuer_policy_digest,
        records,
        key_record: ImportedKeyRecordV1::from_canonical_cbor(
            wire.record(Leaf::ImportedKeyRecord.maximum_bytes())?,
        )?,
        key_tombstone: wire
            .optional_record(Leaf::ImportedKeyTombstone.maximum_bytes())?
            .map(ImportedKeyTombstoneV1::from_canonical_cbor)
            .transpose()?,
        event_evidence: read_event_evidence(wire)?,
        timeline_import: ForkTimelineImportV1::from_canonical_cbor(
            wire.record(Leaf::TimelineImport.maximum_bytes())?,
        )?,
        classifier: read_classifier(wire)?,
        append_operations: wire.records(
            MAX_FORK_ATTRIBUTION_AUTHORITY_EVENTS_V1,
            Leaf::AppendOperation.maximum_bytes(),
        )?,
    })
}

fn read_event_evidence(wire: &mut Reader<'_>) -> Result<Vec<ForkEventEvidenceV1>, Error> {
    let count = wire.bounded_len(MAX_FORK_ATTRIBUTION_AUTHORITY_EVENTS_V1)?;
    (0..count)
        .map(|_| ForkEventEvidenceV1::read(wire))
        .collect()
}

/// Read fields 18–20 and require all present or all `null`.
fn read_classifier(
    wire: &mut Reader<'_>,
) -> Result<Option<ForkAttributionClassifierRecordsV1>, Error> {
    use ForkAttributionClosureLeafTypeV1 as Leaf;
    let source = wire.optional_record(Leaf::ClassifierSource.maximum_bytes())?;
    let table = wire.optional_record(Leaf::ClassifierTable.maximum_bytes())?;
    let registration = wire.optional_record(Leaf::ClassifierRegistration.maximum_bytes())?;
    match (source, table, registration) {
        (Some(source), Some(table), Some(registration)) => {
            Ok(Some(ForkAttributionClassifierRecordsV1 {
                source: source.to_vec(),
                table: table.to_vec(),
                registration: registration.to_vec(),
            }))
        }
        (None, None, None) => Ok(None),
        _ => Err(Error::FieldMismatch),
    }
}

/// Enforce the nonzero digests and every count and aggregate-payload bound.
///
/// Per-record byte bounds are enforced once, by the closure leaf check, as
/// each record is encoded.
fn validate_counts(input: &ForkAttributionAuthorityEnvelopeInputV1) -> Result<(), Error> {
    let payload_bytes = input
        .event_evidence
        .iter()
        .map(|evidence| evidence.payload().len())
        .sum::<usize>();
    if input.import_operation_id == Hash::zero()
        || input.issuer_policy_digest == Hash::zero()
        || input.records.event_origins.len() > MAX_FORK_ATTRIBUTION_AUTHORITY_EVENTS_V1
        || input.records.intervention_admissions.len()
            > MAX_FORK_ATTRIBUTION_AUTHORITY_INTERVENTIONS_V1
        || input.event_evidence.len() > MAX_FORK_ATTRIBUTION_AUTHORITY_EVENTS_V1
        || input.append_operations.len() > MAX_FORK_ATTRIBUTION_AUTHORITY_EVENTS_V1
        || payload_bytes > MAX_FORK_ATTRIBUTION_AUTHORITY_PAYLOAD_BYTES_V1
    {
        return Err(Error::FieldOutOfBounds);
    }
    Ok(())
}

/// Enforce the structural count, all-or-none, child-segment, and
/// key-lifecycle rules.
///
/// Every failure is `FieldMismatch`, which the import seam maps to
/// `InvalidAuthorityClosure` per ADR-105 r6 erratum E5.
fn validate_structure(input: &ForkAttributionAuthorityEnvelopeInputV1) -> Result<(), Error> {
    let events = input.event_evidence.len();
    let unclassified_records = input.classifier.is_none()
        && (events != 0 || !input.records.intervention_admissions.is_empty());
    if input.records.event_origins.len() != events
        || input.append_operations.len() != events
        || unclassified_records
    {
        return Err(Error::FieldMismatch);
    }
    input
        .timeline_import
        .validate_segment(&input.event_evidence)
        .and_then(|()| {
            input
                .key_record
                .validate_tombstone(input.key_tombstone.as_ref())
        })
}

fn leaf_digest(kind: ForkAttributionClosureLeafTypeV1, record: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LEAF_DOMAIN);
    hasher.update(&[kind.code()]);
    hasher.update(&(record.len() as u64).to_be_bytes());
    hasher.update(record);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// Single-pass `FAE1` encoder that hashes each closure leaf as it writes the
/// record, so every record is encoded once and no leaf is copied.
struct ClosureWriter {
    out: Vec<u8>,
    root: blake3::Hasher,
    /// The first violated record bound, if any.
    bounded: Result<(), Error>,
}

impl ClosureWriter {
    fn new() -> Self {
        let mut root = blake3::Hasher::new();
        root.update(ROOT_DOMAIN);
        Self {
            out: Vec::new(),
            root,
            bounded: Ok(()),
        }
    }

    /// Write fields 0–6 with a zero closure-root placeholder and return the
    /// placeholder's offset.
    fn header(
        &mut self,
        input: &ForkAttributionAuthorityEnvelopeInputV1,
        issuer: &[u8],
        authority_origin_digest: Hash,
    ) -> usize {
        let out = &mut self.out;
        array(out, UNSIGNED_FIELDS);
        text(out, "FAE1");
        uint(out, 1);
        hash(out, input.import_operation_id);
        bytes(out, issuer);
        hash(out, input.issuer_policy_digest);
        let root_at = out.len() + DIGEST_HEAD_BYTES;
        hash(out, Hash::zero());
        hash(out, authority_origin_digest);
        root_at
    }

    /// Write fields 7–21, whose order is exactly the closure-root order.
    fn closure(&mut self, input: &ForkAttributionAuthorityEnvelopeInputV1) {
        use ForkAttributionClosureLeafTypeV1 as Leaf;
        let records = &input.records;
        let classifier = input.classifier.as_ref();
        self.record(
            Leaf::PrincipalOwnerBinding,
            &records.principal_owner_binding,
        );
        self.record(Leaf::ForkAdmission, &records.fork_admission);
        self.records(Leaf::EventOrigin, &records.event_origins);
        self.records(
            Leaf::InterventionAdmission,
            &records.intervention_admissions,
        );
        self.record(Leaf::PublicationOperation, &records.publication_operation);
        self.record(Leaf::PublicationBinding, &records.publication_binding);
        self.record(Leaf::PublicationArtifact, &records.publication_artifact);
        self.record(
            Leaf::ImportedKeyRecord,
            &input.key_record.to_canonical_cbor(),
        );
        self.optional(
            Leaf::ImportedKeyTombstone,
            input
                .key_tombstone
                .as_ref()
                .map(ImportedKeyTombstoneV1::to_canonical_cbor)
                .as_deref(),
        );
        self.evidence(&input.event_evidence);
        self.record(
            Leaf::TimelineImport,
            &input.timeline_import.to_canonical_cbor(),
        );
        self.optional(
            Leaf::ClassifierSource,
            classifier.map(|records| records.source.as_slice()),
        );
        self.optional(
            Leaf::ClassifierTable,
            classifier.map(|records| records.table.as_slice()),
        );
        self.optional(
            Leaf::ClassifierRegistration,
            classifier.map(|records| records.registration.as_slice()),
        );
        self.records(Leaf::AppendOperation, &input.append_operations);
    }

    /// Append one leaf digest to the root preimage.
    fn push_leaf(&mut self, kind: ForkAttributionClosureLeafTypeV1, record: &[u8]) {
        self.root.update(leaf_digest(kind, record).as_bytes());
    }

    /// Write one list head and append `u32be(count)` to the root preimage.
    fn push_count(&mut self, count: usize) {
        array(&mut self.out, count as u64);
        // Validated counts are at most 10,000, so they always fit `u32`.
        self.root
            .update(&u32::try_from(count).unwrap_or(u32::MAX).to_be_bytes());
    }

    /// Write one present record, keeping the first violated bound.
    fn record(&mut self, kind: ForkAttributionClosureLeafTypeV1, record: &[u8]) {
        bytes(&mut self.out, record);
        self.bounded = self.bounded.and_then(|()| kind.check_present(record));
        self.push_leaf(kind, record);
    }

    /// Write a present record, or `null` with the typed empty leaf.
    fn optional(&mut self, kind: ForkAttributionClosureLeafTypeV1, record: Option<&[u8]>) {
        if let Some(record) = record {
            self.record(kind, record);
        } else {
            self.out.push(authority_wire::NULL);
            self.push_leaf(kind, &[]);
        }
    }

    fn records(&mut self, kind: ForkAttributionClosureLeafTypeV1, records: &[Vec<u8>]) {
        self.push_count(records.len());
        for record in records {
            self.record(kind, record);
        }
    }

    /// Write field 16 inline. Each `FEE1` is bounded by construction, so its
    /// leaf is hashed straight from the bytes just written.
    fn evidence(&mut self, events: &[ForkEventEvidenceV1]) {
        self.push_count(events.len());
        for event in events {
            let start = self.out.len();
            event.encode(&mut self.out);
            let leaf = leaf_digest(
                ForkAttributionClosureLeafTypeV1::EventEvidence,
                &self.out[start..],
            );
            self.root.update(leaf.as_bytes());
        }
    }

    /// Patch the closure root into field 5 and return the unsigned bytes.
    fn finish(mut self, root_at: usize) -> Result<(Vec<u8>, Hash), Error> {
        let closure_root = Hash::from_bytes(*self.root.finalize().as_bytes());
        self.out[root_at..root_at + 32].copy_from_slice(closure_root.as_bytes());
        self.bounded.map(|()| (self.out, closure_root))
    }
}
