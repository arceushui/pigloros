//! ADR-105 revision 6 `ForkAttributionAuthorityEnvelopeV1` (`FAE1`).
//!
//! This module owns the exact wire profile, every conjunctive byte and count
//! bound, the closed `closure_leaf` and `closure_root`, the primitive `FAO1`
//! code-2 origin digest, the issuer signature message, and the full
//! signed-envelope digest. It is pure: it installs nothing, consults no issuer
//! policy, and validates no cross-record graph against a store. The carried
//! ADR-099 records stay opaque bounded bytes here, so their authority-origin
//! code 2 remains fail closed in every existing decoder.

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
    MAX_FORK_MANIFEST_INTERVENTIONS_V1,
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
/// Maximum code-2 `POB1` bytes carried by `FAE1` field 7.
pub const MAX_IMPORTED_PRINCIPAL_OWNER_BINDING_BYTES_V1: usize = 320;

const LEAF_DOMAIN: &[u8] = b"pigloros/fork-attribution-closure-leaf/v1";
const ROOT_DOMAIN: &[u8] = b"pigloros/fork-attribution-final-closure/v1";
const ORIGIN_DOMAIN: &[u8] = b"pigloros/fork-attribution-authority-origin/v1";
const SIGNATURE_DOMAIN: &[u8] = b"pigloros/fork-attribution-authority-envelope/signature/v1";
const ENVELOPE_DOMAIN: &[u8] = b"pigloros/fork-attribution-authority-envelope/v1";

/// Fields 0–21 form the signed preimage; field 22 is the signature.
const UNSIGNED_FIELDS: u64 = 22;
const SIGNED_FIELDS: u64 = 23;
/// A 64-byte signature adds its 2-byte `bstr` head; both array heads are one byte.
const SIGNATURE_ITEM_BYTES: usize = 2 + 64;

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

    /// Decode a closed type code.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` for every unknown code.
    pub const fn from_code(code: u8) -> Result<Self, Error> {
        match code {
            1 => Ok(Self::PrincipalOwnerBinding),
            2 => Ok(Self::ForkAdmission),
            3 => Ok(Self::EventOrigin),
            4 => Ok(Self::InterventionAdmission),
            5 => Ok(Self::PublicationOperation),
            6 => Ok(Self::PublicationBinding),
            7 => Ok(Self::PublicationArtifact),
            8 => Ok(Self::ImportedKeyRecord),
            9 => Ok(Self::ImportedKeyTombstone),
            10 => Ok(Self::EventEvidence),
            11 => Ok(Self::TimelineImport),
            12 => Ok(Self::ClassifierSource),
            13 => Ok(Self::ClassifierTable),
            14 => Ok(Self::ClassifierRegistration),
            15 => Ok(Self::AppendOperation),
            _ => Err(Error::InvalidEncoding),
        }
    }

    /// Return the exact record bound that a present leaf must satisfy.
    #[must_use]
    pub const fn maximum_bytes(self) -> usize {
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
    #[must_use]
    pub const fn may_be_absent(self) -> bool {
        matches!(
            self,
            Self::ImportedKeyTombstone
                | Self::ClassifierSource
                | Self::ClassifierTable
                | Self::ClassifierRegistration
        )
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
    if record.len() > leaf.maximum_bytes() || (record.is_empty() && !leaf.may_be_absent()) {
        return Err(Error::FieldOutOfBounds);
    }
    Ok(leaf_digest(leaf, record))
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
    let mut out = Vec::with_capacity(320);
    array(&mut out, 7);
    text(&mut out, "FAO1");
    uint(&mut out, 1);
    hash(&mut out, import_operation_id);
    bytes(&mut out, &issuer.to_canonical_cbor());
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
    /// The origin digest uses the `FTI1` parent and child IDs; the import
    /// seam must still prove they equal `FAR1` fields 5 and 6.
    ///
    /// # Errors
    /// Returns `FieldOutOfBounds` for a zero required digest, any
    /// record, count, aggregate-payload, or complete-envelope bound, and
    /// `FieldMismatch` for an Event count that `EOR1` or `FOP1`
    /// does not match, a classifier triple absent for a nonempty segment or
    /// beside any Event record, or an inconsistent key tombstone.
    pub fn new(input: ForkAttributionAuthorityEnvelopeInputV1) -> Result<Self, Error> {
        validate_bounds(&input)?;
        validate_structure(&input)?;
        let fork = input.timeline_import.input();
        let authority_origin_digest = fork_attribution_authority_origin_digest_v1(
            input.import_operation_id,
            &input.issuer,
            input.issuer_policy_digest,
            fork.parent_timeline_id,
            fork.child_timeline_id,
        );
        let closure_root = closure_root(&input);
        let canonical_bytes = encode_unsigned(&input, closure_root, authority_origin_digest);
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

    #[must_use]
    pub const fn unsigned(&self) -> &ForkAttributionAuthorityUnsignedEnvelopeV1 {
        &self.unsigned
    }

    #[must_use]
    pub const fn signature(&self) -> Signature {
        self.signature
    }

    /// Encode the exact canonical 23-element `FAE1`.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let unsigned = self.unsigned.canonical_bytes();
        let mut out = Vec::with_capacity(unsigned.len() + SIGNATURE_ITEM_BYTES);
        array(&mut out, SIGNED_FIELDS);
        out.extend_from_slice(unsigned.get(1..).unwrap_or_default());
        bytes(&mut out, self.signature.as_bytes());
        out
    }

    /// Return the full signed-envelope content address.
    #[must_use]
    pub fn full_envelope_digest(&self) -> Hash {
        domain_digest(ENVELOPE_DOMAIN, &self.to_canonical_cbor())
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
    Ok(ForkAttributionAuthorityRecordsV1 {
        principal_owner_binding: wire
            .record(MAX_IMPORTED_PRINCIPAL_OWNER_BINDING_BYTES_V1)?
            .to_vec(),
        fork_admission: wire.record(MAX_FORK_ADMISSION_RECORD_BYTES_V1)?.to_vec(),
        event_origins: wire.records(
            MAX_FORK_ATTRIBUTION_AUTHORITY_EVENTS_V1,
            MAX_EVENT_ORIGIN_RECORD_BYTES_V1,
        )?,
        intervention_admissions: wire.records(
            MAX_FORK_ATTRIBUTION_AUTHORITY_INTERVENTIONS_V1,
            MAX_FORK_INTERVENTION_ADMISSION_BYTES_V1,
        )?,
        publication_operation: wire
            .record(MAX_FORK_PUBLICATION_OPERATION_BYTES_V1)?
            .to_vec(),
        publication_binding: wire.record(MAX_FORK_PUBLICATION_BINDING_BYTES_V1)?.to_vec(),
        publication_artifact: wire
            .record(MAX_FORK_PUBLICATION_ARTIFACT_BYTES_V1)?
            .to_vec(),
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
    Ok(ForkAttributionAuthorityEnvelopeInputV1 {
        import_operation_id,
        issuer,
        issuer_policy_digest,
        records,
        key_record: ImportedKeyRecordV1::from_canonical_cbor(
            wire.record(MAX_IMPORTED_KEY_RECORD_BYTES_V1)?,
        )?,
        key_tombstone: wire
            .optional_record(MAX_IMPORTED_KEY_TOMBSTONE_BYTES_V1)?
            .map(ImportedKeyTombstoneV1::from_canonical_cbor)
            .transpose()?,
        event_evidence: read_event_evidence(wire)?,
        timeline_import: ForkTimelineImportV1::from_canonical_cbor(
            wire.record(MAX_FORK_TIMELINE_IMPORT_BYTES_V1)?,
        )?,
        classifier: read_classifier(wire)?,
        append_operations: wire.records(
            MAX_FORK_ATTRIBUTION_AUTHORITY_EVENTS_V1,
            MAX_FORK_EVENT_APPEND_OPERATION_BYTES_V1,
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
    let source = wire.optional_record(MAX_FORK_EVENT_CLASSIFIER_TABLE_BYTES_V1)?;
    let table = wire.optional_record(MAX_FORK_EVENT_CLASSIFIER_TABLE_BYTES_V1)?;
    let registration = wire.optional_record(MAX_FORK_EVENT_CLASSIFIER_REGISTRATION_BYTES_V1)?;
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

/// Enforce every per-record, count, and aggregate-payload bound.
fn validate_bounds(input: &ForkAttributionAuthorityEnvelopeInputV1) -> Result<(), Error> {
    if input.import_operation_id == Hash::zero() || input.issuer_policy_digest == Hash::zero() {
        return Err(Error::FieldOutOfBounds);
    }
    validate_record_bounds(&input.records)?;
    if let Some(classifier) = &input.classifier {
        authority_wire::bounded_record(
            &classifier.source,
            MAX_FORK_EVENT_CLASSIFIER_TABLE_BYTES_V1,
        )?;
        authority_wire::bounded_record(
            &classifier.table,
            MAX_FORK_EVENT_CLASSIFIER_TABLE_BYTES_V1,
        )?;
        authority_wire::bounded_record(
            &classifier.registration,
            MAX_FORK_EVENT_CLASSIFIER_REGISTRATION_BYTES_V1,
        )?;
    }
    authority_wire::bounded_records(
        &input.append_operations,
        MAX_FORK_ATTRIBUTION_AUTHORITY_EVENTS_V1,
        MAX_FORK_EVENT_APPEND_OPERATION_BYTES_V1,
    )?;
    let payload_bytes = input
        .event_evidence
        .iter()
        .map(|evidence| evidence.payload().len())
        .sum::<usize>();
    if input.event_evidence.len() > MAX_FORK_ATTRIBUTION_AUTHORITY_EVENTS_V1
        || payload_bytes > MAX_FORK_ATTRIBUTION_AUTHORITY_PAYLOAD_BYTES_V1
    {
        return Err(Error::FieldOutOfBounds);
    }
    Ok(())
}

fn validate_record_bounds(records: &ForkAttributionAuthorityRecordsV1) -> Result<(), Error> {
    authority_wire::bounded_record(
        &records.principal_owner_binding,
        MAX_IMPORTED_PRINCIPAL_OWNER_BINDING_BYTES_V1,
    )?;
    authority_wire::bounded_record(&records.fork_admission, MAX_FORK_ADMISSION_RECORD_BYTES_V1)?;
    authority_wire::bounded_records(
        &records.event_origins,
        MAX_FORK_ATTRIBUTION_AUTHORITY_EVENTS_V1,
        MAX_EVENT_ORIGIN_RECORD_BYTES_V1,
    )?;
    authority_wire::bounded_records(
        &records.intervention_admissions,
        MAX_FORK_ATTRIBUTION_AUTHORITY_INTERVENTIONS_V1,
        MAX_FORK_INTERVENTION_ADMISSION_BYTES_V1,
    )?;
    authority_wire::bounded_record(
        &records.publication_operation,
        MAX_FORK_PUBLICATION_OPERATION_BYTES_V1,
    )?;
    authority_wire::bounded_record(
        &records.publication_binding,
        MAX_FORK_PUBLICATION_BINDING_BYTES_V1,
    )?;
    authority_wire::bounded_record(
        &records.publication_artifact,
        MAX_FORK_PUBLICATION_ARTIFACT_BYTES_V1,
    )
}

/// Enforce the structural count, all-or-none, and key-lifecycle rules.
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
        .key_record
        .validate_tombstone(input.key_tombstone.as_ref())
}

fn leaf_digest(leaf: ForkAttributionClosureLeafTypeV1, record: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LEAF_DOMAIN);
    hasher.update(&[leaf.code()]);
    hasher.update(&(record.len() as u64).to_be_bytes());
    hasher.update(record);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// Append one leaf to the root preimage.
fn leaf(root: &mut blake3::Hasher, leaf: ForkAttributionClosureLeafTypeV1, record: &[u8]) {
    root.update(leaf_digest(leaf, record).as_bytes());
}

/// Append `u32be(count)` and one leaf per record, in carried order.
fn leaves<'a>(
    root: &mut blake3::Hasher,
    kind: ForkAttributionClosureLeafTypeV1,
    records: impl ExactSizeIterator<Item = &'a [u8]>,
) {
    // Validated counts are at most 10,000, so they always fit `u32`.
    root.update(
        &u32::try_from(records.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for record in records {
        leaf(root, kind, record);
    }
}

fn closure_root(input: &ForkAttributionAuthorityEnvelopeInputV1) -> Hash {
    use ForkAttributionClosureLeafTypeV1 as Leaf;
    let records = &input.records;
    let classifier = input.classifier.as_ref();
    let mut root = blake3::Hasher::new();
    root.update(ROOT_DOMAIN);
    leaf(
        &mut root,
        Leaf::PrincipalOwnerBinding,
        &records.principal_owner_binding,
    );
    leaf(&mut root, Leaf::ForkAdmission, &records.fork_admission);
    leaves(
        &mut root,
        Leaf::EventOrigin,
        records.event_origins.iter().map(Vec::as_slice),
    );
    leaves(
        &mut root,
        Leaf::InterventionAdmission,
        records.intervention_admissions.iter().map(Vec::as_slice),
    );
    leaf(
        &mut root,
        Leaf::PublicationOperation,
        &records.publication_operation,
    );
    leaf(
        &mut root,
        Leaf::PublicationBinding,
        &records.publication_binding,
    );
    leaf(
        &mut root,
        Leaf::PublicationArtifact,
        &records.publication_artifact,
    );
    leaf(
        &mut root,
        Leaf::ImportedKeyRecord,
        &input.key_record.to_canonical_cbor(),
    );
    leaf(
        &mut root,
        Leaf::ImportedKeyTombstone,
        &input
            .key_tombstone
            .as_ref()
            .map(ImportedKeyTombstoneV1::to_canonical_cbor)
            .unwrap_or_default(),
    );
    let evidence = input
        .event_evidence
        .iter()
        .map(ForkEventEvidenceV1::to_canonical_cbor)
        .collect::<Vec<_>>();
    leaves(
        &mut root,
        Leaf::EventEvidence,
        evidence.iter().map(Vec::as_slice),
    );
    leaf(
        &mut root,
        Leaf::TimelineImport,
        &input.timeline_import.to_canonical_cbor(),
    );
    leaf(
        &mut root,
        Leaf::ClassifierSource,
        classifier
            .map(|records| records.source.as_slice())
            .unwrap_or_default(),
    );
    leaf(
        &mut root,
        Leaf::ClassifierTable,
        classifier
            .map(|records| records.table.as_slice())
            .unwrap_or_default(),
    );
    leaf(
        &mut root,
        Leaf::ClassifierRegistration,
        classifier
            .map(|records| records.registration.as_slice())
            .unwrap_or_default(),
    );
    leaves(
        &mut root,
        Leaf::AppendOperation,
        input.append_operations.iter().map(Vec::as_slice),
    );
    Hash::from_bytes(*root.finalize().as_bytes())
}

fn encode_unsigned(
    input: &ForkAttributionAuthorityEnvelopeInputV1,
    closure_root: Hash,
    authority_origin_digest: Hash,
) -> Vec<u8> {
    let records = &input.records;
    let classifier = input.classifier.as_ref();
    let mut out = Vec::new();
    array(&mut out, UNSIGNED_FIELDS);
    text(&mut out, "FAE1");
    uint(&mut out, 1);
    hash(&mut out, input.import_operation_id);
    bytes(&mut out, &input.issuer.to_canonical_cbor());
    hash(&mut out, input.issuer_policy_digest);
    hash(&mut out, closure_root);
    hash(&mut out, authority_origin_digest);
    bytes(&mut out, &records.principal_owner_binding);
    bytes(&mut out, &records.fork_admission);
    authority_wire::records(&mut out, &records.event_origins);
    authority_wire::records(&mut out, &records.intervention_admissions);
    bytes(&mut out, &records.publication_operation);
    bytes(&mut out, &records.publication_binding);
    bytes(&mut out, &records.publication_artifact);
    bytes(&mut out, &input.key_record.to_canonical_cbor());
    authority_wire::optional_record(
        &mut out,
        input
            .key_tombstone
            .as_ref()
            .map(ImportedKeyTombstoneV1::to_canonical_cbor)
            .as_deref(),
    );
    array(&mut out, input.event_evidence.len() as u64);
    for evidence in &input.event_evidence {
        evidence.encode(&mut out);
    }
    bytes(&mut out, &input.timeline_import.to_canonical_cbor());
    authority_wire::optional_record(
        &mut out,
        classifier.map(|records| records.source.as_slice()),
    );
    authority_wire::optional_record(&mut out, classifier.map(|records| records.table.as_slice()));
    authority_wire::optional_record(
        &mut out,
        classifier.map(|records| records.registration.as_slice()),
    );
    authority_wire::records(&mut out, &input.append_operations);
    out
}
