//! ADR-105 typed strict decode and pure cross-record validation of one `FAE1`
//! authority closure (#518).
//!
//! Per ADR-105 r6 erratum E1 the envelope codec carries the ADR-099 records as
//! exact bounded bytes. This module decodes every one of them strictly, then
//! checks every store-independent equality of import steps 2, 5, 5a, 6, and 8:
//! the code-2 origins, `POB1` creator ownership, the `FAR1`, `FTI1`, `FRM1`,
//! and `FSM1` coordinates, the `FPO1` source table with `FPB1` and `FPA1`,
//! the retained `IKR1`/`IKT1` evidence, the per-Fork rows G1–G8, and the
//! per-Event rows P1–P8 with the total `EOR1`/`FIA1` classification.
//!
//! A validated closure is not authority. The issuer signature and policy, the
//! `FSM1` signature, #202 Event and #411 range verification, the parent
//! Timeline, and every occupancy rule belong to the import port.

use std::collections::BTreeSet;

use crate::{
    EventOriginRecordV1, ForkAdmissionRecordInputV1, ForkAppendOperationInputV1,
    ForkAppendOperationV1, ForkAttributionAuthorityEnvelopeV1, ForkAttributionClassifierRecordsV1,
    ForkAttributionCodecErrorV1, ForkClassifierRegistrationV1, ForkClassifierSourceV1,
    ForkClassifierTableV1, ForkEventClassifierV1, ForkEventEvidenceV1, ForkEventProvenanceErrorV1,
    ForkInterventionAdmissionV1, ForkPublicationArtifactV1, ForkPublicationBindingV1, Hash,
    ImportedForkAdmissionRecordV1, ImportedForkPublicationOperationV1, ImportedKeyRecordV1,
    ImportedKeyTombstoneV1, ImportedPrincipalOwnerBindingV1, SignedForkReproManifestV1,
};

/// Closed failures of the typed decode and pure closure validation.
///
/// Each variant is the ADR-105 public import error of the same name. Per
/// ADR-105 r6 erratum E9, every failure while decoding a carried ADR-099
/// record is `InvalidEncoding`, including an unsupported version, an
/// out-of-range or zero field, and a record over its own byte bound;
/// `BoundsExceeded` is reserved for the envelope-level limits that the `FAE1`
/// codec enforces.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkAttributionImportClosureErrorV1 {
    /// A carried record does not decode strictly, or a list is out of order.
    #[error("Fork attribution import record encoding is invalid")]
    InvalidEncoding,
    /// The carried records do not form one consistent authority closure.
    #[error("Fork attribution import closure is inconsistent")]
    InvalidAuthorityClosure,
}

type Error = ForkAttributionImportClosureErrorV1;

impl From<ForkAttributionCodecErrorV1> for ForkAttributionImportClosureErrorV1 {
    /// Map an ADR-099 or ADR-105 codec failure.
    ///
    /// `FieldMismatch` covers the step-1 structural rules, which ADR-105 r6
    /// erratum E5 maps to `InvalidAuthorityClosure`, a nested `FSM1` record ID
    /// that `FPA1` contradicts, and a local code-1 origin, which step 2
    /// forbids inside `FAE1`. Every other failure is a nested-record decode
    /// failure, so erratum E9 makes it `InvalidEncoding`.
    fn from(error: ForkAttributionCodecErrorV1) -> Self {
        match error {
            ForkAttributionCodecErrorV1::FieldMismatch => Self::InvalidAuthorityClosure,
            ForkAttributionCodecErrorV1::InvalidEncoding
            | ForkAttributionCodecErrorV1::NonCanonical
            | ForkAttributionCodecErrorV1::UnsupportedVersion
            | ForkAttributionCodecErrorV1::FieldOutOfBounds
            | ForkAttributionCodecErrorV1::ImportedAuthorityUnavailable
            | ForkAttributionCodecErrorV1::InterventionOrder => Self::InvalidEncoding,
        }
    }
}

impl From<ForkEventProvenanceErrorV1> for ForkAttributionImportClosureErrorV1 {
    /// Map an ADR-099 provenance codec or classification failure.
    ///
    /// A source route absent from `FCT1` is a classification failure of the
    /// closure. Every other failure, including an impossible `(0,1)` `EOR1`
    /// pair, arises while decoding a carried record, so erratum E9 makes it
    /// `InvalidEncoding`.
    fn from(error: ForkEventProvenanceErrorV1) -> Self {
        match error {
            ForkEventProvenanceErrorV1::SourceRejected => Self::InvalidAuthorityClosure,
            ForkEventProvenanceErrorV1::InvalidEncoding
            | ForkEventProvenanceErrorV1::NonCanonical
            | ForkEventProvenanceErrorV1::UnsupportedVersion
            | ForkEventProvenanceErrorV1::FieldOutOfBounds
            | ForkEventProvenanceErrorV1::ImportedAuthorityUnavailable
            | ForkEventProvenanceErrorV1::ImpossibleClassification
            | ForkEventProvenanceErrorV1::DuplicateSourceRoute => Self::InvalidEncoding,
        }
    }
}

/// Require one closure equality.
const fn closure_rule(holds: bool) -> Result<(), Error> {
    if holds {
        Ok(())
    } else {
        Err(Error::InvalidAuthorityClosure)
    }
}

/// Require strictly increasing logical sequences, so that a list is ordered
/// and repeats no sequence.
fn strictly_increasing<T>(records: &[T], sequence: fn(&T) -> u64) -> bool {
    records
        .windows(2)
        .all(|pair| sequence(&pair[0]) < sequence(&pair[1]))
}

const fn origin_seq(record: &EventOriginRecordV1) -> u64 {
    record.input().logical_seq
}

const fn intervention_seq(record: &ForkInterventionAdmissionV1) -> u64 {
    record.input().logical_seq
}

const fn operation_seq(record: &ForkAppendOperationV1) -> u64 {
    record.input().logical_seq
}

/// Decode every carried record of one list with its strict decoder.
fn decode_list<T, E>(
    records: &[Vec<u8>],
    decode: fn(&[u8]) -> Result<T, E>,
) -> Result<Vec<T>, Error>
where
    Error: From<E>,
{
    records
        .iter()
        .map(|record| decode(record).map_err(Error::from))
        .collect()
}

/// `FAE1` fields 18–20, strictly decoded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedForkClassifierGraphV1 {
    /// Field 18: the imported `FCS1`, kept apart from local source custody.
    pub source: ForkClassifierSourceV1,
    /// Field 19: the child's `FCT1`.
    pub table: ForkClassifierTableV1,
    /// Field 20: the child's `FCR1`.
    pub registration: ForkClassifierRegistrationV1,
}

impl ImportedForkClassifierGraphV1 {
    fn decode(records: &ForkAttributionClassifierRecordsV1) -> Result<Self, Error> {
        Ok(Self {
            source: ForkClassifierSourceV1::from_canonical_cbor(&records.source)?,
            table: ForkClassifierTableV1::from_canonical_cbor(&records.table)?,
            registration: ForkClassifierRegistrationV1::from_canonical_cbor(&records.registration)?,
        })
    }

    /// Check ADR-105 r6 R6.5 rows G1–G7; the `FCR1` decoder already proved G8.
    fn check(&self, admission: &ForkAdmissionRecordInputV1, admission_digest: Hash) -> bool {
        let source = self.source.input();
        let table = self.table.input();
        let registration = self.registration.input();
        let descriptor = admission.room_revision_descriptor_hash;
        source.room_revision_descriptor_hash == descriptor
            && table.room_revision_descriptor_hash == descriptor
            && registration.room_revision_descriptor_hash == descriptor
            && table.registrar_identifier == source.registrar_identifier
            && table.source_configuration_revision_digest == self.source.digest()
            && table.routes == source.routes
            && table.fork_admission_digest == admission_digest
            && registration.fork_admission_digest == admission_digest
            && registration.classifier_revision_digest == self.table.digest()
            && registration.child_timeline_id == admission.child_timeline_id
            && table.child_timeline_id == admission.child_timeline_id
    }
}

/// The `FIA1` records and `FRM1` sequences that the classified Events imply.
#[derive(Default)]
struct DerivedInterventionsV1 {
    sequences: Vec<u64>,
    admissions: Vec<ForkInterventionAdmissionV1>,
}

/// One strictly decoded `FAE1` closure whose store-independent ADR-105
/// cross-record equalities all hold.
///
/// It proves no issuer trust, no `FSM1` signature, no #202 or #411
/// verification, and no occupancy; it is never authority by itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAttributionImportClosureV1 {
    principal_owner_binding: ImportedPrincipalOwnerBindingV1,
    fork_admission: ImportedForkAdmissionRecordV1,
    fork_admission_digest: Hash,
    event_origins: Vec<EventOriginRecordV1>,
    intervention_admissions: Vec<ForkInterventionAdmissionV1>,
    classifier: Option<ImportedForkClassifierGraphV1>,
    append_operations: Vec<ForkAppendOperationV1>,
    publication_operation: ImportedForkPublicationOperationV1,
    publication_binding: ForkPublicationBindingV1,
    publication_artifact: ForkPublicationArtifactV1,
}

impl ForkAttributionImportClosureV1 {
    /// Strictly decode every carried ADR-099 record, then check every
    /// store-independent closure equality.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` for a record that does not decode strictly
    /// or a list that is not in strict logical-sequence order, and
    /// `InvalidAuthorityClosure` for a local code-1 origin or any failed
    /// equality.
    pub fn validate(envelope: &ForkAttributionAuthorityEnvelopeV1) -> Result<Self, Error> {
        let closure = Self::decode(envelope)?;
        closure.check(envelope).map(|()| closure)
    }

    /// ADR-105 import step 1, typed part: decode, re-encode, and order.
    fn decode(envelope: &ForkAttributionAuthorityEnvelopeV1) -> Result<Self, Error> {
        let input = envelope.unsigned().input();
        let records = &input.records;
        let fork_admission =
            ImportedForkAdmissionRecordV1::from_canonical_cbor(&records.fork_admission)?;
        let closure = Self {
            principal_owner_binding: ImportedPrincipalOwnerBindingV1::from_canonical_cbor(
                &records.principal_owner_binding,
            )?,
            fork_admission_digest: fork_admission.digest(),
            fork_admission,
            event_origins: decode_list(
                &records.event_origins,
                EventOriginRecordV1::from_canonical_cbor,
            )?,
            intervention_admissions: decode_list(
                &records.intervention_admissions,
                ForkInterventionAdmissionV1::from_canonical_cbor,
            )?,
            classifier: input
                .classifier
                .as_ref()
                .map(ImportedForkClassifierGraphV1::decode)
                .transpose()?,
            append_operations: decode_list(
                &input.append_operations,
                ForkAppendOperationV1::from_canonical_cbor,
            )?,
            publication_operation: ImportedForkPublicationOperationV1::from_canonical_cbor(
                &records.publication_operation,
            )?,
            publication_binding: ForkPublicationBindingV1::from_canonical_cbor(
                &records.publication_binding,
            )?,
            publication_artifact: ForkPublicationArtifactV1::from_canonical_cbor(
                &records.publication_artifact,
            )?,
        };
        closure.check_order().map(|()| closure)
    }

    /// Require `EOR1`, `FIA1`, and `FOP1` in strict logical-sequence order.
    fn check_order(&self) -> Result<(), Error> {
        if strictly_increasing(&self.event_origins, origin_seq)
            && strictly_increasing(&self.intervention_admissions, intervention_seq)
            && strictly_increasing(&self.append_operations, operation_seq)
        {
            Ok(())
        } else {
            Err(Error::InvalidEncoding)
        }
    }

    fn check(&self, envelope: &ForkAttributionAuthorityEnvelopeV1) -> Result<(), Error> {
        let input = envelope.unsigned().input();
        let final_logical_head = input.timeline_import.final_logical_head();
        let tombstone = input.key_tombstone.as_ref();
        closure_rule(
            self.origins_match(envelope)
                && self.admission_matches(final_logical_head)
                && self.empty_segment_matches(final_logical_head)
                && self.publication_matches()
                && self.key_evidence_matches(&input.key_record, tombstone)
                && self.classifier_matches(),
        )?;
        self.check_events(&input.event_evidence)
    }

    /// Import step 2: every carried origin is exactly the envelope's `FAO1`
    /// digest, and `FTI1` names exactly the `FAR1` parent, child, cut, and
    /// parent chain hash (erratum E4).
    fn origins_match(&self, envelope: &ForkAttributionAuthorityEnvelopeV1) -> bool {
        let unsigned = envelope.unsigned();
        let origin = unsigned.authority_origin_digest();
        let fork = unsigned.input().timeline_import.input();
        let admission = self.fork_admission.fields();
        self.principal_owner_binding.authority_origin_digest() == origin
            && self.fork_admission.authority_origin_digest() == origin
            && self.publication_operation.authority_origin_digest() == origin
            && fork.parent_timeline_id == admission.parent_timeline_id
            && fork.child_timeline_id == admission.child_timeline_id
            && fork.parent_cut == admission.parent_logical_head
            && fork.parent_chain_hash == admission.parent_chain_head_hash
    }

    /// Import step 5: `POB1` establishes the `FAR1` creator, and `FRM1` and
    /// `FSM1` agree with `FAR1` and the `FTI1` final head.
    fn admission_matches(&self, final_logical_head: u64) -> bool {
        let admission = self.fork_admission.fields();
        let binding = &self.principal_owner_binding;
        let signed_manifest = self.signed_manifest();
        let manifest = signed_manifest.manifest().input();
        binding.digest() == admission.principal_owner_binding_digest
            && binding.owner() == admission.creator
            && signed_manifest.identity().owner_id == admission.creator
            && manifest.admission_digest == self.fork_admission_digest
            && manifest.cut_coordinates() == admission.cut_coordinates()
            && manifest.final_fork_logical_head == final_logical_head
    }

    /// An empty child segment ends exactly at the parent cut, so its final
    /// chain hash is the `FAR1` parent chain hash. `FPO1` field 5 then equals
    /// it too, through the source-table check.
    fn empty_segment_matches(&self, final_logical_head: u64) -> bool {
        let admission = self.fork_admission.fields();
        let manifest = self.signed_manifest().manifest().input();
        final_logical_head != admission.parent_logical_head
            || manifest.final_fork_chain_head_hash == admission.parent_chain_head_hash
    }

    /// The ADR-099 `FPO1` source table, with `FPB1` and `FPA1` duplicating
    /// exactly the same operation, Fork, head, and record ID.
    fn publication_matches(&self) -> bool {
        let operation = self.publication_operation.fields();
        let binding = self.publication_binding.input();
        let artifact = self.publication_artifact.input();
        let signed_manifest = self.signed_manifest();
        let manifest = signed_manifest.manifest().input();
        let record_id = artifact.signed_manifest_record_id;
        operation.child_timeline_id == manifest.fork_timeline_id
            && operation.final_logical_head == manifest.final_fork_logical_head
            && operation.final_chain_head_hash == manifest.final_fork_chain_head_hash
            && operation.admission_digest == self.fork_admission_digest
            && operation.signing_identity == signed_manifest.identity()
            && operation.signed_manifest_record_id == record_id
            && binding.child_timeline_id == operation.child_timeline_id
            && binding.final_logical_head == operation.final_logical_head
            && binding.operation_id == operation.operation_id
            && binding.signed_manifest_record_id == record_id
            && artifact.operation_id == operation.operation_id
    }

    /// Import step 8 equalities: the retained identity and public key equal
    /// `FPO1`, and so `FSM1`, and the live material digest or the tombstone's
    /// destroyed digest equals `FPO1` field 10.
    fn key_evidence_matches(
        &self,
        key: &ImportedKeyRecordV1,
        tombstone: Option<&ImportedKeyTombstoneV1>,
    ) -> bool {
        let operation = self.publication_operation.fields();
        let destroyed = tombstone.map(ImportedKeyTombstoneV1::destroyed_material_digest);
        let material = key.private_material_digest().or(destroyed);
        key.identity() == operation.signing_identity
            && key.public_verification_key() == operation.public_verification_key
            && material == Some(operation.private_material_digest)
    }

    /// Import step 5a: G1–G8 hold whenever `FAE1` fields 18–20 are present.
    fn classifier_matches(&self) -> bool {
        let admission = self.fork_admission.fields();
        let digest = self.fork_admission_digest;
        self.classifier
            .as_ref()
            .is_none_or(|graph| graph.check(admission, digest))
    }

    /// Import step 6: P1–P8 for every Event, exactly the implied `FIA1` set,
    /// and the `FRM1` intervention list.
    ///
    /// Without the classifier triple there is nothing to classify: the `FAE1`
    /// codec's all-or-none rule (`validate_structure`) admits a null triple
    /// only with no `FEE1`, `EOR1`, `FIA1`, or `FOP1`.
    fn check_events(&self, evidence: &[ForkEventEvidenceV1]) -> Result<(), Error> {
        let derived = self
            .classifier
            .as_ref()
            .map(|graph| self.check_event_rows(graph, evidence))
            .transpose()?
            .unwrap_or_default();
        let manifest = self.signed_manifest().manifest().input();
        closure_rule(
            derived.admissions == self.intervention_admissions
                && derived.sequences == manifest.intervention_sequences,
        )
    }

    /// Check P1–P8 for each Event and the P1 distinct `FOP1` operation IDs,
    /// returning the interventions the Events imply.
    ///
    /// The order check makes this index join a logical-sequence join.
    fn check_event_rows(
        &self,
        graph: &ImportedForkClassifierGraphV1,
        evidence: &[ForkEventEvidenceV1],
    ) -> Result<DerivedInterventionsV1, Error> {
        let classifier = ForkEventClassifierV1::from_table(&graph.table);
        let table_digest = graph.table.digest();
        let mut derived = DerivedInterventionsV1::default();
        // `zip` stops at the shortest list; the `FAE1` codec's
        // `validate_structure` proved one `EOR1` and one `FOP1` per `FEE1`.
        let events = evidence
            .iter()
            .zip(&self.event_origins)
            .zip(&self.append_operations);
        for ((event, origin), operation) in events {
            let fields = operation.input();
            let classification = classifier.classify_identity(&fields.source)?;
            let (expected_origin, implied) =
                operation.expected_provenance(&graph.table, classification);
            let implied_digest = implied.as_ref().map(ForkInterventionAdmissionV1::digest);
            closure_rule(
                self.event_matches(event, fields, table_digest)
                    && *origin == expected_origin
                    && origin.digest() == fields.event_origin_digest
                    && implied_digest == fields.intervention_admission_digest,
            )?;
            if let Some(admission) = implied {
                derived.sequences.push(fields.logical_seq);
                derived.admissions.push(admission);
            }
        }
        let operation_ids = self
            .append_operations
            .iter()
            .map(|operation| operation.input().operation_id)
            .collect::<BTreeSet<_>>();
        closure_rule(operation_ids.len() == self.append_operations.len())?;
        Ok(derived)
    }

    /// P1–P4 and P8: one `FOP1` names exactly its Event, the child, `FAR1`,
    /// and `FCT1`.
    fn event_matches(
        &self,
        event: &ForkEventEvidenceV1,
        operation: &ForkAppendOperationInputV1,
        table_digest: Hash,
    ) -> bool {
        let envelope = event.envelope();
        let fields = envelope.input();
        operation.logical_seq == fields.origin_logical_seq.as_u64()
            && operation.child_timeline_id == self.fork_admission.fields().child_timeline_id
            && operation.fork_admission_digest == self.fork_admission_digest
            && operation.classifier_revision_digest == table_digest
            && operation.event_id == fields.event_id
            && operation.payload_hash == envelope.payload_hash()
            && operation.wall_time == fields.wall_time
    }

    /// `FAE1` field 7: the code-2 `POB1`.
    #[must_use]
    pub const fn principal_owner_binding(&self) -> &ImportedPrincipalOwnerBindingV1 {
        &self.principal_owner_binding
    }

    /// `FAE1` field 8: the code-2 `FAR1`.
    #[must_use]
    pub const fn fork_admission(&self) -> &ImportedForkAdmissionRecordV1 {
        &self.fork_admission
    }

    /// The ADR-099 digest of the exact code-2 `FAR1` bytes.
    #[must_use]
    pub const fn fork_admission_digest(&self) -> Hash {
        self.fork_admission_digest
    }

    /// `FAE1` field 9: every `EOR1`, in logical-sequence order.
    #[must_use]
    pub const fn event_origins(&self) -> &[EventOriginRecordV1] {
        self.event_origins.as_slice()
    }

    /// `FAE1` field 10: exactly the implied `FIA1` set, in logical-sequence order.
    #[must_use]
    pub const fn intervention_admissions(&self) -> &[ForkInterventionAdmissionV1] {
        self.intervention_admissions.as_slice()
    }

    /// `FAE1` fields 18–20, when the source registered a classifier.
    #[must_use]
    pub const fn classifier(&self) -> Option<&ImportedForkClassifierGraphV1> {
        self.classifier.as_ref()
    }

    /// `FAE1` field 21: one `FOP1` per Event, in logical-sequence order.
    #[must_use]
    pub const fn append_operations(&self) -> &[ForkAppendOperationV1] {
        self.append_operations.as_slice()
    }

    /// `FAE1` field 11: the code-2 `FPO1`.
    #[must_use]
    pub const fn publication_operation(&self) -> &ImportedForkPublicationOperationV1 {
        &self.publication_operation
    }

    /// `FAE1` field 12: the `FPB1`.
    #[must_use]
    pub const fn publication_binding(&self) -> &ForkPublicationBindingV1 {
        &self.publication_binding
    }

    /// `FAE1` field 13: the `FPA1`.
    #[must_use]
    pub const fn publication_artifact(&self) -> &ForkPublicationArtifactV1 {
        &self.publication_artifact
    }

    /// The only `FSM1` copy, nested in `FPA1` field 4; its signature is not
    /// verified here.
    #[must_use]
    pub const fn signed_manifest(&self) -> &SignedForkReproManifestV1 {
        self.publication_artifact.signed_manifest()
    }
}
