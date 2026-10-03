//! Public-seam tests for the #518 typed `FAE1` closure decode and its
//! store-independent ADR-105 cross-record validation.
//!
//! They cover the import-only code-2 `POB1`/`FAR1`/`FPO1` decoders, the strict
//! decode and order of every carried ADR-099 record, the closed error mapping,
//! and mutations of every closure equality: the code-2 origins, `FTI1`/`FAR1`,
//! `POB1`/`FAR1`/`FRM1`/`FSM1`, the `FPO1` source table, `IKR1`/`IKT1`, the
//! per-Fork rows G1–G8, and the per-Event rows P1–P8.

use ciborium::Value;
use pos_core::{
    fork_attribution_authority_origin_digest_v1, EventId, EventOriginRecordInputV1,
    EventOriginRecordV1, ForkAdmissionRecordInputV1, ForkAdmissionRecordV1,
    ForkAppendOperationInputV1, ForkAppendOperationV1, ForkAppendSourceIdentityV1,
    ForkAttributionAuthorityEnvelopeInputV1, ForkAttributionAuthorityEnvelopeV1,
    ForkAttributionAuthorityRecordsV1, ForkAttributionAuthorityUnsignedEnvelopeV1,
    ForkAttributionClassifierRecordsV1, ForkAttributionCodecErrorV1 as CodecError,
    ForkAttributionImportClosureErrorV1 as ClosureError, ForkAttributionImportClosureV1,
    ForkAttributionOriginV1, ForkAuthorityOriginV1, ForkClassifierRegistrationInputV1,
    ForkClassifierRegistrationV1, ForkClassifierSourceInputV1, ForkClassifierSourceV1,
    ForkClassifierTableInputV1, ForkClassifierTableV1, ForkEventClassifierV1, ForkEventEvidenceV1,
    ForkEventSourceDescriptorV1, ForkExternalInputRouteV1, ForkInterventionAdmissionInputV1,
    ForkInterventionAdmissionV1, ForkPublicationArtifactInputV1, ForkPublicationArtifactV1,
    ForkPublicationBindingInputV1, ForkPublicationBindingV1, ForkPublicationOperationInputV1,
    ForkPublicationOperationV1, ForkReproManifestInputV1, ForkReproManifestV1,
    ForkTimelineImportInputV1, ForkTimelineImportV1, Hash, ImportedForkAdmissionRecordV1,
    ImportedForkClassifierGraphV1, ImportedForkPublicationOperationV1, ImportedKeyRecordV1,
    ImportedKeyTombstoneV1, ImportedPrincipalOwnerBindingV1, KeyIdentityV1, KeyRoleV1, OwnerIdV1,
    PrincipalOwnerBindingInputV1, PrincipalOwnerBindingV1, PublicKey, Signature,
    SignedForkReproManifestV1, WallTime, MAX_FORK_ADMISSION_RECORD_BYTES_V1,
    MAX_FORK_PUBLICATION_OPERATION_BYTES_V1, MAX_IMPORTED_PRINCIPAL_OWNER_BINDING_BYTES_V1,
};
use ulid::Ulid;

pub mod common;

use common::{
    attribution_identity, encode, evidence, hash, issuer, items, timeline_id, Fallible, TestResult,
};

const PARENT_CUT: u64 = 4;
const PUBLICATION_OPERATION: u8 = 0x91;
const ROUTE_A_SCHEMA: u8 = 0x51;
const ROUTE_B_SCHEMA: u8 = 0x52;
const OTHER: u8 = 0x99;
/// The local `authority-origin-v1 = [1]`.
const LOCAL_ORIGIN: [u8; 2] = [0x81, 0x01];

/// The child segment of one fixture.
#[derive(Clone, Copy)]
enum Shape {
    /// Events at 5..=8 classified `(0,0)`, `(1,0)`, `(1,1)`, and `(1,1)`.
    Mixed,
    /// No Events; the source registered a classifier.
    EmptyClassified,
    /// No Events and no classifier triple.
    EmptyUnclassified,
}

impl Shape {
    const fn sequences(self) -> &'static [u64] {
        match self {
            Self::Mixed => &[5, 6, 7, 8],
            Self::EmptyClassified | Self::EmptyUnclassified => &[],
        }
    }
}

/// The derived records of one classified Event.
struct Provenance {
    origin: EventOriginRecordV1,
    intervention: Option<ForkInterventionAdmissionV1>,
    operation: ForkAppendOperationV1,
}

/// Every typed record of one consistent closure. Code-2 records are kept in
/// their local shape beside the origin digest that `FAE1` carries.
#[derive(Clone)]
struct Fixture {
    origin: Hash,
    binding: PrincipalOwnerBindingV1,
    binding_origin: Hash,
    admission: ForkAdmissionRecordV1,
    admission_origin: Hash,
    origins: Vec<EventOriginRecordV1>,
    interventions: Vec<ForkInterventionAdmissionV1>,
    classifier: Option<ImportedForkClassifierGraphV1>,
    operations: Vec<ForkAppendOperationV1>,
    manifest: SignedForkReproManifestV1,
    publication: ForkPublicationOperationV1,
    publication_origin: Hash,
    publication_binding: ForkPublicationBindingV1,
    artifact: ForkPublicationArtifactV1,
    key_record: ImportedKeyRecordV1,
    key_tombstone: Option<ImportedKeyTombstoneV1>,
    events: Vec<ForkEventEvidenceV1>,
    timeline_import: ForkTimelineImportV1,
}

fn owner(value: &str) -> Fallible<OwnerIdV1> {
    Ok(OwnerIdV1::new(value)?)
}

fn binding() -> Fallible<PrincipalOwnerBindingV1> {
    Ok(PrincipalOwnerBindingV1::new(PrincipalOwnerBindingInputV1 {
        operation_id: hash(0x21),
        principal_digest: hash(0x22),
        owner: owner("creator-a")?,
        origin: ForkAuthorityOriginV1::Local,
    })?)
}

fn admission(binding_digest: Hash) -> Fallible<ForkAdmissionRecordV1> {
    Ok(ForkAdmissionRecordV1::new(ForkAdmissionRecordInputV1 {
        operation_id: hash(0x31),
        principal_owner_binding_digest: binding_digest,
        creator: owner("creator-a")?,
        parent_timeline_id: timeline_id(1),
        child_timeline_id: timeline_id(2),
        room_revision_descriptor_hash: hash(0x41),
        parent_logical_head: PARENT_CUT,
        parent_chain_head_hash: hash(0x66),
        completed_fold_cursor: PARENT_CUT,
        post_fold_tick_boundary: PARENT_CUT,
        plugin_composition_hash: hash(0x42),
        attribution_required: true,
        origin: ForkAttributionOriginV1::Local,
    })?)
}

fn route(route: &str, schema: u8, intervention: bool) -> Fallible<ForkExternalInputRouteV1> {
    Ok(ForkExternalInputRouteV1::new(
        ForkEventSourceDescriptorV1::new(route, hash(schema))?,
        intervention,
    ))
}

fn routes() -> Fallible<Vec<ForkExternalInputRouteV1>> {
    Ok(vec![
        route("route-a", ROUTE_A_SCHEMA, true)?,
        route("route-b", ROUTE_B_SCHEMA, false)?,
    ])
}

fn classifier(admission_digest: Hash) -> Fallible<ImportedForkClassifierGraphV1> {
    let source = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
        room_revision_descriptor_hash: hash(0x41),
        registrar_identifier: "registrar-a".to_owned(),
        routes: routes()?,
    })?;
    let table = ForkClassifierTableV1::new(ForkClassifierTableInputV1 {
        child_timeline_id: timeline_id(2),
        fork_admission_digest: admission_digest,
        room_revision_descriptor_hash: hash(0x41),
        registrar_identifier: "registrar-a".to_owned(),
        source_configuration_revision_digest: source.digest(),
        routes: routes()?,
    })?;
    let registration = ForkClassifierRegistrationV1::new(ForkClassifierRegistrationInputV1 {
        operation_id: hash(0x61),
        child_timeline_id: timeline_id(2),
        fork_admission_digest: admission_digest,
        room_revision_descriptor_hash: hash(0x41),
        classifier_revision_digest: table.digest(),
    })?;
    Ok(ImportedForkClassifierGraphV1 {
        source,
        table,
        registration,
    })
}

fn external(route: &str, schema: u8) -> Fallible<ForkAppendSourceIdentityV1> {
    Ok(ForkAppendSourceIdentityV1::ExternalInput {
        adapter_identifier: "adapter-a".to_owned(),
        source: ForkEventSourceDescriptorV1::new(route, hash(schema))?,
    })
}

/// The source of the fixture Event at `seq`.
fn source_at(seq: u64) -> Fallible<ForkAppendSourceIdentityV1> {
    match seq {
        5 => Ok(ForkAppendSourceIdentityV1::HostInternal),
        6 => external("route-b", ROUTE_B_SCHEMA),
        _ => external("route-a", ROUTE_A_SCHEMA),
    }
}

/// Derive `EOR1`, the implied `FIA1`, and `FOP1` for one Event, exactly as
/// the source host's classified append does.
fn provenance(event: &ForkEventEvidenceV1, table: &ForkClassifierTableV1) -> Fallible<Provenance> {
    let fields = event.envelope().input();
    let seq = fields.origin_logical_seq.as_u64();
    let source = source_at(seq)?;
    let classification = ForkEventClassifierV1::from_table(table).classify_identity(&source)?;
    let draft = ForkAppendOperationInputV1 {
        operation_id: Hash::from_bytes([0xa0 | u8::try_from(seq)?; 32]),
        child_timeline_id: timeline_id(2),
        logical_seq: seq,
        event_id: fields.event_id,
        request_digest: hash(0xb0),
        source,
        wall_time: fields.wall_time,
        payload_hash: event.envelope().payload_hash(),
        classifier_revision_digest: table.digest(),
        fork_admission_digest: table.input().fork_admission_digest,
        event_origin_digest: hash(0x01),
        intervention_admission_digest: None,
    };
    let placeholder = ForkAppendOperationV1::new(draft.clone())?;
    let (origin, intervention) = placeholder.expected_provenance(table, classification);
    let intervention_digest = intervention
        .as_ref()
        .map(ForkInterventionAdmissionV1::digest);
    let operation = ForkAppendOperationV1::new(ForkAppendOperationInputV1 {
        event_origin_digest: origin.digest(),
        intervention_admission_digest: intervention_digest,
        ..draft
    })?;
    Ok(Provenance {
        origin,
        intervention,
        operation,
    })
}

fn signed_manifest(
    identity: KeyIdentityV1,
    input: ForkReproManifestInputV1,
) -> Fallible<SignedForkReproManifestV1> {
    Ok(SignedForkReproManifestV1::new(
        identity,
        ForkReproManifestV1::new(input)?,
        Signature::from_bytes([0x88; 64]),
    )?)
}

fn manifest_input(
    admission_digest: Hash,
    intervention_sequences: Vec<u64>,
    final_head: u64,
) -> ForkReproManifestInputV1 {
    ForkReproManifestInputV1 {
        parent_timeline_id: timeline_id(1),
        fork_timeline_id: timeline_id(2),
        admission_digest,
        room_revision_descriptor_hash: hash(0x41),
        parent_logical_head: PARENT_CUT,
        parent_chain_head_hash: hash(0x66),
        post_fold_tick_boundary: PARENT_CUT,
        plugin_composition_hash: hash(0x42),
        intervention_sequences,
        final_fork_logical_head: final_head,
        final_fork_chain_head_hash: hash(0x77),
    }
}

fn publication(
    manifest: &SignedForkReproManifestV1,
    admission_digest: Hash,
) -> Fallible<ForkPublicationOperationV1> {
    let fields = manifest.manifest().input();
    Ok(ForkPublicationOperationV1::new(ForkPublicationOperationInputV1 {
        operation_id: hash(PUBLICATION_OPERATION),
        child_timeline_id: timeline_id(2),
        final_logical_head: fields.final_fork_logical_head,
        final_chain_head_hash: fields.final_fork_chain_head_hash,
        admission_digest,
        signing_identity: attribution_identity(1),
        private_material_digest: hash(0x44),
        public_verification_key: PublicKey::from_bytes([0x55; 32]),
        signed_manifest_record_id: manifest.record_id(),
        origin: ForkAttributionOriginV1::Local,
    })?)
}

fn publication_binding(manifest: &SignedForkReproManifestV1) -> Fallible<ForkPublicationBindingV1> {
    Ok(ForkPublicationBindingV1::new(ForkPublicationBindingInputV1 {
        child_timeline_id: timeline_id(2),
        final_logical_head: manifest.manifest().input().final_fork_logical_head,
        operation_id: hash(PUBLICATION_OPERATION),
        signed_manifest_record_id: manifest.record_id(),
    })?)
}

fn artifact(
    manifest: &SignedForkReproManifestV1,
    operation_id: Hash,
) -> Fallible<ForkPublicationArtifactV1> {
    Ok(ForkPublicationArtifactV1::new(ForkPublicationArtifactInputV1 {
        signed_manifest_record_id: manifest.record_id(),
        operation_id,
        signed_manifest_bytes: manifest.to_canonical_cbor(),
    })?)
}

fn key_record(epoch: u64, material: Option<Hash>, key: u8) -> Fallible<ImportedKeyRecordV1> {
    Ok(ImportedKeyRecordV1::new(
        attribution_identity(epoch),
        material,
        PublicKey::from_bytes([key; 32]),
    )?)
}

fn tombstone(destroyed_material_digest: Hash) -> Fallible<ImportedKeyTombstoneV1> {
    Ok(ImportedKeyTombstoneV1::new(
        attribution_identity(1),
        destroyed_material_digest,
        hash(0x45),
        hash(0x46),
    )?)
}

fn timeline_import(local_head: u64) -> Fallible<ForkTimelineImportV1> {
    Ok(ForkTimelineImportV1::new(ForkTimelineImportInputV1 {
        child_timeline_id: timeline_id(2),
        name: Some("fork".to_owned()),
        owner: None,
        parent_timeline_id: timeline_id(1),
        parent_cut: PARENT_CUT,
        local_head,
        parent_chain_hash: hash(0x66),
    })?)
}

fn encode_all<T>(records: &[T], encode_one: fn(&T) -> Vec<u8>) -> Vec<Vec<u8>> {
    records.iter().map(encode_one).collect()
}

fn classifier_records(graph: &ImportedForkClassifierGraphV1) -> ForkAttributionClassifierRecordsV1 {
    ForkAttributionClassifierRecordsV1 {
        source: graph.source.to_canonical_cbor(),
        table: graph.table.to_canonical_cbor(),
        registration: graph.registration.to_canonical_cbor(),
    }
}

/// Sign `input` with a placeholder: closure validation never verifies the
/// issuer signature.
fn validate_input(
    input: ForkAttributionAuthorityEnvelopeInputV1,
) -> Fallible<Result<ForkAttributionImportClosureV1, ClosureError>> {
    let envelope = ForkAttributionAuthorityEnvelopeV1::new(
        ForkAttributionAuthorityUnsignedEnvelopeV1::new(input)?,
        Signature::from_bytes([OTHER; 64]),
    );
    Ok(ForkAttributionImportClosureV1::validate(&envelope))
}

impl Fixture {
    fn new(shape: Shape) -> Fallible<Self> {
        let origin = fork_attribution_authority_origin_digest_v1(
            hash(0x11),
            &issuer()?,
            hash(0x33),
            timeline_id(1),
            timeline_id(2),
        );
        let binding = binding()?;
        let imported_binding = ImportedPrincipalOwnerBindingV1::from_local(binding.clone(), origin);
        let admission = admission(imported_binding.digest())?;
        let admission_digest =
            ImportedForkAdmissionRecordV1::from_local(admission.clone(), origin).digest();
        let graph = classifier(admission_digest)?;
        let events = shape
            .sequences()
            .iter()
            .map(|seq| evidence(*seq, b"payload"))
            .collect::<Fallible<Vec<_>>>()?;
        let derived = events
            .iter()
            .map(|event| provenance(event, &graph.table))
            .collect::<Fallible<Vec<_>>>()?;
        let local_head = u64::try_from(events.len())?;
        let sequences = derived
            .iter()
            .filter(|record| record.intervention.is_some())
            .map(|record| record.operation.input().logical_seq)
            .collect();
        let input = manifest_input(admission_digest, sequences, PARENT_CUT + local_head);
        let manifest = signed_manifest(attribution_identity(1), input)?;
        Ok(Self {
            origin,
            binding,
            binding_origin: origin,
            admission,
            admission_origin: origin,
            origins: derived.iter().map(|record| record.origin.clone()).collect(),
            interventions: derived
                .iter()
                .filter_map(|record| record.intervention.clone())
                .collect(),
            operations: derived.into_iter().map(|record| record.operation).collect(),
            classifier: (!matches!(shape, Shape::EmptyUnclassified)).then_some(graph),
            publication: publication(&manifest, admission_digest)?,
            publication_origin: origin,
            publication_binding: publication_binding(&manifest)?,
            artifact: artifact(&manifest, hash(PUBLICATION_OPERATION))?,
            manifest,
            key_record: key_record(1, Some(hash(0x44)), 0x55)?,
            key_tombstone: None,
            events,
            timeline_import: timeline_import(local_head)?,
        })
    }

    fn imported_binding(&self) -> ImportedPrincipalOwnerBindingV1 {
        ImportedPrincipalOwnerBindingV1::from_local(self.binding.clone(), self.binding_origin)
    }

    fn imported_admission(&self) -> ImportedForkAdmissionRecordV1 {
        ImportedForkAdmissionRecordV1::from_local(self.admission.clone(), self.admission_origin)
    }

    fn imported_publication(&self) -> ImportedForkPublicationOperationV1 {
        ImportedForkPublicationOperationV1::from_local(
            self.publication.clone(),
            self.publication_origin,
        )
    }

    fn records(&self) -> ForkAttributionAuthorityRecordsV1 {
        ForkAttributionAuthorityRecordsV1 {
            principal_owner_binding: self.imported_binding().to_canonical_cbor(),
            fork_admission: self.imported_admission().to_canonical_cbor(),
            event_origins: encode_all(&self.origins, EventOriginRecordV1::to_canonical_cbor),
            intervention_admissions: encode_all(
                &self.interventions,
                ForkInterventionAdmissionV1::to_canonical_cbor,
            ),
            publication_operation: self.imported_publication().to_canonical_cbor(),
            publication_binding: self.publication_binding.to_canonical_cbor(),
            publication_artifact: self.artifact.to_canonical_cbor(),
        }
    }

    fn input(&self) -> Fallible<ForkAttributionAuthorityEnvelopeInputV1> {
        Ok(ForkAttributionAuthorityEnvelopeInputV1 {
            import_operation_id: hash(0x11),
            issuer: issuer()?,
            issuer_policy_digest: hash(0x33),
            records: self.records(),
            key_record: self.key_record,
            key_tombstone: self.key_tombstone,
            event_evidence: self.events.clone(),
            timeline_import: self.timeline_import.clone(),
            classifier: self.classifier.as_ref().map(classifier_records),
            append_operations: encode_all(
                &self.operations,
                ForkAppendOperationV1::to_canonical_cbor,
            ),
        })
    }

    fn validate(&self) -> Fallible<Result<ForkAttributionImportClosureV1, ClosureError>> {
        validate_input(self.input()?)
    }

    fn rejection(&self) -> Fallible<Option<ClosureError>> {
        Ok(self.validate()?.err())
    }

    /// Replace the source key with a destroyed key and its tombstone.
    fn destroy_key(&mut self, destroyed_material_digest: Hash) -> TestResult {
        self.key_record = key_record(1, None, 0x55)?;
        self.key_tombstone = Some(tombstone(destroyed_material_digest)?);
        Ok(())
    }

    fn graph(&mut self) -> Fallible<&mut ImportedForkClassifierGraphV1> {
        Ok(self.classifier.as_mut().ok_or("no classifier")?)
    }
}

#[test]
fn complete_mixed_closure_validates_with_every_record() -> TestResult {
    let fixture = Fixture::new(Shape::Mixed)?;
    let closure = fixture.validate()??;
    let binding = fixture.imported_binding();
    assert_eq!(closure.principal_owner_binding(), &binding);
    assert_eq!(binding.authority_origin_digest(), fixture.origin);
    let admission = fixture.imported_admission();
    assert_eq!(closure.fork_admission(), &admission);
    assert_eq!(closure.fork_admission_digest(), admission.digest());
    assert_eq!(closure.event_origins(), fixture.origins.as_slice());
    assert_eq!(
        closure.intervention_admissions(),
        fixture.interventions.as_slice()
    );
    assert_eq!(closure.intervention_admissions().len(), 2);
    assert_eq!(closure.classifier(), fixture.classifier.as_ref());
    assert_eq!(closure.append_operations(), fixture.operations.as_slice());
    assert_eq!(
        closure.publication_operation(),
        &fixture.imported_publication()
    );
    assert_eq!(closure.publication_binding(), &fixture.publication_binding);
    assert_eq!(closure.publication_artifact(), &fixture.artifact);
    assert_eq!(closure.signed_manifest(), &fixture.manifest);
    assert_eq!(fixture.artifact.signed_manifest(), &fixture.manifest);
    Ok(())
}

#[test]
fn destroyed_key_and_empty_closures_validate() -> TestResult {
    let mut destroyed = Fixture::new(Shape::Mixed)?;
    destroyed.destroy_key(hash(0x44))?;
    assert!(destroyed.validate()?.is_ok());
    let classified = Fixture::new(Shape::EmptyClassified)?.validate()??;
    assert!(classified.classifier().is_some());
    assert!(classified.event_origins().is_empty());
    let unclassified = Fixture::new(Shape::EmptyUnclassified)?.validate()??;
    assert_eq!(unclassified.classifier(), None);
    assert!(unclassified.append_operations().is_empty());
    Ok(())
}

#[test]
fn closure_errors_name_the_public_import_errors() {
    let cases = [
        (ClosureError::InvalidEncoding, "encoding is invalid"),
        (ClosureError::UnsupportedVersion, "version is unsupported"),
        (ClosureError::BoundsExceeded, "exceeds a bound"),
        (ClosureError::InvalidAuthorityClosure, "inconsistent"),
    ];
    for (error, text) in cases {
        assert!(error.to_string().contains(text));
    }
}

/// Replace the final local `[1]` origin of `local` with `[2, digest]`.
fn code_two(local: &[u8], digest: Hash) -> Vec<u8> {
    let mut out = local.strip_suffix(&LOCAL_ORIGIN).unwrap_or(local).to_vec();
    out.extend_from_slice(&[0x82, 0x02, 0x58, 0x20]);
    out.extend_from_slice(digest.as_bytes());
    out
}

#[test]
fn import_decoders_round_trip_exact_code_two_bytes() -> TestResult {
    let fixture = Fixture::new(Shape::Mixed)?;
    let digest = hash(0x5a);
    let binding = code_two(&fixture.binding.to_canonical_cbor(), digest);
    let decoded = ImportedPrincipalOwnerBindingV1::from_canonical_cbor(&binding)?;
    assert_eq!(decoded.to_canonical_cbor(), binding);
    assert_eq!(decoded.authority_origin_digest(), digest);
    let admission = code_two(&fixture.admission.to_canonical_cbor(), digest);
    let decoded = ImportedForkAdmissionRecordV1::from_canonical_cbor(&admission)?;
    assert_eq!(decoded.to_canonical_cbor(), admission);
    assert_eq!(decoded.authority_origin_digest(), digest);
    let publication = code_two(&fixture.publication.to_canonical_cbor(), digest);
    let decoded = ImportedForkPublicationOperationV1::from_canonical_cbor(&publication)?;
    assert_eq!(decoded.to_canonical_cbor(), publication);
    assert_eq!(decoded.authority_origin_digest(), digest);
    Ok(())
}

fn oversize(maximum: usize) -> Vec<u8> {
    vec![0x82; maximum + 1]
}

#[test]
fn import_decoders_reject_bounds_local_origin_and_malformed_tails() -> TestResult {
    let fixture = Fixture::new(Shape::Mixed)?;
    let binding = fixture.binding.to_canonical_cbor();
    let admission = fixture.admission.to_canonical_cbor();
    let publication = fixture.publication.to_canonical_cbor();
    let short = [0x82, 0x02, 0x58, 0x20, 0x01];
    let binding_bound = oversize(MAX_IMPORTED_PRINCIPAL_OWNER_BINDING_BYTES_V1);
    let admission_bound = oversize(MAX_FORK_ADMISSION_RECORD_BYTES_V1);
    let publication_bound = oversize(MAX_FORK_PUBLICATION_OPERATION_BYTES_V1);
    let cases = [
        (
            ImportedPrincipalOwnerBindingV1::from_canonical_cbor(&binding_bound).err(),
            CodecError::FieldOutOfBounds,
        ),
        (
            ImportedPrincipalOwnerBindingV1::from_canonical_cbor(&binding).err(),
            CodecError::FieldMismatch,
        ),
        (
            ImportedPrincipalOwnerBindingV1::from_canonical_cbor(&short).err(),
            CodecError::InvalidEncoding,
        ),
        (
            ImportedForkAdmissionRecordV1::from_canonical_cbor(&admission_bound).err(),
            CodecError::FieldOutOfBounds,
        ),
        (
            ImportedForkAdmissionRecordV1::from_canonical_cbor(&admission).err(),
            CodecError::FieldMismatch,
        ),
        (
            ImportedForkPublicationOperationV1::from_canonical_cbor(&publication_bound).err(),
            CodecError::FieldOutOfBounds,
        ),
        (
            ImportedForkPublicationOperationV1::from_canonical_cbor(&publication).err(),
            CodecError::FieldMismatch,
        ),
    ];
    for (actual, expected) in cases {
        assert_eq!(actual, Some(expected));
    }
    Ok(())
}

type InputEdit = fn(&mut ForkAttributionAuthorityEnvelopeInputV1) -> TestResult;

/// Validate the mixed fixture after `edit` replaces carried bytes.
fn reject_input(
    edit: impl FnOnce(&mut ForkAttributionAuthorityEnvelopeInputV1) -> TestResult,
) -> Fallible<Option<ClosureError>> {
    let mut input = Fixture::new(Shape::Mixed)?.input()?;
    edit(&mut input)?;
    Ok(validate_input(input)?.err())
}

/// Re-encode `record` with field `at` replaced by `value`.
fn edited(record: &[u8], at: usize, value: Value) -> Fallible<Vec<u8>> {
    let mut fields = items(record)?;
    *fields.get_mut(at).ok_or("field index")? = value;
    encode(fields)
}

fn first(records: &mut [Vec<u8>]) -> Fallible<&mut Vec<u8>> {
    Ok(records.first_mut().ok_or("no record")?)
}

fn int(value: u64) -> Value {
    Value::Integer(value.into())
}

fn garbage() -> Vec<u8> {
    b"garbage".to_vec()
}

#[test]
fn code_two_records_reject_local_origin_and_malformed_bytes() -> TestResult {
    let local = Fixture::new(Shape::Mixed)?;
    let binding = local.binding.to_canonical_cbor();
    let admission = local.admission.to_canonical_cbor();
    let publication = local.publication.to_canonical_cbor();
    let mut undecodable = vec![0x00];
    undecodable.extend(code_two(&LOCAL_ORIGIN, hash(0x5a)));
    let cases = [
        (binding, 0, ClosureError::InvalidAuthorityClosure),
        (undecodable, 0, ClosureError::InvalidEncoding),
        (admission, 1, ClosureError::InvalidAuthorityClosure),
        (garbage(), 1, ClosureError::InvalidEncoding),
        (publication, 2, ClosureError::InvalidAuthorityClosure),
        (garbage(), 2, ClosureError::InvalidEncoding),
    ];
    for (bytes, record, expected) in cases {
        let rejection = reject_input(|input| {
            let records = &mut input.records;
            match record {
                0 => records.principal_owner_binding = bytes,
                1 => records.fork_admission = bytes,
                _ => records.publication_operation = bytes,
            }
            Ok(())
        })?;
        assert_eq!(rejection, Some(expected));
    }
    Ok(())
}

#[test]
fn code_two_admission_maps_version_and_bound_failures() -> TestResult {
    let admission = Fixture::new(Shape::Mixed)?.records().fork_admission;
    let version = edited(&admission, 1, int(2))?;
    let zero_operation = edited(&admission, 2, Value::Bytes(vec![0; 32]))?;
    let cases = [
        (version, ClosureError::UnsupportedVersion),
        (zero_operation, ClosureError::BoundsExceeded),
    ];
    for (bytes, expected) in cases {
        let rejection = reject_input(|input| {
            input.records.fork_admission = bytes;
            Ok(())
        })?;
        assert_eq!(rejection, Some(expected));
    }
    Ok(())
}

#[test]
fn event_origin_failures_map_to_closed_import_errors() -> TestResult {
    let records = Fixture::new(Shape::Mixed)?.records();
    let origin = records.event_origins.first().ok_or("origin")?;
    let cases = [
        (1, 2, ClosureError::UnsupportedVersion),
        (3, 0, ClosureError::BoundsExceeded),
        (5, 2, ClosureError::InvalidEncoding),
        (6, 1, ClosureError::InvalidAuthorityClosure),
    ];
    for (at, value, expected) in cases {
        let bytes = edited(origin, at, int(value))?;
        let rejection = reject_input(|input| {
            *first(&mut input.records.event_origins)? = bytes;
            Ok(())
        })?;
        assert_eq!(rejection, Some(expected));
    }
    Ok(())
}

#[test]
fn every_carried_record_rejects_malformed_bytes() -> TestResult {
    let cases: [InputEdit; 8] = [
        |input| {
            *first(&mut input.records.event_origins)? = garbage();
            Ok(())
        },
        |input| {
            *first(&mut input.records.intervention_admissions)? = garbage();
            Ok(())
        },
        |input| {
            input.classifier.as_mut().ok_or("classifier")?.source = garbage();
            Ok(())
        },
        |input| {
            input.classifier.as_mut().ok_or("classifier")?.table = garbage();
            Ok(())
        },
        |input| {
            input.classifier.as_mut().ok_or("classifier")?.registration = garbage();
            Ok(())
        },
        |input| {
            *first(&mut input.append_operations)? = garbage();
            Ok(())
        },
        |input| {
            input.records.publication_binding = garbage();
            Ok(())
        },
        |input| {
            input.records.publication_artifact = garbage();
            Ok(())
        },
    ];
    for edit in cases {
        assert_eq!(reject_input(edit)?, Some(ClosureError::InvalidEncoding));
    }
    Ok(())
}

/// Swap the first two carried records of one list.
fn swap_first_two(records: &mut [Vec<u8>]) -> TestResult {
    if records.len() < 2 {
        return Err("fewer than two records".into());
    }
    records.swap(0, 1);
    Ok(())
}

#[test]
fn nested_records_reject_noncanonical_order_and_bounds() -> TestResult {
    let fixture = Fixture::new(Shape::Mixed)?;
    let graph = classifier_records(fixture.classifier.as_ref().ok_or("classifier")?);
    let source = items(&graph.source)?;
    let Some(Value::Array(routes)) = source.get(4) else {
        return Err("routes".into());
    };
    let duplicate_route = [routes.clone(), routes.clone()].concat();
    let source = edited(&graph.source, 4, Value::Array(duplicate_route))?;
    let registration = edited(&graph.registration, 2, Value::Bytes(vec![0; 32]))?;
    let artifact = unordered_manifest_artifact(&fixture)?;
    let cases = [
        (source, 0, ClosureError::InvalidEncoding),
        (registration, 1, ClosureError::BoundsExceeded),
        (artifact, 2, ClosureError::InvalidEncoding),
    ];
    for (bytes, record, expected) in cases {
        let rejection = reject_input(|input| {
            let classifier = input.classifier.as_mut().ok_or("classifier")?;
            match record {
                0 => classifier.source = bytes,
                1 => classifier.registration = bytes,
                _ => input.records.publication_artifact = bytes,
            }
            Ok(())
        })?;
        assert_eq!(rejection, Some(expected));
    }
    Ok(())
}

/// An `FPA1` whose nested `FRM1` lists its interventions out of order.
fn unordered_manifest_artifact(fixture: &Fixture) -> Fallible<Vec<u8>> {
    let manifest = fixture.manifest.manifest_bytes();
    let unordered = edited(&manifest, 10, Value::Array(vec![int(8), int(7)]))?;
    let signed = edited(
        &fixture.manifest.to_canonical_cbor(),
        5,
        Value::Bytes(unordered),
    )?;
    edited(
        &fixture.artifact.to_canonical_cbor(),
        4,
        Value::Bytes(signed),
    )
}

#[test]
fn carried_lists_must_be_in_strict_logical_sequence_order() -> TestResult {
    let cases: [InputEdit; 4] = [
        |input| swap_first_two(&mut input.records.event_origins),
        |input| swap_first_two(&mut input.records.intervention_admissions),
        |input| swap_first_two(&mut input.append_operations),
        |input| {
            let admissions = &mut input.records.intervention_admissions;
            let repeated = first(admissions)?.clone();
            admissions.insert(0, repeated);
            Ok(())
        },
    ];
    for edit in cases {
        assert_eq!(reject_input(edit)?, Some(ClosureError::InvalidEncoding));
    }
    Ok(())
}

/// Apply each edit to a fresh fixture and require `InvalidAuthorityClosure`.
fn assert_each_inconsistent<T>(
    shape: Shape,
    apply: fn(&mut Fixture, fn(&mut T)) -> TestResult,
    edits: &[fn(&mut T)],
) -> TestResult {
    for (index, edit) in edits.iter().enumerate() {
        let mut fixture = Fixture::new(shape)?;
        apply(&mut fixture, *edit)?;
        assert_eq!(
            fixture.rejection()?,
            Some(ClosureError::InvalidAuthorityClosure),
            "edit {index}"
        );
    }
    Ok(())
}

fn apply_admission(fixture: &mut Fixture, edit: fn(&mut ForkAdmissionRecordInputV1)) -> TestResult {
    let mut input = fixture.admission.input().clone();
    edit(&mut input);
    fixture.admission = ForkAdmissionRecordV1::new(input)?;
    Ok(())
}

/// Re-sign `FSM1` over the edited `FRM1` and rebuild only `FPA1`, so that
/// `FPO1` and `FPB1` keep the old record ID.
fn apply_manifest(fixture: &mut Fixture, edit: fn(&mut ForkReproManifestInputV1)) -> TestResult {
    let mut input = fixture.manifest.manifest().input().clone();
    edit(&mut input);
    fixture.manifest = signed_manifest(fixture.manifest.identity(), input)?;
    fixture.artifact = artifact(&fixture.manifest, hash(PUBLICATION_OPERATION))?;
    Ok(())
}

fn apply_publication(
    fixture: &mut Fixture,
    edit: fn(&mut ForkPublicationOperationInputV1),
) -> TestResult {
    let mut input = fixture.publication.input().clone();
    edit(&mut input);
    fixture.publication = ForkPublicationOperationV1::new(input)?;
    Ok(())
}

fn apply_publication_binding(
    fixture: &mut Fixture,
    edit: fn(&mut ForkPublicationBindingInputV1),
) -> TestResult {
    let mut input = *fixture.publication_binding.input();
    edit(&mut input);
    fixture.publication_binding = ForkPublicationBindingV1::new(input)?;
    Ok(())
}

#[test]
fn origins_and_timeline_coordinates_must_match() -> TestResult {
    let origin_edits: [fn(&mut Fixture); 3] = [
        |fixture| fixture.binding_origin = hash(OTHER),
        |fixture| fixture.admission_origin = hash(OTHER),
        |fixture| fixture.publication_origin = hash(OTHER),
    ];
    for edit in origin_edits {
        let mut fixture = Fixture::new(Shape::Mixed)?;
        edit(&mut fixture);
        assert_eq!(
            fixture.rejection()?,
            Some(ClosureError::InvalidAuthorityClosure)
        );
    }
    assert_each_inconsistent::<ForkAdmissionRecordInputV1>(
        Shape::Mixed,
        apply_admission,
        &[
            // FAR1 parent.
            |far| far.parent_timeline_id = timeline_id(3),
            // FAR1 child.
            |far| far.child_timeline_id = timeline_id(3),
            // FAR1 cut.
            |far| {
                far.parent_logical_head = 3;
                far.completed_fold_cursor = 3;
                far.post_fold_tick_boundary = 3;
            },
            // FAR1 parent hash.
            |far| far.parent_chain_head_hash = hash(OTHER),
            // FAR1 POB1 digest.
            |far| {
                far.principal_owner_binding_digest = hash(OTHER);
            },
            // FAR1 descriptor.
            |far| {
                far.room_revision_descriptor_hash = hash(OTHER);
            },
            // FAR1 composition.
            |far| far.plugin_composition_hash = hash(OTHER),
        ],
    )
}

#[test]
fn creator_manifest_and_publication_records_must_match() -> TestResult {
    assert_each_inconsistent::<ForkReproManifestInputV1>(
        Shape::Mixed,
        apply_manifest,
        &[
            // FRM1 FAR1 digest.
            |frm| frm.admission_digest = hash(OTHER),
            // FRM1 descriptor.
            |frm| {
                frm.room_revision_descriptor_hash = hash(OTHER);
            },
            // FRM1 final head.
            |frm| frm.final_fork_logical_head += 1,
            // FRM1 final hash.
            |frm| frm.final_fork_chain_head_hash = hash(OTHER),
            // FRM1 interventions.
            |frm| frm.intervention_sequences = vec![8],
        ],
    )?;
    assert_each_inconsistent::<ForkPublicationOperationInputV1>(
        Shape::Mixed,
        apply_publication,
        &[
            // FPO1 child.
            |fpo| fpo.child_timeline_id = timeline_id(3),
            // FPO1 final head.
            |fpo| fpo.final_logical_head += 1,
            // FPO1 final hash.
            |fpo| fpo.final_chain_head_hash = hash(OTHER),
            // FPO1 FAR1 digest.
            |fpo| fpo.admission_digest = hash(OTHER),
            // FPO1 epoch.
            |fpo| fpo.signing_identity = attribution_identity(2),
            // FPO1 record ID.
            |fpo| fpo.signed_manifest_record_id = hash(OTHER),
        ],
    )?;
    assert_each_inconsistent::<ForkPublicationBindingInputV1>(
        Shape::Mixed,
        apply_publication_binding,
        &[
            // FPB1 child.
            |fpb| fpb.child_timeline_id = timeline_id(3),
            // FPB1 final head.
            |fpb| fpb.final_logical_head += 1,
            // FPB1 operation.
            |fpb| fpb.operation_id = hash(OTHER),
            // FPB1 record ID.
            |fpb| fpb.signed_manifest_record_id = hash(OTHER),
        ],
    )
}

#[test]
fn creator_signer_and_artifact_operation_must_match() -> TestResult {
    let mut owner_changed = Fixture::new(Shape::Mixed)?;
    owner_changed.binding = PrincipalOwnerBindingV1::new(PrincipalOwnerBindingInputV1 {
        owner: owner("creator-b")?,
        ..owner_changed.binding.input().clone()
    })?;
    let mut signer_changed = Fixture::new(Shape::Mixed)?;
    signer_changed.manifest = signed_manifest(
        KeyIdentityV1::new("creator-b", KeyRoleV1::SubjectAttributionSigning, 1),
        signer_changed.manifest.manifest().input().clone(),
    )?;
    signer_changed.artifact = artifact(&signer_changed.manifest, hash(PUBLICATION_OPERATION))?;
    let mut operation_changed = Fixture::new(Shape::Mixed)?;
    operation_changed.artifact = artifact(&operation_changed.manifest, hash(OTHER))?;
    for fixture in [owner_changed, signer_changed, operation_changed] {
        assert_eq!(
            fixture.rejection()?,
            Some(ClosureError::InvalidAuthorityClosure)
        );
    }
    Ok(())
}

#[test]
fn retained_key_evidence_must_match_the_publication() -> TestResult {
    let mut epoch = Fixture::new(Shape::Mixed)?;
    epoch.key_record = key_record(2, Some(hash(0x44)), 0x55)?;
    let mut public_key = Fixture::new(Shape::Mixed)?;
    public_key.key_record = key_record(1, Some(hash(0x44)), 0x56)?;
    let mut material = Fixture::new(Shape::Mixed)?;
    material.key_record = key_record(1, Some(hash(0x45)), 0x55)?;
    let mut destroyed = Fixture::new(Shape::Mixed)?;
    destroyed.destroy_key(hash(0x47))?;
    for fixture in [epoch, public_key, material, destroyed] {
        assert_eq!(
            fixture.rejection()?,
            Some(ClosureError::InvalidAuthorityClosure)
        );
    }
    Ok(())
}

fn apply_source(fixture: &mut Fixture, edit: fn(&mut ForkClassifierSourceInputV1)) -> TestResult {
    let graph = fixture.graph()?;
    let mut input = graph.source.input().clone();
    edit(&mut input);
    graph.source = ForkClassifierSourceV1::new(input)?;
    Ok(())
}

fn apply_table(fixture: &mut Fixture, edit: fn(&mut ForkClassifierTableInputV1)) -> TestResult {
    let graph = fixture.graph()?;
    let mut input = graph.table.input().clone();
    edit(&mut input);
    graph.table = ForkClassifierTableV1::new(input)?;
    Ok(())
}

fn apply_registration(
    fixture: &mut Fixture,
    edit: fn(&mut ForkClassifierRegistrationInputV1),
) -> TestResult {
    let graph = fixture.graph()?;
    let mut input = graph.registration.input().clone();
    edit(&mut input);
    graph.registration = ForkClassifierRegistrationV1::new(input)?;
    Ok(())
}

/// G1–G7 against a classified closure of `shape`.
fn assert_classifier_rows(shape: Shape) -> TestResult {
    assert_each_inconsistent::<ForkClassifierSourceInputV1>(
        shape,
        apply_source,
        &[
            // FCS1 descriptor.
            |fcs| {
                fcs.room_revision_descriptor_hash = hash(OTHER);
            },
            // FCS1 registrar.
            |fcs| {
                fcs.registrar_identifier = "registrar-b".to_owned();
            },
            // FCS1 routes.
            |fcs| fcs.routes.truncate(1),
        ],
    )?;
    assert_each_inconsistent::<ForkClassifierTableInputV1>(
        shape,
        apply_table,
        &[
            // FCT1 child.
            |fct| fct.child_timeline_id = timeline_id(3),
            // FCT1 FAR1 digest.
            |fct| fct.fork_admission_digest = hash(OTHER),
            // FCT1 descriptor.
            |fct| {
                fct.room_revision_descriptor_hash = hash(OTHER);
            },
            // FCT1 registrar.
            |fct| {
                fct.registrar_identifier = "registrar-b".to_owned();
            },
            // FCT1 FCS1 digest.
            |fct| {
                fct.source_configuration_revision_digest = hash(OTHER);
            },
            // FCT1 route removed.
            |fct| fct.routes.truncate(1),
        ],
    )?;
    assert_each_inconsistent::<ForkClassifierRegistrationInputV1>(
        shape,
        apply_registration,
        &[
            // FCR1 child.
            |fcr| fcr.child_timeline_id = timeline_id(3),
            // FCR1 FAR1 digest.
            |fcr| fcr.fork_admission_digest = hash(OTHER),
            // FCR1 descriptor.
            |fcr| {
                fcr.room_revision_descriptor_hash = hash(OTHER);
            },
            // FCR1 FCT1 digest.
            |fcr| {
                fcr.classifier_revision_digest = hash(OTHER);
            },
        ],
    )
}

#[test]
fn per_fork_classifier_rows_must_match() -> TestResult {
    assert_classifier_rows(Shape::Mixed)?;
    assert_classifier_rows(Shape::EmptyClassified)
}

#[test]
fn classifier_routes_must_be_copied_exactly() -> TestResult {
    let extra = route("route-c", 0x53, false)?;
    let flipped = route("route-a", ROUTE_A_SCHEMA, false)?;
    for (at, replacement) in [(2, extra), (0, flipped)] {
        let mut fixture = Fixture::new(Shape::Mixed)?;
        let graph = fixture.graph()?;
        let mut input = graph.table.input().clone();
        if at < input.routes.len() {
            input.routes.remove(at);
        }
        input.routes.insert(at, replacement);
        graph.table = ForkClassifierTableV1::new(input)?;
        assert_eq!(
            fixture.rejection()?,
            Some(ClosureError::InvalidAuthorityClosure)
        );
    }
    Ok(())
}

fn apply_operations(
    fixture: &mut Fixture,
    edit: fn(&mut Vec<ForkAppendOperationInputV1>),
) -> TestResult {
    let mut inputs = fixture
        .operations
        .iter()
        .map(|operation| operation.input().clone())
        .collect();
    edit(&mut inputs);
    fixture.operations = inputs
        .into_iter()
        .map(ForkAppendOperationV1::new)
        .collect::<Result<_, _>>()?;
    Ok(())
}

#[test]
fn per_event_operation_rows_must_match() -> TestResult {
    assert_each_inconsistent::<Vec<ForkAppendOperationInputV1>>(
        Shape::Mixed,
        apply_operations,
        &[
            // FOP1 child.
            |ops| ops[1].child_timeline_id = timeline_id(3),
            // FOP1 sequence.
            |ops| ops[3].logical_seq = 9,
            // FOP1 Event ID.
            |ops| {
                ops[1].event_id = EventId::from_ulid(Ulid::from_parts(99, 7));
            },
            // FOP1 payload hash.
            |ops| ops[1].payload_hash = hash(OTHER),
            // FOP1 wall time.
            |ops| ops[1].wall_time = WallTime::from_micros(9),
            // FOP1 FCT1 digest.
            |ops| {
                ops[1].classifier_revision_digest = hash(OTHER);
            },
            // FOP1 FAR1 digest.
            |ops| ops[1].fork_admission_digest = hash(OTHER),
            // FOP1 EOR1 digest.
            |ops| ops[1].event_origin_digest = hash(OTHER),
            // FOP1 FIA1 dropped.
            |ops| {
                ops[2].intervention_admission_digest = None;
            },
            // FOP1 FIA1 added.
            |ops| {
                ops[1].intervention_admission_digest = Some(hash(OTHER));
            },
            // FOP1 FIA1 value.
            |ops| {
                ops[2].intervention_admission_digest = Some(hash(OTHER));
            },
            // FOP1 operation ID reused.
            |ops| {
                ops[1].operation_id = ops[0].operation_id;
            },
        ],
    )
}

#[test]
fn an_unadmitted_source_route_rejects_the_closure() -> TestResult {
    let mut fixture = Fixture::new(Shape::Mixed)?;
    let operation = fixture.operations.get_mut(1).ok_or("operation")?;
    *operation = ForkAppendOperationV1::new(ForkAppendOperationInputV1 {
        source: external("route-z", 0x53)?,
        ..operation.input().clone()
    })?;
    assert_eq!(
        fixture.rejection()?,
        Some(ClosureError::InvalidAuthorityClosure)
    );
    Ok(())
}

fn apply_origins(
    fixture: &mut Fixture,
    edit: fn(&mut Vec<EventOriginRecordInputV1>),
) -> TestResult {
    let mut inputs = fixture
        .origins
        .iter()
        .map(|origin| origin.input().clone())
        .collect();
    edit(&mut inputs);
    fixture.origins = inputs
        .into_iter()
        .map(EventOriginRecordV1::new)
        .collect::<Result<_, _>>()?;
    Ok(())
}

fn apply_interventions(
    fixture: &mut Fixture,
    edit: fn(&mut Vec<ForkInterventionAdmissionInputV1>),
) -> TestResult {
    let mut inputs = fixture
        .interventions
        .iter()
        .map(|intervention| intervention.input().clone())
        .collect();
    edit(&mut inputs);
    fixture.interventions = inputs
        .into_iter()
        .map(ForkInterventionAdmissionV1::new)
        .collect::<Result<_, _>>()?;
    Ok(())
}

#[test]
fn origin_and_intervention_records_must_be_exactly_implied() -> TestResult {
    assert_each_inconsistent::<Vec<EventOriginRecordInputV1>>(
        Shape::Mixed,
        apply_origins,
        &[
            // EOR1 FCT1 digest.
            |origins| {
                origins[0].classifier_revision_digest = hash(OTHER);
            },
            // EOR1 classification.
            |origins| {
                origins[1].classification = origins[0].classification;
            },
        ],
    )?;
    assert_each_inconsistent::<Vec<ForkInterventionAdmissionInputV1>>(
        Shape::Mixed,
        apply_interventions,
        &[
            // FIA1 operation ID.
            |admissions| {
                admissions[0].operation_id = hash(OTHER);
            },
            // FIA1 descriptor.
            |admissions| {
                admissions[0].room_revision_descriptor_hash = hash(OTHER);
            },
            // FIA1 missing.
            |admissions| {
                admissions.remove(0);
            },
            // FIA1 for a non-intervention.
            |admissions| {
                let mut extra = admissions[0].clone();
                extra.logical_seq = 6;
                admissions.insert(0, extra);
            },
        ],
    )
}
