use pos_core::{
    ForkAdmissionRecordInputV1, ForkAdmissionRecordV1, ForkAttributionCodecErrorV1,
    ForkAttributionOriginV1, ForkPublicationArtifactInputV1, ForkPublicationArtifactV1,
    ForkPublicationBindingInputV1, ForkPublicationBindingV1, ForkPublicationOperationInputV1,
    ForkPublicationOperationV1, ForkPublicationReceiptV1, ForkReproManifestInputV1,
    ForkReproManifestV1, Hash, KeyIdentityV1, KeyRoleV1, PublicKey, SignedForkReproManifestV1,
    TimelineId,
};

/// Bytes from the `FRM1` intervention array head to the end of the fixture
/// manifest: the intervention array `[5, 7]` (3 bytes), the final Fork logical
/// head `7` (1 byte), and the final chain hash as `bstr .size 32` (2-byte head
/// plus 32 bytes).
const FRM1_SUFFIX_FROM_INTERVENTIONS_BYTES: usize = 3 + 1 + 2 + 32;

/// Offset of the version uint in every publication record: the one-byte array
/// head plus the five-byte text marker (`0x64` and four ASCII bytes).
const PUBLICATION_VERSION_AT: usize = 1 + 5;

/// Offset of the first record ID byte in `FPA1`: the version byte follows
/// [`PUBLICATION_VERSION_AT`], then the two-byte `bstr .size 32` head.
const FPA1_RECORD_ID_AT: usize = PUBLICATION_VERSION_AT + 1 + 2;

/// Type-erased public decoder for one publication record kind.
type PublicationDecodeV1 = fn(&[u8]) -> Result<(), ForkAttributionCodecErrorV1>;

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

fn admission() -> Result<ForkAdmissionRecordV1, ForkAttributionCodecErrorV1> {
    ForkAdmissionRecordV1::new(ForkAdmissionRecordInputV1 {
        operation_id: hash(1),
        principal_owner_binding_digest: hash(2),
        creator: "creator-a".into(),
        parent_timeline_id: TimelineId::new(),
        child_timeline_id: TimelineId::new(),
        room_revision_descriptor_hash: hash(3),
        parent_logical_head: 4,
        parent_chain_head_hash: hash(4),
        completed_fold_cursor: 4,
        post_fold_tick_boundary: 4,
        plugin_composition_hash: hash(5),
        attribution_required: true,
        origin: ForkAttributionOriginV1::Local,
    })
}

fn manifest(
    admission: &ForkAdmissionRecordV1,
) -> Result<ForkReproManifestV1, ForkAttributionCodecErrorV1> {
    ForkReproManifestV1::from_admission(admission, vec![5, 7], 7, hash(6))
}

fn publication_records(
    admission: &ForkAdmissionRecordV1,
) -> Result<
    (
        ForkPublicationOperationV1,
        ForkPublicationBindingV1,
        ForkPublicationArtifactV1,
    ),
    ForkAttributionCodecErrorV1,
> {
    let signed = SignedForkReproManifestV1::new_from_admission(
        admission,
        1,
        manifest(admission)?,
        pos_core::Signature::from_bytes([9; 64]),
    )?;
    let operation_id = hash(7);
    let operation = ForkPublicationOperationV1::new(ForkPublicationOperationInputV1 {
        operation_id,
        child_timeline_id: admission.input().child_timeline_id,
        final_logical_head: 7,
        final_chain_head_hash: hash(6),
        admission_digest: admission.digest(),
        signing_identity: signed.identity(),
        private_material_digest: hash(8),
        public_verification_key: PublicKey::from_bytes([10; 32]),
        signed_manifest_record_id: signed.record_id(),
        origin: ForkAttributionOriginV1::Local,
    })?;
    let binding = ForkPublicationBindingV1::new(ForkPublicationBindingInputV1 {
        child_timeline_id: admission.input().child_timeline_id,
        final_logical_head: 7,
        operation_id,
        signed_manifest_record_id: signed.record_id(),
    })?;
    let artifact = ForkPublicationArtifactV1::new(ForkPublicationArtifactInputV1 {
        signed_manifest_record_id: signed.record_id(),
        operation_id,
        signed_manifest_bytes: signed.to_canonical_cbor(),
    })?;
    Ok((operation, binding, artifact))
}

#[test]
fn local_fpo1_fpb1_fpa1_and_derived_fpr1_round_trip_at_public_seam(
) -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let (operation, binding, artifact) = publication_records(&admission)?;
    assert_eq!(
        &operation.to_canonical_cbor()[..6],
        &[0x8e, 0x64, b'F', b'P', b'O', b'1']
    );
    assert_eq!(
        &binding.to_canonical_cbor()[..6],
        &[0x86, 0x64, b'F', b'P', b'B', b'1']
    );
    assert_eq!(
        &artifact.to_canonical_cbor()[..6],
        &[0x85, 0x64, b'F', b'P', b'A', b'1']
    );
    assert_eq!(
        ForkPublicationOperationV1::from_canonical_cbor(&operation.to_canonical_cbor()),
        Ok(operation.clone())
    );
    assert_eq!(
        ForkPublicationBindingV1::from_canonical_cbor(&binding.to_canonical_cbor()),
        Ok(binding)
    );
    assert_eq!(
        ForkPublicationArtifactV1::from_canonical_cbor(&artifact.to_canonical_cbor()),
        Ok(artifact)
    );
    let receipt = ForkPublicationReceiptV1::from_records(&operation, &binding)?;
    assert_eq!(
        &receipt.to_canonical_cbor()[..6],
        &[0x86, 0x64, b'F', b'P', b'R', b'1']
    );
    Ok(())
}

#[test]
fn publication_codecs_reject_import_origin_and_mismatched_artifact(
) -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let (operation, _binding, artifact) = publication_records(&admission)?;
    let local = operation.to_canonical_cbor();
    let origin_at = local.len() - 2;
    assert_eq!(local[origin_at..], [0x81, 0x01]);
    let mut bare_code_2 = local.clone();
    bare_code_2[origin_at + 1] = 2;
    assert_eq!(
        ForkPublicationOperationV1::from_canonical_cbor(&bare_code_2),
        Err(ForkAttributionCodecErrorV1::InvalidEncoding)
    );
    // ADR-099 authority-origin-v1 code 2: [2, bstr .size 32].
    let mut imported = local[..origin_at].to_vec();
    imported.extend_from_slice(&[0x82, 0x02, 0x58, 0x20]);
    imported.extend_from_slice(&[0xab; 32]);
    assert_eq!(
        ForkPublicationOperationV1::from_canonical_cbor(&imported),
        Err(ForkAttributionCodecErrorV1::ImportedAuthorityUnavailable)
    );
    imported.push(0);
    assert_eq!(
        ForkPublicationOperationV1::from_canonical_cbor(&imported),
        Err(ForkAttributionCodecErrorV1::InvalidEncoding)
    );
    let mut mismatched = artifact.input().clone();
    mismatched.signed_manifest_record_id = hash(99);
    assert_eq!(
        ForkPublicationArtifactV1::new(mismatched),
        Err(ForkAttributionCodecErrorV1::FieldMismatch)
    );
    Ok(())
}

#[test]
fn publication_constructors_reject_zero_ids_and_foreign_signer_roles(
) -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let (operation, binding, artifact) = publication_records(&admission)?;
    let mut zero_operation = operation.input().clone();
    zero_operation.private_material_digest = Hash::zero();
    let mut wrong_role = operation.input().clone();
    wrong_role.signing_identity.role = KeyRoleV1::TimelineIntegritySigning;
    let mut zero_epoch = operation.input().clone();
    zero_epoch.signing_identity.epoch = 0;
    for input in [zero_operation, wrong_role, zero_epoch] {
        assert_eq!(
            ForkPublicationOperationV1::new(input),
            Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
        );
    }
    let mut zero_binding = *binding.input();
    zero_binding.signed_manifest_record_id = Hash::zero();
    assert_eq!(
        ForkPublicationBindingV1::new(zero_binding),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut zero_artifact = artifact.input().clone();
    zero_artifact.operation_id = Hash::zero();
    assert_eq!(
        ForkPublicationArtifactV1::new(zero_artifact),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut foreign_head = *binding.input();
    foreign_head.final_logical_head = 8;
    assert_eq!(
        ForkPublicationReceiptV1::from_records(
            &operation,
            &ForkPublicationBindingV1::new(foreign_head)?
        ),
        Err(ForkAttributionCodecErrorV1::FieldMismatch)
    );
    Ok(())
}

#[test]
fn publication_operation_accepts_zero_genesis_chain_hash_of_empty_fork(
) -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let (operation, _binding, _artifact) = publication_records(&admission)?;
    let mut genesis = operation.input().clone();
    genesis.final_chain_head_hash = Hash::zero();
    let operation = ForkPublicationOperationV1::new(genesis)?;
    assert_eq!(
        ForkPublicationOperationV1::from_canonical_cbor(&operation.to_canonical_cbor()),
        Ok(operation)
    );
    Ok(())
}

#[test]
fn publication_decoders_reject_role_codes_and_noncanonical_heads(
) -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let (operation, binding, _artifact) = publication_records(&admission)?;
    let local = operation.to_canonical_cbor();
    let role_at = local
        .windows(b"creator-a".len())
        .position(|bytes| bytes == b"creator-a")
        .ok_or("encoded creator is absent")?
        + b"creator-a".len();
    assert_eq!(local[role_at..role_at + 2], [0x01, 0x01]);
    for (role, expected) in [
        (vec![0x02], ForkAttributionCodecErrorV1::FieldOutOfBounds),
        (vec![0x17], ForkAttributionCodecErrorV1::InvalidEncoding),
        (
            vec![0x19, 0x01, 0x00],
            ForkAttributionCodecErrorV1::InvalidEncoding,
        ),
    ] {
        let mut bytes = local[..role_at].to_vec();
        bytes.extend_from_slice(&role);
        bytes.extend_from_slice(&local[role_at + 1..]);
        assert_eq!(
            ForkPublicationOperationV1::from_canonical_cbor(&bytes),
            Err(expected)
        );
    }
    // The final logical head 7 follows the marker, version, and fixed-width
    // fields: FPO1 operation ID plus child Fork ID, FPB1 child Fork ID only.
    let mut operation_head = local;
    assert_eq!(operation_head[58], 7);
    operation_head[58] = 0x18;
    operation_head.insert(59, 7);
    assert_eq!(
        ForkPublicationOperationV1::from_canonical_cbor(&operation_head),
        Err(ForkAttributionCodecErrorV1::NonCanonical)
    );
    let mut binding_head = binding.to_canonical_cbor();
    assert_eq!(binding_head[24], 7);
    binding_head[24] = 0x18;
    binding_head.insert(25, 7);
    assert_eq!(
        ForkPublicationBindingV1::from_canonical_cbor(&binding_head),
        Err(ForkAttributionCodecErrorV1::NonCanonical)
    );
    Ok(())
}

#[test]
fn publication_decoders_reject_version_trailing_byte_and_oversize_input(
) -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let (operation, binding, artifact) = publication_records(&admission)?;
    let codecs: [(Vec<u8>, usize, PublicationDecodeV1); 3] = [
        (
            operation.to_canonical_cbor(),
            pos_core::MAX_FORK_PUBLICATION_OPERATION_BYTES_V1,
            |bytes| ForkPublicationOperationV1::from_canonical_cbor(bytes).map(drop),
        ),
        (
            binding.to_canonical_cbor(),
            pos_core::MAX_FORK_PUBLICATION_BINDING_BYTES_V1,
            |bytes| ForkPublicationBindingV1::from_canonical_cbor(bytes).map(drop),
        ),
        (
            artifact.to_canonical_cbor(),
            pos_core::MAX_FORK_PUBLICATION_ARTIFACT_BYTES_V1,
            |bytes| ForkPublicationArtifactV1::from_canonical_cbor(bytes).map(drop),
        ),
    ];
    for (canonical, maximum, decode) in codecs {
        assert_eq!(decode(&canonical), Ok(()));
        assert_eq!(canonical[PUBLICATION_VERSION_AT], 1);
        let mut version = canonical.clone();
        version[PUBLICATION_VERSION_AT] = 2;
        assert_eq!(
            decode(&version),
            Err(ForkAttributionCodecErrorV1::UnsupportedVersion)
        );
        let mut marker = canonical.clone();
        marker[PUBLICATION_VERSION_AT - 4] = b'X';
        assert_eq!(
            decode(&marker),
            Err(ForkAttributionCodecErrorV1::InvalidEncoding)
        );
        let mut trailing = canonical;
        trailing.push(0);
        assert_eq!(
            decode(&trailing),
            Err(ForkAttributionCodecErrorV1::InvalidEncoding)
        );
        assert_eq!(
            decode(&vec![0; maximum + 1]),
            Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
        );
    }
    Ok(())
}

#[test]
fn fpa1_decoder_rejects_record_id_disagreeing_with_nested_fsm1(
) -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let (_operation, _binding, artifact) = publication_records(&admission)?;
    let mut patched = artifact.to_canonical_cbor();
    let record_id = FPA1_RECORD_ID_AT..FPA1_RECORD_ID_AT + 32;
    assert_eq!(
        patched[FPA1_RECORD_ID_AT - 2..FPA1_RECORD_ID_AT],
        [0x58, 0x20]
    );
    assert_eq!(
        patched[record_id.clone()],
        *artifact.input().signed_manifest_record_id.as_bytes()
    );
    patched[record_id].fill(0xab);
    assert_eq!(
        ForkPublicationArtifactV1::from_canonical_cbor(&patched),
        Err(ForkAttributionCodecErrorV1::FieldMismatch)
    );
    Ok(())
}

#[test]
fn worst_case_derived_fpr1_fits_its_exported_bound() -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let (operation, binding, _artifact) = publication_records(&admission)?;
    let mut widest_operation = operation.input().clone();
    widest_operation.final_logical_head = u64::MAX;
    let mut widest_binding = *binding.input();
    widest_binding.final_logical_head = u64::MAX;
    let receipt = ForkPublicationReceiptV1::from_records(
        &ForkPublicationOperationV1::new(widest_operation)?,
        &ForkPublicationBindingV1::new(widest_binding)?,
    )?;
    assert_eq!(receipt.final_logical_head, u64::MAX);
    assert!(receipt.to_canonical_cbor().len() <= pos_core::MAX_FORK_PUBLICATION_RECEIPT_BYTES_V1);
    Ok(())
}

#[test]
fn local_far1_frm1_and_fsm1_round_trip_at_public_seam() -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let manifest = manifest(&admission)?;
    manifest.validate_against_admission(&admission)?;
    let far1 = admission.to_canonical_cbor();
    assert_eq!(&far1[..6], &[0x8f, 0x64, b'F', b'A', b'R', b'1']);
    let mut binary_far1_marker = far1.clone();
    binary_far1_marker[1] = 0x44;
    assert_eq!(
        ForkAdmissionRecordV1::from_canonical_cbor(&binary_far1_marker),
        Err(ForkAttributionCodecErrorV1::InvalidEncoding)
    );
    let manifest_wire = manifest.to_canonical_cbor();
    assert_eq!(&manifest_wire[..6], &[0x8d, 0x64, b'F', b'R', b'M', b'1']);
    let mut binary_manifest_marker = manifest_wire.clone();
    binary_manifest_marker[1] = 0x44;
    assert_eq!(
        ForkReproManifestV1::from_canonical_cbor(&binary_manifest_marker),
        Err(ForkAttributionCodecErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ForkAdmissionRecordV1::from_canonical_cbor(&far1),
        Ok(admission)
    );
    assert_eq!(
        ForkReproManifestV1::from_canonical_cbor(&manifest_wire),
        Ok(manifest.clone())
    );
    let outer = SignedForkReproManifestV1::new(
        KeyIdentityV1::new("creator-a", KeyRoleV1::SubjectAttributionSigning, 1),
        manifest,
        pos_core::Signature::from_bytes([9; 64]),
    )?;
    let signed_wire = outer.to_canonical_cbor();
    assert_eq!(&signed_wire[..6], &[0x87, 0x64, b'F', b'S', b'M', b'1']);
    let mut binary_signed_marker = signed_wire.clone();
    binary_signed_marker[1] = 0x44;
    assert_eq!(
        SignedForkReproManifestV1::from_canonical_cbor(&binary_signed_marker),
        Err(ForkAttributionCodecErrorV1::InvalidEncoding)
    );
    assert_eq!(outer.manifest().to_canonical_cbor(), outer.manifest_bytes());
    assert_ne!(outer.record_id(), Hash::zero());
    assert_eq!(
        SignedForkReproManifestV1::from_canonical_cbor(&signed_wire),
        Ok(outer)
    );
    Ok(())
}

#[test]
fn admission_bound_construction_derives_creator_and_rejects_creator_b_or_admission_b(
) -> Result<(), Box<dyn std::error::Error>> {
    let admission_a = admission()?;
    let manifest_a = manifest(&admission_a)?;
    let derived = SignedForkReproManifestV1::new_from_admission(
        &admission_a,
        1,
        manifest_a.clone(),
        pos_core::Signature::from_bytes([9; 64]),
    )?;
    assert_eq!(derived.identity().owner_id, admission_a.input().creator);
    assert_eq!(derived.validate_against_admission(&admission_a), Ok(()));
    assert_eq!(
        SignedForkReproManifestV1::new_from_admission(
            &admission_a,
            0,
            manifest_a.clone(),
            pos_core::Signature::from_bytes([9; 64]),
        ),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );

    let creator_b = SignedForkReproManifestV1::new(
        KeyIdentityV1::new("creator-b", KeyRoleV1::SubjectAttributionSigning, 1),
        manifest_a.clone(),
        pos_core::Signature::from_bytes([9; 64]),
    )?;
    assert_eq!(
        creator_b.validate_against_admission(&admission_a),
        Err(ForkAttributionCodecErrorV1::FieldMismatch)
    );

    let mut admission_b_input = admission_a.input().clone();
    admission_b_input.child_timeline_id = TimelineId::new();
    let admission_b = ForkAdmissionRecordV1::new(admission_b_input)?;
    assert_eq!(
        SignedForkReproManifestV1::new_from_admission(
            &admission_b,
            1,
            manifest_a,
            pos_core::Signature::from_bytes([9; 64]),
        ),
        Err(ForkAttributionCodecErrorV1::FieldMismatch)
    );
    Ok(())
}

#[test]
fn local_far1_rejects_reserved_import_origin_and_noncanonical_bytes(
) -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let mut binary_creator = admission.to_canonical_cbor();
    let creator_at = binary_creator
        .windows(b"creator-a".len())
        .position(|bytes| bytes == b"creator-a")
        .ok_or("encoded creator is absent")?;
    binary_creator[creator_at - 1] = 0x49;
    assert_eq!(
        ForkAdmissionRecordV1::from_canonical_cbor(&binary_creator),
        Err(ForkAttributionCodecErrorV1::InvalidEncoding)
    );
    let local = admission.to_canonical_cbor();
    let origin_at = local.len() - 2;
    assert_eq!(local[origin_at..], [0x81, 0x01]);
    let mut bare_code_2 = local.clone();
    bare_code_2[origin_at + 1] = 2;
    assert_eq!(
        ForkAdmissionRecordV1::from_canonical_cbor(&bare_code_2),
        Err(ForkAttributionCodecErrorV1::InvalidEncoding)
    );
    // ADR-099 authority-origin-v1 code 2: [2, bstr .size 32].
    let mut imported = local[..origin_at].to_vec();
    imported.extend_from_slice(&[0x82, 0x02, 0x58, 0x20]);
    imported.extend_from_slice(&[0xab; 32]);
    assert_eq!(
        ForkAdmissionRecordV1::from_canonical_cbor(&imported),
        Err(ForkAttributionCodecErrorV1::ImportedAuthorityUnavailable)
    );
    let mut imported_trailing = imported.clone();
    imported_trailing.push(0);
    assert_eq!(
        ForkAdmissionRecordV1::from_canonical_cbor(&imported_trailing),
        Err(ForkAttributionCodecErrorV1::InvalidEncoding)
    );
    let short_imported = &imported[..imported.len() - 1];
    assert_eq!(
        ForkAdmissionRecordV1::from_canonical_cbor(short_imported),
        Err(ForkAttributionCodecErrorV1::InvalidEncoding)
    );
    let mut local_with_payload = imported;
    local_with_payload[origin_at + 1] = 1;
    assert_eq!(
        ForkAdmissionRecordV1::from_canonical_cbor(&local_with_payload),
        Err(ForkAttributionCodecErrorV1::InvalidEncoding)
    );
    let mut noncanonical = admission.to_canonical_cbor();
    noncanonical[6] = 0x18;
    noncanonical.insert(7, 1);
    assert_eq!(
        ForkAdmissionRecordV1::from_canonical_cbor(&noncanonical),
        Err(ForkAttributionCodecErrorV1::NonCanonical)
    );
    Ok(())
}

#[test]
fn manifest_rejects_unordered_out_of_range_and_mismatched_provenance(
) -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let input = admission.input();
    assert_eq!(
        ForkReproManifestV1::new(ForkReproManifestInputV1 {
            parent_timeline_id: input.parent_timeline_id,
            fork_timeline_id: input.child_timeline_id,
            admission_digest: admission.digest(),
            room_revision_descriptor_hash: input.room_revision_descriptor_hash,
            parent_logical_head: input.parent_logical_head,
            parent_chain_head_hash: input.parent_chain_head_hash,
            post_fold_tick_boundary: input.post_fold_tick_boundary,
            plugin_composition_hash: input.plugin_composition_hash,
            intervention_sequences: vec![7, 6],
            final_fork_logical_head: 7,
            final_fork_chain_head_hash: hash(6),
        }),
        Err(ForkAttributionCodecErrorV1::InterventionOrder)
    );
    let matching = manifest(&admission)?;
    let incorrect = ForkReproManifestV1::new(ForkReproManifestInputV1 {
        parent_timeline_id: input.parent_timeline_id,
        fork_timeline_id: input.child_timeline_id,
        admission_digest: hash(99),
        room_revision_descriptor_hash: input.room_revision_descriptor_hash,
        parent_logical_head: input.parent_logical_head,
        parent_chain_head_hash: input.parent_chain_head_hash,
        post_fold_tick_boundary: input.post_fold_tick_boundary,
        plugin_composition_hash: input.plugin_composition_hash,
        intervention_sequences: vec![],
        final_fork_logical_head: input.parent_logical_head,
        final_fork_chain_head_hash: hash(7),
    })?;
    assert_eq!(
        incorrect.validate_against_admission(&admission),
        Err(ForkAttributionCodecErrorV1::FieldMismatch)
    );
    assert_eq!(matching.validate_against_admission(&admission), Ok(()));
    Ok(())
}

#[test]
fn admission_constructor_rejects_each_required_cut_invariant(
) -> Result<(), Box<dyn std::error::Error>> {
    let valid = admission()?.input().clone();
    let mut operation = valid.clone();
    operation.operation_id = Hash::zero();
    assert_eq!(
        ForkAdmissionRecordV1::new(operation),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut binding = valid.clone();
    binding.principal_owner_binding_digest = Hash::zero();
    assert_eq!(
        ForkAdmissionRecordV1::new(binding),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut descriptor = valid.clone();
    descriptor.room_revision_descriptor_hash = Hash::zero();
    assert_eq!(
        ForkAdmissionRecordV1::new(descriptor),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut composition = valid.clone();
    composition.plugin_composition_hash = Hash::zero();
    assert_eq!(
        ForkAdmissionRecordV1::new(composition),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut timelines = valid.clone();
    timelines.child_timeline_id = timelines.parent_timeline_id;
    assert_eq!(
        ForkAdmissionRecordV1::new(timelines),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut fold = valid.clone();
    fold.completed_fold_cursor += 1;
    assert_eq!(
        ForkAdmissionRecordV1::new(fold),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut tick = valid;
    tick.post_fold_tick_boundary += 1;
    assert_eq!(
        ForkAdmissionRecordV1::new(tick),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn far1_decoder_rejects_malformed_fields_and_limits() -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let canonical = admission.to_canonical_cbor();
    let cases = [
        (0, 0x8e, ForkAttributionCodecErrorV1::InvalidEncoding),
        (2, b'X', ForkAttributionCodecErrorV1::InvalidEncoding),
        (6, 2, ForkAttributionCodecErrorV1::UnsupportedVersion),
        (
            canonical.len() - 3,
            2,
            ForkAttributionCodecErrorV1::InvalidEncoding,
        ),
        (
            canonical.len() - 1,
            3,
            ForkAttributionCodecErrorV1::InvalidEncoding,
        ),
    ];
    for (at, replacement, expected) in cases {
        let mut malformed = canonical.clone();
        malformed[at] = replacement;
        assert_eq!(
            ForkAdmissionRecordV1::from_canonical_cbor(&malformed),
            Err(expected)
        );
    }
    let mut trailing = canonical;
    trailing.push(0);
    assert_eq!(
        ForkAdmissionRecordV1::from_canonical_cbor(&trailing),
        Err(ForkAttributionCodecErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ForkAdmissionRecordV1::from_canonical_cbor(&[0x8f, 0x44, b'F']),
        Err(ForkAttributionCodecErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ForkAdmissionRecordV1::from_canonical_cbor(&vec![
            0;
            pos_core::MAX_FORK_ADMISSION_RECORD_BYTES_V1
                + 1
        ]),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn manifest_constructor_and_decoder_enforce_bounds() -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let valid = manifest(&admission)?.input().clone();
    let mut timelines = valid.clone();
    timelines.fork_timeline_id = timelines.parent_timeline_id;
    assert_eq!(
        ForkReproManifestV1::new(timelines),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut digest = valid.clone();
    digest.admission_digest = Hash::zero();
    assert_eq!(
        ForkReproManifestV1::new(digest),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut descriptor = valid.clone();
    descriptor.room_revision_descriptor_hash = Hash::zero();
    assert_eq!(
        ForkReproManifestV1::new(descriptor),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut composition = valid.clone();
    composition.plugin_composition_hash = Hash::zero();
    assert_eq!(
        ForkReproManifestV1::new(composition),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut final_head = valid.clone();
    final_head.final_fork_logical_head = final_head.parent_logical_head - 1;
    assert_eq!(
        ForkReproManifestV1::new(final_head),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut lower_bound = valid.clone();
    lower_bound.intervention_sequences = vec![lower_bound.parent_logical_head];
    assert_eq!(
        ForkReproManifestV1::new(lower_bound),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut upper_bound = valid.clone();
    upper_bound.intervention_sequences = vec![upper_bound.final_fork_logical_head + 1];
    assert_eq!(
        ForkReproManifestV1::new(upper_bound),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    // ADR-099: post-fold Tick Boundary must equal the parent cut.
    let mut tick = valid.clone();
    tick.post_fold_tick_boundary += 1;
    assert_eq!(
        ForkReproManifestV1::new(tick),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut too_many = valid;
    too_many.parent_logical_head = 0;
    too_many.post_fold_tick_boundary = 0;
    too_many.final_fork_logical_head = 1_025;
    too_many.intervention_sequences = (1..=1_025).collect();
    assert_eq!(
        ForkReproManifestV1::new(too_many),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        ForkReproManifestV1::from_canonical_cbor(&vec![
            0;
            pos_core::MAX_FORK_REPRO_MANIFEST_BYTES_V1
                + 1
        ]),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn wide_cbor_coordinates_round_trip_at_the_public_seam() -> Result<(), Box<dyn std::error::Error>> {
    let parent = TimelineId::new();
    let child = TimelineId::new();
    let admission = ForkAdmissionRecordV1::new(ForkAdmissionRecordInputV1 {
        operation_id: hash(1),
        principal_owner_binding_digest: hash(2),
        creator: "creator-with-an-owner-id-24".into(),
        parent_timeline_id: parent,
        child_timeline_id: child,
        room_revision_descriptor_hash: hash(3),
        parent_logical_head: 24,
        parent_chain_head_hash: hash(4),
        completed_fold_cursor: 24,
        post_fold_tick_boundary: 24,
        plugin_composition_hash: hash(5),
        attribution_required: false,
        origin: ForkAttributionOriginV1::Local,
    })?;
    let manifest = ForkReproManifestV1::new(ForkReproManifestInputV1 {
        parent_timeline_id: parent,
        fork_timeline_id: child,
        admission_digest: admission.digest(),
        room_revision_descriptor_hash: hash(3),
        parent_logical_head: 24,
        parent_chain_head_hash: hash(4),
        post_fold_tick_boundary: 24,
        plugin_composition_hash: hash(5),
        intervention_sequences: vec![25, 256, 65_536],
        final_fork_logical_head: 4_294_967_296,
        final_fork_chain_head_hash: hash(6),
    })?;
    assert_eq!(
        ForkAdmissionRecordV1::from_canonical_cbor(&admission.to_canonical_cbor()),
        Ok(admission)
    );
    assert_eq!(
        ForkReproManifestV1::from_canonical_cbor(&manifest.to_canonical_cbor()),
        Ok(manifest.clone())
    );
    let signed = SignedForkReproManifestV1::new(
        KeyIdentityV1::new(
            "creator-with-an-owner-id-24",
            KeyRoleV1::SubjectAttributionSigning,
            u64::MAX,
        ),
        manifest,
        pos_core::Signature::from_bytes([9; 64]),
    )?;
    assert_eq!(
        SignedForkReproManifestV1::from_canonical_cbor(&signed.to_canonical_cbor()),
        Ok(signed)
    );
    Ok(())
}

#[test]
fn fsm1_rejects_non_attribution_identities_and_outer_limits(
) -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let manifest = manifest(&admission)?;
    assert_eq!(
        SignedForkReproManifestV1::new(
            KeyIdentityV1::new("creator-a", KeyRoleV1::TimelineIntegritySigning, 1),
            manifest.clone(),
            pos_core::Signature::from_bytes([9; 64]),
        ),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        SignedForkReproManifestV1::new(
            KeyIdentityV1::new("creator-a", KeyRoleV1::SubjectAttributionSigning, 0),
            manifest,
            pos_core::Signature::from_bytes([9; 64]),
        ),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        SignedForkReproManifestV1::from_canonical_cbor(&vec![
            0;
            pos_core::MAX_SIGNED_FORK_REPRO_MANIFEST_BYTES_V1
                + 1
        ]),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn every_truncated_attribution_record_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let manifest = manifest(&admission)?;
    let signed = SignedForkReproManifestV1::new(
        KeyIdentityV1::new("creator-a", KeyRoleV1::SubjectAttributionSigning, 1),
        manifest.clone(),
        pos_core::Signature::from_bytes([9; 64]),
    )?;
    let admission_bytes = admission.to_canonical_cbor();
    let manifest_bytes = manifest.to_canonical_cbor();
    let signed_bytes = signed.to_canonical_cbor();
    let truncated = ForkAttributionCodecErrorV1::InvalidEncoding;
    for length in 0..admission_bytes.len() {
        assert_eq!(
            ForkAdmissionRecordV1::from_canonical_cbor(&admission_bytes[..length]),
            Err(truncated)
        );
    }
    for length in 0..manifest_bytes.len() {
        assert_eq!(
            ForkReproManifestV1::from_canonical_cbor(&manifest_bytes[..length]),
            Err(truncated)
        );
    }
    for length in 0..signed_bytes.len() {
        assert_eq!(
            SignedForkReproManifestV1::from_canonical_cbor(&signed_bytes[..length]),
            Err(truncated)
        );
    }
    Ok(())
}

#[test]
fn public_attribution_decoders_reject_forbidden_cbor_shapes(
) -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let manifest = manifest(&admission)?;
    let signed = SignedForkReproManifestV1::new(
        KeyIdentityV1::new("creator-a", KeyRoleV1::SubjectAttributionSigning, 1),
        manifest,
        pos_core::Signature::from_bytes([9; 64]),
    )?;
    let invalid_prefixes: [&[u8]; 9] = [
        &[],
        &[0x9f],
        &[0xbf],
        &[0x5f],
        &[0x7f],
        &[0xff],
        &[0x98, 15],
        &[0x8f, 0x44, b'F', b'A', b'R', b'1', 0x18, 1],
        &[0x8f, 0x44, b'F', b'A', b'R', b'1', 0x01, 0x78, 0x80],
    ];
    let invalid = ForkAttributionCodecErrorV1::InvalidEncoding;
    for bytes in invalid_prefixes {
        assert_eq!(
            ForkAdmissionRecordV1::from_canonical_cbor(bytes),
            Err(invalid)
        );
        assert_eq!(
            ForkReproManifestV1::from_canonical_cbor(bytes),
            Err(invalid)
        );
        assert_eq!(
            SignedForkReproManifestV1::from_canonical_cbor(bytes),
            Err(invalid)
        );
    }
    let mut bad_bool = admission.to_canonical_cbor();
    let bool_at = bad_bool.len() - 3;
    bad_bool[bool_at] = 2;
    assert_eq!(
        ForkAdmissionRecordV1::from_canonical_cbor(&bad_bool),
        Err(invalid)
    );
    let mut bad_signature = signed.to_canonical_cbor();
    bad_signature.pop();
    assert_eq!(
        SignedForkReproManifestV1::from_canonical_cbor(&bad_signature),
        Err(invalid)
    );
    Ok(())
}

#[test]
fn manifest_decoder_rejects_count_coordinates_and_noncanonical_sequence(
) -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let canonical = manifest(&admission)?.to_canonical_cbor();
    let sequences_at = canonical
        .len()
        .checked_sub(FRM1_SUFFIX_FROM_INTERVENTIONS_BYTES)
        .ok_or("manifest is shorter than its sequence suffix")?;
    assert_eq!(
        &canonical[sequences_at..sequences_at + 3],
        &[0x82, 0x05, 0x07]
    );

    let mut too_many = canonical.clone();
    too_many.splice(sequences_at..=sequences_at, [0x99, 0x04, 0x01]);
    assert_eq!(
        ForkReproManifestV1::from_canonical_cbor(&too_many),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );

    let mut bad_final_head = canonical.clone();
    bad_final_head[sequences_at + 3] = 3;
    assert_eq!(
        ForkReproManifestV1::from_canonical_cbor(&bad_final_head),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );

    let mut noncanonical = canonical.clone();
    noncanonical.splice(sequences_at + 1..sequences_at + 2, [0x18, 0x05]);
    assert_eq!(
        ForkReproManifestV1::from_canonical_cbor(&noncanonical),
        Err(ForkAttributionCodecErrorV1::NonCanonical)
    );

    let mut trailing = canonical;
    trailing.push(0);
    assert_eq!(
        ForkReproManifestV1::from_canonical_cbor(&trailing),
        Err(ForkAttributionCodecErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn signed_manifest_decoder_rejects_identity_length_and_inner_mutations(
) -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let inner = manifest(&admission)?;
    let signed = SignedForkReproManifestV1::new(
        KeyIdentityV1::new("creator-a", KeyRoleV1::SubjectAttributionSigning, 1),
        inner,
        pos_core::Signature::from_bytes([9; 64]),
    )?;
    let canonical = signed.to_canonical_cbor();
    let owner_at = canonical
        .windows(b"creator-a".len())
        .position(|window| window == b"creator-a")
        .ok_or("owner marker is absent")?;
    let role_at = owner_at + b"creator-a".len();

    let mut oversized_owner = canonical.clone();
    oversized_owner.splice(owner_at - 1..owner_at, [0x79, 0x00, 0x81]);
    assert_eq!(
        SignedForkReproManifestV1::from_canonical_cbor(&oversized_owner),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut empty_owner = canonical.clone();
    empty_owner[owner_at - 1] = 0x60;
    assert_eq!(
        SignedForkReproManifestV1::from_canonical_cbor(&empty_owner),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut unknown_role = canonical.clone();
    unknown_role[role_at] = 0x17;
    assert_eq!(
        SignedForkReproManifestV1::from_canonical_cbor(&unknown_role),
        Err(ForkAttributionCodecErrorV1::InvalidEncoding)
    );
    let mut oversized_role = canonical.clone();
    oversized_role.splice(role_at..=role_at, [0x19, 0x01, 0x00]);
    assert_eq!(
        SignedForkReproManifestV1::from_canonical_cbor(&oversized_role),
        Err(ForkAttributionCodecErrorV1::InvalidEncoding)
    );
    let mut zero_epoch = canonical.clone();
    zero_epoch[role_at + 1] = 0;
    assert_eq!(
        SignedForkReproManifestV1::from_canonical_cbor(&zero_epoch),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut noncanonical_epoch = canonical.clone();
    noncanonical_epoch.splice(role_at + 1..role_at + 2, [0x18, 0x01]);
    assert_eq!(
        SignedForkReproManifestV1::from_canonical_cbor(&noncanonical_epoch),
        Err(ForkAttributionCodecErrorV1::NonCanonical)
    );

    let inner_bytes = signed.manifest_bytes();
    let inner_at = canonical
        .windows(inner_bytes.len())
        .position(|window| window == inner_bytes)
        .ok_or("inner manifest marker is absent")?;
    assert_eq!(canonical[inner_at - 2], 0x58);
    let mut oversized_inner = canonical.clone();
    oversized_inner.splice(inner_at - 2..inner_at, [0x59, 0x40, 0x01]);
    assert_eq!(
        SignedForkReproManifestV1::from_canonical_cbor(&oversized_inner),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut invalid_inner = canonical.clone();
    invalid_inner[inner_at] = 0xff;
    assert_eq!(
        SignedForkReproManifestV1::from_canonical_cbor(&invalid_inner),
        Err(ForkAttributionCodecErrorV1::InvalidEncoding)
    );
    let mut wrong_signature_length = canonical.clone();
    let signature_length_at = wrong_signature_length.len() - 65;
    wrong_signature_length[signature_length_at] = 63;
    assert_eq!(
        SignedForkReproManifestV1::from_canonical_cbor(&wrong_signature_length),
        Err(ForkAttributionCodecErrorV1::InvalidEncoding)
    );
    let mut trailing = canonical;
    trailing.push(0);
    assert_eq!(
        SignedForkReproManifestV1::from_canonical_cbor(&trailing),
        Err(ForkAttributionCodecErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn admission_decoder_rejects_zero_required_operation_hash() -> Result<(), Box<dyn std::error::Error>>
{
    let mut bytes = admission()?.to_canonical_cbor();
    bytes[9..41].fill(0);
    assert_eq!(
        ForkAdmissionRecordV1::from_canonical_cbor(&bytes),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn every_truncated_publication_record_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let (operation, binding, artifact) = publication_records(&admission)?;
    let codecs: [(Vec<u8>, PublicationDecodeV1); 3] = [
        (operation.to_canonical_cbor(), |bytes| {
            ForkPublicationOperationV1::from_canonical_cbor(bytes).map(drop)
        }),
        (binding.to_canonical_cbor(), |bytes| {
            ForkPublicationBindingV1::from_canonical_cbor(bytes).map(drop)
        }),
        (artifact.to_canonical_cbor(), |bytes| {
            ForkPublicationArtifactV1::from_canonical_cbor(bytes).map(drop)
        }),
    ];
    for (canonical, decode) in codecs {
        assert_eq!(decode(&canonical), Ok(()));
        for length in 0..canonical.len() {
            assert_eq!(
                decode(&canonical[..length]),
                Err(ForkAttributionCodecErrorV1::InvalidEncoding)
            );
        }
    }
    Ok(())
}

#[test]
fn fpo1_decoder_rejects_empty_oversized_and_invalid_utf8_owner(
) -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let (operation, _binding, _artifact) = publication_records(&admission)?;
    let canonical = operation.to_canonical_cbor();
    let owner_at = canonical
        .windows(b"creator-a".len())
        .position(|window| window == b"creator-a")
        .ok_or("encoded creator is absent")?;
    let role_at = owner_at + b"creator-a".len();
    assert_eq!(canonical[owner_at - 1], 0x69);
    let mut empty_owner = canonical.clone();
    empty_owner.splice(owner_at - 1..role_at, [0x60]);
    assert_eq!(
        ForkPublicationOperationV1::from_canonical_cbor(&empty_owner),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut oversized_owner = canonical.clone();
    oversized_owner.splice(owner_at - 1..owner_at, [0x79, 0x00, 0x81]);
    assert_eq!(
        ForkPublicationOperationV1::from_canonical_cbor(&oversized_owner),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut invalid_utf8_owner = canonical;
    invalid_utf8_owner[owner_at] = 0xff;
    assert_eq!(
        ForkPublicationOperationV1::from_canonical_cbor(&invalid_utf8_owner),
        Err(ForkAttributionCodecErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn fpb1_decoder_rejects_zero_operation_id() -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let (_operation, binding, _artifact) = publication_records(&admission)?;
    // FPB1: version byte, the 16-byte child Fork ID behind its one-byte
    // `bstr` head, the one-byte final logical head 7, then the operation ID's
    // two-byte `bstr .size 32` head.
    let operation_id_at = PUBLICATION_VERSION_AT + 1 + 1 + 16 + 1 + 2;
    let operation_id = operation_id_at..operation_id_at + 32;
    let mut zero_operation = binding.to_canonical_cbor();
    assert_eq!(
        zero_operation[operation_id_at - 2..operation_id_at],
        [0x58, 0x20]
    );
    assert_eq!(
        zero_operation[operation_id.clone()],
        *binding.input().operation_id.as_bytes()
    );
    zero_operation[operation_id].fill(0);
    assert_eq!(
        ForkPublicationBindingV1::from_canonical_cbor(&zero_operation),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn fpa1_rejects_invalid_nested_fsm1_oversized_nested_length_and_wide_heads(
) -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let (_operation, _binding, artifact) = publication_records(&admission)?;
    for signed_manifest_bytes in [vec![0xff], Vec::new()] {
        let mut invalid = artifact.input().clone();
        invalid.signed_manifest_bytes = signed_manifest_bytes;
        assert_eq!(
            ForkPublicationArtifactV1::new(invalid),
            Err(ForkAttributionCodecErrorV1::InvalidEncoding)
        );
    }

    // The nested FSM1 `bstr` head follows the record ID and operation ID, each
    // a two-byte `bstr .size 32` head plus 32 bytes.
    let canonical = artifact.to_canonical_cbor();
    let nested = &artifact.input().signed_manifest_bytes;
    let nested_at = canonical
        .len()
        .checked_sub(nested.len())
        .ok_or("artifact is shorter than its nested FSM1")?;
    let nested_head_at = FPA1_RECORD_ID_AT + 32 + 2 + 32;
    assert_eq!(&canonical[nested_at..], nested.as_slice());
    let mut oversized_nested = canonical.clone();
    oversized_nested.splice(nested_head_at..nested_at, [0x59, 0x41, 0x01]);
    assert_eq!(
        ForkPublicationArtifactV1::from_canonical_cbor(&oversized_nested),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );

    let record_id_head = FPA1_RECORD_ID_AT - 2..FPA1_RECORD_ID_AT;
    let mut wide_head = canonical;
    wide_head.splice(record_id_head, [0x59, 0x00, 0x20]);
    assert_eq!(
        ForkPublicationArtifactV1::from_canonical_cbor(&wide_head),
        Err(ForkAttributionCodecErrorV1::NonCanonical)
    );
    Ok(())
}

#[test]
fn publication_constructors_reject_each_zero_id() -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let (operation, binding, artifact) = publication_records(&admission)?;
    let mut zero_operation_id = operation.input().clone();
    zero_operation_id.operation_id = Hash::zero();
    let mut zero_admission = operation.input().clone();
    zero_admission.admission_digest = Hash::zero();
    let mut zero_record_id = operation.input().clone();
    zero_record_id.signed_manifest_record_id = Hash::zero();
    for input in [zero_operation_id, zero_admission, zero_record_id] {
        assert_eq!(
            ForkPublicationOperationV1::new(input),
            Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
        );
    }
    let mut zero_binding_operation = *binding.input();
    zero_binding_operation.operation_id = Hash::zero();
    assert_eq!(
        ForkPublicationBindingV1::new(zero_binding_operation),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    let mut zero_artifact_record = artifact.input().clone();
    zero_artifact_record.signed_manifest_record_id = Hash::zero();
    assert_eq!(
        ForkPublicationArtifactV1::new(zero_artifact_record),
        Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn receipt_rejects_each_mismatched_duplicated_field() -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let (operation, binding, _artifact) = publication_records(&admission)?;
    let mut foreign_operation = *binding.input();
    foreign_operation.operation_id = hash(98);
    let mut foreign_fork = *binding.input();
    foreign_fork.child_timeline_id = TimelineId::new();
    let mut foreign_record = *binding.input();
    foreign_record.signed_manifest_record_id = hash(97);
    for input in [foreign_operation, foreign_fork, foreign_record] {
        assert_eq!(
            ForkPublicationReceiptV1::from_records(
                &operation,
                &ForkPublicationBindingV1::new(input)?
            ),
            Err(ForkAttributionCodecErrorV1::FieldMismatch)
        );
    }
    Ok(())
}
