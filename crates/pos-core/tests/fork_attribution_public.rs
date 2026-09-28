use pos_core::{
    ForkAdmissionRecordInputV1, ForkAdmissionRecordV1, ForkAttributionCodecErrorV1,
    ForkAttributionOriginV1, ForkReproManifestInputV1, ForkReproManifestV1, Hash, KeyIdentityV1,
    KeyRoleV1, SignedForkReproManifestV1, TimelineId,
};

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

#[test]
fn local_far1_frm1_and_fsm1_round_trip_at_public_seam() -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let manifest = manifest(&admission)?;
    manifest.validate_against_admission(&admission)?;
    let far1 = admission.to_canonical_cbor();
    assert_eq!(&far1[..6], &[0x8f, 0x64, b'F', b'A', b'R', b'1']);
    let mut binary_far1_marker = far1.clone();
    binary_far1_marker[1] = 0x44;
    assert!(ForkAdmissionRecordV1::from_canonical_cbor(&binary_far1_marker).is_err());
    let manifest_wire = manifest.to_canonical_cbor();
    assert_eq!(&manifest_wire[..6], &[0x8d, 0x64, b'F', b'R', b'M', b'1']);
    let mut binary_manifest_marker = manifest_wire.clone();
    binary_manifest_marker[1] = 0x44;
    assert!(ForkReproManifestV1::from_canonical_cbor(&binary_manifest_marker).is_err());
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
    assert!(SignedForkReproManifestV1::from_canonical_cbor(&binary_signed_marker).is_err());
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
    let mut imported = admission.to_canonical_cbor();
    let last = imported.len() - 1;
    imported[last] = 2;
    assert_eq!(
        ForkAdmissionRecordV1::from_canonical_cbor(&imported),
        Err(ForkAttributionCodecErrorV1::ImportedAuthorityUnavailable)
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
    for length in 0..admission_bytes.len() {
        assert!(ForkAdmissionRecordV1::from_canonical_cbor(&admission_bytes[..length]).is_err());
    }
    for length in 0..manifest_bytes.len() {
        assert!(ForkReproManifestV1::from_canonical_cbor(&manifest_bytes[..length]).is_err());
    }
    for length in 0..signed_bytes.len() {
        assert!(SignedForkReproManifestV1::from_canonical_cbor(&signed_bytes[..length]).is_err());
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
    for bytes in invalid_prefixes {
        assert!(ForkAdmissionRecordV1::from_canonical_cbor(bytes).is_err());
        assert!(ForkReproManifestV1::from_canonical_cbor(bytes).is_err());
        assert!(SignedForkReproManifestV1::from_canonical_cbor(bytes).is_err());
    }
    let mut bad_bool = admission.to_canonical_cbor();
    let bool_at = bad_bool.len() - 3;
    bad_bool[bool_at] = 2;
    assert!(ForkAdmissionRecordV1::from_canonical_cbor(&bad_bool).is_err());
    let mut bad_signature = signed.to_canonical_cbor();
    bad_signature.pop();
    assert!(SignedForkReproManifestV1::from_canonical_cbor(&bad_signature).is_err());
    Ok(())
}

#[test]
fn manifest_decoder_rejects_count_coordinates_and_noncanonical_sequence(
) -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let canonical = manifest(&admission)?.to_canonical_cbor();
    let sequences_at = canonical
        .len()
        .checked_sub(38)
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
