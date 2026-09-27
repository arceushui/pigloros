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
    let input = admission.input();
    ForkReproManifestV1::new(ForkReproManifestInputV1 {
        parent_timeline_id: input.parent_timeline_id,
        fork_timeline_id: input.child_timeline_id,
        admission_digest: admission.digest(),
        room_revision_descriptor_hash: input.room_revision_descriptor_hash,
        parent_logical_head: input.parent_logical_head,
        parent_chain_head_hash: input.parent_chain_head_hash,
        post_fold_tick_boundary: input.post_fold_tick_boundary,
        plugin_composition_hash: input.plugin_composition_hash,
        intervention_sequences: vec![5, 7],
        final_fork_logical_head: 7,
        final_fork_chain_head_hash: hash(6),
    })
}

#[test]
fn local_far1_frm1_and_fsm1_round_trip_at_public_seam() -> Result<(), Box<dyn std::error::Error>> {
    let admission = admission()?;
    let manifest = manifest(&admission)?;
    manifest.validate_against_admission(&admission)?;
    assert_eq!(
        ForkAdmissionRecordV1::from_canonical_cbor(&admission.to_canonical_cbor()),
        Ok(admission)
    );
    assert_eq!(
        ForkReproManifestV1::from_canonical_cbor(&manifest.to_canonical_cbor()),
        Ok(manifest.clone())
    );
    let outer = SignedForkReproManifestV1::new(
        KeyIdentityV1::new("creator-a", KeyRoleV1::SubjectAttributionSigning, 1),
        manifest,
        pos_core::Signature::from_bytes([9; 64]),
    )?;
    assert_eq!(
        SignedForkReproManifestV1::from_canonical_cbor(&outer.to_canonical_cbor()),
        Ok(outer)
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
