use pos_core::{
    ForkAdmissionRecordInputV1, ForkAdmissionRecordV1, ForkAttributionCodecErrorV1,
    ForkAttributionOriginV1, ForkReproManifestInputV1, ForkReproManifestV1, Hash, KeyIdentityV1,
    KeyRoleV1, SignedForkReproManifestV1, TimelineId,
};

fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

fn admission() -> ForkAdmissionRecordV1 {
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
    .expect("valid admission")
}

fn manifest(admission: &ForkAdmissionRecordV1) -> ForkReproManifestV1 {
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
    .expect("valid manifest")
}

#[test]
fn local_far1_frm1_and_fsm1_round_trip_at_public_seam() {
    let admission = admission();
    let manifest = manifest(&admission);
    manifest
        .validate_against_admission(&admission)
        .expect("matching admission");
    assert_eq!(
        ForkAdmissionRecordV1::from_canonical_cbor(&admission.to_canonical_cbor()),
        Ok(admission.clone())
    );
    assert_eq!(
        ForkReproManifestV1::from_canonical_cbor(&manifest.to_canonical_cbor()),
        Ok(manifest.clone())
    );
    let outer = SignedForkReproManifestV1::new(
        KeyIdentityV1::new("creator-a", KeyRoleV1::SubjectAttributionSigning, 1),
        manifest,
        pos_core::Signature::from_bytes([9; 64]),
    )
    .expect("attribution identity");
    assert_eq!(
        SignedForkReproManifestV1::from_canonical_cbor(&outer.to_canonical_cbor()),
        Ok(outer)
    );
}

#[test]
fn local_far1_rejects_reserved_import_origin_and_noncanonical_bytes() {
    let admission = admission();
    let mut binary_creator = admission.to_canonical_cbor();
    let creator_at = binary_creator
        .windows(b"creator-a".len())
        .position(|bytes| bytes == b"creator-a")
        .expect("encoded creator");
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
}

#[test]
fn manifest_rejects_unordered_out_of_range_and_mismatched_provenance() {
    let admission = admission();
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
    let matching = manifest(&admission);
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
    })
    .expect("structural manifest");
    assert_eq!(
        incorrect.validate_against_admission(&admission),
        Err(ForkAttributionCodecErrorV1::FieldMismatch)
    );
    assert_eq!(matching.validate_against_admission(&admission), Ok(()));
}
