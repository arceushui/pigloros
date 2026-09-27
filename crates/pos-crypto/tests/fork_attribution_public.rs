use pos_core::{
    ForkAdmissionRecordInputV1, ForkAdmissionRecordV1, ForkAttributionOriginV1,
    ForkReproManifestInputV1, ForkReproManifestV1, Hash, KeyIdentityV1, KeyRegistrationV1,
    KeyRegistryStateV1, KeyRoleV1, PublicKey, SignedForkReproManifestV1, TimelineId,
};
use pos_crypto::{
    fork_attribution::{
        sign_local_fork_manifest_for_identity_from_admission_signature_only,
        sign_local_fork_manifest_from_admission_signature_only,
        sign_local_fork_manifest_signature_only, verify_local_fork_manifest_signature_only,
        ForkAttributionSigningErrorV1,
    },
    key_roles::SigningKeyMaterial,
    signing::{generate_keypair, public_key_from_verifying_key, verifying_key_from_public_key},
};

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

fn check_signature(
    signed: &SignedForkReproManifestV1,
    public: PublicKey,
) -> Result<(), Box<dyn std::error::Error>> {
    verify_local_fork_manifest_signature_only(signed, public)?;
    assert!(
        verify_local_fork_manifest_signature_only(signed, PublicKey::from_bytes([0; 32])).is_err()
    );
    let invalid_public_key = (0..=u8::MAX)
        .map(|byte| PublicKey::from_bytes([byte; 32]))
        .find(|key| verifying_key_from_public_key(key).is_err())
        .ok_or("no invalid compressed public key fixture")?;
    assert!(verify_local_fork_manifest_signature_only(signed, invalid_public_key).is_err());

    let identity = signed.identity();
    let changed_owner = SignedForkReproManifestV1::new(
        KeyIdentityV1::new("creator-b", identity.role, identity.epoch),
        signed.manifest().clone(),
        signed.signature(),
    )?;
    let changed_epoch = SignedForkReproManifestV1::new(
        KeyIdentityV1::new(identity.owner_id, identity.role, identity.epoch + 1),
        signed.manifest().clone(),
        signed.signature(),
    )?;
    let mut changed_input = signed.manifest().input().clone();
    changed_input.final_fork_chain_head_hash = hash(7);
    let changed_payload = SignedForkReproManifestV1::new(
        identity,
        ForkReproManifestV1::new(changed_input)?,
        signed.signature(),
    )?;
    for changed in [changed_owner, changed_epoch, changed_payload] {
        let decoded = SignedForkReproManifestV1::from_canonical_cbor(&changed.to_canonical_cbor())?;
        assert!(verify_local_fork_manifest_signature_only(&decoded, public).is_err());
    }
    assert!(SignedForkReproManifestV1::new(
        KeyIdentityV1::new(
            identity.owner_id,
            KeyRoleV1::TimelineIntegritySigning,
            identity.epoch,
        ),
        signed.manifest().clone(),
        signed.signature(),
    )
    .is_err());
    Ok(())
}

#[test]
fn local_signature_only_binds_exact_attribution_identity_and_inner_bytes(
) -> Result<(), Box<dyn std::error::Error>> {
    let parent = TimelineId::new();
    let child = TimelineId::new();
    let admission = ForkAdmissionRecordV1::new(ForkAdmissionRecordInputV1 {
        operation_id: hash(1),
        principal_owner_binding_digest: hash(2),
        creator: "creator-a".into(),
        parent_timeline_id: parent,
        child_timeline_id: child,
        room_revision_descriptor_hash: hash(3),
        parent_logical_head: 0,
        parent_chain_head_hash: hash(4),
        completed_fold_cursor: 0,
        post_fold_tick_boundary: 0,
        plugin_composition_hash: hash(5),
        attribution_required: true,
        origin: ForkAttributionOriginV1::Local,
    })?;
    let manifest = ForkReproManifestV1::from_admission(&admission, vec![], 0, hash(6))?;
    let (private, public) = generate_keypair();
    let private = SigningKeyMaterial::new(private);
    let identity = KeyIdentityV1::new("creator-a", KeyRoleV1::SubjectAttributionSigning, 1);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        identity,
        private.material_digest(),
        Some(public_key_from_verifying_key(&public)),
    ))?;
    let signed = sign_local_fork_manifest_from_admission_signature_only(
        &mut registry,
        &private,
        &admission,
        identity.epoch,
        manifest,
    )?;
    assert_eq!(signed.identity(), identity);
    let Err(zero_epoch) = sign_local_fork_manifest_from_admission_signature_only(
        &mut registry,
        &private,
        &admission,
        0,
        ForkReproManifestV1::from_admission(&admission, vec![], 0, hash(6))?,
    ) else {
        return Err("zero epoch unexpectedly signed".into());
    };
    let ForkAttributionSigningErrorV1::Codec(zero_epoch) = zero_epoch else {
        return Err("zero epoch unexpectedly reached the registry".into());
    };
    assert_eq!(
        zero_epoch,
        pos_core::ForkAttributionCodecErrorV1::FieldOutOfBounds
    );

    let mut admission_b_input = admission.input().clone();
    admission_b_input.child_timeline_id = TimelineId::new();
    let admission_b = ForkAdmissionRecordV1::new(admission_b_input)?;
    let Err(mismatch) = sign_local_fork_manifest_from_admission_signature_only(
        &mut registry,
        &private,
        &admission_b,
        identity.epoch,
        ForkReproManifestV1::from_admission(&admission, vec![], 0, hash(6))?,
    ) else {
        return Err("mismatched FAR1 unexpectedly signed".into());
    };
    let ForkAttributionSigningErrorV1::Codec(mismatch) = mismatch else {
        return Err("FAR1 mismatch unexpectedly reached the registry".into());
    };
    assert_eq!(
        mismatch,
        pos_core::ForkAttributionCodecErrorV1::FieldMismatch
    );

    let (private_b, public_b) = generate_keypair();
    let private_b = SigningKeyMaterial::new(private_b);
    let identity_b = KeyIdentityV1::new("creator-b", KeyRoleV1::SubjectAttributionSigning, 1);
    registry.register_key(KeyRegistrationV1::new(
        identity_b,
        private_b.material_digest(),
        Some(public_key_from_verifying_key(&public_b)),
    ))?;
    let Err(creator_b) = sign_local_fork_manifest_for_identity_from_admission_signature_only(
        &mut registry,
        &private_b,
        identity_b,
        &admission,
        ForkReproManifestV1::from_admission(&admission, vec![], 0, hash(6))?,
    ) else {
        return Err("creator-b FAR1 unexpectedly signed".into());
    };
    let ForkAttributionSigningErrorV1::Codec(creator_b) = creator_b else {
        return Err("creator-b FAR1 mismatch unexpectedly reached the registry".into());
    };
    assert_eq!(
        creator_b,
        pos_core::ForkAttributionCodecErrorV1::FieldMismatch
    );
    check_signature(&signed, public_key_from_verifying_key(&public))?;
    Ok(())
}

#[test]
fn signature_only_rejects_non_attribution_roles_and_absent_registry_identity(
) -> Result<(), Box<dyn std::error::Error>> {
    let parent = TimelineId::new();
    let child = TimelineId::new();
    let admission = ForkAdmissionRecordV1::new(ForkAdmissionRecordInputV1 {
        operation_id: hash(1),
        principal_owner_binding_digest: hash(2),
        creator: "creator-a".into(),
        parent_timeline_id: parent,
        child_timeline_id: child,
        room_revision_descriptor_hash: hash(3),
        parent_logical_head: 0,
        parent_chain_head_hash: hash(4),
        completed_fold_cursor: 0,
        post_fold_tick_boundary: 0,
        plugin_composition_hash: hash(5),
        attribution_required: true,
        origin: ForkAttributionOriginV1::Local,
    })?;
    let manifest = ForkReproManifestV1::new(ForkReproManifestInputV1 {
        parent_timeline_id: parent,
        fork_timeline_id: child,
        admission_digest: admission.digest(),
        room_revision_descriptor_hash: hash(3),
        parent_logical_head: 0,
        parent_chain_head_hash: hash(4),
        post_fold_tick_boundary: 0,
        plugin_composition_hash: hash(5),
        intervention_sequences: vec![],
        final_fork_logical_head: 0,
        final_fork_chain_head_hash: hash(6),
    })?;
    let (private, _) = generate_keypair();
    let private = SigningKeyMaterial::new(private);
    let mut registry = KeyRegistryStateV1::new();
    assert!(sign_local_fork_manifest_signature_only(
        &mut registry,
        &private,
        KeyIdentityV1::new("creator-a", KeyRoleV1::TimelineIntegritySigning, 1),
        manifest.clone(),
    )
    .is_err());
    assert!(sign_local_fork_manifest_signature_only(
        &mut registry,
        &private,
        KeyIdentityV1::new("creator-a", KeyRoleV1::SubjectAttributionSigning, 1),
        manifest,
    )
    .is_err());
    Ok(())
}
