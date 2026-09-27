use pos_core::{
    ForkAdmissionRecordInputV1, ForkAdmissionRecordV1, ForkAttributionOriginV1,
    ForkReproManifestInputV1, ForkReproManifestV1, Hash, KeyIdentityV1, KeyRegistrationV1,
    KeyRegistryStateV1, KeyRoleV1, TimelineId,
};
use pos_crypto::{
    fork_attribution::{
        sign_local_fork_manifest_signature_only, verify_local_fork_manifest_signature_only,
    },
    key_roles::SigningKeyMaterial,
    signing::{generate_keypair, public_key_from_verifying_key},
};

fn hash(value: u8) -> Hash { Hash::from_bytes([value; 32]) }

#[test]
fn local_signature_only_binds_exact_attribution_identity_and_inner_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let parent = TimelineId::new();
    let child = TimelineId::new();
    let admission = ForkAdmissionRecordV1::new(ForkAdmissionRecordInputV1 {
        operation_id: hash(1), principal_owner_binding_digest: hash(2), creator: "creator-a".into(),
        parent_timeline_id: parent, child_timeline_id: child, room_revision_descriptor_hash: hash(3),
        parent_logical_head: 0, parent_chain_head_hash: hash(4), completed_fold_cursor: 0,
        post_fold_tick_boundary: 0, plugin_composition_hash: hash(5), attribution_required: true,
        origin: ForkAttributionOriginV1::Local,
    })?;
    let manifest = ForkReproManifestV1::new(ForkReproManifestInputV1 {
        parent_timeline_id: parent, fork_timeline_id: child, admission_digest: admission.digest(),
        room_revision_descriptor_hash: hash(3), parent_logical_head: 0, parent_chain_head_hash: hash(4),
        post_fold_tick_boundary: 0, plugin_composition_hash: hash(5), intervention_sequences: vec![],
        final_fork_logical_head: 0, final_fork_chain_head_hash: hash(6),
    })?;
    let (private, public) = generate_keypair();
    let private = SigningKeyMaterial::new(private);
    let identity = KeyIdentityV1::new("creator-a", KeyRoleV1::SubjectAttributionSigning, 1);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(identity, private.material_digest(), Some(public_key_from_verifying_key(&public))))?;
    let signed = sign_local_fork_manifest_signature_only(&mut registry, &private, identity, manifest)?;
    verify_local_fork_manifest_signature_only(&signed, public_key_from_verifying_key(&public))?;
    assert!(verify_local_fork_manifest_signature_only(&signed, pos_core::PublicKey::from_bytes([0; 32])).is_err());
    Ok(())
}
