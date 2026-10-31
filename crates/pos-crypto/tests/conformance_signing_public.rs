#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! ADR-062 Revision 8 section 5.2 (K-A, #1237): the two conformance signing roles sign DSSE
//! envelopes through `KeyRegistrySigningPortV1` and nothing else, and no other role signs a
//! DSSE envelope.

use ed25519_dalek::{Signer as _, SigningKey};
use pos_core::{
    CanonicalBytes, Hash, KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1,
    KeyRegistryErrorV1, KeyRegistryStateV1, KeyRoleV1, Signature,
};
use pos_crypto::dsse::{key_id_v1, pae_v1, DsseEnvelopeV1, IN_TOTO_PAYLOAD_TYPE_V1};
use pos_crypto::key_roles::{
    destroy_registered_signing_key, sign_dsse_for_registered_role, sign_for_registered_role,
    verify_for_role, with_registered_encryption_authorization, EncryptionKeyMaterial,
    SigningKeyMaterial,
};
use pos_crypto::signing::public_key_from_verifying_key;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CONFORMANCE_ROLES: [KeyRoleV1; 2] = [
    KeyRoleV1::ConformanceEvaluatorSigning,
    KeyRoleV1::ConformanceReportSigning,
];

const OTHER_ROLES: [KeyRoleV1; 5] = [
    KeyRoleV1::SubjectDataEncryption,
    KeyRoleV1::SubjectAttributionSigning,
    KeyRoleV1::TimelineIntegritySigning,
    KeyRoleV1::PluginReleaseSigning,
    KeyRoleV1::ExportRecipientEncryption,
];

const PAYLOAD: &[u8] = b"{\"_type\":\"https://in-toto.io/Statement/v1\"}";

/// A registry holding `role` epoch 1 for the key with `seed`, and that key's material.
fn registered(
    role: KeyRoleV1,
    seed: u8,
) -> Result<(KeyRegistryStateV1, SigningKeyMaterial, KeyIdentityV1), KeyRegistryErrorV1> {
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    let public_key = public_key_from_verifying_key(&signing_key.verifying_key());
    let material = SigningKeyMaterial::new(signing_key);
    let identity = KeyIdentityV1::new("conformance-owner", role, 1);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        identity,
        material.material_digest(),
        role.is_signing().then_some(public_key),
    ))?;
    Ok((registry, material, identity))
}

fn dsse(
    registry: &mut KeyRegistryStateV1,
    material: &SigningKeyMaterial,
    identity: KeyIdentityV1,
) -> Result<DsseEnvelopeV1, KeyRegistryErrorV1> {
    sign_dsse_for_registered_role(
        registry,
        material,
        identity,
        IN_TOTO_PAYLOAD_TYPE_V1,
        PAYLOAD.to_vec(),
    )
}

#[test]
fn each_conformance_role_signs_a_dsse_envelope_through_the_registry() -> TestResult {
    for (seed, role) in (40..).zip(CONFORMANCE_ROLES) {
        let (mut registry, material, identity) = registered(role, seed)?;
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let envelope = dsse(&mut registry, &material, identity)?;
        // Exactly the plain DSSE signature of the registered key over the PAE.
        assert_eq!(
            envelope,
            DsseEnvelopeV1::sign(IN_TOTO_PAYLOAD_TYPE_V1, PAYLOAD.to_vec(), &signing_key)
        );
        assert_eq!(envelope.key_id(), &key_id_v1(&signing_key.verifying_key()));
        assert_eq!(envelope.payload(), PAYLOAD);
        assert_eq!(envelope.verify(&signing_key.verifying_key()), Ok(()));
        // The signature is over the DSSE PAE, without the ADR-065 role framing.
        let pae = pae_v1(IN_TOTO_PAYLOAD_TYPE_V1, PAYLOAD);
        let reference = DsseEnvelopeV1::from_canonical_json(&envelope.to_canonical_json(), 4096)?;
        assert_eq!(reference.verify(&signing_key.verifying_key()), Ok(()));
        assert!(signing_key
            .verifying_key()
            .verify_strict(&pae, &signing_key.sign(&pae))
            .is_ok());
    }
    Ok(())
}

#[test]
fn dsse_signing_needs_an_active_registered_matching_conformance_key() -> TestResult {
    let (mut registry, material, identity) = registered(KeyRoleV1::ConformanceReportSigning, 50)?;
    assert_eq!(
        dsse(
            &mut registry,
            &material,
            KeyIdentityV1::new("conformance-owner", KeyRoleV1::ConformanceReportSigning, 0),
        ),
        Err(KeyRegistryErrorV1::InvalidEpoch)
    );
    // Another conformance role of the same owner is not registered.
    assert_eq!(
        dsse(
            &mut registry,
            &material,
            KeyIdentityV1::new(
                "conformance-owner",
                KeyRoleV1::ConformanceEvaluatorSigning,
                1
            ),
        ),
        Err(KeyRegistryErrorV1::NotFound)
    );
    // A key that is not the registered material.
    let other = SigningKeyMaterial::new(SigningKey::from_bytes(&[51; 32]));
    assert_eq!(
        dsse(&mut registry, &other, identity),
        Err(KeyRegistryErrorV1::SigningKeyMismatch)
    );

    // Destroyed material signs nothing.
    let mut destroyed = material;
    let request = KeyDestructionRequestV1::new(
        identity,
        destroyed.material_digest(),
        Hash::from_bytes([9; 32]),
    );
    destroy_registered_signing_key(&mut destroyed, request, &mut registry)?;
    assert_eq!(
        dsse(&mut registry, &destroyed, identity),
        Err(KeyRegistryErrorV1::Destroyed)
    );
    Ok(())
}

#[test]
fn no_other_role_signs_a_dsse_envelope() -> TestResult {
    for (seed, role) in (60..).zip(OTHER_ROLES) {
        let (mut registry, material, identity) = registered(role, seed)?;
        assert_eq!(
            dsse(&mut registry, &material, identity),
            Err(KeyRegistryErrorV1::SigningPurposeMismatch),
            "{role:?}"
        );
    }
    Ok(())
}

#[test]
fn conformance_roles_are_refused_for_other_roles_purposes() -> TestResult {
    let payload = CanonicalBytes::from_vec(PAYLOAD.to_vec());
    for (seed, role) in (70..).zip(CONFORMANCE_ROLES) {
        let (mut registry, material, identity) = registered(role, seed)?;
        // No role-bound (ADR-065) signature.
        assert_eq!(
            sign_for_registered_role(&mut registry, &material, identity, &payload),
            Err(KeyRegistryErrorV1::SigningPurposeMismatch)
        );
        // No encryption authorization.
        let encryption = EncryptionKeyMaterial::new([seed; 32]);
        assert_eq!(
            with_registered_encryption_authorization(&mut registry, &encryption, identity, |_| ()),
            Err(KeyRegistryErrorV1::EncryptionRoleRequired)
        );
        // No historical decryption.
        assert_eq!(
            identity.validate_historical_decryption(),
            Err(KeyRegistryErrorV1::HistoricalDecryptionRoleRequired)
        );
        // A role-bound signature in the ADR-065 framing never verifies for a conformance role.
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let owner = identity.owner_id.as_str();
        let mut message = b"pigloros/role-signature/v1".to_vec();
        message.extend_from_slice(&u32::try_from(owner.len())?.to_be_bytes());
        message.extend_from_slice(owner.as_bytes());
        message.push(role.code());
        message.extend_from_slice(&1_u64.to_be_bytes());
        message.extend_from_slice(PAYLOAD);
        let signature = Signature::from_bytes(signing_key.sign(&message).to_bytes());
        assert!(
            verify_for_role(&signing_key.verifying_key(), identity, &payload, &signature).is_err()
        );
        // The same framing verifies for a role that does sign role-bound payloads.
        let mut plugin = b"pigloros/role-signature/v1".to_vec();
        plugin.extend_from_slice(&u32::try_from(owner.len())?.to_be_bytes());
        plugin.extend_from_slice(owner.as_bytes());
        plugin.push(KeyRoleV1::PluginReleaseSigning.code());
        plugin.extend_from_slice(&1_u64.to_be_bytes());
        plugin.extend_from_slice(PAYLOAD);
        let plugin_signature = Signature::from_bytes(signing_key.sign(&plugin).to_bytes());
        verify_for_role(
            &signing_key.verifying_key(),
            KeyIdentityV1::from_parts(identity.owner_id, KeyRoleV1::PluginReleaseSigning, 1),
            &payload,
            &plugin_signature,
        )?;
    }
    Ok(())
}

#[test]
fn the_purpose_mismatch_refusal_names_its_reason() {
    assert_eq!(
        KeyRegistryErrorV1::SigningPurposeMismatch.to_string(),
        "key role is not admitted for this signing purpose"
    );
}
