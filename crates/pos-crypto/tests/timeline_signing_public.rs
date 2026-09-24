use ed25519_dalek::SigningKey;
use pos_core::{
    CanonicalBytes, EntityId, EventId, Hash, KeyDestructionRequestV1, KeyIdentityV1,
    KeyRegistrationV1, KeyRegistryErrorV1, KeyRegistryStateV1, KeyRoleV1, Kind, Seq, Signature,
    TimelineEventEnvelopeErrorV1, TimelineEventEnvelopeInputV1, TimelineEventEnvelopeV1,
    TimelineId, WallTime,
};
use pos_crypto::key_roles::{
    destroy_registered_signing_key, key_material_digest, sign_timeline_event_for_registered_role,
    verify_timeline_event_for_role, SigningKeyMaterial, TimelineEventSigningErrorV1,
};
use pos_crypto::signing::public_key_from_verifying_key;

fn input(identity: KeyIdentityV1) -> TimelineEventEnvelopeInputV1 {
    TimelineEventEnvelopeInputV1 {
        identity,
        origin_timeline_id: TimelineId::new(),
        event_id: EventId::new(),
        origin_logical_seq: Seq::from_u64(1),
        entity_id: EntityId::new(),
        event_type: Kind::new("test.event"),
        schema_version: 1,
        wall_time: WallTime::from_micros(11),
        causation_id: None,
        correlation_id: None,
    }
}

#[test]
fn standalone_timeline_signing_binds_every_context_field() -> Result<(), Box<dyn std::error::Error>>
{
    let identity = KeyIdentityV1::new("timeline-owner", KeyRoleV1::TimelineIntegritySigning, 1);
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let public_key = public_key_from_verifying_key(&signing_key.verifying_key());
    let material = SigningKeyMaterial::new(signing_key.clone());
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        identity,
        key_material_digest(&signing_key.to_bytes()),
        Some(public_key),
    ))?;
    let payload = CanonicalBytes::from_static(b"exact payload");
    let fields = input(identity);
    let envelope = TimelineEventEnvelopeV1::new(fields.clone(), &payload)?;
    let signature =
        sign_timeline_event_for_registered_role(&mut registry, &material, &envelope, &payload)?;
    verify_timeline_event_for_role(
        &signing_key.verifying_key(),
        identity,
        &envelope,
        &payload,
        &signature,
    )?;

    let mut altered = fields.clone();
    altered.origin_timeline_id = TimelineId::new();
    let mut variants = vec![altered];
    let mut altered = fields.clone();
    altered.event_id = EventId::new();
    variants.push(altered);
    let mut altered = fields.clone();
    altered.origin_logical_seq = Seq::from_u64(2);
    variants.push(altered);
    let mut altered = fields.clone();
    altered.entity_id = EntityId::new();
    variants.push(altered);
    let mut altered = fields.clone();
    altered.event_type = Kind::new("other.event");
    variants.push(altered);
    let mut altered = fields.clone();
    altered.schema_version = 2;
    variants.push(altered);
    let mut altered = fields.clone();
    altered.wall_time = WallTime::from_micros(12);
    variants.push(altered);
    let mut altered = fields.clone();
    altered.causation_id = Some(EventId::new());
    variants.push(altered);
    let mut altered = fields.clone();
    altered.correlation_id = Some(pos_core::CorrelationId::new());
    variants.push(altered);
    for changed in variants {
        let changed = TimelineEventEnvelopeV1::new(changed, &payload)?;
        assert_eq!(
            verify_timeline_event_for_role(
                &signing_key.verifying_key(),
                identity,
                &changed,
                &payload,
                &signature,
            ),
            Err(TimelineEventEnvelopeErrorV1::InvalidSignature)
        );
    }
    Ok(())
}

#[test]
fn public_timeline_signer_and_verifier_reject_wrong_context(
) -> Result<(), Box<dyn std::error::Error>> {
    let identity = KeyIdentityV1::new("timeline-owner", KeyRoleV1::TimelineIntegritySigning, 1);
    let signing_key = SigningKey::from_bytes(&[8; 32]);
    let material = SigningKeyMaterial::new(signing_key.clone());
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        identity,
        key_material_digest(&signing_key.to_bytes()),
        Some(public_key_from_verifying_key(&signing_key.verifying_key())),
    ))?;
    let payload = CanonicalBytes::from_static(b"exact payload");
    let envelope = TimelineEventEnvelopeV1::new(input(identity), &payload)?;
    let signature =
        sign_timeline_event_for_registered_role(&mut registry, &material, &envelope, &payload)?;
    let wrong_payload = CanonicalBytes::from_static(b"changed payload");
    assert_eq!(
        sign_timeline_event_for_registered_role(
            &mut registry,
            &material,
            &envelope,
            &wrong_payload,
        ),
        Err(TimelineEventSigningErrorV1::Envelope(
            TimelineEventEnvelopeErrorV1::PayloadHashMismatch
        ))
    );
    assert_eq!(
        verify_timeline_event_for_role(
            &signing_key.verifying_key(),
            identity,
            &envelope,
            &wrong_payload,
            &signature,
        ),
        Err(TimelineEventEnvelopeErrorV1::PayloadHashMismatch)
    );
    for wrong_identity in [
        KeyIdentityV1::new("other-owner", KeyRoleV1::TimelineIntegritySigning, 1),
        KeyIdentityV1::new("timeline-owner", KeyRoleV1::TimelineIntegritySigning, 2),
        KeyIdentityV1::new("timeline-owner", KeyRoleV1::SubjectAttributionSigning, 1),
    ] {
        assert_eq!(
            verify_timeline_event_for_role(
                &signing_key.verifying_key(),
                wrong_identity,
                &envelope,
                &payload,
                &signature,
            ),
            Err(TimelineEventEnvelopeErrorV1::InvalidIdentity)
        );
    }
    for changed_identity in [
        KeyIdentityV1::new("other-owner", KeyRoleV1::TimelineIntegritySigning, 1),
        KeyIdentityV1::new("timeline-owner", KeyRoleV1::TimelineIntegritySigning, 2),
    ] {
        let changed = TimelineEventEnvelopeV1::new(input(changed_identity), &payload)?;
        assert_eq!(
            verify_timeline_event_for_role(
                &signing_key.verifying_key(),
                changed_identity,
                &changed,
                &payload,
                &signature,
            ),
            Err(TimelineEventEnvelopeErrorV1::InvalidSignature)
        );
    }
    let other_key = SigningKey::from_bytes(&[9; 32]);
    assert_eq!(
        verify_timeline_event_for_role(
            &other_key.verifying_key(),
            identity,
            &envelope,
            &payload,
            &signature,
        ),
        Err(TimelineEventEnvelopeErrorV1::InvalidSignature)
    );
    assert_eq!(
        verify_timeline_event_for_role(
            &signing_key.verifying_key(),
            identity,
            &envelope,
            &payload,
            &Signature::from_bytes([0; 64]),
        ),
        Err(TimelineEventEnvelopeErrorV1::InvalidSignature)
    );
    Ok(())
}

#[test]
fn historical_timeline_verification_does_not_require_active_registry(
) -> Result<(), Box<dyn std::error::Error>> {
    let first = KeyIdentityV1::new("timeline-owner", KeyRoleV1::TimelineIntegritySigning, 1);
    let second = KeyIdentityV1::new("timeline-owner", KeyRoleV1::TimelineIntegritySigning, 2);
    let first_key = SigningKey::from_bytes(&[10; 32]);
    let second_key = SigningKey::from_bytes(&[11; 32]);
    let first_material = SigningKeyMaterial::new(first_key.clone());
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        first,
        key_material_digest(&first_key.to_bytes()),
        Some(public_key_from_verifying_key(&first_key.verifying_key())),
    ))?;
    let payload = CanonicalBytes::from_static(b"historical payload");
    let envelope = TimelineEventEnvelopeV1::new(input(first), &payload)?;
    let signature = sign_timeline_event_for_registered_role(
        &mut registry,
        &first_material,
        &envelope,
        &payload,
    )?;
    registry.register_key(KeyRegistrationV1::new(
        second,
        key_material_digest(&second_key.to_bytes()),
        Some(public_key_from_verifying_key(&second_key.verifying_key())),
    ))?;
    assert_eq!(
        sign_timeline_event_for_registered_role(
            &mut registry,
            &first_material,
            &envelope,
            &payload
        ),
        Err(TimelineEventSigningErrorV1::Authorization(
            KeyRegistryErrorV1::InactiveKey
        ))
    );
    verify_timeline_event_for_role(
        &first_key.verifying_key(),
        first,
        &envelope,
        &payload,
        &signature,
    )?;
    let wrong_material = SigningKeyMaterial::new(SigningKey::from_bytes(&[12; 32]));
    let active_envelope = TimelineEventEnvelopeV1::new(input(second), &payload)?;
    assert_eq!(
        sign_timeline_event_for_registered_role(
            &mut registry,
            &wrong_material,
            &active_envelope,
            &payload,
        ),
        Err(TimelineEventSigningErrorV1::Authorization(
            KeyRegistryErrorV1::SigningKeyMismatch
        ))
    );
    Ok(())
}

#[test]
fn destroyed_material_cannot_sign_but_retained_public_key_can_verify(
) -> Result<(), Box<dyn std::error::Error>> {
    let identity = KeyIdentityV1::new("timeline-owner", KeyRoleV1::TimelineIntegritySigning, 1);
    let signing_key = SigningKey::from_bytes(&[13; 32]);
    let mut material = SigningKeyMaterial::new(signing_key.clone());
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        identity,
        key_material_digest(&signing_key.to_bytes()),
        Some(public_key_from_verifying_key(&signing_key.verifying_key())),
    ))?;
    let payload = CanonicalBytes::from_static(b"retained payload");
    let envelope = TimelineEventEnvelopeV1::new(input(identity), &payload)?;
    let signature =
        sign_timeline_event_for_registered_role(&mut registry, &material, &envelope, &payload)?;
    let request = KeyDestructionRequestV1::new(
        identity,
        material.material_digest(),
        Hash::from_bytes([14; 32]),
    );
    destroy_registered_signing_key(&mut material, request, &mut registry)?;
    assert_eq!(
        sign_timeline_event_for_registered_role(&mut registry, &material, &envelope, &payload),
        Err(TimelineEventSigningErrorV1::Authorization(
            KeyRegistryErrorV1::Destroyed
        ))
    );
    verify_timeline_event_for_role(
        &signing_key.verifying_key(),
        identity,
        &envelope,
        &payload,
        &signature,
    )?;
    Ok(())
}
