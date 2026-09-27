use ed25519_dalek::{Signer, SigningKey};
use pos_core::{
    CanonicalBytes, EntityId, Event, EventId, EventOriginV1, Hash, KeyDestructionRequestV1,
    KeyIdentityV1, KeyRegistrationV1, KeyRegistryErrorV1, KeyRegistryStateV1, KeyRoleV1, Kind,
    PublicKey, SchemaVersion, Seq, Signature, TimelineEventEnvelopeErrorV1,
    TimelineEventEnvelopeInputV1, TimelineEventEnvelopeV1, TimelineEventVerificationV1, TimelineId,
    WallTime,
};
use pos_crypto::key_roles::{
    destroy_registered_signing_key, key_material_digest, sign_timeline_event_for_registered_role,
    verify_committed_timeline_event_v1, verify_timeline_event_for_role, SigningKeyMaterial,
    TimelineEventSigningErrorV1,
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

type CommittedFixture = (
    Event,
    KeyRegistryStateV1,
    KeyIdentityV1,
    PublicKey,
    SigningKey,
);

fn committed_fixture() -> Result<CommittedFixture, Box<dyn std::error::Error>> {
    let identity = KeyIdentityV1::new("timeline-owner", KeyRoleV1::TimelineIntegritySigning, 1);
    let key = SigningKey::from_bytes(&[31; 32]);
    let public_key = public_key_from_verifying_key(&key.verifying_key());
    let material = SigningKeyMaterial::new(key.clone());
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        identity,
        material.material_digest(),
        Some(public_key),
    ))?;
    let payload = CanonicalBytes::from_static(b"committed payload");
    let fields = input(identity);
    let envelope = TimelineEventEnvelopeV1::new(fields.clone(), &payload)?;
    let signature =
        sign_timeline_event_for_registered_role(&mut registry, &material, &envelope, &payload)?;
    let event = Event {
        id: fields.event_id,
        entity: fields.entity_id,
        event_type: fields.event_type,
        payload,
        wall_time: fields.wall_time,
        seq: Seq::from_u64(1),
        causation_id: fields.causation_id,
        correlation_id: fields.correlation_id,
        schema_version: SchemaVersion::V1,
        signature: Some(signature),
        signature_identity: Some(identity),
        origin: Some(EventOriginV1 {
            origin_timeline_id: fields.origin_timeline_id,
            origin_logical_seq: fields.origin_logical_seq,
        }),
        payload_hash: envelope.payload_hash(),
    };
    Ok((event, registry, identity, public_key, key))
}

#[test]
fn committed_verifier_binds_context_trust_anchor_and_legacy_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let (event, registry, identity, public_key, key) = committed_fixture()?;
    let verify = |event: &Event, anchor| {
        verify_committed_timeline_event_v1(event, Some(&registry), Some(anchor))
    };
    assert_eq!(
        verify(&event, (identity, public_key)),
        TimelineEventVerificationV1::Verified
    );
    let mutations: [fn(&mut Event); 9] = [
        |value| value.id = EventId::new(),
        |value| value.entity = EntityId::new(),
        |value| value.event_type = Kind::new("altered.event"),
        |value| value.wall_time = WallTime::from_micros(12),
        |value| value.causation_id = Some(EventId::new()),
        |value| value.correlation_id = Some(pos_core::CorrelationId::new()),
        |value| value.payload = CanonicalBytes::from_static(b"changed payload"),
        |value| value.payload_hash = Hash::zero(),
        |value| value.signature = Some(Signature::from_bytes([0; 64])),
    ];
    for mutate in mutations {
        let mut altered = event.clone();
        mutate(&mut altered);
        assert_eq!(
            verify(&altered, (identity, public_key)),
            TimelineEventVerificationV1::Invalid
        );
    }
    let mut altered_origin = event.clone();
    altered_origin.origin = altered_origin.origin.map(|mut origin| {
        origin.origin_timeline_id = TimelineId::new();
        origin
    });
    assert_eq!(
        verify(&altered_origin, (identity, public_key)),
        TimelineEventVerificationV1::Invalid
    );
    let mut altered_sequence = event.clone();
    altered_sequence.origin = altered_sequence.origin.map(|mut origin| {
        origin.origin_logical_seq = Seq::from_u64(2);
        origin
    });
    assert_eq!(
        verify(&altered_sequence, (identity, public_key)),
        TimelineEventVerificationV1::Invalid
    );
    let mut invalid_sequence = event.clone();
    invalid_sequence.origin = invalid_sequence.origin.map(|mut origin| {
        origin.origin_logical_seq = Seq::ZERO;
        origin
    });
    assert_eq!(
        verify(&invalid_sequence, (identity, public_key)),
        TimelineEventVerificationV1::Invalid
    );
    assert_eq!(
        verify(
            &event,
            (
                KeyIdentityV1::new("other-owner", KeyRoleV1::TimelineIntegritySigning, 1),
                public_key
            )
        ),
        TimelineEventVerificationV1::Invalid
    );
    assert_eq!(
        verify(&event, (identity, PublicKey::from_bytes([7; 32]))),
        TimelineEventVerificationV1::Invalid
    );
    let mut legacy = event;
    legacy.signature = Some(Signature::from_bytes(
        key.sign(legacy.payload.as_slice()).to_bytes(),
    ));
    assert_eq!(
        verify(&legacy, (identity, public_key)),
        TimelineEventVerificationV1::Invalid
    );
    Ok(())
}

#[test]
fn committed_verifier_distinguishes_missing_context_and_retained_epochs(
) -> Result<(), Box<dyn std::error::Error>> {
    let (event, mut registry, identity, public_key, key) = committed_fixture()?;
    let anchor = Some((identity, public_key));
    assert_eq!(
        verify_committed_timeline_event_v1(&event, None, anchor),
        TimelineEventVerificationV1::MissingRequiredContext
    );
    assert_eq!(
        verify_committed_timeline_event_v1(&event, Some(&registry), None),
        TimelineEventVerificationV1::MissingRequiredContext
    );
    assert_eq!(
        verify_committed_timeline_event_v1(&event, Some(&KeyRegistryStateV1::new()), anchor),
        TimelineEventVerificationV1::MissingRequiredContext
    );
    let invalid_public_key = (1u8..=255)
        .map(|value| PublicKey::from_bytes([value; 32]))
        .find(|public_key| pos_crypto::signing::verifying_key_from_public_key(public_key).is_err())
        .ok_or("expected an invalid Ed25519 public key")?;
    let mut invalid_key_registry = KeyRegistryStateV1::new();
    invalid_key_registry.register_key(KeyRegistrationV1::new(
        identity,
        key_material_digest(&[45; 32]),
        Some(invalid_public_key),
    ))?;
    assert_eq!(
        verify_committed_timeline_event_v1(
            &event,
            Some(&invalid_key_registry),
            Some((identity, invalid_public_key)),
        ),
        TimelineEventVerificationV1::Invalid
    );
    let missing_mutations: [fn(&mut Event); 3] = [
        |value: &mut Event| value.signature = None,
        |value: &mut Event| value.signature_identity = None,
        |value: &mut Event| value.origin = None,
    ];
    for mutate in missing_mutations {
        let mut missing = event.clone();
        mutate(&mut missing);
        assert_eq!(
            verify_committed_timeline_event_v1(&missing, Some(&registry), anchor),
            TimelineEventVerificationV1::MissingRequiredContext
        );
    }
    for wrong in [
        KeyIdentityV1::new("timeline-owner", KeyRoleV1::SubjectAttributionSigning, 1),
        KeyIdentityV1::new("timeline-owner", KeyRoleV1::TimelineIntegritySigning, 0),
    ] {
        let mut invalid = event.clone();
        invalid.signature_identity = Some(wrong);
        assert_eq!(
            verify_committed_timeline_event_v1(&invalid, Some(&registry), anchor),
            TimelineEventVerificationV1::Invalid
        );
    }
    let second = KeyIdentityV1::new("timeline-owner", KeyRoleV1::TimelineIntegritySigning, 2);
    let second_key = SigningKey::from_bytes(&[32; 32]);
    registry.register_key(KeyRegistrationV1::new(
        second,
        key_material_digest(&second_key.to_bytes()),
        Some(public_key_from_verifying_key(&second_key.verifying_key())),
    ))?;
    assert_eq!(
        verify_committed_timeline_event_v1(&event, Some(&registry), anchor),
        TimelineEventVerificationV1::Verified
    );
    let mut material = SigningKeyMaterial::new(key);
    let material_digest = material.material_digest();
    destroy_registered_signing_key(
        &mut material,
        KeyDestructionRequestV1::new(identity, material_digest, Hash::from_bytes([33; 32])),
        &mut registry,
    )?;
    assert_eq!(
        verify_committed_timeline_event_v1(&event, Some(&registry), anchor),
        TimelineEventVerificationV1::Verified
    );
    Ok(())
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
    let mut altered = fields;
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
