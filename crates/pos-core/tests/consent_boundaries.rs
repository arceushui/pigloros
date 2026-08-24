use pos_core::{
    clock::WallTime,
    consent::{ConsentGate, EVENT_TYPE_CONSENT_GRANTED_V1, EVENT_TYPE_CONSENT_REVOKED_V1},
    event::{CanonicalBytes, Event, Kind, SchemaVersion},
    ConsentAuthority, ConsentError, ConsentGranted, ConsentRevoked, EntityId, EventId, Hash,
    TimelineId,
};

fn test_ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
    })
}

fn event(event_type: &str, entity: EntityId, payload: CanonicalBytes, seq: u64) -> Event {
    Event {
        id: EventId::new(),
        entity,
        event_type: Kind::new(event_type),
        payload,
        wall_time: WallTime::from_micros(1),
        seq: pos_core::Seq::from_u64(seq),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        payload_hash: Hash::from_bytes([0; 32]),
    }
}

fn grant(subject_id: EntityId, grant_seq: u64) -> ConsentGranted {
    ConsentGranted {
        subject_id,
        grantee_id: EntityId::new(),
        purpose: "public-consent-boundary".to_owned(),
        modalities: 0,
        min_geo_resolution: 0,
        fork_permitted: true,
        export_permitted: true,
        retention_days: 30,
        expiry_secs: 0,
        grant_seq,
    }
}

#[test]
fn durable_revocation_decode_and_timeline_fence_are_public_seams() {
    let authority = ConsentAuthority::new();
    let timeline = TimelineId::new();
    let subject = EntityId::new();
    let durable_grant = grant(subject, 1);
    let durable_revocation = ConsentRevoked {
        subject_id: durable_grant.subject_id,
        grantee_id: durable_grant.grantee_id,
        grant_seq: durable_grant.grant_seq,
        fence_seq: 2,
    };
    let token = authority.record_grant_on_timeline(timeline, &durable_grant);

    authority
        .restore_from_history(
            timeline,
            &[
                event(
                    EVENT_TYPE_CONSENT_GRANTED_V1,
                    durable_grant.subject_id,
                    test_ok(durable_grant.encode()),
                    durable_grant.grant_seq,
                ),
                event(
                    EVENT_TYPE_CONSENT_REVOKED_V1,
                    durable_revocation.subject_id,
                    test_ok(durable_revocation.encode()),
                    durable_revocation.fence_seq,
                ),
            ],
        )
        .unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!(
                "durable consent history restores: {error:?}"
            )))
        });
    assert_eq!(
        authority.validate_on_timeline(timeline, &token, 2, 0),
        Err(ConsentError::Revoked)
    );

    let fenced_timeline = TimelineId::new();
    let first = grant(EntityId::new(), 1);
    let second = grant(EntityId::new(), 2);
    let first_token = authority.record_grant_on_timeline(fenced_timeline, &first);
    let second_token = authority.record_grant_on_timeline(fenced_timeline, &second);
    test_ok(ConsentGate::fence_timeline_at(
        &authority,
        fenced_timeline,
        5,
    ));
    assert_eq!(
        authority.validate_on_timeline(fenced_timeline, &first_token, 4, 0),
        Err(ConsentError::Revoked)
    );
    assert_eq!(
        authority.validate_on_timeline(fenced_timeline, &second_token, 4, 0),
        Err(ConsentError::Revoked)
    );
}
