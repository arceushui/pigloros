use piglor_ledger::{verify_source, Source};
use pos_core::{
    CanonicalBytes, EntityId, Event, EventId, Hash, KeyIdentityV1, KeyRegistrationV1,
    KeyRegistryStateV1, KeyRoleV1, Kind, SchemaVersion, Seq, Signature, WallTime,
};
use rusqlite::params;

#[test]
fn public_store_verification_rejects_a_non_timeline_signature_role(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let database_path = database.path().to_path_buf();
    let mut store = pos_store::open_store(pos_store::StoreConfig::Sqlite {
        path: database_path.to_string_lossy().into_owned(),
    })?;
    let timeline = store.create_timeline("verify-public")?;
    let identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
    let (signing_key, verifying_key) = pos_crypto::signing::generate_keypair();
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        identity,
        pos_crypto::key_roles::key_material_digest(&signing_key.to_bytes()),
        Some(pos_core::PublicKey::from_bytes(verifying_key.to_bytes())),
    ))?;
    store.save_key_registry(&registry)?;
    let event_id = EventId::new();
    store.append_committed(
        timeline.id(),
        &[Event {
            id: event_id,
            entity: EntityId::new(),
            event_type: Kind::new(pos_plugin_ledger::EVENT_TYPE_PREDICTION),
            payload: CanonicalBytes::from_static(b"prediction"),
            wall_time: WallTime::from_micros(1),
            seq: Seq::ZERO,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: Some(Signature::from_bytes([0; 64])),
            signature_identity: Some(identity),
            payload_hash: Hash::from_bytes([0; 32]),
        }],
    )?;
    drop(store);

    let connection = rusqlite::Connection::open(&database_path)?;
    connection.execute(
        "UPDATE events SET signature_role = ?1 WHERE event_id = ?2",
        params![
            i64::from(KeyRoleV1::SubjectDataEncryption.code()),
            event_id.to_string(),
        ],
    )?;

    let report = verify_source(&Source::Store(database_path), None, None)?;
    let rendered = report.to_string();
    assert!(rendered.contains("FAIL: store tier — seq=1"));
    assert!(rendered.contains("TimelineIntegritySigning"));
    Ok(())
}
