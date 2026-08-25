use std::path::PathBuf;

use piglor_ledger::{verify_source, Source};
use pos_core::{
    CanonicalBytes, EntityId, Event, EventId, Hash, KeyIdentityV1, KeyRegistrationV1,
    KeyRegistryStateV1, KeyRoleV1, Kind, SchemaVersion, Seq, Signature, WallTime,
};

#[test]
fn public_store_verification_rejects_a_non_timeline_signature_role(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let database_path = database.path().to_path_buf();
    let mut store = pos_store::open_store(pos_store::StoreConfig::Sqlite {
        path: database_path.to_string_lossy().into_owned(),
    })?;
    let timeline = store.create_timeline("verify-public")?;
    let identity = KeyIdentityV1::new(KeyRoleV1::SubjectDataEncryption, 1);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        identity,
        Hash::from_bytes([41; 32]),
        None,
    ))?;
    store.save_key_registry(&registry)?;
    store.append_committed(
        timeline.id(),
        &[Event {
            id: EventId::new(),
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

    let report = verify_source(&Source::Store(PathBuf::from(database_path)), None, None)?;
    let rendered = report.to_string();
    assert!(rendered.contains("FAIL: store tier — seq=1"));
    assert!(rendered.contains("TimelineIntegritySigning"));
    Ok(())
}
