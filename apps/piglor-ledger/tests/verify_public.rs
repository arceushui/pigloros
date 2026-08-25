use piglor_ledger::{run, verify_source, Source};
use pos_core::{
    CanonicalBytes, EntityId, Event, EventId, KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1,
    KeyRoleV1, Kind, SchemaVersion, Seq, WallTime,
};
use rusqlite::params;
use std::fmt::Write as _;

#[test]
fn public_store_verification_fails_closed_on_a_non_timeline_signature_role(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let database_path = database.path().to_path_buf();
    let mut store = pos_store::open_store(pos_store::StoreConfig::Sqlite {
        path: database_path.to_string_lossy().into_owned(),
    })?;
    let timeline = store.create_timeline("ledger")?;
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
    let payload = CanonicalBytes::from_static(b"prediction");
    store.append_committed(
        timeline.id(),
        &[Event {
            id: event_id,
            entity: EntityId::new(),
            event_type: Kind::new(pos_plugin_ledger::EVENT_TYPE_PREDICTION),
            payload: payload.clone(),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: pos_crypto::chain::hash_payload(&payload),
        }],
    )?;
    drop(store);

    let connection = rusqlite::Connection::open(&database_path)?;
    connection.execute(
        "UPDATE events SET signature = zeroblob(64), signature_role = ?1,
         signature_epoch = 1 WHERE event_id = ?2",
        params![
            i64::from(KeyRoleV1::SubjectDataEncryption.code()),
            event_id.to_string(),
        ],
    )?;

    let error = match verify_source(&Source::Store(database_path), None, None) {
        Ok(report) => return Err(format!("malformed identity produced a report: {report}").into()),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("signed event must carry a TimelineIntegritySigning role/epoch identity"));
    Ok(())
}

#[test]
fn public_store_verification_rejects_an_invalid_registry_public_key(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let database_path = database.path().to_path_buf();
    let mut store = pos_store::open_store(pos_store::StoreConfig::Sqlite {
        path: database_path.to_string_lossy().into_owned(),
    })?;
    let timeline = store.create_timeline("ledger")?;
    let identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        identity,
        pos_crypto::key_roles::key_material_digest(&[3; 32]),
        Some(pos_core::PublicKey::from_bytes([0xff; 32])),
    ))?;
    store.save_key_registry(&registry)?;
    let payload = CanonicalBytes::from_static(b"invalid registry public key");
    store.append_committed(
        timeline.id(),
        &[Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new(pos_plugin_ledger::EVENT_TYPE_PREDICTION),
            payload: payload.clone(),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: Some(pos_core::Signature::from_bytes([0; 64])),
            signature_identity: Some(identity),
            payload_hash: pos_crypto::chain::hash_payload(&payload),
        }],
    )?;
    drop(store);

    let error = match verify_source(&Source::Store(database_path), None, None) {
        Ok(report) => {
            return Err(format!("invalid registry key produced a report: {report}").into())
        }
        Err(error) => error,
    };
    assert!(error.to_string().contains("public key"));
    Ok(())
}

#[test]
fn public_store_verification_accepts_a_registry_bound_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("ledger.db");
    let key_path = directory.path().join("signing-key");

    run(&[
        "piglor-ledger".to_owned(),
        "keygen".to_owned(),
        "--out".to_owned(),
        key_path.to_string_lossy().into_owned(),
    ])?;
    run(&[
        "piglor-ledger".to_owned(),
        "predict".to_owned(),
        "--source".to_owned(),
        format!("store:{}", database_path.display()),
        "--key".to_owned(),
        key_path.to_string_lossy().into_owned(),
        "--title".to_owned(),
        "title".to_owned(),
        "--statement".to_owned(),
        "statement".to_owned(),
        "--predicted-outcome".to_owned(),
        "outcome".to_owned(),
        "--confidence".to_owned(),
        "0.7".to_owned(),
        "--made-at".to_owned(),
        "2026-07-25T12:00:00Z".to_owned(),
        "--resolve-by".to_owned(),
        "2026-08-01".to_owned(),
        "--osf".to_owned(),
        "https://osf.io/example".to_owned(),
    ])?;

    let report = verify_source(&Source::Store(database_path), None, None)?;
    assert!(report.to_string().starts_with("OK: store"));
    Ok(())
}

#[test]
fn public_store_verification_accepts_legacy_signature_with_explicit_pubkey(
) -> Result<(), Box<dyn std::error::Error>> {
    use ed25519_dalek::Signer;

    let database = tempfile::NamedTempFile::new()?;
    let database_path = database.path().to_path_buf();
    let mut store = pos_store::open_store(pos_store::StoreConfig::Sqlite {
        path: database_path.to_string_lossy().into_owned(),
    })?;
    let timeline = store.create_timeline("ledger")?;
    let (signing_key, verifying_key) = pos_crypto::signing::generate_keypair();
    let (registry_signing_key, registry_verifying_key) = pos_crypto::signing::generate_keypair();
    let registry_identity = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        registry_identity,
        pos_crypto::key_roles::key_material_digest(&registry_signing_key.to_bytes()),
        Some(pos_core::PublicKey::from_bytes(
            registry_verifying_key.to_bytes(),
        )),
    ))?;
    store.save_key_registry(&registry)?;
    let event_id = EventId::new();
    let payload = CanonicalBytes::from_static(b"legacy prediction");
    let bound_payload = CanonicalBytes::from_static(b"registry-bound prediction");
    let bound_signature = pos_crypto::key_roles::sign_for_registered_role(
        &mut registry,
        &registry_signing_key,
        registry_identity,
        &bound_payload,
    )?;
    store.append_committed(
        timeline.id(),
        &[
            Event {
                id: event_id,
                entity: EntityId::new(),
                event_type: Kind::new(pos_plugin_ledger::EVENT_TYPE_PREDICTION),
                payload: payload.clone(),
                wall_time: WallTime::from_micros(1),
                seq: Seq::from_u64(1),
                causation_id: None,
                correlation_id: None,
                schema_version: SchemaVersion::V1,
                signature: None,
                signature_identity: None,
                payload_hash: pos_crypto::chain::hash_payload(&payload),
            },
            Event {
                id: EventId::new(),
                entity: EntityId::new(),
                event_type: Kind::new(pos_plugin_ledger::EVENT_TYPE_PREDICTION),
                payload: bound_payload.clone(),
                wall_time: WallTime::from_micros(2),
                seq: Seq::from_u64(2),
                causation_id: None,
                correlation_id: None,
                schema_version: SchemaVersion::V1,
                signature: Some(bound_signature),
                signature_identity: Some(registry_identity),
                payload_hash: pos_crypto::chain::hash_payload(&bound_payload),
            },
        ],
    )?;
    store.save_key_registry(&registry)?;
    drop(store);

    let signature = signing_key.sign(payload.as_slice()).to_bytes().to_vec();
    let connection = rusqlite::Connection::open(&database_path)?;
    connection.execute(
        "UPDATE events SET signature = ?1 WHERE event_id = ?2",
        params![signature, event_id.to_string()],
    )?;

    let mut public_key_hex = String::with_capacity(64);
    for byte in verifying_key.to_bytes() {
        write!(&mut public_key_hex, "{byte:02x}")?;
    }
    let report = verify_source(&Source::Store(database_path), Some(&public_key_hex), None)?;
    assert!(report.to_string().starts_with("OK: store"));
    Ok(())
}
