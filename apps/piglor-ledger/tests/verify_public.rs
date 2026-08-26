use ed25519_dalek::SigningKey;
use piglor_ledger::{run, verify_source, Source};
use pos_core::{
    CanonicalBytes, EntityId, Event, EventId, KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1,
    KeyRoleV1, Kind, SchemaVersion, Seq, WallTime,
};
use pos_crypto::key_roles::{sign_for_registered_role, SigningKeyMaterial};
use rusqlite::params;
use std::fmt::Write;
use std::process::Command;

#[test]
fn production_ledger_binary_reports_dispatch_errors() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_piglor-ledger"))
        .args(["predict", "--source", "csv:/tmp/missing-ledger"])
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Error:"));

    let version = Command::new(env!("CARGO_BIN_EXE_piglor-ledger"))
        .arg("version")
        .output()?;
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).contains("piglor-ledger"));
    Ok(())
}

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

    let anchor = "aa".repeat(32);
    let error = match verify_source(&Source::Store(database_path), Some(&anchor), None) {
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
    let mut invalid_public_key = [0_u8; 32];
    invalid_public_key[31] = 0xff;
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        identity,
        pos_crypto::key_roles::key_material_digest(&[3; 32]),
        Some(pos_core::PublicKey::from_bytes(invalid_public_key)),
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

    let mut invalid_public_key_hex = String::with_capacity(invalid_public_key.len() * 2);
    for byte in invalid_public_key {
        write!(&mut invalid_public_key_hex, "{byte:02x}")?;
    }
    let error = match verify_source(
        &Source::Store(database_path),
        Some(&invalid_public_key_hex),
        None,
    ) {
        Ok(report) => {
            return Err(format!("invalid registry key produced a report: {report}").into())
        }
        Err(error) => error,
    };
    assert_eq!(
        error.to_string(),
        "invalid --key: signature verification failed"
    );
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

    let secret = std::fs::read_to_string(&key_path)?;
    let pubkey = piglor_ledger::test_helpers::derive_pubkey_hex(&secret);
    let report = verify_source(&Source::Store(database_path), Some(&pubkey), None)?;
    assert!(report.to_string().starts_with("OK: store"));
    Ok(())
}

#[test]
fn public_store_verification_accepts_a_rotated_timeline_key(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let database_path = database.path().to_path_buf();
    let mut store = pos_store::open_store(pos_store::StoreConfig::Sqlite {
        path: database_path.to_string_lossy().into_owned(),
    })?;
    let timeline = store.create_timeline("ledger")?;
    let identity_one = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 1);
    let identity_two = KeyIdentityV1::new(KeyRoleV1::TimelineIntegritySigning, 2);
    let material_one = SigningKeyMaterial::new(SigningKey::from_bytes(&[41; 32]));
    let material_two = SigningKeyMaterial::new(SigningKey::from_bytes(&[42; 32]));
    let mut registry = KeyRegistryStateV1::new();
    registry.register_key(KeyRegistrationV1::new(
        identity_one,
        material_one.material_digest(),
        Some(material_one.public_verification_key()),
    ))?;
    let payload_one = CanonicalBytes::from_static(b"epoch one");
    let signature_one =
        sign_for_registered_role(&mut registry, &material_one, identity_one, &payload_one)?;
    registry.register_key(KeyRegistrationV1::new(
        identity_two,
        material_two.material_digest(),
        Some(material_two.public_verification_key()),
    ))?;
    let payload_two = CanonicalBytes::from_static(b"epoch two");
    let signature_two =
        sign_for_registered_role(&mut registry, &material_two, identity_two, &payload_two)?;
    store.save_key_registry(&registry)?;
    store.append_committed(
        timeline.id(),
        &[
            Event {
                id: EventId::new(),
                entity: EntityId::new(),
                event_type: Kind::new(pos_plugin_ledger::EVENT_TYPE_PREDICTION),
                payload: payload_one.clone(),
                wall_time: WallTime::from_micros(1),
                seq: Seq::from_u64(1),
                causation_id: None,
                correlation_id: None,
                schema_version: SchemaVersion::V1,
                signature: Some(signature_one),
                signature_identity: Some(identity_one),
                payload_hash: pos_crypto::chain::hash_payload(&payload_one),
            },
            Event {
                id: EventId::new(),
                entity: EntityId::new(),
                event_type: Kind::new(pos_plugin_ledger::EVENT_TYPE_PREDICTION),
                payload: payload_two.clone(),
                wall_time: WallTime::from_micros(2),
                seq: Seq::from_u64(2),
                causation_id: None,
                correlation_id: None,
                schema_version: SchemaVersion::V1,
                signature: Some(signature_two),
                signature_identity: Some(identity_two),
                payload_hash: pos_crypto::chain::hash_payload(&payload_two),
            },
        ],
    )?;
    drop(store);

    let mut anchor_one = String::with_capacity(64);
    for byte in material_one.public_verification_key().as_bytes() {
        write!(&mut anchor_one, "{byte:02x}")?;
    }
    let mut anchor_two = String::with_capacity(64);
    for byte in material_two.public_verification_key().as_bytes() {
        write!(&mut anchor_two, "{byte:02x}")?;
    }
    let anchors = format!("2/1={anchor_one},2/2={anchor_two}");
    let report = verify_source(&Source::Store(database_path), Some(&anchors), None)?;
    assert!(report.to_string().starts_with("OK: store"));

    let single_anchor = material_one
        .public_verification_key()
        .as_bytes()
        .iter()
        .try_fold(String::with_capacity(64), |mut value, byte| {
            write!(&mut value, "{byte:02x}").map(|()| value)
        })?;
    let report = verify_source(
        &Source::Store(database.path().to_path_buf()),
        Some(&single_anchor),
        None,
    )?;
    assert!(report
        .to_string()
        .contains("rotated ledger requires role/epoch keyed public-key trust anchors"));
    Ok(())
}

#[test]
fn public_store_verification_rejects_malformed_key_anchor_sets(
) -> Result<(), Box<dyn std::error::Error>> {
    let database = tempfile::NamedTempFile::new()?;
    let database_path = database.path().to_path_buf();
    for value in ["2/1", "x/1=aa", "2/x=aa", "2/0=aa", "2/1=zz", "2/1=aa"] {
        let error = match verify_source(&Source::Store(database_path.clone()), Some(value), None) {
            Ok(report) => {
                return Err(format!("malformed anchor produced a report: {report}").into())
            }
            Err(error) => error,
        };
        assert!(error.to_string().contains("--pubkey"), "{error}");
    }
    let two_bare_keys = format!("{},{}", "aa".repeat(32), "bb".repeat(32));
    let error = match verify_source(&Source::Store(database_path), Some(&two_bare_keys), None) {
        Ok(report) => return Err(format!("multiple bare keys produced a report: {report}").into()),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("entries must use role-code/epoch=hex format"));
    Ok(())
}
