//! ADR-134 S1, S2 and S3 tests of the Gateway execution-mode profiles.

use super::declaration::compile_declaration_v1;
use super::*;
use pos_core::{GatewayModeBindingKindV1, GatewayModeBindingPortV1 as _};
use pos_runtime::{ErasureCoordinatorCompositionV1, ErasureExecutionHostV1};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore, StoreConfig};
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU64;
use std::path::PathBuf;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DECLARATION: &str =
    include_str!("../../../../contracts/gateway/v1/execution-mode-profiles.json");
const LOCAL_GMP1_HEX: &str = "8c64474d50310175676174657761792d6d6f64652d6c6f63616c2d763165312e302e3001f583010203850102030405026d6c6976652d6c6f63616c2d763101f6";
const AIR_GAPPED_GMP1_HEX: &str = "8c64474d503101781a676174657761792d6d6f64652d6169722d6761707065642d763165312e302e3002f482010385010203040501f601f6";
const LOCAL_DIGEST_HEX: &str = "26d6c7e75b11df673a1ef2d3210733b4ca431648eab0b9ae93bf4a6f6e69da3f";
const AIR_GAPPED_DIGEST_HEX: &str =
    "455883a475edbf5cc24907a03e6e46a476ceec6227ecdb8429999646dac447e5";

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|byte| {
            [byte >> 4, byte & 0x0f]
                .map(|nibble| char::from_digit(u32::from(nibble), 16).unwrap_or_default())
        })
        .collect()
}

fn profile(id: GatewayModeProfileIdV1) -> GatewayModeProfileV1 {
    installed_gateway_mode_profile_v1(id)
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(error.to_string())))
}

fn compiled_bytes(id: GatewayModeProfileIdV1) -> &'static [u8] {
    match id {
        GatewayModeProfileIdV1::Local => compiled::GATEWAY_MODE_LOCAL_V1,
        GatewayModeProfileIdV1::AirGapped => compiled::GATEWAY_MODE_AIR_GAPPED_V1,
    }
}

fn composition(addr: IpAddr) -> GatewayServeCompositionV1 {
    GatewayServeCompositionV1 {
        tcp_addr: SocketAddr::new(addr, 8080),
        owntracks_owner_key: None,
        fork_admission_socket: None,
        ledger_source: None,
        network_grants: BTreeSet::new(),
    }
}

fn loopback() -> GatewayServeCompositionV1 {
    composition(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

fn spectator() -> GatewayServeCompositionV1 {
    composition(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

fn grants(
    mut composition: GatewayServeCompositionV1,
    grants: &[GatewayNetworkGrantV1],
) -> GatewayServeCompositionV1 {
    composition.network_grants = grants.iter().copied().collect();
    composition
}

fn memory_host() -> Result<ErasureExecutionHostV1, Box<dyn std::error::Error>> {
    Ok(ErasureExecutionHostV1::open_with_authority(
        StoreConfig::Memory,
        &ErasureCoordinatorCompositionV1::closed(),
        pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
    )?)
}

fn sqlite_host(path: &str) -> Result<ErasureExecutionHostV1, Box<dyn std::error::Error>> {
    Ok(ErasureExecutionHostV1::open_with_authority(
        StoreConfig::Sqlite {
            path: path.to_owned(),
        },
        &ErasureCoordinatorCompositionV1::closed(),
        pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
    )?)
}

fn temporary_database() -> Result<(tempfile::TempDir, String), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory
        .path()
        .join("gateway.db")
        .to_str()
        .ok_or("temporary path is not UTF-8")?
        .to_owned();
    Ok((directory, path))
}

fn binding_epoch(host: &mut ErasureExecutionHostV1) -> Result<u64, Box<dyn std::error::Error>> {
    Ok(host
        .gateway_mode_binding()
        .load_mode_binding()?
        .ok_or("the store has no binding")?
        .binding_epoch()
        .get())
}

fn reference(id: &str, byte: u8) -> GatewayModeProfileRefV1 {
    GatewayModeProfileRefV1::try_new(id, [byte; 32])
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(error.to_string())))
}

#[test]
fn compiled_profiles_match_their_golden_bytes_and_digests() {
    for (id, bytes, digest) in [
        (
            GatewayModeProfileIdV1::Local,
            LOCAL_GMP1_HEX,
            LOCAL_DIGEST_HEX,
        ),
        (
            GatewayModeProfileIdV1::AirGapped,
            AIR_GAPPED_GMP1_HEX,
            AIR_GAPPED_DIGEST_HEX,
        ),
    ] {
        assert_eq!(hex(compiled_bytes(id)), bytes);
        let installed = profile(id);
        assert_eq!(installed.digest.to_hex(), digest);
        assert_eq!(hex(&installed.digest.revision_bytes()), digest);
        assert_eq!(hex(&installed.digest.store_bytes()), digest);
        assert_eq!(installed.id, id);
        assert_eq!(installed.record.mode_profile_id, id.as_str());
    }
}

#[test]
fn the_public_declaration_recompiles_to_the_compiled_table() -> TestResult {
    let compiled = compile_declaration_v1(DECLARATION)?;
    assert_eq!(
        compiled,
        vec![
            (
                AIR_GAPPED_MODE_PROFILE_ID.to_owned(),
                compiled_bytes(GatewayModeProfileIdV1::AirGapped).to_vec()
            ),
            (
                LOCAL_MODE_PROFILE_ID.to_owned(),
                compiled_bytes(GatewayModeProfileIdV1::Local).to_vec()
            ),
        ]
    );
    Ok(())
}

fn declaration_with(from: &str, to: &str) -> String {
    assert!(DECLARATION.contains(from), "{from}");
    DECLARATION.replacen(from, to, 1)
}

#[test]
fn the_build_rejects_every_unreviewed_declaration() {
    let rejected = [
        declaration_with("\"Reviewed\"", "\"Draft\""),
        declaration_with("\"magic\": \"GMD1\"", "\"magic\": \"DFA1\""),
        declaration_with(
            "\"gateway-execution-mode-only\"",
            "\"repository-test-fixture-only\"",
        ),
        declaration_with("\"Reviewed\"", "\"Candidate\""),
        declaration_with("\"magic\": \"GMD1\"", "\"magic\": \"GMD2\""),
        declaration_with("\"version\": 1", "\"version\": 2"),
        declaration_with("\"gateway-execution-mode-only\"", "\"execution-profile\""),
        declaration_with(
            "\"semantic_version\": \"1.0.0\"",
            "\"semantic_version\": \"01.0.0\"",
        ),
        declaration_with("\"network_allowed\": false", "\"network_allowed\": true"),
        declaration_with("\"mode\": \"air-gapped\"", "\"mode\": \"remote\""),
        declaration_with("\"mode\": \"air-gapped\"", "\"mode\": \"local\""),
        declaration_with("\"loopback-http\"", "\"fork-admission-socket\""),
        declaration_with("\"linux\"", "\"windows\""),
        declaration_with("\"current-by-construction\"", "\"observed\""),
        declaration_with(
            "\"previous_mode_profile_digest\": null",
            "\"previous_mode_profile_digest\": \"ABCD\"",
        ),
        declaration_with(
            "\"previous_mode_profile_digest\": null",
            "\"previous_mode_profile_digest\": \"abcd\"",
        ),
        declaration_with("\"registration_profile_id\": null,\n", ""),
        declaration_with(
            "\"registration_profile_id\": null",
            "\"registration_profile_id\": null,\n      \"capability_ids\": []",
        ),
        declaration_with("\"gateway-mode-local-v1\"", "\"gateway-mode-remote-v1\""),
        declaration_with(
            "\"gateway-mode-air-gapped-v1\"",
            "\"gateway-mode-local-v1\"",
        ),
        DECLARATION.replacen(
            "\"gateway-mode-air-gapped-v1\"",
            "\"gateway-mode-zz-v1\"",
            1,
        ),
        "{".to_owned(),
    ];
    for declaration in rejected {
        assert!(
            compile_declaration_v1(&declaration).is_err(),
            "{declaration}"
        );
    }
    assert!(compile_declaration_v1(&declaration_with(
        "\"registration_profile_id\": null",
        "\"registration_profile_id\": \"live-local-v1\""
    ))
    .is_err());
}

#[test]
fn a_reviewed_revision_carries_its_previous_digest_in_field_eleven() -> TestResult {
    let previous = "ab".repeat(32);
    let compiled = compile_declaration_v1(&declaration_with(
        "\"previous_mode_profile_digest\": null",
        &format!("\"previous_mode_profile_digest\": \"{previous}\""),
    ))?;
    let air_gapped = &compiled[0].1;
    assert!(hex(air_gapped).ends_with(&format!("5820{previous}")));
    let decoded = decode_gmp1(air_gapped).ok_or("revision does not decode")?;
    assert_eq!(decoded.previous_mode_profile_digest, Some([0xab; 32]));
    Ok(())
}

#[test]
fn record_validation_names_each_broken_rule() {
    let valid = profile(GatewayModeProfileIdV1::Local).record;
    assert_eq!(valid.validate(), Ok(()));
    let mut unknown = valid.clone();
    unknown.mode_profile_id = "gateway-mode-remote-v1".to_owned();
    assert!(unknown
        .validate()
        .is_err_and(|error| error.contains("unknown")));
    let mut predicates = valid.clone();
    predicates.startup_predicates = vec![1, 2, 3, 4];
    assert!(predicates
        .validate()
        .is_err_and(|error| error.contains("reviewed meaning")));
    for (version, accepted) in [
        ("1.0.0", true),
        ("123456789.0.0", true),
        ("0.0", false),
        ("1.0.0.0", false),
        ("1.00.0", false),
        ("1.a.0", false),
        ("1234567890.0.0", false),
        ("1..0", false),
    ] {
        let mut record = valid.clone();
        record.semantic_version = version.to_owned();
        assert_eq!(record.validate().is_ok(), accepted, "{version}");
    }
}

fn gmp1_items(id: GatewayModeProfileIdV1) -> Vec<Value> {
    ciborium::de::from_reader::<Value, _>(compiled_bytes(id))
        .ok()
        .and_then(|value| value.into_array().ok())
        .unwrap_or_default()
}

fn encoded(items: Vec<Value>) -> Vec<u8> {
    let mut bytes = Vec::new();
    drop(ciborium::ser::into_writer(&Value::Array(items), &mut bytes));
    bytes
}

#[test]
fn the_decoder_accepts_only_exact_canonical_records() {
    let local = compiled_bytes(GatewayModeProfileIdV1::Local);
    assert!(decode_gmp1(local).is_some());
    assert!(decode_gmp1(&[0; 4_097]).is_none());
    assert!(decode_gmp1(&[0xff]).is_none());
    assert!(decode_gmp1(&[0x01]).is_none());
    let mut trailing = local.to_vec();
    trailing.push(0);
    assert!(decode_gmp1(&trailing).is_none());
    let items = gmp1_items(GatewayModeProfileIdV1::Local);
    assert_eq!(items.len(), 12);
    assert!(decode_gmp1(&encoded(items[..11].to_vec())).is_none());
    for index in 0..items.len() {
        let mut wrong = items.clone();
        wrong[index] = Value::Bytes(Vec::new());
        assert!(decode_gmp1(&encoded(wrong)).is_none(), "field {index}");
    }
    for (index, replacement) in [
        (0, Value::Text("EPF1".to_owned())),
        (1, Value::Integer(2.into())),
        (10, Value::Integer(2.into())),
        (6, Value::Array(vec![Value::Integer(300.into())])),
        (4, Value::Integer(2.into())),
    ] {
        let mut wrong = items.clone();
        wrong[index] = replacement;
        assert!(decode_gmp1(&encoded(wrong)).is_none(), "field {index}");
    }
    let air_gapped = gmp1_items(GatewayModeProfileIdV1::AirGapped);
    let mut short_digest = air_gapped;
    short_digest[11] = Value::Bytes(vec![1; 31]);
    assert!(decode_gmp1(&encoded(short_digest)).is_none());
    let mut non_canonical = local.to_vec();
    non_canonical[0] = 0x9f;
    non_canonical.push(0xff);
    assert!(decode_gmp1(&non_canonical).is_none());
}

#[test]
fn a_profile_decodes_only_under_its_own_identifier() {
    assert_eq!(
        GatewayModeProfileV1::decode(
            GatewayModeProfileIdV1::Local,
            compiled_bytes(GatewayModeProfileIdV1::AirGapped)
        )
        .err(),
        Some(GatewayModeErrorV1::InvalidProfileRecord)
    );
}

#[test]
fn gmp1_and_epf1_never_cross_decode() -> TestResult {
    let epf1 = pos_conformance::draft_execution_profile_bytes_v1("deterministic-local-v1")?;
    assert!(decode_gmp1(&epf1).is_none());
    for id in GatewayModeProfileIdV1::ALL {
        assert!(
            pos_conformance::ExecutionProfileV1::from_canonical_cbor(compiled_bytes(id)).is_err()
        );
        assert!(pos_conformance::host_verified_execution_profile_bytes_v1(id.as_str()).is_err());
    }
    assert!(
        pos_conformance::host_verified_execution_profile_bytes_v1("deterministic-local-v1")
            .is_err()
    );
    Ok(())
}

#[test]
fn identifiers_and_grants_parse_from_their_closed_text() {
    for id in GatewayModeProfileIdV1::ALL {
        assert_eq!(id.as_str().parse(), Ok(id));
    }
    assert_eq!(
        "deterministic-local-v1".parse::<GatewayModeProfileIdV1>(),
        Err(GatewayModeErrorV1::UnknownProfile)
    );
    assert_eq!("owntracks".parse(), Ok(GatewayNetworkGrantV1::OwnTracks));
    assert_eq!(
        "public-read-only".parse(),
        Ok(GatewayNetworkGrantV1::PublicReadOnly)
    );
    assert_eq!(
        "ledger".parse::<GatewayNetworkGrantV1>(),
        Err(GatewayModeErrorV1::UnknownNetworkGrant)
    );
    assert_eq!(GatewayNetworkGrantV1::OwnTracks.tag(), 0x01);
    assert_eq!(GatewayNetworkGrantV1::PublicReadOnly.tag(), 0x02);
}

#[test]
fn startup_predicates_enforce_d6_in_both_modes() {
    use GatewayModeErrorV1 as E;
    use GatewayModeProfileIdV1::{AirGapped, Local};
    use GatewayNetworkGrantV1::{OwnTracks, PublicReadOnly};
    let mut owntracks = loopback();
    owntracks.owntracks_owner_key = Some(PathBuf::from("/private/owner.key"));
    let mut owntracks_spectator = spectator();
    owntracks_spectator.owntracks_owner_key = Some(PathBuf::from("/private/owner.key"));
    let mut fork = loopback();
    fork.fork_admission_socket = Some(PathBuf::from("/run/pigloros/fork.sock"));
    let mut network_ledger = loopback();
    network_ledger.ledger_source = Some(OsString::from("https://ledger.example/"));
    let mut local_ledger = loopback();
    local_ledger.ledger_source = Some(OsString::from("/srv/piglor/ledger"));
    let cases = [
        (Local, loopback(), Ok(())),
        (Local, fork.clone(), Ok(())),
        (Local, local_ledger.clone(), Ok(())),
        (Local, spectator(), Err(E::NetworkGrantRequired)),
        (Local, grants(spectator(), &[PublicReadOnly]), Ok(())),
        (Local, owntracks.clone(), Err(E::NetworkGrantRequired)),
        (Local, grants(owntracks.clone(), &[OwnTracks]), Ok(())),
        (
            Local,
            grants(owntracks_spectator, &[OwnTracks, PublicReadOnly]),
            Err(E::OwnTracksRequiresLoopback),
        ),
        (Local, network_ledger.clone(), Err(E::NetworkLedgerSource)),
        (AirGapped, loopback(), Ok(())),
        (AirGapped, fork, Ok(())),
        (AirGapped, local_ledger, Ok(())),
        (AirGapped, spectator(), Err(E::ListenerOutsideIngress)),
        (
            AirGapped,
            grants(spectator(), &[PublicReadOnly]),
            Err(E::ListenerOutsideIngress),
        ),
        (
            AirGapped,
            grants(loopback(), &[PublicReadOnly]),
            Err(E::NetworkGrantRefused),
        ),
        (
            AirGapped,
            grants(owntracks.clone(), &[OwnTracks]),
            Err(E::NetworkGrantRefused),
        ),
        (AirGapped, owntracks, Err(E::NetworkGrantRequired)),
        (AirGapped, network_ledger, Err(E::NetworkLedgerSource)),
    ];
    for (id, composition, expected) in cases {
        assert_eq!(
            verify_gateway_serve_composition_v1(id, &composition),
            expected,
            "{id:?} {composition:?}"
        );
    }
}

#[test]
fn a_fork_socket_outside_the_ingress_is_refused() {
    let mut narrowed = profile(GatewayModeProfileIdV1::Local);
    narrowed.record.ingress = vec![INGRESS_LOOPBACK_HTTP];
    let mut fork = loopback();
    assert_eq!(verify_predicates(&narrowed, &fork), Ok(()));
    fork.fork_admission_socket = Some(PathBuf::from("/run/pigloros/fork.sock"));
    assert_eq!(
        verify_predicates(&narrowed, &fork),
        Err(GatewayModeErrorV1::ListenerOutsideIngress)
    );
}

#[test]
fn predicate_five_decides_bind_attach_rotate_or_refusal() {
    let current = reference("gateway-mode-local-v1", 2);
    let record = |profile: GatewayModeProfileRefV1| {
        Some(GatewayModeBindingRecordV1::new(profile, NonZeroU64::MIN))
    };
    assert_eq!(decide(None, &current, None), Ok(BindingDecisionV1::Bind));
    assert_eq!(
        decide(record(current.clone()), &current, Some([1; 32])),
        Ok(BindingDecisionV1::Attach)
    );
    let previous = reference("gateway-mode-local-v1", 1);
    assert_eq!(
        decide(record(previous.clone()), &current, Some([1; 32])),
        Ok(BindingDecisionV1::Rotate(previous.clone()))
    );
    assert_eq!(
        decide(record(previous), &current, Some([3; 32])),
        Err(GatewayModeErrorV1::ModeMismatch)
    );
    assert_eq!(
        decide(
            record(reference("gateway-mode-air-gapped-v1", 1)),
            &current,
            Some([1; 32])
        ),
        Err(GatewayModeErrorV1::ModeMismatch)
    );
}

#[test]
fn a_one_hop_rotation_advances_the_epoch() -> TestResult {
    let mut store = MemoryStore::new();
    let previous = reference("gateway-mode-local-v1", 1);
    let host = GatewayModeBindingHostV1::new();
    store.bind_empty_store_mode(host.authorize_bind(previous.clone()))?;
    let current = reference("gateway-mode-local-v1", 2);
    let rotated = apply_decision(
        &mut store,
        current.clone(),
        BindingDecisionV1::Rotate(previous),
    )?;
    assert_eq!(rotated.binding_epoch().get(), 2);
    assert_eq!(rotated.profile(), &current);
    let history = store.load_mode_binding_history()?;
    assert_eq!(
        history
            .iter()
            .map(pos_core::GatewayModeBindingHistoryEntryV1::kind)
            .collect::<Vec<_>>(),
        [
            GatewayModeBindingKindV1::Bind,
            GatewayModeBindingKindV1::Rotate
        ]
    );
    Ok(())
}

#[test]
fn the_first_serve_binds_an_empty_store_and_a_restart_attaches() -> TestResult {
    let (_directory, path) = temporary_database()?;
    let mut first = sqlite_host(&path)?;
    bind_gateway_mode_v1(GatewayModeProfileIdV1::Local, loopback(), &mut first)?;
    assert_eq!(binding_epoch(&mut first)?, 1);
    drop(first);
    let mut restarted = sqlite_host(&path)?;
    bind_gateway_mode_v1(GatewayModeProfileIdV1::Local, loopback(), &mut restarted)?;
    let current = restarted
        .gateway_mode_binding()
        .load_mode_binding()?
        .ok_or("the store has no binding")?;
    assert_eq!(current.binding_epoch().get(), 1);
    assert_eq!(hex(&current.profile().profile_digest()), LOCAL_DIGEST_HEX);
    drop(restarted);
    let mut switched = sqlite_host(&path)?;
    assert_eq!(
        bind_gateway_mode_v1(GatewayModeProfileIdV1::AirGapped, loopback(), &mut switched).err(),
        Some(GatewayModeErrorV1::ModeMismatch)
    );
    Ok(())
}

#[test]
fn binding_refuses_a_d6_violation_and_a_populated_unbound_store() -> TestResult {
    let mut host = memory_host()?;
    assert_eq!(
        bind_gateway_mode_v1(GatewayModeProfileIdV1::AirGapped, spectator(), &mut host).err(),
        Some(GatewayModeErrorV1::ListenerOutsideIngress)
    );
    let timeline = host.command_sender()?.create_timeline("populated")?.id();
    host.command_sender()?.append(
        timeline,
        &[pos_core::EventDraft::new(
            pos_core::EntityId::new(),
            pos_core::Kind::new("gateway.fixture"),
            pos_core::CanonicalBytes::from_vec(Vec::new()),
        )],
    )?;
    assert_eq!(
        bind_gateway_mode_v1(GatewayModeProfileIdV1::Local, loopback(), &mut host).err(),
        Some(GatewayModeErrorV1::Store(
            pos_core::GatewayModeBindingErrorV1::PopulatedUnbound
        ))
    );
    Ok(())
}

#[test]
fn a_stale_process_cannot_commit_after_a_migration() -> TestResult {
    let (_directory, path) = temporary_database()?;
    let mut serving = sqlite_host(&path)?;
    bind_gateway_mode_v1(GatewayModeProfileIdV1::Local, loopback(), &mut serving)?;
    let draft = || {
        pos_core::EventDraft::new(
            pos_core::EntityId::new(),
            pos_core::Kind::new("gateway.fixture"),
            pos_core::CanonicalBytes::from_vec(Vec::new()),
        )
    };
    let timeline = serving.command_sender()?.create_timeline("bound")?.id();
    serving.command_sender()?.append(timeline, &[draft()])?;
    let head = serving.command_sender()?.logical_head(timeline)?;
    let audit = migrate_gateway_mode_v1(
        &path,
        GatewayModeProfileIdV1::Local,
        GatewayModeProfileIdV1::AirGapped,
    )?;
    assert!(audit.contains("to gateway-mode-air-gapped-v1 (455883a4"));
    assert!(audit.ends_with("at binding epoch 2"));
    // The append commits nothing, and the stale adapter instance is told why.
    let refused = serving
        .command_sender()
        .and_then(|mut sender| sender.append(timeline, &[draft()]));
    assert_eq!(
        refused.err(),
        Some(pos_core::ErasureHostErrorV1::ModeBindingStale)
    );
    drop(serving);
    let mut reopened = sqlite_host(&path)?;
    bind_gateway_mode_v1(GatewayModeProfileIdV1::AirGapped, loopback(), &mut reopened)?;
    assert_eq!(binding_epoch(&mut reopened)?, 2);
    assert_eq!(reopened.command_sender()?.logical_head(timeline)?, head);
    Ok(())
}

#[test]
fn migration_refuses_unbound_mismatched_and_identical_modes() -> TestResult {
    use GatewayModeProfileIdV1::{AirGapped, Local};
    let (directory, path) = temporary_database()?;
    assert_eq!(
        migrate_gateway_mode_v1(&path, Local, AirGapped).err(),
        Some(GatewayModeErrorV1::Store(
            pos_core::GatewayModeBindingErrorV1::Unbound
        ))
    );
    let mut host = sqlite_host(&path)?;
    bind_gateway_mode_v1(Local, loopback(), &mut host)?;
    drop(host);
    assert_eq!(
        migrate_gateway_mode_v1(&path, AirGapped, Local).err(),
        Some(GatewayModeErrorV1::Store(
            pos_core::GatewayModeBindingErrorV1::Mismatch
        ))
    );
    assert_eq!(
        migrate_gateway_mode_v1(&path, Local, Local).err(),
        Some(GatewayModeErrorV1::Store(
            pos_core::GatewayModeBindingErrorV1::Mismatch
        ))
    );
    let directory_path = directory.path().to_str().ok_or("path is not UTF-8")?;
    assert_eq!(
        migrate_gateway_mode_v1(directory_path, Local, AirGapped).err(),
        Some(GatewayModeErrorV1::StoreLockUnavailable)
    );
    Ok(())
}

#[test]
fn the_store_lock_excludes_migration_while_the_store_is_in_use() -> TestResult {
    let (directory, path) = temporary_database()?;
    let serving = GatewayModeStoreLockV1::shared(&path)?;
    let writer = GatewayModeStoreLockV1::shared(&path)?;
    assert_eq!(
        GatewayModeStoreLockV1::exclusive(&path).err(),
        Some(GatewayModeErrorV1::StoreLockUnavailable)
    );
    assert_eq!(
        migrate_gateway_mode_v1(
            &path,
            GatewayModeProfileIdV1::Local,
            GatewayModeProfileIdV1::AirGapped
        )
        .err(),
        Some(GatewayModeErrorV1::StoreLockUnavailable)
    );
    drop((serving, writer));
    let migrating = GatewayModeStoreLockV1::exclusive(&path)?;
    assert_eq!(
        GatewayModeStoreLockV1::shared(&path).err(),
        Some(GatewayModeErrorV1::StoreLockUnavailable)
    );
    drop(migrating);
    let missing = directory.path().join("missing").join("gateway.db");
    assert_eq!(
        GatewayModeStoreLockV1::shared(missing.to_str().ok_or("path is not UTF-8")?).err(),
        Some(GatewayModeErrorV1::StoreLockUnavailable)
    );
    Ok(())
}

#[test]
fn offline_writers_attach_only_a_compiled_binding() -> TestResult {
    let (_directory, path) = temporary_database()?;
    let mut unbound = SqliteStore::open(&path)?;
    assert_eq!(
        attach_offline_writer_v1(&mut unbound),
        Err(GatewayModeErrorV1::Store(
            pos_core::GatewayModeBindingErrorV1::Unbound
        ))
    );
    let mut foreign = MemoryStore::new();
    foreign.bind_empty_store_mode(
        GatewayModeBindingHostV1::new().authorize_bind(reference("gateway-mode-local-v1", 9)),
    )?;
    assert_eq!(
        attach_offline_writer_v1(&mut foreign),
        Err(GatewayModeErrorV1::ModeMismatch)
    );
    for id in GatewayModeProfileIdV1::ALL {
        let mut store = MemoryStore::new();
        store.bind_empty_store_mode(
            GatewayModeBindingHostV1::new().authorize_bind(profile(id).reference()?),
        )?;
        assert_eq!(attach_offline_writer_v1(&mut store), Ok(id));
    }
    assert_eq!(refuse_air_gapped(GatewayModeProfileIdV1::Local), Ok(()));
    assert_eq!(
        refuse_air_gapped(GatewayModeProfileIdV1::AirGapped),
        Err(GatewayModeErrorV1::RefusedInMode)
    );
    Ok(())
}

#[test]
fn the_handle_discloses_only_its_revision_inputs_and_selection() {
    let local = test_binding(
        GatewayModeProfileIdV1::Local,
        [
            GatewayNetworkGrantV1::PublicReadOnly,
            GatewayNetworkGrantV1::OwnTracks,
        ],
    );
    assert_eq!(format!("{local:?}"), "GatewayModeBindingV1 { .. }");
    assert_eq!(local.registration_profile_id(), Some("live-local-v1"));
    let revision = local.revision_input();
    assert_eq!(hex(revision.fields()[0]), LOCAL_DIGEST_HEX);
    assert_eq!(revision.fields()[1], [EPF1_EXPLICIT_ABSENT]);
    assert_eq!(revision.fields()[2], [0x01, 0x02]);
    assert!(!revision.revocation_current_by_construction());
    let air_gapped = test_binding(GatewayModeProfileIdV1::AirGapped, []);
    assert_eq!(air_gapped.registration_profile_id(), None);
    let revision = air_gapped.revision_input();
    assert_eq!(hex(revision.fields()[0]), AIR_GAPPED_DIGEST_HEX);
    assert!(revision.fields()[2].is_empty());
    assert!(revision.revocation_current_by_construction());
}

#[tokio::test]
async fn the_stale_signal_wakes_the_serve_loop_once_fired() {
    let binding = test_binding(GatewayModeProfileIdV1::Local, []);
    let signal = binding.stale_signal();
    assert!(!signal.fired());
    binding.stale_signal().fire();
    signal.wait().await;
    assert!(signal.fired());
}

#[test]
fn every_error_has_a_closed_message() {
    use GatewayModeErrorV1 as E;
    for error in [
        E::UnknownProfile,
        E::UnknownNetworkGrant,
        E::UnsupportedPlatform,
        E::InvalidProfileRecord,
        E::ListenerOutsideIngress,
        E::NetworkGrantRequired,
        E::NetworkGrantRefused,
        E::OwnTracksRequiresLoopback,
        E::NetworkLedgerSource,
        E::Store(pos_core::GatewayModeBindingErrorV1::Unbound),
        E::ModeMismatch,
        E::StoreLockUnavailable,
        E::RefusedInMode,
        E::Stale,
    ] {
        assert!(!error.to_string().is_empty());
    }
    assert_eq!(
        E::from(pos_core::GatewayModeBindingErrorV1::Unbound),
        E::Store(pos_core::GatewayModeBindingErrorV1::Unbound)
    );
}

#[test]
fn the_handle_owns_the_verified_listeners_and_its_host() -> TestResult {
    let mut composition = loopback();
    composition.owntracks_owner_key = Some(PathBuf::from("/private/owner.key"));
    composition.fork_admission_socket = Some(PathBuf::from("/run/pigloros/fork.sock"));
    composition.network_grants = std::iter::once(GatewayNetworkGrantV1::OwnTracks).collect();
    let mut bound = memory_host()?;
    let mode = bind_gateway_mode_v1(GatewayModeProfileIdV1::Local, composition, &mut bound)?;
    assert_eq!(
        mode.tcp_addr(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)
    );
    assert_eq!(
        mode.owntracks_owner_key(),
        Some(std::path::Path::new("/private/owner.key"))
    );
    assert_eq!(
        mode.fork_admission_socket(),
        Some(std::path::Path::new("/run/pigloros/fork.sock"))
    );
    assert_eq!(mode.verify_host(&mut bound), Ok(()));
    assert_eq!(
        mode.verify_host(&mut memory_host()?),
        Err(GatewayModeErrorV1::Store(
            pos_core::GatewayModeBindingErrorV1::Unbound
        ))
    );
    let mut other = memory_host()?;
    bind_gateway_mode_v1(GatewayModeProfileIdV1::AirGapped, loopback(), &mut other)?;
    assert_eq!(
        mode.verify_host(&mut other),
        Err(GatewayModeErrorV1::ModeMismatch)
    );
    assert_eq!(GATEWAY_NETWORK_CAPABILITY_V1, "gateway.network.v1");
    Ok(())
}

#[test]
fn an_attach_after_the_binding_changed_is_another_mode() -> TestResult {
    let mut store = MemoryStore::new();
    let host = GatewayModeBindingHostV1::new();
    store.bind_empty_store_mode(host.authorize_bind(reference("gateway-mode-local-v1", 1)))?;
    store.rotate_mode(host.authorize_rotation(
        reference("gateway-mode-local-v1", 1),
        reference("gateway-mode-local-v1", 2),
    )?)?;
    assert_eq!(
        apply_decision(
            &mut store,
            reference("gateway-mode-local-v1", 1),
            BindingDecisionV1::Attach
        ),
        Err(GatewayModeErrorV1::ModeMismatch)
    );
    assert_eq!(
        binding_change_error(pos_core::GatewayModeBindingErrorV1::Unavailable),
        GatewayModeErrorV1::Store(pos_core::GatewayModeBindingErrorV1::Unavailable)
    );
    Ok(())
}

#[test]
fn every_alias_of_one_store_names_one_lock() -> TestResult {
    let (directory, path) = temporary_database()?;
    let alias = directory.path().join("alias");
    std::os::unix::fs::symlink(directory.path(), &alias)?;
    let aliased = alias.join("gateway.db");
    let held = GatewayModeStoreLockV1::shared(aliased.to_str().ok_or("path is not UTF-8")?)?;
    assert_eq!(
        GatewayModeStoreLockV1::exclusive(&path).err(),
        Some(GatewayModeErrorV1::StoreLockUnavailable)
    );
    drop(held);
    std::fs::write(&path, b"")?;
    let linked = directory.path().join("linked.db");
    std::os::unix::fs::symlink(&path, &linked)?;
    let held = GatewayModeStoreLockV1::shared(linked.to_str().ok_or("path is not UTF-8")?)?;
    assert_eq!(
        GatewayModeStoreLockV1::exclusive(&path).err(),
        Some(GatewayModeErrorV1::StoreLockUnavailable)
    );
    drop(held);
    assert!(directory
        .path()
        .join("gateway.db.gateway-mode.lock")
        .exists());
    assert_eq!(
        GatewayModeStoreLockV1::shared("..").err(),
        Some(GatewayModeErrorV1::StoreLockUnavailable)
    );
    Ok(())
}

#[test]
fn migration_never_creates_a_missing_store() -> TestResult {
    let (_directory, path) = temporary_database()?;
    assert_eq!(
        migrate_gateway_mode_v1(
            &path,
            GatewayModeProfileIdV1::Local,
            GatewayModeProfileIdV1::AirGapped
        )
        .err(),
        Some(GatewayModeErrorV1::Store(
            pos_core::GatewayModeBindingErrorV1::Unbound
        ))
    );
    assert!(!std::path::Path::new(&path).exists());
    std::fs::write(
        &path,
        b"not an SQLite database, only a long enough header for SQLite to reject",
    )?;
    assert_eq!(
        migrate_gateway_mode_v1(
            &path,
            GatewayModeProfileIdV1::Local,
            GatewayModeProfileIdV1::AirGapped
        )
        .err(),
        Some(GatewayModeErrorV1::Store(
            pos_core::GatewayModeBindingErrorV1::Unavailable
        ))
    );
    Ok(())
}
