//! Public acceptance vectors for the ADR-103 revision 3 and 4 Plugin TPS1 bridge.

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_conformance::{
    authenticate_plugin_tps1_v1, check_plugin_tps1_artifact_denial_v1,
    check_plugin_tps1_genesis_v1, check_plugin_tps1_global_caps_v1, check_plugin_tps1_successor_v1,
    parse_offline_valid_through_v1, plan_plugin_floor_transition_v1, plugin_floor_transition_v1,
    plugin_revoked_key_id_v1, plugin_root_key_id_v1, verify_plugin_tps1_policy_v1,
    AuthenticatedPluginTps1V1, PluginFloorErrorV1, PluginFloorKindV1, PluginFloorPlanV1,
    PluginFloorStateV1, PluginFloorTransitionV1, PluginTrustBridgeErrorV1,
    PluginTrustPolicyAnchorV1, TrustPolicyRootV1, TrustPolicySnapshotV1,
    OFFLINE_VALID_THROUGH_BYTES_V1, PLUGIN_OPERATOR_ROLE_V1, PLUGIN_TPS1_BRIDGE_ID_BYTES_V1,
};
use pos_core::OwnerIdV1;
use pos_crypto::plugin_trust::{
    verify_plugin_trust_v1, PluginManifestProjectionFixtureV1, PluginTrustErrorV1,
    TrustedPluginRootAnchorV1, ValidatedPluginManifestProjectionV1, VerifiedPluginTrustEvidenceV1,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Floor = (u64, [u8; 32]);

const ROOT_SIGNATURE_DOMAIN: &[u8] = b"pigloros/plugin-trust-root/v1\0";
const REVOCATION_SIGNATURE_DOMAIN: &[u8] = b"pigloros/plugin-revocation/v1\0";
const EVALUATION_UTC: i64 = 50;
const EVALUATION_TICK: u64 = 5;

// Independently generated with a separate CBOR encoder, `b3sum`, and
// Python `cryptography` Ed25519 over operator seed `[0x11; 32]`.
const OPERATOR_PUBLIC_KEY_HEX: &str =
    "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
const GOLDEN_PREIMAGE_HEX: &str = "5069676c6f724f532e545053312e6f70657261746f722d7369676e61747572652e7631008b6454505331016d706c7567696e2e676f6c64656e020781847845707472312d6162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616203674564323535313958204242424242424242424242424242424242424242424242424242424242424242816f7265766f6b65642e6578616d706c658158201111111111111111111111111111111111111111111111111111111111111111818266706c7567696e65312e322e3374323033302d30312d30315430303a30303a30305a58202222222222222222222222222222222222222222222222222222222222222222";
const GOLDEN_TPS1_HEX: &str = "8c6454505331016d706c7567696e2e676f6c64656e020781847845707472312d6162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616203674564323535313958204242424242424242424242424242424242424242424242424242424242424242816f7265766f6b65642e6578616d706c658158201111111111111111111111111111111111111111111111111111111111111111818266706c7567696e65312e322e3374323033302d30312d30315430303a30303a30305a58202222222222222222222222222222222222222222222222222222222222222222584019cddc75717cbe12b3cd9a6e2ccbb478a80333dc0bdb925d56e70ec6d23761fc16ed351cf94f64a8328a8a41c1f7d2a59bcee61a515fed9e527211ef4e8d780f";
const GOLDEN_POLICY_ID_BYTE: usize = 17;
const GOLDEN_POSITION_BYTE: usize = 22;
const GOLDEN_TPS1_DIGEST_HEX: &str =
    "915d839fa1d921bf2cca5e21c40169b16b3e5f32ef80b4a91d956dca2b1cb931";

fn hex_bytes(text: &str) -> TestResult<Vec<u8>> {
    if text.len() & 1 == 1 {
        return Err("odd hex length".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).map_err(Into::into))
        .collect()
}

fn hex_32(text: &str) -> TestResult<[u8; 32]> {
    hex_bytes(text)?
        .try_into()
        .map_err(|_| "not 32 bytes".into())
}

fn anchor_for(scope: &str, operator: [u8; 32]) -> TestResult<PluginTrustPolicyAnchorV1> {
    Ok(PluginTrustPolicyAnchorV1::new(
        scope,
        [1; 32],
        operator,
        PLUGIN_OPERATOR_ROLE_V1,
        [2; 32],
    )?)
}

fn operator_signer() -> SigningKey {
    SigningKey::from_bytes(&[0x11; 32])
}

#[test]
fn golden_operator_signature_preimage_and_signed_tps1_vector() -> TestResult {
    let operator = hex_32(OPERATOR_PUBLIC_KEY_HEX)?;
    assert_eq!(operator, operator_signer().verifying_key().to_bytes());
    let bytes = hex_bytes(GOLDEN_TPS1_HEX)?;
    let snapshot = TrustPolicySnapshotV1::from_canonical_cbor(&bytes)?;
    assert_eq!(
        snapshot.operator_signature_message_v1()?,
        hex_bytes(GOLDEN_PREIMAGE_HEX)?
    );
    let anchor = anchor_for("plugin.golden", operator)?;
    let authenticated = authenticate_plugin_tps1_v1(&anchor, &bytes)?;
    assert_eq!(authenticated.bytes(), bytes.as_slice());
    assert_eq!(authenticated.digest(), hex_32(GOLDEN_TPS1_DIGEST_HEX)?);
    assert_eq!(authenticated.epoch(), 2);
    assert_eq!(authenticated.effective_timeline_position(), 7);
    assert_eq!(authenticated.snapshot(), &snapshot);
    Ok(())
}

#[test]
fn authentication_rejects_scope_key_signature_and_encoding_faults() -> TestResult {
    let operator = hex_32(OPERATOR_PUBLIC_KEY_HEX)?;
    let bytes = hex_bytes(GOLDEN_TPS1_HEX)?;
    let anchor = anchor_for("plugin.golden", operator)?;
    let wrong_scope = anchor_for("plugin.other", operator)?;
    assert_eq!(
        authenticate_plugin_tps1_v1(&wrong_scope, &bytes),
        Err(PluginTrustBridgeErrorV1::ScopeMismatch)
    );
    let foreign_key = SigningKey::from_bytes(&[0x12; 32])
        .verifying_key()
        .to_bytes();
    assert_eq!(
        authenticate_plugin_tps1_v1(&anchor_for("plugin.golden", foreign_key)?, &bytes),
        Err(PluginTrustBridgeErrorV1::InvalidOperatorSignature)
    );
    let mut tampered = bytes.clone();
    let last = tampered.last_mut().ok_or("empty TPS1")?;
    *last ^= 1;
    assert_eq!(
        authenticate_plugin_tps1_v1(&anchor, &tampered),
        Err(PluginTrustBridgeErrorV1::InvalidOperatorSignature)
    );
    // Byte 17 is inside the `policy_id` text `plugin.golden`, so the scope no longer matches.
    let mut scope_changed = bytes.clone();
    scope_changed[GOLDEN_POLICY_ID_BYTE] ^= 0x01;
    assert_eq!(
        authenticate_plugin_tps1_v1(&anchor, &scope_changed),
        Err(PluginTrustBridgeErrorV1::ScopeMismatch)
    );
    // Byte 22 is `effective_timeline_position`: a signed field with a valid new value.
    let mut position_changed = bytes.clone();
    position_changed[GOLDEN_POSITION_BYTE] ^= 0x01;
    assert_eq!(
        authenticate_plugin_tps1_v1(&anchor, &position_changed),
        Err(PluginTrustBridgeErrorV1::InvalidOperatorSignature)
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        authenticate_plugin_tps1_v1(&anchor, &trailing),
        Err(PluginTrustBridgeErrorV1::InvalidSnapshot)
    );
    assert_eq!(
        authenticate_plugin_tps1_v1(&anchor, &bytes[..bytes.len() - 1]),
        Err(PluginTrustBridgeErrorV1::InvalidSnapshot)
    );
    assert_eq!(
        authenticate_plugin_tps1_v1(&anchor, &[]),
        Err(PluginTrustBridgeErrorV1::InvalidSnapshot)
    );
    Ok(())
}

#[test]
fn anchor_requires_plugin_scope_literal_role_and_valid_operator_key() -> TestResult {
    let operator = hex_32(OPERATOR_PUBLIC_KEY_HEX)?;
    let anchor = PluginTrustPolicyAnchorV1::new(
        "plugin.golden",
        [3; 32],
        operator,
        "deployment-operator",
        [4; 32],
    )?;
    assert_eq!(anchor.scope(), "plugin.golden");
    assert_eq!(anchor.ptr1_genesis_digest(), [3; 32]);
    assert_eq!(anchor.operator_key(), operator);
    assert_eq!(anchor.operator_role(), "deployment-operator");
    assert_eq!(anchor.genesis_tps1_digest(), [4; 32]);
    assert_eq!(
        anchor.root_anchor(),
        &TrustedPluginRootAnchorV1::new("plugin.golden", [3; 32])?
    );
    let longest = "a".repeat(128);
    assert!(anchor_for(&longest, operator).is_ok());
    for scope in [
        String::new(),
        "a".repeat(129),
        "Upper".to_owned(),
        "-lead".to_owned(),
    ] {
        assert_eq!(
            PluginTrustPolicyAnchorV1::new(
                &scope,
                [3; 32],
                operator,
                PLUGIN_OPERATOR_ROLE_V1,
                [4; 32]
            ),
            Err(PluginTrustBridgeErrorV1::InvalidAnchorScope)
        );
    }
    for role in [
        "",
        "artifact-root",
        "Deployment-Operator",
        "deployment-operator ",
    ] {
        assert_eq!(
            PluginTrustPolicyAnchorV1::new("scope", [3; 32], operator, role, [4; 32]),
            Err(PluginTrustBridgeErrorV1::InvalidAnchorRole)
        );
    }
    let mut off_curve = [0; 32];
    off_curve[0] = 2;
    assert_eq!(
        PluginTrustPolicyAnchorV1::new(
            "scope",
            [3; 32],
            off_curve,
            PLUGIN_OPERATOR_ROLE_V1,
            [4; 32]
        ),
        Err(PluginTrustBridgeErrorV1::InvalidAnchorOperatorKey)
    );
    Ok(())
}

#[test]
fn root_key_ids_are_ptr1_prefixed_lowercase_hex() {
    let mut id = [0xab; 32];
    id[0] = 0x01;
    id[31] = 0xfe;
    let expected = format!("ptr1-01{}fe", "ab".repeat(30));
    assert_eq!(plugin_root_key_id_v1(id), expected);
    assert_eq!(
        plugin_root_key_id_v1(id).len(),
        PLUGIN_TPS1_BRIDGE_ID_BYTES_V1
    );
    assert_eq!(PLUGIN_TPS1_BRIDGE_ID_BYTES_V1, 69);
    assert_eq!(
        plugin_root_key_id_v1([0; 32]),
        format!("ptr1-{}", "0".repeat(64))
    );
    assert!(!plugin_root_key_id_v1([0xff; 32])
        .bytes()
        .any(|byte| byte.is_ascii_uppercase()));
}

const PKR1_OWNER_VECTORS: [(usize, &str); 4] = [
    (
        1,
        "pkr1-e7f765d7236d71b88d6a71f871a9319f8a7a8c9c8d749e03b39a258e65b54b0a",
    ),
    (
        23,
        "pkr1-bf2e72068a8bb10fb932d46b985e53ff0404f1916aeb406cf3d1d0faef30e4a4",
    ),
    (
        24,
        "pkr1-af7ee8ed6bccbe3ccddba7ee4c04d8398c9c521ba5e407ea767eb6b2d593e245",
    ),
    (
        128,
        "pkr1-d82975fe9f4500e6b06a5ed7dd853f649e8835d9d9c2da98cd3c68045b074997",
    ),
];

const PKR1_EPOCH_VECTORS: [(u64, &str); 10] = [
    (
        0,
        "pkr1-1dc148c8083b04f076ec896911e401026e5656c671159e427874fd5946654bb0",
    ),
    (
        23,
        "pkr1-250e91319a0e6847e233fa6da13ce2e2f1db951e5ae540cc176d353eb5fba7c8",
    ),
    (
        24,
        "pkr1-8a4ec94b0a01299916f9b0cb6b6af9feccdfad143cdbc1d12ac196847e3445bd",
    ),
    (
        255,
        "pkr1-6e5978fa7eb3aa802880d42bdfe3c22a388ba2bad9a91e734d0203a3f870dc3d",
    ),
    (
        256,
        "pkr1-2cc4575ce30e4debad86619ef3823e9fe986bddf58e0a83235302965149c0d00",
    ),
    (
        65_535,
        "pkr1-28890dffe454eb08e400787f9835c92ae7583f00d51d0c1ae2d6403075b82118",
    ),
    (
        65_536,
        "pkr1-ff0f68103bdfc51543f5feaa884252dd937b78825b74afd0280435403ccc7475",
    ),
    (
        4_294_967_295,
        "pkr1-e27f0fed0d2dba715dc4b3456bb985292a206c4a68153385e9d983cfc5f4838e",
    ),
    (
        4_294_967_296,
        "pkr1-52f526936a18585582bd4a61f68dcbe1083caa98745fd2745cefa26a6ca750c3",
    ),
    (
        u64::MAX,
        "pkr1-0c5287914ee70f744029c1355f064c1a339cad7b82322b73376e936885528752",
    ),
];

#[test]
fn revoked_key_ids_match_independent_golden_vectors_at_cbor_width_boundaries() -> TestResult {
    let public = [0x42; 32];
    for (owner_length, expected) in PKR1_OWNER_VECTORS {
        let owner = OwnerIdV1::new(if owner_length == 1 {
            "o".to_owned()
        } else {
            "x".repeat(owner_length)
        })?;
        assert_eq!(plugin_revoked_key_id_v1(&owner, 1, public), expected);
        assert_eq!(expected.len(), PLUGIN_TPS1_BRIDGE_ID_BYTES_V1);
    }
    let owner = OwnerIdV1::new("o")?;
    for (epoch, expected) in PKR1_EPOCH_VECTORS {
        assert_eq!(plugin_revoked_key_id_v1(&owner, epoch, public), expected);
    }
    assert_ne!(
        plugin_revoked_key_id_v1(&owner, 1, public),
        plugin_revoked_key_id_v1(&owner, 1, [0x43; 32])
    );
    Ok(())
}

#[test]
fn offline_valid_through_accepts_only_exact_real_gregorian_utc() {
    assert_eq!(OFFLINE_VALID_THROUGH_BYTES_V1, 20);
    for (text, seconds) in [
        ("1970-01-01T00:00:00Z", 0),
        ("1970-01-01T00:00:01Z", 1),
        ("1969-12-31T23:59:59Z", -1),
        ("2000-02-29T23:59:59Z", 951_868_799),
        ("2000-03-01T00:00:00Z", 951_868_800),
        ("1900-03-01T00:00:00Z", -2_203_891_200),
        ("2024-02-29T12:00:00Z", 1_709_208_000),
        ("2038-01-19T03:14:07Z", 2_147_483_647),
        ("2100-03-01T00:00:00Z", 4_107_542_400),
        ("0000-01-01T00:00:00Z", -62_167_219_200),
        ("9999-12-31T23:59:59Z", 253_402_300_799),
    ] {
        assert_eq!(parse_offline_valid_through_v1(text), Ok(seconds), "{text}");
    }
    for text in [
        "0000-02-29T00:00:00Z",
        "2024-04-30T00:00:00Z",
        "2024-12-31T23:59:59Z",
    ] {
        assert!(parse_offline_valid_through_v1(text).is_ok(), "{text}");
    }
}

#[test]
fn offline_valid_through_rejects_every_non_profile_form() {
    for text in [
        "",
        "2030-01-01T00:00:00",
        "2030-01-01T00:00:00+00:00",
        "2030-01-01T00:00:00.0Z",
        "2030-01-01T00:00:00.000Z",
        "2030-01-01T00:00:00z",
        "2030-01-01t00:00:00Z",
        "2030-01-01 00:00:00Z",
        "2030-01-01T00:00:00ZZ",
        " 2030-01-01T00:00:00Z",
        "2030-01-01T00:00:00Z ",
        "2030/01/01T00:00:00Z",
        "2030-01-01T00-00-00Z",
        "2030-01-01T00:00:0éZ",
        "2030-01-01T00:00:0-Z",
        "2030-0a-01T00:00:00Z",
        "2030-01-0aT00:00:00Z",
        "2030-01-01Ta0:00:00Z",
        "2030-01-01T00:a0:00Z",
        "+030-01-01T00:00:00Z",
        "20300-1-01T00:00:00Z",
        "2030-00-01T00:00:00Z",
        "2030-13-01T00:00:00Z",
        "2030-01-00T00:00:00Z",
        "2030-01-32T00:00:00Z",
        "2030-04-31T00:00:00Z",
        "2023-02-29T00:00:00Z",
        "2100-02-29T00:00:00Z",
        "1900-02-29T00:00:00Z",
        "2024-02-30T00:00:00Z",
        "2030-01-01T24:00:00Z",
        "2030-01-01T00:60:00Z",
        "2030-01-01T23:59:60Z",
        "2016-12-31T23:59:60Z",
    ] {
        assert_eq!(
            parse_offline_valid_through_v1(text),
            Err(PluginTrustBridgeErrorV1::InvalidUtcFormat),
            "{text:?}"
        );
    }
}

#[test]
fn global_tps1_caps_hold_exactly_at_sixty_four_and_4096() {
    assert_eq!(check_plugin_tps1_global_caps_v1(0, 0, 0), Ok(()));
    assert_eq!(check_plugin_tps1_global_caps_v1(64, 4096, 4096), Ok(()));
    for (roots, keys, artifacts) in [(65, 0, 0), (0, 4097, 0), (0, 0, 4097), (65, 4097, 4097)] {
        assert_eq!(
            check_plugin_tps1_global_caps_v1(roots, keys, artifacts),
            Err(PluginTrustBridgeErrorV1::TpsCapExceeded)
        );
    }
    assert_eq!(check_plugin_tps1_global_caps_v1(64, 4095, 4095), Ok(()));
    assert_eq!(check_plugin_tps1_global_caps_v1(63, 4096, 0), Ok(()));
    assert_eq!(check_plugin_tps1_global_caps_v1(0, 4096, 4096), Ok(()));
}

const fn pair(coordinate: u64, fill: u8) -> Floor {
    (coordinate, [fill; 32])
}

fn transition(
    kind: PluginFloorKindV1,
    retained: Option<Floor>,
    candidate: Floor,
    history: &[Floor],
) -> Result<PluginFloorTransitionV1, PluginFloorErrorV1> {
    plugin_floor_transition_v1(kind, retained, candidate, history)
}

#[test]
fn floor_transition_initializes_unchanged_and_rejects_lower_or_forked_coordinates() {
    for kind in [PluginFloorKindV1::Root, PluginFloorKindV1::Revocation] {
        assert_eq!(
            transition(kind, None, pair(5, 1), &[]),
            Ok(PluginFloorTransitionV1::Initialize)
        );
        assert_eq!(
            transition(kind, Some(pair(5, 1)), pair(5, 1), &[]),
            Ok(PluginFloorTransitionV1::Unchanged)
        );
        assert_eq!(
            transition(
                kind,
                Some(pair(5, 1)),
                pair(5, 2),
                &[pair(4, 1), pair(5, 2)]
            ),
            Err(PluginFloorErrorV1::Fork(kind))
        );
        assert_eq!(
            transition(kind, Some(pair(5, 1)), pair(4, 1), &[pair(4, 1)]),
            Err(PluginFloorErrorV1::Rollback(kind))
        );
        assert_eq!(
            transition(kind, Some(pair(5, 1)), pair(1, 1), &[pair(1, 1)]),
            Err(PluginFloorErrorV1::Rollback(kind))
        );
        assert_eq!(
            transition(kind, Some(pair(1, 1)), pair(0, 9), &[]),
            Err(PluginFloorErrorV1::Rollback(kind))
        );
    }
}

#[test]
fn floor_transition_advances_only_with_exact_retained_pair_terminating_at_candidate() {
    for kind in [PluginFloorKindV1::Root, PluginFloorKindV1::Revocation] {
        let retained = Some(pair(2, 2));
        let advance = Ok(PluginFloorTransitionV1::Advance);
        assert_eq!(
            transition(
                kind,
                retained,
                pair(3, 3),
                &[pair(1, 1), pair(2, 2), pair(3, 3)]
            ),
            advance
        );
        assert_eq!(
            transition(kind, retained, pair(3, 3), &[pair(2, 2), pair(3, 3)]),
            advance
        );
        assert_eq!(
            transition(
                kind,
                retained,
                pair(9, 9),
                &[pair(1, 1), pair(2, 2), pair(5, 5), pair(9, 9)]
            ),
            advance
        );
        assert_eq!(
            transition(
                kind,
                retained,
                pair(3, 3),
                &[pair(1, 1), pair(2, 8), pair(3, 3)]
            ),
            Err(PluginFloorErrorV1::Fork(kind))
        );
        assert_eq!(
            transition(kind, retained, pair(3, 3), &[pair(1, 1), pair(3, 3)]),
            Err(PluginFloorErrorV1::Discontinuity(kind))
        );
        assert_eq!(
            transition(kind, retained, pair(3, 3), &[]),
            Err(PluginFloorErrorV1::Discontinuity(kind))
        );
        assert_eq!(
            transition(kind, retained, pair(3, 3), &[pair(2, 2)]),
            Err(PluginFloorErrorV1::Discontinuity(kind))
        );
        assert_eq!(
            transition(kind, retained, pair(3, 3), &[pair(2, 2), pair(3, 4)]),
            Err(PluginFloorErrorV1::Discontinuity(kind))
        );
        assert_eq!(
            transition(
                kind,
                retained,
                pair(3, 3),
                &[pair(2, 2), pair(3, 3), pair(4, 4)]
            ),
            Err(PluginFloorErrorV1::Discontinuity(kind))
        );
    }
}

#[test]
fn floor_transition_rejects_duplicate_and_reordered_membership_proofs() {
    for kind in [PluginFloorKindV1::Root, PluginFloorKindV1::Revocation] {
        let retained = Some(pair(2, 2));
        let discontinuity = Err(PluginFloorErrorV1::Discontinuity(kind));
        assert_eq!(
            transition(
                kind,
                retained,
                pair(3, 3),
                &[pair(2, 2), pair(2, 2), pair(3, 3)]
            ),
            discontinuity
        );
        assert_eq!(
            transition(
                kind,
                retained,
                pair(3, 3),
                &[pair(2, 2), pair(3, 3), pair(3, 3)]
            ),
            discontinuity
        );
        assert_eq!(
            transition(
                kind,
                retained,
                pair(3, 3),
                &[pair(3, 3), pair(2, 2), pair(3, 3)]
            ),
            discontinuity
        );
        assert_eq!(
            transition(
                kind,
                retained,
                pair(4, 4),
                &[pair(3, 3), pair(2, 2), pair(4, 4)]
            ),
            discontinuity
        );
        assert_eq!(
            transition(
                kind,
                retained,
                pair(3, 3),
                &[pair(2, 2), pair(2, 7), pair(3, 3)]
            ),
            discontinuity
        );
    }
}

#[test]
fn partial_floor_state_is_corrupt_and_both_or_neither_is_valid() {
    assert_eq!(
        PluginFloorStateV1::from_retained(None, None),
        Ok(PluginFloorStateV1::Absent)
    );
    assert_eq!(
        PluginFloorStateV1::from_retained(Some(pair(1, 1)), Some(pair(2, 2))),
        Ok(PluginFloorStateV1::Present {
            root: pair(1, 1),
            revocation: pair(2, 2)
        })
    );
    assert_eq!(
        PluginFloorStateV1::from_retained(Some(pair(1, 1)), None),
        Err(PluginFloorErrorV1::PartialFloorState)
    );
    assert_eq!(
        PluginFloorStateV1::from_retained(None, Some(pair(2, 2))),
        Err(PluginFloorErrorV1::PartialFloorState)
    );
}

fn unsigned(value: u64) -> Value {
    Value::Integer(value.into())
}

fn bytes_value(value: [u8; 32]) -> Value {
    Value::Bytes(value.to_vec())
}

fn encode(value: &Value) -> TestResult<Vec<u8>> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded)?;
    Ok(encoded)
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// ADR-103 root key ID, recomputed independently of the crate internals.
fn root_key_id(public: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros/plugin-root-key-id/v1\0");
    hasher.update(&public);
    *hasher.finalize().as_bytes()
}

fn root_signer() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn root_public() -> [u8; 32] {
    root_signer().verifying_key().to_bytes()
}

fn publisher_public() -> [u8; 32] {
    SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes()
}

fn other_publisher_public() -> [u8; 32] {
    SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes()
}

fn signed_record(mut fields: Vec<Value>, domain: &[u8]) -> TestResult<Vec<u8>> {
    let mut message = domain.to_vec();
    message.extend_from_slice(&encode(&Value::Array(fields.clone()))?);
    fields.push(Value::Array(vec![Value::Array(vec![
        bytes_value(root_key_id(root_public())),
        Value::Bytes(root_signer().sign(&message).to_bytes().to_vec()),
    ])]));
    encode(&Value::Array(fields))
}

/// A PTR1 for `scope`: `publisher` holds `plugin-a`; `other-a` is also a known key.
fn ptr1(version: u64, previous: Option<[u8; 32]>) -> TestResult<Vec<u8>> {
    let publisher = Value::Array(vec![
        Value::Text("publisher".to_owned()),
        unsigned(3),
        unsigned(1),
        bytes_value(publisher_public()),
    ]);
    let other = Value::Array(vec![
        Value::Text("other-a".to_owned()),
        unsigned(3),
        unsigned(1),
        bytes_value(other_publisher_public()),
    ]);
    let grant = Value::Array(vec![
        Value::Text("plugin-a".to_owned()),
        Value::Text("publisher".to_owned()),
    ]);
    signed_record(
        vec![
            Value::Text("PTR1".to_owned()),
            unsigned(1),
            Value::Text("scope".to_owned()),
            unsigned(version),
            unsigned(0),
            unsigned(100),
            previous.map_or(Value::Null, bytes_value),
            unsigned(1),
            Value::Array(vec![Value::Array(vec![
                bytes_value(root_key_id(root_public())),
                bytes_value(root_public()),
            ])]),
            Value::Array(vec![other, publisher]),
            Value::Array(vec![grant]),
        ],
        ROOT_SIGNATURE_DOMAIN,
    )
}

fn prv1(
    root_digest: [u8; 32],
    epoch: u64,
    previous: Option<[u8; 32]>,
    keys: Vec<Value>,
    artifacts: Vec<Value>,
) -> TestResult<Vec<u8>> {
    signed_record(
        vec![
            Value::Text("PRV1".to_owned()),
            unsigned(1),
            Value::Text("scope".to_owned()),
            unsigned(epoch),
            unsigned(0),
            unsigned(100),
            bytes_value(root_digest),
            previous.map_or(Value::Null, bytes_value),
            unsigned(EVALUATION_TICK),
            Value::Array(keys),
            Value::Array(artifacts),
        ],
        REVOCATION_SIGNATURE_DOMAIN,
    )
}

fn revoked_key(owner: &str, epoch: u64, public: [u8; 32]) -> Value {
    Value::Array(vec![
        Value::Text(owner.to_owned()),
        unsigned(3),
        unsigned(epoch),
        bytes_value(public),
        unsigned(EVALUATION_TICK),
        unsigned(1),
        Value::Null,
    ])
}

fn revoked_artifact(digest: [u8; 32]) -> Value {
    Value::Array(vec![
        bytes_value(digest),
        unsigned(EVALUATION_TICK),
        unsigned(1),
        Value::Null,
    ])
}

fn evidence_with(
    keys: Vec<Value>,
    artifacts: Vec<Value>,
) -> TestResult<VerifiedPluginTrustEvidenceV1> {
    let root = ptr1(1, None)?;
    let anchor = TrustedPluginRootAnchorV1::new("scope", digest(&root))?;
    let revocation = prv1(digest(&root), 1, None, keys, artifacts)?;
    Ok(verify_plugin_trust_v1(
        &anchor,
        &[&root],
        &[&revocation],
        EVALUATION_UTC,
        EVALUATION_TICK,
    )?)
}

struct ChainDigests {
    roots: [[u8; 32]; 2],
    revocations: [[u8; 32]; 2],
}

fn chain_evidence() -> TestResult<(VerifiedPluginTrustEvidenceV1, ChainDigests)> {
    let genesis_root = ptr1(1, None)?;
    let genesis_root_digest = digest(&genesis_root);
    let genesis_revocation = prv1(genesis_root_digest, 1, None, Vec::new(), Vec::new())?;
    let genesis_revocation_digest = digest(&genesis_revocation);
    let next_root = ptr1(2, Some(genesis_root_digest))?;
    let next_root_digest = digest(&next_root);
    let next_revocation = prv1(
        next_root_digest,
        2,
        Some(genesis_revocation_digest),
        Vec::new(),
        Vec::new(),
    )?;
    let anchor = TrustedPluginRootAnchorV1::new("scope", genesis_root_digest)?;
    let evidence = verify_plugin_trust_v1(
        &anchor,
        &[&genesis_root, &next_root],
        &[&genesis_revocation, &next_revocation],
        EVALUATION_UTC,
        EVALUATION_TICK,
    )?;
    Ok((
        evidence,
        ChainDigests {
            roots: [genesis_root_digest, next_root_digest],
            revocations: [genesis_revocation_digest, digest(&next_revocation)],
        },
    ))
}

fn plan(
    state: PluginFloorStateV1,
    evidence: &VerifiedPluginTrustEvidenceV1,
) -> Result<PluginFloorPlanV1, PluginFloorErrorV1> {
    plan_plugin_floor_transition_v1(&state, evidence)
}

#[test]
fn evidence_floor_plan_covers_first_equal_and_descendant_states() -> TestResult {
    let (evidence, chain) = chain_evidence()?;
    let initialize = PluginFloorTransitionV1::Initialize;
    assert_eq!(
        plan(PluginFloorStateV1::Absent, &evidence),
        Ok(PluginFloorPlanV1 {
            root: initialize,
            revocation: initialize
        })
    );
    let present = |root: Floor, revocation: Floor| PluginFloorStateV1::Present { root, revocation };
    assert_eq!(
        plan(
            present((2, chain.roots[1]), (2, chain.revocations[1])),
            &evidence
        ),
        Ok(PluginFloorPlanV1 {
            root: PluginFloorTransitionV1::Unchanged,
            revocation: PluginFloorTransitionV1::Unchanged
        })
    );
    assert_eq!(
        plan(
            present((1, chain.roots[0]), (1, chain.revocations[0])),
            &evidence
        ),
        Ok(PluginFloorPlanV1 {
            root: PluginFloorTransitionV1::Advance,
            revocation: PluginFloorTransitionV1::Advance
        })
    );
    assert_eq!(
        plan(
            present((2, chain.roots[1]), (1, chain.revocations[0])),
            &evidence
        ),
        Ok(PluginFloorPlanV1 {
            root: PluginFloorTransitionV1::Unchanged,
            revocation: PluginFloorTransitionV1::Advance
        })
    );
    Ok(())
}

#[test]
fn evidence_floor_plan_judges_root_and_revocation_independently() -> TestResult {
    let (evidence, chain) = chain_evidence()?;
    let present = |root: Floor, revocation: Floor| PluginFloorStateV1::Present { root, revocation };
    let good_root = (1, chain.roots[0]);
    let good_revocation = (1, chain.revocations[0]);
    assert_eq!(
        plan(present((1, [9; 32]), good_revocation), &evidence),
        Err(PluginFloorErrorV1::Fork(PluginFloorKindV1::Root))
    );
    assert_eq!(
        plan(present(good_root, (1, [9; 32])), &evidence),
        Err(PluginFloorErrorV1::Fork(PluginFloorKindV1::Revocation))
    );
    assert_eq!(
        plan(present((3, [9; 32]), good_revocation), &evidence),
        Err(PluginFloorErrorV1::Rollback(PluginFloorKindV1::Root))
    );
    assert_eq!(
        plan(present(good_root, (3, [9; 32])), &evidence),
        Err(PluginFloorErrorV1::Rollback(PluginFloorKindV1::Revocation))
    );
    assert_eq!(
        plan(present((0, [9; 32]), good_revocation), &evidence),
        Err(PluginFloorErrorV1::Discontinuity(PluginFloorKindV1::Root))
    );
    assert_eq!(
        plan(present(good_root, (0, [9; 32])), &evidence),
        Err(PluginFloorErrorV1::Discontinuity(
            PluginFloorKindV1::Revocation
        ))
    );
    assert_eq!(
        plan(present((3, [9; 32]), (1, [9; 32])), &evidence),
        Err(PluginFloorErrorV1::Rollback(PluginFloorKindV1::Root))
    );
    Ok(())
}

fn operator_anchor() -> TestResult<PluginTrustPolicyAnchorV1> {
    anchor_for("scope", operator_signer().verifying_key().to_bytes())
}

fn manifest(
    owner: &str,
    not_before: i64,
    not_after: i64,
) -> TestResult<ValidatedPluginManifestProjectionV1> {
    Ok(ValidatedPluginManifestProjectionV1::from(
        PluginManifestProjectionFixtureV1 {
            pmf1_digest: [0x11; 32],
            plugin_id: "plugin-a".to_owned(),
            owner: OwnerIdV1::new(owner)?,
            role: 3,
            epoch: 1,
            not_before,
            not_after,
            release_digest: [0x22; 32],
            previous_release_digest: None,
            descriptor_digests: vec![[0x30; 32], [0x33; 32]],
        },
    ))
}

fn good_manifest() -> TestResult<ValidatedPluginManifestProjectionV1> {
    manifest("publisher", 40, 60)
}

fn plugin_root_entry(version: u64, public: [u8; 32]) -> TrustPolicyRootV1 {
    TrustPolicyRootV1 {
        key_id: plugin_root_key_id_v1(root_key_id(root_public())),
        root_version: version,
        algorithm: "Ed25519".to_owned(),
        public_key: public,
    }
}

fn base_snapshot(revoked_key_ids: Vec<String>, artifacts: Vec<[u8; 32]>) -> TrustPolicySnapshotV1 {
    TrustPolicySnapshotV1 {
        policy_id: "scope".to_owned(),
        epoch: 1,
        effective_timeline_position: 9,
        trust_roots: vec![plugin_root_entry(1, root_public())],
        revoked_key_ids,
        revoked_artifact_digests: artifacts,
        minimum_versions: Vec::new(),
        offline_valid_through: "2030-01-01T00:00:00Z".to_owned(),
        previous_snapshot_digest: None,
        operator_signature: [0; 64],
    }
}

fn sign_with(mut snapshot: TrustPolicySnapshotV1, signer: &SigningKey) -> TestResult<Vec<u8>> {
    snapshot
        .trust_roots
        .sort_by(|left, right| left.key_id.cmp(&right.key_id));
    snapshot.revoked_key_ids.sort();
    snapshot.revoked_artifact_digests.sort_unstable();
    snapshot.operator_signature = signer
        .sign(&snapshot.operator_signature_message_v1()?)
        .to_bytes();
    Ok(snapshot.to_canonical_cbor()?)
}

fn sign(snapshot: TrustPolicySnapshotV1) -> TestResult<Vec<u8>> {
    sign_with(snapshot, &operator_signer())
}

fn authed(snapshot: TrustPolicySnapshotV1) -> TestResult<AuthenticatedPluginTps1V1> {
    Ok(authenticate_plugin_tps1_v1(
        &operator_anchor()?,
        &sign(snapshot)?,
    )?)
}

fn bridge(
    tps1: &[u8],
    evidence: &VerifiedPluginTrustEvidenceV1,
) -> TestResult<Result<(), PluginTrustBridgeErrorV1>> {
    Ok(
        authenticate_plugin_tps1_v1(&operator_anchor()?, tps1).and_then(|authenticated| {
            verify_plugin_tps1_policy_v1(&authenticated, evidence, EVALUATION_UTC, EVALUATION_TICK)
        }),
    )
}

fn other_revocation_evidence() -> TestResult<(VerifiedPluginTrustEvidenceV1, String)> {
    let evidence = evidence_with(
        vec![revoked_key("other-a", 1, other_publisher_public())],
        vec![revoked_artifact([0x77; 32])],
    )?;
    let owner = OwnerIdV1::new("other-a")?;
    Ok((
        evidence,
        plugin_revoked_key_id_v1(&owner, 1, other_publisher_public()),
    ))
}

#[test]
fn policy_bridge_accepts_exact_mapping_and_keeps_authenticated_facts() -> TestResult {
    let (evidence, revoked_id) = other_revocation_evidence()?;
    let mut snapshot = base_snapshot(vec![revoked_id], vec![[0x77; 32]]);
    snapshot.trust_roots.push(TrustPolicyRootV1 {
        key_id: "global.root".to_owned(),
        root_version: 4,
        algorithm: "Ed25519".to_owned(),
        public_key: [0x55; 32],
    });
    snapshot.revoked_key_ids.push("operator.revoked".to_owned());
    snapshot.revoked_artifact_digests.push([0x01; 32]);
    let tps1 = sign(snapshot)?;
    let authenticated = authenticate_plugin_tps1_v1(&operator_anchor()?, &tps1)?;
    assert_eq!(
        verify_plugin_tps1_policy_v1(&authenticated, &evidence, EVALUATION_UTC, EVALUATION_TICK),
        Ok(())
    );
    assert_eq!(authenticated.bytes(), tps1.as_slice());
    assert_eq!(authenticated.digest(), digest(&tps1));
    assert_eq!(authenticated.epoch(), 1);
    assert_eq!(authenticated.effective_timeline_position(), 9);
    Ok(())
}

#[test]
fn bridge_checks_scope_epoch_trusted_utc_and_operator_signature() -> TestResult {
    let evidence = evidence_with(Vec::new(), Vec::new())?;
    let good = base_snapshot(Vec::new(), Vec::new());
    assert_eq!(bridge(&sign(good.clone())?, &evidence)?, Ok(()));
    let foreign_operator = SigningKey::from_bytes(&[0x13; 32]);
    assert_eq!(
        bridge(&sign_with(good.clone(), &foreign_operator)?, &evidence)?,
        Err(PluginTrustBridgeErrorV1::InvalidOperatorSignature)
    );
    assert_eq!(
        bridge(&[0x80], &evidence)?,
        Err(PluginTrustBridgeErrorV1::InvalidSnapshot)
    );
    let mut wrong_policy = good.clone();
    "other".clone_into(&mut wrong_policy.policy_id);
    assert_eq!(
        bridge(&sign(wrong_policy)?, &evidence)?,
        Err(PluginTrustBridgeErrorV1::ScopeMismatch)
    );
    for epoch in [2, 3] {
        let mut wrong_epoch = good.clone();
        wrong_epoch.epoch = epoch;
        assert_eq!(
            bridge(&sign(wrong_epoch)?, &evidence)?,
            Err(PluginTrustBridgeErrorV1::EpochMismatch)
        );
    }
    let authenticated = authed(good)?;
    let run =
        |utc: i64, tick: u64| verify_plugin_tps1_policy_v1(&authenticated, &evidence, utc, tick);
    assert_eq!(run(50, 5), Ok(()));
    for utc in [49, 51] {
        assert_eq!(
            run(utc, 5),
            Err(PluginTrustBridgeErrorV1::EvaluationUtcMismatch)
        );
    }
    for tick in [4, 6] {
        assert_eq!(
            run(50, tick),
            Err(PluginTrustBridgeErrorV1::EvaluationTickMismatch)
        );
    }
    assert_eq!(
        run(51, 6),
        Err(PluginTrustBridgeErrorV1::EvaluationUtcMismatch)
    );
    Ok(())
}

#[test]
fn bridge_evidence_scope_must_equal_the_tps1_policy() -> TestResult {
    let evidence = evidence_with(Vec::new(), Vec::new())?;
    let other = anchor_for("other", operator_signer().verifying_key().to_bytes())?;
    let mut snapshot = base_snapshot(Vec::new(), Vec::new());
    "other".clone_into(&mut snapshot.policy_id);
    let authenticated = authenticate_plugin_tps1_v1(&other, &sign(snapshot)?)?;
    assert_eq!(
        verify_plugin_tps1_policy_v1(&authenticated, &evidence, EVALUATION_UTC, EVALUATION_TICK),
        Err(PluginTrustBridgeErrorV1::ScopeMismatch)
    );
    Ok(())
}

#[test]
fn bridge_requires_utc_strictly_before_offline_valid_through() -> TestResult {
    let evidence = evidence_with(Vec::new(), Vec::new())?;
    let with_expiry = |text: &str| {
        let mut snapshot = base_snapshot(Vec::new(), Vec::new());
        text.clone_into(&mut snapshot.offline_valid_through);
        snapshot
    };
    assert_eq!(
        bridge(&sign(with_expiry("1970-01-01T00:00:51Z"))?, &evidence)?,
        Ok(())
    );
    for text in [
        "1970-01-01T00:00:50Z",
        "1970-01-01T00:00:49Z",
        "1969-12-31T23:59:59Z",
    ] {
        assert_eq!(
            bridge(&sign(with_expiry(text))?, &evidence)?,
            Err(PluginTrustBridgeErrorV1::Expired),
            "{text}"
        );
    }
    for text in [
        "2030-01-01T00:00:00+00:00",
        "2030-01-01T00:00:00.5Z",
        "2030-02-30T00:00:00Z",
        "2016-12-31T23:59:60Z",
    ] {
        assert_eq!(
            bridge(&sign(with_expiry(text))?, &evidence)?,
            Err(PluginTrustBridgeErrorV1::InvalidUtcFormat),
            "{text}"
        );
    }
    Ok(())
}

#[test]
fn bridge_requires_exactly_the_terminal_ptr1_root_keys() -> TestResult {
    let evidence = evidence_with(Vec::new(), Vec::new())?;
    let mismatch = Err(PluginTrustBridgeErrorV1::BridgeRootMismatch);
    let mut wrong_version = base_snapshot(Vec::new(), Vec::new());
    wrong_version.trust_roots = vec![plugin_root_entry(2, root_public())];
    assert_eq!(bridge(&sign(wrong_version)?, &evidence)?, mismatch);
    let mut wrong_public = base_snapshot(Vec::new(), Vec::new());
    wrong_public.trust_roots = vec![plugin_root_entry(1, [0x66; 32])];
    assert_eq!(bridge(&sign(wrong_public)?, &evidence)?, mismatch);
    let mut missing = base_snapshot(Vec::new(), Vec::new());
    missing.trust_roots = vec![TrustPolicyRootV1 {
        key_id: "global.root".to_owned(),
        root_version: 1,
        algorithm: "Ed25519".to_owned(),
        public_key: [0x55; 32],
    }];
    assert_eq!(bridge(&sign(missing)?, &evidence)?, mismatch);
    Ok(())
}

#[test]
fn bridge_rejects_unrelated_ptr1_prefixed_roots_and_keeps_other_roots() -> TestResult {
    let evidence = evidence_with(Vec::new(), Vec::new())?;
    for key_id in [
        plugin_root_key_id_v1([0x99; 32]),
        format!("ptr1-{}", "ab".repeat(31)),
        "ptr1-".to_owned(),
    ] {
        let mut extra = base_snapshot(Vec::new(), Vec::new());
        extra.trust_roots.push(TrustPolicyRootV1 {
            key_id,
            root_version: 1,
            algorithm: "Ed25519".to_owned(),
            public_key: [0x55; 32],
        });
        assert_eq!(
            bridge(&sign(extra)?, &evidence)?,
            Err(PluginTrustBridgeErrorV1::ReservedPrefix)
        );
    }
    let mut coexisting = base_snapshot(Vec::new(), Vec::new());
    for (key_id, fill) in [("ptr1", 0x51), ("ptr1.root", 0x52), ("pkr1-root", 0x53)] {
        coexisting.trust_roots.push(TrustPolicyRootV1 {
            key_id: key_id.to_owned(),
            root_version: 7,
            algorithm: "Ed25519".to_owned(),
            public_key: [fill; 32],
        });
    }
    assert_eq!(bridge(&sign(coexisting)?, &evidence)?, Ok(()));
    Ok(())
}

#[test]
fn bridge_requires_exactly_the_effective_prv1_key_denials() -> TestResult {
    let (evidence, revoked_id) = other_revocation_evidence()?;
    let artifacts = vec![[0x77; 32]];
    let missing = base_snapshot(Vec::new(), artifacts.clone());
    assert_eq!(
        bridge(&sign(missing)?, &evidence)?,
        Err(PluginTrustBridgeErrorV1::BridgeRevocationMismatch)
    );
    let owner = OwnerIdV1::new("other-a")?;
    let wrong_epoch = plugin_revoked_key_id_v1(&owner, 2, other_publisher_public());
    let wrong_key = plugin_revoked_key_id_v1(&owner, 1, publisher_public());
    let foreign =
        plugin_revoked_key_id_v1(&OwnerIdV1::new("other-b")?, 1, other_publisher_public());
    for wrong in [
        wrong_epoch,
        wrong_key,
        foreign,
        format!("pkr1-{}", "ab".repeat(31)),
    ] {
        let substituted = base_snapshot(vec![wrong.clone()], artifacts.clone());
        assert_eq!(
            bridge(&sign(substituted)?, &evidence)?,
            Err(PluginTrustBridgeErrorV1::ReservedPrefix)
        );
        let extra = base_snapshot(vec![revoked_id.clone(), wrong], artifacts.clone());
        assert_eq!(
            bridge(&sign(extra)?, &evidence)?,
            Err(PluginTrustBridgeErrorV1::ReservedPrefix)
        );
    }
    let exact = base_snapshot(vec![revoked_id], artifacts);
    assert_eq!(bridge(&sign(exact)?, &evidence)?, Ok(()));
    Ok(())
}

#[test]
fn bridge_denies_a_tps1_without_an_unrequested_foreign_key_denial() -> TestResult {
    let evidence = evidence_with(Vec::new(), Vec::new())?;
    let foreign =
        plugin_revoked_key_id_v1(&OwnerIdV1::new("other-a")?, 1, other_publisher_public());
    let denied = base_snapshot(vec![foreign], Vec::new());
    assert_eq!(
        bridge(&sign(denied)?, &evidence)?,
        Err(PluginTrustBridgeErrorV1::ReservedPrefix)
    );
    let unrelated = base_snapshot(
        vec!["pkr1".to_owned(), "pkr1.x".to_owned(), "ptr1-x".to_owned()],
        Vec::new(),
    );
    assert_eq!(bridge(&sign(unrelated)?, &evidence)?, Ok(()));
    Ok(())
}

#[test]
fn bridge_requires_every_effective_prv1_artifact_denial() -> TestResult {
    let (evidence, revoked_id) = other_revocation_evidence()?;
    let missing = base_snapshot(vec![revoked_id.clone()], Vec::new());
    assert_eq!(
        bridge(&sign(missing)?, &evidence)?,
        Err(PluginTrustBridgeErrorV1::BridgeRevocationMismatch)
    );
    let wrong = base_snapshot(vec![revoked_id.clone()], vec![[0x78; 32]]);
    assert_eq!(
        bridge(&sign(wrong)?, &evidence)?,
        Err(PluginTrustBridgeErrorV1::BridgeRevocationMismatch)
    );
    let superset = base_snapshot(vec![revoked_id], vec![[0x01; 32], [0x77; 32], [0xee; 32]]);
    assert_eq!(bridge(&sign(superset)?, &evidence)?, Ok(()));
    Ok(())
}

#[test]
fn policy_bridge_error_precedence_matches_the_documented_order() -> TestResult {
    let (evidence, revoked_id) = other_revocation_evidence()?;
    let policy = |snapshot: TrustPolicySnapshotV1, utc: i64, tick: u64| -> TestResult<_> {
        let authenticated = authed(snapshot)?;
        Ok(verify_plugin_tps1_policy_v1(
            &authenticated,
            &evidence,
            utc,
            tick,
        ))
    };
    let mapped = || base_snapshot(vec![revoked_id.clone()], vec![[0x77; 32]]);
    assert_eq!(policy(mapped(), 50, 5)?, Ok(()));
    let wrong_root = |mut snapshot: TrustPolicySnapshotV1| {
        snapshot.trust_roots = vec![plugin_root_entry(2, root_public())];
        snapshot
    };
    let mut other_scope = mapped();
    "other".clone_into(&mut other_scope.policy_id);
    let other = anchor_for("other", operator_signer().verifying_key().to_bytes())?;
    let authenticated = authenticate_plugin_tps1_v1(&other, &sign(wrong_epoch(other_scope))?)?;
    assert_eq!(
        verify_plugin_tps1_policy_v1(&authenticated, &evidence, 51, 6),
        Err(PluginTrustBridgeErrorV1::ScopeMismatch)
    );
    assert_eq!(
        policy(wrong_epoch(mapped()), 51, 6)?,
        Err(PluginTrustBridgeErrorV1::EpochMismatch)
    );
    let expired = |mut snapshot: TrustPolicySnapshotV1| {
        "1970-01-01T00:00:50Z".clone_into(&mut snapshot.offline_valid_through);
        snapshot
    };
    assert_eq!(
        policy(expired(mapped()), 50, 6)?,
        Err(PluginTrustBridgeErrorV1::EvaluationTickMismatch)
    );
    assert_eq!(
        policy(wrong_root(expired(mapped())), 50, 5)?,
        Err(PluginTrustBridgeErrorV1::Expired)
    );
    let mut bad_format = wrong_root(mapped());
    "2030-02-30T00:00:00Z".clone_into(&mut bad_format.offline_valid_through);
    assert_eq!(
        policy(bad_format, 50, 5)?,
        Err(PluginTrustBridgeErrorV1::InvalidUtcFormat)
    );
    let mut roots_and_keys = base_snapshot(Vec::new(), Vec::new());
    roots_and_keys.trust_roots = vec![plugin_root_entry(2, root_public())];
    assert_eq!(
        policy(roots_and_keys, 50, 5)?,
        Err(PluginTrustBridgeErrorV1::BridgeRootMismatch)
    );
    let foreign =
        plugin_revoked_key_id_v1(&OwnerIdV1::new("other-b")?, 1, other_publisher_public());
    assert_eq!(
        policy(base_snapshot(vec![foreign], Vec::new()), 50, 5)?,
        Err(PluginTrustBridgeErrorV1::ReservedPrefix)
    );
    assert_eq!(
        policy(base_snapshot(vec![revoked_id.clone()], Vec::new()), 50, 5)?,
        Err(PluginTrustBridgeErrorV1::BridgeRevocationMismatch)
    );
    let mut extra_root = mapped();
    extra_root.trust_roots = vec![TrustPolicyRootV1 {
        key_id: plugin_root_key_id_v1([0x99; 32]),
        root_version: 1,
        algorithm: "Ed25519".to_owned(),
        public_key: [0x55; 32],
    }];
    assert_eq!(
        policy(extra_root, 50, 5)?,
        Err(PluginTrustBridgeErrorV1::ReservedPrefix)
    );
    Ok(())
}

const fn wrong_epoch(mut snapshot: TrustPolicySnapshotV1) -> TrustPolicySnapshotV1 {
    snapshot.epoch = 2;
    snapshot
}

#[test]
fn policy_bridge_is_release_independent_for_a_revoked_publisher() -> TestResult {
    let evidence = evidence_with(
        vec![revoked_key("publisher", 1, publisher_public())],
        Vec::new(),
    )?;
    let revoked_id = plugin_revoked_key_id_v1(&OwnerIdV1::new("publisher")?, 1, publisher_public());
    let tps1 = sign(base_snapshot(vec![revoked_id], Vec::new()))?;
    assert_eq!(bridge(&tps1, &evidence)?, Ok(()));
    assert_eq!(
        evidence.authorize_release(&good_manifest()?).map(|_| ()),
        Err(PluginTrustErrorV1::PublisherKeyRevoked)
    );
    Ok(())
}

#[test]
fn artifact_denial_check_rejects_every_release_digest_the_tps1_lists() -> TestResult {
    let evidence = evidence_with(Vec::new(), Vec::new())?;
    let authorization = evidence.authorize_release(&good_manifest()?)?;
    let denied = Err(PluginTrustBridgeErrorV1::TpsArtifactDenied);
    for digest in [[0x11; 32], [0x22; 32], [0x30; 32], [0x33; 32]] {
        let tps1 = authed(base_snapshot(
            Vec::new(),
            vec![[0x01; 32], digest, [0xee; 32]],
        ))?;
        assert_eq!(
            check_plugin_tps1_artifact_denial_v1(&tps1, &authorization),
            denied
        );
    }
    for allowed in [
        Vec::new(),
        vec![[0x44; 32]],
        vec![[0x10; 32], [0x31; 32], [0xff; 32]],
    ] {
        let tps1 = authed(base_snapshot(Vec::new(), allowed))?;
        assert_eq!(
            check_plugin_tps1_artifact_denial_v1(&tps1, &authorization),
            Ok(())
        );
    }
    Ok(())
}

fn successor_snapshot(epoch: u64, previous: Option<[u8; 32]>) -> TrustPolicySnapshotV1 {
    let mut snapshot = base_snapshot(Vec::new(), Vec::new());
    snapshot.epoch = epoch;
    snapshot.previous_snapshot_digest = previous;
    snapshot
}

#[test]
fn genesis_check_requires_epoch_one_null_predecessor_and_pinned_digest() -> TestResult {
    let operator = operator_signer().verifying_key().to_bytes();
    let genesis = authed(successor_snapshot(1, None))?;
    let pinned = |digest: [u8; 32]| {
        PluginTrustPolicyAnchorV1::new("scope", [1; 32], operator, PLUGIN_OPERATOR_ROLE_V1, digest)
    };
    assert_eq!(
        check_plugin_tps1_genesis_v1(&pinned(genesis.digest())?, &genesis),
        Ok(())
    );
    let invalid = Err(PluginTrustBridgeErrorV1::InvalidGenesis);
    let mut other_digest = genesis.digest();
    other_digest[31] ^= 1;
    assert_eq!(
        check_plugin_tps1_genesis_v1(&pinned(other_digest)?, &genesis),
        invalid
    );
    for later in [
        successor_snapshot(2, None),
        successor_snapshot(1, Some([0x22; 32])),
        successor_snapshot(2, Some(genesis.digest())),
    ] {
        let later = authed(later)?;
        assert_eq!(
            check_plugin_tps1_genesis_v1(&pinned(later.digest())?, &later),
            invalid
        );
    }
    Ok(())
}

#[test]
fn successor_check_requires_greater_epoch_and_the_exact_predecessor() -> TestResult {
    let retained = authed(successor_snapshot(3, None))?;
    let check = |candidate: TrustPolicySnapshotV1| -> TestResult<_> {
        Ok(check_plugin_tps1_successor_v1(
            3,
            retained.digest(),
            &authed(candidate)?,
        ))
    };
    let previous = Some(retained.digest());
    assert_eq!(check(successor_snapshot(4, previous))?, Ok(()));
    assert_eq!(check(successor_snapshot(9, previous))?, Ok(()));
    let stale = Err(PluginTrustBridgeErrorV1::StaleSnapshot);
    assert_eq!(check(successor_snapshot(3, previous))?, stale);
    assert_eq!(check(successor_snapshot(2, previous))?, stale);
    assert_eq!(check(successor_snapshot(3, Some([0x22; 32])))?, stale);
    let discontinuity = Err(PluginTrustBridgeErrorV1::SnapshotDiscontinuity);
    assert_eq!(check(successor_snapshot(4, None))?, discontinuity);
    assert_eq!(
        check(successor_snapshot(4, Some([0x22; 32])))?,
        discontinuity
    );
    let mut off_by_one = retained.digest();
    off_by_one[0] ^= 1;
    assert_eq!(
        check(successor_snapshot(4, Some(off_by_one)))?,
        discontinuity
    );
    Ok(())
}

#[test]
fn bridge_error_messages_are_stable_and_secret_free() {
    assert_eq!(
        PluginTrustBridgeErrorV1::BridgeRootMismatch.to_string(),
        "TPS1 trust roots differ from the terminal PTR1 root keys"
    );
    assert_eq!(
        PluginTrustBridgeErrorV1::EvaluationTickMismatch.to_string(),
        "evidence Tick differs from the trusted Tick"
    );
    assert_eq!(
        PluginTrustBridgeErrorV1::TpsArtifactDenied.to_string(),
        "TPS1 denies the release artifact"
    );
    assert_eq!(
        PluginFloorErrorV1::Rollback(PluginFloorKindV1::Root).to_string(),
        "PTR1 candidate is below the retained floor"
    );
}
