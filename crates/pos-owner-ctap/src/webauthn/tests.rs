use super::{
    base64url, client_data_json, created, hmac_secret_output, none_attestation, prf_salt, Created,
};
use crate::cbor::{decode, Value, Writer};
use crate::vectors::{array32, vector};

const SALTS: &str = include_str!("../../tests/vectors/prf-salt.txt");

fn counting() -> [u8; 32] {
    std::array::from_fn(|index| u8::try_from(index).unwrap_or(0))
}

#[test]
fn base64url_is_unpadded_and_url_safe() {
    assert_eq!(base64url(&[]), "");
    assert_eq!(base64url(&[0xfb]), "-w");
    assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
    assert_eq!(base64url(&[0xfb, 0xff, 0xbf]), "-_-_");
    assert_eq!(
        base64url(&counting()),
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    );
}

#[test]
fn client_data_json_is_the_browser_shape_for_the_owner_origin() {
    let json = client_data_json("webauthn.get", &counting());
    assert_eq!(
        json,
        b"{\"type\":\"webauthn.get\",\"challenge\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\",\
          \"origin\":\"http://localhost:49291\",\"crossOrigin\":false}"
    );
}

#[test]
fn the_prf_salt_matches_the_adr_golden_vectors() {
    assert_eq!(prf_salt(&[0; 32]).to_vec(), vector(SALTS, "zero"));
    assert_eq!(prf_salt(&counting()).to_vec(), vector(SALTS, "counting"));
    assert_eq!(array32(&vector(SALTS, "counting")), prf_salt(&counting()));
}

#[test]
fn the_attestation_is_rewritten_to_none_around_the_unchanged_auth_data() {
    let auth_data = [0x11; 40];
    let attestation = none_attestation(&auth_data);
    assert_eq!(attestation[..25], *b"\xa3cfmtdnonegattStmt\xa0hauthD");
    let value = decode(&attestation);
    let expected = Value::Map(vec![
        (Value::Text("fmt"), Value::Text("none")),
        (Value::Text("attStmt"), Value::Map(Vec::new())),
        (Value::Text("authData"), Value::Bytes(&auth_data)),
    ]);
    assert_eq!(value, Some(expected));
}

/// Create authenticator data: flags, a 4-byte credential ID, a key item and `tail`.
fn create_data(flags: u8, tail: &[u8]) -> Vec<u8> {
    let mut data = vec![0x22; 32];
    data.push(flags);
    data.extend_from_slice(&[0; 4]);
    data.extend_from_slice(&[0x33; 16]);
    data.extend_from_slice(&[0, 4, 9, 8, 7, 6]);
    data.extend_from_slice(&Writer::default().map(1).unsigned(1).unsigned(2).finish());
    data.extend_from_slice(tail);
    data
}

fn hmac_flag(value: bool) -> Vec<u8> {
    Writer::default()
        .map(1)
        .text("hmac-secret")
        .boolean(value)
        .finish()
}

#[test]
fn created_reads_the_credential_and_the_hmac_secret_flag() {
    let with = create_data(0xc5, &hmac_flag(true));
    let expected = Created {
        credential_id: &[9, 8, 7, 6],
        hmac_secret: true,
    };
    assert_eq!(created(&with), Some(expected));
    let off = create_data(0xc5, &hmac_flag(false));
    assert_eq!(
        created(&off).map(|created| created.hmac_secret),
        Some(false)
    );
    let none = create_data(0x45, &[]);
    assert_eq!(
        created(&none).map(|created| created.hmac_secret),
        Some(false)
    );
}

#[test]
fn created_refuses_malformed_create_data() {
    let mut truncated_id = create_data(0xc5, &hmac_flag(true));
    truncated_id.truncate(57);
    let mut no_key = create_data(0x45, &[]);
    no_key.truncate(59);
    let mut short = vec![0x22; 40];
    short[32] = 0x45;
    let refused = [
        create_data(0x85, &hmac_flag(true)),
        short,
        truncated_id,
        no_key,
        create_data(0x45, &[0x00]),
        create_data(0xc5, &[0xa1]),
        create_data(0xc5, &[0x80]),
    ];
    for data in refused {
        assert_eq!(created(&data), None, "{data:?}");
    }
}

fn get_data(flags: u8, extensions: &[u8]) -> Vec<u8> {
    let mut data = vec![0x22; 32];
    data.push(flags);
    data.extend_from_slice(&[0, 0, 0, 1]);
    data.extend_from_slice(extensions);
    data
}

fn hmac_output(length: usize) -> Vec<u8> {
    Writer::default()
        .map(1)
        .text("hmac-secret")
        .bytes(&vec![0x44; length])
        .finish()
}

#[test]
fn the_hmac_secret_output_must_be_exactly_48_bytes() {
    let honest = get_data(0x85, &hmac_output(48));
    assert_eq!(hmac_secret_output(&honest).map(<[u8]>::len), Some(48));
    let mut short_get = vec![0x22; 34];
    short_get[32] = 0x85;
    let refused = [
        get_data(0x85, &hmac_output(47)),
        get_data(0x85, &hmac_output(49)),
        get_data(0x05, &[]),
        get_data(0xc5, &hmac_output(48)),
        get_data(0x85, &hmac_flag(true)),
        vec![0x22; 32],
        short_get,
    ];
    for data in refused {
        assert_eq!(hmac_secret_output(&data), None, "{data:?}");
    }
}
