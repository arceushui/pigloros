//! ADR-091 and ADR-097 revision 3 (sections 1, 2 and 6) subject key wrap and
//! subject ciphertext vectors at the public `pos-crypto` seam.
//!
//! Every expected byte string is copied from the accepted ADR text. The
//! values were also recalculated outside this crate (Python `cryptography`
//! AES-GCM, standard-library HMAC-SHA-256 HKDF, and a reference BLAKE3) before
//! they were pinned here. The test-side CBOR builders below construct
//! tampered records independently of the crate's encoder.

use aes_gcm::{AeadInOut, Aes256Gcm, KeyInit};
use pos_core::{
    CorrelationId, EntityId, EventId, KeyIdentityV1, KeyRoleV1, Kind, Seq,
    TimelineEventEnvelopeInputV1, TimelineId, WallTime,
};
use pos_crypto::subject_ciphertext::{
    SubjectCiphertextErrorV1, SubjectCiphertextV1, MAX_SUBJECT_CIPHERTEXT_BYTES,
    MAX_SUBJECT_EVENT_TYPE_BYTES, MAX_SUBJECT_FIELD_TAG_BYTES, MAX_SUBJECT_NONCE_COUNTER,
    MAX_SUBJECT_PUBLIC_HEADER_BYTES,
};
use pos_crypto::subject_key::{
    parse_subject_owner_id, subject_owner_id, SubjectKeyUseV1, SubjectKeyWrapErrorV1,
    SubjectKeyWrapParamsV1, SubjectKeyWrapV1, SubjectPrfOutputV1, SubjectRootKeyV1,
    SubjectSubkeyV1, MAX_SUBJECT_CREDENTIAL_ID_BYTES, MAX_SUBJECT_RP_ID_BYTES, SUBJECT_OWNER_BYTES,
    SUBJECT_OWNER_PREFIX,
};
use ulid::Ulid;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const OWNER: &str = "subject:000102030405060708090a0b0c0d0e0f";
const ROOT_DIGEST: &str = "8d2240c535d51bcf87b2fcf6e4904fbb991837544c824c3df1f6b14056ea8519";
const WRAP_CONTEXT: &str = concat!(
    "8578287375626a6563743a30303031303230333034303530363037303830393061",
    "3062306330643065306650000102030405060708090a0b0c0d0e0f01696c6f6361",
    "6c686f737450808182838485868788898a8b8c8d8e8f",
);
const WRAPPING_KEY: &str = "275c27ff1e6b20c76ba16e48dbabf782fcf437fbd2e028353b1797d41c01e1cf";
const WRAP_AAD: &str = concat!(
    "8c44534b57310178287375626a6563743a3030303130323033303430353036303730",
    "38303930613062306330643065306650000102030405060708090a0b0c0d0e0f00",
    "01696c6f63616c686f737450808182838485868788898a8b8c8d8e8f5820a0a1a2",
    "a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf58206061",
    "62636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f582020",
    "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4c00",
    "0000000000000000000001",
);
const WRAPPED_ROOT: &str = concat!(
    "56a500174a1e82e1e96f5686fe7e0d0282744540fddd7e04f3131fb12d1e9141",
    "4402202e9f6935e82dbc0bd2b51a232a",
);
const WRAP: &str = concat!(
    "8d44534b57310178287375626a6563743a3030303130323033303430353036303730",
    "38303930613062306330643065306650000102030405060708090a0b0c0d0e0f00",
    "01696c6f63616c686f737450808182838485868788898a8b8c8d8e8f5820a0a1a2",
    "a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf58206061",
    "62636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f582020",
    "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4c00",
    "0000000000000000000001583056a500174a1e82e1e96f5686fe7e0d0282744540",
    "fddd7e04f3131fb12d1e91414402202e9f6935e82dbc0bd2b51a232a",
);
const DATA_SUBKEY: &str = "9e01bb5508562e85a6f7110c3715bd0097d5d9fddd7e52d6ace6dc0fb37d4242";
const BOOTSTRAP_SUBKEY: &str = "99f6862c0d986de31d7cdc4e48d5ad0e1a8282d3904dc16dfeaf2e7f3476f64c";

const CONSENT_HEADER: &str = concat!(
    "8b44434756320250000102030405060708090a0b0c0d0e0f50101112131415161718",
    "191a1b1c1d1e1f0101f4f4000001",
);
const CONSENT_DIGEST: &str = "513dd9edf3114e25d2d84b53ab30c0bb572d15ecd39d483b0aaed14fbf575612";
const CONSENT_SEALED: &str = "ce7d381b6e54d7843023c0999e3b55b3f78a0ad82f";
const CONSENT_CIPHERTEXT: &str = concat!(
    "9044534443310178287375626a6563743a3030303130323033303430353036303730",
    "38303930613062306330643065306650000102030405060708090a0b0c0d0e0f00",
    "010150202122232425262728292a2b2c2d2e2f0150303132333435363738393a3b",
    "3c3d3e3f72636f6e73656e742e6772616e7465642e76320167707572706f736558",
    "20513dd9edf3114e25d2d84b53ab30c0bb572d15ecd39d483b0aaed14fbf575612",
    "4c00000000000000000000000155ce7d381b6e54d7843023c0999e3b55b3f78a0a",
    "d82f",
);
const CONSENT_AAD: &str = concat!(
    "8f44534443310178287375626a6563743a3030303130323033303430353036303730",
    "38303930613062306330643065306650000102030405060708090a0b0c0d0e0f00",
    "010150202122232425262728292a2b2c2d2e2f0150303132333435363738393a3b",
    "3c3d3e3f72636f6e73656e742e6772616e7465642e76320167707572706f736558",
    "20513dd9edf3114e25d2d84b53ab30c0bb572d15ecd39d483b0aaed14fbf575612",
    "4c000000000000000000000001",
);
const FIELD_HEADER: &str = "8444534450310150000102030405060708090a0b0c0d0e0f6576616c7565";
const FIELD_DIGEST: &str = "e6bf4f8e52a32b8dde63271248768be2856d3419f22fbf0e8c9092ad6ed0434f";
const FIELD_SEALED: &str = "f44051b705eb62c2ab8bde18321611bf094f6d";
const FIELD_CIPHERTEXT: &str = concat!(
    "9044534443310178287375626a6563743a3030303130323033303430353036303730",
    "38303930613062306330643065306650000102030405060708090a0b0c0d0e0f00",
    "010050202122232425262728292a2b2c2d2e2f0250404142434445464748494a4b",
    "4c4d4e4f6f7375626a6563742e646174612e7631016576616c75655820e6bf4f8e",
    "52a32b8dde63271248768be2856d3419f22fbf0e8c9092ad6ed0434f4c00000000",
    "000000000000000153f44051b705eb62c2ab8bde18321611bf094f6d",
);
const FIELD_AAD: &str = concat!(
    "8f44534443310178287375626a6563743a3030303130323033303430353036303730",
    "38303930613062306330643065306650000102030405060708090a0b0c0d0e0f00",
    "010050202122232425262728292a2b2c2d2e2f0250404142434445464748494a4b",
    "4c4d4e4f6f7375626a6563742e646174612e7631016576616c75655820e6bf4f8e",
    "52a32b8dde63271248768be2856d3419f22fbf0e8c9092ad6ed0434f4c00000000",
    "0000000000000001",
);
/// The consent purpose `"demo"` as a canonical CBOR text string.
const CONSENT_PLAINTEXT: &[u8] = b"\x64demo";
/// The subject field value: the CBOR byte string `h'0102'`.
const FIELD_PLAINTEXT: &[u8] = b"\x42\x01\x02";

// ---------------------------------------------------------------------------
// Test-side helpers: hex, byte ranges, an independent CBOR builder, fixtures.
// ---------------------------------------------------------------------------

fn hex(text: &str) -> Vec<u8> {
    let nibble = |digit: u8| {
        if digit.is_ascii_digit() {
            digit - b'0'
        } else {
            digit - b'a' + 10
        }
    };
    text.as_bytes()
        .chunks(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

fn fixed<const N: usize>(bytes: &[u8]) -> [u8; N] {
    std::array::from_fn(|index| bytes[index])
}

/// `N` ascending bytes starting at `start`.
fn ascending<const N: usize>(start: u8) -> [u8; N] {
    let mut out = [0; N];
    let mut value = start;
    for byte in &mut out {
        *byte = value;
        value = value.wrapping_add(1);
    }
    out
}

fn head(major: u8, value: u64) -> Vec<u8> {
    let tag = major << 5;
    let bytes = value.to_be_bytes();
    match value {
        0..=23 => vec![tag | bytes[7]],
        24..=0xff => vec![tag | 0x18, bytes[7]],
        0x100..=0xffff => [&[tag | 0x19][..], &bytes[6..]].concat(),
        0x1_0000..=0xffff_ffff => [&[tag | 0x1a][..], &bytes[4..]].concat(),
        _ => [&[tag | 0x1b][..], &bytes[..]].concat(),
    }
}

fn uint(value: u64) -> Vec<u8> {
    head(0, value)
}

fn bstr(bytes: &[u8]) -> Vec<u8> {
    [head(2, bytes.len() as u64), bytes.to_vec()].concat()
}

fn tstr(text: &str) -> Vec<u8> {
    [head(3, text.len() as u64), text.as_bytes().to_vec()].concat()
}

fn array(items: &[Vec<u8>]) -> Vec<u8> {
    [head(4, items.len() as u64), items.concat()].concat()
}

fn with_item(items: &[Vec<u8>], ordinal: usize, item: Vec<u8>) -> Vec<u8> {
    let mut items = items.to_vec();
    items[ordinal] = item;
    array(&items)
}

const fn entity(bytes: [u8; 16]) -> EntityId {
    EntityId::from_ulid(Ulid::from_bytes(bytes))
}

fn subject() -> EntityId {
    entity(ascending(0))
}

fn event_id(start: u8) -> EventId {
    EventId::from_ulid(Ulid::from_bytes(ascending(start)))
}

fn integrity(owner: &'static str, role: KeyRoleV1, epoch: u64) -> KeyIdentityV1 {
    KeyIdentityV1::new(owner, role, epoch)
}

fn root() -> SubjectRootKeyV1 {
    SubjectRootKeyV1::from_bytes(ascending(0))
}

fn prf() -> SubjectPrfOutputV1 {
    SubjectPrfOutputV1::from_bytes(ascending(0x40))
}

fn params() -> SubjectKeyWrapParamsV1 {
    SubjectKeyWrapParamsV1 {
        subject_id: subject(),
        epoch: 1,
        rp_id: "localhost".to_owned(),
        credential_id: ascending::<16>(0x80).to_vec(),
        prf_input: ascending(0xa0),
        wrap_salt: ascending(0x60),
        subkey_salt: ascending(0x20),
        wrap_nonce: fixed(&hex("000000000000000000000001")),
    }
}

/// The golden wrap inputs after `edit`.
fn params_with(edit: impl FnOnce(&mut SubjectKeyWrapParamsV1)) -> SubjectKeyWrapParamsV1 {
    let mut params = params();
    edit(&mut params);
    params
}

/// The golden root and PRF sealed over the golden inputs after `edit`.
fn seal_with(
    edit: impl FnOnce(&mut SubjectKeyWrapParamsV1),
) -> Result<SubjectKeyWrapV1, SubjectKeyWrapErrorV1> {
    SubjectKeyWrapV1::seal(params_with(edit), &root(), &prf())
}

/// The golden wrap, sealed through the public API.
fn golden_wrap() -> Result<SubjectKeyWrapV1, SubjectKeyWrapErrorV1> {
    seal_with(|_| ())
}

/// The fingerprint of the root that `wrap` releases to `prf`.
fn opened(
    wrap: &SubjectKeyWrapV1,
    prf: &SubjectPrfOutputV1,
) -> Result<pos_core::Hash, SubjectKeyWrapErrorV1> {
    wrap.open(prf).map(|root| root.material_digest())
}

/// The SKW1 record `bytes` with its wrapped root replaced by `wrapped_root`.
fn transplanted(
    bytes: &[u8],
    wrapped_root: &[u8],
) -> Result<SubjectKeyWrapV1, SubjectKeyWrapErrorV1> {
    let mut bytes = bytes.to_vec();
    let start = bytes.len() - 48;
    bytes[start..].copy_from_slice(wrapped_root);
    SubjectKeyWrapV1::from_bytes(&bytes)
}

/// The 13 golden SKW1 items, built from the ADR inputs alone.
fn wrap_items() -> Vec<Vec<u8>> {
    vec![
        bstr(b"SKW1"),
        uint(1),
        tstr(OWNER),
        bstr(&ascending::<16>(0)),
        uint(0),
        uint(1),
        tstr("localhost"),
        bstr(&ascending::<16>(0x80)),
        bstr(&ascending::<32>(0xa0)),
        bstr(&ascending::<32>(0x60)),
        bstr(&ascending::<32>(0x20)),
        bstr(&hex("000000000000000000000001")),
        bstr(&hex(WRAPPED_ROOT)),
    ]
}

/// The golden root's subkey for `key_use`, unwrapped from the golden wrap.
fn golden_subkey(key_use: SubjectKeyUseV1) -> Result<SubjectSubkeyV1, SubjectKeyWrapErrorV1> {
    let wrap = SubjectKeyWrapV1::from_bytes(&hex(WRAP))?;
    let root = wrap.open(&prf())?;
    wrap.derive_subkey(&root, key_use)
}

fn event(event_start: u8, seq: u64, event_type: &str) -> TimelineEventEnvelopeInputV1 {
    TimelineEventEnvelopeInputV1 {
        identity: integrity("timeline-owner", KeyRoleV1::TimelineIntegritySigning, 1),
        origin_timeline_id: TimelineId::from_ulid(Ulid::from_bytes(ascending(0x20))),
        event_id: event_id(event_start),
        origin_logical_seq: Seq::from_u64(seq),
        entity_id: subject(),
        event_type: Kind::new(event_type),
        schema_version: 1,
        wall_time: WallTime::from_micros(1),
        causation_id: None,
        correlation_id: None,
    }
}

fn consent_event() -> TimelineEventEnvelopeInputV1 {
    event(0x30, 1, "consent.granted.v2")
}

fn field_event() -> TimelineEventEnvelopeInputV1 {
    event(0x40, 2, "subject.data.v1")
}

/// The consent vector's Event after `edit`.
fn consent_with(
    edit: impl FnOnce(&mut TimelineEventEnvelopeInputV1),
) -> TimelineEventEnvelopeInputV1 {
    let mut event = consent_event();
    edit(&mut event);
    event
}

/// The subject-field vector's Event after `edit`.
fn field_with(
    edit: impl FnOnce(&mut TimelineEventEnvelopeInputV1),
) -> TimelineEventEnvelopeInputV1 {
    let mut event = field_event();
    edit(&mut event);
    event
}

/// The golden consent ciphertext, encrypted through the public API.
fn consent_ciphertext() -> Result<SubjectCiphertextV1, Box<dyn std::error::Error>> {
    let subkey = golden_subkey(SubjectKeyUseV1::Bootstrap)?;
    let header = hex(CONSENT_HEADER);
    let event = consent_event();
    Ok(SubjectCiphertextV1::encrypt(
        &subkey,
        1,
        &event,
        &header,
        "purpose",
        CONSENT_PLAINTEXT,
    )?)
}

/// The plaintext length that `ciphertext` releases, or the refusal.
fn released(
    ciphertext: &SubjectCiphertextV1,
    subkey: &SubjectSubkeyV1,
    event: &TimelineEventEnvelopeInputV1,
    header: &[u8],
    field_tag: &str,
) -> Result<usize, SubjectCiphertextErrorV1> {
    ciphertext
        .decrypt(subkey, event, header, field_tag)
        .map(|plaintext| plaintext.len())
}

/// The 16 golden consent SDC1 items, built from the ADR inputs alone.
fn consent_items() -> Vec<Vec<u8>> {
    vec![
        bstr(b"SDC1"),
        uint(1),
        tstr(OWNER),
        bstr(&ascending::<16>(0)),
        uint(0),
        uint(1),
        uint(1),
        bstr(&ascending::<16>(0x20)),
        uint(1),
        bstr(&ascending::<16>(0x30)),
        tstr("consent.granted.v2"),
        uint(1),
        tstr("purpose"),
        bstr(&hex(CONSENT_DIGEST)),
        bstr(&nonce(1)),
        bstr(&hex(CONSENT_SEALED)),
    ]
}

fn nonce(counter: u64) -> [u8; 12] {
    let [_, _, _, _, nonce @ ..] = u128::from(counter).to_be_bytes();
    nonce
}

/// The V1 nonce of `counter` with the fixed field `fixed_field` instead.
fn prefixed_nonce(fixed_field: u32, counter: u64) -> [u8; 12] {
    let [_, _, _, _, nonce @ ..] =
        ((u128::from(fixed_field) << 64) | u128::from(counter)).to_be_bytes();
    nonce
}

/// AES-256-GCM computed with the `aes-gcm` crate directly.
fn reference_seal(key: &str, nonce: &[u8], aad: &str, plaintext: &[u8]) -> Option<Vec<u8>> {
    let key: [u8; 32] = fixed(&hex(key));
    let nonce: [u8; 12] = fixed(nonce);
    let mut buffer = plaintext.to_vec();
    let cipher = Aes256Gcm::new((&key).into());
    let tag =
        cipher.encrypt_inout_detached((&nonce).into(), &hex(aad), buffer.as_mut_slice().into());
    tag.ok().map(|tag| [buffer, tag.to_vec()].concat())
}

// ---------------------------------------------------------------------------
// SubjectKeyWrapV1 (ADR-091, ADR-097 section 1)
// ---------------------------------------------------------------------------

#[test]
fn golden_wrap_reproduces_every_published_byte() -> TestResult {
    let wrap = golden_wrap()?;
    assert_eq!(wrap.wrap_context(), hex(WRAP_CONTEXT));
    assert_eq!(wrap.associated_data(), hex(WRAP_AAD));
    assert_eq!(wrap.wrapped_root().to_vec(), hex(WRAPPED_ROOT));
    assert_eq!(wrap.to_bytes(), hex(WRAP));
    assert_eq!(array(&wrap_items()), hex(WRAP));
    assert_eq!(wrap.owner_id(), OWNER);
    assert_eq!(wrap.params(), &params());
    assert_eq!(subject_owner_id(subject()), Ok(OWNER.to_owned()));
    let digest = root().material_digest();
    assert_eq!(digest.as_bytes().to_vec(), hex(ROOT_DIGEST));
    Ok(())
}

#[test]
fn golden_wrap_decodes_opens_and_round_trips() -> TestResult {
    let wrap = SubjectKeyWrapV1::from_bytes(&hex(WRAP))?;
    assert_eq!(wrap, golden_wrap()?);
    assert_eq!(wrap.to_bytes(), hex(WRAP));
    assert_eq!(opened(&wrap, &prf()), Ok(root().material_digest()));
    Ok(())
}

#[test]
fn published_derived_keys_produce_the_published_ciphertexts() {
    // The crate never exposes a derived key. These reference encryptions
    // under the published wrapping key and subkeys produce exactly the bytes
    // that the crate produces in the vector tests, binding each published key.
    let wrap_nonce = hex("000000000000000000000001");
    let wrapped = reference_seal(WRAPPING_KEY, &wrap_nonce, WRAP_AAD, &ascending::<32>(0));
    assert_eq!(wrapped, Some(hex(WRAPPED_ROOT)));
    let consent = reference_seal(BOOTSTRAP_SUBKEY, &nonce(1), CONSENT_AAD, CONSENT_PLAINTEXT);
    assert_eq!(consent, Some(hex(CONSENT_SEALED)));
    let field = reference_seal(DATA_SUBKEY, &nonce(1), FIELD_AAD, FIELD_PLAINTEXT);
    assert_eq!(field, Some(hex(FIELD_SEALED)));
}

#[test]
fn owner_derivation_is_the_exact_lowercase_bijection() {
    let mixed = entity(fixed(&hex("0123456789abcdeffedcba9876543210")));
    let expected = "subject:0123456789abcdeffedcba9876543210".to_owned();
    assert_eq!(subject_owner_id(mixed), Ok(expected));
    let nil = subject_owner_id(entity([0; 16]));
    assert_eq!(nil, Err(SubjectKeyWrapErrorV1::InvalidField { ordinal: 3 }));
    assert_eq!(SUBJECT_OWNER_PREFIX.len() + 32, SUBJECT_OWNER_BYTES);
}

#[test]
fn tampered_tag_or_wrong_prf_releases_no_root() -> TestResult {
    let refused = Err(SubjectKeyWrapErrorV1::AuthenticationFailed);
    let golden = hex(WRAP);
    let last = golden.len() - 1;
    let mut tag = golden.clone();
    tag[last] ^= 0x01;
    assert_eq!(
        opened(&SubjectKeyWrapV1::from_bytes(&tag)?, &prf()),
        refused
    );
    let mut body = golden;
    body[last - 20] ^= 0x80;
    assert_eq!(
        opened(&SubjectKeyWrapV1::from_bytes(&body)?, &prf()),
        refused
    );
    let wrong = SubjectPrfOutputV1::from_bytes(ascending(0x41));
    assert_eq!(opened(&golden_wrap()?, &wrong), refused);
    Ok(())
}

#[test]
fn every_changed_wrap_field_fails_authentication() -> TestResult {
    let changes: [fn(&mut SubjectKeyWrapParamsV1); 8] = [
        |params| params.subject_id = entity(ascending(1)),
        |params| params.epoch = 2,
        |params| params.rp_id = "example.com".to_owned(),
        |params| params.credential_id[0] ^= 1,
        |params| params.prf_input[0] ^= 1,
        |params| params.wrap_salt[0] ^= 1,
        |params| params.subkey_salt[0] ^= 1,
        |params| params.wrap_nonce[11] ^= 1,
    ];
    let wrapped_root = hex(WRAPPED_ROOT);
    for change in changes {
        let wrap = transplanted(&seal_with(change)?.to_bytes(), &wrapped_root)?;
        let refused = Err(SubjectKeyWrapErrorV1::AuthenticationFailed);
        assert_eq!(opened(&wrap, &prf()), refused);
    }
    let unchanged = transplanted(&golden_wrap()?.to_bytes(), &wrapped_root)?;
    assert_eq!(unchanged, golden_wrap()?);
    Ok(())
}

#[test]
fn wrap_decoder_rejects_each_invalid_field() {
    let items = wrap_items();
    let invalid = |ordinal| Err(SubjectKeyWrapErrorV1::InvalidField { ordinal });
    let exceeded = |ordinal| Err(SubjectKeyWrapErrorV1::BoundsExceeded { ordinal });
    let foreign = "subject:0102030405060708090a0b0c0d0e0f10";
    let upper = "subject:000102030405060708090A0B0C0D0E0F";
    let cases = [
        (0, bstr(b"SKW2"), invalid(0)),
        (1, uint(2), Err(SubjectKeyWrapErrorV1::UnsupportedVersion)),
        (1, uint(0), Err(SubjectKeyWrapErrorV1::UnsupportedVersion)),
        (2, tstr(foreign), invalid(2)),
        (2, tstr(upper), invalid(2)),
        (2, tstr(&format!("{OWNER}0")), exceeded(2)),
        (3, bstr(&[0; 16]), invalid(3)),
        (4, uint(1), invalid(4)),
        (5, uint(0), invalid(5)),
        (6, tstr("Localhost"), invalid(6)),
        (6, tstr(&"a".repeat(254)), exceeded(6)),
        (7, bstr(&[]), invalid(7)),
        (7, bstr(&[7; 1025]), exceeded(7)),
    ];
    for (index, item, expected) in cases {
        let bytes = with_item(&items, index, item);
        assert_eq!(SubjectKeyWrapV1::from_bytes(&bytes), expected, "{index}");
    }
}

#[test]
fn wrap_decoder_rejects_every_wrongly_typed_field() {
    let items = wrap_items();
    for ordinal in 0..13_u8 {
        let index = usize::from(ordinal);
        let bytes = with_item(&items, index, vec![0xf6]);
        let expected = SubjectKeyWrapErrorV1::InvalidEncoding { ordinal };
        assert_eq!(
            SubjectKeyWrapV1::from_bytes(&bytes),
            Err(expected),
            "{index}"
        );
    }
}

#[test]
fn wrap_decoder_rejects_cardinality_and_noncanonical_forms() {
    let items = wrap_items();
    let encoding = |ordinal| Err(SubjectKeyWrapErrorV1::InvalidEncoding { ordinal });
    let golden = hex(WRAP);
    let wide_subject = [vec![0x58, 0x10], ascending::<16>(0).to_vec()].concat();
    let bad_utf8 = [vec![0x69, 0xff, 0xfe], b"calhost".to_vec()].concat();
    let chunked = [vec![0x7f], tstr("localhost"), vec![0xff]].concat();
    let cases = [
        (array(&items[..12]), encoding(13)),
        (
            array(&[items.clone(), vec![uint(0)]].concat()),
            encoding(13),
        ),
        ([golden.clone(), vec![0x00]].concat(), encoding(13)),
        (
            [vec![0x9f], items.concat(), vec![0xff]].concat(),
            encoding(13),
        ),
        ([vec![0xa1], items.concat()].concat(), encoding(13)),
        (Vec::new(), encoding(13)),
        (golden[..golden.len() - 1].to_vec(), encoding(12)),
        (with_item(&items, 5, vec![0x18, 0x01]), encoding(5)),
        (with_item(&items, 3, wide_subject), encoding(3)),
        (with_item(&items, 8, bstr(&[0; 31])), encoding(8)),
        (with_item(&items, 11, bstr(&[0; 13])), encoding(11)),
        (with_item(&items, 12, bstr(&[0; 47])), encoding(12)),
        (
            with_item(&items, 5, [vec![0xc1], uint(1)].concat()),
            encoding(5),
        ),
        (with_item(&items, 6, bad_utf8), encoding(6)),
        (with_item(&items, 6, chunked), encoding(6)),
    ];
    for (bytes, expected) in cases {
        assert_eq!(SubjectKeyWrapV1::from_bytes(&bytes), expected);
    }
}

#[test]
fn seal_validates_inputs_at_their_exact_bounds() -> TestResult {
    let longest = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    assert_eq!(longest.len(), MAX_SUBJECT_RP_ID_BYTES);
    let over = format!("{longest}e");
    let at_bound = seal_with(|params| params.rp_id.clone_from(&longest))?;
    assert_eq!(
        SubjectKeyWrapV1::from_bytes(&at_bound.to_bytes())?,
        at_bound
    );
    let refused = seal_with(|params| params.rp_id = over);
    assert_eq!(
        refused,
        Err(SubjectKeyWrapErrorV1::BoundsExceeded { ordinal: 6 })
    );
    let credential = vec![9; MAX_SUBJECT_CREDENTIAL_ID_BYTES];
    let at_bound = seal_with(|params| params.credential_id.clone_from(&credential))?;
    assert_eq!(
        SubjectKeyWrapV1::from_bytes(&at_bound.to_bytes())?,
        at_bound
    );
    let over = MAX_SUBJECT_CREDENTIAL_ID_BYTES + 1;
    let refused = seal_with(|params| params.credential_id = vec![9; over]);
    assert_eq!(
        refused,
        Err(SubjectKeyWrapErrorV1::BoundsExceeded { ordinal: 7 })
    );
    let empty = seal_with(|params| params.credential_id.clear());
    assert_eq!(
        empty,
        Err(SubjectKeyWrapErrorV1::InvalidField { ordinal: 7 })
    );
    let single = seal_with(|params| params.credential_id = vec![9])?;
    assert_eq!(single.to_bytes().len(), hex(WRAP).len() - 15);
    let nil = seal_with(|params| params.subject_id = entity([0; 16]));
    assert_eq!(nil, Err(SubjectKeyWrapErrorV1::InvalidField { ordinal: 3 }));
    let zero = seal_with(|params| params.epoch = 0);
    assert_eq!(
        zero,
        Err(SubjectKeyWrapErrorV1::InvalidField { ordinal: 5 })
    );
    Ok(())
}

#[test]
fn rp_id_grammar_accepts_canonical_domains() {
    let longest_label = "z".repeat(63);
    let accepted = [
        "localhost",
        "a",
        "example.com",
        "a-b.c0",
        "xn--bcher-kva.example",
        "1.2.example",
        "0xg",
        "example.0a",
        "x0",
        longest_label.as_str(),
    ];
    for rp_id in accepted {
        let sealed = seal_with(|params| params.rp_id = rp_id.to_owned());
        assert_eq!(
            sealed.map(|wrap| wrap.params().rp_id.clone()),
            Ok(rp_id.to_owned())
        );
    }
}

#[test]
fn rp_id_grammar_rejects_everything_else() {
    let long_label = "z".repeat(64);
    let rejected = [
        "",
        ".",
        "example.",
        ".example",
        "a..b",
        "Example.com",
        "exa_mple.com",
        "-a.com",
        "a-.com",
        "a.-b",
        "b\u{fc}cher.example",
        "127.0.0.1",
        "1.2.3",
        "0",
        "example.123",
        "0x7f",
        "0x10",
        "example.0x10",
        "a.0x",
        "0x",
        "::1",
        "[::1]",
        "local host",
        long_label.as_str(),
    ];
    for rp_id in rejected {
        let sealed = seal_with(|params| params.rp_id = rp_id.to_owned());
        let expected = Err(SubjectKeyWrapErrorV1::InvalidField { ordinal: 6 });
        assert_eq!(sealed, expected, "{rp_id}");
    }
}

#[test]
fn integer_heads_use_shortest_forms_at_every_boundary() -> TestResult {
    // Field 5 (epoch) starts at byte 67 of the record.
    let cases: [(u64, &[u8]); 10] = [
        (1, &[0x01]),
        (23, &[0x17]),
        (24, &[0x18, 0x18]),
        (0xff, &[0x18, 0xff]),
        (0x100, &[0x19, 0x01, 0x00]),
        (0xffff, &[0x19, 0xff, 0xff]),
        (0x1_0000, &[0x1a, 0x00, 0x01, 0x00, 0x00]),
        (0xffff_ffff, &[0x1a, 0xff, 0xff, 0xff, 0xff]),
        (0x1_0000_0000, &[0x1b, 0, 0, 0, 1, 0, 0, 0, 0]),
        (
            u64::MAX,
            &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ),
    ];
    for (epoch, encoded) in cases {
        let wrap = seal_with(|params| params.epoch = epoch)?;
        let bytes = wrap.to_bytes();
        assert_eq!(&bytes[67..67 + encoded.len()], encoded, "epoch {epoch}");
        assert_eq!(SubjectKeyWrapV1::from_bytes(&bytes)?, wrap);
        assert_eq!(opened(&wrap, &prf()), Ok(root().material_digest()));
    }
    // Field 7 (credential ID) starts at byte 78 when the epoch is 1.
    let long = seal_with(|params| params.credential_id = vec![3; 300])?;
    let bytes = long.to_bytes();
    assert_eq!(&bytes[78..81], &[0x59, 0x01, 0x2c]);
    assert_eq!(SubjectKeyWrapV1::from_bytes(&bytes)?, long);
    Ok(())
}

#[test]
fn secrets_are_redacted_in_debug_output() -> TestResult {
    assert_eq!(format!("{:?}", root()), "SubjectRootKeyV1(<redacted>)");
    assert_eq!(format!("{:?}", prf()), "SubjectPrfOutputV1(<redacted>)");
    let bootstrap = golden_subkey(SubjectKeyUseV1::Bootstrap)?;
    let expected = format!(
        "SubjectSubkeyV1 {{ subject_id: {:?}, epoch: 1, key_use: Bootstrap, .. }}",
        subject()
    );
    assert_eq!(format!("{bootstrap:?}"), expected);
    assert_eq!(bootstrap.subject_id(), subject());
    assert_eq!(bootstrap.epoch(), 1);
    assert_eq!(bootstrap.key_use(), SubjectKeyUseV1::Bootstrap);
    let data = golden_subkey(SubjectKeyUseV1::Data)?;
    assert_eq!(data.key_use(), SubjectKeyUseV1::Data);
    let debug = format!("{bootstrap:?}{data:?}{:?}{:?}", root(), prf());
    for secret in [BOOTSTRAP_SUBKEY, DATA_SUBKEY, "9e01bb", "99f686", "404142"] {
        assert!(!debug.contains(secret));
    }
    Ok(())
}

#[test]
fn v1_limits_are_the_adr_values() {
    assert_eq!(MAX_SUBJECT_CIPHERTEXT_BYTES, 256 * 1024);
    assert_eq!(MAX_SUBJECT_PUBLIC_HEADER_BYTES, 64 * 1024);
    assert_eq!(MAX_SUBJECT_NONCE_COUNTER, (1 << 32) - 1);
    assert_eq!(MAX_SUBJECT_EVENT_TYPE_BYTES, 256);
    assert_eq!(MAX_SUBJECT_FIELD_TAG_BYTES, 128);
    assert_eq!(MAX_SUBJECT_RP_ID_BYTES, 253);
    assert_eq!(MAX_SUBJECT_CREDENTIAL_ID_BYTES, 1024);
    assert_eq!(SUBJECT_OWNER_BYTES, 40);
}

#[test]
fn key_use_codes_are_closed() {
    assert_eq!(SubjectKeyUseV1::Data.code(), 0);
    assert_eq!(SubjectKeyUseV1::Bootstrap.code(), 1);
    assert_eq!(SubjectKeyUseV1::from_code(0), Some(SubjectKeyUseV1::Data));
    assert_eq!(
        SubjectKeyUseV1::from_code(1),
        Some(SubjectKeyUseV1::Bootstrap)
    );
    assert_eq!(SubjectKeyUseV1::from_code(2), None);
    assert_eq!(SubjectKeyUseV1::from_code(u64::MAX), None);
}

#[test]
fn wrap_error_messages_carry_only_the_field() {
    let cases = [
        (
            SubjectKeyWrapErrorV1::InvalidEncoding { ordinal: 13 },
            "invalid SKW1 encoding at field 13",
        ),
        (
            SubjectKeyWrapErrorV1::BoundsExceeded { ordinal: 6 },
            "SKW1 field 6 exceeds a V1 bound",
        ),
        (
            SubjectKeyWrapErrorV1::InvalidField { ordinal: 2 },
            "invalid SKW1 field 2",
        ),
        (
            SubjectKeyWrapErrorV1::UnsupportedVersion,
            "unsupported SKW1 version",
        ),
        (
            SubjectKeyWrapErrorV1::AuthenticationFailed,
            "SKW1 wrapped root failed authentication",
        ),
    ];
    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn ciphertext_error_messages_carry_only_the_field() {
    let cases = [
        (
            SubjectCiphertextErrorV1::InvalidEncoding { ordinal: 16 },
            "invalid SDC1 encoding at field 16",
        ),
        (
            SubjectCiphertextErrorV1::BoundsExceeded { ordinal: 13 },
            "SDC1 field 13 exceeds a V1 bound",
        ),
        (
            SubjectCiphertextErrorV1::InvalidField { ordinal: 14 },
            "invalid SDC1 field 14",
        ),
        (
            SubjectCiphertextErrorV1::UnsupportedVersion,
            "unsupported SDC1 version",
        ),
        (
            SubjectCiphertextErrorV1::ContextMismatch { ordinal: 9 },
            "SDC1 field 9 differs from its expected context",
        ),
        (
            SubjectCiphertextErrorV1::AuthenticationFailed,
            "SDC1 ciphertext failed authentication",
        ),
    ];
    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn two_subjects_under_one_human_have_disjoint_wraps() -> TestResult {
    let second_root = SubjectRootKeyV1::from_bytes(ascending(0x70));
    let second_prf = SubjectPrfOutputV1::from_bytes(ascending(0x90));
    let second_params = params_with(|params| params.subject_id = entity(ascending(0x50)));
    let second = SubjectKeyWrapV1::seal(second_params, &second_root, &second_prf)?;
    let first = golden_wrap()?;
    assert_ne!(second.owner_id(), first.owner_id());
    assert_ne!(second.wrapped_root(), first.wrapped_root());
    assert_ne!(second_root.material_digest(), root().material_digest());
    let refused = Err(SubjectKeyWrapErrorV1::AuthenticationFailed);
    assert_eq!(opened(&first, &second_prf), refused);
    assert_eq!(opened(&second, &prf()), refused);
    let swapped = transplanted(&second.to_bytes(), first.wrapped_root())?;
    assert_eq!(opened(&swapped, &prf()), refused);
    assert_eq!(opened(&swapped, &second_prf), refused);
    assert_eq!(
        opened(&second, &second_prf),
        Ok(second_root.material_digest())
    );
    Ok(())
}

#[test]
fn two_subjects_under_one_human_decrypt_only_their_own_fields() -> TestResult {
    let second_id = entity(ascending(0x50));
    let second_root = SubjectRootKeyV1::from_bytes(ascending(0x70));
    let second_prf = SubjectPrfOutputV1::from_bytes(ascending(0x90));
    let second_params = params_with(|params| params.subject_id = second_id);
    let second = SubjectKeyWrapV1::seal(second_params, &second_root, &second_prf)?;
    let second_key =
        second.derive_subkey(&second.open(&second_prf)?, SubjectKeyUseV1::Bootstrap)?;
    let first_key = golden_subkey(SubjectKeyUseV1::Bootstrap)?;
    let second_event = consent_with(|event| event.entity_id = second_id);
    let first_event = consent_event();
    let header = hex(CONSENT_HEADER);
    let plaintext = CONSENT_PLAINTEXT;
    let mine =
        SubjectCiphertextV1::encrypt(&second_key, 1, &second_event, &header, "purpose", plaintext)?;
    let theirs = consent_ciphertext()?;
    assert_eq!(mine.counter(), theirs.counter());
    assert_ne!(mine.as_bytes(), theirs.as_bytes());
    let own = released(&mine, &second_key, &second_event, &header, "purpose");
    assert_eq!(own, Ok(plaintext.len()));
    let mismatch = Err(SubjectCiphertextErrorV1::ContextMismatch { ordinal: 3 });
    assert_eq!(
        released(&mine, &first_key, &first_event, &header, "purpose"),
        mismatch
    );
    assert_eq!(
        released(&theirs, &second_key, &second_event, &header, "purpose"),
        mismatch
    );
    assert_eq!(
        released(&theirs, &second_key, &first_event, &header, "purpose"),
        mismatch
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// SubjectCiphertextV1 (ADR-097 sections 2 and 6)
// ---------------------------------------------------------------------------

#[test]
fn consent_vector_reproduces_every_published_byte() -> TestResult {
    let ciphertext = consent_ciphertext()?;
    assert_eq!(ciphertext.as_bytes(), hex(CONSENT_CIPHERTEXT));
    assert_eq!(array(&consent_items()), hex(CONSENT_CIPHERTEXT));
    assert_eq!(ciphertext.associated_data(), hex(CONSENT_AAD));
    assert_eq!(ciphertext.context_digest().to_vec(), hex(CONSENT_DIGEST));
    assert_eq!(ciphertext.ciphertext_and_tag(), hex(CONSENT_SEALED));
    assert_eq!(ciphertext.nonce(), nonce(1));
    assert_eq!(ciphertext.counter(), 1);
    assert_eq!(ciphertext.subject_id(), subject());
    assert_eq!(ciphertext.epoch(), 1);
    assert_eq!(ciphertext.key_use(), SubjectKeyUseV1::Bootstrap);
    let event = consent_event();
    assert_eq!(ciphertext.origin_timeline_id(), event.origin_timeline_id);
    assert_eq!(ciphertext.origin_logical_seq(), 1);
    assert_eq!(ciphertext.event_id(), event.event_id);
    assert_eq!(ciphertext.event_type(), "consent.granted.v2");
    assert_eq!(ciphertext.schema_version(), 1);
    assert_eq!(ciphertext.field_tag(), "purpose");
    let subkey = golden_subkey(SubjectKeyUseV1::Bootstrap)?;
    let plaintext = ciphertext.decrypt(&subkey, &event, &hex(CONSENT_HEADER), "purpose")?;
    assert_eq!(*plaintext, CONSENT_PLAINTEXT);
    Ok(())
}

#[test]
fn subject_field_vector_reproduces_every_published_byte() -> TestResult {
    let subkey = golden_subkey(SubjectKeyUseV1::Data)?;
    let header = hex(FIELD_HEADER);
    let event = field_event();
    let ciphertext =
        SubjectCiphertextV1::encrypt(&subkey, 1, &event, &header, "value", FIELD_PLAINTEXT)?;
    assert_eq!(ciphertext.as_bytes(), hex(FIELD_CIPHERTEXT));
    assert_eq!(ciphertext.associated_data(), hex(FIELD_AAD));
    assert_eq!(ciphertext.associated_data()[0], 0x8f);
    assert_eq!(ciphertext.as_bytes()[0], 0x90);
    assert_eq!(ciphertext.context_digest().to_vec(), hex(FIELD_DIGEST));
    assert_eq!(ciphertext.ciphertext_and_tag(), hex(FIELD_SEALED));
    assert_eq!(ciphertext.key_use(), SubjectKeyUseV1::Data);
    assert_eq!(ciphertext.origin_logical_seq(), 2);
    assert_eq!(ciphertext.field_tag(), "value");
    let plaintext = ciphertext.decrypt(&subkey, &event, &header, "value")?;
    assert_eq!(*plaintext, FIELD_PLAINTEXT);
    let decoded = SubjectCiphertextV1::from_bytes(&hex(FIELD_CIPHERTEXT))?;
    assert_eq!(decoded, ciphertext);
    Ok(())
}

#[test]
fn golden_ciphertexts_decode_to_the_encrypted_values() -> TestResult {
    let decoded = SubjectCiphertextV1::from_bytes(&hex(CONSENT_CIPHERTEXT))?;
    assert_eq!(decoded, consent_ciphertext()?);
    assert_eq!(decoded.as_bytes(), hex(CONSENT_CIPHERTEXT));
    assert_eq!(decoded.associated_data(), hex(CONSENT_AAD));
    let subkey = golden_subkey(SubjectKeyUseV1::Bootstrap)?;
    let header = hex(CONSENT_HEADER);
    let plaintext = decoded.decrypt(&subkey, &consent_event(), &header, "purpose")?;
    assert_eq!(*plaintext, CONSENT_PLAINTEXT);
    Ok(())
}

#[test]
fn decryption_rejects_every_changed_event_coordinate() -> TestResult {
    let ciphertext = consent_ciphertext()?;
    let subkey = golden_subkey(SubjectKeyUseV1::Bootstrap)?;
    let header = hex(CONSENT_HEADER);
    let timeline = TimelineId::from_ulid(Ulid::from_bytes(ascending(0x21)));
    let correlation = CorrelationId::from_ulid(Ulid::from_bytes(ascending(0x60)));
    let signing = KeyRoleV1::TimelineIntegritySigning;
    let cases = [
        (
            consent_with(|event| event.entity_id = entity(ascending(1))),
            3,
        ),
        (consent_with(|event| event.origin_timeline_id = timeline), 7),
        (
            consent_with(|event| event.origin_logical_seq = Seq::from_u64(2)),
            8,
        ),
        (consent_with(|event| event.event_id = event_id(0x60)), 9),
        (
            consent_with(|event| event.event_type = Kind::new("consent.granted.v3")),
            10,
        ),
        (consent_with(|event| event.schema_version = 2), 11),
        (
            consent_with(|event| event.wall_time = WallTime::from_micros(2)),
            13,
        ),
        (
            consent_with(|event| event.causation_id = Some(event_id(0x60))),
            13,
        ),
        (
            consent_with(|event| event.correlation_id = Some(correlation)),
            13,
        ),
        (
            consent_with(|event| event.identity = integrity("timeline-other", signing, 1)),
            13,
        ),
        (
            consent_with(|event| event.identity = integrity("timeline-owner", signing, 2)),
            13,
        ),
    ];
    for (event, ordinal) in cases {
        let refused = released(&ciphertext, &subkey, &event, &header, "purpose");
        let expected = Err(SubjectCiphertextErrorV1::ContextMismatch { ordinal });
        assert_eq!(refused, expected, "{ordinal}");
    }
    let event = consent_event();
    let mismatch = |ordinal| Err(SubjectCiphertextErrorV1::ContextMismatch { ordinal });
    assert_eq!(
        released(&ciphertext, &subkey, &event, &header, "Purpose"),
        mismatch(12)
    );
    let mut altered = header.clone();
    altered[33] ^= 1;
    assert_eq!(
        released(&ciphertext, &subkey, &event, &altered, "purpose"),
        mismatch(13)
    );
    let short = &header[..header.len() - 1];
    assert_eq!(
        released(&ciphertext, &subkey, &event, short, "purpose"),
        mismatch(13)
    );
    Ok(())
}

#[test]
fn decryption_rejects_an_invalid_context_before_comparing_it() -> TestResult {
    let ciphertext = consent_ciphertext()?;
    let subkey = golden_subkey(SubjectKeyUseV1::Bootstrap)?;
    let header = hex(CONSENT_HEADER);
    let signing = KeyRoleV1::TimelineIntegritySigning;
    let unsigned = consent_with(|event| event.identity = integrity("timeline-owner", signing, 0));
    let refused = released(&ciphertext, &subkey, &unsigned, &header, "purpose");
    assert_eq!(
        refused,
        Err(SubjectCiphertextErrorV1::InvalidField { ordinal: 13 })
    );
    let oversized = vec![0; MAX_SUBJECT_PUBLIC_HEADER_BYTES + 1];
    let refused = released(
        &ciphertext,
        &subkey,
        &consent_event(),
        &oversized,
        "purpose",
    );
    assert_eq!(
        refused,
        Err(SubjectCiphertextErrorV1::BoundsExceeded { ordinal: 13 })
    );
    let nil = consent_with(|event| event.event_id = EventId::from_ulid(Ulid::nil()));
    let refused = released(&ciphertext, &subkey, &nil, &header, "purpose");
    assert_eq!(
        refused,
        Err(SubjectCiphertextErrorV1::InvalidField { ordinal: 9 })
    );
    Ok(())
}

#[test]
fn decryption_rejects_a_subkey_of_another_identity() -> TestResult {
    let ciphertext = consent_ciphertext()?;
    let header = hex(CONSENT_HEADER);
    let event = consent_event();
    let bootstrap = SubjectKeyUseV1::Bootstrap;
    let data = golden_subkey(SubjectKeyUseV1::Data)?;
    let refused = released(&ciphertext, &data, &event, &header, "purpose");
    assert_eq!(
        refused,
        Err(SubjectCiphertextErrorV1::ContextMismatch { ordinal: 6 })
    );
    let rotated = seal_with(|params| params.epoch = 2)?.derive_subkey(&root(), bootstrap)?;
    assert_eq!(rotated.epoch(), 2);
    let refused = released(&ciphertext, &rotated, &event, &header, "purpose");
    assert_eq!(
        refused,
        Err(SubjectCiphertextErrorV1::ContextMismatch { ordinal: 5 })
    );
    let foreign_root = SubjectRootKeyV1::from_bytes(ascending(1));
    let foreign = golden_wrap()?.derive_subkey(&foreign_root, bootstrap)?;
    let refused = released(&ciphertext, &foreign, &event, &header, "purpose");
    assert_eq!(refused, Err(SubjectCiphertextErrorV1::AuthenticationFailed));
    let resalted = seal_with(|params| params.subkey_salt = ascending(0x21))?;
    let resalted = resalted.derive_subkey(&root(), bootstrap)?;
    let refused = released(&ciphertext, &resalted, &event, &header, "purpose");
    assert_eq!(refused, Err(SubjectCiphertextErrorV1::AuthenticationFailed));
    Ok(())
}

#[test]
fn tampered_ciphertext_fails_authentication() -> TestResult {
    let subkey = golden_subkey(SubjectKeyUseV1::Bootstrap)?;
    let header = hex(CONSENT_HEADER);
    let event = consent_event();
    let items = consent_items();
    let sealed = hex(CONSENT_SEALED);
    let mut tag_flip = sealed.clone();
    let last = tag_flip.len() - 1;
    tag_flip[last] ^= 0x01;
    let mut body_flip = sealed.clone();
    body_flip[0] ^= 0x01;
    let cases = [
        with_item(&items, 15, bstr(&tag_flip)),
        with_item(&items, 15, bstr(&body_flip)),
        with_item(&items, 15, bstr(&sealed[1..])),
        with_item(&items, 14, bstr(&nonce(2))),
    ];
    for bytes in cases {
        let ciphertext = SubjectCiphertextV1::from_bytes(&bytes)?;
        let refused = released(&ciphertext, &subkey, &event, &header, "purpose");
        assert_eq!(refused, Err(SubjectCiphertextErrorV1::AuthenticationFailed));
    }
    let mut digest = hex(CONSENT_DIGEST);
    digest[0] ^= 1;
    let changed = SubjectCiphertextV1::from_bytes(&with_item(&items, 13, bstr(&digest)))?;
    let refused = released(&changed, &subkey, &event, &header, "purpose");
    assert_eq!(
        refused,
        Err(SubjectCiphertextErrorV1::ContextMismatch { ordinal: 13 })
    );
    Ok(())
}

#[test]
fn ciphertext_decoder_rejects_each_invalid_field() {
    let items = consent_items();
    let invalid = |ordinal| Err(SubjectCiphertextErrorV1::InvalidField { ordinal });
    let exceeded = |ordinal| Err(SubjectCiphertextErrorV1::BoundsExceeded { ordinal });
    let foreign = "subject:0102030405060708090a0b0c0d0e0f10";
    let long_type = "e".repeat(MAX_SUBJECT_EVENT_TYPE_BYTES + 1);
    let long_tag = "f".repeat(MAX_SUBJECT_FIELD_TAG_BYTES + 1);
    let cases = [
        (0, bstr(b"SDC2"), invalid(0)),
        (
            1,
            uint(2),
            Err(SubjectCiphertextErrorV1::UnsupportedVersion),
        ),
        (2, tstr(foreign), invalid(2)),
        (2, tstr(&format!("{OWNER}0")), exceeded(2)),
        (3, bstr(&[0; 16]), invalid(3)),
        (4, uint(2), invalid(4)),
        (5, uint(0), invalid(5)),
        (6, uint(2), invalid(6)),
        (7, bstr(&[0; 16]), invalid(7)),
        (8, uint(0), invalid(8)),
        (9, bstr(&[0; 16]), invalid(9)),
        (10, tstr(""), invalid(10)),
        (10, tstr(&long_type), exceeded(10)),
        (11, uint(1 << 32), invalid(11)),
        (12, tstr(""), invalid(12)),
        (12, tstr("purpos\u{e9}"), invalid(12)),
        (12, tstr(&long_tag), exceeded(12)),
        (15, bstr(&[0; 15]), invalid(15)),
        (15, head(2, 300_000), exceeded(15)),
    ];
    for (index, item, expected) in cases {
        let bytes = with_item(&items, index, item);
        assert_eq!(SubjectCiphertextV1::from_bytes(&bytes), expected, "{index}");
    }
}

#[test]
fn ciphertext_decoder_accepts_only_the_v1_nonce_construction() {
    let items = consent_items();
    let invalid = Err(SubjectCiphertextErrorV1::InvalidField { ordinal: 14 });
    let rejected = [
        prefixed_nonce(0x0100_0000, 1),
        prefixed_nonce(1, 1),
        nonce(0),
        nonce(MAX_SUBJECT_NONCE_COUNTER + 1),
        nonce(u64::MAX),
    ];
    for nonce in rejected {
        let bytes = with_item(&items, 14, bstr(&nonce));
        assert_eq!(SubjectCiphertextV1::from_bytes(&bytes), invalid);
    }
    for counter in [1, 2, MAX_SUBJECT_NONCE_COUNTER] {
        let bytes = with_item(&items, 14, bstr(&nonce(counter)));
        let decoded =
            SubjectCiphertextV1::from_bytes(&bytes).map(|ciphertext| ciphertext.counter());
        assert_eq!(decoded, Ok(counter));
    }
}

#[test]
fn ciphertext_decoder_accepts_fields_at_their_exact_bounds() {
    let items = consent_items();
    let accepted = [
        (15, bstr(&[0; 16])),
        (10, tstr(&"e".repeat(MAX_SUBJECT_EVENT_TYPE_BYTES))),
        (12, tstr(&"f".repeat(MAX_SUBJECT_FIELD_TAG_BYTES))),
        (11, uint(u64::from(u32::MAX))),
        (8, uint(u64::MAX)),
        (5, uint(u64::MAX)),
    ];
    for (index, item) in accepted {
        let bytes = with_item(&items, index, item);
        let decoded = SubjectCiphertextV1::from_bytes(&bytes)
            .map(|ciphertext| ciphertext.as_bytes().to_vec());
        assert_eq!(decoded, Ok(bytes), "{index}");
    }
}

#[test]
fn ciphertext_decoder_rejects_every_wrongly_typed_field() {
    let items = consent_items();
    for ordinal in 0..16_u8 {
        let index = usize::from(ordinal);
        let bytes = with_item(&items, index, vec![0xf6]);
        let expected = SubjectCiphertextErrorV1::InvalidEncoding { ordinal };
        assert_eq!(
            SubjectCiphertextV1::from_bytes(&bytes),
            Err(expected),
            "{index}"
        );
    }
}

#[test]
fn ciphertext_decoder_rejects_cardinality_and_noncanonical_forms() {
    let items = consent_items();
    let encoding = |ordinal| Err(SubjectCiphertextErrorV1::InvalidEncoding { ordinal });
    let golden = hex(CONSENT_CIPHERTEXT);
    let cases = [
        (array(&items[..15]), encoding(16)),
        (
            array(&[items.clone(), vec![uint(0)]].concat()),
            encoding(16),
        ),
        ([golden.clone(), vec![0x00]].concat(), encoding(16)),
        (
            [vec![0x9f], items.concat(), vec![0xff]].concat(),
            encoding(16),
        ),
        (Vec::new(), encoding(16)),
        (golden[..golden.len() - 1].to_vec(), encoding(15)),
        (with_item(&items, 8, vec![0x18, 0x01]), encoding(8)),
        (with_item(&items, 13, bstr(&[0; 31])), encoding(13)),
        (with_item(&items, 14, bstr(&[0; 11])), encoding(14)),
        (with_item(&items, 7, bstr(&[0; 17])), encoding(7)),
        (with_item(&items, 10, vec![0x62, 0xc3, 0x28]), encoding(10)),
    ];
    for (bytes, expected) in cases {
        assert_eq!(SubjectCiphertextV1::from_bytes(&bytes), expected);
    }
}

#[test]
fn encryption_rejects_counters_outside_the_project_cap() -> TestResult {
    let subkey = golden_subkey(SubjectKeyUseV1::Bootstrap)?;
    let header = hex(CONSENT_HEADER);
    let event = consent_event();
    let encrypt = |counter| {
        SubjectCiphertextV1::encrypt(&subkey, counter, &event, &header, "purpose", b"\x60")
            .map(|ciphertext| ciphertext.nonce())
    };
    let invalid = Err(SubjectCiphertextErrorV1::InvalidField { ordinal: 14 });
    assert_eq!(encrypt(0), invalid);
    assert_eq!(encrypt(MAX_SUBJECT_NONCE_COUNTER + 1), invalid);
    assert_eq!(encrypt(u64::MAX), invalid);
    assert_eq!(
        encrypt(MAX_SUBJECT_NONCE_COUNTER),
        Ok(nonce(MAX_SUBJECT_NONCE_COUNTER))
    );
    assert_eq!(encrypt(2), Ok(nonce(2)));
    Ok(())
}

#[test]
fn encryption_rejects_invalid_event_contexts() -> TestResult {
    let subkey = golden_subkey(SubjectKeyUseV1::Bootstrap)?;
    let header = hex(CONSENT_HEADER);
    let encrypt = |event: &TimelineEventEnvelopeInputV1| {
        SubjectCiphertextV1::encrypt(&subkey, 1, event, &header, "purpose", b"\x60")
            .map(|ciphertext| ciphertext.counter())
    };
    let invalid = |ordinal| Err(SubjectCiphertextErrorV1::InvalidField { ordinal });
    let nil = Ulid::nil();
    let longest = "t".repeat(MAX_SUBJECT_EVENT_TYPE_BYTES);
    let too_long = format!("{longest}t");
    let attribution = KeyRoleV1::SubjectAttributionSigning;
    let signing = KeyRoleV1::TimelineIntegritySigning;
    let cases = [
        (
            consent_with(|event| event.origin_timeline_id = TimelineId::from_ulid(nil)),
            invalid(7),
        ),
        (
            consent_with(|event| event.origin_logical_seq = Seq::from_u64(0)),
            invalid(8),
        ),
        (
            consent_with(|event| event.event_id = EventId::from_ulid(nil)),
            invalid(9),
        ),
        (
            consent_with(|event| event.event_type = Kind::new("")),
            invalid(10),
        ),
        (
            consent_with(|event| event.event_type = Kind::new(too_long)),
            Err(SubjectCiphertextErrorV1::BoundsExceeded { ordinal: 10 }),
        ),
        (
            consent_with(|event| event.entity_id = entity([0; 16])),
            Err(SubjectCiphertextErrorV1::ContextMismatch { ordinal: 3 }),
        ),
        (
            consent_with(|event| event.identity = integrity("timeline-owner", attribution, 1)),
            invalid(13),
        ),
        (
            consent_with(|event| event.identity = integrity("timeline-owner", signing, 0)),
            invalid(13),
        ),
        (
            consent_with(|event| event.event_type = Kind::new(longest)),
            Ok(1),
        ),
    ];
    for (event, expected) in cases {
        assert_eq!(encrypt(&event), expected);
    }
    Ok(())
}

#[test]
fn encryption_rejects_invalid_field_tags() -> TestResult {
    let subkey = golden_subkey(SubjectKeyUseV1::Bootstrap)?;
    let header = hex(CONSENT_HEADER);
    let event = consent_event();
    let encrypt = |field_tag: &str| {
        SubjectCiphertextV1::encrypt(&subkey, 1, &event, &header, field_tag, b"\x60")
            .map(|ciphertext| ciphertext.field_tag().len())
    };
    let longest = "f".repeat(MAX_SUBJECT_FIELD_TAG_BYTES);
    let invalid = Err(SubjectCiphertextErrorV1::InvalidField { ordinal: 12 });
    assert_eq!(encrypt(""), invalid);
    assert_eq!(encrypt("purpos\u{e9}"), invalid);
    let exceeded = Err(SubjectCiphertextErrorV1::BoundsExceeded { ordinal: 12 });
    assert_eq!(encrypt(&format!("{longest}f")), exceeded);
    assert_eq!(encrypt(&longest), Ok(MAX_SUBJECT_FIELD_TAG_BYTES));
    assert_eq!(encrypt("p"), Ok(1));
    Ok(())
}

#[test]
fn the_encoding_limit_holds_at_its_exact_bound() -> TestResult {
    let subkey = golden_subkey(SubjectKeyUseV1::Data)?;
    let event = field_event();
    let header = hex(FIELD_HEADER);
    let encrypt = |plaintext: &[u8]| {
        SubjectCiphertextV1::encrypt(&subkey, 1, &event, &header, "value", plaintext)
    };
    let probe = encrypt(FIELD_PLAINTEXT)?;
    // A sealed field of at least 64 KiB has a five-byte byte-string head.
    let largest = MAX_SUBJECT_CIPHERTEXT_BYTES - probe.associated_data().len() - 5 - 16;
    let exact = encrypt(&vec![7; largest])?;
    assert_eq!(exact.as_bytes().len(), MAX_SUBJECT_CIPHERTEXT_BYTES);
    let plaintext = exact.decrypt(&subkey, &event, &header, "value")?;
    assert_eq!(plaintext.len(), largest);
    assert_eq!(SubjectCiphertextV1::from_bytes(exact.as_bytes())?, exact);
    let exceeded = Err(SubjectCiphertextErrorV1::BoundsExceeded { ordinal: 16 });
    assert_eq!(encrypt(&vec![7; largest + 1]), exceeded);
    assert_eq!(encrypt(&vec![7; MAX_SUBJECT_CIPHERTEXT_BYTES]), exceeded);
    let one_over = [exact.as_bytes(), &[0]].concat();
    assert_eq!(SubjectCiphertextV1::from_bytes(&one_over), exceeded);
    let empty = encrypt(&[])?;
    assert_eq!(empty.ciphertext_and_tag().len(), 16);
    assert!(empty.decrypt(&subkey, &event, &header, "value")?.is_empty());
    Ok(())
}

#[test]
fn the_public_header_limit_holds_at_its_exact_bound() -> TestResult {
    let subkey = golden_subkey(SubjectKeyUseV1::Data)?;
    let event = field_event();
    let encrypt = |header: &[u8]| {
        SubjectCiphertextV1::encrypt(&subkey, 1, &event, header, "value", FIELD_PLAINTEXT)
    };
    let widest = vec![1; MAX_SUBJECT_PUBLIC_HEADER_BYTES];
    let bound = encrypt(&widest)?;
    let plaintext = bound.decrypt(&subkey, &event, &widest, "value")?;
    assert_eq!(*plaintext, FIELD_PLAINTEXT);
    assert_ne!(
        bound.context_digest(),
        encrypt(&hex(FIELD_HEADER))?.context_digest()
    );
    let exceeded = Err(SubjectCiphertextErrorV1::BoundsExceeded { ordinal: 13 });
    assert_eq!(encrypt(&[widest, vec![1]].concat()), exceeded);
    Ok(())
}

#[test]
fn causation_and_correlation_are_bound_by_the_context() -> TestResult {
    let subkey = golden_subkey(SubjectKeyUseV1::Data)?;
    let header = hex(FIELD_HEADER);
    let causation = event_id(0x70);
    let correlation = CorrelationId::from_ulid(Ulid::from_bytes(ascending(0x70)));
    let base = field_event();
    let events = [
        base.clone(),
        field_with(|event| event.causation_id = Some(causation)),
        field_with(|event| event.correlation_id = Some(correlation)),
        field_with(|event| {
            event.causation_id = Some(causation);
            event.correlation_id = Some(correlation);
        }),
    ];
    let mut digests = Vec::new();
    for event in &events {
        let ciphertext =
            SubjectCiphertextV1::encrypt(&subkey, 1, event, &header, "value", FIELD_PLAINTEXT)?;
        let own = released(&ciphertext, &subkey, event, &header, "value");
        assert_eq!(own, Ok(FIELD_PLAINTEXT.len()));
        let against_base = released(&ciphertext, &subkey, &base, &header, "value");
        let expected = if event == &base {
            Ok(FIELD_PLAINTEXT.len())
        } else {
            Err(SubjectCiphertextErrorV1::ContextMismatch { ordinal: 13 })
        };
        assert_eq!(against_base, expected);
        digests.push(*ciphertext.context_digest());
    }
    for digest in &digests {
        assert_eq!(digests.iter().filter(|other| *other == digest).count(), 1);
    }
    Ok(())
}

#[test]
fn large_coordinates_round_trip() -> TestResult {
    let subkey = seal_with(|params| params.epoch = u64::MAX)?
        .derive_subkey(&root(), SubjectKeyUseV1::Data)?;
    let signing = KeyRoleV1::TimelineIntegritySigning;
    let event = field_with(|event| {
        event.origin_logical_seq = Seq::from_u64(u64::MAX);
        event.schema_version = u32::MAX;
        event.wall_time = WallTime::from_micros(u64::MAX);
        event.identity = integrity("timeline-owner", signing, u64::MAX);
    });
    let header = hex(FIELD_HEADER);
    let counter = 0x1_0000;
    let ciphertext =
        SubjectCiphertextV1::encrypt(&subkey, counter, &event, &header, "value", FIELD_PLAINTEXT)?;
    let decoded = SubjectCiphertextV1::from_bytes(ciphertext.as_bytes())?;
    assert_eq!(decoded, ciphertext);
    assert_eq!(decoded.epoch(), u64::MAX);
    assert_eq!(decoded.origin_logical_seq(), u64::MAX);
    assert_eq!(decoded.schema_version(), u32::MAX);
    assert_eq!(decoded.counter(), counter);
    assert_eq!(decoded.nonce(), nonce(counter));
    let plaintext = decoded.decrypt(&subkey, &event, &header, "value")?;
    assert_eq!(*plaintext, FIELD_PLAINTEXT);
    Ok(())
}

#[test]
fn owner_parsing_accepts_only_the_exact_spelling() {
    assert_eq!(parse_subject_owner_id(OWNER), Ok(subject()));
    let mixed = "subject:0123456789abcdeffedcba9876543210";
    let parsed = parse_subject_owner_id(mixed);
    assert_eq!(parsed.and_then(subject_owner_id), Ok(mixed.to_owned()));
    let invalid = Err(SubjectKeyWrapErrorV1::InvalidField { ordinal: 2 });
    let rejected = [
        "subject:00000000000000000000000000000000",
        "subject:000102030405060708090A0B0C0D0E0F",
        "Subject:000102030405060708090a0b0c0d0e0f",
        "subjects000102030405060708090a0b0c0d0e0f",
        "000102030405060708090a0b0c0d0e0f",
        "subject:000102030405060708090a0b0c0d0e0",
        "subject:000102030405060708090a0b0c0d0e0f0",
        "subject:00102030405060708090a0b0c0d0e0f",
        "subject:+00102030405060708090a0b0c0d0e0f",
        "subject:000102030405060708090a0b0c0d0e0g",
        "subject: 00102030405060708090a0b0c0d0e0f",
        "",
    ];
    for owner in rejected {
        assert_eq!(parse_subject_owner_id(owner), invalid, "{owner}");
    }
}

#[test]
fn decoders_report_the_lowest_malformed_field() {
    let mut items = wrap_items();
    items[3] = bstr(&[0; 16]);
    items[5] = vec![0xf6];
    let refused = SubjectKeyWrapV1::from_bytes(&array(&items));
    assert_eq!(
        refused,
        Err(SubjectKeyWrapErrorV1::InvalidField { ordinal: 3 })
    );
    items[3] = bstr(&ascending::<16>(0));
    items[5] = uint(0);
    items[6] = tstr("Localhost");
    let refused = SubjectKeyWrapV1::from_bytes(&array(&items));
    assert_eq!(
        refused,
        Err(SubjectKeyWrapErrorV1::InvalidField { ordinal: 5 })
    );
    let mut items = consent_items();
    items[3] = bstr(&[0; 16]);
    items[12] = vec![0xf6];
    let refused = SubjectCiphertextV1::from_bytes(&array(&items));
    assert_eq!(
        refused,
        Err(SubjectCiphertextErrorV1::InvalidField { ordinal: 3 })
    );
    let mut items = consent_items();
    items[8] = uint(0);
    items[10] = tstr("");
    items[15] = bstr(&[0; 3]);
    let refused = SubjectCiphertextV1::from_bytes(&array(&items));
    assert_eq!(
        refused,
        Err(SubjectCiphertextErrorV1::InvalidField { ordinal: 8 })
    );
}

#[test]
fn refused_primitive_errors_carry_no_material() {
    let message = SubjectKeyWrapErrorV1::PrimitiveRefused.to_string();
    assert_eq!(message, "SKW1 key derivation or sealing refused its input");
}
