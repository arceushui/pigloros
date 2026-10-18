//! Public ADR-119 record and payload codec tests with independent golden vectors.
//!
//! The byte and BLAKE3 digest vectors were computed outside Rust (Python CBOR
//! encoding and the `b3sum` reference tool).

use pos_core::{
    CompositionPinV1, DomainFallbackPolicyV1, FallbackActivatedInputV1, FallbackActivatedPayloadV1,
    FallbackActivationModeV1 as Mode, FallbackActivationOriginV1 as Origin,
    FallbackDeclaredPayloadV1, FallbackEntryV1, FallbackFieldV1 as F, FallbackRebasedEntryV1,
    FallbackRecordErrorV1, FallbackSkipReasonV1 as Reason, FallbackSkippedCandidateV1,
    FallbackTriggerBasisV1, FallbackTriggerCodeV1 as Trigger, Hash, ImplementationKeyV1,
    COMPOSITION_FALLBACK_ACTIVATED_EVENT_TYPE_V1, COMPOSITION_FALLBACK_DECLARED_EVENT_TYPE_V1,
    COMPOSITION_PIN_DIGEST_DOMAIN_V1, FALLBACK_POLICY_DIGEST_DOMAIN_V1,
    IMPLEMENTATION_KEY_DIGEST_DOMAIN_V1, MAX_COMPOSITION_PIN_BYTES_V1, MAX_FALLBACK_CANDIDATES_V1,
    MAX_FALLBACK_ENTRIES_V1, MAX_FALLBACK_ENTRY_BYTES_V1, MAX_FALLBACK_EVENT_PAYLOAD_BYTES_V1,
    MAX_FALLBACK_POLICY_BYTES_V1, MAX_FALLBACK_ROLES_V1, MAX_IMPLEMENTATION_KEY_BYTES_V1,
};

const IMK1_HEX: &str = concat!(
    "8544494d4b31016f6f72672e6578616d706c652e67656f65312e322e30582011111111111111111111111111",
    "11111111111111111111111111111111111111",
);
const IMK1_DIGEST_HEX: &str = "491ec0426d2ead138803536ac269e7bc20456ab81c0a7dd9c243ef43892379f1";
const LITE_IMK1_DIGEST_HEX: &str =
    "c66901b7919669b297c476c044b615f729f3d15046b83271a02ffb40e2eb3764";
const PPN1_HEX: &str = concat!(
    "844450504e31018544494d4b31016f6f72672e6578616d706c652e67656f65312e322e305820111111111111",
    "111111111111111111111111111111111111111111111111111182676c6f6361746f726a67656f2e72656164",
    "6572",
);
const PIN_DIGEST_HEX: &str = "e92db9b4c3ca6818ec93307f643e89184eec120bf3f270dff841e7cbcd2fdbec";
const DFP1_HEX: &str = concat!(
    "864444465031016d73657373696f6e2e616c70686181856367656f844450504e31018544494d4b31016f6f72",
    "672e6578616d706c652e67656f65312e322e3058201111111111111111111111111111111111111111111111",
    "11111111111111111182676c6f6361746f726a67656f2e72656164657281844450504e31018544494d4b3101",
    "746f72672e6578616d706c652e67656f2d6c69746565302e392e315820222222222222222222222222222222",
    "222222222222222222222222222222222282676c6f6361746f726a67656f2e72656164657282030500f65820",
    "10bd669b5f54a1334799c066a579d308312e3ec69948b7d01ec2e25c7ae8c79b",
);
const DFP1_DIGEST_HEX: &str = "10bd669b5f54a1334799c066a579d308312e3ec69948b7d01ec2e25c7ae8c79b";
const WITHDRAWAL_HEX: &str = concat!(
    "864444465031016d73657373696f6e2e616c70686180582010bd669b5f54a1334799c066a579d308312e3ec6",
    "9948b7d01ec2e25c7ae8c79b5820775b403c8b38ae9447da8002df604795f3206726e92cf31c6ca4e51645a8",
    "7be7",
);
const WITHDRAWAL_DIGEST_HEX: &str =
    "775b403c8b38ae9447da8002df604795f3206726e92cf31c6ca4e51645a87be7";
const DECLARED_HEX: &str = concat!(
    "846d73657373696f6e2e616c706861582010bd669b5f54a1334799c066a579d308312e3ec69948b7d01ec2e2",
    "5c7ae8c79bf681826367656f5820c66901b7919669b297c476c044b615f729f3d15046b83271a02ffb40e2eb",
    "3764",
);
const ACTIVATED_HEX: &str = concat!(
    "8a6d73657373696f6e2e616c706861582010bd669b5f54a1334799c066a579d308312e3ec69948b7d01ec2e2",
    "5c7ae8c79b6367656f00583f8544494d4b31016f6f72672e6578616d706c652e67656f65312e322e30582011",
    "1111111111111111111111111111111111111111111111111111111111111158448544494d4b3101746f7267",
    "2e6578616d706c652e67656f2d6c69746565302e392e31582022222222222222222222222222222222222222",
    "2222222222222222222222222281825820333333333333333333333333333333333333333333333333333333",
    "333333333303034301020007",
);

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;
type Decode = fn(&[u8]) -> Result<(), FallbackRecordErrorV1>;

fn from_hex(text: &str) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    for pair in text.as_bytes().chunks_exact(2) {
        bytes.push(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?);
    }
    Ok(bytes)
}

fn hash_hex(text: &str) -> TestResult<Hash> {
    let bytes = from_hex(text)?;
    Ok(Hash::from_bytes(<[u8; 32]>::try_from(bytes.as_slice())?))
}

fn replace_once(bytes: &[u8], from: &[u8], to: &[u8]) -> TestResult<Vec<u8>> {
    let starts: Vec<usize> = (0..bytes.len())
        .filter(|start| bytes[*start..].starts_with(from))
        .collect();
    if starts.len() != 1 {
        let count = starts.len();
        return Err(format!("pattern {from:02x?} occurs {count} times").into());
    }
    let end = starts[0] + from.len();
    Ok([&bytes[..starts[0]], to, &bytes[end..]].concat())
}

fn primary_key() -> TestResult<ImplementationKeyV1> {
    let digest = Hash::from_bytes([0x11; 32]);
    let id = "org.example.geo".to_owned();
    Ok(ImplementationKeyV1::new(id, "1.2.0".into(), digest)?)
}

fn lite_key() -> TestResult<ImplementationKeyV1> {
    let digest = Hash::from_bytes([0x22; 32]);
    let id = "org.example.geo-lite".to_owned();
    Ok(ImplementationKeyV1::new(id, "0.9.1".into(), digest)?)
}

fn pin(key: ImplementationKeyV1) -> TestResult<CompositionPinV1> {
    let roles = vec!["locator".to_owned(), "geo.reader".to_owned()];
    Ok(CompositionPinV1::new(key, roles)?)
}

fn geo_entry() -> TestResult<FallbackEntryV1> {
    Ok(FallbackEntryV1::new(
        "geo".into(),
        pin(primary_key()?)?,
        vec![pin(lite_key()?)?],
        vec![Trigger::ResourceLimit, Trigger::WorkerCrashed],
        Mode::Automatic,
    )?)
}

fn golden_policy() -> TestResult<DomainFallbackPolicyV1> {
    let scope = "session.alpha".to_owned();
    let entries = vec![geo_entry()?];
    Ok(DomainFallbackPolicyV1::new(scope, entries, None)?)
}

fn activated_input() -> TestResult<FallbackActivatedInputV1> {
    Ok(FallbackActivatedInputV1 {
        scope: "session.alpha".into(),
        policy_digest: hash_hex(DFP1_DIGEST_HEX)?,
        entry_key: "geo".into(),
        closing_tenure_ordinal: 0,
        from: primary_key()?,
        to: lite_key()?,
        skipped: vec![FallbackSkippedCandidateV1 {
            implementation_digest: Hash::from_bytes([0x33; 32]),
            reason: Reason::SourceUnavailable,
        }],
        trigger_code: Trigger::ResourceLimit,
        trigger_basis: FallbackTriggerBasisV1 {
            cause: 0x0102,
            origin: Origin::Automatic,
        },
        activation_ordinal: 7,
    })
}

fn decode_key(bytes: &[u8]) -> Result<(), FallbackRecordErrorV1> {
    ImplementationKeyV1::from_canonical_cbor(bytes).map(drop)
}

fn decode_pin(bytes: &[u8]) -> Result<(), FallbackRecordErrorV1> {
    CompositionPinV1::from_canonical_cbor(bytes).map(drop)
}

fn decode_policy(bytes: &[u8]) -> Result<(), FallbackRecordErrorV1> {
    DomainFallbackPolicyV1::from_canonical_cbor(bytes).map(drop)
}

fn decode_declared(bytes: &[u8]) -> Result<(), FallbackRecordErrorV1> {
    FallbackDeclaredPayloadV1::from_canonical_cbor(bytes).map(drop)
}

fn decode_activated(bytes: &[u8]) -> Result<(), FallbackRecordErrorV1> {
    FallbackActivatedPayloadV1::from_canonical_cbor(bytes).map(drop)
}

fn goldens() -> TestResult<Vec<(Decode, Vec<u8>)>> {
    Ok(vec![
        (decode_key as Decode, from_hex(IMK1_HEX)?),
        (decode_pin, from_hex(PPN1_HEX)?),
        (decode_policy, from_hex(DFP1_HEX)?),
        (decode_policy, from_hex(WITHDRAWAL_HEX)?),
        (decode_declared, from_hex(DECLARED_HEX)?),
        (decode_activated, from_hex(ACTIVATED_HEX)?),
    ])
}

#[test]
fn reserved_event_types_and_digest_domains_are_fixed() {
    assert_eq!(
        COMPOSITION_FALLBACK_DECLARED_EVENT_TYPE_V1,
        "pigloros.composition.fallback-declared"
    );
    assert_eq!(
        COMPOSITION_FALLBACK_ACTIVATED_EVENT_TYPE_V1,
        "pigloros.composition.fallback-activated"
    );
    assert_eq!(
        IMPLEMENTATION_KEY_DIGEST_DOMAIN_V1,
        b"PiglorOS.Composition.ImplementationKey.v1\0"
    );
    assert_eq!(
        COMPOSITION_PIN_DIGEST_DOMAIN_V1,
        b"PiglorOS.Composition.Pin.v1\0"
    );
    assert_eq!(
        FALLBACK_POLICY_DIGEST_DOMAIN_V1,
        b"PiglorOS.Composition.FallbackPolicy.v1\0"
    );
    for domain in [
        IMPLEMENTATION_KEY_DIGEST_DOMAIN_V1,
        COMPOSITION_PIN_DIGEST_DOMAIN_V1,
        FALLBACK_POLICY_DIGEST_DOMAIN_V1,
    ] {
        assert!(domain.starts_with(b"PiglorOS.Composition."));
        assert_eq!(domain.last(), Some(&0));
    }
}

#[test]
fn imk1_and_ppn1_golden_vectors() -> TestResult<()> {
    let key = primary_key()?;
    assert_eq!(key.to_canonical_cbor(), from_hex(IMK1_HEX)?);
    assert_eq!(key.digest(), hash_hex(IMK1_DIGEST_HEX)?);
    assert_eq!(lite_key()?.digest(), hash_hex(LITE_IMK1_DIGEST_HEX)?);
    let decoded = ImplementationKeyV1::from_canonical_cbor(&from_hex(IMK1_HEX)?)?;
    assert_eq!(decoded, key);
    assert_eq!(key.plugin_id(), "org.example.geo");
    assert_eq!(key.version(), "1.2.0");
    assert_eq!(key.release_digest(), Hash::from_bytes([0x11; 32]));
    let pinned = pin(key.clone())?;
    assert_eq!(pinned.to_canonical_cbor(), from_hex(PPN1_HEX)?);
    assert_eq!(pinned.digest(), hash_hex(PIN_DIGEST_HEX)?);
    let decoded = CompositionPinV1::from_canonical_cbor(&from_hex(PPN1_HEX)?)?;
    assert_eq!(decoded, pinned);
    assert_eq!(pinned.implementation(), &key);
    assert_eq!(pinned.roles(), ["locator", "geo.reader"]);
    Ok(())
}

#[test]
fn dfp1_golden_vectors_and_withdrawal() -> TestResult<()> {
    let policy = golden_policy()?;
    assert_eq!(policy.to_canonical_cbor(), from_hex(DFP1_HEX)?);
    assert_eq!(policy.policy_digest(), hash_hex(DFP1_DIGEST_HEX)?);
    let decoded = DomainFallbackPolicyV1::from_canonical_cbor(&from_hex(DFP1_HEX)?)?;
    assert_eq!(decoded, policy);
    assert_eq!(policy.scope(), "session.alpha");
    assert_eq!(policy.previous_policy_digest(), None);
    assert!(!policy.is_withdrawal());
    let entry = &policy.entries()[0];
    assert_eq!(entry, &geo_entry()?);
    assert_eq!(entry.entry_key(), "geo");
    assert_eq!(entry.primary(), &pin(primary_key()?)?);
    assert_eq!(entry.candidates(), [pin(lite_key()?)?]);
    let triggers = [Trigger::ResourceLimit, Trigger::WorkerCrashed];
    assert_eq!(entry.triggers(), triggers);
    assert_eq!(entry.activation_mode(), Mode::Automatic);
    let encoded_entry = entry.to_canonical_cbor();
    let golden = from_hex(DFP1_HEX)?;
    let contained = golden
        .windows(encoded_entry.len())
        .any(|window| window == encoded_entry.as_slice());
    assert!(contained);
    let scope = "session.alpha".to_owned();
    let withdrawal = DomainFallbackPolicyV1::new(scope, Vec::new(), Some(policy.policy_digest()))?;
    assert!(withdrawal.is_withdrawal());
    assert_eq!(withdrawal.to_canonical_cbor(), from_hex(WITHDRAWAL_HEX)?);
    assert_eq!(withdrawal.policy_digest(), hash_hex(WITHDRAWAL_DIGEST_HEX)?);
    let previous = Some(policy.policy_digest());
    assert_eq!(withdrawal.previous_policy_digest(), previous);
    let decoded = DomainFallbackPolicyV1::from_canonical_cbor(&from_hex(WITHDRAWAL_HEX)?)?;
    assert_eq!(decoded, withdrawal);
    Ok(())
}

#[test]
fn first_withdrawal_round_trips_at_the_codec() -> TestResult<()> {
    let first = DomainFallbackPolicyV1::new("session.alpha".into(), Vec::new(), None)?;
    assert!(first.is_withdrawal());
    assert_eq!(first.previous_policy_digest(), None);
    let bytes = first.to_canonical_cbor();
    let decoded = DomainFallbackPolicyV1::from_canonical_cbor(&bytes)?;
    assert_eq!(decoded, first);
    assert_eq!(decoded.policy_digest(), first.policy_digest());
    Ok(())
}

#[test]
fn declaration_payload_golden_vector() -> TestResult<()> {
    let policy = golden_policy()?;
    let rebased = FallbackRebasedEntryV1::new("geo".into(), lite_key()?.digest())?;
    let payload = FallbackDeclaredPayloadV1::for_policy(&policy, vec![rebased.clone()])?;
    assert_eq!(payload.to_canonical_cbor(), from_hex(DECLARED_HEX)?);
    let decoded = FallbackDeclaredPayloadV1::from_canonical_cbor(&from_hex(DECLARED_HEX)?)?;
    assert_eq!(decoded, payload);
    assert_eq!(payload.scope(), "session.alpha");
    assert_eq!(payload.policy_digest(), policy.policy_digest());
    assert_eq!(payload.previous_policy_digest(), None);
    assert_eq!(payload.rebased(), std::slice::from_ref(&rebased));
    assert_eq!(rebased.entry_key(), "geo");
    let lite_digest = hash_hex(LITE_IMK1_DIGEST_HEX)?;
    assert_eq!(rebased.implementation_digest(), lite_digest);
    let scope = "session.alpha".to_owned();
    let withdrawal = DomainFallbackPolicyV1::new(scope, Vec::new(), Some(policy.policy_digest()))?;
    let withdrawn = FallbackDeclaredPayloadV1::for_policy(&withdrawal, Vec::new())?;
    assert_eq!(withdrawn.policy_digest(), hash_hex(WITHDRAWAL_DIGEST_HEX)?);
    let previous = Some(policy.policy_digest());
    assert_eq!(withdrawn.previous_policy_digest(), previous);
    let bytes = withdrawn.to_canonical_cbor();
    let decoded = FallbackDeclaredPayloadV1::from_canonical_cbor(&bytes)?;
    assert_eq!(decoded, withdrawn);
    Ok(())
}

#[test]
fn activation_payload_golden_vector() -> TestResult<()> {
    let payload = FallbackActivatedPayloadV1::new(activated_input()?)?;
    assert_eq!(payload.to_canonical_cbor(), from_hex(ACTIVATED_HEX)?);
    let decoded = FallbackActivatedPayloadV1::from_canonical_cbor(&from_hex(ACTIVATED_HEX)?)?;
    assert_eq!(decoded, payload);
    assert_eq!(payload.as_input(), &activated_input()?);
    assert_eq!(payload.opening_tenure_ordinal(), Some(1));
    let last = FallbackActivatedPayloadV1::new(FallbackActivatedInputV1 {
        closing_tenure_ordinal: u64::MAX,
        ..activated_input()?
    })?;
    assert_eq!(last.opening_tenure_ordinal(), None);
    Ok(())
}

#[test]
fn every_strict_prefix_is_rejected() -> TestResult<()> {
    for (decode, bytes) in goldens()? {
        assert_eq!(decode(&bytes), Ok(()));
        for length in 0..bytes.len() {
            let result = decode(&bytes[..length]);
            assert_eq!(result, Err(ENCODING), "{length}");
        }
    }
    Ok(())
}

#[test]
fn trailing_and_oversized_inputs_are_rejected() -> TestResult<()> {
    for (decode, bytes) in goldens()? {
        let trailing = [bytes.as_slice(), &[0]].concat();
        assert_eq!(decode(&trailing), Err(FallbackRecordErrorV1::NonCanonical));
    }
    for (decode, maximum) in [
        (decode_key as Decode, MAX_IMPLEMENTATION_KEY_BYTES_V1),
        (decode_pin, MAX_COMPOSITION_PIN_BYTES_V1),
        (decode_policy, MAX_FALLBACK_POLICY_BYTES_V1),
        (decode_declared, MAX_FALLBACK_EVENT_PAYLOAD_BYTES_V1),
        (decode_activated, MAX_FALLBACK_EVENT_PAYLOAD_BYTES_V1),
    ] {
        let oversized = vec![0; maximum + 1];
        assert_eq!(decode(&oversized), Err(FallbackRecordErrorV1::TooLarge));
    }
    Ok(())
}

const ENCODING: FallbackRecordErrorV1 = FallbackRecordErrorV1::InvalidEncoding;
const NONCANONICAL: FallbackRecordErrorV1 = FallbackRecordErrorV1::NonCanonical;
const NARROW_TEXT: &[u8] = &[0x6f, b'o'];
const WIDE_TEXT: &[u8] = &[0x78, 15, b'o'];
const BAD_UTF8: &[u8] = &[0xff, 0, 0, 0];
const ROLES: &[u8] = &[0x82, 0x67];
const TRIGGERS: &[u8] = &[0x82, 3, 5, 0];
const CANDIDATES: &[u8] = &[0x72, 0x81, 0x84];
const ENTRIES: &[u8] = &[0x61, 0x81, 0x85];
const REBASED: &[u8] = &[0xf6, 0x81];
const SKIPPED: &[u8] = &[0x81, 0x82];
const CODES: &[u8] = &[0x33, 3, 3];
const BASIS: &[u8] = &[0x43, 1, 2, 0];

type Case<'a> = (&'a [u8], &'a [u8], FallbackRecordErrorV1);

const fn bad(field: F) -> FallbackRecordErrorV1 {
    FallbackRecordErrorV1::InvalidField(field)
}

fn check_all(decode: Decode, bytes: &[u8], cases: &[Case<'_>]) -> TestResult<()> {
    for (from, to, expected) in cases {
        let mutated = replace_once(bytes, from, to)?;
        assert_eq!(decode(&mutated), Err(*expected), "{to:02x?}");
    }
    Ok(())
}

#[test]
fn mutated_records_fail_closed() -> TestResult<()> {
    let key_cases: [Case<'_>; 4] = [
        (b"IMK1", b"IMK2", ENCODING),
        (b"org.", BAD_UTF8, ENCODING),
        (NARROW_TEXT, WIDE_TEXT, NONCANONICAL),
        (&[0x58, 0x20], &[0x58, 0x1f], ENCODING),
    ];
    check_all(decode_key, &from_hex(IMK1_HEX)?, &key_cases)?;
    let pin_cases: [Case<'_>; 2] = [
        (b"PPN1", b"PPN2", ENCODING),
        (ROLES, &[0x91, 0x67], bad(F::Roles)),
    ];
    check_all(decode_pin, &from_hex(PPN1_HEX)?, &pin_cases)?;
    let policy_cases: [Case<'_>; 8] = [
        (b"DFP1", b"DFP2", ENCODING),
        (TRIGGERS, &[0x82, 3, 6, 0], bad(F::Triggers)),
        (TRIGGERS, &[0x86, 3, 5, 0], bad(F::Triggers)),
        (TRIGGERS, &[0x82, 5, 3, 0], bad(F::Triggers)),
        (TRIGGERS, &[0x82, 3, 5, 2], bad(F::ActivationMode)),
        (CANDIDATES, &[0x72, 0x83, 0x84], bad(F::Candidates)),
        (ENTRIES, &[0x61, 0x98, 33, 0x85], bad(F::Entries)),
        (ENTRIES, &[0x61, 0x81, 0x84], ENCODING),
    ];
    let policy = from_hex(DFP1_HEX)?;
    check_all(decode_policy, &policy, &policy_cases)?;
    let mut wrong_digest = policy;
    if let Some(last) = wrong_digest.last_mut() {
        *last ^= 1;
    }
    let mismatch = Err(FallbackRecordErrorV1::PolicyDigestMismatch);
    assert_eq!(decode_policy(&wrong_digest), mismatch);
    Ok(())
}

#[test]
fn mutated_payloads_fail_closed() -> TestResult<()> {
    let declared_cases: [Case<'_>; 2] = [
        (REBASED, &[0xf6, 0x98, 33], bad(F::Rebased)),
        (REBASED, &[0xf5, 0x81], ENCODING),
    ];
    check_all(decode_declared, &from_hex(DECLARED_HEX)?, &declared_cases)?;
    let activated_cases: [Case<'_>; 7] = [
        (SKIPPED, &[0x83, 0x82], bad(F::Skipped)),
        (CODES, &[0x33, 7, 3], bad(F::SkipReason)),
        (CODES, &[0x33, 3, 0], bad(F::TriggerCode)),
        (CODES, &[0x33, 3, 0x19, 1, 3], bad(F::TriggerCode)),
        (BASIS, &[0x43, 1, 2, 2], bad(F::TriggerOrigin)),
        (BASIS, &[0x44, 1, 2, 0], ENCODING),
        (b"K1\x01t", b"K2\x01t", ENCODING),
    ];
    let activated = from_hex(ACTIVATED_HEX)?;
    check_all(decode_activated, &activated, &activated_cases)?;
    let mut wide_ordinal = activated;
    wide_ordinal.pop();
    wide_ordinal.extend_from_slice(&[0x18, 7]);
    assert_eq!(decode_activated(&wide_ordinal), Err(NONCANONICAL));
    Ok(())
}

type Record<T> = Result<T, FallbackRecordErrorV1>;

fn key_named(plugin_id: &str) -> Record<ImplementationKeyV1> {
    ImplementationKeyV1::new(plugin_id.into(), "1".into(), Hash::zero())
}

fn pin_named(plugin_id: &str) -> Record<CompositionPinV1> {
    CompositionPinV1::new(key_named(plugin_id)?, vec!["role".to_owned()])
}

fn entry_named(key: &str, primary: &str, candidate: &str) -> Record<FallbackEntryV1> {
    let primary = pin_named(primary)?;
    let candidates = vec![pin_named(candidate)?];
    let triggers = vec![Trigger::ArtifactRevoked];
    FallbackEntryV1::new(key.into(), primary, candidates, triggers, Mode::Manual)
}

fn entry_with(
    candidates: Vec<CompositionPinV1>,
    triggers: Vec<Trigger>,
) -> Record<FallbackEntryV1> {
    let primary = pin_named("a")?;
    FallbackEntryV1::new("geo".into(), primary, candidates, triggers, Mode::Manual)
}

fn numbered_entry(index: usize) -> Record<FallbackEntryV1> {
    let key = format!("e{index:02}");
    entry_named(&key, &format!("p{index}"), &format!("c{index}"))
}

fn numbered_pair(index: usize) -> Record<FallbackRebasedEntryV1> {
    FallbackRebasedEntryV1::new(format!("{index:02}{}", "k".repeat(62)), Hash::zero())
}

fn wide_key(tag: &str) -> Record<ImplementationKeyV1> {
    let plugin_id = format!("{tag}{}", "p".repeat(128 - tag.len()));
    ImplementationKeyV1::new(plugin_id, "v".repeat(64), Hash::zero())
}

fn wide_pin(tag: &str) -> Record<CompositionPinV1> {
    let roles = (0..16).map(|role| format!("{role:064}")).collect();
    CompositionPinV1::new(wide_key(tag)?, roles)
}

fn wide_entry(index: usize) -> Record<FallbackEntryV1> {
    let key = format!("{index:02}{}", "k".repeat(62));
    let primary = wide_pin(&format!("{index:02}0"))?;
    let first = wide_pin(&format!("{index:02}1"))?;
    let second = wide_pin(&format!("{index:02}2"))?;
    let candidates = vec![first, second];
    let triggers = Trigger::ALL.to_vec();
    FallbackEntryV1::new(key, primary, candidates, triggers, Mode::Manual)
}

#[test]
fn implementation_key_and_pin_bounds() -> TestResult<()> {
    let digest = Hash::zero();
    for (plugin_id, version, expected) in [
        (String::new(), "1".to_owned(), F::PluginId),
        ("p".repeat(129), "1".to_owned(), F::PluginId),
        ("p".to_owned(), String::new(), F::Version),
        ("p".to_owned(), "v".repeat(65), F::Version),
    ] {
        let result = ImplementationKeyV1::new(plugin_id, version, digest);
        assert_eq!(result, Err(bad(expected)));
    }
    let many: Vec<String> = (0..17).map(|role| format!("r{role}")).collect();
    for roles in [
        Vec::new(),
        many,
        vec!["a".to_owned(), "a".to_owned()],
        vec![String::new()],
        vec!["r".repeat(65)],
    ] {
        let result = CompositionPinV1::new(key_named("p")?, roles);
        assert_eq!(result, Err(bad(F::Roles)));
    }
    let widest = wide_pin("p")?;
    assert_eq!(widest.roles().len(), MAX_FALLBACK_ROLES_V1);
    Ok(())
}

#[test]
fn entry_bounds_and_distinctness() -> TestResult<()> {
    let long_key = "k".repeat(65);
    for key in ["", "a b", "geo/1", long_key.as_str()] {
        assert_eq!(entry_named(key, "a", "b"), Err(bad(F::EntryKey)));
    }
    let punctuated = entry_named("geo.v2-x_Y", "a", "b")?;
    assert_eq!(punctuated.entry_key(), "geo.v2-x_Y");
    assert_eq!(entry_named("geo", "a", "a"), Err(bad(F::Distinctness)));
    for candidates in [Vec::new(), vec![pin_named("b")?; 3]] {
        let result = entry_with(candidates, vec![Trigger::ArtifactRevoked]);
        assert_eq!(result, Err(bad(F::Candidates)));
    }
    let unsorted = vec![Trigger::WorkerCrashed, Trigger::ComponentTrap];
    for triggers in [Vec::new(), unsorted, vec![Trigger::ComponentTrap; 2]] {
        let result = entry_with(vec![pin_named("b")?], triggers);
        assert_eq!(result, Err(bad(F::Triggers)));
    }
    let chain = vec![pin_named("b")?, pin_named("c")?];
    let longest = entry_with(chain, Trigger::ALL.to_vec())?;
    assert_eq!(longest.candidates().len(), MAX_FALLBACK_CANDIDATES_V1);
    Ok(())
}

#[test]
fn policy_bounds_and_distinctness() -> TestResult<()> {
    let entry = entry_named("geo", "a", "b")?;
    for scope in [String::new(), "s".repeat(129)] {
        let result = DomainFallbackPolicyV1::new(scope, vec![entry.clone()], None);
        assert_eq!(result, Err(bad(F::Scope)));
    }
    let duplicate = vec![entry.clone(), entry.clone()];
    let unsorted = vec![entry_named("map", "c", "d")?, entry.clone()];
    let too_many = (0..33).map(numbered_entry).collect::<Record<Vec<_>>>()?;
    let shared = entry_named("map", "a", "d")?;
    for (entries, expected) in [
        (unsorted, F::Entries),
        (duplicate, F::Entries),
        (too_many, F::Entries),
        (vec![entry, shared], F::Distinctness),
    ] {
        let result = DomainFallbackPolicyV1::new("s".into(), entries, None);
        assert_eq!(result, Err(bad(expected)));
    }
    let entries = (0..32).map(numbered_entry).collect::<Record<Vec<_>>>()?;
    let full = DomainFallbackPolicyV1::new("s".into(), entries, None)?;
    assert_eq!(full.entries().len(), MAX_FALLBACK_ENTRIES_V1);
    Ok(())
}

#[test]
fn payload_bounds() -> TestResult<()> {
    let zero = Hash::zero();
    let bad_key = FallbackRebasedEntryV1::new("a b".into(), zero);
    assert_eq!(bad_key, Err(bad(F::EntryKey)));
    let unsorted = vec![numbered_pair(1)?, numbered_pair(0)?];
    let too_many = (0..33).map(numbered_pair).collect::<Record<Vec<_>>>()?;
    for (scope, rebased, expected) in [
        (String::new(), Vec::new(), F::Scope),
        ("s".to_owned(), unsorted, F::Rebased),
        ("s".to_owned(), too_many, F::Rebased),
    ] {
        let result = FallbackDeclaredPayloadV1::new(scope, zero, None, rebased);
        assert_eq!(result, Err(bad(expected)));
    }
    let skipped = activated_input()?.skipped[0];
    let mut cases = Vec::new();
    let mut input = activated_input()?;
    input.scope = String::new();
    cases.push((input, F::Scope));
    let mut input = activated_input()?;
    input.entry_key = "a b".into();
    cases.push((input, F::EntryKey));
    let mut input = activated_input()?;
    input.skipped = vec![skipped; 3];
    cases.push((input, F::Skipped));
    let mut input = activated_input()?;
    input.to = primary_key()?;
    cases.push((input, F::Implementation));
    for (input, expected) in cases {
        assert_eq!(FallbackActivatedPayloadV1::new(input), Err(bad(expected)));
    }
    Ok(())
}

#[test]
fn maximal_records_meet_their_bounds() -> TestResult<()> {
    let key_len = wide_key("k")?.to_canonical_cbor().len();
    assert_eq!(key_len, MAX_IMPLEMENTATION_KEY_BYTES_V1);
    let pin_len = wide_pin("k")?.to_canonical_cbor().len();
    assert_eq!(pin_len, MAX_COMPOSITION_PIN_BYTES_V1);
    let entry_len = wide_entry(0)?.to_canonical_cbor().len();
    assert_eq!(entry_len, MAX_FALLBACK_ENTRY_BYTES_V1);
    let zero = Hash::zero();
    let entries = (0..32).map(wide_entry).collect::<Record<Vec<_>>>()?;
    let policy = DomainFallbackPolicyV1::new("s".repeat(128), entries, Some(zero))?;
    let bytes = policy.to_canonical_cbor();
    assert_eq!(bytes.len(), 127_503);
    assert!(bytes.len() <= MAX_FALLBACK_POLICY_BYTES_V1);
    let decoded = DomainFallbackPolicyV1::from_canonical_cbor(&bytes)?;
    assert_eq!(decoded, policy);
    let rebased = (0..32).map(numbered_pair).collect::<Record<Vec<_>>>()?;
    let declared = FallbackDeclaredPayloadV1::new("s".repeat(128), zero, Some(zero), rebased)?;
    let bytes = declared.to_canonical_cbor();
    assert_eq!(bytes.len(), 3_433);
    let decoded = FallbackDeclaredPayloadV1::from_canonical_cbor(&bytes)?;
    assert_eq!(decoded, declared);
    let skipped = FallbackSkippedCandidateV1 {
        implementation_digest: zero,
        reason: Reason::SwapRefused,
    };
    let activated = FallbackActivatedPayloadV1::new(FallbackActivatedInputV1 {
        scope: "s".repeat(128),
        policy_digest: zero,
        entry_key: "k".repeat(64),
        closing_tenure_ordinal: u64::MAX,
        from: wide_key("a")?,
        to: wide_key("b")?,
        skipped: vec![skipped; 2],
        trigger_code: Trigger::WorkerCrashed,
        trigger_basis: FallbackTriggerBasisV1 {
            cause: u16::MAX,
            origin: Origin::Owner,
        },
        activation_ordinal: u64::MAX,
    })?;
    let bytes = activated.to_canonical_cbor();
    assert_eq!(bytes.len(), 805);
    let decoded = FallbackActivatedPayloadV1::from_canonical_cbor(&bytes)?;
    assert_eq!(decoded, activated);
    Ok(())
}

#[test]
fn closed_codes_round_trip() {
    let triggers: Vec<u8> = Trigger::ALL.into_iter().map(Trigger::code).collect();
    assert_eq!(triggers, [1, 2, 3, 4, 5]);
    let reasons: Vec<u8> = Reason::ALL.into_iter().map(Reason::code).collect();
    assert_eq!(reasons, [1, 2, 3, 4, 5, 6]);
    assert_eq!(Mode::ALL.map(Mode::code), [0, 1]);
    assert_eq!(Origin::ALL.map(Origin::code), [0, 1]);
    for trigger in Trigger::ALL {
        assert_eq!(Trigger::from_code(trigger.code()), Some(trigger));
    }
    for reason in Reason::ALL {
        assert_eq!(Reason::from_code(reason.code()), Some(reason));
    }
    for mode in Mode::ALL {
        assert_eq!(Mode::from_code(mode.code()), Some(mode));
    }
    for origin in Origin::ALL {
        assert_eq!(Origin::from_code(origin.code()), Some(origin));
    }
    assert_eq!(Trigger::from_code(0), None);
    assert_eq!(Reason::from_code(0), None);
    assert_eq!(Mode::from_code(2), None);
    assert_eq!(Origin::from_code(2), None);
}

#[test]
fn errors_and_records_render() -> TestResult<()> {
    let fields = [
        F::PluginId,
        F::Version,
        F::Roles,
        F::EntryKey,
        F::Candidates,
        F::Triggers,
        F::ActivationMode,
        F::Distinctness,
        F::Scope,
        F::Entries,
        F::Rebased,
        F::Skipped,
        F::SkipReason,
        F::TriggerCode,
        F::TriggerOrigin,
        F::Implementation,
    ];
    for field in fields {
        let message = bad(field).to_string();
        assert!(message.contains(&format!("{field:?}")), "{message}");
    }
    let too_large = FallbackRecordErrorV1::TooLarge;
    let mismatch = FallbackRecordErrorV1::PolicyDigestMismatch;
    for error in [ENCODING, NONCANONICAL, too_large, mismatch] {
        assert!(!error.to_string().is_empty(), "{error:?}");
    }
    let policy = golden_policy()?;
    assert!(format!("{policy:?}").contains("session.alpha"));
    let payload = FallbackActivatedPayloadV1::new(activated_input()?)?;
    assert!(format!("{payload:?}").contains("org.example.geo-lite"));
    let rebased = FallbackRebasedEntryV1::new("geo".into(), Hash::zero())?;
    let declared = FallbackDeclaredPayloadV1::for_policy(&policy, vec![rebased])?;
    assert!(format!("{declared:?}").contains("geo"));
    Ok(())
}
