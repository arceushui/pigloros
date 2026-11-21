//! ADR-129 §4 CES1 (revision 9, R9.1) and the closed source catalogue
//! (owner 2026-11-21 (#560), item (f)) at their public seam.
//!
//! Every expected wire is built independently with `ciborium` from the ADR
//! field list, every digest from the `H(record)` rule with `blake3`, and the
//! key-dependency list is compared with an ARD1 of the same list.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityEventSourceInputV1 as Input, CommunityEventSourceV1 as Source,
    CommunityLifecycleErrorV1 as Error, CommunitySourceCatalogueV1 as Catalogue,
    CommunitySourceSchemaRuleV1 as Rule, COMMUNITY_NATIVE_EVENT_EXTRACTOR_RULE_V1,
    MAX_COMMUNITY_EVENT_SOURCE_BYTES_V1, MAX_COMMUNITY_EVENT_SOURCE_KEYS_V1,
    MAX_COMMUNITY_SOURCE_CATALOGUE_ROWS_V1, MAX_COMMUNITY_SOURCE_RULE_TEXT_BYTES_V1,
};
use pos_core::{
    ArtifactDataClassV1, ArtifactKeyDependencyV1, ArtifactOptionalityV1,
    ArtifactRegistrationFieldsV1, ArtifactRegistrationV1, ArtifactTransitionRuleV1,
    ErasureArtifactClassV1, Hash, KeyIdentityV1, KeyRoleV1, OwnerIdV1, TimelineId,
};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

const fn timeline() -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes([4; 16]))
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out)?;
    Ok(out)
}

fn adr_h(magic: &str, bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(format!("PiglorOS.Community.{magic}.v1\0").as_bytes());
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

const RULE: Rule<'static> = Rule {
    event_type: "world.action",
    schema_version: 1,
    extractor_rule: "pos.community.native-event",
    extractor_rule_version: 1,
};

fn key(epoch: u64, role: KeyRoleV1) -> Fallible<ArtifactKeyDependencyV1> {
    Ok(ArtifactKeyDependencyV1 {
        identity: KeyIdentityV1::new(OwnerIdV1::new("owner-a")?, role, epoch),
        material_digest: hash(0x40),
        private_material_required: epoch.is_multiple_of(2),
    })
}

fn keys(count: u64) -> Fallible<Vec<ArtifactKeyDependencyV1>> {
    (1..=count)
        .map(|epoch| key(epoch, KeyRoleV1::CommunityArtifactEncryption))
        .collect()
}

const fn input(keys: Vec<ArtifactKeyDependencyV1>) -> Input<'static> {
    Input {
        timeline: timeline(),
        logical_seq: 3,
        event_id: [5; 16],
        payload_hash: hash(6),
        event_envelope_digest: hash(7),
        owner_reference: hash(8),
        source_scope_binding_digest: hash(9),
        source_schema_rule: RULE,
        required_key_dependencies: keys,
        admitted_policy_digest: hash(10),
        evidence_not_after_micros: 1_000,
    }
}

fn key_value(key: &ArtifactKeyDependencyV1) -> Value {
    Value::Array(vec![
        text(key.identity.owner_id.as_str()),
        uint(u64::from(key.identity.role.code())),
        uint(key.identity.epoch),
        bytes(key.material_digest.as_bytes()),
        Value::Bool(key.private_material_required),
    ])
}

fn expected(keys: &[ArtifactKeyDependencyV1]) -> Value {
    Value::Array(vec![
        bytes(b"CES1"),
        uint(1),
        bytes(&[4; 16]),
        uint(3),
        bytes(&[5; 16]),
        bytes(&[6; 32]),
        bytes(&[7; 32]),
        bytes(&[8; 32]),
        bytes(&[9; 32]),
        Value::Array(vec![
            text("world.action"),
            uint(1),
            text("pos.community.native-event"),
            uint(1),
        ]),
        Value::Array(keys.iter().map(key_value).collect()),
        bytes(&[10; 32]),
        uint(1_000),
    ])
}

fn fields(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    value.as_array_mut().ok_or_else(|| "array".into())
}

fn decode_error(value: &Value) -> Fallible<Option<Error>> {
    Ok(Source::from_canonical_cbor(&encode(value)?).err())
}

#[test]
fn ces1_has_the_exact_wire_digest_and_roundtrips() -> TestResult {
    let keys = vec![
        key(1, KeyRoleV1::SubjectDataEncryption)?,
        key(2, KeyRoleV1::CommunityArtifactEncryption)?,
    ];
    let source = Source::new(input(keys.clone()))?;
    let wire = encode(&expected(&keys))?;
    assert_eq!(source.to_canonical_cbor().as_slice(), wire.as_slice());
    assert_eq!(source.digest(), adr_h("CES1", &wire));
    let decoded = Source::from_canonical_cbor(&wire)?;
    assert_eq!(decoded.as_input(), source.as_input());
    assert_eq!(decoded, source);
    Ok(())
}

#[test]
fn key_dependencies_use_the_ard1_encoding_and_bound() -> TestResult {
    let pair = vec![
        key(1, KeyRoleV1::SubjectDataEncryption)?,
        key(2, KeyRoleV1::CommunityArtifactEncryption)?,
    ];
    let registration = ArtifactRegistrationV1::new(ArtifactRegistrationFieldsV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: hash(1),
        owner_reference: hash(2),
        data_class: ArtifactDataClassV1::PrivateSubjectData,
        optionality: ArtifactOptionalityV1::Required,
        transition_rule: ArtifactTransitionRuleV1::Remove,
        required_key_roles: vec![
            KeyRoleV1::SubjectDataEncryption,
            KeyRoleV1::CommunityArtifactEncryption,
        ],
        key_dependencies: pair.clone(),
        child_artifacts: Vec::new(),
    })?;
    let list = encode(&Value::Array(pair.iter().map(key_value).collect()))?;
    let ces1 = Source::new(input(pair))?.to_canonical_cbor();
    let contains = |haystack: &[u8]| haystack.windows(list.len()).any(|window| window == list);
    assert!(contains(registration.canonical_cbor()));
    assert!(contains(&ces1));
    // 2,048 keys are admitted and roundtrip; 2,049 are refused at both
    // construction and decoding.
    assert_eq!(MAX_COMMUNITY_EVENT_SOURCE_KEYS_V1, 2048);
    let full = Source::new(input(keys(2048)?))?;
    assert_eq!(
        Source::from_canonical_cbor(&full.to_canonical_cbor())?.as_input(),
        full.as_input()
    );
    assert_eq!(
        Source::new(input(keys(2049)?)).err(),
        Some(Error::BoundsExceeded)
    );
    assert_eq!(
        decode_error(&expected(&keys(2049)?))?,
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn unsorted_repeated_and_epoch_zero_keys_are_refused() -> TestResult {
    let one = key(1, KeyRoleV1::CommunityArtifactEncryption)?;
    let two = key(2, KeyRoleV1::CommunityArtifactEncryption)?;
    for keys in [
        vec![two, one],
        vec![one, one],
        vec![key(0, KeyRoleV1::CommunityArtifactEncryption)?],
    ] {
        assert_eq!(
            Source::new(input(keys.clone())).err(),
            Some(Error::InvalidBinding)
        );
        assert_eq!(decode_error(&expected(&keys))?, Some(Error::InvalidBinding));
    }
    Ok(())
}

#[test]
fn every_identity_is_required_and_the_horizon_is_bounded() {
    type Edit = fn(&mut Input<'static>);
    let edits: [Edit; 8] = [
        |input| input.timeline = TimelineId::from_ulid(ulid::Ulid::from_bytes([0; 16])),
        |input| input.logical_seq = 0,
        |input| input.event_id = [0; 16],
        |input| input.payload_hash = Hash::zero(),
        |input| input.event_envelope_digest = Hash::zero(),
        |input| input.owner_reference = Hash::zero(),
        |input| input.source_scope_binding_digest = Hash::zero(),
        |input| input.admitted_policy_digest = Hash::zero(),
    ];
    for edit in edits {
        let mut changed = input(Vec::new());
        edit(&mut changed);
        assert_eq!(Source::new(changed).err(), Some(Error::InvalidBinding));
    }
    for horizon in [0, u64::MAX / 2 + 1] {
        let mut changed = input(Vec::new());
        changed.evidence_not_after_micros = horizon;
        assert_eq!(Source::new(changed).err(), Some(Error::BoundsExceeded));
    }
}

#[test]
fn schema_rule_texts_are_bounded_and_the_extractor_rule_follows_the_id_grammar() {
    assert_eq!(MAX_COMMUNITY_SOURCE_RULE_TEXT_BYTES_V1, 128);
    let long = "a".repeat(128);
    let over = "a".repeat(129);
    let long: &'static str = Box::leak(long.into_boxed_str());
    let over: &'static str = Box::leak(over.into_boxed_str());
    let with = |rule: Rule<'static>| {
        let mut changed = input(Vec::new());
        changed.source_schema_rule = rule;
        Source::new(changed).map(|source| source.to_canonical_cbor().len())
    };
    assert!(with(Rule {
        event_type: long,
        extractor_rule: long,
        ..RULE
    })
    .is_ok());
    for (rule, error) in [
        (
            Rule {
                event_type: "",
                ..RULE
            },
            Error::InvalidBinding,
        ),
        (
            Rule {
                event_type: over,
                ..RULE
            },
            Error::BoundsExceeded,
        ),
        (
            Rule {
                extractor_rule: over,
                ..RULE
            },
            Error::BoundsExceeded,
        ),
        (
            Rule {
                extractor_rule: "",
                ..RULE
            },
            Error::InvalidBinding,
        ),
        (
            Rule {
                extractor_rule: "Pos.Upper",
                ..RULE
            },
            Error::InvalidBinding,
        ),
    ] {
        assert_eq!(with(rule).err(), Some(error));
    }
}

#[test]
fn decoding_refuses_malformed_versioned_oversized_and_trailing_records() -> TestResult {
    let keys = vec![key(1, KeyRoleV1::CommunityArtifactEncryption)?];
    let wire = encode(&expected(&keys))?;
    let mut trailing = wire.clone();
    trailing.push(0);
    assert_eq!(
        Source::from_canonical_cbor(&trailing).err(),
        Some(Error::InvalidEncoding)
    );
    for end in 0..wire.len() {
        assert!(Source::from_canonical_cbor(&wire[..end]).is_err());
    }
    let mut versioned = expected(&keys);
    fields(&mut versioned)?[1] = uint(2);
    assert_eq!(decode_error(&versioned)?, Some(Error::UnsupportedVersion));
    assert_eq!(
        Source::from_canonical_cbor(&vec![0; MAX_COMMUNITY_EVENT_SOURCE_BYTES_V1 + 1]).err(),
        Some(Error::BoundsExceeded)
    );
    let edits: [(usize, Value, Error); 3] = [
        (
            9,
            Value::Array(vec![text("world.action"), uint(1), text("rule")]),
            Error::InvalidEncoding,
        ),
        (
            9,
            Value::Array(vec![
                text("world.action"),
                uint(u64::from(u32::MAX) + 1),
                text("rule"),
                uint(1),
            ]),
            Error::BoundsExceeded,
        ),
        (
            9,
            Value::Array(vec![
                text("world.action"),
                uint(1),
                text("rule"),
                uint(u64::from(u32::MAX) + 1),
            ]),
            Error::BoundsExceeded,
        ),
    ];
    for (field, value, error) in edits {
        let mut changed = expected(&keys);
        fields(&mut changed)?[field] = value;
        assert_eq!(decode_error(&changed)?, Some(error));
    }
    // Key rows: an unknown role, an over-wide role code, an invalid owner
    // text, a non-boolean flag and a short row.
    let row = |owner: Value, role: Value, flag: Value| {
        Value::Array(vec![owner, role, uint(1), bytes(&[0x40; 32]), flag])
    };
    for bad in [
        row(text("owner-a"), uint(8), Value::Bool(true)),
        row(text("owner-a"), uint(256), Value::Bool(true)),
        row(text(""), uint(7), Value::Bool(true)),
        row(text("owner-a"), uint(7), uint(1)),
        Value::Array(vec![text("owner-a"), uint(7)]),
    ] {
        let mut changed = expected(&keys);
        fields(&mut changed)?[10] = Value::Array(vec![bad]);
        assert_eq!(decode_error(&changed)?, Some(Error::InvalidEncoding));
    }
    let mut false_flag = expected(&keys);
    fields(&mut false_flag)?[10] =
        Value::Array(vec![row(text("owner-a"), uint(7), Value::Bool(false))]);
    let false_wire = encode(&false_flag)?;
    let decoded = Source::from_canonical_cbor(&false_wire)?;
    assert!(!decoded.as_input().required_key_dependencies[0].private_material_required);
    Ok(())
}

#[test]
fn the_source_catalogue_is_closed_sorted_and_digested() -> TestResult {
    assert_eq!(
        COMMUNITY_NATIVE_EVENT_EXTRACTOR_RULE_V1,
        ("pos.community.native-event", 1)
    );
    let rows = [
        Rule {
            event_type: "a.event",
            ..RULE
        },
        Rule {
            event_type: "a.event",
            schema_version: 2,
            ..RULE
        },
        RULE,
    ];
    let catalogue = Catalogue::new(&rows)?;
    let preimage = encode(&Value::Array(
        rows.iter()
            .map(|row| {
                Value::Array(vec![
                    text(row.event_type),
                    uint(u64::from(row.schema_version)),
                    text(row.extractor_rule),
                    uint(u64::from(row.extractor_rule_version)),
                ])
            })
            .collect(),
    ))?;
    assert_eq!(catalogue.digest(), adr_h("SourceCatalogue", &preimage));
    assert_eq!(catalogue.rule("world.action", 1), Some(RULE));
    assert_eq!(catalogue.rule("a.event", 2), Some(rows[1]));
    assert_eq!(catalogue.rule("world.action", 2), None);
    assert_eq!(catalogue.rule("b.event", 1), None);
    assert_eq!(
        Catalogue::new(&[])?.digest(),
        adr_h("SourceCatalogue", &[0x80])
    );
    for invalid in [[rows[1], rows[0]], [rows[0], rows[0]], [rows[2], rows[0]]] {
        assert_eq!(Catalogue::new(&invalid).err(), Some(Error::InvalidBinding));
    }
    assert_eq!(
        Catalogue::new(&[Rule {
            event_type: "",
            ..RULE
        }])
        .err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn the_source_catalogue_holds_at_most_4096_rows() -> TestResult {
    assert_eq!(MAX_COMMUNITY_SOURCE_CATALOGUE_ROWS_V1, 4096);
    let rows: Vec<Rule<'static>> = (0..=4096_u32)
        .map(|schema_version| Rule {
            schema_version,
            ..RULE
        })
        .collect();
    let catalogue = Catalogue::new(&rows[..4096])?;
    assert_eq!(catalogue.rule("world.action", 4095), Some(rows[4095]));
    assert_eq!(catalogue.rule("world.action", 0), Some(rows[0]));
    assert_eq!(catalogue.rule("world.action", 4096), None);
    assert_eq!(Catalogue::new(&rows).err(), Some(Error::BoundsExceeded));
    Ok(())
}
