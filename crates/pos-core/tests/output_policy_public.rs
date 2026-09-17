use ciborium::value::Value;
use pos_core::output_policy::{
    OutputAuthorityV1, OutputDeclarationV1, OutputFidelityV1, OutputPolicyErrorV1,
    OutputPolicyInputV1, OutputPolicyV1,
};
use pos_core::{Hash, PluginId};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn input(declarations: Vec<OutputDeclarationV1>) -> OutputPolicyInputV1 {
    OutputPolicyInputV1 {
        plugin_id: PluginId::from_ulid(ulid::Ulid::from(7u128)),
        plugin_version: "1.0".to_owned(),
        implementation_hash: Hash::from_bytes([1; 32]),
        base_configuration_digest: Hash::from_bytes([2; 32]),
        executable_profile_hash: Hash::from_bytes([3; 32]),
        retention_policy_hash: Hash::from_bytes([4; 32]),
        policy_revision: 1,
        output_declarations: declarations,
    }
}

fn declaration(kind: &str) -> Result<OutputDeclarationV1, OutputPolicyErrorV1> {
    OutputDeclarationV1::new(kind.to_owned(), OutputAuthorityV1::Authoritative,
        OutputFidelityV1::L0, 4096, None, None)
}

fn encode(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn replace(value: &mut Value, path: &[usize], replacement: Value) -> TestResult {
    if let Some((index, tail)) = path.split_first() {
        let Value::Array(fields) = value else { return Err("fixture is not an array".into()); };
        let field = fields.get_mut(*index).ok_or("missing fixture field")?;
        replace(field, tail, replacement)
    } else {
        *value = replacement;
        Ok(())
    }
}

#[test]
fn canonical_encoding_and_domain_digest_match_independent_oracles() -> TestResult {
    let policy = OutputPolicyV1::new(input(vec![declaration("world.obs.v1")?]))?;
    let independent = Value::Array(vec![Value::Bytes(b"EOP1".to_vec()), Value::Integer(1.into()),
        Value::Bytes(7u128.to_be_bytes().to_vec()), Value::Text("1.0".to_owned()),
        Value::Bytes(vec![1; 32]), Value::Bytes(vec![2; 32]), Value::Bytes(vec![3; 32]),
        Value::Bytes(vec![4; 32]), Value::Integer(1.into()), Value::Array(vec![Value::Array(vec![
            Value::Text("world.obs.v1".to_owned()), Value::Integer(0.into()), Value::Integer(0.into()),
            Value::Integer(4096.into()), Value::Null, Value::Null])])]);
    let bytes = encode(&independent)?;
    assert_eq!(policy.to_canonical_cbor(), bytes);
    assert_eq!(OutputPolicyV1::from_canonical_cbor(&bytes)?, policy);
    let mut preimage = b"pigloros.output-policy.v1\0".to_vec();
    preimage.extend_from_slice(&bytes);
    assert_eq!(policy.digest().as_bytes(), blake3::hash(&preimage).as_bytes());
    assert_eq!(policy.fields().plugin_id, input(Vec::new()).plugin_id);
    let row = &policy.fields().output_declarations[0];
    assert_eq!(row.event_type(), "world.obs.v1");
    assert_eq!(row.authority(), OutputAuthorityV1::Authoritative);
    assert_eq!(row.fidelity(), OutputFidelityV1::L0);
    assert_eq!(row.max_bytes(), 4096);
    assert_eq!(row.stride_ticks(), None);
    assert_eq!(row.aggregate_min_group(), None);
    Ok(())
}

#[test]
fn empty_policy_and_every_integer_width_roundtrip() -> TestResult {
    let empty = OutputPolicyV1::new(input(Vec::new()))?;
    assert_eq!(OutputPolicyV1::from_canonical_cbor(&empty.to_canonical_cbor())?, empty);
    for number in [1, 23, 24, 255, 256, 65_535, 65_536, u32::MAX] {
        let row = OutputDeclarationV1::new("view".to_owned(), OutputAuthorityV1::ReproducibleDerived,
            OutputFidelityV1::L2, number, None, Some(number.max(10)))?;
        let mut fields = input(vec![row]);
        fields.policy_revision = number;
        let policy = OutputPolicyV1::new(fields)?;
        assert_eq!(OutputPolicyV1::from_canonical_cbor(&policy.to_canonical_cbor())?, policy);
    }
    Ok(())
}

#[test]
fn declaration_counts_and_utf8_bounds_are_exact() -> TestResult {
    for count in [1, 23, 24, 255, 256] {
        let declarations = (0..count).map(|index| declaration(&format!("{index:03}{}", "x".repeat(125))))
            .collect::<Result<Vec<_>, _>>()?;
        let mut fields = input(declarations);
        fields.plugin_version = "é".repeat(32);
        let policy = OutputPolicyV1::new(fields)?;
        assert_eq!(OutputPolicyV1::from_canonical_cbor(&policy.to_canonical_cbor())?, policy);
    }
    let over = (0..257).map(|index| declaration(&format!("{index:03}"))).collect::<Result<Vec<_>, _>>()?;
    assert_eq!(OutputPolicyV1::new(input(over)), Err(OutputPolicyErrorV1::FieldOutOfBounds));
    for kind in ["".to_owned(), "é".repeat(65)] {
        assert_eq!(declaration(&kind), Err(OutputPolicyErrorV1::FieldOutOfBounds));
    }
    let unicode = declaration(&"é".repeat(64))?;
    assert_eq!(unicode.event_type().len(), 128);
    for version in [String::new(), "v".repeat(65)] {
        let mut fields = input(Vec::new()); fields.plugin_version = version;
        assert_eq!(OutputPolicyV1::new(fields), Err(OutputPolicyErrorV1::FieldOutOfBounds));
    }
    Ok(())
}

#[test]
fn fidelity_and_authority_rules_cannot_be_defaulted() -> TestResult {
    for authority in [OutputAuthorityV1::Authoritative, OutputAuthorityV1::ReproducibleDerived,
        OutputAuthorityV1::Ephemeral] {
        for (level, stride, group) in [(OutputFidelityV1::L0, None, None),
            (OutputFidelityV1::L1, Some(32), None), (OutputFidelityV1::L2, None, Some(10))] {
            let result = OutputDeclarationV1::new("output".to_owned(), authority, level, 1, stride, group);
            if authority == OutputAuthorityV1::Authoritative && level != OutputFidelityV1::L0 {
                assert_eq!(result, Err(OutputPolicyErrorV1::IncompatibleDeclaration));
            } else {
                let row = result?;
                assert_eq!(row.stride_ticks(), stride);
                assert_eq!(row.aggregate_min_group(), group);
                let policy = OutputPolicyV1::new(input(vec![row]))?;
                assert_eq!(OutputPolicyV1::from_canonical_cbor(&policy.to_canonical_cbor())?, policy);
            }
        }
    }
    for (level, stride, group) in [(OutputFidelityV1::L0, Some(1), None),
        (OutputFidelityV1::L0, None, Some(10)), (OutputFidelityV1::L1, None, None),
        (OutputFidelityV1::L1, Some(0), None), (OutputFidelityV1::L1, Some(33), None),
        (OutputFidelityV1::L1, Some(1), Some(10)), (OutputFidelityV1::L2, None, None),
        (OutputFidelityV1::L2, None, Some(9)), (OutputFidelityV1::L2, Some(1), Some(10))] {
        assert_eq!(OutputDeclarationV1::new("output".to_owned(), OutputAuthorityV1::ReproducibleDerived,
            level, 1, stride, group), Err(OutputPolicyErrorV1::IncompatibleDeclaration));
    }
    assert_eq!(OutputDeclarationV1::new("output".to_owned(), OutputAuthorityV1::Authoritative,
        OutputFidelityV1::L0, 0, None, None), Err(OutputPolicyErrorV1::FieldOutOfBounds));
    Ok(())
}

#[test]
fn duplicates_order_zero_references_and_revision_are_rejected() -> TestResult {
    for kinds in [["a", "a"], ["b", "a"]] {
        assert_eq!(OutputPolicyV1::new(input(vec![declaration(kinds[0])?, declaration(kinds[1])?])),
            Err(OutputPolicyErrorV1::NonCanonical));
    }
    for position in 0..5 {
        let mut fields = input(Vec::new());
        match position { 0 => fields.implementation_hash = Hash::zero(),
            1 => fields.base_configuration_digest = Hash::zero(),
            2 => fields.executable_profile_hash = Hash::zero(),
            3 => fields.retention_policy_hash = Hash::zero(), _ => fields.policy_revision = 0 }
        assert_eq!(OutputPolicyV1::new(fields), Err(OutputPolicyErrorV1::FieldOutOfBounds));
    }
    Ok(())
}

#[test]
fn every_record_field_mutation_changes_identity() -> TestResult {
    let base = input(vec![declaration("a")?]);
    let digest = OutputPolicyV1::new(base.clone())?.digest();
    for position in 0..8 {
        let mut changed = base.clone();
        match position { 0 => changed.plugin_id = PluginId::from_ulid(ulid::Ulid::from(8u128)),
            1 => changed.plugin_version = "2.0".to_owned(),
            2 => changed.implementation_hash = Hash::from_bytes([5; 32]),
            3 => changed.base_configuration_digest = Hash::from_bytes([5; 32]),
            4 => changed.executable_profile_hash = Hash::from_bytes([5; 32]),
            5 => changed.retention_policy_hash = Hash::from_bytes([5; 32]),
            6 => changed.policy_revision = 2, _ => changed.output_declarations = vec![declaration("b")?] }
        assert_ne!(OutputPolicyV1::new(changed)?.digest(), digest);
    }
    for row in [OutputDeclarationV1::new("a".to_owned(), OutputAuthorityV1::Ephemeral,
        OutputFidelityV1::L0, 4096, None, None)?, declaration("b")?,
        OutputDeclarationV1::new("a".to_owned(), OutputAuthorityV1::Authoritative,
            OutputFidelityV1::L0, 4095, None, None)?] {
        assert_ne!(OutputPolicyV1::new(input(vec![row]))?.digest(), digest);
    }
    Ok(())
}

#[test]
fn malformed_wire_fields_reject_through_public_decoder() -> TestResult {
    let bytes = OutputPolicyV1::new(input(vec![declaration("a")?]))?.to_canonical_cbor();
    let base: Value = ciborium::from_reader(bytes.as_slice())?;
    for (path, replacement, error) in [
        (vec![0], Value::Bytes(b"BAD1".to_vec()), OutputPolicyErrorV1::InvalidEncoding),
        (vec![1], Value::Integer(2.into()), OutputPolicyErrorV1::UnsupportedValue),
        (vec![2], Value::Bytes(vec![7; 15]), OutputPolicyErrorV1::InvalidEncoding),
        (vec![3], Value::Text(String::new()), OutputPolicyErrorV1::FieldOutOfBounds),
        (vec![3], Value::Text("v".repeat(65)), OutputPolicyErrorV1::FieldOutOfBounds),
        (vec![4], Value::Bytes(vec![1; 33]), OutputPolicyErrorV1::FieldOutOfBounds),
        (vec![8], Value::Integer(u64::MAX.into()), OutputPolicyErrorV1::FieldOutOfBounds),
        (vec![9, 0, 0], Value::Text("x".repeat(129)), OutputPolicyErrorV1::FieldOutOfBounds),
        (vec![9, 0, 1], Value::Integer(3.into()), OutputPolicyErrorV1::UnsupportedValue),
        (vec![9, 0, 2], Value::Integer(3.into()), OutputPolicyErrorV1::UnsupportedValue),
        (vec![9, 0, 3], Value::Integer(0.into()), OutputPolicyErrorV1::FieldOutOfBounds),
        (vec![9, 0, 4], Value::Integer(1.into()), OutputPolicyErrorV1::IncompatibleDeclaration),
        (vec![9, 0, 5], Value::Integer(10.into()), OutputPolicyErrorV1::IncompatibleDeclaration),
    ] {
        let mut value = base.clone(); replace(&mut value, &path, replacement)?;
        assert_eq!(OutputPolicyV1::from_canonical_cbor(&encode(&value)?), Err(error));
    }
    for replacement in [Value::Map(Vec::new()), Value::Tag(1, Box::new(Value::Null)),
        Value::Float(1.0), Value::Integer((-1).into()), Value::Bool(true)] {
        let mut value = base.clone(); replace(&mut value, &[8], replacement)?;
        assert_eq!(OutputPolicyV1::from_canonical_cbor(&encode(&value)?), Err(OutputPolicyErrorV1::InvalidEncoding));
    }
    for count in [9, 11] {
        let mut value = base.clone();
        let Value::Array(fields) = &mut value else { return Err("fixture shape".into()); };
        if count == 9 { fields.pop(); } else { fields.push(Value::Null); }
        assert_eq!(OutputPolicyV1::from_canonical_cbor(&encode(&value)?), Err(OutputPolicyErrorV1::InvalidEncoding));
    }
    Ok(())
}

#[test]
fn truncation_nonpreferred_widths_and_outer_bounds_reject() -> TestResult {
    let bytes = OutputPolicyV1::new(input(vec![declaration("a")?]))?.to_canonical_cbor();
    for end in 0..bytes.len() { assert!(OutputPolicyV1::from_canonical_cbor(&bytes[..end]).is_err()); }
    for prefix in [vec![0x98, 10], vec![0x99, 0, 10], vec![0x9a, 0, 0, 0, 10],
        vec![0x9b, 0, 0, 0, 0, 0, 0, 0, 10]] {
        let mut malformed = prefix; malformed.extend_from_slice(&bytes[1..]);
        assert_eq!(OutputPolicyV1::from_canonical_cbor(&malformed), Err(OutputPolicyErrorV1::NonCanonical));
    }
    for initial in [0x9c, 0x9d, 0x9e, 0x9f, 0xff] {
        let mut malformed = bytes.clone(); malformed[0] = initial;
        assert_eq!(OutputPolicyV1::from_canonical_cbor(&malformed), Err(OutputPolicyErrorV1::InvalidEncoding));
    }
    let mut malformed = bytes.clone(); malformed[27] = 0xff;
    assert_eq!(OutputPolicyV1::from_canonical_cbor(&malformed), Err(OutputPolicyErrorV1::InvalidEncoding));
    let mut trailing = bytes; trailing.resize(65_536, 0);
    assert_eq!(OutputPolicyV1::from_canonical_cbor(&trailing), Err(OutputPolicyErrorV1::NonCanonical));
    trailing.push(0);
    assert_eq!(OutputPolicyV1::from_canonical_cbor(&trailing), Err(OutputPolicyErrorV1::FieldOutOfBounds));
    Ok(())
}
