//! ADR-116 witnesses through the public native registry read boundary.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use ciborium::Value;
use pos_core::{
    deletion_receipt, Hash, KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1,
    KeyRegistryReadErrorV1 as ReadError, KeyRegistryReadGuardV1, KeyRegistryReadRefusedV1,
    KeyRegistryReadWorkV1 as Work, KeyRegistryStateV1, KeyRoleV1, OwnerIdV1, PublicKey,
};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

struct Guard {
    remaining: usize,
    failed: bool,
    stop_at: Option<usize>,
    events: Vec<Work>,
}

impl Guard {
    const fn new(remaining: usize) -> Self {
        Self {
            remaining,
            failed: false,
            stop_at: None,
            events: Vec::new(),
        }
    }
}

impl KeyRegistryReadGuardV1 for Guard {
    fn observe(&mut self, work: Work) -> Result<(), KeyRegistryReadRefusedV1> {
        if self.failed {
            return Err(KeyRegistryReadRefusedV1);
        }
        let index = self.events.len();
        self.events.push(work);
        if self.stop_at == Some(index) {
            self.failed = true;
            return Err(KeyRegistryReadRefusedV1);
        }
        if let Work::MaterializeBytes(bytes) = work {
            if let Some(remaining) = self.remaining.checked_sub(bytes) {
                self.remaining = remaining;
            } else {
                self.failed = true;
                return Err(KeyRegistryReadRefusedV1);
            }
        }
        Ok(())
    }
}

fn encoded<T: serde::Serialize>(value: &T) -> Fallible<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn ordinary(bytes: &[u8]) -> Result<KeyRegistryStateV1, ReadError> {
    ciborium::from_reader(bytes)
        .map_err(|_| ReadError::InvalidSnapshot)
        .and_then(|state: KeyRegistryStateV1| {
            state
                .validate()
                .map(|()| state)
                .map_err(|_| ReadError::InvalidSnapshot)
        })
}

fn parity(bytes: &[u8]) -> Result<KeyRegistryStateV1, ReadError> {
    let mut guard = Guard::new(usize::MAX);
    let bounded = KeyRegistryStateV1::from_durable_cbor_with_read_guard(bytes, &mut guard);
    assert_eq!(bounded, ordinary(bytes));
    assert!(!guard.events.contains(&Work::MaterializeBytes(0)));
    assert!(!guard.failed);
    bounded
}

fn lifecycle(owner: &str, role: KeyRoleV1) -> Fallible<Vec<(KeyRegistryStateV1, usize)>> {
    let identity = KeyIdentityV1::from_parts(OwnerIdV1::new(owner)?, role, 1);
    let material = Hash::from_bytes([0x51; 32]);
    let key = role
        .is_signing()
        .then_some(PublicKey::from_bytes([0x52; 32]));
    let mut live = KeyRegistryStateV1::new();
    live.register_key(KeyRegistrationV1::new(identity, material, key))?;
    let request = KeyDestructionRequestV1::new(identity, material, Hash::from_bytes([0x53; 32]));
    let mut pending = live.clone();
    pending.begin_key_destruction(request)?;
    let mut destroyed = pending.clone();
    destroyed.complete_key_destruction(request, deletion_receipt(&request))?;

    // Literal ADR-116 field inventory, independent of guard output:
    // I = owner String + retained owner + role + epoch; S = owner + role;
    // D = temporary 32-byte buffer + retained 32-byte hash/key.
    let n = owner.len();
    let i = 2 * n + 1 + 8;
    let s = 2 * n + 1;
    let d = 32 + 32;
    let public = if role.is_signing() { d } else { 0 };
    let live_decode = 3 * i + 2 * s + d + public + 8 + 1;
    let terminal_decode = 4 * i + s + 3 * d + public + 8 + 1;
    Ok(vec![
        (KeyRegistryStateV1::new(), 1),
        (live, live_decode + 4 * n + 44),
        (pending, terminal_decode + 3 * n + 43),
        (destroyed, terminal_decode + 2 * n + 42),
    ])
}

const ROLES: [KeyRoleV1; 5] = [
    KeyRoleV1::SubjectDataEncryption,
    KeyRoleV1::SubjectAttributionSigning,
    KeyRoleV1::TimelineIntegritySigning,
    KeyRoleV1::PluginReleaseSigning,
    KeyRoleV1::ExportRecipientEncryption,
];

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn exact_native_units_cover_all_roles_lifecycles_and_max_utf8_owner() -> Fallible<()> {
    for owner in ["a".to_owned(), "é".repeat(64)] {
        for role in ROLES {
            for (state, required) in lifecycle(&owner, role)? {
                let bytes = encoded(&state)?;
                assert_eq!(parity(&bytes)?, state);
                for limit in [0, required - 1, required, required + 1] {
                    let mut guard = Guard::new(limit);
                    let actual =
                        KeyRegistryStateV1::from_durable_cbor_with_read_guard(&bytes, &mut guard);
                    if limit >= required {
                        assert_eq!(actual?, state);
                        assert_eq!(guard.remaining, limit - required);
                        assert!(!guard.failed);
                    } else {
                        assert_eq!(actual, Err(ReadError::ReadRefused));
                        assert!(guard.failed);
                    }
                    assert!(!guard.events.contains(&Work::MaterializeBytes(0)));
                }
            }
        }
    }
    // The independently specified one-live-signing fixture is exactly 224.
    assert_eq!(
        lifecycle("a", KeyRoleV1::TimelineIntegritySigning)?[1].1,
        224
    );
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn repeats_use_the_same_guard_without_reset_or_refund() -> Fallible<()> {
    for (state, required) in lifecycle("a", KeyRoleV1::TimelineIntegritySigning)? {
        let bytes = encoded(&state)?;
        for limit in [2 * required - 1, 2 * required] {
            let mut guard = Guard::new(limit);
            assert_eq!(
                KeyRegistryStateV1::from_durable_cbor_with_read_guard(&bytes, &mut guard)?,
                state
            );
            let second = KeyRegistryStateV1::from_durable_cbor_with_read_guard(&bytes, &mut guard);
            if limit == 2 * required {
                assert_eq!(second?, state);
                assert_eq!(guard.remaining, 0);
            } else {
                assert_eq!(second, Err(ReadError::ReadRefused));
                let observations = guard.events.len();
                assert_eq!(
                    KeyRegistryStateV1::from_durable_cbor_with_read_guard(&bytes, &mut guard),
                    Err(ReadError::ReadRefused)
                );
                assert_eq!(guard.events.len(), observations);
            }
        }
    }
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn every_public_factory_observation_can_refuse_without_following_work() -> Fallible<()> {
    for (state, required) in lifecycle("a", KeyRoleV1::TimelineIntegritySigning)? {
        let bytes = encoded(&state)?;
        let mut baseline = Guard::new(required);
        assert_eq!(
            KeyRegistryStateV1::from_durable_cbor_with_read_guard(&bytes, &mut baseline)?,
            state
        );
        for index in 0..baseline.events.len() {
            let mut guard = Guard::new(required);
            guard.stop_at = Some(index);
            assert_eq!(
                KeyRegistryStateV1::from_durable_cbor_with_read_guard(&bytes, &mut guard),
                Err(ReadError::ReadRefused)
            );
            assert_eq!(guard.events, baseline.events[..=index]);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Wire {
    Preferred,
    IndefiniteMaps,
    SegmentedOwners,
    NestedSegments,
    SegmentedBytes,
    NestedByteSegments,
    ByteArrays,
    IndefiniteByteArrays,
    Tagged,
    Wide,
    BigIntegers,
    ByteFieldNames,
    UndefinedOptions,
    ReverseMaps,
}

fn title(output: &mut Vec<u8>, major: u8, number: u64, wide: bool) -> Fallible<()> {
    let (minor, size) = if wide || number > u64::from(u32::MAX) {
        (27, 8)
    } else if number > u64::from(u16::MAX) {
        (26, 4)
    } else if number > u64::from(u8::MAX) {
        (25, 2)
    } else if number > 23 {
        (24, 1)
    } else {
        output.push((major << 5) | u8::try_from(number)?);
        return Ok(());
    };
    output.push((major << 5) | minor);
    output.extend_from_slice(&number.to_be_bytes()[8 - size..]);
    Ok(())
}

fn owner_text(text: &str) -> bool {
    text == "a" || text.starts_with('é')
}

fn wire(value: &Value, mode: Wire, output: &mut Vec<u8>) -> Fallible<()> {
    if mode == Wire::Tagged {
        title(output, 6, 42, false)?;
    }
    match value {
        Value::Map(fields) => wire_map(fields, mode, output),
        Value::Array(values) => {
            title(output, 4, u64::try_from(values.len())?, mode == Wire::Wide)?;
            for value in values {
                wire(value, mode, output)?;
            }
            Ok(())
        }
        Value::Text(text)
            if owner_text(text) && matches!(mode, Wire::SegmentedOwners | Wire::NestedSegments) =>
        {
            output.push(0x7f);
            if mode == Wire::NestedSegments {
                output.push(0x7f);
            }
            for character in text.chars() {
                let mut scratch = [0; 4];
                let chunk = character.encode_utf8(&mut scratch).as_bytes();
                title(output, 3, u64::try_from(chunk.len())?, false)?;
                output.extend_from_slice(chunk);
            }
            if mode == Wire::NestedSegments {
                output.push(0xff);
            }
            output.push(0xff);
            Ok(())
        }
        Value::Bytes(bytes)
            if matches!(
                mode,
                Wire::SegmentedBytes
                    | Wire::NestedByteSegments
                    | Wire::ByteArrays
                    | Wire::IndefiniteByteArrays
            ) =>
        {
            wire_bytes(bytes, mode, output)
        }
        Value::Integer(integer) if mode == Wire::BigIntegers => {
            let number = u64::try_from(*integer)?;
            title(output, 6, 2, false)?;
            title(output, 2, 8, false)?;
            output.extend_from_slice(&number.to_be_bytes());
            Ok(())
        }
        Value::Integer(integer) if mode == Wire::Wide => {
            title(output, 0, u64::try_from(*integer)?, true)
        }
        Value::Text(text) if mode == Wire::Wide => {
            title(output, 3, u64::try_from(text.len())?, true)?;
            output.extend_from_slice(text.as_bytes());
            Ok(())
        }
        Value::Bytes(bytes) if mode == Wire::Wide => {
            title(output, 2, u64::try_from(bytes.len())?, true)?;
            output.extend_from_slice(bytes);
            Ok(())
        }
        Value::Null if mode == Wire::UndefinedOptions => {
            output.push(0xf7);
            Ok(())
        }
        _ => ciborium::into_writer(value, output).map_err(Into::into),
    }
}

fn wire_bytes(bytes: &[u8], mode: Wire, output: &mut Vec<u8>) -> Fallible<()> {
    if matches!(mode, Wire::SegmentedBytes | Wire::NestedByteSegments) {
        output.push(0x5f);
        if mode == Wire::NestedByteSegments {
            output.push(0x5f);
        }
        for byte in bytes {
            output.extend_from_slice(&[0x41, *byte]);
        }
        if mode == Wire::NestedByteSegments {
            output.push(0xff);
        }
        output.push(0xff);
    } else {
        if mode == Wire::IndefiniteByteArrays {
            output.push(0x9f);
        } else {
            title(output, 4, u64::try_from(bytes.len())?, false)?;
        }
        for byte in bytes {
            title(output, 0, u64::from(*byte), false)?;
        }
        if mode == Wire::IndefiniteByteArrays {
            output.push(0xff);
        }
    }
    Ok(())
}

fn wire_map(fields: &[(Value, Value)], mode: Wire, output: &mut Vec<u8>) -> Fallible<()> {
    if mode == Wire::IndefiniteMaps {
        output.push(0xbf);
    } else {
        title(output, 5, u64::try_from(fields.len())?, mode == Wire::Wide)?;
    }
    for position in 0..fields.len() {
        let index = if mode == Wire::ReverseMaps {
            fields.len() - 1 - position
        } else {
            position
        };
        let (key, value) = &fields[index];
        if mode == Wire::ByteFieldNames {
            if let Value::Text(text) = key {
                wire(&Value::Bytes(text.as_bytes().to_vec()), mode, output)?;
            } else {
                wire(key, mode, output)?;
            }
        } else {
            wire(key, mode, output)?;
        }
        wire(value, mode, output)?;
    }
    if mode == Wire::IndefiniteMaps {
        output.push(0xff);
    }
    Ok(())
}

fn value(state: &KeyRegistryStateV1) -> Fallible<Value> {
    Ok(ciborium::from_reader(encoded(state)?.as_slice())?)
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn pinned_wire_variants_match_ordinary_loading_without_canonical_only_restrictions() -> Fallible<()>
{
    for owner in ["a".to_owned(), "é".repeat(64)] {
        for (state, required) in lifecycle(&owner, KeyRoleV1::TimelineIntegritySigning)? {
            let value = value(&state)?;
            for mode in [
                Wire::Preferred,
                Wire::IndefiniteMaps,
                Wire::SegmentedOwners,
                Wire::NestedSegments,
                Wire::SegmentedBytes,
                Wire::NestedByteSegments,
                Wire::ByteArrays,
                Wire::IndefiniteByteArrays,
                Wire::Tagged,
                Wire::Wide,
                Wire::BigIntegers,
                Wire::ByteFieldNames,
                Wire::UndefinedOptions,
                Wire::ReverseMaps,
            ] {
                let mut bytes = Vec::new();
                wire(&value, mode, &mut bytes)?;
                let result = parity(&bytes);
                if let Ok(decoded) = result {
                    assert_eq!(decoded, state);
                    let mut guard = Guard::new(required);
                    assert_eq!(
                        KeyRegistryStateV1::from_durable_cbor_with_read_guard(&bytes, &mut guard)?,
                        state
                    );
                    assert_eq!(guard.remaining, 0);
                }
            }
        }
    }
    Ok(())
}

fn fields(value: &mut Value) -> Fallible<&mut Vec<(Value, Value)>> {
    match value {
        Value::Map(fields) => Ok(fields),
        _ => Err("fixture map expected".into()),
    }
}

fn field<'value>(value: &'value mut Value, name: &str) -> Fallible<&'value mut Value> {
    fields(value)?
        .iter_mut()
        .find(|(key, _)| *key == Value::Text(name.to_owned()))
        .map(|(_, value)| value)
        .ok_or_else(|| "fixture field missing".into())
}

fn record(value: &mut Value) -> Fallible<&mut Value> {
    fields(field(value, "records")?)?
        .first_mut()
        .map(|(_, record)| record)
        .ok_or_else(|| "fixture record missing".into())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn wrong_length_buffers_stop_before_fixed_copy_and_refusal_wins_after_native_fault() -> Fallible<()>
{
    let live = lifecycle("a", KeyRoleV1::TimelineIntegritySigning)?
        .swap_remove(1)
        .0;
    for length in [0, 1, 31, 33, 4_097] {
        let mut value = value(&live)?;
        *field(record(&mut value)?, "public_verification_key")? = Value::Bytes(vec![0x52; length]);
        let bytes = encoded(&value)?;
        let mut guard = Guard::new(86 + length); // two I(1) + private D + temporary key only
        assert_eq!(
            KeyRegistryStateV1::from_durable_cbor_with_read_guard(&bytes, &mut guard),
            Err(ReadError::InvalidSnapshot)
        );
        assert_eq!(guard.remaining, 0);
        assert_eq!(ordinary(&bytes), Err(ReadError::InvalidSnapshot));
        let native_trace = guard.events;
        let mut refused = Guard::new(86 + length);
        refused.stop_at = Some(native_trace.len() - 1);
        assert_eq!(
            KeyRegistryStateV1::from_durable_cbor_with_read_guard(&bytes, &mut refused),
            Err(ReadError::ReadRefused)
        );
        assert_eq!(refused.events, native_trace);
    }
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn duplicate_map_keys_charge_new_carriers_but_duplicate_struct_fields_do_not_decode_values(
) -> Fallible<()> {
    let live = lifecycle("a", KeyRoleV1::TimelineIntegritySigning)?
        .swap_remove(1)
        .0;
    let mut duplicate = value(&live)?;
    let records = fields(field(&mut duplicate, "records")?)?;
    records.push(records.first().ok_or("record entry")?.clone());
    let bytes = encoded(&duplicate)?;
    assert_eq!(parity(&bytes)?, live);
    let mut guard = Guard::new(224 + 150); // one extra I + (I + two D), no refund
    assert_eq!(
        KeyRegistryStateV1::from_durable_cbor_with_read_guard(&bytes, &mut guard)?,
        live
    );
    assert_eq!(guard.remaining, 0);

    let mut duplicate = value(&live)?;
    fields(&mut duplicate)?.push((Value::Text("version".to_owned()), Value::Integer(1.into())));
    let mut guard = Guard::new(176); // decode only; duplicate stops before invariants
    let bytes = encoded(&duplicate)?;
    assert_eq!(
        KeyRegistryStateV1::from_durable_cbor_with_read_guard(&bytes, &mut guard),
        Err(ReadError::InvalidSnapshot)
    );
    assert_eq!(guard.remaining, 0);
    assert_eq!(ordinary(&bytes), Err(ReadError::InvalidSnapshot));
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn truncation_bit_faults_missing_fields_and_trailing_input_keep_closed_native_parity(
) -> Fallible<()> {
    let live = lifecycle("a", KeyRoleV1::TimelineIntegritySigning)?
        .swap_remove(1)
        .0;
    let bytes = encoded(&live)?;
    for end in 0..bytes.len() {
        assert_eq!(parity(&bytes[..end]), Err(ReadError::InvalidSnapshot));
    }
    for index in 0..bytes.len() {
        for bit in [1, 0x20, 0x80] {
            let mut changed = bytes.clone();
            changed[index] ^= bit;
            drop(parity(&changed));
        }
    }
    let mut trailing = bytes;
    trailing.extend_from_slice(&[0xff, 0x1c, 0]);
    assert_eq!(parity(&trailing)?, live);
    let original = value(&live)?;
    for name in [
        "records",
        "active",
        "tombstones",
        "highest_epoch",
        "pending_destructions",
        "version",
    ] {
        let mut missing = original.clone();
        fields(&mut missing)?.retain(|(key, _)| *key != Value::Text(name.to_owned()));
        assert_eq!(parity(&encoded(&missing)?), Err(ReadError::InvalidSnapshot));
    }
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn nested_unknown_values_missing_options_and_recursion_keep_derived_serde_behavior() -> Fallible<()>
{
    let live = lifecycle("a", KeyRoleV1::TimelineIntegritySigning)?
        .swap_remove(1)
        .0;
    let long_text = "x".repeat(4_095) + "💠" + &"z".repeat(4_097);
    for ignored in [
        Value::Null,
        Value::Bool(true),
        Value::Float(f64::NAN),
        Value::Integer((-1).into()),
        Value::Bytes(vec![0x71; 4_097]),
        Value::Text(long_text),
        Value::Map(vec![(
            Value::Bytes(vec![0xff]),
            Value::Array(vec![Value::Bool(false)]),
        )]),
        Value::Tag(42, Box::new(Value::Null)),
        Value::Tag(2, Box::new(Value::Bytes(vec![0xff; 16]))),
        Value::Tag(3, Box::new(Value::Bytes(vec![0x7f; 16]))),
        Value::Tag(3, Box::new(Value::Bytes(vec![0xff; 16]))),
        Value::Tag(2, Box::new(Value::Bytes(vec![0xff; 17]))),
    ] {
        let mut changed = value(&live)?;
        fields(record(&mut changed)?)?.push((Value::Text("extra".to_owned()), ignored.clone()));
        let bytes = encoded(&changed)?;
        if parity(&bytes).is_ok() {
            let mut guard = Guard::new(224);
            assert_eq!(
                KeyRegistryStateV1::from_durable_cbor_with_read_guard(&bytes, &mut guard)?,
                live
            );
            // The selected skip route borrows chunks instead of allocating
            // discarded unknown data. Only actual native carriers are charged.
            assert_eq!(guard.remaining, 0);
        }
        let mut root_unknown = value(&live)?;
        fields(&mut root_unknown)?.push((Value::Text("extra".to_owned()), ignored));
        assert_eq!(
            parity(&encoded(&root_unknown)?),
            Err(ReadError::InvalidSnapshot)
        );
    }
    for depth in [0, 1, 252, 253, 254, 255, 256, 257] {
        let mut ignored = Value::Null;
        for _ in 0..depth {
            ignored = Value::Array(vec![ignored]);
        }
        let mut changed = value(&live)?;
        fields(record(&mut changed)?)?.push((Value::Text("extra".to_owned()), ignored));
        let actual = parity(&encoded(&changed)?);
        if depth <= 253 {
            assert_eq!(actual?, live);
        } else {
            assert_eq!(actual, Err(ReadError::InvalidSnapshot));
        }
    }
    let mut encryption = value(
        &lifecycle("a", KeyRoleV1::SubjectDataEncryption)?
            .swap_remove(1)
            .0,
    )?;
    fields(record(&mut encryption)?)?
        .retain(|(name, _)| *name != Value::Text("public_verification_key".to_owned()));
    assert!(parity(&encoded(&encryption)?).is_ok());
    let destroyed = lifecycle("a", KeyRoleV1::TimelineIntegritySigning)?
        .swap_remove(3)
        .0;
    let mut missing_option = value(&destroyed)?;
    fields(record(&mut missing_option)?)?
        .retain(|(name, _)| *name != Value::Text("private_material_digest".to_owned()));
    assert_eq!(parity(&encoded(&missing_option)?)?, destroyed);
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn owner_faults_and_impossible_cardinalities_do_not_allocate_declared_aggregates() -> Fallible<()> {
    let live = lifecycle("a", KeyRoleV1::TimelineIntegritySigning)?
        .swap_remove(1)
        .0;
    for text in [String::new(), "a".repeat(129)] {
        let mut changed = value(&live)?;
        let (key, _) = fields(field(&mut changed, "records")?)?
            .first_mut()
            .ok_or("record")?;
        *field(key, "owner_id")? = Value::Text(text.clone());
        let mut guard = Guard::new(text.len());
        let bytes = encoded(&changed)?;
        assert_eq!(
            KeyRegistryStateV1::from_durable_cbor_with_read_guard(&bytes, &mut guard),
            Err(ReadError::InvalidSnapshot)
        );
        assert_eq!(guard.remaining, 0); // String only; no invalid OwnerId copy
        assert_eq!(ordinary(&bytes), Err(ReadError::InvalidSnapshot));
    }
    for bytes in [
        vec![0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        vec![0xbf, 0xff],
        vec![0x9f, 0xff],
        vec![0x7f, 0xff],
        vec![0x5f, 0xff],
        vec![0xff],
        vec![0x1c],
        vec![0x1f],
        vec![0x3f],
        vec![0xdf],
    ] {
        assert_eq!(parity(&bytes), Err(ReadError::InvalidSnapshot));
    }
    Ok(())
}

fn replace_first(bytes: &[u8], needle: &[u8], replacement: &[u8]) -> Fallible<Vec<u8>> {
    let index = bytes
        .windows(needle.len())
        .position(|part| part == needle)
        .ok_or("wire needle")?;
    let mut result = bytes[..index].to_vec();
    result.extend_from_slice(replacement);
    result.extend_from_slice(&bytes[index + needle.len()..]);
    Ok(result)
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn pinned_tuple_and_unit_enum_stream_consumption_is_not_silently_tightened() -> Fallible<()> {
    let live = lifecycle("a", KeyRoleV1::TimelineIntegritySigning)?
        .swap_remove(1)
        .0;
    let bytes = encoded(&live)?;
    let role = encoded(&Value::Text("TimelineIntegritySigning".to_owned()))?;
    // A unit enum map consumes its header and identifier, not its value.
    // With no inserted value the pinned typed decoder therefore still sees
    // exactly the original following epoch field. This is not strict whole CBOR.
    let mut map_role = vec![0xa1];
    map_role.extend_from_slice(&role);
    assert_eq!(parity(&replace_first(&bytes, &role, &map_role)?)?, live);
    let mut null_role = map_role.clone();
    null_role.push(0xf6);
    assert_eq!(
        parity(&replace_first(&bytes, &role, &null_role)?),
        Err(ReadError::InvalidSnapshot)
    );
    let mut scope = vec![0x82, 0x61, b'a'];
    scope.extend_from_slice(&role);
    let mut longer_scope = scope.clone();
    longer_scope[0] = 0x83; // the third declared element is not consumed
    assert_eq!(
        parity(&replace_first(&bytes, &scope, &longer_scope)?)?,
        live
    );
    let mut indefinite_scope = scope.clone();
    indefinite_scope[0] = 0x9f;
    assert_eq!(
        parity(&replace_first(&bytes, &scope, &indefinite_scope)?)?,
        live
    );
    indefinite_scope.push(0xff); // consuming this terminator would change parity
    assert_eq!(
        parity(&replace_first(&bytes, &scope, &indefinite_scope)?),
        Err(ReadError::InvalidSnapshot)
    );
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn truncated_utf8_tagged_options_and_bignum_faults_match_native_rejection() -> Fallible<()> {
    let live = lifecycle("a", KeyRoleV1::TimelineIntegritySigning)?
        .swap_remove(1)
        .0;
    let bytes = encoded(&live)?;
    for replacement in [
        vec![0x61, 0xff],
        vec![0x62, 0xc3, 0],
        vec![0x7f, 0x61, 0xc3, 0x61, 0xa9, 0xff], // UTF-8 cannot cross segments
        vec![0x7f, 0x5f, 0xff, 0xff],
    ] {
        let bad = replace_first(&bytes, &[0x61, b'a'], &replacement)?;
        assert_eq!(parity(&bad), Err(ReadError::InvalidSnapshot));
    }
    for integer in [
        Value::Integer(0.into()),
        Value::Integer(2.into()),
        Value::Integer(256.into()),
        Value::Integer((-1).into()),
        Value::Bool(true),
        Value::Tag(2, Box::new(Value::Bytes(vec![0xff; 17]))),
        Value::Tag(3, Box::new(Value::Bytes(vec![0]))),
        Value::Tag(2, Box::new(Value::Null)),
        Value::Tag(2, Box::new(Value::Bytes(vec![0xff; 9]))),
    ] {
        let mut changed = value(&live)?;
        *field(&mut changed, "version")? = integer;
        assert_eq!(parity(&encoded(&changed)?), Err(ReadError::InvalidSnapshot));
    }
    let destroyed = lifecycle("a", KeyRoleV1::TimelineIntegritySigning)?
        .swap_remove(3)
        .0;
    let mut tagged_none = value(&destroyed)?;
    *field(record(&mut tagged_none)?, "private_material_digest")? =
        Value::Tag(42, Box::new(Value::Null));
    assert_eq!(
        parity(&encoded(&tagged_none)?),
        Err(ReadError::InvalidSnapshot)
    );
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn missing_native_fields_and_short_scope_tuples_fail_at_the_public_decode_seam() -> Fallible<()>
{
    let states = lifecycle("a", KeyRoleV1::TimelineIntegritySigning)?;
    for (index, map, required) in [
        (1, "records", &["identity"][..]),
        (
            2,
            "pending_destructions",
            &["identity", "expected_material_digest", "authorization_digest"][..],
        ),
        (
            3,
            "tombstones",
            &[
                "identity",
                "destroyed_material_digest",
                "destruction_digest",
                "deletion_receipt",
            ][..],
        ),
    ] {
        let original = value(&states[index].0)?;
        for name in required {
            let mut changed = original.clone();
            let (_, native) = fields(field(&mut changed, map)?)?
                .first_mut()
                .ok_or("native fixture entry")?;
            fields(native)?.retain(|(key, _)| *key != Value::Text((*name).to_owned()));
            // Remove a required wire field below the typed constructors.
            // Both readers must reject decoding, before registry invariants.
            assert_eq!(parity(&encoded(&changed)?), Err(ReadError::InvalidSnapshot));
        }
    }
    let original = value(&states[1].0)?;
    for in_key in [false, true] {
        for name in ["owner_id", "role", "epoch"] {
            let mut changed = original.clone();
            let (key, record_value) = fields(field(&mut changed, "records")?)?
                .first_mut()
                .ok_or("identity fixture entry")?;
            let identity = if in_key {
                key
            } else {
                field(record_value, "identity")?
            };
            fields(identity)?.retain(|(key, _)| *key != Value::Text(name.to_owned()));
            assert_eq!(parity(&encoded(&changed)?), Err(ReadError::InvalidSnapshot));
        }
    }
    for items in [Vec::new(), vec![Value::Text("a".to_owned())]] {
        let mut changed = original.clone();
        let (scope, _) = fields(field(&mut changed, "highest_epoch")?)?
            .first_mut()
            .ok_or("scope fixture entry")?;
        *scope = Value::Array(items);
        // A scope requires both tuple members, unlike an unconsumed third item.
        assert_eq!(parity(&encoded(&changed)?), Err(ReadError::InvalidSnapshot));
    }
    Ok(())
}
