//! Lifting of guest return values into validated host types.
//!
//! Wasmtime lifts a guest return into a dynamic `Val` that follows the
//! export's declared type. These helpers turn it into host types and fail
//! closed: a value of the wrong shape, length, encoding or order is
//! `InvalidGuestOutput`, and a count or size bound is `OutputLimitExceeded`.

use pos_crypto::plugin_execution::is_valid_id_v1;
use pos_runtime::community_plugin_host::{
    CommunityPluginHostErrorV1, FieldRefV1, GuestPluginErrorV1, GuestReturnV1, PluginErrorCodeV1,
};
use wasmtime::component::Val;

/// A lifted value or the closed error that ends the invocation.
pub(crate) type Lifted<T> = Result<T, CommunityPluginHostErrorV1>;

/// A guest value of the wrong shape, length, encoding or order.
pub(crate) const INVALID: CommunityPluginHostErrorV1 =
    CommunityPluginHostErrorV1::InvalidGuestOutput;
/// A guest value beyond a count or size bound.
pub(crate) const LIMIT: CommunityPluginHostErrorV1 =
    CommunityPluginHostErrorV1::OutputLimitExceeded;

/// WIT bound on a `canonical-coordinate`, in bytes.
const MAX_COORDINATE_BYTES: usize = 128;

/// `Ok(())` when `condition` holds, otherwise `error`.
pub(crate) const fn ensure(condition: bool, error: CommunityPluginHostErrorV1) -> Lifted<()> {
    if condition {
        Ok(())
    } else {
        Err(error)
    }
}

/// Lift `result<T, plugin-error>`, lifting the `ok` payload with `ok`.
pub(crate) fn guest_return<T>(
    value: &Val,
    ok: impl FnOnce(&Val) -> Lifted<T>,
) -> Lifted<GuestReturnV1<T>> {
    match value {
        Val::Result(Ok(Some(payload))) => ok(payload).map(Ok),
        Val::Result(Err(Some(payload))) => plugin_error(payload).map(Err),
        _ => Err(INVALID),
    }
}

/// The field values of a record with exactly `N` fields, in WIT order.
pub(crate) fn fields<const N: usize>(value: &Val) -> Lifted<[&Val; N]> {
    let Val::Record(fields) = value else {
        return Err(INVALID);
    };
    fields
        .iter()
        .map(|(_, field)| field)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| INVALID)
}

/// The items of a list.
pub(crate) fn list(value: &Val) -> Lifted<&[Val]> {
    match value {
        Val::List(items) => Ok(items),
        _ => Err(INVALID),
    }
}

/// The bytes of a `list<u8>`.
pub(crate) fn bytes(value: &Val) -> Lifted<Vec<u8>> {
    list(value)?
        .iter()
        .map(|item| match item {
            Val::U8(byte) => Ok(*byte),
            _ => Err(INVALID),
        })
        .collect()
}

/// A `list<u8>` of exactly `N` bytes.
pub(crate) fn fixed<const N: usize>(value: &Val) -> Lifted<[u8; N]> {
    <[u8; N]>::try_from(bytes(value)?).map_err(|_| INVALID)
}

/// A `digest32` of exactly 32 bytes.
pub(crate) fn digest(value: &Val) -> Lifted<[u8; 32]> {
    let [inner] = fields(value)?;
    fixed(inner)
}

/// A `bounded-text` that is valid UTF-8.
pub(crate) fn text(value: &Val) -> Lifted<String> {
    let [inner] = fields(value)?;
    String::from_utf8(bytes(inner)?).map_err(|_| INVALID)
}

/// A `bounded-text` that is an ADR-061 ID.
pub(crate) fn id(value: &Val) -> Lifted<String> {
    let text = text(value)?;
    ensure(is_valid_id_v1(&text), INVALID)?;
    Ok(text)
}

// The engine supports only targets whose `usize` fits in a `u64`, so
// [`widen`] is lossless.
const _: () = assert!(usize::BITS <= u64::BITS);

/// A byte or element count as a `u64`; lossless on every supported target.
pub(crate) const fn widen(count: usize) -> u64 {
    count as u64
}

/// A `u16`.
pub(crate) const fn u16_value(value: &Val) -> Lifted<u16> {
    match value {
        Val::U16(number) => Ok(*number),
        _ => Err(INVALID),
    }
}

/// A `u32`.
pub(crate) const fn u32_value(value: &Val) -> Lifted<u32> {
    match value {
        Val::U32(number) => Ok(*number),
        _ => Err(INVALID),
    }
}

/// A `list<digest32>` in strictly increasing order, without duplicates.
pub(crate) fn ordered_digests(value: &Val) -> Lifted<Vec<[u8; 32]>> {
    let digests = list(value)?
        .iter()
        .map(digest)
        .collect::<Lifted<Vec<_>>>()?;
    ensure(strictly_increasing(&digests), INVALID)?;
    Ok(digests)
}

/// Whether every item is strictly greater than the one before it.
pub(crate) fn strictly_increasing<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|pair| pair[0] < pair[1])
}

/// `OutputLimitExceeded` unless `count <= limit`.
pub(crate) const fn within(count: usize, limit: u64) -> Lifted<()> {
    ensure(widen(count) <= limit, LIMIT)
}

/// A `plugin-error`.
fn plugin_error(value: &Val) -> Lifted<GuestPluginErrorV1> {
    let [code, coordinate, related] = fields(value)?;
    Ok(GuestPluginErrorV1 {
        code: error_code(code)?,
        canonical_coordinate: optional(coordinate, coordinate_bytes)?,
        related_digest: optional(related, digest)?,
    })
}

/// A `plugin-error-code`.
fn error_code(value: &Val) -> Lifted<PluginErrorCodeV1> {
    let Val::Variant(case, payload) = value else {
        return Err(INVALID);
    };
    match (case.as_str(), payload.as_deref()) {
        ("invalid-invocation", Some(payload)) => {
            field_ref(payload).map(PluginErrorCodeV1::InvalidInvocation)
        }
        ("unsupported-schema", Some(payload)) => {
            u32_value(payload).map(PluginErrorCodeV1::UnsupportedSchema)
        }
        ("capability-required", Some(payload)) => {
            id(payload).map(PluginErrorCodeV1::CapabilityRequired)
        }
        ("dependency-missing", Some(payload)) => {
            digest(payload).map(PluginErrorCodeV1::DependencyMissing)
        }
        ("deterministic-budget-exhausted", None) => {
            Ok(PluginErrorCodeV1::DeterministicBudgetExhausted)
        }
        ("invalid-state", Some(payload)) => field_ref(payload).map(PluginErrorCodeV1::InvalidState),
        ("migration-rejected", Some(payload)) => {
            field_ref(payload).map(PluginErrorCodeV1::MigrationRejected)
        }
        ("guest-declared-failure", Some(payload)) => {
            u16_value(payload).map(PluginErrorCodeV1::GuestDeclaredFailure)
        }
        _ => Err(INVALID),
    }
}

/// A `field-ref`.
fn field_ref(value: &Val) -> Lifted<FieldRefV1> {
    let [schema_id, field_ordinal] = fields(value)?;
    Ok(FieldRefV1 {
        schema_id: u32_value(schema_id)?,
        field_ordinal: u16_value(field_ordinal)?,
    })
}

/// An `option<T>` lifted with `lift`.
fn optional<T>(value: &Val, lift: impl FnOnce(&Val) -> Lifted<T>) -> Lifted<Option<T>> {
    match value {
        Val::Option(inner) => inner.as_deref().map(lift).transpose(),
        _ => Err(INVALID),
    }
}

/// A `canonical-coordinate` of at most 128 bytes.
fn coordinate_bytes(value: &Val) -> Lifted<Vec<u8>> {
    let coordinate = bytes(value)?;
    ensure(coordinate.len() <= MAX_COORDINATE_BYTES, INVALID)?;
    Ok(coordinate)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::lower::byte_list;
    use crate::test_values::{digest_val, digests_val, record, text_val};

    fn some(value: Val) -> Val {
        Val::Option(Some(Box::new(value)))
    }

    fn code(case: &str, payload: Option<Val>) -> Val {
        Val::Variant(case.to_owned(), payload.map(Box::new))
    }

    fn field_ref_val() -> Val {
        record(vec![
            ("schema-id", Val::U32(3)),
            ("field-ordinal", Val::U16(4)),
        ])
    }

    fn error_val(code: Val, coordinate: Val, related: Val) -> Val {
        record(vec![
            ("code", code),
            ("canonical-coordinate", coordinate),
            ("related-digest", related),
        ])
    }

    fn err_return(error: Val) -> Val {
        Val::Result(Err(Some(Box::new(error))))
    }

    fn lifted_error(value: &Val) -> Lifted<GuestReturnV1<()>> {
        guest_return(value, |_| Ok(()))
    }

    const FIELD_REF: FieldRefV1 = FieldRefV1 {
        schema_id: 3,
        field_ordinal: 4,
    };

    #[test]
    fn guest_returns_lift_ok_and_err_payloads_only() {
        let ok = Val::Result(Ok(Some(Box::new(Val::U32(1)))));
        assert_eq!(guest_return(&ok, u32_value), Ok(Ok(1)));
        assert_eq!(guest_return(&ok, u16_value), Err(INVALID));
        assert_eq!(
            guest_return(&Val::Result(Ok(None)), u32_value),
            Err(INVALID)
        );
        assert_eq!(
            guest_return(&Val::Result(Err(None)), u32_value),
            Err(INVALID)
        );
        assert_eq!(guest_return(&Val::U32(1), u32_value), Err(INVALID));
    }

    #[test]
    fn every_plugin_error_code_lifts_with_its_payload() {
        let cases = [
            (
                code("invalid-invocation", Some(field_ref_val())),
                PluginErrorCodeV1::InvalidInvocation(FIELD_REF),
            ),
            (
                code("unsupported-schema", Some(Val::U32(9))),
                PluginErrorCodeV1::UnsupportedSchema(9),
            ),
            (
                code("capability-required", Some(text_val("kv.read"))),
                PluginErrorCodeV1::CapabilityRequired("kv.read".to_owned()),
            ),
            (
                code("dependency-missing", Some(digest_val(&[5; 32]))),
                PluginErrorCodeV1::DependencyMissing([5; 32]),
            ),
            (
                code("deterministic-budget-exhausted", None),
                PluginErrorCodeV1::DeterministicBudgetExhausted,
            ),
            (
                code("invalid-state", Some(field_ref_val())),
                PluginErrorCodeV1::InvalidState(FIELD_REF),
            ),
            (
                code("migration-rejected", Some(field_ref_val())),
                PluginErrorCodeV1::MigrationRejected(FIELD_REF),
            ),
            (
                code("guest-declared-failure", Some(Val::U16(7))),
                PluginErrorCodeV1::GuestDeclaredFailure(7),
            ),
        ];
        for (value, expected) in cases {
            let error = err_return(error_val(value, Val::Option(None), Val::Option(None)));
            let lifted = GuestPluginErrorV1 {
                code: expected,
                canonical_coordinate: None,
                related_digest: None,
            };
            assert_eq!(lifted_error(&error), Ok(Err(lifted)));
        }
    }

    #[test]
    fn plugin_errors_with_bad_codes_or_bounds_are_invalid() {
        let bad_codes = [
            code("deterministic-budget-exhausted", Some(Val::U16(1))),
            code("guest-declared-failure", None),
            code("unknown", Some(Val::U16(1))),
            code("capability-required", Some(text_val("Kv"))),
            code("guest-declared-failure", Some(Val::U32(1))),
            Val::U16(1),
        ];
        for bad in bad_codes {
            let error = err_return(error_val(bad, Val::Option(None), Val::Option(None)));
            assert_eq!(lifted_error(&error), Err(INVALID));
        }
        let failure = || code("guest-declared-failure", Some(Val::U16(1)));
        let longest = some(byte_list(&[1; MAX_COORDINATE_BYTES]));
        let accepted = err_return(error_val(failure(), longest, some(digest_val(&[2; 32]))));
        let expected = GuestPluginErrorV1 {
            code: PluginErrorCodeV1::GuestDeclaredFailure(1),
            canonical_coordinate: Some(vec![1; MAX_COORDINATE_BYTES]),
            related_digest: Some([2; 32]),
        };
        assert_eq!(lifted_error(&accepted), Ok(Err(expected)));
        let long = some(byte_list(&[1; MAX_COORDINATE_BYTES + 1]));
        let error = err_return(error_val(failure(), long, Val::Option(None)));
        assert_eq!(lifted_error(&error), Err(INVALID));
        let short = some(digest_val(&[2; 31]));
        let error = err_return(error_val(failure(), Val::Option(None), short));
        assert_eq!(lifted_error(&error), Err(INVALID));
        let error = err_return(error_val(failure(), Val::U8(0), Val::Option(None)));
        assert_eq!(lifted_error(&error), Err(INVALID));
        let error = err_return(record(vec![("code", failure())]));
        assert_eq!(lifted_error(&error), Err(INVALID));
        let bad_ref = record(vec![
            ("schema-id", Val::U16(3)),
            ("field-ordinal", Val::U16(4)),
        ]);
        let error = err_return(error_val(
            code("invalid-state", Some(bad_ref)),
            Val::Option(None),
            Val::Option(None),
        ));
        assert_eq!(lifted_error(&error), Err(INVALID));
    }

    #[test]
    fn primitive_lifts_reject_other_shapes() {
        assert_eq!(bytes(&Val::U8(1)), Err(INVALID));
        assert_eq!(ordered_digests(&Val::U8(1)), Err(INVALID));
        assert_eq!(
            id(&record(vec![("utf8", byte_list(&[0xff]))])),
            Err(INVALID)
        );
        let bad_ordinal = record(vec![
            ("schema-id", Val::U32(3)),
            ("field-ordinal", Val::U32(4)),
        ]);
        assert_eq!(field_ref(&bad_ordinal), Err(INVALID));
        assert_eq!(fields::<1>(&Val::U8(1)), Err(INVALID));
        assert_eq!(list(&Val::U8(1)), Err(INVALID));
        assert_eq!(bytes(&Val::List(vec![Val::U16(1)])), Err(INVALID));
        assert_eq!(fixed::<2>(&byte_list(&[1, 2])), Ok([1, 2]));
        assert_eq!(fixed::<2>(&byte_list(&[1])), Err(INVALID));
        assert_eq!(text(&text_val("ok")), Ok("ok".to_owned()));
        assert_eq!(
            text(&record(vec![("utf8", byte_list(&[0xff]))])),
            Err(INVALID)
        );
        assert_eq!(id(&text_val("a.b")), Ok("a.b".to_owned()));
        assert_eq!(id(&text_val("")), Err(INVALID));
        assert_eq!(u16_value(&Val::U32(1)), Err(INVALID));
        assert_eq!(u32_value(&Val::U16(1)), Err(INVALID));
    }

    #[test]
    fn digest_lists_are_strictly_increasing() {
        assert_eq!(
            ordered_digests(&digests_val(&[[1; 32], [2; 32]])),
            Ok(vec![[1; 32], [2; 32]])
        );
        assert_eq!(
            ordered_digests(&digests_val(&[[2; 32], [1; 32]])),
            Err(INVALID)
        );
        assert_eq!(
            ordered_digests(&digests_val(&[[1; 32], [1; 32]])),
            Err(INVALID)
        );
        assert_eq!(ordered_digests(&digests_val(&[])), Ok(Vec::new()));
        assert_eq!(
            ordered_digests(&Val::List(vec![digest_val(&[1; 31])])),
            Err(INVALID)
        );
    }

    #[test]
    fn counts_stay_within_their_limit() {
        assert_eq!(within(3, 3), Ok(()));
        assert_eq!(within(4, 3), Err(LIMIT));
        assert_eq!(within(0, 0), Ok(()));
    }
}
