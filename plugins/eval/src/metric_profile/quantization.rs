//! Section 4.4 item 1: bit-pattern quantization and the `MTQ1`/`MQR1` test records.

use super::cbor::{
    check_structure, put_array, put_text, put_unsigned, require, text, unsigned, Coordinate,
    Reader, Shape,
};
use super::{MetricErrorV1, MetricFailureV1, MAX_QUANTIZATION_PATTERNS, MICROS_PER_UNIT};

const SHAPE: Shape = Shape {
    fields: &["magic", "version", "patterns"],
    list: 2,
    element_fields: None,
};

/// The bit pattern of binary64 `1.0`.
const ONE: u64 = 0x3ff0_0000_0000_0000;
const SIGN: u64 = 1 << 63;
const FRACTION_BITS: u32 = 52;
const FRACTION_MASK: u64 = (1 << FRACTION_BITS) - 1;
/// Any shift at or above this leaves `mantissa * 10^6 < 2^73` below one half, so it rounds to
/// 0 exactly as the clamped shift does, and the clamp keeps `u128` shifts in range.
const MAX_SHIFT: u32 = 100;

/// Quantize one IEEE-754 binary64 bit pattern to probability micro-units with integer
/// arithmetic only: `round(exact_value * 10^6)`, half to even.
///
/// # Errors
/// Returns [`MetricErrorV1::InvalidProbability`] for NaN, either infinity, a value below 0
/// other than -0.0, and a value above 1. Nothing is clamped (ADR-024 Revision 2 check 4).
pub fn quantize_probability(bits: u64) -> Result<u32, MetricErrorV1> {
    let magnitude = bits & !SIGN;
    if magnitude == 0 {
        return Ok(0);
    }
    // Positive patterns order like their values, so `magnitude > ONE` covers values above 1,
    // both infinities and every NaN; a set sign bit is a negative non-zero value.
    if bits & SIGN != 0 || magnitude > ONE {
        return Err(MetricErrorV1::InvalidProbability);
    }
    let exponent = u32::try_from(magnitude >> FRACTION_BITS).unwrap_or_default();
    let fraction = magnitude & FRACTION_MASK;
    // The value is `mantissa / 2^shift`; a value at most 1 has `shift >= 52`.
    let (mantissa, shift) = if exponent == 0 {
        (fraction, 1074)
    } else {
        (fraction + (1 << FRACTION_BITS), 1075 - exponent)
    };
    let shift = shift.min(MAX_SHIFT);
    let scaled = u128::from(mantissa) * u128::from(MICROS_PER_UNIT);
    let quotient = scaled >> shift;
    let remainder = scaled & ((1 << shift) - 1);
    let half = 1 << (shift - 1);
    let up = remainder > half || (remainder == half && quotient & 1 == 1);
    Ok(u32::try_from(quotient + u128::from(up)).unwrap_or(u32::MAX))
}

/// Strictly decode an `MTQ1` input to its bit patterns, in the section 4.6 order (G11).
///
/// # Errors
/// Returns the first [`MetricFailureV1`]: structural `InvalidEncoding`, `UnsupportedVersion`
/// at `magic` or `version`, `InvalidEncoding` at `patterns` when it is empty, `ResourceLimit`
/// at `patterns` above 4,096 entries, or `InvalidEncoding` at `patterns/<i>` for an entry
/// that is not an unsigned integer.
pub fn decode_quantization_input_v1(bytes: &[u8]) -> Result<Vec<u64>, MetricFailureV1> {
    check_structure(bytes, &SHAPE)?;
    let mut reader = Reader::fields(bytes);
    let version = MetricErrorV1::UnsupportedVersion;
    reader.header("magic", text, &b"MTQ1".as_slice(), version)?;
    reader.header("version", unsigned, &1, version)?;
    let patterns = Coordinate::name("patterns");
    let count = reader.list();
    require(count > 0, &patterns, MetricErrorV1::InvalidEncoding)?;
    require(
        count <= MAX_QUANTIZATION_PATTERNS,
        &patterns,
        MetricErrorV1::ResourceLimit,
    )?;
    (0..count)
        .map(|index| reader.field(&patterns.child(index), unsigned))
        .collect()
}

/// Encode an `MQR1` result: each entry is the micro-unit value, or the one-item array
/// `[MetricErrorV1]` of its failure (G8).
#[must_use]
pub fn encode_quantization_result_v1(entries: &[Result<u32, MetricErrorV1>]) -> Vec<u8> {
    let mut out = Vec::new();
    put_array(&mut out, 3);
    put_text(&mut out, "MQR1");
    put_unsigned(&mut out, 1);
    put_array(&mut out, u64::try_from(entries.len()).unwrap_or(u64::MAX));
    for entry in entries {
        match entry {
            Ok(micros) => put_unsigned(&mut out, u64::from(*micros)),
            Err(error) => {
                put_array(&mut out, 1);
                put_unsigned(&mut out, u64::from(error.code()));
            }
        }
    }
    out
}
