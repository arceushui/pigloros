//! ADR-097 B4 plaintext grammar of the `persona.preference_weights` field.
//!
//! The plaintext is one RFC 8949 §4.2.1 core-deterministic CBOR map from a
//! Preference dimension name to a definite two-element array
//! `[score, confidence]`. It uses preferred serialization, the shortest form
//! of every argument, no indefinite lengths, and keys sorted by the bytewise
//! order of their deterministic encodings. A dimension name is 1 to 64 bytes
//! of `a`–`z`, `0`–`9`, `_` and `-`; a map has 1 to 64 entries; score and
//! confidence are finite floats, never negative zero, in the shortest of
//! half, single or double precision that holds their value; score is in
//! `[-1.0, 1.0]` and confidence in `[0.0, 1.0]`; and the whole plaintext is
//! at most 8 KiB. Every other value type, a tag, and trailing bytes are
//! rejected.
//!
//! The grammar admits at most 5,442 bytes: 64 entries of a 64-byte name and
//! two double-precision floats behind a two-byte map head. The 8 KiB bound is
//! therefore checked first and never reached by a valid plaintext.
//!
//! [`validate_preference_weights`] checks a plaintext without copying any of
//! it, so a protected owner read can validate its wiped staging in place.
//! [`PreferenceWeightsV1`] is the typed weight set whose encoder produces
//! exactly the accepted bytes.

use std::fmt;

use thiserror::Error;
use zeroize::Zeroizing;

use crate::strict_cbor::{Reader, StrictCborError};
use crate::subject_cbor;

/// The largest plaintext the grammar reads, in bytes.
pub const MAX_PREFERENCE_WEIGHTS_PLAINTEXT_BYTES: usize = 8_192;
/// The most Preference dimensions one weight set holds.
pub const MAX_PREFERENCE_DIMENSIONS: usize = 64;
/// The longest Preference dimension name, in bytes.
pub const MAX_PREFERENCE_DIMENSION_NAME_BYTES: usize = 64;

/// The reader ordinals that classify an encoding failure.
const STRUCTURE: u8 = 0;
const NAME: u8 = 1;
const WEIGHT: u8 = 2;

/// A closed, payload-free rejection of a `persona.preference_weights` plaintext.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PreferenceWeightsErrorV1 {
    /// The plaintext is over 8 KiB.
    #[error("preference weights plaintext exceeds 8 KiB")]
    TooLarge,
    /// The plaintext is not exactly one definite, untagged, shortest-form map.
    #[error("preference weights plaintext is not one deterministic CBOR map")]
    Encoding,
    /// The map has no entries or more than 64.
    #[error("preference weights entry count is out of range")]
    EntryCount,
    /// A key is not definite text of 1 to 64 bytes of `a`–`z`, `0`–`9`, `_` or `-`.
    #[error("preference dimension name is invalid")]
    DimensionName,
    /// A key repeats or follows a key whose encoding sorts after it.
    #[error("preference dimension names are not unique and sorted")]
    KeyOrder,
    /// A value is not `[score, confidence]` of shortest finite floats in range.
    #[error("preference weight is invalid")]
    Weight,
}

impl StrictCborError for PreferenceWeightsErrorV1 {
    fn invalid_encoding(ordinal: u8) -> Self {
        match ordinal {
            NAME => Self::DimensionName,
            WEIGHT => Self::Weight,
            _ => Self::Encoding,
        }
    }

    // Only a dimension name has a reader bound.
    fn bounds_exceeded(_: u8) -> Self {
        Self::DimensionName
    }
}

/// One Preference dimension's `[score, confidence]` pair.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PreferenceWeightV1 {
    /// Affinity in `[-1.0, 1.0]`.
    pub score: f64,
    /// Confidence in `[0.0, 1.0]`.
    pub confidence: f64,
}

impl PreferenceWeightV1 {
    fn is_admitted(self) -> bool {
        in_range(self.score, -1.0) && in_range(self.confidence, 0.0)
    }
}

/// `value` is in `[low, 1.0]`, which excludes NaN and the infinities, and is
/// not negative zero.
fn in_range(value: f64, low: f64) -> bool {
    (low..=1.0).contains(&value) && value.to_bits() != (-0.0_f64).to_bits()
}

const fn is_name_byte(byte: u8) -> bool {
    matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-')
}

fn is_dimension_name(name: &str) -> bool {
    (1..=MAX_PREFERENCE_DIMENSION_NAME_BYTES).contains(&name.len())
        && name.bytes().all(is_name_byte)
}

fn checked_count(count: u64) -> Result<u64, PreferenceWeightsErrorV1> {
    if (1..=MAX_PREFERENCE_DIMENSIONS as u64).contains(&count) {
        Ok(count)
    } else {
        Err(PreferenceWeightsErrorV1::EntryCount)
    }
}

/// Admit one entry after `previous`, the entry before it (empty for the first).
///
/// A text key's deterministic encoding is its length head and bytes, and a
/// name of at most 64 bytes has a head that grows with its length, so the
/// bytewise order of encodings is length first, then bytes.
fn admit<'n>(
    previous: &str,
    name: &'n str,
    weight: PreferenceWeightV1,
) -> Result<&'n str, PreferenceWeightsErrorV1> {
    if !is_dimension_name(name) {
        Err(PreferenceWeightsErrorV1::DimensionName)
    } else if (previous.len(), previous) >= (name.len(), name) {
        Err(PreferenceWeightsErrorV1::KeyOrder)
    } else if weight.is_admitted() {
        Ok(name)
    } else {
        Err(PreferenceWeightsErrorV1::Weight)
    }
}

fn read_entry<'a>(
    reader: &mut Reader<'a, PreferenceWeightsErrorV1>,
    previous: &str,
    visit: &mut dyn FnMut(&str, PreferenceWeightV1),
) -> Result<&'a str, PreferenceWeightsErrorV1> {
    reader.at(NAME);
    reader
        .text(MAX_PREFERENCE_DIMENSION_NAME_BYTES)
        .and_then(|name| {
            reader.at(WEIGHT);
            reader
                .fixed_array(2)
                .and_then(|()| reader.float())
                .and_then(|score| {
                    reader
                        .float()
                        .map(|confidence| PreferenceWeightV1 { score, confidence })
                })
                .and_then(|weight| admit(previous, name, weight).map(|name| (name, weight)))
                .map(|(name, weight)| {
                    visit(name, weight);
                    name
                })
        })
}

fn parse(
    plaintext: &[u8],
    visit: &mut dyn FnMut(&str, PreferenceWeightV1),
) -> Result<(), PreferenceWeightsErrorV1> {
    if plaintext.len() > MAX_PREFERENCE_WEIGHTS_PLAINTEXT_BYTES {
        return Err(PreferenceWeightsErrorV1::TooLarge);
    }
    let mut reader = Reader::new(plaintext);
    reader.at(STRUCTURE);
    reader
        .head()
        .and_then(|(major, count)| {
            if major == 5 {
                checked_count(count)
            } else {
                Err(PreferenceWeightsErrorV1::Encoding)
            }
        })
        .and_then(|count| {
            (0..count).try_fold("", |previous, _| read_entry(&mut reader, previous, visit))
        })
        .and_then(|_| {
            reader.at(STRUCTURE);
            reader.finish()
        })
}

/// Check that `plaintext` is exactly one accepted `persona.preference_weights`
/// value, without copying any of it.
///
/// # Errors
/// Returns the closed [`PreferenceWeightsErrorV1`] of the first rule broken.
pub fn validate_preference_weights(plaintext: &[u8]) -> Result<(), PreferenceWeightsErrorV1> {
    parse(plaintext, &mut |_, _| {})
}

/// A complete, valid Preference weight set in its deterministic key order.
///
/// Its debug form names only the dimension count.
#[derive(Clone, PartialEq)]
pub struct PreferenceWeightsV1 {
    dimensions: Vec<(String, PreferenceWeightV1)>,
}

impl PreferenceWeightsV1 {
    /// Admit `dimensions` in any order.
    ///
    /// # Errors
    /// Returns [`PreferenceWeightsErrorV1::EntryCount`] for no dimensions or
    /// more than 64, [`PreferenceWeightsErrorV1::DimensionName`] for an
    /// invalid name, [`PreferenceWeightsErrorV1::KeyOrder`] for a repeated
    /// name, and [`PreferenceWeightsErrorV1::Weight`] for a weight out of its
    /// domain.
    pub fn new(
        mut dimensions: Vec<(String, PreferenceWeightV1)>,
    ) -> Result<Self, PreferenceWeightsErrorV1> {
        dimensions.sort_by(|(left, _), (right, _)| {
            left.len().cmp(&right.len()).then_with(|| left.cmp(right))
        });
        checked_count(dimensions.len() as u64)
            .and_then(|_| {
                dimensions
                    .iter()
                    .try_fold("", |previous, (name, weight)| {
                        admit(previous, name, *weight)
                    })
                    .map(|_| ())
            })
            .map(|()| Self { dimensions })
    }

    /// Decode one accepted plaintext.
    ///
    /// # Errors
    /// As [`validate_preference_weights`].
    pub fn decode(plaintext: &[u8]) -> Result<Self, PreferenceWeightsErrorV1> {
        let mut dimensions = Vec::new();
        let parsed = parse(plaintext, &mut |name, weight| {
            dimensions.push((name.to_owned(), weight));
        });
        parsed.map(|()| Self { dimensions })
    }

    /// The dimensions in deterministic key order.
    pub fn dimensions(&self) -> impl Iterator<Item = (&str, PreferenceWeightV1)> {
        self.dimensions
            .iter()
            .map(|(name, weight)| (name.as_str(), *weight))
    }

    /// The exact accepted plaintext of this weight set, wiped on drop.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut output = Zeroizing::new(Vec::with_capacity(MAX_PREFERENCE_WEIGHTS_PLAINTEXT_BYTES));
        subject_cbor::head(&mut output, 5, self.dimensions.len() as u64);
        for (name, weight) in &self.dimensions {
            subject_cbor::text(&mut output, name);
            subject_cbor::head(&mut output, 4, 2);
            subject_cbor::float(&mut output, weight.score);
            subject_cbor::float(&mut output, weight.confidence);
        }
        output
    }
}

impl fmt::Debug for PreferenceWeightsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreferenceWeightsV1")
            .field("dimensions", &self.dimensions.len())
            .finish_non_exhaustive()
    }
}
