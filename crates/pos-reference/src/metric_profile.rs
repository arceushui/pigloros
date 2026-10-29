//! Independent recomputation of the `pigloros.w8.metric-computation` profile.
//!
//! This module reimplements ADR-062 Revision 7 sections 4.2 to 4.4 from the profile text
//! (`fixtures/conformance/profiles/metric-conformance/normative-requirements.md`): the strict
//! core-deterministic CBOR decoder for `MTI1` and `MTQ1`, the closed [`MetricErrorV1`] with its
//! decode-order precedence and zero-based first coordinate, the section 4.3 algorithms in exact
//! integer arithmetic with one final round-half-to-even, the `MTR1` and `MQR1` encoders and the
//! section 4.4 bit-pattern quantizer. It depends on no plugin, on no conformance crate and on no
//! metric implementation under test; its only external crate is `blake3` for the
//! domain-separated digests.
//!
//! Decoding runs in one pass that checks structure everywhere and latches the first semantic
//! failure. A structural defect anywhere in the input (section 4.6 item 1) therefore outranks
//! every header or record failure, and the first semantic failure in index order (section 4.6
//! items 2 and 3, gap-fill G2) wins among the rest. The validating pass keeps nothing; only an
//! input it accepts is decoded a second time into the exact sums, so a declared `record_count`
//! above 262,144 is `ResourceLimit` before any record is allocated.
//!
//! Gap-fills this module adds, recorded for the profile owner:
//!
//! - **Nesting depth.** An array nested more than [`MAX_NESTING_DEPTH`] levels deep (the root
//!   array is level 1) is `InvalidEncoding` at that array's coordinate. Every well-formed public
//!   record nests at most 3 levels, so the cap only bounds the structural walk of malformed
//!   input.
//! - **`MTQ1` shape.** The quantization coordinates follow G6: `input`, `magic`, `version`,
//!   `patterns`, `patterns/<i>` and `trailing`. A `patterns` field that is not an array is a
//!   structural `InvalidEncoding`, an empty pattern list is `InvalidEncoding` at `patterns`, and
//!   more than 4,096 patterns is `ResourceLimit` at `patterns`.
//! - **`MTR1` acceptance (G9).** The root coordinate of a result is `result`. Acceptance checks
//!   the core-deterministic structure, a 13-field root and the four identity fields; it does not
//!   recompute a result.

use std::cmp::Ordering;
use std::collections::BTreeMap;

/// The metric algorithm identifier of algorithm major 1.
pub const ALGORITHM_ID: &str = "pigloros.metric.binary-calibration";

/// The only metric algorithm major this profile version defines.
pub const ALGORITHM_MAJOR: u64 = 1;

/// The largest declared `record_count` and `minimum_scored_records` (2^18).
pub const MAX_RECORDS: u64 = 262_144;

/// The largest `prediction_id` or `entity_id`, in UTF-8 bytes.
pub const MAX_IDENTIFIER_BYTES: usize = 64;

/// The largest number of bit patterns in one `MTQ1`.
pub const MAX_QUANTIZATION_PATTERNS: u64 = 4_096;

/// The deepest array nesting the structural pass walks; the root array is level 1.
pub const MAX_NESTING_DEPTH: usize = 16;

const INPUT_MAGIC: &[u8] = b"MTI1";
const RESULT_MAGIC: &[u8] = b"MTR1";
const QUANTIZATION_MAGIC: &[u8] = b"MTQ1";
const QUANTIZATION_RESULT_MAGIC: &str = "MQR1";
const RECORD_VERSION: u64 = 1;
const EQUAL_WIDTH_10: u64 = 0;
const INPUT_DOMAIN: &[u8] = b"PiglorOS.MetricInput.v1\0";
const RESULT_DOMAIN: &[u8] = b"PiglorOS.MetricResult.v1\0";

const INPUT_FIELDS: u64 = 8;
const RECORD_FIELDS: u64 = 6;
const RESULT_FIELDS: u64 = 13;
const QUANTIZATION_FIELDS: u64 = 3;

/// `D = 10^6`, the micro-unit scale.
const MICROS: i128 = 1_000_000;
/// The scale of the personal-base-rate intermediate quantization, `10^18`.
const TERM_SCALE: i128 = 1_000_000_000_000_000_000;
const MAX_PROBABILITY_MICROS: u64 = 1_000_000;
const BIN_WIDTH_MICROS: i128 = 100_000;
const BIN_COUNT: usize = 10;
const LAST_BIN: i128 = 9;

/// The binary64 bit pattern of `1.0`; every non-negative pattern up to it is in `[0, 1]`.
const ONE_BITS: u64 = 0x3FF0_0000_0000_0000;
/// The binary64 bit pattern of `-0.0`.
const NEGATIVE_ZERO_BITS: u64 = 0x8000_0000_0000_0000;
const FRACTION_MASK: u64 = (1 << 52) - 1;
const IMPLICIT_BIT: u64 = 1 << 52;
/// `2^-1074` is the weight of one subnormal fraction unit.
const SUBNORMAL_SHIFT: u64 = 1_074;
/// The binary64 exponent bias plus the 52 fraction bits.
const NORMAL_SHIFT_BASE: u64 = 1_075;
/// The widest shift that can still round to a non-zero micro value: with a significand below
/// `2^53`, a shift of 74 or more leaves a value below `2^-21`, under half a micro.
const MAX_ROUNDING_SHIFT: u64 = 73;

/// The closed `MetricErrorV1` failure set of section 4.2, with its wire codes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MetricErrorV1 {
    /// A structural, encoding or CBOR type defect.
    InvalidEncoding = 0,
    /// An unknown record magic or version.
    UnsupportedVersion = 1,
    /// An unknown algorithm identifier or algorithm major.
    UnsupportedAlgorithm = 2,
    /// A binning other than `EqualWidth10`.
    InvalidBinning = 3,
    /// A records array whose length differs from `record_count`.
    InconsistentLength = 4,
    /// A probability outside `0..=1000000` micros, or a pattern outside `[0, 1]`.
    InvalidProbability = 5,
    /// An outcome state, outcome or predictor-supplied flag that does not agree.
    InvalidOutcome = 6,
    /// An identifier outside 1..=64 bytes or not valid UTF-8.
    InvalidIdentifier = 7,
    /// A `prediction_id` equal to the previous record's.
    DuplicatePrediction = 8,
    /// A `prediction_id` below the previous record's in UTF-8 byte order.
    NonCanonicalOrder = 9,
    /// A `minimum_scored_records` outside 1..=262144.
    InvalidMinimum = 10,
    /// A declared count above its bound, raised before any record is allocated.
    ResourceLimit = 11,
}

impl MetricErrorV1 {
    /// The wire code of this failure.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// A rejected input: the closed failure and the CNR1 zero-based `first_coordinate`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetricFailure {
    /// The closed failure.
    pub error: MetricErrorV1,
    /// The zero-based path of the failing item, for example `records/17/2`.
    pub first_coordinate: String,
}

/// One coordinate segment: a named field or a zero-based index.
#[derive(Clone, Copy, Debug)]
enum Segment {
    Name(&'static str),
    Index(u64),
}

fn render(path: &[Segment]) -> String {
    let segments: Vec<String> = path
        .iter()
        .map(|segment| match segment {
            Segment::Name(name) => (*name).to_owned(),
            Segment::Index(index) => index.to_string(),
        })
        .collect();
    segments.join("/")
}

fn failure(error: MetricErrorV1, path: &[Segment]) -> MetricFailure {
    MetricFailure {
        error,
        first_coordinate: render(path),
    }
}

fn invalid_encoding(path: &[Segment]) -> MetricFailure {
    failure(MetricErrorV1::InvalidEncoding, path)
}

/// One well-formed, core-deterministic data item. An array's members are not consumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Item<'a> {
    Unsigned(u64),
    Text(&'a [u8]),
    Array(u64),
    Bool(bool),
    Null,
    /// A negative integer or a byte string: well formed, but never a valid field type here.
    Other,
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    const fn finished(&self) -> bool {
        self.at == self.bytes.len()
    }

    fn take(&mut self, count: u64) -> Option<&'a [u8]> {
        let bytes = self.bytes;
        let start = self.at;
        usize::try_from(count)
            .ok()
            .and_then(|count| start.checked_add(count))
            .and_then(|end| bytes.get(start..end).map(|piece| (end, piece)))
            .map(|(end, piece)| {
                self.at = end;
                piece
            })
    }

    /// The argument of a head with additional information `info`, in its preferred width.
    fn argument(&mut self, info: u8) -> Option<u64> {
        match info {
            0..=23 => Some(u64::from(info)),
            24..=27 => {
                let width = 1_u64 << (info - 24);
                let minimum = if width == 1 { 24 } else { 1_u64 << (4 * width) };
                self.take(width)
                    .map(|bytes| {
                        let mut word = [0_u8; 8];
                        word[8 - bytes.len()..].copy_from_slice(bytes);
                        u64::from_be_bytes(word)
                    })
                    .filter(|value| *value >= minimum)
            }
            _ => None,
        }
    }

    /// Reads one item head (and a string's content). Maps, tags, floats, simple values other
    /// than `false`, `true` and `null`, indefinite lengths, non-preferred heads and truncation
    /// are `None`.
    fn item(&mut self) -> Option<Item<'a>> {
        let initial = self.take(1)?[0];
        let info = initial & 0x1f;
        match initial >> 5 {
            0 => self.argument(info).map(Item::Unsigned),
            1 => self.argument(info).map(|_| Item::Other),
            2 => self
                .argument(info)
                .and_then(|length| self.take(length))
                .map(|_| Item::Other),
            3 => self
                .argument(info)
                .and_then(|length| self.take(length))
                .map(Item::Text),
            4 => self.argument(info).map(Item::Array),
            7 => match info {
                20 => Some(Item::Bool(false)),
                21 => Some(Item::Bool(true)),
                22 => Some(Item::Null),
                _ => None,
            },
            _ => None,
        }
    }
}

/// The single decode pass: structural failures return at once, the first semantic failure is
/// latched until the structure of the whole input has been checked.
struct Decoder<'a> {
    reader: Reader<'a>,
    latched: Option<MetricFailure>,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self {
            reader: Reader::new(bytes),
            latched: None,
        }
    }

    fn flag(&mut self, error: MetricErrorV1, path: &[Segment]) {
        if self.latched.is_none() {
            self.latched = Some(failure(error, path));
        }
    }

    fn require(&mut self, valid: bool, error: MetricErrorV1, path: &[Segment]) {
        if !valid {
            self.flag(error, path);
        }
    }

    /// Reads one item head; its array members, if any, are left to the caller.
    fn next(&mut self, path: &[Segment]) -> Result<Item<'a>, MetricFailure> {
        self.reader.item().ok_or_else(|| invalid_encoding(path))
    }

    /// Reads an array head that must have exactly `length` members.
    fn array_of(&mut self, path: &[Segment], length: u64) -> Result<(), MetricFailure> {
        if self.next(path)? == Item::Array(length) {
            Ok(())
        } else {
            Err(invalid_encoding(path))
        }
    }

    /// Reads an array head of any length.
    fn array(&mut self, path: &[Segment]) -> Result<u64, MetricFailure> {
        if let Item::Array(length) = self.next(path)? {
            Ok(length)
        } else {
            Err(invalid_encoding(path))
        }
    }

    /// Reads one field item at nesting `level`, walking the structure of any nested array.
    fn field(&mut self, path: &[Segment], level: usize) -> Result<Item<'a>, MetricFailure> {
        let item = self.next(path)?;
        if let Item::Array(members) = item {
            self.skip_members(members, &mut path.to_vec(), level)?;
        }
        Ok(item)
    }

    fn skip_members(
        &mut self,
        members: u64,
        path: &mut Vec<Segment>,
        level: usize,
    ) -> Result<(), MetricFailure> {
        if level > MAX_NESTING_DEPTH {
            return Err(invalid_encoding(path));
        }
        for index in 0..members {
            path.push(Segment::Index(index));
            if let Item::Array(inner) = self.next(path)? {
                self.skip_members(inner, path, level + 1)?;
            }
            path.pop();
        }
        Ok(())
    }

    /// A text field that must equal `expected`; another text is `error`.
    fn expect_text(
        &mut self,
        path: &[Segment],
        expected: &[u8],
        error: MetricErrorV1,
    ) -> Result<(), MetricFailure> {
        if let Item::Text(text) = self.field(path, 2)? {
            self.require(text == expected, error, path);
        } else {
            self.flag(MetricErrorV1::InvalidEncoding, path);
        }
        Ok(())
    }

    /// An unsigned field that must satisfy `valid`; another unsigned value is `error`.
    fn expect_unsigned(
        &mut self,
        path: &[Segment],
        level: usize,
        valid: fn(u64) -> bool,
        error: MetricErrorV1,
    ) -> Result<u64, MetricFailure> {
        let item = self.field(path, level)?;
        if let Item::Unsigned(value) = item {
            self.require(valid(value), error, path);
            Ok(value)
        } else {
            self.flag(MetricErrorV1::InvalidEncoding, path);
            Ok(0)
        }
    }

    /// A `prediction_id` or `entity_id`: text of 1..=64 bytes of valid UTF-8.
    fn identifier(&mut self, path: &[Segment]) -> Result<Option<&'a [u8]>, MetricFailure> {
        let item = self.field(path, 4)?;
        if let Item::Text(text) = item {
            let valid = (1..=MAX_IDENTIFIER_BYTES).contains(&text.len())
                && std::str::from_utf8(text).is_ok();
            self.require(valid, MetricErrorV1::InvalidIdentifier, path);
            Ok(valid.then_some(text))
        } else {
            self.flag(MetricErrorV1::InvalidEncoding, path);
            Ok(None)
        }
    }

    /// Ends the pass: trailing bytes are structural, then the latched failure, if any.
    fn finish(self) -> Result<(), MetricFailure> {
        if !self.reader.finished() {
            return Err(invalid_encoding(&[Segment::Name("trailing")]));
        }
        self.latched.map_or(Ok(()), Err)
    }
}

/// The outcome of one record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    Observed { positive: bool },
    Pending,
    Redacted,
    Unavailable,
}

/// One decoded `MetricRecordV1`; identifiers are borrowed from the input.
#[derive(Clone, Copy, Debug)]
struct Record<'a> {
    entity: &'a [u8],
    probability: i128,
    outcome: Outcome,
    supplied: bool,
}

const fn is_version(value: u64) -> bool {
    value == RECORD_VERSION
}

const fn is_algorithm_major(value: u64) -> bool {
    value == ALGORITHM_MAJOR
}

const fn is_binning(value: u64) -> bool {
    value == EQUAL_WIDTH_10
}

const fn is_minimum(value: u64) -> bool {
    matches!(value, 1..=MAX_RECORDS)
}

const fn is_record_count(value: u64) -> bool {
    value <= MAX_RECORDS
}

const fn is_probability(value: u64) -> bool {
    value <= MAX_PROBABILITY_MICROS
}

const fn is_outcome_state(value: u64) -> bool {
    value <= 3
}

const fn any_pattern(_: u64) -> bool {
    true
}

const fn name(name: &'static str) -> [Segment; 1] {
    [Segment::Name(name)]
}

/// Decodes one `MTI1` and returns its `minimum_scored_records`. The validating pass has no
/// `tally` and keeps nothing; only an input already validated is decoded again into a tally, so
/// no record of a rejected input is ever kept.
fn decode_input<'a>(
    bytes: &'a [u8],
    mut tally: Option<&mut Tally<'a>>,
) -> Result<u64, MetricFailure> {
    let mut decoder = Decoder::new(bytes);
    decoder.array_of(&name("input"), INPUT_FIELDS)?;
    decoder.expect_text(
        &name("magic"),
        INPUT_MAGIC,
        MetricErrorV1::UnsupportedVersion,
    )?;
    decoder.expect_unsigned(
        &name("version"),
        2,
        is_version,
        MetricErrorV1::UnsupportedVersion,
    )?;
    decoder.expect_text(
        &name("algorithm_id"),
        ALGORITHM_ID.as_bytes(),
        MetricErrorV1::UnsupportedAlgorithm,
    )?;
    decoder.expect_unsigned(
        &name("algorithm_major"),
        2,
        is_algorithm_major,
        MetricErrorV1::UnsupportedAlgorithm,
    )?;
    decoder.expect_unsigned(
        &name("binning"),
        2,
        is_binning,
        MetricErrorV1::InvalidBinning,
    )?;
    let minimum = decoder.expect_unsigned(
        &name("minimum_scored_records"),
        2,
        is_minimum,
        MetricErrorV1::InvalidMinimum,
    )?;
    let declared = decoder.expect_unsigned(
        &name("record_count"),
        2,
        is_record_count,
        MetricErrorV1::ResourceLimit,
    )?;
    let length = decoder.array(&name("records"))?;
    decoder.require(
        length == declared,
        MetricErrorV1::InconsistentLength,
        &name("records"),
    );
    let mut previous = None;
    for index in 0..length {
        let record = decode_record(&mut decoder, index, &mut previous)?;
        if let (Some(tally), Some(record)) = (tally.as_deref_mut(), record) {
            tally.add(&record);
        }
    }
    decoder.finish()?;
    Ok(minimum)
}

/// The coordinate `records/<index>/<field>`.
const fn record_field(index: u64, field: u64) -> [Segment; 3] {
    [
        Segment::Name("records"),
        Segment::Index(index),
        Segment::Index(field),
    ]
}

fn decode_record<'a>(
    decoder: &mut Decoder<'a>,
    index: u64,
    previous: &mut Option<&'a [u8]>,
) -> Result<Option<Record<'a>>, MetricFailure> {
    decoder.array_of(
        &[Segment::Name("records"), Segment::Index(index)],
        RECORD_FIELDS,
    )?;
    let at = record_field(index, 0);
    let prediction = decoder.identifier(&at)?;
    match prediction
        .zip(*previous)
        .map(|(current, last)| current.cmp(last))
    {
        Some(Ordering::Equal) => decoder.flag(MetricErrorV1::DuplicatePrediction, &at),
        Some(Ordering::Less) => decoder.flag(MetricErrorV1::NonCanonicalOrder, &at),
        _ => {}
    }
    *previous = prediction.or(*previous);
    let entity = decoder.identifier(&record_field(index, 1))?;
    let probability = decoder.expect_unsigned(
        &record_field(index, 2),
        4,
        is_probability,
        MetricErrorV1::InvalidProbability,
    )?;
    let (outcome, supplied) = decode_outcome(decoder, index)?;
    Ok(entity.map(|entity| Record {
        entity,
        probability: i128::from(probability),
        outcome,
        supplied,
    }))
}

/// Fields 3 to 5 of a record: `outcome_state`, `outcome` and `predictor_supplied`.
fn decode_outcome(decoder: &mut Decoder<'_>, index: u64) -> Result<(Outcome, bool), MetricFailure> {
    let state = decoder.expect_unsigned(
        &record_field(index, 3),
        4,
        is_outcome_state,
        MetricErrorV1::InvalidOutcome,
    )?;
    let observed = state == 0;
    let at = record_field(index, 4);
    let outcome = match decoder.field(&at, 4)? {
        Item::Unsigned(value) => Some(value),
        Item::Null => None,
        _ => {
            decoder.flag(MetricErrorV1::InvalidEncoding, &at);
            None
        }
    };
    let agrees = outcome.map_or(!observed, |value| observed && value <= 1);
    decoder.require(agrees, MetricErrorV1::InvalidOutcome, &at);
    let at = record_field(index, 5);
    let supplied = if let Item::Bool(flag) = decoder.field(&at, 4)? {
        flag
    } else {
        decoder.flag(MetricErrorV1::InvalidEncoding, &at);
        false
    };
    decoder.require(observed || !supplied, MetricErrorV1::InvalidOutcome, &at);
    let outcome = match state {
        0 => Outcome::Observed {
            positive: outcome == Some(1),
        },
        1 => Outcome::Pending,
        2 => Outcome::Redacted,
        _ => Outcome::Unavailable,
    };
    Ok((outcome, supplied))
}

/// `round(numerator / denominator)`, half to even, for a positive denominator.
fn round_half_even(numerator: i128, denominator: i128) -> i128 {
    let quotient = numerator.div_euclid(denominator);
    let twice_remainder = 2 * numerator.rem_euclid(denominator);
    let up = twice_remainder > denominator
        || (twice_remainder == denominator && quotient.rem_euclid(2) == 1);
    quotient + i128::from(up)
}

#[derive(Clone, Copy, Debug, Default)]
struct Bin {
    count: i128,
    probability_sum: i128,
    positives: i128,
}

/// The exact sums of section 4.3 over one decoded input.
#[derive(Debug, Default)]
struct Tally<'a> {
    pending: i128,
    redacted: i128,
    unavailable: i128,
    supplied: i128,
    scored: i128,
    squared_error: i128,
    probability_sum: i128,
    positives: i128,
    bins: [Bin; BIN_COUNT],
    entities: BTreeMap<&'a [u8], (i128, i128)>,
}

impl<'a> Tally<'a> {
    fn add(&mut self, record: &Record<'a>) {
        match record.outcome {
            Outcome::Observed { positive } => self.score(record, i128::from(positive)),
            Outcome::Pending => self.pending += 1,
            Outcome::Redacted => self.redacted += 1,
            Outcome::Unavailable => self.unavailable += 1,
        }
    }

    fn score(&mut self, record: &Record<'a>, outcome: i128) {
        let probability = record.probability;
        let error = probability - MICROS * outcome;
        self.scored += 1;
        self.squared_error += error * error;
        self.probability_sum += probability;
        self.positives += outcome;
        self.supplied += i128::from(record.supplied);
        // `k = min(p div 100000, 9)`, already in 0..=9 before the index conversion.
        let index =
            usize::try_from((probability / BIN_WIDTH_MICROS).min(LAST_BIN)).unwrap_or_default();
        let bin = &mut self.bins[index];
        bin.count += 1;
        bin.probability_sum += probability;
        bin.positives += outcome;
        let entity = self.entities.entry(record.entity).or_default();
        entity.0 += 1;
        entity.1 += outcome;
    }

    /// `redaction_state`: the weakest state wins.
    const fn redaction_state(&self) -> i128 {
        if self.unavailable > 0 {
            3
        } else if self.redacted > 0 {
            1
        } else {
            0
        }
    }

    /// `MetricValuesV1`, each value rounded once from its exact rational.
    fn metrics(&self) -> [i128; 9] {
        let n = self.scored;
        let squared_error = self.squared_error;
        let sum = self.probability_sum;
        let positives = self.positives;
        let brier = round_half_even(squared_error, n * MICROS);
        let calibration_gap: i128 = self
            .bins
            .iter()
            .map(|bin| (bin.probability_sum - MICROS * bin.positives).abs())
            .sum();
        // sum_S (P - n*y_i)^2, expanded with y_i^2 = D * y_i.
        let population_error =
            n * sum * sum - 2 * n * sum * positives * MICROS + n * n * positives * MICROS * MICROS;
        let population_scale = n * n * n * MICROS;
        let persistence = positives * (n - positives);
        let terms: i128 = self
            .entities
            .values()
            .map(|(count, hits)| entity_term(*count, *hits))
            .sum();
        let term_scale = n * MICROS * MICROS;
        [
            brier,
            brier,
            round_half_even(calibration_gap, n),
            round_half_even(population_error, population_scale),
            round_half_even(population_error - n * n * squared_error, population_scale),
            round_half_even(persistence * MICROS, n * n),
            round_half_even(
                persistence * MICROS * MICROS - n * squared_error,
                n * n * MICROS,
            ),
            round_half_even(terms, term_scale),
            round_half_even(terms - MICROS * squared_error, term_scale),
        ]
    }
}

/// `T'_e = floor(T_e * 10^18)`, the only intermediate rounding of the algorithm.
const fn entity_term(count: i128, positives: i128) -> i128 {
    if count == 1 {
        positives * TERM_SCALE
    } else {
        (positives * (count - positives) * count * TERM_SCALE).div_euclid((count - 1) * (count - 1))
    }
}

/// A core-deterministic CBOR writer for the result records.
struct Encoder(Vec<u8>);

impl Encoder {
    fn head(&mut self, major: u8, argument: u128) {
        let bytes = argument.to_be_bytes();
        let (info, width) = if argument < 24 {
            (bytes[15], 0)
        } else if argument <= 0xff {
            (24, 1)
        } else if argument <= 0xffff {
            (25, 2)
        } else if argument <= 0xffff_ffff {
            (26, 4)
        } else {
            (27, 8)
        };
        self.0.push((major << 5) + info);
        self.0.extend_from_slice(&bytes[bytes.len() - width..]);
    }

    fn integer(&mut self, value: i128) {
        if value < 0 {
            self.head(1, (-1 - value).unsigned_abs());
        } else {
            self.head(0, value.unsigned_abs());
        }
    }

    fn bytes(&mut self, major: u8, content: &[u8]) {
        self.head(major, u128::try_from(content.len()).unwrap_or(u128::MAX));
        self.0.extend_from_slice(content);
    }

    fn text(&mut self, text: &str) {
        self.bytes(3, text.as_bytes());
    }

    fn array(&mut self, length: usize) {
        self.head(4, u128::try_from(length).unwrap_or(u128::MAX));
    }

    fn integers(&mut self, values: &[i128]) {
        self.array(values.len());
        for value in values {
            self.integer(*value);
        }
    }

    fn null(&mut self) {
        self.0.push(0xf6);
    }
}

fn digest(domain: &[u8], prefix: &[u8], content: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(prefix);
    hasher.update(content);
    *hasher.finalize().as_bytes()
}

fn encode_result(input: &[u8], tally: &Tally<'_>, minimum: u64) -> Vec<u8> {
    let computed = tally.scored >= i128::from(minimum);
    let mut fields = Encoder(Vec::new());
    fields.text("MTR1");
    fields.integer(i128::from(RECORD_VERSION));
    fields.text(ALGORITHM_ID);
    fields.integer(i128::from(ALGORITHM_MAJOR));
    fields.integer(i128::from(EQUAL_WIDTH_10));
    fields.bytes(2, &digest(INPUT_DOMAIN, &[], input));
    fields.integer(i128::from(!computed));
    fields.integers(&[
        tally.scored + tally.pending + tally.redacted + tally.unavailable,
        tally.scored,
        tally.pending,
        tally.redacted,
        tally.unavailable,
        tally.supplied,
        i128::try_from(tally.entities.len()).unwrap_or(i128::MAX),
    ]);
    fields.integer(i128::from(minimum));
    fields.integer(tally.redaction_state());
    if computed {
        fields.integers(&tally.metrics());
        fields.array(BIN_COUNT);
        for bin in &tally.bins {
            fields.integers(&[bin.count, bin.probability_sum, bin.positives]);
        }
    } else {
        fields.null();
        fields.null();
    }
    // `fields 0..11` is the encoding of the 12-item array of those fields (gap-fill G7).
    let mut array_head = Encoder(Vec::new());
    array_head.array(12);
    let result_digest = digest(RESULT_DOMAIN, &array_head.0, &fields.0);
    let mut result = Encoder(Vec::new());
    result.array(13);
    result.0.extend_from_slice(&fields.0);
    result.bytes(2, &result_digest);
    result.0
}

/// Recomputes the `MTR1` bytes of one `MTI1` input (sections 4.2 and 4.3).
///
/// # Errors
///
/// Returns the first [`MetricFailure`] in decode order when `input` is not a valid `MTI1`.
pub fn recompute_result_v1(input: &[u8]) -> Result<Vec<u8>, MetricFailure> {
    decode_input(input, None).and_then(|_| {
        let mut tally = Tally::default();
        decode_input(input, Some(&mut tally)).map(|minimum| encode_result(input, &tally, minimum))
    })
}

/// Accepts an `MTR1` only as a result of this profile's record version and algorithm major
/// (gap-fill G9); a result of another version or algorithm has no fallback.
///
/// # Errors
///
/// Returns `InvalidEncoding` for a structural defect, `UnsupportedVersion` for another magic or
/// version and `UnsupportedAlgorithm` for another algorithm identifier or major, at that field.
pub fn accept_result_v1(result: &[u8]) -> Result<(), MetricFailure> {
    let mut decoder = Decoder::new(result);
    decoder.array_of(&name("result"), RESULT_FIELDS)?;
    decoder.expect_text(
        &name("magic"),
        RESULT_MAGIC,
        MetricErrorV1::UnsupportedVersion,
    )?;
    decoder.expect_unsigned(
        &name("version"),
        2,
        is_version,
        MetricErrorV1::UnsupportedVersion,
    )?;
    decoder.expect_text(
        &name("algorithm_id"),
        ALGORITHM_ID.as_bytes(),
        MetricErrorV1::UnsupportedAlgorithm,
    )?;
    decoder.expect_unsigned(
        &name("algorithm_major"),
        2,
        is_algorithm_major,
        MetricErrorV1::UnsupportedAlgorithm,
    )?;
    for index in 4..RESULT_FIELDS {
        decoder.field(&[Segment::Name("result"), Segment::Index(index)], 2)?;
    }
    decoder.finish()
}

/// Quantizes one IEEE-754 binary64 bit pattern to `probability_micros` (section 4.4 item 1)
/// with integer arithmetic only: `round(exact_value * 10^6)`, half to even.
///
/// # Errors
///
/// Returns [`MetricErrorV1::InvalidProbability`] for NaN, either infinity, a value below 0
/// other than `-0.0`, and a value above 1. Nothing is clamped.
pub fn quantize_probability_v1(bits: u64) -> Result<u32, MetricErrorV1> {
    (bits <= ONE_BITS || bits == NEGATIVE_ZERO_BITS)
        .then(|| {
            let exponent = (bits >> 52) & 0x7ff;
            let fraction = bits & FRACTION_MASK;
            let (significand, shift) = if exponent == 0 {
                (fraction, SUBNORMAL_SHIFT)
            } else {
                (fraction + IMPLICIT_BIT, NORMAL_SHIFT_BASE - exponent)
            };
            if shift > MAX_ROUNDING_SHIFT {
                0
            } else {
                round_half_even(i128::from(significand) * MICROS, 1_i128 << shift)
            }
        })
        .and_then(|micros| u32::try_from(micros).ok())
        .ok_or(MetricErrorV1::InvalidProbability)
}

/// Recomputes the `MQR1` bytes of one `MTQ1` input (section 4.4 item 1): each pattern becomes
/// its `probability_micros`, or the one-item array `[5]` when it is `InvalidProbability`
/// (gap-fill G8).
///
/// # Errors
///
/// Returns the first [`MetricFailure`] in decode order when `input` is not a valid `MTQ1`.
pub fn recompute_quantization_v1(input: &[u8]) -> Result<Vec<u8>, MetricFailure> {
    decode_quantization(input, None).and_then(|()| {
        let mut patterns = Vec::new();
        decode_quantization(input, Some(&mut patterns)).map(|()| encode_quantization(&patterns))
    })
}

/// Decodes one `MTQ1`; like [`decode_input`], only a validated input fills `patterns`.
fn decode_quantization(
    input: &[u8],
    mut patterns: Option<&mut Vec<u64>>,
) -> Result<(), MetricFailure> {
    let mut decoder = Decoder::new(input);
    decoder.array_of(&name("input"), QUANTIZATION_FIELDS)?;
    decoder.expect_text(
        &name("magic"),
        QUANTIZATION_MAGIC,
        MetricErrorV1::UnsupportedVersion,
    )?;
    decoder.expect_unsigned(
        &name("version"),
        2,
        is_version,
        MetricErrorV1::UnsupportedVersion,
    )?;
    let length = decoder.array(&name("patterns"))?;
    decoder.require(
        length != 0,
        MetricErrorV1::InvalidEncoding,
        &name("patterns"),
    );
    decoder.require(
        length <= MAX_QUANTIZATION_PATTERNS,
        MetricErrorV1::ResourceLimit,
        &name("patterns"),
    );
    for index in 0..length {
        let pattern = decoder.expect_unsigned(
            &[Segment::Name("patterns"), Segment::Index(index)],
            3,
            any_pattern,
            MetricErrorV1::InvalidEncoding,
        )?;
        if let Some(patterns) = patterns.as_deref_mut() {
            patterns.push(pattern);
        }
    }
    decoder.finish()
}

fn encode_quantization(patterns: &[u64]) -> Vec<u8> {
    let mut result = Encoder(Vec::new());
    result.array(3);
    result.text(QUANTIZATION_RESULT_MAGIC);
    result.integer(i128::from(RECORD_VERSION));
    result.array(patterns.len());
    for pattern in patterns {
        match quantize_probability_v1(*pattern) {
            Ok(micros) => result.integer(i128::from(micros)),
            Err(error) => result.integers(&[i128::from(error.code())]),
        }
    }
    result.0
}
