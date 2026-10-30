//! ADR-062 Revision 7 metric computation profile `pigloros.w8.metric-computation`.
//!
//! This module is plugins/eval's own implementation of algorithm
//! `pigloros.metric.binary-calibration` major 1, written from the profile text
//! (`fixtures/conformance/profiles/metric-conformance/normative-requirements.md`). It owns:
//!
//! - the strict deterministic-CBOR codecs of the public records `MTI1` (input), `MTR1`
//!   (result), `MTQ1` (quantization input) and `MQR1` (quantization result);
//! - the section 4.3 integer algorithms: exact `u128`/`i128` intermediates, one final
//!   round-half-to-even to micro-units (10^-6), and the single documented 10^-18 floor of the
//!   personal base rate. No metric is computed with floating-point arithmetic;
//! - the section 4.4 bit-pattern quantization of an IEEE-754 binary64 probability.
//!
//! The decoder follows the section 4.6 decode order: one structural pass over the whole input
//! that keeps nothing, then the header fields in index order, then the records in order with
//! their fields in index order. The first failure wins. Arrays nested deeper than
//! [`MAX_NESTING_DEPTH`] levels (the root array is level 1) are `InvalidEncoding` at the
//! over-deep array.

mod cbor;
mod compute;
mod input;
mod quantization;

pub use quantization::{
    decode_quantization_input_v1, encode_quantization_result_v1, quantize_probability,
};

/// The algorithm identifier of profile `pigloros.w8.metric-computation`.
pub const METRIC_ALGORITHM_ID: &str = "pigloros.metric.binary-calibration";
/// The algorithm major version this implementation computes.
pub const METRIC_ALGORITHM_MAJOR: u64 = 1;
/// The largest record count an `MTI1` input may declare (2^18).
pub const MAX_METRIC_RECORDS: u64 = 262_144;
/// The longest identifier, in UTF-8 bytes.
pub const MAX_METRIC_IDENTIFIER_BYTES: usize = 64;
/// The most bit patterns an `MTQ1` input may carry.
pub const MAX_QUANTIZATION_PATTERNS: u64 = 4_096;
/// The deepest array nesting the structural pass accepts; the root array is level 1.
pub const MAX_NESTING_DEPTH: usize = 16;
/// One probability unit: probabilities and metrics are integers in units of 10^-6.
pub const MICROS_PER_UNIT: u32 = 1_000_000;

/// The closed `MetricErrorV1` failure set of the profile, with its wire codes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MetricErrorV1 {
    /// A structural defect or a well-formed item of the wrong CBOR type.
    InvalidEncoding,
    /// An unknown magic or record version.
    UnsupportedVersion,
    /// An unknown algorithm identifier or algorithm major.
    UnsupportedAlgorithm,
    /// A binning other than `EqualWidth10`.
    InvalidBinning,
    /// `record_count` differs from the length of `records`.
    InconsistentLength,
    /// A probability outside `0..=1000000`, or a binary64 pattern that is not a probability.
    InvalidProbability,
    /// An outcome state, outcome or predictor-supplied flag that is not allowed together.
    InvalidOutcome,
    /// An identifier that is not 1..=64 bytes of UTF-8.
    InvalidIdentifier,
    /// A `prediction_id` equal to the previous record's.
    DuplicatePrediction,
    /// A `prediction_id` below the previous record's.
    NonCanonicalOrder,
    /// `minimum_scored_records` outside `1..=262144`.
    InvalidMinimum,
    /// A declared count above its bound.
    ResourceLimit,
}

impl MetricErrorV1 {
    /// The closed wire code of this failure.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::InvalidEncoding => 0,
            Self::UnsupportedVersion => 1,
            Self::UnsupportedAlgorithm => 2,
            Self::InvalidBinning => 3,
            Self::InconsistentLength => 4,
            Self::InvalidProbability => 5,
            Self::InvalidOutcome => 6,
            Self::InvalidIdentifier => 7,
            Self::DuplicatePrediction => 8,
            Self::NonCanonicalOrder => 9,
            Self::InvalidMinimum => 10,
            Self::ResourceLimit => 11,
        }
    }
}

/// A rejected input: the closed failure and its zero-based first coordinate, for example
/// `records/17/2`.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{error:?} at {coordinate}")]
pub struct MetricFailureV1 {
    /// The closed failure.
    pub error: MetricErrorV1,
    /// The section 4.6 coordinate of the first failure.
    pub coordinate: String,
}

/// The outcome state of one record, with the fields that state allows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricRecordStateV1 {
    /// The outcome is observed and scored.
    Observed {
        /// The binary outcome.
        outcome: bool,
        /// The outcome came from the predictor's own source (ADR-024 Revision 1 Decision 5).
        predictor_supplied: bool,
    },
    /// No outcome is known yet.
    Pending,
    /// The outcome is withheld by redaction.
    Redacted,
    /// The outcome evidence is missing.
    Unavailable,
}

/// One `MetricRecordV1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetricRecordV1 {
    /// Identifier of the prediction; records sort strictly by its UTF-8 bytes.
    pub prediction_id: String,
    /// Identifier of the entity the prediction is about.
    pub entity_id: String,
    /// The predicted probability in micro-units, `0..=1000000`.
    pub probability_micros: u32,
    /// The outcome state.
    pub state: MetricRecordStateV1,
}

/// A validated `MTI1` input together with its canonical bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetricInputV1 {
    bytes: Vec<u8>,
    minimum_scored_records: u32,
    records: Vec<MetricRecordV1>,
}

impl MetricInputV1 {
    /// Strictly decode and validate one `MTI1` input.
    ///
    /// # Errors
    /// Returns the first [`MetricFailureV1`] in section 4.6 decode order.
    pub fn decode(bytes: &[u8]) -> Result<Self, MetricFailureV1> {
        input::decode(bytes)
    }

    /// Build the canonical `MTI1` input of the given records, validating it exactly as
    /// [`MetricInputV1::decode`] validates the same bytes.
    ///
    /// # Errors
    /// Returns the first [`MetricFailureV1`] of the encoded input, for example
    /// `NonCanonicalOrder` for unsorted records or `ResourceLimit` above 262,144 records.
    pub fn from_records(
        minimum_scored_records: u32,
        records: &[MetricRecordV1],
    ) -> Result<Self, MetricFailureV1> {
        input::decode(&input::encode(minimum_scored_records, records))
    }

    /// The canonical `MTI1` bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// The caller-declared minimum number of scored records.
    #[must_use]
    pub const fn minimum_scored_records(&self) -> u32 {
        self.minimum_scored_records
    }

    /// The records in canonical order.
    #[must_use]
    pub const fn records(&self) -> &[MetricRecordV1] {
        self.records.as_slice()
    }

    /// Compute the section 4.3 `MTR1` result of this input.
    #[must_use]
    pub fn compute(&self) -> MetricResultV1 {
        compute::result_of(self)
    }
}

/// `MetricValuesV1`: every metric in signed micro-units (10^-6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetricValuesV1 {
    /// Brier Score.
    pub brier: i64,
    /// CRPS; equal to the Brier Score for binary outcomes.
    pub crps: i64,
    /// Expected Calibration Error over the ten equal-width bins.
    pub ece: i64,
    /// Brier Score of the constant mean predicted probability.
    pub population_avg_brier: i64,
    /// Population-average baseline Brier Score minus the Brier Score, rounded once.
    pub lift_vs_population_avg: i64,
    /// Brier Score of the constant fraction of positive outcomes.
    pub persistence_brier: i64,
    /// Persistence baseline Brier Score minus the Brier Score, rounded once.
    pub lift_vs_persistence: i64,
    /// Brier Score of the leave-one-out personal base rate.
    pub personal_base_rate_brier: i64,
    /// Personal-base-rate Brier Score minus the Brier Score, rounded once.
    pub lift_vs_personal_base_rate: i64,
}

/// One reliability bin: exact integer sums; means are left to the consumer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReliabilityBin {
    /// Number of scored records in the bin.
    pub count: u64,
    /// Sum of their probabilities in micro-units.
    pub probability_sum_micros: u64,
    /// Number of positive outcomes among them.
    pub positives: u64,
}

/// The counts of an `MTR1` result.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MetricCountsV1 {
    /// Number of records in the input.
    pub record_count: u64,
    /// Number of Observed records.
    pub scored: u64,
    /// Number of Pending records.
    pub pending: u64,
    /// Number of Redacted records.
    pub redacted: u64,
    /// Number of Unavailable records.
    pub unavailable: u64,
    /// Number of scored records whose outcome is predictor-supplied.
    pub predictor_supplied: u64,
    /// Number of distinct entities among the scored records.
    pub scored_entities: u64,
}

/// The `MTR1` redaction state; the weakest state wins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricRedactionStateV1 {
    /// No record is Redacted or Unavailable.
    None,
    /// At least one record is Redacted and none is Unavailable.
    RedactedViews,
    /// At least one record is Unavailable.
    EvidenceMissing,
}

/// The `MTR1` result kind with the values it carries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetricOutcomeV1 {
    /// At least `minimum_scored_records` records were scored.
    Computed {
        /// The metric values.
        values: MetricValuesV1,
        /// The ten reliability bins in index order.
        bins: [ReliabilityBin; 10],
    },
    /// Fewer than `minimum_scored_records` records were scored; no metric is reported.
    InsufficientSamples,
}

/// One `MTR1` result, bound to the digest of the `MTI1` it was computed from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetricResultV1 {
    /// `BLAKE3("PiglorOS.MetricInput.v1\0" || MTI1 bytes)`.
    pub input_digest: [u8; 32],
    /// The record counts.
    pub counts: MetricCountsV1,
    /// The minimum copied from the input.
    pub minimum_scored_records: u32,
    /// The redaction state of the records.
    pub redaction_state: MetricRedactionStateV1,
    /// The result kind and its values.
    pub outcome: MetricOutcomeV1,
}

impl MetricResultV1 {
    /// The canonical `MTR1` bytes, ending with the domain-separated result digest.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        compute::encode_result(self)
    }
}
