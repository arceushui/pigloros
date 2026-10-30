//! The `MTI1` codec: section 4.6 decode order and the canonical encoder.

use std::cmp::Ordering;

use super::cbor::{
    boolean, check_structure, optional_unsigned, put_array, put_simple, put_text, put_unsigned,
    require, text, unsigned, Coordinate, Reader, Shape,
};
use super::{
    MetricErrorV1, MetricFailureV1, MetricInputV1, MetricRecordStateV1, MetricRecordV1,
    MAX_METRIC_IDENTIFIER_BYTES, MAX_METRIC_RECORDS, METRIC_ALGORITHM_ID, METRIC_ALGORITHM_MAJOR,
    MICROS_PER_UNIT,
};

const SHAPE: Shape = Shape {
    fields: &[
        "magic",
        "version",
        "algorithm_id",
        "algorithm_major",
        "binning",
        "minimum_scored_records",
        "record_count",
        "records",
    ],
    list: 7,
    element_fields: Some(6),
};

const OBSERVED: u64 = 0;
const PENDING: u64 = 1;
const REDACTED: u64 = 2;
const UNAVAILABLE: u64 = 3;
/// The encoding of `null`.
const NULL: u8 = 0xf6;

pub(super) fn decode(bytes: &[u8]) -> Result<MetricInputV1, MetricFailureV1> {
    check_structure(bytes, &SHAPE)?;
    let mut reader = Reader::fields(bytes);
    let version = MetricErrorV1::UnsupportedVersion;
    let algorithm = MetricErrorV1::UnsupportedAlgorithm;
    reader.header("magic", text, &b"MTI1".as_slice(), version)?;
    reader.header("version", unsigned, &1, version)?;
    let algorithm_id = METRIC_ALGORITHM_ID.as_bytes();
    reader.header("algorithm_id", text, &algorithm_id, algorithm)?;
    reader.header(
        "algorithm_major",
        unsigned,
        &METRIC_ALGORITHM_MAJOR,
        algorithm,
    )?;
    reader.header("binning", unsigned, &0, MetricErrorV1::InvalidBinning)?;
    let minimum_scored_records = minimum(&mut reader)?;
    let declared = Coordinate::name("record_count");
    let record_count = reader.field(&declared, unsigned)?;
    require(
        record_count <= MAX_METRIC_RECORDS,
        &declared,
        MetricErrorV1::ResourceLimit,
    )?;
    let records_at = Coordinate::name("records");
    require(
        reader.list() == record_count,
        &records_at,
        MetricErrorV1::InconsistentLength,
    )?;
    let mut records: Vec<MetricRecordV1> =
        Vec::with_capacity(usize::try_from(record_count).unwrap_or_default());
    for index in 0..record_count {
        let at = records_at.child(index);
        let previous = records.last().map(|record| record.prediction_id.as_bytes());
        let record = read_record(&mut reader, &at, previous)?;
        records.push(record);
    }
    Ok(MetricInputV1 {
        bytes: bytes.to_vec(),
        minimum_scored_records,
        records,
    })
}

fn minimum(reader: &mut Reader<'_>) -> Result<u32, MetricFailureV1> {
    let at = Coordinate::name("minimum_scored_records");
    let value = reader.field(&at, unsigned)?;
    u32::try_from(value)
        .ok()
        .filter(|minimum| (1..=MAX_METRIC_RECORDS).contains(&u64::from(*minimum)))
        .ok_or_else(|| at.failure(MetricErrorV1::InvalidMinimum))
}

/// Read a 1..=64-byte UTF-8 identifier (G1).
fn identifier(reader: &mut Reader<'_>, at: &Coordinate<'_>) -> Result<String, MetricFailureV1> {
    let bytes = reader.field(at, text)?;
    std::str::from_utf8(bytes)
        .ok()
        .filter(|id| (1..=MAX_METRIC_IDENTIFIER_BYTES).contains(&id.len()))
        .map(str::to_owned)
        .ok_or_else(|| at.failure(MetricErrorV1::InvalidIdentifier))
}

fn read_record(
    reader: &mut Reader<'_>,
    at: &Coordinate<'_>,
    previous: Option<&[u8]>,
) -> Result<MetricRecordV1, MetricFailureV1> {
    reader.element();
    let prediction_at = at.child(0);
    let prediction_id = identifier(reader, &prediction_at)?;
    match previous.map(|previous| prediction_id.as_bytes().cmp(previous)) {
        Some(Ordering::Equal) => Err(prediction_at.failure(MetricErrorV1::DuplicatePrediction)),
        Some(Ordering::Less) => Err(prediction_at.failure(MetricErrorV1::NonCanonicalOrder)),
        _ => Ok(()),
    }?;
    let entity_id = identifier(reader, &at.child(1))?;
    let probability_at = at.child(2);
    let probability = reader.field(&probability_at, unsigned)?;
    let probability_micros = u32::try_from(probability)
        .ok()
        .filter(|micros| *micros <= MICROS_PER_UNIT)
        .ok_or_else(|| probability_at.failure(MetricErrorV1::InvalidProbability))?;
    let state = read_state(reader, at)?;
    Ok(MetricRecordV1 {
        prediction_id,
        entity_id,
        probability_micros,
        state,
    })
}

/// Read `outcome_state`, `outcome` and `predictor_supplied` (G3, G4).
fn read_state(
    reader: &mut Reader<'_>,
    at: &Coordinate<'_>,
) -> Result<MetricRecordStateV1, MetricFailureV1> {
    let invalid = MetricErrorV1::InvalidOutcome;
    let state_at = at.child(3);
    let state = reader.field(&state_at, unsigned)?;
    require(state <= UNAVAILABLE, &state_at, invalid)?;
    let outcome_at = at.child(4);
    let outcome = reader.field(&outcome_at, optional_unsigned)?;
    let observed = state == OBSERVED;
    let outcome = match (observed, outcome) {
        (true, Some(value @ 0..=1)) => Ok(Some(value == 1)),
        (false, None) => Ok(None),
        _ => Err(outcome_at.failure(invalid)),
    }?;
    let supplied_at = at.child(5);
    let predictor_supplied = reader.field(&supplied_at, boolean)?;
    require(observed || !predictor_supplied, &supplied_at, invalid)?;
    Ok(match (state, outcome) {
        (PENDING, _) => MetricRecordStateV1::Pending,
        (REDACTED, _) => MetricRecordStateV1::Redacted,
        (UNAVAILABLE, _) => MetricRecordStateV1::Unavailable,
        (_, outcome) => MetricRecordStateV1::Observed {
            outcome: outcome == Some(true),
            predictor_supplied,
        },
    })
}

/// The canonical `MTI1` bytes of `records`, written without validation.
pub(super) fn encode(minimum_scored_records: u32, records: &[MetricRecordV1]) -> Vec<u8> {
    let mut out = Vec::new();
    put_array(&mut out, 8);
    put_text(&mut out, "MTI1");
    put_unsigned(&mut out, 1);
    put_text(&mut out, METRIC_ALGORITHM_ID);
    put_unsigned(&mut out, METRIC_ALGORITHM_MAJOR);
    put_unsigned(&mut out, 0);
    put_unsigned(&mut out, u64::from(minimum_scored_records));
    let count = u64::try_from(records.len()).unwrap_or(u64::MAX);
    put_unsigned(&mut out, count);
    put_array(&mut out, count);
    for record in records {
        // The outcome is the one-byte unsigned integer 0 or 1, or `null`.
        let (state, outcome, supplied) = match record.state {
            MetricRecordStateV1::Observed {
                outcome,
                predictor_supplied,
            } => (OBSERVED, u8::from(outcome), predictor_supplied),
            MetricRecordStateV1::Pending => (PENDING, NULL, false),
            MetricRecordStateV1::Redacted => (REDACTED, NULL, false),
            MetricRecordStateV1::Unavailable => (UNAVAILABLE, NULL, false),
        };
        put_array(&mut out, 6);
        put_text(&mut out, &record.prediction_id);
        put_text(&mut out, &record.entity_id);
        put_unsigned(&mut out, u64::from(record.probability_micros));
        put_unsigned(&mut out, state);
        out.push(outcome);
        put_simple(&mut out, Some(supplied));
    }
    out
}
