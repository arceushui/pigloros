//! Section 4.3 integer algorithms and the `MTR1` encoder.
//!
//! Every metric is the exact rational value of a closed formula over integers, evaluated in
//! `i128`, then rounded once, half to even, to micro-units. Under the profile bounds
//! (2^18 records, probabilities at most 10^6) the largest intermediate, the entity term
//! numerator `K_e * (n_e - K_e) * n_e * 10^18`, stays below 4.6 * 10^33.

use std::collections::BTreeMap;

use super::cbor::{put_array, put_bytes, put_signed, put_simple, put_text, put_unsigned};
use super::{
    MetricCountsV1, MetricInputV1, MetricOutcomeV1, MetricRecordStateV1, MetricRedactionStateV1,
    MetricResultV1, MetricValuesV1, ReliabilityBin, METRIC_ALGORITHM_ID, METRIC_ALGORITHM_MAJOR,
};

const INPUT_DOMAIN: &[u8] = b"PiglorOS.MetricInput.v1\0";
const RESULT_DOMAIN: &[u8] = b"PiglorOS.MetricResult.v1\0";
const D: i128 = 1_000_000;
/// The scale of the single intermediate quantization of the personal base rate.
const ENTITY_SCALE: i128 = 1_000_000_000_000_000_000;
const BIN_WIDTH: u32 = 100_000;

/// The exact sums of one input.
#[derive(Default)]
struct Tally<'a> {
    counts: MetricCountsV1,
    /// `E = sum (p_i - y_i)^2` over the scored set.
    squared_error: i128,
    /// `P = sum p_i` over the scored set.
    probability_sum: i128,
    /// `K`, the number of positive scored outcomes.
    positives: i128,
    bins: [ReliabilityBin; 10],
    /// `(n_e, K_e)` per scored entity.
    entities: BTreeMap<&'a str, (i128, i128)>,
}

impl<'a> Tally<'a> {
    fn of(input: &'a MetricInputV1) -> Self {
        let mut tally = Self::default();
        tally.counts.record_count = u64::try_from(input.records().len()).unwrap_or(u64::MAX);
        for record in input.records() {
            match record.state {
                MetricRecordStateV1::Observed {
                    outcome,
                    predictor_supplied,
                } => tally.score(
                    &record.entity_id,
                    record.probability_micros,
                    outcome,
                    predictor_supplied,
                ),
                MetricRecordStateV1::Pending => tally.counts.pending += 1,
                MetricRecordStateV1::Redacted => tally.counts.redacted += 1,
                MetricRecordStateV1::Unavailable => tally.counts.unavailable += 1,
            }
        }
        tally.counts.scored_entities = u64::try_from(tally.entities.len()).unwrap_or(u64::MAX);
        tally
    }

    fn score(&mut self, entity: &'a str, probability: u32, outcome: bool, supplied: bool) {
        let micros = i128::from(probability);
        let positive = i128::from(outcome);
        self.counts.scored += 1;
        self.counts.predictor_supplied += u64::from(supplied);
        self.squared_error += (micros - D * positive).pow(2);
        self.probability_sum += micros;
        self.positives += positive;
        let bin = &mut self.bins[usize::try_from((probability / BIN_WIDTH).min(9)).unwrap_or(9)];
        bin.count += 1;
        bin.probability_sum_micros += u64::from(probability);
        bin.positives += u64::from(outcome);
        let entity = self.entities.entry(entity).or_insert((0, 0));
        entity.0 += 1;
        entity.1 += positive;
    }

    fn values(&self) -> MetricValuesV1 {
        let scored = i128::from(self.counts.scored);
        let squared = self.squared_error;
        let positives = self.positives;
        let sum = self.probability_sum;
        let brier = round(squared, scored * D);
        let ece = round(
            self.bins
                .iter()
                .map(|bin| {
                    (i128::from(bin.probability_sum_micros) - D * i128::from(bin.positives)).abs()
                })
                .sum(),
            scored,
        );
        // sum (P - n*y_i)^2: K positive terms (P - n*D)^2 and n - K negative terms P^2.
        let population = positives * (sum - scored * D).pow(2) + (scored - positives) * sum.pow(2);
        let population_scale = scored.pow(3) * D;
        let persistence = positives * (scored - positives);
        let personal = self.personal_term_sum();
        let personal_scale = scored * D * D;
        MetricValuesV1 {
            brier,
            crps: brier,
            ece,
            population_avg_brier: round(population, population_scale),
            lift_vs_population_avg: round(population - scored * scored * squared, population_scale),
            persistence_brier: round(persistence * D, scored * scored),
            lift_vs_persistence: round(persistence * D * D - scored * squared, scored * scored * D),
            personal_base_rate_brier: round(personal, personal_scale),
            lift_vs_personal_base_rate: round(personal - D * squared, personal_scale),
        }
    }

    /// `sum_e floor(T_e * 10^18)`: `T_e = K_e (n_e - K_e) n_e / (n_e - 1)^2` for `n_e >= 2`,
    /// and `T_e = K_e` for a singleton, whose baseline is 0.
    fn personal_term_sum(&self) -> i128 {
        self.entities
            .values()
            .map(|&(count, positives)| {
                let denominator = (count - 1).pow(2).max(1);
                let numerator = if count == 1 {
                    positives
                } else {
                    positives * (count - positives) * count
                };
                (numerator * ENTITY_SCALE).div_euclid(denominator)
            })
            .sum()
    }
}

/// Round `numerator / denominator` half to even; `denominator` is positive.
fn round(numerator: i128, denominator: i128) -> i64 {
    let quotient = numerator.div_euclid(denominator);
    let twice_remainder = 2 * numerator.rem_euclid(denominator);
    let odd = quotient.rem_euclid(2) == 1;
    let up = twice_remainder > denominator || (twice_remainder == denominator && odd);
    i64::try_from(quotient + i128::from(up)).unwrap_or(i64::MAX)
}

pub(super) fn result_of(input: &MetricInputV1) -> MetricResultV1 {
    let tally = Tally::of(input);
    let counts = tally.counts;
    let redaction_state = if counts.unavailable > 0 {
        MetricRedactionStateV1::EvidenceMissing
    } else if counts.redacted > 0 {
        MetricRedactionStateV1::RedactedViews
    } else {
        MetricRedactionStateV1::None
    };
    let outcome = if counts.scored < u64::from(input.minimum_scored_records()) {
        MetricOutcomeV1::InsufficientSamples
    } else {
        MetricOutcomeV1::Computed {
            values: tally.values(),
            bins: Box::new(tally.bins),
        }
    };
    MetricResultV1 {
        input_digest: digest(INPUT_DOMAIN, input.as_bytes()),
        counts,
        minimum_scored_records: input.minimum_scored_records(),
        redaction_state,
        outcome,
    }
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

/// `MTR1` fields 0 to 11, without their array head.
fn result_fields(result: &MetricResultV1) -> Vec<u8> {
    let mut out = Vec::new();
    put_text(&mut out, "MTR1");
    put_unsigned(&mut out, 1);
    put_text(&mut out, METRIC_ALGORITHM_ID);
    put_unsigned(&mut out, METRIC_ALGORITHM_MAJOR);
    put_unsigned(&mut out, 0);
    put_bytes(&mut out, &result.input_digest);
    let counts = result.counts;
    let kind = match result.outcome {
        MetricOutcomeV1::Computed { .. } => 0,
        MetricOutcomeV1::InsufficientSamples => 1,
    };
    put_unsigned(&mut out, kind);
    put_array(&mut out, 7);
    for count in [
        counts.record_count,
        counts.scored,
        counts.pending,
        counts.redacted,
        counts.unavailable,
        counts.predictor_supplied,
        counts.scored_entities,
    ] {
        put_unsigned(&mut out, count);
    }
    put_unsigned(&mut out, u64::from(result.minimum_scored_records));
    put_unsigned(
        &mut out,
        match result.redaction_state {
            MetricRedactionStateV1::None => 0,
            MetricRedactionStateV1::RedactedViews => 1,
            MetricRedactionStateV1::EvidenceMissing => 3,
        },
    );
    match &result.outcome {
        MetricOutcomeV1::Computed { values, bins } => {
            put_values(&mut out, values);
            put_array(&mut out, 10);
            for bin in bins.iter() {
                put_array(&mut out, 3);
                put_unsigned(&mut out, bin.count);
                put_unsigned(&mut out, bin.probability_sum_micros);
                put_unsigned(&mut out, bin.positives);
            }
        }
        MetricOutcomeV1::InsufficientSamples => {
            put_simple(&mut out, None);
            put_simple(&mut out, None);
        }
    }
    out
}

fn put_values(out: &mut Vec<u8>, values: &MetricValuesV1) {
    put_array(out, 9);
    for value in [
        values.brier,
        values.crps,
        values.ece,
        values.population_avg_brier,
        values.lift_vs_population_avg,
        values.persistence_brier,
        values.lift_vs_persistence,
        values.personal_base_rate_brier,
        values.lift_vs_personal_base_rate,
    ] {
        put_signed(out, value);
    }
}

/// The canonical `MTR1` bytes: the 13-field array whose last field is
/// `BLAKE3("PiglorOS.MetricResult.v1\0" || encoding of the 12-field array of fields 0..11)`.
pub(super) fn encode_result(result: &MetricResultV1) -> Vec<u8> {
    let fields = result_fields(result);
    let mut sealed = Vec::with_capacity(fields.len() + 1);
    put_array(&mut sealed, 12);
    sealed.extend_from_slice(&fields);
    let result_digest = digest(RESULT_DOMAIN, &sealed);
    let mut out = Vec::with_capacity(fields.len() + 35);
    put_array(&mut out, 13);
    out.extend_from_slice(&fields);
    put_bytes(&mut out, &result_digest);
    out
}
