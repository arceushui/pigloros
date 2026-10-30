# Metric computation profile requirements

Profile `pigloros.w8.metric-computation`, claim layer `MetricConformance = 5`, subject adapter
`exported-artifact`. Source: ADR-062 Revision 7 "Metric Computation Profile" (accepted
2026-10-28), sections 4.1 to 4.5, which are reproduced below. Section 4.6 restates the 4.2
decode order and lists the gaps that sections 4.2 and 4.4 leave open, which the fixtures pin;
section 4.7 is the CDDL of the four public records; section 5 lists the
fixture sub-cases.

## 4.1 Profile identity, claim and versioning

1. The profile `pigloros.w8.metric-computation` (claim layer `MetricConformance = 5`, subject
   adapter `exported-artifact`) defines **metric algorithm `pigloros.metric.binary-calibration`,
   algorithm major 1**. The algorithm covers Brier Score, CRPS, ECE with reliability bins, three
   Lift baselines (population average, persistence, personal base rate) and the
   personal-base-rate Brier Score, all for binary outcomes.
2. A pass establishes only that the implementation under test turned each public `MTI1` input
   into the expected `MTR1` bytes or the expected closed failure. It does **not** establish
   calibration quality, predictive benefit, representativeness (ADR-040), external validity or
   deployment fitness. Empirical evaluation (claim layer 6) stays separate.
3. **Versioning.** A change to any of the following creates a new profile **major** version,
   with a new algorithm major and new record versions:
   - a formula, bin edge or assignment rule;
   - the quantization or rounding rule;
   - a bound;
   - the failure set or its precedence;
   - a field, or the meaning of an existing field.

   Additive fixture cases that do not change the expected result of any existing case create a
   **minor** version. Changes to wording only, with no byte changes, create a **patch**.

   The first normative content that replaces a Draft placeholder (item 4) keeps
   `semantic_version` 1.0.0, because there is no earlier expected behaviour for it to change.
   After that, any change to the expected behaviour of a case, including a change to a rule of
   section 4.6, creates a new major version as listed above.

   Records carry a numeric schema version (`1`). An unknown magic, version, algorithm ID or
   algorithm major is `UnsupportedVersion` or `UnsupportedAlgorithm`. There are no upcasters,
   aliases or fallbacks. Results stay bound to the `MTI1` digest, the `MTR1` digest and the CPF1
   profile digest they were produced under, and old results are never rewritten.
4. **The Draft placeholder is replaced, not migrated.** The `fixture-ratio` records were Draft,
   and no CNR1 report reached Candidate or Stable. The provider is
   `pigloros.fixture.metric-conformance@2.0.0`. The placeholder has no reader, alias or
   compatibility window.

## 4.2 Public records

All records are RFC 8949 core-deterministic, definite-length CBOR arrays of exact length.
Parsers reject maps, tags, floats (major type 7 except `null`, `true` and `false` where a field
allows them), indefinite lengths, non-preferred integer widths, invalid UTF-8, unknown, missing
or trailing fields, and trailing bytes. Every integer is checked, and overflow fails closed.

```text
MetricInputV1 (MTI1) = [
  "MTI1", 1,
  algorithm_id,              # exact "pigloros.metric.binary-calibration"
  algorithm_major,           # 1
  binning,                   # EqualWidth10 = 0 (closed enum; only 0 in v1)
  minimum_scored_records,    # u32, 1..=262144
  record_count,              # u32, 0..=262144; must equal len(records)
  records                    # array of record_count MetricRecordV1
]

MetricRecordV1 = [
  prediction_id,             # tstr, 1..=64 UTF-8 bytes
  entity_id,                 # tstr, 1..=64 UTF-8 bytes
  probability_micros,        # uint, 0..=1000000
  outcome_state,             # Observed=0 | Pending=1 | Redacted=2 | Unavailable=3
  outcome,                   # 0 | 1 when outcome_state = Observed, else null
  predictor_supplied         # bool; true only when Observed (ADR-024 R1 D5)
]
```

Records sort strictly by `prediction_id` UTF-8 bytes, with no duplicates. Because every metric
is an exact integer function, the order fixes only the canonical bytes and the input digest. It
never fixes a value.

```text
MetricResultV1 (MTR1) = [
  "MTR1", 1, algorithm_id, algorithm_major, binning,
  input_digest32,            # BLAKE3("PiglorOS.MetricInput.v1\0" || MTI1 bytes)
  result_kind,               # Computed=0 | InsufficientSamples=1
  counts,                    # [record_count, scored, pending, redacted,
                             #  unavailable, predictor_supplied, scored_entities]
  minimum_scored_records,    # copied from MTI1
  redaction_state,           # None=0 | RedactedViews=1 | EvidenceMissing=3 (ADR-062 CNR1 enum)
  metrics_or_null,           # MetricValuesV1 when Computed, null otherwise
  bins_or_null,              # 10 x [count, probability_sum_micros, positives] when Computed
  result_digest32            # BLAKE3("PiglorOS.MetricResult.v1\0" || fields 0..11)
]

MetricValuesV1 = [           # all in signed micro-units (10^-6)
  brier_micros,              # 0..=1000000
  crps_micros,               # 0..=1000000
  ece_micros,                # 0..=1000000
  population_avg_brier_micros,
  lift_vs_population_avg_micros,     # -1000000..=1000000
  persistence_brier_micros,
  lift_vs_persistence_micros,
  personal_base_rate_brier_micros,
  lift_vs_personal_base_rate_micros
]
```

`redaction_state` is `EvidenceMissing` if `unavailable > 0`, otherwise `RedactedViews` if
`redacted > 0`, otherwise `None`. The weakest state wins.

A rejected input is not an `MTR1`. It is an `EOE1` Failure carrying the closed
`MetricErrorV1`:

`InvalidEncoding=0 | UnsupportedVersion=1 | UnsupportedAlgorithm=2 | InvalidBinning=3 |
InconsistentLength=4 | InvalidProbability=5 | InvalidOutcome=6 | InvalidIdentifier=7 |
DuplicatePrediction=8 | NonCanonicalOrder=9 | InvalidMinimum=10 | ResourceLimit=11`

**Failure precedence.** The first failure in decode order wins: structure, then header fields
in index order, then records in order, with fields in index order inside each record.
`ResourceLimit` on a declared `record_count` above 262,144 is raised before any record is
allocated. CNR1 `first_coordinate` is the zero-based path, for example `records/17/2`.

**Bounds**:

| Bound | Value |
|---|---|
| Records | 262,144 (2^18) |
| Identifier length | 64 bytes |
| Encoded `MTI1` | 64 MiB, the #222 member ceiling |
| Encoded `MTR1` | 1 KiB |

Under these bounds every intermediate value in 4.3 fits in u128/i128 (worst case
`sum (P - n*y_i)^2 <= 2^18 * (2^18 * 10^6)^2 ~ 1.9e28`).

## 4.3 Algorithms

Notation: `D = 10^6`, `p_i` = `probability_micros`, `o_i` is in `{0,1}`, and `y_i = D * o_i`.
The scored set `S` is the set of records with `outcome_state = Observed`, and `n = |S|`.
`round(x)` is round-half-to-even of the exact rational `x` to an integer: `q = floor(x)`,
`r = x - q`; return `q + 1` if `r > 1/2`, or if `r = 1/2` and `q` is odd; otherwise return `q`.
`floor` is toward negative infinity.

0. **Undersized and empty inputs.** If `n < minimum_scored_records`, the result is
   `InsufficientSamples`, with counts and `redaction_state` filled in and metrics and bins
   `null`. An input with zero records, or one where every record is Pending, Redacted or
   Unavailable, is therefore `InsufficientSamples`, never zeros. `minimum_scored_records = 0`
   is `InvalidMinimum`. The profile asserts no statistical adequacy threshold: the caller
   declares its minimum, and representativeness stays ADR-040's.
1. **Brier Score.** `E = sum_S (p_i - y_i)^2` (exact, units 10^-12).
   `brier_micros = round(E / (n * D))`.
2. **CRPS.** For a Bernoulli forecast `p` against an outcome `o` in `{0,1}`, CRPS equals
   `(p - o)^2`. Algorithm major 1 defines CRPS only for binary outcomes, so
   `crps_micros = brier_micros`. Any continuous-distribution CRPS is a new algorithm major.
3. **ECE and reliability bins.** The bin index is `k = min(p_i div 100000, 9)`, using integer
   division. Bin `k` therefore covers `[k*100000, (k+1)*100000)` and bin 9 also includes
   1,000,000. For each bin, `count_k` is the number of scored records, `P_k = sum p_i` and `Y_k`
   is the number of positives. `ece_micros = round(sum_k |P_k - D*Y_k| / n)`. This equals
   `sum_k (count_k/n) * |mean_p_k - frac_k|` exactly. `bins` lists all ten bins in index order,
   including empty ones as `[0,0,0]`. Means can be derived from the counts and sums, and are
   not stored.
4. **Population-average baseline.** `P = sum_S p_i`.
   `B_pop = sum_S (P - n*y_i)^2 / (n^3 * D^2)`, which is the Brier Score of the constant `P/n`.
   `population_avg_brier_micros = round(B_pop * D)`.
   `lift_vs_population_avg_micros = round((B_pop - E/(n*D^2)) * D)`. The exact difference is
   rounded once and is not a difference of rounded values.
5. **Persistence baseline.** `K` is the number of positives in `S`. `B_pers = K*(n - K) / n^2`.
   `persistence_brier_micros = round(B_pers * D)`.
   `lift_vs_persistence_micros = round((B_pers - E/(n*D^2)) * D)`.
6. **Personal base rate (leave-one-out).** Group `S` by `entity_id`. For an entity `e` with
   `n_e` records and `K_e` positives:
   - if `n_e >= 2`, the entity term is `T_e = K_e*(n_e - K_e)*n_e / (n_e - 1)^2`. This is the
     exact sum of `(b_i - o_i)^2` with `b_i = (K_e - o_i)/(n_e - 1)`;
   - if `n_e = 1`, the baseline is 0, so `T_e = K_e`.

   **Intermediate quantization:** `T'_e = floor(T_e * 10^18)`, which is the only intermediate
   rounding in the algorithm. Then `B_pbr = sum_e T'_e / (n * 10^18)`,
   `personal_base_rate_brier_micros = round(B_pbr * D)`, and
   `lift_vs_personal_base_rate_micros = round((sum_e T'_e - 10^6 * E) / (n * 10^12))`.
   `scored_entities` is the number of distinct entities in `S`.
7. **Counts.** `predictor_supplied` counts scored records with `predictor_supplied = true`
   (ADR-024 R1 D5 label). It does not change any value.

**Worked example** (positive sub-case `pos.1`). Records, already in `prediction_id` order:

| Entity | `p` | Outcome |
|---|---|---|
| e1 | 700000 | 1 |
| e1 | 200000 | 0 |
| e1 | 900000 | 1 |
| e2 | 500000 | 0 |
| e3 | 100000 | Pending |

Result, with `minimum_scored_records = 1`:

- `scored` = 4, `pending` = 1, `scored_entities` = 2.
- `brier` 97500 (= 39/400) and `crps` 97500.
- `ece` 275000 (= 11/40).
- `population_avg_brier` 255625, lift 158125.
- `persistence_brier` 250000, lift 152500.
- `personal_base_rate_brier` 375000 (e1 has `T` = 3/2 and e2 has `T` = 0), lift 277500.
- Non-empty bins: 2 = `[1,200000,0]`, 5 = `[1,500000,0]`, 7 = `[1,700000,1]`,
  9 = `[1,900000,1]`.

## 4.4 Mapping committed `eval.*` Events to `MTI1` (plugins/eval)

The profile tests `MTI1 -> MTR1`. plugins/eval also owns the deterministic mapping from a
committed, authorized Event sequence to `MTI1`, specified here so that two readers of the same
Events build the same input:

1. **Probability quantization (`MTQ1` vectors).** `predicted_prob` is taken as its IEEE-754
   binary64 **bit pattern** (u64) and converted with integer arithmetic only:
   - NaN, +Inf, -Inf, values below 0 (other than -0.0) and values above 1 are
     `InvalidProbability` (ADR-024 R2 check 4, no clamping);
   - otherwise the result is `round(exact_value * 10^6)`, half to even.

   Normative vectors:

   | Input | `probability_micros` |
   |---|---|
   | `0x0000000000000000` (0.0) | 0 |
   | `0x8000000000000000` (-0.0) | 0 |
   | `0x3FF0000000000000` (1.0) | 1000000 |
   | 0.1 | 100000 |
   | 0.15 | 150000 |
   | 2^-7 = 0.0078125 | 7812 (tie to even) |
   | 3 * 2^-7 | 23438 (tie to even) |
   | smallest subnormal | 0 |
   | 1.000001 | `InvalidProbability` |

   `MTQ1 = ["MTQ1", 1, [* u64]]` (1..=4096 patterns) and
   `MQR1 = ["MQR1", 1, [* (uint / error)]]` are public test records for this mapping only.
2. One `MetricRecordV1` is built per `eval.prediction`. `prediction_id` and `entity_id` come
   from the payload, and identifiers outside 1..=64 bytes are `InvalidIdentifier`.
3. A second `eval.prediction` with the same `prediction_id` is `DuplicatePrediction`. A second
   `eval.outcome` for the same `prediction_id` is a mapping error `DuplicateOutcome`. The
   mapping never silently keeps the first one. An outcome that names no prediction is not part
   of `MTI1`; it is reported as a mapping diagnostic count, not as a metric.
4. A prediction with no outcome is `Pending`. A prediction or outcome withheld by the ADR-060
   host evaluation is `Redacted`, or `Unavailable` when the evidence is missing. Nothing is
   reconstructed. `CalibrationReport::apply_artifact_evaluation` keeps weakening the report's
   ReplayClaim and redaction state.
5. The mapping walks the Events in Timeline Order and checks the fields of one Event in
   `MTI1` record field-index order, the first failure winning as in 4.2, so an Event with an
   invalid `prediction_id` and an invalid probability is `InvalidIdentifier`; a withheld
   prediction's probability is never read or quantized (ADR-062 R7 Event mapping note,
   2026-10-30).

## 4.5 Implementations and oracle independence

1. **plugins/eval (the implementation under test).** It exposes the public
   `MTI1`/`MTR1`/`MTQ1` codecs and computation, and `compute_report_from_events` builds
   `CalibrationReport` from `MTR1`. The f64 metric fields
   become the micro-unit integers, and `InsufficientSamples` replaces the zero-filled empty
   report. No authoritative path uses f64 arithmetic for a metric.
2. **Expected results** are public immutable data written by an offline generator that calls no
   Rust (`scripts/generate_metric_conformance_fixtures.py`). The generator uses exact rational
   arithmetic (Python `fractions.Fraction` and integers), and its `--check` mode regenerates and
   compares every file.
3. **crates/pos-reference** reimplements decoding, validation, the 4.3 algorithms and the 4.4
   quantization from this text. It does not depend on plugins/eval, pos-conformance or any
   plugin, and it must reproduce every oracle byte. plugins/eval is never called to produce or
   check an expected result.
4. Local and Air-Gapped materializations bind identical oracle bytes. A pass requires identical
   `MTR1` bytes or the identical failure code and first coordinate in both modes.
5. These three agreeing (generator, pos-reference, plugins/eval) is Candidate evidence. Under
   ADR-062, Stable still requires two independently developed implementations under test.
   pos-reference is the evaluator side, and an evaluator does not count as a second
   implementation under test.

## 4.6 Decode order and the details the fixtures fill in

The decode order is the one section 4.2 states: structure, then header fields in index order,
then records in order, with fields in index order inside each record. The first failure wins.

1. **Structure.** A single structural pass covers the whole input before any field is
   interpreted. It keeps nothing, so it allocates no record. It rejects the structural defects
   that 4.2 lists, all as `InvalidEncoding`:
   - maps, tags, floats and simple values other than `false`, `true` and `null`;
   - indefinite lengths and non-preferred integer or length heads;
   - truncated items;
   - missing or trailing fields: a root that is not an array of exactly 8 fields, a `records`
     field that is not an array, or a record that is not an array of exactly 6 fields;
   - an array nested deeper than 16 levels (G10);
   - trailing bytes after the root item.

   The structural pass reads the records array head but keeps no record. It does not compare
   that length with `record_count`.
2. **Header fields**, in index order:
   - a magic other than the text `"MTI1"`, or a version other than 1, is `UnsupportedVersion`;
   - an algorithm id other than the exact text, or an algorithm major other than 1, is
     `UnsupportedAlgorithm`;
   - binning other than 0 is `InvalidBinning`;
   - a minimum outside 1..=262144 is `InvalidMinimum`;
   - a declared `record_count` above 262,144 is `ResourceLimit`. This check reads only the
     declared count, before any record is allocated or decoded;
   - a records array whose length differs from `record_count` is `InconsistentLength`.
3. **Records** in order, and fields in index order inside each record:
   - `prediction_id`: `InvalidIdentifier`, then its order against the previous record (equal is
     `DuplicatePrediction`, smaller is `NonCanonicalOrder`);
   - `entity_id`: `InvalidIdentifier`;
   - `probability_micros`: `InvalidProbability`;
   - `outcome_state`, `outcome` and `predictor_supplied`: `InvalidOutcome`.

The following points fill gaps that sections 4.2 and 4.4 leave open. The profile owner
confirmed them as normative on 2026-10-30, and the fixtures pin them:

- **G1. Identifier UTF-8.** Invalid UTF-8 in an identifier is `InvalidIdentifier` (section 5,
  `mal.11`), not a structural `InvalidEncoding`. It is checked when that field is read.
- **G2. Wrong CBOR type.** A well-formed item of the wrong CBOR type for its field is
  `InvalidEncoding` at that field. It is found when that field is read in step 2 or 3. Examples
  are a text string or negative integer where an unsigned integer is required, and a non-boolean
  `predictor_supplied`.
- **G3. Out-of-range `outcome_state`.** An `outcome_state` above 3 is `InvalidOutcome` at
  `records/<i>/3`.
- **G4. `predictor_supplied` on a non-Observed record.** `true` there is `InvalidOutcome` at
  `records/<i>/5`. The rule is in 4.2; the error is not.
- **G5. Order check position.** The order check runs right after `prediction_id`, so its
  coordinate is `records/<i>/0`.
- **G6. Coordinates.**
  - Header fields are named `magic`, `version`, `algorithm_id`, `algorithm_major`, `binning`,
    `minimum_scored_records`, `record_count` and `records`.
  - A record is `records/<i>` and its fields are `records/<i>/<j>`, zero-based.
  - A nested item inside a field appends its index.
  - The root item is `input`, and bytes after it are `trailing`.
- **G7. `MTR1` digest.** `fields 0..11` is the deterministic CBOR encoding of the 12-item array
  of fields 0 to 11. `result_digest32` is the BLAKE3 hash of the domain followed by that encoding.
- **G8. `MQR1` error.** A pattern that is `InvalidProbability` is the one-item array `[5]`
  (`[MetricErrorV1]`), so it cannot be confused with an unsigned result.
- **G9. `MTR1` acceptance.** A result whose magic or version differs is `UnsupportedVersion`.
  One whose algorithm id or algorithm major differs is `UnsupportedAlgorithm`, at that field.
- **G10. Nesting depth.** The root array is level 1, a header field level 2, a record level 3
  and a record field level 4. An array nested deeper than 16 levels is `InvalidEncoding` at
  the coordinate of the over-deep array (the first array at level 17), found by the structural
  pass. An array at level 16 passes the structural pass; it is then a field of the wrong type
  (G2). Every well-formed public record nests at most 3 levels, so the cap bounds only the walk
  of malformed input (`mal.14a`, `mal.14b`).
- **G11. `MTQ1` shape.** The `MTQ1` fields are named `magic`, `version` and `patterns`, and a
  pattern is `patterns/<i>`. The decode order is the one above: structure (a root that is not
  an array of exactly 3 fields, or a `patterns` field that is not an array, is
  `InvalidEncoding`), then `magic` and `version` (`UnsupportedVersion`), then `patterns`, then
  each pattern in index order:
  - a `patterns` field that is not an array, or an empty `patterns` array, is
    `InvalidEncoding` at `patterns`;
  - more than 4,096 patterns is `ResourceLimit` at `patterns`;
  - an entry that is not an unsigned integer is `InvalidEncoding` at `patterns/<i>`.

  (`mal.16a` to `mal.16d`.)
- **G12. Header text UTF-8.** Invalid UTF-8 in a header text field is that field's failure,
  not a structural `InvalidEncoding`: in `magic` it is `UnsupportedVersion` and in
  `algorithm_id` it is `UnsupportedAlgorithm`, at that field (`mal.15a`, `mal.15b`).

## 4.7 CDDL

```cddl
metric-input = [
  magic: "MTI1",
  version: 1,
  algorithm-id: "pigloros.metric.binary-calibration",
  algorithm-major: 1,
  binning: equal-width-10,
  minimum-scored-records: 1..262144,
  record-count: 0..262144,          ; equals the length of records
  records: [* metric-record],
]

equal-width-10 = 0

metric-record = [
  prediction-id: identifier,        ; strictly ascending by UTF-8 bytes
  entity-id: identifier,
  probability-micros: 0..1000000,
  outcome-state: observed / pending / redacted / unavailable,
  outcome: 0 / 1 / null,            ; 0 or 1 exactly when outcome-state is observed
  predictor-supplied: bool,         ; true only when outcome-state is observed
]

identifier = tstr .size (1..64)
observed = 0
pending = 1
redacted = 2
unavailable = 3

metric-result = [
  magic: "MTR1",
  version: 1,
  algorithm-id: "pigloros.metric.binary-calibration",
  algorithm-major: 1,
  binning: equal-width-10,
  input-digest: bstr .size 32,
  result-kind: computed / insufficient-samples,
  counts: [
    record-count: uint,
    scored: uint,
    pending-count: uint,
    redacted-count: uint,
    unavailable-count: uint,
    predictor-supplied-count: uint,
    scored-entities: uint,
  ],
  minimum-scored-records: 1..262144,
  redaction-state: redaction-none / redacted-views / evidence-missing,
  metrics: metric-values / null,    ; metric-values exactly when computed
  bins: [10*10 reliability-bin] / null,
  result-digest: bstr .size 32,
]

computed = 0
insufficient-samples = 1
redaction-none = 0
redacted-views = 1
evidence-missing = 3

metric-values = [
  brier-micros: 0..1000000,
  crps-micros: 0..1000000,
  ece-micros: 0..1000000,
  population-avg-brier-micros: 0..1000000,
  lift-vs-population-avg-micros: -1000000..1000000,
  persistence-brier-micros: 0..1000000,
  lift-vs-persistence-micros: -1000000..1000000,
  personal-base-rate-brier-micros: 0..1000000,
  lift-vs-personal-base-rate-micros: -1000000..1000000,
]

reliability-bin = [count: uint, probability-sum-micros: uint, positives: uint]

quantization-input = [
  magic: "MTQ1",
  version: 1,
  patterns: [1*4096 uint .size 8],  ; IEEE-754 binary64 bit patterns
]

quantization-result = [
  magic: "MQR1",
  version: 1,
  entries: [1*4096 (0..1000000 / quantization-error)],
]

quantization-error = [metric-error]

metric-error = 0..11                ; MetricErrorV1
```

## 5. Fixture families and sub-cases

Provider `pigloros.fixture.metric-conformance@2.0.0` uses the `metric-cbor-v1` adapter. Each
family has one JSON payload (schema `pigloros.metric-conformance.case.v2`) that names its
sub-cases, the BLAKE3 digest of each sub-case's auxiliary member and the expectation, and one
auxiliary composite `MCS1 = ["MCS1", 1, [* [digest32, member]]]` that carries the members
(`MTI1`, `MTQ1`, or for `dgr.3` an `MTR1`), sorted by digest. Canonical-output oracles carry the
`MTR1`/`MQR1` bytes of every sub-case; failure oracles carry the family's namespaced failure and,
per sub-case, the closed `MetricErrorV1` and first coordinate (or the transport, capability,
budget or contract failure). Every family is materialized for both `deterministic-local-v1` and
`deterministic-air-gapped-v1` with identical oracle bytes. Evidence-status records stay
`pending`.

- **positive**: `pos.1` worked example; `pos.2` bin edges 0, 99999, 100000, 899999, 900000,
  999999, 1000000; `pos.3a` to `pos.3e` half-way ties of brier, ece and negative lifts;
  `pos.4` personal base rate with `n_e` = 1, 2, 4 and 7, all-positive and all-negative entities
  and terms whose 10^-18 floor changes the rounded lift; `pos.5` predictor-supplied counting
  with a 64-byte identifier; `pos.6a` perfect and `pos.6b` worst predictor; `pos.7` the `MTQ1`
  vectors of 4.4; `pos.8a` to `pos.8c` `InsufficientSamples`.
- **denied**: `den.1` a capability other than `read-public-bundle`; `den.2` network use.
- **malformed**: `mal.1a` to `mal.12b`, and `mal.13a` to `mal.13i`, which have several defects
  each and pin the precedence and first coordinate. Structural defects come before header
  failures, record failures and trailing bytes. `mal.14a` and `mal.14b` nest arrays 16 and 17
  levels deep (G10); `mal.15a` and `mal.15b` carry invalid UTF-8 in `magic` and `algorithm_id`
  (G12); `mal.16a` to `mal.16d` are `MTQ1` inputs whose `patterns` is not an array, is empty,
  holds a text entry or holds 4,097 entries (G11).
- **resource-exhaustion**: `res.1` declared `record_count` 262,145; `res.2` an `MTI1` member of
  64 MiB + 1 byte, described by its length and rejected by the #222 transport
  (`FieldOutOfBounds`) without being stored in the repository; `res.3` the execution-step
  budget.
- **deletion-redaction**: `del.1a`, `del.1b` exclusion and `redaction_state`; `del.2` all
  Redacted; `del.3` a synthetic canary in `entity_id` that never appears in `MTR1`.
- **downgrade**: `dgr.1` `MTI1` version 2; `dgr.2` provider 1.0.0 where 2.0.0 is required;
  `dgr.3` an `MTR1` of algorithm major 2.
- **independent-evaluation**: `ind.1` a mixed 40-record input that pos-reference recomputes
  together with every positive and deletion-redaction oracle; `ind.2` the generator `--check`;
  `ind.3` further `MTQ1` patterns for pos-reference.

Operational watchdog expiry is not an executed conformance result.
