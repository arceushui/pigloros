//! The ADR-140 C1 seam (#305). The golden payloads, the claim key and the
//! request digest come from an independent Python encoding (a pure-Python
//! BLAKE3 and a hand-written deterministic CBOR encoder), and the Match Score
//! corpus from an independent Python implementation of ADR-140 section 1.

use std::error::Error;

use ciborium::value::Value as Cbor;
use serde::Deserialize;
use serde_json::{json, Value};

use super::*;

type TestResult = Result<(), Box<dyn Error>>;
type Fallible<T> = Result<T, Box<dyn Error>>;

/// The frozen normative corpus of `pigloros.match-score.v1` (ADR-140 P8).
const CORPUS: &str = include_str!("match_score_v1_vectors.json");

/// The ADR-140 C1 test-plan cases the corpus must hold.
const REQUIRED_VECTORS: [&str; 20] = [
    "worked-example",
    "rounding-1-2",
    "rounding-minus-1-minus-2",
    "rounding-1-1-1",
    "rounding-1-0-0",
    "rounding-1-1-0",
    "rounding-800000-500000",
    "extreme-scores-and-margin",
    "largest-signed-sums",
    "margin-19999-is-a-toss-up",
    "margin-20000-is-not-a-toss-up",
    "margin-0-tie-for-the-maximum",
    "insufficient-evidence",
    "zero-tag-option",
    "unmatched-tags-do-not-dilute",
    "substring-and-prefix-do-not-match",
    "lean-hint-and-coordinates-are-ignored",
    "maximum-weights-options-and-tags",
    "sixteen-matched-tags-per-option",
    "signed-sum-zero-is-computed",
];

const PRINCIPAL: &str = "01JC0GATEWAYPR1NC1PA100001";
const ACTOR: &str = "01JC0GATEWAYF1XTVREACT0R00";
const ROOM: &str = "01JC0GATEWAYW9R00M00000001";
const PREFERENCE: &str = "01JC0GATEWAYPREFERENCE0001";
const OPTION_SPEC: &str = "01JC0GATEWAY0PT10NSPEC0001";
const CONSENT: &str = "01JC0GATEWAYW90PR1VACY0001";
const PREVIEW: &str = "01JC0GATEWAYPREV1EW0000001";
const PROFILE: &str = "deterministic-local-v1";
const IDEMPOTENCY_KEY: &str = "retry-key-0001";

const GOLDEN_CLAIM_KEY: &str = "7f4f1ed9e408fb64534cd743700667efd935160a217df1c94a824b6eae5275df";
const GOLDEN_CLAIM_ENTITY: &str = "3Z9WFDKS08ZDJ56K6Q8DR0CSZF";
const GOLDEN_REQUEST_DIGEST: &str =
    "d875b8741c3c44bde8c6d013dc2e8720392b734de5a4c731a92e7bb1d094c687";
const GOLDEN_CLAIM: &str = concat!(
    "8b645052513101781a30314a4330474154455741595052314e43315041313030303031781a30314a",
    "433047415445574159463158545652454143543052303083781a30314a4330474154455741595739",
    "5230304d303030303030303103784061616161616161616161616161616161616161616161616161",
    "61616161616161616161616161616161616161616161616161616161616161616161616161616183",
    "781a30314a433047415445574159505245464552454e434530303031017840626262626262626262",
    "62626262626262626262626262626262626262626262626262626262626262626262626262626262",
    "62626262626262626262626262626283781a30314a43304741544557415930505431304e53504543",
    "3030303119012c784063636363636363636363636363636363636363636363636363636363636363",
    "636363636363636363636363636363636363636363636363636363636363636363781a30314a4330",
    "4741544557415957393050523156414359303030317664657465726d696e69737469632d6c6f6361",
    "6c2d7631784034343434343434343434343434343434343434343434343434343434343434343434",
    "34343434343434343434343434343434343434343434343434343434343478403535353535353535",
    "35353535353535353535353535353535353535353535353535353535353535353535353535353535",
    "35353535353535353535353535353535",
);
const GOLDEN_COMPUTED: &str = concat!(
    "86645052533101781a30314a433047415445574159505245563145573030303030303168636f6d70",
    "75746564777069676c6f726f732e6d617463682d73636f72652e7631f6",
);
const GOLDEN_FAILED: &str = concat!(
    "86645052533101781a30314a4330474154455741595052455631455730303030303031666661696c",
    "6564f66d696e7075742d64656c65746564",
);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    function_id: String,
    toss_up_margin_micro: i64,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Vector {
    name: String,
    weights: Vec<WireWeight>,
    options: Vec<WireOption>,
    expected: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireWeight {
    dimension: String,
    weight_micro: i64,
}

/// One corpus option. Its `lean_hint_micro` and `coordinates`, when present,
/// are ignored here because the function has no input for them (P2).
#[derive(Deserialize)]
struct WireOption {
    key: String,
    tags: Vec<String>,
}

fn weight(dimension: &str, weight_micro: i64) -> PreferenceWeightV1 {
    PreferenceWeightV1 {
        dimension: dimension.to_owned(),
        weight_micro,
    }
}

fn option(key: &str, tags: &[&str]) -> PreviewOptionV1 {
    PreviewOptionV1 {
        key: key.to_owned(),
        tags: tags.iter().copied().map(str::to_owned).collect(),
    }
}

fn worked_weights() -> Vec<PreferenceWeightV1> {
    vec![
        weight("city", -300_000),
        weight("nature", 800_000),
        weight("quiet", 500_000),
    ]
}

fn worked_options() -> Vec<PreviewOptionV1> {
    vec![
        option("coast", &["nature", "quiet", "surf"]),
        option("city", &["city", "nightlife"]),
    ]
}

fn numbered_weights(count: usize) -> Vec<PreferenceWeightV1> {
    (0..count)
        .map(|index| weight(&format!("dimension-{index}"), 0))
        .collect()
}

fn numbered_options(count: usize) -> Vec<PreviewOptionV1> {
    (0..count)
        .map(|index| option(&format!("option-{index}"), &["nature"]))
        .collect()
}

fn refusal(
    weights: &[PreferenceWeightV1],
    options: &[PreviewOptionV1],
) -> Option<MatchScoreErrorV1> {
    match_score_v1(weights, options).err()
}

fn render_score(score: &OptionScoreV1) -> Value {
    json!({"option_key": score.option_key, "match_score_micro": score.match_score_micro})
}

/// The corpus form of a Recommendation, the contract's `recommendation`.
fn render(recommendation: &RecommendationV1) -> Value {
    match recommendation {
        RecommendationV1::InsufficientEvidence => json!({"status": "insufficient-evidence"}),
        RecommendationV1::Computed(computed) => json!({
            "status": "computed",
            "scores": computed.scores.iter().map(render_score).collect::<Vec<_>>(),
            "margin_micro": computed.margin_micro,
            "toss_up": computed.toss_up,
            "option_key": computed.option_key,
        }),
    }
}

#[test]
fn match_score_v1_vectors_are_frozen() -> TestResult {
    let corpus: Corpus = serde_json::from_str(CORPUS)?;
    assert_eq!(corpus.function_id, MATCH_SCORE_FUNCTION_ID_V1);
    assert_eq!(corpus.toss_up_margin_micro, TOSS_UP_MARGIN_MICRO_V1);
    let mut names = BTreeSet::new();
    for vector in corpus.vectors {
        let weights: Vec<_> = vector
            .weights
            .iter()
            .map(|wire| weight(&wire.dimension, wire.weight_micro))
            .collect();
        let options: Vec<_> = vector
            .options
            .into_iter()
            .map(|wire| PreviewOptionV1 {
                key: wire.key,
                tags: wire.tags,
            })
            .collect();
        let actual = match_score_v1(&weights, &options)?;
        assert_eq!(render(&actual), vector.expected, "{}", vector.name);
        assert!(names.insert(vector.name), "a vector name repeats");
    }
    for name in REQUIRED_VECTORS {
        assert!(names.contains(name), "{name}");
    }
    Ok(())
}

#[test]
fn the_worked_example_recommends_coast() -> TestResult {
    let expected = RecommendationV1::Computed(ComputedRecommendationV1 {
        scores: vec![
            OptionScoreV1 {
                option_key: "coast".to_owned(),
                match_score_micro: 650_000,
            },
            OptionScoreV1 {
                option_key: "city".to_owned(),
                match_score_micro: -300_000,
            },
        ],
        margin_micro: 950_000,
        toss_up: false,
        option_key: Some("coast".to_owned()),
    });
    let actual = match_score_v1(&worked_weights(), &worked_options())?;
    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn every_bound_is_inclusive_at_its_limit() {
    let mut weights = numbered_weights(MAX_PREFERENCE_WEIGHTS_V1);
    weights[0].weight_micro = -MAX_MATCH_WEIGHT_MICRO_V1;
    weights[1].weight_micro = MAX_MATCH_WEIGHT_MICRO_V1;
    let tags: Vec<String> = (0..MAX_OPTION_TAGS_V1)
        .map(|index| format!("dimension-{index}"))
        .collect();
    let mut options = numbered_options(MAX_PREVIEW_OPTIONS_V1);
    options[0].tags = tags;
    let key = "k".repeat(128);
    options[1].key.clone_from(&key);
    weights[2].dimension.clone_from(&key);
    assert!(match_score_v1(&weights, &options).is_ok());
    let pair = numbered_options(MIN_PREVIEW_OPTIONS_V1);
    assert!(match_score_v1(&weights[..1], &pair).is_ok());
}

#[test]
fn every_out_of_bounds_input_is_refused() {
    use MatchScoreErrorV1 as Refusal;
    let weights = worked_weights();
    let options = worked_options();
    let too_many_weights = numbered_weights(MAX_PREFERENCE_WEIGHTS_V1 + 1);
    assert_eq!(refusal(&[], &options), Some(Refusal::WeightCount));
    assert_eq!(
        refusal(&too_many_weights, &options),
        Some(Refusal::WeightCount)
    );
    let long_key = "k".repeat(129);
    for invalid in ["", "Nature", "1nature", "na ture", long_key.as_str()] {
        let mut changed = weights.clone();
        changed[0].dimension = String::from(invalid);
        assert_eq!(
            refusal(&changed, &options),
            Some(Refusal::InvalidDimension),
            "{invalid}"
        );
    }
    let mut repeated = weights.clone();
    repeated.push(weight("nature", 1));
    assert_eq!(
        refusal(&repeated, &options),
        Some(Refusal::DuplicateDimension)
    );
    for out_of_range in [1_000_001, -1_000_001, i64::MAX, i64::MIN] {
        let mut changed = weights.clone();
        changed[0].weight_micro = out_of_range;
        assert_eq!(
            refusal(&changed, &options),
            Some(Refusal::WeightOutOfRange),
            "{out_of_range}"
        );
    }
    for count in [0, 1, MAX_PREVIEW_OPTIONS_V1 + 1] {
        assert_eq!(
            refusal(&weights, &numbered_options(count)),
            Some(Refusal::OptionCount),
            "{count}"
        );
    }
    let mut upper_case_key = options.clone();
    upper_case_key[0].key = String::from("Coast");
    assert_eq!(
        refusal(&weights, &upper_case_key),
        Some(Refusal::InvalidOptionKey)
    );
    let mut repeated_key = options.clone();
    repeated_key[1].key = String::from("coast");
    assert_eq!(
        refusal(&weights, &repeated_key),
        Some(Refusal::DuplicateOptionKey)
    );
    let mut changed = options.clone();
    changed[0].tags = (0..=MAX_OPTION_TAGS_V1)
        .map(|index| format!("tag-{index}"))
        .collect();
    assert_eq!(refusal(&weights, &changed), Some(Refusal::TagCount));
    let mut changed = options.clone();
    changed[1].tags.push("Surf".to_owned());
    assert_eq!(refusal(&weights, &changed), Some(Refusal::InvalidTag));
    let mut changed = options;
    changed[1].tags.push("city".to_owned());
    assert_eq!(refusal(&weights, &changed), Some(Refusal::DuplicateTag));
}

#[test]
fn every_error_has_a_distinct_message() {
    use MatchScoreErrorV1 as Refusal;
    let refusals = [
        Refusal::WeightCount,
        Refusal::InvalidDimension,
        Refusal::DuplicateDimension,
        Refusal::WeightOutOfRange,
        Refusal::OptionCount,
        Refusal::InvalidOptionKey,
        Refusal::DuplicateOptionKey,
        Refusal::TagCount,
        Refusal::InvalidTag,
        Refusal::DuplicateTag,
    ];
    let messages: BTreeSet<String> = refusals.iter().map(ToString::to_string).collect();
    assert_eq!(messages.len(), refusals.len());
    let too_large = PreviewPayloadErrorV1::TooLarge.to_string();
    assert_ne!(too_large, PreviewPayloadErrorV1::Corrupt.to_string());
}

/// A reproducible xorshift sequence for the property cases.
struct Draws(u64);

impl Draws {
    fn draw(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// A draw in `0..bound`.
    fn below(&mut self, bound: usize) -> usize {
        let bound = u64::try_from(bound).unwrap_or(u64::MAX);
        usize::try_from(self.draw() % bound).unwrap_or(0)
    }

    /// A weight in range, at either extreme one time in four.
    fn weight_micro(&mut self) -> i64 {
        let span = 2 * MAX_MATCH_WEIGHT_MICRO_V1.unsigned_abs() + 1;
        let uniform = i64::try_from(self.draw() % span).unwrap_or(0) - MAX_MATCH_WEIGHT_MICRO_V1;
        match self.below(8) {
            0 => MAX_MATCH_WEIGHT_MICRO_V1,
            1 => -MAX_MATCH_WEIGHT_MICRO_V1,
            _ => uniform,
        }
    }

    /// `count` distinct names drawn from a pool of 80.
    fn names(&mut self, count: usize) -> Vec<String> {
        let mut pool: Vec<usize> = (0..80).collect();
        for index in 0..count {
            let pick = index + self.below(pool.len() - index);
            pool.swap(index, pick);
        }
        pool.truncate(count);
        pool.iter().map(|name| format!("d{name}")).collect()
    }

    fn input(&mut self) -> (Vec<PreferenceWeightV1>, Vec<PreviewOptionV1>) {
        let weight_count = 1 + self.below(MAX_PREFERENCE_WEIGHTS_V1);
        let weights = self
            .names(weight_count)
            .into_iter()
            .map(|dimension| weight(&dimension, self.weight_micro()))
            .collect();
        let option_count = MIN_PREVIEW_OPTIONS_V1 + self.below(MAX_PREVIEW_OPTIONS_V1 - 1);
        let options = (0..option_count)
            .map(|index| {
                let tag_count = self.below(MAX_OPTION_TAGS_V1 + 1);
                PreviewOptionV1 {
                    key: format!("option-{index}"),
                    tags: self.names(tag_count),
                }
            })
            .collect();
        (weights, options)
    }
}

fn no_tag_matches(weights: &[PreferenceWeightV1], options: &[PreviewOptionV1]) -> bool {
    options
        .iter()
        .flat_map(|option| &option.tags)
        .all(|tag| weights.iter().all(|entry| entry.dimension != *tag))
}

/// The ranges and the Toss-up rule of one computed Recommendation.
fn assert_in_range(options: &[PreviewOptionV1], computed: &ComputedRecommendationV1) {
    let keys: Vec<&String> = computed
        .scores
        .iter()
        .map(|score| &score.option_key)
        .collect();
    let authored: Vec<&String> = options.iter().map(|option| &option.key).collect();
    assert_eq!(keys, authored);
    let mut ranked: Vec<i64> = computed
        .scores
        .iter()
        .map(|score| score.match_score_micro)
        .collect();
    ranked.sort_unstable();
    ranked.reverse();
    assert!(ranked[0] <= MAX_MATCH_WEIGHT_MICRO_V1);
    assert!(ranked[ranked.len() - 1] >= -MAX_MATCH_WEIGHT_MICRO_V1);
    assert_eq!(computed.margin_micro, ranked[0] - ranked[1]);
    assert!(computed.margin_micro <= 2 * MAX_MATCH_WEIGHT_MICRO_V1);
    assert_eq!(
        computed.toss_up,
        computed.margin_micro < TOSS_UP_MARGIN_MICRO_V1
    );
    let winner = computed
        .scores
        .iter()
        .find(|score| score.match_score_micro == ranked[0])
        .map(|score| score.option_key.clone());
    let expected_key = if computed.toss_up { None } else { winner };
    assert_eq!(computed.option_key, expected_key);
}

#[test]
fn scores_stay_in_range_and_ignore_tag_and_weight_order() -> TestResult {
    let mut draws = Draws(0x5eed_0000_0305_0001);
    for _ in 0..2_000 {
        let (mut weights, mut options) = draws.input();
        let actual = match_score_v1(&weights, &options)?;
        if let RecommendationV1::Computed(computed) = &actual {
            assert_in_range(&options, computed);
        } else {
            assert!(no_tag_matches(&weights, &options));
        }
        let turn = draws.below(weights.len());
        weights.rotate_left(turn);
        for option in &mut options {
            option.tags.reverse();
        }
        assert_eq!(match_score_v1(&weights, &options)?, actual);
    }
    Ok(())
}

fn unhex(text: &str) -> Fallible<Vec<u8>> {
    let bytes: Result<Vec<u8>, _> = (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16))
        .collect();
    Ok(bytes?)
}

fn ulid(text: &str) -> Fallible<Ulid> {
    Ok(Ulid::from_string(text)?)
}

fn revision_ref(id: &str, revision: u64, digest: u8) -> Fallible<PreviewRevisionRefV1> {
    Ok(PreviewRevisionRefV1 {
        id: ulid(id)?,
        revision: NonZeroU64::new(revision).ok_or("zero revision")?,
        digest: [digest; 32],
    })
}

fn request() -> Fallible<PreviewRequestV1> {
    Ok(PreviewRequestV1 {
        scenario_room: revision_ref(ROOM, 3, 0xaa)?,
        preference: revision_ref(PREFERENCE, 1, 0xbb)?,
        option_spec: revision_ref(OPTION_SPEC, 300, 0xcc)?,
        profile_id: PROFILE.to_owned(),
    })
}

fn claim() -> Fallible<PreviewClaimV1> {
    Ok(PreviewClaimV1 {
        principal_id: ulid(PRINCIPAL)?.to_bytes(),
        actor_entity_id: EntityId::from_ulid(ulid(ACTOR)?),
        request: request()?,
        consent_ref: EntityId::from_ulid(ulid(CONSENT)?),
        profile_digest: [0x44; 32],
        mode_profile_digest: [0x55; 32],
    })
}

fn result(outcome: PreviewOutcomeV1) -> Fallible<PreviewResultV1> {
    Ok(PreviewResultV1 {
        preview_id: EventId::from_ulid(ulid(PREVIEW)?),
        outcome,
    })
}

fn text(value: &str) -> Cbor {
    Cbor::Text(value.to_owned())
}

fn unsigned(value: u64) -> Cbor {
    Cbor::Integer(value.into())
}

fn reference(id: &str, revision: Cbor, digest: &str) -> Cbor {
    Cbor::Array(vec![text(id), revision, text(digest)])
}

/// The golden claim's fields, for tampering.
fn claim_fields() -> Vec<Cbor> {
    vec![
        text("PRQ1"),
        unsigned(1),
        text(PRINCIPAL),
        text(ACTOR),
        reference(ROOM, unsigned(3), &"aa".repeat(32)),
        reference(PREFERENCE, unsigned(1), &"bb".repeat(32)),
        reference(OPTION_SPEC, unsigned(300), &"cc".repeat(32)),
        text(CONSENT),
        text(PROFILE),
        text(&"44".repeat(32)),
        text(&"55".repeat(32)),
    ]
}

/// The golden `failed` result's fields, for tampering.
fn failed_fields() -> Vec<Cbor> {
    vec![
        text("PRS1"),
        unsigned(1),
        text(PREVIEW),
        text("failed"),
        Cbor::Null,
        text("input-deleted"),
    ]
}

fn encode(fields: Vec<Cbor>) -> Fallible<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(&Cbor::Array(fields), &mut bytes)?;
    Ok(bytes)
}

/// `fields` with field `index` replaced by `value`, encoded.
fn replaced(mut fields: Vec<Cbor>, index: usize, value: Cbor) -> Fallible<Vec<u8>> {
    fields[index] = value;
    encode(fields)
}

#[test]
fn the_claim_key_and_its_entity_match_the_independent_derivation() -> TestResult {
    let principal_id = ulid(PRINCIPAL)?.to_bytes();
    let actor = EntityId::from_ulid(ulid(ACTOR)?);
    let key = PreviewClaimKeyV1::derive(principal_id, actor, IDEMPOTENCY_KEY);
    assert_eq!(key.as_bytes().to_vec(), unhex(GOLDEN_CLAIM_KEY)?);
    assert_eq!(key.entity().to_string(), GOLDEN_CLAIM_ENTITY);
    let other_actor = EntityId::from_ulid(ulid(CONSENT)?);
    let changed = [
        PreviewClaimKeyV1::derive([0; 16], actor, IDEMPOTENCY_KEY),
        PreviewClaimKeyV1::derive(principal_id, other_actor, IDEMPOTENCY_KEY),
        PreviewClaimKeyV1::derive(principal_id, actor, "retry-key-0002"),
    ];
    assert!(changed.iter().all(|other| *other != key));
    Ok(())
}

#[test]
fn the_request_digest_matches_the_independent_encoding() -> TestResult {
    let request = request()?;
    assert_eq!(request.digest().to_vec(), unhex(GOLDEN_REQUEST_DIGEST)?);
    let stored = PreviewClaimV1::from_payload(&unhex(GOLDEN_CLAIM)?)?;
    assert_eq!(stored.request.digest(), request.digest());
    let mut other = request.clone();
    other.profile_id = String::from("replay-v1");
    assert_ne!(other.digest(), request.digest());
    Ok(())
}

#[test]
fn a_claim_matches_the_independent_golden_encoding() -> TestResult {
    let golden = unhex(GOLDEN_CLAIM)?;
    assert_eq!(claim()?.to_payload()?, golden);
    assert_eq!(encode(claim_fields())?, golden);
    assert_eq!(PreviewClaimV1::from_payload(&golden)?, claim()?);
    Ok(())
}

#[test]
fn results_match_the_independent_golden_encoding() -> TestResult {
    let computed = result(PreviewOutcomeV1::Computed)?;
    let golden = unhex(GOLDEN_COMPUTED)?;
    assert_eq!(computed.to_payload(), golden);
    assert_eq!(PreviewResultV1::from_payload(&golden)?, computed);
    let input_deleted = PreviewFailureCodeV1::input_deleted();
    let failed = result(PreviewOutcomeV1::Failed(input_deleted))?;
    let golden = unhex(GOLDEN_FAILED)?;
    assert_eq!(failed.to_payload(), golden);
    assert_eq!(encode(failed_fields())?, golden);
    assert_eq!(PreviewResultV1::from_payload(&golden)?, failed);
    Ok(())
}

#[test]
fn every_head_width_round_trips() -> TestResult {
    let widths = [23, 24, 255, 256, 65_535, 65_536, 1 << 32, u64::MAX];
    for revision in widths {
        let mut changed = claim()?;
        changed.request.preference.revision = NonZeroU64::new(revision).ok_or("zero")?;
        let payload = changed.to_payload()?;
        assert_eq!(PreviewClaimV1::from_payload(&payload)?, changed);
    }
    Ok(())
}

#[test]
fn a_claim_payload_is_at_most_one_kibibyte() -> TestResult {
    let mut largest = claim()?;
    largest.request.profile_id = "p".repeat(508);
    let payload = largest.to_payload()?;
    assert_eq!(payload.len(), MAX_PREVIEW_CLAIM_BYTES_V1);
    assert_eq!(PreviewClaimV1::from_payload(&payload)?, largest);
    let mut oversized = largest;
    oversized.request.profile_id.push('p');
    assert_eq!(
        oversized.to_payload().err(),
        Some(PreviewPayloadErrorV1::TooLarge)
    );
    let stored = replaced(claim_fields(), 8, text(&"p".repeat(509)))?;
    assert_eq!(
        PreviewClaimV1::from_payload(&stored),
        Err(PreviewPayloadErrorV1::Corrupt)
    );
    Ok(())
}

#[test]
fn a_corrupt_or_non_canonical_claim_is_refused() -> TestResult {
    let golden = unhex(GOLDEN_CLAIM)?;
    let profile = golden
        .windows(PROFILE.len())
        .position(|window| window == PROFILE.as_bytes())
        .ok_or("the golden claim names no profile")?;
    let mut invalid_utf8 = golden.clone();
    invalid_utf8[profile] = 0xff;
    let mut extra = claim_fields();
    extra.push(Cbor::Null);
    let mut missing = claim_fields();
    missing.pop();
    let mut swapped = claim_fields();
    swapped.swap(7, 8);
    let fields = claim_fields;
    let (lower, upper, short) = ("aa".repeat(32), "AA".repeat(32), "aa".repeat(31));
    let revision_text = reference(PREFERENCE, text("1"), &"bb".repeat(32));
    let tampered = [
        [&golden[..6], &[0x18, 0x01][..], &golden[7..]].concat(),
        [&[0x9f][..], &golden[1..], &[0xff][..]].concat(),
        [&golden[..], &[0x00][..]].concat(),
        invalid_utf8,
        encode(extra)?,
        encode(missing)?,
        encode(swapped)?,
        replaced(fields(), 0, text("PRQ2"))?,
        replaced(fields(), 1, unsigned(2))?,
        replaced(fields(), 2, text(&PRINCIPAL.to_lowercase()))?,
        replaced(fields(), 2, text("not-a-ulid"))?,
        replaced(fields(), 2, text("81JC0GATEWAYPR1NC1PA100001"))?,
        replaced(fields(), 2, unsigned(7))?,
        replaced(fields(), 3, text("not-a-ulid"))?,
        replaced(fields(), 4, reference(ROOM, unsigned(0), &lower))?,
        replaced(fields(), 4, reference(ROOM, unsigned(3), &upper))?,
        replaced(fields(), 4, reference(ROOM, unsigned(3), &short))?,
        replaced(fields(), 4, text(ROOM))?,
        replaced(fields(), 5, revision_text)?,
        replaced(fields(), 7, text("not-a-ulid"))?,
        replaced(fields(), 9, text(&"44".repeat(31)))?,
        replaced(fields(), 10, Cbor::Null)?,
    ];
    for payload in tampered {
        assert_eq!(
            PreviewClaimV1::from_payload(&payload),
            Err(PreviewPayloadErrorV1::Corrupt)
        );
    }
    Ok(())
}

#[test]
fn a_corrupt_or_non_canonical_result_is_refused() -> TestResult {
    let fields = failed_fields;
    let computed = |function_id: Cbor, failure_code: Cbor| {
        let mut changed = failed_fields();
        changed[3] = text("computed");
        changed[4] = function_id;
        changed[5] = failure_code;
        encode(changed)
    };
    let mut extra = failed_fields();
    extra.push(Cbor::Null);
    let tampered = [
        computed(text("pigloros.match-score.v2"), Cbor::Null)?,
        computed(Cbor::Null, Cbor::Null)?,
        computed(text(MATCH_SCORE_FUNCTION_ID_V1), text("input-deleted"))?,
        replaced(fields(), 0, text("PRS2"))?,
        replaced(fields(), 1, unsigned(2))?,
        replaced(fields(), 2, text("not-a-ulid"))?,
        replaced(fields(), 3, text("pending"))?,
        replaced(fields(), 4, text(MATCH_SCORE_FUNCTION_ID_V1))?,
        replaced(fields(), 5, Cbor::Null)?,
        replaced(fields(), 5, text("Input-Deleted"))?,
        encode(extra)?,
    ];
    for payload in tampered {
        assert_eq!(
            PreviewResultV1::from_payload(&payload),
            Err(PreviewPayloadErrorV1::Corrupt)
        );
    }
    Ok(())
}

#[test]
fn a_stored_failure_code_is_an_open_string() -> TestResult {
    let payload = replaced(failed_fields(), 5, text("store-fault"))?;
    let stored = PreviewResultV1::from_payload(&payload)?;
    assert_eq!(stored.to_payload(), payload);
    let PreviewOutcomeV1::Failed(code) = stored.outcome else {
        return Err("the stored result is not failed".into());
    };
    assert_eq!(code.as_str(), "store-fault");
    Ok(())
}

#[test]
fn a_failure_code_follows_the_contract_pattern() {
    for valid in ["input-deleted", "a", "a1", "a-1", "a1-b2"] {
        let parsed = PreviewFailureCodeV1::parse(valid);
        assert_eq!(parsed.map(|code| code.0), Some(valid.to_owned()));
    }
    for invalid in ["", "-a", "a-", "a--b", "1a", "A", "a_b", "a.b"] {
        assert_eq!(PreviewFailureCodeV1::parse(invalid), None, "{invalid}");
    }
    let longest = "x".repeat(64);
    assert!(PreviewFailureCodeV1::parse(&longest).is_some());
    assert!(PreviewFailureCodeV1::parse(&format!("{longest}x")).is_none());
}

#[test]
fn every_truncated_payload_is_refused() -> TestResult {
    for golden in [GOLDEN_CLAIM, GOLDEN_COMPUTED, GOLDEN_FAILED] {
        let bytes = unhex(golden)?;
        for length in 0..bytes.len() {
            let prefix = &bytes[..length];
            let corrupt = Some(PreviewPayloadErrorV1::Corrupt);
            assert_eq!(PreviewClaimV1::from_payload(prefix).err(), corrupt);
            assert_eq!(PreviewResultV1::from_payload(prefix).err(), corrupt);
        }
    }
    Ok(())
}
