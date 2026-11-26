//! The ADR-140 Decision Preview seam (Redmine #305, parent #245).
//!
//! It holds the parts of a Decision Preview that need no store and no
//! Gateway:
//!
//! - [`match_score_v1`], the pure integer Match Score and Recommendation
//!   function `pigloros.match-score.v1` (ADR-140 section 1). Its normative
//!   definition is the frozen golden-vector corpus
//!   `decision_preview/match_score_v1_vectors.json`; any change to any output
//!   is a new function ID with its own corpus.
//! - [`PreviewClaimKeyV1`], the claim key of one `createDecisionPreview`
//!   request and the entity of its claim Event (ADR-140 section 3).
//! - [`PreviewRequestV1::digest`], the `request_digest` an exact retry is
//!   recognized by (ADR-140 section 3).
//! - [`PreviewClaimV1`] and [`PreviewResultV1`], the `PRQ1` and `PRS1`
//!   payloads of the `preview.request.v1` and `preview.result.v1` Events
//!   (ADR-140 sections 3 and 4). A stored payload is read back only when it
//!   re-encodes to the same bytes.
//!
//! The function reads no clock, randomness, store or environment and uses no
//! floating point. ADR-041 section 10 applies: all of this is compiled
//! unconditionally, with no feature flag.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
};

use pos_core::{EntityId, EventId};
use ulid::Ulid;

use crate::community_plugin_host::cbor;
use crate::scenario_room::{hex, hex_bytes, is_key};

/// The identity of the Match Score function, recorded in every `PRS1`.
pub const MATCH_SCORE_FUNCTION_ID_V1: &str = "pigloros.match-score.v1";
/// The margin below which a computed Recommendation is a Toss-up.
pub const TOSS_UP_MARGIN_MICRO_V1: i64 = 20_000;
/// The largest magnitude of a Preference weight, in micro-units.
pub const MAX_MATCH_WEIGHT_MICRO_V1: i64 = 1_000_000;
/// The most weights one Preference revision holds.
pub const MAX_PREFERENCE_WEIGHTS_V1: usize = 64;
/// The fewest options one `OptionSpec` revision holds.
pub const MIN_PREVIEW_OPTIONS_V1: usize = 2;
/// The most options one `OptionSpec` revision holds.
pub const MAX_PREVIEW_OPTIONS_V1: usize = 16;
/// The most tags one option holds.
pub const MAX_OPTION_TAGS_V1: usize = 16;
/// The Event type of the claim Event, whose payload is `PRQ1`.
pub const PREVIEW_REQUEST_EVENT_TYPE_V1: &str = "preview.request.v1";
/// The Event type of the result Event, whose payload is `PRS1`.
pub const PREVIEW_RESULT_EVENT_TYPE_V1: &str = "preview.result.v1";
/// The `schema_version` of a `createDecisionPreview` request.
pub const PREVIEW_REQUEST_SCHEMA_VERSION_V1: u64 = 1;
/// The largest `PRQ1` payload, in bytes.
pub const MAX_PREVIEW_CLAIM_BYTES_V1: usize = 1_024;

const CLAIM_KEY_CONTEXT: &str = "PiglorOS Gateway DecisionPreviewRequest v1";
const REQUEST_DOMAIN: &[u8] = b"PiglorOS.GatewayDecisionPreviewRequest.v1\0";
const CLAIM_MAGIC: &str = "PRQ1";
const RESULT_MAGIC: &str = "PRS1";
const PAYLOAD_VERSION: u64 = 1;
const CLAIM_FIELDS: usize = 11;
const RESULT_FIELDS: usize = 6;
const OUTCOME_COMPUTED: &str = "computed";
const OUTCOME_FAILED: &str = "failed";
const INPUT_DELETED: &str = "input-deleted";
const MAX_FAILURE_CODE_BYTES: usize = 64;
const CBOR_UNSIGNED: u8 = 0;
const CBOR_TEXT: u8 = 3;
const CBOR_ARRAY: u8 = 4;
const CBOR_NULL: u8 = 0xf6;

/// Why the Match Score function refuses its input (ADR-140 section 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MatchScoreErrorV1 {
    /// The Preference holds no weight, or more than 64.
    #[error("the Preference holds no weight or more than 64")]
    WeightCount,
    /// A Preference dimension is not a domain key.
    #[error("a Preference dimension is not a domain key")]
    InvalidDimension,
    /// A Preference dimension appears twice.
    #[error("a Preference dimension appears twice")]
    DuplicateDimension,
    /// A weight lies outside `[-1,000,000, 1,000,000]`.
    #[error("a Preference weight lies outside [-1000000, 1000000]")]
    WeightOutOfRange,
    /// The `OptionSpec` holds fewer than 2 or more than 16 options.
    #[error("the OptionSpec holds fewer than 2 or more than 16 options")]
    OptionCount,
    /// An option key is not a domain key.
    #[error("an option key is not a domain key")]
    InvalidOptionKey,
    /// An option key appears twice.
    #[error("an option key appears twice")]
    DuplicateOptionKey,
    /// An option holds more than 16 tags.
    #[error("an option holds more than 16 tags")]
    TagCount,
    /// A tag is not a domain key.
    #[error("an option tag is not a domain key")]
    InvalidTag,
    /// A tag appears twice in one option.
    #[error("an option tag appears twice in one option")]
    DuplicateTag,
}

/// One weight of a Preference revision, in micro-units.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreferenceWeightV1 {
    pub dimension: String,
    pub weight_micro: i64,
}

/// One option of an `OptionSpec` revision, as the Match Score reads it.
///
/// `lean_hint_micro` and `coordinates` are not part of it: they never enter
/// `pigloros.match-score.v1` (ADR-140 P2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewOptionV1 {
    pub key: String,
    pub tags: Vec<String>,
}

/// The Match Score of one option, in micro-units.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OptionScoreV1 {
    pub option_key: String,
    pub match_score_micro: i64,
}

/// A Recommendation that at least one matched tag supports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputedRecommendationV1 {
    /// Every option once, in the `OptionSpec`'s authored order.
    pub scores: Vec<OptionScoreV1>,
    /// The largest score minus the second-largest, in `[0, 2,000,000]`.
    pub margin_micro: i64,
    /// Whether `margin_micro` is below [`TOSS_UP_MARGIN_MICRO_V1`].
    pub toss_up: bool,
    /// The key of the unique highest option, or `None` for a Toss-up.
    pub option_key: Option<String>,
}

/// The output of `pigloros.match-score.v1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecommendationV1 {
    /// No tag of any option matches a Preference dimension.
    InsufficientEvidence,
    /// At least one tag matches.
    Computed(ComputedRecommendationV1),
}

/// Compute the `pigloros.match-score.v1` Recommendation of `weights` over `options`.
///
/// `weights` are one Preference revision's, and `options` one `OptionSpec`
/// revision's in authored order. A tag matches a dimension only when the two
/// are byte-identical. An option's score is the mean of its matched weights,
/// rounded half away from zero, or 0 when no tag matches; unmatched tags do
/// not dilute it.
///
/// # Errors
/// A [`MatchScoreErrorV1`] when an input lies outside the bounds of ADR-140
/// section 1.
pub fn match_score_v1(
    weights: &[PreferenceWeightV1],
    options: &[PreviewOptionV1],
) -> Result<RecommendationV1, MatchScoreErrorV1> {
    let refusal = input_checks(weights, options)
        .into_iter()
        .find_map(|(holds, error)| (!holds).then_some(error));
    refusal.map_or_else(|| Ok(recommend(weights, options)), Err)
}

/// Every bound of ADR-140 section 1, in refusal order.
fn input_checks(
    weights: &[PreferenceWeightV1],
    options: &[PreviewOptionV1],
) -> [(bool, MatchScoreErrorV1); 10] {
    use MatchScoreErrorV1 as Error;
    [
        (
            (1..=MAX_PREFERENCE_WEIGHTS_V1).contains(&weights.len()),
            Error::WeightCount,
        ),
        (
            weights.iter().all(|weight| is_key(&weight.dimension)),
            Error::InvalidDimension,
        ),
        (
            distinct(weights.iter().map(|weight| &weight.dimension)),
            Error::DuplicateDimension,
        ),
        (
            weights
                .iter()
                .all(|weight| is_weight_micro(weight.weight_micro)),
            Error::WeightOutOfRange,
        ),
        (
            (MIN_PREVIEW_OPTIONS_V1..=MAX_PREVIEW_OPTIONS_V1).contains(&options.len()),
            Error::OptionCount,
        ),
        (
            options.iter().all(|option| is_key(&option.key)),
            Error::InvalidOptionKey,
        ),
        (
            distinct(options.iter().map(|option| &option.key)),
            Error::DuplicateOptionKey,
        ),
        (
            options
                .iter()
                .all(|option| option.tags.len() <= MAX_OPTION_TAGS_V1),
            Error::TagCount,
        ),
        (
            options
                .iter()
                .flat_map(|option| &option.tags)
                .all(|tag| is_key(tag)),
            Error::InvalidTag,
        ),
        (
            options.iter().all(|option| distinct(&option.tags)),
            Error::DuplicateTag,
        ),
    ]
}

const fn is_weight_micro(weight_micro: i64) -> bool {
    weight_micro.unsigned_abs() <= MAX_MATCH_WEIGHT_MICRO_V1.unsigned_abs()
}

fn distinct<T: Ord>(items: impl IntoIterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    for item in items {
        if !seen.insert(item) {
            return false;
        }
    }
    true
}

/// The Recommendation of a validated input (ADR-140 P5).
fn recommend(weights: &[PreferenceWeightV1], options: &[PreviewOptionV1]) -> RecommendationV1 {
    let table: BTreeMap<&str, i64> = weights
        .iter()
        .map(|entry| (entry.dimension.as_str(), entry.weight_micro))
        .collect();
    let matched = options
        .iter()
        .flat_map(|option| &option.tags)
        .any(|tag| table.contains_key(tag.as_str()));
    if !matched {
        return RecommendationV1::InsufficientEvidence;
    }
    let scores: Vec<OptionScoreV1> = options
        .iter()
        .map(|option| OptionScoreV1 {
            option_key: option.key.clone(),
            match_score_micro: option_score(&table, &option.tags),
        })
        .collect();
    let mut ranked: Vec<i64> = scores
        .iter()
        .map(|scored_option| scored_option.match_score_micro)
        .collect();
    ranked.sort_unstable_by_key(|score| Reverse(*score));
    // At least two options are validated, and the bounds keep every score in
    // [-10^6, 10^6], so the margin lies in [0, 2 * 10^6].
    let top = ranked[0];
    let margin_micro = top - ranked[1];
    let toss_up = margin_micro < TOSS_UP_MARGIN_MICRO_V1;
    let option_key = scores
        .iter()
        .find(|score| !toss_up && score.match_score_micro == top)
        .map(|score| score.option_key.clone());
    RecommendationV1::Computed(ComputedRecommendationV1 {
        scores,
        margin_micro,
        toss_up,
        option_key,
    })
}

/// The Match Score of one option (ADR-140 P3 and P4).
///
/// With `n` matched tags whose weights sum to `S`, it is
/// `sign(S) * floor((2|S| + n) / (2n))`, or 0 when `n` is 0. `|S|` is at most
/// 16 * 10^6, so no `i64` operation can overflow.
fn option_score(table: &BTreeMap<&str, i64>, tags: &[String]) -> i64 {
    let (sum, n) = tags
        .iter()
        .filter_map(|tag| table.get(tag.as_str()).copied())
        .fold((0_i64, 0_i64), |(sum, n), weight| (sum + weight, n + 1));
    (2 * sum.abs() + n)
        .checked_div(2 * n)
        .map_or(0, |mean| sum.signum() * mean)
}

/// The claim key of one `createDecisionPreview` request (ADR-140 P12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreviewClaimKeyV1([u8; 32]);

impl PreviewClaimKeyV1 {
    /// Derive the claim key of `idempotency_key` for a Principal and actor.
    ///
    /// The material is the 16 raw bytes of `principal_id`, the 16 big-endian
    /// bytes of the actor's ULID and the raw key bytes, with no separator.
    #[must_use]
    pub fn derive(
        principal_id: [u8; 16],
        actor_entity_id: EntityId,
        idempotency_key: &str,
    ) -> Self {
        let actor = actor_entity_id.inner().to_bytes();
        let material = [&principal_id[..], &actor[..], idempotency_key.as_bytes()].concat();
        Self(blake3::derive_key(CLAIM_KEY_CONTEXT, &material))
    }

    /// The 32 bytes of the key.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The entity of the claim Event: the ULID of the key's first 16 bytes.
    #[must_use]
    pub fn entity(&self) -> EntityId {
        let mut prefix = [0; 16];
        prefix.copy_from_slice(&self.0[..16]);
        EntityId::from_ulid(Ulid::from_bytes(prefix))
    }
}

/// One exact input revision a preview binds: `[id, revision, digest]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewRevisionRefV1 {
    pub id: Ulid,
    pub revision: NonZeroU64,
    pub digest: [u8; 32],
}

impl PreviewRevisionRefV1 {
    fn write(&self, out: &mut Vec<u8>) {
        cbor::array(out, 3);
        cbor::text(out, &self.id.to_string());
        cbor::unsigned(out, self.revision.get());
        cbor::text(out, &hex(&self.digest));
    }

    fn read(reader: &mut CborReader<'_>) -> Option<Self> {
        reader.head(CBOR_ARRAY)?;
        let id = reader.ulid()?;
        let revision = reader.head(CBOR_UNSIGNED).and_then(NonZeroU64::new)?;
        let digest = reader.digest()?;
        Some(Self {
            id,
            revision,
            digest,
        })
    }
}

/// The members of a `createDecisionPreview` request that its digest binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewRequestV1 {
    /// The room revision, whose digest is its `provenance.digest`.
    pub scenario_room: PreviewRevisionRefV1,
    pub preference: PreviewRevisionRefV1,
    pub option_spec: PreviewRevisionRefV1,
    pub profile_id: String,
}

impl PreviewRequestV1 {
    /// The `request_digest` of the request (ADR-140 P13).
    ///
    /// It is BLAKE3 of `PiglorOS.GatewayDecisionPreviewRequest.v1`, a 0x00
    /// byte and the deterministic CBOR array `[schema_version, room_ref,
    /// preference_ref, option_spec_ref, profile_id]`, with `schema_version` 1.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut out = REQUEST_DOMAIN.to_vec();
        cbor::array(&mut out, 5);
        cbor::unsigned(&mut out, PREVIEW_REQUEST_SCHEMA_VERSION_V1);
        self.write_refs(&mut out);
        cbor::text(&mut out, &self.profile_id);
        *blake3::hash(&out).as_bytes()
    }

    fn write_refs(&self, out: &mut Vec<u8>) {
        self.scenario_room.write(out);
        self.preference.write(out);
        self.option_spec.write(out);
    }
}

/// Why a preview payload is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PreviewPayloadErrorV1 {
    /// A `PRQ1` payload would exceed [`MAX_PREVIEW_CLAIM_BYTES_V1`].
    #[error("the preview claim payload exceeds 1 KiB")]
    TooLarge,
    /// A stored payload does not decode to a record with the same bytes.
    #[error("the stored preview payload is corrupt")]
    Corrupt,
}

/// The `PRQ1` payload of one claim Event (ADR-140 P14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewClaimV1 {
    pub principal_id: [u8; 16],
    pub actor_entity_id: EntityId,
    /// Fields 4 to 6 and 8, from which `request_digest` is recomputed.
    pub request: PreviewRequestV1,
    /// The bound room revision's `privacy_export_ref`.
    pub consent_ref: EntityId,
    /// The raw EPF1 digest at admission.
    pub profile_digest: [u8; 32],
    /// The digest of the execution-mode binding the claim commits under.
    pub mode_profile_digest: [u8; 32],
}

impl PreviewClaimV1 {
    /// The deterministic CBOR bytes of the claim.
    ///
    /// # Errors
    /// [`PreviewPayloadErrorV1::TooLarge`] when the bytes would exceed
    /// [`MAX_PREVIEW_CLAIM_BYTES_V1`].
    pub fn to_payload(&self) -> Result<Vec<u8>, PreviewPayloadErrorV1> {
        let mut out = Vec::new();
        cbor::array(&mut out, CLAIM_FIELDS);
        cbor::text(&mut out, CLAIM_MAGIC);
        cbor::unsigned(&mut out, PAYLOAD_VERSION);
        let principal_id = Ulid::from_bytes(self.principal_id);
        cbor::text(&mut out, &principal_id.to_string());
        cbor::text(&mut out, &self.actor_entity_id.to_string());
        self.request.write_refs(&mut out);
        cbor::text(&mut out, &self.consent_ref.to_string());
        cbor::text(&mut out, &self.request.profile_id);
        cbor::text(&mut out, &hex(&self.profile_digest));
        cbor::text(&mut out, &hex(&self.mode_profile_digest));
        (out.len() <= MAX_PREVIEW_CLAIM_BYTES_V1)
            .then_some(out)
            .ok_or(PreviewPayloadErrorV1::TooLarge)
    }

    /// Read a stored `PRQ1` payload back.
    ///
    /// The payload must decode to a claim that re-encodes to exactly the same
    /// bytes, so an unknown, missing, extra or out-of-order field, another
    /// magic or version, and any non-canonical encoding are refused.
    ///
    /// # Errors
    /// [`PreviewPayloadErrorV1::Corrupt`].
    pub fn from_payload(payload: &[u8]) -> Result<Self, PreviewPayloadErrorV1> {
        Self::read(&mut CborReader { rest: payload })
            .filter(|claim| claim.to_payload().as_deref() == Ok(payload))
            .ok_or(PreviewPayloadErrorV1::Corrupt)
    }

    /// Decode the fields in order; the magic, the version and every head
    /// count are checked by the re-encoding.
    fn read(reader: &mut CborReader<'_>) -> Option<Self> {
        reader.head(CBOR_ARRAY)?;
        reader.text()?;
        reader.head(CBOR_UNSIGNED)?;
        let principal_id = reader.ulid()?.to_bytes();
        let actor_entity_id = EntityId::from_ulid(reader.ulid()?);
        let scenario_room = PreviewRevisionRefV1::read(reader)?;
        let preference = PreviewRevisionRefV1::read(reader)?;
        let option_spec = PreviewRevisionRefV1::read(reader)?;
        let consent_ref = EntityId::from_ulid(reader.ulid()?);
        let profile_id = reader.text()?.to_owned();
        let profile_digest = reader.digest()?;
        let mode_profile_digest = reader.digest()?;
        Some(Self {
            principal_id,
            actor_entity_id,
            request: PreviewRequestV1 {
                scenario_room,
                preference,
                option_spec,
                profile_id,
            },
            consent_ref,
            profile_digest,
            mode_profile_digest,
        })
    }
}

/// The typed terminal failure of a preview (ADR-140 P18).
///
/// It matches `^[a-z][a-z0-9]*(-[a-z0-9]+)*$` with at most 64 bytes. The set
/// is open, but #305 records only [`Self::input_deleted`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewFailureCodeV1(String);

impl PreviewFailureCodeV1 {
    /// `input-deleted`: a bound input was erased before the result committed.
    #[must_use]
    pub fn input_deleted() -> Self {
        Self(INPUT_DELETED.to_owned())
    }

    fn parse(code: &str) -> Option<Self> {
        let well_formed = code.len() <= MAX_FAILURE_CODE_BYTES
            && code.starts_with(|first: char| first.is_ascii_lowercase())
            && code.split('-').all(is_code_segment);
        well_formed.then(|| Self(code.to_owned()))
    }

    /// The code text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_code_segment(segment: &str) -> bool {
    !segment.is_empty() && segment.bytes().all(is_code_byte)
}

const fn is_code_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

/// What the result Event records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreviewOutcomeV1 {
    /// The Recommendation was computed under `pigloros.match-score.v1`.
    Computed,
    /// The preview failed with a typed code.
    Failed(PreviewFailureCodeV1),
}

impl PreviewOutcomeV1 {
    /// A `function_id` text, checked by the re-encoding, then a null code.
    fn read_computed(reader: &mut CborReader<'_>) -> Option<Self> {
        reader.text()?;
        reader.null().then_some(Self::Computed)
    }

    /// A null `function_id`, then the failure code.
    fn read_failed(reader: &mut CborReader<'_>) -> Option<Self> {
        let code = reader.null().then(|| reader.text()).flatten()?;
        PreviewFailureCodeV1::parse(code).map(Self::Failed)
    }
}

/// The `PRS1` payload of one result Event (ADR-140 P16).
///
/// It carries no score, winner, margin or Recommendation status: the read
/// recomputes them from the bound revisions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewResultV1 {
    /// The claim Event's ID.
    pub preview_id: EventId,
    pub outcome: PreviewOutcomeV1,
}

impl PreviewResultV1 {
    /// The deterministic CBOR bytes of the result.
    #[must_use]
    pub fn to_payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        cbor::array(&mut out, RESULT_FIELDS);
        cbor::text(&mut out, RESULT_MAGIC);
        cbor::unsigned(&mut out, PAYLOAD_VERSION);
        cbor::text(&mut out, &self.preview_id.to_string());
        match &self.outcome {
            PreviewOutcomeV1::Computed => {
                cbor::text(&mut out, OUTCOME_COMPUTED);
                cbor::text(&mut out, MATCH_SCORE_FUNCTION_ID_V1);
                out.push(CBOR_NULL);
            }
            PreviewOutcomeV1::Failed(code) => {
                cbor::text(&mut out, OUTCOME_FAILED);
                out.push(CBOR_NULL);
                cbor::text(&mut out, code.as_str());
            }
        }
        out
    }

    /// Read a stored `PRS1` payload back.
    ///
    /// The payload must decode to a result that re-encodes to exactly the
    /// same bytes, so a `computed` result names `pigloros.match-score.v1` and
    /// no failure code, and a `failed` one names no function and a code.
    ///
    /// # Errors
    /// [`PreviewPayloadErrorV1::Corrupt`].
    pub fn from_payload(payload: &[u8]) -> Result<Self, PreviewPayloadErrorV1> {
        Self::read(&mut CborReader { rest: payload })
            .filter(|result| result.to_payload() == payload)
            .ok_or(PreviewPayloadErrorV1::Corrupt)
    }

    /// Decode the fields in order; the magic, the version, the head count
    /// and `function_id` are checked by the re-encoding.
    fn read(reader: &mut CborReader<'_>) -> Option<Self> {
        reader.head(CBOR_ARRAY)?;
        reader.text()?;
        reader.head(CBOR_UNSIGNED)?;
        let preview_id = EventId::from_ulid(reader.ulid()?);
        let outcome = match reader.text()? {
            OUTCOME_COMPUTED => PreviewOutcomeV1::read_computed(reader),
            OUTCOME_FAILED => PreviewOutcomeV1::read_failed(reader),
            _ => None,
        }?;
        Some(Self {
            preview_id,
            outcome,
        })
    }
}

/// A reader of the definite-length CBOR items the payloads use.
struct CborReader<'a> {
    rest: &'a [u8],
}

impl<'a> CborReader<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        self.rest.split_at_checked(count).map(|(taken, rest)| {
            self.rest = rest;
            taken
        })
    }

    fn byte(&mut self) -> Option<u8> {
        self.rest.split_first().map(|(first, rest)| {
            self.rest = rest;
            *first
        })
    }

    /// Consume the next item when it is a null.
    const fn null(&mut self) -> bool {
        if let [CBOR_NULL, rest @ ..] = self.rest {
            self.rest = rest;
            true
        } else {
            false
        }
    }

    /// The argument of the next head, which must have major type `major`.
    fn head(&mut self, major: u8) -> Option<u64> {
        let initial = self.byte().filter(|initial| initial >> 5 == major)?;
        match initial & 0x1f {
            info @ 0..=23 => Some(u64::from(info)),
            info @ 24..=27 => self.number(1 << (info - 24)),
            _ => None,
        }
    }

    /// A big-endian head argument of `width` bytes, at most 8.
    fn number(&mut self, width: usize) -> Option<u64> {
        self.take(width).map(|bytes| {
            let mut padded = [0; 8];
            padded[8 - width..].copy_from_slice(bytes);
            u64::from_be_bytes(padded)
        })
    }

    fn text(&mut self) -> Option<&'a str> {
        let length = self.head(CBOR_TEXT)?;
        usize::try_from(length)
            .ok()
            .and_then(|length| self.take(length))
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
    }

    fn ulid(&mut self) -> Option<Ulid> {
        self.text().and_then(|text| text.parse().ok())
    }

    fn digest(&mut self) -> Option<[u8; 32]> {
        self.text().and_then(hex_bytes::<32>)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
