//! The served Preference and `OptionSpec` resources (#304).
//!
//! A Preference is one subject's set of named dimension weights; an
//! `OptionSpec` is one subject's ordered set of typed alternatives. Both are
//! user-authored, subject-scoped chains of immutable revisions that the
//! Gateway stores itself (owner decisions on #304), outside every Timeline:
//!
//! - `POST /v1/preferences` and `POST /v1/option-specs` create revision 1 of
//!   a new resource, or with `parent` the next revision of an existing one.
//!   The parent must be the current head (`409 append-conflict` otherwise),
//!   and an identical content is never deduplicated: `Idempotency-Key`
//!   alone makes a retry return the original revision.
//! - `GET .../{id}/revisions/{revision}` answers one revision to its
//!   subject; any other caller gets the same `404 not-found-or-unavailable`
//!   as for an unknown revision. An erased revision answers `410 deleted` to
//!   its subject only, from a payload-free tombstone.
//!
//! The subject is the acting entity of the request, which the Local
//! Principal's grant must cover; a request never names another subject. A
//! request names its `schema_version`; any version other than 1 is
//! `400 unsupported-version`.
//!
//! The revision `digest` is BLAKE3 of a family domain tag
//! (`PiglorOS.GatewayPreferenceRevision.v1\0` or
//! `PiglorOS.GatewayOptionSpecRevision.v1\0`) followed by the revision's
//! canonical bytes: the RFC 8949 §4.2.1 deterministic CBOR array
//! `[schema_id, schema_version, id, revision, parent_revision, subject_entity_id, entries]`
//! (see `ContentV1`). `provenance.digest` is BLAKE3 of
//! `PiglorOS.GatewayRevisionProvenance.v1\0` followed by the deterministic
//! CBOR array `[origin, principal_id, subject_entity_id, mode_profile_id,
//! mode_profile_digest, binding_epoch, digest]` (see `ProvenanceV1`).
//! Both are what the contract README states.

use std::{num::NonZeroU64, ops::RangeInclusive};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use pos_core::{
    CoreError, EntityId, GatewayModeBindingRecordV1, GatewayRevisionCommitV1,
    GatewayRevisionDraftV1, GatewayRevisionErrorV1, GatewayRevisionIdempotencyV1,
    GatewayRevisionKeyV1, GatewayRevisionKindV1, GatewayRevisionRecordV1, GatewayRevisionStateV1,
};
use pos_runtime::{PreferenceWeightV1, PreviewOptionV1};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use ulid::Ulid;

use crate::{
    executor::StoreExecutorError,
    mode_profile::GatewayModeProfileIdV1,
    operation::{OperationAuthority, OperationSpecV1},
    problem::{ProblemCodeV1, ProblemV1},
    Gateway, GatewayError, GatewayOperationPermitV1,
};

/// The only request and content schema version of both families.
const SCHEMA_VERSION: u64 = 1;
/// The largest revision number and coordinate magnitude a client can
/// represent exactly (2^53 - 1).
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
/// A weight or lean hint in [-1, 1] as integer micro-units.
const MICRO_UNIT: RangeInclusive<i64> = -1_000_000..=1_000_000;
/// A coordinate in integer micro-units.
const SAFE_INTEGER: RangeInclusive<i64> = -MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER;
/// The longest canonical key and the most UTF-8 bytes of a label.
const MAX_TEXT_BYTES: usize = 128;
/// Domain of the idempotency key digest; the raw key is never stored.
const KEY_DOMAIN: &[u8] = b"PiglorOS.GatewayRevisionKey.v1\0";
/// Domain of the canonical request digest an idempotent retry is compared by.
const REQUEST_DOMAIN: &[u8] = b"PiglorOS.GatewayRevisionRequest.v1\0";
/// Domain of the provenance digest.
const PROVENANCE_DOMAIN: &[u8] = b"PiglorOS.GatewayRevisionProvenance.v1\0";
/// The provenance origin of every revision: the Principal authored it.
const ORIGIN: &str = "principal-authored";

/// One served revision family: its store kind, schema, digest domain and
/// canonical entries.
pub(crate) trait GatewayRevisionFamilyV1 {
    /// The request body.
    type Request: DeserializeOwned;
    /// One canonical entry of the content.
    type Entry: Serialize + DeserializeOwned + Send + 'static;
    /// The store kind.
    const KIND: GatewayRevisionKindV1;
    /// The `$id` of the revision schema.
    const SCHEMA_ID: &'static str;
    /// The domain of the revision digest.
    const DIGEST_DOMAIN: &'static [u8];
    /// The member that holds the entries.
    const MEMBER: &'static str;

    /// The validated, canonical entries and parent of a request.
    ///
    /// # Errors
    /// Returns the `400 invalid-request` of the first violated rule.
    fn admit(request: Self::Request) -> Result<(Vec<Self::Entry>, Option<ParentV1>), ProblemV1>;

    /// The JSON of the canonical entries.
    fn render(entries: &[Self::Entry]) -> Value;
}

/// The Preference family.
pub(crate) struct PreferenceFamily;

/// The `OptionSpec` family.
pub(crate) struct OptionSpecFamily;

/// A validated parent: the resource ID and its head revision.
pub(crate) struct ParentV1 {
    id: Ulid,
    revision: NonZeroU64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParentRequestV1 {
    id: String,
    revision: u64,
}

impl ParentRequestV1 {
    fn admit(self) -> Option<ParentV1> {
        canonical_ulid(&self.id)
            .zip(revision_number(self.revision))
            .map(|(id, revision)| ParentV1 { id, revision })
    }
}

/// `POST /v1/preferences`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreferenceRequestV1 {
    schema_version: u64,
    weights: Vec<WeightRequestV1>,
    parent: Option<ParentRequestV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WeightRequestV1 {
    dimension: String,
    weight_micro: i64,
}

/// One canonical weight: `[dimension, weight_micro]`, ordered by its
/// dimension.
#[derive(Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub(crate) struct WeightV1(String, i64);

/// `POST /v1/option-specs`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OptionSpecRequestV1 {
    schema_version: u64,
    options: Vec<OptionRequestV1>,
    parent: Option<ParentRequestV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OptionRequestV1 {
    key: String,
    label: String,
    tags: Vec<String>,
    lean_hint_micro: Option<i64>,
    coordinates: Option<CoordinatesRequestV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoordinatesRequestV1 {
    x_micro: i64,
    z_micro: i64,
}

/// One canonical option:
/// `[key, label, tags, lean_hint_micro | null, [x_micro, z_micro] | null]`,
/// its tags in byte order.
#[derive(Serialize, Deserialize)]
pub(crate) struct OptionV1(String, String, Vec<String>, Option<i64>, Option<(i64, i64)>);

/// The canonical bytes of one revision, as a deterministic CBOR array:
/// `[schema_id, schema_version, id, revision, parent_revision | null,
/// subject_entity_id, entries]`. IDs are canonical ULID text.
#[derive(Serialize, Deserialize)]
pub(crate) struct ContentV1<E>(String, u64, String, u64, Option<u64>, String, Vec<E>);

/// The canonical request an idempotent retry is compared by:
/// `[schema_id, schema_version, [parent_id, parent_revision] | null,
/// subject_entity_id, entries]`.
#[derive(Serialize)]
struct RequestV1<'a, E>(&'a str, u64, Option<(String, u64)>, String, &'a [E]);

/// The provenance record of one revision: `[origin, principal_id,
/// subject_entity_id, mode_profile_id, mode_profile_digest, binding_epoch,
/// digest]`, digests in lower-case hex.
#[derive(Serialize)]
pub(crate) struct ProvenanceV1(&'static str, String, String, String, String, u64, String);

fn invalid(detail: &'static str) -> ProblemV1 {
    ProblemV1::new(
        ProblemCodeV1::InvalidRequest,
        StatusCode::BAD_REQUEST,
        detail,
    )
}

/// The first violated rule, or `Ok`.
fn first_violation(rules: &[(bool, &'static str)]) -> Result<(), ProblemV1> {
    rules
        .iter()
        .find(|(holds, _)| !holds)
        .map_or(Ok(()), |(_, detail)| Err(invalid(detail)))
}

/// A canonical lower-case key: `^[a-z][a-z0-9_.-]*$`, 1 to 128 bytes.
fn domain_key(value: &str) -> bool {
    value.len() <= MAX_TEXT_BYTES
        && value
            .bytes()
            .next()
            .is_some_and(|first| first.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.-".contains(&byte)
        })
}

/// Display text of 1 to 128 UTF-8 bytes without control characters.
fn label(value: &str) -> bool {
    (1..=MAX_TEXT_BYTES).contains(&value.len())
        && !value
            .chars()
            .any(|character| character <= '\u{1f}' || character == '\u{7f}')
}

/// Whether no key appears twice.
fn unique<'a>(keys: impl Iterator<Item = &'a str>) -> bool {
    let mut sorted = keys.collect::<Vec<_>>();
    sorted.sort_unstable();
    sorted.windows(2).all(|pair| pair[0] != pair[1])
}

/// A canonical upper-case ULID.
pub(crate) fn canonical_ulid(value: &str) -> Option<Ulid> {
    Ulid::from_string(value)
        .ok()
        .filter(|ulid| ulid.to_string() == value)
}

/// A revision number of 1 to 2^53 - 1.
fn revision_number(value: u64) -> Option<NonZeroU64> {
    NonZeroU64::new(value).filter(|revision| revision.get() <= MAX_SAFE_INTEGER.unsigned_abs())
}

/// The validated parent of a request.
fn parent(request: Option<ParentRequestV1>) -> Result<Option<ParentV1>, ProblemV1> {
    request
        .map(ParentRequestV1::admit)
        .map_or(Ok(None), |admitted| {
            admitted
                .map(Some)
                .ok_or_else(|| invalid("the parent is not a canonical revision"))
        })
}

impl GatewayRevisionFamilyV1 for PreferenceFamily {
    type Request = PreferenceRequestV1;
    type Entry = WeightV1;
    const KIND: GatewayRevisionKindV1 = GatewayRevisionKindV1::Preference;
    const SCHEMA_ID: &'static str = "urn:pigloros:gateway:v1:schema:preference-revision";
    const DIGEST_DOMAIN: &'static [u8] = b"PiglorOS.GatewayPreferenceRevision.v1\0";
    const MEMBER: &'static str = "weights";

    fn admit(request: Self::Request) -> Result<(Vec<WeightV1>, Option<ParentV1>), ProblemV1> {
        let weights = &request.weights;
        first_violation(&[
            (
                request.schema_version == SCHEMA_VERSION,
                "unsupported schema_version",
            ),
            (
                (1..=64).contains(&weights.len()),
                "a Preference has 1 to 64 weights",
            ),
            (
                weights.iter().all(|weight| domain_key(&weight.dimension)),
                "a dimension is not a canonical key",
            ),
            (
                weights
                    .iter()
                    .all(|weight| MICRO_UNIT.contains(&weight.weight_micro)),
                "a weight is outside [-1, 1]",
            ),
            (
                unique(weights.iter().map(|weight| weight.dimension.as_str())),
                "a dimension appears more than once",
            ),
        ])?;
        let mut entries = request
            .weights
            .into_iter()
            .map(|weight| WeightV1(weight.dimension, weight.weight_micro))
            .collect::<Vec<_>>();
        entries.sort_unstable();
        parent(request.parent).map(|parent| (entries, parent))
    }

    fn render(entries: &[WeightV1]) -> Value {
        entries
            .iter()
            .map(|WeightV1(dimension, weight_micro)| {
                json!({"dimension": dimension, "weight_micro": weight_micro})
            })
            .collect()
    }
}

impl GatewayRevisionFamilyV1 for OptionSpecFamily {
    type Request = OptionSpecRequestV1;
    type Entry = OptionV1;
    const KIND: GatewayRevisionKindV1 = GatewayRevisionKindV1::OptionSpec;
    const SCHEMA_ID: &'static str = "urn:pigloros:gateway:v1:schema:option-spec-revision";
    const DIGEST_DOMAIN: &'static [u8] = b"PiglorOS.GatewayOptionSpecRevision.v1\0";
    const MEMBER: &'static str = "options";

    fn admit(request: Self::Request) -> Result<(Vec<OptionV1>, Option<ParentV1>), ProblemV1> {
        let options = &request.options;
        first_violation(&[
            (
                request.schema_version == SCHEMA_VERSION,
                "unsupported schema_version",
            ),
            (
                (2..=16).contains(&options.len()),
                "an OptionSpec has 2 to 16 options",
            ),
            (
                options.iter().all(|option| domain_key(&option.key)),
                "an option key is not a canonical key",
            ),
            (
                options.iter().all(|option| label(&option.label)),
                "a label is empty, over 128 UTF-8 bytes or has a control character",
            ),
            (
                options.iter().all(|option| {
                    option.tags.len() <= 16 && option.tags.iter().all(|tag| domain_key(tag))
                }),
                "an option has over 16 tags or a tag is not a canonical key",
            ),
            (
                options
                    .iter()
                    .all(|option| unique(option.tags.iter().map(String::as_str))),
                "a tag appears more than once in an option",
            ),
            (
                options.iter().all(|option| {
                    option
                        .lean_hint_micro
                        .is_none_or(|lean| MICRO_UNIT.contains(&lean))
                }),
                "a lean hint is outside [-1, 1]",
            ),
            (
                options.iter().all(|option| {
                    option.coordinates.as_ref().is_none_or(|coordinates| {
                        SAFE_INTEGER.contains(&coordinates.x_micro)
                            && SAFE_INTEGER.contains(&coordinates.z_micro)
                    })
                }),
                "a coordinate is outside the exact integer range",
            ),
            (
                unique(options.iter().map(|option| option.key.as_str())),
                "an option key appears more than once",
            ),
        ])?;
        let entries = request
            .options
            .into_iter()
            .map(|option| {
                let mut tags = option.tags;
                tags.sort_unstable();
                OptionV1(
                    option.key,
                    option.label,
                    tags,
                    option.lean_hint_micro,
                    option
                        .coordinates
                        .map(|coordinates| (coordinates.x_micro, coordinates.z_micro)),
                )
            })
            .collect();
        parent(request.parent).map(|parent| (entries, parent))
    }

    fn render(entries: &[OptionV1]) -> Value {
        entries
            .iter()
            .map(|OptionV1(key, label, tags, lean, coordinates)| {
                let mut option = json!({"key": key, "label": label, "tags": tags});
                if let Some(lean) = lean {
                    option["lean_hint_micro"] = json!(lean);
                }
                if let Some((x_micro, z_micro)) = coordinates {
                    option["coordinates"] = json!({"x_micro": x_micro, "z_micro": z_micro});
                }
                option
            })
            .collect()
    }
}

/// The deterministic CBOR of `value`; it never fails for these records.
fn cbor(value: &impl Serialize) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map(|()| bytes)
        .unwrap_or_default()
}

/// BLAKE3 of `domain` followed by `bytes`.
fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn hex(digest: [u8; 32]) -> String {
    blake3::Hash::from_bytes(digest).to_hex().to_string()
}

fn entity_text(entity: EntityId) -> String {
    entity.to_string()
}

/// The canonical content bytes of revision `revision` of `id`.
pub(crate) fn content_bytes<F: GatewayRevisionFamilyV1>(
    id: Ulid,
    revision: NonZeroU64,
    parent: Option<NonZeroU64>,
    subject: EntityId,
    entries: Vec<F::Entry>,
) -> Vec<u8> {
    cbor(&ContentV1(
        F::SCHEMA_ID.to_owned(),
        SCHEMA_VERSION,
        id.to_string(),
        revision.get(),
        parent.map(NonZeroU64::get),
        entity_text(subject),
        entries,
    ))
}

/// The weights of stored Preference content, as the Match Score reads them.
///
/// The content is decoded without re-validating its bounds, so an
/// out-of-bounds weight reaches the refusal of
/// [`pos_runtime::match_score_v1`] (ADR-140 test plan); `None` for content
/// that does not decode.
pub(crate) fn preview_weights(content: &[u8]) -> Option<Vec<PreferenceWeightV1>> {
    ciborium::from_reader::<ContentV1<WeightV1>, _>(content)
        .ok()
        .map(|ContentV1(.., weights)| {
            weights
                .into_iter()
                .map(|WeightV1(dimension, weight_micro)| PreferenceWeightV1 {
                    dimension,
                    weight_micro,
                })
                .collect()
        })
}

/// The options of stored `OptionSpec` content in authored order, as the
/// Match Score reads them: their keys and tags (ADR-140 P2 leaves out the
/// label, the lean hint and the coordinates); `None` for content that does
/// not decode.
pub(crate) fn preview_options(content: &[u8]) -> Option<Vec<PreviewOptionV1>> {
    ciborium::from_reader::<ContentV1<OptionV1>, _>(content)
        .ok()
        .map(|ContentV1(.., options)| {
            options
                .into_iter()
                .map(|OptionV1(key, _, tags, _, _)| PreviewOptionV1 { key, tags })
                .collect()
        })
}

/// The provenance digest of `record`.
pub(crate) fn provenance_digest(record: &GatewayRevisionRecordV1) -> [u8; 32] {
    let tombstone = record.tombstone();
    let mode = record.mode();
    domain_digest(
        PROVENANCE_DOMAIN,
        &cbor(&ProvenanceV1(
            ORIGIN,
            Ulid::from_bytes(record.principal_id()).to_string(),
            entity_text(tombstone.subject()),
            mode.profile().profile_id().to_owned(),
            hex(mode.profile().profile_digest()),
            mode.binding_epoch().get(),
            hex(tombstone.digest()),
        )),
    )
}

/// The `ModeProfile` a revision was produced under, from the binding its
/// commit recorded; `None` for a profile this Gateway does not know.
fn produced_under(mode: &GatewayModeBindingRecordV1) -> Option<Value> {
    mode.profile()
        .profile_id()
        .parse::<GatewayModeProfileIdV1>()
        .ok()
        .map(|id| {
            json!({
                "profile_kind": "gateway-mode-v1",
                "mode_profile_id": id.as_str(),
                "mode": id.mode(),
                "mode_profile_digest": hex(mode.profile().profile_digest()),
                "binding_epoch": mode.binding_epoch().get(),
            })
        })
}

/// The revision resource of a stored record.
///
/// # Errors
/// Returns `500 internal-safe-failure` for content or a mode profile this
/// Gateway cannot decode.
pub(crate) fn render<F: GatewayRevisionFamilyV1>(
    record: &GatewayRevisionRecordV1,
) -> Result<Value, ProblemV1> {
    let tombstone = record.tombstone();
    ciborium::from_reader::<ContentV1<F::Entry>, _>(record.content())
        .ok()
        .zip(produced_under(record.mode()))
        .map(
            |(ContentV1(schema_id, version, id, revision, parent, subject, entries), mode)| {
                let mut body = json!({
                    "schema_id": schema_id,
                    "schema_version": version,
                    "id": id,
                    "revision": revision,
                    "provenance": {
                        "digest": hex(provenance_digest(record)),
                        "origin": ORIGIN,
                    },
                    "mode_profile": mode,
                    "execution_profile": {
                        "profile_kind": "epf1",
                        "state": "unavailable",
                        "reason": "not-installed",
                    },
                    "availability": {"state": "available", "withheld": []},
                    "subject_entity_id": subject,
                    "parent_revision": parent,
                    "digest": hex(tombstone.digest()),
                });
                body[F::MEMBER] = F::render(&entries);
                body
            },
        )
        .ok_or_else(|| ProblemV1::internal(StatusCode::INTERNAL_SERVER_ERROR))
}

fn not_found() -> Response {
    ProblemV1::new(
        ProblemCodeV1::NotFoundOrUnavailable,
        StatusCode::NOT_FOUND,
        "not found or unavailable",
    )
    .into_response()
}

fn deleted() -> Response {
    ProblemV1::new(
        ProblemCodeV1::Deleted,
        StatusCode::GONE,
        "the subject erased this revision",
    )
    .into_response()
}

/// The public answer to a revision store failure.
pub(crate) fn store_failure(error: GatewayRevisionErrorV1) -> Response {
    match error {
        GatewayRevisionErrorV1::IdempotencyConflict => ProblemV1::new(
            ProblemCodeV1::IdempotencyConflict,
            StatusCode::CONFLICT,
            "the Idempotency-Key was used for a different request",
        )
        .into_response(),
        GatewayRevisionErrorV1::ParentNotHead => ProblemV1::new(
            ProblemCodeV1::AppendConflict,
            StatusCode::CONFLICT,
            "the parent is not the current revision",
        )
        .into_response(),
        GatewayRevisionErrorV1::ParentUnavailable => not_found(),
        GatewayRevisionErrorV1::ModeBindingStale => {
            GatewayError::Store(CoreError::ModeBindingStale).into_response()
        }
        GatewayRevisionErrorV1::InvalidRecord => {
            ProblemV1::internal(StatusCode::INTERNAL_SERVER_ERROR).into_response()
        }
        GatewayRevisionErrorV1::Unavailable => ProblemV1::new(
            ProblemCodeV1::TemporarilyUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "the revision store is unavailable",
        )
        .retryable()
        .into_response(),
    }
}

/// Why one revision request was not answered with a revision: a request
/// problem, a store answer, or a store command that never ran.
#[derive(Debug)]
pub(crate) enum RevisionFailureV1 {
    /// The request violates the contract.
    Problem(ProblemV1),
    /// The revision store refused or could not answer.
    Store(GatewayRevisionErrorV1),
    /// The store command never ran.
    Executor(StoreExecutorError),
}

impl From<ProblemV1> for RevisionFailureV1 {
    fn from(problem: ProblemV1) -> Self {
        Self::Problem(problem)
    }
}

impl From<GatewayRevisionErrorV1> for RevisionFailureV1 {
    fn from(error: GatewayRevisionErrorV1) -> Self {
        Self::Store(error)
    }
}

impl From<StoreExecutorError> for RevisionFailureV1 {
    fn from(error: StoreExecutorError) -> Self {
        Self::Executor(error)
    }
}

impl IntoResponse for RevisionFailureV1 {
    fn into_response(self) -> Response {
        match self {
            Self::Problem(problem) => problem.into_response(),
            Self::Store(error) => store_failure(error),
            Self::Executor(error) => GatewayError::from(error).into_response(),
        }
    }
}

/// The value of a store command, or why it has none.
fn settled<T>(
    outcome: Result<Result<T, GatewayRevisionErrorV1>, StoreExecutorError>,
) -> Result<T, RevisionFailureV1> {
    outcome
        .map_err(RevisionFailureV1::from)
        .and_then(|result| result.map_err(RevisionFailureV1::from))
}

/// A rendered revision with `status`.
fn answer<F: GatewayRevisionFamilyV1>(
    status: StatusCode,
    record: &GatewayRevisionRecordV1,
) -> Response {
    render::<F>(record).map_or_else(ProblemV1::into_response, |body| {
        (status, Json(body)).into_response()
    })
}

/// The request of a body whose `schema_version` is 1.
///
/// # Errors
/// Returns `400 unsupported-version` for any other integer version and
/// `400 invalid-request` for a body outside the request schema.
fn request<F: GatewayRevisionFamilyV1>(body: Value) -> Result<F::Request, ProblemV1> {
    if body
        .get("schema_version")
        .and_then(Value::as_u64)
        .is_some_and(|version| version != SCHEMA_VERSION)
    {
        return Err(ProblemV1::new(
            ProblemCodeV1::UnsupportedVersion,
            StatusCode::BAD_REQUEST,
            "unsupported schema_version",
        ));
    }
    serde_json::from_value(body).map_err(|_| invalid("the request does not match its schema"))
}

/// A fresh resource ID from the pos-core monotonic ULID generator, which
/// every Gateway identifier uses.
fn fresh_resource_id() -> Ulid {
    EntityId::new().inner()
}

/// The draft of one admitted request by `actor` for `principal_id`.
fn draft<F: GatewayRevisionFamilyV1>(
    principal_id: [u8; 16],
    actor: EntityId,
    key: &str,
    entries: Vec<F::Entry>,
    parent: Option<ParentV1>,
) -> Result<GatewayRevisionDraftV1, RevisionFailureV1> {
    let parent_ref = parent
        .as_ref()
        .map(|parent| (parent.id.to_string(), parent.revision.get()));
    let request_digest = domain_digest(
        REQUEST_DOMAIN,
        &cbor(&RequestV1(
            F::SCHEMA_ID,
            SCHEMA_VERSION,
            parent_ref,
            entity_text(actor),
            &entries,
        )),
    );
    let id = parent
        .as_ref()
        .map_or_else(fresh_resource_id, |parent| parent.id);
    let parent_revision = parent.map(|parent| parent.revision);
    let revision = parent_revision.map_or(NonZeroU64::MIN, |parent| parent.saturating_add(1));
    let content = content_bytes::<F>(id, revision, parent_revision, actor, entries);
    GatewayRevisionDraftV1::try_new(
        GatewayRevisionIdempotencyV1::new(
            principal_id,
            F::KIND,
            domain_digest(KEY_DOMAIN, key.as_bytes()),
            request_digest,
        ),
        id.to_bytes(),
        parent_revision,
        actor,
        domain_digest(F::DIGEST_DOMAIN, &content),
        content,
    )
    .map_err(RevisionFailureV1::from)
}

/// Commit `draft` on its own task, which owns `permit` until the commit
/// completes, so a cancelled request never releases the authority fence
/// early.
async fn commit_holding(
    gateway: Gateway,
    permit: GatewayOperationPermitV1,
    draft: GatewayRevisionDraftV1,
) -> Result<Result<GatewayRevisionCommitV1, GatewayRevisionErrorV1>, StoreExecutorError> {
    tokio::spawn(async move {
        let outcome = gateway
            .store
            .gateway_revision(move |port| port.commit_gateway_revision(draft))
            .await;
        drop(permit);
        outcome
    })
    .await
    .unwrap_or(Err(StoreExecutorError::Unhealthy))
}

/// The answer to one committed or replayed request.
fn committed<F: GatewayRevisionFamilyV1>(commit: GatewayRevisionCommitV1) -> Response {
    match commit {
        GatewayRevisionCommitV1::Committed(record) => answer::<F>(StatusCode::CREATED, &record),
        GatewayRevisionCommitV1::Replayed(GatewayRevisionStateV1::Present(record)) => {
            answer::<F>(StatusCode::OK, &record)
        }
        GatewayRevisionCommitV1::Replayed(GatewayRevisionStateV1::Erased(_)) => deleted(),
    }
}

/// `POST /v1/preferences` or `POST /v1/option-specs`: admit one revision
/// under the permit of its create decision.
pub(crate) async fn create<F: GatewayRevisionFamilyV1, O: OperationSpecV1>(
    gateway: &Gateway,
    authority: OperationAuthority<O>,
    key: &str,
    body: Value,
) -> Response {
    match authority.authorize(gateway, None).await {
        Ok(permit) => create_under::<F>(gateway, permit, key, body).await,
        Err(error) => error.into_response(),
    }
}

/// Admit and commit one revision under its create decision's `permit`, which
/// is held from admission until the commit settles.
async fn create_under<F: GatewayRevisionFamilyV1>(
    gateway: &Gateway,
    permit: GatewayOperationPermitV1,
    key: &str,
    body: Value,
) -> Response {
    let Some((principal_id, actor)) = permit.decision().map(|decision| {
        (
            *decision.principal().principal_id(),
            decision.actor_entity_id(),
        )
    }) else {
        return GatewayError::AuthorizationUnavailable.into_response();
    };
    let admitted = request::<F>(body)
        .and_then(F::admit)
        .map_err(RevisionFailureV1::from)
        .and_then(|(entries, parent)| draft::<F>(principal_id, actor, key, entries, parent));
    let draft = match admitted {
        Ok(draft) => draft,
        Err(failure) => return failure.into_response(),
    };
    let outcome = commit_holding(gateway.clone(), permit, draft).await;
    settled(outcome).map_or_else(RevisionFailureV1::into_response, committed::<F>)
}

/// The answer to `actor`'s read of one revision state.
fn read_answer<F: GatewayRevisionFamilyV1>(
    state: Option<GatewayRevisionStateV1>,
    actor: EntityId,
) -> Response {
    match state {
        Some(GatewayRevisionStateV1::Present(record)) if record.tombstone().subject() == actor => {
            answer::<F>(StatusCode::OK, &record)
        }
        Some(GatewayRevisionStateV1::Erased(tombstone)) if tombstone.subject() == actor => {
            deleted()
        }
        _ => not_found(),
    }
}

/// `GET .../{id}/revisions/{revision}`: one revision, answered to its
/// subject only, under the permit of its read decision.
pub(crate) async fn read<F: GatewayRevisionFamilyV1, O: OperationSpecV1>(
    gateway: &Gateway,
    authority: OperationAuthority<O>,
    id: &str,
    revision: u64,
) -> Response {
    let permit = match authority.authorize(gateway, None).await {
        Ok(permit) => permit,
        Err(error) => return error.into_response(),
    };
    let Some(actor) = permit
        .decision()
        .map(crate::GatewayAuthorizationDecision::actor_entity_id)
    else {
        return GatewayError::AuthorizationUnavailable.into_response();
    };
    let Some(key) = canonical_ulid(id)
        .zip(revision_number(revision))
        .map(|(id, revision)| GatewayRevisionKeyV1::new(F::KIND, id.to_bytes(), revision))
    else {
        return invalid("the path does not name a canonical revision").into_response();
    };
    let loaded = gateway
        .store
        .gateway_revision(move |port| port.load_gateway_revision(key))
        .await;
    drop(permit);
    settled(loaded).map_or_else(RevisionFailureV1::into_response, |state| {
        read_answer::<F>(state, actor)
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
