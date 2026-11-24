//! The Scenario Room resources of Gateway v1 (#1398, parent #303).
//!
//! A client authors a declarative ADR-041 descriptor; the Gateway decides the
//! operation through the C3 seam (every `persona` participant must be an
//! actor the Principal's grant covers, #303 decision 3a), and the store
//! worker admits it as one immutable revision
//! ([`crate::executor::scenario_room`]). The response is the
//! `ScenarioRoomRevision` resource: the frozen envelope, the admitted
//! descriptor and the committed Event receipt.

use axum::http::StatusCode;
use std::sync::Arc;

use pos_core::{AuthorityErrorV1, AuthorizationOutcomeV1, EntityId, EventId, Hash};
use pos_runtime::{
    HostCatalogueEntryV1, RoomInitialConditionV1, RoomParticipantKindV1, RoomParticipantV1,
    RoomPluginRefV1, RoomRuleV1, ScenarioRoomCatalogueV1, ScenarioRoomDescriptorV1,
    ScenarioRoomErrorV1, ScenarioRoomInputV1,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    executor::scenario_room::{
        RoomAdmissionV1, RoomClaimV1, RoomOperationV1, RoomOutcomeV1, RoomStoreErrorV1,
        StoredRoomRevisionV1,
    },
    problem::{ProblemCodeV1, ProblemV1},
    Gateway, GatewayAuthorization, GatewayError, GatewayOperationPermitV1, PendingAuthorityDenial,
};

/// The `$id` of the served `ScenarioRoomRevision` schema.
const REVISION_SCHEMA_ID: &str = "urn:pigloros:gateway:v1:schema:scenario-room-revision";
/// The `$id` of the committed Event receipt schema.
const RECEIPT_SCHEMA_ID: &str = "urn:pigloros:gateway:v1:schema:committed-event-receipt";
/// The domain of a revision's provenance digest: this prefix, the 32
/// `descriptor_hash` bytes and the 16 big-endian bytes of the committed
/// `EventId`.
const PROVENANCE_DOMAIN: &[u8] = b"PiglorOS.GatewayScenarioRoomRevision.v1\0";
const CLAIM_KEY_CONTEXT: &str = "PiglorOS Gateway ScenarioRoomRequest v1";
const REQUEST_DIGEST_DOMAIN: &[u8] = b"PiglorOS.GatewayScenarioRoomRequest.v1\0";

/// A Scenario Room failure as its public problem.
#[derive(Debug)]
pub(crate) enum RoomFailureV1 {
    /// A failure every protected operation shares.
    Gateway(GatewayError),
    /// The request does not match its schema.
    Invalid,
    /// The store refused the operation.
    Store(RoomStoreErrorV1),
}

impl From<RoomFailureV1> for ProblemV1 {
    fn from(failure: RoomFailureV1) -> Self {
        match failure {
            RoomFailureV1::Gateway(error) => Self::from(error),
            RoomFailureV1::Invalid => Self::new(
                ProblemCodeV1::InvalidRequest,
                StatusCode::BAD_REQUEST,
                "the Scenario Room request does not match its schema",
            ),
            RoomFailureV1::Store(error) => Self::from(error),
        }
    }
}

impl From<RoomStoreErrorV1> for ProblemV1 {
    fn from(error: RoomStoreErrorV1) -> Self {
        use ProblemCodeV1 as Code;
        let (code, status, detail) = match error {
            RoomStoreErrorV1::Room(error) => return Self::from(RoomAdmissionErrorV1(error)),
            RoomStoreErrorV1::GovernanceUnknown => (
                Code::AdmissionRejected,
                StatusCode::UNPROCESSABLE_ENTITY,
                "the room names no governance record of this host",
            ),
            RoomStoreErrorV1::NotFound => (
                Code::NotFoundOrUnavailable,
                StatusCode::NOT_FOUND,
                "not found or unavailable",
            ),
            RoomStoreErrorV1::StaleParent => (
                Code::AppendConflict,
                StatusCode::CONFLICT,
                "the parent revision is not the head of the room",
            ),
            RoomStoreErrorV1::IdempotencyConflict => (
                Code::IdempotencyConflict,
                StatusCode::CONFLICT,
                "the Idempotency-Key was used for a different request",
            ),
            RoomStoreErrorV1::TimelineCeiling => (
                Code::ResourceLimitExceeded,
                StatusCode::TOO_MANY_REQUESTS,
                "the host reached its root-Timeline ceiling; a retry cannot succeed",
            ),
            RoomStoreErrorV1::EventCeiling => (
                Code::ResourceLimitExceeded,
                StatusCode::TOO_MANY_REQUESTS,
                "the room or request Timeline reached its Event ceiling (permanent)",
            ),
            RoomStoreErrorV1::Store(error) => return Self::from(GatewayError::Store(error)),
            RoomStoreErrorV1::ModeUnavailable => {
                return Self::new(
                    Code::TemporarilyUnavailable,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the Scenario Room store is unavailable",
                )
                .retryable()
            }
        };
        Self::new(code, status, detail)
    }
}

/// A refusal of the ADR-041 descriptor seam.
struct RoomAdmissionErrorV1(ScenarioRoomErrorV1);

impl From<RoomAdmissionErrorV1> for ProblemV1 {
    fn from(RoomAdmissionErrorV1(error): RoomAdmissionErrorV1) -> Self {
        use ProblemCodeV1 as Code;
        let (code, status) = match error {
            ScenarioRoomErrorV1::UnsupportedSchemaVersion => {
                (Code::UnsupportedVersion, StatusCode::BAD_REQUEST)
            }
            ScenarioRoomErrorV1::InvalidField(_) => (Code::InvalidRequest, StatusCode::BAD_REQUEST),
            ScenarioRoomErrorV1::LimitExceeded(_) => {
                (Code::ResourceLimitExceeded, StatusCode::PAYLOAD_TOO_LARGE)
            }
            ScenarioRoomErrorV1::PluginNotBundled | ScenarioRoomErrorV1::RuleWithoutPlugin => {
                (Code::AdmissionRejected, StatusCode::UNPROCESSABLE_ENTITY)
            }
            ScenarioRoomErrorV1::EntropyUnavailable | ScenarioRoomErrorV1::CorruptPayload => {
                return Self::internal(StatusCode::INTERNAL_SERVER_ERROR)
            }
        };
        Self::new(code, status, error.to_string())
    }
}

/// `POST /v1/scenario-rooms`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateScenarioRoomRequestV1 {
    descriptor: WireInputV1,
}

/// `POST /v1/scenario-rooms/{room_id}/revisions`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeriveScenarioRoomRequestV1 {
    parent_revision: u64,
    descriptor: WireInputV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireInputV1 {
    schema_version: u64,
    tick_duration_ms: u32,
    max_ticks: u32,
    scheduler_seed: String,
    scheduler_policy: u8,
    intervention_policy: u8,
    plugins: Vec<WirePluginV1>,
    rules: Vec<WireRuleV1>,
    participants: Vec<WireParticipantV1>,
    initial_conditions: Vec<WireConditionV1>,
    governance_ref: String,
    privacy_export_ref: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePluginV1 {
    plugin_id: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRuleV1 {
    rule_id: String,
    value_micro: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireParticipantV1 {
    entity_id: String,
    kind: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireConditionV1 {
    entity_id: String,
    dimension: String,
    value_micro: i64,
}

/// An entity ID in its canonical form only: a ULID string that re-encodes
/// to itself, so a lower-case ID is refused rather than case-folded.
pub(crate) fn canonical_entity(text: &str) -> Option<EntityId> {
    ulid::Ulid::from_string(text)
        .ok()
        .filter(|ulid| ulid.to_string() == text)
        .map(EntityId::from_ulid)
}

fn seed(text: &str) -> Option<[u8; 32]> {
    let mut out = [0; 32];
    let decoded = text.len() == 64
        && text
            .as_bytes()
            .chunks_exact(2)
            .zip(out.iter_mut())
            .all(|(pair, byte)| {
                let digits = std::str::from_utf8(pair).ok();
                digits
                    .filter(|digits| {
                        digits
                            .bytes()
                            .all(|digit| matches!(digit, b'0'..=b'9' | b'a'..=b'f'))
                    })
                    .and_then(|digits| u8::from_str_radix(digits, 16).ok())
                    .map(|value| *byte = value)
                    .is_some()
            });
    decoded.then_some(out)
}

impl WireInputV1 {
    fn into_input(self) -> Option<ScenarioRoomInputV1> {
        let participants = self
            .participants
            .iter()
            .map(|participant| {
                canonical_entity(&participant.entity_id)
                    .zip(RoomParticipantKindV1::from_wire(&participant.kind))
                    .map(|(entity_id, kind)| RoomParticipantV1 { entity_id, kind })
            })
            .collect::<Option<Vec<_>>>();
        let initial_conditions = self
            .initial_conditions
            .into_iter()
            .map(|condition| {
                canonical_entity(&condition.entity_id).map(|entity_id| RoomInitialConditionV1 {
                    entity_id,
                    dimension: condition.dimension,
                    value_micro: condition.value_micro,
                })
            })
            .collect::<Option<Vec<_>>>();
        let refs =
            canonical_entity(&self.governance_ref).zip(canonical_entity(&self.privacy_export_ref));
        seed(&self.scheduler_seed)
            .zip(refs)
            .zip(participants.zip(initial_conditions))
            .map(
                |(
                    (scheduler_seed, (governance_ref, privacy_export_ref)),
                    (participants, initial_conditions),
                )| {
                    ScenarioRoomInputV1 {
                        schema_version: self.schema_version,
                        tick_duration_ms: self.tick_duration_ms,
                        max_ticks: self.max_ticks,
                        scheduler_seed,
                        scheduler_policy: self.scheduler_policy,
                        intervention_policy: self.intervention_policy,
                        plugins: self
                            .plugins
                            .into_iter()
                            .map(|plugin| RoomPluginRefV1 {
                                plugin_id: plugin.plugin_id,
                                version: plugin.version,
                            })
                            .collect(),
                        rules: self
                            .rules
                            .into_iter()
                            .map(|rule| RoomRuleV1 {
                                rule_id: rule.rule_id,
                                value_micro: rule.value_micro,
                            })
                            .collect(),
                        participants,
                        initial_conditions,
                        governance_ref,
                        privacy_export_ref,
                    }
                },
            )
    }
}

/// A room ID path segment: a canonical ULID, otherwise `400`.
pub(crate) fn parse_room_id(text: &str) -> Result<EntityId, ProblemV1> {
    canonical_entity(text).ok_or_else(|| {
        ProblemV1::new(
            ProblemCodeV1::InvalidRequest,
            StatusCode::BAD_REQUEST,
            "the room ID is not a canonical ULID",
        )
    })
}

/// The `persona` participants of `input`: the entities the Principal's
/// grant must cover as actors.
pub(crate) fn personas(input: &ScenarioRoomInputV1) -> Vec<EntityId> {
    input
        .participants
        .iter()
        .filter(|participant| participant.kind == RoomParticipantKindV1::Persona)
        .map(|participant| participant.entity_id)
        .collect()
}

/// A parsed create request: its input and its digest.
pub(crate) struct ParsedRoomRequestV1 {
    pub(crate) input: ScenarioRoomInputV1,
    parent_revision: u64,
    request_digest: [u8; 32],
}

/// Parse a create request body. The request digest covers the operation and
/// the body's canonical JSON (keys sorted), so an exact retry with other
/// whitespace or member order is still exact.
pub(crate) fn parse_create(body: &Value) -> Result<ParsedRoomRequestV1, RoomFailureV1> {
    CreateScenarioRoomRequestV1::deserialize(body)
        .ok()
        .and_then(|request| request.descriptor.into_input())
        .map(|input| ParsedRoomRequestV1 {
            input,
            parent_revision: 0,
            request_digest: request_digest("create", None, body),
        })
        .ok_or(RoomFailureV1::Invalid)
}

/// Parse a derive request body for `room_id`.
pub(crate) fn parse_derive(
    room_id: EntityId,
    body: &Value,
) -> Result<ParsedRoomRequestV1, RoomFailureV1> {
    DeriveScenarioRoomRequestV1::deserialize(body)
        .ok()
        .and_then(|request| {
            let parent_revision = request.parent_revision;
            request
                .descriptor
                .into_input()
                .map(|input| (input, parent_revision))
        })
        .map(|(input, parent_revision)| ParsedRoomRequestV1 {
            input,
            parent_revision,
            request_digest: request_digest("derive", Some(room_id), body),
        })
        .ok_or(RoomFailureV1::Invalid)
}

fn request_digest(operation: &str, room_id: Option<EntityId>, body: &Value) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REQUEST_DIGEST_DOMAIN);
    hasher.update(operation.as_bytes());
    hasher.update(&[0]);
    hasher.update(&room_id.map_or([0; 16], |room| room.inner().to_bytes()));
    let mut canonical = String::new();
    canonical_json(body, &mut canonical);
    hasher.update(canonical.as_bytes());
    *hasher.finalize().as_bytes()
}

/// The canonical text of `value`: object members sorted by name at every
/// depth, no whitespace, strings and numbers as `serde_json` writes them.
/// Member order and whitespace therefore never change a request digest.
fn canonical_json(value: &Value, out: &mut String) {
    match value {
        Value::Object(members) => {
            let mut names: Vec<&String> = members.keys().collect();
            names.sort_unstable();
            out.push('{');
            for (index, name) in names.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&Value::from(name.as_str()).to_string());
                out.push(':');
                canonical_json(&members[name], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                canonical_json(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

/// The claim of `key` for `operation` by the Principal `permit` admitted.
fn claim(
    permit: &GatewayOperationPermitV1,
    operation: &str,
    room_id: Option<EntityId>,
    key: &str,
    request_digest: [u8; 32],
) -> RoomClaimV1 {
    let principal = permit
        .decision()
        .map_or([0; 16], |decision| *decision.principal().principal_id());
    let mut material = Vec::with_capacity(64 + key.len());
    material.extend_from_slice(&principal);
    material.extend_from_slice(operation.as_bytes());
    material.push(0);
    material.extend_from_slice(&room_id.map_or([0; 16], |room| room.inner().to_bytes()));
    material.extend_from_slice(key.as_bytes());
    RoomClaimV1 {
        key: blake3::derive_key(CLAIM_KEY_CONTEXT, &material),
        request_digest,
    }
}

impl Gateway {
    fn room_admission(&self) -> RoomAdmissionV1 {
        RoomAdmissionV1 {
            catalogue: room_catalogue(),
            governance_record: self
                .authorization
                .as_deref()
                .and_then(crate::GatewayAuthorization::governance_record),
            max_events: self.limits.max_events_per_timeline,
            max_timelines: self.limits.max_timelines,
            host_timelines: self.host_timelines(),
        }
    }

    async fn room_operation(
        &self,
        operation: RoomOperationV1,
    ) -> Result<RoomOutcomeV1, RoomFailureV1> {
        self.store
            .scenario_room(operation, self.room_admission())
            .await
            .map_err(|error| RoomFailureV1::Gateway(GatewayError::from(error)))?
            .map_err(RoomFailureV1::Store)
    }

    /// The denial of the consent `privacy_export_ref` names, as the
    /// decision of `permit` pinned it (#303 decision 2a), with the authorizer
    /// to record it: a consent the acting Principal does not hold is
    /// `consent-invalid` (ADN1 outcome `ConsentMissing`), a revoked one
    /// `revoked` (`RevokedAtFence`). Only the in-process harness composition
    /// protects nothing; it has no authorizer and checks no consent.
    ///
    /// # Errors
    /// A refusal that yields no recordable denial fails closed with
    /// [`GatewayError::AuthorizationEvidenceUnavailable`] (`503`): a permit
    /// without a decision (one a composition that protects nothing issued)
    /// never skips a protected composition's consent check.
    fn room_consent_denial(
        &self,
        permit: &GatewayOperationPermitV1,
        input: &ScenarioRoomInputV1,
    ) -> Result<Option<(Arc<GatewayAuthorization>, PendingAuthorityDenial)>, RoomFailureV1> {
        let Some(authorization) = self.authorization.clone() else {
            return Ok(None);
        };
        let consent =
            self.consent_pinned(permit, EventId::from_ulid(input.privacy_export_ref.inner()));
        let refusal = match consent {
            None => Some((
                AuthorizationOutcomeV1::ConsentMissing,
                AuthorityErrorV1::ConsentMissing,
            )),
            Some(consent) if consent.revocation().is_some() => Some((
                AuthorizationOutcomeV1::RevokedAtFence,
                AuthorityErrorV1::RevokedAtFence,
            )),
            Some(_) => None,
        };
        refusal
            .map(|(outcome, error)| {
                permit
                    .decision()
                    .and_then(|decision| {
                        GatewayAuthorization::deny_at_commit_fence(decision, outcome, Some(error))
                    })
                    .map(|pending| (Arc::clone(&authorization), pending))
                    .ok_or(RoomFailureV1::Gateway(
                        GatewayError::AuthorizationEvidenceUnavailable,
                    ))
            })
            .transpose()
    }

    /// Run a room write under `permit`, after its consent check. A consent
    /// denial releases the permit first, then is recorded as ADN1 denial
    /// evidence (under the denial-record bounds) and answered.
    async fn room_write(
        &self,
        permit: GatewayOperationPermitV1,
        input: &ScenarioRoomInputV1,
        operation: RoomOperationV1,
    ) -> Result<RoomOutcomeV1, RoomFailureV1> {
        if let Some((authorization, pending)) = self.room_consent_denial(&permit, input)? {
            drop(permit);
            return Err(RoomFailureV1::Gateway(
                self.recorded_denial(&authorization, pending).await,
            ));
        }
        let outcome = self.room_operation(operation).await;
        drop(permit);
        outcome
    }

    /// Create revision 1 of a room under the `permit` of its decision.
    pub(crate) async fn create_scenario_room(
        &self,
        permit: GatewayOperationPermitV1,
        key: &str,
        request: ParsedRoomRequestV1,
    ) -> Result<RoomOutcomeV1, RoomFailureV1> {
        let claim = claim(&permit, "create", None, key, request.request_digest);
        let input = request.input;
        let operation = RoomOperationV1::Create {
            claim,
            input: Box::new(input.clone()),
        };
        self.room_write(permit, &input, operation).await
    }

    /// Derive the next revision of `room_id` under the `permit` of its decision.
    pub(crate) async fn derive_scenario_room(
        &self,
        permit: GatewayOperationPermitV1,
        room_id: EntityId,
        key: &str,
        request: ParsedRoomRequestV1,
    ) -> Result<RoomOutcomeV1, RoomFailureV1> {
        let claim = claim(
            &permit,
            "derive",
            Some(room_id),
            key,
            request.request_digest,
        );
        let input = request.input;
        let operation = RoomOperationV1::Derive {
            claim,
            room_id,
            parent_revision: request.parent_revision,
            input: Box::new(input.clone()),
        };
        self.room_write(permit, &input, operation).await
    }

    /// Read revision `revision` of `room_id`.
    pub(crate) async fn read_scenario_room(
        &self,
        room_id: EntityId,
        revision: u64,
    ) -> Result<RoomOutcomeV1, RoomFailureV1> {
        self.room_operation(RoomOperationV1::Read { room_id, revision })
            .await
    }
}

/// The status and `ScenarioRoomRevision` body of a room outcome.
pub(crate) fn revision_response(outcome: &RoomOutcomeV1) -> (StatusCode, Value) {
    match outcome {
        RoomOutcomeV1::Committed(stored) => (StatusCode::CREATED, revision_json(stored)),
        RoomOutcomeV1::Existing(stored) => (StatusCode::OK, revision_json(stored)),
    }
}

/// The `ScenarioRoomRevision` of one stored revision.
pub(crate) fn revision_json(stored: &StoredRoomRevisionV1) -> Value {
    let descriptor = descriptor_json(&stored.descriptor);
    let mode_profile = mode_profile_json(stored);
    let revision = stored.descriptor.revision().get();
    let timeline_id = stored.timeline.to_string();
    json!({
        "schema_id": REVISION_SCHEMA_ID,
        "id": stored.descriptor.room_id().to_string(),
        "revision": revision,
        "provenance": {
            "digest": revision_provenance_digest_v1(
                &stored.descriptor.descriptor_hash(),
                stored.event_id,
            ),
            "origin": "principal-authored",
        },
        "mode_profile": mode_profile,
        "execution_profile": {
            "profile_kind": "epf1",
            "state": "unavailable",
            "reason": "not-installed",
        },
        "availability": {"state": "available", "withheld": []},
        "descriptor": descriptor,
        "parent_revision": revision.checked_sub(1).filter(|parent| *parent > 0),
        "commit": {
            "schema_id": RECEIPT_SCHEMA_ID,
            "timeline_id": timeline_id,
            "event_id": stored.event_id.to_string(),
            "seq": stored.seq.as_u64(),
            "event_schema_id": crate::executor::scenario_room::ROOM_REVISION_EVENT_TYPE,
            "next_cursor": crate::event_cursor(
                stored.generation,
                &timeline_id,
                stored.seq.as_u64().saturating_add(1),
            ),
        },
    })
}

/// The GMP1 `mode_profile` the revision's commit was produced under: the
/// profile its recorded binding epoch names.
fn mode_profile_json(stored: &StoredRoomRevisionV1) -> Value {
    let (id, digest, epoch) = &stored.produced_under;
    json!({
        "profile_kind": "gateway-mode-v1",
        "mode_profile_id": id.as_str(),
        "mode": id.mode(),
        "mode_profile_digest": hex(digest),
        "binding_epoch": epoch.get(),
    })
}

/// The `ScenarioRoomDescriptor` of an admitted revision, built from its
/// fields: the members, values and canonical list order of its
/// `room.revision.v1` payload.
fn descriptor_json(descriptor: &ScenarioRoomDescriptorV1) -> Value {
    let input = descriptor.input();
    let plugins: Vec<Value> = input
        .plugins
        .iter()
        .map(|plugin| json!({"plugin_id": plugin.plugin_id, "version": plugin.version}))
        .collect();
    let rules: Vec<Value> = input
        .rules
        .iter()
        .map(|rule| json!({"rule_id": rule.rule_id, "value_micro": rule.value_micro}))
        .collect();
    let participants: Vec<Value> = input
        .participants
        .iter()
        .map(|participant| {
            json!({
                "entity_id": participant.entity_id.to_string(),
                "kind": participant.kind.as_str(),
            })
        })
        .collect();
    let initial_conditions: Vec<Value> = input
        .initial_conditions
        .iter()
        .map(|condition| {
            json!({
                "entity_id": condition.entity_id.to_string(),
                "dimension": condition.dimension,
                "value_micro": condition.value_micro,
            })
        })
        .collect();
    json!({
        "room_id": descriptor.room_id().to_string(),
        "revision": descriptor.revision().get(),
        "schema_version": input.schema_version,
        "tick_duration_ms": input.tick_duration_ms,
        "max_ticks": input.max_ticks,
        "scheduler_seed": hex(&input.scheduler_seed),
        "scheduler_policy": input.scheduler_policy,
        "intervention_policy": input.intervention_policy,
        "plugins": plugins,
        "rules": rules,
        "participants": participants,
        "initial_conditions": initial_conditions,
        "governance_ref": input.governance_ref.to_string(),
        "privacy_export_ref": input.privacy_export_ref.to_string(),
        "correlation_id": hex(descriptor.correlation_id().as_bytes()),
        "plugin_composition_hash": hex(descriptor.plugin_composition_hash().as_bytes()),
        "rule_set_hash": hex(descriptor.rule_set_hash().as_bytes()),
        "descriptor_hash": hex(descriptor.descriptor_hash().as_bytes()),
    })
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .map(|digit| char::from(DIGITS[usize::from(digit)]))
        .collect()
}

/// The Plugins a room may name: the reviewed host catalogue entry the
/// Gateway ships, described without registering or running it (#303 owner
/// decision of 2026-11-15), so rooms work before an EPF1 is installed.
pub(crate) fn room_catalogue() -> ScenarioRoomCatalogueV1 {
    crate::FrozenGatewayActionConfiguration::resolve(std::iter::empty())
        .ok()
        .and_then(|frozen| {
            HostCatalogueEntryV1::<crate::GatewayActionPlugin>::gateway()
                .scenario_room_catalogue_v1(&frozen)
                .ok()
        })
        .unwrap_or_default()
}

/// The `provenance.digest` of one `ScenarioRoomRevision`.
///
/// It is BLAKE3 of the domain separator
/// `PiglorOS.GatewayScenarioRoomRevision.v1\0`, the revision's
/// `descriptor_hash` and the 16 bytes of the `EventId` that committed it,
/// in lower-case hex.
#[must_use]
pub fn revision_provenance_digest_v1(descriptor_hash: &Hash, event_id: EventId) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROVENANCE_DOMAIN);
    hasher.update(descriptor_hash.as_bytes());
    hasher.update(&event_id.inner().to_bytes());
    hasher.finalize().to_hex().to_string()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
