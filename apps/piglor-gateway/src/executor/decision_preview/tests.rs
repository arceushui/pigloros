//! The Decision Preview store commands on a bound in-memory host (ADR-140
//! C2 test plan). The fixtures are shared with the Gateway-level tests of
//! [`crate::decision_preview`].

use std::{error::Error, num::NonZeroU64};

use pos_core::{
    ErasureRecoveryLimitsV1, GatewayModeBindingHostV1, GatewayModeProfileRefV1,
    GatewayRevisionDraftV1, GatewayRevisionErasureHostV1, GatewayRevisionIdempotencyV1,
};
use pos_runtime::{
    ComputedRecommendationV1, OptionScoreV1, RoomParticipantV1, RoomPluginRefV1, RoomRuleV1,
    ScenarioRoomInputV1,
};
use pos_store::StoreConfig;
use serde::Serialize;

use super::*;
use crate::{
    executor::scenario_room::{
        run_room_operation, RoomAdmissionV1, RoomClaimV1, RoomOperationV1, RoomOutcomeV1,
    },
    host_timelines::HostTimelinesV1,
    mode_profile::test_bound_host,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The Principal of every fixture claim.
pub(crate) const PRINCIPAL: [u8; 16] = [7; 16];
/// The acting entity and persona participant of the fixture inputs.
pub(crate) const ACTOR: &str = "01JC0GATEWAYF1XTVREACT0R00";
const OTHER: &str = "01JC0GATEWAYQ0CA1ACT0R0000";
const GOVERNANCE: &str = "01JC0GATEWAYW90G0VERN00001";
const CONSENT: &str = "01JC0GATEWAYW90C0NSENT0001";
/// The installed profile of the fixture admissions.
const PROFILE: &str = "deterministic-local-v1";
const PROFILE_DIGEST: [u8; 32] = [1; 32];
/// The golden GMP1 digests `scripts/check_gateway_contract.py` pins.
const LOCAL_DIGEST: &str = "26d6c7e75b11df673a1ef2d3210733b4ca431648eab0b9ae93bf4a6f6e69da3f";
const AIR_GAPPED_DIGEST: &str = "455883a475edbf5cc24907a03e6e46a476ceec6227ecdb8429999646dac447e5";
const PREFERENCE_SCHEMA: &str = "urn:pigloros:gateway:v1:schema:preference-revision";
const OPTION_SPEC_SCHEMA: &str = "urn:pigloros:gateway:v1:schema:option-spec-revision";

pub(crate) fn entity(text: &str) -> Result<EntityId, String> {
    Ulid::from_string(text)
        .map(EntityId::from_ulid)
        .map_err(|error| error.to_string())
}

pub(crate) fn actor() -> Result<EntityId, String> {
    entity(ACTOR)
}

fn digest_of(text: &str) -> Result<[u8; 32], String> {
    let mut bytes = [0; 32];
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).map_err(|error| error.to_string())?;
        *byte = u8::from_str_radix(pair, 16).map_err(|error| error.to_string())?;
    }
    Ok(bytes)
}

/// The value of a preview result, or its refusal as a test error.
fn ok<T>(result: PreviewResult<T>) -> Result<T, String> {
    result.map_err(|error| format!("{error:?}"))
}

/// The refusal of a preview result, as text.
fn refusal<T>(result: PreviewResult<T>) -> String {
    result
        .err()
        .map_or_else(String::new, |error| format!("{error:?}"))
}

fn host() -> TestResult<ErasureExecutionHostV1> {
    let mut host = ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Memory,
        ErasureRecoveryLimitsV1::compiled_maximum(),
    )?;
    drop(test_bound_host(&mut host, GatewayModeProfileIdV1::Local));
    Ok(host)
}

fn limits(max_events: u64) -> PreviewLimitsV1 {
    PreviewLimitsV1 {
        max_events,
        quota: Arc::default(),
    }
}

/// A room revision whose only participant is `participant` of `kind`, and
/// whose `privacy_export_ref` is `consent`.
fn room(
    host: &mut ErasureExecutionHostV1,
    participant: EntityId,
    kind: RoomParticipantKindV1,
    consent: EntityId,
) -> Result<PreviewRevisionRefV1, String> {
    let governance = entity(GOVERNANCE)?;
    let input = ScenarioRoomInputV1 {
        schema_version: 1,
        tick_duration_ms: 100,
        max_ticks: 600,
        scheduler_seed: [4; 32],
        scheduler_policy: 0,
        intervention_policy: 1,
        plugins: vec![RoomPluginRefV1 {
            plugin_id: "gateway-world-actions".to_owned(),
            version: "0.1.0".to_owned(),
        }],
        rules: vec![RoomRuleV1 {
            rule_id: "gateway-world-actions.impulse.scale".to_owned(),
            value_micro: 250_000,
        }],
        participants: vec![RoomParticipantV1 {
            entity_id: participant,
            kind,
        }],
        initial_conditions: Vec::new(),
        governance_ref: governance,
        privacy_export_ref: consent,
    };
    let admission = RoomAdmissionV1 {
        catalogue: crate::scenario_room::room_catalogue(),
        governance_record: Some(governance),
        max_events: 16,
        max_timelines: 16,
        host_timelines: HostTimelinesV1::new(None),
    };
    let mut key = [0; 32];
    key[..16].copy_from_slice(&EntityId::new().inner().to_bytes());
    let outcome = run_room_operation(
        host,
        RoomOperationV1::Create {
            claim: RoomClaimV1 {
                key,
                request_digest: [0; 32],
            },
            input: Box::new(input),
        },
        &admission,
    )
    .map_err(|error| format!("{error:?}"))?;
    let RoomOutcomeV1::Committed(stored) = outcome else {
        return Err("the room did not commit".to_owned());
    };
    let provenance = crate::scenario_room::revision_provenance_digest_v1(
        &stored.descriptor.descriptor_hash(),
        stored.event_id,
    );
    Ok(PreviewRevisionRefV1 {
        id: stored.descriptor.room_id().inner(),
        revision: stored.descriptor.revision(),
        digest: digest_of(&provenance)?,
    })
}

fn cbor(value: &impl Serialize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).map_err(|error| error.to_string())?;
    Ok(bytes)
}

/// Commit revision 1 of a `kind` resource `id` of `subject` with raw
/// `content` through the revision port, as a #304 commit stores it: the
/// content is not validated, so it may be out of bounds or undecodable.
pub(crate) fn raw_revision(
    host: &mut ErasureExecutionHostV1,
    kind: GatewayRevisionKindV1,
    id: Ulid,
    subject: EntityId,
    content: Vec<u8>,
) -> Result<PreviewRevisionRefV1, String> {
    let digest = *blake3::hash(&content).as_bytes();
    let draft = GatewayRevisionDraftV1::try_new(
        GatewayRevisionIdempotencyV1::new(
            PRINCIPAL,
            kind,
            *blake3::hash(&id.to_bytes()).as_bytes(),
            [0; 32],
        ),
        id.to_bytes(),
        None,
        subject,
        digest,
        content,
    )
    .map_err(|error| error.to_string())?;
    host.command_sender()
        .map_err(|error| error.to_string())?
        .with_gateway_revisions(|port| port.commit_gateway_revision(draft))
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
    Ok(PreviewRevisionRefV1 {
        id,
        revision: NonZeroU64::MIN,
        digest,
    })
}

/// A Preference of `subject` with `weights`.
fn preference(
    host: &mut ErasureExecutionHostV1,
    subject: EntityId,
    weights: &[(&str, i64)],
) -> Result<PreviewRevisionRefV1, String> {
    let id = EntityId::new().inner();
    let entries: Vec<(String, i64)> = weights
        .iter()
        .map(|(dimension, weight)| ((*dimension).to_owned(), *weight))
        .collect();
    let content = cbor(&(
        PREFERENCE_SCHEMA,
        1_u64,
        id.to_string(),
        1_u64,
        None::<u64>,
        subject.to_string(),
        entries,
    ))?;
    raw_revision(
        host,
        GatewayRevisionKindV1::Preference,
        id,
        subject,
        content,
    )
}

/// One `OptionSpec` option: `[key, label, tags, lean_hint_micro,
/// coordinates]`.
type OptionEntryV1 = (String, String, Vec<String>, Option<i64>, Option<(i64, i64)>);

/// An `OptionSpec` of `subject` with `options`, each with a lean hint and
/// coordinates the Match Score ignores.
fn option_spec(
    host: &mut ErasureExecutionHostV1,
    subject: EntityId,
    options: &[(&str, &[&str])],
) -> Result<PreviewRevisionRefV1, String> {
    let id = EntityId::new().inner();
    let entries: Vec<OptionEntryV1> = options
        .iter()
        .map(|(key, tags)| {
            (
                (*key).to_owned(),
                key.to_uppercase(),
                tags.iter().map(|tag| (*tag).to_owned()).collect(),
                Some(1_000_000),
                Some((5, -5)),
            )
        })
        .collect();
    let content = cbor(&(
        OPTION_SPEC_SCHEMA,
        1_u64,
        id.to_string(),
        1_u64,
        None::<u64>,
        subject.to_string(),
        entries,
    ))?;
    raw_revision(
        host,
        GatewayRevisionKindV1::OptionSpec,
        id,
        subject,
        content,
    )
}

/// The ADR-140 worked example's inputs for [`ACTOR`], over a room whose
/// consent is `consent`.
pub(crate) fn seeded(
    host: &mut ErasureExecutionHostV1,
    consent: EntityId,
) -> Result<PreviewRequestV1, String> {
    let actor = actor()?;
    Ok(PreviewRequestV1 {
        scenario_room: room(host, actor, RoomParticipantKindV1::Persona, consent)?,
        preference: preference(
            host,
            actor,
            &[("city", -300_000), ("nature", 800_000), ("quiet", 500_000)],
        )?,
        option_spec: option_spec(
            host,
            actor,
            &[
                ("coast", &["nature", "quiet", "surf"]),
                ("city", &["city", "nightlife"]),
            ],
        )?,
        profile_id: PROFILE.to_owned(),
    })
}

fn worked_example() -> RecommendationV1 {
    RecommendationV1::Computed(ComputedRecommendationV1 {
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
    })
}

/// The claim key of `key` for the fixture Principal and actor.
fn claim_key(key: &str) -> Result<PreviewClaimKeyV1, String> {
    Ok(PreviewClaimKeyV1::derive(PRINCIPAL, actor()?, key))
}

/// Admit `request` under `key` as the Gateway does: the profile gate and
/// inputs, then the commit command.
fn admit(
    host: &mut ErasureExecutionHostV1,
    request: &PreviewRequestV1,
    key: &str,
    limits: &PreviewLimitsV1,
    now: Instant,
) -> Result<PreviewResult<AdmittedPreviewV1>, String> {
    let actor = actor()?;
    let key = claim_key(key)?;
    let installed = Some((PROFILE.to_owned(), PROFILE_DIGEST));
    let admitted = admit_inputs(host, actor, request, installed).and_then(|(_, profile_digest)| {
        let fresh = FreshPreviewV1 {
            principal_id: PRINCIPAL,
            actor,
            request: request.clone(),
            profile_digest,
        };
        let commit = PreviewCommitV1 {
            key,
            request_digest: request.digest(),
            fresh: Some(fresh),
        };
        commit_preview(host, commit, limits, now)
    });
    Ok(admitted)
}

/// Finish the claim of `request` under `key`, as the retry's second store
/// command does.
fn finish_retry(
    host: &mut ErasureExecutionHostV1,
    request: &PreviewRequestV1,
    key: &str,
    max_events: u64,
) -> Result<PreviewResult<AdmittedPreviewV1>, String> {
    Ok(commit_preview(
        host,
        PreviewCommitV1 {
            key: claim_key(key)?,
            request_digest: request.digest(),
            fresh: None,
        },
        &limits(max_events),
        Instant::now(),
    ))
}

/// The fixture actor's read of `preview_id`.
fn read(
    host: &mut ErasureExecutionHostV1,
    preview_id: EventId,
) -> Result<PreviewResult<DecisionPreviewV1>, String> {
    let read = read_preview(host, preview_id, PRINCIPAL, actor()?);
    Ok(read.and_then(|read| read.view))
}

/// Every Event of the `decision-previews` Timeline.
fn events(host: &mut ErasureExecutionHostV1) -> Result<Vec<Event>, String> {
    ok(scan(host)).map(|scan| scan.events)
}

fn results(host: &mut ErasureExecutionHostV1) -> Result<usize, String> {
    let events = events(host)?;
    Ok(events.iter().filter(|event| is_result(event)).count())
}

/// Append one Event to the `decision-previews` Timeline outside every
/// check, as a store fault or another writer would.
fn raw(
    host: &mut ErasureExecutionHostV1,
    entity: EntityId,
    kind: &str,
    payload: Vec<u8>,
) -> Result<Event, String> {
    ok(open_previews_timeline(host))?;
    host.command_sender()
        .map_err(|error| error.to_string())?
        .append(
            decision_previews_timeline(),
            &[EventDraft::new(
                entity,
                Kind::new(kind),
                CanonicalBytes::from_vec(payload),
            )],
        )
        .map_err(|error| error.to_string())?
        .into_iter()
        .next()
        .ok_or_else(|| "nothing was appended".to_owned())
}

/// The claim of `request` under `key` with no result: an attempt the host
/// interrupted between its two appends. Its mode digest is the current
/// binding's unless `mode_profile_digest` names another.
pub(crate) fn interrupted(
    host: &mut ErasureExecutionHostV1,
    request: &PreviewRequestV1,
    key: &str,
    consent: EntityId,
    mode_profile_digest: Option<[u8; 32]>,
) -> Result<EventId, String> {
    let (_, current) = ok(current_binding(host))?;
    let claim = PreviewClaimV1 {
        principal_id: PRINCIPAL,
        actor_entity_id: actor()?,
        request: request.clone(),
        consent_ref: consent,
        profile_digest: PROFILE_DIGEST,
        mode_profile_digest: mode_profile_digest.unwrap_or(current),
    };
    let payload = claim.to_payload().map_err(|error| error.to_string())?;
    raw(
        host,
        claim_key(key)?.entity(),
        PREVIEW_REQUEST_EVENT_TYPE_V1,
        payload,
    )
    .map(|event| event.id)
}

fn erase(
    host: &mut ErasureExecutionHostV1,
    kind: GatewayRevisionKindV1,
    reference: &PreviewRevisionRefV1,
) -> TestResult {
    let key = GatewayRevisionKeyV1::new(kind, reference.id.to_bytes(), reference.revision);
    let erased = host.command_sender()?.with_gateway_revisions(|port| {
        port.erase_gateway_revision(GatewayRevisionErasureHostV1::new().authorize_erasure(key))
    })??;
    assert!(erased.is_some());
    Ok(())
}

#[test]
fn a_preview_commits_its_claim_and_result_and_reads_them_back() -> TestResult {
    let mut host = host()?;
    let request = seeded(&mut host, entity(CONSENT)?)?;
    let admitted = ok(admit(
        &mut host,
        &request,
        "k-1",
        &limits(64),
        Instant::now(),
    )?)?;
    // The claim, then its result: the preview ID is the claim Event's ID,
    // the claim's entity is the claim key's, the result's is the preview.
    let stored = events(&mut host)?;
    assert_eq!(stored.len(), 2);
    let (claim, result) = (&stored[0], &stored[1]);
    assert_eq!(claim.id, admitted.preview_id);
    assert_eq!(claim.event_type.as_str(), PREVIEW_REQUEST_EVENT_TYPE_V1);
    assert_eq!(claim.entity, claim_key("k-1")?.entity());
    assert_eq!(result.event_type.as_str(), PREVIEW_RESULT_EVENT_TYPE_V1);
    assert_eq!(
        result.entity,
        EntityId::from_ulid(admitted.preview_id.inner())
    );
    assert_eq!(result.causation_id, Some(admitted.preview_id));
    assert_eq!(
        PreviewResultV1::from_payload(result.payload.as_slice()),
        Ok(PreviewResultV1 {
            preview_id: admitted.preview_id,
            outcome: PreviewOutcomeV1::Computed,
        })
    );
    // PRQ1 binds the room's consent, the installed profile and the binding
    // the claim committed under.
    let (_, local_digest) = ok(current_binding(&mut host))?;
    assert_eq!(
        PreviewClaimV1::from_payload(claim.payload.as_slice()).as_ref(),
        Ok(&admitted.claim)
    );
    assert_eq!(admitted.claim.request, request);
    assert_eq!(admitted.claim.consent_ref, entity(CONSENT)?);
    assert_eq!(admitted.claim.profile_digest, PROFILE_DIGEST);
    assert_eq!(admitted.claim.mode_profile_digest, local_digest);
    assert_eq!(local_digest, digest_of(LOCAL_DIGEST)?);
    // The Timeline is the host's: found by its derived identity, unowned.
    let timeline = host
        .read_sender()?
        .timeline(decision_previews_timeline())?
        .ok_or("the decision-previews Timeline is recorded")?;
    assert_eq!(timeline.meta.name.as_deref(), Some("decision-previews"));
    assert!(timeline.meta.owner.is_none());
    // The read recomputes the worked example.
    let preview = ok(read(&mut host, admitted.preview_id)?)?;
    assert_eq!(
        preview.state,
        DecisionPreviewStateV1::Committed {
            result: DecisionPreviewResultEventV1 {
                event_id: result.id,
                seq: result.seq,
            },
            recommendation: worked_example(),
        }
    );
    assert_eq!(preview.state.generation(), 2);
    assert_eq!(preview.claim, admitted.claim);
    assert_eq!(
        (preview.mode_profile.profile, preview.mode_profile.digest),
        (GatewayModeProfileIdV1::Local, local_digest)
    );
    assert_eq!(preview.mode_profile.binding_epoch, NonZeroU64::MIN);
    // A second read is the same resource.
    assert_eq!(ok(read(&mut host, admitted.preview_id)?)?, preview);
    Ok(())
}

#[test]
fn an_exact_retry_returns_the_preview_and_appends_nothing() -> TestResult {
    let mut host = host()?;
    let request = seeded(&mut host, entity(CONSENT)?)?;
    let limits = limits(64);
    let now = Instant::now();
    let first = ok(admit(&mut host, &request, "k-1", &limits, now)?)?;
    let found = ok(lookup_claim(
        &mut host,
        &claim_key("k-1")?,
        request.digest(),
    ))?
    .ok_or("the claim is found by its key")?;
    assert!(found.is_finished());
    // The step-12 re-lookup answers an equal claim as an exact retry, from
    // its stored claim, and the quota does not count it.
    let again = ok(admit(&mut host, &request, "k-1", &limits, now)?)?;
    assert_eq!(
        (again.preview_id, &again.claim),
        (first.preview_id, &first.claim)
    );
    let retried = ok(finish_retry(&mut host, &request, "k-1", 64)?)?;
    assert_eq!(retried.preview_id, first.preview_id);
    assert_eq!(events(&mut host)?.len(), 2);
    let counted = limits
        .quota
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .windows
        .get(&PRINCIPAL)
        .map(|(_, count)| *count);
    assert_eq!(counted, Some(1));
    // The same key with another request is a conflict; another key is
    // unclaimed.
    let other = PreviewRequestV1 {
        profile_id: "replay-v1".to_owned(),
        ..request.clone()
    };
    assert_eq!(
        refusal(lookup_claim(&mut host, &claim_key("k-1")?, other.digest())),
        "IdempotencyConflict"
    );
    assert_eq!(
        refusal(admit(&mut host, &other, "k-1", &limits, now)?),
        "IncompatibleProfile"
    );
    assert_eq!(
        refusal(finish_retry(&mut host, &other, "k-1", 64)?),
        "IdempotencyConflict"
    );
    let unclaimed = ok(lookup_claim(
        &mut host,
        &claim_key("k-2")?,
        request.digest(),
    ))?;
    assert!(unclaimed.is_none());
    // A finish without a claim to finish is the internal-failure arm.
    assert_eq!(
        refusal(finish_retry(&mut host, &request, "k-2", 64)?),
        "Internal"
    );
    assert_eq!(events(&mut host)?.len(), 2);
    Ok(())
}

#[test]
fn an_interrupted_claim_is_finished_once_by_its_retry() -> TestResult {
    let mut host = host()?;
    let consent = entity(CONSENT)?;
    let request = seeded(&mut host, consent)?;
    let preview_id = interrupted(&mut host, &request, "k-1", consent, None)?;
    let admitted = ok(read(&mut host, preview_id)?)?;
    assert_eq!(admitted.state, DecisionPreviewStateV1::Admitted);
    assert_eq!(admitted.state.generation(), 1);
    let found = ok(lookup_claim(
        &mut host,
        &claim_key("k-1")?,
        request.digest(),
    ))?
    .ok_or("the claim is found")?;
    assert!(!found.is_finished());
    let finished = ok(finish_retry(&mut host, &request, "k-1", 64)?)?;
    assert_eq!(finished.preview_id, preview_id);
    let committed = ok(read(&mut host, preview_id)?)?;
    assert!(matches!(
        committed.state,
        DecisionPreviewStateV1::Committed { .. }
    ));
    // The provenance changes once, when the result commits.
    assert_ne!(committed.provenance_digest, admitted.provenance_digest);
    // A forced second finish appends no second result.
    ok(finish_retry(&mut host, &request, "k-1", 64)?)?;
    assert_eq!(results(&mut host)?, 1);
    Ok(())
}

#[test]
fn an_input_erased_before_the_finish_fails_the_preview_for_good() -> TestResult {
    let mut host = host()?;
    let consent = entity(CONSENT)?;
    let request = seeded(&mut host, consent)?;
    let preview_id = interrupted(&mut host, &request, "k-1", consent, None)?;
    erase(
        &mut host,
        GatewayRevisionKindV1::Preference,
        &request.preference,
    )?;
    ok(finish_retry(&mut host, &request, "k-1", 64)?)?;
    let failed = ok(read(&mut host, preview_id)?)?;
    assert_eq!(
        failed.state,
        DecisionPreviewStateV1::Failed {
            code: PreviewFailureCodeV1::input_deleted(),
        }
    );
    assert_eq!(failed.state.generation(), 2);
    // A failed preview stays failed after a later erasure.
    erase(
        &mut host,
        GatewayRevisionKindV1::OptionSpec,
        &request.option_spec,
    )?;
    assert_eq!(ok(read(&mut host, preview_id)?)?.state, failed.state);
    Ok(())
}

#[test]
fn a_later_erasure_degrades_a_computed_preview() -> TestResult {
    let mut host = host()?;
    let request = seeded(&mut host, entity(CONSENT)?)?;
    let admitted = ok(admit(
        &mut host,
        &request,
        "k-1",
        &limits(64),
        Instant::now(),
    )?)?;
    let committed = ok(read(&mut host, admitted.preview_id)?)?;
    erase(
        &mut host,
        GatewayRevisionKindV1::OptionSpec,
        &request.option_spec,
    )?;
    let degraded = ok(read(&mut host, admitted.preview_id)?)?;
    let DecisionPreviewStateV1::Committed { result, .. } = committed.state else {
        return Err("the preview committed".into());
    };
    assert_eq!(degraded.state, DecisionPreviewStateV1::Degraded { result });
    assert_eq!(degraded.state.generation(), 2);
    // Degradation writes nothing, so the provenance is unchanged.
    assert_eq!(degraded.provenance_digest, committed.provenance_digest);
    assert_eq!(events(&mut host)?.len(), 2);
    // The erased input is now 404 to a fresh admission.
    assert_eq!(
        refusal(admit(
            &mut host,
            &request,
            "k-2",
            &limits(64),
            Instant::now()
        )?),
        "NotFound"
    );
    Ok(())
}

#[test]
fn the_ceiling_keeps_a_slot_for_every_unfinished_claim() -> TestResult {
    let mut host = host()?;
    let consent = entity(CONSENT)?;
    let request = seeded(&mut host, consent)?;
    let now = Instant::now();
    // Two Events of one preview, then one claim without its result.
    ok(admit(&mut host, &request, "k-1", &limits(5), now)?)?;
    interrupted(&mut host, &request, "k-2", consent, None)?;
    // A fresh preview needs its two Events beside the slot reserved for the
    // unfinished claim: 3 + 2 + 1 > 5, a permanent refusal in the commit.
    assert_eq!(
        refusal(admit(&mut host, &request, "k-3", &limits(5), now)?),
        "StoreFull"
    );
    assert_eq!(events(&mut host)?.len(), 3);
    // The reserved slot lets the retry finish.
    ok(finish_retry(&mut host, &request, "k-2", 5)?)?;
    assert_eq!(events(&mut host)?.len(), 4);
    assert_eq!(
        refusal(admit(&mut host, &request, "k-3", &limits(5), now)?),
        "StoreFull"
    );
    ok(admit(&mut host, &request, "k-3", &limits(6), now)?)?;
    assert_eq!(events(&mut host)?.len(), 6);
    Ok(())
}

/// An unfinished claim whose reserved slot another writer took cannot be
/// finished: the store is inconsistent, and nothing is appended.
#[test]
fn a_finish_without_its_reserved_slot_is_the_internal_arm() -> TestResult {
    let mut host = host()?;
    let consent = entity(CONSENT)?;
    let request = seeded(&mut host, consent)?;
    interrupted(&mut host, &request, "k-1", consent, None)?;
    raw(&mut host, EntityId::new(), "filler", Vec::new())?;
    assert_eq!(
        refusal(finish_retry(&mut host, &request, "k-1", 2)?),
        "Internal"
    );
    assert_eq!(results(&mut host)?, 0);
    Ok(())
}

#[test]
fn the_quota_window_counts_new_claims_only() -> TestResult {
    let mut quota = PreviewQuotaV1::default();
    let opened = Instant::now();
    for _ in 0..MAX_ADMISSIONS_PER_MINUTE {
        assert_eq!(quota.check(PRINCIPAL, opened), Ok(()));
        quota.count(PRINCIPAL, opened);
    }
    assert_eq!(quota.check(PRINCIPAL, opened), Err(QUOTA_WINDOW));
    let later = opened + Duration::from_secs(20);
    assert_eq!(quota.check(PRINCIPAL, later), Err(Duration::from_secs(40)));
    // Another Principal has its own window, and a closed window reopens.
    assert_eq!(quota.check([8; 16], later), Ok(()));
    assert_eq!(quota.check(PRINCIPAL, opened + QUOTA_WINDOW), Ok(()));

    // In the commit command: a full window refuses a new claim, retryably,
    // and counts nothing, while an exact retry is still answered.
    let mut host = host()?;
    let request = seeded(&mut host, entity(CONSENT)?)?;
    let limits = limits(64);
    let now = Instant::now();
    let first = ok(admit(&mut host, &request, "k-1", &limits, now)?)?;
    {
        let mut quota = limits.quota.lock().unwrap_or_else(PoisonError::into_inner);
        for _ in 1..MAX_ADMISSIONS_PER_MINUTE {
            quota.count(PRINCIPAL, now);
        }
    }
    assert_eq!(
        refusal(admit(&mut host, &request, "k-2", &limits, now)?),
        format!(
            "{:?}",
            DecisionPreviewErrorV1::QuotaExceeded {
                retry_after: QUOTA_WINDOW
            }
        )
    );
    assert_eq!(
        ok(admit(&mut host, &request, "k-1", &limits, now)?)?.preview_id,
        first.preview_id
    );
    assert_eq!(events(&mut host)?.len(), 2);
    ok(admit(
        &mut host,
        &request,
        "k-2",
        &limits,
        now + QUOTA_WINDOW,
    )?)?;
    Ok(())
}

/// Stored #304 content is decoded without re-validating its bounds, so an
/// out-of-bounds weight reaches the Match Score refusal: the internal-failure
/// arm, before anything is appended.
#[test]
fn a_match_score_refusal_is_the_internal_arm() -> TestResult {
    let mut host = host()?;
    let mut request = seeded(&mut host, entity(CONSENT)?)?;
    request.preference = preference(&mut host, actor()?, &[("nature", 2_000_000)])?;
    assert_eq!(
        refusal(admit(
            &mut host,
            &request,
            "k-1",
            &limits(64),
            Instant::now()
        )?),
        "Internal"
    );
    assert!(!ok(scan(&mut host))?.recorded);
    Ok(())
}

#[test]
fn undecodable_inputs_are_the_internal_arm() -> TestResult {
    let mut host = host()?;
    let request = seeded(&mut host, entity(CONSENT)?)?;
    let actor = actor()?;
    for kind in [
        GatewayRevisionKindV1::Preference,
        GatewayRevisionKindV1::OptionSpec,
    ] {
        let undecodable =
            raw_revision(&mut host, kind, EntityId::new().inner(), actor, vec![0xff])?;
        let mut corrupt = request.clone();
        match kind {
            GatewayRevisionKindV1::Preference => corrupt.preference = undecodable,
            GatewayRevisionKindV1::OptionSpec => corrupt.option_spec = undecodable,
        }
        assert_eq!(
            refusal(admit(
                &mut host,
                &corrupt,
                "k-1",
                &limits(64),
                Instant::now()
            )?),
            "Internal",
            "{kind:?}"
        );
    }
    assert!(!ok(scan(&mut host))?.recorded);
    Ok(())
}

/// A stored claim naming a revision the store does not hold, or another
/// digest (of a present or an erased revision), or a payload that does not
/// re-encode, or a commit binding other than its own: each is the
/// internal-failure arm and appends nothing.
#[test]
fn every_stored_inconsistency_is_the_internal_arm() -> TestResult {
    let mut host = host()?;
    let consent = entity(CONSENT)?;
    let request = seeded(&mut host, consent)?;
    let missing = PreviewRequestV1 {
        preference: PreviewRevisionRefV1 {
            id: EntityId::new().inner(),
            ..request.preference.clone()
        },
        ..request.clone()
    };
    let mismatched = PreviewRequestV1 {
        option_spec: PreviewRevisionRefV1 {
            digest: [9; 32],
            ..request.option_spec.clone()
        },
        ..request.clone()
    };
    // An erased input whose tombstone digest is not the one the claim names.
    let erased = preference(&mut host, actor()?, &[("city", 1)])?;
    erase(&mut host, GatewayRevisionKindV1::Preference, &erased)?;
    let erased_mismatched = PreviewRequestV1 {
        preference: PreviewRevisionRefV1 {
            digest: [9; 32],
            ..erased
        },
        ..request.clone()
    };
    for (key, claimed) in [
        ("missing", &missing),
        ("mismatched", &mismatched),
        ("erased-mismatched", &erased_mismatched),
    ] {
        let preview_id = interrupted(&mut host, claimed, key, consent, None)?;
        assert_eq!(
            refusal(finish_retry(&mut host, claimed, key, 64)?),
            "Internal"
        );
        // A computed result over such a claim cannot be recomputed.
        let payload = PreviewResultV1 {
            preview_id,
            outcome: PreviewOutcomeV1::Computed,
        }
        .to_payload();
        raw(
            &mut host,
            EntityId::from_ulid(preview_id.inner()),
            PREVIEW_RESULT_EVENT_TYPE_V1,
            payload,
        )?;
        assert_eq!(refusal(read(&mut host, preview_id)?), "Internal");
    }
    // A claim committed under another binding than its field 10 names.
    let rebound = interrupted(&mut host, &request, "rebound", consent, Some([9; 32]))?;
    assert_eq!(refusal(read(&mut host, rebound)?), "Internal");
    let before = events(&mut host)?.len();
    // A claim payload that does not decode, and results that do not decode
    // or name another preview.
    raw(
        &mut host,
        claim_key("corrupt")?.entity(),
        PREVIEW_REQUEST_EVENT_TYPE_V1,
        vec![0xff],
    )?;
    assert_eq!(
        refusal(lookup_claim(
            &mut host,
            &claim_key("corrupt")?,
            request.digest()
        )),
        "Internal"
    );
    for (key, payload) in [
        ("broken", vec![0xff]),
        (
            "elsewhere",
            PreviewResultV1 {
                preview_id: EventId::new(),
                outcome: PreviewOutcomeV1::Computed,
            }
            .to_payload(),
        ),
    ] {
        let preview_id = interrupted(&mut host, &request, key, consent, None)?;
        raw(
            &mut host,
            EntityId::from_ulid(preview_id.inner()),
            PREVIEW_RESULT_EVENT_TYPE_V1,
            payload,
        )?;
        assert_eq!(refusal(read(&mut host, preview_id)?), "Internal", "{key}");
        assert_eq!(
            refusal(finish_retry(&mut host, &request, key, 64)?),
            "Internal",
            "{key}"
        );
    }
    // Only the fixture Events above were appended; no command appended any.
    assert_eq!(events(&mut host)?.len(), before + 5);
    Ok(())
}

#[test]
fn admission_answers_every_unusable_input_with_not_found() -> TestResult {
    let mut host = host()?;
    let consent = entity(CONSENT)?;
    let request = seeded(&mut host, consent)?;
    let actor = actor()?;
    let other = entity(OTHER)?;
    let non_persona = room(&mut host, actor, RoomParticipantKindV1::Society, consent)?;
    let foreign_room = room(&mut host, other, RoomParticipantKindV1::Persona, consent)?;
    let foreign_preference = preference(&mut host, other, &[("city", 1)])?;
    let foreign_option_spec = option_spec(&mut host, other, &[("a", &[]), ("b", &[])])?;
    let erased_preference = preference(&mut host, actor, &[("city", 1)])?;
    erase(
        &mut host,
        GatewayRevisionKindV1::Preference,
        &erased_preference,
    )?;
    let unknown = |reference: &PreviewRevisionRefV1| PreviewRevisionRefV1 {
        id: EntityId::new().inner(),
        ..reference.clone()
    };
    let later = |reference: &PreviewRevisionRefV1| PreviewRevisionRefV1 {
        revision: NonZeroU64::MIN.saturating_add(1),
        ..reference.clone()
    };
    let mismatched = |reference: &PreviewRevisionRefV1| PreviewRevisionRefV1 {
        digest: [9; 32],
        ..reference.clone()
    };
    let with_room = |scenario_room| PreviewRequestV1 {
        scenario_room,
        ..request.clone()
    };
    let with_preference = |preference| PreviewRequestV1 {
        preference,
        ..request.clone()
    };
    let with_option_spec = |option_spec| PreviewRequestV1 {
        option_spec,
        ..request.clone()
    };
    for refused in [
        with_room(unknown(&request.scenario_room)),
        with_room(later(&request.scenario_room)),
        with_room(mismatched(&request.scenario_room)),
        with_room(non_persona),
        with_room(foreign_room),
        with_preference(unknown(&request.preference)),
        with_preference(mismatched(&request.preference)),
        with_preference(foreign_preference),
        with_preference(erased_preference),
        with_option_spec(unknown(&request.option_spec)),
        with_option_spec(foreign_option_spec),
    ] {
        assert_eq!(
            refusal(admit(
                &mut host,
                &refused,
                "k-1",
                &limits(64),
                Instant::now()
            )?),
            "NotFound",
            "{refused:?}"
        );
    }
    assert!(!ok(scan(&mut host))?.recorded);
    // The key was never claimed: the valid request admits under it now.
    ok(admit(
        &mut host,
        &request,
        "k-1",
        &limits(64),
        Instant::now(),
    )?)?;
    Ok(())
}

/// A room the store cannot decode is the internal-failure arm, not `404`.
#[test]
fn an_undecodable_room_is_the_internal_arm() -> TestResult {
    let mut host = host()?;
    let request = seeded(&mut host, entity(CONSENT)?)?;
    let room = EntityId::new();
    let timeline = host
        .command_sender()?
        .create_timeline(&format!("scenario-room/{room}"))?;
    host.command_sender()?.append(
        timeline.id(),
        &[EventDraft::new(
            room,
            Kind::new(crate::executor::scenario_room::ROOM_REVISION_EVENT_TYPE),
            CanonicalBytes::from_vec(vec![0xff]),
        )],
    )?;
    let corrupt = PreviewRequestV1 {
        scenario_room: PreviewRevisionRefV1 {
            id: room.inner(),
            ..request.scenario_room.clone()
        },
        ..request
    };
    assert_eq!(
        refusal(admit(
            &mut host,
            &corrupt,
            "k-1",
            &limits(64),
            Instant::now()
        )?),
        "Internal"
    );
    Ok(())
}

#[test]
fn the_profile_gate_needs_an_installed_servable_profile() -> TestResult {
    for (mode, profile_id, served) in [
        (GatewayModeProfileIdV1::Local, "replay-v1", true),
        (
            GatewayModeProfileIdV1::Local,
            "deterministic-local-v1",
            true,
        ),
        (GatewayModeProfileIdV1::Local, "live-local-v1", true),
        (
            GatewayModeProfileIdV1::Local,
            "deterministic-air-gapped-v1",
            false,
        ),
        (GatewayModeProfileIdV1::Local, "live-air-gapped-v1", false),
        (GatewayModeProfileIdV1::AirGapped, "replay-v1", true),
        (
            GatewayModeProfileIdV1::AirGapped,
            "deterministic-air-gapped-v1",
            true,
        ),
        (
            GatewayModeProfileIdV1::AirGapped,
            "live-air-gapped-v1",
            true,
        ),
        (
            GatewayModeProfileIdV1::AirGapped,
            "deterministic-local-v1",
            false,
        ),
        (GatewayModeProfileIdV1::AirGapped, "unknown-v1", false),
    ] {
        assert_eq!(servable(mode, profile_id), served, "{mode:?} {profile_id}");
    }
    let mut host = host()?;
    let request = seeded(&mut host, entity(CONSENT)?)?;
    let actor = actor()?;
    let air_gapped = PreviewRequestV1 {
        profile_id: "deterministic-air-gapped-v1".to_owned(),
        ..request.clone()
    };
    for (request, installed) in [
        // No installed EPF1, as the release composition answers.
        (&request, None),
        // A port answering for another profile.
        (&request, Some(("replay-v1".to_owned(), PROFILE_DIGEST))),
        // Installed, but not servable in the bound Local mode.
        (
            &air_gapped,
            Some(("deterministic-air-gapped-v1".to_owned(), PROFILE_DIGEST)),
        ),
    ] {
        assert_eq!(
            refusal(admit_inputs(&mut host, actor, request, installed)),
            "IncompatibleProfile"
        );
    }
    // The gate comes before the inputs: an unknown room is still 409.
    let unknown_room = PreviewRequestV1 {
        scenario_room: PreviewRevisionRefV1 {
            id: EntityId::new().inner(),
            ..request.scenario_room.clone()
        },
        ..request.clone()
    };
    assert_eq!(
        refusal(admit_inputs(&mut host, actor, &unknown_room, None)),
        "IncompatibleProfile"
    );
    // An unbound store has no mode to serve a profile in.
    let mut unbound = ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Memory,
        ErasureRecoveryLimitsV1::compiled_maximum(),
    )?;
    assert_eq!(
        refusal(admit_inputs(
            &mut unbound,
            actor,
            &request,
            Some((PROFILE.to_owned(), PROFILE_DIGEST))
        )),
        "ModeUnavailable"
    );
    Ok(())
}

/// ADR-140 P9: the Timeline is found by its identity; a client root named
/// `decision-previews` is never used.
#[test]
fn a_client_root_named_decision_previews_is_never_used() -> TestResult {
    let mut host = host()?;
    let request = seeded(&mut host, entity(CONSENT)?)?;
    let decoy = host
        .command_sender()?
        .create_timeline("decision-previews")?;
    raw_decoy(&mut host, decoy.id())?;
    assert!(!ok(scan(&mut host))?.recorded);
    let admitted = ok(admit(
        &mut host,
        &request,
        "k-1",
        &limits(64),
        Instant::now(),
    )?)?;
    assert_eq!(events(&mut host)?.len(), 2);
    assert!(matches!(
        ok(read(&mut host, admitted.preview_id)?)?.state,
        DecisionPreviewStateV1::Committed { .. }
    ));
    let decoy_events =
        host.read_sender()?
            .read_bounded(decoy.id(), SeqRange::all(), read_bounds())?;
    assert_eq!(decoy_events.len(), 1);
    assert_ne!(decoy.id(), decision_previews_timeline());
    Ok(())
}

/// A claim-shaped Event on the client root `decoy`, which no lookup reads.
fn raw_decoy(host: &mut ErasureExecutionHostV1, decoy: pos_core::TimelineId) -> TestResult {
    host.command_sender()?.append(
        decoy,
        &[EventDraft::new(
            claim_key("k-1")?.entity(),
            Kind::new(PREVIEW_REQUEST_EVENT_TYPE_V1),
            CanonicalBytes::from_vec(vec![0xff]),
        )],
    )?;
    Ok(())
}

#[test]
fn a_preview_is_read_only_by_its_principal_and_actor() -> TestResult {
    let mut host = host()?;
    // No Timeline yet: every read is 404.
    assert_eq!(
        refusal(read_preview(&mut host, EventId::new(), PRINCIPAL, actor()?)),
        "NotFound"
    );
    let request = seeded(&mut host, entity(CONSENT)?)?;
    let admitted = ok(admit(
        &mut host,
        &request,
        "k-1",
        &limits(64),
        Instant::now(),
    )?)?;
    let result = events(&mut host)?
        .into_iter()
        .find(is_result)
        .ok_or("the result committed")?;
    for (preview_id, principal_id, reader) in [
        (admitted.preview_id, [8; 16], actor()?),
        (admitted.preview_id, PRINCIPAL, entity(OTHER)?),
        (EventId::new(), PRINCIPAL, actor()?),
        (result.id, PRINCIPAL, actor()?),
    ] {
        assert_eq!(
            refusal(read_preview(&mut host, preview_id, principal_id, reader)),
            "NotFound"
        );
    }
    let read = ok(read_preview(
        &mut host,
        admitted.preview_id,
        PRINCIPAL,
        actor()?,
    ))?;
    assert_eq!(read.consent_ref, entity(CONSENT)?);
    Ok(())
}

/// ADR-140 C18: the read reports the binding the claim's commit recorded,
/// not the binding current at the read.
#[test]
fn a_preview_keeps_the_binding_its_claim_committed_under() -> TestResult {
    let mut host = host()?;
    let request = seeded(&mut host, entity(CONSENT)?)?;
    let admitted = ok(admit(
        &mut host,
        &request,
        "k-1",
        &limits(64),
        Instant::now(),
    )?)?;
    let reference = |id: &str, digest: &str| -> TestResult<GatewayModeProfileRefV1> {
        Ok(GatewayModeProfileRefV1::try_new(id, digest_of(digest)?)?)
    };
    let permit = GatewayModeBindingHostV1::new().authorize_migration(
        reference("gateway-mode-local-v1", LOCAL_DIGEST)?,
        reference("gateway-mode-air-gapped-v1", AIR_GAPPED_DIGEST)?,
    )?;
    host.gateway_mode_binding().migrate_mode(permit)?;
    let preview = ok(read(&mut host, admitted.preview_id)?)?;
    assert_eq!(
        (
            preview.mode_profile.profile,
            preview.mode_profile.binding_epoch.get()
        ),
        (GatewayModeProfileIdV1::Local, 1)
    );
    Ok(())
}

/// A host refusal of the Timeline read is a store failure: a Timeline
/// holding an Event past the read bounds cannot be read.
#[test]
fn a_host_refusal_is_a_store_failure() -> TestResult {
    let mut host = host()?;
    raw(
        &mut host,
        EntityId::new(),
        &"x".repeat(PREVIEW_REQUEST_EVENT_TYPE_V1.len() + 1),
        Vec::new(),
    )?;
    assert_eq!(
        refusal(lookup_claim(&mut host, &claim_key("k-1")?, [0; 32])),
        format!(
            "{:?}",
            DecisionPreviewErrorV1::Store(host_error_to_core(ErasureHostErrorV1::AdapterFailure))
        )
    );
    Ok(())
}

/// ADR-140 P30: an `AuthorizationDenied` topology refusal is the
/// non-retryable unavailability, any other host refusal a store failure.
/// (A host recovered through `open_with_authority`, even with the closed
/// composition, always holds an authority and a coordinator, so the
/// refusal cannot be provoked through a recovered store.)
#[test]
fn host_and_room_errors_map_to_their_preview_errors() {
    assert_eq!(
        format!(
            "{:?}",
            topology_error(ErasureHostErrorV1::AuthorizationDenied)
        ),
        "TopologyUnavailable"
    );
    assert_eq!(
        format!("{:?}", topology_error(ErasureHostErrorV1::Conflict)),
        format!(
            "{:?}",
            DecisionPreviewErrorV1::Store(host_error_to_core(ErasureHostErrorV1::Conflict))
        )
    );
    assert_eq!(
        format!(
            "{:?}",
            room_error(RoomStoreErrorV1::Store(
                pos_core::CoreError::ErasureAccessFrozen
            ))
        ),
        format!(
            "{:?}",
            DecisionPreviewErrorV1::Store(pos_core::CoreError::ErasureAccessFrozen)
        )
    );
    assert_eq!(
        format!("{:?}", room_error(RoomStoreErrorV1::StaleParent)),
        "Internal"
    );
}

/// The test-only stores have no erasure host, and an expired command
/// answers that its deadline passed.
#[test]
fn a_store_without_a_host_or_an_expired_command_answers() -> TestResult {
    let (reply, receiver) = oneshot::channel();
    let mut state = ExecutorState {
        store: ExecutorStore::Generic(Box::new(pos_store::memory::MemoryStore::new())),
        owntracks_owner_key: None,
        owntracks_rate_limiter: super::super::OwnTracksRateLimiter {
            buckets: HashMap::new(),
        },
    };
    let command: Box<PreviewCommandV1<()>> = Box::new(PreviewCommandV1 {
        operation: Box::new(|_| Ok(())),
        reply,
    });
    command.run_on_worker(&mut state);
    assert_eq!(
        format!("{:?}", receiver.blocking_recv()?),
        format!(
            "{:?}",
            Ok::<PreviewResult<()>, StoreExecutorError>(Err(DecisionPreviewErrorV1::Store(
                pos_core::CoreError::ErasureContainmentUnavailable
            )))
        )
    );
    let (reply, receiver) = oneshot::channel();
    super::super::expire_command(super::super::Command::Action(Box::new(PreviewCommandV1::<
        (),
    > {
        operation: Box::new(|_| Ok(())),
        reply,
    })));
    assert!(matches!(
        receiver.blocking_recv()?,
        Err(StoreExecutorError::DeadlineExceeded)
    ));
    Ok(())
}

/// The hand-written CBOR of the provenance record is the deterministic
/// encoding: every head width and the null item agree with `ciborium`.
#[test]
fn the_provenance_record_is_deterministic_cbor() -> TestResult {
    for value in [
        0,
        23,
        24,
        0xff,
        0x100,
        0xffff,
        0x1_0000,
        0xffff_ffff,
        0x1_0000_0000,
        u64::MAX,
    ] {
        let mut head = Vec::new();
        cbor_head(&mut head, CBOR_UNSIGNED, value);
        assert_eq!(head, cbor(&value)?, "{value}");
    }
    for length in [0, 23, 26, 64, 300] {
        let text = "a".repeat(length);
        assert_eq!(cbor_text(&text), cbor(&text)?, "{length}");
    }
    // A preview read before and after its result commits: the record is
    // the CBOR array ADR-140 P24 names, with a null result digest first.
    let mut host = host()?;
    let consent = entity(CONSENT)?;
    let request = seeded(&mut host, consent)?;
    let preview_id = interrupted(&mut host, &request, "k-1", consent, None)?;
    let admitted = ok(read(&mut host, preview_id)?)?;
    ok(finish_retry(&mut host, &request, "k-1", 64)?)?;
    let committed = ok(read(&mut host, preview_id)?)?;
    let stored = events(&mut host)?;
    // The expected digests come from BLAKE3 directly, not from the function
    // under test.
    let digest = |payload: &CanonicalBytes| blake3::hash(payload.as_slice()).to_hex().to_string();
    for (preview, result) in [
        (&admitted, None),
        (&committed, Some(digest(&stored[1].payload))),
    ] {
        let mut expected = PROVENANCE_DOMAIN.to_vec();
        expected.extend(cbor(&(
            ORIGIN,
            Ulid::from_bytes(PRINCIPAL).to_string(),
            ACTOR,
            preview_id.to_string(),
            digest(&stored[0].payload),
            result,
            preview.mode_profile.profile.as_str(),
            hex(preview.mode_profile.digest),
            preview.mode_profile.binding_epoch.get(),
        ))?);
        assert_eq!(
            preview.provenance_digest,
            *blake3::hash(&expected).as_bytes()
        );
    }
    Ok(())
}
