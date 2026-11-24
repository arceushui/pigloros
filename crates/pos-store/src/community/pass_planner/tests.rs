//! The pass planner through its public entry points, over a fake read port
//! that serves the domain-private quarantine index, recorded-set counters,
//! retained-outcome and control-operation counts, live keys, selected CGR1
//! counts, closure index and scope rows (A4c adds the Memory domain's
//! storage). Each case names its ADR-129 revision 10 or 11 obligation.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use pos_core::community_lifecycle::{
    ArtifactRefV1, CommunityDurableBackendV1, CommunityDurableProfileInputV1,
    CommunityDurableProfileV1, CommunityHostProgressV1, CommunityLifecycleErrorV1 as Error,
    CommunityPassQuoteInputV1, CommunityPassQuoteMemberV1, CommunityPassQuoteV1,
    CommunityPreparedInvocationInputV1, CommunityProfileMemberV1, CommunityProfileRetentionV1,
    CommunityQuarantineKeyV1, CommunityQuarantineReasonV1, CommunitySharedCountsV1,
    CommunityTypedInputRefV1, TimelinePositionV1,
};
use pos_core::community_lifecycle::{
    CommunityGraphCountsV1, CommunityLocatorProducerV1, CommunityMetadataLocatorV1,
    CommunityMetadataSchemaV1, CommunityNativeNodeReferenceV1, CommunityPassDomainV1,
    CommunityPassGraphTermsV1, CommunityProtectionSizesV1, CommunityScopeMemberV1,
    COMMUNITY_MAXIMUM_STORE_KEYS_V1,
};
use pos_core::{ErasureArtifactClassV1, Hash, ImplementationKeyV1, TimelineId};
use std::sync::Arc;
use std::time::Duration;

use pos_core::community_lifecycle::{
    CommunityReducerBindingV1, CommunitySourceCatalogueV1, CommunitySourceSchemaRuleV1,
};
use pos_core::store::{EventStore, SeqRange};
use pos_core::{
    AuthorityTrustRootSealV1, CanonicalBytes, EntityId, ErasureContainmentGateV1, Event,
    EventDraft, Kind, Seq,
};
use ulid::Ulid;
use zeroize::Zeroizing;

use super::super::erasure_budget::{
    CommunityErasureBudgetPortV1, CommunityErasureBudgetV1, CommunityPendingErasureV1,
};
use super::super::{
    prepare_community_observation_v1, CommunityObservationConsumerV1, CommunityObservationEventV1,
    CommunityObservationInstallationV1, CommunityObservationMaterializationInputV1,
    CommunityObservationMaterializationV1, CommunityObservationPassV1,
    CommunityObservationSourcesV1, MemoryCommunityDomainV1,
};
use crate::memory::MemoryStore;
use crate::MemoryTrustedClockAuthorityV1;

use super::{
    plan_community_pass_v1, CommunityPassDueV1, CommunityPassInstallationV1,
    CommunityPassMemberViewV1, CommunityPassObservationUseV1, CommunityPassPlanV1,
    CommunityPassReadPortV1, CommunityPassRequestV1, CommunityPassStepInputsV1,
    CommunityPassViewV1, CommunityQuarantineIndexV1,
};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const ENTRIES: [&str; 3] = ["entry-a", "entry-b", "entry-c"];
const CADENCE: [u64; 3] = [10, 20, 30];
const STATE_LIMITS: [u64; 3] = [100, 200, 300];
const G: [u8; 16] = [2; 16];
/// `t_r` of every fixture request.
const T_R: u64 = 1_000_000;
/// `t_r` plus the 27 s decision deadline.
const BOUND: u64 = T_R + 27_000_000;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn key() -> Fallible<ImplementationKeyV1> {
    Ok(ImplementationKeyV1::new(
        "plugin-a".into(),
        "host-v1".into(),
        hash(4),
    )?)
}

fn timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([1; 16]))
}

/// The fake domain reads.
#[derive(Default)]
struct Port {
    quarantine: BTreeMap<[u8; 32], Vec<CommunityQuarantineReasonV1>>,
    counters: CommunitySharedCountsV1,
    outcomes: u64,
    operations: u64,
    reads: Cell<u32>,
    live_keys: u64,
    selected: Option<CommunityGraphCountsV1>,
    retained: BTreeSet<[u8; 32]>,
    reused: CommunityPassGraphTermsV1,
    scopes: BTreeMap<[u8; 32], Vec<CommunityScopeMemberV1>>,
    scope_reads: Cell<u32>,
    budget: CommunityErasureBudgetV1,
    budget_unavailable: bool,
    pending: BTreeMap<EntityId, CommunityPendingErasureV1>,
}

/// The selected CGR1 counts the fake serves by default.
const SELECTED: CommunityGraphCountsV1 = CommunityGraphCountsV1 {
    registrations: 15,
    edges: 18,
    keys: 2,
    maximum_depth: 3,
    registration_bytes: 1000,
    artifact_bytes: 2000,
};

impl Port {
    fn quarantine(
        &mut self,
        key: &ImplementationKeyV1,
        slot: usize,
        reasons: Vec<CommunityQuarantineReasonV1>,
    ) -> TestResult {
        let key = CommunityQuarantineKeyV1::new(timeline(), ENTRIES[slot], key)?;
        self.quarantine.insert(*key.digest().as_bytes(), reasons);
        Ok(())
    }
}

impl CommunityQuarantineIndexV1 for Port {
    fn quarantine_reasons(&self, key: Hash) -> Option<Vec<CommunityQuarantineReasonV1>> {
        self.reads.set(self.reads.get() + 1);
        self.quarantine.get(key.as_bytes()).cloned()
    }
}

impl CommunityErasureBudgetPortV1 for Port {
    fn erasure_budget(&self, timeline: TimelineId) -> Result<CommunityErasureBudgetV1, Error> {
        assert_eq!(timeline, self::timeline());
        if self.budget_unavailable {
            Err(Error::EvidenceUnavailable)
        } else {
            Ok(self.budget.clone())
        }
    }
}

impl CommunityPassReadPortV1 for Port {
    fn recorded_set_counters(&self, timeline: TimelineId) -> CommunitySharedCountsV1 {
        assert_eq!(timeline, self::timeline());
        self.counters
    }

    fn retained_pass_outcomes(&self, timeline: TimelineId, generation: [u8; 16]) -> u64 {
        assert_eq!((timeline, generation), (self::timeline(), G));
        self.outcomes
    }

    fn control_operations(&self, timeline: TimelineId, generation: [u8; 16]) -> u64 {
        assert_eq!((timeline, generation), (self::timeline(), G));
        self.operations
    }

    fn live_keys(&self) -> u64 {
        self.live_keys
    }

    fn selected_graph(&self, timeline: TimelineId) -> CommunityGraphCountsV1 {
        assert_eq!(timeline, self::timeline());
        self.selected.unwrap_or(SELECTED)
    }

    fn event_source_in_closure(&self, timeline: TimelineId, event_source: Hash) -> bool {
        assert_eq!(timeline, self::timeline());
        self.retained.contains(event_source.as_bytes())
    }

    fn observation_graph(
        &self,
        timeline: TimelineId,
        observation: CommunityNativeNodeReferenceV1,
    ) -> CommunityPassGraphTermsV1 {
        assert_eq!(
            (timeline, observation.node_digest),
            (self::timeline(), hash(90))
        );
        self.reused
    }

    fn scope_rows(
        &self,
        timeline: TimelineId,
        reference: CommunityTypedInputRefV1<'_>,
    ) -> Result<Vec<CommunityScopeMemberV1>, Error> {
        assert_eq!(timeline, self::timeline());
        self.scope_reads.set(self.scope_reads.get() + 1);
        self.scopes
            .get(reference.digest().as_bytes())
            .cloned()
            .ok_or(Error::EvidenceUnavailable)
    }

    fn pending_erasure_demand(&self, actor: EntityId) -> CommunityPendingErasureV1 {
        self.pending.get(&actor).cloned().unwrap_or_default()
    }
}

struct Fixture {
    progress: CommunityHostProgressV1,
    members: Vec<CommunityPassMemberViewV1>,
    generation_not_after: u64,
    recording_not_after: u64,
}

impl Fixture {
    fn new() -> Fallible<Self> {
        Ok(Self {
            progress: CommunityHostProgressV1::new(timeline(), G, Some(5), Some(1000))?,
            // Due at 1000: never stepped, and stepped at 980 with interval 20;
            // not due: stepped at 1000 with interval 10.
            members: vec![member(1, Some(1000)), member(2, Some(980)), member(3, None)],
            generation_not_after: BOUND + 1,
            recording_not_after: BOUND + 1,
        })
    }

    fn roster(key: &ImplementationKeyV1) -> Fallible<Vec<CommunityProfileMemberV1<'_>>> {
        ENTRIES
            .iter()
            .zip(CADENCE)
            .map(|(entry, cadence)| {
                Ok(CommunityProfileMemberV1::new(
                    entry,
                    key,
                    hash(5),
                    hash(6),
                    hash(7),
                    ArtifactRefV1 {
                        schema_id: 1,
                        byte_length: 2,
                        digest: [8; 32],
                    },
                    cadence,
                )?)
            })
            .collect()
    }

    fn profile<'a>(
        &self,
        roster: &'a [CommunityProfileMemberV1<'a>],
    ) -> Fallible<CommunityDurableProfileV1<'a>> {
        self.profile_with_catalogue(roster, hash(10))
    }

    fn profile_with_catalogue<'a>(
        &self,
        roster: &'a [CommunityProfileMemberV1<'a>],
        catalogue: Hash,
    ) -> Fallible<CommunityDurableProfileV1<'a>> {
        Ok(CommunityDurableProfileV1::new(
            CommunityDurableProfileInputV1 {
                backend: CommunityDurableBackendV1::RetainedMemory,
                execution_profile_digest: hash(9),
                roster,
                source_catalogue_digest: catalogue,
                authority_catalogue_digest: hash(11),
                retention: CommunityProfileRetentionV1 {
                    generation_not_after_micros: self.generation_not_after,
                    recovery_window_micros: 1,
                    quarantine_not_after_micros: BOUND + 1,
                    metadata_not_after_micros: BOUND + 1,
                    recording_not_after_micros: self.recording_not_after,
                },
            },
        )?)
    }

    fn view(&self) -> CommunityPassViewV1<'_> {
        CommunityPassViewV1 {
            host_progress: &self.progress,
            members: &self.members,
            operation_active: false,
            unresolved_pass: false,
            selected_root_not_after_micros: BOUND + 1,
        }
    }
}

const fn member(byte: u8, last: Option<u64>) -> CommunityPassMemberViewV1 {
    CommunityPassMemberViewV1 {
        member_binding_digest: hash(byte),
        last_step_simulation_time: last,
    }
}

const fn request(tick: u64, simulation_time: u64) -> CommunityPassRequestV1 {
    CommunityPassRequestV1 {
        tick,
        simulation_time,
        reservation_sample_micros: T_R,
    }
}

const fn installation<'a>(
    profile: &'a CommunityDurableProfileV1<'a>,
) -> CommunityPassInstallationV1<'a> {
    CommunityPassInstallationV1 {
        profile,
        state_limit_bytes: &STATE_LIMITS,
    }
}

/// The step-4 outcome as a code, or `None` for `NoPass`, or the due indices.
fn outcome(result: Result<CommunityPassPlanV1<'_>, Error>) -> Result<Option<Vec<usize>>, Error> {
    result.map(|plan| match plan {
        CommunityPassPlanV1::NoPass => None,
        CommunityPassPlanV1::Due(due) => Some(due.due_members().to_vec()),
    })
}

fn plan_due<'a>(
    port: &Port,
    installation: CommunityPassInstallationV1<'a>,
    view: CommunityPassViewV1<'a>,
) -> Fallible<CommunityPassDueV1<'a>> {
    match plan_community_pass_v1(port, installation, view, request(5, 1000))? {
        CommunityPassPlanV1::Due(due) => Ok(due),
        CommunityPassPlanV1::NoPass => Err("due expected".into()),
    }
}

#[test]
fn the_due_set_follows_each_members_interval_in_roster_order() -> TestResult {
    let key = key()?;
    // R10.1(2): never stepped is due; 980 + 20 is due at 1000; 1000 + 10 is
    // not. Request Tick takes no part.
    let fixture = Fixture::new()?;
    let roster = Fixture::roster(&key)?;
    let profile = fixture.profile(&roster)?;
    let port = Port::default();
    for tick in [5, u64::MAX] {
        assert_eq!(
            outcome(plan_community_pass_v1(
                &port,
                installation(&profile),
                fixture.view(),
                request(tick, 1000)
            ))?,
            Some(vec![1, 2])
        );
    }
    assert_eq!(
        outcome(plan_community_pass_v1(
            &port,
            installation(&profile),
            fixture.view(),
            request(5, 1010)
        ))?,
        Some(vec![0, 1, 2])
    );
    Ok(())
}

#[test]
fn no_due_member_is_no_pass_even_after_new_events() -> TestResult {
    let key = key()?;
    // R10.2 and I87: an empty due set is `NoPass`; nothing else is read.
    let mut fixture = Fixture::new()?;
    fixture.members = vec![
        member(1, Some(1000)),
        member(2, Some(1000)),
        member(3, Some(990)),
    ];
    let roster = Fixture::roster(&key)?;
    let profile = fixture.profile(&roster)?;
    let port = Port::default();
    assert_eq!(
        outcome(plan_community_pass_v1(
            &port,
            installation(&profile),
            fixture.view(),
            request(5, 1000)
        ))?,
        None
    );
    assert_eq!(port.reads.get(), 3);
    Ok(())
}

#[test]
fn the_step_four_checks_return_in_the_r10_7_order() -> TestResult {
    let key = key()?;
    // I98: 15, 7, 6, 9, 13 and `NoPass`, removed one by one.
    let mut fixture = Fixture::new()?;
    fixture.members = vec![
        member(1, Some(1000)),
        member(2, Some(1000)),
        member(3, Some(1000)),
    ];
    let roster = Fixture::roster(&key)?;
    let profile = fixture.profile(&roster)?;
    let mut port = Port::default();
    port.quarantine(&key, 1, vec![CommunityQuarantineReasonV1::Trapped])?;
    let mut view = fixture.view();
    view.selected_root_not_after_micros = BOUND;
    view.operation_active = true;
    view.unresolved_pass = true;
    let stale = request(4, 1000);
    let run = |port: &Port, view, request| {
        outcome(plan_community_pass_v1(
            port,
            installation(&profile),
            view,
            request,
        ))
    };
    assert_eq!(run(&port, view, stale), Err(Error::OperationActive));
    view.operation_active = false;
    assert_eq!(run(&port, view, stale), Err(Error::PassUnresolved));
    view.unresolved_pass = false;
    assert_eq!(run(&port, view, stale), Err(Error::StaleFrontier));
    assert_eq!(run(&port, view, request(5, 1000)), Err(Error::Quarantined));
    port.quarantine.clear();
    assert_eq!(
        run(&port, view, request(5, 1000)),
        Err(Error::EvidenceExpired)
    );
    view.selected_root_not_after_micros = BOUND + 1;
    assert_eq!(run(&port, view, request(5, 1000))?, None);
    Ok(())
}

#[test]
fn a_request_below_a_committed_boundary_is_stale() -> TestResult {
    let key = key()?;
    // R10.5 and I94: below either committed value gives 6; equal values and
    // an initial `[0]` value admit any request.
    let mut fixture = Fixture::new()?;
    let roster = Fixture::roster(&key)?;
    let profile = fixture.profile(&roster)?;
    let port = Port::default();
    let run = |fixture: &Fixture, tick, time| {
        outcome(plan_community_pass_v1(
            &port,
            installation(&profile),
            fixture.view(),
            request(tick, time),
        ))
    };
    assert_eq!(run(&fixture, 4, 1000), Err(Error::StaleFrontier));
    assert_eq!(run(&fixture, 5, 999), Err(Error::StaleFrontier));
    assert_eq!(run(&fixture, 5, 1000)?, Some(vec![1, 2]));
    fixture.progress = CommunityHostProgressV1::new(timeline(), G, None, None)?;
    fixture.members = vec![member(1, None), member(2, None), member(3, None)];
    assert_eq!(run(&fixture, 0, 0)?, Some(vec![0, 1, 2]));
    fixture.progress = CommunityHostProgressV1::new(timeline(), G, Some(0), None)?;
    assert_eq!(run(&fixture, 0, 0)?, Some(vec![0, 1, 2]));
    Ok(())
}

#[test]
fn any_quarantined_roster_member_due_or_not_gives_9() -> TestResult {
    let key = key()?;
    // R10.6 and I96, I97: a not-due member, a due member and a closed entry
    // (a non-empty set) each give 9; an empty set or no row does not.
    let fixture = Fixture::new()?;
    let roster = Fixture::roster(&key)?;
    let profile = fixture.profile(&roster)?;
    for (slot, reasons, expected) in [
        (
            0,
            vec![CommunityQuarantineReasonV1::Unavailable],
            Err(Error::Quarantined),
        ),
        (
            2,
            vec![CommunityQuarantineReasonV1::Revoked],
            Err(Error::Quarantined),
        ),
        (1, Vec::new(), Ok(Some(vec![1, 2]))),
    ] {
        let mut port = Port::default();
        port.quarantine(&key, slot, reasons)?;
        assert_eq!(
            outcome(plan_community_pass_v1(
                &port,
                installation(&profile),
                fixture.view(),
                request(5, 1000)
            )),
            expected
        );
    }
    Ok(())
}

#[test]
fn a_horizon_within_the_decision_deadline_is_expired() -> TestResult {
    let key = key()?;
    // R10.7 step 4f: the generation horizon or the selected root's horizon
    // at or below t_r + 27 s gives 13.
    let mut fixture = Fixture::new()?;
    let port = Port::default();
    for (generation, root, expected) in [
        (BOUND, BOUND + 1, Err(Error::EvidenceExpired)),
        (BOUND + 1, BOUND, Err(Error::EvidenceExpired)),
        (BOUND + 1, BOUND + 1, Ok(Some(vec![1, 2]))),
    ] {
        fixture.generation_not_after = generation;
        let roster = Fixture::roster(&key)?;
        let profile = fixture.profile(&roster)?;
        let mut view = fixture.view();
        view.selected_root_not_after_micros = root;
        assert_eq!(
            outcome(plan_community_pass_v1(
                &port,
                installation(&profile),
                view,
                request(5, 1000)
            )),
            expected
        );
    }
    let roster = Fixture::roster(&key)?;
    let profile = fixture.profile(&roster)?;
    let mut late = request(5, 1000);
    late.reservation_sample_micros = u64::MAX;
    assert_eq!(
        outcome(plan_community_pass_v1(
            &port,
            installation(&profile),
            fixture.view(),
            late
        )),
        Err(Error::EvidenceExpired)
    );
    Ok(())
}

#[test]
fn inputs_that_do_not_cover_the_roster_are_refused_first() -> TestResult {
    let key = key()?;
    let mut fixture = Fixture::new()?;
    let roster = Fixture::roster(&key)?;
    let profile = fixture.profile(&roster)?;
    let port = Port::default();
    let short = CommunityPassInstallationV1 {
        profile: &profile,
        state_limit_bytes: &STATE_LIMITS[..2],
    };
    let mut view = fixture.view();
    view.operation_active = true;
    assert_eq!(
        outcome(plan_community_pass_v1(&port, short, view, request(5, 1000))),
        Err(Error::InvalidBinding)
    );
    fixture.members.pop();
    let mut view = fixture.view();
    view.operation_active = true;
    assert_eq!(
        outcome(plan_community_pass_v1(
            &port,
            installation(&profile),
            view,
            request(5, 1000)
        )),
        Err(Error::EvidenceUnavailable)
    );
    Ok(())
}

#[test]
fn caps_come_before_the_recording_horizon() -> TestResult {
    let key = key()?;
    // R10.4(3)-(4), I92 and I93: 256 retained outcomes give 14; 8192 control
    // operations give 14 only when minting; the recording horizon at
    // t_r + 27 s gives 19, one microsecond later admits.
    let mut fixture = Fixture::new()?;
    let roster = Fixture::roster(&key)?;
    let admitted = fixture.profile(&roster)?;
    fixture.recording_not_after = BOUND;
    let profile = fixture.profile(&roster)?;
    let mut port = Port::default();
    let due = plan_due(&port, installation(&profile), fixture.view())?;
    for (outcomes, operations, minting, expected) in [
        (256, 0, false, Err(Error::CapacityExhausted)),
        (0, 8192, true, Err(Error::CapacityExhausted)),
        (255, 8192, false, Err(Error::RecordingUnavailable)),
        (255, 8191, true, Err(Error::RecordingUnavailable)),
    ] {
        port.outcomes = outcomes;
        port.operations = operations;
        assert_eq!(due.admit(&port, minting), expected);
    }
    let due = plan_due(&port, installation(&admitted), fixture.view())?;
    assert_eq!(due.admit(&port, true), Ok(()));
    Ok(())
}

fn invocation(member: Hash, payload: &[u8]) -> CommunityPreparedInvocationInputV1<'_> {
    let reference = ArtifactRefV1 {
        schema_id: 3,
        byte_length: 4,
        digest: [5; 32],
    };
    CommunityPreparedInvocationInputV1 {
        member_binding_digest: member,
        invocation_id: [6; 16],
        timeline_position: TimelinePositionV1 {
            timeline_id: timeline().inner().to_bytes(),
            seq: 7,
            tick: 5,
            scheduler_position: 0,
        },
        output_base_ordinal: 2,
        principal_ref: reference,
        authorization_ref: reference,
        observation_snapshot_ref: reference,
        observation_bytes: payload,
        prior_state_schema_digest: [6; 32],
        prior_state_bytes: payload,
        execution_profile_digest: [9; 32],
        trust_policy_snapshot_digest: [12; 32],
        deterministic_budget_id: "budget-a",
        deterministic_random_domain: [13; 32],
        provenance_root: [14; 32],
        simulation_time: 1000,
        watchdog_epochs: 0,
    }
}

fn artifact(byte: u8) -> CommunityTypedInputRefV1<'static> {
    CommunityTypedInputRefV1::Artifact {
        owner_reference: hash(20),
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: hash(byte),
        registration_address: hash(22),
        source_scope_binding_digest: hash(23),
    }
}

fn refs() -> Vec<CommunityTypedInputRefV1<'static>> {
    vec![artifact(21)]
}

fn metadata(slot: u16) -> CommunityTypedInputRefV1<'static> {
    CommunityTypedInputRefV1::Metadata {
        schema: CommunityMetadataSchemaV1::Cmb1,
        locator: CommunityMetadataLocatorV1 {
            timeline: timeline(),
            generation: G,
            producer: CommunityLocatorProducerV1::Control([5; 16]),
            record_role: 1,
            slot,
        },
        envelope_address: hash(24),
        private_record_digest: hash(25),
    }
}

fn row(byte: u8) -> CommunityScopeMemberV1 {
    CommunityScopeMemberV1 {
        scope_reference: hash(byte),
        source_timeline: timeline(),
        owner_reference: hash(26),
        retention_lease_reference: hash(27),
        not_after_micros: 9,
    }
}

const REUSED: CommunityNativeNodeReferenceV1 = CommunityNativeNodeReferenceV1 {
    store_incarnation: [7; 16],
    producer_ordinal: 4,
    node_ordinal: 0,
    node_digest: hash(90),
};

/// A port whose one artifact ref has one scope row.
fn scoped_port() -> Port {
    let mut port = Port::default();
    port.scopes
        .insert(*artifact(21).digest().as_bytes(), vec![row(30)]);
    port
}

fn steps<'a>(
    payload: &'a [u8],
    refs: &'a [CommunityTypedInputRefV1<'a>],
    minted: bool,
) -> Vec<CommunityPassStepInputsV1<'a>> {
    [hash(2), hash(3)]
        .into_iter()
        .map(|member| CommunityPassStepInputsV1 {
            prepared_invocation: invocation(member, payload),
            step_inputs: refs,
            consumes_minted_observation: minted,
        })
        .collect()
}

#[test]
fn the_quote_names_the_due_rows_limits_and_guarded_counts() -> TestResult {
    let key = key()?;
    // R10.3, I89 and R11.3(1)-(3): the planner fills each due row's CMB1,
    // CNT1 and S_m from the view and installation, the prior counts, the
    // selected graph, the live keys and the reused observation's closure
    // additions from the port.
    let fixture = Fixture::new()?;
    let roster = Fixture::roster(&key)?;
    let profile = fixture.profile(&roster)?;
    let mut port = scoped_port();
    port.counters = CommunitySharedCountsV1 {
        nodes: 1,
        edges: 2,
        declared_inputs: 3,
        encoded_record_bytes: 4,
    };
    port.live_keys = 11;
    port.reused = CommunityPassGraphTermsV1 {
        registrations: 3,
        edges: 4,
        keys: 1,
        registration_bytes: 5,
        artifact_bytes: 6,
    };
    let due = plan_due(&port, installation(&profile), fixture.view())?;
    let payload = [7; 16];
    let refs = refs();
    let steps = steps(&payload, &refs, false);
    let reused = CommunityPassObservationUseV1::Reused(REUSED);
    let quoted = due.quote(&port, &steps, reused)?;
    let quote = quoted.quote();
    // No actor bounds T's budget in the fake.
    assert_eq!(quoted.trace_rows(), u64::MAX);
    let members: Vec<_> = [(1, hash(2)), (2, hash(3))]
        .into_iter()
        .zip(&steps)
        .map(|((slot, member), step)| CommunityPassQuoteMemberV1 {
            member_binding_digest: member,
            negotiated_tuple_digest: hash(7),
            state_limit_bytes: STATE_LIMITS[slot],
            prepared_invocation: step.prepared_invocation,
            step_inputs: step.step_inputs,
            consumes_minted_observation: false,
        })
        .collect();
    let expected = CommunityPassQuoteV1::new(CommunityPassQuoteInputV1 {
        timeline: timeline(),
        generation: G,
        profile_digest: profile.digest(),
        prior_shared_counts: port.counters,
        members: &members,
        minted_observation: None,
    })?;
    assert!(quote.quote() == expected.quote());
    assert_eq!(quote.state_terms(), expected.state_terms());
    assert_eq!(
        quote.demand(CommunityPassDomainV1 {
            selected_graph: SELECTED,
            live_keys: 11,
            observation_graph: port.reused,
            observation_keys: 0,
            observation_rows: 0,
        }),
        expected.demand(CommunityPassDomainV1 {
            selected_graph: SELECTED,
            live_keys: 11,
            observation_graph: port.reused,
            observation_keys: 0,
            observation_rows: 0,
        })
    );
    // One scope read for the ref both members share.
    assert_eq!(port.scope_reads.get(), 1);
    assert_eq!(
        due.quote(&port, &steps[..1], reused).err(),
        Some(Error::InvalidBinding)
    );
    let minted_without_mint = self::steps(&payload, &refs, true);
    assert_eq!(
        due.quote(&port, &minted_without_mint, reused).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn every_5g_demand_refuses_state_with_14_and_recording_with_19() -> TestResult {
    let key = key()?;
    // R10.4(2), R11.5(1), I91, I107 and I112, in the R11.5(1) order: the
    // CBQ1, the live keys and the ARD1 graph.
    let fixture = Fixture::new()?;
    let roster = Fixture::roster(&key)?;
    let profile = fixture.profile(&roster)?;
    let payload = [7; 16];
    let refs = refs();
    let steps = steps(&payload, &refs, false);
    let reused = CommunityPassObservationUseV1::Reused(REUSED);
    let mut port = scoped_port();
    let due = plan_due(&port, installation(&profile), fixture.view())?;
    let quoted = due.quote(&port, &steps, reused)?;
    let base = quoted.quote();
    let [nodes, ..] = pos_core::community_lifecycle::COMMUNITY_CUMULATIVE_RECORD_LIMITS_V1;
    let spare = nodes - base.total_terms().nodes;
    let run = |port: &Port| due.quote(port, &steps, reused).err();
    port.counters.nodes = spare + 1;
    assert_eq!(run(&port), Some(Error::RecordingUnavailable));
    port.counters.nodes = spare + 3;
    assert_eq!(run(&port), Some(Error::CapacityExhausted));
    port.counters.nodes = 0;
    let demand = base.demand(CommunityPassDomainV1 {
        selected_graph: SELECTED,
        live_keys: 0,
        observation_graph: CommunityPassGraphTermsV1::default(),
        observation_keys: 0,
        observation_rows: 0,
    })?;
    let [state_keys, _] = demand.keys();
    port.live_keys = COMMUNITY_MAXIMUM_STORE_KEYS_V1 - state_keys;
    assert_eq!(run(&port), Some(Error::RecordingUnavailable));
    port.live_keys += 1;
    assert_eq!(run(&port), Some(Error::CapacityExhausted));
    port.live_keys = 0;
    let [state, recording] = demand.graph();
    let free = 4096 - (state.registrations - SELECTED.registrations);
    port.selected = Some(CommunityGraphCountsV1 {
        registrations: free - (recording.registrations - state.registrations) + 1,
        ..SELECTED
    });
    assert_eq!(run(&port), Some(Error::RecordingUnavailable));
    port.selected = Some(CommunityGraphCountsV1 {
        registrations: free + 1,
        ..SELECTED
    });
    assert_eq!(run(&port), Some(Error::CapacityExhausted));
    port.selected = None;
    let mut invalid = steps.clone();
    invalid[0].prepared_invocation.member_binding_digest = Hash::zero();
    assert_eq!(
        due.quote(&port, &invalid, reused).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn the_pass_scope_records_bound_refs_rows_and_member_scopes() -> TestResult {
    let key = key()?;
    // R11.4(1)-(3), R11.1(2), I106 and I115.
    let fixture = Fixture::new()?;
    let roster = Fixture::roster(&key)?;
    let profile = fixture.profile(&roster)?;
    let payload = [7; 16];
    let reused = CommunityPassObservationUseV1::Reused(REUSED);
    let port = scoped_port();
    let due = plan_due(&port, installation(&profile), fixture.view())?;
    // 4,097 distinct mode-3 refs across the two members: 14.
    let first: Vec<_> = (0..4096).map(metadata).collect();
    let second: Vec<_> = (1..4097).map(metadata).collect();
    let mut wide = steps(&payload, &first, false);
    wide[1].step_inputs = &second;
    assert_eq!(
        due.quote(&port, &wide, reused).err(),
        Some(Error::CapacityExhausted)
    );
    wide[1].step_inputs = &first;
    due.quote(&port, &wide, reused)?;
    // Members whose scopes differ: 3.
    let mut split = scoped_port();
    split
        .scopes
        .insert(*artifact(40).digest().as_bytes(), vec![row(31)]);
    let one = [artifact(21)];
    let other = [artifact(40)];
    let mut differing = steps(&payload, &one, false);
    differing[1].step_inputs = &other;
    assert_eq!(
        due.quote(&split, &differing, reused).err(),
        Some(Error::InvalidBinding)
    );
    // A scope read the domain cannot serve: 12.
    let unknown = [artifact(41)];
    assert_eq!(
        due.quote(&split, &steps(&payload, &unknown, false), reused)
            .err(),
        Some(Error::EvidenceUnavailable)
    );
    // 2,048 rows fit; 2,049 give 14.
    for (rows, expected) in [(2048_u16, None), (2049, Some(Error::CapacityExhausted))] {
        let mut broad = Port::default();
        broad.scopes.insert(
            *artifact(21).digest().as_bytes(),
            (0..rows)
                .map(|index| CommunityScopeMemberV1 {
                    not_after_micros: u64::from(index),
                    ..row(30)
                })
                .collect(),
        );
        let refs = refs();
        assert_eq!(
            due.quote(&broad, &steps(&payload, &refs, false), reused)
                .err(),
            expected
        );
    }
    Ok(())
}

#[test]
fn a_minted_observation_shares_its_rows_terms_and_keys() -> TestResult {
    let key = key()?;
    // R11.1(4), R11.3(3) and R11.4(2): a minted observation adds its CBQ1
    // row, its closure records and keys and its scope rows.
    let fixture = Fixture::new()?;
    let roster = Fixture::roster(&key)?;
    let profile = fixture.profile(&roster)?;
    let sources = minted_sources(2)?;
    let mut port = Port::default();
    let due = plan_due(&port, installation(&profile), fixture.view())?;
    let payload = [7; 16];
    let none: [CommunityTypedInputRefV1<'_>; 0] = [];
    let steps = steps(&payload, &none, true);
    let minted = CommunityPassObservationUseV1::Minted(&sources);
    let quoted = due.quote(&port, &steps, minted)?;
    let quote = quoted.quote();
    let sizes = CommunityProtectionSizesV1::new(timeline(), G)?;
    let share = sources.quote_terms(&sizes, |_| false)?;
    let members: Vec<_> = [(1, hash(2)), (2, hash(3))]
        .into_iter()
        .zip(&steps)
        .map(|((slot, member), step)| CommunityPassQuoteMemberV1 {
            member_binding_digest: member,
            negotiated_tuple_digest: hash(7),
            state_limit_bytes: STATE_LIMITS[slot],
            prepared_invocation: step.prepared_invocation,
            step_inputs: step.step_inputs,
            consumes_minted_observation: true,
        })
        .collect();
    let expected = CommunityPassQuoteV1::new(CommunityPassQuoteInputV1 {
        timeline: timeline(),
        generation: G,
        profile_digest: profile.digest(),
        prior_shared_counts: port.counters,
        members: &members,
        minted_observation: Some(share.observation),
    })?;
    assert!(quote.quote() == expected.quote());
    // The minted observation's keys push the live count over the limit.
    let demand = expected.demand(CommunityPassDomainV1 {
        selected_graph: SELECTED,
        live_keys: 0,
        observation_graph: share.graph,
        observation_keys: share.keys,
        observation_rows: share.erasure_rows,
    })?;
    port.live_keys = COMMUNITY_MAXIMUM_STORE_KEYS_V1 - demand.keys()[0];
    assert_eq!(
        due.quote(&port, &steps, minted).err(),
        Some(Error::RecordingUnavailable)
    );
    port.live_keys = 0;
    // The minted ref counts once among the 4,096 distinct refs.
    let many: Vec<_> = (0..4096).map(metadata).collect();
    let crowded = self::steps(&payload, &many, true);
    assert_eq!(
        due.quote(&port, &crowded, minted).err(),
        Some(Error::CapacityExhausted)
    );
    // A retained CES1 is not a new registration.
    let retained = sources.quote_terms(&sizes, |_| true)?.graph.registrations;
    assert!(retained < share.graph.registrations);
    Ok(())
}

/// The stage-1 sources of a root Timeline with `events` Events, prepared
/// over a real Memory domain.
fn minted_sources(events: usize) -> Fallible<CommunityObservationSourcesV1> {
    static SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();
    let rules = [CommunitySourceSchemaRuleV1 {
        event_type: "world.action",
        schema_version: 1,
        extractor_rule: "pos.community.native-event",
        extractor_rule_version: 1,
    }];
    let catalogue = CommunitySourceCatalogueV1::new(&rules)?;
    let key = key()?;
    let roster = Fixture::roster(&key)?;
    let mut fixture = Fixture::new()?;
    fixture.generation_not_after = 5000;
    let profile = fixture.profile_with_catalogue(&roster, catalogue.digest())?;
    let mut store = MemoryStore::new();
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let root = store.create_timeline("root")?.id();
    let drafts: Vec<EventDraft> = (0..events)
        .map(|index| {
            EventDraft::new(
                EntityId::new(),
                Kind::new("world.action"),
                CanonicalBytes::from_vec(vec![u8::try_from(index).unwrap_or(0)]),
            )
        })
        .collect();
    store.append(root, &drafts)?;
    let stored = store.read(
        root,
        SeqRange {
            from: Seq::from_u64(1),
            to: Some(store.logical_head(root)?),
        },
    )?;
    let domain =
        MemoryCommunityDomainV1::new(store, [0x5a; 16], MemoryTrustedClockAuthorityV1::new())?;
    Ok(prepare_community_observation_v1(
        &domain,
        CommunityObservationInstallationV1 {
            profile: &profile,
            source_catalogue: catalogue,
            observation_schema_id: ENCODER,
        },
        CommunityObservationPassV1 {
            generation: G,
            reservation_operation_id: [0x30; 16],
        },
        &CommunityObservationMaterializationV1::new(&SEAL, observation_input(root, &stored)),
    )?)
}

/// The observation installed encoder's schema ID in the minted fixture.
const ENCODER: u32 = 0x4f42_0001;

/// The publisher's honest input for `root`'s full prefix `stored`.
fn observation_input(
    root: TimelineId,
    stored: &[Event],
) -> CommunityObservationMaterializationInputV1 {
    CommunityObservationMaterializationInputV1 {
        timeline: root,
        through_seq: stored.len() as u64,
        events: stored
            .iter()
            .map(|event| CommunityObservationEventV1 {
                owning_timeline: root,
                logical_seq: event.seq.as_u64(),
                event_id: event.id.inner().to_bytes(),
                payload_hash: event.payload_hash,
            })
            .collect(),
        consumers: vec![CommunityObservationConsumerV1 {
            binding: CommunityReducerBindingV1 {
                consumer_identity_digest: hash(0x50),
                schema_digest: hash(0x61),
                reducer_digest: hash(0x62),
                configuration_digest: hash(0x63),
                admission_evidence_digest: hash(0x64),
                minimization_policy_digest: hash(0x65),
            },
            callback_bound: Duration::from_millis(1),
        }],
        timeline_scopes: vec![(root, hash(0x70))],
        observation_artifact_ref: ArtifactRefV1 {
            schema_id: ENCODER,
            byte_length: 11,
            digest: [0x77; 32],
        },
        observation_bytes: Zeroizing::new(b"observation".to_vec()),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn the_memory_domain_serves_step_4e_from_its_quarantine_index() -> TestResult {
    // R10.6(2): the Memory domain's A4e-1 index row of a roster member's
    // CQK1 gives 9; no row gives none.
    use super::super::quarantine::QuarantineLedgerV1;
    use crate::community_initialization_fixture::{trusted_store, World, TRUST_SCOPE};
    use pos_core::community_lifecycle::CommunityQuarantineReasonEvidenceV1;
    use pos_core::AuthorityTrustRootSealV1;

    static SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();
    let key = key()?;
    let fixture = Fixture::new()?;
    let roster = Fixture::roster(&key)?;
    let profile = fixture.profile(&roster)?;
    let (store, _harness) = trusted_store(true)?;
    let mut world = World::new(
        &SEAL,
        store,
        TRUST_SCOPE,
        MemoryTrustedClockAuthorityV1::new(),
    )?;
    let run = |world: &World| {
        outcome(plan_community_pass_v1(
            &world.domain,
            installation(&profile),
            fixture.view(),
            request(5, 1000),
        ))
    };
    assert_eq!(run(&world)?, Some(vec![1, 2]));
    let quarantined = CommunityQuarantineKeyV1::new(timeline(), ENTRIES[0], &key)?.digest();
    world.domain.quarantine_index.insert(
        quarantined,
        QuarantineLedgerV1 {
            head: hash(40),
            ordinal: 1,
            reasons: vec![CommunityQuarantineReasonEvidenceV1 {
                reason: CommunityQuarantineReasonV1::Trapped,
                failure_evidence_digest: hash(41),
            }],
            evidence_not_after_micros: BOUND,
        },
    );
    assert_eq!(run(&world), Err(Error::Quarantined));
    Ok(())
}

mod erasure;
