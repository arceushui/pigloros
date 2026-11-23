//! The pass planner through its public entry points, over a fake read port
//! that serves the domain-private quarantine index, recorded-set counters
//! and retained-outcome and control-operation counts (A4c adds the Memory
//! domain's storage). Each case names its ADR-129 revision 10 obligation.

use std::cell::Cell;
use std::collections::BTreeMap;

use pos_core::community_lifecycle::{
    ArtifactRefV1, CommunityDurableBackendV1, CommunityDurableProfileInputV1,
    CommunityDurableProfileV1, CommunityHostProgressV1, CommunityLifecycleErrorV1 as Error,
    CommunityPassObservationV1, CommunityPassQuoteInputV1, CommunityPassQuoteMemberV1,
    CommunityPassQuoteV1, CommunityPassTermsV1, CommunityPreparedInvocationInputV1,
    CommunityProfileMemberV1, CommunityProfileRetentionV1, CommunityQuarantineKeyV1,
    CommunityQuarantineReasonV1, CommunitySharedCountsV1, CommunityTypedInputRefV1,
    TimelinePositionV1, COMMUNITY_SHARED_RECORD_LIMITS_V1,
};
use pos_core::{ErasureArtifactClassV1, Hash, ImplementationKeyV1, TimelineId};
use ulid::Ulid;

use super::{
    plan_community_pass_v1, CommunityPassDueV1, CommunityPassInstallationV1,
    CommunityPassMemberViewV1, CommunityPassPlanV1, CommunityPassReadPortV1,
    CommunityPassRequestV1, CommunityPassStepInputsV1, CommunityPassViewV1,
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
}

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

impl CommunityPassReadPortV1 for Port {
    fn quarantine_reasons(
        &self,
        key: &CommunityQuarantineKeyV1<'_>,
    ) -> Option<Vec<CommunityQuarantineReasonV1>> {
        self.reads.set(self.reads.get() + 1);
        self.quarantine.get(key.digest().as_bytes()).cloned()
    }

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
        Ok(CommunityDurableProfileV1::new(
            CommunityDurableProfileInputV1 {
                backend: CommunityDurableBackendV1::RetainedMemory,
                execution_profile_digest: hash(9),
                roster,
                source_catalogue_digest: hash(10),
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

fn refs() -> Vec<CommunityTypedInputRefV1<'static>> {
    vec![CommunityTypedInputRefV1::Artifact {
        owner_reference: hash(20),
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: hash(21),
        registration_address: hash(22),
        source_scope_binding_digest: hash(23),
    }]
}

const OBSERVATION: CommunityPassObservationV1 = CommunityPassObservationV1 {
    terms: CommunityPassTermsV1 {
        nodes: 1,
        edges: 1,
        bytes: 500,
    },
    node_ordinal: 0,
};

#[test]
fn the_quote_names_the_due_rows_limits_and_guarded_counters() -> TestResult {
    let key = key()?;
    // R10.3 and I89: the planner fills each due row's CMB1, CNT1 and S_m from
    // the view and installation, and the prior counts from the port.
    let fixture = Fixture::new()?;
    let roster = Fixture::roster(&key)?;
    let profile = fixture.profile(&roster)?;
    let port = Port {
        counters: CommunitySharedCountsV1 {
            nodes: 1,
            edges: 2,
            declared_inputs: 3,
            encoded_record_bytes: 4,
        },
        ..Port::default()
    };
    let due = plan_due(&port, installation(&profile), fixture.view())?;
    let payload = [7; 16];
    let refs = refs();
    let steps: Vec<_> = [hash(2), hash(3)]
        .into_iter()
        .map(|member| CommunityPassStepInputsV1 {
            prepared_invocation: invocation(member, &payload),
            step_inputs: &refs,
            consumes_minted_observation: true,
        })
        .collect();
    let quote = due.quote(&port, &steps, Some(OBSERVATION))?;
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
        minted_observation: Some(OBSERVATION),
    })?;
    assert!(quote.quote() == expected.quote());
    assert_eq!(quote.state_terms(), expected.state_terms());
    assert_eq!(
        due.quote(&port, &steps[..1], None).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn the_quote_refuses_state_demand_with_14_and_recording_demand_with_19() -> TestResult {
    let key = key()?;
    // R10.4(2) and I91.
    let fixture = Fixture::new()?;
    let roster = Fixture::roster(&key)?;
    let profile = fixture.profile(&roster)?;
    let payload = [7; 16];
    let refs = refs();
    let steps: Vec<_> = [hash(2), hash(3)]
        .into_iter()
        .map(|member| CommunityPassStepInputsV1 {
            prepared_invocation: invocation(member, &payload),
            step_inputs: &refs,
            consumes_minted_observation: false,
        })
        .collect();
    let mut port = Port::default();
    let due = plan_due(&port, installation(&profile), fixture.view())?;
    let base = due.quote(&port, &steps, None)?;
    let [nodes, ..] = pos_core::community_lifecycle::COMMUNITY_CUMULATIVE_RECORD_LIMITS_V1;
    let spare = nodes - base.total_terms().nodes;
    port.counters.nodes = spare + 1;
    assert_eq!(
        due.quote(&port, &steps, None).err(),
        Some(Error::RecordingUnavailable)
    );
    port.counters.nodes = spare + 3;
    assert_eq!(
        due.quote(&port, &steps, None).err(),
        Some(Error::CapacityExhausted)
    );
    let huge = CommunityPassObservationV1 {
        terms: CommunityPassTermsV1 {
            bytes: COMMUNITY_SHARED_RECORD_LIMITS_V1[2],
            ..OBSERVATION.terms
        },
        ..OBSERVATION
    };
    port.counters.nodes = 0;
    assert_eq!(
        due.quote(&port, &steps, Some(huge)).err(),
        Some(Error::CapacityExhausted)
    );
    let mut invalid = steps.clone();
    invalid[0].prepared_invocation.member_binding_digest = Hash::zero();
    assert_eq!(
        due.quote(&port, &invalid, None).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}
