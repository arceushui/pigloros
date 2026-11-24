//! Step 5g's erasure-target budget (ADR-129 revision 13, R13.1(3)-(5),
//! R13.4(1)): over a fake budget for the split, the pending addition and
//! the order, and over the Memory domain's counters for the capacity
//! table, the Event history and the second bound (I130, I132, I133, I142
//! and I144; the Reserve and Commit paths of I133-I135 are A4c's).

use super::*;
use crate::community::pass_planner::CommunityPassQuotedV1;
use pos_core::community_lifecycle::{
    COMMUNITY_ERASURE_ROW_LIMIT_V1, COMMUNITY_ERASURE_TARGET_LINE_V1,
};

use super::super::super::erasure_budget::CommunityErasureActorV1;

const LINE: u64 = COMMUNITY_ERASURE_TARGET_LINE_V1;
const ROWS: u64 = COMMUNITY_ERASURE_ROW_LIMIT_V1;
const ACTOR: EntityId = EntityId::from_ulid(Ulid::from_bytes([0xa1; 16]));
const OTHER: EntityId = EntityId::from_ulid(Ulid::from_bytes([0xb1; 16]));
/// `F_q` of a three-member context.
const RESERVE: u64 = 24;

fn other_timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([9; 16]))
}

/// The step-5g outcome of the fixture's two-member pass over `port`, which
/// reuses its observation.
fn run(port: &Port) -> Fallible<Result<CommunityPassQuotedV1, Error>> {
    let key = key()?;
    let fixture = Fixture::new()?;
    let roster = Fixture::roster(&key)?;
    let profile = fixture.profile(&roster)?;
    let due = plan_due(port, installation(&profile), fixture.view())?;
    let payload = [7; 16];
    let refs = refs();
    let steps = steps(&payload, &refs, false);
    Ok(due.quote(port, &steps, CommunityPassObservationUseV1::Reused(REUSED)))
}

/// A port whose budget holds `actors` and `rows`.
fn budgeted(actors: &[(EntityId, u64)], rows: &[(TimelineId, u64)]) -> Port {
    let mut port = scoped_port();
    port.budget = CommunityErasureBudgetV1 {
        actors: actors
            .iter()
            .map(|(actor, targets)| CommunityErasureActorV1 {
                actor: *actor,
                targets: *targets,
                quarantine_reserve: RESERVE,
            })
            .collect(),
        rows: rows.iter().copied().collect(),
    };
    port
}

/// The trace rows of `port`'s pass, or its refusal.
fn trace(port: &Port) -> Fallible<Result<u64, Error>> {
    Ok(run(port)?.map(|quoted| quoted.trace_rows()))
}

#[test]
fn the_pass_demand_is_its_state_rows_its_recording_rows_and_f_p() -> TestResult {
    // R13.1(3) and (5): two due members, a reused observation: 2 x 7 + CED1
    // and CEB1 State rows, 2 x 2 + 1 recording rows and F_p = 2(2 + 1).
    let quoted = run(&scoped_port())??;
    assert_eq!(quoted.demand().erasure_rows(), [16, 21]);
    assert_eq!(quoted.demand().failure_reserve(), 6);
    Ok(())
}

#[test]
fn targets_short_of_state_and_f_p_give_14_and_of_the_recording_19() -> TestResult {
    // I133 at 5g: one target short of State + F_p gives 14; State fitting
    // and the recording not gives 19; the full demand at the line admits no
    // trace row, two targets more admit one.
    let state = LINE - RESERVE - 6 - 2 * 16;
    let full = LINE - RESERVE - 6 - 2 * 21;
    let rows = [(timeline(), 0)];
    for (targets, expected) in [
        (state + 1, Err(Error::CapacityExhausted)),
        (state, Err(Error::RecordingUnavailable)),
        (full + 1, Err(Error::RecordingUnavailable)),
        (full, Ok(0)),
        (full - 1, Ok(0)),
        (full - 2, Ok(1)),
    ] {
        assert_eq!(trace(&budgeted(&[(ACTOR, targets)], &rows))?, expected);
    }
    Ok(())
}

#[test]
fn pending_reservations_count_as_committed_targets_and_rows() -> TestResult {
    // R13.1(4): the planner adds the ledger's pending demand of each actor
    // (A4c serves it) to the committed counts.
    let full = LINE - RESERVE - 6 - 2 * 21;
    let mut port = budgeted(&[(ACTOR, full - 10)], &[(timeline(), 0)]);
    port.pending.insert(
        ACTOR,
        CommunityPendingErasureV1 {
            targets: 10,
            rows: BTreeMap::new(),
        },
    );
    assert_eq!(trace(&port)?, Ok(0));
    port.pending.entry(ACTOR).or_default().targets = 11;
    assert_eq!(trace(&port)?, Err(Error::RecordingUnavailable));
    // Another actor's pending demand is not this scope's.
    port.pending.remove(&ACTOR);
    port.pending.insert(
        OTHER,
        CommunityPendingErasureV1 {
            targets: LINE,
            rows: BTreeMap::new(),
        },
    );
    assert_eq!(trace(&port)?, Ok(5));
    // Pending rows on T count against rows(T) with the new rows.
    let limit = ROWS - 21 - 3;
    let mut port = budgeted(&[(ACTOR, 0)], &[(timeline(), limit - 4)]);
    port.pending.insert(
        ACTOR,
        CommunityPendingErasureV1 {
            targets: 0,
            rows: std::iter::once((timeline(), 4)).collect(),
        },
    );
    assert_eq!(trace(&port)?, Ok(0));
    port.pending
        .entry(ACTOR)
        .or_default()
        .rows
        .insert(timeline(), 5);
    assert_eq!(trace(&port)?, Err(Error::RecordingUnavailable));
    Ok(())
}

#[test]
fn every_rows_u_stays_within_4096_with_the_new_rows_on_t_alone() -> TestResult {
    // R13.1(1), (3) and I130's second bound: T's rows with the pass's rows
    // and the F_p rows, then with the recording; another affected Timeline
    // gains no new row but its pending rows count.
    let actors = [(ACTOR, 0)];
    let state = ROWS - 16 - 3;
    let full = ROWS - 21 - 3;
    for (rows, expected) in [
        (state + 1, Err(Error::CapacityExhausted)),
        (state, Err(Error::RecordingUnavailable)),
        (full + 1, Err(Error::RecordingUnavailable)),
        (full, Ok(0)),
        (full - 3, Ok(3)),
    ] {
        let port = budgeted(&actors, &[(timeline(), rows), (other_timeline(), ROWS)]);
        assert_eq!(trace(&port)?, expected);
    }
    let mut port = budgeted(&actors, &[(timeline(), 0), (other_timeline(), ROWS)]);
    port.pending.insert(
        ACTOR,
        CommunityPendingErasureV1 {
            targets: 0,
            rows: std::iter::once((other_timeline(), 1)).collect(),
        },
    );
    assert_eq!(trace(&port)?, Err(Error::CapacityExhausted));
    // The trace headroom is the least of the target and row rooms.
    let room = LINE - RESERVE - 6 - 2 * 21 - 2 * 7;
    let port = budgeted(&[(ACTOR, room)], &[(timeline(), full - 9)]);
    assert_eq!(trace(&port)?, Ok(7));
    Ok(())
}

#[test]
fn every_actor_in_the_scope_must_fit() -> TestResult {
    // R13.1(3): the check holds for every A in T's scope; the trace
    // headroom is the least of theirs.
    let state = LINE - RESERVE - 6 - 2 * 16;
    let full = LINE - RESERVE - 6 - 2 * 21;
    let rows = [(timeline(), 0)];
    for (other, expected) in [
        (state + 1, Err(Error::CapacityExhausted)),
        (full + 1, Err(Error::RecordingUnavailable)),
        (full - 4, Ok(2)),
    ] {
        let port = budgeted(&[(ACTOR, full - 20), (OTHER, other)], &rows);
        assert_eq!(trace(&port)?, expected);
    }
    Ok(())
}

#[test]
fn the_budget_runs_after_the_graph_and_before_the_scope_bounds() -> TestResult {
    // R13.4(1): a graph refusal (19) wins over the budget's 14, and the
    // budget's 14 over a member-scope mismatch (3); an unreadable budget
    // gives 12.
    let over = [(ACTOR, LINE)];
    let rows = [(timeline(), 0)];
    let mut port = budgeted(&over, &rows);
    let base = run(&scoped_port())??;
    let [state, recording] = base.demand().graph();
    let free = 4096 - (state.registrations - SELECTED.registrations);
    port.selected = Some(CommunityGraphCountsV1 {
        registrations: free - (recording.registrations - state.registrations) + 1,
        ..SELECTED
    });
    assert_eq!(trace(&port)?, Err(Error::RecordingUnavailable));
    let key = key()?;
    let fixture = Fixture::new()?;
    let roster = Fixture::roster(&key)?;
    let profile = fixture.profile(&roster)?;
    let mut split = budgeted(&over, &rows);
    split
        .scopes
        .insert(*artifact(40).digest().as_bytes(), vec![row(31)]);
    let due = plan_due(&split, installation(&profile), fixture.view())?;
    let payload = [7; 16];
    let one = [artifact(21)];
    let other = [artifact(40)];
    let mut differing = steps(&payload, &one, false);
    differing[1].step_inputs = &other;
    let reused = CommunityPassObservationUseV1::Reused(REUSED);
    assert_eq!(
        due.quote(&split, &differing, reused).err(),
        Some(Error::CapacityExhausted)
    );
    split.budget.actors.clear();
    assert_eq!(
        due.quote(&split, &differing, reused).err(),
        Some(Error::InvalidBinding)
    );
    split.budget_unavailable = true;
    assert_eq!(
        due.quote(&split, &differing, reused).err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

#[cfg(target_os = "linux")]
mod capacity;
