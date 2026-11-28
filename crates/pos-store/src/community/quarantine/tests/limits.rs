//! `SetReason` at the erasure limits (ADR-129 revision 13, R13.1(5), R13.7
//! I136 and its revision 14 RN.5 rows case): a pre-execution `SetReason`
//! spends its pair's `F_q` share on its own CFO1 row, so it is never refused
//! for the budget, and the actor and the Timeline stay at, not above, their
//! limits. The reset's 14 is in `reset/tests.rs` (#1589); the passes that run
//! to 14 before the rows case's `SetReason`s are `pass_writer/tests/bounds.rs`
//! (#1584).
//! `SetReason` takes only the reason `Revoked` before execution, so the
//! pairs here are one `Revoked` per roster member.

use super::*;
use crate::community::erasure_budget::{
    CommunityErasureBudgetPortV1, CommunityPendingReservationV1,
};
use crate::community::pass_planner::CommunityPassReadPortV1;
use crate::erasure_budget_rows::{community_rows, erasure_row};
use pos_core::community_lifecycle::COMMUNITY_ERASURE_TARGET_LINE_V1;
use pos_core::ArtifactDataClassV1;

/// The rows bound of a Timeline (R13.1(1)).
const ROW_BOUND: u64 = 4_096;

/// The rows the rows case's pending reservation holds.
const PENDING_ROWS: u64 = 3;

/// The parts of what T's actor and T hold, from the domain's own budget:
/// the actor's committed targets and its quarantine reserve, T's committed
/// rows and its quarantine rows, and what the pending reservations hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Parts {
    targets: u64,
    reserve: u64,
    rows: u64,
    quarantine_rows: u64,
    pending_targets: u64,
    pending_rows: u64,
}

fn parts(case: &QuarantineCase) -> Fallible<Parts> {
    let domain = domain(case);
    let budget = domain.erasure_budget(target())?;
    let owner = budget.actors.first().ok_or("an actor")?;
    let pending = domain.pending_erasure_demand(owner.actor);
    let rows = |map: &std::collections::BTreeMap<_, u64>| map.get(&target()).copied().unwrap_or(0);
    Ok(Parts {
        targets: owner.targets,
        reserve: owner.quarantine_reserve,
        rows: rows(&budget.rows),
        quarantine_rows: rows(&budget.quarantine_rows),
        pending_targets: pending.targets,
        pending_rows: rows(&pending.rows),
    })
}

/// What T's actor holds: its targets with the quarantine reserve and the
/// pending reservations, and T's rows with its quarantine rows and pending
/// rows.
fn held(case: &QuarantineCase) -> Fallible<(u64, u64)> {
    let parts = parts(case)?;
    Ok((
        parts.targets + parts.reserve + parts.pending_targets,
        parts.rows + parts.quarantine_rows + parts.pending_rows,
    ))
}

/// The `Revoked` claim of the roster's `member`th entry.
fn revoked(member: u8) -> Claim<'static> {
    Claim {
        entry: ENTRIES[usize::from(member)],
        control: [0x40 + member; 16],
        ..claim(Basis::Artifact)
    }
}

/// The roster's members.
const MEMBERS: u8 = 2;

/// One committed `Revoked` `SetReason` of the roster's `member`th entry.
fn mint(case: &mut QuarantineCase, member: u8) -> TestResult {
    set_reason(case, revoked(member))??;
    Ok(())
}

/// What one member's committed `SetReason` changes (R13.1(5)): its CFO1 binds
/// one row and two targets, and its pair's `F_q` share gives the same back.
fn assert_member_deltas(was: &Parts, now: &Parts, member: u8) {
    assert_eq!(
        now.targets,
        was.targets + 2,
        "member {member}: CFO1 targets"
    );
    assert_eq!(now.reserve, was.reserve - 2, "member {member}: F_q targets");
    assert_eq!(now.rows, was.rows + 1, "member {member}: CFO1 row");
    assert_eq!(
        now.quarantine_rows,
        was.quarantine_rows - 1,
        "member {member}: F_q row"
    );
}

/// One member's `SetReason` commits with those deltas and leaves `held` at
/// `before`.
fn member_commits(case: &mut QuarantineCase, member: u8, before: (u64, u64)) -> TestResult {
    let was = parts(case)?;
    mint(case, member)?;
    let now = parts(case)?;
    assert_member_deltas(&was, &now, member);
    let after = held(case)?;
    assert_eq!(after, before);
    Ok(())
}

/// A `SetReason` for every roster member, each committing and leaving
/// `held` as it was.
fn every_member_commits(case: &mut QuarantineCase) -> TestResult {
    assert_eq!(ENTRIES.len(), usize::from(MEMBERS));
    let before = held(case)?;
    for member in 0..MEMBERS {
        member_commits(case, member, before)?;
    }
    Ok(())
}

/// What T's actor holds in targets.
fn held_targets(case: &QuarantineCase) -> Fallible<u64> {
    Ok(held(case)?.0)
}

/// What T holds in rows.
fn held_rows(case: &QuarantineCase) -> Fallible<u64> {
    Ok(held(case)?.1)
}

/// `read` of the case is exactly `expected`.
fn assert_held_at(
    case: &QuarantineCase,
    read: fn(&QuarantineCase) -> Fallible<u64>,
    expected: u64,
) -> TestResult {
    let now = read(case)?;
    assert_eq!(now, expected);
    Ok(())
}

/// T's actor exactly at the community line: committed targets, `F_q` and a
/// pending reservation fill it.
fn fill_targets_line(case: &mut QuarantineCase) -> TestResult {
    let (targets, _) = held(case)?;
    let free = COMMUNITY_ERASURE_TARGET_LINE_V1 - targets;
    let domain = &mut case.domain.world.domain;
    domain
        .store
        .bind_erasure_rows_for_test(target(), community_rows(1_000, free / 2)?);
    domain.pending_reservations.insert(
        (target(), [9; 16]),
        CommunityPendingReservationV1 {
            targets: free % 2,
            rows: 0,
        },
    );
    assert_held_at(case, held_targets, COMMUNITY_ERASURE_TARGET_LINE_V1)
}

/// I136, targets: with T's actor exactly at the community line, a
/// `SetReason` of each member mints its CFO1 (two targets) from its own
/// `F_q` share (two targets), is never refused, and leaves the actor at the
/// line.
#[test]
fn a_set_reason_at_the_targets_line_is_never_refused() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
    fill_targets_line(&mut case)?;
    every_member_commits(&mut case)?;
    assert_held_at(&case, held_targets, COMMUNITY_ERASURE_TARGET_LINE_V1)
}

/// T's rows exactly at the bound: rows of a class that costs no targets fill
/// T's view list; three of the rows are a pending reservation's, so the held
/// sum counts the pending side too.
fn fill_rows_bound(case: &mut QuarantineCase) -> TestResult {
    let (_, rows) = held(case)?;
    let consented = (0..ROW_BOUND - rows - PENDING_ROWS)
        .map(|seed| erasure_row("budget", ArtifactDataClassV1::ConsentedSharedData, 0, seed))
        .collect::<Fallible<Vec<_>>>()?;
    let domain = &mut case.domain.world.domain;
    domain.store.bind_erasure_rows_for_test(target(), consented);
    domain.pending_reservations.insert(
        (target(), [9; 16]),
        CommunityPendingReservationV1 {
            targets: 0,
            rows: PENDING_ROWS,
        },
    );
    assert_held_at(case, held_rows, ROW_BOUND)
}

/// RN.5 rows case: with T's rows and its `F_q` rows exactly at 4,096, a
/// `SetReason` of each member still mints its CFO1, and `rows(T)` stays at
/// 4,096.
#[test]
fn a_set_reason_at_the_rows_bound_is_never_refused() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
    fill_rows_bound(&mut case)?;
    every_member_commits(&mut case)?;
    assert_held_at(&case, held_rows, ROW_BOUND)
}
