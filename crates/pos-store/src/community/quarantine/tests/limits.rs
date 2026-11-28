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

/// A `SetReason` for every roster member, each committing and leaving
/// `held` as it was: its CFO1 binds one row and two targets, and its pair's
/// `F_q` share gives exactly the same back (R13.1(5)).
fn every_member_commits(case: &mut QuarantineCase) -> TestResult {
    let before = held(case)?;
    for member in 0..u8::try_from(ENTRIES.len())? {
        let was = parts(case)?;
        set_reason(case, revoked(member))??;
        let now = parts(case)?;
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
        assert_eq!(held(case)?, before);
    }
    Ok(())
}

/// I136, targets: with T's actor exactly at the community line (committed
/// targets, `F_q` and a pending reservation fill it), a `SetReason` of each
/// member mints its CFO1 (two targets) from its own `F_q` share (two
/// targets), is never refused, and leaves the actor at the line.
#[test]
fn a_set_reason_at_the_targets_line_is_never_refused() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
    let (targets, _) = held(&case)?;
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
    assert_eq!(held(&case)?.0, COMMUNITY_ERASURE_TARGET_LINE_V1);
    every_member_commits(&mut case)?;
    assert_eq!(held(&case)?.0, COMMUNITY_ERASURE_TARGET_LINE_V1);
    Ok(())
}

/// RN.5 rows case: rows of a class that costs no targets fill T's view
/// list, so T's rows with its `F_q` rows are exactly at 4,096; a `SetReason`
/// of each member still mints its CFO1, and `rows(T)` stays at 4,096.
#[test]
fn a_set_reason_at_the_rows_bound_is_never_refused() -> TestResult {
    let mut case = QuarantineCase::new(&SEAL, Revocation::Artifact)?;
    let (_, rows) = held(&case)?;
    // Three of the rows are a pending reservation's, so the held sum counts
    // the pending side too.
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
    assert_eq!(held(&case)?.1, ROW_BOUND);
    every_member_commits(&mut case)?;
    assert_eq!(held(&case)?.1, ROW_BOUND);
    Ok(())
}
