//! `SetReason` at the erasure limits (ADR-129 revision 13, R13.1(5), R13.7
//! I136 and its revision 14 RN.5 rows case): a pre-execution `SetReason`
//! spends its pair's `F_q` share on its own CFO1 row, so it is never refused
//! for the budget, and the actor and the Timeline stay at, not above, their
//! limits. The reset's 14 is in `reset/tests.rs`; the passes that run to 14
//! before the rows case's `SetReason`s are `pass_writer/tests/bounds.rs`.
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

/// What T's actor holds: its targets with the quarantine reserve and the
/// pending reservations, and T's rows with its quarantine rows and pending
/// rows, from the domain's own budget.
fn held(case: &QuarantineCase) -> Fallible<(u64, u64)> {
    let domain = domain(case);
    let budget = domain.erasure_budget(target())?;
    let owner = budget.actors.first().ok_or("an actor")?;
    let pending = domain.pending_erasure_demand(owner.actor);
    let rows = |map: &std::collections::BTreeMap<_, u64>| map.get(&target()).copied().unwrap_or(0);
    Ok((
        owner.targets + owner.quarantine_reserve + pending.targets,
        rows(&budget.rows) + rows(&budget.quarantine_rows) + rows(&pending.rows),
    ))
}

/// The `Revoked` claim of the roster's `member`th entry.
fn revoked(member: usize) -> Claim<'static> {
    Claim {
        entry: ENTRIES[member],
        control: [0x40 + u8::try_from(member).unwrap_or(0); 16],
        ..claim(Basis::Artifact)
    }
}

/// A `SetReason` for every roster member, each committing and leaving
/// `held` as it was.
fn every_member_commits(case: &mut QuarantineCase) -> TestResult {
    let before = held(case)?;
    for member in 0..ENTRIES.len() {
        set_reason(case, revoked(member))??;
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
    let consented = (0..ROW_BOUND - rows)
        .map(|seed| erasure_row("budget", ArtifactDataClassV1::ConsentedSharedData, 0, seed))
        .collect::<Fallible<Vec<_>>>()?;
    case.domain
        .world
        .domain
        .store
        .bind_erasure_rows_for_test(target(), consented);
    assert_eq!(held(&case)?.1, ROW_BOUND);
    every_member_commits(&mut case)?;
    assert_eq!(held(&case)?.1, ROW_BOUND);
    Ok(())
}
