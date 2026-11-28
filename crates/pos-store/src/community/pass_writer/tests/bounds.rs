//! The erasure bounds across concurrent reservations (ADR-129 revision 13,
//! R13.7 I134 and I146): two Timelines of one scope, a Fork parent and its
//! child, whose Reserves, Aborts and Commits interleave. The writer-level
//! operations bind no rows (the pipeline does), so the invariant is the
//! budget line itself: committed targets, pending reservations and the
//! quarantine reserve stay within the community line, and every `rows(U)`
//! within the view-list bound.

use super::*;

/// The pass rows a Reserve plans: small ones, and ones that fit alone
/// but not beside each other.
const ROWS: [u64; 4] = [24, 1_900, 1_900, 1_000];

/// The next pseudo-random value of a xorshift sequence.
const fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// The pass state of the Fork child: T's, with the observation to reuse.
fn child_state() -> CommunityPassStateV1 {
    let mut state = pass_state();
    state.retained.insert(
        reference(),
        CommunityRetainedObservationV1 {
            generation: GENERATION,
            not_after_micros: GENERATION_HORIZON,
            cut: cut(),
        },
    );
    state
}

/// The domain over T and its Fork child, both able to reserve.
fn scope() -> Result<MemoryCommunityDomainV1, Box<dyn std::error::Error>> {
    let mut domain = domain()?;
    domain.pass_states.insert(id(2), child_state());
    Ok(domain)
}

/// A Reserve of `rows` pass rows on `timeline`, reusing the retained
/// observation.
fn reserve_input(
    timeline: TimelineId,
    operation: [u8; 16],
    rows: u64,
) -> Result<CommunityReserveInputV1, Box<dyn std::error::Error>> {
    let call = CommunityReserveInputV1 {
        timeline,
        reservation_operation_id: operation,
        pass_rows: rows,
        ..reuse()?
    };
    Ok(bound(call)?)
}

/// Stage and apply a Reserve; the refusal when it is refused.
fn reserve(
    domain: &mut MemoryCommunityDomainV1,
    timeline: TimelineId,
    operation: [u8; 16],
    rows: u64,
) -> Result<Option<Error>, Box<dyn std::error::Error>> {
    match domain.stage_reserve(reserve_input(timeline, operation, rows)?) {
        Ok(staged) => {
            domain.apply_reserve(&SEAL, staged)?;
            Ok(None)
        }
        Err(error) => Ok(Some(error)),
    }
}

/// The `index`-th pending reservation, modulo their count, with its rows.
fn pick(domain: &MemoryCommunityDomainV1, index: u64) -> Option<((TimelineId, [u8; 16]), u64)> {
    let count = domain.pending_reservations.len() as u64;
    index.checked_rem(count).and_then(|at| {
        domain
            .pending_reservations
            .iter()
            .nth(usize::try_from(at).ok()?)
            .map(|(key, entry)| (*key, entry.rows))
    })
}

/// Abort a pending reservation registering at most its rows.
fn abort(domain: &mut MemoryCommunityDomainV1, draw: u64) -> TestResult {
    if let Some((key, rows)) = pick(domain, draw) {
        let staged = domain.stage_abort(key.0, key.1, (draw >> 24) % (rows + 1))?;
        domain.apply_abort(&SEAL, &staged)?;
    }
    Ok(())
}

/// Commit a pending reservation binding at most its rows, with no
/// additions and the head its Timeline already holds.
fn commit(domain: &mut MemoryCommunityDomainV1, draw: u64) -> TestResult {
    if let Some((key, rows)) = pick(domain, draw) {
        let head = domain.pass_states.get(&key.0).ok_or("state")?.head;
        let staged = domain.stage_commit(CommunityCommitInputV1 {
            timeline: key.0,
            reservation_operation_id: key.1,
            selected_head: head,
            additions: CommunitySharedCountsV1 {
                nodes: 0,
                edges: 0,
                declared_inputs: 0,
                encoded_record_bytes: 0,
            },
            annotations: 0,
            closure: Vec::new(),
            observation: None,
            bound_rows: (draw >> 24) % (rows + 1),
            scope_rows: Vec::new(),
            ..commit_input()
        })?;
        domain.apply_commit(&SEAL, staged)?;
    }
    Ok(())
}

/// Every actor of both Timelines' scopes stays within the targets line with
/// its pending reservations and quarantine reserve, and every Timeline
/// within the rows bound (R13.1(3)).
fn assert_bounds(domain: &MemoryCommunityDomainV1) -> TestResult {
    for timeline in [id(1), id(2)] {
        let budget = domain.erasure_budget(timeline)?;
        for actor in &budget.actors {
            let pending = domain.pending_erasure_demand(actor.actor);
            assert!(
                actor.targets + pending.targets + actor.quarantine_reserve
                    <= COMMUNITY_ERASURE_TARGET_LINE_V1
            );
            for (affected, committed) in &budget.rows {
                let held = pending.rows.get(affected).copied().unwrap_or(0);
                let reserve = budget.quarantine_rows.get(affected).copied().unwrap_or(0);
                assert!(committed + held + reserve <= COMMUNITY_ERASURE_ROW_LIMIT_V1);
            }
        }
    }
    Ok(())
}

/// R13.7 I134: a parent and its Fork child each plan a pass that fits alone
/// but not together. The second Reserve writer gives 6; the first resolves;
/// the second then fits.
#[test]
fn the_second_reserve_waits_for_the_first_to_resolve() -> TestResult {
    let mut domain = scope()?;
    assert_eq!(reserve(&mut domain, id(1), [1; 16], 1_900)?, None);
    assert_eq!(
        reserve(&mut domain, id(2), [2; 16], 1_900)?,
        Some(Error::StaleFrontier)
    );
    assert_bounds(&domain)?;
    let staged = domain.stage_abort(id(1), [1; 16], 0)?;
    domain.apply_abort(&SEAL, &staged)?;
    assert_eq!(reserve(&mut domain, id(2), [3; 16], 1_900)?, None);
    assert_bounds(&domain)
}

/// R13.7 I146: community operations never take `targets(A)` above the
/// community line or any `rows(U)` above 4,096, over random interleavings
/// of Reserve, Abort and Commit across a Fork parent and its child.
#[test]
fn random_interleavings_never_exceed_the_bounds() -> TestResult {
    for seed in [0x9e37_79b9_7f4a_7c15_u64, 0x1234_5678_9abc_def1, 7] {
        let mut domain = scope()?;
        let mut state = seed;
        for step in 1..=120_u8 {
            let draw = next(&mut state);
            match draw % 4 {
                0 | 1 => {
                    let timeline = [id(1), id(2)][((draw >> 8) & 1) as usize];
                    let rows = ROWS[((draw >> 16) % 4) as usize];
                    let refusal = reserve(&mut domain, timeline, [step; 16], rows)?;
                    assert!(matches!(
                        refusal,
                        None | Some(Error::StaleFrontier | Error::PassUnresolved)
                    ));
                }
                2 => abort(&mut domain, draw >> 32)?,
                _ => commit(&mut domain, draw >> 32)?,
            }
            assert_bounds(&domain)?;
        }
    }
    Ok(())
}
