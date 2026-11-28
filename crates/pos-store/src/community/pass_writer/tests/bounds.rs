//! The erasure bounds across concurrent reservations (ADR-129 revision 13,
//! R13.1(3)-(4), R13.7 I134 and I146), over a Fork parent T and its child
//! whose owners share T's scope.
//!
//! The writer-level operations bind no rows (the pipeline does), so the
//! domain is seeded with committed rows and a quarantine context, and a
//! shadow model written from the spec literals (the `4,096 - 128` targets
//! line, 4,096 rows, two targets per row, `F_p` of 4 targets, `F_q` of `8n`)
//! predicts every refusal and the pending ledger. The bounds are the spec's
//! literals, not the domain's constants; the committed values are checked
//! against literals too, and the domain's own budget is asserted within the
//! bounds after every step.
//!
//! Interleavings covered: Reserve, Abort and Commit across the two Timelines.
//! Not covered here: `fork_current` (no implementation exists yet), and
//! `SetReason` and reset, whose `F_q` spend and re-arm are the failure-path
//! tests (the I136 PR on the reset's 14, #1589 and its follow-up). At the
//! writer level an Abort or Commit replaces the pending entry by the rows it
//! registers or binds, and those rows are the pipeline's: the committed rows
//! do not change, so the edge sizes exercise the entry-size compare (3), not
//! the ledger.
//!
//! Not here: the 14 at step 5g after the first Reserve commits (the planner
//! owns it, `pass_planner/tests/erasure.rs`), two owned root Timelines (the
//! scope walk is the store's, `every_actor_of_the_scope_must_fit`), and a row
//! another owner binds between 5g and the writer (the pipeline's).

use super::*;
use crate::erasure_budget_rows::{community_rows, erasure_row};
use pos_core::ArtifactDataClassV1;

/// `4,096 - R_other`, the targets line (R13.1(3), (6)).
const LINE: u64 = 3_968;
/// The rows bound of a Timeline (R13.1(1)).
const ROW_BOUND: u64 = 4_096;
/// The roster members of the context seeded on T.
const MEMBERS: u64 = 3;
/// `F_q` in targets (`8n`) and in rows (`4n`).
const RESERVE_TARGETS: u64 = 8 * MEMBERS;
const RESERVE_ROWS: u64 = 4 * MEMBERS;
/// The rows committed to T: community rows (two targets each) and consented
/// rows (no targets).
const COMMUNITY_ROWS: u64 = 1_000;
const CONSENTED_ROWS: u64 = 2_800;
/// `F_p` of the fixture's pass of one due member: `2 * (n_due + 1)` = 4
/// targets, which the entry holds as 4 targets and 2 rows.
const PASS_RESERVE_TARGETS: u64 = 4;
const PASS_RESERVE_ROWS: u64 = 2;

/// One pending reservation of the shadow ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Held {
    /// 0 for T, 1 for its child.
    timeline: usize,
    operation: [u8; 16],
    targets: u64,
    rows: u64,
}

/// The shadow model: the committed targets of the two owners (T's and the
/// child's), read once from the seeded domain, and the pending ledger.
struct Model {
    committed: [u64; 2],
    pending: Vec<Held>,
}

/// The Timelines of the scope, by model index.
fn timeline_of(index: usize) -> TimelineId {
    [id(1), id(2)][index]
}

impl Model {
    /// The pending targets in an owner's scope: T's owner (0) holds both
    /// Timelines, the child's owner (1) its own.
    fn pending_targets(&self, owner: usize) -> u64 {
        self.pending
            .iter()
            .filter(|held| owner == 0 || held.timeline == 1)
            .map(|held| held.targets)
            .sum()
    }

    /// The pending rows of a Timeline.
    fn pending_rows(&self, timeline: usize) -> u64 {
        self.pending
            .iter()
            .filter(|held| held.timeline == timeline)
            .map(|held| held.rows)
            .sum()
    }

    /// The owners whose scope holds a Timeline.
    fn owners_of(timeline: usize) -> &'static [usize] {
        [&[0_usize][..], &[1, 0][..]][timeline]
    }

    /// Every owner of the Timeline's scope stays within the targets line
    /// with a pass of `rows` rows added.
    fn targets_fit(&self, timeline: usize, rows: u64) -> bool {
        Self::owners_of(timeline).iter().all(|&owner| {
            self.committed[owner]
                + [RESERVE_TARGETS, 0][owner]
                + self.pending_targets(owner)
                + 2 * rows
                + PASS_RESERVE_TARGETS
                <= LINE
        })
    }

    /// Every Timeline stays within the rows bound with a pass of `rows` rows
    /// added to `timeline`.
    fn rows_fit(&self, timeline: usize, rows: u64) -> bool {
        (0..2).all(|index| {
            let added = if index == timeline {
                rows + PASS_RESERVE_ROWS
            } else {
                0
            };
            [COMMUNITY_ROWS + CONSENTED_ROWS, 0][index]
                + [RESERVE_ROWS, 0][index]
                + self.pending_rows(index)
                + added
                <= ROW_BOUND
        })
    }

    /// The refusal a Reserve of `rows` rows on `timeline` gets: 7 when the
    /// Timeline has a pending reservation, else 6 when the budget does not
    /// fit.
    fn outcome(&self, timeline: usize, rows: u64) -> Option<Error> {
        if self.pending.iter().any(|held| held.timeline == timeline) {
            Some(Error::PassUnresolved)
        } else if self.targets_fit(timeline, rows) && self.rows_fit(timeline, rows) {
            None
        } else {
            Some(Error::StaleFrontier)
        }
    }

    /// The largest pass `timeline` takes with nothing pending beside it.
    fn largest(&self, timeline: usize) -> u64 {
        (1..=ROW_BOUND)
            .take_while(|&rows| self.targets_fit(timeline, rows) && self.rows_fit(timeline, rows))
            .last()
            .unwrap_or(0)
    }

    /// The spec bound over the shadow ledger: no owner above the targets
    /// line, no Timeline above the rows bound.
    fn within_bounds(&self) -> bool {
        (0..2).all(|owner| {
            self.committed[owner] + [RESERVE_TARGETS, 0][owner] + self.pending_targets(owner)
                <= LINE
        }) && (0..2).all(|timeline| {
            [COMMUNITY_ROWS + CONSENTED_ROWS, 0][timeline]
                + [RESERVE_ROWS, 0][timeline]
                + self.pending_rows(timeline)
                <= ROW_BOUND
        })
    }

    /// The ledger as the domain keeps it, in its key order.
    fn ledger(&self) -> Vec<(TimelineId, [u8; 16], u64, u64)> {
        let mut held: Vec<_> = self
            .pending
            .iter()
            .map(|held| {
                (
                    timeline_of(held.timeline),
                    held.operation,
                    held.targets,
                    held.rows,
                )
            })
            .collect();
        held.sort();
        held
    }
}

/// The pending ledger the domain keeps.
fn domain_ledger(domain: &MemoryCommunityDomainV1) -> Vec<(TimelineId, [u8; 16], u64, u64)> {
    domain
        .pending_reservations
        .iter()
        .map(|((timeline, operation), entry)| (*timeline, *operation, entry.targets, entry.rows))
        .collect()
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

/// The committed targets of the owner `byte` over `timeline`'s scope.
fn committed_of(
    domain: &MemoryCommunityDomainV1,
    timeline: TimelineId,
    byte: u8,
) -> Result<u64, Box<dyn std::error::Error>> {
    Ok(domain
        .erasure_budget(timeline)?
        .actors
        .iter()
        .find(|owner| owner.actor == actor(byte))
        .ok_or("owner in scope")?
        .targets)
}

/// The domain over T and its Fork child, both able to reserve, seeded with
/// the committed rows and the quarantine context, and its shadow model.
fn seeded() -> Result<(MemoryCommunityDomainV1, Model), Box<dyn std::error::Error>> {
    let mut domain = domain()?;
    domain.pass_states.insert(id(2), child_state());
    domain.count_erasure_context(id(1), MEMBERS);
    let consented = (0..CONSENTED_ROWS)
        .map(|seed| erasure_row("budget", ArtifactDataClassV1::ConsentedSharedData, 0, seed))
        .collect::<Result<Vec<_>, _>>()?;
    domain.store.bind_erasure_rows_for_test(id(1), consented);
    domain
        .store
        .bind_erasure_rows_for_test(id(1), community_rows(10_000, COMMUNITY_ROWS)?);
    // R13.1(1): one store target, one `timeline-payload` per affected
    // Timeline (T's owner holds T and its child, the child's owner its own)
    // and two targets per community row: 1 + 2 + 2,000 and 1 + 1.
    let committed = [2_003, 2];
    assert_eq!(committed[0], committed_of(&domain, id(1), 10)?);
    assert_eq!(committed[1], committed_of(&domain, id(2), 11)?);
    Ok((
        domain,
        Model {
            committed,
            pending: Vec::new(),
        },
    ))
}

/// Stage and apply a Reserve of `rows` rows on the model Timeline
/// `timeline`, reusing the retained observation; the refusal when refused.
fn reserve(
    domain: &mut MemoryCommunityDomainV1,
    timeline: usize,
    operation: [u8; 16],
    rows: u64,
) -> Result<Option<Error>, Box<dyn std::error::Error>> {
    let call = CommunityReserveInputV1 {
        timeline: timeline_of(timeline),
        reservation_operation_id: operation,
        pass_rows: rows,
        ..reuse()?
    };
    match domain.stage_reserve(bound(call)?) {
        Ok(staged) => {
            domain.apply_reserve(&SEAL, staged)?;
            Ok(None)
        }
        Err(error) => Ok(Some(error)),
    }
}

/// Reserve and check the refusal against the model, which then records an
/// accepted pass.
fn modeled_reserve(
    domain: &mut MemoryCommunityDomainV1,
    model: &mut Model,
    timeline: usize,
    operation: [u8; 16],
    rows: u64,
) -> Result<Option<Error>, Box<dyn std::error::Error>> {
    let expected = model.outcome(timeline, rows);
    let actual = reserve(domain, timeline, operation, rows)?;
    assert_eq!(actual, expected, "{timeline} {rows}");
    if actual.is_none() {
        model.pending.push(Held {
            timeline,
            operation,
            targets: 2 * rows + PASS_RESERVE_TARGETS,
            rows: rows + PASS_RESERVE_ROWS,
        });
    }
    Ok(actual)
}

/// Which edge of `0..=rows` a draw picks, from bits the action and the
/// pick do not use: 0 none, 1 all, 2 the middle, 3 any.
const fn variant(draw: u64) -> usize {
    match (draw >> 40) & 3 {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 3,
    }
}

/// The edge of `0..=rows` a draw picks.
const fn edge(draw: u64, rows: u64) -> u64 {
    match variant(draw) {
        0 => 0,
        1 => rows,
        2 => rows / 2,
        _ => (draw >> 44) % (rows + 1),
    }
}

/// Take the pending reservation a draw picks out of the model.
fn take(model: &mut Model, draw: u64) -> Result<Option<Held>, Box<dyn std::error::Error>> {
    let at = usize::try_from((draw >> 32) & 0xff)?.checked_rem(model.pending.len());
    Ok(at.map(|at| model.pending.remove(at)))
}

/// Abort the reservation `held`, registering `rows` rows.
fn finish_abort(domain: &mut MemoryCommunityDomainV1, held: Held, rows: u64) -> TestResult {
    let staged = domain.stage_abort(timeline_of(held.timeline), held.operation, rows)?;
    domain.apply_abort(&SEAL, &staged)?;
    Ok(())
}

/// Commit the reservation `held`, binding `rows` rows; the Timeline's head
/// stays, so a later 6 is the budget's.
fn finish_commit(domain: &mut MemoryCommunityDomainV1, held: Held, rows: u64) -> TestResult {
    let timeline = timeline_of(held.timeline);
    let before = domain.pass_states.get(&timeline).map(|state| state.head);
    let staged = domain.stage_commit(commit_of(domain, timeline, held.operation, rows)?)?;
    domain.apply_commit(&SEAL, staged)?;
    assert_eq!(
        domain.pass_states.get(&timeline).map(|state| state.head),
        before
    );
    Ok(())
}

/// Resolve the pending reservation a draw picks by an Abort, or by a Commit
/// when `commit`, registering or binding an edge of its entry's rows; the
/// edge variant used, if a reservation was pending. One more row than the
/// entry holds is refused (3) first.
fn resolve(
    domain: &mut MemoryCommunityDomainV1,
    model: &mut Model,
    draw: u64,
    commit: bool,
) -> Result<Option<usize>, Box<dyn std::error::Error>> {
    let Some(held) = take(model, draw)? else {
        return Ok(None);
    };
    assert_eq!(
        domain
            .stage_abort(timeline_of(held.timeline), held.operation, held.rows + 1)
            .err(),
        Some(Error::InvalidBinding)
    );
    let rows = edge(draw, held.rows);
    if commit {
        finish_commit(domain, held, rows)?;
    } else {
        finish_abort(domain, held, rows)?;
    }
    Ok(Some(variant(draw)))
}

/// A Commit binding `rows` rows with no additions and the head the Timeline
/// already holds.
fn commit_of(
    domain: &MemoryCommunityDomainV1,
    timeline: TimelineId,
    operation: [u8; 16],
    rows: u64,
) -> Result<CommunityCommitInputV1, Box<dyn std::error::Error>> {
    Ok(CommunityCommitInputV1 {
        timeline,
        reservation_operation_id: operation,
        selected_head: domain.pass_states.get(&timeline).ok_or("state")?.head,
        additions: CommunitySharedCountsV1 {
            nodes: 0,
            edges: 0,
            declared_inputs: 0,
            encoded_record_bytes: 0,
        },
        annotations: 0,
        closure: Vec::new(),
        observation: None,
        bound_rows: rows,
        scope_rows: Vec::new(),
        ..commit_input()
    })
}

/// The domain's ledger is the model's, the model is within the spec bounds,
/// and so is what the domain itself reports: every owner's committed targets
/// with its quarantine reserve and pending reservations within 3,968, and
/// every Timeline's rows with its pending and quarantine rows within 4,096.
fn assert_model(domain: &MemoryCommunityDomainV1, model: &Model) -> TestResult {
    assert_eq!(domain_ledger(domain), model.ledger());
    assert!(model.within_bounds());
    for timeline in [id(1), id(2)] {
        let budget = domain.erasure_budget(timeline)?;
        for owner in &budget.actors {
            let pending = domain.pending_erasure_demand(owner.actor);
            assert!(owner.targets + owner.quarantine_reserve + pending.targets <= LINE);
            for (affected, committed) in &budget.rows {
                let held = pending.rows.get(affected).copied().unwrap_or(0);
                let reserve = budget.quarantine_rows.get(affected).copied().unwrap_or(0);
                assert!(committed + held + reserve <= ROW_BOUND);
            }
        }
    }
    Ok(())
}

/// R13.7 I134, the writer's part: a parent and its Fork child each plan a
/// pass that fits alone but not together. The second Reserve writer gives 6;
/// when the first resolves, the second fits. A pass of exactly the largest
/// size fits and one row more gives 6, on each Timeline.
#[test]
fn the_second_reserve_waits_for_the_first_to_resolve() -> TestResult {
    let (mut domain, mut model) = seeded()?;
    let (parent, child) = (model.largest(0), model.largest(1));
    assert!(parent > 0 && child > 0);
    assert_eq!(
        modeled_reserve(&mut domain, &mut model, 0, [1; 16], parent + 1)?,
        Some(Error::StaleFrontier)
    );
    assert_eq!(
        modeled_reserve(&mut domain, &mut model, 1, [2; 16], child + 1)?,
        Some(Error::StaleFrontier)
    );
    assert_eq!(
        modeled_reserve(&mut domain, &mut model, 0, [3; 16], parent)?,
        None
    );
    // The first pass holds T's owner's line: the child's pass no longer fits.
    assert_eq!(
        modeled_reserve(&mut domain, &mut model, 1, [4; 16], child)?,
        Some(Error::StaleFrontier)
    );
    assert_model(&domain, &model)?;
    assert!(resolve(&mut domain, &mut model, 0, false)?.is_some());
    assert_eq!(
        modeled_reserve(&mut domain, &mut model, 1, [5; 16], child)?,
        None
    );
    assert_model(&domain, &model)
}

/// R13.7 I146: over random interleavings of Reserve, Abort and Commit across
/// a Fork parent and its child, with committed rows and a quarantine context
/// seeded, the domain's ledger equals the shadow ledger, every refusal is
/// the model's (7 or 6), and the spec bounds hold after every step. The
/// property reaches the limits: it accepts, refuses with 6 and refuses with 7.
#[test]
fn random_interleavings_never_exceed_the_bounds() -> TestResult {
    let mut outcomes = [0_u32; 3];
    let mut edges = [[0_u32; 4]; 2];
    for seed in [0x9e37_79b9_7f4a_7c15_u64, 0x1234_5678_9abc_def1, 7] {
        let (mut domain, mut model) = seeded()?;
        let sizes = [
            1,
            24,
            model.largest(0),
            model.largest(0) + 1,
            model.largest(1),
            model.largest(1) + 1,
        ];
        let mut state = seed;
        for step in 1..=120_u8 {
            let draw = next(&mut state);
            if draw % 4 < 2 {
                let timeline = usize::from((draw >> 8) & 1 == 1);
                let rows = sizes[usize::try_from((draw >> 16) % 6)?];
                let refusal = modeled_reserve(&mut domain, &mut model, timeline, [step; 16], rows)?;
                tally(&mut outcomes, refusal);
            } else if let Some(used) = resolve(&mut domain, &mut model, draw, draw % 4 == 3)? {
                edges[usize::from(draw % 4 == 3)][used] += 1;
            }
            assert_model(&domain, &model)?;
        }
    }
    assert!(outcomes.iter().all(|count| *count > 0), "{outcomes:?}");
    // Every edge of an entry's rows is reached by an Abort and by a Commit.
    assert!(edges.iter().flatten().all(|count| *count > 0), "{edges:?}");
    Ok(())
}

/// Count an accepted Reserve, a 6 and any other refusal.
fn tally(outcomes: &mut [u32; 3], refusal: Option<Error>) {
    outcomes[match refusal {
        None => 0,
        Some(Error::StaleFrontier) => 1,
        Some(_) => 2,
    }] += 1;
}

/// The next pseudo-random value of a xorshift sequence.
const fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
