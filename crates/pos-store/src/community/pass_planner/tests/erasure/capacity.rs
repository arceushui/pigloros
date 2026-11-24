//! The R13.3 capacity table and Event history through the planner over the
//! Memory domain's erasure counters (I130, I132, I142 and I144).
//!
//! Each simulated pass is planned at step 5g against the domain's real
//! budget, and its rows are then bound into the Memory catalogue through
//! the counted test seam, as its Commit would bind them. The pass rows of a
//! lockstep pair are held as the other's pending reservation (R13.1(4)).
//! Every other domain read is a fixed fake: the closure grows by each
//! pass's State graph demand, and no key, outcome or scope bound binds.

use std::cell::RefCell;

use super::*;
use crate::erasure_budget_rows::{community_rows, erasure_row};
use pos_core::community_lifecycle::CommunityPassDemandV1;
use pos_core::ArtifactDataClassV1;

/// The context's Timeline T and its Fork child.
fn child() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([3; 16]))
}

/// The Memory domain with T owned by [`ACTOR`] and, for a Fork column, its
/// Fork child, and the fake reads of the rest of the domain.
struct World {
    domain: MemoryCommunityDomainV1,
    members: usize,
    seed: u64,
    selected: BTreeMap<TimelineId, CommunityGraphCountsV1>,
    retained: BTreeMap<TimelineId, BTreeSet<[u8; 32]>>,
    queried: RefCell<BTreeSet<[u8; 32]>>,
    pending: BTreeMap<EntityId, CommunityPendingErasureV1>,
}

/// A Memory domain over a store holding T, owned by [`ACTOR`].
fn capacity_domain() -> Fallible<MemoryCommunityDomainV1> {
    let mut store = MemoryStore::new();
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    store.create_timeline_with_meta(pos_core::TimelineMeta {
        id: timeline(),
        ..pos_core::TimelineMeta::root_owned("capacity", ACTOR)
    })?;
    Ok(MemoryCommunityDomainV1::new(
        store,
        [0x5a; 16],
        MemoryTrustedClockAuthorityV1::new(),
    )?)
}

/// T's initialization: its `5n` rows bound and its context's `F_q` held.
fn initialized(domain: &mut MemoryCommunityDomainV1, members: u64) -> TestResult {
    domain
        .store
        .bind_erasure_rows_for_test(timeline(), community_rows(1_000_000, 5 * members)?);
    domain.count_erasure_context(timeline(), members);
    Ok(())
}

/// T's Fork child, holding its own context and no rows (`fork_current`
/// mints no ARD1 row).
fn fork_child(domain: &mut MemoryCommunityDomainV1, members: u64) -> TestResult {
    domain
        .store
        .create_timeline_with_meta(pos_core::TimelineMeta {
            id: child(),
            owner: Some(ACTOR),
            fork_point: Some((timeline(), Seq::ZERO)),
            ..pos_core::TimelineMeta::root("capacity-fork")
        })?;
    domain.count_erasure_context(child(), members);
    Ok(())
}

/// `members` roster views, none of which has stepped, so all are due.
fn never_stepped(members: usize) -> Fallible<Vec<CommunityPassMemberViewV1>> {
    Ok((1..=members)
        .map(|byte| u8::try_from(byte).map(|byte| member(byte, None)))
        .collect::<Result<_, std::num::TryFromIntError>>()?)
}

/// The planner fixture for `members` due members on `timeline`.
fn fixture_on(timeline: TimelineId, members: usize) -> Fallible<Fixture> {
    let mut fixture = Fixture::new()?;
    fixture.progress = CommunityHostProgressV1::new(timeline, G, None, None)?;
    fixture.members = never_stepped(members)?;
    Ok(fixture)
}

/// Step 4 over the domain's quarantine index, which must find a due set.
fn due_on<'a>(
    world: &World,
    installation: CommunityPassInstallationV1<'a>,
    view: CommunityPassViewV1<'a>,
) -> Fallible<CommunityPassDueV1<'a>> {
    match plan_community_pass_v1(&world.domain, installation, view, request(5, 1000))? {
        CommunityPassPlanV1::Due(due) => Ok(due),
        CommunityPassPlanV1::NoPass => Err("due expected".into()),
    }
}

impl World {
    /// T initialized with `members` members and, with `fork`, its Fork
    /// child.
    fn new(members: usize, fork: bool) -> Fallible<Self> {
        let mut domain = capacity_domain()?;
        let n = members as u64;
        initialized(&mut domain, n)?;
        fork.then(|| fork_child(&mut domain, n)).transpose()?;
        Ok(Self {
            domain,
            members,
            seed: 0,
            selected: BTreeMap::new(),
            retained: BTreeMap::new(),
            queried: RefCell::new(BTreeSet::new()),
            pending: BTreeMap::new(),
        })
    }

    /// Plan one pass of every member on `timeline` at 5g: the first mints
    /// `minted`, a later one reuses its observation.
    fn plan(
        &self,
        timeline: TimelineId,
        minted: Option<&CommunityObservationSourcesV1>,
    ) -> Fallible<Result<CommunityPassQuotedV1, Error>> {
        let key = key()?;
        let roster = Fixture::roster(&key)?;
        fixture_on(timeline, self.members).and_then(|fixture| {
            fixture
                .profile(&roster[..self.members])
                .and_then(|profile| self.quote_with(&profile, &fixture, minted))
        })
    }

    /// Step 5g of the pass `fixture` views under `profile`.
    fn quote_with(
        &self,
        profile: &CommunityDurableProfileV1<'_>,
        fixture: &Fixture,
        minted: Option<&CommunityObservationSourcesV1>,
    ) -> Fallible<Result<CommunityPassQuotedV1, Error>> {
        let installation = CommunityPassInstallationV1 {
            profile,
            state_limit_bytes: &STATE_LIMITS[..self.members],
        };
        let due = due_on(self, installation, fixture.view())?;
        let prior = [CommunityTypedInputRefV1::Native(
            CommunityNativeNodeReferenceV1 {
                node_digest: hash(91),
                ..REUSED
            },
        )];
        let reused = [prior[0], CommunityTypedInputRefV1::Native(REUSED)];
        let inputs: &[CommunityTypedInputRefV1<'_>] = minted.map_or(&reused, |_| &prior);
        let payload = [7; 16];
        let steps: Vec<_> = (0..self.members)
            .map(|_| CommunityPassStepInputsV1 {
                prepared_invocation: invocation(hash(2), &payload),
                step_inputs: inputs,
                consumes_minted_observation: minted.is_some(),
            })
            .collect();
        let observation = minted.map_or(
            CommunityPassObservationUseV1::Reused(REUSED),
            CommunityPassObservationUseV1::Minted,
        );
        Ok(due.quote(self, &steps, observation))
    }

    /// Commit a planned pass on `timeline`: bind its rows, select its
    /// closure and retain the CES1s its materialization minted.
    fn commit(&mut self, timeline: TimelineId, demand: &CommunityPassDemandV1) -> TestResult {
        let [_, rows] = demand.erasure_rows();
        self.domain
            .store
            .bind_erasure_rows_for_test(timeline, community_rows(self.seed, rows)?);
        self.seed += rows;
        self.selected.insert(timeline, demand.graph()[0]);
        let queried = std::mem::take(&mut *self.queried.borrow_mut());
        self.retained.entry(timeline).or_default().extend(queried);
        let (targets, _) = self.domain.store.erasure_recount_for_test(ACTOR);
        // I132: after every operation the counters equal the recount.
        let budget = self.domain.erasure_budget(timeline)?;
        assert_eq!(budget.actors[0].targets, targets);
        Ok(())
    }

    /// The pending entry of a planned pass: its rows and `F_p` (R13.1(4)).
    fn hold(&mut self, timeline: TimelineId, demand: &CommunityPassDemandV1) {
        let [_, rows] = demand.erasure_rows();
        let pending = self.pending.entry(ACTOR).or_default();
        pending.targets += 2 * rows + demand.failure_reserve();
        *pending.rows.entry(timeline).or_default() += rows + demand.failure_reserve() / 2;
    }

    /// Plan and commit one pass on T, or the refusal that stops it.
    fn step(&mut self, first: Option<&CommunityObservationSourcesV1>) -> Fallible<Option<Error>> {
        match self.plan(timeline(), first)? {
            Ok(quoted) => self.commit(timeline(), quoted.demand()).map(|()| None),
            Err(error) => Ok(Some(error)),
        }
    }

    /// Passes on T alone until the budget refuses one, and that refusal;
    /// the first pass mints `minted`.
    fn passes(&mut self, minted: &CommunityObservationSourcesV1) -> Fallible<(u64, Error)> {
        let mut passes = 0;
        loop {
            if let Some(error) = self.step((passes == 0).then_some(minted))? {
                return Ok((passes, error));
            }
            passes += 1;
        }
    }

    /// Reserve T's pass and then its Fork child's, the parent's held as
    /// pending; `None` once the budget refuses either.
    fn reserve_pair(
        &mut self,
        first: Option<&CommunityObservationSourcesV1>,
    ) -> Fallible<Option<(CommunityPassQuotedV1, CommunityPassQuotedV1)>> {
        self.plan(timeline(), first)?
            .ok()
            .map_or(Ok(None), |parent| {
                self.hold(timeline(), parent.demand());
                self.plan(child(), first)
                    .map(|forked| forked.ok().map(|forked| (parent, forked)))
            })
    }

    /// One lockstep round: both passes reserved before either commits.
    fn round(&mut self, first: Option<&CommunityObservationSourcesV1>) -> Fallible<bool> {
        match self.reserve_pair(first)? {
            None => Ok(false),
            Some((parent, forked)) => {
                self.pending.clear();
                self.commit(timeline(), parent.demand())
                    .and_then(|()| self.commit(child(), forked.demand()))
                    .map(|()| true)
            }
        }
    }

    /// Lockstep rounds of T and its Fork child until the budget refuses a
    /// pass; each first pass mints the prefix (the child re-mints every
    /// CES1, R9 I81).
    fn rounds(&mut self, minted: &CommunityObservationSourcesV1) -> Fallible<u64> {
        let mut rounds = 0;
        loop {
            if !self.round((rounds == 0).then_some(minted))? {
                return Ok(rounds);
            }
            rounds += 1;
        }
    }
}

impl CommunityQuarantineIndexV1 for World {
    fn quarantine_reasons(&self, key: Hash) -> Option<Vec<CommunityQuarantineReasonV1>> {
        self.domain.quarantine_reasons(key)
    }
}

impl CommunityErasureBudgetPortV1 for World {
    fn erasure_budget(&self, timeline: TimelineId) -> Result<CommunityErasureBudgetV1, Error> {
        self.domain.erasure_budget(timeline)
    }
}

impl CommunityPassReadPortV1 for World {
    fn recorded_set_counters(&self, _timeline: TimelineId) -> CommunitySharedCountsV1 {
        CommunitySharedCountsV1::default()
    }

    fn retained_pass_outcomes(&self, _timeline: TimelineId, _generation: [u8; 16]) -> u64 {
        0
    }

    fn control_operations(&self, _timeline: TimelineId, _generation: [u8; 16]) -> u64 {
        0
    }

    fn live_keys(&self) -> u64 {
        0
    }

    fn selected_graph(&self, timeline: TimelineId) -> CommunityGraphCountsV1 {
        let members = self.members as u64;
        self.selected
            .get(&timeline)
            .copied()
            .unwrap_or(CommunityGraphCountsV1 {
                registrations: 5 * members,
                edges: 6 * members,
                ..SELECTED
            })
    }

    fn event_source_in_closure(&self, timeline: TimelineId, event_source: Hash) -> bool {
        self.queried.borrow_mut().insert(*event_source.as_bytes());
        self.retained
            .get(&timeline)
            .is_some_and(|retained| retained.contains(event_source.as_bytes()))
    }

    fn observation_graph(
        &self,
        _timeline: TimelineId,
        _observation: CommunityNativeNodeReferenceV1,
    ) -> CommunityPassGraphTermsV1 {
        CommunityPassGraphTermsV1::default()
    }

    fn scope_rows(
        &self,
        _timeline: TimelineId,
        _reference: CommunityTypedInputRefV1<'_>,
    ) -> Result<Vec<CommunityScopeMemberV1>, Error> {
        Ok(Vec::new())
    }

    fn pending_erasure_demand(&self, actor: EntityId) -> CommunityPendingErasureV1 {
        self.pending.get(&actor).cloned().unwrap_or_default()
    }
}

#[test]
fn one_timeline_runs_the_r13_3_passes_before_its_refusal() -> TestResult {
    // I142, first column: no new Event, the first pass minting the empty
    // cut; 164 passes at n = 1 and the floor's 64 at n = 3. At n = 1 the
    // next pass's State and F_p no longer fit (14); at n = 3 they do and
    // only its recording does not, which R13.1(3) refuses with 19.
    let empty = minted_sources(0)?;
    for (members, expected) in [
        (1, (164, Error::CapacityExhausted)),
        (3, (64, Error::RecordingUnavailable)),
    ] {
        assert_eq!(World::new(members, false)?.passes(&empty)?, expected);
    }
    Ok(())
}

#[test]
fn a_lockstep_fork_shares_the_budget_with_its_parent() -> TestResult {
    // I142, Fork columns: two pending F_p a round, the child re-minting the
    // prefix; E = 1 and E = 500.
    let one = minted_sources(1)?;
    let wide = minted_sources(500)?;
    for (members, sources, expected) in
        [(1, &one, 81), (1, &wide, 39), (3, &one, 32), (3, &wide, 15)]
    {
        assert_eq!(World::new(members, true)?.rounds(sources)?, expected);
    }
    Ok(())
}

#[test]
fn a_first_pass_observes_at_most_the_r13_3_event_history() -> TestResult {
    // I144: with no Fork and no earlier pass, 1,941 Events fit at n = 1 and
    // 1,903 at n = 3. One Event more is refused at 5g: its State and F_p
    // still fit, so R13.1(3) gives 19 until the State itself overflows,
    // which gives 14 (at 1,945 and 1,911 Events).
    for (members, fitting, state) in [(1, 1941, 1944), (3, 1903, 1910)] {
        let world = World::new(members, false)?;
        let observe = |events| -> Fallible<Option<Error>> {
            Ok(world
                .plan(timeline(), Some(&minted_sources(events)?))?
                .err())
        };
        assert_eq!(observe(fitting)?, None);
        assert_eq!(observe(fitting + 1)?, Some(Error::RecordingUnavailable));
        assert_eq!(observe(state)?, Some(Error::RecordingUnavailable));
        assert_eq!(observe(state + 1)?, Some(Error::CapacityExhausted));
    }
    Ok(())
}

#[test]
fn rows_of_any_class_refuse_a_community_row_while_targets_fit() -> TestResult {
    // I130's second bound: consented rows cost no target but fill T's view
    // list; at 4,096 rows with the pass's rows and F_p rows it still fits,
    // one more gives 14.
    let mut world = World::new(1, false)?;
    let quoted = world.plan(timeline(), None)??;
    let [state, _] = quoted.demand().erasure_rows();
    let held = state + quoted.demand().failure_reserve() / 2;
    let consented = (0..ROWS - 5 - held)
        .map(|seed| {
            erasure_row(
                "budget-owner",
                ArtifactDataClassV1::ConsentedSharedData,
                0,
                seed,
            )
        })
        .collect::<Fallible<Vec<_>>>()?;
    world
        .domain
        .store
        .bind_erasure_rows_for_test(timeline(), consented);
    assert_eq!(
        world.plan(timeline(), None)?.err(),
        Some(Error::RecordingUnavailable)
    );
    let more = erasure_row(
        "budget-owner",
        ArtifactDataClassV1::ConsentedSharedData,
        0,
        ROWS,
    )?;
    world
        .domain
        .store
        .bind_erasure_rows_for_test(timeline(), vec![more]);
    assert_eq!(
        world.plan(timeline(), None)?.err(),
        Some(Error::CapacityExhausted)
    );
    let budget = world.domain.erasure_budget(timeline())?;
    assert!(budget.actors[0].targets < LINE / 2);
    Ok(())
}

#[test]
fn the_quarantine_reserve_follows_every_context_in_the_scope() -> TestResult {
    // R13.1(5): F_q(A) is 8n per initialized context on a Timeline of
    // affected(A), less two targets per active (member, reason) pair; a
    // reset re-arms its pairs, and a context outside the scope is not A's.
    let mut world = World::new(3, true)?;
    let reserve = |world: &World| -> Fallible<u64> {
        Ok(world.domain.erasure_budget(timeline())?.actors[0].quarantine_reserve)
    };
    assert_eq!(reserve(&world)?, 48);
    world.domain.count_erasure_context(other_timeline(), 3);
    assert_eq!(reserve(&world)?, 48);
    world.domain.count_quarantine_pairs(child(), 0, 2);
    assert_eq!(reserve(&world)?, 44);
    world.domain.count_quarantine_pairs(child(), 2, 1);
    assert_eq!(reserve(&world)?, 46);
    world.domain.count_quarantine_pairs(timeline(), 0, 13);
    assert_eq!(reserve(&world)?, 22);
    Ok(())
}
