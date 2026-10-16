//! ADR-117 explicit ordinary classifications through the protected consumers.
//!
//! Replay histories are empty; Compare has one real shared Event at cut one.
//! Every two-level Fork has no publication and deliberately mints Some(complete
//! sources), never the distinct None attestation bypass. All assertions cross
//! Replay, Replay-at or Compare without changing their authority preconditions.

use crate::test_support::{with_release, ProtectedFixture};
use pos_core::{
    CanonicalBytes, CoreError, EntityId, ErasureRecoveryLimitsV1, ErasureReferenceV1,
    ErasureReplayClaimV1, EventDraft, EventReadBounds, Hash, Kind, Reducer, Seq, State, TimelineId,
    WorldReplayClosureV1,
};
use pos_runtime::{
    ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, VerifiedWorldReplayV1,
    WorldReplayForkSourceV1, WorldReplayUseV1, WorldReplayVerificationErrorV1,
    WorldReplayVerifierV1,
};
use pos_store::{ForkReplayReadLimitsV1, StoreConfig};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type OrdinaryLineage = (TimelineId, TimelineId, [TimelineId; 2], Option<EntityId>);

struct EmptyReducer;

impl Reducer for EmptyReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, _: &mut State, _: &pos_core::Event) {}
}

fn empty_reducer() -> Box<dyn Reducer> {
    Box::new(EmptyReducer)
}

#[derive(Clone, Copy, Debug)]
enum Consumer {
    Replay,
    ReplayAt,
    Compare,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Edge {
    Exact,
    OneOver,
    BytesShort,
    RowsShort,
    VisitsShort,
    ArmDepthShort,
}

impl Edge {
    const fn succeeds(self) -> bool {
        matches!(self, Self::Exact | Self::OneOver)
    }
}

#[derive(Clone, Copy)]
struct Classification {
    root: TimelineId,
    parent: TimelineId,
    arms: [TimelineId; 2],
    shared_entity: Option<EntityId>,
    limits: ForkReplayReadLimitsV1,
    arm_depth: usize,
}

struct OrdinaryVerifier {
    classification: Mutex<Option<Classification>>,
    admissions: AtomicUsize,
}

impl OrdinaryVerifier {
    fn new() -> Self {
        Self {
            classification: Mutex::new(None),
            admissions: AtomicUsize::new(0),
        }
    }
}

impl WorldReplayVerifierV1 for OrdinaryVerifier {
    fn read_profile(
        &self,
        _closure: &WorldReplayClosureV1,
        intent: &pos_runtime::WorldReplayReadIntentV1,
        _generation: ErasureReferenceV1,
    ) -> Result<(EventReadBounds, ForkReplayReadLimitsV1), WorldReplayVerificationErrorV1> {
        let classification = self
            .classification
            .lock()
            .map_err(|_| WorldReplayVerificationErrorV1::EvidenceUnavailable)?
            .ok_or(WorldReplayVerificationErrorV1::EvidenceUnavailable)?;
        if !classification.arms.contains(&intent.timeline_id()) {
            return Err(WorldReplayVerificationErrorV1::EvidenceUnavailable);
        }
        Ok((
            EventReadBounds::new_with_total_bytes_and_elapsed(
                1_024,
                128,
                classification.arm_depth,
                64,
                1_024,
                30_000_000,
            ),
            classification.limits,
        ))
    }

    fn verify(
        &self,
        closure: &WorldReplayClosureV1,
        requested: &WorldReplayUseV1,
        generation: ErasureReferenceV1,
    ) -> Result<VerifiedWorldReplayV1, WorldReplayVerificationErrorV1> {
        let classification = self
            .classification
            .lock()
            .map_err(|_| WorldReplayVerificationErrorV1::EvidenceUnavailable)?
            .ok_or(WorldReplayVerificationErrorV1::EvidenceUnavailable)?;
        if !classification.arms.contains(&requested.timeline_id()) {
            return Err(WorldReplayVerificationErrorV1::EvidenceUnavailable);
        }
        self.admissions.fetch_add(1, Ordering::SeqCst);
        let sources = [
            requested.timeline_id(),
            classification.parent,
            classification.root,
        ]
        .into_iter()
        .map(|timeline| WorldReplayForkSourceV1::new(timeline, None))
        .collect::<Result<Vec<_>, _>>()?;
        let bounds = EventReadBounds::new_with_total_bytes_and_elapsed(
            1_024,
            128,
            classification.arm_depth,
            64,
            1_024,
            30_000_000,
        );
        let verified = pos_runtime::world_replay::test_verified_world_replay_with_fields_and_bounds(
            closure.digest(),
            closure.timeline_id(),
            closure.source_head(),
            requested.clone(),
            generation,
            ErasureReplayClaimV1::Exact,
            bounds,
        );
        Ok(
            pos_runtime::world_replay::test_verified_world_replay_with_fork_attribution(
                verified,
                Some(Hash::from_bytes([0xc7; 32])),
                sources,
                Vec::new(),
                classification.limits,
            ),
        )
    }
}

/// Independent ADR-118 totals for each arm's three-member ordinary lineage.
/// Fence and validation each inspect [leaf,parent,root], [parent,root], [root].
/// Memory validation: 3*65 + 3*41 + 3*16 + 2*24 = 414 bytes, six rows.
/// `SQLite` validation: 3*143 + 3*93 + 3*16 + 2*24 = 804 bytes, 24 rows.
/// The fence retains 3*16 IDs and 2*16 parents instead of 2*24 parent/cuts,
/// adding 32 bytes. Each of TWO head reads walks the three members; Event
/// materialization walks them again, independently of both head observations.
/// Compare's one unsigned root Event adds one 8-byte candidate per root visit
/// in Memory, or an additional 8-byte type/E1 row in `SQLite`. Its selected
/// Event costs Memory 8+8 bytes/one row, `SQLite` 144+8 bytes/four rows.
/// The owned `SQLite` interval adds one freshness row for the whole operation.
/// No measured ledger or production debit/length helper supplies these totals.
fn limits(
    consumer: Consumer,
    edge: Edge,
    sqlite: bool,
) -> Result<ForkReplayReadLimitsV1, Box<dyn std::error::Error>> {
    let compare = matches!(consumer, Consumer::Compare);
    let arms = if compare { 2 } else { 1 };
    // Each pair is (bytes, rows), in operation-stage order.
    let [(fence_bytes, fence_rows), (head_bytes, head_rows), (phase_bytes, phase_rows), (event_bytes, event_rows)] =
        match (sqlite, compare) {
            (false, false) => [(446, 6), (211, 3), (414, 6), (203, 3)],
            (true, false) => [(836, 24), (419, 12), (804, 24), (411, 12)],
            (false, true) => [(470, 9), (219, 4), (438, 9), (227, 5)],
            (true, true) => [(884, 30), (435, 14), (852, 30), (579, 18)],
        };
    let bytes = arms * (fence_bytes + 2 * head_bytes + 2 * phase_bytes + event_bytes);
    let rows =
        usize::from(sqlite) + arms * (fence_rows + 2 * head_rows + 2 * phase_rows + event_rows);
    let visits = arms * (6 + 2 * 3 + 2 * 6 + 3);
    let adjust = |value, short| {
        if edge == short {
            value - 1
        } else if edge == Edge::OneOver {
            value + 1
        } else {
            value
        }
    };
    Ok(ForkReplayReadLimitsV1::new(
        8,
        adjust(visits, Edge::VisitsShort),
        adjust(rows, Edge::RowsShort),
        adjust(bytes, Edge::BytesShort),
        30_000_000,
    )?)
}

fn seed(
    host: &mut ErasureExecutionHostV1,
    consumer: Consumer,
) -> Result<OrdinaryLineage, Box<dyn std::error::Error>> {
    let mut commands = host.command_sender()?;
    let root = commands
        .create_timeline(&"unselected private name ".repeat(4_096))?
        .id();
    let shared_entity = matches!(consumer, Consumer::Compare).then(EntityId::new);
    let cut = if let Some(entity) = shared_entity {
        let events = commands.append(
            root,
            &[EventDraft::new(
                entity,
                Kind::new("ordinary"),
                CanonicalBytes::from_vec(Vec::new()),
            )],
        )?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].seq, Seq::from_u64(1));
        assert_eq!(events[0].payload.len(), 0);
        assert_eq!(events[0].event_type.as_str(), "ordinary");
        assert!(events[0].signature.is_none());
        assert!(events[0].signature_identity.is_none());
        assert!(events[0].causation_id.is_none());
        assert!(events[0].correlation_id.is_none());
        Seq::from_u64(1)
    } else {
        Seq::ZERO
    };
    let parent = commands.fork_timeline(root, cut, "ordinary parent")?.id();
    let first = commands.fork_timeline(parent, cut, "ordinary first")?.id();
    let second = commands.fork_timeline(parent, cut, "ordinary second")?.id();
    Ok((root, parent, [first, second], shared_entity))
}

fn exercise(
    mut host: ErasureExecutionHostV1,
    classification: Classification,
    verifier: &OrdinaryVerifier,
    consumer: Consumer,
    edge: Edge,
) -> TestResult {
    *verifier
        .classification
        .lock()
        .map_err(|_| "classification fixture poisoned")? = Some(classification);
    verifier.admissions.store(0, Ordering::SeqCst);
    let fixture = ProtectedFixture::new("count", empty_reducer);
    let gate = host.containment_gate();
    let generation = Hash::from_bytes(gate.inventory_generation()?.digest());
    let [first, second] = classification.arms;
    let first_closure = WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(
        first, generation,
    )?;
    let second_closure = WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(
        second, generation,
    )?;
    let mut a = fixture.registry(Arc::clone(&gate));
    let mut b = fixture.registry(gate);
    let before_a = a.state_snapshot(first)?;
    let before_b = b.state_snapshot(second)?;
    let mut reads = host.read_sender()?;
    let result = with_release(|release| match consumer {
        Consumer::Replay => crate::replay(
            &mut reads,
            first,
            &mut a,
            &first_closure,
            release,
            &fixture.fold(),
        ),
        Consumer::ReplayAt => crate::replay_at(
            &mut reads,
            first,
            Seq::ZERO,
            &mut a,
            &first_closure,
            release,
            &fixture.fold(),
        ),
        Consumer::Compare => crate::compare(
            &mut reads,
            [first, second],
            Seq::from_u64(1),
            [&mut a, &mut b],
            [&first_closure, &second_closure],
            release,
            [&fixture.fold(), &fixture.fold()],
        )
        .map(|diff| {
            assert_eq!(diff.fork_seq, Seq::from_u64(1));
            assert!(diff.diverged_entities.is_empty());
        }),
    });
    if edge.succeeds() {
        result?;
    } else {
        assert_eq!(
            result.map_err(|error| error.to_string()),
            Err(CoreError::ArtifactUnavailable.to_string())
        );
    }
    if let Some(entity) = classification.shared_entity.filter(|_| edge.succeeds()) {
        for (registry, timeline) in [(&a, first), (&b, second)] {
            let snapshot = registry.state_snapshot(timeline)?;
            assert_eq!(snapshot["count"].len(), 1);
            assert_eq!(snapshot["count"].get(&entity), Some(&State::new()));
        }
    } else {
        assert_eq!(a.state_snapshot(first)?, before_a);
        assert_eq!(b.state_snapshot(second)?, before_b);
    }
    let arms = if matches!(consumer, Consumer::Compare) {
        2
    } else {
        1
    };
    let phases = if edge == Edge::ArmDepthShort { 0 } else { 2 };
    assert_eq!(verifier.admissions.load(Ordering::SeqCst), arms * phases);
    Ok(())
}

#[test]
fn explicit_ordinary_lineage_is_bounded_across_both_phases_and_compare_arms() -> TestResult {
    for consumer in [Consumer::Replay, Consumer::ReplayAt, Consumer::Compare] {
        for edge in [
            Edge::Exact,
            Edge::OneOver,
            Edge::BytesShort,
            Edge::RowsShort,
            Edge::VisitsShort,
            Edge::ArmDepthShort,
        ] {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("ordinary-lineage.sqlite");
            let path = path.to_str().ok_or("utf-8 path")?;
            for config in [
                StoreConfig::Memory,
                StoreConfig::SqliteInMemory,
                StoreConfig::Sqlite {
                    path: path.to_owned(),
                },
            ] {
                let sqlite = !matches!(&config, StoreConfig::Memory);
                let file_backed = matches!(&config, StoreConfig::Sqlite { .. });
                let verifier = Arc::new(OrdinaryVerifier::new());
                let composition = ErasureCoordinatorCompositionV1::closed()
                    .with_world_replay_verifier(verifier.clone());
                let mut host = ErasureExecutionHostV1::open_with_authority(
                    config,
                    &composition,
                    ErasureRecoveryLimitsV1::compiled_maximum(),
                )?;
                let (root, parent, arms, shared_entity) = seed(&mut host, consumer)?;
                let classification = Classification {
                    root,
                    parent,
                    arms,
                    shared_entity,
                    limits: limits(consumer, edge, sqlite)?,
                    arm_depth: if edge == Edge::ArmDepthShort { 1 } else { 8 },
                };
                exercise(host, classification, &verifier, consumer, edge).map_err(|error| {
                    format!("{consumer:?}/{edge:?}, sqlite={sqlite}, RW: {error}")
                })?;
                if file_backed {
                    let readonly = ErasureExecutionHostV1::open_read_only_with_authority(
                        path,
                        &composition,
                        ErasureRecoveryLimitsV1::compiled_maximum(),
                    )?;
                    exercise(readonly, classification, &verifier, consumer, edge)
                        .map_err(|error| format!("{consumer:?}/{edge:?}, SQLite RO: {error}"))?;
                }
            }
        }
    }
    Ok(())
}
