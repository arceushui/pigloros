//! Read-only native metadata and conservative ancestry visibility.

use super::MemoryStore;
use crate::{
    fork_replay::{
        corrupt, gate_error, remember_member, LineageReadContextV1, LineageReadResult as ReadResult,
    },
    ForkReplayLineageNodeV1, ForkReplayLineageReadErrorV1 as Error,
};
use pos_core::{ErasureGate, ErasureProtectedOperationV1, Seq, TimelineId};

impl MemoryStore {
    pub(super) fn read_lineage_member(
        &self,
        timeline: TimelineId,
        visited: &mut Vec<TimelineId>,
        context: &mut LineageReadContextV1<'_, '_>,
        validate_events: bool,
    ) -> ReadResult<Option<(ForkReplayLineageNodeV1, Seq)>> {
        self.with_replay_read_fence(timeline, context, |context| {
            self.lineage_metadata_and_visibility(timeline, visited, context, validate_events)
        })
    }

    pub(super) fn with_replay_read_fence<T>(
        &self,
        timeline: TimelineId,
        context: &mut LineageReadContextV1<'_, '_>,
        mut effect: impl FnMut(&mut LineageReadContextV1<'_, '_>) -> ReadResult<T>,
    ) -> ReadResult<T> {
        context.step(|context| {
            let gate = context.step(|_| {
                self.validated_erasure_gate()
                    .map_err(|_| Error::ContainmentUnavailable)
            })?;
            let mut result = Err(Error::ContainmentUnavailable);
            let fenced = gate.with_fence(timeline, ErasureProtectedOperationV1::Read, &mut || {
                result = effect(context);
            });
            context.check()?;
            context.step(|_| {
                crate::validate_bound_erasure_inventory_generation(
                    self.erasure_gate_bound,
                    &gate,
                    self.erasure_inventory_generation,
                )
                .map_err(|_| Error::ContainmentUnavailable)
            })?;
            fenced.map_err(gate_error).and(result)
        })
    }

    fn lineage_metadata_and_visibility(
        &self,
        timeline: TimelineId,
        visited: &mut Vec<TimelineId>,
        context: &mut LineageReadContextV1<'_, '_>,
        validate_events: bool,
    ) -> ReadResult<Option<(ForkReplayLineageNodeV1, Seq)>> {
        context.step(|context| {
            remember_member(timeline, visited, context)?;
            let Some(state) = self.timelines.get(&timeline) else {
                return if visited.len() == 1 {
                    Ok(None)
                } else {
                    corrupt()
                };
            };
            context.row()?;
            context.step(|_| {
                if state.timeline.id() == timeline {
                    Ok(())
                } else {
                    corrupt()
                }
            })?;
            context.bytes(if state.timeline.meta.fork_point.is_some() {
                49
            } else {
                25
            })?;
            let metadata = (
                ForkReplayLineageNodeV1::new(timeline, state.timeline.meta.fork_point),
                state.timeline.head,
            );
            context.check()?;
            if context.step(|_| Ok(self.geographic_timelines.contains(&timeline)))? {
                context.row()?;
                return Ok(None);
            }
            let mut cursor = Seq::ZERO;
            for (index, event) in state.events.iter().enumerate() {
                context.check()?;
                context.row()?;
                context.step(|_| {
                    if event.seq > cursor
                        && (!validate_events || index != 0 || event.seq == Seq::from_u64(1))
                    {
                        Ok(())
                    } else {
                        corrupt()
                    }
                })?;
                context.bytes(8)?;
                cursor = event.seq;
                if context.step(|_| Ok(pos_core::is_geographic_event_type(&event.event_type)))? {
                    return Ok(None);
                }
            }
            if validate_events {
                context.step(|_| {
                    let count = u64::try_from(state.events.len()).unwrap_or(u64::MAX);
                    if state.timeline.head == cursor && cursor.as_u64() == count {
                        Ok(())
                    } else {
                        corrupt()
                    }
                })?;
            }
            context.check().map(|()| Some(metadata))
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{
        ForkReplayAuthorityReadErrorV1, ForkReplayAuthorityReadPortV1, ForkReplayReadBudgetV1,
        ForkReplayReadLimitsV1,
    };
    use pos_core::{
        trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1},
        CanonicalBytes, EntityId, ErasureContainmentGateV1, EventDraft, EventStore, Kind,
    };
    use std::{sync::Arc, time::Duration};

    type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

    #[test]
    fn fixture_gate_transfer_refuses_real_and_missing_gates() -> Fallible<()> {
        for store in [
            MemoryStore::new(),
            MemoryStore::new().without_erasure_gate(),
        ] {
            assert!(matches!(
                store.detach_fixture_gate_for_host(),
                Err(pos_core::CoreError::ErasureContainmentUnavailable)
            ));
        }
        let mut store = MemoryStore::new();
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        let mut detached = store.detach_fixture_gate_for_host()?;
        let timeline = detached.create_timeline("unbound fixture")?.id();
        let draft = EventDraft::new(
            EntityId::new(),
            Kind::new("ordinary"),
            CanonicalBytes::from_static(b"fixture"),
        );
        assert!(matches!(
            detached.append(timeline, std::slice::from_ref(&draft)),
            Err(pos_core::CoreError::ErasureContainmentUnavailable)
        ));
        detached.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        assert_eq!(detached.append(timeline, &[draft])?.len(), 1);
        Ok(())
    }

    fn fixture() -> Fallible<(MemoryStore, TimelineId, TimelineId)> {
        let mut store = MemoryStore::new();
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        let root = store.create_timeline("memory lineage fault root")?.id();
        drop(store.append(
            root,
            &[EventDraft::new(
                EntityId::new(),
                Kind::new("ordinary"),
                CanonicalBytes::from_static(b"uninspected payload"),
            )],
        )?);
        let child = store
            .fork(root, Seq::from_u64(1), "memory lineage child")?
            .id();
        Ok((store, root, child))
    }

    fn read(
        store: &MemoryStore,
        timeline: TimelineId,
    ) -> Fallible<ReadResult<Option<ForkReplayLineageNodeV1>>> {
        let limits = ForkReplayReadLimitsV1::new(8, 128, 512, 16_384, 1_000_000)?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        Ok(store.read_fork_replay_lineage_node(timeline, 0, 8, &mut budget))
    }

    #[test]
    fn impossible_native_topology_is_refused_at_the_public_read_seam() -> Fallible<()> {
        for fault in 0..3 {
            let (mut store, _, child) = fixture()?;
            let state = store
                .timelines
                .get_mut(&child)
                .ok_or("child fixture missing")?;
            match fault {
                0 => state.timeline.meta.id = TimelineId::new(),
                1 => state.timeline.meta.fork_point = Some((TimelineId::new(), Seq::ZERO)),
                _ => state.timeline.meta.fork_point = Some((child, Seq::ZERO)),
            }
            assert_eq!(
                read(&store, child)?,
                Err(Error::Read(
                    ForkReplayAuthorityReadErrorV1::CorruptAuthority
                ))
            );
        }
        Ok(())
    }

    #[test]
    fn zero_and_duplicate_native_event_cursors_refuse_the_visible_child() -> Fallible<()> {
        for zero in [true, false] {
            let (mut store, root, child) = fixture()?;
            drop(store.append(
                root,
                &[EventDraft::new(
                    EntityId::new(),
                    Kind::new("ordinary"),
                    CanonicalBytes::from_static(b"second ordinary Event"),
                )],
            )?);
            assert!(read(&store, child)??.is_some());
            // Public append cannot create these impossible native orders.
            // Only the stored cursor is corrupted; the read still crosses
            // the public port with its real installed containment gate.
            let state = store.timelines.get_mut(&root).ok_or("root fixture")?;
            assert_eq!(state.events.len(), 2);
            for event in &mut state.events {
                event.seq = if zero { Seq::ZERO } else { Seq::from_u64(1) };
            }
            assert_eq!(
                read(&store, child)?,
                Err(Error::Read(
                    ForkReplayAuthorityReadErrorV1::CorruptAuthority
                ))
            );
        }
        Ok(())
    }

    #[test]
    fn late_ancestor_markers_and_actual_event_types_are_both_hidden() -> Fallible<()> {
        for marker in [true, false] {
            for kind in ["geo.cell", "geo.location"] {
                let (mut store, root, child) = fixture()?;
                if marker {
                    store.geographic_timelines.insert(root);
                } else {
                    let state = store
                        .timelines
                        .get_mut(&root)
                        .ok_or("root fixture missing")?;
                    let event = state
                        .events
                        .first_mut()
                        .ok_or("root Event fixture missing")?;
                    event.event_type = Kind::new(kind);
                }
                assert_eq!(read(&store, child)?, Ok(None));
            }
        }
        Ok(())
    }

    #[test]
    fn absent_containment_cannot_be_reinterpreted_as_a_missing_timeline() -> Fallible<()> {
        let (mut store, root, _) = fixture()?;
        store.erasure_gate = None;
        assert_eq!(read(&store, root)?, Err(Error::ContainmentUnavailable));
        Ok(())
    }

    fn complete_events(
        store: &MemoryStore,
        child: TimelineId,
    ) -> Fallible<ReadResult<Vec<pos_core::Event>>> {
        let limits = ForkReplayReadLimitsV1::new(8, 128, 512, 16_384, 1_000_000)?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        let bounds = pos_core::EventReadBounds::new_with_total_bytes_and_elapsed(
            128, 128, 8, 4, 1_024, 1_000_000,
        );
        Ok(store.read_fork_replay_events(child, pos_core::SeqRange::all(), bounds, &mut budget))
    }

    #[test]
    fn complete_event_reads_reject_corrupt_counts_origins_signatures_and_cuts() -> Fallible<()> {
        for fault in 0..6 {
            let (mut store, root, child) = fixture()?;
            assert_eq!(complete_events(&store, child)??.len(), 1);
            // Public writes cannot produce these states. Corrupt only the
            // retained field, then exercise the complete public read port.
            if fault == 5 {
                store
                    .timelines
                    .get_mut(&child)
                    .ok_or("child")?
                    .timeline
                    .meta
                    .fork_point = Some((root, Seq::from_u64(2)));
            } else {
                let state = store.timelines.get_mut(&root).ok_or("root")?;
                match fault {
                    0 => state.timeline.head = Seq::from_u64(2),
                    1 => state.events.clear(),
                    2 => state.events[0].origin = None,
                    3 => {
                        state.events[0].origin = Some(pos_core::EventOriginV1 {
                            origin_timeline_id: TimelineId::new(),
                            origin_logical_seq: Seq::from_u64(1),
                        });
                    }
                    _ => state.events[0].signature = Some(pos_core::Signature::from_bytes([0; 64])),
                }
            }
            assert_eq!(
                complete_events(&store, child)?,
                Err(Error::Read(
                    ForkReplayAuthorityReadErrorV1::CorruptAuthority
                )),
                "accepted corrupt native Event case {fault}",
            );
        }
        Ok(())
    }
}
