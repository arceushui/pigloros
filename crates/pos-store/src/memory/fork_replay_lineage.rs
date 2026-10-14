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
    ) -> ReadResult<Option<(ForkReplayLineageNodeV1, Seq)>> {
        context.step(|context| {
            let gate = context.step(|_| {
                self.validated_erasure_gate()
                    .map_err(|_| Error::ContainmentUnavailable)
            })?;
            let mut result = Err(Error::ContainmentUnavailable);
            let fenced = gate.with_fence(timeline, ErasureProtectedOperationV1::Read, &mut || {
                result = self.lineage_metadata_and_visibility(timeline, visited, context);
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
            for event in &state.events {
                context.check()?;
                context.row()?;
                context.step(|_| {
                    if event.seq > cursor {
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
}
