//! Private original-g0 context and grow-as-visited lineage traversal.

use super::{
    ForkReplayAuthorityReadErrorV1 as ReadError, ForkReplayLineageNodeV1,
    ForkReplayLineageReadErrorV1 as Error, ForkReplayReadBudgetV1,
};
use pos_core::{ErasureContainmentErrorV1, Seq, TimelineId};

pub type ReadResult<T> = Result<T, Error>;

pub struct LineageReadContextV1<'budget, 'clock> {
    budget: &'budget mut ForkReplayReadBudgetV1<'clock>,
    cap: usize,
}

impl<'budget, 'clock> LineageReadContextV1<'budget, 'clock> {
    pub(crate) fn new(
        budget: &'budget mut ForkReplayReadBudgetV1<'clock>,
        cap: usize,
    ) -> ReadResult<Self> {
        budget.check_time().map_err(Error::Read)?;
        budget
            .accept(cap <= budget.limits().max_fork_depth_per_traversal())
            .map_err(Error::Read)?;
        Ok(Self { budget, cap })
    }

    pub(crate) fn check(&mut self) -> ReadResult<()> {
        self.budget.check_time().map_err(Error::Read)
    }

    /// Always post-check a completed batch, including failed native work.
    pub(crate) fn step<T>(
        &mut self,
        effect: impl FnOnce(&mut Self) -> ReadResult<T>,
    ) -> ReadResult<T> {
        self.check().and_then(|()| {
            let result = effect(self);
            self.check().and(result)
        })
    }

    pub(crate) fn bytes(&mut self, bytes: usize) -> ReadResult<()> {
        self.budget.charge_bytes(bytes).map_err(Error::Read)
    }

    pub(crate) fn row(&mut self) -> ReadResult<()> {
        self.budget.charge_rows(1).map_err(Error::Read)
    }

    fn node(&mut self, depth: Option<usize>) -> ReadResult<()> {
        self.check().and_then(|()| {
            if let Some(depth) = depth.filter(|depth| *depth <= self.cap) {
                self.budget.charge_node(depth).map_err(Error::Read)
            } else {
                self.budget.accept(false).map_err(Error::Read)
            }
        })
    }
}

pub const fn corrupt<T>() -> ReadResult<T> {
    Err(Error::Read(ReadError::CorruptAuthority))
}

pub const fn gate_error(error: ErasureContainmentErrorV1) -> Error {
    match error {
        ErasureContainmentErrorV1::AccessFrozen => Error::AccessFrozen,
        ErasureContainmentErrorV1::RecoveryUnavailable => Error::ContainmentUnavailable,
    }
}

/// Runs every member inside its adapter's Read fence. The borrowed prefix is
/// checked and the ID inserted only after the gate grants access.
pub fn read_visible_lineage(
    target: TimelineId,
    depth: usize,
    context: &mut LineageReadContextV1<'_, '_>,
    mut member: impl FnMut(
        TimelineId,
        &mut Vec<TimelineId>,
        &mut LineageReadContextV1<'_, '_>,
    ) -> ReadResult<Option<(ForkReplayLineageNodeV1, Seq)>>,
) -> ReadResult<Option<ForkReplayLineageNodeV1>> {
    context.step(|context| {
        let mut visited = Vec::new();
        let mut current = target;
        let mut result = None;
        loop {
            context.node(depth.checked_add(visited.len()))?;
            let metadata = member(current, &mut visited, context)?;
            let Some((node, _head)) = metadata else {
                return Ok(None);
            };
            let parent = node.fork_point();
            let next = parent
                .map(|(parent, _)| context.bytes(16).map(|()| *parent))
                .transpose()?;
            if result.is_none() {
                result = Some(node);
            }
            if let Some(parent) = next {
                current = parent;
            } else {
                return Ok(result);
            }
        }
    })
}

pub fn remember_member(
    timeline: TimelineId,
    visited: &mut Vec<TimelineId>,
    context: &mut LineageReadContextV1<'_, '_>,
) -> ReadResult<()> {
    for previous in visited.iter() {
        context.step(|_| if *previous == timeline { corrupt() } else { Ok(()) })?;
    }
    context.bytes(16)?;
    visited.push(timeline);
    context.check()
}
