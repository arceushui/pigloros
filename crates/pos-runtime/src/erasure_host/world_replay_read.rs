//! ADR-118's owning read interval, gate nests and complete Event boundary.

use super::{finish_protected_effect_interval, map_fork_replay_lineage_error, ErasureReadSenderV1};
use crate::{PreparedWorldReplayReadV1, VerifiedWorldReplayV1};
use pos_core::{
    ErasureHostErrorV1 as Error, ErasureProtectedEffectDispositionV1 as Disposition,
    ErasureProtectedEffectIntervalV1 as Interval, Event, TimelineId,
};
use pos_store::ForkReplayReadBudgetV1;
use std::sync::Arc;

#[cfg(any(test, feature = "test-support"))]
use crate::world_replay::test_support::{record_replay_phase, ObservedGateV1, ReplayPhaseV1};

type Result<T> = std::result::Result<T, Error>;

fn checkpoint(budget: &mut ForkReplayReadBudgetV1<'_>) -> Result<()> {
    budget.check_time().map_err(|_| Error::AdapterFailure)
}

/// The native adapters return exclusively owned, already-funded plaintext.
/// A failed Runtime post-check or unwind must scrub that plaintext too.
struct EventBatchV1(Vec<Event>);

impl Drop for EventBatchV1 {
    fn drop(&mut self) {
        let scrubbed = pos_core::store::zeroize_event_plaintext_staging(&mut self.0);
        debug_assert!(scrubbed);
    }
}

impl ErasureReadSenderV1<'_> {
    /// Materialize an authoritative use through the same original ledger.
    ///
    /// Reobserves its actual head before allocation and checks complete count
    /// and contiguous logical coordinates. Store owns every native byte debit.
    ///
    /// # Errors
    /// Refuses exhausted budgets, stale or non-authoritative capabilities,
    /// changed heads, incomplete reads and any native containment failure.
    pub fn read_world_replay_events(
        &mut self,
        verified: &VerifiedWorldReplayV1,
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> Result<Vec<Event>> {
        checkpoint(budget)?;
        self.host.ensure_generation(self.generation)?;
        if verified.inventory_generation() != self.generation {
            return Err(Error::StaleGeneration);
        }
        if verified.fork_read_limits() != budget.limits() || !verified.has_finite_read_bounds() {
            return Err(Error::Conflict);
        }
        verified
            .require_authoritative_use()
            .map_err(super::map_world_replay_verification_error)?;
        let cap = verified
            .read_bounds()
            .max_fork_depth()
            .min(budget.limits().max_fork_depth_per_traversal());
        let head = self.host.store.host_store().fork_replay_logical_head(
            verified.timeline_id(),
            cap,
            budget,
        );
        checkpoint(budget)?;
        let head = head.map_err(map_fork_replay_lineage_error)?.as_u64();
        let (first, count) = checked_range(verified, head)?;
        let result = self
            .host
            .store
            .host_store()
            .read_fork_replay_events(
                verified.timeline_id(),
                verified.requested_use().range(),
                verified.read_bounds(),
                budget,
            )
            .map(EventBatchV1);
        checkpoint(budget)?;
        let mut events = result.map_err(map_fork_replay_lineage_error)?;
        let complete = (|| {
            if events.0.len() != count {
                return Err(Error::AdapterFailure);
            }
            for (index, event) in events.0.iter().enumerate() {
                checkpoint(budget)?;
                let expected = u64::try_from(index)
                    .ok()
                    .and_then(|index| first.checked_add(index));
                if expected != Some(event.seq.as_u64()) {
                    return Err(Error::AdapterFailure);
                }
            }
            Ok(())
        })();
        checkpoint(budget).and(complete)?;
        Ok(std::mem::take(&mut events.0))
    }

    /// Own one operation's native interval and every arm/ancestor gate.
    ///
    /// `prepare` may return only detached State and its held Time guard.
    /// `complete` may return an error only before installing State. A successful
    /// install is followed solely by inert owned read-interval rollback;
    /// uncertain cleanup poisons the host without rewriting installed success.
    ///
    /// # Errors
    /// Refuses invalid/stale preparation, exhausted budgets, inaccessible
    /// ancestry and any preinstall failure. Cleanup uncertainty poisons the host.
    pub fn with_world_replay_read_fence<'clock, T, P, C>(
        &mut self,
        prepared: &[&PreparedWorldReplayReadV1],
        budget: &mut ForkReplayReadBudgetV1<'clock>,
        prepare: P,
        complete: C,
    ) -> Result<()>
    where
        P: FnOnce(&mut Self, &mut ForkReplayReadBudgetV1<'clock>) -> Result<T>,
        C: FnOnce(T, Result<()>) -> Result<()>,
    {
        checkpoint(budget)?;
        if !(1..=2).contains(&prepared.len()) {
            return Err(Error::Conflict);
        }
        for arm in prepared {
            self.require_prepared_world_replay(arm, budget)?;
        }
        let acquired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.host
                .store
                .host_store()
                .begin_fork_replay_read_interval(budget)
        }));
        let acquired = match acquired {
            Ok(result) => result,
            Err(payload) => {
                // Store cleans any partially acquired native resources before
                // resuming. Runtime must close even when setup itself unwinds.
                self.host.poison();
                std::panic::resume_unwind(payload)
            }
        };
        let interval = match acquired {
            Ok(interval) => interval,
            Err(error) => {
                let post = checkpoint(budget);
                if error
                    == pos_store::ForkReplayLineageReadErrorV1::Read(
                        pos_store::ForkReplayAuthorityReadErrorV1::StorageUnavailable,
                    )
                {
                    self.host.poison();
                }
                return post.and_then(|()| Err(map_fork_replay_lineage_error(error)));
            }
        };
        let mut fence = ReadFenceV1 {
            prepared,
            budget,
            interval: Some(interval),
            visited: Vec::new(),
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            checkpoint(fence.budget)?;
            fence.arm(self, 0, (prepare, complete))
        }));
        match result {
            Ok(result) => {
                if fence.interval.is_some() {
                    // Only a preinstall path can retain an unsettled token.
                    let post = checkpoint(fence.budget);
                    fence.rollback(self).and(post).and(result)
                } else {
                    result
                }
            }
            Err(payload) => {
                // Rollback handles its error by poisoning. Unwind additionally
                // poisons even when cleanup succeeds, then resumes unchanged.
                match fence.rollback(self) {
                    Ok(()) | Err(_) => {
                        self.host.poison();
                        std::panic::resume_unwind(payload)
                    }
                }
            }
        }
    }
}

fn checked_range(verified: &VerifiedWorldReplayV1, head: u64) -> Result<(u64, usize)> {
    let requested = verified.requested_use();
    let range = requested.range();
    let first = range.from.as_u64().max(1);
    let last = range.to.map_or(head, pos_core::Seq::as_u64);
    if requested.source_logical_head().as_u64() != head
        || first > head.saturating_add(1)
        || last > head
    {
        return Err(Error::AdapterFailure);
    }
    let count = if first > last { 0 } else { last - (first - 1) };
    let count = usize::try_from(count).map_err(|_| Error::AdapterFailure)?;
    if count > verified.read_bounds().max_events() {
        return Err(Error::AdapterFailure);
    }
    Ok((first, count))
}

struct ReadFenceV1<'prepared, 'budget, 'clock> {
    prepared: &'prepared [&'prepared PreparedWorldReplayReadV1],
    budget: &'budget mut ForkReplayReadBudgetV1<'clock>,
    interval: Option<Interval>,
    visited: Vec<TimelineId>,
}

impl<'clock> ReadFenceV1<'_, '_, 'clock> {
    fn rollback(&mut self, sender: &mut ErasureReadSenderV1<'_>) -> Result<()> {
        #[cfg(any(test, feature = "test-support"))]
        if self.interval == Some(Interval::Owned) {
            record_replay_phase(ReplayPhaseV1::BeforeRollback);
        }
        if self.interval.take() == Some(Interval::Owned) {
            let result = finish_protected_effect_interval(
                sender.host,
                Interval::Owned,
                Disposition::Rollback,
            );
            #[cfg(any(test, feature = "test-support"))]
            record_replay_phase(ReplayPhaseV1::AfterRollback);
            result
        } else {
            Ok(())
        }
    }

    fn arm<'host, T, P, C>(
        &mut self,
        sender: &mut ErasureReadSenderV1<'host>,
        index: usize,
        callbacks: (P, C),
    ) -> Result<()>
    where
        P: FnOnce(
            &mut ErasureReadSenderV1<'host>,
            &mut ForkReplayReadBudgetV1<'clock>,
        ) -> Result<T>,
        C: FnOnce(T, Result<()>) -> Result<()>,
    {
        if let Some(prepared) = self.prepared.get(index) {
            self.member(
                sender,
                (index, self.visited.len()),
                prepared.intent().timeline_id(),
                callbacks,
            )
        } else {
            let (prepare, complete) = callbacks;
            let staged = prepare(sender, self.budget);
            #[cfg(any(test, feature = "test-support"))]
            if staged.is_ok() {
                record_replay_phase(ReplayPhaseV1::Staged);
            }
            let verdict = checkpoint(self.budget);
            match staged {
                Err(error) => self.rollback(sender).and(verdict).and(Err(error)),
                Ok(staged) => {
                    if let Err(error) = verdict {
                        let verdict = self.rollback(sender).and(Err(error));
                        complete(staged, verdict).and(verdict)
                    } else {
                        #[cfg(any(test, feature = "test-support"))]
                        record_replay_phase(ReplayPhaseV1::BeforeComplete);
                        let installed = complete(staged, Ok(()));
                        #[cfg(any(test, feature = "test-support"))]
                        if installed.is_ok() {
                            record_replay_phase(ReplayPhaseV1::Installed);
                        }
                        let cleanup = self.rollback(sender);
                        match installed {
                            Ok(()) => match cleanup {
                                // rollback already permanently poisoned the
                                // host on Err; installed success stays final.
                                Ok(()) | Err(_) => Ok(()),
                            },
                            Err(error) => cleanup.and(Err(error)),
                        }
                    }
                }
            }
        }
    }

    fn member<'host, T, P, C>(
        &mut self,
        sender: &mut ErasureReadSenderV1<'host>,
        (arm, start): (usize, usize),
        timeline: TimelineId,
        callbacks: (P, C),
    ) -> Result<()>
    where
        P: FnOnce(
            &mut ErasureReadSenderV1<'host>,
            &mut ForkReplayReadBudgetV1<'clock>,
        ) -> Result<T>,
        C: FnOnce(T, Result<()>) -> Result<()>,
    {
        checkpoint(self.budget)?;
        let prepared = self.prepared[arm];
        let gate = Arc::clone(&sender.host.gate);
        gate.with_fence_value(timeline, prepared.intent().operation(), || {
            #[cfg(any(test, feature = "test-support"))]
            let _observed_gate = ObservedGateV1::enter(timeline);
            for previous in &self.visited[start..] {
                checkpoint(self.budget)?;
                let cycle = *previous == timeline;
                checkpoint(self.budget)?;
                if cycle {
                    return Err(Error::AdapterFailure);
                }
            }
            let depth = self.visited.len() - start;
            let cap = prepared
                .read_bounds()
                .max_fork_depth()
                .min(self.budget.limits().max_fork_depth_per_traversal());
            let node = sender
                .host
                .store
                .host_store()
                .read_fork_replay_lineage_node(timeline, depth, cap, self.budget);
            checkpoint(self.budget)?;
            let node = node
                .map_err(map_fork_replay_lineage_error)?
                .ok_or(Error::AdapterFailure)?;
            if node.timeline_id() != &timeline {
                return Err(Error::AdapterFailure);
            }
            self.budget
                .charge_bytes(16)
                .map_err(|_| Error::AdapterFailure)?;
            self.visited.push(timeline);
            if let Some((parent, _)) = node.fork_point() {
                self.budget
                    .charge_bytes(16)
                    .map_err(|_| Error::AdapterFailure)?;
                self.member(sender, (arm, start), *parent, callbacks)
            } else {
                self.arm(sender, arm + 1, callbacks)
            }
        })
        .map_err(Error::from)?
    }
}
