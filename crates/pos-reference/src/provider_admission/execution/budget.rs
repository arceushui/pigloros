//! One lock for source buffers, payload bytes and live policy intersections.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use super::{ProviderExecutionPolicy, StagingError};
use crate::provider_admission::AdmittedAuthority;

/// Provider-owned configuration; per-attempt limits never come from configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StagingLimits {
    /// Q9.7 aggregate bound for every retained source, input and output byte.
    pub aggregate_bytes: u64,
}

/// Lowest dispatchable revocation/policy epochs; restored by #442 before activation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlFloor {
    /// Lowest dispatchable revocation epoch.
    pub revocation_epoch: u64,
    /// Lowest dispatchable policy epoch.
    pub policy_epoch: u64,
}

/// Consistent accounting snapshot. Zero counters are an empty, inactive ledger.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StagingUsage {
    /// Every live source/payload byte reservation.
    pub reserved_bytes: u64,
    /// Source exchanges before their policy is derived.
    pub pending_controls: u64,
    /// Incomplete input transfers.
    pub queued_inputs: u64,
    /// Live attempts, including retained output reservations.
    pub attempts: u64,
    /// Failed unlink operations; any nonzero value permanently closes admission.
    pub leaked_files: u64,
    /// Current control floor.
    pub floor: ControlFloor,
}

#[derive(Debug, Default)]
struct State {
    usage: StagingUsage,
    queue_ceilings: BTreeMap<u64, u64>,
    attempt_ceilings: BTreeMap<u64, u64>,
}

impl State {
    const fn ensure_open(&self) -> Result<(), StagingError> {
        if self.usage.leaked_files == 0 {
            Ok(())
        } else {
            Err(StagingError::CleanupFailed)
        }
    }
}

#[derive(Debug)]
struct Shared {
    maximum: u64,
    state: Mutex<State>,
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn total(&self, state: &State, bytes: u64) -> Result<u64, StagingError> {
        state.ensure_open().and_then(|()| {
            state
                .usage
                .reserved_bytes
                .checked_add(bytes)
                .filter(|total| *total <= self.maximum)
                .ok_or(StagingError::AggregateExceeded)
        })
    }
}

/// Shared, provider-owned staging accounting. This does not activate a listener.
#[derive(Clone, Debug)]
pub struct StagingLedger {
    shared: Arc<Shared>,
}

impl StagingLedger {
    /// Create an empty ledger with the owner's exact Q9.7 aggregate ceiling.
    #[must_use]
    pub fn new(limits: StagingLimits) -> Self {
        Self {
            shared: Arc::new(Shared {
                maximum: limits.aggregate_bytes,
                state: Mutex::new(State::default()),
            }),
        }
    }

    /// Current counters and control floor, read together.
    #[must_use]
    pub fn usage(&self) -> StagingUsage {
        self.shared.state().usage
    }

    /// Raise each floor component without weakening an earlier one.
    pub fn raise_floor(&self, floor: ControlFloor) {
        let mut state = self.shared.state();
        state.usage.floor.revocation_epoch = state
            .usage
            .floor
            .revocation_epoch
            .max(floor.revocation_epoch);
        state.usage.floor.policy_epoch = state.usage.floor.policy_epoch.max(floor.policy_epoch);
    }

    /// Charge private storage only; this value grants no admission or input proof.
    ///
    /// # Errors
    /// Refuses a closed ledger or a checked aggregate sum above the owner's cap.
    pub fn reserve_storage(&self, bytes: u64) -> Result<StagingCharge, StagingError> {
        let mut state = self.shared.state();
        state.usage.reserved_bytes = self.shared.total(&state, bytes)?;
        drop(state);
        Ok(self.charge(bytes, None, None))
    }

    pub(super) fn control(&self, bhc_slots: u64) -> Result<ControlSlot, StagingError> {
        let mut state = self.shared.state();
        state.ensure_open()?;
        if state.usage.pending_controls >= bhc_slots.min(256) {
            return Err(StagingError::ControlSlotsExhausted);
        }
        state.usage.pending_controls += 1;
        drop(state);
        Ok(ControlSlot(Arc::clone(&self.shared)))
    }

    pub(super) fn prepare(
        &self,
        authority: AdmittedAuthority,
        policy: &ProviderExecutionPolicy,
    ) -> Result<(Arc<AttemptSlot>, StagingCharge), StagingError> {
        self.prepare_with(
            authority,
            ReservationPolicy {
                bytes: policy.input.byte_length,
                input_ceiling: policy.limit(7),
                attempt_ceiling: policy.limit(13),
                queue_ceiling: policy.limit(14),
            },
        )
    }

    fn prepare_with(
        &self,
        authority: AdmittedAuthority,
        policy: ReservationPolicy,
    ) -> Result<(Arc<AttemptSlot>, StagingCharge), StagingError> {
        let ReservationPolicy {
            bytes,
            input_ceiling,
            attempt_ceiling,
            queue_ceiling,
        } = policy;
        if bytes > input_ceiling {
            return Err(StagingError::InputTooLarge);
        }
        let mut state = self.shared.state();
        state.ensure_open()?;
        check_floor(state.usage.floor, authority)?;
        if state.usage.attempts >= intersection(&state.attempt_ceilings, attempt_ceiling) {
            return Err(StagingError::AttemptsExhausted);
        }
        if state.usage.queued_inputs >= intersection(&state.queue_ceilings, queue_ceiling) {
            return Err(StagingError::QueueFull);
        }
        let total = self.shared.total(&state, bytes)?;
        state.usage.reserved_bytes = total;
        state.usage.attempts += 1;
        state.usage.queued_inputs += 1;
        *state.attempt_ceilings.entry(attempt_ceiling).or_default() += 1;
        *state.queue_ceilings.entry(queue_ceiling).or_default() += 1;
        drop(state);
        let slot = Arc::new(AttemptSlot {
            shared: Arc::clone(&self.shared),
            ceiling: attempt_ceiling,
            output_claimed: Mutex::new(false),
        });
        Ok((slot, self.charge(bytes, Some(queue_ceiling), None)))
    }

    fn charge(
        &self,
        bytes: u64,
        queued: Option<u64>,
        attempt: Option<Arc<AttemptSlot>>,
    ) -> StagingCharge {
        StagingCharge(Arc::new(Charge {
            shared: Arc::clone(&self.shared),
            bytes,
            queued: Mutex::new(queued),
            _attempt: attempt,
            #[cfg(test)]
            before_release: Mutex::new(None),
        }))
    }
}

#[derive(Clone, Copy)]
struct ReservationPolicy {
    bytes: u64,
    input_ceiling: u64,
    attempt_ceiling: u64,
    queue_ceiling: u64,
}

fn intersection(ceilings: &BTreeMap<u64, u64>, candidate: u64) -> u64 {
    ceilings
        .first_key_value()
        .map_or(candidate, |(ceiling, _)| candidate.min(*ceiling))
}

fn remove_ceiling(ceilings: &mut BTreeMap<u64, u64>, ceiling: u64) {
    // Only a successfully inserted, uniquely owned reservation calls this.
    ceilings.entry(ceiling).and_modify(|count| *count -= 1);
    ceilings.retain(|_, count| *count != 0);
}

pub(super) const fn check_floor(
    floor: ControlFloor,
    authority: AdmittedAuthority,
) -> Result<(), StagingError> {
    if authority.revocation_epoch < floor.revocation_epoch
        || authority.policy_epoch < floor.policy_epoch
    {
        Err(StagingError::BelowControlFloor)
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct ControlSlot(Arc<Shared>);

impl Drop for ControlSlot {
    fn drop(&mut self) {
        self.0.state().usage.pending_controls -= 1;
    }
}

#[derive(Debug)]
pub(super) struct AttemptSlot {
    shared: Arc<Shared>,
    ceiling: u64,
    output_claimed: Mutex<bool>,
}

impl AttemptSlot {
    pub(super) fn recheck(&self, authority: AdmittedAuthority) -> Result<(), StagingError> {
        let state = self.shared.state();
        state
            .ensure_open()
            .and_then(|()| check_floor(state.usage.floor, authority))
    }

    pub(super) fn output(
        self: &Arc<Self>,
        policy: &ProviderExecutionPolicy,
        bytes: u64,
    ) -> Result<StagingCharge, StagingError> {
        self.output_with_limit(policy.limit(8), bytes)
    }

    fn output_with_limit(
        self: &Arc<Self>,
        ceiling: u64,
        bytes: u64,
    ) -> Result<StagingCharge, StagingError> {
        if bytes > ceiling {
            return Err(StagingError::OutputTooLarge);
        }
        let mut state = self.shared.state();
        let mut claimed = self
            .output_claimed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *claimed {
            return Err(StagingError::OutputAlreadyReserved);
        }
        let total = self.shared.total(&state, bytes)?;
        *claimed = true;
        state.usage.reserved_bytes = total;
        drop((state, claimed));
        Ok(StagingLedger {
            shared: Arc::clone(&self.shared),
        }
        .charge(bytes, None, Some(Arc::clone(self))))
    }
}

impl Drop for AttemptSlot {
    fn drop(&mut self) {
        let mut state = self.shared.state();
        state.usage.attempts -= 1;
        remove_ceiling(&mut state.attempt_ceilings, self.ceiling);
    }
}

#[derive(Debug)]
struct Charge {
    shared: Arc<Shared>,
    bytes: u64,
    queued: Mutex<Option<u64>>,
    _attempt: Option<Arc<AttemptSlot>>,
    #[cfg(test)]
    before_release: Mutex<Option<ReleaseProbe>>,
}

#[cfg(test)]
type ReleaseProbe = (std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>);

/// Shared byte ownership. Cloning keeps the same charge alive; it grants no authority.
#[derive(Clone, Debug)]
pub struct StagingCharge(Arc<Charge>);

impl StagingCharge {
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(super) fn before_release_for_test(
        &self,
        reached: std::sync::mpsc::Sender<()>,
        proceed: std::sync::mpsc::Receiver<()>,
    ) {
        *self
            .0
            .before_release
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some((reached, proceed));
    }

    /// Close all live-ledger admission before a possibly residual file's charge drops.
    ///
    /// This live ledger cannot be reopened by dropping reservations or raising floors.
    /// Lifecycle reconciliation must prove cleanup before installing a fresh ledger.
    pub fn record_leak(&self) {
        let mut state = self.0.shared.state();
        state.usage.leaked_files = state.usage.leaked_files.saturating_add(1);
    }

    pub(super) fn recheck(&self) -> Result<(), StagingError> {
        self.0.shared.state().ensure_open()
    }

    pub(super) fn finish_input(&self) {
        let mut state = self.0.shared.state();
        let mut queued = self.0.queued.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(ceiling) = queued.take() {
            state.usage.queued_inputs -= 1;
            remove_ceiling(&mut state.queue_ceilings, ceiling);
        }
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        #[cfg(test)]
        self.wait_before_release_for_test();

        let mut state = self.shared.state();
        state.usage.reserved_bytes -= self.bytes;
        if let Some(ceiling) = self
            .queued
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            state.usage.queued_inputs -= 1;
            remove_ceiling(&mut state.queue_ceilings, ceiling);
        }
    }
}

impl Charge {
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn wait_before_release_for_test(&mut self) {
        let Some((reached, proceed)) = self
            .before_release
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        else {
            return;
        };
        if reached.send(()).is_ok() {
            let _resume_result = proceed.recv_timeout(std::time::Duration::from_secs(30));
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn new_ledger(bytes: u64) -> StagingLedger {
        StagingLedger::new(StagingLimits {
            aggregate_bytes: bytes,
        })
    }

    fn authority(revocation_epoch: u64, policy_epoch: u64) -> AdmittedAuthority {
        AdmittedAuthority {
            apt1_digest: [1; 32],
            trs1_digest: [2; 32],
            rvs1_digest: [3; 32],
            trust_epoch: 1,
            revocation_epoch,
            policy_epoch,
        }
    }

    fn policy(bytes: u64, attempts: u64, queue: u64) -> ReservationPolicy {
        ReservationPolicy {
            bytes,
            input_ceiling: 100,
            attempt_ceiling: attempts,
            queue_ceiling: queue,
        }
    }

    #[test]
    fn all_reservations_publish_atomically_and_release_once() -> TestResult {
        let ledger = new_ledger(100);
        let (slot, input) = ledger.prepare_with(authority(1, 1), policy(60, 2, 2))?;
        let before = ledger.usage();
        assert!(matches!(
            ledger.prepare_with(authority(1, 1), policy(41, 2, 2)),
            Err(StagingError::AggregateExceeded)
        ));
        assert_eq!(ledger.usage(), before);
        let (other, second) = ledger.prepare_with(authority(1, 1), policy(40, 2, 2))?;
        assert!(matches!(
            ledger.prepare_with(authority(1, 1), policy(0, 100, 100)),
            Err(StagingError::AttemptsExhausted)
        ));
        input.finish_input();
        input.finish_input();
        assert_eq!(ledger.usage().queued_inputs, 1);
        assert_eq!(ledger.usage().reserved_bytes, 100);
        let clone = input.clone();
        drop(input);
        assert_eq!(ledger.usage().reserved_bytes, 100);
        drop((clone, slot, other, second));
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }

    #[test]
    fn a_looser_candidate_cannot_weaken_any_live_global_ceiling() -> TestResult {
        let ledger = new_ledger(100);
        let (strict, input) = ledger.prepare_with(authority(1, 1), policy(0, 1, 100))?;
        assert!(matches!(
            ledger.prepare_with(authority(1, 1), policy(0, 100, 100)),
            Err(StagingError::AttemptsExhausted)
        ));
        drop((strict, input));
        let (first, queued) = ledger.prepare_with(authority(1, 1), policy(0, 100, 1))?;
        let before = ledger.usage();
        assert!(matches!(
            ledger.prepare_with(authority(1, 1), policy(0, 100, 100)),
            Err(StagingError::QueueFull)
        ));
        assert_eq!(ledger.usage(), before);
        queued.finish_input();
        let (second, input) = ledger.prepare_with(authority(1, 1), policy(0, 100, 100))?;
        assert_eq!(ledger.usage().attempts, 2);
        drop((first, queued, second, input));
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }

    #[test]
    fn candidate_zero_and_lower_ceilings_are_literal() -> TestResult {
        let ledger = new_ledger(100);
        assert!(matches!(
            ledger.prepare_with(authority(1, 1), policy(0, 0, 100)),
            Err(StagingError::AttemptsExhausted)
        ));
        assert!(matches!(
            ledger.prepare_with(authority(1, 1), policy(0, 100, 0)),
            Err(StagingError::QueueFull)
        ));
        let (slot, input) = ledger.prepare_with(authority(1, 1), policy(0, 100, 100))?;
        assert!(matches!(
            ledger.prepare_with(authority(1, 1), policy(0, 1, 100)),
            Err(StagingError::AttemptsExhausted)
        ));
        assert!(matches!(
            ledger.prepare_with(authority(1, 1), policy(0, 100, 1)),
            Err(StagingError::QueueFull)
        ));
        drop((slot, input));
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }

    #[test]
    fn input_and_output_limits_and_overflow_change_no_accounting() -> TestResult {
        let ledger = new_ledger(u64::MAX);
        assert!(matches!(
            ledger.prepare_with(authority(1, 1), policy(101, 1, 1)),
            Err(StagingError::InputTooLarge)
        ));
        let (slot, input) = ledger.prepare_with(authority(1, 1), policy(1, 1, 1))?;
        let before = ledger.usage();
        assert!(matches!(
            slot.output_with_limit(2, 3),
            Err(StagingError::OutputTooLarge)
        ));
        assert!(matches!(
            slot.output_with_limit(u64::MAX, u64::MAX),
            Err(StagingError::AggregateExceeded)
        ));
        assert_eq!(ledger.usage(), before);
        input.finish_input();
        let output = slot.output_with_limit(2, 2)?;
        assert!(matches!(
            slot.output_with_limit(2, 0),
            Err(StagingError::OutputAlreadyReserved)
        ));
        assert_eq!(ledger.usage().attempts, 1);
        drop((slot, input));
        assert_eq!(ledger.usage().attempts, 1);
        assert_eq!(ledger.usage().reserved_bytes, 2);
        drop(output);
        assert_eq!(ledger.usage(), StagingUsage::default());
        let zero = new_ledger(0);
        assert!(matches!(
            zero.reserve_storage(1),
            Err(StagingError::AggregateExceeded)
        ));
        let empty = zero.reserve_storage(0)?;
        drop(empty);
        Ok(())
    }

    #[test]
    fn control_slots_are_separate_bhc_bounded_and_released() -> TestResult {
        let ledger = new_ledger(0);
        assert!(matches!(
            ledger.control(0),
            Err(StagingError::ControlSlotsExhausted)
        ));
        let first = ledger.control(1)?;
        assert!(matches!(
            ledger.control(1),
            Err(StagingError::ControlSlotsExhausted)
        ));
        assert_eq!(ledger.usage().attempts, 0);
        drop(first);
        let slots = (0..256)
            .map(|_| ledger.control(u64::MAX))
            .collect::<Result<Vec<_>, _>>()?;
        assert!(matches!(
            ledger.control(u64::MAX),
            Err(StagingError::ControlSlotsExhausted)
        ));
        drop(slots);
        assert_eq!(ledger.usage(), StagingUsage::default());
        Ok(())
    }

    #[test]
    fn floor_only_rises_and_is_checked_for_reservation_and_dispatch() -> TestResult {
        let ledger = new_ledger(10);
        ledger.raise_floor(ControlFloor {
            revocation_epoch: 5,
            policy_epoch: 7,
        });
        ledger.raise_floor(ControlFloor {
            revocation_epoch: 3,
            policy_epoch: 9,
        });
        assert_eq!(
            ledger.usage().floor,
            ControlFloor {
                revocation_epoch: 5,
                policy_epoch: 9
            }
        );
        for authority in [authority(4, 9), authority(5, 8)] {
            assert!(matches!(
                ledger.prepare_with(authority, policy(0, 1, 1)),
                Err(StagingError::BelowControlFloor)
            ));
        }
        let (slot, input) = ledger.prepare_with(authority(5, 9), policy(1, 1, 1))?;
        slot.recheck(authority(5, 9))?;
        ledger.raise_floor(ControlFloor {
            revocation_epoch: 6,
            policy_epoch: 0,
        });
        assert!(matches!(
            slot.recheck(authority(5, 9)),
            Err(StagingError::BelowControlFloor)
        ));
        drop((slot, input));
        assert_eq!(ledger.usage().attempts, 0);
        Ok(())
    }

    #[test]
    fn cleanup_failure_closes_every_admission_path_after_reservations_drop() -> TestResult {
        let ledger = new_ledger(100);
        let (slot, input) = ledger.prepare_with(authority(1, 1), policy(5, 2, 2))?;
        let storage = ledger.reserve_storage(1)?;
        storage.record_leak();
        assert!(matches!(
            ledger.control(2),
            Err(StagingError::CleanupFailed)
        ));
        assert!(matches!(
            ledger.reserve_storage(0),
            Err(StagingError::CleanupFailed)
        ));
        assert!(matches!(
            ledger.prepare_with(authority(1, 1), policy(0, 2, 2)),
            Err(StagingError::CleanupFailed)
        ));
        assert!(matches!(
            slot.recheck(authority(1, 1)),
            Err(StagingError::CleanupFailed)
        ));
        assert!(matches!(
            slot.output_with_limit(1, 1),
            Err(StagingError::CleanupFailed)
        ));
        assert!(matches!(input.recheck(), Err(StagingError::CleanupFailed)));
        drop((slot, input, storage));
        ledger.raise_floor(ControlFloor {
            revocation_epoch: 2,
            policy_epoch: 2,
        });
        assert_eq!(ledger.usage().reserved_bytes, 0);
        assert_eq!(ledger.usage().attempts, 0);
        assert_eq!(ledger.usage().queued_inputs, 0);
        assert_eq!(ledger.usage().leaked_files, 1);
        assert!(matches!(
            ledger.reserve_storage(0),
            Err(StagingError::CleanupFailed)
        ));
        assert!(matches!(
            ledger.control(2),
            Err(StagingError::CleanupFailed)
        ));
        Ok(())
    }

    #[test]
    fn poisoned_accounting_and_transfer_locks_preserve_owned_release() -> TestResult {
        let ledger = new_ledger(100);
        let (slot, input) = ledger.prepare_with(authority(1, 1), policy(5, 2, 2))?;
        let shared = Arc::clone(&ledger.shared);
        assert!(std::thread::spawn(move || {
            let _guard = shared.state.lock();
            std::panic::resume_unwind(Box::new(()));
        })
        .join()
        .is_err());
        let clone = input.clone();
        assert!(std::thread::spawn(move || {
            let _guard = clone.0.queued.lock();
            std::panic::resume_unwind(Box::new(()));
        })
        .join()
        .is_err());
        input.finish_input();
        let output = slot.output_with_limit(0, 0)?;
        input.record_leak();
        drop((slot, input, output));
        assert_eq!(ledger.usage().reserved_bytes, 0);
        assert_eq!(ledger.usage().attempts, 0);
        assert_eq!(ledger.usage().leaked_files, 1);
        Ok(())
    }
}
