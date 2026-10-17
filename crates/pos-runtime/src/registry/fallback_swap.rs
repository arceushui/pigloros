//! The ADR-119 registry swap seams (section 4.4 steps 2, 3, 5 and 6).
//!
//! The composition boundary transaction runs in `pos-plugin-supervisor`
//! (slice 6), which holds both the registry and the community host. It uses
//! these registry-side seams:
//!
//! - [`PluginRegistry::prepare_pinned_generated_v1`]: every registration
//!   check of a candidate, with the primary excluded from the Event-type and
//!   role checks, and no mutation;
//! - [`PluginRegistry::validate_swap_v1`]: the registry side of the
//!   `validate_swap` dry run, including the capacity reservation;
//! - [`PluginRegistry::validate_recovery_prefix_v1`]: the prefix check every
//!   restore runs, for the pre-commit prefix read;
//! - [`PluginRegistry::swap_entry_v1`]: the candidate takes the primary's
//!   registry index, and nothing else changes;
//! - [`PluginRegistry::restore_entry_from_history_v1`]: the restore of the
//!   candidate's entry alone.
//!
//! A restart registers its candidate fresh, through
//! [`PluginRegistry::install_prepared_v1`] or the ordinary registration path.

use pos_core::{clock::Seq, event::Event, Kind, Plugin, PluginId};
use thiserror::Error;

use super::{
    driver_visible_event, pass_state, validate_recovery_evidence, PendingRegistrationCallbacksV1,
    PluginEntry, PluginRegistry, PreparedRegistrationV1, ReducerSlotV1, RegistrationOptions,
    StepChainV1,
};
use crate::composition::PluginRegistrationV1;
use crate::driver::{Driver, DriverRecoveryEvidence, TimelineHistorySegment};
use crate::error::RuntimeError;

/// Closed refusals of the ADR-119 registry swap seams (section 4.4).
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FallbackSwapRefusalV1 {
    /// The candidate is the primary it would replace.
    #[error("the fallback candidate is the primary it replaces")]
    SameAsPrimary,
    /// The prepared registration replaces no primary, so it cannot swap.
    #[error("the prepared registration replaces no primary")]
    NotReplacing,
    /// The prepared registration replaces a primary, so it cannot be
    /// installed next to it.
    #[error("a registration prepared to replace a primary cannot be installed")]
    NotInstallable,
    /// The registry changed after the registration was prepared.
    #[error("the registry changed after the registration was prepared")]
    StalePreparation,
    /// The primary is not registered.
    #[error("the replaced primary is not registered")]
    UnknownPrimary,
    /// The candidate does not own exactly the primary's Event types.
    #[error("the fallback candidate does not own exactly the primary's Event types")]
    OwnedTypesDiffer,
    /// The registry could not reserve the capacity the swap needs.
    #[error("the registry could not reserve capacity for the swap")]
    CapacityUnavailable,
    /// The candidate's `PluginId` is already registered.
    #[error("the fallback candidate is already registered")]
    CandidateRegistered,
}

impl PluginRegistry {
    /// Prepare a pinned local registration without mutating the registry.
    ///
    /// It runs every check of [`Self::register_pinned_generated`] with no
    /// reducer and no approver, and captures the Driver's observation. With
    /// `replacing = Some(primary)` (ADR-119 section 4.4 step 2), the
    /// exclusive Event-type and role checks ignore the primary's
    /// registration; the `PluginId` check does not.
    ///
    /// # Errors
    /// Returns [`FallbackSwapRefusalV1::SameAsPrimary`] when the Plugin is
    /// `replacing`, and otherwise the errors `register_pinned_generated`
    /// returns before any mutation.
    pub fn prepare_pinned_generated_v1(
        &self,
        plugin: &dyn Plugin,
        registration: PluginRegistrationV1,
        driver: Option<Box<dyn Driver>>,
        replacing: Option<PluginId>,
    ) -> Result<PreparedRegistrationV1, RuntimeError> {
        let callbacks = PendingRegistrationCallbacksV1 {
            driver,
            approver: None,
            approver_event_types: std::iter::empty(),
        };
        let options = RegistrationOptions {
            registration: Some(registration),
            output_admission: None,
            reducer_slot: ReducerSlotV1::ByPluginId,
            manifest_slot: None,
        };
        Self::generated_output_binding(plugin).and_then(|binding| {
            self.prepare_registration(plugin, binding, None, callbacks, options, replacing)
        })
    }

    /// Install a registration prepared with no primary to replace.
    ///
    /// # Errors
    /// Returns [`FallbackSwapRefusalV1::NotInstallable`] for a registration
    /// prepared to replace a primary, then
    /// [`FallbackSwapRefusalV1::StalePreparation`] when the registry changed
    /// after preparation, then the reducer-slot error of the ordinary path.
    pub fn install_prepared_v1(
        &mut self,
        prepared: PreparedRegistrationV1,
    ) -> Result<(), RuntimeError> {
        if prepared.replacing.is_some() {
            return Err(FallbackSwapRefusalV1::NotInstallable.into());
        }
        self.ensure_fresh(&prepared)?;
        self.install_prepared(prepared)
    }

    /// The registry side of the ADR-119 `validate_swap` dry run (section
    /// 4.4 step 3).
    ///
    /// It requires Live execution, no pending step, no in-doubt admission and
    /// no poisoned Driver; a registration prepared to replace a registered
    /// primary at the current registry revision; and owned Event types equal
    /// to the primary's. It then reserves one slot in the entry map and in the
    /// scheduled bindings, so the swap cannot fail on allocation. It changes
    /// no entry.
    ///
    /// The Implementation key (IMK1) checks, the host member lookup and the
    /// prefix read belong to the host-level `validate_swap`.
    ///
    /// # Errors
    /// Returns [`RuntimeError::ModeMismatch`] in Replay, the pending-step and
    /// poisoned-Driver errors, then [`FallbackSwapRefusalV1`] as
    /// [`RuntimeError::FallbackSwap`].
    pub fn validate_swap_v1(
        &mut self,
        prepared: &PreparedRegistrationV1,
    ) -> Result<(), RuntimeError> {
        self.swap_index(prepared).and(Ok(()))
    }

    /// Move `prepared` into the registry index of its primary (section 4.4
    /// step 5).
    ///
    /// The candidate's entry replaces the primary's at the same index, so the
    /// registration order is kept and Event-type ownership passes in one step.
    /// The primary's scheduled binding moves to the candidate and its last
    /// Tick is kept. The revision advances and the restored Fork binding is
    /// cleared. The schemas, projections, approver routes and every other
    /// entry are untouched, and the primary's entry and Driver are dropped.
    ///
    /// It re-runs [`Self::validate_swap_v1`] first, so after a successful dry
    /// run with no registry change in between it cannot fail.
    ///
    /// # Errors
    /// Returns the errors of [`Self::validate_swap_v1`], with nothing changed.
    pub fn swap_entry_v1(&mut self, prepared: PreparedRegistrationV1) -> Result<(), RuntimeError> {
        self.swap_index(&prepared)
            .and_then(|index| self.replace_entry(index, prepared))
    }

    /// Restore one entry from validated history (section 4.4 step 6).
    ///
    /// It validates the prefix as every restore does, then stages and commits
    /// only this entry's Driver restore. The entry's Event cursor moves to the
    /// restored head, its carried set is cleared, its history node is rebuilt
    /// and its step chain resolves by lookup. Every other entry is untouched,
    /// and the restored Fork binding is left cleared.
    ///
    /// # Errors
    /// Returns [`RuntimeError::ModeMismatch`] in Replay, the pending-step and
    /// poisoned-Driver errors, [`RuntimeError::InvalidRecoveryEvidence`],
    /// [`RuntimeError::NoDriver`] for an unregistered Plugin, the Driver's
    /// own staging error after it is aborted, or
    /// [`RuntimeError::DriverRestorePanicked`], which poisons the registry.
    pub fn restore_entry_from_history_v1(
        &mut self,
        plugin_id: PluginId,
        timeline_segments: &[TimelineHistorySegment],
        events: &[Event],
    ) -> Result<(), RuntimeError> {
        self.ensure_live_execution()?;
        self.ensure_no_pending_step()?;
        validate_recovery_evidence(timeline_segments, events)?;
        self.restore_entry_live(plugin_id, timeline_segments, events)
    }

    /// Validate a durable prefix exactly as every restore does, and restore
    /// nothing.
    ///
    /// # Errors
    /// Returns [`RuntimeError::InvalidRecoveryEvidence`] for an empty,
    /// duplicate or unordered ancestry, or Events that do not run
    /// contiguously from sequence 1 to the final Timeline bound.
    pub fn validate_recovery_prefix_v1(
        timeline_segments: &[TimelineHistorySegment],
        events: &[Event],
    ) -> Result<(), RuntimeError> {
        validate_recovery_evidence(timeline_segments, events)
    }

    /// Refuse a prepared registration older than the registry.
    const fn ensure_fresh(
        &self,
        prepared: &PreparedRegistrationV1,
    ) -> Result<(), FallbackSwapRefusalV1> {
        if prepared.revision == self.registration_revision {
            Ok(())
        } else {
            Err(FallbackSwapRefusalV1::StalePreparation)
        }
    }

    /// Every dry-run check, then the reservation; the primary's index.
    fn swap_index(&mut self, prepared: &PreparedRegistrationV1) -> Result<usize, RuntimeError> {
        self.ensure_live_execution()?;
        self.ensure_no_pending_step()?;
        let index = self.replaced_index(prepared)?;
        self.reserve_swap_capacity()
            .map(|()| index)
            .map_err(RuntimeError::from)
    }

    fn replaced_index(
        &self,
        prepared: &PreparedRegistrationV1,
    ) -> Result<usize, FallbackSwapRefusalV1> {
        let primary = prepared
            .replacing
            .ok_or(FallbackSwapRefusalV1::NotReplacing)?;
        self.ensure_fresh(prepared)?;
        let (index, _, entry) = self
            .plugins
            .get_full(&primary)
            .ok_or(FallbackSwapRefusalV1::UnknownPrimary)?;
        same_owned_types(&entry.owned_event_types, &prepared.owned_event_types)
            .then_some(index)
            .ok_or(FallbackSwapRefusalV1::OwnedTypesDiffer)
    }

    /// A successful `try_reserve(1)` leaves room for the one insert a swap
    /// may need, and erasing the old key consumes none of it.
    fn reserve_swap_capacity(&mut self) -> Result<(), FallbackSwapRefusalV1> {
        let refused = Err(FallbackSwapRefusalV1::CapacityUnavailable);
        let reserved = self.plugins.try_reserve(1).or(refused);
        reserved.and_then(|()| self.scheduled_profiles.try_reserve(1).or(refused))
    }

    fn replace_entry(
        &mut self,
        index: usize,
        prepared: PreparedRegistrationV1,
    ) -> Result<(), RuntimeError> {
        let replaced = self.plugins.replace_index(index, prepared.id);
        let registered = Err(RuntimeError::FallbackSwap(
            FallbackSwapRefusalV1::CandidateRegistered,
        ));
        replaced
            .map(|primary| self.move_entry(index, primary, prepared))
            .or(registered)
    }

    fn move_entry(&mut self, index: usize, primary: PluginId, prepared: PreparedRegistrationV1) {
        let candidate = prepared.id;
        let mut entry = prepared.into_parts().1;
        entry.last_tick = self.plugins[index].last_tick;
        self.plugins[index] = entry;
        self.move_binding(primary, candidate);
        self.registration_revision += 1;
        self.restored_binding = None;
    }

    /// The primary's scheduled binding, if it has one, moves to the candidate.
    fn move_binding(&mut self, primary: PluginId, candidate: PluginId) {
        if let Some(binding) = self.scheduled_profiles.remove(&primary) {
            self.scheduled_profiles.insert(candidate, binding);
        }
    }

    fn restore_entry_live(
        &mut self,
        plugin_id: PluginId,
        timeline_segments: &[TimelineHistorySegment],
        events: &[Event],
    ) -> Result<(), RuntimeError> {
        // Consent is host control-plane history: the Driver never sees it.
        let visible: Vec<Event> = events
            .iter()
            .filter(|event| driver_visible_event(event))
            .cloned()
            .collect();
        let restored_head = events.last().map_or(Seq::ZERO, |event| event.seq);
        let unknown = || RuntimeError::NoDriver {
            name: plugin_id.to_string(),
        };
        let entry = self.plugins.get_mut(&plugin_id).ok_or_else(unknown)?;
        let poisoned = &mut self.poisoned_driver;
        let restored =
            restore_entry_state(entry, poisoned, timeline_segments, &visible, restored_head);
        self.restored_binding = None;
        restored
    }
}

/// Restore one entry's Driver, if it has one, then reset its pass state to
/// the restored head.
fn restore_entry_state(
    entry: &mut PluginEntry,
    poisoned: &mut Option<String>,
    timeline_segments: &[TimelineHistorySegment],
    visible: &[Event],
    restored_head: Seq,
) -> Result<(), RuntimeError> {
    entry.driver.as_deref_mut().map_or(Ok(()), |driver| {
        restore_one_driver(driver, poisoned, timeline_segments, visible)
    })?;
    entry.event_cursor = restored_head;
    entry.pass_state.carried.clear();
    entry.pass_state.history = pass_state::restored_history(visible, restored_head);
    entry.chain = StepChainV1::Lookup;
    Ok(())
}

/// Stage, then commit, one Driver's restore. A staging error aborts the
/// stage; a commit panic poisons the registry.
fn restore_one_driver(
    driver: &mut dyn Driver,
    poisoned: &mut Option<String>,
    timeline_segments: &[TimelineHistorySegment],
    visible: &[Event],
) -> Result<(), RuntimeError> {
    let evidence = DriverRecoveryEvidence::from_events(timeline_segments, visible, |header| {
        driver.needs_recovery_payload(header)
    });
    driver
        .stage_restore_from_history(&evidence)
        .inspect_err(|_| driver.abort_restore_from_history())?;
    let name = driver.name().to_owned();
    let committed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        driver.commit_restore_from_history();
    }));
    committed.map_err(|_| {
        *poisoned = Some(name.clone());
        RuntimeError::DriverRestorePanicked { name }
    })
}

/// Whether two declarations own the same Event types. The ownership check
/// already refused a type listed twice in one declaration.
fn same_owned_types(left: &[Kind], right: &[Kind]) -> bool {
    left.len() == right.len() && left.iter().all(|kind| right.contains(kind))
}
