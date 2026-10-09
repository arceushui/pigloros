//! The adapter's in-memory, non-durable state and the host's handle on it.
//!
//! Everything here lives in process memory only. It is lost on restart and
//! is never an authoritative record: the Plugin state, the invocation
//! receipts and the quarantine are all non-durable until a follow-up (#560)
//! decides how to store them.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use pos_core::PluginId;
use pos_plugin_release::ContentValidationV1;
use pos_runtime::community_plugin_host::{
    quarantine_for, CommunityPassAuthorizationV1, CommunityPluginHostErrorV1,
    EffectiveExecutionLimitsV1, GuestPluginErrorV1, MeteringV1, NegotiatedCommunityPluginV1,
};
use pos_runtime::{PluginAvailabilityV1, PluginRegistry, RuntimeError};

/// The most receipts a handle retains; the oldest is dropped beyond it.
pub const MAX_RETAINED_RECEIPTS_V1: usize = 256;

/// One Plugin state value: its schema digest and canonical bytes.
///
/// Non-durable: the adapter holds it in memory and commits it only after the
/// whole scheduled batch commits. It is lost on restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityStateV1 {
    /// The state schema digest.
    pub schema: [u8; 32],
    /// The canonical state bytes, at most 1 MiB.
    pub bytes: Vec<u8>,
}

/// What became of one invocation's staged result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptDispositionV1 {
    /// Staged in the pending pass; the batch has not committed or aborted.
    Staged,
    /// The whole batch committed and the next state was adopted.
    Committed,
    /// Discarded: the pass aborted, or the invocation failed after the guest
    /// returned.
    Discarded,
}

/// In-memory record of one invocation that reached a worker (non-durable).
///
/// It holds what the follow-up `ReproManifest` record needs: the negotiated
/// tuple, the output digest, the effective limits and the metering. A failed
/// invocation keeps its receipt too, with the closed `failure` and, for a
/// guest-declared failure, the guest's exact `plugin-error` (code, field
/// ordinal and related digest). Nothing here is persisted or authoritative.
/// The effective limits fixed at negotiation are
/// [`CommunityInvocationReceiptV1::limits()`]; the profile digest the
/// invocation was bound to is `negotiated.execution_profile_digest()`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityInvocationReceiptV1 {
    /// The host-built invocation's ID.
    pub invocation_id: [u8; 16],
    /// The negotiated tuple: world, release, ABI, features, capabilities not
    /// granted, mode, limits and pinned runtime.
    pub negotiated: NegotiatedCommunityPluginV1,
    /// The V1 output digest the guest returned, or `None` when it returned
    /// its own `plugin-error` or no return at all.
    pub output_digest: Option<[u8; 32]>,
    /// The deterministic metering the worker reported, or `None` when the
    /// invocation ended without a report (a crash, a watchdog stop, an engine
    /// failure or a supervisor check).
    pub metering: Option<MeteringV1>,
    /// The number of trace annotations validated and then dropped.
    pub dropped_trace_annotations: usize,
    /// The closed host error that ended the invocation, if it failed.
    pub failure: Option<CommunityPluginHostErrorV1>,
    /// The guest's own `plugin-error`, kept exactly when `failure` is
    /// `GuestDeclaredFailure`.
    pub guest_error: Option<GuestPluginErrorV1>,
    /// What became of the staged result.
    pub disposition: ReceiptDispositionV1,
    /// What was checked about the release content: until #574 the constant
    /// `NotPerformed` (ADR-061 revision 7 decision 12).
    pub content_validation: ContentValidationV1,
}

impl CommunityInvocationReceiptV1 {
    /// The effective limits fixed at negotiation.
    #[must_use]
    pub const fn limits(&self) -> EffectiveExecutionLimitsV1 {
        self.negotiated.limits()
    }
}

#[derive(Debug)]
struct Inner {
    availability: PluginAvailabilityV1,
    last_failure: Option<CommunityPluginHostErrorV1>,
    receipts: VecDeque<CommunityInvocationReceiptV1>,
    committed: CommunityStateV1,
    /// The one-shot authorization offered for the current pass.
    slot: Option<CommunityPassAuthorizationV1>,
    /// The failure the current pass produced for this Plugin.
    pass_failure: Option<CommunityPluginHostErrorV1>,
    /// The invocation ID the Driver built for the current pass.
    pass_invocation_id: Option<[u8; 16]>,
}

/// State shared between one adapter and its host handle.
#[derive(Debug)]
pub(super) struct Shared {
    plugin_id: PluginId,
    inner: Mutex<Inner>,
}

impl Shared {
    pub(super) const fn new(plugin_id: PluginId, initial: CommunityStateV1) -> Self {
        Self {
            plugin_id,
            inner: Mutex::new(Inner {
                availability: PluginAvailabilityV1::Available,
                last_failure: None,
                receipts: VecDeque::new(),
                committed: initial,
                slot: None,
                pass_failure: None,
                pass_invocation_id: None,
            }),
        }
    }

    /// The lock, whose data stays consistent across a holder's panic because
    /// each update is made under one guard and leaves `Inner` valid at every
    /// panic point.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) const fn plugin_id(&self) -> PluginId {
        self.plugin_id
    }

    pub(super) fn availability(&self) -> PluginAvailabilityV1 {
        self.lock().availability
    }

    pub(super) fn committed_state(&self) -> CommunityStateV1 {
        self.lock().committed.clone()
    }

    /// Mark the failing Plugin, and quarantine it when the failure class
    /// quarantines. Another Plugin's state is never touched. The failure is
    /// also the current pass's.
    pub(super) fn record_failure(&self, error: CommunityPluginHostErrorV1) {
        let mut inner = self.lock();
        inner.last_failure = Some(error);
        inner.pass_failure = Some(error);
        if let Some(availability) = quarantine_for(error) {
            inner.availability = availability;
        }
    }

    /// Start a pass: forget the previous pass's failure and invocation ID, then
    /// keep `authorization` unless an earlier one still occupies the slot.
    pub(super) fn offer(
        &self,
        authorization: CommunityPassAuthorizationV1,
    ) -> Result<(), CommunityPluginHostErrorV1> {
        let mut inner = self.lock();
        inner.pass_failure = None;
        inner.pass_invocation_id = None;
        if inner.slot.is_some() {
            Err(CommunityPluginHostErrorV1::InvalidInvocation)
        } else {
            inner.slot = Some(authorization);
            Ok(())
        }
    }

    /// End a pass: drop an unconsumed authorization and the pass's failure and
    /// invocation ID.
    pub(super) fn close(&self) {
        let mut inner = self.lock();
        inner.slot = None;
        inner.pass_failure = None;
        inner.pass_invocation_id = None;
    }

    /// Read the offered authorization without taking it.
    pub(super) fn peek<T>(
        &self,
        read: impl FnOnce(&CommunityPassAuthorizationV1) -> T,
    ) -> Option<T> {
        self.lock().slot.as_ref().map(read)
    }

    /// Take the offered authorization: a launch consumes it.
    pub(super) fn take_authorization(&self) -> Option<CommunityPassAuthorizationV1> {
        self.lock().slot.take()
    }

    pub(super) fn set_invocation_id(&self, invocation_id: [u8; 16]) {
        self.lock().pass_invocation_id = Some(invocation_id);
    }

    pub(super) fn push_receipt(&self, receipt: CommunityInvocationReceiptV1) {
        let mut inner = self.lock();
        inner.receipts.push_back(receipt);
        if inner.receipts.len() > MAX_RETAINED_RECEIPTS_V1 {
            inner.receipts.pop_front();
        }
    }

    /// Adopt `state` and settle every staged receipt as committed.
    pub(super) fn commit(&self, state: CommunityStateV1) {
        let mut inner = self.lock();
        inner.committed = state;
        settle(&mut inner.receipts, ReceiptDispositionV1::Committed);
    }

    /// Settle every staged receipt as discarded.
    pub(super) fn discard(&self) {
        settle(&mut self.lock().receipts, ReceiptDispositionV1::Discarded);
    }

    fn clear(&self) {
        let mut inner = self.lock();
        inner.availability = PluginAvailabilityV1::Available;
        inner.last_failure = None;
    }
}

fn settle(
    receipts: &mut VecDeque<CommunityInvocationReceiptV1>,
    disposition: ReceiptDispositionV1,
) {
    receipts
        .iter_mut()
        .filter(|receipt| receipt.disposition == ReceiptDispositionV1::Staged)
        .for_each(|receipt| receipt.disposition = disposition);
}

/// The host's view of one community Plugin's in-memory adapter state.
///
/// Cloning shares the same state. Everything it reports is non-durable and
/// lost on restart: availability (the quarantine), the last failure, the
/// invocation receipts and the committed Plugin state.
///
/// A failure changes the handle's availability at once, but the registry only
/// learns it through [`Self::sync_registry()`]; the host calls that after every
/// pass. Until it does, the adapter itself already refuses to run.
#[derive(Clone, Debug)]
pub struct CommunityPluginHandleV1 {
    shared: Arc<Shared>,
}

impl CommunityPluginHandleV1 {
    pub(super) const fn new(shared: Arc<Shared>) -> Self {
        Self { shared }
    }

    /// The Plugin this handle belongs to.
    #[must_use]
    pub fn plugin_id(&self) -> PluginId {
        self.shared.plugin_id()
    }

    /// Whether the Plugin may run: `Available`, or the quarantine state a
    /// failure put it in (`Trapped`, `ResourceExhausted`, `Revoked` or, after
    /// a worker crash, `Unavailable`).
    #[must_use]
    pub fn availability(&self) -> PluginAvailabilityV1 {
        self.shared.availability()
    }

    /// The most recent failure of this Plugin, quarantining or not.
    ///
    /// A failure that does not quarantine leaves the Plugin available and
    /// only marks it here. Another Plugin's failure never appears.
    #[must_use]
    pub fn last_failure(&self) -> Option<CommunityPluginHostErrorV1> {
        self.shared.lock().last_failure
    }

    /// The retained invocation receipts, oldest first (non-durable).
    #[must_use]
    pub fn receipts(&self) -> Vec<CommunityInvocationReceiptV1> {
        self.shared.lock().receipts.iter().cloned().collect()
    }

    /// The newest retained receipt of the invocation `invocation_id`, if any.
    ///
    /// Fixtures reuse a constant ID, so the newest match wins (non-durable).
    #[must_use]
    pub fn receipt_for(&self, invocation_id: [u8; 16]) -> Option<CommunityInvocationReceiptV1> {
        self.shared
            .lock()
            .receipts
            .iter()
            .rev()
            .find(|receipt| receipt.invocation_id == invocation_id)
            .cloned()
    }

    /// The failure the current pass produced for this Plugin, if any.
    ///
    /// Set by [`Self::record_refusal()`] and by the Driver's own failure path;
    /// cleared by [`Self::offer_authorization()`] and [`Self::close_pass()`].
    /// It is distinct from [`Self::last_failure()`], which every failure sets
    /// and only [`Self::clear_quarantine()`] clears.
    #[must_use]
    pub fn pass_failure(&self) -> Option<CommunityPluginHostErrorV1> {
        self.shared.lock().pass_failure
    }

    /// The invocation ID the Driver built for the current pass, set once the
    /// host's context source has answered and cleared with the pass failure.
    #[must_use]
    pub fn pass_invocation_id(&self) -> Option<[u8; 16]> {
        self.shared.lock().pass_invocation_id
    }

    /// Offer this pass's one-shot authorization to the Driver.
    ///
    /// Starts the pass: the previous pass's failure and invocation ID are
    /// cleared first.
    ///
    /// # Errors
    /// Returns `InvalidInvocation` when an earlier authorization still occupies
    /// the slot; the earlier one is kept and `authorization` is dropped.
    pub fn offer_authorization(
        &self,
        authorization: CommunityPassAuthorizationV1,
    ) -> Result<(), CommunityPluginHostErrorV1> {
        self.shared.offer(authorization)
    }

    /// Record a failure the host raised for this Plugin outside `step`, as a
    /// failure raised inside `step` would be: it sets the last failure and the
    /// pass failure and applies the failure class's quarantine.
    pub fn record_refusal(&self, error: CommunityPluginHostErrorV1) {
        self.shared.record_failure(error);
    }

    /// End the pass: drop an unconsumed authorization and clear the pass
    /// failure and invocation ID.
    pub fn close_pass(&self) {
        self.shared.close();
    }

    /// The last committed Plugin state (non-durable).
    #[must_use]
    pub fn committed_state(&self) -> CommunityStateV1 {
        self.shared.committed_state()
    }

    /// Mirror this handle's availability into the registry.
    ///
    /// # Errors
    /// Returns the registry's composition error for an unregistered or
    /// unpinned Plugin.
    pub fn sync_registry(&self, registry: &mut PluginRegistry) -> Result<(), RuntimeError> {
        registry.set_availability(self.plugin_id(), self.availability())
    }

    /// Clear the quarantine and the last failure, in the registry and here.
    ///
    /// The registry is updated first, so a failure leaves both quarantined.
    ///
    /// # Errors
    /// Returns the registry's composition error for an unregistered or
    /// unpinned Plugin.
    pub fn clear_quarantine(&self, registry: &mut PluginRegistry) -> Result<(), RuntimeError> {
        registry
            .set_availability(self.plugin_id(), PluginAvailabilityV1::Available)
            .map(|()| self.shared.clear())
    }
}
