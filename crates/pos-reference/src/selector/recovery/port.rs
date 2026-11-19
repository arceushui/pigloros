//! The recovery operations of the provider lifecycle port: their targets and
//! observations (ADR-069 R12 §4.2).
//!
//! Only [`super::ProviderTerminationAuthority`] builds a target, from one
//! loaded [`super::PendingRecoveryTarget`] and a fresh challenge. The adapter
//! reads a target and reports an observation, which it builds through a
//! public constructor. An observation is never a proof: the authority checks
//! each one against its target and against the kernel before it mints one.

use std::marker::PhantomData;
use std::num::NonZeroU64;
use std::time::Duration;

use crate::selector::runtime_lifecycle::{CgroupPath, ObservationChallenge};

/// The previous runtime the adapter must terminate and reconcile (R12 §7.1).
///
/// The adapter terminates by lifecycle scope, never by PID (owner decision
/// O5), so the target carries no PID.
#[derive(Debug)]
pub struct PreviousRuntimeTarget<'a> {
    challenge: ObservationChallenge,
    provider_id: &'a str,
    provider_binary_digest: [u8; 32],
    runtime_instance_id: [u8; 16],
    lifecycle_scope_id: [u8; 16],
    recovery_lifecycle_scope_id: [u8; 16],
    previous_live_attempt_ids: &'a [[u8; 16]],
}

/// The identities a [`PreviousRuntimeTarget`] names, as SIR1 records them.
pub(super) struct PreviousRuntimeIds {
    pub(super) provider_binary_digest: [u8; 32],
    pub(super) runtime_instance_id: [u8; 16],
    pub(super) lifecycle_scope_id: [u8; 16],
    pub(super) recovery_lifecycle_scope_id: [u8; 16],
}

impl<'a> PreviousRuntimeTarget<'a> {
    pub(super) const fn new(
        challenge: ObservationChallenge,
        provider_id: &'a str,
        ids: &PreviousRuntimeIds,
        previous_live_attempt_ids: &'a [[u8; 16]],
    ) -> Self {
        Self {
            challenge,
            provider_id,
            provider_binary_digest: ids.provider_binary_digest,
            runtime_instance_id: ids.runtime_instance_id,
            lifecycle_scope_id: ids.lifecycle_scope_id,
            recovery_lifecycle_scope_id: ids.recovery_lifecycle_scope_id,
            previous_live_attempt_ids,
        }
    }

    /// A target for adapter tests in other crates.
    #[cfg(any(test, feature = "test-support"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[doc(hidden)]
    #[must_use]
    pub const fn for_test(
        challenge: ObservationChallenge,
        provider_id: &'a str,
        [runtime_instance_id, lifecycle_scope_id, recovery_lifecycle_scope_id]: [[u8; 16]; 3],
        previous_live_attempt_ids: &'a [[u8; 16]],
    ) -> Self {
        Self {
            challenge,
            provider_id,
            provider_binary_digest: [0; 32],
            runtime_instance_id,
            lifecycle_scope_id,
            recovery_lifecycle_scope_id,
            previous_live_attempt_ids,
        }
    }

    /// The challenge the observation must echo.
    #[must_use]
    pub const fn challenge(&self) -> ObservationChallenge {
        self.challenge
    }

    /// The previous provider's SPM1 provider ID.
    #[must_use]
    pub const fn provider_id(&self) -> &'a str {
        self.provider_id
    }

    /// The SIR1 previous-provider binary digest.
    #[must_use]
    pub const fn provider_binary_digest(&self) -> [u8; 32] {
        self.provider_binary_digest
    }

    /// The SIR1 previous runtime-instance ID.
    #[must_use]
    pub const fn runtime_instance_id(&self) -> [u8; 16] {
        self.runtime_instance_id
    }

    /// The SIR1 previous lifecycle-scope ID, which names the runtime unit.
    #[must_use]
    pub const fn lifecycle_scope_id(&self) -> [u8; 16] {
        self.lifecycle_scope_id
    }

    /// The SIR1 recovery-peer lifecycle-scope ID: the one recovery unit that
    /// may be loaded besides the runtime unit (R12 §7.1 step 2).
    #[must_use]
    pub const fn recovery_lifecycle_scope_id(&self) -> [u8; 16] {
        self.recovery_lifecycle_scope_id
    }

    /// The complete SIR1 previous-live attempt set, in canonical order.
    #[must_use]
    pub const fn previous_live_attempt_ids(&self) -> &'a [[u8; 16]] {
        self.previous_live_attempt_ids
    }
}

/// The SIR1 recovery-peer slot the adapter must reconcile (R12 §7.3).
#[derive(Debug)]
pub struct RecoverySlotTarget<'a> {
    challenge: ObservationChallenge,
    recovery_lifecycle_scope_id: [u8; 16],
    pending: PhantomData<&'a ()>,
}

impl RecoverySlotTarget<'_> {
    pub(super) const fn new(
        challenge: ObservationChallenge,
        recovery_lifecycle_scope_id: [u8; 16],
    ) -> Self {
        Self {
            challenge,
            recovery_lifecycle_scope_id,
            pending: PhantomData,
        }
    }

    /// A target for adapter tests in other crates.
    #[cfg(any(test, feature = "test-support"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[doc(hidden)]
    #[must_use]
    pub const fn for_test(
        challenge: ObservationChallenge,
        recovery_lifecycle_scope_id: [u8; 16],
    ) -> Self {
        Self::new(challenge, recovery_lifecycle_scope_id)
    }

    /// The challenge the observation must echo.
    #[must_use]
    pub const fn challenge(&self) -> ObservationChallenge {
        self.challenge
    }

    /// The SIR1 recovery-peer lifecycle-scope ID, which names the peer unit.
    #[must_use]
    pub const fn recovery_lifecycle_scope_id(&self) -> [u8; 16] {
        self.recovery_lifecycle_scope_id
    }
}

/// The previous provider binary, re-hashed by the authority to the SIR1
/// binary digest just before the one peer start (R12 §6 step 6).
#[derive(Debug)]
pub struct VerifiedProviderBinary {
    path: String,
    digest: [u8; 32],
}

impl VerifiedProviderBinary {
    pub(super) const fn new(path: String, digest: [u8; 32]) -> Self {
        Self { path, digest }
    }

    /// A binary for adapter tests in other crates.
    #[cfg(any(test, feature = "test-support"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[doc(hidden)]
    #[must_use]
    pub const fn for_test(path: String, digest: [u8; 32]) -> Self {
        Self::new(path, digest)
    }

    /// The SIC1 kind-11 object path, the same path the runtime unit uses.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The BLAKE3 content digest, equal to the SIR1 binary digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// The one recovery-peer start the authority authorized (R12 §6 step 7).
#[derive(Debug)]
pub struct RecoveryPeerLaunch<'a> {
    slot: RecoverySlotTarget<'a>,
    recovery_endpoint_id: [u8; 16],
    provider_binary: &'a VerifiedProviderBinary,
}

impl<'a> RecoveryPeerLaunch<'a> {
    pub(super) const fn new(
        slot: RecoverySlotTarget<'a>,
        recovery_endpoint_id: [u8; 16],
        provider_binary: &'a VerifiedProviderBinary,
    ) -> Self {
        Self {
            slot,
            recovery_endpoint_id,
            provider_binary,
        }
    }

    /// A launch for adapter tests in other crates.
    #[cfg(any(test, feature = "test-support"))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[doc(hidden)]
    #[must_use]
    pub const fn for_test(
        slot: RecoverySlotTarget<'a>,
        recovery_endpoint_id: [u8; 16],
        provider_binary: &'a VerifiedProviderBinary,
    ) -> Self {
        Self::new(slot, recovery_endpoint_id, provider_binary)
    }

    /// The challenge the observation must echo: the slot's.
    #[must_use]
    pub const fn challenge(&self) -> ObservationChallenge {
        self.slot.challenge
    }

    /// The slot whose unit the adapter starts.
    #[must_use]
    pub const fn slot(&self) -> &RecoverySlotTarget<'a> {
        &self.slot
    }

    /// The SIR1 recovery-endpoint ID, the peer's only argument.
    #[must_use]
    pub const fn recovery_endpoint_id(&self) -> [u8; 16] {
        self.recovery_endpoint_id
    }

    /// The previous provider binary object; the authority re-hashed it to
    /// the SIR1 digest.
    #[must_use]
    pub const fn provider_binary(&self) -> &'a VerifiedProviderBinary {
        self.provider_binary
    }
}

/// What the adapter reports after it terminated and reconciled the previous
/// runtime. `Ok` means every resource of the target is proven absent; any
/// residue is an `Err`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviousRuntimeObservation {
    challenge: ObservationChallenge,
    lifecycle_scope_id: [u8; 16],
    control_group: CgroupPath,
    reconciled_attempt_ids: Vec<[u8; 16]>,
    activation_wait: Duration,
}

impl PreviousRuntimeObservation {
    /// Record one completed termination as the adapter observed it, with
    /// the #1200 D2 recent-activation wait its cleanup applied (zero
    /// without a recent activation).
    #[must_use]
    pub const fn new(
        challenge: ObservationChallenge,
        lifecycle_scope_id: [u8; 16],
        control_group: CgroupPath,
        reconciled_attempt_ids: Vec<[u8; 16]>,
        activation_wait: Duration,
    ) -> Self {
        Self {
            challenge,
            lifecycle_scope_id,
            control_group,
            reconciled_attempt_ids,
            activation_wait,
        }
    }

    /// The recent-activation wait the cleanup applied beyond its deadline.
    #[must_use]
    pub const fn activation_wait(&self) -> Duration {
        self.activation_wait
    }

    /// The echoed challenge.
    #[must_use]
    pub const fn challenge(&self) -> ObservationChallenge {
        self.challenge
    }

    /// The lifecycle-scope ID of the terminated runtime unit.
    #[must_use]
    pub const fn lifecycle_scope_id(&self) -> [u8; 16] {
        self.lifecycle_scope_id
    }

    /// The terminated runtime unit's control group.
    #[must_use]
    pub const fn control_group(&self) -> &CgroupPath {
        &self.control_group
    }

    /// The previous runtime's attempts that reconciliation removed.
    #[must_use]
    pub fn reconciled_attempt_ids(&self) -> &[[u8; 16]] {
        &self.reconciled_attempt_ids
    }
}

/// What the adapter reports after it reconciled the recovery-peer slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverySlotObservation {
    challenge: ObservationChallenge,
    recovery_lifecycle_scope_id: [u8; 16],
    control_group: CgroupPath,
}

impl RecoverySlotObservation {
    /// Record one reconciled slot as the adapter observed it.
    #[must_use]
    pub const fn new(
        challenge: ObservationChallenge,
        recovery_lifecycle_scope_id: [u8; 16],
        control_group: CgroupPath,
    ) -> Self {
        Self {
            challenge,
            recovery_lifecycle_scope_id,
            control_group,
        }
    }

    /// The echoed challenge.
    #[must_use]
    pub const fn challenge(&self) -> ObservationChallenge {
        self.challenge
    }

    /// The lifecycle-scope ID of the reconciled peer unit.
    #[must_use]
    pub const fn recovery_lifecycle_scope_id(&self) -> [u8; 16] {
        self.recovery_lifecycle_scope_id
    }

    /// The peer unit's control group.
    #[must_use]
    pub const fn control_group(&self) -> &CgroupPath {
        &self.control_group
    }
}

/// What the adapter reports after it started the peer and saw it ready.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPeerObservation {
    challenge: ObservationChallenge,
    recovery_lifecycle_scope_id: [u8; 16],
    main_pid: NonZeroU64,
    main_start_time_ticks: u64,
    control_group: CgroupPath,
}

impl RecoveryPeerObservation {
    /// Record one started peer as the adapter observed it.
    #[must_use]
    pub const fn new(
        challenge: ObservationChallenge,
        recovery_lifecycle_scope_id: [u8; 16],
        main_pid: NonZeroU64,
        main_start_time_ticks: u64,
        control_group: CgroupPath,
    ) -> Self {
        Self {
            challenge,
            recovery_lifecycle_scope_id,
            main_pid,
            main_start_time_ticks,
            control_group,
        }
    }

    /// The echoed challenge.
    #[must_use]
    pub const fn challenge(&self) -> ObservationChallenge {
        self.challenge
    }

    /// The lifecycle-scope ID of the started peer unit.
    #[must_use]
    pub const fn recovery_lifecycle_scope_id(&self) -> [u8; 16] {
        self.recovery_lifecycle_scope_id
    }

    /// The peer unit's reported `MainPID`.
    #[must_use]
    pub const fn main_pid(&self) -> NonZeroU64 {
        self.main_pid
    }

    /// The peer's `/proc/<pid>/stat` start-time ticks.
    #[must_use]
    pub const fn main_start_time_ticks(&self) -> u64 {
        self.main_start_time_ticks
    }

    /// The peer unit's reported `ControlGroup`.
    #[must_use]
    pub const fn control_group(&self) -> &CgroupPath {
        &self.control_group
    }
}
