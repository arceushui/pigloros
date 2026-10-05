//! ADR-112 trusted-clock protected-use fence.
//!
//! A protected Replay or `ReproManifest` release first commits a durable
//! reservation sample `t_r` with `synchronous=FULL`, decides against the bound
//! `D = t_r + 32 s`, and then hands a fully staged in-memory value over inside
//! the guard only when a fresh sample `t_f` satisfies
//! `max(t_r, high_water) <= t_f <= D` and no more than 30 s of monotonic time
//! has elapsed since `g0`.
//!
//! Every check and every value lives in this module. Storage adapters implement
//! [`TrustedClockStorePortV1`] and [`ReleaseGuardPortV1`] and only report raw rows
//! and lock state. Those two ports are trusted-host interfaces: hosted CI
//! rejects implementations outside `pos-store`, `pos-runtime` and `test-support`
//! fixtures.
//!
//! The handoff token cannot be constructed outside this module:
//!
//! ```compile_fail,E0451
//! let _token = pos_core::trusted_clock::HandoffTokenV1 { _private: () };
//! ```
//!
//! ```compile_fail,E0624
//! let _token = pos_core::trusted_clock::HandoffTokenV1::mint();
//! ```
//!
//! Staged output exposes no accessor:
//!
//! ```compile_fail,E0616
//! use pos_core::trusted_clock::{StagedArtifactBytesV1, StagedProtectedOutputV1};
//! let staged = StagedProtectedOutputV1::stage(StagedArtifactBytesV1::new(vec![1]));
//! let _bytes = staged.value;
//! ```
//!
//! Handoff targets and time sources are sealed:
//!
//! ```compile_fail,E0277
//! struct Forged;
//! impl pos_core::trusted_clock::ProtectedHandoffTargetV1 for Forged {
//!     type Committed = ();
//!     fn commit(self, _token: pos_core::trusted_clock::HandoffTokenV1) {}
//! }
//! ```
//!
//! ```compile_fail,E0277
//! use pos_core::trusted_clock::{TrustedClockErrorV1, TrustedWallSourceV1};
//! struct Forged;
//! impl TrustedWallSourceV1 for Forged {
//!     fn sample(&mut self) -> Result<pos_core::WallTime, TrustedClockErrorV1> {
//!         Ok(pos_core::WallTime::from_micros(0))
//!     }
//! }
//! ```
//!
//! A target cannot be committed without a token:
//!
//! ```compile_fail,E0061
//! use pos_core::trusted_clock::{ProtectedHandoffTargetV1, StagedArtifactBytesV1};
//! let _bytes = StagedArtifactBytesV1::new(vec![1]).commit();
//! ```
//!
//! Fence values cannot be forged:
//!
//! ```compile_fail,E0451
//! let _expiries = pos_core::trusted_clock::ApplicableExpiriesV1 {
//!     domain: [0; 16],
//!     reservation_seq: 0,
//!     earliest: u64::MAX,
//! };
//! ```
//!
//! ```compile_fail,E0451
//! let _use = pos_core::trusted_clock::AuthorizedArtifactUseV1 { value: (), overrun: None };
//! ```
//!
//! ```compile_fail,E0451
//! let _reservation = pos_core::trusted_clock::TrustedClockReservationV1 {
//!     domain: [0; 16],
//!     seq: 0,
//!     sampled: 0,
//!     decision_bound: i64::MAX,
//!     g0: todo!(),
//! };
//! ```
//!
//! ```compile_fail,E0451
//! let _guard = pos_core::trusted_clock::ReleaseGuardV1 {
//!     port: todo!(),
//!     reservation: todo!(),
//!     high_water: 0,
//! };
//! ```
//!
//! ```compile_fail,E0277
//! struct Forged;
//! impl pos_core::trusted_clock::GuardMonotonicSourceV1 for Forged {
//!     fn mark(&mut self) -> pos_core::trusted_clock::MonotonicMarkV1 {
//!         todo!()
//!     }
//! }
//! ```

use crate::authority::{AuthenticatedPrincipalResultV1, ConsentGrantRefV1, PrincipalRefV1};
use crate::consent::ConsentGrantedV1;
use crate::retention::WorldRetentionLeaseV1;
use crate::{Hash, WallTime};
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Safety margin `M` added to the guard budget.
pub const TRUSTED_CLOCK_MARGIN: Duration = Duration::from_secs(2);
/// Monotonic guard budget measured from `g0`.
pub const TRUSTED_CLOCK_GUARD_BUDGET: Duration = Duration::from_secs(30);
/// Reservation window `W`, the guard budget plus the margin.
pub const TRUSTED_CLOCK_RESERVATION_WINDOW: Duration = Duration::from_secs(32);
/// Total wait shared by owner locks, the reservation and the guard.
pub const TRUSTED_CLOCK_WAIT_BUDGET: Duration = Duration::from_millis(250);
/// The only record format version V1 accepts.
pub const TRUSTED_CLOCK_FORMAT_VERSION_V1: i64 = 1;
/// Payload-free health signal emitted for a post-handoff overrun.
pub const TRUSTED_CLOCK_FENCE_OVERRUN_SIGNAL: &str = "trusted_clock_fence_overrun";
/// Health signal stating that protected release is latched closed.
pub const PROTECTED_RELEASE_LATCHED_SIGNAL: &str = "protected_release_latched";

const RESERVATION_WINDOW_MICROS: i64 = 32_000_000;
const MICROS_PER_SECOND: u64 = 1_000_000;
const MAX_TRUSTED_MICROS: u64 = i64::MAX.unsigned_abs();
const PRINCIPAL_DIGEST_DOMAIN: &[u8] = b"pigloros.trusted-clock.operator-principal.v1\0";

/// Seal shared with [`crate::staged_install`] and
/// [`crate::manifest_owner_link_verifier`], whose handoff targets must be
/// declared beside it (ADR-113 §2).
pub(crate) mod sealed {
    pub trait Sealed {}
}

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

/// Phase charged when the shared 250 ms wait budget runs out.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum WaitPhaseV1 {
    /// Owner shared-lock acquisition before the reservation.
    OwnerLocks,
    /// The reservation's `BEGIN IMMEDIATE`.
    Reservation,
    /// The guard's `BEGIN IMMEDIATE` or shared `MemoryStore` lock.
    Guard,
}

/// Closed fail-closed outcomes of the trusted-clock fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TrustedClockErrorV1 {
    /// Wall-source error, pre-epoch value, or a value above `i64::MAX` microseconds.
    SourceUnavailable,
    /// A record row is missing in an initialized catalog.
    HighWaterMissing,
    /// A record row failed a constraint, could not be decoded, or is duplicated.
    HighWaterCorrupt,
    /// A record carries a format version other than 1.
    UnsupportedFormat,
    /// A sample regressed below the durable high-water or monotonic time regressed.
    Rollback,
    /// The guard re-read observed another domain, a lower sequence or a lower high-water.
    AuthorityRegressed,
    /// The shared wait budget ran out in the given phase.
    WaitBudgetExceeded(WaitPhaseV1),
    /// The durability pragmas could not be verified, or the authority store failed.
    DurabilityUnavailable,
    /// The reservation could not be committed.
    ReservationCommitFailed,
    /// Checked arithmetic overflowed.
    Overflow,
    /// An applicable expiry is not known.
    ExpiryUnknown,
    /// The decision bound reaches an applicable expiry.
    Expired,
    /// The final check is outside the enforced window.
    WindowExceeded,
    /// Protected release is latched closed after an overrun.
    OverrunLatched,
    /// The acknowledgement does not name the current overrun count.
    StaleAcknowledgement,
    /// The operator is not authorized to acknowledge the overrun.
    AcknowledgementUnauthorized,
}

impl std::fmt::Display for TrustedClockErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "trusted-clock fence unavailable: {self:?}")
    }
}

impl std::error::Error for TrustedClockErrorV1 {}

/// Raw failure reported by a trusted-clock storage or guard port.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TrustedClockPortErrorV1 {
    /// The authority lock was not acquired within the supplied timeout.
    Busy,
    /// Any other storage failure.
    Storage,
    /// A stored row was read but could not be decoded into its record type.
    Corrupt,
}

/// Kind of a detected post-handoff overrun.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TrustedClockOverrunKindV1 {
    /// Monotonic time since `g0` exceeded 32 s after the handoff.
    MonotonicBudgetExceeded,
    /// The post-handoff wall sample was beyond `D` or unavailable.
    WallBeyondDecisionBound,
    /// Monotonic time regressed after the handoff.
    MonotonicRegression,
}

impl TrustedClockOverrunKindV1 {
    /// Stable `last_overrun_kind` record code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::MonotonicBudgetExceeded => 1,
            Self::WallBeyondDecisionBound => 2,
            Self::MonotonicRegression => 3,
        }
    }
}

/// Recorded reason of an operator overrun acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OverrunAckReasonV1 {
    /// An investigated benign stall.
    BenignStall,
    /// A host suspend or VM pause.
    SuspendOrVmPause,
    /// Another recorded incident.
    OtherRecordedIncident,
}

impl OverrunAckReasonV1 {
    /// Stable `reason_code` record code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::BenignStall => 1,
            Self::SuspendOrVmPause => 2,
            Self::OtherRecordedIncident => 3,
        }
    }
}

// ---------------------------------------------------------------------------
// Operator authority
// ---------------------------------------------------------------------------

/// Host authorization-provenance digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct HostAuthorizationProvenanceV1([u8; 32]);

impl HostAuthorizationProvenanceV1 {
    /// Wrap the host's 32-byte authorization-provenance digest.
    #[must_use]
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// Return the digest bytes.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Closed host administrative actions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum HostAdministrativeActionV1 {
    /// Clear the trusted-clock overrun latch after an audited review.
    AcknowledgeTrustedClockOverrun,
}

/// Host authorization of one Principal for one closed administrative action
/// under the host's pinned trust revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostAdministrativeAuthorizationV1 {
    action: HostAdministrativeActionV1,
    principal: PrincipalRefV1,
    trust_revision: Hash,
    provenance: HostAuthorizationProvenanceV1,
}

impl HostAdministrativeAuthorizationV1 {
    /// Record the host's authorization decision.
    #[must_use]
    pub const fn new(
        action: HostAdministrativeActionV1,
        principal: PrincipalRefV1,
        trust_revision: Hash,
        provenance: HostAuthorizationProvenanceV1,
    ) -> Self {
        Self {
            action,
            principal,
            trust_revision,
            provenance,
        }
    }

    /// The authorized action.
    #[must_use]
    pub const fn action(&self) -> HostAdministrativeActionV1 {
        self.action
    }

    /// The authorized Principal.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalRefV1 {
        &self.principal
    }

    /// The pinned trust revision.
    #[must_use]
    pub const fn trust_revision(&self) -> Hash {
        self.trust_revision
    }

    /// The authorization-provenance digest.
    #[must_use]
    pub const fn provenance(&self) -> HostAuthorizationProvenanceV1 {
        self.provenance
    }
}

/// Inputs of one audited overrun acknowledgement.
#[derive(Clone, Copy, Debug)]
pub struct TrustedClockOverrunAcknowledgementV1<'a> {
    /// The authenticated operator.
    pub operator: &'a AuthenticatedPrincipalResultV1,
    /// The host authorization for `AcknowledgeTrustedClockOverrun`.
    pub authorization: &'a HostAdministrativeAuthorizationV1,
    /// The overrun count the operator reviewed.
    pub expected_overrun_count: u64,
    /// The recorded reason.
    pub reason: OverrunAckReasonV1,
}

// ---------------------------------------------------------------------------
// Time sources
// ---------------------------------------------------------------------------

/// Convert an epoch duration to trusted wall time, rounding nanoseconds up.
///
/// # Errors
/// Returns [`TrustedClockErrorV1::SourceUnavailable`] above `i64::MAX` microseconds.
pub fn wall_time_from_epoch_duration(duration: Duration) -> Result<WallTime, TrustedClockErrorV1> {
    match u64::try_from(duration.as_nanos().div_ceil(1_000)) {
        Ok(micros) if micros <= MAX_TRUSTED_MICROS => Ok(WallTime::from_micros(micros)),
        _ => Err(TrustedClockErrorV1::SourceUnavailable),
    }
}

/// Convert a system time to trusted wall time without saturation.
///
/// # Errors
/// Returns [`TrustedClockErrorV1::SourceUnavailable`] before the epoch or above
/// `i64::MAX` microseconds.
pub fn wall_time_from_system_time(time: SystemTime) -> Result<WallTime, TrustedClockErrorV1> {
    time.duration_since(UNIX_EPOCH).map_or(
        Err(TrustedClockErrorV1::SourceUnavailable),
        wall_time_from_epoch_duration,
    )
}

/// Sealed trusted wall source.
pub trait TrustedWallSourceV1: sealed::Sealed + Send {
    /// Take one trusted wall sample.
    ///
    /// # Errors
    /// Returns [`TrustedClockErrorV1::SourceUnavailable`] when no trusted sample exists.
    fn sample(&mut self) -> Result<WallTime, TrustedClockErrorV1>;
}

/// Opaque monotonic mark.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct MonotonicMarkV1(Instant);

impl MonotonicMarkV1 {
    /// Elapsed time since an earlier mark, or `None` when time regressed.
    #[must_use]
    pub fn checked_elapsed_since(self, earlier: Self) -> Option<Duration> {
        self.0.checked_duration_since(earlier.0)
    }
}

/// Sealed monotonic source for wait and guard budgets.
pub trait GuardMonotonicSourceV1: sealed::Sealed + Send {
    /// Take one monotonic mark.
    fn mark(&mut self) -> MonotonicMarkV1;
}

/// Production wall source over `SystemTime::now()`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemTrustedWallSourceV1;

impl sealed::Sealed for SystemTrustedWallSourceV1 {}

impl TrustedWallSourceV1 for SystemTrustedWallSourceV1 {
    fn sample(&mut self) -> Result<WallTime, TrustedClockErrorV1> {
        wall_time_from_system_time(SystemTime::now())
    }
}

/// Production monotonic source over `Instant::now()`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemGuardMonotonicSourceV1;

impl sealed::Sealed for SystemGuardMonotonicSourceV1 {}

impl GuardMonotonicSourceV1 for SystemGuardMonotonicSourceV1 {
    fn mark(&mut self) -> MonotonicMarkV1 {
        MonotonicMarkV1(Instant::now())
    }
}

/// One scripted wall sample.
#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScriptedWallSampleV1 {
    /// A nanosecond-level duration since the epoch.
    SinceEpoch(Duration),
    /// A system time, possibly before the epoch.
    System(SystemTime),
    /// A wall-source error.
    Unavailable,
}

/// Test wall source; every value passes through the public conversions.
#[cfg(feature = "test-support")]
#[derive(Clone, Debug, Default)]
pub struct ScriptedTrustedWallSourceV1 {
    script: std::collections::VecDeque<ScriptedWallSampleV1>,
}

#[cfg(feature = "test-support")]
impl ScriptedTrustedWallSourceV1 {
    /// Script samples in FIFO order. An exhausted script is unavailable.
    #[must_use]
    pub fn new(samples: impl IntoIterator<Item = ScriptedWallSampleV1>) -> Self {
        Self {
            script: samples.into_iter().collect(),
        }
    }

    /// Script whole-microsecond samples in FIFO order.
    #[must_use]
    pub fn from_micros(samples: impl IntoIterator<Item = u64>) -> Self {
        let samples = samples.into_iter().map(Duration::from_micros);
        Self::new(samples.map(ScriptedWallSampleV1::SinceEpoch))
    }

    /// Append one sample.
    pub fn push(&mut self, sample: ScriptedWallSampleV1) {
        self.script.push_back(sample);
    }

    /// Number of unconsumed samples.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.script.len()
    }
}

#[cfg(feature = "test-support")]
impl sealed::Sealed for ScriptedTrustedWallSourceV1 {}

#[cfg(feature = "test-support")]
impl TrustedWallSourceV1 for ScriptedTrustedWallSourceV1 {
    fn sample(&mut self) -> Result<WallTime, TrustedClockErrorV1> {
        match self.script.pop_front() {
            Some(ScriptedWallSampleV1::SinceEpoch(duration)) => {
                wall_time_from_epoch_duration(duration)
            }
            Some(ScriptedWallSampleV1::System(time)) => wall_time_from_system_time(time),
            Some(ScriptedWallSampleV1::Unavailable) | None => {
                Err(TrustedClockErrorV1::SourceUnavailable)
            }
        }
    }
}

/// Test monotonic source scripted as offsets from one origin; offsets may
/// regress. An exhausted script repeats its last offset.
#[cfg(feature = "test-support")]
#[derive(Clone, Debug)]
pub struct ScriptedGuardMonotonicSourceV1 {
    origin: Instant,
    script: std::collections::VecDeque<Duration>,
    last: Duration,
}

#[cfg(feature = "test-support")]
impl ScriptedGuardMonotonicSourceV1 {
    /// Script offsets in FIFO order.
    #[must_use]
    pub fn new(offsets: impl IntoIterator<Item = Duration>) -> Self {
        Self {
            origin: Instant::now(),
            script: offsets.into_iter().collect(),
            last: Duration::ZERO,
        }
    }

    /// Append one offset.
    pub fn push(&mut self, offset: Duration) {
        self.script.push_back(offset);
    }
}

#[cfg(feature = "test-support")]
impl sealed::Sealed for ScriptedGuardMonotonicSourceV1 {}

#[cfg(feature = "test-support")]
impl GuardMonotonicSourceV1 for ScriptedGuardMonotonicSourceV1 {
    fn mark(&mut self) -> MonotonicMarkV1 {
        self.last = self.script.pop_front().unwrap_or(self.last);
        MonotonicMarkV1(self.origin.checked_add(self.last).unwrap_or(self.origin))
    }
}

/// Shared 250 ms wait budget, charged per phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitBudgetV1 {
    remaining: Duration,
}

impl WaitBudgetV1 {
    /// A fresh 250 ms budget.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            remaining: TRUSTED_CLOCK_WAIT_BUDGET,
        }
    }

    /// The unspent budget.
    #[must_use]
    pub const fn remaining(&self) -> Duration {
        self.remaining
    }

    /// Charge a measured wait to a phase.
    ///
    /// # Errors
    /// Returns [`TrustedClockErrorV1::WaitBudgetExceeded`] when the wait exceeds
    /// the remaining budget.
    pub const fn charge(
        &mut self,
        phase: WaitPhaseV1,
        waited: Duration,
    ) -> Result<(), TrustedClockErrorV1> {
        let Some(remaining) = self.remaining.checked_sub(waited) else {
            return Err(TrustedClockErrorV1::WaitBudgetExceeded(phase));
        };
        self.remaining = remaining;
        Ok(())
    }
}

impl Default for WaitBudgetV1 {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Durable records and ports
// ---------------------------------------------------------------------------

/// Raw `trusted_clock_high_water` row as stored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedClockHighWaterRowV1 {
    pub format_version: i64,
    pub clock_domain: Vec<u8>,
    pub high_water_micros: i64,
    pub reserved_until_micros: i64,
    pub reservation_seq: i64,
}

/// Raw `trusted_clock_overrun_latch` row as stored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedClockOverrunLatchRowV1 {
    pub format_version: i64,
    pub latched: i64,
    pub overrun_count: i64,
    pub last_overrun_reservation: i64,
    pub last_overrun_kind: i64,
    pub last_overrun_at_micros: i64,
}

impl TrustedClockOverrunLatchRowV1 {
    /// The initial unlatched, zero-count latch row.
    pub const UNLATCHED: Self = Self {
        format_version: TRUSTED_CLOCK_FORMAT_VERSION_V1,
        latched: 0,
        overrun_count: 0,
        last_overrun_reservation: 0,
        last_overrun_kind: 0,
        last_overrun_at_micros: 0,
    };
}

/// Raw immutable `trusted_clock_overrun_acknowledgements` row; the adapter
/// assigns `ack_seq`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedClockAcknowledgementRowV1 {
    pub acknowledged_overrun_count: i64,
    pub operator_principal_digest: [u8; 32],
    pub authorization_provenance_digest: [u8; 32],
    pub trust_revision_digest: [u8; 32],
    pub acknowledged_at_micros: i64,
    pub reason_code: i64,
}

/// Every stored row of both single-row tables.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrustedClockRowsV1 {
    pub high_water: Vec<TrustedClockHighWaterRowV1>,
    pub overrun_latch: Vec<TrustedClockOverrunLatchRowV1>,
}

/// Trusted-host storage port on the reservation connection.
///
/// Implementations report rows and lock state truthfully and perform no checks.
pub trait TrustedClockStorePortV1 {
    /// Set `journal_mode=WAL` and `synchronous=FULL` on the connection that
    /// commits reservations, read both back, and report whether both match.
    ///
    /// # Errors
    /// Returns a port error when the pragmas cannot be set or read.
    fn verify_durability_pragmas(&mut self) -> Result<bool, TrustedClockPortErrorV1>;

    /// Set the busy timeout and begin one immediate write transaction.
    ///
    /// # Errors
    /// Returns [`TrustedClockPortErrorV1::Busy`] when the writer lock was not
    /// acquired in time, which the fence charges to the wait budget, or
    /// [`TrustedClockPortErrorV1::Storage`] for any other failure. Lock
    /// acquisition reads no row and never returns
    /// [`TrustedClockPortErrorV1::Corrupt`].
    fn begin_immediate(&mut self, busy_timeout: Duration) -> Result<(), TrustedClockPortErrorV1>;

    /// Count authoritative `validated_ARD1_address` catalog entries.
    ///
    /// # Errors
    /// Returns a port error when the catalog cannot be read.
    fn authoritative_catalog_entries(&mut self) -> Result<u64, TrustedClockPortErrorV1>;

    /// Read every stored row inside the open transaction.
    ///
    /// # Errors
    /// Returns [`TrustedClockPortErrorV1::Corrupt`] when a row cannot be
    /// decoded, or another port error when it cannot be read. A busy read is
    /// not a lock wait: the fence reports it as `DurabilityUnavailable`.
    fn read_rows(&mut self) -> Result<TrustedClockRowsV1, TrustedClockPortErrorV1>;

    /// Generate 16 fresh random clock-domain bytes.
    ///
    /// # Errors
    /// Returns a port error when entropy is unavailable.
    fn generate_clock_domain(&mut self) -> Result<[u8; 16], TrustedClockPortErrorV1>;

    /// Replace the single high-water row inside the open transaction.
    ///
    /// # Errors
    /// Returns a port error when the write fails.
    fn write_high_water(
        &mut self,
        row: &TrustedClockHighWaterRowV1,
    ) -> Result<(), TrustedClockPortErrorV1>;

    /// Replace the single overrun-latch row inside the open transaction.
    ///
    /// # Errors
    /// Returns a port error when the write fails.
    fn write_overrun_latch(
        &mut self,
        row: &TrustedClockOverrunLatchRowV1,
    ) -> Result<(), TrustedClockPortErrorV1>;

    /// Append one immutable acknowledgement row inside the open transaction.
    ///
    /// # Errors
    /// Returns a port error when the write fails.
    fn append_acknowledgement(
        &mut self,
        row: &TrustedClockAcknowledgementRowV1,
    ) -> Result<(), TrustedClockPortErrorV1>;

    /// Commit the open transaction durably.
    ///
    /// # Errors
    /// Returns a port error when the commit fails.
    fn commit(&mut self) -> Result<(), TrustedClockPortErrorV1>;

    /// Roll back any open transaction and release the writer lock.
    fn rollback(&mut self);
}

/// Trusted-host guard port: the authority `BEGIN IMMEDIATE` transaction or the
/// shared `MemoryStore` lock that the release holds until teardown.
pub trait ReleaseGuardPortV1 {
    /// Set the busy timeout and acquire the authority write lock.
    ///
    /// # Errors
    /// Returns [`TrustedClockPortErrorV1::Busy`] when the lock was not acquired
    /// in time, which the fence charges to the wait budget, or
    /// [`TrustedClockPortErrorV1::Storage`] for any other failure. Lock
    /// acquisition reads no row and never returns
    /// [`TrustedClockPortErrorV1::Corrupt`].
    fn begin_guard(&mut self, busy_timeout: Duration) -> Result<(), TrustedClockPortErrorV1>;

    /// Re-read every stored row under the held lock.
    ///
    /// # Errors
    /// Returns [`TrustedClockPortErrorV1::Corrupt`] when a row cannot be
    /// decoded, or another port error when it cannot be read. A busy read is
    /// not a lock wait: the fence reports it as `DurabilityUnavailable`.
    fn reread_rows(&mut self) -> Result<TrustedClockRowsV1, TrustedClockPortErrorV1>;

    /// Roll back the release transaction and release the lock.
    fn rollback_and_release(&mut self);
}

#[derive(Clone, Copy, Debug)]
struct HighWaterStateV1 {
    domain: [u8; 16],
    high_water: i64,
    reserved_until: i64,
    seq: i64,
}

#[derive(Clone, Copy, Debug)]
struct LatchStateV1 {
    latched: bool,
    overrun_count: i64,
    row: TrustedClockOverrunLatchRowV1,
}

fn single_row<T: Clone>(rows: &[T]) -> Result<T, TrustedClockErrorV1> {
    match rows {
        [row] => Ok(row.clone()),
        [] => Err(TrustedClockErrorV1::HighWaterMissing),
        _ => Err(TrustedClockErrorV1::HighWaterCorrupt),
    }
}

fn validate_rows(
    rows: &TrustedClockRowsV1,
) -> Result<(HighWaterStateV1, LatchStateV1), TrustedClockErrorV1> {
    let high_water = single_row(&rows.high_water)?;
    let latch = single_row(&rows.overrun_latch)?;
    if high_water.format_version != TRUSTED_CLOCK_FORMAT_VERSION_V1
        || latch.format_version != TRUSTED_CLOCK_FORMAT_VERSION_V1
    {
        return Err(TrustedClockErrorV1::UnsupportedFormat);
    }
    let high_water = validate_high_water(&high_water)?;
    validate_latch(latch).map(|latch| (high_water, latch))
}

fn validate_high_water(
    row: &TrustedClockHighWaterRowV1,
) -> Result<HighWaterStateV1, TrustedClockErrorV1> {
    let domain = <[u8; 16]>::try_from(row.clock_domain.as_slice());
    let ordered = row.high_water_micros >= 0
        && row.reserved_until_micros >= row.high_water_micros
        && row.reservation_seq >= 0;
    match domain {
        Ok(domain) if ordered => Ok(HighWaterStateV1 {
            domain,
            high_water: row.high_water_micros,
            reserved_until: row.reserved_until_micros,
            seq: row.reservation_seq,
        }),
        _ => Err(TrustedClockErrorV1::HighWaterCorrupt),
    }
}

const fn validate_latch(
    row: TrustedClockOverrunLatchRowV1,
) -> Result<LatchStateV1, TrustedClockErrorV1> {
    if matches!(row.latched, 0 | 1)
        && row.overrun_count >= 0
        && row.last_overrun_reservation >= 0
        && matches!(row.last_overrun_kind, 0..=3)
        && row.last_overrun_at_micros >= 0
    {
        Ok(LatchStateV1 {
            latched: row.latched == 1,
            overrun_count: row.overrun_count,
            row,
        })
    } else {
        Err(TrustedClockErrorV1::HighWaterCorrupt)
    }
}

const fn write_error(_: TrustedClockPortErrorV1) -> TrustedClockErrorV1 {
    TrustedClockErrorV1::ReservationCommitFailed
}

const fn durability_error(_: TrustedClockPortErrorV1) -> TrustedClockErrorV1 {
    TrustedClockErrorV1::DurabilityUnavailable
}

/// Map a lock-acquisition failure of `begin_immediate` or `begin_guard`.
///
/// Only a busy lock is charged to the wait budget of `phase`; any other
/// failure leaves the authority store unavailable. Lock acquisition reads no
/// row, so `begin_*` never reports [`TrustedClockPortErrorV1::Corrupt`]; it is
/// folded into the storage outcome rather than given its own meaning.
const fn lock_outcome(error: TrustedClockPortErrorV1, phase: WaitPhaseV1) -> TrustedClockErrorV1 {
    match error {
        TrustedClockPortErrorV1::Busy => TrustedClockErrorV1::WaitBudgetExceeded(phase),
        TrustedClockPortErrorV1::Storage | TrustedClockPortErrorV1::Corrupt => {
            TrustedClockErrorV1::DurabilityUnavailable
        }
    }
}

/// Map a failed row or catalog read inside an already-held lock.
///
/// An undecodable row is corrupt. A busy or failed read happens after the
/// lock wait was charged, so it never claims the wait budget ran out: the
/// authority store is unavailable.
const fn read_outcome(error: TrustedClockPortErrorV1) -> TrustedClockErrorV1 {
    match error {
        TrustedClockPortErrorV1::Corrupt => TrustedClockErrorV1::HighWaterCorrupt,
        TrustedClockPortErrorV1::Busy | TrustedClockPortErrorV1::Storage => {
            TrustedClockErrorV1::DurabilityUnavailable
        }
    }
}

const fn reservation_lock_error(error: TrustedClockPortErrorV1) -> TrustedClockErrorV1 {
    lock_outcome(error, WaitPhaseV1::Reservation)
}

const fn guard_lock_error(error: TrustedClockPortErrorV1) -> TrustedClockErrorV1 {
    lock_outcome(error, WaitPhaseV1::Guard)
}

fn sample_trusted(wall: &mut dyn TrustedWallSourceV1) -> Result<i64, TrustedClockErrorV1> {
    match wall.sample().map(|time| i64::try_from(time.as_micros())) {
        Ok(Ok(micros)) => Ok(micros),
        _ => Err(TrustedClockErrorV1::SourceUnavailable),
    }
}

// ---------------------------------------------------------------------------
// Process-shared pending overrun flags, keyed by authority identity
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct PendingOverrunV1 {
    kind: TrustedClockOverrunKindV1,
    reservation_seq: i64,
    at_micros: i64,
}

static PENDING_OVERRUNS: Mutex<BTreeMap<[u8; 16], PendingOverrunV1>> = Mutex::new(BTreeMap::new());

fn pending_overruns() -> MutexGuard<'static, BTreeMap<[u8; 16], PendingOverrunV1>> {
    PENDING_OVERRUNS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

fn pending_overrun(domain: [u8; 16]) -> Option<PendingOverrunV1> {
    pending_overruns().get(&domain).copied()
}

fn set_pending_overrun(domain: [u8; 16], pending: PendingOverrunV1) {
    pending_overruns().insert(domain, pending);
}

fn clear_pending_overrun(domain: [u8; 16]) {
    pending_overruns().remove(&domain);
}

fn latched_row(
    latch: &LatchStateV1,
    pending: PendingOverrunV1,
) -> Result<TrustedClockOverrunLatchRowV1, TrustedClockErrorV1> {
    let Some(overrun_count) = latch.overrun_count.checked_add(1) else {
        return Err(TrustedClockErrorV1::Overflow);
    };
    Ok(TrustedClockOverrunLatchRowV1 {
        format_version: TRUSTED_CLOCK_FORMAT_VERSION_V1,
        latched: 1,
        overrun_count,
        last_overrun_reservation: pending.reservation_seq,
        last_overrun_kind: i64::from(pending.kind.code()),
        last_overrun_at_micros: pending.at_micros,
    })
}

/// Write the latch for this identity's pending overrun, if one is set.
fn write_pending_latch(
    store: &mut dyn TrustedClockStorePortV1,
    high_water: &HighWaterStateV1,
    latch: &LatchStateV1,
) -> Result<bool, TrustedClockErrorV1> {
    let Some(pending) = pending_overrun(high_water.domain) else {
        return Ok(false);
    };
    let row = latched_row(latch, pending)?;
    store.write_overrun_latch(&row).map_err(write_error)?;
    Ok(true)
}

fn commit_or_rollback(
    store: &mut dyn TrustedClockStorePortV1,
    error: TrustedClockErrorV1,
) -> Result<(), TrustedClockErrorV1> {
    let committed = store.commit();
    if committed.is_err() {
        store.rollback();
    }
    committed.or(Err(error))
}

fn begin_reservation_tx(
    store: &mut dyn TrustedClockStorePortV1,
    timeout: Duration,
) -> Result<(), TrustedClockErrorV1> {
    store
        .begin_immediate(timeout)
        .map_err(reservation_lock_error)
}

fn require_durability(store: &mut dyn TrustedClockStorePortV1) -> Result<(), TrustedClockErrorV1> {
    match store.verify_durability_pragmas() {
        Ok(true) => Ok(()),
        _ => Err(TrustedClockErrorV1::DurabilityUnavailable),
    }
}

fn charge_wait(
    wait: &mut WaitBudgetV1,
    phase: WaitPhaseV1,
    before: MonotonicMarkV1,
    after: MonotonicMarkV1,
) -> Result<(), TrustedClockErrorV1> {
    after
        .checked_elapsed_since(before)
        .ok_or(TrustedClockErrorV1::Rollback)
        .and_then(|waited| wait.charge(phase, waited))
}

// ---------------------------------------------------------------------------
// Reservation
// ---------------------------------------------------------------------------

/// A committed durable reservation. It cannot be cloned or forged.
#[derive(Debug)]
pub struct TrustedClockReservationV1 {
    domain: [u8; 16],
    seq: i64,
    sampled: i64,
    decision_bound: i64,
    g0: MonotonicMarkV1,
}

impl TrustedClockReservationV1 {
    /// The committed reservation sequence.
    #[must_use]
    pub const fn reservation_seq(&self) -> u64 {
        self.seq.unsigned_abs()
    }

    /// The committed reservation sample `t_r`.
    #[must_use]
    pub const fn sampled_at(&self) -> WallTime {
        WallTime::from_micros(self.sampled.unsigned_abs())
    }

    /// The decision bound `D = t_r + 32 s`.
    #[must_use]
    pub const fn decision_bound(&self) -> WallTime {
        WallTime::from_micros(self.decision_bound.unsigned_abs())
    }
}

enum ReserveStepV1 {
    Reserved(TrustedClockReservationV1),
    LatchCommitted([u8; 16]),
}

/// Commit a durable trusted-clock reservation before the release transaction.
///
/// `owner_lock_g0` is the mark taken when the first owner lock was acquired;
/// without owner locks `g0` is the reservation's `BEGIN IMMEDIATE`. A
/// supplied mark later than the reservation's own acquisition start would
/// silently extend the guard budget, so it is refused with
/// [`TrustedClockErrorV1::Rollback`] before the lock is requested.
///
/// # Errors
/// Returns the ADR-112 fail-closed outcome. Nothing changes except a committed
/// overrun latch for a pending flag of this identity.
pub fn reserve_trusted_clock(
    store: &mut dyn TrustedClockStorePortV1,
    wall: &mut dyn TrustedWallSourceV1,
    mono: &mut dyn GuardMonotonicSourceV1,
    wait: &mut WaitBudgetV1,
    owner_lock_g0: Option<MonotonicMarkV1>,
) -> Result<TrustedClockReservationV1, TrustedClockErrorV1> {
    require_durability(store)?;
    let before = mono.mark();
    if owner_lock_g0 > Some(before) {
        return Err(TrustedClockErrorV1::Rollback);
    }
    begin_reservation_tx(store, wait.remaining())?;
    let acquired = mono.mark();
    let g0 = owner_lock_g0.unwrap_or(acquired);
    let step = charge_wait(wait, WaitPhaseV1::Reservation, before, acquired)
        .and_then(|()| reserve_in_transaction(store, wall, g0));
    finish_reservation(store, step)
}

fn finish_reservation(
    store: &mut dyn TrustedClockStorePortV1,
    step: Result<ReserveStepV1, TrustedClockErrorV1>,
) -> Result<TrustedClockReservationV1, TrustedClockErrorV1> {
    match step {
        Ok(ReserveStepV1::Reserved(reservation)) => {
            commit_or_rollback(store, TrustedClockErrorV1::ReservationCommitFailed)?;
            Ok(reservation)
        }
        Ok(ReserveStepV1::LatchCommitted(domain)) => {
            let committed = commit_or_rollback(store, TrustedClockErrorV1::OverrunLatched);
            if committed.is_ok() {
                clear_pending_overrun(domain);
            }
            Err(TrustedClockErrorV1::OverrunLatched)
        }
        Err(error) => {
            store.rollback();
            Err(error)
        }
    }
}

fn reserve_in_transaction(
    store: &mut dyn TrustedClockStorePortV1,
    wall: &mut dyn TrustedWallSourceV1,
    g0: MonotonicMarkV1,
) -> Result<ReserveStepV1, TrustedClockErrorV1> {
    let rows = store.read_rows().map_err(read_outcome)?;
    let (rows, presampled) = migrate_missing_rows(store, wall, rows)?;
    let (high_water, latch) = validate_rows(&rows)?;
    if latch.latched {
        return Err(TrustedClockErrorV1::OverrunLatched);
    }
    if write_pending_latch(store, &high_water, &latch)? {
        return Ok(ReserveStepV1::LatchCommitted(high_water.domain));
    }
    let sampled = presampled.map_or_else(|| sample_trusted(wall), Ok)?;
    let (row, reservation) = reserved_row(&high_water, sampled, g0)?;
    store.write_high_water(&row).map_err(write_error)?;
    Ok(ReserveStepV1::Reserved(reservation))
}

fn reserved_row(
    state: &HighWaterStateV1,
    sampled: i64,
    g0: MonotonicMarkV1,
) -> Result<(TrustedClockHighWaterRowV1, TrustedClockReservationV1), TrustedClockErrorV1> {
    if sampled < state.high_water {
        return Err(TrustedClockErrorV1::Rollback);
    }
    let seq = state.seq.checked_add(1);
    let decision_bound = sampled.checked_add(RESERVATION_WINDOW_MICROS);
    let (Some(seq), Some(decision_bound)) = (seq, decision_bound) else {
        return Err(TrustedClockErrorV1::Overflow);
    };
    let row = TrustedClockHighWaterRowV1 {
        format_version: TRUSTED_CLOCK_FORMAT_VERSION_V1,
        clock_domain: state.domain.to_vec(),
        high_water_micros: sampled,
        reserved_until_micros: state.reserved_until.max(decision_bound),
        reservation_seq: seq,
    };
    let reservation = TrustedClockReservationV1 {
        domain: state.domain,
        seq,
        sampled,
        decision_bound,
        g0,
    };
    Ok((row, reservation))
}

/// One-time fail-closed migration: create missing rows only while the
/// authoritative catalog holds no entries.
fn migrate_missing_rows(
    store: &mut dyn TrustedClockStorePortV1,
    wall: &mut dyn TrustedWallSourceV1,
    mut rows: TrustedClockRowsV1,
) -> Result<(TrustedClockRowsV1, Option<i64>), TrustedClockErrorV1> {
    if !rows.high_water.is_empty() && !rows.overrun_latch.is_empty() {
        return Ok((rows, None));
    }
    if store
        .authoritative_catalog_entries()
        .map_err(read_outcome)?
        != 0
    {
        return Err(TrustedClockErrorV1::HighWaterMissing);
    }
    let sampled = sample_trusted(wall)?;
    if rows.high_water.is_empty() {
        let domain = store.generate_clock_domain().map_err(durability_error)?;
        let row = TrustedClockHighWaterRowV1 {
            format_version: TRUSTED_CLOCK_FORMAT_VERSION_V1,
            clock_domain: domain.to_vec(),
            high_water_micros: sampled,
            reserved_until_micros: sampled,
            reservation_seq: 0,
        };
        store.write_high_water(&row).map_err(write_error)?;
        rows.high_water.push(row);
    }
    if rows.overrun_latch.is_empty() {
        let row = TrustedClockOverrunLatchRowV1::UNLATCHED;
        store.write_overrun_latch(&row).map_err(write_error)?;
        rows.overrun_latch.push(row);
    }
    Ok((rows, Some(sampled)))
}

// ---------------------------------------------------------------------------
// Guard
// ---------------------------------------------------------------------------

/// The held authority guard. Dropping it rolls back and releases the lock.
pub struct ReleaseGuardV1<'host> {
    port: &'host mut dyn ReleaseGuardPortV1,
    reservation: TrustedClockReservationV1,
    high_water: i64,
}

impl Drop for ReleaseGuardV1<'_> {
    fn drop(&mut self) {
        self.port.rollback_and_release();
    }
}

/// Acquire the authority guard for a committed reservation and re-read its
/// record under the held lock.
///
/// # Errors
/// Returns [`TrustedClockErrorV1::WaitBudgetExceeded`],
/// [`TrustedClockErrorV1::AuthorityRegressed`],
/// [`TrustedClockErrorV1::OverrunLatched`] or a record outcome. The lock is
/// released before any error returns.
pub fn open_release_guard<'host>(
    port: &'host mut dyn ReleaseGuardPortV1,
    reservation: TrustedClockReservationV1,
    wait: &mut WaitBudgetV1,
    mono: &mut dyn GuardMonotonicSourceV1,
) -> Result<ReleaseGuardV1<'host>, TrustedClockErrorV1> {
    let before = mono.mark();
    port.begin_guard(wait.remaining())
        .map_err(guard_lock_error)?;
    let acquired = mono.mark();
    let checked = charge_wait(wait, WaitPhaseV1::Guard, before, acquired)
        .and_then(|()| port.reread_rows().map_err(read_outcome))
        .and_then(|rows| guarded_high_water(&rows, &reservation));
    match checked {
        Ok(high_water) => Ok(ReleaseGuardV1 {
            port,
            reservation,
            high_water,
        }),
        Err(error) => {
            port.rollback_and_release();
            Err(error)
        }
    }
}

fn guarded_high_water(
    rows: &TrustedClockRowsV1,
    reservation: &TrustedClockReservationV1,
) -> Result<i64, TrustedClockErrorV1> {
    let (high_water, latch) = validate_rows(rows)?;
    let other_domain = high_water.domain != reservation.domain;
    let older_sequence = high_water.seq < reservation.seq;
    let older_sample = high_water.high_water < reservation.sampled;
    if other_domain || older_sequence || older_sample {
        return Err(TrustedClockErrorV1::AuthorityRegressed);
    }
    if latch.latched || pending_overrun(high_water.domain).is_some() {
        return Err(TrustedClockErrorV1::OverrunLatched);
    }
    Ok(high_water.high_water)
}

/// Expiry premises read inside the guard.
#[derive(Clone, Copy, Debug)]
pub struct ExpiryPremisesV1<'a> {
    /// Every applicable RLS1 lease; at least one is required.
    pub retention_leases: &'a [WorldRetentionLeaseV1],
    /// Every applicable consent grant; `expiry_secs` is absolute Unix seconds.
    pub consent_grants: &'a [ConsentGrantedV1],
    /// Every applicable consent reference.
    pub consent_references: &'a [ConsentGrantRefV1],
    /// The caller's access authorization; required.
    pub access: Option<&'a AuthenticatedPrincipalResultV1>,
}

/// The checked earliest applicable expiry, bound to one guard.
#[derive(Debug, Eq, PartialEq)]
pub struct ApplicableExpiriesV1 {
    domain: [u8; 16],
    reservation_seq: i64,
    earliest: u64,
}

impl ApplicableExpiriesV1 {
    /// The exclusive earliest applicable expiry `E_min`.
    #[must_use]
    pub const fn earliest_expiry(&self) -> WallTime {
        WallTime::from_micros(self.earliest)
    }
}

impl ReleaseGuardV1<'_> {
    /// The reservation this guard covers.
    #[must_use]
    pub const fn reservation(&self) -> &TrustedClockReservationV1 {
        &self.reservation
    }

    /// The guard start `g0`: the monotonic mark at the first acquired owner
    /// lock, or else at the reservation's own lock acquisition.
    #[must_use]
    pub const fn guard_started_at(&self) -> MonotonicMarkV1 {
        self.reservation.g0
    }

    /// The high-water re-read under this guard.
    #[must_use]
    pub const fn high_water(&self) -> WallTime {
        WallTime::from_micros(self.high_water.unsigned_abs())
    }

    /// Compute `E_min` from premises read inside the guard and require `D < E_min`.
    ///
    /// # Errors
    /// Returns [`TrustedClockErrorV1::ExpiryUnknown`] without a lease or access
    /// authorization, and [`TrustedClockErrorV1::Expired`] when `D >= E_min`.
    pub fn applicable_expiries(
        &self,
        premises: &ExpiryPremisesV1<'_>,
    ) -> Result<ApplicableExpiriesV1, TrustedClockErrorV1> {
        let earliest = earliest_expiry(premises)?;
        if self.reservation.decision_bound.unsigned_abs() < earliest {
            Ok(ApplicableExpiriesV1 {
                domain: self.reservation.domain,
                reservation_seq: self.reservation.seq,
                earliest,
            })
        } else {
            Err(TrustedClockErrorV1::Expired)
        }
    }

    fn final_check(
        &self,
        wall: &mut dyn TrustedWallSourceV1,
        mono: &mut dyn GuardMonotonicSourceV1,
    ) -> Result<(), TrustedClockErrorV1> {
        let elapsed = mono
            .mark()
            .checked_elapsed_since(self.reservation.g0)
            .ok_or(TrustedClockErrorV1::Rollback)?;
        if elapsed > TRUSTED_CLOCK_GUARD_BUDGET {
            return Err(TrustedClockErrorV1::WindowExceeded);
        }
        let final_sample = sample_trusted(wall)?;
        if final_sample < self.reservation.sampled.max(self.high_water) {
            return Err(TrustedClockErrorV1::Rollback);
        }
        if final_sample > self.reservation.decision_bound {
            return Err(TrustedClockErrorV1::WindowExceeded);
        }
        Ok(())
    }

    fn post_handoff_overrun(
        &self,
        wall: &mut dyn TrustedWallSourceV1,
        mono: &mut dyn GuardMonotonicSourceV1,
    ) -> Option<TrustedClockOverrunKindV1> {
        let elapsed = mono.mark().checked_elapsed_since(self.reservation.g0);
        let post_sample = sample_trusted(wall);
        let kind = match (elapsed, post_sample) {
            (None, _) => Some(TrustedClockOverrunKindV1::MonotonicRegression),
            (Some(elapsed), _) if elapsed > TRUSTED_CLOCK_RESERVATION_WINDOW => {
                Some(TrustedClockOverrunKindV1::MonotonicBudgetExceeded)
            }
            (_, Ok(sample)) if sample <= self.reservation.decision_bound => None,
            _ => Some(TrustedClockOverrunKindV1::WallBeyondDecisionBound),
        };
        if let Some(kind) = kind {
            let pending = PendingOverrunV1 {
                kind,
                reservation_seq: self.reservation.seq,
                at_micros: post_sample.unwrap_or(self.reservation.decision_bound),
            };
            set_pending_overrun(self.reservation.domain, pending);
        }
        kind
    }
}

fn earliest_expiry(premises: &ExpiryPremisesV1<'_>) -> Result<u64, TrustedClockErrorV1> {
    let access = premises.access.ok_or(TrustedClockErrorV1::ExpiryUnknown)?;
    let retention = premises
        .retention_leases
        .iter()
        .map(|lease| lease.as_input().retention_deadline_micros)
        .min()
        .ok_or(TrustedClockErrorV1::ExpiryUnknown)?;
    // A u32 seconds value times 10^6 always fits in u64.
    let consent = premises
        .consent_grants
        .iter()
        .filter(|grant| grant.expiry_secs != 0)
        .map(|grant| u64::from(grant.expiry_secs) * MICROS_PER_SECOND);
    let references = premises
        .consent_references
        .iter()
        .map(|reference| reference.valid_until().as_micros());
    let floor = retention.min(access.expires_at().as_micros());
    Ok(consent.chain(references).fold(floor, u64::min))
}

// ---------------------------------------------------------------------------
// Handoff
// ---------------------------------------------------------------------------

/// Proof that the final trusted-time check passed. Only [`handoff_checked`]
/// mints one, and [`ProtectedHandoffTargetV1::commit`] consumes it.
#[derive(Debug)]
pub struct HandoffTokenV1 {
    _private: (),
}

impl HandoffTokenV1 {
    const fn mint() -> Self {
        Self { _private: () }
    }
}

/// Sealed infallible protected-use move.
pub trait ProtectedHandoffTargetV1: sealed::Sealed {
    /// The exposed value.
    type Committed;

    /// The protected-use move. Infallible; no I/O, allocation, lock or callback.
    fn commit(self, token: HandoffTokenV1) -> Self::Committed;
}

/// Fully staged Replay or `ReproManifest` bytes.
#[derive(Debug, Eq, PartialEq)]
pub struct StagedArtifactBytesV1 {
    bytes: Vec<u8>,
}

impl StagedArtifactBytesV1 {
    /// Stage a complete private buffer.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl sealed::Sealed for StagedArtifactBytesV1 {}

impl ProtectedHandoffTargetV1 for StagedArtifactBytesV1 {
    type Committed = Vec<u8>;

    fn commit(self, _token: HandoffTokenV1) -> Vec<u8> {
        self.bytes
    }
}

/// A staged protected value with no accessor.
#[derive(Debug)]
pub struct StagedProtectedOutputV1<T: ProtectedHandoffTargetV1> {
    value: T,
}

impl<T: ProtectedHandoffTargetV1> StagedProtectedOutputV1<T> {
    /// Stage a value for the handoff.
    #[must_use]
    pub const fn stage(value: T) -> Self {
        Self { value }
    }
}

/// An exposed protected value. Only [`handoff_checked`] constructs one.
#[derive(Debug)]
pub struct AuthorizedArtifactUseV1<C> {
    value: C,
    overrun: Option<TrustedClockOverrunKindV1>,
}

impl<C> AuthorizedArtifactUseV1<C> {
    /// Borrow the exposed value.
    #[must_use]
    pub const fn value(&self) -> &C {
        &self.value
    }

    /// The `trusted_clock_fence_overrun{kind}` health signal, when the
    /// post-handoff check detected an overrun. Protected release on this
    /// identity is then latched closed.
    #[must_use]
    pub const fn overrun_signal(&self) -> Option<TrustedClockOverrunKindV1> {
        self.overrun
    }
}

/// The sole token minter: run the final in-guard checks, move the staged
/// value, then run the post-handoff overrun check and release the guard.
///
/// # Errors
/// Returns [`TrustedClockErrorV1::AuthorityRegressed`] for expiries of another
/// guard, [`TrustedClockErrorV1::WindowExceeded`],
/// [`TrustedClockErrorV1::Rollback`] or
/// [`TrustedClockErrorV1::SourceUnavailable`]. Staged output is discarded.
pub fn handoff_checked<T: ProtectedHandoffTargetV1>(
    guard: ReleaseGuardV1<'_>,
    expiries: &ApplicableExpiriesV1,
    staged: StagedProtectedOutputV1<T>,
    wall: &mut dyn TrustedWallSourceV1,
    mono: &mut dyn GuardMonotonicSourceV1,
) -> Result<AuthorizedArtifactUseV1<T::Committed>, TrustedClockErrorV1> {
    if expiries.domain != guard.reservation.domain
        || expiries.reservation_seq != guard.reservation.seq
    {
        return Err(TrustedClockErrorV1::AuthorityRegressed);
    }
    guard.final_check(wall, mono)?;
    let value = staged.value.commit(HandoffTokenV1::mint());
    let overrun = guard.post_handoff_overrun(wall, mono);
    drop(guard);
    Ok(AuthorizedArtifactUseV1 { value, overrun })
}

// ---------------------------------------------------------------------------
// Latch commit and acknowledgement
// ---------------------------------------------------------------------------

/// Durably commit this identity's pending overrun latch after teardown.
///
/// Returns `true` when a pending flag was latched and cleared.
///
/// # Errors
/// Returns a record or durability outcome; the pending flag then stays set and
/// the next reservation on this identity commits it.
pub fn commit_pending_overrun_latch(
    store: &mut dyn TrustedClockStorePortV1,
) -> Result<bool, TrustedClockErrorV1> {
    require_durability(store)?;
    begin_reservation_tx(store, TRUSTED_CLOCK_WAIT_BUDGET)?;
    match latch_in_transaction(store) {
        Ok(Some(domain)) => {
            commit_or_rollback(store, TrustedClockErrorV1::DurabilityUnavailable)?;
            clear_pending_overrun(domain);
            Ok(true)
        }
        Ok(None) => {
            store.rollback();
            Ok(false)
        }
        Err(error) => {
            store.rollback();
            Err(error)
        }
    }
}

fn latch_in_transaction(
    store: &mut dyn TrustedClockStorePortV1,
) -> Result<Option<[u8; 16]>, TrustedClockErrorV1> {
    let rows = store.read_rows().map_err(read_outcome)?;
    let (high_water, latch) = validate_rows(&rows)?;
    let wrote = write_pending_latch(store, &high_water, &latch)?;
    Ok(wrote.then_some(high_water.domain))
}

/// Clear the overrun latch through one audited operator acknowledgement.
///
/// # Errors
/// Returns [`TrustedClockErrorV1::Rollback`] for a sample below the high-water,
/// [`TrustedClockErrorV1::AcknowledgementUnauthorized`] without a matching
/// unexpired authorization, [`TrustedClockErrorV1::StaleAcknowledgement`] when
/// the latch is not set at the expected count, or a record outcome.
pub fn acknowledge_trusted_clock_overrun(
    store: &mut dyn TrustedClockStorePortV1,
    wall: &mut dyn TrustedWallSourceV1,
    request: &TrustedClockOverrunAcknowledgementV1<'_>,
) -> Result<(), TrustedClockErrorV1> {
    require_durability(store)?;
    begin_reservation_tx(store, TRUSTED_CLOCK_WAIT_BUDGET)?;
    match acknowledge_in_transaction(store, wall, request) {
        Ok(()) => commit_or_rollback(store, TrustedClockErrorV1::DurabilityUnavailable),
        Err(error) => {
            store.rollback();
            Err(error)
        }
    }
}

fn acknowledge_in_transaction(
    store: &mut dyn TrustedClockStorePortV1,
    wall: &mut dyn TrustedWallSourceV1,
    request: &TrustedClockOverrunAcknowledgementV1<'_>,
) -> Result<(), TrustedClockErrorV1> {
    let rows = store.read_rows().map_err(read_outcome)?;
    let (high_water, latch) = validate_rows(&rows)?;
    let sampled = sample_trusted(wall)?;
    if sampled < high_water.high_water {
        return Err(TrustedClockErrorV1::Rollback);
    }
    authorize_acknowledgement(request, sampled)?;
    let expected = i64::try_from(request.expected_overrun_count);
    if !latch.latched || expected != Ok(latch.overrun_count) {
        return Err(TrustedClockErrorV1::StaleAcknowledgement);
    }
    let cleared = TrustedClockOverrunLatchRowV1 {
        latched: 0,
        ..latch.row
    };
    let acknowledgement = acknowledgement_row(request, latch.overrun_count, sampled);
    store.write_overrun_latch(&cleared).map_err(write_error)?;
    store
        .append_acknowledgement(&acknowledgement)
        .map_err(write_error)
}

fn authorize_acknowledgement(
    request: &TrustedClockOverrunAcknowledgementV1<'_>,
    sampled: i64,
) -> Result<(), TrustedClockErrorV1> {
    // Adding an action variant makes this pattern refutable and forces review.
    let HostAdministrativeActionV1::AcknowledgeTrustedClockOverrun = request.authorization.action;
    let authorized = request.authorization.principal == *request.operator.principal();
    let unexpired = request.operator.expires_at().as_micros() > sampled.unsigned_abs();
    if authorized && unexpired {
        Ok(())
    } else {
        Err(TrustedClockErrorV1::AcknowledgementUnauthorized)
    }
}

fn acknowledgement_row(
    request: &TrustedClockOverrunAcknowledgementV1<'_>,
    overrun_count: i64,
    sampled: i64,
) -> TrustedClockAcknowledgementRowV1 {
    TrustedClockAcknowledgementRowV1 {
        acknowledged_overrun_count: overrun_count,
        operator_principal_digest: principal_digest(request.operator.principal()),
        authorization_provenance_digest: *request.authorization.provenance.digest(),
        trust_revision_digest: *request.authorization.trust_revision.as_bytes(),
        acknowledged_at_micros: sampled,
        reason_code: i64::from(request.reason.code()),
    }
}

/// Domain-separated BLAKE3 digest of a Principal reference.
#[must_use]
pub fn principal_digest(principal: &PrincipalRefV1) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PRINCIPAL_DIGEST_DOMAIN);
    hasher.update(principal.principal_id());
    hasher.update(principal.trust_domain().as_bytes());
    *hasher.finalize().as_bytes()
}
