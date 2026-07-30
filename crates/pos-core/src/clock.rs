use crate::error::CoreError;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Wall-clock timestamp in microseconds since Unix epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WallTime(u64);

impl WallTime {
    #[must_use]
    pub const fn from_micros(micros: u64) -> Self {
        Self(micros)
    }

    #[must_use]
    pub const fn as_micros(self) -> u64 {
        self.0
    }

    #[must_use]
    pub fn now() -> Self {
        let micros = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_micros(),
        )
        .unwrap_or(u64::MAX);
        Self(micros)
    }
}

/// Trusted clock used for server-side admission timestamps and durable TTLs.
pub trait AdmissionClock: Send {
    /// Return the current durable epoch time.
    ///
    /// # Errors
    /// Implementations may return a clock or storage error.
    fn now(&mut self) -> Result<WallTime, CoreError>;
}

/// Production host wall clock for admission operations.
#[derive(Debug, Default)]
pub struct SystemAdmissionClock;

impl AdmissionClock for SystemAdmissionClock {
    fn now(&mut self) -> Result<WallTime, CoreError> {
        Ok(WallTime::now())
    }
}

/// Deterministic clock for backend contract tests.
#[derive(Debug, Clone, Copy)]
pub struct FixedAdmissionClock(pub WallTime);

impl AdmissionClock for FixedAdmissionClock {
    fn now(&mut self) -> Result<WallTime, CoreError> {
        Ok(self.0)
    }
}

/// Lamport logical sequence number. Monotonically increasing within a timeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Seq(u64);

impl Seq {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn from_u64(n: u64) -> Self {
        Self(n)
    }

    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }

    #[must_use = "returns the pre-advance value; use next() if you don't need the old value"]
    pub fn advance(&mut self) -> Self {
        let current = *self;
        self.0 += 1;
        current
    }
}

/// Simulation-internal time in nanoseconds. Decoupled from wall time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SimTime(i64);

impl SimTime {
    pub const EPOCH: Self = Self(0);

    #[must_use]
    pub const fn from_nanos(nanos: i64) -> Self {
        Self(nanos)
    }

    #[must_use]
    pub const fn as_nanos(self) -> i64 {
        self.0
    }

    pub fn checked_add(self, duration: SimDuration) -> Option<Self> {
        self.0.checked_add(duration.0).map(Self)
    }

    pub fn checked_sub(self, other: Self) -> Option<SimDuration> {
        self.0.checked_sub(other.0).map(SimDuration)
    }
}

/// A duration in simulation time (nanoseconds).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SimDuration(i64);

impl SimDuration {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn from_nanos(nanos: i64) -> Self {
        Self(nanos)
    }

    #[must_use]
    pub const fn as_nanos(self) -> i64 {
        self.0
    }

    #[must_use]
    pub const fn from_secs(secs: i64) -> Self {
        Self(secs * 1_000_000_000)
    }

    #[must_use]
    pub const fn from_millis(millis: i64) -> Self {
        Self(millis * 1_000_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{
        append_identity_expires_at, checked_append_identity_expires_at,
        APPEND_IDENTITY_RETENTION_MICROS,
    };

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn wall_time_round_trip_json() {
        let t = WallTime::from_micros(1_700_000_000_000_000);
        let s = serde_json::to_string(&t).unwrap();
        let back: WallTime = serde_json::from_str(&s).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn admission_clocks_return_configured_times() {
        let expected = WallTime::from_micros(9);
        let mut fixed = FixedAdmissionClock(expected);
        assert_eq!(fixed.now().unwrap(), expected);
        let mut system = SystemAdmissionClock;
        assert!(system.now().unwrap().as_micros() > 0);
    }

    #[test]
    fn append_identity_expiry_helpers_cover_saturation_and_overflow() {
        let admitted_at = WallTime::from_micros(42);
        assert_eq!(
            append_identity_expires_at(admitted_at),
            WallTime::from_micros(42 + APPEND_IDENTITY_RETENTION_MICROS)
        );
        assert_eq!(
            checked_append_identity_expires_at(admitted_at).unwrap(),
            append_identity_expires_at(admitted_at)
        );
        assert_eq!(
            append_identity_expires_at(WallTime::from_micros(u64::MAX)),
            WallTime::from_micros(u64::MAX)
        );
        assert!(checked_append_identity_expires_at(WallTime::from_micros(u64::MAX)).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn wall_time_round_trip_cbor() {
        let t = WallTime::from_micros(42);
        let mut buf = Vec::new();
        ciborium::into_writer(&t, &mut buf).unwrap();
        let back: WallTime = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn wall_time_ordering() {
        let earlier = WallTime::from_micros(100);
        let later = WallTime::from_micros(200);
        assert!(earlier < later);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seq_zero_is_smallest() {
        assert_eq!(Seq::ZERO.as_u64(), 0);
        assert!(Seq::ZERO < Seq::from_u64(1));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seq_next_increments() {
        let s = Seq::from_u64(5);
        assert_eq!(s.next().as_u64(), 6);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seq_advance_mutates_and_returns_old() {
        let mut s = Seq::from_u64(3);
        let old = s.advance();
        assert_eq!(old.as_u64(), 3);
        assert_eq!(s.as_u64(), 4);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seq_round_trip_json() {
        let s = Seq::from_u64(999);
        let back: Seq = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seq_round_trip_cbor() {
        let s = Seq::from_u64(999);
        let mut buf = Vec::new();
        ciborium::into_writer(&s, &mut buf).unwrap();
        let back: Seq = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn sim_time_epoch_is_zero() {
        assert_eq!(SimTime::EPOCH.as_nanos(), 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn sim_time_add_duration() {
        let t = SimTime::from_nanos(1000);
        let d = SimDuration::from_nanos(500);
        assert_eq!(t.checked_add(d).unwrap().as_nanos(), 1500);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn sim_time_sub_duration() {
        let a = SimTime::from_nanos(1000);
        let b = SimTime::from_nanos(400);
        assert_eq!(a.checked_sub(b).unwrap().as_nanos(), 600);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn sim_duration_from_secs() {
        assert_eq!(SimDuration::from_secs(1).as_nanos(), 1_000_000_000);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn sim_duration_from_millis() {
        assert_eq!(SimDuration::from_millis(1).as_nanos(), 1_000_000);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn sim_time_round_trip_json() {
        let t = SimTime::from_nanos(-42);
        let back: SimTime = serde_json::from_str(&serde_json::to_string(&t).unwrap()).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn sim_time_round_trip_cbor() {
        let t = SimTime::from_nanos(999_999);
        let mut buf = Vec::new();
        ciborium::into_writer(&t, &mut buf).unwrap();
        let back: SimTime = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(t, back);
    }

    proptest::proptest! {
        #[test]
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn seq_ord_is_total(a: u64, b: u64) {
            let sa = Seq::from_u64(a);
            let sb = Seq::from_u64(b);
            let lt = sa < sb;
            let eq = sa == sb;
            let gt = sa > sb;
            assert_eq!(u8::from(lt) + u8::from(eq) + u8::from(gt), 1);
        }

        #[test]
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn seq_ord_stable_after_serde(a: u64, b: u64) {
            let sa = Seq::from_u64(a);
            let sb = Seq::from_u64(b);
            let sa2: Seq = serde_json::from_str(&serde_json::to_string(&sa).unwrap()).unwrap();
            let sb2: Seq = serde_json::from_str(&serde_json::to_string(&sb).unwrap()).unwrap();
            assert_eq!(sa.cmp(&sb), sa2.cmp(&sb2));
        }

        #[test]
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn wall_time_ord_is_total(a: u64, b: u64) {
            let ta = WallTime::from_micros(a);
            let tb = WallTime::from_micros(b);
            let lt = ta < tb;
            let eq = ta == tb;
            let gt = ta > tb;
            assert_eq!(u8::from(lt) + u8::from(eq) + u8::from(gt), 1);
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn wall_time_as_micros_roundtrip() {
        let t = WallTime::from_micros(42);
        assert_eq!(t.as_micros(), 42);
    }
}
