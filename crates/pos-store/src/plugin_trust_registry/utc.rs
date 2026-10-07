//! The trusted UTC second of one registry transaction.

use pos_core::trusted_clock::TrustedWallSourceV1;

use super::error::PluginTrustPolicyRegistryErrorV1;

const MICROS_PER_SECOND: u64 = 1_000_000;

/// One signed UTC second sampled from the sealed ADR-112 trusted wall source.
///
/// The only production constructor is [`Self::from_source`]. Because
/// `TrustedWallSourceV1` is sealed, no caller, TPS1, PTR1, PRV1, or Plugin can
/// supply another source.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TrustedUtcSecondV1(i64);

impl TrustedUtcSecondV1 {
    /// Sample `source` once and floor the microseconds to whole seconds.
    ///
    /// A sample is a non-negative microsecond count bounded by `i64::MAX`, so
    /// the integer division equals the floor and cannot overflow.
    ///
    /// # Errors
    /// Returns `TrustedTimeUnavailable` when the source fails.
    pub fn from_source(
        source: &mut impl TrustedWallSourceV1,
    ) -> Result<Self, PluginTrustPolicyRegistryErrorV1> {
        source
            .sample()
            .or(Err(
                PluginTrustPolicyRegistryErrorV1::TrustedTimeUnavailable,
            ))
            .and_then(|sample| {
                i64::try_from(sample.as_micros() / MICROS_PER_SECOND).or(Err(
                    PluginTrustPolicyRegistryErrorV1::TrustedTimeUnavailable,
                ))
            })
            .map(Self)
    }

    /// The UTC second since the Unix epoch.
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self.0
    }
}
