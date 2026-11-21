#![cfg(any(test, feature = "test-support"))]
//! The owner V2 consent permit mint (ADR-137 L8, G2).
//!
//! It stays in this test-support-gated module until activation (#1438):
//! minting an [`OwnerConsentV2PermitV1`] outside test support is activation
//! surface item (viii).

use crate::consent::OwnerConsentV2PermitV1;
use crate::CoreError;

type Entropy = fn(&mut [u8]) -> Result<(), getrandom::Error>;

/// Mint a fresh owner V2 consent permit from operating-system randomness.
///
/// # Errors
/// Returns a [`CoreError::Storage`] refusal when no randomness is available.
pub fn mint_owner_consent_v2_permit() -> Result<OwnerConsentV2PermitV1, CoreError> {
    mint_with(getrandom::fill)
}

fn mint_with(fill: Entropy) -> Result<OwnerConsentV2PermitV1, CoreError> {
    let mut nonce = [0; 32];
    fill(&mut nonce)
        .map(|()| OwnerConsentV2PermitV1::from_nonce(nonce))
        .map_err(|_| CoreError::Storage("owner consent permit randomness unavailable".to_owned()))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn a_failed_entropy_source_mints_nothing() {
        let refused = mint_with(|_| Err(getrandom::Error::UNSUPPORTED));
        assert_eq!(
            refused.map_err(|error| error.to_string()),
            Err("storage error: owner consent permit randomness unavailable".to_owned())
        );
    }

    #[test]
    fn the_permit_carries_the_entropy_and_hides_it_in_debug() -> Result<(), CoreError> {
        let first = mint_with(|bytes| {
            bytes.fill(7);
            Ok(())
        })?;
        let same = mint_with(|bytes| {
            bytes.fill(7);
            Ok(())
        })?;
        let other = mint_with(|bytes| {
            bytes.fill(8);
            Ok(())
        })?;
        assert_eq!(first, same);
        assert_ne!(first, other);
        assert_eq!(format!("{first:?}"), "OwnerConsentV2PermitV1(..)");
        Ok(())
    }
}
