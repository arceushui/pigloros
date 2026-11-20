//! The deployment trust of every Local erasure root: the authenticated
//! current TPS1 of the profile's trust state store (ADR-104, ADR-135; owner
//! decision Q1 of 2026-11-17 on #1412).
//!
//! The release anchor is never read from the TPS1 it authenticates. The
//! operator installs it as the systemd credential
//! [`RELEASE_TRUST_CREDENTIAL_NAME`], a TOML document that pins the
//! policy id, the operator's Ed25519 public key and the digest of the
//! genesis TPS1, each key and digest as 64 lowercase hex characters:
//!
//! ```toml
//! policy_id = "pigloros-local"
//! operator_public_key = "<64 lowercase hex characters>"
//! genesis_digest = "<64 lowercase hex characters>"
//! ```
//!
//! The trust state store lives at the fixed path
//! [`DEPLOYMENT_TRUST_STATE_PATH`]; it is provisioned explicitly, never by
//! the Gateway. [`load_deployment_trust_v1`] opens it read-only against the
//! anchor and returns its current TPS1 through
//! `DeploymentTrustPolicyRegistryV1::current_trust_policy`, so every
//! consumer sees a TPS1 the operator key signed and the genesis chain
//! reaches. The Gateway's `provision-local-erasure` and serve composition
//! and every key-less root ([`crate::LocalErasureRecoveryV1`]) use it.
//!
//! The constants exist on every target; the trust state store, and so the
//! loader, is Linux-only.

#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
use pos_store::trust_policy_registry::{
    CurrentTrustPolicyV1, DeploymentTrustPolicyRegistryV1, OperatorReleaseTrustV1,
    TrustPolicyRegistryErrorV1,
};
#[cfg(target_os = "linux")]
use serde::Deserialize;
#[cfg(target_os = "linux")]
use thiserror::Error;

/// The systemd credential that pins the deployment release anchor.
pub const RELEASE_TRUST_CREDENTIAL_NAME: &str = "pigloros.release-trust";

/// The largest release-anchor credential accepted.
pub const MAX_RELEASE_TRUST_CREDENTIAL_BYTES: usize = 4_096;

/// The fixed path of the deployment trust state store.
pub const DEPLOYMENT_TRUST_STATE_PATH: &str = "/var/lib/pigloros/trust-state.db";

#[cfg(target_os = "linux")]
/// Closed deployment-trust failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum DeploymentTrustErrorV1 {
    /// The release-anchor credential is not the documented TOML document.
    #[error("the release trust credential is invalid")]
    ReleaseTrustInvalid,
    /// The trust state store is missing, corrupt or does not authenticate
    /// against the release anchor.
    #[error("deployment trust is unavailable: {0}")]
    TrustState(TrustPolicyRegistryErrorV1),
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseTrustDocumentV1 {
    policy_id: String,
    operator_public_key: String,
    genesis_digest: String,
}

#[cfg(target_os = "linux")]
/// Decode the release-anchor credential.
///
/// # Errors
/// Returns [`DeploymentTrustErrorV1::ReleaseTrustInvalid`] for anything but
/// UTF-8 TOML with exactly the three documented fields, each key and digest
/// 64 lowercase hex characters.
pub fn release_trust_from_credential(
    bytes: &[u8],
) -> Result<OperatorReleaseTrustV1, DeploymentTrustErrorV1> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| toml::from_str::<ReleaseTrustDocumentV1>(text).ok())
        .and_then(|document| {
            lower_hex_32(&document.operator_public_key)
                .zip(lower_hex_32(&document.genesis_digest))
                .map(|(operator_public_key, genesis_digest)| {
                    OperatorReleaseTrustV1::new(
                        document.policy_id,
                        operator_public_key,
                        genesis_digest,
                    )
                })
        })
        .ok_or(DeploymentTrustErrorV1::ReleaseTrustInvalid)
}

#[cfg(target_os = "linux")]
/// The current TPS1 of the trust state store at `state_path`,
/// authenticated against `release`.
///
/// # Errors
/// Returns [`DeploymentTrustErrorV1::TrustState`] when the store is
/// missing, corrupt, replaced, or holds a TPS1 the anchor does not
/// authenticate.
pub fn load_deployment_trust_v1(
    state_path: &Path,
    release: OperatorReleaseTrustV1,
) -> Result<CurrentTrustPolicyV1, DeploymentTrustErrorV1> {
    DeploymentTrustPolicyRegistryV1::open_current(state_path, release)
        .and_then(|registry| registry.current_trust_policy())
        .map_err(DeploymentTrustErrorV1::TrustState)
}

#[cfg(target_os = "linux")]
/// Decode exactly 64 lowercase hex characters.
fn lower_hex_32(text: &str) -> Option<[u8; 32]> {
    let nibbles = text
        .bytes()
        .map(|byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        })
        .collect::<Option<Vec<u8>>>()?;
    (nibbles.len() == 64)
        .then(|| std::array::from_fn(|index| nibbles[2 * index] * 16 + nibbles[2 * index + 1]))
}

#[cfg(all(test, target_os = "linux"))]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn document(key: &str, digest: &str) -> String {
        format!(
            "policy_id = \"pigloros-local\"\noperator_public_key = \"{key}\"\ngenesis_digest = \"{digest}\"\n"
        )
    }

    #[test]
    fn the_release_trust_is_exactly_the_documented_toml() {
        let key = "0123456789abcdef".repeat(4);
        let digest = "fe".repeat(32);
        assert!(release_trust_from_credential(document(&key, &digest).as_bytes()).is_ok());
        for invalid in [
            vec![0xff, 0xfe],
            b"policy_id = ".to_vec(),
            format!("{}extra = 1\n", document(&key, &digest)).into_bytes(),
            document(&key.to_uppercase(), &digest).into_bytes(),
            document(&key, &digest[..62]).into_bytes(),
            document(&format!("{key}00"), &digest).into_bytes(),
            document("g".repeat(64).as_str(), &digest).into_bytes(),
        ] {
            assert_eq!(
                release_trust_from_credential(&invalid).err(),
                Some(DeploymentTrustErrorV1::ReleaseTrustInvalid)
            );
        }
    }

    #[test]
    fn lower_hex_decodes_each_byte_from_its_high_and_low_nibble() {
        let key = "0123456789abcdef".repeat(4);
        let expected: [u8; 32] = std::array::from_fn(|index| {
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef][index % 8]
        });
        assert_eq!(lower_hex_32(&key), Some(expected));
        assert_eq!(lower_hex_32(&"fe".repeat(32)), Some([0xfe; 32]));
    }

    #[test]
    fn a_missing_trust_state_store_is_unavailable() -> TestResult {
        let directory = tempfile::tempdir()?;
        let release = OperatorReleaseTrustV1::new("pigloros-local".to_owned(), [1; 32], [2; 32]);
        let error = load_deployment_trust_v1(&directory.path().join("absent.db"), release)
            .err()
            .ok_or("an absent store has no trust")?;
        assert_eq!(
            error,
            DeploymentTrustErrorV1::TrustState(TrustPolicyRegistryErrorV1::MissingState)
        );
        assert!(error.to_string().contains("not provisioned"));
        assert_eq!(
            DeploymentTrustErrorV1::ReleaseTrustInvalid.to_string(),
            "the release trust credential is invalid"
        );
        Ok(())
    }
}
