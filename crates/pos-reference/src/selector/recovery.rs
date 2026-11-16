//! Root-owned recovery of one pending SIR1 transaction (ADR-069 R12).
//!
//! A pending SIR1 is loaded only from the fixed installation root, and only
//! when the selector can rebuild it byte for byte from the installed objects
//! (R12 §4.1). The loaded [`PendingRecoveryTarget`] names its exact
//! transaction through [`RecoveryTransactionIdentity`]. Neither type can be
//! constructed, cloned, serialized or decoded outside this module.
//!
//! While a target is pending the selector stays closed: it exposes no
//! evaluator endpoint and its administrative listener answers only the
//! mode-1 challenge of this transaction (R12 §8).

use crate::selector::installation::authority::{InstallationChallenge, VerifiedPendingRecovery};
use crate::selector::installation::InstalledSelectorState;
use crate::selector::SelectorBoundaryError;

/// Closed failures of one recovery operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecoveryError {
    /// The pending SIR1, or a record or object it names, failed authentication.
    #[error(transparent)]
    Boundary(#[from] SelectorBoundaryError),
    /// The evaluator endpoint pathname exists while a SIR1 is pending.
    ///
    /// The selector never unlinks a crash-stale node, so recovery stops
    /// closed until an operator removes it (ADR-069 R12 §8 M4).
    #[error("the evaluator endpoint exists while recovery is pending")]
    EvaluatorEndpointPresent,
}

impl From<RecoveryError> for SelectorBoundaryError {
    fn from(error: RecoveryError) -> Self {
        match error {
            RecoveryError::Boundary(error) => error,
            RecoveryError::EvaluatorEndpointPresent => Self::ArtifactInvalid,
        }
    }
}

/// Requires that no node exists at the evaluator endpoint `pathname`.
///
/// It only inspects the pathname, without following a symlink, and never
/// removes anything.
///
/// # Errors
/// Returns [`RecoveryError::EvaluatorEndpointPresent`] for any node at
/// `pathname`, and [`RecoveryError::Boundary`] when it cannot be inspected.
pub(crate) fn require_absent_evaluator_endpoint(
    pathname: &std::path::Path,
) -> Result<(), RecoveryError> {
    std::fs::symlink_metadata(pathname).map_or_else(
        |error| {
            (error.kind() == std::io::ErrorKind::NotFound)
                .then_some(())
                .ok_or(RecoveryError::Boundary(SelectorBoundaryError::Io))
        },
        |_| Err(RecoveryError::EvaluatorEndpointPresent),
    )
}

/// One authenticated pending SIR1, loaded only from the fixed installation
/// root.
///
/// Its fields are private, so no other module can build one:
///
/// ```compile_fail,E0451
/// use pos_reference::selector::recovery::PendingRecoveryTarget;
///
/// let _ = PendingRecoveryTarget { pending_update: Vec::new() };
/// ```
///
/// It is not `Clone`:
///
/// ```compile_fail,E0277
/// use pos_reference::selector::recovery::PendingRecoveryTarget;
///
/// fn duplicate<T: Clone>() {}
/// duplicate::<PendingRecoveryTarget>();
/// ```
///
/// and it has no decoder:
///
/// ```compile_fail,E0599
/// use pos_reference::selector::recovery::PendingRecoveryTarget;
///
/// let _ = PendingRecoveryTarget::from_canonical_cbor(&[]);
/// ```
#[derive(Debug)]
pub struct PendingRecoveryTarget {
    identity: RecoveryTransactionIdentity,
    previous_installation_digest: [u8; 32],
    selector_nonce: [u8; 16],
    pending_update: Vec<u8>,
}

impl PendingRecoveryTarget {
    /// Loads the pending SIR1 of `installed`.
    ///
    /// SIR1 is decoded within its 48 MiB bound and must be rebuilt byte for
    /// byte: the current SIC1 equals its previous or next SIC1, both states
    /// and every object they name are revalidated, RCU1 is re-authenticated
    /// against the previous state, RCC1 is re-derived, and the previous
    /// role-3 runtime key is resolved from the previous SIC1, TRS1, RVS1 and
    /// SPM1 even when the next RVS1 revokes it.
    ///
    /// # Errors
    /// Returns [`RecoveryError::Boundary`] for any SIR1, record or object that
    /// fails those checks.
    pub(crate) fn load(installed: &InstalledSelectorState) -> Result<Self, RecoveryError> {
        VerifiedPendingRecovery::load(installed)
            .map(Self::from_verified)
            .map_err(RecoveryError::from)
    }

    fn from_verified(verified: VerifiedPendingRecovery) -> Self {
        Self {
            identity: RecoveryTransactionIdentity {
                sir1_digest: verified.sir1_digest,
                previous_provider_binding_digest: verified.previous_provider_binding_digest,
                previous_runtime_instance_id: verified.previous_runtime_instance_id,
                previous_lifecycle_scope_id: verified.previous_lifecycle_scope_id,
                previous_live_attempt_ids: verified.previous_live_attempt_ids,
                recovery_peer_slot: verified.recovery_peer_slot,
            },
            previous_installation_digest: verified.previous_installation_digest,
            selector_nonce: verified.selector_nonce,
            pending_update: verified.pending_update,
        }
    }

    /// The exact transaction this target names.
    #[must_use]
    pub const fn identity(&self) -> &RecoveryTransactionIdentity {
        &self.identity
    }

    /// The exact SIU1 that committed this SIR1, rebuilt from it.
    pub(crate) fn pending_update_bytes(&self) -> &[u8] {
        &self.pending_update
    }

    /// A fresh SICN1 mode-1 challenge: the previous SIC1 digest and the
    /// nonce of the committed RCU1.
    pub(crate) fn challenge(&self) -> InstallationChallenge {
        InstallationChallenge::for_pending_transaction(
            self.previous_installation_digest,
            self.selector_nonce,
        )
    }
}

/// The tuple that names one pending transaction (ADR-069 §4.1).
///
/// Its elements are the SIR1 digest, the previous-provider binding digest,
/// the previous runtime and lifecycle-scope IDs, the complete previous-live
/// attempt set, and the recovery-peer slot.
///
/// Equality compares every element. The type is not `Clone`, `Copy`,
/// `Serialize` or `Deserialize`; its fields are private:
///
/// ```compile_fail,E0451
/// use pos_reference::selector::recovery::RecoveryTransactionIdentity;
///
/// let _ = RecoveryTransactionIdentity { sir1_digest: [0; 32] };
/// ```
///
/// ```compile_fail,E0277
/// use pos_reference::selector::recovery::RecoveryTransactionIdentity;
///
/// fn duplicate<T: Clone>() {}
/// duplicate::<RecoveryTransactionIdentity>();
/// ```
///
/// ```compile_fail,E0599
/// use pos_reference::selector::recovery::RecoveryTransactionIdentity;
///
/// let _ = RecoveryTransactionIdentity::from_canonical_cbor(&[]);
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct RecoveryTransactionIdentity {
    sir1_digest: [u8; 32],
    previous_provider_binding_digest: [u8; 32],
    previous_runtime_instance_id: [u8; 16],
    previous_lifecycle_scope_id: [u8; 16],
    previous_live_attempt_ids: Vec<[u8; 16]>,
    /// Recovery runtime, lifecycle-scope and endpoint IDs, in that order.
    recovery_peer_slot: [[u8; 16]; 3],
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::fs::File;

    use super::*;
    use crate::selector::installation::tests::updates::{SuccessorRevocation, UpdateFixture};
    use crate::selector::installation::FixedInstallation;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn pending_target(fixture: &UpdateFixture) -> TestResult<PendingRecoveryTarget> {
        match InstalledSelectorState::open_fixed_at_for_test(&File::open(fixture.path())?)? {
            FixedInstallation::RecoveryPending(installed) => {
                Ok(PendingRecoveryTarget::load(&installed)?)
            }
            FixedInstallation::Admissible(_) => Err("no SIR1 is pending".into()),
        }
    }

    #[test]
    fn a_reloaded_target_names_the_same_transaction() -> TestResult {
        let fixture = UpdateFixture::new()?;
        let (committed, request) = fixture.commit_pending_update(
            vec![[41; 16], [42; 16]],
            vec![[42; 16]],
            SuccessorRevocation::Nothing,
        )?;
        let first = pending_target(&fixture)?;
        let second = pending_target(&fixture)?;
        assert_eq!(first.identity(), second.identity());
        assert_eq!(first.identity().sir1_digest, committed.sir1_digest());
        assert_eq!(
            first.identity().previous_provider_binding_digest,
            committed
                .cancellation_context()?
                .previous_provider_binding_digest
        );
        assert_eq!(
            first.identity().previous_live_attempt_ids,
            vec![[41; 16], [42; 16]]
        );
        assert_eq!(first.pending_update_bytes(), request);
        Ok(())
    }

    #[test]
    fn identity_equality_compares_every_element() -> TestResult {
        let fixture = UpdateFixture::new()?;
        fixture.commit_pending_update(
            vec![[41; 16]],
            vec![[41; 16]],
            SuccessorRevocation::Nothing,
        )?;
        let reference = pending_target(&fixture)?.identity;
        let mutations: [fn(&mut RecoveryTransactionIdentity); 6] = [
            |identity| identity.sir1_digest[0] ^= 1,
            |identity| identity.previous_provider_binding_digest[0] ^= 1,
            |identity| identity.previous_runtime_instance_id[0] ^= 1,
            |identity| identity.previous_lifecycle_scope_id[0] ^= 1,
            |identity| identity.previous_live_attempt_ids.push([99; 16]),
            |identity| identity.recovery_peer_slot[2][0] ^= 1,
        ];
        for mutate in mutations {
            let mut changed = pending_target(&fixture)?.identity;
            assert_eq!(changed, reference);
            mutate(&mut changed);
            assert_ne!(changed, reference);
        }
        Ok(())
    }

    #[test]
    fn the_mode_one_challenge_names_the_pending_transaction() -> TestResult {
        let fixture = UpdateFixture::new()?;
        let (_committed, request) =
            fixture.commit_pending_update(Vec::new(), Vec::new(), SuccessorRevocation::Nothing)?;
        let target = pending_target(&fixture)?;
        let challenge =
            crate::evaluator_protocol::decode_canonical(&target.challenge().to_canonical_cbor()?)?;
        let fields = crate::evaluator_protocol::array(&challenge, 5)?;
        let update = crate::evaluator_protocol::decode_canonical(&request)?;
        let update_fields = crate::evaluator_protocol::array(&update, 5)?;
        assert_eq!(fields[0], ciborium::value::Value::Text("SICN1".to_owned()));
        assert_eq!(fields[2], update_fields[2]);
        assert_eq!(crate::evaluator_protocol::uint(&fields[4])?, 1);
        let ciborium::value::Value::Bytes(rcu1) = &update_fields[4] else {
            return Err("SIU1 RCU1 is not bytes".into());
        };
        let rcu1 = crate::evaluator_protocol::decode_canonical(rcu1)?;
        let rcu1_fields =
            crate::evaluator_protocol::array(&crate::evaluator_protocol::array(&rcu1, 3)?[0], 8)?;
        assert_eq!(fields[3], rcu1_fields[6]);
        Ok(())
    }

    #[test]
    fn recovery_errors_close_as_boundary_errors() {
        assert_eq!(
            SelectorBoundaryError::from(RecoveryError::from(SelectorBoundaryError::Io)),
            SelectorBoundaryError::Io
        );
        assert_eq!(
            SelectorBoundaryError::from(RecoveryError::EvaluatorEndpointPresent),
            SelectorBoundaryError::ArtifactInvalid
        );
    }

    #[test]
    fn any_node_at_the_evaluator_endpoint_stops_recovery_and_is_kept() -> TestResult {
        let directory = tempfile::tempdir()?;
        let endpoint = directory.path().join("sandbox-provider.sock");
        require_absent_evaluator_endpoint(&endpoint)?;

        drop(std::os::unix::net::UnixListener::bind(&endpoint)?);
        assert_eq!(
            require_absent_evaluator_endpoint(&endpoint),
            Err(RecoveryError::EvaluatorEndpointPresent)
        );
        assert!(endpoint.exists());
        std::fs::remove_file(&endpoint)?;

        std::os::unix::fs::symlink("missing-target", &endpoint)?;
        assert_eq!(
            require_absent_evaluator_endpoint(&endpoint),
            Err(RecoveryError::EvaluatorEndpointPresent)
        );
        assert!(std::fs::symlink_metadata(&endpoint).is_ok());

        // A parent that is not a directory cannot be inspected.
        let file = directory.path().join("file");
        std::fs::write(&file, b"")?;
        assert_eq!(
            require_absent_evaluator_endpoint(&file.join("sandbox-provider.sock")),
            Err(RecoveryError::Boundary(SelectorBoundaryError::Io))
        );
        Ok(())
    }
}
