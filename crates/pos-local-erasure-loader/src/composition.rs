//! The Local erasure composition every root shares.
//!
//! It passes the installed bundle credentials, the deployment trust and the
//! recorded Local Principal to [`ErasureCoordinatorCompositionV1::local`].
//!
//! The Gateway passes its executor's binding and composes the authority
//! its signer and driver serve; a key-less root passes none
//! ([`crate::LocalErasureRecoveryV1`]).

use std::path::Path;

use pos_core::{
    AuthorityPersistencePortV1, ErasureInventoryPersistencePortV1, ErasurePersistencePortV1,
    ErasureReferenceV1, EventStore, LocalErasureExecutionBindingV1,
};
use pos_runtime::{ErasureCoordinatorCompositionV1, LocalErasureCompositionInputsV1};
use pos_store::trust_policy_registry::OperatorReleaseTrustV1;
use zeroize::Zeroizing;

use crate::credentials::ExactCredentialsV1;
use crate::deployment_trust::{
    load_deployment_trust_v1, release_trust_from_credential, MAX_RELEASE_TRUST_CREDENTIAL_BYTES,
    RELEASE_TRUST_CREDENTIAL_NAME,
};
use crate::local_principal::{
    local_principal_authority_timeline, local_principal_grant_id, recorded_registry_digest,
};
use crate::{
    LocalErasureLoadErrorV1, LOCAL_ERASURE_BUNDLE_CREDENTIAL_NAME,
    LOCAL_ERASURE_BUNDLE_SIGNATURE_CREDENTIAL_NAME, MAX_LOCAL_ERASURE_BUNDLE_CREDENTIAL_BYTES,
};

/// The installed bundle, its signature and the decoded release anchor.
pub struct LocalErasureTrustCredentialsV1 {
    /// The installed ELB1 bytes.
    pub bundle: Zeroizing<Vec<u8>>,
    /// The installed ELB1S bytes.
    pub bundle_signature: Zeroizing<Vec<u8>>,
    /// The deployment release anchor.
    pub release: OperatorReleaseTrustV1,
}

impl LocalErasureTrustCredentialsV1 {
    /// Read the bundle, its signature and the release anchor from
    /// `credentials`, each within its bound, and decode the anchor.
    ///
    /// # Errors
    /// Returns [`LocalErasureLoadErrorV1::Credentials`] for an unreadable or
    /// over-long credential and [`LocalErasureLoadErrorV1::Trust`] for a
    /// release anchor that is not the documented TOML document.
    pub fn read(credentials: &ExactCredentialsV1) -> Result<Self, LocalErasureLoadErrorV1> {
        let read = |name: &str, maximum: usize| {
            credentials
                .read(name, maximum)
                .ok()
                .ok_or(LocalErasureLoadErrorV1::Credentials)
        };
        let bundle_bytes = MAX_LOCAL_ERASURE_BUNDLE_CREDENTIAL_BYTES;
        read(LOCAL_ERASURE_BUNDLE_CREDENTIAL_NAME, bundle_bytes)
            .and_then(|bundle| {
                read(LOCAL_ERASURE_BUNDLE_SIGNATURE_CREDENTIAL_NAME, bundle_bytes)
                    .map(|signature| (bundle, signature))
            })
            .and_then(|(bundle, bundle_signature)| {
                read(
                    RELEASE_TRUST_CREDENTIAL_NAME,
                    MAX_RELEASE_TRUST_CREDENTIAL_BYTES,
                )
                .and_then(|release| {
                    release_trust_from_credential(&release).map_err(LocalErasureLoadErrorV1::Trust)
                })
                .map(|release| Self {
                    bundle,
                    bundle_signature,
                    release,
                })
            })
    }
}

/// The bundle, the trust state store and the executor binding of one
/// composition.
#[derive(Clone, Copy)]
pub struct LocalErasureLoadInputsV1<'a> {
    /// The installed ELB1 bytes.
    pub bundle: &'a [u8],
    /// The installed ELB1S bytes.
    pub bundle_signature: &'a [u8],
    /// The deployment trust state store.
    pub trust_state: &'a Path,
    /// The composed executor's binding, or `None` for a root that composes
    /// no executor.
    pub execution_binding: Option<&'a LocalErasureExecutionBindingV1>,
}

/// Compose the Local erasure authority over `store`.
///
/// It runs under the TPS1 the trust state store holds for `release`, bound
/// to the Local Principal the store records, with the Unix clock
/// ([`crate::unix_now`]).
///
/// # Errors
/// Returns [`LocalErasureLoadErrorV1::Trust`] when the trust state store
/// does not authenticate, [`LocalErasureLoadErrorV1::Principal`] when the
/// Local Principal record cannot be read,
/// [`LocalErasureLoadErrorV1::PrincipalMissing`] when the store records
/// none, and [`LocalErasureLoadErrorV1::Composition`] when the bundle keeps
/// the authority closed.
pub fn compose_local_erasure<S>(
    store: &mut S,
    inputs: &LocalErasureLoadInputsV1<'_>,
    release: OperatorReleaseTrustV1,
) -> Result<ErasureCoordinatorCompositionV1, LocalErasureLoadErrorV1>
where
    S: ErasureInventoryPersistencePortV1
        + ErasurePersistencePortV1
        + EventStore
        + AuthorityPersistencePortV1
        + ?Sized,
{
    let operator_public_key = release.operator_public_key();
    load_deployment_trust_v1(inputs.trust_state, release)
        .map_err(LocalErasureLoadErrorV1::Trust)
        .and_then(|trust| {
            recorded_registry_digest(&*store)
                .map_err(LocalErasureLoadErrorV1::Principal)
                .and_then(|registry| registry.ok_or(LocalErasureLoadErrorV1::PrincipalMissing))
                .and_then(|registry| {
                    ErasureCoordinatorCompositionV1::local(
                        &LocalErasureCompositionInputsV1 {
                            bundle: inputs.bundle,
                            bundle_signature: inputs.bundle_signature,
                            trust: &trust,
                            operator_public_key,
                            authority_registry_digest: ErasureReferenceV1::from_digest(
                                *registry.as_bytes(),
                            ),
                            execution_binding: inputs.execution_binding,
                            principal_grant: local_principal_grant_id(),
                            authority_timeline: local_principal_authority_timeline(),
                            clock: crate::unix_now,
                        },
                        store,
                    )
                    .map_err(LocalErasureLoadErrorV1::Composition)
                })
        })
}
