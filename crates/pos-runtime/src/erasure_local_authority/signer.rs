//! `LocalErasureSignerV1`: the role-2 host signer of the single-host erasure
//! authority (ADR-136 §5; ticket #1431).
//!
//! The signer holds the role-2 private key and does not implement the
//! authority trait. Each signature is one host command: the signer first
//! re-derives the digest it is asked to sign from a fresh snapshot of the
//! committed state, then signs `["ELS1-SIG", 1, purpose, digest]` with
//! `sign_for_registered_role` against the store's key registry inside that
//! same command, and retains the ELS1. A digest it cannot re-derive is
//! refused, so the signer is no blind-signing oracle: its signature attests
//! that the host verified what it signs, not merely that the driver asked.

use pos_core::{
    local_erasure_signature_message_v1, CanonicalBytes, ErasureHostErrorV1, ErasureReferenceV1,
    KeyIdentityV1, KeyRoleV1, LocalErasureSignaturePurposeV1, LocalErasureSignatureV1,
    LocalErasureSignerIdentityV1, OwnerIdV1,
};
use pos_crypto::key_roles::{sign_for_registered_role, SigningKeyMaterial};

use crate::erasure_host::LocalFreezePreparationV1;
use crate::{ErasureCommandSenderV1, ErasureExecutionHostV1};

/// What the driver asks the signer to sign (ADR-136 §5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalErasureSigningRequestV1 {
    /// Purpose 0: the ERFA1-AUTH `body` digest of the freeze of `request`,
    /// which must equal the body the freeze of the current snapshot admits
    /// under the compiled ELP1 and the bundle.
    FreezeAuthorization {
        /// The ERQ1 request to freeze.
        request: ErasureReferenceV1,
        /// `CA(ERFA1-AUTH)`.
        body: ErasureReferenceV1,
    },
    /// Purpose 1: `CA(ELO1)` of an owner result, which must answer a
    /// command of its request's active attempt and bind exactly the effect
    /// committed with it.
    OwnerResult {
        /// `CA(ELO1)`.
        owner_result: ErasureReferenceV1,
    },
    /// Purpose 2: the ERCB1 `body` digest of the receipt that closes the
    /// active attempt of `request`, which must equal the body recomputed
    /// from the committed record and the effective acknowledgement
    /// inventory.
    ReceiptBody {
        /// The ERQ1 request whose attempt the receipt closes.
        request: ErasureReferenceV1,
        /// `CA(ERCB1)`.
        body: ErasureReferenceV1,
    },
}

/// The role-2 signer of one Local erasure deployment.
pub struct LocalErasureSignerV1 {
    key: SigningKeyMaterial,
    identity: KeyIdentityV1,
}

impl LocalErasureSignerV1 {
    /// A signer of the role-2 key `key`, registered in the store's key
    /// registry as `signer_identity` `[owner, 2, epoch]`, the identity and
    /// key the installed bundle pins.
    #[must_use]
    pub const fn new(key: SigningKeyMaterial, owner: OwnerIdV1, epoch: u64) -> Self {
        Self {
            key,
            identity: KeyIdentityV1::from_parts(owner, KeyRoleV1::TimelineIntegritySigning, epoch),
        }
    }

    /// Re-derive `request`'s digest and sign it as one host command, and
    /// return the address of the retained ELS1.
    ///
    /// Ed25519 is deterministic, so signing the same digest again, after a
    /// crash between signing and the lifecycle command, retains the same
    /// bytes at the same address.
    ///
    /// # Errors
    /// [`ErasureHostErrorV1::AuthorizationDenied`] when the digest does not
    /// re-derive, an owner result's ELO1 or effect is not committed, or the
    /// key registry refuses this key; [`ErasureHostErrorV1::Conflict`] for
    /// an owner result the active attempt does not dispatch; otherwise the
    /// payload-free error of a host that is not ready or a store that
    /// cannot be read or written.
    pub fn sign(
        &self,
        host: &mut ErasureExecutionHostV1,
        request: LocalErasureSigningRequestV1,
    ) -> Result<ErasureReferenceV1, ErasureHostErrorV1> {
        host.command_sender().and_then(|mut sender| {
            rederived(&mut sender, request)
                .and_then(|(purpose, digest)| self.signed(&mut sender, purpose, digest))
        })
    }

    /// Sign `digest` for `purpose` under the store's key registry and
    /// retain the ELS1.
    fn signed(
        &self,
        sender: &mut ErasureCommandSenderV1<'_>,
        purpose: LocalErasureSignaturePurposeV1,
        digest: ErasureReferenceV1,
    ) -> Result<ErasureReferenceV1, ErasureHostErrorV1> {
        sender
            .local_signing_registry()
            .and_then(|mut registry| {
                local_erasure_signature_message_v1(purpose, digest)
                    .ok()
                    .and_then(|message| {
                        sign_for_registered_role(
                            &mut registry,
                            &self.key,
                            self.identity,
                            &CanonicalBytes::from_vec(message),
                        )
                        .ok()
                    })
                    .and_then(|signature| {
                        LocalErasureSignatureV1 {
                            purpose,
                            signed_digest: digest,
                            signer_identity: LocalErasureSignerIdentityV1 {
                                owner_id: self.identity.owner_id.as_str().as_bytes().to_vec(),
                                epoch: self.identity.epoch,
                            },
                            signature: *signature.as_bytes(),
                        }
                        .to_canonical_cbor()
                        .ok()
                    })
                    .ok_or(ErasureHostErrorV1::AuthorizationDenied)
            })
            .and_then(|record| sender.retain_local_erasure_object(&record))
    }
}

/// The purpose and digest of `request` once the committed state re-derives
/// it.
///
/// # Errors
/// As [`LocalErasureSignerV1::sign`].
fn rederived(
    sender: &mut ErasureCommandSenderV1<'_>,
    request: LocalErasureSigningRequestV1,
) -> Result<(LocalErasureSignaturePurposeV1, ErasureReferenceV1), ErasureHostErrorV1> {
    match request {
        LocalErasureSigningRequestV1::FreezeAuthorization { request, body } => sender
            .local_freeze_preparation(request)
            .and_then(|(preparation, _)| {
                refused_unless(preparation == LocalFreezePreparationV1::Sign(body))
            })
            .map(|()| (LocalErasureSignaturePurposeV1::FreezeAuthorization, body)),
        LocalErasureSigningRequestV1::OwnerResult { owner_result } => sender
            .verified_owner_result(owner_result)
            .map(|()| (LocalErasureSignaturePurposeV1::OwnerResult, owner_result)),
        LocalErasureSigningRequestV1::ReceiptBody { request, body } => sender
            .prepare_local_receipt(request)
            .and_then(|preparation| refused_unless(preparation.body == body))
            .map(|()| (LocalErasureSignaturePurposeV1::ReceiptBody, body)),
    }
}

/// `Ok` only when the digest re-derived.
///
/// # Errors
/// [`ErasureHostErrorV1::AuthorizationDenied`] otherwise.
const fn refused_unless(rederived: bool) -> Result<(), ErasureHostErrorV1> {
    if rederived {
        Ok(())
    } else {
        Err(ErasureHostErrorV1::AuthorizationDenied)
    }
}
