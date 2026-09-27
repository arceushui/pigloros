//! Host-owned local Fork admission authority (ADR-099).
//!
//! These types deliberately separate trusted Principal-to-Owner provisioning
//! from an admitted Fork request.  A Fork caller cannot select an Owner,
//! child identifier, parent head, chain hash, or provenance bytes.

use crate::{
    AuthenticatedPrincipalResultV1, Hash, OwnerIdV1, PrincipalRefV1, TimelineId, WallTime,
};

/// Only locally committed authority is usable until the #447 import boundary exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkAuthorityOriginV1 {
    /// Locally committed authority.
    Local,
}

/// Closed errors returned by the Fork-admission authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkAdmissionErrorV1 {
    #[error("invalid Fork admission request")]
    InvalidRequest,
    #[error("authentication evidence is not trusted")]
    Unauthenticated,
    #[error("Principal-to-Owner binding conflicts")]
    PrincipalOwnerConflict,
    #[error("the completed fold boundary is stale")]
    StaleFoldBoundary,
    #[error("the parent Timeline changed")]
    ParentChanged,
    #[error("Fork admission conflicts with a committed operation")]
    Conflict,
    #[error("Fork admission authority is corrupt")]
    CorruptAuthority,
    #[error("Fork admission storage outcome is indeterminate")]
    StorageIndeterminate,
}

/// Host-pinned authentication policy for Principal-to-Owner provisioning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalOwnerTrustV1 {
    adapter_id: String,
    minimum_assurance: u8,
    authentication_bindings: Vec<Hash>,
}

impl PrincipalOwnerTrustV1 {
    /// Construct one independently trusted authentication policy.
    ///
    /// # Errors
    /// Rejects empty/oversized adapter identifiers, zero assurance, zero
    /// bindings, and duplicate or unordered bindings.
    pub fn new(
        adapter_id: String,
        minimum_assurance: u8,
        authentication_bindings: Vec<Hash>,
    ) -> Result<Self, ForkAdmissionErrorV1> {
        if adapter_id.is_empty()
            || adapter_id.len() > 128
            || minimum_assurance == 0
            || authentication_bindings.is_empty()
            || authentication_bindings
                .iter()
                .any(|value| *value == Hash::zero())
            || authentication_bindings
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(ForkAdmissionErrorV1::InvalidRequest);
        }
        Ok(Self {
            adapter_id,
            minimum_assurance,
            authentication_bindings,
        })
    }

    /// Validate current trusted adapter evidence at the host boundary.
    pub fn validate(
        &self,
        authenticated: &AuthenticatedPrincipalResultV1,
        now: WallTime,
    ) -> Result<(), ForkAdmissionErrorV1> {
        if authenticated.adapter_id() != self.adapter_id
            || authenticated.assurance().get() < self.minimum_assurance
            || authenticated.issued_at() > now
            || authenticated.expires_at() <= now
            || self
                .authentication_bindings
                .binary_search(&authenticated.registry_binding_digest())
                .is_err()
        {
            return Err(ForkAdmissionErrorV1::Unauthenticated);
        }
        Ok(())
    }
}

/// Immutable local `POB1` fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalOwnerBindingInputV1 {
    pub operation_id: Hash,
    pub principal_digest: Hash,
    pub owner: OwnerIdV1,
    pub origin: ForkAuthorityOriginV1,
}

/// Immutable local Principal-to-Owner binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalOwnerBindingV1(PrincipalOwnerBindingInputV1);

impl PrincipalOwnerBindingV1 {
    /// Validate one local POB1 binding.
    pub fn new(input: PrincipalOwnerBindingInputV1) -> Result<Self, ForkAdmissionErrorV1> {
        if input.operation_id == Hash::zero() || input.principal_digest == Hash::zero() {
            return Err(ForkAdmissionErrorV1::InvalidRequest);
        }
        Ok(Self(input))
    }

    #[must_use]
    pub const fn input(&self) -> &PrincipalOwnerBindingInputV1 {
        &self.0
    }

    /// Encode the exact six-field local POB1 CBOR array.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let value = &self.0;
        let mut output = Vec::with_capacity(128 + value.owner.as_str().len());
        output.push(0x86);
        bytes(&mut output, b"POB1");
        output.push(1);
        bytes(&mut output, value.operation_id.as_bytes());
        bytes(&mut output, value.principal_digest.as_bytes());
        text(&mut output, value.owner.as_str());
        output.push(0x81);
        output.push(1);
        output
    }

    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(
            b"pigloros/principal-owner-binding/v1",
            &self.to_canonical_cbor(),
        )
    }
}

/// Compute the exact ADR-099 PrincipalRef digest.
pub fn principal_digest_v1(principal: &PrincipalRefV1) -> Result<Hash, ForkAdmissionErrorV1> {
    principal
        .encode()
        .map(|bytes| digest(b"pigloros/principal-ref/v1", bytes.as_slice()))
        .map_err(|_| ForkAdmissionErrorV1::Unauthenticated)
}

/// Return the exact host-request binding used to recognize an admission retry.
pub fn fork_admission_request_digest_v1(
    request: &CreateForkAdmittedRequestV1,
) -> Result<Hash, ForkAdmissionErrorV1> {
    let principal = request
        .authenticated
        .principal()
        .encode()
        .map_err(|_| ForkAdmissionErrorV1::Unauthenticated)?;
    let mut bytes_out = Vec::new();
    bytes(&mut bytes_out, request.operation_id.as_bytes());
    bytes(&mut bytes_out, principal.as_slice());
    text(&mut bytes_out, request.authenticated.adapter_id());
    bytes_out.push(request.authenticated.assurance().get());
    bytes_out.extend_from_slice(&request.authenticated.issued_at().as_micros().to_be_bytes());
    bytes_out.extend_from_slice(&request.authenticated.expires_at().as_micros().to_be_bytes());
    bytes(
        &mut bytes_out,
        request.authenticated.binding_digest().as_bytes(),
    );
    bytes(
        &mut bytes_out,
        &request.parent_timeline_id.inner().to_bytes(),
    );
    bytes_out.extend_from_slice(&request.completed_fold_cursor.to_be_bytes());
    bytes_out.extend_from_slice(&request.post_fold_tick_boundary.to_be_bytes());
    bytes(
        &mut bytes_out,
        request.room_revision_descriptor_hash.as_bytes(),
    );
    bytes(&mut bytes_out, request.plugin_composition_hash.as_bytes());
    bytes_out.push(u8::from(request.attribution_required));
    text(&mut bytes_out, &request.child_name);
    Ok(digest(b"pigloros/fork-admission-request/v1", &bytes_out))
}

/// Host-resolved, caller-limited Fork admission request.
///
/// The trusted host derives the room revision, Plugin composition, and
/// attribution policy from its admitted Room state at the completed Tick
/// Boundary. A network client must never construct this value directly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateForkAdmittedRequestV1 {
    pub operation_id: Hash,
    pub authenticated: AuthenticatedPrincipalResultV1,
    pub parent_timeline_id: TimelineId,
    pub completed_fold_cursor: u64,
    pub post_fold_tick_boundary: u64,
    pub room_revision_descriptor_hash: Hash,
    pub plugin_composition_hash: Hash,
    pub attribution_required: bool,
    pub child_name: String,
}

/// Receipt returned only after child and FAR1 commit together.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkAdmissionReceiptV1 {
    pub child_id: TimelineId,
    pub admission_digest: Hash,
}

/// Storage authority for trusted local POB1 and atomic FAR1 child creation.
pub trait ForkAdmissionAuthorityPortV1 {
    /// Pin the host's authentication trust policy. Rebinding different policy rejects.
    fn bind_principal_owner_trust(
        &mut self,
        trust: PrincipalOwnerTrustV1,
    ) -> Result<(), ForkAdmissionErrorV1>;

    /// Commit a host-provisioned local POB1 after independently trusted auth validation.
    fn commit_local_binding(
        &mut self,
        operation_id: Hash,
        authenticated: &AuthenticatedPrincipalResultV1,
        owner: OwnerIdV1,
        now: WallTime,
    ) -> Result<PrincipalOwnerBindingV1, ForkAdmissionErrorV1>;

    /// Create child metadata and FAR1 in one transaction, resolving POB1 internally.
    fn create_fork_admitted(
        &mut self,
        request: &CreateForkAdmittedRequestV1,
        now: WallTime,
    ) -> Result<ForkAdmissionReceiptV1, ForkAdmissionErrorV1>;

    /// Read the one committed local FAR1 authority by child Fork identifier.
    fn read_fork_admission(
        &self,
        child_id: TimelineId,
    ) -> Result<Option<crate::ForkAdmissionRecordV1>, ForkAdmissionErrorV1>;
}

fn digest(domain: &[u8], bytes_in: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes_in);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn bytes(output: &mut Vec<u8>, value: &[u8]) {
    head(output, 2, value.len());
    output.extend_from_slice(value);
}

fn text(output: &mut Vec<u8>, value: &str) {
    head(output, 3, value.len());
    output.extend_from_slice(value.as_bytes());
}

fn head(output: &mut Vec<u8>, major: u8, length: usize) {
    if length < 24 {
        output.push((major << 5) | u8::try_from(length).unwrap_or(0));
    } else {
        output.push((major << 5) | 24);
        output.push(u8::try_from(length).unwrap_or(u8::MAX));
    }
}
