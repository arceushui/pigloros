//! Host-owned local Fork admission authority (ADR-099).
//!
//! The host is the only party that can turn authenticated Principal evidence
//! and resolved Room state into adapter-consumable permits. Callers therefore
//! cannot select an Owner, authentication policy, or raw admission request.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::{
    AuthenticatedPrincipalResultV1, ForkAdmissionRecordV1, Hash, OwnerIdV1, PrincipalRefV1,
    TimelineId, WallTime,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkAuthorityOriginV1 {
    Local,
}

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

#[derive(Clone, Debug, Eq, PartialEq)]
struct PrincipalOwnerTrustV1 {
    adapter_id: String,
    minimum_assurance: u8,
    authentication_bindings: Vec<Hash>,
}

impl PrincipalOwnerTrustV1 {
    fn new(
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

    fn validate(
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

/// Opaque adapter binding issued by one Fork-admission composition root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkAdmissionHostBindingV1 {
    host_id: u64,
}

/// Host-owned fields describing the Room and completed cut for one Fork.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ForkAdmissionIntentV1 {
    operation_id: Hash,
    parent_timeline_id: TimelineId,
    completed_fold_cursor: u64,
    post_fold_tick_boundary: u64,
    room_revision_descriptor_hash: Hash,
    plugin_composition_hash: Hash,
    attribution_required: bool,
    child_name: String,
}

impl ForkAdmissionIntentV1 {
    fn new(
        operation_id: Hash,
        parent_timeline_id: TimelineId,
        completed_fold_cursor: u64,
        post_fold_tick_boundary: u64,
        room_revision_descriptor_hash: Hash,
        plugin_composition_hash: Hash,
        attribution_required: bool,
        child_name: String,
    ) -> Result<Self, ForkAdmissionErrorV1> {
        let value = Self {
            operation_id,
            parent_timeline_id,
            completed_fold_cursor,
            post_fold_tick_boundary,
            room_revision_descriptor_hash,
            plugin_composition_hash,
            attribution_required,
            child_name,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ForkAdmissionErrorV1> {
        if self.operation_id == Hash::zero()
            || self.room_revision_descriptor_hash == Hash::zero()
            || self.plugin_composition_hash == Hash::zero()
            || self.child_name.is_empty()
            || self.child_name.len() > 128
            || self.completed_fold_cursor != self.post_fold_tick_boundary
        {
            return Err(ForkAdmissionErrorV1::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalOwnerBindingInputV1 {
    pub operation_id: Hash,
    pub principal_digest: Hash,
    pub owner: OwnerIdV1,
    pub origin: ForkAuthorityOriginV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalOwnerBindingV1(PrincipalOwnerBindingInputV1);

impl PrincipalOwnerBindingV1 {
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

/// Opaque exact permit to persist one host-authorized local POB1 binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalPrincipalOwnerBindingPermitV1 {
    host_binding: ForkAdmissionHostBindingV1,
    binding: PrincipalOwnerBindingV1,
}

impl LocalPrincipalOwnerBindingPermitV1 {
    #[must_use]
    pub const fn host_binding(&self) -> ForkAdmissionHostBindingV1 {
        self.host_binding
    }

    #[must_use]
    pub const fn binding(&self) -> &PrincipalOwnerBindingV1 {
        &self.binding
    }
}

/// Opaque exact permit to create one child Fork and its FAR1 record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateForkAdmittedRequestV1 {
    host_binding: ForkAdmissionHostBindingV1,
    principal_digest: Hash,
    intent: ForkAdmissionIntentV1,
    operation_commitment: Hash,
}

impl CreateForkAdmittedRequestV1 {
    #[must_use]
    pub const fn host_binding(&self) -> ForkAdmissionHostBindingV1 {
        self.host_binding
    }
    #[must_use]
    pub const fn principal_digest(&self) -> Hash {
        self.principal_digest
    }
    #[must_use]
    pub const fn operation_id(&self) -> Hash {
        self.intent.operation_id
    }
    #[must_use]
    pub const fn parent_timeline_id(&self) -> TimelineId {
        self.intent.parent_timeline_id
    }
    #[must_use]
    pub const fn completed_fold_cursor(&self) -> u64 {
        self.intent.completed_fold_cursor
    }
    #[must_use]
    pub const fn post_fold_tick_boundary(&self) -> u64 {
        self.intent.post_fold_tick_boundary
    }
    #[must_use]
    pub const fn room_revision_descriptor_hash(&self) -> Hash {
        self.intent.room_revision_descriptor_hash
    }
    #[must_use]
    pub const fn plugin_composition_hash(&self) -> Hash {
        self.intent.plugin_composition_hash
    }
    #[must_use]
    pub const fn attribution_required(&self) -> bool {
        self.intent.attribution_required
    }
    #[must_use]
    pub fn child_name(&self) -> &str {
        &self.intent.child_name
    }
    #[must_use]
    pub const fn operation_commitment(&self) -> Hash {
        self.operation_commitment
    }
}

/// Trusted Fork-admission composition-root owner.
#[derive(Debug)]
pub struct ForkAdmissionHostV1 {
    binding: ForkAdmissionHostBindingV1,
    trust: PrincipalOwnerTrustV1,
}

static NEXT_FORK_ADMISSION_HOST_ID: AtomicU64 = AtomicU64::new(1);

impl ForkAdmissionHostV1 {
    /// Construct a private authentication policy and a unique adapter binding.
    ///
    /// Constructing this value declares that the caller is the trusted
    /// composition root for the adapter it binds. It is not an external
    /// credential or attestation. The composition root must not expose this
    /// host, its permits, or a mutable authority adapter to untrusted code.
    ///
    /// # Errors
    /// Returns InvalidRequest for an invalid trust policy.
    pub fn new(
        adapter_id: String,
        minimum_assurance: u8,
        authentication_bindings: Vec<Hash>,
    ) -> Result<Self, ForkAdmissionErrorV1> {
        Ok(Self {
            binding: ForkAdmissionHostBindingV1 {
                host_id: NEXT_FORK_ADMISSION_HOST_ID.fetch_add(1, Ordering::Relaxed),
            },
            trust: PrincipalOwnerTrustV1::new(
                adapter_id,
                minimum_assurance,
                authentication_bindings,
            )?,
        })
    }

    #[must_use]
    pub const fn host_binding(&self) -> ForkAdmissionHostBindingV1 {
        self.binding
    }

    /// Validate current authentication evidence and permit exact POB1 provisioning.
    ///
    /// Owner resolution stays in the host and is absent from the adapter port.
    ///
    /// # Errors
    /// Returns Unauthenticated when authentication is not current under this host policy.
    pub fn permit_local_binding(
        &self,
        operation_id: Hash,
        authenticated: &AuthenticatedPrincipalResultV1,
        owner: OwnerIdV1,
        now: WallTime,
    ) -> Result<LocalPrincipalOwnerBindingPermitV1, ForkAdmissionErrorV1> {
        self.trust.validate(authenticated, now)?;
        let principal_digest = principal_digest_v1(authenticated.principal())?;
        Ok(LocalPrincipalOwnerBindingPermitV1 {
            host_binding: self.binding,
            binding: PrincipalOwnerBindingV1::new(PrincipalOwnerBindingInputV1 {
                operation_id,
                principal_digest,
                owner,
                origin: ForkAuthorityOriginV1::Local,
            })?,
        })
    }

    /// Validate current authentication evidence and permit exact Fork creation.
    ///
    /// The request carries no Owner or raw authentication result.
    ///
    /// # Errors
    /// Returns Unauthenticated when authentication is not current under this host policy.
    pub fn permit_fork_creation(
        &self,
        authenticated: &AuthenticatedPrincipalResultV1,
        operation_id: Hash,
        parent_timeline_id: TimelineId,
        completed_fold_cursor: u64,
        post_fold_tick_boundary: u64,
        room_revision_descriptor_hash: Hash,
        plugin_composition_hash: Hash,
        attribution_required: bool,
        child_name: String,
        now: WallTime,
    ) -> Result<CreateForkAdmittedRequestV1, ForkAdmissionErrorV1> {
        self.trust.validate(authenticated, now)?;
        let principal_digest = principal_digest_v1(authenticated.principal())?;
        let intent = ForkAdmissionIntentV1::new(
            operation_id,
            parent_timeline_id,
            completed_fold_cursor,
            post_fold_tick_boundary,
            room_revision_descriptor_hash,
            plugin_composition_hash,
            attribution_required,
            child_name,
        )?;
        let operation_commitment =
            fork_admission_operation_commitment_v1(principal_digest, &intent)?;
        Ok(CreateForkAdmittedRequestV1 {
            host_binding: self.binding,
            principal_digest,
            intent,
            operation_commitment,
        })
    }
}

/// Compute the immutable retry commitment for host-approved Fork intent.
///
/// Authentication timestamps, adapter identity, registry binding, and host
/// binding are deliberately excluded. Durable FAR1, POB1, and child name can
/// reproduce this value.
///
/// # Errors
/// Returns InvalidRequest for invalid intent or a zero Principal digest.
fn fork_admission_operation_commitment_v1(
    principal_digest: Hash,
    intent: &ForkAdmissionIntentV1,
) -> Result<Hash, ForkAdmissionErrorV1> {
    intent.validate()?;
    if principal_digest == Hash::zero() {
        return Err(ForkAdmissionErrorV1::InvalidRequest);
    }
    let mut bytes_out = Vec::new();
    bytes(&mut bytes_out, intent.operation_id.as_bytes());
    bytes(&mut bytes_out, principal_digest.as_bytes());
    bytes(
        &mut bytes_out,
        &intent.parent_timeline_id.inner().to_bytes(),
    );
    bytes_out.extend_from_slice(&intent.completed_fold_cursor.to_be_bytes());
    bytes_out.extend_from_slice(&intent.post_fold_tick_boundary.to_be_bytes());
    bytes(
        &mut bytes_out,
        intent.room_revision_descriptor_hash.as_bytes(),
    );
    bytes(&mut bytes_out, intent.plugin_composition_hash.as_bytes());
    bytes_out.push(u8::from(intent.attribution_required));
    text(&mut bytes_out, &intent.child_name);
    Ok(digest(b"pigloros/fork-admission-operation/v1", &bytes_out))
}

/// Recompute an immutable operation commitment from durable admission records.
/// POB1 provisioning and FAR1 creation have distinct operation identifiers;
/// this computation uses the FAR1 identifier and the POB1 Principal digest.
///
/// # Errors
/// Returns CorruptAuthority when FAR1 and POB1 disagree.
pub fn fork_admission_operation_commitment_from_records_v1(
    admission: &ForkAdmissionRecordV1,
    binding: &PrincipalOwnerBindingV1,
    child_name: &str,
) -> Result<Hash, ForkAdmissionErrorV1> {
    let record = admission.input();
    let pob1 = binding.input();
    if record.principal_owner_binding_digest != binding.digest() || record.creator != pob1.owner {
        return Err(ForkAdmissionErrorV1::CorruptAuthority);
    }
    let intent = ForkAdmissionIntentV1::new(
        record.operation_id,
        record.parent_timeline_id,
        record.completed_fold_cursor,
        record.post_fold_tick_boundary,
        record.room_revision_descriptor_hash,
        record.plugin_composition_hash,
        record.attribution_required,
        child_name.to_owned(),
    )?;
    fork_admission_operation_commitment_v1(pob1.principal_digest, &intent)
}

/// Compute the exact ADR-099 PrincipalRefV1 digest.
///
/// # Errors
/// Returns Unauthenticated when the Principal cannot be canonically encoded.
pub fn principal_digest_v1(principal: &PrincipalRefV1) -> Result<Hash, ForkAdmissionErrorV1> {
    principal
        .encode()
        .map(|bytes| digest(b"pigloros/principal-ref/v1", bytes.as_slice()))
        .map_err(|_| ForkAdmissionErrorV1::Unauthenticated)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkAdmissionReceiptV1 {
    pub child_id: TimelineId,
    pub admission_digest: Hash,
}

/// Storage authority for trusted local POB1 and atomic FAR1 child creation.
pub trait ForkAdmissionAuthorityPortV1 {
    /// Bind the trusted composition root once. A different host must reject.
    fn bind_fork_admission_host(
        &mut self,
        host: ForkAdmissionHostBindingV1,
    ) -> Result<(), ForkAdmissionErrorV1>;

    /// Commit one exact host-authorized POB1 binding.
    fn commit_local_binding(
        &mut self,
        permit: &LocalPrincipalOwnerBindingPermitV1,
    ) -> Result<PrincipalOwnerBindingV1, ForkAdmissionErrorV1>;

    /// Create child metadata and FAR1 in one transaction using an exact host permit.
    fn create_fork_admitted(
        &mut self,
        request: &CreateForkAdmittedRequestV1,
    ) -> Result<ForkAdmissionReceiptV1, ForkAdmissionErrorV1>;

    fn read_fork_admission(
        &self,
        child_id: TimelineId,
    ) -> Result<Option<ForkAdmissionRecordV1>, ForkAdmissionErrorV1>;
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
        output.push((major << 5) | 0x18_u8);
        output.push(u8::try_from(length).unwrap_or(u8::MAX));
    }
}
