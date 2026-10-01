//! Local ADR-099 signed Fork-manifest publication authority.
//!
//! The port owns the boundary between an admitted Fork's authoritative
//! provenance and the immutable `FPO1`/`FPB1`/`FPA1` sidecar graph.  It never
//! accepts manifest bytes or provenance fields from a caller.

use pos_core::{
    EventOriginRecordV1, ForkAdmissionRecordV1, ForkAppendOperationV1, ForkAttributionOriginV1,
    ForkInterventionAdmissionV1, ForkPublicationArtifactInputV1, ForkPublicationArtifactV1,
    ForkPublicationBindingInputV1, ForkPublicationBindingV1, ForkPublicationOperationInputV1,
    ForkPublicationOperationV1, ForkPublicationReceiptV1, ForkReproManifestV1, Hash, KeyIdentityV1,
    KeyRegistryStateV1, KeyRoleV1, PublicKey, Signature, SignedForkReproManifestV1, TimelineId,
};
use pos_crypto::fork_attribution::verify_local_fork_manifest_signature_only;

/// Input that can be supplied by the trusted composition root for one local
/// publication attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkManifestPublicationRequestV1 {
    /// Stable identity used for recovery after an indeterminate commit.
    pub operation_id: Hash,
    /// Admitted Fork whose final logical head is being published.
    pub child_timeline_id: TimelineId,
    /// Exact final logical head observed by the host.
    pub expected_final_logical_head: u64,
    /// Exact creator attribution identity expected to sign the manifest.
    pub signing_identity: KeyIdentityV1,
    /// Fingerprint of the private signing material retained by the host.
    pub private_material_digest: Hash,
    /// Public key paired with the held private material.
    pub public_verification_key: PublicKey,
    /// Durable registry snapshot that must still be current for new issuance.
    pub expected_registry: KeyRegistryStateV1,
}

/// Immutable authorization held only while a publisher invokes its signer.
///
/// The value has no public constructor, no store reference, and no cloning
/// operation.  A signer receives it by reference, so it cannot become a
/// reusable authorization token after the callback returns.
#[derive(Debug)]
pub struct HeldRegistryAuthorizationV1 {
    identity: KeyIdentityV1,
    private_material_digest: Hash,
    public_verification_key: PublicKey,
}

impl HeldRegistryAuthorizationV1 {
    pub(crate) const fn new(
        identity: KeyIdentityV1,
        private_material_digest: Hash,
        public_verification_key: PublicKey,
    ) -> Self {
        Self {
            identity,
            private_material_digest,
            public_verification_key,
        }
    }

    /// The exact owner, role, and epoch authorized for this callback.
    #[must_use]
    pub const fn identity(&self) -> KeyIdentityV1 {
        self.identity
    }

    /// The fingerprint of the host-held private material.
    #[must_use]
    pub const fn private_material_digest(&self) -> Hash {
        self.private_material_digest
    }

    /// The retained public verification key for the held identity.
    #[must_use]
    pub const fn public_verification_key(&self) -> PublicKey {
        self.public_verification_key
    }
}

/// A sidecar graph returned only after a complete trusted read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedForkManifestV1 {
    /// Receipt derived from the two matching committed publication rows.
    pub receipt: ForkPublicationReceiptV1,
    /// Strictly decoded `FPO1` authorization projection.
    pub operation: ForkPublicationOperationV1,
    /// Strictly decoded `FPB1` Fork/head binding.
    pub binding: ForkPublicationBindingV1,
    /// Recomputed `FSM1` record address.
    pub record_id: Hash,
    /// Exact nested canonical `FSM1` bytes from `FPA1`.
    pub outer_bytes: Vec<u8>,
}

/// Closed outcomes for local Fork-manifest publication and trusted reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkManifestPublicationErrorV1 {
    /// The caller did not provide a valid local publication request.
    #[error("invalid Fork-manifest publication request")]
    InvalidRequest,
    /// The durable key registry is unavailable or malformed.
    #[error("Fork-manifest registry is unavailable")]
    RegistryUnavailable,
    /// The durable key registry differs from the expected snapshot.
    #[error("Fork-manifest registry changed")]
    RegistryChanged,
    /// The requested signing identity is absent.
    #[error("Fork-manifest signing identity was not found")]
    NotFound,
    /// The requested signing identity was destroyed.
    #[error("Fork-manifest signing identity was destroyed")]
    Destroyed,
    /// The requested signing identity has a pending destruction.
    #[error("Fork-manifest signing identity destruction is pending")]
    DestructionPending,
    /// The requested signing identity is not the active attribution key.
    #[error("Fork-manifest signing identity is inactive")]
    InactiveKey,
    /// The supplied private-material fingerprint or public key differs.
    #[error("Fork-manifest signing key differs from the registry")]
    SigningKeyMismatch,
    /// The held signing identity does not equal the admitted Fork creator.
    #[error("Fork-manifest creator does not match the admitted Fork")]
    PrincipalOwnerConflict,
    /// The requested final Fork head no longer matches durable state.
    #[error("Fork-manifest final head changed")]
    HeadChanged,
    /// The synchronous signer failed or returned an invalid signature.
    #[error("Fork-manifest signing failed")]
    SigningFailed,
    /// A stable operation ID or Fork/head binding was reused unequally.
    #[error("Fork-manifest publication conflicts with committed state")]
    Conflict,
    /// The sidecar graph or its authoritative sources are incomplete or unequal.
    #[error("Fork-manifest publication authority is corrupt")]
    CorruptAuthority,
    /// No committed sidecar exists for the requested Fork and logical head.
    #[error("Fork-manifest publication is missing")]
    PublicationMissing,
    /// The adapter cannot determine whether its transaction committed.
    #[error("Fork-manifest publication storage outcome is indeterminate")]
    StorageIndeterminate,
}

/// Purpose-specific local publication and trusted-sidecar read port.
pub trait ForkManifestPublicationPortV1 {
    /// Authorize, sign, and atomically commit one local `FPO1`/`FPB1`/`FPA1`
    /// graph, or recover the exact graph without invoking `sign` again.
    ///
    /// # Errors
    ///
    /// Returns a closed publication error when authorization, provenance,
    /// signing, graph validation, or the atomic storage transition fails.
    fn commit_authorized<E, F>(
        &mut self,
        request: ForkManifestPublicationRequestV1,
        sign: F,
    ) -> Result<ForkPublicationReceiptV1, ForkManifestPublicationErrorV1>
    where
        F: FnOnce(&HeldRegistryAuthorizationV1, &[u8]) -> Result<Signature, E>;

    /// Read and validate the one trusted local sidecar for a Fork/head key.
    ///
    /// # Errors
    ///
    /// Returns a closed publication error when no committed graph exists or
    /// its authority, provenance, key retention, or signature is invalid.
    fn read_committed(
        &self,
        child_timeline_id: TimelineId,
        final_logical_head: u64,
    ) -> Result<CommittedForkManifestV1, ForkManifestPublicationErrorV1>;
}

/// Result of one adapter-independent publication step.
type PublicationResultV1<T> = Result<T, ForkManifestPublicationErrorV1>;

/// One child suffix row: Event origin, optional intervention, append operation.
pub(crate) type PublicationSuffixV1 = Vec<(
    EventOriginRecordV1,
    Option<ForkInterventionAdmissionV1>,
    ForkAppendOperationV1,
)>;

/// Authoritative sources an adapter read under its publication transaction.
pub(crate) struct PublicationSourcesV1 {
    registry: KeyRegistryStateV1,
    admission: ForkAdmissionRecordV1,
    final_chain_head_hash: Hash,
    manifest: ForkReproManifestV1,
}

/// Complete signed sidecar graph ready for one atomic adapter insert.
pub(crate) struct PublicationGraphV1 {
    pub(crate) operation: ForkPublicationOperationV1,
    pub(crate) binding: ForkPublicationBindingV1,
    pub(crate) artifact: ForkPublicationArtifactV1,
    pub(crate) receipt: ForkPublicationReceiptV1,
}

/// Committed rows plus the trusted sources an adapter read for one Fork/head.
pub(crate) struct CommittedPublicationSourcesV1<'a> {
    pub(crate) child_timeline_id: TimelineId,
    pub(crate) final_logical_head: u64,
    pub(crate) binding: ForkPublicationBindingV1,
    pub(crate) operation: ForkPublicationOperationV1,
    pub(crate) artifact: ForkPublicationArtifactV1,
    pub(crate) admission: &'a ForkAdmissionRecordV1,
    pub(crate) final_chain_head_hash: Hash,
    pub(crate) registry: Option<&'a KeyRegistryStateV1>,
}

/// Reject a request that cannot name a local attribution-signing operation.
pub(crate) fn validate_publication_request(
    request: &ForkManifestPublicationRequestV1,
) -> PublicationResultV1<()> {
    (request.operation_id != Hash::zero()
        && request.signing_identity.role == KeyRoleV1::SubjectAttributionSigning
        && request.signing_identity.epoch != 0)
        .then_some(())
        .ok_or(ForkManifestPublicationErrorV1::InvalidRequest)
}

/// ADR-099 recovery: an existing `FPO1` must carry the exact durable request
/// tuple, and its graph must pass the complete trusted read. The signer is
/// never invoked on this path.
pub(crate) fn recovered_publication_receipt(
    operation: &ForkPublicationOperationV1,
    request: &ForkManifestPublicationRequestV1,
    committed: PublicationResultV1<CommittedForkManifestV1>,
) -> PublicationResultV1<ForkPublicationReceiptV1> {
    let input = operation.input();
    if (
        input.child_timeline_id,
        input.final_logical_head,
        input.signing_identity,
        input.private_material_digest,
        input.public_verification_key,
    ) != (
        request.child_timeline_id,
        request.expected_final_logical_head,
        request.signing_identity,
        request.private_material_digest,
        request.public_verification_key,
    ) {
        return Err(ForkManifestPublicationErrorV1::Conflict);
    }
    committed
        .ok()
        .filter(|committed| committed.operation == *operation)
        .map(|committed| committed.receipt)
        .ok_or(ForkManifestPublicationErrorV1::CorruptAuthority)
}

/// Check the expected registry, admitted creator, and final head, then derive
/// `FRM1` only from the adapter's authoritative Fork sources.
pub(crate) fn publication_sources(
    request: &ForkManifestPublicationRequestV1,
    registry: Option<KeyRegistryStateV1>,
    admission: Option<ForkAdmissionRecordV1>,
    head_and_chain: Option<(u64, Hash)>,
    suffix: Option<PublicationSuffixV1>,
) -> PublicationResultV1<PublicationSourcesV1> {
    let registry = registry.ok_or(ForkManifestPublicationErrorV1::RegistryUnavailable)?;
    if registry != request.expected_registry {
        return Err(ForkManifestPublicationErrorV1::RegistryChanged);
    }
    let ((admission, (head, chain)), suffix) = admission
        .zip(head_and_chain)
        .zip(suffix)
        .ok_or(ForkManifestPublicationErrorV1::CorruptAuthority)?;
    if admission.input().creator != request.signing_identity.owner_id {
        return Err(ForkManifestPublicationErrorV1::PrincipalOwnerConflict);
    }
    if head != request.expected_final_logical_head {
        return Err(ForkManifestPublicationErrorV1::HeadChanged);
    }
    let interventions = suffix
        .into_iter()
        .filter_map(|(origin, intervention, _)| intervention.map(|_| origin.input().logical_seq))
        .collect();
    ForkReproManifestV1::from_admission(&admission, interventions, head, chain)
        .ok()
        .map(|manifest| PublicationSourcesV1 {
            registry,
            admission,
            final_chain_head_hash: chain,
            manifest,
        })
        .ok_or(ForkManifestPublicationErrorV1::CorruptAuthority)
}

/// Invoke the signer exactly once under the held registry authorization,
/// verify its signature, and derive the complete sidecar graph.
pub(crate) fn sign_publication<E, F>(
    request: &ForkManifestPublicationRequestV1,
    sources: PublicationSourcesV1,
    sign: F,
) -> PublicationResultV1<PublicationGraphV1>
where
    F: FnOnce(&HeldRegistryAuthorizationV1, &[u8]) -> Result<Signature, E>,
{
    let PublicationSourcesV1 {
        mut registry,
        admission,
        final_chain_head_hash,
        manifest,
    } = sources;
    let authorization = HeldRegistryAuthorizationV1::new(
        request.signing_identity,
        request.private_material_digest,
        request.public_verification_key,
    );
    SignedForkReproManifestV1::new(
        request.signing_identity,
        manifest,
        Signature::from_bytes([0; 64]),
    )
    .ok()
    .and_then(|unsigned| {
        registry
            .with_signing_authorization(
                request.signing_identity,
                request.private_material_digest,
                request.public_verification_key,
                || sign(&authorization, &unsigned.manifest_bytes()),
            )
            .ok()
            .and_then(Result::ok)
            .map(|signature| unsigned.with_signature(signature))
    })
    .filter(|signed| {
        verify_local_fork_manifest_signature_only(signed, request.public_verification_key).is_ok()
    })
    .ok_or(ForkManifestPublicationErrorV1::SigningFailed)
    .and_then(|signed| publication_graph(request, &admission, final_chain_head_hash, &signed))
}

/// Derive `FPO1`, `FPB1`, `FPA1`, and `FPR1` from the ADR-099 source table.
fn publication_graph(
    request: &ForkManifestPublicationRequestV1,
    admission: &ForkAdmissionRecordV1,
    final_chain_head_hash: Hash,
    signed: &SignedForkReproManifestV1,
) -> PublicationResultV1<PublicationGraphV1> {
    let record_id = signed.record_id();
    let operation = ForkPublicationOperationV1::new(ForkPublicationOperationInputV1 {
        operation_id: request.operation_id,
        child_timeline_id: request.child_timeline_id,
        final_logical_head: request.expected_final_logical_head,
        final_chain_head_hash,
        admission_digest: admission.digest(),
        signing_identity: request.signing_identity,
        private_material_digest: request.private_material_digest,
        public_verification_key: request.public_verification_key,
        signed_manifest_record_id: record_id,
        origin: ForkAttributionOriginV1::Local,
    });
    let binding = ForkPublicationBindingV1::new(ForkPublicationBindingInputV1 {
        child_timeline_id: request.child_timeline_id,
        final_logical_head: request.expected_final_logical_head,
        operation_id: request.operation_id,
        signed_manifest_record_id: record_id,
    });
    let artifact = ForkPublicationArtifactV1::new(ForkPublicationArtifactInputV1 {
        signed_manifest_record_id: record_id,
        operation_id: request.operation_id,
        signed_manifest_bytes: signed.to_canonical_cbor(),
    });
    operation
        .ok()
        .zip(binding.ok())
        .zip(artifact.ok())
        .and_then(|((operation, binding), artifact)| {
            ForkPublicationReceiptV1::from_records(&operation, &binding)
                .ok()
                .map(|receipt| PublicationGraphV1 {
                    operation,
                    binding,
                    artifact,
                    receipt,
                })
        })
        .ok_or(ForkManifestPublicationErrorV1::CorruptAuthority)
}

/// ADR-099 trusted read over one committed graph and its trusted sources.
pub(crate) fn trusted_committed_manifest(
    sources: &CommittedPublicationSourcesV1<'_>,
) -> PublicationResultV1<CommittedForkManifestV1> {
    let outer_bytes = &sources.artifact.input().signed_manifest_bytes;
    SignedForkReproManifestV1::from_canonical_cbor(outer_bytes)
        .ok()
        .filter(|signed| {
            committed_graph_is_consistent(sources, signed)
                && verify_local_fork_manifest_signature_only(
                    signed,
                    sources.operation.input().public_verification_key,
                )
                .is_ok()
        })
        .and_then(|signed| {
            ForkPublicationReceiptV1::from_records(&sources.operation, &sources.binding)
                .ok()
                .map(|receipt| CommittedForkManifestV1 {
                    receipt,
                    operation: sources.operation.clone(),
                    binding: sources.binding,
                    record_id: signed.record_id(),
                    outer_bytes: outer_bytes.clone(),
                })
        })
        .ok_or(ForkManifestPublicationErrorV1::CorruptAuthority)
}

/// Enforce every cross-record and FPO1 source-table equality.
fn committed_graph_is_consistent(
    sources: &CommittedPublicationSourcesV1<'_>,
    signed: &SignedForkReproManifestV1,
) -> bool {
    let record_id = signed.record_id();
    let binding = sources.binding.input();
    let operation = sources.operation.input();
    let artifact = sources.artifact.input();
    let manifest = signed.manifest().input();
    let lookup = (
        sources.child_timeline_id,
        sources.final_logical_head,
        sources.final_chain_head_hash,
    );
    (
        binding.child_timeline_id,
        binding.final_logical_head,
        binding.operation_id,
        binding.signed_manifest_record_id,
    ) == (lookup.0, lookup.1, operation.operation_id, record_id)
        && (
            operation.child_timeline_id,
            operation.final_logical_head,
            operation.final_chain_head_hash,
        ) == lookup
        && (
            manifest.fork_timeline_id,
            manifest.final_fork_logical_head,
            manifest.final_fork_chain_head_hash,
        ) == lookup
        && (artifact.operation_id, artifact.signed_manifest_record_id)
            == (operation.operation_id, record_id)
        && operation.signed_manifest_record_id == record_id
        && operation.admission_digest == sources.admission.digest()
        && signed.identity() == operation.signing_identity
        && signed.validate_against_admission(sources.admission).is_ok()
        && retained_key_is_consistent(sources.registry, operation)
}

/// The retained exact-identity key must keep the FPO1 public key, and its
/// live material digest or its matching tombstone must equal FPO1's.
fn retained_key_is_consistent(
    registry: Option<&KeyRegistryStateV1>,
    operation: &ForkPublicationOperationInputV1,
) -> bool {
    registry.is_some_and(|registry| {
        let identity = operation.signing_identity;
        let record = registry.key_record(identity);
        record.is_some_and(|record| {
            record.public_verification_key == Some(operation.public_verification_key)
        }) && (record.and_then(|record| record.private_material_digest)
            == Some(operation.private_material_digest)
            || registry.tombstone(identity).is_some_and(|tombstone| {
                tombstone.destroyed_material_digest == operation.private_material_digest
            }))
    })
}
