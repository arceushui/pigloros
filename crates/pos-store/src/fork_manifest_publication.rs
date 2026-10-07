//! Local ADR-099 signed Fork-manifest publication authority.
//!
//! The port owns the boundary between an admitted Fork's authoritative
//! provenance and the immutable `FPO1`/`FPB1`/`FPA1` sidecar graph.  It never
//! accepts manifest bytes or provenance fields from a caller.

use pos_core::{
    CoreError, EventOriginRecordV1, ForkAppendOperationV1, ForkAttributionCodecErrorV1,
    ForkAttributionOriginV1, ForkInterventionAdmissionV1, ForkPublicationArtifactInputV1,
    ForkPublicationArtifactV1, ForkPublicationBindingInputV1, ForkPublicationBindingV1,
    ForkPublicationOperationInputV1, ForkPublicationOperationV1, ForkPublicationReceiptV1,
    ForkReproManifestV1, Hash, ImportedForkPublicationOperationV1, ImportedKeyRecordV1,
    ImportedKeyTombstoneV1, KeyIdentityV1, KeyRegistryErrorV1, KeyRegistryStateV1, KeyRoleV1,
    PublicKey, Signature, SignedForkReproManifestV1, TimelineId,
};
use pos_crypto::fork_attribution::verify_local_fork_manifest_signature_only;

use crate::{
    fork_event_authority::{AuthorityValidatorV1, ValidatedAdmissionV1, ValidatedOriginV1},
    ForkEventAuthorityErrorV1,
};

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
///
/// The read accepts a local sidecar and a code-2 imported one (ADR-105 r6
/// R6.9). The result is evidence, never publication or write authority, and
/// only the publication port constructs it.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct CommittedForkManifestV1 {
    /// Receipt derived from the two matching committed publication rows.
    pub receipt: ForkPublicationReceiptV1,
    /// Strictly decoded `FPO1` authorization projection.
    ///
    /// For an imported sidecar this is the local projection of the code-2
    /// `FPO1`, and [`Self::authority_origin_digest`] carries its origin. The
    /// projection is not publication authority.
    pub operation: ForkPublicationOperationV1,
    /// The code-2 authority-origin digest of an imported sidecar, or `None`
    /// for a local one (ADR-105 r6 R6.9 read validator (b)).
    pub authority_origin_digest: Option<Hash>,
    /// Strictly decoded `FPB1` Fork/head binding.
    pub binding: ForkPublicationBindingV1,
    /// Recomputed `FSM1` record address.
    pub record_id: Hash,
    /// Exact nested canonical `FSM1` bytes from `FPA1`.
    pub outer_bytes: Vec<u8>,
}

/// Closed outcomes for local Fork-manifest publication and trusted reads.
///
/// Registry variants follow the ADR-099 / ADR-065 precedence: `InvalidEpoch`,
/// `SigningRoleRequired`, `RegistryUnavailable` or `RegistryChanged`,
/// `NotFound`, `Destroyed`, `DestructionPending`, `InactiveKey`, then
/// `SigningKeyMismatch`; creator/head/provenance errors follow them.
///
/// The graph and authority failures are scoped by operation, where "new"
/// and "recovery" are the two `commit_authorized` paths:
///
/// | Variant                | New issuance | Recovery | `read_committed` |
/// |------------------------|--------------|----------|------------------|
/// | `Conflict`             | yes          | yes      | no               |
/// | `CorruptAuthority`     | yes          | no       | no               |
/// | `CorruptOrConflicting` | yes          | yes      | no               |
/// | `PublicationConflict`  | no           | no       | yes              |
///
/// - `Conflict`: new issuance finds the Fork/head binding held by another
///   operation; recovery finds an `FPO1` with an unequal request tuple.
/// - `CorruptAuthority`: new issuance cannot read valid Fork provenance or
///   derive a valid graph from it.
/// - `CorruptOrConflicting`: new issuance finds an orphan row naming the
///   operation ID, or any `FPO1`/`FPB1`/`FPA1` at the new record ID; recovery
///   finds a noncanonical `FPO1` or a graph that fails the trusted read.
/// - `PublicationConflict`: a trusted read finds a missing join, extra row,
///   or failed check; recovery reports the same failure as
///   `CorruptOrConflicting`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkManifestPublicationErrorV1 {
    /// The caller did not provide a nonzero publication operation ID.
    #[error("invalid Fork-manifest publication request")]
    InvalidRequest,
    /// The requested signing epoch is zero.
    #[error("Fork-manifest signing epoch zero is reserved")]
    InvalidEpoch,
    /// The requested role is not exactly `SubjectAttributionSigning`.
    #[error("Fork-manifest signing requires the attribution-signing role")]
    SigningRoleRequired,
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
    #[error("Fork-manifest final sequence or head changed")]
    SequenceOrHeadChanged,
    /// The synchronous signer failed or returned an invalid signature.
    #[error("Fork-manifest signing failed")]
    SigningFailed,
    /// A stable operation ID or Fork/head binding was reused unequally.
    #[error("Fork-manifest publication conflicts with committed state")]
    Conflict,
    /// An authoritative Fork provenance source for new issuance is absent,
    /// malformed, or cannot produce a valid publication graph.
    #[error("Fork-manifest provenance authority is corrupt")]
    CorruptAuthority,
    /// Recovery found a partial, orphaned, or unequal publication graph.
    #[error("Fork-manifest publication graph is corrupt or conflicting")]
    CorruptOrConflicting,
    /// No committed sidecar exists for the requested Fork and logical head.
    #[error("Fork-manifest publication is missing")]
    PublicationMissing,
    /// A trusted read found a missing join, extra row, invalid origin,
    /// noncanonical record, missing retained key, invalid signature, or
    /// unequal recomputed field.
    #[error("Fork-manifest publication conflicts with its trusted sources")]
    PublicationConflict,
    /// The adapter cannot determine whether its transaction committed.
    #[error("Fork-manifest publication storage outcome is indeterminate")]
    StorageIndeterminate,
}

impl From<KeyRegistryErrorV1> for ForkManifestPublicationErrorV1 {
    /// Map ADR-065 active-signing authorization failures one-to-one.
    fn from(error: KeyRegistryErrorV1) -> Self {
        match error {
            KeyRegistryErrorV1::InvalidEpoch => Self::InvalidEpoch,
            KeyRegistryErrorV1::SigningRoleRequired => Self::SigningRoleRequired,
            KeyRegistryErrorV1::NotFound => Self::NotFound,
            KeyRegistryErrorV1::Destroyed => Self::Destroyed,
            KeyRegistryErrorV1::DestructionPending => Self::DestructionPending,
            KeyRegistryErrorV1::InactiveKey => Self::InactiveKey,
            KeyRegistryErrorV1::SigningKeyMismatch => Self::SigningKeyMismatch,
            KeyRegistryErrorV1::RegistryUnavailable
            | KeyRegistryErrorV1::InvalidOwnerId
            | KeyRegistryErrorV1::InvalidRoleCode
            | KeyRegistryErrorV1::StaleEpoch { .. }
            | KeyRegistryErrorV1::IdentityConflict
            | KeyRegistryErrorV1::MaterialReuse
            | KeyRegistryErrorV1::MissingPublicVerificationKey
            | KeyRegistryErrorV1::UnexpectedPublicVerificationKey
            | KeyRegistryErrorV1::EncryptionRoleRequired
            | KeyRegistryErrorV1::EncryptionKeyMismatch
            | KeyRegistryErrorV1::HistoricalDecryptionRoleRequired
            | KeyRegistryErrorV1::InvalidState
            | KeyRegistryErrorV1::MaterialDigestMismatch
            | KeyRegistryErrorV1::DestructionAuthorizationMismatch
            | KeyRegistryErrorV1::DestructionNotPending
            | KeyRegistryErrorV1::DeletionReceiptMismatch => Self::RegistryUnavailable,
        }
    }
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

    /// Read and validate the one trusted sidecar for a Fork/head key.
    ///
    /// This is read validator (b) of ADR-105 r6 R6.9: the sidecar of a local
    /// Fork and the sidecar of a code-2 imported Fork are both accepted, each
    /// under its own origin rules, and the result is never write authority.
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

/// Result of one adapter read of an authoritative publication source.
pub(crate) type PublicationSourceResultV1<T> = Result<T, PublicationSourceErrorV1>;

/// One child suffix row: Event origin, optional intervention, append operation.
pub(crate) type PublicationSuffixV1 = Vec<(
    EventOriginRecordV1,
    Option<ForkInterventionAdmissionV1>,
    ForkAppendOperationV1,
)>;

/// Classified failure of one authoritative source read: a storage failure
/// stays indeterminate, every other failure is a conflict for its caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationSourceErrorV1 {
    /// The adapter could not read the stored value.
    Storage,
    /// The stored value is absent, malformed, or unequal.
    Invalid,
}

impl PublicationSourceErrorV1 {
    const fn classify(
        self,
        invalid: ForkManifestPublicationErrorV1,
    ) -> ForkManifestPublicationErrorV1 {
        match self {
            Self::Storage => ForkManifestPublicationErrorV1::StorageIndeterminate,
            Self::Invalid => invalid,
        }
    }

    /// A new issuance cannot read a valid Fork provenance source.
    pub(crate) const fn into_corrupt_authority(self) -> ForkManifestPublicationErrorV1 {
        self.classify(ForkManifestPublicationErrorV1::CorruptAuthority)
    }

    /// A new issuance cannot read a valid durable key registry.
    pub(crate) const fn into_registry_unavailable(self) -> ForkManifestPublicationErrorV1 {
        self.classify(ForkManifestPublicationErrorV1::RegistryUnavailable)
    }

    /// A trusted read cannot obtain one of its comparison sources.
    pub(crate) const fn into_publication_conflict(self) -> ForkManifestPublicationErrorV1 {
        self.classify(ForkManifestPublicationErrorV1::PublicationConflict)
    }
}

impl From<CoreError> for PublicationSourceErrorV1 {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::Storage(_) | CoreError::StorageOutcomeUnknown(_) => Self::Storage,
            _ => Self::Invalid,
        }
    }
}

impl From<ForkEventAuthorityErrorV1> for PublicationSourceErrorV1 {
    fn from(error: ForkEventAuthorityErrorV1) -> Self {
        match error {
            ForkEventAuthorityErrorV1::StorageIndeterminate => Self::Storage,
            _ => Self::Invalid,
        }
    }
}

/// Authoritative Fork sources validated for one new issuance.
pub(crate) struct PublicationSourcesV1 {
    admission: ValidatedAdmissionV1,
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

/// Committed rows an adapter joined for one Fork/head lookup key.
pub(crate) struct CommittedPublicationRowsV1 {
    pub(crate) child_timeline_id: TimelineId,
    pub(crate) final_logical_head: u64,
    pub(crate) binding: ForkPublicationBindingV1,
    pub(crate) operation: ForkPublicationOperationV1,
    /// The authority origin the stored `FPO1` carries.
    pub(crate) origin: ValidatedOriginV1,
    pub(crate) artifact: ForkPublicationArtifactV1,
}

/// Trusted sources an adapter read under the same snapshot as the rows.
pub(crate) struct CommittedPublicationSourcesV1 {
    pub(crate) admission: PublicationSourceResultV1<ValidatedAdmissionV1>,
    pub(crate) retained: PublicationSourceResultV1<RetainedKeyEvidenceV1>,
    pub(crate) final_chain_head_hash: PublicationSourceResultV1<Hash>,
    pub(crate) suffix: PublicationSourceResultV1<PublicationSuffixV1>,
    pub(crate) registry: PublicationSourceResultV1<Option<KeyRegistryStateV1>>,
}

/// Comparison sources a trusted read obtained successfully.
struct TrustedPublicationSourcesV1 {
    admission: ValidatedAdmissionV1,
    key_evidence: RetainedKeyEvidenceV1,
    final_chain_head_hash: Hash,
    intervention_sequences: Vec<u64>,
    registry: Option<KeyRegistryStateV1>,
}

/// ADR-099 step 1: reject zero epoch, then any role other than exactly
/// `SubjectAttributionSigning`, then a zero operation ID, before any
/// transaction begins.
pub(crate) fn validate_publication_request(
    request: &ForkManifestPublicationRequestV1,
) -> PublicationResultV1<()> {
    let identity = request.signing_identity;
    if identity.epoch == 0 {
        return Err(ForkManifestPublicationErrorV1::InvalidEpoch);
    }
    if identity.role != KeyRoleV1::SubjectAttributionSigning {
        return Err(ForkManifestPublicationErrorV1::SigningRoleRequired);
    }
    (request.operation_id != Hash::zero())
        .then_some(())
        .ok_or(ForkManifestPublicationErrorV1::InvalidRequest)
}

/// What an adapter observed before issuing a new publication graph.
#[derive(Clone, Copy)]
pub(crate) struct AbsentPublicationPreflightV1 {
    /// A stored `FPB1` or `FPA1` already references the operation ID.
    pub(crate) operation_is_referenced: bool,
    /// The requested Fork/head binding key is already occupied.
    pub(crate) binding_is_occupied: bool,
}

/// ADR-099 recovery preflight for an absent `FPO1`: a binding or artifact
/// that already references the operation ID is an orphan, and an occupied
/// Fork/head binding belongs to another operation.
pub(crate) const fn require_absent_publication_graph(
    preflight: AbsentPublicationPreflightV1,
) -> PublicationResultV1<()> {
    if preflight.operation_is_referenced {
        return Err(ForkManifestPublicationErrorV1::CorruptOrConflicting);
    }
    if preflight.binding_is_occupied {
        return Err(ForkManifestPublicationErrorV1::Conflict);
    }
    Ok(())
}

/// A trusted-read failure during recovery is a corrupt or conflicting graph
/// unless storage itself is indeterminate.
const fn recovery_error(error: ForkManifestPublicationErrorV1) -> ForkManifestPublicationErrorV1 {
    match error {
        ForkManifestPublicationErrorV1::StorageIndeterminate => error,
        _ => ForkManifestPublicationErrorV1::CorruptOrConflicting,
    }
}

/// The parent cut of an admitted Fork, or the failure of its admission read.
pub(crate) fn publication_parent_head(
    admission: &PublicationSourceResultV1<ValidatedAdmissionV1>,
) -> PublicationSourceResultV1<u64> {
    admission
        .as_ref()
        .map(|admission| admission.fields().parent_logical_head)
        .map_err(|error| *error)
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
    committed.map_err(recovery_error).and_then(|committed| {
        (committed.operation == *operation)
            .then_some(committed.receipt)
            .ok_or(ForkManifestPublicationErrorV1::CorruptOrConflicting)
    })
}

/// ADR-099 step 2: require the durable registry read inside the publisher
/// transaction to equal the expected snapshot, then run ADR-065's complete
/// active signing authorization before any Fork provenance is read.
pub(crate) fn authorize_publication(
    request: &ForkManifestPublicationRequestV1,
    registry: PublicationSourceResultV1<Option<KeyRegistryStateV1>>,
) -> PublicationResultV1<HeldRegistryAuthorizationV1> {
    registry
        .map_err(PublicationSourceErrorV1::into_registry_unavailable)
        .and_then(|registry| registry.ok_or(ForkManifestPublicationErrorV1::RegistryUnavailable))
        .and_then(|registry| {
            (registry == request.expected_registry)
                .then_some(registry)
                .ok_or(ForkManifestPublicationErrorV1::RegistryChanged)
        })
        .and_then(|mut registry| {
            registry
                .with_signing_authorization(
                    request.signing_identity,
                    request.private_material_digest,
                    request.public_verification_key,
                    || (),
                )
                .map_err(ForkManifestPublicationErrorV1::from)
        })
        .map(|()| {
            HeldRegistryAuthorizationV1::new(
                request.signing_identity,
                request.private_material_digest,
                request.public_verification_key,
            )
        })
}

/// ADR-099 step 3: after authorization, check the admitted creator and final
/// head, then derive `FRM1` only from the adapter's authoritative sources.
pub(crate) fn publication_sources(
    request: &ForkManifestPublicationRequestV1,
    admission: PublicationSourceResultV1<ValidatedAdmissionV1>,
    head_and_chain: PublicationSourceResultV1<(u64, Hash)>,
    suffix: PublicationSourceResultV1<PublicationSuffixV1>,
) -> PublicationResultV1<PublicationSourcesV1> {
    admission
        .and_then(|admission| head_and_chain.map(|head_and_chain| (admission, head_and_chain)))
        .and_then(|(admission, head_and_chain)| {
            suffix.map(|suffix| (admission, head_and_chain, suffix))
        })
        .map_err(PublicationSourceErrorV1::into_corrupt_authority)
        .and_then(|(admission, (head, chain), suffix)| {
            bind_publication_sources(request, admission, head, chain, suffix)
        })
}

fn bind_publication_sources(
    request: &ForkManifestPublicationRequestV1,
    admission: ValidatedAdmissionV1,
    head: u64,
    chain: Hash,
    suffix: PublicationSuffixV1,
) -> PublicationResultV1<PublicationSourcesV1> {
    if admission.fields().creator != request.signing_identity.owner_id {
        return Err(ForkManifestPublicationErrorV1::PrincipalOwnerConflict);
    }
    if head != request.expected_final_logical_head {
        return Err(ForkManifestPublicationErrorV1::SequenceOrHeadChanged);
    }
    let interventions = intervention_sequences(suffix, head);
    ForkReproManifestV1::from_admission_fields(
        admission.digest(),
        admission.fields(),
        interventions,
        head,
        chain,
    )
    .ok()
    .map(|manifest| PublicationSourcesV1 {
        admission,
        final_chain_head_hash: chain,
        manifest,
    })
    .ok_or(ForkManifestPublicationErrorV1::CorruptAuthority)
}

/// The ordered classified intervention sequences at or below a final head.
fn intervention_sequences(suffix: PublicationSuffixV1, final_logical_head: u64) -> Vec<u64> {
    suffix
        .into_iter()
        .filter_map(|(origin, intervention, _)| intervention.map(|_| origin.input().logical_seq))
        // New issuance reads the suffix at the current head, so this bound
        // only drops rows on the trusted-read path, where the Fork may have
        // grown past the published head.
        .filter(|sequence| *sequence <= final_logical_head)
        .collect()
}

/// ADR-099 steps 4-7: invoke the signer exactly once with the held
/// authorization, verify its signature, and derive the complete graph.
/// Only the callback's own failure or an unverifiable signature is
/// `SigningFailed`.
pub(crate) fn sign_publication<E, F>(
    request: &ForkManifestPublicationRequestV1,
    authorization: &HeldRegistryAuthorizationV1,
    sources: PublicationSourcesV1,
    sign: F,
) -> PublicationResultV1<PublicationGraphV1>
where
    F: FnOnce(&HeldRegistryAuthorizationV1, &[u8]) -> Result<Signature, E>,
{
    let PublicationSourcesV1 {
        admission,
        final_chain_head_hash,
        manifest,
    } = sources;
    SignedForkReproManifestV1::new(
        authorization.identity(),
        manifest,
        Signature::from_bytes([0; 64]),
    )
    .ok()
    .and_then(|unsigned| {
        sign(authorization, &unsigned.manifest_bytes())
            .ok()
            .map(|signature| unsigned.with_signature(signature))
    })
    .filter(|signed| {
        verify_local_fork_manifest_signature_only(signed, authorization.public_verification_key())
            .is_ok()
    })
    .ok_or(ForkManifestPublicationErrorV1::SigningFailed)
    .and_then(|signed| publication_graph(request, &admission, final_chain_head_hash, &signed))
}

/// Derive `FPO1`, `FPB1`, `FPA1`, and `FPR1` from the ADR-099 source table.
fn publication_graph(
    request: &ForkManifestPublicationRequestV1,
    admission: &ValidatedAdmissionV1,
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
///
/// Besides the `FPO1` source table, the signed `FRM1` intervention vector
/// must equal the durable classified intervention rows at or below the
/// published head.
pub(crate) fn trusted_committed_manifest(
    rows: &CommittedPublicationRowsV1,
    sources: CommittedPublicationSourcesV1,
) -> PublicationResultV1<CommittedForkManifestV1> {
    let CommittedPublicationSourcesV1 {
        admission,
        retained,
        final_chain_head_hash,
        suffix,
        registry,
    } = sources;
    admission
        .and_then(|admission| final_chain_head_hash.map(|chain| (admission, chain)))
        .and_then(|(admission, chain)| suffix.map(|suffix| (admission, chain, suffix)))
        .and_then(|(admission, chain, suffix)| {
            retained.map(|key_evidence| (admission, chain, suffix, key_evidence))
        })
        .and_then(|(admission, chain, suffix, key_evidence)| {
            registry.map(|registry| TrustedPublicationSourcesV1 {
                admission,
                key_evidence,
                final_chain_head_hash: chain,
                intervention_sequences: intervention_sequences(suffix, rows.final_logical_head),
                registry,
            })
        })
        .map_err(PublicationSourceErrorV1::into_publication_conflict)
        .and_then(|trusted| verified_committed_origin(rows, &trusted))
}

/// ADR-105 r6 R6.9: the stored `FPO1` carries the same authority origin as
/// the `FAR1` that validated, before the shared trusted read runs.
fn verified_committed_origin(
    rows: &CommittedPublicationRowsV1,
    trusted: &TrustedPublicationSourcesV1,
) -> PublicationResultV1<CommittedForkManifestV1> {
    if rows.origin == trusted.admission.origin() {
        verified_committed_manifest(rows, trusted)
    } else {
        Err(ForkManifestPublicationErrorV1::PublicationConflict)
    }
}

/// One stored `FPO1` decoded with its authority origin.
pub(crate) type DecodedPublicationOperationV1 =
    Result<(ForkPublicationOperationV1, ValidatedOriginV1), ForkAttributionCodecErrorV1>;

/// The `FPO1` decoder that one R6.9 validator may use.
///
/// Validator (a) reads with the strict local decoder alone, which rejects
/// code 2, so issuance and recovery never decode a code-2 record. Only
/// validator (b) may fall back to the code-2 decoder.
pub(crate) fn publication_operation_decoder(
    validator: AuthorityValidatorV1,
) -> fn(&[u8]) -> DecodedPublicationOperationV1 {
    match validator {
        AuthorityValidatorV1::LocalOnly => decode_local_publication_operation,
        AuthorityValidatorV1::CodeTwoAware => decode_publication_operation,
    }
}

/// Strictly decode one stored `FPO1` as the local record only.
fn decode_local_publication_operation(bytes: &[u8]) -> DecodedPublicationOperationV1 {
    ForkPublicationOperationV1::from_canonical_cbor(bytes)
        .map(|operation| (operation, ValidatedOriginV1::Local))
}

/// Strictly decode one stored `FPO1` as the local record or, failing that, as
/// the code-2 record, and report which origin it carries.
///
/// ADR-105 r6 R6.9: only read validator (b) reaches this decoder.
fn decode_publication_operation(bytes: &[u8]) -> DecodedPublicationOperationV1 {
    decode_local_publication_operation(bytes).or_else(|_| {
        ImportedForkPublicationOperationV1::from_canonical_cbor(bytes).map(|operation| {
            (
                operation.projection().clone(),
                ValidatedOriginV1::Imported(operation.authority_origin_digest()),
            )
        })
    })
}

fn verified_committed_manifest(
    rows: &CommittedPublicationRowsV1,
    trusted: &TrustedPublicationSourcesV1,
) -> PublicationResultV1<CommittedForkManifestV1> {
    let outer_bytes = &rows.artifact.input().signed_manifest_bytes;
    SignedForkReproManifestV1::from_canonical_cbor(outer_bytes)
        .ok()
        .filter(|signed| {
            committed_graph_is_consistent(rows, trusted, signed)
                && verify_local_fork_manifest_signature_only(
                    signed,
                    rows.operation.input().public_verification_key,
                )
                .is_ok()
        })
        .and_then(|signed| {
            ForkPublicationReceiptV1::from_records(&rows.operation, &rows.binding)
                .ok()
                .map(|receipt| CommittedForkManifestV1 {
                    receipt,
                    operation: rows.operation.clone(),
                    authority_origin_digest: rows.origin.imported_digest(),
                    binding: rows.binding,
                    record_id: signed.record_id(),
                    outer_bytes: outer_bytes.clone(),
                })
        })
        .ok_or(ForkManifestPublicationErrorV1::PublicationConflict)
}

/// Enforce every cross-record and FPO1 source-table equality.
fn committed_graph_is_consistent(
    rows: &CommittedPublicationRowsV1,
    trusted: &TrustedPublicationSourcesV1,
    signed: &SignedForkReproManifestV1,
) -> bool {
    let record_id = signed.record_id();
    let binding = rows.binding.input();
    let operation = rows.operation.input();
    let artifact = rows.artifact.input();
    let manifest = signed.manifest().input();
    let lookup = (
        rows.child_timeline_id,
        rows.final_logical_head,
        trusted.final_chain_head_hash,
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
        && operation.admission_digest == trusted.admission.digest()
        && signed.identity() == operation.signing_identity
        && signed
            .validate_against_admission_fields(
                trusted.admission.digest(),
                trusted.admission.fields(),
            )
            .is_ok()
        && manifest.intervention_sequences == trusted.intervention_sequences
        && trusted
            .key_evidence
            .accepts(trusted.registry.as_ref(), operation)
}

/// Where a trusted read takes the retained `FPO1`/`FSM1` verification key
/// from (ADR-105 erratum E12).
///
/// A local sidecar keeps the ADR-099 rule: the destination's live registry
/// retains the key. A code-2 sidecar takes it from the `IKR1`/`IKT1` evidence
/// stored with its import admission, which never enters the live registry.
/// Validator (a) and every write path use [`Self::LiveRegistry`] only and
/// never read the retained evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RetainedKeyEvidenceV1 {
    /// The live `KeyRegistryStateV1` retains the key.
    LiveRegistry,
    /// The imported `IKR1` and optional `IKT1` retain the key.
    Imported(Box<RetainedImportedKeyV1>),
}

/// The `IKR1` and optional `IKT1` stored with one import admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetainedImportedKeyV1 {
    pub(crate) record: ImportedKeyRecordV1,
    pub(crate) tombstone: Option<ImportedKeyTombstoneV1>,
}

impl RetainedKeyEvidenceV1 {
    /// Whether the retained key agrees with the `FPO1` it signed under.
    fn accepts(
        &self,
        registry: Option<&KeyRegistryStateV1>,
        operation: &ForkPublicationOperationInputV1,
    ) -> bool {
        match self {
            Self::LiveRegistry => retained_key_is_consistent(registry, operation),
            Self::Imported(retained) => {
                imported_key_is_consistent(&retained.record, retained.tombstone.as_ref(), operation)
                    && local_key_agrees(&retained.record, registry)
            }
        }
    }
}

/// The imported evidence names exactly the `FPO1` identity, public key, and
/// material digest, as import step 8 required.
fn imported_key_is_consistent(
    record: &ImportedKeyRecordV1,
    tombstone: Option<&ImportedKeyTombstoneV1>,
    operation: &ForkPublicationOperationInputV1,
) -> bool {
    let destroyed = tombstone.map(ImportedKeyTombstoneV1::destroyed_material_digest);
    record.identity() == operation.signing_identity
        && record.public_verification_key() == operation.public_verification_key
        && record.private_material_digest().or(destroyed) == Some(operation.private_material_digest)
}

/// A local record of the same key identity must equal the retained `IKR1`
/// byte for byte (ADR-105 erratum E12); no local record is no disagreement.
///
/// Equality is deliberate and fails closed: a later local rotation or
/// destruction of an equal-identity key changes the local record, and the
/// imported publication is then unreadable until the records agree again.
fn local_key_agrees(record: &ImportedKeyRecordV1, registry: Option<&KeyRegistryStateV1>) -> bool {
    registry
        .and_then(|registry| registry.key_record(record.identity()))
        .is_none_or(|local| {
            ImportedKeyRecordV1::from_key_record(&local).is_ok_and(|local| local == *record)
        })
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use pos_core::{CoreError, KeyRegistryErrorV1};

    use super::{
        recovery_error, ForkManifestPublicationErrorV1 as PublicationError,
        PublicationSourceErrorV1 as SourceError,
    };
    use crate::ForkEventAuthorityErrorV1;

    #[test]
    fn registry_authorization_errors_map_one_to_one() {
        for (registry, expected) in [
            (
                KeyRegistryErrorV1::InvalidEpoch,
                PublicationError::InvalidEpoch,
            ),
            (
                KeyRegistryErrorV1::SigningRoleRequired,
                PublicationError::SigningRoleRequired,
            ),
            (
                KeyRegistryErrorV1::RegistryUnavailable,
                PublicationError::RegistryUnavailable,
            ),
            (KeyRegistryErrorV1::NotFound, PublicationError::NotFound),
            (KeyRegistryErrorV1::Destroyed, PublicationError::Destroyed),
            (
                KeyRegistryErrorV1::DestructionPending,
                PublicationError::DestructionPending,
            ),
            (
                KeyRegistryErrorV1::InactiveKey,
                PublicationError::InactiveKey,
            ),
            (
                KeyRegistryErrorV1::SigningKeyMismatch,
                PublicationError::SigningKeyMismatch,
            ),
            (
                KeyRegistryErrorV1::InvalidState,
                PublicationError::RegistryUnavailable,
            ),
        ] {
            assert_eq!(PublicationError::from(registry), expected);
        }
    }

    /// Keeps only the mapper arms the public-seam publication tests do not
    /// exercise, such as adapter storage failures and an unreadable registry.
    #[test]
    fn source_errors_keep_storage_indeterminate() {
        assert_eq!(
            SourceError::from(CoreError::Storage(String::new())),
            SourceError::Storage
        );
        assert_eq!(
            SourceError::from(CoreError::StorageOutcomeUnknown(String::new())),
            SourceError::Storage
        );
        assert_eq!(
            SourceError::from(CoreError::ArtifactUnavailable),
            SourceError::Invalid
        );
        assert_eq!(
            SourceError::from(ForkEventAuthorityErrorV1::CorruptAuthority),
            SourceError::Invalid
        );
        assert_eq!(
            SourceError::from(ForkEventAuthorityErrorV1::StorageIndeterminate),
            SourceError::Storage
        );
        assert_eq!(
            SourceError::Storage.into_corrupt_authority(),
            PublicationError::StorageIndeterminate
        );
        assert_eq!(
            SourceError::Invalid.into_registry_unavailable(),
            PublicationError::RegistryUnavailable
        );
    }

    #[test]
    fn recovery_keeps_only_storage_indeterminate() {
        assert_eq!(
            recovery_error(PublicationError::StorageIndeterminate),
            PublicationError::StorageIndeterminate
        );
    }
}
