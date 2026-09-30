//! Durable ADR-106 Fork-admission host bootstrap.
//!
//! The port owns challenge entropy and its one-use lifecycle. Host keys sign
//! only the returned canonical challenge bytes through `pos-crypto`'s typed
//! wrapper; this module never accepts a seed or a generic signing callback.

use pos_core::{
    fork_authentication::{
        principal_digest_v1, AuthenticatedPrincipalEvidenceV1, ForkAuthenticationPolicyV1,
    },
    ErasureAdmittedForkContextV1, ErasureContainmentErrorV1, ErasureContainmentGateV1,
    ErasureProtectedOperationV1, ErasureTopologyStoreBindingV1, ForkAdmissionCommandFactsV1,
    ForkAdmissionHostCommandV1, ForkAdmissionHostRecordV1, ForkAdmissionInitializeChallengeV1,
    ForkAdmissionOpenChallengeV1, ForkAdmissionOperationKindV1, ForkAdmissionOperationResultV1,
    ForkAdmissionRecordV1, ForkAdmissionRecoveryProofV1, ForkCreateCommitmentInputV1, Hash,
    PrincipalOwnerBindingV1, PrincipalOwnerCommitmentInputV1, PublicKey, Signature, TimelineId,
};
use pos_crypto::fork_authentication::{
    verify_authenticated_principal_evidence_v1, verify_fork_admission_host_command_v1,
    verify_fork_admission_initialize_v1, verify_fork_admission_open_v1,
    verify_fork_admission_recovery_proof_v1,
};
use rand::{rngs::SysRng, TryRng};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
use std::{
    collections::HashSet,
    sync::{LazyLock, Mutex},
};

const SESSION_IDENTITY_DOMAIN: &[u8] = b"pigloros/fork-admission-session/v1";
const ENTROPY_ATTEMPTS: usize = 2;

#[cfg(test)]
static ISSUED_AUTHORITY_ENTROPY: LazyLock<Mutex<HashSet<[u8; 32]>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

#[cfg(test)]
thread_local! {
    static FAIL_AUTHORITY_ENTROPY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_AUTHORITY_ENTROPY: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static ZERO_AUTHORITY_ENTROPY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FORCED_AUTHORITY_ENTROPY: std::cell::RefCell<Vec<[u8; 32]>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Closed failures for the durable ADR-106 bootstrap boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkAdmissionAuthorityErrorV1 {
    /// No canonical FAH1 has been provisioned.
    #[error("Fork-admission authority is uninitialized")]
    AuthorityUninitialized,
    /// Provisioning found an already initialized store.
    #[error("Fork-admission authority is already initialized")]
    AuthorityAlreadyInitialized,
    /// A host proof, policy, store, or current session binding differs.
    #[error("Fork-admission host authority does not match")]
    HostAuthorityMismatch,
    /// Operating-system entropy was unavailable.
    #[error("Fork-admission entropy is unavailable")]
    EntropyUnavailable,
    /// A public custom-clock adapter cannot host Fork authority.
    #[error("Fork-admission authority clock is unavailable")]
    AuthorityClockUnavailable,
    /// The first mutation clock moved below the durable fence.
    #[error("Fork-admission authority clock rolled back")]
    ClockRollback,
    /// The durable authority row is malformed or internally inconsistent.
    #[error("Fork-admission authority state is corrupt")]
    CorruptAuthority,
    /// Storage could not determine an outcome.
    #[error("Fork-admission authority storage outcome is indeterminate")]
    StorageIndeterminate,
}

/// Carry every bootstrap-boundary failure into the closed ADR-106 host error
/// table without collapsing distinct causes.
impl From<ForkAdmissionAuthorityErrorV1> for pos_core::ForkAdmissionErrorV1 {
    fn from(error: ForkAdmissionAuthorityErrorV1) -> Self {
        match error {
            ForkAdmissionAuthorityErrorV1::AuthorityUninitialized => Self::AuthorityUninitialized,
            ForkAdmissionAuthorityErrorV1::AuthorityAlreadyInitialized => {
                Self::AuthorityAlreadyInitialized
            }
            ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch => Self::HostAuthorityMismatch,
            ForkAdmissionAuthorityErrorV1::EntropyUnavailable => Self::EntropyUnavailable,
            ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable => {
                Self::AuthorityClockUnavailable
            }
            ForkAdmissionAuthorityErrorV1::ClockRollback => Self::ClockRollback,
            ForkAdmissionAuthorityErrorV1::CorruptAuthority => Self::CorruptAuthority,
            ForkAdmissionAuthorityErrorV1::StorageIndeterminate => Self::StorageIndeterminate,
        }
    }
}

/// Non-cloneable, non-serializable proof that one FAO1 challenge was consumed.
///
/// It contains no host key, signature, or public constructor. Future FAC1 and
/// FRP1 operations bind their host proof to its exact session identity.
#[derive(Debug)]
pub struct ForkAdmissionAuthoritySessionV1 {
    store_id: Hash,
    identity: Hash,
    host_key: PublicKey,
    policy_digest: Hash,
}

/// The integrity-only private operation row used by both durable adapters.
///
/// It intentionally excludes transient evidence, commands, signatures, times,
/// and session data. ADR-106 permits only their derived evidence digest,
/// immutable command commitment, and result references to survive a commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ForkAdmissionOperationRowV1 {
    pub(crate) kind: ForkAdmissionOperationKindV1,
    pub(crate) operation_id: Hash,
    pub(crate) evidence_digest: Hash,
    pub(crate) commitment: Hash,
    pub(crate) result_digest: Hash,
    pub(crate) child_id: Option<TimelineId>,
}

/// Verified, transient FAC1 facts passed from the common command boundary to
/// an adapter transaction.  None of these values are persisted directly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum VerifiedForkAdmissionCommandV1 {
    PrincipalOwner {
        operation_id: Hash,
        evidence_digest: Hash,
        principal_digest: Hash,
        owner: pos_core::OwnerIdV1,
        commitment: Hash,
        issued_at: u64,
        expires_at: u64,
    },
    Fork {
        operation_id: Hash,
        evidence_digest: Hash,
        principal_digest: Hash,
        parent_id: TimelineId,
        cut: u64,
        descriptor_hash: Hash,
        composition_hash: Hash,
        attribution_required: bool,
        child_name: String,
        commitment: Hash,
        issued_at: u64,
        expires_at: u64,
    },
}

impl VerifiedForkAdmissionCommandV1 {
    pub(crate) const fn kind(&self) -> ForkAdmissionOperationKindV1 {
        match self {
            Self::PrincipalOwner { .. } => ForkAdmissionOperationKindV1::PrincipalOwner,
            Self::Fork { .. } => ForkAdmissionOperationKindV1::Fork,
        }
    }

    pub(crate) const fn operation_id(&self) -> Hash {
        match self {
            Self::PrincipalOwner { operation_id, .. } | Self::Fork { operation_id, .. } => {
                *operation_id
            }
        }
    }

    pub(crate) const fn commitment(&self) -> Hash {
        match self {
            Self::PrincipalOwner { commitment, .. } | Self::Fork { commitment, .. } => *commitment,
        }
    }

    pub(crate) const fn evidence_digest(&self) -> Hash {
        match self {
            Self::PrincipalOwner {
                evidence_digest, ..
            }
            | Self::Fork {
                evidence_digest, ..
            } => *evidence_digest,
        }
    }

    /// Return the FCC1 operation ID and parent, or `None` for a POC1.
    pub(crate) const fn fork_target(&self) -> Option<(Hash, TimelineId)> {
        match self {
            Self::PrincipalOwner { .. } => None,
            Self::Fork {
                operation_id,
                parent_id,
                ..
            } => Some((*operation_id, *parent_id)),
        }
    }
}

/// ADR-106 r3 closed meaning of a payload-free erasure containment decision.
pub(crate) const fn containment_admission_error(
    error: ErasureContainmentErrorV1,
) -> pos_core::ForkAdmissionErrorV1 {
    match error {
        ErasureContainmentErrorV1::AccessFrozen => {
            pos_core::ForkAdmissionErrorV1::ParentErasureContained
        }
        ErasureContainmentErrorV1::RecoveryUnavailable => {
            pos_core::ForkAdmissionErrorV1::ErasureContainmentUnavailable
        }
    }
}

/// Whether an FCC1 outcome may have added a child to the store topology, so
/// the adapter's captured inventory generation must be re-established.
pub(crate) const fn admitted_fork_may_have_changed_topology<T>(
    result: &Result<T, pos_core::ForkAdmissionErrorV1>,
) -> bool {
    matches!(
        result,
        Ok(_) | Err(pos_core::ForkAdmissionErrorV1::StorageIndeterminate)
    )
}

/// The FCC1 operation ID and parent the permit-bearing method may admit.
///
/// A POC1 is not a topology mutation and is `InvalidRequest` there.
pub(crate) fn admitted_fork_target(
    command: &VerifiedForkAdmissionCommandV1,
) -> Result<(Hash, TimelineId), pos_core::ForkAdmissionErrorV1> {
    command
        .fork_target()
        .ok_or(pos_core::ForkAdmissionErrorV1::InvalidRequest)
}

/// Resolve the ADR-106 r3 containment decision of the permit-bearing
/// method for one FCC1 `target`.
///
/// The adapter applies the returned decision only on the absent-operation
/// branch, after the parent-visibility check. `gate` is the adapter's
/// validated gate, and `binding` its host-issued topology binding.
pub(crate) fn admitted_fork_context_containment(
    context: &ErasureAdmittedForkContextV1<'_>,
    gate: Option<&ErasureContainmentGateV1>,
    binding: Option<&ErasureTopologyStoreBindingV1>,
    (operation_id, parent): (Hash, TimelineId),
) -> Result<(), pos_core::ForkAdmissionErrorV1> {
    gate.zip(binding).map_or(
        Err(pos_core::ForkAdmissionErrorV1::ErasureContainmentUnavailable),
        |(gate, binding)| {
            context
                .authorize_admitted_fork(gate, binding, operation_id, parent)
                .map_err(containment_admission_error)
        },
    )
}

/// Run one FAC1 under the ADR-106 r3 rules of the unfenced method.
///
/// A POC1 runs unchanged. A new FCC1 on a store whose binding requires
/// topology permits is `ErasureContainmentUnavailable`; on any other store it
/// runs inside `with_fence(parent, Fork)` exactly as `LedgerStore::fork`, so
/// the gate fence is taken before the adapter write boundary. When the fence
/// refuses the parent, `run` still executes lookup-only: an exact committed
/// operation returns its result and an absent one receives the containment
/// rejection after the parent-visibility check.
pub(crate) fn with_unfenced_fork_containment<T>(
    command: &VerifiedForkAdmissionCommandV1,
    requires_permit: bool,
    gate: Result<std::sync::Arc<ErasureContainmentGateV1>, pos_core::CoreError>,
    mut run: impl FnMut(Result<(), pos_core::ForkAdmissionErrorV1>) -> T,
) -> T {
    let Some((_, parent)) = command.fork_target() else {
        return run(Ok(()));
    };
    if requires_permit {
        return run(Err(
            pos_core::ForkAdmissionErrorV1::ErasureContainmentUnavailable,
        ));
    }
    let mut outcome = None;
    let fenced = gate
        .map_err(|_| pos_core::ForkAdmissionErrorV1::ErasureContainmentUnavailable)
        .and_then(|gate| {
            pos_core::ErasureGate::with_fence(
                gate.as_ref(),
                parent,
                ErasureProtectedOperationV1::Fork,
                &mut || {
                    outcome = Some(run(Ok(())));
                },
            )
            .map_err(containment_admission_error)
        });
    outcome.unwrap_or_else(|| {
        // `with_fence` runs its effect exactly when it authorizes, so a fence
        // that ran nothing carries its rejection; any other shape fails
        // closed as unavailable.
        let rejection = fenced
            .err()
            .unwrap_or(pos_core::ForkAdmissionErrorV1::ErasureContainmentUnavailable);
        run(Err(rejection))
    })
}

/// A current-session, host-proven lookup key decoded from FRP1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ForkAdmissionRecoveryQueryV1 {
    pub(crate) kind: ForkAdmissionOperationKindV1,
    pub(crate) operation_id: Hash,
}

/// Require the presented session to be the adapter instance's current one.
///
/// ADR-106 binds a session to exactly one adapter instance and open proof. A
/// superseded session, or one opened on another adapter instance of the same
/// store, is rejected before any operation lookup or write.
fn require_current_session(
    session: &ForkAdmissionAuthoritySessionV1,
    current_session: Option<Hash>,
) -> Result<(), pos_core::ForkAdmissionErrorV1> {
    if current_session == Some(session.identity()) {
        Ok(())
    } else {
        Err(pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch)
    }
}

/// Verify FRP1 and return only its lookup key. This never opens a mutation
/// path and never exposes the command's store or session values.
pub(crate) fn verify_recovery_proof(
    session: &ForkAdmissionAuthoritySessionV1,
    current_session: Option<Hash>,
    host: ForkAdmissionHostRecordV1,
    proof: &ForkAdmissionRecoveryProofV1,
) -> Result<ForkAdmissionRecoveryQueryV1, pos_core::ForkAdmissionErrorV1> {
    require_current_session(session, current_session)?;
    if verify_fork_admission_recovery_proof_v1(host.host_verifying_key(), proof).is_err() {
        return Err(pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch);
    }
    let facts = proof.validated_command_facts();
    let store_id = facts.store_id;
    let identity = facts.session_identity;
    if !session.matches(host, store_id, identity) {
        return Err(pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch);
    }
    Ok(ForkAdmissionRecoveryQueryV1 {
        kind: facts.kind,
        operation_id: facts.operation_id,
    })
}

/// Verify all ephemeral FAC1 facts before an adapter takes its write boundary.
///
/// `host` is the FAH1 read before verification. The durable adapter must
/// re-read FAH1 inside its write transaction and require it to equal `host`
/// (which also pins the policy digest), then validate the graph before
/// authorizing a first mutation.
pub(crate) fn verify_command(
    session: &ForkAdmissionAuthoritySessionV1,
    current_session: Option<Hash>,
    host: ForkAdmissionHostRecordV1,
    policy: &ForkAuthenticationPolicyV1,
    command: &ForkAdmissionHostCommandV1,
) -> Result<VerifiedForkAdmissionCommandV1, pos_core::ForkAdmissionErrorV1> {
    require_current_session(session, current_session)?;
    if verify_fork_admission_host_command_v1(host.host_verifying_key(), command).is_err() {
        return Err(pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch);
    }
    // FAC1 decoding already validated FAE1, and its digests only re-encode
    // that record, so every evidence failure collapses into one fail-closed
    // `Unauthenticated` result.
    let (verified, evidence_digest, principal_digest) =
        AuthenticatedPrincipalEvidenceV1::from_canonical_cbor(&command.evidence_bytes())
            .ok()
            .and_then(|evidence| verify_authenticated_principal_evidence_v1(policy, evidence).ok())
            .and_then(|verified| {
                let evidence_digest = verified.evidence().digest().ok();
                let principal_digest =
                    principal_digest_v1(&verified.evidence().record().principal).ok();
                evidence_digest
                    .zip(principal_digest)
                    .map(|(evidence_digest, principal_digest)| {
                        (verified, evidence_digest, principal_digest)
                    })
            })
            .ok_or(pos_core::ForkAdmissionErrorV1::Unauthenticated)?;
    let issued_at = verified.evidence().record().issued_at;
    let expires_at = verified.evidence().record().expires_at;
    let facts = command.validated_command_facts();
    let (ForkAdmissionCommandFactsV1::PrincipalOwner {
        store_id,
        session_identity,
        evidence_digest: command_evidence_digest,
        principal_digest: command_principal_digest,
        ..
    }
    | ForkAdmissionCommandFactsV1::Fork {
        store_id,
        session_identity,
        evidence_digest: command_evidence_digest,
        principal_digest: command_principal_digest,
        ..
    }) = facts;
    if !session.matches(host, *store_id, *session_identity) {
        return Err(pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch);
    }
    // The host signs FAC1 only over bound evidence; the digest re-check is
    // defense in depth against a host that signs unbound command facts.
    (*command_evidence_digest == evidence_digest && *command_principal_digest == principal_digest)
        .then(|| {
            verified_command(
                facts,
                evidence_digest,
                principal_digest,
                issued_at,
                expires_at,
            )
        })
        .ok_or(pos_core::ForkAdmissionErrorV1::Unauthenticated)
}

fn verified_command(
    facts: &ForkAdmissionCommandFactsV1,
    evidence_digest: Hash,
    principal_digest: Hash,
    issued_at: u64,
    expires_at: u64,
) -> VerifiedForkAdmissionCommandV1 {
    let commitment = facts.commitment();
    match facts {
        ForkAdmissionCommandFactsV1::PrincipalOwner {
            operation_id,
            owner,
            ..
        } => VerifiedForkAdmissionCommandV1::PrincipalOwner {
            operation_id: *operation_id,
            evidence_digest,
            principal_digest,
            owner: *owner,
            commitment,
            issued_at,
            expires_at,
        },
        ForkAdmissionCommandFactsV1::Fork {
            operation_id,
            parent_id,
            cut,
            descriptor_hash,
            composition_hash,
            attribution_required,
            child_name,
            ..
        } => VerifiedForkAdmissionCommandV1::Fork {
            operation_id: *operation_id,
            evidence_digest,
            principal_digest,
            parent_id: *parent_id,
            cut: *cut,
            descriptor_hash: *descriptor_hash,
            composition_hash: *composition_hash,
            attribution_required: *attribution_required,
            child_name: child_name.clone(),
            commitment,
            issued_at,
            expires_at,
        },
    }
}

/// Reconstruct the immutable POC1 commitment from durable POB1 state.
pub(crate) fn principal_owner_commitment(
    store_id: Hash,
    binding: &PrincipalOwnerBindingV1,
    evidence_digest: Hash,
) -> Hash {
    let input = binding.input();
    PrincipalOwnerCommitmentInputV1 {
        store_id,
        operation_id: input.operation_id,
        evidence_digest,
        principal_digest: input.principal_digest,
        owner: input.owner,
    }
    .commitment()
}

/// Reconstruct the immutable FCC1 commitment from the durable FAR1 graph.
///
/// A valid FAR1 has equal parent head, completed Fold Cursor, and post-fold
/// Tick Boundary, so its parent head is the command cut.
pub(crate) fn fork_commitment(
    store_id: Hash,
    principal_digest: Hash,
    evidence_digest: Hash,
    admission: &ForkAdmissionRecordV1,
    child_name: &str,
) -> Hash {
    let input = admission.input();
    ForkCreateCommitmentInputV1 {
        store_id,
        operation_id: input.operation_id,
        evidence_digest,
        principal_digest,
        parent_id: input.parent_timeline_id,
        cut: input.parent_logical_head,
        descriptor_hash: input.room_revision_descriptor_hash,
        composition_hash: input.plugin_composition_hash,
        attribution_required: input.attribution_required,
        child_name,
    }
    .commitment()
}

impl ForkAdmissionAuthoritySessionV1 {
    /// Return the exact FAO1-plus-signature identity FAC1 and FRP1 must bind.
    #[must_use]
    pub const fn identity(&self) -> Hash {
        self.identity
    }

    /// Confirm this session belongs to `host` and to the claimed store and
    /// session identity of a decoded FAC1 or FRP1.
    ///
    /// The session cannot be constructed outside this crate; it is obtained
    /// only by consuming the store's FAO1 challenge. Comparing the claimed
    /// store identifier prevents one host key from authorizing commands for
    /// another store instance that happens to use the same key.
    fn matches(&self, host: ForkAdmissionHostRecordV1, store_id: Hash, identity: Hash) -> bool {
        self.store_id == store_id
            && self.store_id == host.store_id()
            && self.identity == identity
            && self.host_key == host.host_verifying_key()
            && self.policy_digest == host.authentication_policy_digest()
    }

    pub(crate) const fn store_id(&self) -> Hash {
        self.store_id
    }
}

/// The private durable state shared by `MemoryStore` and `SQLite`.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ForkAdmissionAuthorityStateV1 {
    pub(crate) host: Option<ForkAdmissionHostRecordV1>,
    pub(crate) initialize_challenge: Option<ForkAdmissionInitializeChallengeV1>,
    pub(crate) open_challenge: Option<ForkAdmissionOpenChallengeV1>,
    pub(crate) session_identity: Option<Hash>,
    pub(crate) last_authority_wall_time: u64,
}

/// Generate a distinct nonzero 256-bit challenge identity from the operating system.
pub(crate) fn authority_entropy() -> Result<Hash, ForkAdmissionAuthorityErrorV1> {
    for _ in 0..ENTROPY_ATTEMPTS {
        let mut bytes = [0_u8; 32];
        #[cfg(test)]
        let filled = if FAIL_AUTHORITY_ENTROPY.with(std::cell::Cell::get)
            || FAIL_NEXT_AUTHORITY_ENTROPY.with(|failures| {
                let remaining = failures.get();
                failures.set(remaining.saturating_sub(1));
                remaining != 0
            }) {
            Err(())
        } else if let Some(forced) =
            FORCED_AUTHORITY_ENTROPY.with(|values| values.borrow_mut().pop())
        {
            bytes = forced;
            Ok(())
        } else {
            SysRng.try_fill_bytes(&mut bytes).map_err(|_| ())
        };
        #[cfg(not(test))]
        let filled = SysRng.try_fill_bytes(&mut bytes).map_err(|_| ());
        if filled.is_err() {
            continue;
        }
        #[cfg(test)]
        if ZERO_AUTHORITY_ENTROPY.with(std::cell::Cell::get) {
            bytes = [0; 32];
        }
        if bytes == [0; 32] {
            continue;
        }
        #[cfg(test)]
        if !ISSUED_AUTHORITY_ENTROPY
            .lock()
            .is_ok_and(|mut issued| issued.insert(bytes))
        {
            continue;
        }
        return Ok(Hash::from_bytes(bytes));
    }
    Err(ForkAdmissionAuthorityErrorV1::EntropyUnavailable)
}

pub(crate) fn begin_initialize(
    state: &mut ForkAdmissionAuthorityStateV1,
    authority_enabled: bool,
    host_key: PublicKey,
    policy_digest: Hash,
) -> Result<ForkAdmissionInitializeChallengeV1, ForkAdmissionAuthorityErrorV1> {
    if !authority_enabled {
        return Err(ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable);
    }
    if state.host.is_some() {
        return Err(ForkAdmissionAuthorityErrorV1::AuthorityAlreadyInitialized);
    }
    let store_id = authority_entropy()?;
    let nonce = authority_entropy()?;
    let challenge =
        ForkAdmissionInitializeChallengeV1::new(store_id, nonce, host_key, policy_digest)
            .map_err(|_| ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)?;
    state.initialize_challenge = Some(challenge);
    Ok(challenge)
}

pub(crate) fn finalize_initialize(
    state: &mut ForkAdmissionAuthorityStateV1,
    authority_enabled: bool,
    challenge: &ForkAdmissionInitializeChallengeV1,
    signature: &Signature,
) -> Result<ForkAdmissionHostRecordV1, ForkAdmissionAuthorityErrorV1> {
    if !authority_enabled {
        return Err(ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable);
    }
    // Consume the outstanding FAI1 before any rejection so no path can leave
    // a stale challenge redeemable later.
    let issued = state.initialize_challenge.take();
    if state.host.is_some() {
        return Err(ForkAdmissionAuthorityErrorV1::AuthorityAlreadyInitialized);
    }
    if issued != Some(*challenge) {
        return Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch);
    }
    verify_fork_admission_initialize_v1(challenge, signature)
        .map_err(|_| ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)?;
    let host = challenge.host_record();
    state.host = Some(host);
    Ok(host)
}

pub(crate) fn begin_open(
    state: &mut ForkAdmissionAuthorityStateV1,
    authority_enabled: bool,
    host_key: PublicKey,
    policy_digest: Hash,
) -> Result<ForkAdmissionOpenChallengeV1, ForkAdmissionAuthorityErrorV1> {
    if !authority_enabled {
        return Err(ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable);
    }
    let host = state
        .host
        .ok_or(ForkAdmissionAuthorityErrorV1::AuthorityUninitialized)?;
    if host.host_verifying_key() != host_key || host.authentication_policy_digest() != policy_digest
    {
        return Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch);
    }
    let challenge = authority_entropy().and_then(|nonce| {
        ForkAdmissionOpenChallengeV1::new(host.store_id(), nonce, policy_digest)
            .map_err(|_| ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    })?;
    state.open_challenge = Some(challenge);
    Ok(challenge)
}

pub(crate) fn finalize_open(
    state: &mut ForkAdmissionAuthorityStateV1,
    authority_enabled: bool,
    challenge: &ForkAdmissionOpenChallengeV1,
    signature: &Signature,
) -> Result<ForkAdmissionAuthoritySessionV1, ForkAdmissionAuthorityErrorV1> {
    if !authority_enabled {
        return Err(ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable);
    }
    let host = state
        .host
        .ok_or(ForkAdmissionAuthorityErrorV1::AuthorityUninitialized)?;
    let issued = state.open_challenge.take();
    if issued != Some(*challenge) {
        return Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch);
    }
    verify_fork_admission_open_v1(&host, challenge, signature)
        .map_err(|_| ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)?;
    let identity = session_identity(challenge, signature);
    state.session_identity = Some(identity);
    Ok(ForkAdmissionAuthoritySessionV1 {
        store_id: host.store_id(),
        identity,
        host_key: host.host_verifying_key(),
        policy_digest: host.authentication_policy_digest(),
    })
}

pub(crate) fn advance_wall_fence(
    state: &mut ForkAdmissionAuthorityStateV1,
    authority_enabled: bool,
    session: &ForkAdmissionAuthoritySessionV1,
) -> Result<(), ForkAdmissionAuthorityErrorV1> {
    if !authority_enabled {
        return Err(ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable);
    }
    let host = state
        .host
        .ok_or(ForkAdmissionAuthorityErrorV1::AuthorityUninitialized)?;
    let Some(identity) = state.session_identity else {
        return Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch);
    };
    if !session.matches(host, host.store_id(), identity) {
        return Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch);
    }
    authority_wall_time().and_then(|commit_now| {
        if commit_now < state.last_authority_wall_time {
            return Err(ForkAdmissionAuthorityErrorV1::ClockRollback);
        }
        state.last_authority_wall_time = commit_now;
        Ok(())
    })
}

fn session_identity(challenge: &ForkAdmissionOpenChallengeV1, signature: &Signature) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SESSION_IDENTITY_DOMAIN);
    hasher.update(&challenge.canonical_bytes());
    hasher.update(signature.as_bytes());
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// Require that an ADR-099 operation presents the currently live local session.
pub(crate) fn validate_live_session(
    state: &ForkAdmissionAuthorityStateV1,
    session: &ForkAdmissionAuthoritySessionV1,
) -> bool {
    state
        .host
        .zip(state.session_identity)
        .is_some_and(|(host, identity)| session.matches(host, host.store_id(), identity))
}

fn authority_wall_time() -> Result<u64, ForkAdmissionAuthorityErrorV1> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable)
        .and_then(|duration| {
            u64::try_from(duration.as_micros())
                .map_err(|_| ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable)
        })
}

/// Store adapter seam for ADR-106 bootstrap and the commit-time rollback fence.
pub trait ForkAdmissionAuthorityBootstrapPortV1 {
    /// Produce one opaque FAI1 challenge for an empty store.
    ///
    /// # Errors
    /// Returns an authority, clock, entropy, or storage error if the challenge cannot be issued.
    fn begin_fork_admission_initialize(
        &mut self,
        host_key: PublicKey,
        policy_digest: Hash,
    ) -> Result<ForkAdmissionInitializeChallengeV1, ForkAdmissionAuthorityErrorV1>;
    /// Verify and consume the exact outstanding FAI1 proof, then persist FAH1.
    ///
    /// # Errors
    /// Returns an authority or storage error if the proof cannot be committed.
    fn finalize_fork_admission_initialize(
        &mut self,
        challenge: &ForkAdmissionInitializeChallengeV1,
        signature: &Signature,
    ) -> Result<ForkAdmissionHostRecordV1, ForkAdmissionAuthorityErrorV1>;
    /// Read the immutable FAH1 without creating authority.
    ///
    /// # Errors
    /// Returns an authority or storage error if the record cannot be read.
    fn fork_admission_host_record(
        &self,
    ) -> Result<ForkAdmissionHostRecordV1, ForkAdmissionAuthorityErrorV1>;
    /// Produce one opaque FAO1 challenge after exact key and policy matching.
    ///
    /// # Errors
    /// Returns an authority, clock, entropy, or storage error if the challenge cannot be issued.
    fn begin_fork_admission_open(
        &mut self,
        host_key: PublicKey,
        policy_digest: Hash,
    ) -> Result<ForkAdmissionOpenChallengeV1, ForkAdmissionAuthorityErrorV1>;
    /// Verify and consume FAO1, yielding a non-cloneable session.
    ///
    /// # Errors
    /// Returns an authority or storage error if the proof cannot be consumed.
    fn finalize_fork_admission_open(
        &mut self,
        challenge: &ForkAdmissionOpenChallengeV1,
        signature: &Signature,
    ) -> Result<ForkAdmissionAuthoritySessionV1, ForkAdmissionAuthorityErrorV1>;
    /// Atomically advance the durable commit-time rollback fence for a live session.
    /// The adapter reads the production wall clock while it owns the write lock.
    ///
    /// # Errors
    /// Returns an authority, clock, or storage error if the fence cannot be advanced.
    fn advance_fork_admission_wall_fence(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
    ) -> Result<(), ForkAdmissionAuthorityErrorV1>;
}

/// Store-owned ADR-106 command boundary.
///
/// The caller supplies only canonical opaque command envelopes and the policy
/// whose digest is already pinned by FAH1. Implementations must verify the
/// host proof before opening a write transaction, then own all exact-graph,
/// expiry, rollback-fence, and atomic-persistence decisions.
pub trait ForkAdmissionAuthorityPortV1 {
    /// Execute one authenticated FAC1 operation without a topology permit.
    ///
    /// A POC1 is unchanged and an exact committed FCC1 returns its original
    /// result. A new FCC1 on a store whose erasure binding requires topology
    /// permits is `ErasureContainmentUnavailable`. On any other store the
    /// parent must be generically visible and pass the erasure fence for
    /// `Fork`, as for `LedgerStore::fork` (ADR-106 revision 3).
    ///
    /// # Errors
    /// Returns a closed authority error without exposing partial POB1, child,
    /// FAR1, or operation-row state.
    fn execute_fork_admission_command(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        policy: &ForkAuthenticationPolicyV1,
        command: &ForkAdmissionHostCommandV1,
    ) -> Result<ForkAdmissionOperationResultV1, pos_core::ForkAdmissionErrorV1>;

    /// Reconcile one lookup-only FRP1 operation.
    ///
    /// # Errors
    /// Returns `OperationMissing` for an absent exact operation and never
    /// creates, repairs, or falls back to an FAC1 mutation.
    fn recover_fork_admission_command(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        proof: &ForkAdmissionRecoveryProofV1,
    ) -> Result<ForkAdmissionOperationResultV1, pos_core::ForkAdmissionErrorV1>;

    /// Execute one authenticated FCC1 inside the erasure host's gate topology
    /// transition (ADR-106 revision 3).
    ///
    /// The host builds `context` inside the transition callback. After the
    /// same pre-transaction verification as
    /// [`Self::execute_fork_admission_command`], the adapter claims the
    /// context's permit, requires the context to name this FCC1's operation
    /// ID and parent, and evaluates its parent verdict before taking its
    /// write boundary. An exact committed operation returns its original
    /// result without applying that verdict; otherwise the verdict is applied
    /// after the parent-visibility check.
    ///
    /// # Errors
    /// Returns `InvalidRequest` for a POC1, `ParentErasureContained` or
    /// `ErasureContainmentUnavailable` for a contained or unbindable new Fork,
    /// and otherwise the same closed errors as
    /// [`Self::execute_fork_admission_command`], never leaving a partial
    /// child, FAR1, operation row, or wall-fence advance.
    fn execute_fork_admission_command_in_topology_transition(
        &mut self,
        context: &ErasureAdmittedForkContextV1<'_>,
        session: &ForkAdmissionAuthoritySessionV1,
        policy: &ForkAuthenticationPolicyV1,
        command: &ForkAdmissionHostCommandV1,
    ) -> Result<ForkAdmissionOperationResultV1, pos_core::ForkAdmissionErrorV1>;
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::memory::MemoryStore;
    use ciborium::value::Value;
    use pos_crypto::fork_authentication::ForkHostSigningKeyV1;

    fn open_after_initialize(
        store: &mut MemoryStore,
        challenge: &ForkAdmissionInitializeChallengeV1,
        signer: &ForkHostSigningKeyV1,
        policy_digest: Hash,
    ) -> Result<ForkAdmissionAuthoritySessionV1, Box<dyn std::error::Error>> {
        let signature = signer.sign_initialize(&challenge.canonical_bytes())?;
        store.finalize_fork_admission_initialize(challenge, &signature)?;
        let host_key = PublicKey::from_bytes(signer.public_key());
        let open = store.begin_fork_admission_open(host_key, policy_digest)?;
        let signature = signer.sign_open(&open.canonical_bytes())?;
        Ok(store.finalize_fork_admission_open(&open, &signature)?)
    }

    fn encode(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes)?;
        Ok(bytes)
    }

    #[test]
    fn authority_entropy_fails_closed_when_the_system_source_fails_or_returns_zero() {
        FAIL_AUTHORITY_ENTROPY.with(|flag| flag.set(true));
        assert_eq!(
            authority_entropy(),
            Err(ForkAdmissionAuthorityErrorV1::EntropyUnavailable)
        );
        FAIL_AUTHORITY_ENTROPY.with(|flag| flag.set(false));

        ZERO_AUTHORITY_ENTROPY.with(|flag| flag.set(true));
        assert_eq!(
            authority_entropy(),
            Err(ForkAdmissionAuthorityErrorV1::EntropyUnavailable)
        );
        ZERO_AUTHORITY_ENTROPY.with(|flag| flag.set(false));
    }

    #[test]
    fn authority_entropy_regenerates_zero_and_same_process_repeats(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let signer = ForkHostSigningKeyV1::from_seed([13; 32])?;
        let host_key = PublicKey::from_bytes(signer.public_key());
        let policy_digest = Hash::from_bytes([2; 32]);
        FORCED_AUTHORITY_ENTROPY.with(|values| {
            *values.borrow_mut() = vec![[6; 32], [0; 32]];
        });
        let mut zero_store = MemoryStore::new();
        let zero_challenge = zero_store.begin_fork_admission_initialize(host_key, policy_digest)?;
        assert_eq!(zero_challenge.store_id(), Hash::from_bytes([6; 32]));

        FORCED_AUTHORITY_ENTROPY.with(|values| {
            *values.borrow_mut() = vec![[8; 32], [7; 32]];
        });
        let mut first_store = MemoryStore::new();
        let first_challenge =
            first_store.begin_fork_admission_initialize(host_key, policy_digest)?;
        assert_eq!(first_challenge.store_id(), Hash::from_bytes([7; 32]));

        FORCED_AUTHORITY_ENTROPY.with(|values| {
            *values.borrow_mut() = vec![[10; 32], [9; 32], [7; 32]];
        });
        let mut second_store = MemoryStore::new();
        let second_challenge =
            second_store.begin_fork_admission_initialize(host_key, policy_digest)?;
        assert_eq!(second_challenge.store_id(), Hash::from_bytes([9; 32]));
        let first_session =
            open_after_initialize(&mut first_store, &first_challenge, &signer, policy_digest)?;
        let second_session =
            open_after_initialize(&mut second_store, &second_challenge, &signer, policy_digest)?;
        assert_eq!(
            first_store.advance_fork_admission_wall_fence(&second_session),
            Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
        );
        assert_eq!(
            second_store.advance_fork_admission_wall_fence(&first_session),
            Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
        );
        first_store.advance_fork_admission_wall_fence(&first_session)?;
        second_store.advance_fork_admission_wall_fence(&second_session)?;
        Ok(())
    }

    #[test]
    fn authority_entropy_retries_one_source_failure() -> Result<(), Box<dyn std::error::Error>> {
        FAIL_NEXT_AUTHORITY_ENTROPY.with(|failures| failures.set(1));
        FORCED_AUTHORITY_ENTROPY.with(|values| {
            *values.borrow_mut() = vec![[12; 32], [11; 32]];
        });
        let mut store = MemoryStore::new();
        let challenge = store.begin_fork_admission_initialize(
            PublicKey::from_bytes([1; 32]),
            Hash::from_bytes([2; 32]),
        )?;
        assert_eq!(challenge.store_id(), Hash::from_bytes([11; 32]));
        Ok(())
    }

    #[test]
    fn initialize_fails_closed_when_the_second_entropy_draw_repeats() {
        FORCED_AUTHORITY_ENTROPY.with(|values| {
            *values.borrow_mut() = vec![[21; 32], [21; 32], [21; 32]];
        });
        let mut state = ForkAdmissionAuthorityStateV1::default();
        assert_eq!(
            begin_initialize(
                &mut state,
                true,
                PublicKey::from_bytes([1; 32]),
                Hash::from_bytes([2; 32]),
            ),
            Err(ForkAdmissionAuthorityErrorV1::EntropyUnavailable)
        );
        assert_eq!(state.initialize_challenge, None);
        FORCED_AUTHORITY_ENTROPY.with(|values| values.borrow_mut().clear());
    }

    #[test]
    fn authority_entropy_failure_propagates_through_challenge_issuance(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let host_key = PublicKey::from_bytes([1; 32]);
        let policy_digest = Hash::from_bytes([2; 32]);

        let mut uninitialized = ForkAdmissionAuthorityStateV1::default();
        FAIL_AUTHORITY_ENTROPY.with(|flag| flag.set(true));
        assert_eq!(
            begin_initialize(&mut uninitialized, true, host_key, policy_digest),
            Err(ForkAdmissionAuthorityErrorV1::EntropyUnavailable)
        );
        FAIL_AUTHORITY_ENTROPY.with(|flag| flag.set(false));

        let mut initialized = ForkAdmissionAuthorityStateV1 {
            host: Some(ForkAdmissionHostRecordV1::new(
                Hash::from_bytes([3; 32]),
                host_key,
                policy_digest,
            )?),
            ..ForkAdmissionAuthorityStateV1::default()
        };
        FAIL_AUTHORITY_ENTROPY.with(|flag| flag.set(true));
        assert_eq!(
            begin_open(&mut initialized, true, host_key, policy_digest),
            Err(ForkAdmissionAuthorityErrorV1::EntropyUnavailable)
        );
        FAIL_AUTHORITY_ENTROPY.with(|flag| flag.set(false));
        Ok(())
    }

    #[test]
    fn recovery_proof_verification_rejects_signature_and_session_mismatch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let signer = ForkHostSigningKeyV1::from_seed([61; 32])?;
        let host = ForkAdmissionHostRecordV1::new(
            Hash::from_bytes([62; 32]),
            PublicKey::from_bytes(signer.public_key()),
            Hash::from_bytes([63; 32]),
        )?;
        let session = ForkAdmissionAuthoritySessionV1 {
            store_id: host.store_id(),
            identity: Hash::from_bytes([65; 32]),
            host_key: host.host_verifying_key(),
            policy_digest: host.authentication_policy_digest(),
        };
        let command = encode(&Value::Array(vec![
            Value::Text("FRC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(host.store_id().as_bytes().to_vec()),
            Value::Bytes(session.identity().as_bytes().to_vec()),
            Value::Integer(2.into()),
            Value::Bytes(vec![66; 32]),
        ]))?;
        let proof = encode(&Value::Array(vec![
            Value::Text("FRP1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(command.clone()),
            Value::Bytes(signer.sign_recovery(&command)?.as_bytes().to_vec()),
        ]))?;
        let proof = ForkAdmissionRecoveryProofV1::from_canonical_cbor(&proof)?;
        let current = Some(session.identity());
        assert_eq!(
            verify_recovery_proof(&session, current, host, &proof)?.kind,
            ForkAdmissionOperationKindV1::Fork
        );

        let principal_command = encode(&Value::Array(vec![
            Value::Text("FRC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(host.store_id().as_bytes().to_vec()),
            Value::Bytes(session.identity().as_bytes().to_vec()),
            Value::Integer(1.into()),
            Value::Bytes(vec![68; 32]),
        ]))?;
        let principal_proof = encode(&Value::Array(vec![
            Value::Text("FRP1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(principal_command.clone()),
            Value::Bytes(
                signer
                    .sign_recovery(&principal_command)?
                    .as_bytes()
                    .to_vec(),
            ),
        ]))?;
        let principal_proof = ForkAdmissionRecoveryProofV1::from_canonical_cbor(&principal_proof)?;
        assert_eq!(
            verify_recovery_proof(&session, current, host, &principal_proof)?.kind,
            ForkAdmissionOperationKindV1::PrincipalOwner
        );

        let mut invalid = proof.to_canonical_cbor();
        let last = invalid.len() - 1;
        invalid[last] ^= 1;
        let invalid = ForkAdmissionRecoveryProofV1::from_canonical_cbor(&invalid)?;
        assert_eq!(
            verify_recovery_proof(&session, current, host, &invalid),
            Err(pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch)
        );

        let wrong_session = ForkAdmissionAuthoritySessionV1 {
            identity: Hash::from_bytes([67; 32]),
            ..session
        };
        assert_eq!(
            verify_recovery_proof(&wrong_session, current, host, &proof),
            Err(pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch)
        );
        assert_eq!(
            verify_recovery_proof(&wrong_session, Some(wrong_session.identity()), host, &proof),
            Err(pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch)
        );
        Ok(())
    }
}
