//! ADR-105 section 4 `FIP1` issuer-policy installation and issuer admission.
//!
//! The destination operator provisions exact `FIP1` bytes out of band, and the
//! trusted deployment composition boundary authenticates a pin naming the
//! exact policy scope and digest. This port installs the operator-pinned
//! genesis or one successor at a time, keeping the complete accepted history
//! plus a durable floor in one atomic store transition. Imported `FAE1` bytes
//! can name an issuer and a policy, but can never add, rotate, retire, revoke,
//! or replace a root.
//!
//! The issuer-admission lookup is the seam the atomic `FAE1` import uses. A
//! committed import found by its operation ID is checked against the exact
//! historical policy its admission recorded, never against the current
//! policy; only a wholly absent import is checked against the current floor.

use std::cmp::Ordering;

use pos_core::{
    ForkAttributionCodecErrorV1, ForkAttributionIssuerPolicyEntryV1, ForkAttributionIssuerPolicyV1,
    ForkAttributionIssuerStateV1, ForkAttributionIssuerV1, Hash,
};
use pos_crypto::fork_attribution_authority::{
    verify_fork_attribution_issuer_key_v1, verify_fork_attribution_issuer_policy_keys_v1,
    ForkAttributionAuthoritySignatureErrorV1,
};

/// Lifetime ceiling on retained `FIP1` records in one policy scope.
///
/// Generations are contiguous from genesis, so the floor generation is also
/// the retained-history length. A 97th record is never accepted.
pub const MAX_FORK_ATTRIBUTION_ISSUER_POLICY_HISTORY_V1: u64 = 96;

/// An out-of-band operator pin for one exact candidate `FIP1`.
///
/// Only the trusted deployment composition boundary constructs a pin, after
/// authenticating the operator by a deployment-specific mechanism. It is never
/// derived from `FIP1` or `FAE1` bytes, and it grants no Fork attribution by
/// itself: it only names the policy the operator approved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedOperatorPolicyPinV1 {
    scope: String,
    policy_digest: Hash,
}

impl AuthenticatedOperatorPolicyPinV1 {
    /// Pin one exact policy scope and complete `FIP1` digest.
    #[must_use]
    pub fn new(scope: impl Into<String>, policy_digest: Hash) -> Self {
        Self {
            scope: scope.into(),
            policy_digest,
        }
    }

    /// The exact, unnormalized policy scope the operator approved.
    #[must_use]
    pub const fn scope(&self) -> &str {
        self.scope.as_str()
    }

    /// The complete `FIP1` digest the operator approved.
    #[must_use]
    pub const fn policy_digest(&self) -> Hash {
        self.policy_digest
    }
}

/// `IssuerPolicyFloorV1`: the newest accepted policy in the destination scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerPolicyFloorV1 {
    /// Exact policy scope.
    pub scope: String,
    /// Accepted generation; also the retained-history length.
    pub generation: u64,
    /// Complete `FIP1` digest.
    pub digest: Hash,
}

impl IssuerPolicyFloorV1 {
    pub(crate) fn from_policy(policy: &ForkAttributionIssuerPolicyV1) -> Self {
        let input = policy.input();
        Self {
            scope: input.scope.clone(),
            generation: input.generation,
            digest: policy.digest(),
        }
    }
}

/// How an install request was satisfied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssuerPolicyInstallOutcomeV1 {
    /// The candidate was appended to the history and is the new floor.
    Installed,
    /// The candidate is byte-identical to the current floor, so a retry after
    /// an indeterminate commit changed nothing (ADR-105 r6 erratum E7).
    AlreadyInstalled,
}

/// Result of one successful operator-pinned policy installation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerPolicyInstallReceiptV1 {
    /// The floor after the request.
    pub floor: IssuerPolicyFloorV1,
    /// Whether this request appended the policy.
    pub outcome: IssuerPolicyInstallOutcomeV1,
}

/// Which durable policy an issuer admission is decided against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkAttributionIssuerAdmissionBasisV1 {
    /// ADR-105 import step 3: the import operation is already committed, and
    /// its stored admission names this historical policy generation. The
    /// current floor and current issuer states are never consulted, so a
    /// committed import stays recoverable after retirement or revocation.
    ///
    /// The recorded generation must be one in which the issuer was `Active`,
    /// because that policy admitted the import. This port still returns
    /// `IssuerRetired` or `IssuerRevoked` when the recorded policy says
    /// otherwise; it does not remap them. The caller (#518) must treat either
    /// result for a committed import as corrupt authority.
    CommittedImport {
        /// Generation recorded by the committed import admission.
        policy_generation: u64,
    },
    /// ADR-105 import step 4: the import operation is wholly absent, so the
    /// issuer must be `Active` in the current floor policy.
    AbsentImport,
}

/// One issuer-admission lookup for an `FAE1` import.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAttributionIssuerAdmissionQueryV1 {
    /// Exact `FAE1` field-3 issuer identity.
    pub issuer: ForkAttributionIssuerV1,
    /// Exact `FAE1` field-4 issuer-policy digest.
    pub policy_digest: Hash,
    /// Committed recovery or new admission.
    pub basis: ForkAttributionIssuerAdmissionBasisV1,
}

/// The accepted policy under which the issuer is `Active`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkAttributionIssuerAdmissionV1 {
    /// Generation of the deciding policy.
    pub policy_generation: u64,
    /// Complete digest of the deciding policy.
    pub policy_digest: Hash,
}

/// Closed failures for issuer-policy installation and issuer admission.
///
/// One enum serves both operations: install returns the encoding, pin,
/// continuity, ceiling, and transition variants; admission returns the key,
/// availability, change, and issuer-state variants; both can return
/// `CorruptPolicy` and `StorageIndeterminate`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkAttributionIssuerPolicyErrorV1 {
    /// The candidate `FIP1` bytes are malformed or noncanonical.
    #[error("Fork attribution issuer policy encoding is invalid")]
    InvalidEncoding,
    /// The candidate `FIP1` declares an unsupported version.
    #[error("Fork attribution issuer policy version is unsupported")]
    UnsupportedVersion,
    /// The candidate exceeds a byte, field, or 32-identity bound.
    #[error("Fork attribution issuer policy exceeds a bound")]
    BoundsExceeded,
    /// An issuer public key is not valid, non-weak Ed25519 material.
    #[error("Fork attribution issuer key is invalid")]
    InvalidIssuerKey,
    /// The operator pin names a different scope or digest.
    #[error("Fork attribution issuer policy does not match the operator pin")]
    PinMismatch,
    /// The candidate names a scope other than the installed one; new-scope
    /// recovery needs a separately accepted contract.
    #[error("Fork attribution issuer policy scope differs from the installed scope")]
    ScopeMismatch,
    /// The candidate generation is below the durable floor.
    #[error("Fork attribution issuer policy rolls back the floor")]
    Rollback,
    /// A different policy already holds the candidate generation.
    #[error("Fork attribution issuer policy generation is already occupied")]
    GenerationConflict,
    /// The candidate generation skips past the floor's successor.
    #[error("Fork attribution issuer policy generation was skipped")]
    GenerationSkipped,
    /// The candidate does not name the floor as its predecessor, or names a
    /// predecessor when no policy is installed.
    #[error("Fork attribution issuer policy predecessor is wrong")]
    WrongPredecessor,
    /// The retained history already holds 96 records.
    #[error("Fork attribution issuer policy history is exhausted")]
    HistoryExhausted,
    /// An identity disappeared, changed key, regressed state, entered other
    /// than `Active`, or stayed `Active` beside a newer epoch.
    #[error("Fork attribution issuer policy transition is not permitted")]
    IllegalTransition,
    /// The successor adds no identity and advances no state.
    #[error("Fork attribution issuer policy successor changes nothing")]
    NoOpSuccessor,
    /// The successor leaves no `Active` identity although it retires, rather
    /// than revokes, an identity `Active` in the predecessor; only an
    /// emergency successor that revokes every such identity may leave zero
    /// `Active` issuers.
    #[error("Fork attribution issuer policy leaves no active issuer")]
    NoActiveIssuer,
    /// No issuer policy is installed, so no new import can be admitted.
    #[error("Fork attribution issuer policy is unavailable")]
    PolicyUnavailable,
    /// The requested digest is not the current floor.
    #[error("Fork attribution issuer policy changed")]
    PolicyChanged,
    /// The issuer is not named by the deciding policy.
    #[error("Fork attribution issuer is not trusted")]
    UntrustedIssuer,
    /// The issuer is `Retired` in the deciding policy.
    #[error("Fork attribution issuer is retired")]
    IssuerRetired,
    /// The issuer is `Revoked` in the deciding policy.
    #[error("Fork attribution issuer is revoked")]
    IssuerRevoked,
    /// Durable policy state is missing, undecodable, or inconsistent, or a
    /// committed admission names a policy absent from the retained history.
    #[error("Fork attribution issuer policy state is corrupt")]
    CorruptPolicy,
    /// Storage failure; for writes the commit state is unknown.
    #[error("Fork attribution issuer storage failure; for writes the commit state is unknown")]
    StorageIndeterminate,
}

impl From<ForkAttributionCodecErrorV1> for ForkAttributionIssuerPolicyErrorV1 {
    fn from(error: ForkAttributionCodecErrorV1) -> Self {
        match error {
            ForkAttributionCodecErrorV1::FieldOutOfBounds => Self::BoundsExceeded,
            ForkAttributionCodecErrorV1::UnsupportedVersion => Self::UnsupportedVersion,
            _ => Self::InvalidEncoding,
        }
    }
}

impl From<ForkAttributionAuthoritySignatureErrorV1> for ForkAttributionIssuerPolicyErrorV1 {
    fn from(error: ForkAttributionAuthoritySignatureErrorV1) -> Self {
        // This port calls only the `pos-crypto` key checks, so every failure
        // it can see is an invalid key. Listing the variants keeps a new
        // crypto failure from being absorbed silently.
        match error {
            ForkAttributionAuthoritySignatureErrorV1::InvalidIssuerKey
            | ForkAttributionAuthoritySignatureErrorV1::InvalidSignature => Self::InvalidIssuerKey,
        }
    }
}

/// Operator-pinned `FIP1` installation and `FAE1` issuer admission.
///
/// Adapters must apply one install atomically: the policy history and the
/// floor become visible together or not at all.
pub trait ForkAttributionIssuerPolicyInstallationPortV1 {
    /// Install the exact operator-pinned genesis or floor successor.
    ///
    /// The port decodes the candidate strictly, recomputes its digest, compares
    /// it with the pin, requires valid Ed25519 issuer keys, and checks
    /// continuity, the ceilings, and the transition rules against the floor.
    /// A byte-identical retry of the current floor returns
    /// [`IssuerPolicyInstallOutcomeV1::AlreadyInstalled`] (ADR-105 r6
    /// erratum E7).
    ///
    /// # Errors
    /// Returns a closed policy error, and changes nothing, when any check or
    /// the atomic store transition fails.
    fn install(
        &mut self,
        pin: &AuthenticatedOperatorPolicyPinV1,
        policy_bytes: &[u8],
    ) -> Result<IssuerPolicyInstallReceiptV1, ForkAttributionIssuerPolicyErrorV1>;

    /// Read the current durable floor, if any policy is installed.
    ///
    /// # Errors
    /// Returns [`ForkAttributionIssuerPolicyErrorV1::CorruptPolicy`] for
    /// inconsistent durable state, or a storage error.
    fn issuer_policy_floor(
        &self,
    ) -> Result<Option<IssuerPolicyFloorV1>, ForkAttributionIssuerPolicyErrorV1>;

    /// Decide whether an `FAE1` issuer is admitted under durable policy.
    ///
    /// The import must first look up its operation ID. Only a committed import
    /// may use [`ForkAttributionIssuerAdmissionBasisV1::CommittedImport`], and
    /// only a wholly absent one uses
    /// [`ForkAttributionIssuerAdmissionBasisV1::AbsentImport`].
    ///
    /// # Errors
    /// Returns a closed policy error unless the issuer key is valid and the
    /// issuer is `Active` in the deciding policy.
    fn admit_issuer(
        &self,
        query: &ForkAttributionIssuerAdmissionQueryV1,
    ) -> Result<ForkAttributionIssuerAdmissionV1, ForkAttributionIssuerPolicyErrorV1>;
}

pub(crate) type PolicyResultV1<T> = Result<T, ForkAttributionIssuerPolicyErrorV1>;

/// One adapter read of the policy deciding an issuer admission.
pub(crate) type LoadedIssuerPolicyV1 = PolicyResultV1<Option<ForkAttributionIssuerPolicyV1>>;

impl ForkAttributionIssuerAdmissionBasisV1 {
    /// The failure when the deciding policy is not durable.
    const fn missing_policy(self) -> ForkAttributionIssuerPolicyErrorV1 {
        match self {
            Self::CommittedImport { .. } => ForkAttributionIssuerPolicyErrorV1::CorruptPolicy,
            Self::AbsentImport => ForkAttributionIssuerPolicyErrorV1::PolicyUnavailable,
        }
    }

    /// The failure when the deciding policy has another digest.
    const fn unequal_policy(self) -> ForkAttributionIssuerPolicyErrorV1 {
        match self {
            Self::CommittedImport { .. } => ForkAttributionIssuerPolicyErrorV1::CorruptPolicy,
            Self::AbsentImport => ForkAttributionIssuerPolicyErrorV1::PolicyChanged,
        }
    }
}

/// Decode one candidate and bind it to the operator pin and valid keys.
pub(crate) fn pinned_issuer_policy(
    pin: &AuthenticatedOperatorPolicyPinV1,
    policy_bytes: &[u8],
) -> PolicyResultV1<ForkAttributionIssuerPolicyV1> {
    ForkAttributionIssuerPolicyV1::from_canonical_cbor(policy_bytes)
        .map_err(ForkAttributionIssuerPolicyErrorV1::from)
        .and_then(|policy| {
            if policy.input().scope == pin.scope() && policy.digest() == pin.policy_digest() {
                Ok(policy)
            } else {
                Err(ForkAttributionIssuerPolicyErrorV1::PinMismatch)
            }
        })
        .and_then(|policy| {
            verify_fork_attribution_issuer_policy_keys_v1(&policy)
                .map(|()| policy)
                .map_err(ForkAttributionIssuerPolicyErrorV1::from)
        })
}

/// Decide whether a pinned candidate is a new floor or an exact retry.
pub(crate) fn plan_issuer_policy_install(
    candidate: &ForkAttributionIssuerPolicyV1,
    current: Option<&ForkAttributionIssuerPolicyV1>,
) -> PolicyResultV1<IssuerPolicyInstallReceiptV1> {
    current
        .map_or_else(
            || install_genesis(candidate),
            |current| install_successor(candidate, current),
        )
        .map(|outcome| IssuerPolicyInstallReceiptV1 {
            floor: IssuerPolicyFloorV1::from_policy(candidate),
            outcome,
        })
}

fn install_genesis(
    candidate: &ForkAttributionIssuerPolicyV1,
) -> PolicyResultV1<IssuerPolicyInstallOutcomeV1> {
    if candidate.input().generation == 1 {
        validate_transition(&[], candidate)
    } else {
        Err(ForkAttributionIssuerPolicyErrorV1::WrongPredecessor)
    }
}

fn install_successor(
    candidate: &ForkAttributionIssuerPolicyV1,
    current: &ForkAttributionIssuerPolicyV1,
) -> PolicyResultV1<IssuerPolicyInstallOutcomeV1> {
    let next = candidate.input();
    let floor = current.input();
    if next.scope != floor.scope {
        return Err(ForkAttributionIssuerPolicyErrorV1::ScopeMismatch);
    }
    match next.generation.cmp(&floor.generation) {
        Ordering::Less => Err(ForkAttributionIssuerPolicyErrorV1::Rollback),
        // ADR-105 r6 erratum E7: an exact retry of the floor recovers an
        // indeterminate install instead of being refused as a rollback.
        Ordering::Equal if candidate == current => {
            Ok(IssuerPolicyInstallOutcomeV1::AlreadyInstalled)
        }
        Ordering::Equal => Err(ForkAttributionIssuerPolicyErrorV1::GenerationConflict),
        Ordering::Greater => advance_floor(candidate, current),
    }
}

/// Check one candidate whose generation is above the floor.
fn advance_floor(
    candidate: &ForkAttributionIssuerPolicyV1,
    current: &ForkAttributionIssuerPolicyV1,
) -> PolicyResultV1<IssuerPolicyInstallOutcomeV1> {
    let next = candidate.input();
    let floor = current.input();
    // `next.generation > floor.generation >= 1`, so the subtraction is exact.
    if next.generation - 1 != floor.generation {
        Err(ForkAttributionIssuerPolicyErrorV1::GenerationSkipped)
    } else if floor.generation >= MAX_FORK_ATTRIBUTION_ISSUER_POLICY_HISTORY_V1 {
        Err(ForkAttributionIssuerPolicyErrorV1::HistoryExhausted)
    } else if next.previous_policy_digest != Some(current.digest()) {
        Err(ForkAttributionIssuerPolicyErrorV1::WrongPredecessor)
    } else {
        validate_transition(&floor.entries, candidate)
    }
}

/// Apply the ADR-105 transition rules from `previous` entries (empty at
/// genesis) to the candidate.
///
/// Every previous identity stays with the same key and a non-regressing
/// state (`Active` < `Retired` < `Revoked`); every new identity enters
/// `Active`; for one issuer ID only the newest epoch may be `Active`, so a
/// rotation retires its predecessor in the same policy; and the candidate
/// must add an identity or advance a state. At least one identity must stay
/// `Active`, unless the candidate is an emergency successor that revokes
/// every identity `Active` in the predecessor; with the no-op rule it then
/// revokes at least one, and zero `Active` identities fail every new import
/// closed.
fn validate_transition(
    previous: &[ForkAttributionIssuerPolicyEntryV1],
    candidate: &ForkAttributionIssuerPolicyV1,
) -> PolicyResultV1<IssuerPolicyInstallOutcomeV1> {
    let entries = &candidate.input().entries;
    let advanced = entries.len() > previous.len()
        || previous
            .iter()
            .any(|old| candidate.issuer_state(&old.issuer) != Some(old.state));
    let legal = transition_is_legal(previous, candidate);
    let keeps_active = keeps_active_or_revokes_all(previous, candidate);
    match (legal, advanced, keeps_active) {
        (false, _, _) => Err(ForkAttributionIssuerPolicyErrorV1::IllegalTransition),
        (true, false, _) => Err(ForkAttributionIssuerPolicyErrorV1::NoOpSuccessor),
        (true, true, false) => Err(ForkAttributionIssuerPolicyErrorV1::NoActiveIssuer),
        (true, true, true) => Ok(IssuerPolicyInstallOutcomeV1::Installed),
    }
}

/// Identities stay with a non-regressing state, enter `Active`, and only the
/// newest epoch of one issuer ID is `Active`.
fn transition_is_legal(
    previous: &[ForkAttributionIssuerPolicyEntryV1],
    candidate: &ForkAttributionIssuerPolicyV1,
) -> bool {
    let entries = &candidate.input().entries;
    let retained = previous.iter().all(|old| {
        candidate
            .issuer_state(&old.issuer)
            .is_some_and(|state| state.code() >= old.state.code())
    });
    let entered_active = entries.iter().all(|entry| {
        entry.state == ForkAttributionIssuerStateV1::Active
            || previous.iter().any(|old| old.issuer == entry.issuer)
    });
    let newest_active = entries.windows(2).all(|pair| {
        pair[0].issuer.issuer_id() != pair[1].issuer.issuer_id()
            || pair[0].state != ForkAttributionIssuerStateV1::Active
    });
    retained && entered_active && newest_active
}

/// The candidate keeps an `Active` identity, or revokes every identity that
/// was `Active` in the predecessor.
fn keeps_active_or_revokes_all(
    previous: &[ForkAttributionIssuerPolicyEntryV1],
    candidate: &ForkAttributionIssuerPolicyV1,
) -> bool {
    let active = ForkAttributionIssuerStateV1::Active;
    let revoked = Some(ForkAttributionIssuerStateV1::Revoked);
    let entries = &candidate.input().entries;
    let keeps = entries.iter().any(|entry| entry.state == active);
    keeps
        || previous
            .iter()
            .filter(|old| old.state == active)
            .all(|old| candidate.issuer_state(&old.issuer) == revoked)
}

/// Require a retained policy to be exactly the expected scope, generation,
/// and stored digest; any mismatch is corrupt durable state.
pub(crate) fn checked_retained_policy(
    policy: ForkAttributionIssuerPolicyV1,
    scope: &str,
    generation: u64,
    digest: Hash,
) -> PolicyResultV1<ForkAttributionIssuerPolicyV1> {
    let input = policy.input();
    if input.scope == scope && input.generation == generation && policy.digest() == digest {
        Ok(policy)
    } else {
        Err(ForkAttributionIssuerPolicyErrorV1::CorruptPolicy)
    }
}

/// Decide one issuer admission against the policy the query basis selects:
/// `retained` loads the policy at a committed generation, and `floor` loads
/// the current floor policy.
pub(crate) fn admit_fork_attribution_issuer<R, F>(
    query: &ForkAttributionIssuerAdmissionQueryV1,
    retained: R,
    floor: F,
) -> PolicyResultV1<ForkAttributionIssuerAdmissionV1>
where
    R: FnOnce(u64) -> LoadedIssuerPolicyV1,
    F: FnOnce() -> LoadedIssuerPolicyV1,
{
    let missing = query.basis.missing_policy();
    verify_fork_attribution_issuer_key_v1(&query.issuer)
        .map_err(ForkAttributionIssuerPolicyErrorV1::from)
        .and_then(|()| match query.basis {
            ForkAttributionIssuerAdmissionBasisV1::CommittedImport { policy_generation } => {
                retained(policy_generation)
            }
            ForkAttributionIssuerAdmissionBasisV1::AbsentImport => floor(),
        })
        .and_then(|policy| policy.ok_or(missing))
        .and_then(|policy| {
            if policy.digest() == query.policy_digest {
                issuer_admission(&policy, &query.issuer)
            } else {
                Err(query.basis.unequal_policy())
            }
        })
}

/// Map the issuer's state in the deciding policy to an admission.
fn issuer_admission(
    policy: &ForkAttributionIssuerPolicyV1,
    issuer: &ForkAttributionIssuerV1,
) -> PolicyResultV1<ForkAttributionIssuerAdmissionV1> {
    let admission = ForkAttributionIssuerAdmissionV1 {
        policy_generation: policy.input().generation,
        policy_digest: policy.digest(),
    };
    match policy.issuer_state(issuer) {
        Some(ForkAttributionIssuerStateV1::Active) => Ok(admission),
        Some(ForkAttributionIssuerStateV1::Retired) => {
            Err(ForkAttributionIssuerPolicyErrorV1::IssuerRetired)
        }
        Some(ForkAttributionIssuerStateV1::Revoked) => {
            Err(ForkAttributionIssuerPolicyErrorV1::IssuerRevoked)
        }
        None => Err(ForkAttributionIssuerPolicyErrorV1::UntrustedIssuer),
    }
}
