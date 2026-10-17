//! ADR-119 section 4.3 runtime `declare` (slice 4).
//!
//! The runtime `declare` is the trusted host's only way to declare, re-base
//! or withdraw a `DomainFallbackPolicyV1`. Before it calls the composition
//! fallback registry port it checks what the port cannot see:
//!
//! - the `composition.fallback.declare` host-native grant;
//! - `TargetNotStepped`: the target Timeline is the Timeline the community
//!   passes step;
//! - the DFP1 record rules, by decoding the bytes;
//! - rules 1-7 for every candidate, over host-supplied facts;
//! - `PrimaryNotEffective` against the implementation the registry runs, so
//!   an entry the port has never recorded (tenure 0) is checked against the
//!   composer's base implementation.
//!
//! It then hands the port the primaries' host-supplied conformance sets,
//! which the port freezes into the declaration's ledger row.

use std::collections::{BTreeMap, BTreeSet};

use pos_core::{
    DomainFallbackPolicyV1, FallbackEntryV1, FallbackRecordErrorV1, Hash, ImplementationKeyV1,
    Seq, TimelineId,
};
use pos_store::composition_fallback_registry::{
    CompositionFallbackRegistryErrorV1, CompositionFallbackRegistryV1,
    CompositionFallbackTargetV1, FallbackCommitReceiptV1, FallbackConformanceSetsV1,
    FallbackDeclareRequestV1,
};

use super::{validate_fallback_candidate_v1, FallbackCandidateFactsV1, InvalidFallbackPolicyV1};
use crate::RequiredPluginCompositionV1;

/// The host-native grant that authorizes a declaration (ADR-119 section 4.3).
pub const COMPOSITION_FALLBACK_DECLARE_GRANT_V1: &str = "composition.fallback.declare";

/// The host-native grants the session controller holds for one principal.
///
/// The grants are host-native: the session controller checks them, and no
/// Plugin is ever given one. A deployment owner forbids fallback by granting
/// `composition.fallback.declare` to no one.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FallbackHostGrantsV1 {
    /// The granted host-native capability names.
    pub grants: BTreeSet<String>,
}

impl FallbackHostGrantsV1 {
    /// Whether the principal holds `grant`.
    #[must_use]
    pub fn holds(&self, grant: &str) -> bool {
        self.grants.contains(grant)
    }
}

/// The host-supplied facts of one declared entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackEntryFactsV1 {
    /// The facts of the entry's declared primary. Its host conformance
    /// profiles are the set the declaration freezes for the entry.
    pub primary: FallbackCandidateFactsV1,
    /// The facts of each declared candidate, in policy order.
    pub candidates: Vec<FallbackCandidateFactsV1>,
}

impl FallbackEntryFactsV1 {
    /// Whether these facts are for exactly the pins `entry` declares.
    fn describes(&self, entry: &FallbackEntryV1) -> bool {
        let pins = self.candidates.iter().map(|candidate| &candidate.pin);
        self.primary.pin == *entry.primary() && pins.eq(entry.candidates())
    }
}

/// One runtime declaration, withdrawal or re-base (ADR-119 section 4.3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackDeclarationV1 {
    /// The composition scope; the DFP1 scope must equal it.
    pub scope: String,
    /// The Timeline and entity of the declaration Event.
    pub target: CompositionFallbackTargetV1,
    /// The Timeline the composition's community passes step.
    pub stepped_timeline: TimelineId,
    /// The state revision the caller derived its decision from.
    pub expected_state_revision: u64,
    /// The target Timeline's Logical Head the caller derived its decision from.
    pub expected_logical_head: Seq,
    /// The canonical DFP1 bytes.
    pub policy_bytes: Vec<u8>,
    /// The effective required composition, which holds every primary.
    pub composition: RequiredPluginCompositionV1,
    /// The implementation the registry runs for each entry key: the
    /// composer's base implementation for an entry in tenure 0, otherwise the
    /// implementation of the entry's current tenure.
    pub effective: BTreeMap<String, ImplementationKeyV1>,
    /// The host-supplied facts of every declared entry, by entry key.
    pub facts: BTreeMap<String, FallbackEntryFactsV1>,
}

/// A closed refusal of the runtime `declare`.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FallbackDeclareErrorV1 {
    /// The principal does not hold `composition.fallback.declare`.
    #[error("the principal does not hold composition.fallback.declare")]
    NotGranted,
    /// The target Timeline is not the Timeline the community passes step.
    #[error("the declaration target is not the stepped Timeline")]
    TargetNotStepped,
    /// The DFP1 bytes fail the ADR-119 record rules.
    #[error("invalid DFP1: {0}")]
    Record(FallbackRecordErrorV1),
    /// The host supplied no facts for an entry, or facts of other pins.
    #[error("no matching facts for fallback entry '{entry_key}'")]
    FactsMismatch {
        /// The DFP1 entry key.
        entry_key: String,
    },
    /// A candidate breaks one of the section 4.1 rules.
    #[error(transparent)]
    InvalidPolicy(InvalidFallbackPolicyV1),
    /// The composition fallback registry refused, including
    /// `PrimaryNotEffective` for an entry it has never recorded.
    #[error("composition fallback registry refused: {0}")]
    Registry(CompositionFallbackRegistryErrorV1),
}

type Outcome<T> = Result<T, FallbackDeclareErrorV1>;

/// Declare, re-base or withdraw a fallback policy (ADR-119 section 4.3).
///
/// The checks run in this order: the grant, `TargetNotStepped`, the DFP1
/// record rules, the facts and rules 1-7 of every candidate, then
/// `PrimaryNotEffective` for every entry against
/// [`FallbackDeclarationV1::effective`]. Only then is the port called, with
/// each primary's host-supplied conformance profiles as the entry's
/// conformance set; the port runs its own checks in section 4.3 order.
///
/// # Errors
/// Returns the first refusal, as a [`FallbackDeclareErrorV1`].
pub fn declare_composition_fallback_v1(
    registry: &mut (impl CompositionFallbackRegistryV1 + ?Sized),
    grants: &FallbackHostGrantsV1,
    declaration: &FallbackDeclarationV1,
) -> Outcome<FallbackCommitReceiptV1> {
    authorize(grants, declaration)?;
    let policy = DomainFallbackPolicyV1::from_canonical_cbor(&declaration.policy_bytes)
        .map_err(FallbackDeclareErrorV1::Record)?;
    let conformance = validate_entries(declaration, &policy)?;
    require_effective(declaration, &policy)?;
    let request = port_request(declaration, conformance);
    registry
        .declare(&request)
        .map_err(FallbackDeclareErrorV1::Registry)
}

/// `Ok` when `condition` holds, otherwise `error`.
fn require(condition: bool, error: FallbackDeclareErrorV1) -> Outcome<()> {
    condition.then_some(()).ok_or(error)
}

/// The grant, then `TargetNotStepped`.
fn authorize(grants: &FallbackHostGrantsV1, declaration: &FallbackDeclarationV1) -> Outcome<()> {
    let granted = grants.holds(COMPOSITION_FALLBACK_DECLARE_GRANT_V1);
    let stepped = declaration.target.timeline == declaration.stepped_timeline;
    require(granted, FallbackDeclareErrorV1::NotGranted)
        .and_then(|()| require(stepped, FallbackDeclareErrorV1::TargetNotStepped))
}

/// Validate every entry and collect the conformance sets of the primaries.
fn validate_entries(
    declaration: &FallbackDeclarationV1,
    policy: &DomainFallbackPolicyV1,
) -> Outcome<FallbackConformanceSetsV1> {
    let sets = policy
        .entries()
        .iter()
        .map(|entry| validate_entry(declaration, entry))
        .collect::<Outcome<BTreeMap<_, _>>>()?;
    Ok(FallbackConformanceSetsV1::new(sets))
}

/// Validate every candidate of `entry` and return its conformance set.
fn validate_entry(
    declaration: &FallbackDeclarationV1,
    entry: &FallbackEntryV1,
) -> Outcome<(String, BTreeSet<Hash>)> {
    let entry_key = entry.entry_key();
    let facts = entry_facts(declaration, entry)?;
    let composition = &declaration.composition;
    facts
        .candidates
        .iter()
        .try_for_each(|candidate| {
            validate_fallback_candidate_v1(entry_key, composition, &facts.primary, candidate)
        })
        .map_err(FallbackDeclareErrorV1::InvalidPolicy)?;
    let profiles = facts.primary.host.conformance_profiles.clone();
    Ok((entry_key.to_owned(), profiles))
}

/// The facts of exactly the pins `entry` declares.
fn entry_facts<'a>(
    declaration: &'a FallbackDeclarationV1,
    entry: &FallbackEntryV1,
) -> Outcome<&'a FallbackEntryFactsV1> {
    declaration
        .facts
        .get(entry.entry_key())
        .filter(|facts| facts.describes(entry))
        .ok_or_else(|| FallbackDeclareErrorV1::FactsMismatch {
            entry_key: entry.entry_key().to_owned(),
        })
}

/// Every declared primary is the implementation the registry runs for its
/// entry; an entry the registry has never recorded runs the composer's base.
fn require_effective(
    declaration: &FallbackDeclarationV1,
    policy: &DomainFallbackPolicyV1,
) -> Outcome<()> {
    let effective = policy
        .entries()
        .iter()
        .all(|entry| runs_primary(&declaration.effective, entry));
    let refusal = CompositionFallbackRegistryErrorV1::PrimaryNotEffective;
    require(effective, FallbackDeclareErrorV1::Registry(refusal))
}

/// Whether the registry runs `entry`'s declared primary.
fn runs_primary(
    effective: &BTreeMap<String, ImplementationKeyV1>,
    entry: &FallbackEntryV1,
) -> bool {
    let primary = entry.primary().implementation().digest();
    effective
        .get(entry.entry_key())
        .is_some_and(|running| running.digest() == primary)
}

/// The port request of `declaration` with the frozen `conformance` sets.
fn port_request(
    declaration: &FallbackDeclarationV1,
    conformance: FallbackConformanceSetsV1,
) -> FallbackDeclareRequestV1 {
    FallbackDeclareRequestV1 {
        scope: declaration.scope.clone(),
        target: declaration.target,
        expected_state_revision: declaration.expected_state_revision,
        expected_logical_head: declaration.expected_logical_head,
        policy_bytes: declaration.policy_bytes.clone(),
        conformance,
    }
}
