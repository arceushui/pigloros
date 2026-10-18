//! ADR-119 section 4.1 scratch validation of one candidate, rules 1-7.

use pos_core::output_policy::OutputDeclarationV1;
use pos_crypto::plugin_execution::DeterministicBudgetV1;

use super::{
    enforce_required_plugin_v1, required_plugin_v1, FallbackCandidateFactsV1,
    FallbackValidationFieldV1 as Field, InvalidFallbackPolicyV1,
};
use crate::{
    PluginCompositionErrorV1, RequiredPluginCompositionV1, RequiredPluginV1,
    ScheduledDriverBindingV1,
};

type Facts = FallbackCandidateFactsV1;

/// One rule check over `(primary, candidate)`: `true` when the rule holds.
type Check = (Field, fn(&Facts, &Facts) -> bool);

/// The rule 1 identity checks, in order.
const IDENTITY_CHECKS: [Check; 3] = [
    (Field::Identity, identities_bound),
    (Field::Roles, roles_equal),
    (Field::Distinctness, distinct),
];

/// The checks of rules 2-7, in order.
const FACT_CHECKS: [Check; 11] = [
    (Field::EventTypes, event_types_equal),
    (Field::Schemas, schemas_equal),
    (Field::OutputPolicy, outputs_within),
    (Field::Namespace, namespaces_allow),
    (Field::Capabilities, capabilities_within),
    (Field::Subscriptions, subscriptions_within),
    (Field::Budgets, budgets_within),
    (Field::Profile, profiles_equal),
    (Field::DriverInterval, intervals_equal),
    (Field::Admission, candidate_admitted),
    (Field::Conformance, conformance_parity),
];

/// Validate `candidate` as a fallback for `primary` in one entry (ADR-119
/// section 4.1, rules 1-7).
///
/// `composition` is the effective composition, which holds the primary's
/// derived [`RequiredPluginV1`]. The candidate's facts come from the
/// facts-only scratch registry, so it is never co-registered with the
/// primary. Rule 7 compares the host-supplied conformance sets frozen at
/// declaration.
///
/// # Errors
/// Returns [`InvalidFallbackPolicyV1`] with the entry key and the first rule
/// the candidate breaks.
pub fn validate_fallback_candidate_v1(
    entry_key: &str,
    composition: &RequiredPluginCompositionV1,
    primary: &Facts,
    candidate: &Facts,
) -> Result<(), InvalidFallbackPolicyV1> {
    run_checks(&IDENTITY_CHECKS, primary, candidate)
        .and_then(|()| enforce_both(primary, candidate))
        .and_then(|()| check_composition(composition, primary, candidate))
        .and_then(|()| run_checks(&FACT_CHECKS, primary, candidate))
        .map_err(|field| InvalidFallbackPolicyV1 {
            entry_key: entry_key.to_owned(),
            field,
        })
}

/// The first check of `checks` that fails.
fn run_checks(checks: &[Check], primary: &Facts, candidate: &Facts) -> Result<(), Field> {
    checks
        .iter()
        .find(|(_, holds)| !holds(primary, candidate))
        .map_or(Ok(()), |(field, _)| Err(*field))
}

/// The IMK1 binding of both registered implementations.
fn enforce_both(primary: &Facts, candidate: &Facts) -> Result<(), Field> {
    enforce(primary).and_then(|()| enforce(candidate))
}

fn enforce(facts: &Facts) -> Result<(), Field> {
    enforce_required_plugin_v1(
        &facts.registry.version,
        facts.registry.pin.as_ref(),
        &facts.pin,
    )
}

/// The primary's derived requirement is in `composition`, and replacing it
/// with the candidate's still passes `RequiredPluginCompositionV1::try_new`.
fn check_composition(
    composition: &RequiredPluginCompositionV1,
    primary: &Facts,
    candidate: &Facts,
) -> Result<(), Field> {
    let primary_required = required(primary);
    let index = composition
        .plugins()
        .iter()
        .position(|plugin| Some(plugin) == primary_required.as_ref());
    index
        .zip(required(candidate))
        .and_then(|(index, replacement)| replaced(composition, index, replacement).ok())
        .map(drop)
        .ok_or(Field::Composition)
}

fn required(facts: &Facts) -> Option<RequiredPluginV1> {
    let required = required_plugin_v1(facts.registry.plugin_id, &facts.pin);
    required.ok()
}

fn replaced(
    composition: &RequiredPluginCompositionV1,
    index: usize,
    replacement: RequiredPluginV1,
) -> Result<RequiredPluginCompositionV1, PluginCompositionErrorV1> {
    let mut plugins = composition.plugins().to_vec();
    plugins[index] = replacement;
    RequiredPluginCompositionV1::try_new(composition.mode(), plugins)
}

/// The PMF1 Plugin ID and release digest equal the IMK1's, for both.
fn identities_bound(primary: &Facts, candidate: &Facts) -> bool {
    identity_bound(primary) && identity_bound(candidate)
}

fn identity_bound(facts: &Facts) -> bool {
    let key = facts.pin.implementation();
    facts.execution.plugin_id == key.plugin_id()
        && facts.execution.release_digest == key.release_digest()
}

/// The PPN1 role sets are equal (PPN1 roles are unique).
fn roles_equal(primary: &Facts, candidate: &Facts) -> bool {
    let (left, right) = (primary.pin.roles(), candidate.pin.roles());
    left.len() == right.len() && subset(right, left)
}

/// Distinct Plugin ID texts and distinct run-local Plugin IDs.
fn distinct(primary: &Facts, candidate: &Facts) -> bool {
    plugin_text(primary) != plugin_text(candidate)
        && primary.registry.plugin_id != candidate.registry.plugin_id
}

fn plugin_text(facts: &Facts) -> &str {
    facts.pin.implementation().plugin_id()
}

fn event_types_equal(primary: &Facts, candidate: &Facts) -> bool {
    primary.registry.owned_event_types == candidate.registry.owned_event_types
}

fn schemas_equal(primary: &Facts, candidate: &Facts) -> bool {
    primary.registry.schemas == candidate.registry.schemas
}

/// Every declaration keeps its type, authority and fidelity and lowers or
/// keeps `max_bytes`.
fn outputs_within(primary: &Facts, candidate: &Facts) -> bool {
    let (left, right) = (&primary.registry.outputs, &candidate.registry.outputs);
    left.len() == right.len() && left.iter().zip(right).all(output_within)
}

fn output_within((primary, candidate): (&OutputDeclarationV1, &OutputDeclarationV1)) -> bool {
    primary.event_type() == candidate.event_type()
        && primary.authority() == candidate.authority()
        && fidelity_equal(primary, candidate)
        && candidate.max_bytes() <= primary.max_bytes()
}

fn fidelity_equal(primary: &OutputDeclarationV1, candidate: &OutputDeclarationV1) -> bool {
    primary.fidelity() == candidate.fidelity()
        && primary.stride_ticks() == candidate.stride_ticks()
        && primary.aggregate_min_group() == candidate.aggregate_min_group()
}

/// Rule 2 namespaces: a candidate from the primary's publisher passes; any
/// other candidate must hold a namespace grant covering every owned type.
///
/// It fails closed. A publisher is the same only when the host names it for
/// both releases. ADR-119 section 4.1 rule 2 lets a cross-publisher candidate
/// own a type that is not publisher-prefixed, but no store records which
/// types are prefixed, so V1 narrows the rule: every owned type of a
/// cross-publisher candidate is treated as publisher-prefixed and needs a
/// grant. Empty grants therefore refuse every cross-publisher or unattributed
/// candidate.
fn namespaces_allow(primary: &Facts, candidate: &Facts) -> bool {
    let grants = &candidate.host.namespace_grants;
    let owned = &candidate.registry.owned_event_types;
    same_publisher(primary, candidate) || owned.iter().all(|kind| granted(grants, kind))
}

/// Whether the host names one publisher for both releases.
fn same_publisher(primary: &Facts, candidate: &Facts) -> bool {
    let publisher = &primary.host.publisher;
    publisher.is_some() && *publisher == candidate.host.publisher
}

/// Whether `event_type` is `<namespace>.<rest>` for a granted namespace.
fn granted(grants: &[String], event_type: &str) -> bool {
    grants.iter().any(|namespace| {
        event_type
            .strip_prefix(namespace.as_str())
            .is_some_and(|rest| rest.starts_with('.'))
    })
}

fn capabilities_within(primary: &Facts, candidate: &Facts) -> bool {
    subset(
        &candidate.execution.capabilities,
        &primary.execution.capabilities,
    )
}

fn subscriptions_within(primary: &Facts, candidate: &Facts) -> bool {
    let (left, right) = (&primary.registry, &candidate.registry);
    subset(&right.subscriptions, &left.subscriptions)
        && subset(&right.event_subscriptions, &left.event_subscriptions)
}

/// Rule 4: every PMF1 limit and every CPU reservation is at most the
/// primary's.
///
/// The PMF1 limits are all eight `DeterministicBudgetV1` members, so "output"
/// covers every output-side limit: Event count and bytes, state bytes, and log
/// calls and bytes. A CPU reservation missing on either side refuses: the rule
/// fails closed.
fn budgets_within(primary: &Facts, candidate: &Facts) -> bool {
    let limits = budget_values(primary.execution.budget);
    let candidate_limits = budget_values(candidate.execution.budget);
    let reservations = primary.registry.cpu_reservations_us;
    all_within(&candidate_limits, &limits)
        && reservations
            .zip(candidate.registry.cpu_reservations_us)
            .is_some_and(|(left, right)| all_within(&right, &left))
}

const fn budget_values(budget: DeterministicBudgetV1) -> [u64; 8] {
    [
        budget.memory_bytes,
        budget.fuel,
        budget.host_calls,
        budget.event_count,
        budget.event_bytes,
        budget.state_bytes,
        budget.log_calls,
        budget.log_bytes,
    ]
}

/// Whether each value is at most the bound at its position.
fn all_within<T: PartialOrd>(values: &[T], bounds: &[T]) -> bool {
    values
        .iter()
        .zip(bounds)
        .all(|(value, bound)| value <= bound)
}

/// Both are non-participant: the binding of a community entry.
fn profiles_equal(primary: &Facts, candidate: &Facts) -> bool {
    let non_participant = Some(ScheduledDriverBindingV1::NonParticipant);
    candidate.registry.binding == non_participant && primary.registry.binding == non_participant
}

fn intervals_equal(primary: &Facts, candidate: &Facts) -> bool {
    primary.registry.driver_interval == candidate.registry.driver_interval
}

/// The candidate release is the active admitted release of its Plugin ID.
fn candidate_admitted(_primary: &Facts, candidate: &Facts) -> bool {
    candidate.host.active_release_digest == Some(candidate.pin.implementation().release_digest())
}

/// The candidate's profile digests contain every one of the primary's.
fn conformance_parity(primary: &Facts, candidate: &Facts) -> bool {
    primary
        .host
        .conformance_profiles
        .is_subset(&candidate.host.conformance_profiles)
}

fn subset<T: PartialEq>(items: &[T], of: &[T]) -> bool {
    items.iter().all(|item| of.contains(item))
}
