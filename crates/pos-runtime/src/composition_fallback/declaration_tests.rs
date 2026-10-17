//! Unit tests of the ADR-119 runtime `declare` (slice 4), on `MemoryStore`.

use std::collections::BTreeMap;
use std::sync::Arc;

use pos_core::store::EventStore;
use pos_core::{
    DomainFallbackPolicyV1, ErasureContainmentGateV1, FallbackActivationModeV1, FallbackEntryV1,
    FallbackRecordErrorV1, FallbackTriggerCodeV1, MAX_FALLBACK_POLICY_BYTES_V1,
};
use pos_store::composition_fallback_registry::{
    CompositionFallbackRegistryErrorV1 as RegistryError, CompositionFallbackRegistryV1,
    CompositionFallbackTargetV1, FallbackCommitOutcomeV1, FallbackCommitReceiptV1,
    FallbackConformanceSetsV1, FallbackLedgerBodyV1,
};
use pos_store::memory::MemoryStore;

use super::*;

const SCOPE: &str = "scope";

type DeclareError = FallbackDeclareErrorV1;
type Declared = Result<FallbackCommitReceiptV1, DeclareError>;
type Refusal = Result<Option<DeclareError>, Box<dyn Error>>;

/// A provisioned store with one Timeline, a declaration of the fixture's
/// one-entry policy on it, and the declare grant.
struct World {
    store: MemoryStore,
    declaration: FallbackDeclarationV1,
    grants: FallbackHostGrantsV1,
}

impl World {
    fn declare(&mut self) -> Declared {
        declare_composition_fallback_v1(&mut self.store, &self.grants, &self.declaration)
    }

    /// The current Logical Head of the target Timeline.
    fn head(&self) -> Result<pos_core::Seq, Box<dyn Error>> {
        let timeline = self.declaration.target.timeline;
        Ok(self.store.logical_head(timeline)?)
    }
}

fn entry(fixture: &Fixture) -> Result<FallbackEntryV1, Box<dyn Error>> {
    let triggers = vec![FallbackTriggerCodeV1::ResourceLimit];
    let mode = FallbackActivationModeV1::Automatic;
    let pins = vec![fixture.candidate.pin.clone()];
    let (key, primary) = (ENTRY.to_owned(), fixture.primary.pin.clone());
    Ok(FallbackEntryV1::new(key, primary, pins, triggers, mode)?)
}

fn policy(
    entries: Vec<FallbackEntryV1>,
    previous: Option<Hash>,
) -> Result<DomainFallbackPolicyV1, Box<dyn Error>> {
    let scope = SCOPE.to_owned();
    Ok(DomainFallbackPolicyV1::new(scope, entries, previous)?)
}

fn world() -> Result<World, Box<dyn Error>> {
    let fixture = fixture()?;
    let mut store = MemoryStore::new();
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    store.provision_fallback_registry()?;
    let timeline = store.create_timeline("composition")?.id();
    let first = policy(vec![entry(&fixture)?], None)?;
    let primary = fixture.primary.pin.implementation().clone();
    let facts = FallbackEntryFactsV1 {
        primary: fixture.primary,
        candidates: vec![fixture.candidate],
    };
    let declaration = FallbackDeclarationV1 {
        scope: SCOPE.to_owned(),
        target: CompositionFallbackTargetV1 {
            timeline,
            entity: EntityId::new(),
        },
        stepped_timeline: timeline,
        expected_state_revision: 0,
        expected_logical_head: store.logical_head(timeline)?,
        policy_bytes: first.to_canonical_cbor(),
        composition: fixture.composition,
        effective: BTreeMap::from([(ENTRY.to_owned(), primary)]),
        facts: BTreeMap::from([(ENTRY.to_owned(), facts)]),
    };
    let grant = COMPOSITION_FALLBACK_DECLARE_GRANT_V1.to_owned();
    let grants = FallbackHostGrantsV1 {
        grants: BTreeSet::from([grant]),
    };
    Ok(World {
        store,
        declaration,
        grants,
    })
}

/// The refusal of a fresh world after `edit` changes it; nothing is recorded.
fn refusal_after(edit: impl FnOnce(&mut World)) -> Refusal {
    let mut world = world()?;
    edit(&mut world);
    let refusal = world.declare().err();
    let timeline = world.declaration.target.timeline;
    assert_eq!(world.store.registry_row(SCOPE, timeline)?, None);
    Ok(refusal)
}

/// Apply `edit` to the facts of every declared entry.
fn edit_facts(world: &mut World, edit: FactsEdit) {
    for facts in world.declaration.facts.values_mut() {
        edit(facts);
    }
}

#[test]
fn a_valid_declaration_commits_and_freezes_the_primary_conformance_set() -> TestResult {
    let mut world = world()?;
    let receipt = world.declare()?;
    assert_eq!(receipt.outcome(), FallbackCommitOutcomeV1::Committed);
    let profiles = BTreeSet::from([Hash::from_bytes([9; 32])]);
    let sets = FallbackConformanceSetsV1::new(BTreeMap::from([(ENTRY.to_owned(), profiles)]));
    let frozen = FallbackLedgerBodyV1::Declaration {
        conformance_digest: sets.digest(),
    };
    assert_eq!(receipt.row().body(), &frozen);
    let retry = world.declare()?;
    assert_eq!(retry.outcome(), FallbackCommitOutcomeV1::IdempotentReplay);
    assert_eq!(retry.row(), receipt.row());
    Ok(())
}

#[test]
fn a_withdrawal_names_the_current_policy_and_needs_no_facts() -> TestResult {
    let mut world = world()?;
    let first = world.declare()?;
    let withdrawal = policy(Vec::new(), Some(first.row().policy_digest()))?;
    world.declaration.policy_bytes = withdrawal.to_canonical_cbor();
    world.declaration.expected_state_revision = 1;
    world.declaration.expected_logical_head = world.head()?;
    world.declaration.facts.clear();
    world.declaration.effective.clear();
    let receipt = world.declare()?;
    assert_eq!(receipt.outcome(), FallbackCommitOutcomeV1::Committed);
    let digest = receipt.row().policy_digest();
    assert_eq!(digest, withdrawal.policy_digest());
    Ok(())
}

#[test]
fn a_principal_without_the_declare_grant_is_refused() -> TestResult {
    let activate = BTreeSet::from(["composition.fallback.activate".to_owned()]);
    let refusal = refusal_after(|world| world.grants.grants = activate)?;
    assert_eq!(refusal, Some(DeclareError::NotGranted));
    let none = refusal_after(|world| world.grants.grants.clear())?;
    assert_eq!(none, Some(DeclareError::NotGranted));
    let empty = FallbackHostGrantsV1::default();
    assert!(!empty.holds(COMPOSITION_FALLBACK_DECLARE_GRANT_V1));
    Ok(())
}

#[test]
fn a_target_that_is_not_the_stepped_timeline_is_refused() -> TestResult {
    let refusal = refusal_after(|world| {
        world.declaration.stepped_timeline = TimelineId::new();
    })?;
    assert_eq!(refusal, Some(DeclareError::TargetNotStepped));
    Ok(())
}

#[test]
fn invalid_dfp1_bytes_are_refused_with_the_record_error() -> TestResult {
    let oversized = vec![0; MAX_FALLBACK_POLICY_BYTES_V1 + 1];
    let refusal = refusal_after(|world| world.declaration.policy_bytes = oversized)?;
    let too_large = DeclareError::Record(FallbackRecordErrorV1::TooLarge);
    assert_eq!(refusal, Some(too_large));
    Ok(())
}

#[test]
fn missing_or_mismatched_facts_are_refused() -> TestResult {
    let mismatch = Some(DeclareError::FactsMismatch {
        entry_key: ENTRY.to_owned(),
    });
    let missing = refusal_after(|world| world.declaration.facts.clear())?;
    assert_eq!(missing, mismatch);
    let fewer = refusal_after(|world| {
        edit_facts(world, |facts| facts.candidates.clear());
    })?;
    assert_eq!(fewer, mismatch);
    let swapped = refusal_after(|world| {
        edit_facts(world, |facts| {
            std::mem::swap(&mut facts.primary, &mut facts.candidates[0]);
        });
    })?;
    assert_eq!(swapped, mismatch);
    Ok(())
}

#[test]
fn a_candidate_that_breaks_a_rule_is_refused_with_its_field() -> TestResult {
    let refusal = refusal_after(|world| {
        edit_facts(world, |facts| {
            facts.candidates[0].host.conformance_profiles.clear();
        });
    })?;
    let invalid = DeclareError::InvalidPolicy(InvalidFallbackPolicyV1 {
        entry_key: ENTRY.to_owned(),
        field: Field::Conformance,
    });
    assert_eq!(refusal, Some(invalid));
    Ok(())
}

/// A candidate whose owned type has another schema (rule 2).
fn schema_changed(facts: &mut FallbackEntryFactsV1) {
    facts.candidates[0].registry.schemas = vec![Some("{}".to_owned())];
}

/// A candidate without the primary's output declarations (rule 2).
fn outputs_dropped(facts: &mut FallbackEntryFactsV1) {
    facts.candidates[0].registry.outputs.clear();
}

/// A candidate without the non-participant profile (rule 5).
fn profile_dropped(facts: &mut FallbackEntryFactsV1) {
    facts.candidates[0].registry.binding = None;
}

/// A primary whose registered pin is not the IMK1 release digest.
fn primary_unpinned(facts: &mut FallbackEntryFactsV1) {
    facts.primary.registry.pin = None;
}

/// An in-place edit of one entry's facts.
type FactsEdit = fn(&mut FallbackEntryFactsV1);

/// The section 4.1 rules PCH1 cannot break through the facts-only path with
/// one Plugin type, driven here through the runtime `declare`.
const REGISTRY_FACT_RULES: [(Field, FactsEdit); 4] = [
    (Field::Schemas, schema_changed),
    (Field::OutputPolicy, outputs_dropped),
    (Field::Profile, profile_dropped),
    (Field::ConfigurationDigest, primary_unpinned),
];

#[test]
fn registry_fact_rules_are_refused_through_declare() -> TestResult {
    for (field, edit) in REGISTRY_FACT_RULES {
        let refusal = refusal_after(|world| edit_facts(world, edit))?;
        let invalid = DeclareError::InvalidPolicy(InvalidFallbackPolicyV1 {
            entry_key: ENTRY.to_owned(),
            field,
        });
        assert_eq!(refusal, Some(invalid));
    }
    Ok(())
}

#[test]
fn a_tenure_zero_primary_that_is_not_the_base_implementation_is_refused() -> TestResult {
    let not_effective = Some(DeclareError::PrimaryNotEffective {
        entry_key: ENTRY.to_owned(),
    });
    let other = ImplementationKeyV1::new(
        "acme.other".to_owned(),
        "1.0.0".to_owned(),
        Hash::from_bytes([7; 32]),
    )?;
    let replaced = refusal_after(|world| {
        world.declaration.effective.insert(ENTRY.to_owned(), other);
    })?;
    assert_eq!(replaced, not_effective);
    let unknown = refusal_after(|world| world.declaration.effective.clear())?;
    assert_eq!(unknown, not_effective);
    Ok(())
}

#[test]
fn a_port_refusal_is_returned_unchanged() -> TestResult {
    let empty = policy(Vec::new(), None)?.to_canonical_cbor();
    let refusal = refusal_after(|world| world.declaration.policy_bytes = empty)?;
    let empty_first = DeclareError::Registry(RegistryError::EmptyFirstPolicy);
    assert_eq!(refusal, Some(empty_first));
    Ok(())
}

#[test]
fn declaration_values_are_comparable_and_printable() -> TestResult {
    let world = world()?;
    let declaration = world.declaration.clone();
    assert_eq!(declaration, world.declaration);
    assert!(format!("{declaration:?}").contains(SCOPE));
    let grants = world.grants.clone();
    assert_eq!(grants, world.grants);
    let printed = format!("{grants:?}");
    assert!(printed.contains(COMPOSITION_FALLBACK_DECLARE_GRANT_V1));
    let facts = declaration.facts.values().next().cloned();
    assert_eq!(facts.as_ref(), declaration.facts.get(ENTRY));
    let mismatch = DeclareError::FactsMismatch {
        entry_key: ENTRY.to_owned(),
    };
    let stale = DeclareError::PrimaryNotEffective {
        entry_key: ENTRY.to_owned(),
    };
    let messages = [
        DeclareError::NotGranted.to_string(),
        DeclareError::TargetNotStepped.to_string(),
        DeclareError::Record(FallbackRecordErrorV1::TooLarge).to_string(),
        mismatch.to_string(),
        DeclareError::Registry(RegistryError::Conflict).to_string(),
        stale.to_string(),
    ];
    assert!(messages.iter().all(|message| !message.is_empty()));
    assert!(messages[3].contains(ENTRY));
    assert!(messages[5].contains(ENTRY));
    assert!(format!("{mismatch:?}").contains(ENTRY));
    Ok(())
}
