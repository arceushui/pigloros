//! The committed state of an `initialize` that the domain exposes to no
//! caller: the published ARD1 rows, the successor CSI1, the retained keys,
//! records and COA1s, the burned producer ordinal, the compare-and-swap of
//! the inventory generation and CSI1, and the retry's evidence checks.

use pos_core::community_lifecycle::{
    community_catalogue_owner_v1, community_initializer_set_ref_v1, ArtifactRefV1,
    CommunityArtifactAdmissionInputV1, CommunityArtifactAdmissionV1, CommunityArtifactOperationV1,
    CommunityArtifactPurposeV1, CommunityDurableProfileV1, CommunityInitializationSourceV1,
    CommunityLifecycleErrorV1 as Error, CommunityMetadataPolicyV1, CommunitySelectionV1,
};
use pos_core::community_lifecycle::{
    CommunityBudgetQuoteV1, CommunityMaterializationV1, CommunitySharedCountsV1,
    COMMUNITY_ERASURE_TARGET_LINE_V1,
};
use pos_core::store::EventStore;
use pos_core::RecordedSetCountsV1;
use pos_core::{
    ArtifactDataClassV1, AuthorityTrustRootSealV1, EntityId, Hash, Seq, TimelineId, TimelineMeta,
};
use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use crate::erasure_budget_rows::{community_rows, erasure_row};
use crate::memory::MemoryStore;
use crate::MemoryTrustedClockAuthorityV1;

use super::super::erasure_budget::CommunityErasureBudgetPortV1;
use super::super::erasure_budget::CommunityErasureContextV1;
use super::super::pass_planner::CommunityPassReadPortV1;
use super::super::pass_state::{CommunityPassStateV1, CommunityPendingReservationV1};
use super::{
    CommittedInitializationV1, CommunityInitializationContextV1, CommunityInitializationReceiptV1,
    CommunityInitializeCallV1, PreparedV1, SealedMetadataV1, StagedInitializationV1,
};
use crate::community::MemoryCommunityDomainV1;
use crate::community::{
    CommunityAdministrativeOperationV1, CommunityAdministrativeRequestV1, CommunityDomainBindingV1,
    CommunityInitializationInstallationV1, CommunityInitializeFormV1, CommunityInitializerOwnerV1,
};
use crate::community_initialization_fixture::{
    hash, profile_until, target, trusted_store, Bootstrapped, Fallible, Roster, World, DATA_LEAF,
    GENERATION, HORIZON, INCARNATION, INSTALLED_CATALOGUE, METADATA_LEAF, NATIVE_PROFILE,
    OPERATION, STATE_LIMITS, TRUST_SCOPE,
};

/// The trust-root seal of the test composition.
const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();

type TestResult = Fallible<()>;

/// One edit of a retained initialization.
type Tamper = fn(&mut CommittedInitializationV1);

fn form(profile: &CommunityDurableProfileV1<'_>, operation: [u8; 16]) -> CommunityInitializeFormV1 {
    CommunityInitializeFormV1 {
        timeline: target(),
        operation_id: operation,
        initial_source: CommunityInitializationSourceV1::Initializer(
            community_initializer_set_ref_v1(profile),
        ),
    }
}

fn request(
    profile: &CommunityDurableProfileV1<'_>,
    operation: [u8; 16],
) -> Fallible<CommunityAdministrativeRequestV1> {
    let form = form(profile, operation);
    Ok(CommunityAdministrativeRequestV1::derive(
        &CommunityAdministrativeOperationV1::Initialize {
            timeline: form.timeline,
            operation_id: form.operation_id,
            initial_source: form.initial_source,
            expected_prior_generation: None,
            expected_prior_head_digest: None,
        },
    )?)
}

struct Case {
    domain: Bootstrapped,
    state: Vec<u8>,
}

impl Case {
    fn new(roster: &Roster, admit: bool) -> Fallible<Self> {
        Ok(Self {
            domain: Bootstrapped::new(&SEAL, roster, admit, true)?,
            state: roster.state.clone(),
        })
    }

    /// Run every step before the writer for `operation`.
    fn prepare(
        &mut self,
        profile: &CommunityDurableProfileV1<'_>,
        operation: [u8; 16],
    ) -> Fallible<Result<PreparedV1, Error>> {
        let credential = self.domain.world.credential(request(profile, operation)?)?;
        let owner = CommunityInitializerOwnerV1::new(
            &SEAL,
            profile,
            vec![Zeroizing::new(self.state.clone()); 2],
        )?;
        let policy = CommunityMetadataPolicyV1::new(*self.domain.policy.as_input())?;
        let context = CommunityInitializationContextV1 {
            installation: CommunityInitializationInstallationV1 {
                store_incarnation: INCARNATION,
                profile,
                native_profile_digest: NATIVE_PROFILE,
                installed_owner_catalogue_digest: hash(0x62),
                installation_id: [0x63; 16],
                state_limit_bytes: &STATE_LIMITS,
            },
            binding: CommunityDomainBindingV1 {
                metadata_policy: &policy,
                installed_catalogue_digest: INSTALLED_CATALOGUE,
                native_profile_digest: NATIVE_PROFILE,
            },
            initializer: &owner,
        };
        let world = &mut self.domain.world;
        Ok(world.domain.prepare(
            &SEAL,
            context,
            &mut world.authority,
            &mut self.domain.metadata,
            CommunityInitializeCallV1 {
                credential: &credential,
                form: form(profile, operation),
                administrative_leaf: DATA_LEAF,
                initializer_leaves: &[DATA_LEAF],
                member_leaves: &[DATA_LEAF, DATA_LEAF],
            },
        ))
    }

    /// Prepare `operation`, check the writer bound and commit it.
    fn initialize(
        &mut self,
        profile: &CommunityDurableProfileV1<'_>,
        operation: [u8; 16],
    ) -> Fallible<Result<CommunityInitializationReceiptV1, Error>> {
        Ok(match self.prepare(profile, operation)? {
            Ok(PreparedV1::Original(receipt)) => Ok(receipt),
            Ok(PreparedV1::Staged(staged, call)) => {
                let world = &mut self.domain.world;
                world
                    .authority
                    .check_writer_bound(call, &mut world.domain)
                    .and_then(|()| world.domain.commit(*staged))
            }
            Err(error) => Err(error),
        })
    }

    fn retained(&mut self) -> Fallible<&mut CommittedInitializationV1> {
        Ok(self
            .domain
            .world
            .domain
            .initializations
            .get_mut(&(target(), OPERATION))
            .ok_or("the initialization must be retained")?)
    }
}

fn staged(prepared: Result<PreparedV1, Error>) -> Fallible<Box<StagedInitializationV1>> {
    match prepared? {
        PreparedV1::Staged(staged, _) => Ok(staged),
        PreparedV1::Original(_) => Err("a new initialization must stage".into()),
    }
}

fn copy(records: &[SealedMetadataV1]) -> Vec<SealedMetadataV1> {
    records
        .iter()
        .map(|record| SealedMetadataV1 {
            envelope: record.envelope.clone(),
            address: record.address,
            commitment: record.commitment,
        })
        .collect()
}

/// The commit publishes every ARD1 under the generation's catalogue owner,
/// bound to the Timeline (G7), advances the inventory generation once (G5),
/// installs the successor CSI1 with the burned ordinal and the new row
/// (item 5), and retains both closed keys (items 3 and 4), every sealed
/// record and every COA1.
#[test]
fn the_commit_publishes_and_retains_the_whole_initialization() -> TestResult {
    let roster = Roster::release_one()?;
    let mut case = Case::new(&roster, true)?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), case.domain.world.catalogue)?;
    let receipt = case.initialize(&profile, OPERATION)??;
    assert_eq!(receipt.generation(), GENERATION);
    let (_, administrative) = case
        .domain
        .world
        .call_and_admit(request(&profile, OPERATION)?, DATA_LEAF)?;
    let domain = &case.domain.world.domain;
    assert_eq!(domain.inventory_generation, 1);
    assert_eq!(domain.native_producer_ordinal, 1);
    // ADR-129 revision 13, R13.1(5): the context holds F_q = 8n for its
    // two members.
    let context = domain.erasure_contexts.get(&target()).copied();
    assert_eq!(
        context.map(|context| (context.members, context.active_pairs)),
        Some((2, 0))
    );
    assert_eq!(context.map(CommunityErasureContextV1::reserve), Some(16));
    // R13.1(2): the batch's ten community rows, two targets each, are
    // counted in the publishing commit.
    assert_eq!(domain.store.erasure_counts_for_test(target()), (10, 20));

    let owner = community_catalogue_owner_v1(target(), GENERATION)?;
    let published = domain
        .store
        .artifact_registrations_for_timeline(target(), 64)?;
    assert_eq!(published.len(), 10);
    for row in &published {
        assert_eq!(row.owner_id(), &owner);
        assert!(domain
            .store
            .read_artifact_registration(&owner, row.registration_address())?
            .is_some());
    }

    let committed = domain
        .initializations
        .get(&(target(), OPERATION))
        .ok_or("the initialization must be retained")?;
    // Two CMB1s, COB1, CGI1, CSB1, CBQ1, CPV1, CAU1, ten CMI1s, two CMS1s,
    // CST1, CSH1, CGR1, two CCI1s and the CGA1.
    assert_eq!(committed.records.len(), 26);
    assert_eq!(committed.admissions.len(), 10);
    for admission in &committed.admissions {
        assert!(published
            .iter()
            .any(|row| row.registration_address() == admission.as_input().registration_address));
        assert_eq!(admission.as_input().admission_inventory_generation, 0);
    }
    assert_eq!(committed.leaf_grant_id, DATA_LEAF);
    assert_eq!(committed.profile_digest, profile.digest());

    let (selection_key, sealed) = domain.selection.as_ref().ok_or("a successor CSI1")?;
    assert_eq!(*selection_key, committed.metadata_key);
    let metadata_key = domain.keys.get(selection_key).ok_or("the metadata key")?;
    let plaintext = metadata_key.open(sealed)?;
    let selection = CommunitySelectionV1::from_canonical_cbor(&plaintext)?;
    let fields = selection.as_input();
    assert_eq!(fields.store_incarnation, INCARNATION);
    assert_eq!(fields.highest_native_producer_ordinal, 1);
    assert_eq!(fields.installed_catalogue_digest, INSTALLED_CATALOGUE);
    assert_eq!(fields.native_profile_digest, NATIVE_PROFILE);
    assert_eq!(fields.metadata_not_after_micros, HORIZON);
    let floors = fields
        .timeline_floors
        .iter()
        .collect::<Result<Vec<_>, Error>>()?;
    assert_eq!(floors.len(), 1);
    assert_eq!(floors[0].timeline, target());
    assert_eq!(floors[0].active_generation, Some(GENERATION));
    assert_eq!(floors[0].highest_pass_ordinal, 0);
    assert!(floors[0].closed_generations.is_empty());
    assert!(!floors[0].closed);
    assert!(floors[0]
        .selected_head
        .is_some_and(|head| head != Hash::zero()));

    let intent = metadata_key.intent().as_input();
    assert!(intent.parent_operation == CommunityArtifactOperationV1::Initialization(OPERATION));
    assert!(intent.purpose == CommunityArtifactPurposeV1::LifecycleControl);
    assert_eq!((intent.timeline, intent.generation), (target(), GENERATION));
    assert_eq!(intent.evidence_not_after_micros, HORIZON);
    assert_eq!(domain.keys.len(), 3);
    let cohort = domain
        .keys
        .values()
        .map(|key| key.intent().as_input())
        .find(|intent| intent.purpose == CommunityArtifactPurposeV1::ExecutionState)
        .ok_or("the cohort key")?;
    assert_eq!(
        cohort.authority_request_digest,
        administrative.decision().request_digest()
    );
    assert_ne!(
        intent.authority_request_digest,
        cohort.authority_request_digest
    );
    assert_eq!(domain.store.logical_head(target())?, pos_core::Seq::ZERO);
    Ok(())
}

/// ADR-129 revision 10, R10.3(6) and I90, with the byte counter limited to
/// what the store reports (revision 14 erratum candidate: the store counts
/// no history bytes): the CBQ1 `prior_shared_counts` and the seeded
/// counters carry T's recorded-set nodes, edges and declared inputs, and the
/// initialization adds its own two CPN1 nodes and edges per member. The
/// selected graph is the CGR1's, and the key reads count the three retained
/// keys. Only the three seedable counters are asserted exactly.
#[test]
fn the_history_seeds_the_quote_and_the_pass_state() -> TestResult {
    let roster = Roster::release_one()?;
    let mut case = Case::new(&roster, true)?;
    case.domain.world.domain.store.fill_factual_set_for_test(
        target(),
        RecordedSetCountsV1 {
            nodes: 7,
            edges: 5,
            inputs: 3,
        },
    );
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), case.domain.world.catalogue)?;
    case.initialize(&profile, OPERATION)??;
    let domain = &case.domain.world.domain;
    let committed = domain
        .initializations
        .get(&(target(), OPERATION))
        .ok_or("the initialization must be retained")?;
    let key = domain
        .keys
        .get(&committed.metadata_key)
        .ok_or("the metadata key")?;
    // After the two CMB1s, COB1, CGI1 and CSB1 comes the CBQ1.
    let quote = CommunityBudgetQuoteV1::from_canonical_cbor(&key.open(&committed.records[5])?)?;
    let prior = quote.as_input().prior_shared_counts;
    assert_eq!((prior.nodes, prior.edges, prior.declared_inputs), (7, 5, 3));
    let state = domain
        .pass_states
        .get(&target())
        .ok_or("the pass state must be retained")?;
    let counters = state.counters;
    assert_eq!(
        (counters.nodes, counters.edges, counters.declared_inputs),
        (11, 9, 3)
    );
    // The graph's own additions agree with the CBQ1's `2n` maxima.
    let maxima = quote.as_input();
    assert_eq!(counters.nodes - prior.nodes, maxima.maximum_required_nodes);
    assert_eq!(counters.edges - prior.edges, maxima.maximum_required_edges);
    // The history reports no bytes, so the counter is the initialization's
    // own: the ten CMI1s (after the two CMB1s, COB1, CGI1, CSB1, CBQ1, CPV1
    // and CAU1) name each record's plaintext length.
    let mut total = 0;
    for sealed in &committed.records[8..18] {
        let plaintext = key.open(sealed)?;
        total += CommunityMaterializationV1::from_canonical_cbor(&plaintext)?
            .as_input()
            .plaintext_length;
    }
    assert!(total > 0);
    assert_eq!(counters.encoded_record_bytes, total);
    assert_eq!(state.graph.registrations, 10);
    assert_eq!(domain.live_keys(), 3);
    Ok(())
}

/// G5: the writer compares the inventory generation CAU1 read and the CSI1
/// the operation read; either having moved refuses with no effect.
#[test]
fn the_writer_compares_and_swaps_the_inventory_and_selection() -> TestResult {
    let roster = Roster::release_one()?;
    let mut case = Case::new(&roster, true)?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), case.domain.world.catalogue)?;
    let first = staged(case.prepare(&profile, OPERATION)?)?;
    let second = staged(case.prepare(&profile, [0x12; 16])?)?;
    let domain = &mut case.domain.world.domain;
    domain.inventory_generation = 1;
    assert_eq!(
        domain.commit(*first).err(),
        Some(Error::EvidenceUnavailable)
    );
    domain.inventory_generation = 0;
    let third = staged(case.prepare(&profile, [0x13; 16])?)?;
    let domain = &mut case.domain.world.domain;
    domain.selection = Some(([0x44; 16], second.selection));
    assert_eq!(
        domain.commit(*third).err(),
        Some(Error::EvidenceUnavailable)
    );
    assert!(domain.initializations.is_empty());
    assert!(domain
        .store
        .artifact_registrations_for_timeline(target(), 64)?
        .is_empty());
    Ok(())
}

/// G7: a batch whose rows are already catalogued, by registration address
/// or by artifact identity, is a `Conflict` that leaves the domain's
/// inventory unchanged.
#[test]
fn a_catalogued_row_refuses_the_commit() -> TestResult {
    let roster = Roster::release_one()?;
    let mut case = Case::new(&roster, true)?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), case.domain.world.catalogue)?;
    let first = staged(case.prepare(&profile, OPERATION)?)?;
    let domain = &mut case.domain.world.domain;
    domain.store.commit_community_artifact_batch(&first.batch)?;
    assert_eq!(
        domain
            .store
            .commit_community_artifact_batch(&first.batch)
            .err(),
        Some(Error::Conflict)
    );
    // A catalogued artifact identity refuses on its own, even when its
    // registration address is not catalogued.
    domain.store.forget_artifact_registration_addresses();
    assert_eq!(
        domain
            .store
            .commit_community_artifact_batch(&first.batch)
            .err(),
        Some(Error::Conflict)
    );
    assert_eq!(domain.commit(*first).err(), Some(Error::Conflict));
    assert_eq!(domain.inventory_generation, 0);
    assert!(domain.selection.is_none());
    assert!(domain.initializations.is_empty());
    Ok(())
}

/// Item 5: an allocation burns its ordinal even when the operation is then
/// refused, and an exhausted allocator refuses.
#[test]
fn the_producer_ordinal_is_burned_on_failure() -> TestResult {
    let roster = Roster::release_one()?;
    let mut case = Case::new(&roster, false)?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), case.domain.world.catalogue)?;
    for burned in 1..=2 {
        assert_eq!(
            case.prepare(&profile, OPERATION)?.err(),
            Some(Error::AdmissionDenied)
        );
        assert_eq!(case.domain.world.domain.native_producer_ordinal, burned);
    }
    case.domain.world.domain.native_producer_ordinal = u64::MAX;
    assert_eq!(
        case.prepare(&profile, OPERATION)?.err(),
        Some(Error::CapacityExhausted)
    );
    Ok(())
}

/// A5.3(5)–(6) and item 6: a retry compares the original principal through
/// the retained leaf grant and resolves the retained CGA1 and every COA1's
/// ARD1; any of them missing or other is refused, and restoring them
/// resolves the original receipt again.
#[test]
fn a_retry_checks_the_retained_principal_and_evidence() -> TestResult {
    let roster = Roster::release_one()?;
    let mut case = Case::new(&roster, true)?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), case.domain.world.catalogue)?;
    let receipt = case.initialize(&profile, OPERATION)??;
    let tampers: [(Tamper, Error); 5] = [
        (
            |original| original.leaf_grant_id = METADATA_LEAF,
            Error::Conflict,
        ),
        (
            |original| {
                original.initial_source =
                    CommunityInitializationSourceV1::Initializer(ArtifactRefV1 {
                        schema_id: 0x4341_0004,
                        byte_length: 1,
                        digest: [9; 32],
                    });
            },
            Error::Conflict,
        ),
        (
            |original| original.leaf_grant_id = Hash::from_bytes([0x77; 32]),
            Error::EvidenceUnavailable,
        ),
        (
            |original| {
                let last = original.records.len() - 1;
                original.records.swap(0, last);
            },
            Error::EvidenceUnavailable,
        ),
        (
            |original| original.records.clear(),
            Error::EvidenceUnavailable,
        ),
    ];
    for (tamper, expected) in tampers {
        let original = case.retained()?;
        let records = copy(&original.records);
        let leaf = original.leaf_grant_id;
        let source = original.initial_source;
        tamper(original);
        assert_eq!(case.initialize(&profile, OPERATION)?.err(), Some(expected));
        let original = case.retained()?;
        original.records = records;
        original.leaf_grant_id = leaf;
        original.initial_source = source;
    }
    let original = case.retained()?;
    let admission = original.admissions.remove(0);
    original.admissions.insert(
        0,
        CommunityArtifactAdmissionV1::new(CommunityArtifactAdmissionInputV1 {
            registration_address: Hash::from_bytes([0x78; 32]),
            ..*admission.as_input()
        })?,
    );
    assert_eq!(
        case.initialize(&profile, OPERATION)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    case.retained()?.admissions[0] = admission;
    assert_eq!(case.initialize(&profile, OPERATION)??, receipt);

    // Review L2 on #1301: one unresolved ARD1 among the ten is enough,
    // wherever it sits, while every other still resolves.
    let count = case.retained()?.admissions.len();
    for index in [1, count / 2, count - 1] {
        let original = case.retained()?;
        let input = *original.admissions[index].as_input();
        let admission = std::mem::replace(
            &mut original.admissions[index],
            CommunityArtifactAdmissionV1::new(CommunityArtifactAdmissionInputV1 {
                registration_address: Hash::from_bytes([0x79; 32]),
                ..input
            })?,
        );
        assert_eq!(
            case.initialize(&profile, OPERATION)?.err(),
            Some(Error::EvidenceUnavailable)
        );
        case.retained()?.admissions[index] = admission;
    }
    assert_eq!(case.initialize(&profile, OPERATION)??, receipt);

    // The current CSI1 is sealed by the metadata key, so without it nothing
    // can be read.
    let metadata_key = case.retained()?.metadata_key;
    case.domain.world.domain.keys.remove(&metadata_key);
    assert_eq!(
        case.initialize(&profile, OPERATION)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// A5.4: the final writer is the call's own authority's, on the domain it
/// was installed for; another authority's or another domain's writer check
/// refuses the call.
#[test]
fn only_the_installed_authority_and_domain_check_the_writer_bound() -> TestResult {
    let roster = Roster::release_one()?;
    let mut case = Case::new(&roster, true)?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), case.domain.world.catalogue)?;
    let (store, _harness) = trusted_store(true)?;
    let mut other = World::new(
        &SEAL,
        store,
        TRUST_SCOPE,
        MemoryTrustedClockAuthorityV1::new(),
    )?;
    assert_ne!(other.catalogue, case.domain.world.catalogue);
    let mut foreign = MemoryCommunityDomainV1::new(
        MemoryStore::new(),
        [0x5b; 16],
        MemoryTrustedClockAuthorityV1::new(),
    )?;
    for (index, operation) in [[0x21; 16], [0x22; 16]].into_iter().enumerate() {
        let call = match case.prepare(&profile, operation)?? {
            PreparedV1::Staged(_, call) => call,
            PreparedV1::Original(_) => return Err("a new initialization must stage".into()),
        };
        let refused = if index == 0 {
            other
                .authority
                .check_writer_bound(call, &mut case.domain.world.domain)
        } else {
            case.domain
                .world
                .authority
                .check_writer_bound(call, &mut foreign)
        };
        assert_eq!(refused.err(), Some(Error::EvidenceUnavailable));
    }
    Ok(())
}

/// The owner of the planned Timeline in the budget cases.
fn owner() -> EntityId {
    EntityId::from_ulid(ulid::Ulid::from_bytes([0x77; 16]))
}

impl Case {
    /// A case whose planned Timeline has an owner, so the erasure budget
    /// has an actor to bound it.
    fn owned(roster: &Roster) -> Fallible<Self> {
        let mut case = Self {
            domain: Bootstrapped::new(&SEAL, roster, true, false)?,
            state: roster.state.clone(),
        };
        case.domain
            .world
            .domain
            .store
            .create_timeline_with_meta(TimelineMeta {
                id: target(),
                owner: Some(owner()),
                ..TimelineMeta::root("owned")
            })?;
        Ok(case)
    }
}

/// ADR-129 revision 13, R13.1(3) and revision 14, RN.3, for `initialize`:
/// the context adds `5n` rows and `F_q`'s `4n` rows to T's `rows(T)`. The
/// two members of the fixture add 18: T at 4,096 - 18 consented rows
/// initializes, one more row refuses with 14 and nothing is staged.
#[test]
fn initialize_checks_the_rows_bound_with_its_quarantine_rows() -> TestResult {
    for (rows, allowed) in [(4096 - 18, true), (4096 - 17, false)] {
        let roster = Roster::release_one()?;
        let mut case = Case::owned(&roster)?;
        let consented = (0..rows)
            .map(|seed| erasure_row("budget", ArtifactDataClassV1::ConsentedSharedData, 0, seed))
            .collect::<Fallible<Vec<_>>>()?;
        case.domain
            .world
            .domain
            .store
            .bind_erasure_rows_for_test(target(), consented);
        let rows = roster.rows()?;
        let profile = profile_until(&rows, HORIZON, hash(1), case.domain.world.catalogue)?;
        let result = case.prepare(&profile, OPERATION)?;
        assert_eq!(result.is_ok(), allowed);
        if !allowed {
            assert_eq!(result.err(), Some(Error::CapacityExhausted));
        }
    }
    Ok(())
}

/// R13.1(3): the targets line holds the actor's targets, its pending
/// reservations, the existing contexts' `F_q`, the `5n` rows at two targets
/// each and the new context's `8n` targets: 20 + 16 more for two members.
/// One existing one-member context holds 8 more targets.
#[test]
fn initialize_checks_the_targets_line_with_its_quarantine_targets() -> TestResult {
    let line = COMMUNITY_ERASURE_TARGET_LINE_V1;
    for (pending, allowed) in [(0, true), (1, false)] {
        let roster = Roster::release_one()?;
        let mut case = Case::owned(&roster)?;
        let domain = &mut case.domain.world.domain;
        domain.count_erasure_context(target(), 1);
        let base = domain.erasure_budget(target())?.actors[0].targets;
        // Community rows cost two targets each.
        let filled = (line - 36 - 8 - base) / 2;
        domain
            .store
            .bind_erasure_rows_for_test(target(), community_rows(1_000, filled)?);
        let slack = line - 36 - 8 - base - 2 * filled;
        // A pending reservation holds the rest, and one target more.
        domain.pending_reservations.insert(
            (target(), [9; 16]),
            CommunityPendingReservationV1 {
                targets: slack + pending,
                rows: 0,
            },
        );
        let rows = roster.rows()?;
        let profile = profile_until(&rows, HORIZON, hash(1), case.domain.world.catalogue)?;
        let result = case.prepare(&profile, OPERATION)?;
        assert_eq!(result.is_ok(), allowed);
        if !allowed {
            assert_eq!(result.err(), Some(Error::CapacityExhausted));
        }
    }
    Ok(())
}

/// R13.1(3): the check holds for every actor of the scope, each with its own
/// pending reservations. A Fork child's scope holds its owner and its
/// parent's: only the child's owner, who also owns an unrelated Timeline, is
/// at the line, either through that Timeline's rows or through a pending
/// reservation on it.
#[test]
fn the_budget_check_holds_for_every_actor_of_the_scope() -> TestResult {
    let line = COMMUNITY_ERASURE_TARGET_LINE_V1;
    let child = TimelineId::from_ulid(ulid::Ulid::from_bytes([0x78; 16]));
    let unrelated = TimelineId::from_ulid(ulid::Ulid::from_bytes([0x79; 16]));
    let second = EntityId::from_ulid(ulid::Ulid::from_bytes([0x7a; 16]));
    for (pending, allowed, via_rows) in [
        (0, true, true),
        (1, false, true),
        (0, true, false),
        (1, false, false),
    ] {
        let roster = Roster::release_one()?;
        let mut case = Case::owned(&roster)?;
        let domain = &mut case.domain.world.domain;
        for (id, owner, fork_point) in [
            (child, second, Some((target(), Seq::ZERO))),
            (unrelated, second, None),
        ] {
            domain.store.create_timeline_with_meta(TimelineMeta {
                id,
                owner: Some(owner),
                fork_point,
                ..TimelineMeta::root("scoped")
            })?;
        }
        let scope = domain.erasure_budget(child)?;
        let base = scope
            .actors
            .iter()
            .find(|actor| actor.actor == second)
            .map(|actor| actor.targets)
            .ok_or("the child's owner is in its scope")?;
        assert_eq!(scope.actors.len(), 2);
        let room = line - 36 - base;
        let (filled, held) = if via_rows { (room / 2, 0) } else { (0, room) };
        domain
            .store
            .bind_erasure_rows_for_test(unrelated, community_rows(2_000, filled)?);
        let slack = if via_rows { room % 2 } else { held };
        domain.pending_reservations.insert(
            (unrelated, [9; 16]),
            CommunityPendingReservationV1 {
                targets: slack + pending,
                rows: 0,
            },
        );
        assert_eq!(
            domain.check_initialize_budget(child, 2).is_ok(),
            allowed,
            "{via_rows}/{pending}"
        );
    }
    Ok(())
}

/// R13.1(3): every `rows(U)` of the scope counts, not only T's: a Fork
/// child holding 4,096 rows, with its context's `F_q` rows or a pending
/// reservation, refuses the parent's initialize.
#[test]
fn initialize_checks_every_affected_timeline() -> TestResult {
    let child = TimelineId::from_ulid(ulid::Ulid::from_bytes([0x78; 16]));
    for (held, pending, allowed) in [(0, 0, true), (1, 0, false), (0, 1, false)] {
        let roster = Roster::release_one()?;
        let mut case = Case::owned(&roster)?;
        let domain = &mut case.domain.world.domain;
        domain.store.create_timeline_with_meta(TimelineMeta {
            id: child,
            owner: Some(owner()),
            fork_point: Some((target(), Seq::ZERO)),
            ..TimelineMeta::root("child")
        })?;
        // One member's context on the child holds four rows.
        domain.count_erasure_context(child, 1);
        let free = 4096 - 4 + held;
        let rows = (0..free)
            .map(|seed| erasure_row("budget", ArtifactDataClassV1::ConsentedSharedData, 0, seed))
            .collect::<Fallible<Vec<_>>>()?;
        domain.store.bind_erasure_rows_for_test(child, rows);
        if pending > 0 {
            domain.pending_reservations.insert(
                (child, [9; 16]),
                CommunityPendingReservationV1 {
                    targets: 0,
                    rows: 1,
                },
            );
        }
        let rows = roster.rows()?;
        let profile = profile_until(&rows, HORIZON, hash(1), case.domain.world.catalogue)?;
        let result = case.prepare(&profile, OPERATION)?;
        assert_eq!(result.is_ok(), allowed);
    }
    Ok(())
}

/// R10.3(6): the store counts a Fork child's own set only, so the history
/// seed of a Fork child would undercount its inherited prefix. A Fork child
/// is refused until the Fork slice reads that prefix; a root Timeline and a
/// missing one keep their results.
#[test]
fn a_fork_child_has_no_history_seed_yet() -> TestResult {
    let roster = Roster::release_one()?;
    let mut case = Case::owned(&roster)?;
    let child = TimelineId::from_ulid(ulid::Ulid::from_bytes([0x78; 16]));
    let domain = &mut case.domain.world.domain;
    domain.store.create_timeline_with_meta(TimelineMeta {
        id: child,
        owner: Some(owner()),
        fork_point: Some((target(), Seq::ZERO)),
        ..TimelineMeta::root("child")
    })?;
    assert_eq!(
        domain.history_counts(child).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        domain
            .history_counts(TimelineId::from_ulid(ulid::Ulid::from_bytes([0x79; 16])))
            .err(),
        Some(Error::EvidenceUnavailable)
    );
    assert!(domain.history_counts(target()).is_ok());
    // A store that refuses the read is unavailable evidence.
    let store = std::mem::replace(&mut domain.store, MemoryStore::new());
    domain.store = store.without_erasure_gate();
    assert_eq!(
        domain.history_counts(target()).err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// A Timeline initializes once: a pass state already retained for it is
/// never overwritten, and the refused commit publishes nothing.
#[test]
fn a_second_pass_state_never_replaces_the_first() -> TestResult {
    let roster = Roster::release_one()?;
    let mut case = Case::new(&roster, true)?;
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), case.domain.world.catalogue)?;
    let staged = staged(case.prepare(&profile, OPERATION)?)?;
    let domain = &mut case.domain.world.domain;
    domain.pass_states.insert(
        target(),
        CommunityPassStateV1 {
            counters: CommunitySharedCountsV1::default(),
            graph: staged.pass_state.graph,
            closure: BTreeSet::new(),
            observations: BTreeMap::new(),
            scope_rows: BTreeMap::new(),
            generations: BTreeMap::new(),
        },
    );
    assert_eq!(domain.commit(*staged).err(), Some(Error::Conflict));
    assert!(domain.initializations.is_empty());
    assert!(domain
        .store
        .artifact_registrations_for_timeline(target(), 64)?
        .is_empty());
    Ok(())
}
