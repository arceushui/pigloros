//! The Reserve's record publication: its two keys, its sealed records, the
//! successor CSI1 and the writer compares, over a real initialized domain.

use pos_core::community_lifecycle::{
    community_prepared_input_set_digest_v1, CommunityArtifactKindV1, CommunityArtifactOperationV1,
    CommunityArtifactPurposeV1, CommunityCopyHolderV1, CommunityCopyInventoryV1,
    CommunityCopyStateV1, CommunityDurableProfileV1, CommunityLifecycleErrorV1 as Error,
    CommunityMemberSlotsV1, CommunityMetadataEnvelopeV1, CommunityMetadataPolicyV1,
    CommunityMetadataSchemaV1, CommunityNativeNodeReferenceV1, CommunityPassKeyV1,
    CommunityProfileMemberV1, CommunityProfileRetentionV1, CommunityRecordKindsV1,
    CommunityReservationRequestInputV1, CommunityReservationRequestV1, CommunityReservationV1,
};
use pos_core::store::EventStore;
use pos_core::{AuthorityTrustRootSealV1, Hash};
use zeroize::Zeroizing;

use super::super::pass_install::{CommunityHorizonPolicyV1, CommunityOwnerHorizonsV1};
use super::super::pass_record::{CommunityPassMemberDigestsV1, CommunityPassStatusV1};
use super::super::pass_state::CommunityRetainedObservationV1;
use super::super::pass_writer::{
    community_reserve_selection_v1, CommunityObservationCutV1, CommunityReserveInputV1,
    CommunityReservePassFactsV1, CommunityStagedReserveV1,
};
use super::super::private_hash::scope_set_digest;
use super::super::sealer::SealedMetadataV1;
use super::super::vault::VaultKeyV1;
use super::{CommunityQuarantineContextV1, CommunityReservePublicationV1, MemoryCommunityDomainV1};
use crate::community::community_roster_quarantine_keys_v1;
use crate::community::CommunityDomainBindingV1;
use crate::community_initialization_fixture::{
    hash, initial_head, initialize_target, profile_until, target, Bootstrapped, Fallible, Roster,
    HORIZON, INSTALLED_CATALOGUE, NATIVE_PROFILE,
};

/// The trust-root seal of the test composition.
const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();

type TestResult = Fallible<()>;

/// The reservation identity of the first Reserve.
const OPERATION: [u8; 16] = [0x30; 16];
/// The reservation identity of the second Reserve.
const SECOND: [u8; 16] = [0x31; 16];
/// `t_r`.
const SAMPLE: u64 = 1_000;
/// The pass metadata key's protection ID.
const METADATA: [u8; 16] = [0x61; 16];
/// The failure cohort key's protection ID.
const FAILURE: [u8; 16] = [0x62; 16];
/// The Reserve's metadata `write` request digest.
const WRITE: Hash = hash(0x55);
/// `authority_request_digest` of the pass CRI1.
const AUTHORITY: Hash = hash(88);

/// An initialized domain with the Reserve's installed horizons and one
/// observation to reuse.
struct Case<'a> {
    domain: Bootstrapped,
    profile: CommunityDurableProfileV1<'a>,
    policy: CommunityMetadataPolicyV1,
    head: Hash,
}

/// A bootstrapped domain and the CDP1 over `rows` on its catalogue.
fn bootstrapped<'a>(
    roster: &Roster,
    rows: &'a [CommunityProfileMemberV1<'a>],
) -> Fallible<(Bootstrapped, CommunityDurableProfileV1<'a>)> {
    let domain = Bootstrapped::new(&SEAL, roster, true, true)?;
    let profile = profile_until(rows, HORIZON, hash(1), domain.world.catalogue)?;
    Ok((domain, profile))
}

/// Initialize [`target`] under `profile`; its committed head.
fn initialized(
    domain: &mut Bootstrapped,
    roster: &Roster,
    profile: &CommunityDurableProfileV1<'_>,
) -> Fallible<Hash> {
    let receipt = initialize_target(&SEAL, domain, roster, profile)??;
    initial_head(&receipt)
}

impl<'a> Case<'a> {
    fn new(roster: &Roster, rows: &'a [CommunityProfileMemberV1<'a>]) -> Fallible<Self> {
        let (mut domain, profile) = bootstrapped(roster, rows)?;
        let head = initialized(&mut domain, roster, &profile)?;
        let policy = CommunityMetadataPolicyV1::new(*domain.policy.as_input())?;
        let mut case = Self {
            domain,
            profile,
            policy,
            head,
        };
        case.install(29_000_000, HORIZON);
        case.retain_observation()?;
        Ok(case)
    }

    /// Install horizons with the failure horizon `quarantine` and the owner
    /// evidence horizon `evidence`, so `H_g` is the earlier of `evidence`
    /// and [`HORIZON`].
    fn install(&mut self, quarantine: u64, evidence: u64) {
        self.domain.world.domain.pass_horizons = Some(CommunityHorizonPolicyV1 {
            retention: CommunityProfileRetentionV1 {
                generation_not_after_micros: HORIZON,
                recovery_window_micros: 1_000,
                quarantine_not_after_micros: quarantine,
                metadata_not_after_micros: HORIZON,
                recording_not_after_micros: HORIZON,
            },
            owners: CommunityOwnerHorizonsV1 {
                recording_micros: HORIZON,
                metadata_micros: HORIZON,
                evidence_micros: evidence,
            },
            profile_digest: self.profile.digest(),
            roster_len: 2,
        });
    }

    /// An observation of T's whole history, retained to reuse.
    fn retain_observation(&mut self) -> TestResult {
        let domain = &mut self.domain.world.domain;
        let head = domain.store.logical_head(target())?;
        let chain = domain.store.chain_hash_at(target(), head)?;
        let state = domain.pass_states.get_mut(&target()).ok_or("state")?;
        state.retained.insert(
            reference(),
            CommunityRetainedObservationV1 {
                generation: state.generation,
                not_after_micros: HORIZON,
                cut: CommunityObservationCutV1 {
                    through_seq: head.as_u64(),
                    chain_heads: vec![(target(), head.as_u64(), chain)],
                },
            },
        );
        Ok(())
    }

    /// A Reserve of two due members, reusing the retained observation.
    fn input(&self, operation: [u8; 16]) -> Fallible<CommunityReserveInputV1> {
        let state = self
            .domain
            .world
            .domain
            .pass_states
            .get(&target())
            .ok_or("state")?;
        let members = vec![member(0, 100), member(1, 101)];
        let pairs: Vec<(Hash, Hash)> = members
            .iter()
            .map(|member| (member.cmb1_digest, member.cin1_digest))
            .collect();
        Ok(CommunityReserveInputV1 {
            timeline: target(),
            generation: state.generation,
            reservation_operation_id: operation,
            selected_head: self.head,
            prior_shared_counts: state.counters,
            roster_quarantine_keys: community_roster_quarantine_keys_v1(&self.profile, target())?,
            reservation_sample_micros: SAMPLE,
            pass_rows: 12,
            failure_reserve: 6,
            minted: None,
            reused: Some(reference()),
            request: CommunityReservationRequestInputV1 {
                timeline: target(),
                generation: state.generation,
                reservation_operation_id: operation,
                expected_head_digest: self.head,
                prepared_input_set_digest: community_prepared_input_set_digest_v1(&pairs)?,
                roster_digest: hash(81),
                profile_digest: self.profile.digest(),
                authority_request_digest: AUTHORITY,
                source_closure_digest: hash(89),
                requested_evidence_horizon: 1_001,
            },
            pass: CommunityReservePassFactsV1 {
                cbq1_digest: hash(84),
                quote_maxima: [1, 2, 3],
                trace_rows: 3,
                members,
                metadata_key: METADATA,
                failure_cohort_key: FAILURE,
                scope_set_digest: hash(90),
            },
        })
    }

    fn stage(&self, operation: [u8; 16]) -> Fallible<CommunityStagedReserveV1> {
        Ok(self
            .domain
            .world
            .domain
            .stage_reserve(self.input(operation)?)?)
    }
}

fn member(roster_index: usize, cmb1: u8) -> CommunityPassMemberDigestsV1 {
    CommunityPassMemberDigestsV1 {
        roster_index,
        cmb1_digest: hash(cmb1),
        cin1_digest: hash(86),
        trust_policy_snapshot_digest: hash(87),
    }
}

fn reference() -> CommunityNativeNodeReferenceV1 {
    CommunityNativeNodeReferenceV1 {
        store_incarnation: [0x5a; 16],
        producer_ordinal: 3,
        node_ordinal: 1,
        node_digest: hash(9),
    }
}

fn publication<'a>(
    profile: &'a CommunityDurableProfileV1<'a>,
    policy: &'a CommunityMetadataPolicyV1,
) -> CommunityReservePublicationV1<'a> {
    CommunityReservePublicationV1 {
        context: CommunityQuarantineContextV1 {
            profile,
            binding: CommunityDomainBindingV1 {
                metadata_policy: policy,
                installed_catalogue_digest: INSTALLED_CATALOGUE,
                native_profile_digest: NATIVE_PROFILE,
            },
        },
        metadata_request_digest: WRITE,
    }
}

/// Flip one bit of the sealed record `index` of the Reserve of
/// [`OPERATION`].
fn flip(domain: &mut MemoryCommunityDomainV1, index: usize) -> TestResult {
    let sealed = domain
        .reserve_publications
        .get_mut(&(target(), OPERATION))
        .ok_or("publication")?
        .records
        .get_mut(index)
        .ok_or("record")?;
    *sealed.envelope.first_mut().ok_or("envelope")? ^= 1;
    Ok(())
}

/// What a refused publication must leave alone.
fn snapshot(
    domain: &MemoryCommunityDomainV1,
) -> (usize, u64, Option<Hash>, usize, usize, usize, u64) {
    (
        domain.keys.len(),
        domain.inventory_generation,
        domain.selection.as_ref().map(|(_, sealed)| sealed.address),
        domain.pass_records.len(),
        domain.pending_reservations.len(),
        domain.reserve_publications.len(),
        domain.native_producer_ordinal,
    )
}

/// The two keys' intents: the metadata key has parent CPK1, no slots, the
/// metadata horizon and the Reserve's metadata `write` request digest; the
/// failure cohort key has the pass scope set, the due members' slots and the
/// CRI1's request digest, and also allows kind 8 for its CAR1 proofs.
fn check_key_intents(
    vault: &VaultKeyV1,
    failure: &VaultKeyV1,
    pass_key: CommunityPassKeyV1,
    generation: [u8; 16],
) -> TestResult {
    let metadata = vault.intent().as_input();
    assert!(
        metadata.allowed_record_kinds
            == CommunityRecordKindsV1::empty().with(CommunityArtifactKindV1::LifecycleControl)
    );
    assert!(metadata.parent_operation == CommunityArtifactOperationV1::Pass(pass_key));
    assert!(metadata.purpose == CommunityArtifactPurposeV1::LifecycleControl);
    assert!(metadata.member_slots == CommunityMemberSlotsV1::empty());
    assert_eq!(metadata.scope_set_digest, scope_set_digest(&[0x80]));
    assert_eq!(metadata.evidence_not_after_micros, HORIZON);
    assert_eq!(metadata.authority_request_digest, WRITE);
    assert_eq!(
        (metadata.timeline, metadata.generation),
        (target(), generation)
    );

    let cohort = failure.intent().as_input();
    assert!(cohort.parent_operation == CommunityArtifactOperationV1::Pass(pass_key));
    assert!(cohort.purpose == CommunityArtifactPurposeV1::LifecycleControl);
    assert!(cohort.member_slots == CommunityMemberSlotsV1::new(&[0, 1])?);
    assert_eq!(cohort.scope_set_digest, hash(90));
    assert_eq!(cohort.authority_request_digest, AUTHORITY);
    assert_eq!((cohort.timeline, cohort.generation), (target(), generation));
    assert!(
        cohort.allowed_record_kinds
            == CommunityRecordKindsV1::empty()
                .with(CommunityArtifactKindV1::LifecycleControl)
                .with(CommunityArtifactKindV1::ClassificationProof)
    );
    Ok(())
}

/// The Reserve publishes its keys, its CRI1, CPR1 and CCI1s, the successor
/// CSI1 and its pass state in one commit, and advances the inventory
/// generation once.
#[test]
fn a_reserve_publishes_its_keys_records_selection_and_state() -> TestResult {
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    let mut case = Case::new(&roster, &rows)?;
    let staged = case.stage(OPERATION)?;
    let (native, pass) = (staged.native_ordinal, staged.pass_ordinal);
    let reservation = CommunityReservationV1::new(staged.record.reserved.reservation)?;
    let request = CommunityReservationRequestV1::new(staged.request)?;
    let before = snapshot(&case.domain.world.domain);
    let publication = publication(&case.profile, &case.policy);
    let (anchor, old, _) = case
        .domain
        .world
        .domain
        .read_selection(publication.context)?;
    let generation = case
        .domain
        .world
        .domain
        .pass_states
        .get(&target())
        .ok_or("state")?
        .generation;
    let successor = community_reserve_selection_v1(&old, target(), generation, native, pass)?;
    case.domain
        .world
        .domain
        .publish_reserved_pass(&SEAL, staged, publication)?;
    let domain = &case.domain.world.domain;
    assert_eq!(domain.inventory_generation, before.1 + 1);
    assert_eq!(domain.keys.len(), before.0 + 2);
    assert_eq!(domain.pass_records.len(), before.3 + 1);
    assert_eq!(domain.pending_reservations.len(), before.4 + 1);
    assert_eq!(domain.native_producer_ordinal, native);

    // The selection is the successor, sealed under the pass metadata key.
    let (_, current, address) = domain.read_selection(publication.context)?;
    assert_eq!(current.as_slice(), successor.as_slice());
    let (selected_by, sealed) = domain.selection.as_ref().ok_or("selection")?;
    assert_eq!(*selected_by, METADATA);
    assert_eq!(sealed.address, address);

    // The four records open under the metadata key, in order.
    let committed = domain
        .reserve_publications
        .get(&(target(), OPERATION))
        .ok_or("publication")?;
    assert_eq!(committed.metadata_key, METADATA);
    assert_eq!(committed.records.len(), 4);
    let vault = domain.keys.get(&METADATA).ok_or("metadata key")?;
    let open = |index: usize| -> Fallible<Zeroizing<Vec<u8>>> {
        Ok(vault.open(committed.records.get(index).ok_or("record")?)?)
    };
    assert_eq!(open(0)?.as_slice(), request.to_canonical_cbor().as_slice());
    assert_eq!(
        open(1)?.as_slice(),
        reservation.to_canonical_cbor().as_slice()
    );
    let failure = domain.keys.get(&FAILURE).ok_or("failure key")?;
    let schemas = [
        CommunityMetadataSchemaV1::Cri1,
        CommunityMetadataSchemaV1::Cpr1,
        CommunityMetadataSchemaV1::Cci1,
        CommunityMetadataSchemaV1::Cci1,
    ];
    for (record, schema) in committed.records.iter().zip(schemas) {
        let framed = CommunityMetadataEnvelopeV1::from_canonical_cbor(&record.envelope)?;
        assert!(framed.schema() == schema);
    }
    let selection = CommunityMetadataEnvelopeV1::from_canonical_cbor(&sealed.envelope)?;
    assert!(selection.schema() == CommunityMetadataSchemaV1::Csi1);
    let pass_key = CommunityPassKeyV1::new(target(), generation, pass)?;
    for (index, key, scope) in [
        (2, vault, scope_set_digest(&[0x80])),
        (3, failure, hash(90)),
    ] {
        let copy = CommunityCopyInventoryV1::from_canonical_cbor(&open(index)?)?;
        let fields = copy.as_input();
        assert_eq!(fields.revision, 1);
        assert_eq!(fields.predecessor, None);
        assert!(fields.parent_operation == CommunityArtifactOperationV1::Pass(pass_key));
        assert!(fields.purpose == CommunityArtifactPurposeV1::LifecycleControl);
        assert_eq!(fields.state, CommunityCopyStateV1::Owned);
        assert_eq!(fields.holder, CommunityCopyHolderV1::KeyVault);
        assert_eq!((fields.timeline, fields.generation), (target(), generation));
        assert_eq!(copy.as_input().holder_digest, key.intent().digest());
        assert_eq!(copy.as_input().scope_set_digest, scope);
        assert_eq!(
            copy.as_input().deadline_micros,
            key.intent().as_input().evidence_not_after_micros
        );
    }

    check_key_intents(vault, failure, pass_key, generation)?;
    assert_eq!(anchor.0, target());
    Ok(())
}

/// The failure cohort key lives to the earlier of the failure and
/// generation horizons (R15.2).
#[test]
fn the_failure_horizon_is_the_earlier_of_quarantine_and_generation() -> TestResult {
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    // `H_g` is 40 s, the quarantine horizon 29 s; then `H_g` is 30 s and the
    // quarantine horizon 39 s.
    for (quarantine, evidence, expected) in [
        (29_000_000, HORIZON, 29_000_000),
        (39_000_000, 30_000_000, 30_000_000),
    ] {
        let mut case = Case::new(&roster, &rows)?;
        case.install(quarantine, evidence);
        let staged = case.stage(OPERATION)?;
        let publication = publication(&case.profile, &case.policy);
        case.domain
            .world
            .domain
            .publish_reserved_pass(&SEAL, staged, publication)?;
        let key = case
            .domain
            .world
            .domain
            .keys
            .get(&FAILURE)
            .ok_or("failure key")?;
        assert_eq!(key.intent().as_input().evidence_not_after_micros, expected);
    }
    Ok(())
}

/// Both keys stay encryption-open after the Reserve, so the pass's Abort
/// and Seal can still seal under them, and the five records burned exactly
/// five credits of the metadata key.
#[test]
fn the_keys_stay_encryption_open() -> TestResult {
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    let mut case = Case::new(&roster, &rows)?;
    let staged = case.stage(OPERATION)?;
    let publication = publication(&case.profile, &case.policy);
    let domain = &mut case.domain.world.domain;
    domain.publish_reserved_pass(&SEAL, staged, publication)?;
    let generation = domain.pass_states.get(&target()).ok_or("state")?.generation;
    let metadata = domain.keys.get(&METADATA).ok_or("metadata key")?;
    assert_eq!(metadata.burned_credits(), 5);
    assert_eq!(
        domain
            .keys
            .get(&FAILURE)
            .ok_or("failure key")?
            .burned_credits(),
        0
    );
    let scope = super::reserve_scope(
        domain.store_incarnation,
        (target(), generation),
        metadata,
        HORIZON,
    )?;
    for id in [METADATA, FAILURE] {
        let key = domain.keys.get_mut(&id).ok_or("key")?;
        assert!(key
            .seal(&scope, CommunityMetadataSchemaV1::Cci1, b"x")
            .is_ok());
    }
    Ok(())
}

/// A lost Reserve response discovers the original CRI1 and CPR1 by its
/// identity, authenticated under the pass metadata key.
#[test]
fn the_original_reserve_reads_back_its_cri1_and_cpr1() -> TestResult {
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    let mut case = Case::new(&roster, &rows)?;
    let staged = case.stage(OPERATION)?;
    let request = CommunityReservationRequestV1::new(staged.request)?.to_canonical_cbor();
    let reservation =
        CommunityReservationV1::new(staged.record.reserved.reservation)?.to_canonical_cbor();
    let publication = publication(&case.profile, &case.policy);
    let domain = &mut case.domain.world.domain;
    assert_eq!(
        domain.original_reserve(target(), OPERATION).err(),
        Some(Error::EvidenceUnavailable)
    );
    domain.publish_reserved_pass(&SEAL, staged, publication)?;
    let original = domain.original_reserve(target(), OPERATION)?;
    assert_eq!(original.request(), request.as_slice());
    assert_eq!(original.reservation(), reservation.as_slice());
    assert_ne!(original.request(), original.reservation());

    // Another identity of T was not reserved here.
    assert_eq!(
        domain.original_reserve(target(), SECOND).err(),
        Some(Error::EvidenceUnavailable)
    );
    // A record that no longer opens, a missing record and a missing key
    // each refuse.
    for index in [0, 1] {
        flip(domain, index)?;
        assert_eq!(
            domain.original_reserve(target(), OPERATION).err(),
            Some(Error::EvidenceUnavailable)
        );
        flip(domain, index)?;
    }
    assert!(domain.original_reserve(target(), OPERATION).is_ok());
    let record = domain
        .reserve_publications
        .get_mut(&(target(), OPERATION))
        .ok_or("publication")?;
    record.records.truncate(1);
    assert_eq!(
        domain.original_reserve(target(), OPERATION).err(),
        Some(Error::EvidenceUnavailable)
    );
    domain.keys.remove(&METADATA);
    assert_eq!(
        domain.original_reserve(target(), OPERATION).err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// One edit of the domain or the staged token between the stage and the
/// publication.
type Tamper = fn(&mut MemoryCommunityDomainV1, &mut CommunityStagedReserveV1) -> TestResult;

/// Every edit of the staged Reserve or the domain the publication refuses, with
/// its refusal; the last is another CDP1 than the pass's.
fn refusals() -> [(Tamper, Error); 12] {
    [
        (
            |domain, _| {
                domain.pass_horizons = None;
                Ok(())
            },
            Error::EvidenceUnavailable,
        ),
        (
            |domain, _| {
                domain.bootstrap = None;
                domain.selection = None;
                Ok(())
            },
            Error::EvidenceUnavailable,
        ),
        (
            |domain, _| {
                domain.pass_states.remove(&target());
                Ok(())
            },
            Error::EvidenceUnavailable,
        ),
        (
            |_, staged| {
                staged.record.reserved.reservation.pass_key =
                    CommunityPassKeyV1::new(target(), [0x99; 16], staged.pass_ordinal)?;
                Ok(())
            },
            Error::StaleGeneration,
        ),
        (
            |_, staged| {
                staged.record.reserved.metadata_key = [0; 16];
                Ok(())
            },
            Error::InvalidBinding,
        ),
        (
            |_, staged| {
                staged.failure_scope = Hash::zero();
                Ok(())
            },
            Error::InvalidBinding,
        ),
        (
            |_, staged| {
                staged.record.reserved.members[1].roster_index = 70_000;
                Ok(())
            },
            Error::InvalidBinding,
        ),
        (
            |_, staged| {
                staged.record.reserved.members[0].roster_index = 1;
                staged.record.reserved.members[1].roster_index = 0;
                Ok(())
            },
            Error::InvalidBinding,
        ),
        (
            |_, staged| {
                staged.record.reserved.members[1].roster_index = 64;
                Ok(())
            },
            Error::BoundsExceeded,
        ),
        (
            |_, staged| {
                staged.request.roster_digest = Hash::zero();
                Ok(())
            },
            Error::InvalidBinding,
        ),
        (
            |_, staged| {
                // The CPR1 refuses a horizon outside `1..=i64::MAX` as out of
                // range, not as a bad binding.
                staged.record.reserved.reservation.evidence_not_after_micros = 0;
                Ok(())
            },
            Error::BoundsExceeded,
        ),
        (|_, _| Ok(()), Error::InvalidBinding),
    ]
}

/// Every refusal before the commit leaves the domain unchanged: the keys,
/// the inventory generation, the selection, the pass state and the burned
/// ordinal stay as they were.
#[test]
fn a_refused_publication_changes_nothing() -> TestResult {
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    let cases = refusals();
    for (index, (tamper, expected)) in cases.into_iter().enumerate() {
        let mut case = Case::new(&roster, &rows)?;
        let mut staged = case.stage(OPERATION)?;
        tamper(&mut case.domain.world.domain, &mut staged)?;
        let before = snapshot(&case.domain.world.domain);
        // The last case is another CDP1 than the one the pass was reserved
        // under, so it needs no tamper.
        let other = profile_until(&rows, HORIZON, hash(2), case.domain.world.catalogue)?;
        let publication = if index == 11 {
            publication(&other, &case.policy)
        } else {
            publication(&case.profile, &case.policy)
        };
        assert_eq!(
            case.domain
                .world
                .domain
                .publish_reserved_pass(&SEAL, staged, publication)
                .err(),
            Some(expected),
            "case {index}"
        );
        assert_eq!(snapshot(&case.domain.world.domain), before, "case {index}");
    }
    Ok(())
}

/// The writer compares the inventory generation and the CSI1 the call read
/// with the current ones (G5): either moving refuses, and the CSI1 the
/// bootstrap sealed is current when no operation replaced it.
#[test]
fn the_writer_compares_the_inventory_generation_and_the_selection() -> TestResult {
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    let mut case = Case::new(&roster, &rows)?;
    let staged = case.stage(OPERATION)?;
    let publication = publication(&case.profile, &case.policy);
    let domain = &mut case.domain.world.domain;
    let mut prepared = domain.prepare_reserve_records(&SEAL, &staged, publication)?;
    assert!(domain.check_reserve_publication(&staged, &prepared).is_ok());

    domain.inventory_generation += 1;
    assert_eq!(
        domain.check_reserve_publication(&staged, &prepared).err(),
        Some(Error::EvidenceUnavailable)
    );
    domain.inventory_generation -= 1;

    let (key, sealed) = domain.selection.take().ok_or("selection")?;
    domain.selection = Some((
        key,
        SealedMetadataV1 {
            envelope: Zeroizing::new(Vec::new()),
            address: hash(0x77),
            commitment: hash(1),
        },
    ));
    assert_eq!(
        domain.check_reserve_publication(&staged, &prepared).err(),
        Some(Error::EvidenceUnavailable)
    );
    domain.selection = Some((key, sealed));
    assert!(domain.check_reserve_publication(&staged, &prepared).is_ok());

    // With no operation's CSI1 yet, the bootstrap one is the current.
    domain.selection = None;
    prepared.read_selection = domain
        .bootstrap
        .as_ref()
        .ok_or("bootstrap")?
        .selection
        .address;
    assert!(domain.check_reserve_publication(&staged, &prepared).is_ok());
    Ok(())
}

/// A reused host-allocated key ID would overwrite a live key and the
/// records of the pass it sealed: either ID in the vault already refuses
/// (`Conflict`), and the failed publication changes nothing.
#[test]
fn a_reused_key_id_refuses_without_overwriting() -> TestResult {
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    for (metadata, failure) in [([0x63; 16], FAILURE), (METADATA, [0x64; 16])] {
        let mut case = Case::new(&roster, &rows)?;
        let staged = case.stage(OPERATION)?;
        let publication = publication(&case.profile, &case.policy);
        case.domain
            .world
            .domain
            .publish_reserved_pass(&SEAL, staged, publication)?;
        // The first pass resolves, so only the key IDs can refuse the next.
        let domain = &mut case.domain.world.domain;
        assert!(domain.set_pass_status(target(), OPERATION, CommunityPassStatusV1::Aborted));
        domain.pending_reservations.clear();
        let mut input = case.input(SECOND)?;
        input.pass.metadata_key = metadata;
        input.pass.failure_cohort_key = failure;
        let staged = case.domain.world.domain.stage_reserve(input)?;
        let before = snapshot(&case.domain.world.domain);
        assert_eq!(
            case.domain
                .world
                .domain
                .publish_reserved_pass(&SEAL, staged, publication)
                .err(),
            Some(Error::Conflict)
        );
        assert_eq!(snapshot(&case.domain.world.domain), before);
        assert!(case
            .domain
            .world
            .domain
            .original_reserve(target(), OPERATION)
            .is_ok());
    }
    Ok(())
}

/// A second identity's Reserve, with key IDs of its own.
fn second_input(case: &Case<'_>) -> Fallible<CommunityReserveInputV1> {
    let mut other = case.input(SECOND)?;
    other.pass.metadata_key = [0x63; 16];
    other.pass.failure_cohort_key = [0x64; 16];
    Ok(other)
}

/// Tokens staged before another Reserve published are stale. Through
/// `publish_reserved_pass` the CSI1 successor refuses them first, because
/// `prepare_reserve_records` runs before the writer's compares and their
/// ordinals are no longer the next ones (`InvalidBinding`); the snapshot
/// stays unchanged.
#[test]
fn a_stale_token_is_refused_by_the_successor_before_the_compares() -> TestResult {
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    let mut case = Case::new(&roster, &rows)?;
    let first = case.stage(OPERATION)?;
    let replay = case.stage(OPERATION)?;
    let second = case
        .domain
        .world
        .domain
        .stage_reserve(second_input(&case)?)?;
    let publication = publication(&case.profile, &case.policy);
    let domain = &mut case.domain.world.domain;
    domain.publish_reserved_pass(&SEAL, first, publication)?;
    let before = snapshot(domain);
    for stale in [replay, second] {
        assert_eq!(
            domain
                .publish_reserved_pass(&SEAL, stale, publication)
                .err(),
            Some(Error::InvalidBinding)
        );
        assert_eq!(snapshot(domain), before);
    }
    Ok(())
}

/// The writer's own compares, over records prepared before the first
/// Reserve published: a recorded identity is `Conflict` and a second
/// unresolved pass of T is `PassUnresolved`. A fresh stage refuses both
/// earlier, so only a stale token reaches them.
#[test]
fn the_writer_refuses_a_replay_and_a_second_unresolved_pass() -> TestResult {
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    let mut case = Case::new(&roster, &rows)?;
    let first = case.stage(OPERATION)?;
    let replay = case.stage(OPERATION)?;
    let second = case
        .domain
        .world
        .domain
        .stage_reserve(second_input(&case)?)?;
    let publication = publication(&case.profile, &case.policy);
    let domain = &mut case.domain.world.domain;
    let replay_records = domain.prepare_reserve_records(&SEAL, &replay, publication)?;
    let second_records = domain.prepare_reserve_records(&SEAL, &second, publication)?;
    domain.publish_reserved_pass(&SEAL, first, publication)?;
    let before = snapshot(domain);
    assert_eq!(
        domain
            .check_reserve_publication(&replay, &replay_records)
            .err(),
        Some(Error::Conflict)
    );
    assert_eq!(
        domain
            .check_reserve_publication(&second, &second_records)
            .err(),
        Some(Error::PassUnresolved)
    );
    assert_eq!(snapshot(domain), before);
    Ok(())
}

/// The two fresh keys must differ from each other as well as from the
/// vault: a metadata key and a failure cohort key of one ID would overwrite
/// each other at the commit (`Conflict`).
#[test]
fn two_keys_of_one_id_refuse() -> TestResult {
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    let case = Case::new(&roster, &rows)?;
    let mut staged = case.stage(OPERATION)?;
    staged.record.reserved.failure_cohort_key = staged.record.reserved.metadata_key;
    let publication = publication(&case.profile, &case.policy);
    let domain = &case.domain.world.domain;
    let prepared = domain.prepare_reserve_records(&SEAL, &staged, publication)?;
    assert_eq!(
        domain.check_fresh_keys(&prepared).err(),
        Some(Error::Conflict)
    );
    Ok(())
}
