//! The authenticated pass Abort, reasons 0 and 4 (I201, I208 for a retry
//! of an administrative Abort, I210, I211 and I213): its refusals in the
//! A5.5 order, the records it commits and the state it leaves.

use std::time::Duration;

use pos_core::community_lifecycle::{
    CommunityAbortReasonV1 as Reason, CommunityAbortV1, CommunityArtifactKindV1,
    CommunityArtifactOperationV1, CommunityArtifactPurposeV1, CommunityAuthorityEvidenceV1,
    CommunityCurrentViewV1, CommunityKeyIntentInputV1, CommunityLifecycleErrorV1 as Error,
    CommunityMemberSlotsV1, CommunityMetadataPolicyV1, CommunityPassFrontierV1, CommunityPassKeyV1,
    CommunityRecordKindsV1, CommunityReservationInputV1, CommunityReservationV1,
    CommunitySharedCountsV1,
};
use pos_core::{AuthorityTrustRootSealV1, Hash};
use zeroize::Zeroizing;

use super::{
    CommunityPassAbortCallV1, CommunityPassAbortReceiptV1, PreparedAbortV1, StagedPassAbortV1,
};
use crate::community::erasure_budget::CommunityPendingReservationV1;
use crate::community::pass_record::{
    CommunityPassMemberDigestsV1, CommunityPassRecordV1, CommunityPassStatusV1,
    CommunityReservedPassV1,
};
use crate::community::private_hash::{private_digest, scope_set_digest};
use crate::community::vault::VaultKeyV1;
use crate::community::{
    CommunityAdministrativeOperationV1, CommunityAdministrativeRequestV1, CommunityDomainBindingV1,
    CommunityLifecycleAuthorityV1, CommunityMetadataAuthorityV1, CommunityQuarantineContextV1,
    MemoryCommunityDomainV1,
};
use crate::community_initialization_fixture::{
    hash, initial_head, initialize_target, metadata_authority, metadata_registry, profile_until,
    target, Bootstrapped, Fallible, Roster, DATA_LEAF, EXPIRES, GENERATION, HORIZON,
    INSTALLED_CATALOGUE, METADATA_LEAF, NATIVE_PROFILE, NOW,
};

/// The trust-root seal of the test composition.
const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();

type TestResult = Fallible<()>;

/// The aborted pass's `reservation_operation_id`.
const OPERATION: [u8; 16] = [0x30; 16];

/// The protection ID of the pass's one metadata key.
const PASS_KEY_ID: [u8; 16] = [0x61; 16];

/// The pass's CPR1 horizon, which the CAB1 copies.
const PASS_HORIZON: u64 = 9_000_000;

/// The pass's pending erasure entry.
const ENTRY: CommunityPendingReservationV1 = CommunityPendingReservationV1 {
    targets: 6,
    rows: 3,
};

fn pass_key() -> Result<CommunityPassKeyV1, Error> {
    CommunityPassKeyV1::new(target(), GENERATION, 7)
}

/// One initialized domain, and a pass that may be reserved on it.
struct Case {
    roster: Roster,
    domain: Bootstrapped,
    head: Hash,
}

impl Case {
    /// An initialized domain, as a Reserve finds it.
    fn new() -> Fallible<Self> {
        let roster = Roster::release_one()?;
        let mut domain = Bootstrapped::new(&SEAL, &roster, true, true)?;
        let head = {
            let rows = roster.rows()?;
            let profile = profile_until(&rows, HORIZON, hash(1), domain.world.catalogue)?;
            let receipt = initialize_target(&SEAL, &mut domain, &roster, &profile)??;
            initial_head(&receipt)?
        };
        Ok(Self {
            roster,
            domain,
            head,
        })
    }

    /// A domain with no initialization, under a metadata horizon of
    /// `horizon`.
    fn uninitialized(horizon: u64) -> Fallible<Self> {
        let roster = Roster::release_one()?;
        let domain = Bootstrapped::until(&SEAL, &roster, true, true, horizon)?;
        Ok(Self {
            roster,
            domain,
            head: hash(0x30),
        })
    }

    /// Reserve the pass: its record, its metadata key and its pending
    /// entry, whose `run_pass` call is live when `live`.
    fn reserve(&mut self, live: bool) -> Fallible<()> {
        let pass_key = pass_key()?;
        let reservation = CommunityReservationInputV1 {
            pass_key,
            request_digest: hash(80),
            native_producer_ordinal: 5,
            predecessor_head_digest: self.head,
            roster_digest: hash(81),
            prepared_input_set_digest: hash(82),
            profile_digest: hash(83),
            evidence_not_after_micros: PASS_HORIZON,
        };
        let vault = VaultKeyV1::provision(CommunityKeyIntentInputV1 {
            protection_operation_id: PASS_KEY_ID,
            parent_operation: CommunityArtifactOperationV1::Pass(pass_key),
            timeline: target(),
            generation: GENERATION,
            purpose: CommunityArtifactPurposeV1::LifecycleControl,
            scope_set_digest: scope_set_digest(&[0x80]),
            evidence_not_after_micros: HORIZON,
            allowed_record_kinds: CommunityRecordKindsV1::empty()
                .with(CommunityArtifactKindV1::LifecycleControl),
            member_slots: CommunityMemberSlotsV1::empty(),
            material_fingerprint: Hash::zero(),
            authority_request_digest: hash(0x44),
        })?;
        let domain = &mut self.domain.world.domain;
        domain.keys.insert(PASS_KEY_ID, vault);
        domain.pass_records.insert(
            (target(), OPERATION),
            CommunityPassRecordV1 {
                reserved: CommunityReservedPassV1 {
                    reservation,
                    cbq1_digest: hash(84),
                    quote_maxima: [1, 2, 3],
                    trace_rows: 2,
                    members: vec![CommunityPassMemberDigestsV1 {
                        roster_index: 0,
                        cmb1_digest: hash(85),
                        cin1_digest: hash(86),
                        trust_policy_snapshot_digest: hash(87),
                    }],
                    metadata_key: PASS_KEY_ID,
                    failure_cohort_key: [0x62; 16],
                    generation_horizon_micros: HORIZON,
                    outcome_horizon_micros: PASS_HORIZON,
                },
                prior_shared_counts: CommunitySharedCountsV1 {
                    nodes: 1,
                    edges: 1,
                    declared_inputs: 1,
                    encoded_record_bytes: 1,
                },
                materialization: None,
                status: CommunityPassStatusV1::Reserved,
                live,
            },
        );
        domain
            .pending_reservations
            .insert((target(), OPERATION), ENTRY);
        Ok(())
    }

    /// The domain.
    const fn domain(&self) -> &MemoryCommunityDomainV1 {
        &self.domain.world.domain
    }

    /// The domain, to change what a call reads.
    const fn domain_mut(&mut self) -> &mut MemoryCommunityDomainV1 {
        &mut self.domain.world.domain
    }

    /// The FAE1 of an Abort of `operation`, or none for an operation the
    /// request derivation refuses.
    fn credential(&self, operation: [u8; 16]) -> Fallible<Vec<u8>> {
        Ok(CommunityAdministrativeRequestV1::derive(
            &CommunityAdministrativeOperationV1::PassAbort {
                timeline: target(),
                reservation_operation_id: operation,
            },
        )
        .ok()
        .map(|request| self.domain.world.credential(request))
        .transpose()?
        .unwrap_or_default())
    }

    /// Run `run` with the installed composition and the call of `reason`
    /// on `operation`, whose administrative decision comes from `leaf`.
    fn with_call<T>(
        &mut self,
        operation: [u8; 16],
        reason: Reason,
        leaf: Hash,
        run: impl FnOnce(
            &mut MemoryCommunityDomainV1,
            CommunityQuarantineContextV1<'_>,
            &mut CommunityLifecycleAuthorityV1,
            &mut CommunityMetadataAuthorityV1,
            CommunityPassAbortCallV1<'_>,
        ) -> T,
    ) -> Fallible<T> {
        let credential = self.credential(operation)?;
        self.with_credential(&credential, operation, reason, leaf, run)
    }

    /// [`Self::with_call`] with the FAE1 `credential`.
    fn with_credential<T>(
        &mut self,
        credential: &[u8],
        operation: [u8; 16],
        reason: Reason,
        leaf: Hash,
        run: impl FnOnce(
            &mut MemoryCommunityDomainV1,
            CommunityQuarantineContextV1<'_>,
            &mut CommunityLifecycleAuthorityV1,
            &mut CommunityMetadataAuthorityV1,
            CommunityPassAbortCallV1<'_>,
        ) -> T,
    ) -> Fallible<T> {
        let rows = self.roster.rows()?;
        let profile = profile_until(&rows, HORIZON, hash(1), self.domain.world.catalogue)?;
        let policy = CommunityMetadataPolicyV1::new(*self.domain.policy.as_input())?;
        let context = CommunityQuarantineContextV1 {
            profile: &profile,
            binding: CommunityDomainBindingV1 {
                metadata_policy: &policy,
                installed_catalogue_digest: INSTALLED_CATALOGUE,
                native_profile_digest: NATIVE_PROFILE,
            },
        };
        let world = &mut self.domain.world;
        Ok(run(
            &mut world.domain,
            context,
            &mut world.authority,
            &mut self.domain.metadata,
            CommunityPassAbortCallV1 {
                credential,
                timeline: target(),
                reservation_operation_id: operation,
                reason,
                administrative_leaf: leaf,
            },
        ))
    }

    /// The Abort of `reason` on the pass, through the public entry.
    fn abort(&mut self, reason: Reason) -> Fallible<Result<CommunityPassAbortReceiptV1, Error>> {
        self.abort_of(OPERATION, reason)
    }

    /// The Abort of `reason` on `operation`.
    fn abort_of(
        &mut self,
        operation: [u8; 16],
        reason: Reason,
    ) -> Fallible<Result<CommunityPassAbortReceiptV1, Error>> {
        self.with_call(
            operation,
            reason,
            DATA_LEAF,
            |domain, context, authority, metadata, call| {
                domain.abort_pass(&SEAL, context, authority, metadata, call)
            },
        )
    }

    /// Every step before the writer, whose staged commit is returned.
    fn staged(&mut self) -> Fallible<StagedPassAbortV1> {
        let prepared = self.with_call(
            OPERATION,
            Reason::AuthenticatedCancellation,
            DATA_LEAF,
            |domain, context, authority, metadata, call| {
                domain.prepare_pass_abort(context, authority, metadata, call)
            },
        )??;
        match prepared {
            PreparedAbortV1::Staged(staged, _) => Ok(*staged),
            PreparedAbortV1::Original(_) => Err("expected a first Abort".into()),
        }
    }

    /// The plaintext of each sealed record of the committed Abort.
    fn records(&self) -> Fallible<Vec<Vec<u8>>> {
        let domain = self.domain();
        let committed = domain
            .pass_aborts
            .get(&(target(), OPERATION))
            .ok_or("no committed Abort")?;
        let vault = domain
            .keys
            .get(&committed.metadata_key)
            .ok_or("no metadata key")?;
        Ok(committed
            .records
            .iter()
            .map(|sealed| vault.open(sealed).map(|bytes| bytes.to_vec()))
            .collect::<Result<Vec<_>, Error>>()?)
    }

    /// `H(CPR1)` of the reserved pass.
    fn reservation_digest(&self) -> Fallible<Hash> {
        let record = self
            .domain()
            .pass_record(target(), OPERATION)
            .ok_or("no pass")?;
        let reservation = CommunityReservationV1::new(record.reserved.reservation)?;
        Ok(private_digest(
            b"PiglorOS.Community.CPR1.v1",
            &[reservation.to_canonical_cbor().as_slice()],
        ))
    }

    /// The script that makes the writer's time the call's sample plus
    /// `writer`.
    fn script_writer(&self, writer: Duration) {
        let zero = Duration::ZERO;
        self.domain
            .script_mono(&[zero, zero, zero, zero, writer, zero]);
    }
}

/// I201: a reason-0 Abort commits one transaction: the pass is Aborted and
/// no longer live, its entry is gone, the inventory generation advanced
/// once and no key, producer ordinal or CSI1 row changed. The CAB1 binds the
/// pass and its CPR1 and copies the CPR1 horizon; the CAU1 is Pass/H(CAB1)
/// with the abort and metadata decisions; the metadata key is closed.
#[test]
fn an_abort_commits_its_records_in_one_transaction() -> TestResult {
    let mut case = Case::new()?;
    case.reserve(false)?;
    let before = case.domain();
    let (inventory, ordinal, keys) = (
        before.inventory_generation,
        before.native_producer_ordinal,
        before.keys.len(),
    );
    let selection = before.selection.as_ref().map(|(_, sealed)| sealed.address);
    let receipt = case.abort(Reason::AuthenticatedCancellation)??;
    let after = case.domain();
    assert_eq!(after.inventory_generation, inventory + 1);
    assert_eq!(after.native_producer_ordinal, ordinal);
    assert_eq!(after.keys.len(), keys);
    assert_eq!(
        after.selection.as_ref().map(|(_, sealed)| sealed.address),
        selection
    );
    assert_eq!(
        after.pass_status(target(), OPERATION),
        Some(CommunityPassStatusV1::Aborted)
    );
    assert!(!after.pass_is_live(target(), OPERATION));
    assert!(!after
        .pending_reservations
        .contains_key(&(target(), OPERATION)));
    assert_eq!(receipt.timeline(), target());
    assert_eq!(receipt.reservation_operation_id(), OPERATION);
    let abort = CommunityAbortV1::from_canonical_cbor(receipt.abort())?;
    let fields = abort.as_input();
    assert!(matches!(fields.reason, Reason::AuthenticatedCancellation));
    assert!(fields.pass_key == pass_key()?);
    assert_eq!(fields.reservation_digest, case.reservation_digest()?);
    assert_eq!(fields.sealed_result_digest, None);
    assert_eq!(fields.failure_evidence_digest, None);
    assert_eq!(fields.quarantine_delta_digest, None);
    assert_eq!(fields.evidence_not_after_micros, PASS_HORIZON);
    assert_eq!(
        receipt.abort_digest(),
        private_digest(b"PiglorOS.Community.CAB1.v1", &[receipt.abort()])
    );
    let records = case.records()?;
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].as_slice(), receipt.abort());
    let view = CommunityCurrentViewV1::from_canonical_cbor(&records[1])?;
    let read = view.as_input();
    assert_eq!(read.inventory_generation, inventory);
    assert!(matches!(read.frontier, CommunityPassFrontierV1::Initial));
    assert_eq!(read.authority_rows.len(), 1);
    assert_eq!(read.trust_rows.len(), 1);
    assert_eq!(read.key_rows.len(), 1);
    let evidence = CommunityAuthorityEvidenceV1::from_canonical_cbor(&records[2])?;
    let cau1 = evidence.as_input();
    assert!(cau1.operation == CommunityArtifactOperationV1::Pass(pass_key()?));
    assert_eq!(cau1.input_identity, receipt.abort_digest());
    assert!(cau1.object_bindings.is_empty());
    assert_eq!(cau1.current_premise_digest, view.digest());
    assert_eq!(cau1.evidence_not_after_micros, HORIZON);
    let leaves: Vec<Hash> = cau1
        .decision_rows
        .iter()
        .map(|row| row.leaf_grant_id)
        .collect();
    assert_eq!(leaves.len(), 2);
    assert!(leaves.contains(&DATA_LEAF) && leaves.contains(&METADATA_LEAF));
    Ok(())
}

/// Reason 4 is the same Abort with its own code.
#[test]
fn a_reason_four_abort_records_its_reason() -> TestResult {
    let mut case = Case::new()?;
    case.reserve(false)?;
    let receipt = case.abort(Reason::RetiringGeneration)??;
    let abort = CommunityAbortV1::from_canonical_cbor(receipt.abort())?;
    assert!(matches!(
        abort.as_input().reason,
        Reason::RetiringGeneration
    ));
    Ok(())
}

/// I208 for an administrative Abort: an identical retry returns the
/// original receipt and changes nothing; another reason, another principal
/// and a retained CAB1 that no longer opens do not.
#[test]
fn a_retry_returns_the_original_or_conflicts() -> TestResult {
    let mut case = Case::new()?;
    case.reserve(false)?;
    let receipt = case.abort(Reason::AuthenticatedCancellation)??;
    let inventory = case.domain().inventory_generation;
    assert_eq!(case.abort(Reason::AuthenticatedCancellation)??, receipt);
    assert_eq!(case.domain().inventory_generation, inventory);
    assert_eq!(
        case.abort(Reason::RetiringGeneration)?.err(),
        Some(Error::Conflict)
    );
    let original = case
        .domain_mut()
        .pass_aborts
        .get_mut(&(target(), OPERATION))
        .ok_or("no committed Abort")?;
    original.leaf_grant_id = METADATA_LEAF;
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::Conflict)
    );
    let original = case
        .domain_mut()
        .pass_aborts
        .get_mut(&(target(), OPERATION))
        .ok_or("no committed Abort")?;
    original.leaf_grant_id = DATA_LEAF;
    original.abort = Zeroizing::new(vec![0]);
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    case.domain_mut().keys.remove(&PASS_KEY_ID);
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// I210: another call's Abort of a pass whose `run_pass` call is live gives
/// 15, and commits once that call has ended.
#[test]
fn an_abort_during_the_live_call_gives_15() -> TestResult {
    let mut case = Case::new()?;
    case.reserve(true)?;
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::OperationActive)
    );
    assert_eq!(
        case.domain().pass_status(target(), OPERATION),
        Some(CommunityPassStatusV1::Reserved)
    );
    case.domain_mut().end_live_call(&SEAL, target(), OPERATION);
    case.abort(Reason::AuthenticatedCancellation)??;
    Ok(())
}

/// A pass nobody reserved is 12 and a Committed pass is 4 (R8.3(3)).
#[test]
fn an_unknown_pass_gives_12_and_a_committed_pass_gives_4() -> TestResult {
    let mut case = Case::new()?;
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    case.reserve(false)?;
    assert!(case.domain_mut().set_pass_status(
        target(),
        OPERATION,
        CommunityPassStatusV1::Committed
    ));
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::Conflict)
    );
    Ok(())
}

/// A5.5 step 1: a reason other than 0 and 4 and a zero identity are 3,
/// before any authority call.
#[test]
fn a_shape_the_table_refuses_gives_3() -> TestResult {
    let mut case = Case::new()?;
    case.reserve(false)?;
    for reason in [
        Reason::ValidatedInvocationFailure,
        Reason::AdmissionRefused,
        Reason::ProtectedUseRefused,
    ] {
        assert_eq!(case.abort(reason)?.err(), Some(Error::InvalidBinding));
    }
    assert_eq!(
        case.abort_of([0; 16], Reason::AuthenticatedCancellation)?
            .err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

/// Every authority failure is 12: a credential for another operation, an
/// administrative leaf that does not admit, and a denied metadata `write`.
#[test]
fn an_authority_failure_gives_12_with_no_effect() -> TestResult {
    let mut case = Case::new()?;
    case.reserve(false)?;
    let inventory = case.domain().inventory_generation;
    let foreign = case.credential([0x31; 16])?;
    let foreign_credential = case.with_credential(
        &foreign,
        OPERATION,
        Reason::AuthenticatedCancellation,
        DATA_LEAF,
        |domain, context, authority, metadata, call| {
            domain.abort_pass(&SEAL, context, authority, metadata, call)
        },
    )?;
    assert_eq!(foreign_credential.err(), Some(Error::EvidenceUnavailable));
    let unadmitted = case.with_call(
        OPERATION,
        Reason::AuthenticatedCancellation,
        hash(0x77),
        |domain, context, authority, metadata, call| {
            domain.abort_pass(&SEAL, context, authority, metadata, call)
        },
    )?;
    assert_eq!(unadmitted.err(), Some(Error::EvidenceUnavailable));
    let mut denied = metadata_authority(&SEAL, metadata_registry(&SEAL)?, 0)?;
    std::mem::swap(&mut case.domain.metadata, &mut denied);
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    std::mem::swap(&mut case.domain.metadata, &mut denied);
    assert_eq!(case.domain().inventory_generation, inventory);
    assert_eq!(
        case.domain().pass_status(target(), OPERATION),
        Some(CommunityPassStatusV1::Reserved)
    );
    Ok(())
}

/// The generation (5) and head (6) fences, and a Sealed pass, whose CPS1
/// digest the record does not carry yet (12).
#[test]
fn a_moved_generation_or_head_and_a_sealed_pass_are_refused() -> TestResult {
    let mut case = Case::new()?;
    case.reserve(false)?;
    let record = case
        .domain_mut()
        .pass_records
        .get_mut(&(target(), OPERATION))
        .ok_or("no pass")?;
    let reservation = record.reserved.reservation;
    record.reserved.reservation.pass_key = CommunityPassKeyV1::new(target(), [0x21; 16], 7)?;
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::StaleGeneration)
    );
    let record = case
        .domain_mut()
        .pass_records
        .get_mut(&(target(), OPERATION))
        .ok_or("no pass")?;
    record.reserved.reservation = CommunityReservationInputV1 {
        predecessor_head_digest: hash(0x99),
        ..reservation
    };
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::StaleFrontier)
    );
    let record = case
        .domain_mut()
        .pass_records
        .get_mut(&(target(), OPERATION))
        .ok_or("no pass")?;
    record.reserved.reservation = reservation;
    assert!(case
        .domain_mut()
        .set_pass_status(target(), OPERATION, CommunityPassStatusV1::Sealed));
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// A decision bound after the metadata horizon is 13: the pass metadata key
/// could not seal the CAB1 inside its metadata policy.
#[test]
fn a_bound_after_the_metadata_horizon_gives_13() -> TestResult {
    let mut case = Case::uninitialized(EXPIRES - 1)?;
    case.reserve(false)?;
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::EvidenceExpired)
    );
    Ok(())
}

/// The writer refuses at the call's decision bound and leaves the pass
/// unresolved with its entry; a retry commits.
#[test]
fn the_writer_refuses_at_the_decision_bound() -> TestResult {
    let mut case = Case::new()?;
    case.reserve(false)?;
    let inventory = case.domain().inventory_generation;
    case.script_writer(Duration::from_micros(EXPIRES - NOW));
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    let domain = case.domain();
    assert_eq!(domain.inventory_generation, inventory);
    assert_eq!(
        domain.pass_status(target(), OPERATION),
        Some(CommunityPassStatusV1::Reserved)
    );
    assert!(domain
        .pending_reservations
        .contains_key(&(target(), OPERATION)));
    case.abort(Reason::AuthenticatedCancellation)??;
    Ok(())
}

/// The commit compares the inventory generation the CAU1 read, finds the
/// pass's entry and its key, and seals before it changes anything: each
/// refusal leaves the pass unresolved with its entry.
#[test]
fn a_refused_commit_leaves_the_pass_unresolved() -> TestResult {
    let mut case = Case::new()?;
    case.reserve(false)?;
    let staged = case.staged()?;
    case.domain_mut().inventory_generation += 1;
    assert_eq!(
        case.domain_mut().commit_pass_abort(&SEAL, staged).err(),
        Some(Error::EvidenceUnavailable)
    );
    let staged = case.staged()?;
    case.domain_mut()
        .pending_reservations
        .remove(&(target(), OPERATION));
    assert_eq!(
        case.domain_mut().commit_pass_abort(&SEAL, staged).err(),
        Some(Error::InvalidBinding)
    );
    case.domain_mut()
        .pending_reservations
        .insert((target(), OPERATION), ENTRY);
    let staged = case.staged()?;
    case.domain_mut()
        .keys
        .get_mut(&PASS_KEY_ID)
        .ok_or("no key")?
        .close();
    assert_eq!(
        case.domain_mut().commit_pass_abort(&SEAL, staged).err(),
        Some(Error::CapacityExhausted)
    );
    let staged = case.staged()?;
    case.domain_mut().keys.remove(&PASS_KEY_ID);
    assert_eq!(
        case.domain_mut().commit_pass_abort(&SEAL, staged).err(),
        Some(Error::EvidenceUnavailable)
    );
    assert_eq!(
        case.domain().pass_status(target(), OPERATION),
        Some(CommunityPassStatusV1::Reserved)
    );
    assert!(case
        .domain()
        .pending_reservations
        .contains_key(&(target(), OPERATION)));
    Ok(())
}
