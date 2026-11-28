//! The failure Abort, reasons 1 to 3 (I200, I204, I205, I206, I207, I208
//! for a producer retry, I212 and I213): its refusals in the A5.5 order, the
//! records it commits and the state it leaves.

use pos_core::community_lifecycle::{
    community_catalogue_owner_v1, CommunityAbortReasonV1 as Reason, CommunityAbortV1,
    CommunityArtifactKindV1, CommunityArtifactOperationV1, CommunityArtifactPurposeV1,
    CommunityAuthorityEvidenceV1, CommunityBudgetQuoteInputV1, CommunityBudgetQuoteV1,
    CommunityCurrentViewV1, CommunityDueMemberBudgetV1, CommunityDurableProfileV1,
    CommunityKeyIntentInputV1, CommunityLifecycleErrorV1 as Error, CommunityMaterializationV1,
    CommunityMemberSlotsV1, CommunityMetadataPolicyV1, CommunityOriginalProvenanceInputV1,
    CommunityOriginalProvenanceV1, CommunityPassFrontierV1, CommunityPluginHostErrorV1 as Host,
    CommunityProducerBindingV1, CommunityQuarantineDispositionV1, CommunityQuarantineKeyV1,
    CommunityQuarantineOutcomeV1, CommunityQuarantineReasonEvidenceV1, CommunityQuarantineReasonV1,
    CommunityRecordKindsV1, CommunityScopeBindingInputV1, CommunityScopeBindingV1,
    CommunityScopeCoverageRowsV1, CommunityScopeMembersV1, CommunitySharedCountsV1,
    CommunityTypedInputRefsV1, ComponentTrapClassV1, TrapReproductionV1, TrustDenialBasisV1,
};
use pos_core::{ArtifactRegistrationPersistencePortV1, AuthorityTrustRootSealV1, Hash};

use super::super::operator::tests::{
    pass_key, profile_rows, Case, ENTRY, OPERATION, PASS_HORIZON, PASS_KEY_ID,
};
use super::{
    CommunityPassAbortFailureCallV1, CommunityPassAbortFailureV1, CommunityPassAbortScopeV1,
    PreparedFailureV1, StagedFailureAbortV1,
};
use crate::community::current_view_head::tests::state_revisions;
use crate::community::pass_abort::failure::{
    derive_failure, CommunityObservedFailureV1 as Observed,
    CommunityPassAbortFailureInputV1 as Input,
};
use crate::community::pass_record::{CommunityPassMemberDigestsV1, CommunityPassStatusV1};
use crate::community::private_hash::scope_set_digest;
use crate::community::quarantine::{
    CommittedQuarantineControlV1, CommunityQuarantineReceiptV1, QuarantineLedgerV1,
    QuarantineReasonStateV1, RetainedControlV1, RetainedSetReasonV1, SealedControlV1,
    SetReasonBoundV1,
};
use crate::community::vault::VaultKeyV1;
use crate::community::{
    CommunityDomainBindingV1, CommunityLifecycleAuthorityV1, CommunityMetadataAuthorityV1,
    CommunityPassAbortReceiptV1, CommunityQuarantineContextV1, MemoryCommunityDomainV1,
};
use crate::community_initialization_fixture::{
    hash, metadata_authority, metadata_registry, profile_until, target, Fallible, GENERATION,
    HORIZON, INCARNATION, INSTALLED_CATALOGUE, NATIVE_PROFILE, NOW,
};

/// The trust-root seal of the test composition.
const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();

type TestResult = Fallible<()>;

/// The protection ID of the failure cohort key `Case::reserve` records.
const COHORT_ID: [u8; 16] = [0x62; 16];

/// The CMB1 digests of the pass's two due members.
const MEMBER_ZERO: Hash = Hash::from_bytes([85; 32]);
const MEMBER_ONE: Hash = Hash::from_bytes([95; 32]);

/// The pass scope bytes a live call holds.
struct ScopeBytes {
    csb1: Vec<u8>,
    cpv1: Vec<u8>,
    cbq1: Vec<u8>,
    quote_digest: Hash,
}

impl ScopeBytes {
    fn scope(&self) -> CommunityPassAbortScopeV1<'_> {
        CommunityPassAbortScopeV1 {
            csb1: &self.csb1,
            cpv1: &self.cpv1,
            cbq1: &self.cbq1,
        }
    }
}

/// The CSB1, CPV1 and CBQ1 of the pass, the CPV1 naming `budget` as its
/// budget identity when given.
fn scope_bytes(
    profile: &CommunityDurableProfileV1<'_>,
    (budget, identity): (Option<Hash>, u8),
) -> Fallible<ScopeBytes> {
    let operation = CommunityArtifactOperationV1::Pass(pass_key()?);
    let quote = CommunityBudgetQuoteV1::new(CommunityBudgetQuoteInputV1 {
        timeline: target(),
        generation: GENERATION,
        profile_digest: profile.digest(),
        prior_shared_counts: CommunitySharedCountsV1 {
            nodes: 0,
            edges: 0,
            declared_inputs: 0,
            encoded_record_bytes: 0,
        },
        due_members: vec![CommunityDueMemberBudgetV1 {
            member_binding_digest: MEMBER_ZERO,
            negotiated_tuple_digest: hash(88),
        }],
        maximum_required_nodes: 0,
        maximum_required_edges: 0,
        maximum_required_bytes: 16_384,
    })?;
    let scope = CommunityScopeBindingV1::new(CommunityScopeBindingInputV1 {
        store_incarnation: INCARNATION,
        timeline: target(),
        generation: GENERATION,
        operation,
        input_identity: hash(identity),
        coverage_rows: CommunityScopeCoverageRowsV1::from_rows(&[]),
        scope_members: CommunityScopeMembersV1::from_members(&[]),
        policy_revision: hash(91),
        evidence_not_after_micros: HORIZON,
    })?;
    let provenance = CommunityOriginalProvenanceV1::new(CommunityOriginalProvenanceInputV1 {
        store_incarnation: INCARNATION,
        timeline: target(),
        generation: GENERATION,
        operation,
        input_identity: hash(identity),
        scope_binding_digest: scope.digest(),
        source_root_refs: CommunityTypedInputRefsV1::from_references(&[]),
        rule_bundle_digest: hash(92),
        budget_identity: budget.unwrap_or_else(|| quote.digest()),
        evidence_not_after_micros: HORIZON,
    })?;
    Ok(ScopeBytes {
        csb1: scope.to_canonical_cbor().to_vec(),
        cpv1: provenance.to_canonical_cbor().to_vec(),
        cbq1: quote.to_canonical_cbor().to_vec(),
        quote_digest: quote.digest(),
    })
}

/// The failure cohort key `Reserve` provisions: parent the pass, the failure
/// horizon and the kinds a CFO1 and its proof need.
fn cohort_key(horizon: u64, kinds: CommunityRecordKindsV1) -> Fallible<VaultKeyV1> {
    Ok(VaultKeyV1::provision(CommunityKeyIntentInputV1 {
        protection_operation_id: COHORT_ID,
        parent_operation: CommunityArtifactOperationV1::Pass(pass_key()?),
        timeline: target(),
        generation: GENERATION,
        purpose: CommunityArtifactPurposeV1::LifecycleControl,
        scope_set_digest: scope_set_digest(&[0x80]),
        evidence_not_after_micros: horizon,
        allowed_record_kinds: kinds,
        member_slots: CommunityMemberSlotsV1::empty(),
        material_fingerprint: Hash::zero(),
        authority_request_digest: hash(0x45),
    })?)
}

fn cohort_kinds() -> CommunityRecordKindsV1 {
    CommunityRecordKindsV1::empty()
        .with(CommunityArtifactKindV1::LifecycleControl)
        .with(CommunityArtifactKindV1::ClassificationProof)
}

/// A Reserved pass with two due members, its failure cohort key and its
/// scope bytes.
struct Scene {
    case: Case,
    bytes: ScopeBytes,
    horizon: u64,
}

/// The pass scope bytes of `case` and the failure horizon of its profile.
fn scope_and_horizon(case: &Case) -> Fallible<(ScopeBytes, u64)> {
    let rows = case.roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), case.domain.world.catalogue)?;
    let horizon = profile
        .as_input()
        .retention
        .quarantine_not_after_micros
        .min(HORIZON);
    scope_bytes(&profile, (None, 90)).map(|bytes| (bytes, horizon))
}

/// Give the reserved pass its second due member, the quote of `bytes` and
/// the failure cohort key `Reserve` provisions.
fn adopt(case: &mut Case, bytes: &ScopeBytes, horizon: u64) -> TestResult {
    let key = cohort_key(horizon, cohort_kinds())?;
    let domain = case.domain_mut();
    let record = domain
        .pass_records
        .get_mut(&(target(), OPERATION))
        .ok_or("no pass")?;
    record.reserved.cbq1_digest = bytes.quote_digest;
    record.reserved.members.push(CommunityPassMemberDigestsV1 {
        roster_index: 1,
        cmb1_digest: MEMBER_ONE,
        cin1_digest: hash(96),
        trust_policy_snapshot_digest: hash(97),
    });
    domain.keys.insert(COHORT_ID, key);
    Ok(())
}

impl Scene {
    fn new(live: bool) -> Fallible<Self> {
        let mut case = Case::new()?;
        case.reserve(live)?;
        let (bytes, horizon) = scope_and_horizon(&case)?;
        adopt(&mut case, &bytes, horizon)?;
        Ok(Self {
            case,
            bytes,
            horizon,
        })
    }

    /// The failure Abort of `input` with the scene's scope bytes.
    fn abort(&mut self, input: Input<'_>) -> Fallible<Result<CommunityPassAbortReceiptV1, Error>> {
        run(&mut self.case, input, &self.bytes)
    }

    /// The failure Abort of one reason-1 trap of `member` with `control`.
    fn trap_abort(
        &mut self,
        member: Hash,
        control: u8,
    ) -> Fallible<Result<CommunityPassAbortReceiptV1, Error>> {
        self.abort(input(
            Reason::ValidatedInvocationFailure,
            &[trap(member, control)],
        ))
    }

    fn pass_status(&self) -> Option<CommunityPassStatusV1> {
        self.case.domain().pass_status(target(), OPERATION)
    }

    /// The pass is unchanged: Reserved, its entry pending and its cohort
    /// key still held.
    fn unresolved(&self) -> bool {
        let domain = self.case.domain();
        self.pass_status() == Some(CommunityPassStatusV1::Reserved)
            && domain
                .pending_reservations
                .contains_key(&(target(), OPERATION))
            && domain.keys.contains_key(&COHORT_ID)
            && domain.quarantine_index.is_empty()
            && !domain.pass_aborts.contains_key(&(target(), OPERATION))
    }

    /// The CQK1 digest of roster member `index`.
    fn member_key(&self, index: usize) -> Fallible<Hash> {
        let rows = self.case.roster.rows()?;
        let row = rows.get(index).ok_or("no roster row")?;
        Ok(
            CommunityQuarantineKeyV1::new(target(), row.stable_entry(), row.implementation())?
                .digest(),
        )
    }
}

/// Run the failure Abort of `input` over `bytes`.
fn run(
    case: &mut Case,
    input: Input<'_>,
    bytes: &ScopeBytes,
) -> Fallible<Result<CommunityPassAbortReceiptV1, Error>> {
    with_call(
        case,
        input,
        bytes,
        |domain, context, authority, metadata, call| {
            domain.abort_pass_failure(&SEAL, context, authority, metadata, call)
        },
    )
}

/// Run `run` with the installed composition and the call of `input` over
/// `bytes`.
fn with_call<T>(
    case: &mut Case,
    input: Input<'_>,
    bytes: &ScopeBytes,
    run: impl FnOnce(
        &mut MemoryCommunityDomainV1,
        CommunityQuarantineContextV1<'_>,
        &mut CommunityLifecycleAuthorityV1,
        &mut CommunityMetadataAuthorityV1,
        CommunityPassAbortFailureCallV1<'_>,
    ) -> T,
) -> Fallible<T> {
    let rows = profile_rows(&case.roster, case.extra_plugin.as_ref())?;
    let profile = profile_until(&rows, HORIZON, hash(1), case.domain.world.catalogue)?;
    let policy = CommunityMetadataPolicyV1::new(*case.domain.policy.as_input())?;
    let context = CommunityQuarantineContextV1 {
        profile: &profile,
        binding: CommunityDomainBindingV1 {
            metadata_policy: &policy,
            installed_catalogue_digest: INSTALLED_CATALOGUE,
            native_profile_digest: NATIVE_PROFILE,
        },
    };
    let failure = CommunityPassAbortFailureV1::new(&SEAL, input);
    let world = &mut case.domain.world;
    Ok(run(
        &mut world.domain,
        context,
        &mut world.authority,
        &mut case.domain.metadata,
        CommunityPassAbortFailureCallV1 {
            failure: &failure,
            scope: bytes.scope(),
        },
    ))
}

fn input<'a>(reason: Reason, failures: &'a [Observed<'a>]) -> Input<'a> {
    Input {
        timeline: target(),
        reservation_operation_id: OPERATION,
        reason,
        failures,
    }
}

const TRAP: Host = Host::ComponentTrap {
    class: ComponentTrapClassV1::Other,
    reproduction: TrapReproductionV1::Unverified,
};

/// A reason-1 trap of `member`, which quarantines under `control`.
fn trap(member: Hash, control: u8) -> Observed<'static> {
    Observed {
        member_binding_digest: member,
        invocation_id: Some([control; 16]),
        host_failure: TRAP,
        guest_error: None,
        control_operation_id: Some([control; 16]),
    }
}

/// A reason-1 failure of `member` that quarantines nothing.
fn invalid_output(member: Hash) -> Observed<'static> {
    Observed {
        member_binding_digest: member,
        invocation_id: Some([0x33; 16]),
        host_failure: Host::InvalidGuestOutput,
        guest_error: None,
        control_operation_id: None,
    }
}

/// A reason-2 launch refusal of `member` with `host_failure`.
fn refused(member: Hash, host_failure: Host) -> Observed<'static> {
    Observed {
        member_binding_digest: member,
        invocation_id: None,
        host_failure,
        guest_error: None,
        control_operation_id: None,
    }
}

/// I200: a reason-1 trap commits one transaction. The pass is Aborted and
/// no longer live, its entry is gone, the inventory generation advanced
/// once, and both keys are closed. The CAB1 binds the CFO1 and the quarantine
/// delta; the CAV1 has no scope rows, one authority row and both keys; the
/// CAU1 is Pass/H(CAB1) with one row per COW1 and the one metadata decision.
#[test]
fn a_trap_commits_its_records_and_quarantines_its_member() -> TestResult {
    let mut scene = Scene::new(true)?;
    let before = scene.case.domain();
    let (inventory, ordinal) = (before.inventory_generation, before.native_producer_ordinal);
    assert!(scene.case.key_seals()?);
    let receipt = scene.trap_abort(MEMBER_ZERO, 0x71)??;
    assert!(!scene.case.key_seals()?);
    let domain = scene.case.domain();
    assert_eq!(domain.inventory_generation, inventory + 1);
    assert_eq!(domain.native_producer_ordinal, ordinal);
    assert_eq!(
        domain
            .erasure_contexts
            .get(&target())
            .map_or(0, |context| context.active_pairs),
        0
    );
    assert_eq!(
        domain.pass_status(target(), OPERATION),
        Some(CommunityPassStatusV1::Aborted)
    );
    assert!(!domain.pass_is_live(target(), OPERATION));
    assert!(!domain
        .pending_reservations
        .contains_key(&(target(), OPERATION)));
    let abort = CommunityAbortV1::from_canonical_cbor(receipt.abort())?;
    let fields = abort.as_input();
    assert!(matches!(fields.reason, Reason::ValidatedInvocationFailure));
    assert_eq!(fields.evidence_not_after_micros, PASS_HORIZON);
    assert_eq!(fields.sealed_result_digest, None);
    let members = scene
        .case
        .domain()
        .pass_record(target(), OPERATION)
        .ok_or("no pass")?
        .reserved
        .members
        .clone();
    let failures = [trap(MEMBER_ZERO, 0x71)];
    let derived = derive_failure(pass_key()?, &members, &failures, scene.horizon)?;
    assert_eq!(fields.failure_evidence_digest, Some(derived.failure_digest));
    assert!(fields.quarantine_delta_digest.is_some());
    let key = scene.member_key(0)?;
    let ledger = scene
        .case
        .domain()
        .quarantine_index
        .get(&key)
        .ok_or("no ledger")?;
    assert_eq!(ledger.ordinal, 1);
    assert_eq!(ledger.evidence_not_after_micros, scene.horizon);
    assert_eq!(
        ledger
            .states
            .get(&CommunityQuarantineReasonV1::Trapped.code()),
        Some(&QuarantineReasonStateV1 {
            evidence_not_after_micros: scene.horizon,
            share_spent: false,
        })
    );
    assert_eq!(ledger.reasons.len(), 1);
    assert!(ledger.reasons[0].reason == CommunityQuarantineReasonV1::Trapped);
    assert_eq!(
        ledger.reasons[0].failure_evidence_digest,
        derived.failure_digest
    );
    let control = scene
        .case
        .domain()
        .quarantine_controls
        .get(&(target(), [0x71; 16]))
        .ok_or("no retry entry")?;
    assert_eq!(control.receipt.selected_ledger_digest, ledger.head);
    Ok(())
}

/// The sealed records of the same Abort: the CAB1, the CAV1 with no scope
/// rows, the CAU1 with one object row per COW1, the pass scope bytes, one CMI1
/// per COW1 and the CQC1, CQR1 and CQO1, with the ARD1s published.
#[test]
fn a_trap_seals_its_records_under_the_pass_key() -> TestResult {
    let mut scene = Scene::new(true)?;
    let inventory = scene.case.domain().inventory_generation;
    let receipt = scene.trap_abort(MEMBER_ZERO, 0x71)??;
    let key = scene.member_key(0)?;
    let ledger = scene
        .case
        .domain()
        .quarantine_index
        .get(&key)
        .ok_or("no ledger")?;
    let control = scene
        .case
        .domain()
        .quarantine_controls
        .get(&(target(), [0x71; 16]))
        .ok_or("no retry entry")?;
    let records = scene.case.records()?;
    assert_eq!(records.len(), 11);
    assert_eq!(records[0].as_slice(), receipt.abort());
    let outcome = CommunityQuarantineOutcomeV1::from_canonical_cbor(&records[10])?;
    assert!(matches!(
        outcome.as_input().disposition,
        CommunityQuarantineDispositionV1::Applied
    ));
    assert_eq!(outcome.as_input().selected_ledger_digest, ledger.head);
    assert_eq!(control.receipt.outcome(), records[10].as_slice());
    let view = CommunityCurrentViewV1::from_canonical_cbor(&records[1])?;
    let read = view.as_input();
    assert!(matches!(read.frontier, CommunityPassFrontierV1::Initial));
    let refs = state_revisions(scene.case.domain())?;
    assert!(read.selected_head == Some(refs[0]));
    assert!(read.scope_rows.is_empty());
    assert_eq!(read.authority_rows.len(), 1);
    assert_eq!(read.key_rows.len(), 2);
    assert_eq!(read.inventory_generation, inventory);
    let evidence = CommunityAuthorityEvidenceV1::from_canonical_cbor(&records[2])?;
    let cau1 = evidence.as_input();
    assert!(cau1.operation == CommunityArtifactOperationV1::Pass(pass_key()?));
    assert_eq!(cau1.input_identity, receipt.abort_digest());
    assert_eq!(cau1.object_bindings.len(), 2);
    assert_eq!(cau1.decision_rows.len(), 1);
    assert_eq!(cau1.current_premise_digest, view.digest());
    assert_eq!(records[3], scene.bytes.cbq1);
    assert_eq!(records[4], scene.bytes.csb1);
    assert_eq!(records[5], scene.bytes.cpv1);
    let committed = scene
        .case
        .domain()
        .pass_aborts
        .get(&(target(), OPERATION))
        .ok_or("no committed Abort")?;
    assert_eq!(committed.admissions.len(), 2);
    for (index, magic) in [(6, *b"CFI1"), (7, *b"CFO1")] {
        let materialization = CommunityMaterializationV1::from_canonical_cbor(&records[index])?;
        let fields = materialization.as_input();
        assert_eq!(fields.record_magic, magic);
        assert!(matches!(
            fields.producer,
            CommunityProducerBindingV1::Control(digest) if digest == receipt.abort_digest()
        ));
        assert_eq!(
            fields.materialization.attestation_address,
            committed.admissions[index - 6].digest()
        );
    }
    let retained = &control.set_reason().ok_or("no SetReason")?.sealed;
    let vault = scene
        .case
        .domain()
        .keys
        .get(&retained.metadata_key)
        .ok_or("no pass key")?;
    assert_eq!(retained.records.len(), 1);
    assert_eq!(
        vault.open(&retained.records[0])?.as_slice(),
        records[10].as_slice()
    );
    let owner = community_catalogue_owner_v1(target(), GENERATION)?;
    for admission in &committed.admissions {
        assert!(matches!(
            ArtifactRegistrationPersistencePortV1::read_artifact_registration(
                &scene.case.domain().store,
                &owner,
                admission.as_input().registration_address,
            ),
            Ok(Some(_))
        ));
    }
    assert!(scene
        .case
        .domain()
        .keys
        .get(&COHORT_ID)
        .is_some_and(|key| key.intent().as_input().protection_operation_id == COHORT_ID));
    assert_ne!(PASS_KEY_ID, COHORT_ID);
    Ok(())
}

/// A failure that maps to no quarantine reason has no control identity and
/// leaves the quarantine index alone: no delta, no retry entry.
#[test]
fn an_unmapped_failure_quarantines_nothing() -> TestResult {
    let mut scene = Scene::new(true)?;
    let receipt = scene.abort(input(
        Reason::ValidatedInvocationFailure,
        &[invalid_output(MEMBER_ZERO)],
    ))??;
    let abort = CommunityAbortV1::from_canonical_cbor(receipt.abort())?;
    assert!(abort.as_input().failure_evidence_digest.is_some());
    assert_eq!(abort.as_input().quarantine_delta_digest, None);
    let domain = scene.case.domain();
    assert!(domain.quarantine_index.is_empty());
    assert!(domain.quarantine_controls.is_empty());
    assert_eq!(scene.case.records()?.len(), 8);
    Ok(())
}

/// A reason-2 launch refusal has a null invocation and quarantines nothing.
#[test]
fn a_launch_refusal_commits_as_reason_two() -> TestResult {
    let mut scene = Scene::new(true)?;
    let receipt = scene.abort(input(
        Reason::AdmissionRefused,
        &[refused(MEMBER_ONE, Host::MissingFeature { index: 3 })],
    ))??;
    let abort = CommunityAbortV1::from_canonical_cbor(receipt.abort())?;
    assert!(matches!(abort.as_input().reason, Reason::AdmissionRefused));
    assert_eq!(abort.as_input().quarantine_delta_digest, None);
    assert!(scene.case.domain().quarantine_index.is_empty());
    Ok(())
}

/// Two failures: both members quarantine, the CFO1 lists both CFI1s, and
/// the three rows exactly fill the pending entry (R15.4).
#[test]
fn two_failures_register_every_row_the_entry_holds() -> TestResult {
    let mut scene = Scene::new(true)?;
    assert_eq!(ENTRY.rows, 3);
    let failures = [trap(MEMBER_ZERO, 0x71), trap(MEMBER_ONE, 0x72)];
    let receipt = scene.abort(input(Reason::ValidatedInvocationFailure, &failures))??;
    let domain = scene.case.domain();
    assert_eq!(domain.quarantine_index.len(), 2);
    assert_eq!(domain.quarantine_controls.len(), 2);
    assert_eq!(
        domain
            .erasure_contexts
            .get(&target())
            .map_or(0, |context| context.active_pairs),
        0
    );
    let committed = domain
        .pass_aborts
        .get(&(target(), OPERATION))
        .ok_or("no committed Abort")?;
    assert_eq!(committed.admissions.len(), 3);
    assert_eq!(scene.case.records()?.len(), 6 + 3 + 6);
    assert_eq!(receipt.abort(), committed.abort.as_slice());
    Ok(())
}

/// A pending entry smaller than the rows the Abort registers refuses it
/// with nothing changed: the pass stays unresolved with its cohort key.
#[test]
fn an_entry_smaller_than_the_registered_rows_refuses_the_abort() -> TestResult {
    let mut scene = Scene::new(true)?;
    scene
        .case
        .domain_mut()
        .pending_reservations
        .get_mut(&(target(), OPERATION))
        .ok_or("no entry")?
        .rows = 2;
    let failures = [trap(MEMBER_ZERO, 0x71), trap(MEMBER_ONE, 0x72)];
    assert_eq!(
        scene
            .abort(input(Reason::ValidatedInvocationFailure, &failures))?
            .err(),
        Some(Error::InvalidBinding)
    );
    assert!(scene.unresolved());
    assert!(scene.case.domain().quarantine_controls.is_empty());
    Ok(())
}

/// A reason already active on the member's ledger is kept: the new revision
/// is the next ordinal over it, with the reasons in code order and the
/// horizon no later than the existing one (R15.2(1)).
#[test]
fn a_new_reason_appends_to_the_current_ledger() -> TestResult {
    let mut scene = Scene::new(true)?;
    let key = scene.member_key(0)?;
    let earlier = scene.horizon - 1;
    scene.case.domain_mut().quarantine_index.insert(
        key,
        QuarantineLedgerV1 {
            head: hash(0x93),
            ordinal: 4,
            reasons: vec![CommunityQuarantineReasonEvidenceV1 {
                reason: CommunityQuarantineReasonV1::Revoked,
                failure_evidence_digest: hash(0x94),
            }],
            evidence_not_after_micros: earlier,
            states: std::collections::BTreeMap::from([(
                CommunityQuarantineReasonV1::Revoked.code(),
                QuarantineReasonStateV1 {
                    evidence_not_after_micros: earlier,
                    share_spent: true,
                },
            )]),
        },
    );
    scene.trap_abort(MEMBER_ZERO, 0x71)??;
    let ledger = scene
        .case
        .domain()
        .quarantine_index
        .get(&key)
        .ok_or("no ledger")?;
    assert_eq!(ledger.ordinal, 5);
    assert_eq!(ledger.evidence_not_after_micros, earlier);
    let codes: Vec<u8> = ledger.reasons.iter().map(|row| row.reason.code()).collect();
    assert_eq!(codes, [0, 2]);
    assert_eq!(ledger.states.len(), 2);
    assert!(ledger.states.values().any(|state| state.share_spent));
    assert!(ledger.states.values().any(|state| !state.share_spent));
    Ok(())
}

/// I208: an identical retry returns the original receipt and changes
/// nothing; other bound content conflicts; a retry at or after `H_r` is
/// discovery of expired evidence (13) and one just before returns the
/// original.
#[test]
fn a_retry_returns_the_original_or_conflicts() -> TestResult {
    let mut scene = Scene::new(true)?;
    let receipt = scene.trap_abort(MEMBER_ZERO, 0x71)??;
    let inventory = scene.case.domain().inventory_generation;
    assert_eq!(scene.trap_abort(MEMBER_ZERO, 0x71)??, receipt);
    assert_eq!(scene.case.domain().inventory_generation, inventory);
    assert_eq!(
        scene.trap_abort(MEMBER_ZERO, 0x72)?.err(),
        Some(Error::Conflict)
    );
    assert_eq!(
        scene.trap_abort(MEMBER_ONE, 0x71)?.err(),
        Some(Error::Conflict)
    );
    scene
        .case
        .domain_mut()
        .pass_aborts
        .get_mut(&(target(), OPERATION))
        .ok_or("no committed Abort")?
        .evidence_not_after_micros = NOW;
    assert_eq!(
        scene.trap_abort(MEMBER_ZERO, 0x71)?.err(),
        Some(Error::EvidenceExpired)
    );
    scene
        .case
        .domain_mut()
        .pass_aborts
        .get_mut(&(target(), OPERATION))
        .ok_or("no committed Abort")?
        .evidence_not_after_micros = NOW + 1;
    assert_eq!(scene.trap_abort(MEMBER_ZERO, 0x71)??, receipt);
    Ok(())
}

/// A retained CAB1 that no longer opens, and an ARD1 that no longer
/// resolves, are unavailable evidence (12).
#[test]
fn a_retry_with_unavailable_evidence_gives_12() -> TestResult {
    let mut scene = Scene::new(true)?;
    scene.trap_abort(MEMBER_ZERO, 0x71)??;
    let committed = scene
        .case
        .domain_mut()
        .pass_aborts
        .get_mut(&(target(), OPERATION))
        .ok_or("no committed Abort")?;
    committed.generation = [0x55; 16];
    assert_eq!(
        scene.trap_abort(MEMBER_ZERO, 0x71)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    scene
        .case
        .domain_mut()
        .pass_aborts
        .get_mut(&(target(), OPERATION))
        .ok_or("no committed Abort")?
        .generation = GENERATION;
    scene
        .case
        .domain_mut()
        .pass_aborts
        .get_mut(&(target(), OPERATION))
        .ok_or("no committed Abort")?
        .metadata_key = [0xee; 16];
    assert_eq!(
        scene.trap_abort(MEMBER_ZERO, 0x71)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// R15.3(3): reason 3 and reason 2 code 1 give 12 in V1 and leave the pass
/// unresolved, as does a cohort key the Reserve did not leave.
#[test]
fn the_unreachable_reasons_give_12_and_change_nothing() -> TestResult {
    let mut scene = Scene::new(true)?;
    assert_eq!(
        scene.abort(input(Reason::ProtectedUseRefused, &[]))?.err(),
        Some(Error::EvidenceUnavailable)
    );
    let expired = Host::ArtifactTrustDenied {
        basis: TrustDenialBasisV1::Expired,
    };
    assert_eq!(
        scene
            .abort(input(
                Reason::AdmissionRefused,
                &[refused(MEMBER_ZERO, expired)]
            ))?
            .err(),
        Some(Error::EvidenceUnavailable)
    );
    assert!(scene.unresolved());
    Ok(())
}

/// Step 1 refuses with 3 before any clock use: the reasons that are not a
/// failure input, no failures, and a member that is not due.
#[test]
fn a_malformed_input_gives_3() -> TestResult {
    let mut scene = Scene::new(true)?;
    for bad in [
        input(Reason::AuthenticatedCancellation, &[]),
        input(Reason::ValidatedInvocationFailure, &[]),
        input(Reason::ProtectedUseRefused, &[invalid_output(MEMBER_ZERO)]),
    ] {
        assert_eq!(scene.abort(bad)?.err(), Some(Error::InvalidBinding));
    }
    let stranger = [invalid_output(hash(0x77))];
    assert_eq!(
        scene
            .abort(input(Reason::ValidatedInvocationFailure, &stranger))?
            .err(),
        Some(Error::InvalidBinding)
    );
    let reversed = [invalid_output(MEMBER_ONE), invalid_output(MEMBER_ZERO)];
    assert_eq!(
        scene
            .abort(input(Reason::ValidatedInvocationFailure, &reversed))?
            .err(),
        Some(Error::InvalidBinding)
    );
    assert!(scene.unresolved());
    Ok(())
}

/// The retry lookup and the first-Abort preconditions: a pass nobody
/// reserved gives 12, a Committed pass 4, and a pass that is not Reserved or
/// whose call has ended gives 3 (N18).
#[test]
fn the_pass_must_be_reserved_with_its_call_live() -> TestResult {
    let mut scene = Scene::new(true)?;
    let mut elsewhere = input(Reason::ValidatedInvocationFailure, &[]);
    let failures = [trap(MEMBER_ZERO, 0x71)];
    elsewhere.failures = &failures;
    elsewhere.reservation_operation_id = [0x99; 16];
    assert_eq!(
        scene.abort(elsewhere)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    assert!(scene.case.domain_mut().set_pass_status(
        target(),
        OPERATION,
        CommunityPassStatusV1::Sealed
    ));
    assert_eq!(
        scene.trap_abort(MEMBER_ZERO, 0x71)?.err(),
        Some(Error::InvalidBinding)
    );
    assert!(scene.case.domain_mut().set_pass_status(
        target(),
        OPERATION,
        CommunityPassStatusV1::Committed
    ));
    assert_eq!(
        scene.trap_abort(MEMBER_ZERO, 0x71)?.err(),
        Some(Error::Conflict)
    );
    let mut ended = Scene::new(false)?;
    assert_eq!(
        ended.trap_abort(MEMBER_ZERO, 0x71)?.err(),
        Some(Error::InvalidBinding)
    );
    assert!(ended.unresolved());
    Ok(())
}

/// R15.3(2) step 5: a control identity already in the CQC1 retry index
/// gives 4.
#[test]
fn a_used_control_identity_conflicts() -> TestResult {
    let mut scene = Scene::new(true)?;
    scene.case.domain_mut().quarantine_controls.insert(
        (target(), [0x71; 16]),
        CommittedQuarantineControlV1 {
            kind: RetainedControlV1::SetReason(RetainedSetReasonV1 {
                bound: SetReasonBoundV1 {
                    key: hash(1),
                    expected_ledger: None,
                    reason: 0,
                    host_failure: TRAP,
                    trust_policy_snapshot_digest: hash(2),
                    expected_generation: GENERATION,
                    expected_head: hash(3),
                },
                generation: GENERATION,
                sealed: SealedControlV1 {
                    metadata_key: PASS_KEY_ID,
                    records: Vec::new(),
                },
                admission: None,
            }),
            receipt: CommunityQuarantineReceiptV1 {
                timeline: target(),
                control_operation_id: [0x71; 16],
                request_digest: hash(4),
                selected_ledger_digest: hash(5),
                already_quarantined: false,
                outcome: zeroize::Zeroizing::new(Vec::new()),
            },
        },
    );
    assert_eq!(
        scene.trap_abort(MEMBER_ZERO, 0x71)?.err(),
        Some(Error::Conflict)
    );
    assert!(scene.case.domain().quarantine_index.is_empty());
    assert_eq!(scene.pass_status(), Some(CommunityPassStatusV1::Reserved));
    Ok(())
}

/// R15.1(4): the scope bytes must be the pass's. Bytes that do not decode,
/// a quote other than the Reserve's, a CPV1 of another budget and a CPV1
/// of another scope each give 3 and change nothing.
#[test]
fn scope_bytes_that_are_not_the_passes_give_3() -> TestResult {
    let mut scene = Scene::new(true)?;
    let rows = scene.case.roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), scene.case.domain.world.catalogue)?;
    let other_budget = scope_bytes(&profile, (Some(hash(0x99)), 90))?;
    let other_scope = scope_bytes(&profile, (None, 91))?;
    let good = scope_bytes(&profile, (None, 90))?;
    let failures = [trap(MEMBER_ZERO, 0x71)];
    let call = || input(Reason::ValidatedInvocationFailure, &failures);
    let garbage = ScopeBytes {
        csb1: vec![0],
        cpv1: good.cpv1.clone(),
        cbq1: good.cbq1.clone(),
        quote_digest: good.quote_digest,
    };
    let wrong_scope = ScopeBytes {
        csb1: other_scope.csb1,
        cpv1: good.cpv1.clone(),
        cbq1: good.cbq1.clone(),
        quote_digest: good.quote_digest,
    };
    let wrong_budget = ScopeBytes {
        csb1: good.csb1.clone(),
        cpv1: other_budget.cpv1,
        cbq1: good.cbq1.clone(),
        quote_digest: good.quote_digest,
    };
    for bytes in [&garbage, &wrong_budget, &wrong_scope] {
        assert_eq!(
            run(&mut scene.case, call(), bytes)?.err(),
            Some(Error::InvalidBinding)
        );
    }
    scene
        .case
        .domain_mut()
        .pass_records
        .get_mut(&(target(), OPERATION))
        .ok_or("no pass")?
        .reserved
        .cbq1_digest = hash(0x98);
    assert_eq!(scene.abort(call())?.err(), Some(Error::InvalidBinding));
    assert!(scene.unresolved());
    Ok(())
}

/// The cohort key must be the Reserve's: a missing key and one with
/// another horizon give 12, and a key whose kinds cannot protect a CFO1
/// refuses with 3 and goes back into the domain.
#[test]
fn the_failure_cohort_key_must_fit_the_pass() -> TestResult {
    let mut scene = Scene::new(true)?;
    let horizon = scene.horizon;
    let domain = scene.case.domain_mut();
    domain
        .keys
        .insert(COHORT_ID, cohort_key(horizon - 1, cohort_kinds())?);
    assert_eq!(
        scene.trap_abort(MEMBER_ZERO, 0x71)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    scene.case.domain_mut().keys.remove(&COHORT_ID);
    assert_eq!(
        scene.trap_abort(MEMBER_ZERO, 0x71)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    scene.case.domain_mut().keys.insert(
        COHORT_ID,
        cohort_key(
            horizon,
            CommunityRecordKindsV1::empty().with(CommunityArtifactKindV1::ClassificationProof),
        )?,
    );
    assert_eq!(
        scene.trap_abort(MEMBER_ZERO, 0x71)?.err(),
        Some(Error::InvalidBinding)
    );
    assert!(scene.unresolved());
    Ok(())
}

/// Every authority failure is 12 with no effect: a denied metadata `write`.
#[test]
fn a_denied_metadata_write_gives_12_with_no_effect() -> TestResult {
    let mut scene = Scene::new(true)?;
    let mut denied = metadata_authority(&SEAL, metadata_registry(&SEAL)?, 0)?;
    std::mem::swap(&mut scene.case.domain.metadata, &mut denied);
    assert_eq!(
        scene.trap_abort(MEMBER_ZERO, 0x71)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    std::mem::swap(&mut scene.case.domain.metadata, &mut denied);
    assert!(scene.unresolved());
    Ok(())
}

/// A pass record naming a roster row the CDP1 does not hold, and a pass
/// whose metadata key is gone, each refuse with the pass unresolved and the
/// cohort key back in the domain.
#[test]
fn a_pass_the_installed_profile_cannot_describe_refuses_the_abort() -> TestResult {
    let mut scene = Scene::new(true)?;
    scene
        .case
        .domain_mut()
        .pass_records
        .get_mut(&(target(), OPERATION))
        .ok_or("no pass")?
        .reserved
        .members[1]
        .roster_index = 9;
    assert_eq!(
        scene.trap_abort(MEMBER_ONE, 0x72)?.err(),
        Some(Error::InvalidBinding)
    );
    assert!(scene.unresolved());
    let mut keyless = Scene::new(true)?;
    keyless.case.domain_mut().keys.remove(&PASS_KEY_ID);
    assert_eq!(
        keyless.trap_abort(MEMBER_ZERO, 0x71)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    assert!(keyless.unresolved());
    Ok(())
}

/// The staged commit compares its premises again: a moved inventory
/// generation (12), a metadata key that can no longer seal and an ARD1
/// already catalogued each refuse it with the pass unresolved.
#[test]
fn a_staged_commit_that_cannot_proceed_changes_nothing() -> TestResult {
    let failures = [trap(MEMBER_ZERO, 0x71)];
    let staged = |scene: &mut Scene| -> Fallible<Box<StagedFailureAbortV1>> {
        let prepared = with_call(
            &mut scene.case,
            input(Reason::ValidatedInvocationFailure, &failures),
            &scene.bytes,
            |domain, context, authority, metadata, call| {
                domain.prepare_failure_abort(&SEAL, context, authority, metadata, call)
            },
        )??;
        match prepared {
            PreparedFailureV1::Staged(staged, ..) => Ok(staged),
            PreparedFailureV1::Original(_) => Err("expected a first Abort".into()),
        }
    };
    let mut moved = Scene::new(true)?;
    let first = staged(&mut moved)?;
    moved.case.domain_mut().inventory_generation += 1;
    assert_eq!(
        moved
            .case
            .domain_mut()
            .commit_failure_abort(&SEAL, *first)
            .err(),
        Some(Error::EvidenceUnavailable)
    );
    assert!(moved.unresolved());
    let mut closed = Scene::new(true)?;
    let second = staged(&mut closed)?;
    closed
        .case
        .domain_mut()
        .keys
        .get_mut(&PASS_KEY_ID)
        .ok_or("no pass key")?
        .close();
    assert!(closed
        .case
        .domain_mut()
        .commit_failure_abort(&SEAL, *second)
        .is_err());
    assert!(closed.unresolved());
    let mut taken = Scene::new(true)?;
    let third = staged(&mut taken)?;
    taken
        .case
        .domain_mut()
        .store
        .commit_community_artifact_batch(&third.batch)?;
    assert_eq!(
        taken
            .case
            .domain_mut()
            .commit_failure_abort(&SEAL, *third)
            .err(),
        Some(Error::Conflict)
    );
    assert!(taken.unresolved());
    Ok(())
}

/// The control identity is present exactly when the failure maps to a
/// quarantine reason (R15.3(2) step 1, N7): a trap without one and an
/// unmapped failure with one are shape refusals, so no failure with an
/// identity can lack a reason.
#[test]
fn a_control_identity_is_present_exactly_for_a_mapped_failure() -> TestResult {
    let mut scene = Scene::new(true)?;
    let mut bare = trap(MEMBER_ZERO, 0x71);
    bare.control_operation_id = None;
    let mut named = invalid_output(MEMBER_ZERO);
    named.control_operation_id = Some([0x72; 16]);
    for failure in [bare, named] {
        assert_eq!(
            scene
                .abort(input(Reason::ValidatedInvocationFailure, &[failure]))?
                .err(),
            Some(Error::InvalidBinding)
        );
    }
    assert!(scene.unresolved());
    Ok(())
}
