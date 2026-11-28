//! The authenticated pass Abort, reasons 0 and 4 (I201, I208 for a retry
//! of an administrative Abort, I210, I211 and I213): its refusals in the
//! A5.5 order, the records it commits and the state it leaves.

use std::time::Duration;

use pos_core::community_lifecycle::{
    CommunityAbortReasonV1 as Reason, CommunityAbortV1, CommunityArtifactKindV1,
    CommunityArtifactOperationV1, CommunityArtifactPurposeV1, CommunityAuthorityEvidenceV1,
    CommunityAuthorityViewRowV1, CommunityCurrentViewV1, CommunityDurableProfileV1,
    CommunityInitializationRequestV1, CommunityKeyIntentInputV1,
    CommunityLifecycleErrorV1 as Error, CommunityMaterializationV1, CommunityMemberSlotsV1,
    CommunityMetadataPolicyV1, CommunityMetadataSchemaV1, CommunityMetadataScopeInputV1,
    CommunityMetadataScopeV1, CommunityPassFrontierV1, CommunityPassKeyV1,
    CommunityProfileMemberV1, CommunityRecordKindsV1, CommunityReservationInputV1,
    CommunityReservationV1, CommunityScopeMembersV1, CommunitySharedCountsV1,
};
use pos_core::{AuthorityTrustRootSealV1, Hash, ImplementationKeyV1};
use zeroize::Zeroizing;

use super::{
    CommunityPassAbortCallV1, CommunityPassAbortReceiptV1, PreparedAbortV1, StagedPassAbortV1,
};
use crate::community::current_view_head::tests::{
    opened_records, simulate_commit, state_revisions, views_agree,
};
use crate::community::current_view_head::CommunitySelectedViewV1;
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
    authority_timeline, hash, initial_head, initialize_target, metadata_authority,
    metadata_registry, profile_until, target, Bootstrapped, Fallible, Roster, DATA_LEAF, EXPIRES,
    GENERATION, HORIZON, INCARNATION, INSTALLED_CATALOGUE, METADATA_LEAF, NATIVE_PROFILE, NOW,
    POLICY_REVISION, REGISTRY, SCHEMA, TRUST_SCOPE,
};
use crate::plugin_trust_registry_fixtures::release_one;

/// The trust-root seal of the test composition.
const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();

type TestResult = Fallible<()>;

/// The aborted pass's `reservation_operation_id`.
pub(in crate::community::pass_abort) const OPERATION: [u8; 16] = [0x30; 16];

/// The protection ID of the pass's one metadata key.
pub(in crate::community::pass_abort) const PASS_KEY_ID: [u8; 16] = [0x61; 16];

/// The pass's CPR1 horizon, which the CAB1 copies.
pub(in crate::community::pass_abort) const PASS_HORIZON: u64 = 9_000_000;

/// The pass's pending erasure entry.
pub(in crate::community::pass_abort) const ENTRY: CommunityPendingReservationV1 =
    CommunityPendingReservationV1 {
        targets: 6,
        rows: 3,
    };

pub(in crate::community::pass_abort) fn pass_key() -> Result<CommunityPassKeyV1, Error> {
    CommunityPassKeyV1::new(target(), GENERATION, 7)
}

/// Initialize T under the fixture's CDP1 and return its initialization head.
fn initialize(domain: &mut Bootstrapped, roster: &Roster) -> Fallible<Hash> {
    let rows = roster.rows()?;
    let profile = profile_until(&rows, HORIZON, hash(1), domain.world.catalogue)?;
    initialization_head(domain, roster, &profile)
}

/// The head the initialization under `profile` committed.
fn initialization_head(
    domain: &mut Bootstrapped,
    roster: &Roster,
    profile: &CommunityDurableProfileV1<'_>,
) -> Fallible<Hash> {
    let receipt = initialize_target(&SEAL, domain, roster, profile)??;
    initial_head(&receipt)
}

/// The installed CDP1 roster: the fixture's two members, and a third of a
/// Plugin the registry holds no release of when `extra` names it.
pub(in crate::community::pass_abort) fn profile_rows<'a>(
    roster: &'a Roster,
    extra: Option<&'a ImplementationKeyV1>,
) -> Fallible<Vec<CommunityProfileMemberV1<'a>>> {
    let mut rows = roster.rows()?;
    if let Some(implementation) = extra {
        rows.push(CommunityProfileMemberV1::new(
            "Entry-C_1",
            implementation,
            hash(0x55),
            SCHEMA,
            hash(6),
            roster.initializer(),
            10,
        )?);
    }
    Ok(rows)
}

/// One initialized domain, and a pass that may be reserved on it.
pub(in crate::community::pass_abort) struct Case {
    pub(in crate::community::pass_abort) roster: Roster,
    pub(in crate::community::pass_abort) domain: Bootstrapped,
    pub(in crate::community::pass_abort) head: Hash,
    /// A third roster member of a Plugin the registry holds no release of.
    pub(in crate::community::pass_abort) extra_plugin: Option<ImplementationKeyV1>,
}

impl Case {
    /// An initialized domain, as a Reserve finds it.
    pub(in crate::community::pass_abort) fn new() -> Fallible<Self> {
        Self::with_horizon(HORIZON)
    }

    /// An initialized domain under a metadata horizon of `horizon`.
    fn with_horizon(horizon: u64) -> Fallible<Self> {
        let roster = Roster::release_one()?;
        let mut domain = Bootstrapped::until(&SEAL, &roster, true, true, horizon)?;
        let head = initialize(&mut domain, &roster)?;
        Ok(Self {
            roster,
            domain,
            head,
            extra_plugin: None,
        })
    }

    /// A domain with no initialization: its CSI1 holds no floor for T.
    fn uninitialized() -> Fallible<Self> {
        let roster = Roster::release_one()?;
        let domain = Bootstrapped::until(&SEAL, &roster, true, true, HORIZON)?;
        Ok(Self {
            roster,
            domain,
            head: hash(0x30),
            extra_plugin: None,
        })
    }

    /// Reserve the pass: its record, its metadata key and its pending
    /// entry, whose `run_pass` call is live when `live`.
    pub(in crate::community::pass_abort) fn reserve(&mut self, live: bool) -> Fallible<()> {
        let pass_key = pass_key()?;
        let reservation = CommunityReservationInputV1 {
            pass_key,
            request_digest: hash(80),
            native_producer_ordinal: 5,
            predecessor_head_digest: self.head,
            roster_digest: hash(81),
            prepared_input_set_digest: hash(82),
            profile_digest: {
                let rows = profile_rows(&self.roster, self.extra_plugin.as_ref())?;
                profile_until(&rows, HORIZON, hash(1), self.domain.world.catalogue)?.digest()
            },
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
                sealed_result_digest: None,
                live,
            },
        );
        domain
            .pending_reservations
            .insert((target(), OPERATION), ENTRY);
        Ok(())
    }

    /// The domain.
    pub(in crate::community::pass_abort) const fn domain(&self) -> &MemoryCommunityDomainV1 {
        &self.domain.world.domain
    }

    /// The domain, to change what a call reads.
    pub(in crate::community::pass_abort) const fn domain_mut(
        &mut self,
    ) -> &mut MemoryCommunityDomainV1 {
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

    /// The Abort of `reason` whose FAE1 expires at `expires`.
    fn abort_until(
        &mut self,
        expires: u64,
    ) -> Fallible<Result<CommunityPassAbortReceiptV1, Error>> {
        let request = CommunityAdministrativeRequestV1::derive(
            &CommunityAdministrativeOperationV1::PassAbort {
                timeline: target(),
                reservation_operation_id: OPERATION,
            },
        )?;
        let credential = self.domain.world.credential_until(request, expires)?;
        self.abort_with_credential(&credential, Reason::AuthenticatedCancellation)
    }

    /// The Abort of `reason` on the pass with the FAE1 bytes `credential`.
    fn abort_with_credential(
        &mut self,
        credential: &[u8],
        reason: Reason,
    ) -> Fallible<Result<CommunityPassAbortReceiptV1, Error>> {
        self.with_credential(
            credential,
            OPERATION,
            reason,
            DATA_LEAF,
            |domain, context, authority, metadata, call| {
                domain.abort_pass(&SEAL, context, authority, metadata, call)
            },
        )
    }

    /// Whether the pass metadata key is still open: it seals one probe
    /// record under a CSM1 cover built like the Reserve's, and a closed key
    /// refuses.
    pub(in crate::community::pass_abort) fn key_seals(&mut self) -> Fallible<bool> {
        let scope = CommunityMetadataScopeV1::new(CommunityMetadataScopeInputV1 {
            store_incarnation: INCARNATION,
            metadata_anchor_timeline: target(),
            metadata_anchor_generation: GENERATION,
            protection_operation_id: PASS_KEY_ID,
            scope_members: CommunityScopeMembersV1::from_members(&[]),
            metadata_not_after_micros: HORIZON,
        })?;
        let vault = self
            .domain_mut()
            .keys
            .get_mut(&PASS_KEY_ID)
            .ok_or("no pass key")?;
        Ok(vault
            .seal(&scope, CommunityMetadataSchemaV1::Cab1, b"probe")
            .is_ok())
    }

    /// The Abort of `reason` on the pass whose administrative decision
    /// comes from `leaf`.
    fn abort_by(&mut self, leaf: Hash) -> Fallible<Result<CommunityPassAbortReceiptV1, Error>> {
        self.with_call(
            OPERATION,
            Reason::AuthenticatedCancellation,
            leaf,
            |domain, context, authority, metadata, call| {
                domain.abort_pass(&SEAL, context, authority, metadata, call)
            },
        )
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
        let rows = profile_rows(&self.roster, self.extra_plugin.as_ref())?;
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
    pub(in crate::community::pass_abort) fn records(&self) -> Fallible<Vec<Vec<u8>>> {
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
    assert!(case.key_seals()?);
    let receipt = case.abort(Reason::AuthenticatedCancellation)??;
    assert!(!case.key_seals()?);
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
    let authority = &read.authority_rows[0];
    assert_eq!(authority.authority_timeline, authority_timeline());
    assert_eq!(authority.registry_digest, REGISTRY);
    assert_eq!(authority.capability_policy_revision, POLICY_REVISION);
    assert_eq!(read.trust_rows.len(), 1);
    assert_eq!(read.trust_rows[0].scope, TRUST_SCOPE);
    assert_eq!(read.trust_rows[0].plugin_id, release_one().plugin_id);
    assert_eq!(read.key_rows.len(), 1);
    let vault = case.domain().keys.get(&PASS_KEY_ID).ok_or("no key")?;
    assert_eq!(read.key_rows[0].key_intent_digest, vault.intent().digest());
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
    assert!(cau1.decision_rows.iter().all(|row| {
        row.authority_timeline == authority_timeline()
            && row.policy_revision == POLICY_REVISION
            && row.head_seq == authority.head_seq
            && row.revocation_epoch == authority.revocation_epoch
            && row.request_digest != Hash::zero()
            && row.decision_digest != Hash::zero()
    }));
    assert_ne!(
        cau1.decision_rows[0].request_digest,
        cau1.decision_rows[1].request_digest
    );
    assert_ne!(
        cau1.decision_rows[0].decision_digest,
        cau1.decision_rows[1].decision_digest
    );
    Ok(())
}

/// I235: the Abort's CAV1 states the initialization head's frontier and the
/// CMI1 reference of the first roster member's CSR1, which the sealed
/// initialization records name independently of the domain's selected view.
#[test]
fn an_abort_states_the_first_members_state_revision() -> TestResult {
    let mut case = Case::new()?;
    let refs = state_revisions(case.domain())?;
    assert_eq!(refs.len(), 2);
    assert!(refs[0] != refs[1]);
    let selected = case
        .domain()
        .selected_views
        .get(&target())
        .ok_or("no selected view")?;
    assert!(matches!(
        selected.frontier,
        CommunityPassFrontierV1::Initial
    ));
    assert!(selected.head_ref == refs[0]);
    assert!(views_agree(case.domain(), target()));
    assert_eq!(selected.head_digest, case.head);
    case.reserve(false)?;
    case.abort(Reason::AuthenticatedCancellation)??;
    let records = case.records()?;
    let view = CommunityCurrentViewV1::from_canonical_cbor(&records[1])?;
    assert!(matches!(
        view.as_input().frontier,
        CommunityPassFrontierV1::Initial
    ));
    assert!(view.as_input().selected_head == Some(refs[0]));
    Ok(())
}

/// R16.5(4): the head ref is the CSR1 of the CGI1's first listed member. The
/// fixture builds the graph in the CGI1's order (`check_input` requires it),
/// so the check reads the CGI1 from the sealed records and takes that
/// member's slot, then the CSR1 `at` finds in the CMI1 list: the first
/// member's, not the second's. A wrong index is refused.
#[test]
fn the_head_ref_is_the_cgi1_first_members_state_revision() -> TestResult {
    let case = Case::new()?;
    let refs = state_revisions(case.domain())?;
    let opened = opened_records(case.domain())?;
    let request = opened
        .iter()
        .find_map(|bytes| CommunityInitializationRequestV1::from_canonical_cbor(bytes).ok())
        .ok_or("no CGI1")?;
    assert_eq!(request.as_input().member_binding_digests.len(), 2);
    let cmis: Vec<Zeroizing<Vec<u8>>> = opened
        .into_iter()
        .filter(|bytes| CommunityMaterializationV1::from_canonical_cbor(bytes).is_ok())
        .collect();
    assert_eq!(cmis.len(), 10);
    let head = hash(1);
    let first = CommunitySelectedViewV1::at(head, 2, &cmis)?;
    let second = CommunitySelectedViewV1::at(head, 7, &cmis)?;
    assert!(first.head_ref == refs[0] && second.head_ref == refs[1]);
    let selected = case
        .domain()
        .selected_views
        .get(&target())
        .ok_or("no selected view")?;
    assert!(selected.head_ref == first.head_ref && selected.head_ref != second.head_ref);
    for index in [0, 1, 3, 4, 99] {
        assert_eq!(
            CommunitySelectedViewV1::at(head, index, &cmis).err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    assert!(CommunitySelectedViewV1::at(head, 0, &[Zeroizing::new(vec![0xff])]).is_err());
    Ok(())
}

/// I235: an operator Abort on a committed head succeeds, and its CAV1 states
/// that head's frontier and ref. A Commit does not exist yet (slice 3), so
/// the head is what a Commit will install in one transaction: a new
/// `pass_states` head and the selected view of a real CSR1 CMI1 reference
/// (the second member's) under the `Committed` frontier of the pass key.
#[test]
fn an_abort_on_a_committed_head_succeeds() -> TestResult {
    let mut case = Case::new()?;
    let refs = state_revisions(case.domain())?;
    let key = pass_key()?;
    simulate_commit(
        case.domain_mut(),
        target(),
        &CommunitySelectedViewV1 {
            head_digest: hash(0x77),
            frontier: CommunityPassFrontierV1::Committed(key),
            head_ref: refs[1],
        },
    )?;
    assert!(views_agree(case.domain(), target()));
    case.reserve(false)?;
    case.abort(Reason::AuthenticatedCancellation)??;
    assert!(views_agree(case.domain(), target()));
    let records = case.records()?;
    let view = CommunityCurrentViewV1::from_canonical_cbor(&records[1])?;
    assert!(matches!(
        view.as_input().frontier,
        CommunityPassFrontierV1::Committed(committed) if committed == key
    ));
    assert!(view.as_input().selected_head == Some(refs[1]));
    Ok(())
}

/// A Timeline with no selected view, or one whose view reads another head
/// than the pass state's, has no head ref to state: the Abort stages
/// nothing.
#[test]
fn an_abort_without_an_agreeing_selected_view_is_refused() -> TestResult {
    let mut case = Case::new()?;
    case.reserve(false)?;
    let view = *case
        .domain()
        .selected_views
        .get(&target())
        .ok_or("no selected view")?;
    case.domain_mut().selected_views.insert(
        target(),
        CommunitySelectedViewV1 {
            head_digest: hash(0x78),
            ..view
        },
    );
    assert!(!views_agree(case.domain(), target()));
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    case.domain_mut().selected_views.clear();
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    assert_eq!(
        case.domain().pass_status(target(), OPERATION),
        Some(CommunityPassStatusV1::Reserved)
    );
    Ok(())
}

/// R16.2(4): the CAV1 carries the metadata `write` decision's chain row
/// whenever its key is not another row's. The administrative and metadata
/// chains share a key in this fixture, so one row stands; a chain row at
/// another head gives two, ascending.
#[test]
fn the_metadata_chain_row_joins_a_distinct_chain_row() -> TestResult {
    let mut case = Case::new()?;
    case.reserve(false)?;
    let (alone, joined) = case.with_call(
        OPERATION,
        Reason::AuthenticatedCancellation,
        DATA_LEAF,
        |domain, context, _, metadata, _| -> Fallible<_> {
            let write = domain.abort_metadata_write(context, metadata)?;
            let metadata = (write.leaf_grant_id, &write.request);
            let alone = domain.head_view(target(), vec![], metadata)?;
            let chain = alone.authority_rows[0];
            let later = CommunityAuthorityViewRowV1 {
                head_seq: chain.head_seq + 1,
                ..chain
            };
            let joined = domain.head_view(target(), vec![later], metadata)?;
            Ok((alone.authority_rows, joined.authority_rows))
        },
    )??;
    assert_eq!(alone.len(), 1);
    assert_eq!(alone[0].authority_timeline, authority_timeline());
    assert_eq!(joined.len(), 2);
    assert!(joined[0] == alone[0]);
    assert_eq!(joined[1].head_seq, alone[0].head_seq + 1);
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
    original.leaf_grant_id = hash(0x66);
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::EvidenceUnavailable)
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
        // The shape is refused before any authority call: an unreadable
        // FAE1 would otherwise give 12.
        assert_eq!(
            case.abort_with_credential(b"unreadable", reason)?.err(),
            Some(Error::InvalidBinding)
        );
    }
    for reason in [
        Reason::AuthenticatedCancellation,
        Reason::RetiringGeneration,
    ] {
        assert_eq!(
            case.abort_with_credential(b"unreadable", reason)?.err(),
            Some(Error::EvidenceUnavailable)
        );
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

/// The generation (5) and head (6) fences.
#[test]
fn a_moved_generation_or_head_is_refused() -> TestResult {
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
    assert!(case.abort(Reason::AuthenticatedCancellation)?.is_ok());
    Ok(())
}

/// A Sealed pass is aborted with its CPS1 digest in the CAB1 (I211). A
/// Sealed pass whose call is live is 15 like a Reserved one.
#[test]
fn a_sealed_pass_is_aborted_with_its_cps1_digest() -> TestResult {
    let mut case = Case::new()?;
    case.reserve(false)?;
    assert!(case
        .domain_mut()
        .set_pass_status(target(), OPERATION, CommunityPassStatusV1::Sealed));
    let record = case
        .domain_mut()
        .pass_records
        .get_mut(&(target(), OPERATION))
        .ok_or("no pass")?;
    record.sealed_result_digest = Some(hash(0x71));
    let receipt = case.abort(Reason::AuthenticatedCancellation)??;
    let abort = CommunityAbortV1::from_canonical_cbor(receipt.abort())?;
    assert_eq!(abort.as_input().sealed_result_digest, Some(hash(0x71)));
    Ok(())
}

/// The decision bound is compared with the metadata horizon after the
/// fences: a bound equal to it commits, one past it gives 13, and a stale
/// head with a passed horizon gives 6, as A5.5 step 4 orders them. The FAE1
/// of the later calls outlives the initialization's.
#[test]
fn a_bound_after_the_metadata_horizon_gives_13_after_the_fences() -> TestResult {
    let mut case = Case::with_horizon(EXPIRES)?;
    case.reserve(false)?;
    assert_eq!(
        case.abort_until(EXPIRES + 1_000)?.err(),
        Some(Error::EvidenceExpired)
    );
    let record = case
        .domain_mut()
        .pass_records
        .get_mut(&(target(), OPERATION))
        .ok_or("no pass")?;
    let reservation = record.reserved.reservation;
    record.reserved.reservation = CommunityReservationInputV1 {
        predecessor_head_digest: hash(0x99),
        ..reservation
    };
    assert_eq!(
        case.abort_until(EXPIRES + 1_000)?.err(),
        Some(Error::StaleFrontier)
    );
    let record = case
        .domain_mut()
        .pass_records
        .get_mut(&(target(), OPERATION))
        .ok_or("no pass")?;
    record.reserved.reservation = reservation;
    case.abort(Reason::AuthenticatedCancellation)??;
    Ok(())
}

/// A first Abort at or after the pass's `H_r` still commits its CAB1
/// (N17); a retry at or after it is discovery of expired evidence (13),
/// and one just before it returns the original (R15.2(3a), I213).
#[test]
fn a_retry_at_or_after_the_pass_horizon_gives_13() -> TestResult {
    let mut case = Case::new()?;
    case.reserve(false)?;
    let record = case
        .domain_mut()
        .pass_records
        .get_mut(&(target(), OPERATION))
        .ok_or("no pass")?;
    record.reserved.reservation.evidence_not_after_micros = NOW;
    let receipt = case.abort(Reason::AuthenticatedCancellation)??;
    let abort = CommunityAbortV1::from_canonical_cbor(receipt.abort())?;
    assert_eq!(abort.as_input().evidence_not_after_micros, NOW);
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::EvidenceExpired)
    );
    case.domain_mut()
        .pass_aborts
        .get_mut(&(target(), OPERATION))
        .ok_or("no committed Abort")?
        .evidence_not_after_micros = NOW + 1;
    assert_eq!(case.abort(Reason::AuthenticatedCancellation)??, receipt);
    Ok(())
}

/// The CAB1 binds a CPR1 the codec accepts: a reservation with a zero link
/// is refused before anything is staged (3).
#[test]
fn a_malformed_reservation_gives_3() -> TestResult {
    let mut case = Case::new()?;
    case.reserve(false)?;
    let record = case
        .domain_mut()
        .pass_records
        .get_mut(&(target(), OPERATION))
        .ok_or("no pass")?;
    record.reserved.reservation.roster_digest = Hash::zero();
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

/// A domain that cannot read its CSI1, a Timeline with no floor in it and a
/// pass whose metadata key is gone are each 12.
#[test]
fn a_missing_selection_floor_or_key_gives_12() -> TestResult {
    let mut case = Case::new()?;
    case.reserve(false)?;
    case.domain_mut().keys.remove(&PASS_KEY_ID);
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    let mut case = Case::new()?;
    case.reserve(false)?;
    case.domain_mut().bootstrap = None;
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    let mut case = Case::uninitialized()?;
    case.reserve(false)?;
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// A caller without the administrative decision gets 12 and never learns
/// whether the pass exists or is Committed (no existence oracle), and a
/// retry without the metadata `write` decision is 12 as well.
#[test]
fn authority_comes_before_the_pass_lookup() -> TestResult {
    let mut case = Case::new()?;
    assert_eq!(
        case.abort_by(hash(0x77))?.err(),
        Some(Error::EvidenceUnavailable)
    );
    case.reserve(false)?;
    assert!(case.domain_mut().set_pass_status(
        target(),
        OPERATION,
        CommunityPassStatusV1::Committed
    ));
    assert_eq!(
        case.abort_by(hash(0x77))?.err(),
        Some(Error::EvidenceUnavailable)
    );
    let mut case = Case::new()?;
    case.reserve(false)?;
    case.abort(Reason::AuthenticatedCancellation)??;
    let mut denied = metadata_authority(&SEAL, metadata_registry(&SEAL)?, 0)?;
    std::mem::swap(&mut case.domain.metadata, &mut denied);
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::EvidenceUnavailable)
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
    let mut moved = Case::new()?;
    moved.reserve(false)?;
    let staged = moved.staged()?;
    moved
        .domain_mut()
        .selection
        .as_mut()
        .ok_or("no committed CSI1")?
        .1
        .address = hash(1);
    assert_eq!(
        moved.domain_mut().commit_pass_abort(&SEAL, staged).err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// Owner decision on #560, 2026-11-25 (R6.5(4) erratum): a roster Plugin
/// with no active release has the row its Reserve retained, so the Abort is
/// never refused for it and its CAV1 is never partial. The registry has no
/// release of the third member's Plugin; the CDP1 the call installs names it.
#[test]
fn a_plugin_with_no_active_release_has_its_reserve_time_row() -> TestResult {
    let mut case = Case::new()?;
    let missing = ImplementationKeyV1::new("no.release".into(), "host-v1".into(), hash(0x56))?;
    case.extra_plugin = Some(missing);
    case.reserve(false)?;
    case.abort(Reason::AuthenticatedCancellation)??;
    let records = case.records()?;
    let view = CommunityCurrentViewV1::from_canonical_cbor(&records[1])?;
    let rows = &view.as_input().trust_rows;
    assert_eq!(rows.len(), 2);
    let retained = rows
        .iter()
        .find(|row| row.plugin_id == "no.release")
        .ok_or("no retained row")?;
    assert_eq!(retained.policy_digest, hash(87));
    assert_eq!(retained.active_manifest_digest, hash(0x55));
    assert_eq!(retained.active_release_digest, hash(0x56));
    assert_eq!(
        (
            retained.policy_floor,
            retained.release_floor,
            retained.highest_trusted_utc_second
        ),
        (0, 0, 0)
    );
    let current = rows
        .iter()
        .find(|row| row.plugin_id != "no.release")
        .ok_or("no registry row")?;
    assert_ne!(current.active_manifest_digest, hash(0x55));
    Ok(())
}

/// A due member of the Plugin itself gives the retained policy digest, not
/// the first member's.
#[test]
fn the_retained_row_takes_its_own_members_policy_digest() -> TestResult {
    let mut case = Case::new()?;
    let missing = ImplementationKeyV1::new("no.release".into(), "host-v1".into(), hash(0x56))?;
    case.extra_plugin = Some(missing);
    case.reserve(false)?;
    case.domain_mut()
        .pass_records
        .get_mut(&(target(), OPERATION))
        .ok_or("no pass")?
        .reserved
        .members
        .push(CommunityPassMemberDigestsV1 {
            roster_index: 2,
            cmb1_digest: hash(88),
            cin1_digest: hash(89),
            trust_policy_snapshot_digest: hash(90),
        });
    case.abort(Reason::AuthenticatedCancellation)??;
    let records = case.records()?;
    let view = CommunityCurrentViewV1::from_canonical_cbor(&records[1])?;
    let retained = view
        .as_input()
        .trust_rows
        .iter()
        .find(|row| row.plugin_id == "no.release")
        .ok_or("no retained row")?;
    assert_eq!(retained.policy_digest, hash(90));
    Ok(())
}

/// The Abort reads its CAV1 trust rows from the CDP1 the call installs, so
/// it must be the one the pass was reserved under (3); a pass without a due
/// member records nothing to retain and is refused (12).
#[test]
fn the_installed_profile_must_be_the_reserves() -> TestResult {
    let mut case = Case::new()?;
    case.reserve(false)?;
    let record = case
        .domain_mut()
        .pass_records
        .get_mut(&(target(), OPERATION))
        .ok_or("no pass")?;
    let profile_digest = record.reserved.reservation.profile_digest;
    record.reserved.reservation.profile_digest = hash(0x99);
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::InvalidBinding)
    );
    let record = case
        .domain_mut()
        .pass_records
        .get_mut(&(target(), OPERATION))
        .ok_or("no pass")?;
    record.reserved.reservation.profile_digest = profile_digest;
    record.reserved.members.clear();
    assert_eq!(
        case.abort(Reason::AuthenticatedCancellation)?.err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}
