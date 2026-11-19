//! The CAV1, CAU1, COA1 and CMI1 of a planned code-0 initialization (#560
//! A3c-2c-2; ADR-129 §3, §4, R6.5, R6.6, R6.7) through the planner's public
//! seam, over one real Memory domain, Plugin trust registry and initial
//! graph: authority rows from the domain's own chain, trust rows from its
//! registry (I26, owner decisions 10 and 11 of 2026-11-19), key rows
//! (decisions 3 and 15), the clock latch and the inventory generation (G5).
#![cfg(target_os = "linux")]

#[path = "support/plugin_trust_registry_fixtures.rs"]
pub mod plugin_trust_registry_fixtures;

#[path = "support/community_initialization_fixture.rs"]
pub mod community_initialization_fixture;

use ciborium::Value;
use community_initialization_fixture::*;
use plugin_trust_registry_fixtures::release_one;
use pos_core::community_lifecycle::{
    community_initializer_set_ref_v1, CommunityArtifactKindV1, CommunityArtifactOperationV1,
    CommunityArtifactPurposeV1, CommunityAuthorityEvidenceV1, CommunityCurrentViewV1,
    CommunityDurableProfileV1, CommunityInitializationSourceV1 as Source, CommunityKeyStateV1,
    CommunityLifecycleErrorV1 as Error, CommunityMaterializationV1, CommunityPassFrontierV1,
};
use pos_core::trusted_clock::{TrustedClockOverrunLatchRowV1, TrustedClockStorePortV1};
use pos_core::{AuthorityTrustRootSealV1, Hash, KeyRoleV1};
use pos_store::community::{
    CommunityAdministrativeOperationV1, CommunityAdministrativeRequestV1 as Request,
    CommunityAuthorityAdmissionV1, CommunityAuthorityCallV1,
    CommunityInitializationEvidenceInputV1, CommunityInitializationGraphV1,
    CommunityInitializationPlannerV1, CommunityInitializationRecordsV1, MemoryCommunityDomainV1,
};
use pos_store::memory::MemoryStore;
use pos_store::plugin_trust_registry::PluginTrustPolicyRegistryV1;
use pos_store::MemoryTrustedClockAuthorityV1;

/// The trust-root seal of the test composition.
const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();

type TestResult = Fallible<()>;

// ------------------------------------------------------------------ tests

/// I26 (planner part) and R6.7: every CAV1 row of a code-0 initialize.
#[test]
fn the_view_reads_every_row_from_the_domain() -> TestResult {
    let (store, _harness) = trusted_store(true)?;
    let policy = store.retained_policy_state(TRUST_SCOPE)?;
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    let profile = profile(&rows)?;
    let planner = planner(&SEAL, &profile)?;
    let mut world = World::new(
        &SEAL,
        store,
        TRUST_SCOPE,
        MemoryTrustedClockAuthorityV1::new(),
    )?;
    let admission = world.admit(planner.request())?;
    let again = world.admit(planner.request())?;
    let metadata = key(
        0x0b,
        CommunityArtifactPurposeV1::LifecycleControl,
        CommunityArtifactKindV1::LifecycleControl,
    )?;
    let cohort = key(
        0x0a,
        CommunityArtifactPurposeV1::ExecutionState,
        CommunityArtifactKindV1::StateContent,
    )?;
    let view = planner.current_view(
        &world.domain,
        &world.authority,
        GENERATION,
        &[&admission, &again],
        &[&metadata, &cohort],
    )?;
    assert_eq!(view.inventory_generation(), 0);
    let decoded = CommunityCurrentViewV1::from_canonical_cbor(view.view())?;
    assert_eq!(decoded.digest(), view.view_digest());
    let fields = decoded.as_input();
    assert_eq!(fields.store_incarnation, INCARNATION);
    assert_eq!(fields.timeline, target());
    assert_eq!(fields.generation, GENERATION);
    assert_eq!(fields.inventory_generation, 0);
    assert!(fields.frontier == CommunityPassFrontierV1::Initial);
    assert!(fields.selected_head.is_none());
    assert!(fields.scope_rows.is_empty());
    // Two decisions on one chain give one authority row.
    assert_eq!(fields.authority_rows.len(), 1);
    let authority = fields.authority_rows[0];
    assert_eq!(authority.authority_timeline, authority_timeline());
    assert_eq!(
        authority.head_seq,
        admission.request().at_position().as_u64()
    );
    assert_eq!(authority.revocation_epoch, 0);
    assert_eq!(authority.registry_digest, REGISTRY);
    assert_eq!(authority.capability_policy_revision, POLICY_REVISION);
    assert_eq!(authority.consent_policy_revision, CONSENT_REVISION);
    // Two members of one Plugin give one trust row.
    assert_eq!(fields.trust_rows.len(), 1);
    let trust = &fields.trust_rows[0];
    assert_eq!(trust.scope, TRUST_SCOPE);
    assert_eq!(trust.plugin_id, "plugin-a");
    assert_eq!(trust.policy_digest, Hash::from_bytes(policy.tps1_digest()));
    assert_eq!(
        trust.policy_floor,
        policy.ptr1_floor().map_or(0, |(floor, _)| floor)
    );
    assert_eq!(
        trust.release_floor,
        policy.prv1_floor().map_or(0, |(floor, _)| floor)
    );
    assert_eq!(
        trust.highest_trusted_utc_second,
        u64::try_from(policy.highest_trusted_utc_second().unwrap_or(0))?
    );
    assert_eq!(trust.active_manifest_digest, roster.pmf1);
    assert_eq!(
        trust.active_release_digest,
        Hash::from_bytes(release_one().release_digest()?)
    );
    // Key rows are in owner-text order, whatever order they came in.
    let keys: Vec<_> = fields.key_rows.iter().collect();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].owner, cohort.key_owner_text());
    assert_eq!(keys[1].owner, metadata.key_owner_text());
    for (row, intent) in keys.iter().zip([&cohort, &metadata]) {
        assert_eq!(row.role, KeyRoleV1::CommunityArtifactEncryption);
        assert_eq!(row.epoch, 1);
        assert!(row.state == CommunityKeyStateV1::Available);
        assert_eq!(row.key_intent_digest, intent.digest());
    }
    assert_eq!(fields.clock_latch.overrun_count, 0);
    assert!(!fields.clock_latch.latched);
    Ok(())
}

/// R6.5(4), decisions 10 and 11: no active release, or one whose PMF1 or
/// release differs from the member's, is `AdmissionDenied`; a missing
/// scope is 12.
#[test]
fn trust_rows_deny_or_refuse() -> TestResult {
    // (admit release_one, member PMF1, member release, CAP1 trust scope)
    let cases = [
        (false, None, None, TRUST_SCOPE, Error::AdmissionDenied),
        (
            true,
            Some(hash(0x99)),
            None,
            TRUST_SCOPE,
            Error::AdmissionDenied,
        ),
        (
            true,
            None,
            Some(hash(0x98)),
            TRUST_SCOPE,
            Error::AdmissionDenied,
        ),
        (true, None, None, "other-scope", Error::EvidenceUnavailable),
    ];
    for (admit, pmf1, release, scope, expected) in cases {
        let (store, _harness) = trusted_store(admit)?;
        let roster = Roster::new(&release_one(), pmf1, release)?;
        let rows = roster.rows()?;
        let profile = profile(&rows)?;
        let planner = planner(&SEAL, &profile)?;
        let mut world = World::new(&SEAL, store, scope, MemoryTrustedClockAuthorityV1::new())?;
        let admission = world.admit(planner.request())?;
        assert_eq!(
            planner
                .current_view(
                    &world.domain,
                    &world.authority,
                    GENERATION,
                    &[&admission],
                    &[]
                )
                .err(),
            Some(expected)
        );
    }
    Ok(())
}

/// Another domain, an unloadable chain and a clock with no latch row are 12.
#[test]
fn the_view_refuses_unavailable_evidence() -> TestResult {
    let (store, _harness) = trusted_store(true)?;
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    let profile = profile(&rows)?;
    let planner = planner(&SEAL, &profile)?;
    let clock = MemoryTrustedClockAuthorityV1::new();
    let mut world = World::new(&SEAL, store, TRUST_SCOPE, clock.handle())?;
    let admission = world.admit(planner.request())?;
    // A domain sharing the clock but holding no grant chain.
    let bare = MemoryCommunityDomainV1::new(MemoryStore::new(), INCARNATION, clock.handle())?;
    // A domain whose clock never reserved.
    let unlatched = MemoryCommunityDomainV1::new(
        MemoryStore::new(),
        INCARNATION,
        MemoryTrustedClockAuthorityV1::new(),
    )?;
    let foreign = MemoryCommunityDomainV1::new(
        MemoryStore::new(),
        [1; 16],
        MemoryTrustedClockAuthorityV1::new(),
    )?;
    for domain in [&bare, &unlatched, &foreign] {
        assert_eq!(
            planner
                .current_view(domain, &world.authority, GENERATION, &[&admission], &[])
                .err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    Ok(())
}

/// The facts one planned initialization's CAU1 is built from.
struct Operation<'a> {
    world: &'a mut World,
    planner: &'a CommunityInitializationPlannerV1<'a>,
    profile: &'a CommunityDurableProfileV1<'a>,
    roster: &'a Roster,
    call: &'a CommunityAuthorityCallV1,
    admission: &'a CommunityAuthorityAdmissionV1,
    records: &'a CommunityInitializationRecordsV1,
    graph: &'a CommunityInitializationGraphV1,
    input: CommunityInitializationEvidenceInputV1<'a>,
}

impl Operation<'_> {
    /// The caller form of a code-0 initialize of `profile` under `operation_id`.
    fn initialize(
        profile: &CommunityDurableProfileV1<'_>,
        operation_id: [u8; 16],
    ) -> CommunityAdministrativeOperationV1 {
        CommunityAdministrativeOperationV1::Initialize {
            timeline: target(),
            operation_id,
            initial_source: Source::Initializer(community_initializer_set_ref_v1(profile)),
            expected_prior_generation: None,
            expected_prior_head_digest: None,
        }
    }
}

/// Plan, view and assemble one initialization, then run `check` on it.
fn with_operation(check: impl FnOnce(Operation<'_>) -> TestResult) -> TestResult {
    let (store, _harness) = trusted_store(true)?;
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    let profile = profile(&rows)?;
    let planner = planner(&SEAL, &profile)?;
    let mut world = World::new(
        &SEAL,
        store,
        TRUST_SCOPE,
        MemoryTrustedClockAuthorityV1::new(),
    )?;
    let (call, admission) = world.call_and_admit(planner.request(), LEAVES[0])?;
    let records = planner.records(GENERATION, &admission, &ADDRESSES)?;
    let view = planner.current_view(
        &world.domain,
        &world.authority,
        GENERATION,
        &[&admission, &admission],
        &[],
    )?;
    let graph = graph(&SEAL, &planner, &profile, &roster, &records, GENERATION)?;
    let input = CommunityInitializationEvidenceInputV1 {
        call: &call,
        records: &records,
        view: &view,
        graph: &graph,
    };
    check(Operation {
        world: &mut world,
        planner: &planner,
        profile: &profile,
        roster: &roster,
        call: &call,
        admission: &admission,
        records: &records,
        graph: &graph,
        input,
    })
}

/// R6.6 and A5.3(4): CAU1 binds the CGI1, every protected record, the
/// CAV1, the call's decisions, the recipient (G6) and the clock bound (G1).
#[test]
fn the_authority_evidence_binds_the_whole_operation() -> TestResult {
    with_operation(|operation| {
        let Operation {
            world,
            planner,
            call,
            admission,
            records,
            graph,
            input,
            ..
        } = operation;
        let view = input.view;
        let evidence = planner.authority_evidence(&world.authority, GENERATION, input)?;
        assert_eq!(evidence.inventory_generation(), 0);
        let decoded = CommunityAuthorityEvidenceV1::from_canonical_cbor(evidence.evidence())?;
        assert_eq!(decoded.digest(), evidence.evidence_digest());
        let fields = decoded.as_input();
        assert_eq!(fields.store_incarnation, INCARNATION);
        assert_eq!(fields.timeline, target());
        assert_eq!(fields.generation, GENERATION);
        assert!(fields.operation == CommunityArtifactOperationV1::Initialization(OPERATION));
        assert_eq!(fields.input_identity, records.request_digest());
        let mut objects: Vec<(Hash, Hash, Hash)> = graph
            .records()
            .iter()
            .map(|record| {
                let protected = record.protected();
                (
                    protected.object_address(),
                    protected.registration().fields().artifact_digest,
                    protected.registration().address(),
                )
            })
            .collect();
        objects.sort_unstable();
        assert_eq!(objects.len(), 10);
        assert_eq!(
            fields
                .object_bindings
                .iter()
                .map(|row| (
                    row.object_address,
                    row.artifact_digest,
                    row.registration_address
                ))
                .collect::<Vec<_>>(),
            objects
        );
        assert_eq!(fields.inventory_generation, 0);
        assert_eq!(fields.current_premise_digest, view.view_digest());
        // The decision given twice is one row.
        assert_eq!(fields.decision_rows.len(), 1);
        let row = fields.decision_rows[0];
        let request = admission.request();
        assert_eq!(
            row.decision_digest,
            Hash::from_bytes(admission.authorization_ref().digest)
        );
        assert_eq!(row.request_digest, request.binding_digest());
        assert_eq!(row.leaf_grant_id, LEAVES[0]);
        assert_eq!(row.authority_timeline, authority_timeline());
        assert_eq!(row.head_seq, request.at_position().as_u64());
        assert_eq!(row.revocation_epoch, 0);
        assert_eq!(row.policy_revision, POLICY_REVISION);
        assert_eq!(
            fields.recipient_identity_digest,
            adr_h(
                "RecipientIdentity",
                &encode(&Value::Text(RECIPIENT.into()))?
            )
        );
        assert_eq!(fields.clock_bound.reservation_id, call.reservation_id());
        assert_eq!(fields.clock_bound.reservation_sample_micros, NOW);
        assert_eq!(
            fields.clock_bound.decision_bound_micros,
            call.decision_bound().as_micros()
        );
        assert_eq!(fields.evidence_not_after_micros, HORIZON);

        Ok(())
    })
}

/// M4: the CAU1 inputs must belong together. A call of another request,
/// a graph of another CGI1, a view of another Timeline or generation, and a
/// view without the CGI1's administrative decision each refuse.
#[test]
fn the_authority_evidence_refuses_inputs_that_do_not_belong_together() -> TestResult {
    with_operation(|operation| {
        let Operation {
            world,
            planner,
            profile,
            roster,
            admission,
            input,
            ..
        } = operation;
        let (other, _) = world.call_and_admit(
            Request::derive(&Operation::initialize(profile, [0x11; 16]))?,
            LEAVES[0],
        )?;
        let other_records = planner.records(OTHER_GENERATION, admission, &ADDRESSES)?;
        let other_graph = graph(
            &SEAL,
            planner,
            profile,
            roster,
            &other_records,
            OTHER_GENERATION,
        )?;
        let elsewhere = planner_at(&SEAL, profile, other_timeline())?;
        let other_view = elsewhere.current_view(
            &world.domain,
            &world.authority,
            GENERATION,
            &[admission],
            &[],
        )?;
        let undecided =
            planner.current_view(&world.domain, &world.authority, GENERATION, &[], &[])?;
        for (generation, input) in [
            (
                GENERATION,
                CommunityInitializationEvidenceInputV1 {
                    call: &other,
                    ..input
                },
            ),
            (
                GENERATION,
                CommunityInitializationEvidenceInputV1 {
                    graph: &other_graph,
                    ..input
                },
            ),
            (
                GENERATION,
                CommunityInitializationEvidenceInputV1 {
                    view: &other_view,
                    ..input
                },
            ),
            (OTHER_GENERATION, input),
            (
                GENERATION,
                CommunityInitializationEvidenceInputV1 {
                    view: &undecided,
                    ..input
                },
            ),
        ] {
            assert_eq!(
                planner
                    .authority_evidence(&world.authority, generation, input)
                    .err(),
                Some(Error::InvalidBinding)
            );
        }
        Ok(())
    })
}

/// ADR-128 §3: one COA1 per protected record, binding the CAU1.
#[test]
fn every_protected_record_gets_its_coa1() -> TestResult {
    with_operation(|operation| {
        let Operation {
            world,
            planner,
            records,
            graph,
            input,
            ..
        } = operation;
        let evidence = planner.authority_evidence(&world.authority, GENERATION, input)?;
        let admissions = planner.admissions(graph, &evidence)?;
        assert_eq!(admissions.len(), graph.records().len());
        let owner = planner.bindings(GENERATION)?.owner_binding_digest();
        for (admission, record) in admissions.iter().zip(graph.records()) {
            let fields = admission.as_input();
            let protected = record.protected();
            assert_eq!(fields.protected_object_address, protected.object_address());
            assert_eq!(
                fields.artifact_digest,
                protected.registration().fields().artifact_digest
            );
            assert_eq!(
                fields.registration_address,
                protected.registration().address()
            );
            assert_eq!(fields.owner_binding_digest, owner);
            assert_eq!(fields.scope_cover_digest, records.scope_binding_digest());
            assert_eq!(fields.evidence_not_after_micros, HORIZON);
            assert_eq!(fields.admission_inventory_generation, 0);
            assert_eq!(fields.authority_evidence_digest, evidence.evidence_digest());
        }
        Ok(())
    })
}

/// Note 22661, item 7: one CMI1 per protected record, each naming its own
/// record's COA1; a COA1 list of another length is refused.
#[test]
fn every_protected_record_gets_its_cmi1() -> TestResult {
    with_operation(|operation| {
        let Operation {
            world,
            planner,
            graph,
            input,
            ..
        } = operation;
        let evidence = planner.authority_evidence(&world.authority, GENERATION, input)?;
        let admissions = planner.admissions(graph, &evidence)?;
        let materializations = planner.materializations(GENERATION, graph, &admissions)?;
        assert_eq!(materializations.len(), graph.records().len());
        for ((bytes, admission), record) in materializations
            .iter()
            .zip(&admissions)
            .zip(graph.records())
        {
            let materialization = CommunityMaterializationV1::from_canonical_cbor(bytes)?;
            let fields = materialization.as_input();
            assert_eq!(
                fields.materialization.attestation_address,
                admission.digest()
            );
            assert_eq!(
                fields.materialization.object_address,
                record.protected().object_address()
            );
            assert_eq!(fields.record_magic, record.record_magic());
            assert_eq!(fields.timeline, target());
            assert_eq!(fields.generation, GENERATION);
        }
        assert_eq!(
            planner
                .materializations(GENERATION, graph, &admissions[1..])
                .err(),
            Some(Error::InvalidBinding)
        );
        Ok(())
    })
}

/// R6.7: a latched clock is read as latched with its overrun count, and an
/// out-of-range latch row is 12.
#[test]
fn the_view_reads_the_clock_latch() -> TestResult {
    let (store, _harness) = trusted_store(true)?;
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    let profile = profile(&rows)?;
    let planner = planner(&SEAL, &profile)?;
    let clock = MemoryTrustedClockAuthorityV1::new();
    let mut world = World::new(&SEAL, store, TRUST_SCOPE, clock.handle())?;
    let admission = world.admit(planner.request())?;
    let write = |overrun_count: i64| -> TestResult {
        let mut port = clock.handle();
        let port_error = |error| format!("trusted-clock port: {error:?}");
        port.begin_immediate(std::time::Duration::ZERO)
            .map_err(port_error)?;
        port.write_overrun_latch(&TrustedClockOverrunLatchRowV1 {
            latched: 1,
            overrun_count,
            last_overrun_reservation: 1,
            last_overrun_kind: 1,
            last_overrun_at_micros: 1,
            ..TrustedClockOverrunLatchRowV1::UNLATCHED
        })
        .map_err(port_error)?;
        port.commit().map_err(port_error)?;
        Ok(())
    };
    write(3)?;
    let view = planner.current_view(
        &world.domain,
        &world.authority,
        GENERATION,
        &[&admission],
        &[],
    )?;
    let decoded = CommunityCurrentViewV1::from_canonical_cbor(view.view())?;
    assert_eq!(decoded.as_input().clock_latch.overrun_count, 3);
    assert!(decoded.as_input().clock_latch.latched);
    write(-1)?;
    assert_eq!(
        planner
            .current_view(
                &world.domain,
                &world.authority,
                GENERATION,
                &[&admission],
                &[]
            )
            .err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// Two different chains at one `(T, head, epoch)` and a repeated key are
/// refused by the view's strict row order.
#[test]
fn the_view_refuses_rows_that_collide() -> TestResult {
    let (store, _harness) = trusted_store(true)?;
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    let profile = profile(&rows)?;
    let planner = planner(&SEAL, &profile)?;
    let mut world = World::new(
        &SEAL,
        store,
        TRUST_SCOPE,
        MemoryTrustedClockAuthorityV1::new(),
    )?;
    let first = world.admit(planner.request())?;
    let (_, second) = world.call_and_admit(planner.request(), LEAVES[1])?;
    let key = key(
        0x0b,
        CommunityArtifactPurposeV1::LifecycleControl,
        CommunityArtifactKindV1::LifecycleControl,
    )?;
    for (decisions, keys) in [
        (vec![&first, &second], vec![]),
        (vec![&first], vec![&key, &key]),
    ] {
        assert_eq!(
            planner
                .current_view(
                    &world.domain,
                    &world.authority,
                    GENERATION,
                    &decisions,
                    &keys
                )
                .err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

/// L3 soundness: the quoted CPN1 bytes bound the real graph's CPN1s. With
/// the commit's real producer ordinal 7 instead of the widest one, each
/// member's two CPN1s are exactly 24 bytes shorter: 8 in each node's
/// producer ordinal and 8 in the `StateRevision` node's native input.
#[test]
fn the_quoted_node_bytes_bound_the_real_graph() -> TestResult {
    with_operation(|operation| {
        let Operation {
            world,
            planner,
            records,
            graph,
            input,
            ..
        } = operation;
        let evidence = planner.authority_evidence(&world.authority, GENERATION, input)?;
        let admissions = planner.admissions(graph, &evidence)?;
        let materializations = planner.materializations(GENERATION, graph, &admissions)?;
        let mut actual = [0_u64; 2];
        for (index, bytes) in materializations.iter().enumerate() {
            let materialization = CommunityMaterializationV1::from_canonical_cbor(bytes)?;
            if materialization.as_input().record_magic == *b"CPN1" {
                actual[index / 5] += materialization.as_input().plaintext_length;
            }
        }
        let quote = pos_core::community_lifecycle::CommunityBudgetQuoteV1::from_canonical_cbor(
            records.budget_quote(),
        )?;
        let fixed: u64 = STATE_LIMITS.iter().map(|limit| limit + 1_024 + 512).sum();
        let quoted = quote.as_input().maximum_required_bytes - fixed;
        for member in actual {
            assert!(member > 0);
        }
        assert_eq!(quoted, actual[0] + actual[1] + 2 * 24);
        Ok(())
    })
}
