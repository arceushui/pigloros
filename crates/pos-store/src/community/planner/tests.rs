//! Planner reads a real domain cannot produce, through a fake store domain
//! that delegates to a real Memory domain and overrides one seam answer: a
//! negative trusted UTC second, a missing scope beside an absent release,
//! several Plugins with distinct floors, a non-zero inventory generation,
//! chains on several authority Timelines and a moved chain head or epoch.

use pos_core::community_lifecycle::{
    CommunityAuthorityEvidenceV1, CommunityAuthorityViewRowV1, CommunityClockLatchV1,
    CommunityCurrentViewV1, CommunityLifecycleErrorV1 as Error, CommunityProfileMemberV1,
};
use pos_core::trusted_clock::{
    GuardMonotonicSourceV1, TrustedClockReservationV1, TrustedWallSourceV1,
};
use pos_core::{
    AuthorityTrustRootSealV1, AuthorizationRequestV1, EventId, Hash, ImplementationKeyV1,
    PersistedAuthorityV1, SchemaVersion, Seq, TimelineId,
};
use ulid::Ulid;

use super::super::store_domain::CommunityStoreDomainV1;
use super::{CommunityInitializationEvidenceInputV1, CommunityInitializationPlannerV1};
use crate::community::MemoryCommunityDomainV1;
use crate::community_initialization_fixture::{
    graph, planner, profile, trusted_store, Fallible, Roster, World, ADDRESSES, GENERATION, LEAVES,
    TRUST_SCOPE,
};
use crate::plugin_trust_registry::{
    ActivationEventIdentityV1, ActiveReleaseV1, RetainedPolicyStateV1,
};
use crate::MemoryTrustedClockAuthorityV1;

/// The trust-root seal of the test composition.
const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();

type TestResult = Fallible<()>;

/// One overridden authority row: the leaf's Timeline and the shifts of its
/// head and epoch from the evaluated request.
type RowOverride = fn(Hash) -> (TimelineId, u64, u64);

/// A store domain that answers from `inner` unless a field overrides it.
struct Fake<'a> {
    inner: &'a MemoryCommunityDomainV1,
    inventory_generation: u64,
    policy: Option<Result<RetainedPolicyStateV1, Error>>,
    actives: Option<Vec<(String, Option<ActiveReleaseV1>)>>,
    rows: Option<RowOverride>,
}

impl<'a> Fake<'a> {
    const fn new(inner: &'a MemoryCommunityDomainV1) -> Self {
        Self {
            inner,
            inventory_generation: 0,
            policy: None,
            actives: None,
            rows: None,
        }
    }
}

impl CommunityStoreDomainV1 for Fake<'_> {
    fn store_incarnation(&self) -> [u8; 16] {
        self.inner.store_incarnation()
    }

    fn load_authority(&self, leaf_grant_id: Hash) -> Result<PersistedAuthorityV1, Error> {
        self.inner.load_authority(leaf_grant_id)
    }

    fn reserve_clock(
        &mut self,
        _wall: &mut dyn TrustedWallSourceV1,
        _mono: &mut dyn GuardMonotonicSourceV1,
    ) -> Result<TrustedClockReservationV1, Error> {
        Err(Error::EvidenceUnavailable)
    }

    fn inventory_generation(&self) -> u64 {
        self.inventory_generation
    }

    fn clock_latch(&self) -> Result<CommunityClockLatchV1, Error> {
        self.inner.clock_latch()
    }

    fn plugin_trust_policy(&self, scope: &str) -> Result<RetainedPolicyStateV1, Error> {
        self.policy
            .clone()
            .unwrap_or_else(|| self.inner.plugin_trust_policy(scope))
    }

    fn active_release(
        &self,
        scope: &str,
        plugin_id: &str,
    ) -> Result<Option<ActiveReleaseV1>, Error> {
        self.actives.as_ref().map_or_else(
            || self.inner.active_release(scope, plugin_id),
            |actives| {
                Ok(actives
                    .iter()
                    .find(|(id, _)| id == plugin_id)
                    .and_then(|(_, active)| active.clone()))
            },
        )
    }

    fn authority_row(
        &self,
        leaf_grant_id: Hash,
        pins: &AuthorizationRequestV1,
    ) -> Result<CommunityAuthorityViewRowV1, Error> {
        self.inner.authority_row(leaf_grant_id, pins).map(|row| {
            self.rows.map_or(row, |shift| {
                let (timeline, head, epoch) = shift(leaf_grant_id);
                CommunityAuthorityViewRowV1 {
                    authority_timeline: timeline,
                    head_seq: row.head_seq + head,
                    revocation_epoch: row.revocation_epoch + epoch,
                    ..row
                }
            })
        })
    }
}

fn policy(utc: Option<i64>) -> RetainedPolicyStateV1 {
    RetainedPolicyStateV1 {
        scope: TRUST_SCOPE.to_owned(),
        tps1_epoch: 1,
        tps1_digest: [0x31; 32],
        tps1_effective_position: 1,
        tps1_bytes: vec![],
        ptr1_floor: Some((5, [0x32; 32])),
        prv1_floor: Some((9, [0x33; 32])),
        highest_trusted_utc_second: utc,
    }
}

fn active(implementation: &ImplementationKeyV1, pmf1: Hash) -> ActiveReleaseV1 {
    ActiveReleaseV1 {
        scope: TRUST_SCOPE.to_owned(),
        plugin_id: implementation.plugin_id().to_owned(),
        pmf1_digest: *pmf1.as_bytes(),
        release_digest: *implementation.release_digest().as_bytes(),
        activation_event: ActivationEventIdentityV1 {
            timeline: TimelineId::from_ulid(Ulid::from_bytes([3; 16])),
            event_id: EventId::from_ulid(Ulid::from_bytes([4; 16])),
            seq: Seq::from_u64(1),
            event_type: "plugin.activated".to_owned(),
            schema_version: SchemaVersion::V1,
            payload_digest: [5; 32],
            origin_logical_seq: None,
        },
    }
}

/// M1 and decision 10: a negative trusted UTC second is 12, and a missing
/// scope is 12 even where every release is absent (which alone is 10).
#[test]
fn trust_reads_refuse_before_any_denial() -> TestResult {
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
    let admission = world.admit(planner.request())?;
    for (policy, actives, expected) in [
        (Ok(policy(Some(-1))), None, Error::EvidenceUnavailable),
        (
            Err(Error::EvidenceUnavailable),
            Some(vec![]),
            Error::EvidenceUnavailable,
        ),
        (Ok(policy(Some(1))), Some(vec![]), Error::AdmissionDenied),
    ] {
        let fake = Fake {
            policy: Some(policy),
            actives,
            ..Fake::new(&world.domain)
        };
        assert_eq!(
            planner
                .current_view(&fake, &world.authority, GENERATION, &[&admission], &[])
                .err(),
            Some(expected)
        );
    }
    Ok(())
}

/// Decision 11 with two Plugins whose IDs sort opposite to roster order:
/// one row per Plugin in ID order, with the scope's distinct floors and UTC
/// second; a Plugin absent from the registry is 10.
#[test]
fn trust_rows_follow_plugin_order_with_the_scope_floors() -> TestResult {
    let (store, _harness) = trusted_store(true)?;
    let roster = Roster::release_one()?;
    let implementations = [
        ImplementationKeyV1::new(
            "plugin-z".into(),
            "host-v1".into(),
            Hash::from_bytes([0x41; 32]),
        )?,
        ImplementationKeyV1::new(
            "plugin-b".into(),
            "host-v1".into(),
            Hash::from_bytes([0x42; 32]),
        )?,
    ];
    let pmf1 = [Hash::from_bytes([0x51; 32]), Hash::from_bytes([0x52; 32])];
    let rows = ["Entry-A_1", "Entry-B_1"]
        .iter()
        .zip(&implementations)
        .zip(pmf1)
        .map(|((entry, implementation), pmf1)| {
            Ok(CommunityProfileMemberV1::new(
                entry,
                implementation,
                pmf1,
                crate::community_initialization_fixture::SCHEMA,
                Hash::from_bytes([6; 32]),
                roster.initializer(),
            )?)
        })
        .collect::<Fallible<Vec<_>>>()?;
    let profile = profile(&rows)?;
    let planner = planner(&SEAL, &profile)?;
    let mut world = World::new(
        &SEAL,
        store,
        TRUST_SCOPE,
        MemoryTrustedClockAuthorityV1::new(),
    )?;
    let admission = world.admit(planner.request())?;
    let actives = vec![
        (
            "plugin-z".to_owned(),
            Some(active(&implementations[0], pmf1[0])),
        ),
        (
            "plugin-b".to_owned(),
            Some(active(&implementations[1], pmf1[1])),
        ),
    ];
    let fake = Fake {
        policy: Some(Ok(policy(Some(42)))),
        actives: Some(actives.clone()),
        ..Fake::new(&world.domain)
    };
    let view = planner.current_view(&fake, &world.authority, GENERATION, &[&admission], &[])?;
    let decoded = CommunityCurrentViewV1::from_canonical_cbor(view.view())?;
    let trust = &decoded.as_input().trust_rows;
    assert_eq!(trust.len(), 2);
    for (row, index) in trust.iter().zip([1, 0]) {
        assert_eq!(row.scope, TRUST_SCOPE);
        assert_eq!(row.plugin_id, implementations[index].plugin_id());
        assert_eq!(row.policy_digest, Hash::from_bytes([0x31; 32]));
        assert_eq!(row.policy_floor, 5);
        assert_eq!(row.release_floor, 9);
        assert_eq!(row.highest_trusted_utc_second, 42);
        assert_eq!(row.active_manifest_digest, pmf1[index]);
        assert_eq!(
            row.active_release_digest,
            implementations[index].release_digest()
        );
    }
    let absent = Fake {
        policy: Some(Ok(policy(None))),
        actives: Some(actives[..1].to_vec()),
        ..Fake::new(&world.domain)
    };
    assert_eq!(
        planner
            .current_view(&absent, &world.authority, GENERATION, &[&admission], &[])
            .err(),
        Some(Error::AdmissionDenied)
    );
    Ok(())
}

/// G5 with a non-zero inventory generation: CAV1, CAU1 and every COA1 read
/// the domain's value, and so do both getters.
#[test]
fn a_non_zero_inventory_generation_flows_into_every_record() -> TestResult {
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
    let fake = Fake {
        inventory_generation: 7,
        ..Fake::new(&world.domain)
    };
    let view = planner.current_view(&fake, &world.authority, GENERATION, &[&admission], &[])?;
    assert_eq!(view.inventory_generation(), 7);
    let decoded = CommunityCurrentViewV1::from_canonical_cbor(view.view())?;
    assert_eq!(decoded.as_input().inventory_generation, 7);
    let graph = graph(&SEAL, &planner, &profile, &roster, &records, GENERATION)?;
    let evidence = planner.authority_evidence(
        &world.authority,
        GENERATION,
        CommunityInitializationEvidenceInputV1 {
            call: &call,
            records: &records,
            view: &view,
            graph: &graph,
        },
    )?;
    assert_eq!(evidence.inventory_generation(), 7);
    let cau1 = CommunityAuthorityEvidenceV1::from_canonical_cbor(evidence.evidence())?;
    assert_eq!(cau1.as_input().inventory_generation, 7);
    for admission in planner.admissions(&graph, &evidence)? {
        assert_eq!(admission.as_input().admission_inventory_generation, 7);
    }
    Ok(())
}

const fn low() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([0x20; 16]))
}

const fn high() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([0x30; 16]))
}

/// The first leaf on the higher Timeline, the second on the lower one.
fn two_timelines(leaf: Hash) -> (TimelineId, u64, u64) {
    (if leaf == LEAVES[0] { high() } else { low() }, 0, 0)
}

fn moved_head(_: Hash) -> (TimelineId, u64, u64) {
    (low(), 1, 0)
}

fn moved_epoch(_: Hash) -> (TimelineId, u64, u64) {
    (low(), 0, 1)
}

/// Authority rows of chains on two Timelines, supplied in reverse Timeline
/// order, come out in `(T, head, epoch)` order; the CAU1 decision rows of
/// the same decisions, a duplicate included, come out sorted and
/// deduplicated; and a chain whose head or epoch has moved is stale (12).
#[test]
fn authority_and_decision_rows_are_ordered_and_current() -> TestResult {
    let (store, _harness) = trusted_store(true)?;
    let roster = Roster::release_one()?;
    let rows = roster.rows()?;
    let profile = profile(&rows)?;
    let planner: CommunityInitializationPlannerV1<'_> = planner(&SEAL, &profile)?;
    let mut world = World::new(
        &SEAL,
        store,
        TRUST_SCOPE,
        MemoryTrustedClockAuthorityV1::new(),
    )?;
    let first = world.admit(planner.request())?;
    let (_, second) = world.call_and_admit(planner.request(), LEAVES[1])?;
    let fake = Fake {
        rows: Some(two_timelines),
        ..Fake::new(&world.domain)
    };
    let view = planner.current_view(
        &fake,
        &world.authority,
        GENERATION,
        &[&first, &second, &first],
        &[],
    )?;
    let decoded = CommunityCurrentViewV1::from_canonical_cbor(view.view())?;
    let timelines: Vec<TimelineId> = decoded
        .as_input()
        .authority_rows
        .iter()
        .map(|row| row.authority_timeline)
        .collect();
    assert_eq!(timelines, vec![low(), high()]);
    let mut digests = [
        Hash::from_bytes(first.authorization_ref().digest),
        Hash::from_bytes(second.authorization_ref().digest),
    ];
    digests.sort_unstable();
    assert_eq!(
        view.decision_rows
            .iter()
            .map(|row| row.decision_digest)
            .collect::<Vec<_>>(),
        digests
    );
    let reversed =
        planner.current_view(&fake, &world.authority, GENERATION, &[&second, &first], &[])?;
    assert_eq!(reversed.view_digest(), view.view_digest());
    assert!(reversed.decision_rows == view.decision_rows);
    for shift in [moved_head as RowOverride, moved_epoch] {
        let stale = Fake {
            rows: Some(shift),
            ..Fake::new(&world.domain)
        };
        assert_eq!(
            planner
                .current_view(&stale, &world.authority, GENERATION, &[&first], &[])
                .err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    Ok(())
}
