//! The installation checks' error propagation over synthetic domains that a
//! real minimum pass, with at most 9 members, cannot reach (R11.5(3)): each
//! check's 14 and 19 must reach the caller, in the R11.5(1) order.

use super::{check_minimum, CommunityPassDomainV1};
use crate::community_lifecycle::{
    ArtifactRefV1, CommunityGraphCountsV1, CommunityLifecycleErrorV1 as Error,
    CommunityLocatorProducerV1, CommunityMetadataLocatorV1, CommunityMetadataSchemaV1,
    CommunityPassGraphTermsV1, CommunityPassQuoteInputV1, CommunityPassQuoteMemberV1,
    CommunityPassQuoteV1, CommunityPreparedInvocationInputV1, CommunitySharedCountsV1,
    CommunityTypedInputRefV1, TimelinePositionV1, COMMUNITY_CUMULATIVE_RECORD_LIMITS_V1,
    COMMUNITY_MAXIMUM_STORE_KEYS_V1,
};
use crate::{Hash, TimelineId};

type Fallible<T> = core::result::Result<T, Box<dyn std::error::Error>>;

const G: [u8; 16] = [2; 16];

fn timeline() -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes([1; 16]))
}

const BASE: CommunityGraphCountsV1 = CommunityGraphCountsV1 {
    registrations: 10,
    edges: 10,
    keys: 2,
    maximum_depth: 3,
    registration_bytes: 1000,
    artifact_bytes: 2000,
};

const fn domain(selected: CommunityGraphCountsV1, live_keys: u64) -> CommunityPassDomainV1 {
    CommunityPassDomainV1 {
        selected_graph: selected,
        live_keys,
        observation_graph: CommunityPassGraphTermsV1 {
            registrations: 0,
            edges: 0,
            keys: 0,
            registration_bytes: 0,
            artifact_bytes: 0,
        },
        observation_keys: 0,
    }
}

fn invocation(member: Hash) -> CommunityPreparedInvocationInputV1<'static> {
    let reference = ArtifactRefV1 {
        schema_id: 1,
        byte_length: 2,
        digest: [3; 32],
    };
    CommunityPreparedInvocationInputV1 {
        member_binding_digest: member,
        invocation_id: [4; 16],
        timeline_position: TimelinePositionV1 {
            timeline_id: timeline().inner().to_bytes(),
            seq: 1,
            tick: 1,
            scheduler_position: 0,
        },
        output_base_ordinal: 2,
        principal_ref: reference,
        authorization_ref: reference,
        observation_snapshot_ref: reference,
        observation_bytes: &[],
        prior_state_schema_digest: [5; 32],
        prior_state_bytes: &[],
        execution_profile_digest: [6; 32],
        trust_policy_snapshot_digest: [7; 32],
        deterministic_budget_id: "budget-a",
        deterministic_random_domain: [8; 32],
        provenance_root: [9; 32],
        simulation_time: 1,
        watchdog_epochs: 0,
    }
}

fn metadata(slot: u16) -> CommunityTypedInputRefV1<'static> {
    CommunityTypedInputRefV1::Metadata {
        schema: CommunityMetadataSchemaV1::Cmb1,
        locator: CommunityMetadataLocatorV1 {
            timeline: timeline(),
            generation: G,
            producer: CommunityLocatorProducerV1::Control([5; 16]),
            record_role: 1,
            slot,
        },
        envelope_address: Hash::from_bytes([6; 32]),
        private_record_digest: Hash::from_bytes([7; 32]),
    }
}

/// A quote of `members` due members, the first `grouped` of them with 4,096
/// mode-3 inputs (16 groups, no ARD1 edges), over `prior` counts.
fn quote(
    members: u8,
    grouped: u8,
    inputs: &[CommunityTypedInputRefV1<'static>],
    prior: CommunitySharedCountsV1,
) -> Fallible<CommunityPassQuoteV1> {
    let rows: Vec<_> = (0..members)
        .map(|index| {
            let member = Hash::from_bytes([index + 1; 32]);
            CommunityPassQuoteMemberV1 {
                member_binding_digest: member,
                negotiated_tuple_digest: Hash::from_bytes([0xee; 32]),
                state_limit_bytes: 64,
                prepared_invocation: invocation(member),
                step_inputs: if index < grouped { inputs } else { &[] },
                consumes_minted_observation: false,
            }
        })
        .collect();
    Ok(CommunityPassQuoteV1::new(CommunityPassQuoteInputV1 {
        timeline: timeline(),
        generation: G,
        profile_digest: Hash::from_bytes([0xdd; 32]),
        prior_shared_counts: prior,
        members: &rows,
        minted_observation: None,
    })?)
}

#[test]
fn every_installation_check_refuses_with_its_own_14_and_19() -> Fallible<()> {
    let quote = quote(1, 0, &[], CommunitySharedCountsV1::default())?;
    let installed = check_minimum(&quote, domain(BASE, 0))?;
    assert_eq!(installed.quote, [quote.state_terms(), quote.total_terms()]);
    // The CBQ1, through its cumulative node limit.
    let [nodes, _, _] = COMMUNITY_CUMULATIVE_RECORD_LIMITS_V1;
    let spare = nodes - quote.total_terms().nodes;
    for (slack, expected) in [
        (1, Error::RecordingUnavailable),
        (2, Error::CapacityExhausted),
    ] {
        let prior = CommunitySharedCountsV1 {
            nodes: spare + slack,
            ..CommunitySharedCountsV1::default()
        };
        let over = self::quote(1, 0, &[], prior)?;
        assert_eq!(check_minimum(&over, domain(BASE, 0)).err(), Some(expected));
    }
    // The keys.
    let [state_keys, _] = installed.demand.keys();
    let free = COMMUNITY_MAXIMUM_STORE_KEYS_V1 - state_keys;
    assert_eq!(
        check_minimum(&quote, domain(BASE, free)).err(),
        Some(Error::RecordingUnavailable)
    );
    assert_eq!(
        check_minimum(&quote, domain(BASE, free + 1)).err(),
        Some(Error::CapacityExhausted)
    );
    // The graph, through its depth.
    for (depth, expected) in [
        (4093, Error::RecordingUnavailable),
        (4094, Error::CapacityExhausted),
    ] {
        let deep = CommunityGraphCountsV1 {
            maximum_depth: depth,
            ..BASE
        };
        assert_eq!(check_minimum(&quote, domain(deep, 0)).err(), Some(expected));
    }
    Ok(())
}

#[test]
fn the_object_bound_is_the_last_installation_check() -> Fallible<()> {
    let inputs: Vec<_> = (0..4096).map(metadata).collect();
    // 64 x 7 + 2 x 16 x 48 + 2 = 1,986 objects, 2,115 with the recording.
    let recording = quote(64, 48, &inputs, CommunitySharedCountsV1::default())?;
    assert_eq!(
        check_minimum(&recording, domain(BASE, 0)).err(),
        Some(Error::RecordingUnavailable)
    );
    // 64 x 7 + 2 x 16 x 50 + 2 = 2,050 objects.
    let state = quote(64, 50, &inputs, CommunitySharedCountsV1::default())?;
    assert_eq!(
        check_minimum(&state, domain(BASE, 0)).err(),
        Some(Error::CapacityExhausted)
    );
    Ok(())
}
