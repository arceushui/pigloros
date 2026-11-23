//! The R10.4(5) installation check of a CDP1 through its public seam
//! (ADR-129 revision 10, R10.4(5); revision 11, R11.5(3) and R11.6; I101,
//! I118 and I122).

use pos_core::community_lifecycle::{
    check_community_pass_installation_v1, ArtifactRefV1, CommunityDurableBackendV1,
    CommunityDurableProfileInputV1, CommunityDurableProfileV1, CommunityGraphCountsV1,
    CommunityLifecycleErrorV1 as Error, CommunityPassTermsV1, CommunityProfileMemberV1,
    CommunityProfileRetentionV1,
};
use pos_core::{Hash, ImplementationKeyV1};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const MIB: u64 = 1 << 20;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn roster<'a>(
    key: &'a ImplementationKeyV1,
    entries: &'a [String],
) -> Fallible<Vec<CommunityProfileMemberV1<'a>>> {
    entries
        .iter()
        .map(|entry| {
            Ok(CommunityProfileMemberV1::new(
                entry,
                key,
                hash(4),
                hash(5),
                hash(6),
                ArtifactRefV1 {
                    schema_id: 7,
                    byte_length: 8,
                    digest: [9; 32],
                },
                10,
            )?)
        })
        .collect()
}

fn profile<'a>(
    roster: &'a [CommunityProfileMemberV1<'a>],
) -> Fallible<CommunityDurableProfileV1<'a>> {
    Ok(CommunityDurableProfileV1::new(
        CommunityDurableProfileInputV1 {
            backend: CommunityDurableBackendV1::RetainedMemory,
            execution_profile_digest: hash(1),
            roster,
            source_catalogue_digest: hash(2),
            authority_catalogue_digest: hash(3),
            retention: CommunityProfileRetentionV1 {
                generation_not_after_micros: 12,
                recovery_window_micros: 13,
                quarantine_not_after_micros: 14,
                metadata_not_after_micros: 15,
                recording_not_after_micros: 16,
            },
        },
    )?)
}

#[test]
fn the_minimum_required_pass_of_every_admissible_roster_fits() -> TestResult {
    let key = ImplementationKeyV1::new("plugin-a".into(), "host-v1".into(), hash(11))?;
    let mut observed = Vec::new();
    for members in [1_u64, 9] {
        let entries: Vec<String> = (0..members).map(|index| format!("entry-{index}")).collect();
        let rows = roster(&key, &entries)?;
        let profile = profile(&rows)?;
        let limits = vec![MIB; entries.len()];
        let installed = check_community_pass_installation_v1(&profile, &limits)?;
        let [state, total] = installed.quote;
        // Per member: the step and its StateRevision, the step's two inputs
        // and the revision's one; the empty-cut observation adds one node
        // and one edge; the recording one Measurement node and edge each.
        assert_eq!(
            (state.nodes, state.edges),
            (2 * members + 1, 3 * members + 1)
        );
        assert_eq!(
            (total.nodes, total.edges),
            (3 * members + 1, 4 * members + 1)
        );
        let [graph, replay] = installed.demand.graph();
        // Initialization 5n/6n, the pass 7n and (2 + 9)n, the observation 2
        // registrations and 1 edge (R11.6).
        assert_eq!(graph.registrations, 12 * members + 2);
        assert_eq!(graph.edges, 17 * members + 1);
        assert_eq!((graph.keys, graph.maximum_depth), (4, 6));
        assert_eq!(replay.registrations, graph.registrations + 1 + 2 * members);
        assert_eq!(replay.edges, graph.edges + 4 * members);
        assert_eq!((replay.keys, replay.maximum_depth), (6, 7));
        assert_eq!(installed.demand.keys(), [7, 8]);
        assert_eq!(
            installed.demand.objects(),
            [7 * members + 2, 9 * members + 3]
        );
        observed.push((state.bytes, total.bytes, graph, replay));
    }
    // The byte columns, pinned: every term is a fixed widest width or S_m.
    let pinned: Vec<(u64, u64, u64, u64, u64, u64)> = observed
        .iter()
        .map(
            |(state, total, graph, replay): &(
                u64,
                u64,
                CommunityGraphCountsV1,
                CommunityGraphCountsV1,
            )| {
                (
                    *state,
                    *total,
                    graph.registration_bytes,
                    graph.artifact_bytes,
                    replay.registration_bytes,
                    replay.artifact_bytes,
                )
            },
        )
        .collect();
    assert_eq!(pinned, PINNED);
    Ok(())
}

/// `(CBQ1 State bytes, CBQ1 total bytes, CGR1 registration bytes, CGR1
/// artifact bytes, Replay registration bytes, Replay artifact bytes)` for one
/// and nine members at 1 MiB.
const PINNED: [(u64, u64, u64, u64, u64, u64); 2] = [
    (2_113_254, 2_114_133, 4568, 3_163_758, 5557, 3_167_554),
    (
        18_906_438, 18_913_781, 36_784, 28_455_934, 43_805, 28_482_515,
    ),
];

#[test]
fn state_limits_must_cover_the_roster_within_one_mib() -> TestResult {
    let key = ImplementationKeyV1::new("plugin-a".into(), "host-v1".into(), hash(11))?;
    let entries = vec!["entry-a".to_owned(), "entry-b".to_owned()];
    let rows = roster(&key, &entries)?;
    let profile = profile(&rows)?;
    assert_eq!(
        check_community_pass_installation_v1(&profile, &[MIB]).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        check_community_pass_installation_v1(&profile, &[MIB, MIB + 1]).err(),
        Some(Error::BoundsExceeded)
    );
    let installed = check_community_pass_installation_v1(&profile, &[0, MIB])?;
    let [state, _] = installed.quote;
    assert!(state.bytes > MIB);
    let _: CommunityPassTermsV1 = state;
    Ok(())
}
