use pos_core::{
    check_manifest_policy_seeds_v1, ArtifactDataClassV1, ArtifactOptionalityV1,
    ArtifactTransitionRuleV1, CanonicalBytes, Hash, ManifestOwnerLinkErrorV1,
    ManifestPolicyLeafExpectationV1, ManifestPolicySeedV1, ManifestSlotBindingInputV1,
    ManifestSlotBindingRowV1, ManifestSlotBindingV1, PluginId, WorldArtifactErrorV1,
    WorldArtifactKindV1, WorldArtifactLeafInputV1, WorldArtifactLeafV1, WorldClosureReadLimitsV1,
    WorldDependencyBranchV1, WorldDependencyDirectoryErrorV1, WorldDependencyDirectoryV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SCOPE: Hash = Hash::from_bytes([0x51; 32]);
const LEASE: Hash = Hash::from_bytes([0x52; 32]);
const OWNER: [u8; 32] = [0x53; 32];
const LEAF_DOMAIN: &[u8] = b"pigloros.world-evidence.artifact-leaf.v1\0";
const BRANCH_DOMAIN: &[u8] = b"pigloros.world-evidence.dependency-branch.v1\0";

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn indexed(tag: u8, index: u16) -> Hash {
    let mut bytes = [tag; 32];
    bytes[30..].copy_from_slice(&index.to_be_bytes());
    Hash::from_bytes(bytes)
}

fn plugin(index: u16) -> PluginId {
    let mut bytes = [7; 16];
    bytes[14..].copy_from_slice(&index.to_be_bytes());
    PluginId::from_ulid(ulid::Ulid::from_bytes(bytes))
}

const fn expectation() -> ManifestPolicyLeafExpectationV1 {
    ManifestPolicyLeafExpectationV1 {
        source_lease_hash: LEASE,
        owner: OWNER,
        data_class: ArtifactDataClassV1::ConsentedSharedData,
        transition: ArtifactTransitionRuleV1::PreserveExact,
    }
}

const fn limits(
    max_node_visits: u64,
    max_native_bytes: u64,
    max_combined_depth: u8,
) -> WorldClosureReadLimitsV1 {
    WorldClosureReadLimitsV1 {
        max_node_visits,
        max_native_bytes,
        max_combined_depth,
    }
}

const fn generous() -> WorldClosureReadLimitsV1 {
    limits(1_000_000, u64::MAX, 32)
}

const fn leaf_input(
    kind: WorldArtifactKindV1,
    native_digest: Hash,
    native_byte_length: u64,
) -> WorldArtifactLeafInputV1 {
    WorldArtifactLeafInputV1 {
        scope: SCOPE,
        kind,
        native_digest,
        native_byte_length,
        owner: OWNER,
        data_class: ArtifactDataClassV1::ConsentedSharedData,
        optionality: ArtifactOptionalityV1::Required,
        transition: ArtifactTransitionRuleV1::PreserveExact,
        source_lease_hash: LEASE,
        key_dependencies: Vec::new(),
        child_node_hashes: Vec::new(),
    }
}

fn leaf(
    kind: WorldArtifactKindV1,
    native_digest: Hash,
    native_byte_length: u64,
) -> Result<WorldArtifactLeafV1, WorldArtifactErrorV1> {
    WorldArtifactLeafV1::new(leaf_input(kind, native_digest, native_byte_length))
}

// Native digests descend as row indexes ascend, so canonical directory order
// is never the MSB1 row order.
fn seed(index: u16) -> Result<ManifestPolicySeedV1, WorldArtifactErrorV1> {
    let reversed = u16::MAX - index;
    Ok(ManifestPolicySeedV1 {
        plugin_id: plugin(index),
        eop1_leaf: leaf(
            WorldArtifactKindV1::OutputPolicy,
            indexed(0x10, reversed),
            100 + u64::from(index),
        )?,
        opc1_leaf: leaf(
            WorldArtifactKindV1::OutputPolicyClosure,
            indexed(0x20, reversed),
            200 + u64::from(index),
        )?,
    })
}

fn seed_range(
    indexes: std::ops::Range<u16>,
) -> Result<Vec<ManifestPolicySeedV1>, WorldArtifactErrorV1> {
    indexes.map(seed).collect()
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn leaf_hash(leaf: &WorldArtifactLeafV1) -> Hash {
    domain_hash(LEAF_DOMAIN, &leaf.to_canonical_cbor())
}

fn binding_for(
    seeds: &[ManifestPolicySeedV1],
) -> Result<ManifestSlotBindingV1, ManifestOwnerLinkErrorV1> {
    ManifestSlotBindingV1::new(ManifestSlotBindingInputV1 {
        scope: SCOPE,
        wcs1_hash: hash(0x54),
        rows: seeds
            .iter()
            .enumerate()
            .map(|(index, seed)| ManifestSlotBindingRowV1 {
                stable_slot: format!("slot-{index:03}"),
                plugin_id: seed.plugin_id,
                eop1_wal1_hash: leaf_hash(&seed.eop1_leaf),
                closure_hash: seed.opc1_leaf.as_input().native_digest,
            })
            .collect(),
    })
}

// Independent preferred-CBOR WDB1 oracle; it shares no production encoder.
#[derive(Clone, Copy)]
struct ExpectedChild {
    first: (u8, Hash),
    last: (u8, Hash),
    count: u64,
    node_hash: Hash,
}

fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    let tag = major << 5;
    let bytes = value.to_be_bytes();
    match value {
        0..=23 => out.push(tag | bytes[7]),
        24..=255 => out.extend_from_slice(&[tag | 0x18, bytes[7]]),
        // The oracle encodes only the values these fixtures use, all below 65,536.
        _ => {
            out.push(tag | 0x19);
            out.extend_from_slice(&bytes[6..]);
        }
    }
}

fn bytes32(out: &mut Vec<u8>, value: Hash) {
    head(out, 2, 32);
    out.extend_from_slice(value.as_bytes());
}

fn key(out: &mut Vec<u8>, (kind, digest): (u8, Hash)) {
    head(out, 4, 2);
    head(out, 0, u64::from(kind));
    bytes32(out, digest);
}

fn expected_branch(height: u8, children: &[ExpectedChild]) -> Vec<u8> {
    let mut out = vec![0x88, 0x44];
    out.extend_from_slice(b"WDB1");
    out.push(0x01);
    bytes32(&mut out, SCOPE);
    head(&mut out, 0, u64::from(height));
    key(&mut out, children[0].first);
    key(&mut out, children[children.len() - 1].last);
    head(&mut out, 0, children.iter().map(|child| child.count).sum());
    head(&mut out, 4, children.len() as u64);
    for child in children {
        out.push(0x84);
        key(&mut out, child.first);
        key(&mut out, child.last);
        head(&mut out, 0, child.count);
        bytes32(&mut out, child.node_hash);
    }
    out
}

fn leaf_child(leaf: &WorldArtifactLeafV1) -> ExpectedChild {
    let endpoint = (leaf.as_input().kind.code(), leaf.as_input().native_digest);
    ExpectedChild {
        first: endpoint,
        last: endpoint,
        count: 1,
        node_hash: leaf_hash(leaf),
    }
}

fn branch_child(bytes: &[u8], children: &[ExpectedChild]) -> ExpectedChild {
    ExpectedChild {
        first: children[0].first,
        last: children[children.len() - 1].last,
        count: children.iter().map(|child| child.count).sum(),
        node_hash: domain_hash(BRANCH_DOMAIN, bytes),
    }
}

fn assert_branch(actual: &WorldDependencyBranchV1, expected: &[u8]) -> TestResult {
    assert_eq!(actual.encode().as_slice(), expected);
    assert_eq!(
        &WorldDependencyBranchV1::decode(&CanonicalBytes::from_vec(expected.to_vec()))?,
        actual
    );
    Ok(())
}

fn sorted_children(mut leaves: Vec<&WorldArtifactLeafV1>) -> Vec<ExpectedChild> {
    leaves.sort_by_key(|leaf| *leaf.as_input().native_digest.as_bytes());
    leaves.into_iter().map(leaf_child).collect()
}

#[test]
fn full_admitted_roster_packs_512_seed_memberships_into_exact_branches() -> TestResult {
    let seeds = seed_range(0..256)?;
    let binding = binding_for(&seeds)?;
    let native_bytes = seeds.iter().fold(0, |total, seed| {
        total
            + seed.eop1_leaf.as_input().native_byte_length
            + seed.opc1_leaf.as_input().native_byte_length
    });
    let exact = limits(515, native_bytes, 3);
    let directory = WorldDependencyDirectoryV1::pack_with_manifest_policy_seeds(
        &binding,
        &seeds,
        expectation(),
        Vec::new(),
        exact,
    )?;

    let eop1 = sorted_children(seeds.iter().map(|seed| &seed.eop1_leaf).collect());
    let opc1 = sorted_children(seeds.iter().map(|seed| &seed.opc1_leaf).collect());
    let eop1_branch = expected_branch(1, &eop1);
    let opc1_branch = expected_branch(1, &opc1);
    let root = expected_branch(
        2,
        &[
            branch_child(&eop1_branch, &eop1),
            branch_child(&opc1_branch, &opc1),
        ],
    );
    assert_eq!(directory.branches().len(), 3);
    assert_branch(&directory.branches()[0], &eop1_branch)?;
    assert_branch(&directory.branches()[1], &opc1_branch)?;
    assert_branch(&directory.branches()[2], &root)?;
    assert_eq!(directory.root_hash(), domain_hash(BRANCH_DOMAIN, &root));
    assert_eq!(directory.height(), 2);
    assert_eq!(directory.scope(), SCOPE);
    assert_eq!(directory.leaves().len(), 512);
    assert_eq!(directory.leaves()[0], seeds[255].eop1_leaf);
    assert_eq!(directory.leaves()[511], seeds[0].opc1_leaf);
    Ok(())
}

#[test]
fn recorded_visit_byte_and_depth_limits_reject_the_full_roster() -> TestResult {
    let seeds = seed_range(0..256)?;
    let binding = binding_for(&seeds)?;
    let native_bytes = 256 * 300 + 2 * (255 * 256 / 2);
    for exceeded in [
        limits(514, native_bytes, 3),
        limits(515, native_bytes - 1, 3),
        limits(515, native_bytes, 2),
    ] {
        assert_eq!(
            WorldDependencyDirectoryV1::pack_with_manifest_policy_seeds(
                &binding,
                &seeds,
                expectation(),
                Vec::new(),
                exceeded,
            )
            .err(),
            Some(WorldDependencyDirectoryErrorV1::LimitExceeded)
        );
    }
    Ok(())
}

#[test]
fn single_deduplicated_leaf_is_its_own_root() -> TestResult {
    let only = leaf(WorldArtifactKindV1::ReducerImplementation, hash(0x30), 9)?;
    let directory =
        WorldDependencyDirectoryV1::pack(SCOPE, vec![only.clone(), only.clone()], limits(1, 9, 1))?;
    assert_eq!(directory.root_hash(), leaf_hash(&only));
    assert_eq!(directory.height(), 0);
    assert!(directory.branches().is_empty());
    assert_eq!(directory.leaves(), [only]);
    Ok(())
}

#[test]
fn zero_output_plugin_and_duplicate_producer_seed_pack_after_row_checks() -> TestResult {
    // Two distinct PluginIds; display names are not part of MSB1 or WAL1
    // identity, so same-name Plugins differ only by these row identities.
    let seeds = seed_range(1..3)?;
    let binding = binding_for(&seeds)?;
    let reducer = leaf(WorldArtifactKindV1::ReducerImplementation, hash(0x31), 5)?;
    // WCS1 lists only the first Plugin; the second is reducer-only and
    // zero-output, but its Required policy leaves still enter the directory.
    let other_seeds = vec![seeds[0].eop1_leaf.clone(), reducer.clone()];
    let directory = WorldDependencyDirectoryV1::pack_with_manifest_policy_seeds(
        &binding,
        &seeds,
        expectation(),
        other_seeds,
        generous(),
    )?;

    let ordered = [
        &seeds[1].eop1_leaf,
        &seeds[0].eop1_leaf,
        &reducer,
        &seeds[1].opc1_leaf,
        &seeds[0].opc1_leaf,
    ];
    let children: Vec<ExpectedChild> = ordered.into_iter().map(leaf_child).collect();
    let expected = expected_branch(1, &children);
    assert_eq!(directory.branches().len(), 1);
    assert_branch(&directory.branches()[0], &expected)?;
    assert_eq!(directory.root_hash(), domain_hash(BRANCH_DOMAIN, &expected));
    assert_eq!(directory.leaves(), ordered.map(Clone::clone));

    assert_eq!(
        check_manifest_policy_seeds_v1(&binding, &seeds, expectation())?,
        vec![
            seeds[0].eop1_leaf.clone(),
            seeds[0].opc1_leaf.clone(),
            seeds[1].eop1_leaf.clone(),
            seeds[1].opc1_leaf.clone(),
        ]
    );
    Ok(())
}

fn with_eop1(
    seed: &ManifestPolicySeedV1,
    change: impl FnOnce(&mut WorldArtifactLeafInputV1),
) -> Result<ManifestPolicySeedV1, WorldArtifactErrorV1> {
    let mut input = seed.eop1_leaf.as_input().clone();
    change(&mut input);
    Ok(ManifestPolicySeedV1 {
        eop1_leaf: WorldArtifactLeafV1::new(input)?,
        ..seed.clone()
    })
}

fn with_opc1(
    seed: &ManifestPolicySeedV1,
    change: impl FnOnce(&mut WorldArtifactLeafInputV1),
) -> Result<ManifestPolicySeedV1, WorldArtifactErrorV1> {
    let mut input = seed.opc1_leaf.as_input().clone();
    change(&mut input);
    Ok(ManifestPolicySeedV1 {
        opc1_leaf: WorldArtifactLeafV1::new(input)?,
        ..seed.clone()
    })
}

#[test]
fn wrong_policy_leaf_registration_rejects_before_packing() -> TestResult {
    let seeds = seed_range(1..3)?;
    let binding = binding_for(&seeds)?;
    let first = &seeds[0];
    let cases = [
        (
            with_opc1(first, |leaf| {
                leaf.kind = WorldArtifactKindV1::RuntimeIdentity;
            })?,
            WorldDependencyDirectoryErrorV1::WrongKind,
        ),
        (
            with_eop1(first, |leaf| leaf.scope = hash(0x60))?,
            WorldDependencyDirectoryErrorV1::WrongScope,
        ),
        (
            with_opc1(first, |leaf| leaf.source_lease_hash = hash(0x61))?,
            WorldDependencyDirectoryErrorV1::WrongLease,
        ),
        (
            with_eop1(first, |leaf| leaf.owner = [0x62; 32])?,
            WorldDependencyDirectoryErrorV1::WrongOwner,
        ),
        (
            with_opc1(first, |leaf| {
                leaf.optionality = ArtifactOptionalityV1::Optional;
            })?,
            WorldDependencyDirectoryErrorV1::WrongPolicy,
        ),
        (
            with_eop1(first, |leaf| {
                leaf.data_class = ArtifactDataClassV1::PublicRecord;
            })?,
            WorldDependencyDirectoryErrorV1::WrongPolicy,
        ),
        (
            with_opc1(first, |leaf| {
                leaf.transition = ArtifactTransitionRuleV1::Remove;
            })?,
            WorldDependencyDirectoryErrorV1::WrongPolicy,
        ),
        (
            with_eop1(first, |leaf| leaf.native_byte_length += 1)?,
            WorldDependencyDirectoryErrorV1::IdentityMismatch,
        ),
        (
            with_opc1(first, |leaf| leaf.native_digest = hash(0x63))?,
            WorldDependencyDirectoryErrorV1::IdentityMismatch,
        ),
        (
            ManifestPolicySeedV1 {
                plugin_id: first.plugin_id,
                ..seeds[1].clone()
            },
            WorldDependencyDirectoryErrorV1::IdentityMismatch,
        ),
    ];
    for (changed, expected) in cases {
        let supplied = [changed, seeds[1].clone()];
        assert_eq!(
            WorldDependencyDirectoryV1::pack_with_manifest_policy_seeds(
                &binding,
                &supplied,
                expectation(),
                Vec::new(),
                generous(),
            )
            .err(),
            Some(expected)
        );
    }
    Ok(())
}

#[test]
fn omitted_duplicate_or_extra_policy_membership_rejects() -> TestResult {
    let seeds = seed_range(1..4)?;
    let binding = binding_for(&seeds[..2])?;
    for (supplied, expected) in [
        (
            vec![seeds[0].clone()],
            WorldDependencyDirectoryErrorV1::MissingPolicyLeaf,
        ),
        (
            vec![seeds[0].clone(), seeds[0].clone(), seeds[1].clone()],
            WorldDependencyDirectoryErrorV1::UnexpectedPolicyLeaf,
        ),
        (
            seeds.clone(),
            WorldDependencyDirectoryErrorV1::UnexpectedPolicyLeaf,
        ),
    ] {
        assert_eq!(
            check_manifest_policy_seeds_v1(&binding, &supplied, expectation()).err(),
            Some(expected)
        );
    }

    let altered = with_eop1(&seeds[0], |leaf| {
        leaf.transition = ArtifactTransitionRuleV1::RetainStructure;
    })?;
    for extra in [seeds[2].opc1_leaf.clone(), altered.eop1_leaf] {
        assert_eq!(
            WorldDependencyDirectoryV1::pack_with_manifest_policy_seeds(
                &binding,
                &seeds[..2],
                expectation(),
                vec![extra],
                generous(),
            )
            .err(),
            Some(WorldDependencyDirectoryErrorV1::UnexpectedPolicyLeaf)
        );
    }
    Ok(())
}

#[test]
fn empty_wrong_scope_or_conflicting_directory_seed_rejects() -> TestResult {
    assert_eq!(
        WorldDependencyDirectoryV1::pack(SCOPE, Vec::new(), generous()).err(),
        Some(WorldDependencyDirectoryErrorV1::Empty)
    );

    let reducer = leaf(WorldArtifactKindV1::ReducerImplementation, hash(0x32), 5)?;
    let mut foreign = leaf_input(WorldArtifactKindV1::Schema, hash(0x33), 5);
    foreign.scope = hash(0x60);
    let mut conflicting = reducer.as_input().clone();
    conflicting.native_byte_length = 6;
    for (supplied, expected) in [
        (
            vec![reducer.clone(), WorldArtifactLeafV1::new(foreign)?],
            WorldDependencyDirectoryErrorV1::WrongScope,
        ),
        (
            vec![reducer, WorldArtifactLeafV1::new(conflicting)?],
            WorldDependencyDirectoryErrorV1::ConflictingRegistration,
        ),
    ] {
        assert_eq!(
            WorldDependencyDirectoryV1::pack(SCOPE, supplied, generous()).err(),
            Some(expected)
        );
    }
    Ok(())
}

#[test]
fn every_closed_directory_error_has_a_message() {
    for error in [
        WorldDependencyDirectoryErrorV1::Empty,
        WorldDependencyDirectoryErrorV1::WrongScope,
        WorldDependencyDirectoryErrorV1::ConflictingRegistration,
        WorldDependencyDirectoryErrorV1::LimitExceeded,
        WorldDependencyDirectoryErrorV1::MissingPolicyLeaf,
        WorldDependencyDirectoryErrorV1::UnexpectedPolicyLeaf,
        WorldDependencyDirectoryErrorV1::WrongKind,
        WorldDependencyDirectoryErrorV1::WrongLease,
        WorldDependencyDirectoryErrorV1::WrongOwner,
        WorldDependencyDirectoryErrorV1::WrongPolicy,
        WorldDependencyDirectoryErrorV1::IdentityMismatch,
    ] {
        assert!(!error.to_string().is_empty());
    }
}
