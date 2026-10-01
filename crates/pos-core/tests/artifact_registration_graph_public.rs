use pos_core::{
    inspect_artifact_registration_graph_v1, ArtifactChildEdgeV1, ArtifactDataClassV1,
    ArtifactKeyDependencyV1, ArtifactOptionalityV1, ArtifactRegistrationFieldsV1,
    ArtifactRegistrationGraphErrorV1, ArtifactRegistrationGraphNodeV1, ArtifactRegistrationV1,
    ArtifactTransitionRuleV1, ErasureArtifactClassV1, Hash, KeyIdentityV1, KeyRoleV1, OwnerIdV1,
    MAX_ARTIFACT_GRAPH_DEPTH_V1, MAX_ARTIFACT_GRAPH_EDGES_V1, MAX_ARTIFACT_GRAPH_KEYS_V1,
    MAX_ARTIFACT_GRAPH_REGISTRATIONS_V1,
};

fn node(
    label: u64,
    owner_id: OwnerIdV1,
    artifact_class: ErasureArtifactClassV1,
    optionality: ArtifactOptionalityV1,
    mut children: Vec<ArtifactChildEdgeV1>,
    keys: Vec<ArtifactKeyDependencyV1>,
) -> Result<ArtifactRegistrationGraphNodeV1, Box<dyn std::error::Error>> {
    children.sort_by_key(|edge| {
        (
            edge.artifact_class,
            edge.artifact_digest,
            edge.registration_address,
        )
    });
    let artifact_digest =
        ArtifactRegistrationV1::artifact_digest(artifact_class, &label.to_be_bytes());
    let required_key_roles = if keys.is_empty() {
        Vec::new()
    } else {
        vec![KeyRoleV1::SubjectDataEncryption]
    };
    let registration = ArtifactRegistrationV1::new(ArtifactRegistrationFieldsV1 {
        artifact_class,
        artifact_digest,
        owner_reference: ArtifactRegistrationV1::owner_reference(&owner_id),
        data_class: ArtifactDataClassV1::StructuralAuditMetadata,
        optionality,
        transition_rule: ArtifactTransitionRuleV1::RetainStructure,
        required_key_roles,
        key_dependencies: keys,
        child_artifacts: children,
    })?;
    Ok(ArtifactRegistrationGraphNodeV1 {
        address: registration.address(),
        owner_id,
        artifact_class,
        artifact_digest,
        registration,
    })
}

const fn edge(child: &ArtifactRegistrationGraphNodeV1, required: bool) -> ArtifactChildEdgeV1 {
    ArtifactChildEdgeV1 {
        artifact_class: child.artifact_class,
        artifact_digest: child.artifact_digest,
        registration_address: child.address,
        required,
    }
}

fn owner() -> Result<OwnerIdV1, Box<dyn std::error::Error>> {
    Ok(OwnerIdV1::new("alice")?)
}

#[test]
fn structural_dag_checks_catalog_and_counts_shared_children_once(
) -> Result<(), Box<dyn std::error::Error>> {
    let owner_id = owner()?;
    let leaf = node(
        1,
        owner_id,
        ErasureArtifactClassV1::Export,
        ArtifactOptionalityV1::Optional,
        Vec::new(),
        Vec::new(),
    )?;
    let left = node(
        2,
        owner_id,
        ErasureArtifactClassV1::CausalTrace,
        ArtifactOptionalityV1::Required,
        vec![edge(&leaf, true)],
        Vec::new(),
    )?;
    let right = node(
        3,
        owner_id,
        ErasureArtifactClassV1::CalibrationReport,
        ArtifactOptionalityV1::Required,
        vec![edge(&leaf, false)],
        Vec::new(),
    )?;
    let root = node(
        4,
        owner_id,
        ErasureArtifactClassV1::TimelineReplay,
        ArtifactOptionalityV1::Required,
        vec![edge(&left, true), edge(&right, true)],
        Vec::new(),
    )?;
    let total_bytes = [
        root.registration.canonical_cbor().len(),
        left.registration.canonical_cbor().len(),
        right.registration.canonical_cbor().len(),
        leaf.registration.canonical_cbor().len(),
    ]
    .into_iter()
    .sum::<usize>();
    let summary = inspect_artifact_registration_graph_v1(root.address, &[root, right, left, leaf])?;
    assert_eq!(summary.registrations, 4);
    assert_eq!(summary.edges, 4);
    assert_eq!(summary.keys, 0);
    assert_eq!(summary.registration_bytes, total_bytes);
    Ok(())
}

#[test]
fn root_and_catalog_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let owner_id = owner()?;
    let required = node(
        1,
        owner_id,
        ErasureArtifactClassV1::TimelineReplay,
        ArtifactOptionalityV1::Required,
        Vec::new(),
        Vec::new(),
    )?;
    assert_eq!(
        inspect_artifact_registration_graph_v1(Hash::zero(), std::slice::from_ref(&required)),
        Err(ArtifactRegistrationGraphErrorV1::InvalidRoot)
    );
    let optional = node(
        2,
        owner_id,
        ErasureArtifactClassV1::TimelineReplay,
        ArtifactOptionalityV1::Optional,
        Vec::new(),
        Vec::new(),
    )?;
    assert_eq!(
        inspect_artifact_registration_graph_v1(optional.address, &[optional]),
        Err(ArtifactRegistrationGraphErrorV1::InvalidRoot)
    );
    assert_eq!(
        inspect_artifact_registration_graph_v1(
            required.address,
            &[required.clone(), required.clone()]
        ),
        Err(ArtifactRegistrationGraphErrorV1::DuplicateAddress)
    );
    let extra = node(
        3,
        owner_id,
        ErasureArtifactClassV1::Export,
        ArtifactOptionalityV1::Required,
        Vec::new(),
        Vec::new(),
    )?;
    assert_eq!(
        inspect_artifact_registration_graph_v1(required.address, &[required.clone(), extra]),
        Err(ArtifactRegistrationGraphErrorV1::ExtraRegistration)
    );
    let mut wrong_owner = required.clone();
    wrong_owner.owner_id = OwnerIdV1::new("bob")?;
    assert_eq!(
        inspect_artifact_registration_graph_v1(wrong_owner.address, &[wrong_owner]),
        Err(ArtifactRegistrationGraphErrorV1::OwnerMismatch)
    );
    let mut wrong_class = required.clone();
    wrong_class.artifact_class = ErasureArtifactClassV1::Export;
    assert_eq!(
        inspect_artifact_registration_graph_v1(wrong_class.address, &[wrong_class]),
        Err(ArtifactRegistrationGraphErrorV1::IdentityMismatch)
    );
    let mut wrong_digest = required;
    wrong_digest.artifact_digest = Hash::zero();
    assert_eq!(
        inspect_artifact_registration_graph_v1(wrong_digest.address, &[wrong_digest]),
        Err(ArtifactRegistrationGraphErrorV1::IdentityMismatch)
    );
    Ok(())
}

#[test]
fn edges_reject_missing_wrong_and_aliased_children() -> Result<(), Box<dyn std::error::Error>> {
    let owner_id = owner()?;
    let child = node(
        1,
        owner_id,
        ErasureArtifactClassV1::Export,
        ArtifactOptionalityV1::Required,
        Vec::new(),
        Vec::new(),
    )?;
    let root = node(
        2,
        owner_id,
        ErasureArtifactClassV1::TimelineReplay,
        ArtifactOptionalityV1::Required,
        vec![edge(&child, true)],
        Vec::new(),
    )?;
    assert_eq!(
        inspect_artifact_registration_graph_v1(root.address, std::slice::from_ref(&root)),
        Err(ArtifactRegistrationGraphErrorV1::MissingChild)
    );
    let mut wrong_class = child.clone();
    wrong_class.artifact_class = ErasureArtifactClassV1::CausalTrace;
    assert_eq!(
        inspect_artifact_registration_graph_v1(root.address, &[root.clone(), wrong_class]),
        Err(ArtifactRegistrationGraphErrorV1::IdentityMismatch)
    );
    let mut wrong_owner = child.clone();
    wrong_owner.owner_id = OwnerIdV1::new("bob")?;
    assert_eq!(
        inspect_artifact_registration_graph_v1(root.address, &[root.clone(), wrong_owner]),
        Err(ArtifactRegistrationGraphErrorV1::OwnerMismatch)
    );
    let mut wrong_address = child.clone();
    wrong_address.address = Hash::from_bytes([99; 32]);
    let alias_root = node(
        3,
        owner_id,
        ErasureArtifactClassV1::TimelineReplay,
        ArtifactOptionalityV1::Required,
        vec![edge(&wrong_address, true)],
        Vec::new(),
    )?;
    assert_eq!(
        inspect_artifact_registration_graph_v1(alias_root.address, &[alias_root, wrong_address]),
        Err(ArtifactRegistrationGraphErrorV1::IdentityMismatch)
    );
    let mut alias = child;
    alias.address = root.registration.fields().child_artifacts[0].registration_address;
    alias.registration = node(
        3,
        owner_id,
        ErasureArtifactClassV1::Export,
        ArtifactOptionalityV1::Required,
        Vec::new(),
        Vec::new(),
    )?
    .registration;
    assert_eq!(
        inspect_artifact_registration_graph_v1(root.address, &[root, alias]),
        Err(ArtifactRegistrationGraphErrorV1::IdentityMismatch)
    );
    Ok(())
}

#[test]
fn corrupt_catalog_cycle_and_depth_limit_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let owner_id = owner()?;
    let alias_address = Hash::from_bytes([99; 32]);
    let alias_stub = ArtifactRegistrationGraphNodeV1 {
        address: alias_address,
        owner_id,
        artifact_class: ErasureArtifactClassV1::Export,
        artifact_digest: Hash::from_bytes([12; 32]),
        registration: node(
            1,
            owner_id,
            ErasureArtifactClassV1::Export,
            ArtifactOptionalityV1::Required,
            Vec::new(),
            Vec::new(),
        )?
        .registration,
    };
    let root = node(
        2,
        owner_id,
        ErasureArtifactClassV1::TimelineReplay,
        ArtifactOptionalityV1::Required,
        vec![edge(&alias_stub, true)],
        Vec::new(),
    )?;
    let mut alias = node(
        3,
        owner_id,
        ErasureArtifactClassV1::Export,
        ArtifactOptionalityV1::Required,
        vec![edge(&root, true)],
        Vec::new(),
    )?;
    alias.address = alias_address;
    alias.artifact_digest = alias.registration.fields().artifact_digest;
    let mut root_with_matching_alias = root.clone();
    let mut root_fields = root.registration.fields().clone();
    root_fields.child_artifacts[0].artifact_digest = alias.artifact_digest;
    root_with_matching_alias.registration = ArtifactRegistrationV1::new(root_fields)?;
    root_with_matching_alias.address = root_with_matching_alias.registration.address();
    // Rebuild the corrupt child so its reverse edge refers to the final root.
    let mut child_fields = alias.registration.fields().clone();
    child_fields.child_artifacts[0] = edge(&root_with_matching_alias, true);
    alias.registration = ArtifactRegistrationV1::new(child_fields)?;
    assert_eq!(
        inspect_artifact_registration_graph_v1(
            root_with_matching_alias.address,
            &[root_with_matching_alias, alias]
        ),
        Err(ArtifactRegistrationGraphErrorV1::Cycle)
    );

    let mut chain = vec![node(
        100,
        owner_id,
        ErasureArtifactClassV1::Export,
        ArtifactOptionalityV1::Required,
        Vec::new(),
        Vec::new(),
    )?];
    for label in 101..=u64::try_from(MAX_ARTIFACT_GRAPH_DEPTH_V1 + 100)? {
        let previous = edge(chain.last().ok_or("missing chain node")?, true);
        chain.push(node(
            label,
            owner_id,
            ErasureArtifactClassV1::Export,
            ArtifactOptionalityV1::Required,
            vec![previous],
            Vec::new(),
        )?);
    }
    let root = chain.last().ok_or("missing chain root")?.address;
    assert_eq!(
        inspect_artifact_registration_graph_v1(root, &chain),
        Err(ArtifactRegistrationGraphErrorV1::BoundExceeded)
    );
    Ok(())
}

#[test]
fn shared_child_cannot_hide_a_longer_root_path() -> Result<(), Box<dyn std::error::Error>> {
    let owner_id = owner()?;
    let shared = node(
        500,
        owner_id,
        ErasureArtifactClassV1::ConformanceReport,
        ArtifactOptionalityV1::Required,
        Vec::new(),
        Vec::new(),
    )?;
    let short = node(
        501,
        owner_id,
        ErasureArtifactClassV1::CausalTrace,
        ArtifactOptionalityV1::Required,
        vec![edge(&shared, true)],
        Vec::new(),
    )?;
    let mut deep = vec![shared];
    for offset in 0..MAX_ARTIFACT_GRAPH_DEPTH_V1 - 1 {
        let previous = edge(deep.last().ok_or("missing deep node")?, true);
        deep.push(node(
            600 + u64::try_from(offset)?,
            owner_id,
            ErasureArtifactClassV1::ForkOrSnapshot,
            ArtifactOptionalityV1::Required,
            vec![previous],
            Vec::new(),
        )?);
    }
    let long_branch = deep.last().ok_or("missing long branch")?;
    let root = node(
        900,
        owner_id,
        ErasureArtifactClassV1::TimelineReplay,
        ArtifactOptionalityV1::Required,
        vec![edge(&short, true), edge(long_branch, true)],
        Vec::new(),
    )?;
    let root_address = root.address;
    deep.push(short);
    deep.push(root);
    assert_eq!(
        inspect_artifact_registration_graph_v1(root_address, &deep),
        Err(ArtifactRegistrationGraphErrorV1::BoundExceeded)
    );
    Ok(())
}

#[test]
fn shared_subtree_checks_its_longest_root_path() -> Result<(), Box<dyn std::error::Error>> {
    let owner_id = owner()?;
    for long_path_nodes in [3, 4] {
        let leaf = node(
            1_000,
            owner_id,
            ErasureArtifactClassV1::ConformanceReport,
            ArtifactOptionalityV1::Required,
            Vec::new(),
            Vec::new(),
        )?;
        let mut graph = vec![leaf.clone()];
        let mut shared = leaf;
        for offset in 0..59_u64 {
            let next = node(
                1_001 + offset,
                owner_id,
                ErasureArtifactClassV1::ConformanceReport,
                ArtifactOptionalityV1::Required,
                vec![edge(&shared, true)],
                Vec::new(),
            )?;
            graph.push(next.clone());
            shared = next;
        }
        let short = node(
            2_000,
            owner_id,
            ErasureArtifactClassV1::CausalTrace,
            ArtifactOptionalityV1::Required,
            vec![edge(&shared, true)],
            Vec::new(),
        )?;
        graph.push(short.clone());
        let mut long = shared;
        for offset in 0..long_path_nodes {
            let next = node(
                3_000 + offset,
                owner_id,
                ErasureArtifactClassV1::ForkOrSnapshot,
                ArtifactOptionalityV1::Required,
                vec![edge(&long, true)],
                Vec::new(),
            )?;
            graph.push(next.clone());
            long = next;
        }
        let root = node(
            4_000,
            owner_id,
            ErasureArtifactClassV1::TimelineReplay,
            ArtifactOptionalityV1::Required,
            vec![edge(&short, true), edge(&long, true)],
            Vec::new(),
        )?;
        let root_address = root.address;
        graph.push(root);
        let result = inspect_artifact_registration_graph_v1(root_address, &graph);
        if long_path_nodes == 3 {
            assert_eq!(result?.registrations, graph.len());
        } else {
            assert_eq!(result, Err(ArtifactRegistrationGraphErrorV1::BoundExceeded));
        }
    }
    Ok(())
}

#[test]
fn catalog_identity_cannot_name_two_registration_addresses(
) -> Result<(), Box<dyn std::error::Error>> {
    let owner_id = owner()?;
    let required = node(
        5_000,
        owner_id,
        ErasureArtifactClassV1::Export,
        ArtifactOptionalityV1::Required,
        Vec::new(),
        Vec::new(),
    )?;
    let optional = node(
        5_000,
        owner_id,
        ErasureArtifactClassV1::Export,
        ArtifactOptionalityV1::Optional,
        Vec::new(),
        Vec::new(),
    )?;
    assert_ne!(required.address, optional.address);
    let root = node(
        5_001,
        owner_id,
        ErasureArtifactClassV1::TimelineReplay,
        ArtifactOptionalityV1::Required,
        vec![edge(&required, true), edge(&optional, false)],
        Vec::new(),
    )?;
    assert_eq!(
        inspect_artifact_registration_graph_v1(root.address, &[root, required, optional]),
        Err(ArtifactRegistrationGraphErrorV1::IdentityMismatch)
    );
    Ok(())
}

#[test]
fn registration_count_is_bounded_before_catalog_use() -> Result<(), Box<dyn std::error::Error>> {
    let root = node(
        1,
        owner()?,
        ErasureArtifactClassV1::TimelineReplay,
        ArtifactOptionalityV1::Required,
        Vec::new(),
        Vec::new(),
    )?;
    let graph = std::iter::repeat_n(root.clone(), MAX_ARTIFACT_GRAPH_REGISTRATIONS_V1 + 1)
        .collect::<Vec<_>>();
    assert_eq!(
        inspect_artifact_registration_graph_v1(root.address, &graph),
        Err(ArtifactRegistrationGraphErrorV1::BoundExceeded)
    );
    Ok(())
}

#[test]
fn distinct_key_budget_is_enforced_across_shared_graph() -> Result<(), Box<dyn std::error::Error>> {
    let owner_id = owner()?;
    let mut leaves = Vec::new();
    for group in 0..3_u64 {
        let keys = (1..=2_048_u64)
            .map(|epoch| ArtifactKeyDependencyV1 {
                identity: KeyIdentityV1::from_parts(
                    owner_id,
                    KeyRoleV1::SubjectDataEncryption,
                    group * 2_048 + epoch,
                ),
                material_digest: Hash::from_bytes([1; 32]),
                private_material_required: true,
            })
            .collect();
        leaves.push(node(
            group,
            owner_id,
            ErasureArtifactClassV1::Export,
            ArtifactOptionalityV1::Required,
            Vec::new(),
            keys,
        )?);
    }
    let within_budget = node(
        20,
        owner_id,
        ErasureArtifactClassV1::TimelineReplay,
        ArtifactOptionalityV1::Required,
        leaves[..2].iter().map(|leaf| edge(leaf, true)).collect(),
        Vec::new(),
    )?;
    assert_eq!(
        inspect_artifact_registration_graph_v1(
            within_budget.address,
            &[within_budget, leaves[0].clone(), leaves[1].clone()]
        )?
        .keys,
        MAX_ARTIFACT_GRAPH_KEYS_V1
    );
    let over_budget = node(
        21,
        owner_id,
        ErasureArtifactClassV1::TimelineReplay,
        ArtifactOptionalityV1::Required,
        leaves.iter().map(|leaf| edge(leaf, true)).collect(),
        Vec::new(),
    )?;
    let root_address = over_budget.address;
    let mut graph = leaves;
    graph.push(over_budget);
    assert_eq!(
        inspect_artifact_registration_graph_v1(root_address, &graph),
        Err(ArtifactRegistrationGraphErrorV1::BoundExceeded)
    );
    Ok(())
}

#[test]
fn edge_budget_counts_each_distinct_registration_once() -> Result<(), Box<dyn std::error::Error>> {
    let owner_id = owner()?;
    let mut leaves = Vec::new();
    for label in 1..=2_048 {
        leaves.push(node(
            label,
            owner_id,
            ErasureArtifactClassV1::Export,
            ArtifactOptionalityV1::Required,
            Vec::new(),
            Vec::new(),
        )?);
    }
    let common_edges: Vec<_> = leaves.iter().map(|leaf| edge(leaf, true)).collect();
    let mut branches = Vec::new();
    for label in 3_000..3_005 {
        branches.push(node(
            label,
            owner_id,
            ErasureArtifactClassV1::CausalTrace,
            ArtifactOptionalityV1::Required,
            common_edges.clone(),
            Vec::new(),
        )?);
    }
    let root = node(
        4_000,
        owner_id,
        ErasureArtifactClassV1::TimelineReplay,
        ArtifactOptionalityV1::Required,
        branches.iter().map(|branch| edge(branch, true)).collect(),
        Vec::new(),
    )?;
    let root_address = root.address;
    leaves.extend(branches);
    leaves.push(root);
    assert_eq!(MAX_ARTIFACT_GRAPH_EDGES_V1, 8_192);
    assert_eq!(
        inspect_artifact_registration_graph_v1(root_address, &leaves),
        Err(ArtifactRegistrationGraphErrorV1::BoundExceeded)
    );
    Ok(())
}

#[test]
fn registration_byte_ceiling_is_checked_through_the_public_inspector(
) -> Result<(), Box<dyn std::error::Error>> {
    let owner_id = OwnerIdV1::new("a".repeat(128))?;
    let shared_keys = (1..=2_048_u64)
        .map(|epoch| ArtifactKeyDependencyV1 {
            identity: KeyIdentityV1::from_parts(owner_id, KeyRoleV1::SubjectDataEncryption, epoch),
            material_digest: Hash::from_bytes([1; 32]),
            private_material_required: true,
        })
        .collect::<Vec<_>>();
    let mut leaves = Vec::new();
    for label in 10_000..10_192 {
        leaves.push(node(
            label,
            owner_id,
            ErasureArtifactClassV1::Export,
            ArtifactOptionalityV1::Required,
            Vec::new(),
            shared_keys.clone(),
        )?);
    }
    let child_edges = leaves.iter().map(|leaf| edge(leaf, true)).collect();
    let within_root = node(
        20_000,
        owner_id,
        ErasureArtifactClassV1::TimelineReplay,
        ArtifactOptionalityV1::Required,
        child_edges.clone(),
        Vec::new(),
    )?;
    let within_root_address = within_root.address;
    let mut graph = leaves;
    graph.push(within_root);
    let summary = inspect_artifact_registration_graph_v1(within_root_address, &graph)?;
    assert_eq!(summary.registrations, 193);
    assert_eq!(summary.edges, 192);
    assert_eq!(summary.keys, MAX_ARTIFACT_GRAPH_KEYS_V1 / 2);
    assert!(summary.registration_bytes <= MAX_ARTIFACT_GRAPH_REGISTRATION_BYTES_V1);

    graph.pop().ok_or("within-limit root is missing")?;
    let over_root = node(
        20_000,
        owner_id,
        ErasureArtifactClassV1::TimelineReplay,
        ArtifactOptionalityV1::Required,
        child_edges,
        shared_keys,
    )?;
    let over_root_address = over_root.address;
    graph.push(over_root);
    assert_eq!(
        inspect_artifact_registration_graph_v1(over_root_address, &graph),
        Err(ArtifactRegistrationGraphErrorV1::BoundExceeded)
    );
    Ok(())
}
