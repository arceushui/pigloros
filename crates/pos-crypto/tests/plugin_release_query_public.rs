//! ADR-103 release-query tests.
//!
//! Most manifest projections come from the `test-support` fixture, which
//! models a caller-fabricated projection, so this target declares
//! `required-features = ["test-support"]` in `Cargo.toml` (the hosted test,
//! Clippy, and coverage gates run with `--all-features`). The golden tests
//! compare the real `from_verified_bundle` projection of the independently
//! generated golden closure with a fixture holding the generator's facts.
//! Tests that need no fixture stay in `plugin_trust_public.rs` and
//! `plugin_manifest_public.rs` and always run.

use std::collections::BTreeMap;

use pos_core::OwnerIdV1;
use pos_crypto::plugin_execution::{
    DeterministicBudgetV1, PluginAbiRequirementV1, PluginCapabilityDescriptorV1,
    PluginExecutionProjectionFixtureV1, PluginExecutionProjectionV1,
};
use pos_crypto::plugin_trust::{
    verify_plugin_trust_v1, PluginManifestProjectionFixtureV1, PluginTrustErrorV1,
    TrustedPluginRootAnchorV1, ValidatedPluginManifestProjectionV1, VerifiedPluginTrustEvidenceV1,
};
use pos_plugin_release::{verify_oci_closure_v1, BundleAddressV1, VerifiedReleaseBundleV1};

include!("support/plugin_trust_records.rs");
include!("support/pmf1_golden_vectors.rs");

const PMF1_DIGEST: [u8; 32] = [0x11; 32];
const RELEASE_DIGEST: [u8; 32] = [0x22; 32];
const FIRST_DESCRIPTOR: [u8; 32] = [0x30; 32];
const NESTED_DESCRIPTOR: [u8; 32] = [0x33; 32];

fn manifest() -> Result<PluginManifestProjectionFixtureV1, Box<dyn std::error::Error>> {
    Ok(PluginManifestProjectionFixtureV1 {
        pmf1_digest: PMF1_DIGEST,
        plugin_id: "plugin-a".to_owned(),
        owner: OwnerIdV1::new("publisher")?,
        role: 3,
        epoch: 1,
        not_before: 40,
        not_after: 60,
        release_digest: RELEASE_DIGEST,
        descriptor_digests: vec![FIRST_DESCRIPTOR, NESTED_DESCRIPTOR],
    })
}

fn authorize(
    evidence: &VerifiedPluginTrustEvidenceV1,
    manifest: PluginManifestProjectionFixtureV1,
) -> Result<[u8; 32], PluginTrustErrorV1> {
    evidence
        .authorize_release(&ValidatedPluginManifestProjectionV1::from(manifest))
        .map(|fact| fact.resolved_public_key())
}

fn revoked_key(public: [u8; 32], tick: u64) -> Value {
    Value::Array(vec![
        Value::Text("publisher".to_owned()),
        unsigned(3),
        unsigned(1),
        Value::Bytes(public.to_vec()),
        unsigned(tick),
        unsigned(1),
        Value::Null,
    ])
}

fn revoked_artifact(digest: [u8; 32], tick: u64) -> Value {
    Value::Array(vec![
        Value::Bytes(digest.to_vec()),
        unsigned(tick),
        unsigned(1),
        Value::Null,
    ])
}

/// Verify the default PTR1 with one PRV1 (effective Tick 5) at UTC 50.
fn verified(
    keys: Vec<Value>,
    artifacts: Vec<Value>,
    evaluation_tick: u64,
) -> Result<VerifiedPluginTrustEvidenceV1, Box<dyn std::error::Error>> {
    let ptr1 = root(1, None)?;
    let anchor = TrustedPluginRootAnchorV1::new("scope", digest(&ptr1))?;
    let prv1 = signed_record(
        revocation_fields(digest(&ptr1), 1, None, 5, keys, artifacts),
        REVOCATION_SIGNATURE_DOMAIN,
        &signer(),
    )?;
    verify_plugin_trust_v1(&anchor, &[&ptr1], &[&prv1], 50, evaluation_tick).map_err(Into::into)
}

#[test]
fn release_query_resolves_key_and_binds_complete_manifest_fact() -> TestResult {
    let evidence = verified(Vec::new(), Vec::new(), 4)?;
    let fact =
        evidence.authorize_release(&ValidatedPluginManifestProjectionV1::from(manifest()?))?;
    assert_eq!(fact.resolved_public_key(), publisher_public());
    assert_eq!(fact.pmf1_digest(), PMF1_DIGEST);
    assert_eq!(fact.terminal_root(), evidence.terminal_root());
    assert_eq!(fact.terminal_revocation(), evidence.terminal_revocation());
    assert_eq!(fact.evaluation_coordinates(), (50, 4));
    Ok(())
}

#[test]
fn incomplete_manifest_projection_fails_closed() -> TestResult {
    let evidence = verified(Vec::new(), Vec::new(), 4)?;
    let mut cases = Vec::new();
    let mut wrong_role = manifest()?;
    wrong_role.role = 2;
    cases.push(wrong_role);
    let mut zero_epoch = manifest()?;
    zero_epoch.epoch = 0;
    cases.push(zero_epoch);
    let mut empty_interval = manifest()?;
    empty_interval.not_before = 60;
    cases.push(empty_interval);
    let mut invalid_plugin_id = manifest()?;
    "-plugin-a".clone_into(&mut invalid_plugin_id.plugin_id);
    cases.push(invalid_plugin_id);
    let mut unsorted = manifest()?;
    unsorted.descriptor_digests = vec![NESTED_DESCRIPTOR, FIRST_DESCRIPTOR];
    cases.push(unsorted);
    let mut duplicate = manifest()?;
    duplicate.descriptor_digests = vec![FIRST_DESCRIPTOR, FIRST_DESCRIPTOR];
    cases.push(duplicate);
    for case in cases {
        assert_eq!(
            authorize(&evidence, case),
            Err(PluginTrustErrorV1::IncompleteManifestProjection)
        );
    }
    Ok(())
}

#[test]
fn manifest_interval_must_contain_evidence_utc_second() -> TestResult {
    let evidence = verified(Vec::new(), Vec::new(), 4)?;
    let mut not_yet_valid = manifest()?;
    not_yet_valid.not_before = 51;
    assert_eq!(
        authorize(&evidence, not_yet_valid),
        Err(PluginTrustErrorV1::ManifestExpired)
    );
    let mut expired = manifest()?;
    expired.not_after = 50;
    assert_eq!(
        authorize(&evidence, expired),
        Err(PluginTrustErrorV1::ManifestExpired)
    );
    let mut exact_edges = manifest()?;
    exact_edges.not_before = 50;
    exact_edges.not_after = 51;
    assert_eq!(authorize(&evidence, exact_edges), Ok(publisher_public()));
    Ok(())
}

#[test]
fn unknown_publisher_key_and_ungranted_plugin_id_fail_closed() -> TestResult {
    let evidence = verified(Vec::new(), Vec::new(), 4)?;
    let mut other_owner = manifest()?;
    other_owner.owner = OwnerIdV1::new("other")?;
    assert_eq!(
        authorize(&evidence, other_owner),
        Err(PluginTrustErrorV1::UnknownPublisherKey)
    );
    let mut other_epoch = manifest()?;
    other_epoch.epoch = 2;
    assert_eq!(
        authorize(&evidence, other_epoch),
        Err(PluginTrustErrorV1::UnknownPublisherKey)
    );
    let mut other_plugin = manifest()?;
    "plugin-b".clone_into(&mut other_plugin.plugin_id);
    assert_eq!(
        authorize(&evidence, other_plugin),
        Err(PluginTrustErrorV1::PluginIdNotGranted)
    );
    Ok(())
}

#[test]
fn grant_to_another_owner_does_not_authorize_known_publisher() -> TestResult {
    let other_public = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    let ptr1 = signed_record(
        root_fields(
            1,
            None,
            vec![
                publisher_entry("other", 1, other_public),
                publisher_entry("publisher", 1, publisher_public()),
            ],
            vec![grant("plugin-a", "publisher")],
        ),
        ROOT_SIGNATURE_DOMAIN,
        &signer(),
    )?;
    let anchor = TrustedPluginRootAnchorV1::new("scope", digest(&ptr1))?;
    let prv1 = revocation(digest(&ptr1), 1, None)?;
    let evidence = verify_plugin_trust_v1(&anchor, &[&ptr1], &[&prv1], 50, 4)?;
    assert_eq!(authorize(&evidence, manifest()?), Ok(publisher_public()));
    let mut other_owner = manifest()?;
    other_owner.owner = OwnerIdV1::new("other")?;
    assert_eq!(
        authorize(&evidence, other_owner),
        Err(PluginTrustErrorV1::PluginIdNotGranted)
    );
    Ok(())
}

#[test]
fn publisher_key_revocation_applies_from_its_effective_tick() -> TestResult {
    let keys = || vec![revoked_key(publisher_public(), 5)];
    let before = verified(keys(), Vec::new(), 4)?;
    assert_eq!(authorize(&before, manifest()?), Ok(publisher_public()));
    let at_edge = verified(keys(), Vec::new(), 5)?;
    assert_eq!(
        authorize(&at_edge, manifest()?),
        Err(PluginTrustErrorV1::PublisherKeyRevoked)
    );
    Ok(())
}

#[test]
fn release_and_nested_descriptor_revocations_deny_release() -> TestResult {
    for revoked in [RELEASE_DIGEST, NESTED_DESCRIPTOR] {
        let artifacts = || vec![revoked_artifact(revoked, 5)];
        let before = verified(Vec::new(), artifacts(), 4)?;
        assert_eq!(authorize(&before, manifest()?), Ok(publisher_public()));
        let at_edge = verified(Vec::new(), artifacts(), 5)?;
        assert_eq!(
            authorize(&at_edge, manifest()?),
            Err(PluginTrustErrorV1::ArtifactRevoked)
        );
    }
    Ok(())
}

fn golden_manifest() -> Result<PluginManifestProjectionFixtureV1, Box<dyn std::error::Error>> {
    let mut golden = manifest()?;
    "alpha/plugin".clone_into(&mut golden.plugin_id);
    golden.epoch = 9;
    golden.not_before = -1;
    golden.not_after = 1;
    Ok(golden)
}

#[test]
fn golden_evidence_resolves_then_revokes_exact_publisher_key() -> TestResult {
    let ptr1 = hex_bytes(PTR1_HEX)?;
    let prv1 = hex_bytes(PRV1_HEX)?;
    let anchor = TrustedPluginRootAnchorV1::new("trust.example", digest(&ptr1))?;
    let before = verify_plugin_trust_v1(&anchor, &[&ptr1], &[&prv1], 0, 9)?;
    let fact = before.authorize_release(&ValidatedPluginManifestProjectionV1::from(
        golden_manifest()?,
    ))?;
    assert_eq!(
        fact.resolved_public_key(),
        [
            0xa0, 0x9a, 0xa5, 0xf4, 0x7a, 0x67, 0x59, 0x80, 0x2f, 0xf9, 0x55, 0xf8, 0xdc, 0x2d,
            0x2a, 0x14, 0xa5, 0xc9, 0x9d, 0x23, 0xbe, 0x97, 0xf8, 0x64, 0x12, 0x7f, 0xf9, 0x38,
            0x34, 0x55, 0xa4, 0xf0,
        ]
    );
    assert_eq!(fact.terminal_root(), (42, digest(&ptr1)));
    assert_eq!(fact.terminal_revocation(), (7, digest(&prv1)));
    let effective = verify_plugin_trust_v1(&anchor, &[&ptr1], &[&prv1], 0, 10)?;
    assert_eq!(
        authorize(&effective, golden_manifest()?),
        Err(PluginTrustErrorV1::PublisherKeyRevoked)
    );
    Ok(())
}

#[test]
fn full_future_effective_artifact_collection_exhausts_release_capacity() -> TestResult {
    let artifacts = (0..4096_u32)
        .map(|index| {
            let mut revoked = [0; 32];
            revoked[..4].copy_from_slice(&index.to_be_bytes());
            revoked_artifact(revoked, 10)
        })
        .collect::<Vec<_>>();
    let ptr1 = root(1, None)?;
    let anchor = TrustedPluginRootAnchorV1::new("scope", digest(&ptr1))?;
    let prv1 = signed_record(
        revocation_fields(digest(&ptr1), 1, None, 10, Vec::new(), artifacts),
        REVOCATION_SIGNATURE_DOMAIN,
        &signer(),
    )?;
    let evidence = verify_plugin_trust_v1(&anchor, &[&ptr1], &[&prv1], 50, 5)?;
    assert_eq!(evidence.effective_artifact_revocations().count(), 0);
    assert_eq!(
        authorize(&evidence, manifest()?),
        Err(PluginTrustErrorV1::RevocationCapacityExhausted)
    );
    Ok(())
}

#[test]
fn full_future_effective_key_collection_exhausts_release_capacity() -> TestResult {
    // A PTR1 can name 256 publisher keys. Sixteen linked PTR1 records make
    // 4096 distinct future-effective PRV1 key entries known to the verifier.
    let mut roots = Vec::new();
    let mut revoked_keys = Vec::new();
    let mut previous = None;
    for root_index in 0_u16..16 {
        let mut publishers = Vec::new();
        for publisher_index in 0_u16..256 {
            let mut seed = [0; 32];
            seed[..2].copy_from_slice(&root_index.to_be_bytes());
            seed[2..4].copy_from_slice(&publisher_index.to_be_bytes());
            seed[31] = 1;
            let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
            let owner = format!("owner-{root_index:02}-{publisher_index:03}");
            publishers.push(publisher_entry(&owner, 1, public));
            revoked_keys.push(Value::Array(vec![
                Value::Text(owner),
                unsigned(3),
                unsigned(1),
                Value::Bytes(public.to_vec()),
                unsigned(10),
                unsigned(1),
                Value::Null,
            ]));
        }
        let fields = root_fields(u64::from(root_index) + 1, previous, publishers, Vec::new());
        let ptr1 = signed_record(fields, ROOT_SIGNATURE_DOMAIN, &signer())?;
        previous = Some(digest(&ptr1));
        roots.push(ptr1);
    }
    let terminal_root = previous.ok_or("no PTR1")?;
    let anchor = TrustedPluginRootAnchorV1::new("scope", digest(&roots[0]))?;
    let prv1 = signed_record(
        revocation_fields(terminal_root, 1, None, 10, revoked_keys, Vec::new()),
        REVOCATION_SIGNATURE_DOMAIN,
        &signer(),
    )?;
    let root_references = roots.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let evidence = verify_plugin_trust_v1(&anchor, &root_references, &[&prv1], 50, 5)?;
    assert_eq!(evidence.effective_key_revocations().count(), 0);
    assert_eq!(
        authorize(&evidence, manifest()?),
        Err(PluginTrustErrorV1::RevocationCapacityExhausted)
    );
    Ok(())
}

fn golden_digest(hex: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    Ok(hex_bytes(hex)?.as_slice().try_into()?)
}

/// The generator's golden closure, verified by the ADR-102 transport verifier.
fn golden_bundle() -> Result<VerifiedReleaseBundleV1, Box<dyn std::error::Error>> {
    let manifest = GOLDEN_OCI_MANIFEST.as_bytes().to_vec();
    let address = BundleAddressV1::new(
        GOLDEN_OCI_MANIFEST_DIGEST.to_owned(),
        u64::try_from(manifest.len())?,
    )?;
    let mut blobs = BTreeMap::new();
    for (oci_digest, hex) in GOLDEN_BLOBS_HEX {
        blobs.insert(oci_digest.to_owned(), hex_bytes(hex)?);
    }
    Ok(verify_oci_closure_v1(address, manifest, blobs)?)
}

/// Every projection fact of the golden PMF1, as computed by the generator.
fn golden_fixture() -> Result<PluginManifestProjectionFixtureV1, Box<dyn std::error::Error>> {
    Ok(PluginManifestProjectionFixtureV1 {
        pmf1_digest: golden_digest(GOLDEN_PMF1_DIGEST_HEX)?,
        plugin_id: "alpha/plugin".to_owned(),
        owner: OwnerIdV1::new("publisher")?,
        role: 3,
        epoch: 9,
        not_before: -100,
        not_after: 100,
        release_digest: golden_digest(GOLDEN_RELEASE_DIGEST_HEX)?,
        descriptor_digests: GOLDEN_DESCRIPTOR_DIGESTS_HEX
            .iter()
            .map(|hex| golden_digest(hex))
            .collect::<Result<_, _>>()?,
    })
}

#[test]
fn golden_closure_projects_exactly_the_independent_golden_facts() -> TestResult {
    let bundle = golden_bundle()?;
    let pmf1 = hex_bytes(GOLDEN_PMF1_HEX)?;
    let pmf1_member = bundle.members().first().ok_or("no PMF1 member")?;
    assert_eq!(pmf1_member.size(), u64::try_from(pmf1.len())?);
    let projection = ValidatedPluginManifestProjectionV1::from_verified_bundle(&bundle)?;
    let golden = golden_fixture()?;
    assert_eq!(digest(&pmf1), golden.pmf1_digest);
    assert_eq!(
        projection,
        ValidatedPluginManifestProjectionV1::from(golden.clone())
    );
    for carried in [
        GOLDEN_UNSIGNED_MANIFEST_DIGEST_HEX,
        GOLDEN_PREVIOUS_RELEASE_HEX,
    ] {
        let carried = golden_digest(carried)?;
        assert!(pmf1.windows(32).any(|window| window == carried.as_slice()));
        assert!(!golden.descriptor_digests.contains(&carried));
    }
    let ptr1 = hex_bytes(PTR1_HEX)?;
    let prv1 = hex_bytes(PRV1_HEX)?;
    let anchor = TrustedPluginRootAnchorV1::new("trust.example", digest(&ptr1))?;
    let evidence = verify_plugin_trust_v1(&anchor, &[&ptr1], &[&prv1], 0, 9)?;
    let fact = evidence.authorize_release(&projection)?;
    assert_eq!(fact.pmf1_digest(), golden.pmf1_digest);
    let fixture_key = authorize(&evidence, golden);
    assert_eq!(Ok(fact.resolved_public_key()), fixture_key);
    Ok(())
}

#[test]
fn golden_digests_deny_the_real_but_not_a_fabricated_partial_projection() -> TestResult {
    let projection = ValidatedPluginManifestProjectionV1::from_verified_bundle(&golden_bundle()?)?;
    let ptr1 = signed_record(
        root_fields(
            1,
            None,
            vec![publisher_entry("publisher", 9, publisher_public())],
            vec![grant("alpha/plugin", "publisher")],
        ),
        ROOT_SIGNATURE_DOMAIN,
        &signer(),
    )?;
    let anchor = TrustedPluginRootAnchorV1::new("scope", digest(&ptr1))?;
    for (index, hex) in GOLDEN_DESCRIPTOR_DIGESTS_HEX.iter().enumerate() {
        let prv1 = signed_record(
            revocation_fields(
                digest(&ptr1),
                1,
                None,
                5,
                Vec::new(),
                vec![revoked_artifact(golden_digest(hex)?, 5)],
            ),
            REVOCATION_SIGNATURE_DOMAIN,
            &signer(),
        )?;
        let evidence = verify_plugin_trust_v1(&anchor, &[&ptr1], &[&prv1], 50, 5)?;
        assert_eq!(
            evidence.authorize_release(&projection).err(),
            Some(PluginTrustErrorV1::ArtifactRevoked)
        );
        let mut partial = golden_fixture()?;
        let removed = partial.descriptor_digests.remove(index);
        assert_eq!(removed, golden_digest(hex)?);
        assert_eq!(authorize(&evidence, partial), Ok(publisher_public()));
    }
    Ok(())
}

/// One golden capability descriptor with the generator's shared members.
fn golden_capability(
    operation: &str,
    purpose: &str,
    required: bool,
    limits: [u64; 3],
) -> PluginCapabilityDescriptorV1 {
    PluginCapabilityDescriptorV1 {
        capability_id: "kv".to_owned(),
        operation: operation.to_owned(),
        resource_pattern: "state/*".to_owned(),
        purpose: purpose.to_owned(),
        audience: "plugin".to_owned(),
        required,
        max_calls: limits[0],
        max_request_bytes: limits[1],
        max_response_bytes: limits[2],
    }
}

/// The generator's golden ABI, capability and budget facts.
fn golden_execution() -> Result<PluginExecutionProjectionFixtureV1, Box<dyn std::error::Error>> {
    Ok(PluginExecutionProjectionFixtureV1 {
        pmf1_digest: golden_digest(GOLDEN_PMF1_DIGEST_HEX)?,
        release_digest: golden_digest(GOLDEN_RELEASE_DIGEST_HEX)?,
        plugin_id: "alpha/plugin".to_owned(),
        abi: PluginAbiRequirementV1 {
            major: 0,
            min_minor: 1,
            max_minor: 3,
            required_features: vec!["clock.v1".to_owned(), "log".to_owned()],
        },
        capabilities: vec![
            golden_capability("read", "Read Plugin state", true, [24, 1_024, 2_048]),
            golden_capability("write", "Write Plugin state", false, [10, 2_048, 0]),
        ],
        budget: DeterministicBudgetV1 {
            memory_bytes: 1_048_576,
            fuel: 1 << 40,
            host_calls: 1_000,
            event_count: 16,
            event_bytes: 4_096,
            state_bytes: 65_536,
            log_calls: 24,
            log_bytes: 2_048,
        },
    })
}

#[test]
fn golden_closure_projects_exactly_the_independent_execution_facts() -> TestResult {
    let bundle = golden_bundle()?;
    let execution = PluginExecutionProjectionV1::from_verified_bundle(&bundle)?;
    let golden = golden_execution()?;
    assert_eq!(execution, PluginExecutionProjectionV1::from(golden.clone()));
    assert_eq!(execution.pmf1_digest(), golden.pmf1_digest);
    assert_eq!(execution.release_digest(), golden.release_digest);
    assert_eq!(execution.plugin_id(), "alpha/plugin");
    assert_eq!(execution.abi(), &golden.abi);
    assert_eq!(execution.capabilities(), golden.capabilities.as_slice());
    assert_eq!(execution.budget(), golden.budget);
    let manifest = ValidatedPluginManifestProjectionV1::from_verified_bundle(&bundle)?;
    assert!(execution.is_bound_to(&manifest));
    Ok(())
}

#[test]
fn execution_binding_needs_both_the_pmf1_and_release_digests() -> TestResult {
    let manifest = ValidatedPluginManifestProjectionV1::from(golden_fixture()?);
    let golden = golden_execution()?;
    assert!(PluginExecutionProjectionV1::from(golden.clone()).is_bound_to(&manifest));
    let mut other_pmf1 = golden.clone();
    other_pmf1.pmf1_digest[0] ^= 1;
    assert!(!PluginExecutionProjectionV1::from(other_pmf1).is_bound_to(&manifest));
    let mut other_release = golden;
    other_release.release_digest[0] ^= 1;
    assert!(!PluginExecutionProjectionV1::from(other_release).is_bound_to(&manifest));
    Ok(())
}
