//! ADR-103 release-query tests.
//!
//! Manifest projections come from the `test-support` fixture because only
//! #401's PMF1 parser may construct a real one, so this target declares
//! `required-features = ["test-support"]` in `Cargo.toml` (the hosted test,
//! Clippy, and coverage gates run with `--all-features`). Tests that need no
//! fixture stay in `plugin_trust_public.rs` and always run.

use pos_core::OwnerIdV1;
use pos_crypto::plugin_trust::{
    verify_plugin_trust_v1, PluginManifestProjectionFixtureV1, PluginTrustErrorV1,
    TrustedPluginRootAnchorV1, ValidatedPluginManifestProjectionV1, VerifiedPluginTrustEvidenceV1,
};

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/support/plugin_trust_records.rs"
));

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
    invalid_plugin_id.plugin_id = "-plugin-a".to_owned();
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
    other_plugin.plugin_id = "plugin-b".to_owned();
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
    golden.plugin_id = "alpha/plugin".to_owned();
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
