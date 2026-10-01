use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_crypto::plugin_trust::{
    verify_plugin_trust_v1, PluginTrustErrorV1, PluginTrustRootRecordV1, TrustedPluginRootAnchorV1,
};

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/plugin_trust_vectors.rs"
));

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ROOT_SIGNATURE_DOMAIN: &[u8] = b"pigloros/plugin-trust-root/v1\0";
const REVOCATION_SIGNATURE_DOMAIN: &[u8] = b"pigloros/plugin-revocation/v1\0";

fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// ADR-103 root key ID, recomputed independently of the crate internals.
fn root_key_id(public: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros/plugin-root-key-id/v1\0");
    hasher.update(&public);
    *hasher.finalize().as_bytes()
}

fn unsigned(value: u64) -> Value {
    Value::Integer(value.into())
}

fn bytes<const N: usize>(value: [u8; N]) -> Value {
    Value::Bytes(value.to_vec())
}

fn encode(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded)?;
    Ok(encoded)
}

/// Sign the exact 11-field unsigned prefix and append the signature array.
fn signed_record(
    mut fields: Vec<Value>,
    domain: &[u8],
    signer: &SigningKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut message = domain.to_vec();
    message.extend_from_slice(&encode(&Value::Array(fields.clone()))?);
    let public = signer.verifying_key().to_bytes();
    fields.push(Value::Array(vec![Value::Array(vec![
        bytes(root_key_id(public)),
        bytes(signer.sign(&message).to_bytes()),
    ])]));
    encode(&Value::Array(fields))
}

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn publisher_public() -> [u8; 32] {
    SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes()
}

fn publisher_entry(owner: &str, epoch: u64, public: [u8; 32]) -> Value {
    Value::Array(vec![
        Value::Text(owner.to_owned()),
        unsigned(3),
        unsigned(epoch),
        bytes(public),
    ])
}

fn grant(plugin_id: &str, owner: &str) -> Value {
    Value::Array(vec![
        Value::Text(plugin_id.to_owned()),
        Value::Text(owner.to_owned()),
    ])
}

/// PTR1 fields 0-10 for scope `scope`, valid for UTC seconds 0..100.
fn root_fields(
    version: u64,
    previous: Option<[u8; 32]>,
    publishers: Vec<Value>,
    grants: Vec<Value>,
) -> Vec<Value> {
    let public = signer().verifying_key().to_bytes();
    vec![
        Value::Text("PTR1".to_owned()),
        unsigned(1),
        Value::Text("scope".to_owned()),
        unsigned(version),
        unsigned(0),
        unsigned(100),
        previous.map_or(Value::Null, bytes),
        unsigned(1),
        Value::Array(vec![Value::Array(vec![
            bytes(root_key_id(public)),
            bytes(public),
        ])]),
        Value::Array(publishers),
        Value::Array(grants),
    ]
}

/// A PTR1 granting `plugin-a` to `publisher`, epoch 1.
fn root(version: u64, previous: Option<[u8; 32]>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    signed_record(
        root_fields(
            version,
            previous,
            vec![publisher_entry("publisher", 1, publisher_public())],
            vec![grant("plugin-a", "publisher")],
        ),
        ROOT_SIGNATURE_DOMAIN,
        &signer(),
    )
}

/// PRV1 fields 0-10 for scope `scope`, valid for UTC seconds 0..100.
fn revocation_fields(
    root_digest: [u8; 32],
    epoch: u64,
    previous: Option<[u8; 32]>,
    tick: u64,
    keys: Vec<Value>,
    artifacts: Vec<Value>,
) -> Vec<Value> {
    vec![
        Value::Text("PRV1".to_owned()),
        unsigned(1),
        Value::Text("scope".to_owned()),
        unsigned(epoch),
        unsigned(0),
        unsigned(100),
        bytes(root_digest),
        previous.map_or(Value::Null, bytes),
        unsigned(tick),
        Value::Array(keys),
        Value::Array(artifacts),
    ]
}

/// An empty PRV1 with effective Tick 5.
fn revocation(
    root_digest: [u8; 32],
    epoch: u64,
    previous: Option<[u8; 32]>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    signed_record(
        revocation_fields(root_digest, epoch, previous, 5, Vec::new(), Vec::new()),
        REVOCATION_SIGNATURE_DOMAIN,
        &signer(),
    )
}

#[test]
fn public_verifier_distinguishes_unknown_root_key_from_invalid_signature() -> TestResult {
    let ptr1 = hex_bytes(PTR1_HEX)?;
    let prv1 = hex_bytes(PRV1_HEX)?;
    let baseline_anchor = TrustedPluginRootAnchorV1::new("trust.example", digest(&ptr1))?;
    let evidence = verify_plugin_trust_v1(&baseline_anchor, &[&ptr1], &[&prv1], 0, 10)?;
    assert_eq!(
        evidence.verified_root_history().collect::<Vec<_>>(),
        vec![(42, digest(&ptr1))]
    );
    assert_eq!(
        evidence.verified_revocation_history().collect::<Vec<_>>(),
        vec![(7, digest(&prv1))]
    );
    let signature_start = ptr1.len() - 64;
    let signer_id_start = signature_start - 34;
    assert_eq!(&ptr1[signer_id_start - 2..signer_id_start], &[0x58, 0x20]);

    let mut unknown_signer = ptr1.clone();
    unknown_signer[signer_id_start] ^= 1;
    let unknown_anchor = TrustedPluginRootAnchorV1::new("trust.example", digest(&unknown_signer))?;
    assert!(matches!(
        verify_plugin_trust_v1(&unknown_anchor, &[&unknown_signer], &[&prv1], 0, 10),
        Err(PluginTrustErrorV1::UnknownRootKey)
    ));

    let mut invalid_signature = ptr1;
    let last_signature_byte = invalid_signature.last_mut().ok_or("empty PTR1")?;
    *last_signature_byte ^= 1;
    let invalid_anchor =
        TrustedPluginRootAnchorV1::new("trust.example", digest(&invalid_signature))?;
    assert!(matches!(
        verify_plugin_trust_v1(&invalid_anchor, &[&invalid_signature], &[&prv1], 0, 10),
        Err(PluginTrustErrorV1::InvalidSignature)
    ));
    Ok(())
}

#[test]
fn verified_history_exposes_only_complete_authenticated_chains() -> TestResult {
    let genesis_root = root(1, None)?;
    let genesis_root_digest = digest(&genesis_root);
    let genesis_revocation = revocation(genesis_root_digest, 1, None)?;
    let genesis_revocation_digest = digest(&genesis_revocation);
    let next_root = root(2, Some(genesis_root_digest))?;
    let next_root_digest = digest(&next_root);
    let next_revocation = revocation(next_root_digest, 2, Some(genesis_revocation_digest))?;
    let next_revocation_digest = digest(&next_revocation);
    let anchor = TrustedPluginRootAnchorV1::new("scope", genesis_root_digest)?;

    let evidence = verify_plugin_trust_v1(
        &anchor,
        &[&genesis_root, &next_root],
        &[&genesis_revocation, &next_revocation],
        50,
        5,
    )?;
    assert_eq!(
        evidence.verified_root_history().collect::<Vec<_>>(),
        vec![(1, genesis_root_digest), (2, next_root_digest)]
    );
    assert_eq!(
        evidence.verified_revocation_history().collect::<Vec<_>>(),
        vec![(1, genesis_revocation_digest), (2, next_revocation_digest)]
    );
    assert_eq!(evidence.terminal_root(), (2, next_root_digest));
    assert_eq!(evidence.terminal_revocation(), (2, next_revocation_digest));

    let forked_root = root(2, Some([0xa5; 32]))?;
    assert!(matches!(
        verify_plugin_trust_v1(
            &anchor,
            &[&genesis_root, &forked_root],
            &[&genesis_revocation, &next_revocation],
            50,
            5,
        ),
        Err(PluginTrustErrorV1::DigestMismatch)
    ));
    let forked_revocation = revocation(next_root_digest, 2, Some([0xa5; 32]))?;
    assert!(matches!(
        verify_plugin_trust_v1(
            &anchor,
            &[&genesis_root, &next_root],
            &[&genesis_revocation, &forked_revocation],
            50,
            5,
        ),
        Err(PluginTrustErrorV1::DigestMismatch)
    ));
    assert!(matches!(
        verify_plugin_trust_v1(
            &anchor,
            &[&next_root],
            &[&genesis_revocation, &next_revocation],
            50,
            5,
        ),
        Err(PluginTrustErrorV1::AnchorMismatch)
    ));
    Ok(())
}

#[test]
fn full_history_limits_are_lifetime_ceilings() -> TestResult {
    let genesis_root = root(1, None)?;
    let anchor = TrustedPluginRootAnchorV1::new("scope", digest(&genesis_root))?;
    let mut roots = vec![genesis_root];
    for version in 2..=65 {
        let previous = digest(roots.last().ok_or("no PTR1")?);
        roots.push(root(version, Some(previous))?);
    }
    let terminal_root = digest(roots.get(63).ok_or("no 64th PTR1")?);
    let mut revocations = vec![revocation(terminal_root, 1, None)?];
    for epoch in 2..=257 {
        let previous = digest(revocations.last().ok_or("no PRV1")?);
        revocations.push(revocation(terminal_root, epoch, Some(previous))?);
    }
    let root_refs = roots.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let revocation_refs = revocations.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let evidence =
        verify_plugin_trust_v1(&anchor, &root_refs[..64], &revocation_refs[..256], 50, 5)?;
    assert_eq!(evidence.verified_root_history().count(), 64);
    assert_eq!(evidence.verified_revocation_history().count(), 256);
    assert!(matches!(
        verify_plugin_trust_v1(&anchor, &root_refs[..65], &revocation_refs[..256], 50, 5),
        Err(PluginTrustErrorV1::RootHistoryCapacityExceeded)
    ));
    assert!(matches!(
        verify_plugin_trust_v1(&anchor, &root_refs[..64], &revocation_refs[..257], 50, 5),
        Err(PluginTrustErrorV1::RevocationHistoryCapacityExceeded)
    ));
    assert!(matches!(
        verify_plugin_trust_v1(&anchor, &root_refs[1..64], &revocation_refs[..256], 50, 5),
        Err(PluginTrustErrorV1::AnchorMismatch)
    ));
    Ok(())
}

#[test]
fn empty_histories_fail_closed_without_evidence() -> TestResult {
    let genesis_root = root(1, None)?;
    let genesis_revocation = revocation(digest(&genesis_root), 1, None)?;
    let anchor = TrustedPluginRootAnchorV1::new("scope", digest(&genesis_root))?;
    assert!(matches!(
        verify_plugin_trust_v1(&anchor, &[], &[&genesis_revocation], 50, 5),
        Err(PluginTrustErrorV1::ChainDiscontinuity)
    ));
    assert!(matches!(
        verify_plugin_trust_v1(&anchor, &[&genesis_root], &[], 50, 5),
        Err(PluginTrustErrorV1::ChainDiscontinuity)
    ));
    Ok(())
}

#[test]
fn root_threshold_outside_one_to_thirty_two_fails_closed() -> TestResult {
    for threshold in [0, 33, 256, u64::MAX] {
        let mut fields = root_fields(
            1,
            None,
            vec![publisher_entry("publisher", 1, publisher_public())],
            vec![grant("plugin-a", "publisher")],
        );
        fields[7] = unsigned(threshold);
        let encoded = signed_record(fields, ROOT_SIGNATURE_DOMAIN, &signer())?;
        assert!(matches!(
            PluginTrustRootRecordV1::decode(&encoded),
            Err(PluginTrustErrorV1::InvalidEncoding)
        ));
    }
    Ok(())
}

/// ADR-103 release-query tests. Projections come from the `test-support`
/// fixture because only #401's PMF1 parser may construct a real one.
#[cfg(feature = "test-support")]
mod release_query {
    use super::{
        digest, grant, hex_bytes, publisher_entry, publisher_public, revocation, revocation_fields,
        root, root_fields, signed_record, signer, unsigned, PluginTrustErrorV1, TestResult,
        TrustedPluginRootAnchorV1, Value, PRV1_HEX, PTR1_HEX, REVOCATION_SIGNATURE_DOMAIN,
        ROOT_SIGNATURE_DOMAIN,
    };
    use ed25519_dalek::SigningKey;
    use pos_core::OwnerIdV1;
    use pos_crypto::plugin_trust::{
        verify_plugin_trust_v1, PluginManifestProjectionFixtureV1,
        ValidatedPluginManifestProjectionV1, VerifiedPluginTrustEvidenceV1,
    };

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
}
