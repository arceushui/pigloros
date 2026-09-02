use std::collections::BTreeMap;
use std::error::Error;
use std::io;

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_reference::evaluator_protocol::{
    EvaluationRequest, ImplementationIdentity, OutputCapability, SubjectAdapterKind,
};

pub struct Corpus {
    pub request: Vec<u8>,
    pub archive: Vec<u8>,
    pub trust_policy: Vec<u8>,
    pub subject_digest: [u8; 32],
    pub expected_output: Vec<u8>,
}

type TestResult<T> = Result<T, Box<dyn Error>>;

pub fn corpus() -> TestResult<Corpus> {
    let signing_key = SigningKey::from_bytes(&[9; 32]);
    let trust_policy = trust_policy(&signing_key)?;
    let trust_digest = hash(&trust_policy);
    let execution_profile = canonical(&array(vec![text("EPF1"), uint(1), text("test-profile")]))?;
    let execution_digest = hash(&execution_profile);
    let expected_output = b"accepted".to_vec();
    let mut members = support_members(&trust_policy, &execution_profile);
    let hard_caps = hard_caps();
    let fixtures = fixtures(
        &mut members,
        execution_digest,
        trust_digest,
        &expected_output,
    )?;
    let profile = profile(
        &members,
        fixtures,
        execution_digest,
        trust_digest,
        &hard_caps,
    )?;
    let profile_digest = hash_contract("PiglorOS.ConformanceProfile.v1", &profile)?;
    let mut profile_fields = fields(profile)?;
    profile_fields.push(bytes(&profile_digest));
    members.insert(
        "profile/CPF1.cbor".to_owned(),
        (canonical(&array(profile_fields))?, 2),
    );
    let archive = archive(&signing_key, &members, profile_digest, execution_digest)?;
    let archive_digest = hash(&archive);
    let subject_digest = [41; 32];
    let hard_caps_digest = hash_contract("PiglorOS.EvaluatorHardCaps.v1", &hard_caps)?;
    let mut request = EvaluationRequest {
        request_id: [1; 16],
        profile_digest,
        fixture_bundle_digest: archive_digest,
        subject_adapter: SubjectAdapterKind::ExportedArtifact,
        subject_artifact_digest: subject_digest,
        implementation: ImplementationIdentity {
            implementation_id: "public-subject".to_owned(),
            source_digest: [42; 32],
            build_digest: [43; 32],
            binary_digest: [44; 32],
            public_contract_digest: [45; 32],
            organization_id: None,
        },
        execution_profile_digest: execution_digest,
        trust_policy_snapshot_digest: trust_digest,
        output_capability: OutputCapability {
            capability_digest: [1; 32],
            report_bytes_limit: 1024 * 1024,
            diagnostic_bytes_limit: 1024 * 1024,
        },
        evaluator_protocol_digest: member_hash(&members, "support/evaluator-protocol-v1.json")?,
        evaluator_hard_caps_digest: hard_caps_digest,
        request_digest: [1; 32],
    };
    request.output_capability.capability_digest = request.expected_output_capability_digest()?;
    request.request_digest = request.digest()?;
    Ok(Corpus {
        request: request.to_canonical_cbor()?,
        archive,
        trust_policy,
        subject_digest,
        expected_output,
    })
}

fn support_members(trust: &[u8], execution: &[u8]) -> BTreeMap<String, (Vec<u8>, u8)> {
    BTreeMap::from([
        (
            "authority/execution-matrix.json".to_owned(),
            (b"{}".to_vec(), 11),
        ),
        (
            "authority/fixture-provider-registry.fpr1".to_owned(),
            (b"registry".to_vec(), 12),
        ),
        (
            "authority/test-profile.epf1".to_owned(),
            (execution.to_vec(), 14),
        ),
        (
            "authority/trust-policy-snapshot.tps1".to_owned(),
            (trust.to_vec(), 15),
        ),
        (
            "support/evaluator-protocol-v1.json".to_owned(),
            (b"evaluator protocol".to_vec(), 4),
        ),
        (
            "support/evaluator-report-v1.cddl".to_owned(),
            (b"report schema".to_vec(), 4),
        ),
        (
            "support/evaluator-request-v1.cddl".to_owned(),
            (b"request schema".to_vec(), 4),
        ),
        (
            "support/fixture-family-contract.json".to_owned(),
            (b"fixture policy".to_vec(), 18),
        ),
        ("support/limitations.md".to_owned(), (b"limits".to_vec(), 9)),
        (
            "support/normative-requirements.md".to_owned(),
            (b"normative".to_vec(), 3),
        ),
        (
            "support/publication-review.json".to_owned(),
            (b"review".to_vec(), 8),
        ),
    ])
}

fn fixtures(
    members: &mut BTreeMap<String, (Vec<u8>, u8)>,
    execution: [u8; 32],
    trust: [u8; 32],
    expected: &[u8],
) -> TestResult<Vec<Value>> {
    let schema_path = "fixtures/schema.json";
    members.insert(schema_path.to_owned(), (b"schema".to_vec(), 4));
    (0_u64..=6)
        .map(|family| -> TestResult<Value> {
            let case_id = format!("case-{family}");
            let payload_path = format!("fixtures/{case_id}.input");
            let evidence_path = format!("fixtures/{case_id}.evidence");
            let output_path = format!("fixtures/{case_id}.expected");
            members.insert(payload_path.clone(), (vec![u8::try_from(family)?], 0));
            members.insert(evidence_path.clone(), (b"draft".to_vec(), 17));
            members.insert(output_path.clone(), (expected.to_vec(), 1));
            let provider = provider_key(1);
            let transition = if family == 5 {
                array(vec![provider_key(2), provider.clone()])
            } else {
                Value::Null
            };
            let trust_binding = if family == 5 {
                bytes(&trust)
            } else {
                Value::Null
            };
            let release_binding = if family == 5 {
                bytes(&[46; 32])
            } else {
                Value::Null
            };
            let mut fixture = vec![
                text(&case_id),
                Value::Bool(true),
                uint(0),
                uint(family),
                provider,
                uint(0),
                bytes(&execution),
                array(vec![uint(0), uint(1)]),
                descriptor(members, schema_path)?,
                descriptor(members, &payload_path)?,
                array(vec![descriptor(members, &evidence_path)?]),
                array(vec![
                    uint(0),
                    descriptor(members, &output_path)?,
                    Value::Null,
                    Value::Null,
                ]),
                uint(0),
                Value::Null,
                uint(0),
                uint(0),
                array(vec![uint(100); 8]),
                array(vec![uint(1_000)]),
                array(vec![Value::Bool(false), array(Vec::new())]),
                trust_binding,
                release_binding,
                provenance(),
                transition,
            ];
            let digest = hash_contract("PiglorOS.Conformance.Fixture.v1", &array(fixture.clone()))?;
            fixture.push(bytes(&digest));
            Ok(array(fixture))
        })
        .collect()
}

fn profile(
    members: &BTreeMap<String, (Vec<u8>, u8)>,
    fixtures: Vec<Value>,
    execution: [u8; 32],
    trust: [u8; 32],
    hard_caps: &Value,
) -> TestResult<Value> {
    Ok(array(vec![
        text("CPF1"),
        uint(1),
        text("test-conformance"),
        text("1.0.0"),
        uint(0),
        bytes(&member_hash(members, "support/normative-requirements.md")?),
        bytes(&member_hash(members, "authority/execution-matrix.json")?),
        array(vec![bytes(&execution)]),
        array(vec![
            descriptor_with_media(
                members,
                "authority/fixture-provider-registry.fpr1",
                "application/cbor",
            )?,
            array(vec![provider_key(1)]),
        ]),
        array(fixtures),
        array(Vec::new()),
        array(vec![
            text("evaluator-v1"),
            bytes(&member_hash(members, "support/evaluator-protocol-v1.json")?),
            bytes(&member_hash(members, "support/evaluator-request-v1.cddl")?),
            bytes(&member_hash(members, "support/evaluator-report-v1.cddl")?),
            hard_caps.clone(),
        ]),
        array(vec![
            Value::Bool(true),
            Value::Bool(true),
            Value::Bool(false),
            bytes(&trust),
            bytes(&[47; 32]),
        ]),
        bytes(&member_hash(
            members,
            "support/fixture-family-contract.json",
        )?),
        bytes(&member_hash(members, "support/limitations.md")?),
        bytes(&member_hash(members, "support/publication-review.json")?),
        Value::Null,
    ]))
}

fn archive(
    signing_key: &SigningKey,
    members: &BTreeMap<String, (Vec<u8>, u8)>,
    profile: [u8; 32],
    execution: [u8; 32],
) -> TestResult<Vec<u8>> {
    let descriptors = members
        .iter()
        .map(|(path, (member, role))| -> TestResult<Value> {
            Ok(array(vec![
                text(path),
                uint(u64::try_from(member.len())?),
                bytes(&hash(member)),
                uint(u64::from(*role)),
            ]))
        })
        .collect::<TestResult<Vec<_>>>()?;
    let archive_members = members
        .iter()
        .map(|(path, (member, role))| {
            array(vec![
                text(path),
                Value::Bytes(member.clone()),
                uint(u64::from(*role)),
            ])
        })
        .collect();
    let expected = (0_u64..=6)
        .map(|family| -> TestResult<(Vec<u8>, Value)> {
            let case_id = format!("case-{family}");
            let path = format!("fixtures/{case_id}.expected");
            let value = array(vec![
                text(&case_id),
                uint(0),
                bytes(&execution),
                uint(0),
                text(&path),
                bytes(&member_hash(members, &path)?),
            ]);
            Ok((canonical(&value)?, value))
        })
        .collect::<TestResult<Vec<_>>>()?;
    let mut expected = expected;
    expected.sort_by(|left, right| left.0.cmp(&right.0));
    let expected = expected.into_iter().map(|(_, value)| value).collect();
    let manifest = array(vec![
        text("CFB1"),
        uint(0),
        uint(0),
        bytes(&profile),
        array(descriptors),
        array(expected),
    ]);
    let signature = signing_key.sign(&canonical(&manifest)?).to_bytes();
    canonical(&array(vec![
        manifest,
        array(archive_members),
        bytes(&signing_key.verifying_key().to_bytes()),
        bytes(&signature),
    ]))
}

fn trust_policy(signing_key: &SigningKey) -> TestResult<Vec<u8>> {
    let mut fields = vec![
        text("TPS1"),
        uint(1),
        text("test-policy"),
        uint(1),
        uint(1),
        array(vec![array(vec![
            text("test-key"),
            uint(1),
            text("Ed25519"),
            bytes(&signing_key.verifying_key().to_bytes()),
        ])]),
        array(Vec::new()),
        array(Vec::new()),
        array(vec![array(vec![text("cfb1"), text("1.0.0")])]),
        text("2099-01-01T00:00:00Z"),
        Value::Null,
    ];
    let signature = signing_key
        .sign(&canonical(&array(fields.clone()))?)
        .to_bytes();
    fields.push(bytes(&signature));
    canonical(&array(fields))
}

fn provenance() -> Value {
    array(vec![
        text("Apache-2.0"),
        bytes(&[51; 32]),
        bytes(&[52; 32]),
        bytes(&[53; 32]),
        bytes(&[54; 32]),
        bytes(&[55; 32]),
        bytes(&[56; 32]),
    ])
}

fn provider_key(minor: u64) -> Value {
    array(vec![
        text("test-provider"),
        text("1.0.0"),
        uint(1),
        uint(minor),
    ])
}

fn hard_caps() -> Value {
    array(vec![
        uint(16 * 1024 * 1024),
        uint(65_536),
        uint(65_536),
        uint(256),
        uint(64 * 1024 * 1024),
        uint(1024 * 1024 * 1024),
        uint(100),
        uint(32),
        uint(128),
        uint(1024 * 1024),
        uint(1024 * 1024 * 1024),
        uint(1_000_000_000),
        uint(1_000_000),
        uint(1_000_000),
        uint(64 * 1024 * 1024),
        uint(1024 * 1024 * 1024),
        uint(1_000_000_000),
        uint(86_400_000_000_000),
    ])
}

fn descriptor(members: &BTreeMap<String, (Vec<u8>, u8)>, path: &str) -> TestResult<Value> {
    descriptor_with_media(members, path, "application/octet-stream")
}

fn descriptor_with_media(
    members: &BTreeMap<String, (Vec<u8>, u8)>,
    path: &str,
    media_type: &str,
) -> TestResult<Value> {
    let member = &members
        .get(path)
        .ok_or_else(|| io::Error::other("test member is missing"))?
        .0;
    Ok(array(vec![
        text(path),
        text(media_type),
        uint(u64::try_from(member.len())?),
        bytes(&hash(member)),
    ]))
}

fn member_hash(members: &BTreeMap<String, (Vec<u8>, u8)>, path: &str) -> TestResult<[u8; 32]> {
    let member = members
        .get(path)
        .ok_or_else(|| io::Error::other("test member is missing"))?;
    Ok(hash(&member.0))
}

fn hash(value: &[u8]) -> [u8; 32] {
    *blake3::hash(value).as_bytes()
}

fn hash_contract(domain: &str, value: &Value) -> TestResult<[u8; 32]> {
    let encoded = canonical(value)?;
    let mut source = Vec::new();
    source.extend_from_slice(domain.as_bytes());
    source.push(0);
    source.extend_from_slice(&u64::try_from(encoded.len())?.to_be_bytes());
    source.extend_from_slice(&encoded);
    Ok(hash(&source))
}

fn fields(value: Value) -> TestResult<Vec<Value>> {
    let Value::Array(fields) = value else {
        return Err(io::Error::other("test value is not an array").into());
    };
    Ok(fields)
}

fn canonical(value: &Value) -> TestResult<Vec<u8>> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded)?;
    Ok(encoded)
}

fn array(values: Vec<Value>) -> Value {
    Value::Array(values)
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn bytes<const N: usize>(value: &[u8; N]) -> Value {
    Value::Bytes(value.to_vec())
}
