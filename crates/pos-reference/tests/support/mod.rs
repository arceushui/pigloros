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

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ProfileMutation {
    ProviderKeyNumericBoundary(u8),
    DivergenceCoordinateLong,
    SelectedCapBoundary(u8),
    ExecutionContractBoundary(u8),
    FixtureSemanticBoundary(u8),
    ProvenanceBoundary(u8),
    DescriptorValueBoundary(u8),
    IdentifierBoundary(u8),
    SemanticVersionBoundary(u8),
    MemberPathBoundary(u8),
    MediaTypeBoundary(u8),
    ExecutionListBoundary(u8),
    RawProfileField(u8),
    RawFixtureField(u8),
    RawProviderBindingField(u8),
    RawRequiredProviderField(u8),
    RawProtocolField(u8),
    RawHardCapField(u8),
    RawRequirementField(u8),
    RawFixtureProviderField(u8),
    RawFixtureSchemaField(u8),
    RawFixturePayloadField(u8),
    RawFixtureAuxiliaryField(u8),
    RawFixtureOracleField(u8),
    RawFixtureBudgetField(u8),
    RawFixtureSafetyField(u8),
    RawFixtureCapabilityField(u8),
    RawFixtureProvenanceField(u8),
    RawFixtureTransitionField(u8),
    RawExecutionField(u8),
    RawExecutionNetworkField(u8),
    RawExecutionBudgetField(u8),
    RawExecutionVersionField(u8),
    RawRegistryField(u8),
    RawRegistryRecordField(u8),
    RawPackageField(u8),
    RawPackageProviderField(u8),
    RawPackageSchemaBindingField(u8),
    RawPackageSchemaDescriptorField(u8),
    RawPackageSupportDescriptorField(u8),
    Magic,
    Version,
    ProfileId,
    ProfileSemver,
    Lifecycle,
    NormativeDigest,
    MatrixDigest,
    FixturePolicyDigest,
    LimitationsDigest,
    PublicationDigest,
    PreviousDigest,
    ExecutionProfilesEmpty,
    ExecutionProfilesUnsorted,
    ProvidersEmpty,
    ProvidersUnsorted,
    FixturesEmpty,
    FixturesUnsorted,
    AllowedDivergenceUndeclared,
    AllowedDivergenceUnsorted,
    AllowedDivergenceCoordinate,
    ProtocolId,
    ProtocolDigest,
    ProtocolRequestDigest,
    ProtocolReportDigest,
    HardCapZero,
    HardCapAboveMaximum,
    RequirementDigest,
    RequirementDeclaration,
    FixtureModesEmpty,
    FixtureModesUnsorted,
    FixtureModeOutOfRange,
    FixtureAdapter,
    FixtureProvider,
    FixtureCaseId,
    FixtureExecutionDigest,
    FixtureClaimLayer,
    FixtureFamily,
    FixtureOutcome,
    FixtureReplay,
    FixtureRedaction,
    FixtureBudget,
    FixtureBudgetAboveCap,
    FixtureWatchdog,
    FixtureNetworkPlugin,
    FixtureNetworkAirGapped,
    FixtureCapabilities,
    FixtureCapabilitiesUnsorted,
    FixtureAuxiliaryTooMany,
    FixtureDuplicatePath,
    FixtureDescriptor,
    FixturePayloadDescriptor,
    FixtureOracle,
    FixtureOracleOutputMissing,
    FixtureOracleDivergenceCoordinate,
    FixtureUnexpectedVerificationError,
    FixtureClaimMismatch,
    FixtureProvenance,
    FixtureDowngradeBinding,
    FixtureDigest,
    ExecutionMagic,
    ExecutionVersion,
    ExecutionId,
    ExecutionSemver,
    ExecutionModes,
    ExecutionArchitecture,
    ExecutionNumerics,
    ExecutionDriverOrder,
    ExecutionTickPolicy,
    ExecutionSchemas,
    ExecutionArtifacts,
    ExecutionNetwork,
    ExecutionBudget,
    ExecutionCompatibility,
    ExecutionPrevious,
    ExecutionDigest,
    RegistryMagic,
    RegistryVersion,
    RegistryProviders,
    RegistryDigest,
    PackageMagic,
    PackageVersion,
    PackageProvider,
    PackageClaimLayer,
    PackageAdapter,
    PackageSchemas,
    PackageSupportRole,
    PackageDigest,
}

#[derive(Clone, Copy)]
pub enum BundleMutation {
    PathBoundary(u8),
    ExpectedCaseBoundary(u8),
    RawManifestField(u8),
    RawDescriptorField(u8),
    RawMemberField(u8),
    RawExpectedField(u8),
    RawArchiveField(u8),
    Magic,
    Version,
    Mode,
    ProfileDigest,
    DescriptorOrder,
    DescriptorDuplicate,
    DescriptorSize,
    DescriptorDigest,
    DescriptorRole,
    MemberOrder,
    MemberDuplicate,
    MemberBytes,
    ExpectedOrder,
    ExpectedDuplicate,
    Signer,
    Signature,
    ArchiveShape,
}

#[derive(Clone, Copy)]
pub enum TrustMutation {
    IdentifierBoundary(u8),
    SemanticVersionBoundary(u8),
    ExpiryBoundary(u8),
    RawField(u8),
    RawRootField(u8),
    RawMinimumVersionField(u8),
    Magic,
    Version,
    PolicyId,
    Epoch,
    RootsEmpty,
    RootsMultiple,
    RootsTooMany,
    AdditionalRoot,
    DuplicateRootKey,
    Revocations,
    RevocationsTooMany,
    RevocationsOrder,
    NonMatchingRevocations,
    RevokedArtifact,
    Replacements,
    ReplacementsTooMany,
    ReplacementsOrder,
    KeyId,
    KeyEpoch,
    Algorithm,
    PublicKey,
    VersionsEmpty,
    VersionsTooMany,
    VersionsOrder,
    Expiry,
    Previous,
    PreviousInvalid,
    Signature,
}

#[derive(Clone, Copy)]
pub enum ReleaseMutation {
    Magic,
    Version,
    Lifecycle,
    CaseId,
    ExecutionDigest,
    TrustDigest,
    FromProvider,
    ToProvider,
    AllowFallback,
    SignerId,
    Signature,
    MissingMember,
    ExtraMember,
    MissingBinding,
}

pub type TestResult<T> = Result<T, Box<dyn Error>>;

struct FixtureExpectation {
    auxiliary: Value,
    oracle: Value,
    expected_outcome: Value,
    expected_error: Value,
}

/// Build a complete independently signed public evaluator corpus.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn corpus() -> TestResult<Corpus> {
    corpus_for_mode(0, None, None, false, None, None, None)
}

/// Build a signed corpus containing additional bytes for secret-scan tests.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn corpus_with_secret(secret: &[u8]) -> TestResult<Corpus> {
    corpus_for_mode(0, Some(secret), None, false, None, None, None)
}

/// Build a complete Air-Gapped corpus with non-network capabilities.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn air_gapped_corpus() -> TestResult<Corpus> {
    corpus_for_mode(1, None, None, false, None, None, None)
}

/// Build a signed corpus whose downgrade admission enables fallback.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn corpus_with_invalid_release_admission() -> TestResult<Corpus> {
    corpus_for_mode(
        0,
        None,
        Some(ReleaseMutation::AllowFallback),
        false,
        None,
        None,
        None,
    )
}

/// Build a signed corpus containing output, typed-failure, and divergence oracles.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn mixed_oracle_corpus() -> TestResult<Corpus> {
    corpus_for_mode(0, None, None, true, None, None, None)
}

/// Build a cryptographically bound corpus with one invalid CPF1 contract field.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn corpus_with_profile_mutation(mutation: ProfileMutation) -> TestResult<Corpus> {
    corpus_for_mode(0, None, None, false, Some(mutation), None, None)
}

/// Build a request-bound corpus containing one signed CFB1 attack shape.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn corpus_with_bundle_mutation(mutation: BundleMutation) -> TestResult<Corpus> {
    corpus_for_mode(0, None, None, false, None, Some(mutation), None)
}

/// Build a request-bound corpus containing one invalid TPS1 authority contract.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn corpus_with_trust_mutation(mutation: TrustMutation) -> TestResult<Corpus> {
    corpus_for_mode(0, None, None, false, None, None, Some(mutation))
}

/// Build a signed corpus containing one invalid RAD1 admission contract.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn corpus_with_release_mutation(mutation: ReleaseMutation) -> TestResult<Corpus> {
    corpus_for_mode(0, None, Some(mutation), false, None, None, None)
}

fn corpus_for_mode(
    mode: u64,
    extra: Option<&[u8]>,
    release_mutation: Option<ReleaseMutation>,
    mixed_oracles: bool,
    profile_mutation: Option<ProfileMutation>,
    bundle_mutation: Option<BundleMutation>,
    trust_mutation: Option<TrustMutation>,
) -> TestResult<Corpus> {
    let signing_key = SigningKey::from_bytes(&[9; 32]);
    let execution_profile = execution_profile(profile_mutation)?;
    let execution_digest = hash(&execution_profile);
    let trust_policy = trust_policy(&signing_key, trust_mutation, execution_digest)?;
    let trust_digest = hash(&trust_policy);
    let expected_output = b"accepted".to_vec();
    let mut members = support_members(&trust_policy, &execution_profile);
    add_provider_contracts(&mut members, profile_mutation)?;
    if let Some(bytes) = extra {
        members.insert("fixtures/prohibited.bin".to_owned(), (bytes.to_vec(), 0));
    }
    let mut hard_caps = hard_caps();
    if let Some(ProfileMutation::SelectedCapBoundary(index)) = profile_mutation {
        select_hard_cap_boundary(&mut hard_caps, index)?;
    }
    let fixtures = fixtures(
        &mut members,
        &signing_key,
        execution_digest,
        trust_digest,
        &expected_output,
        release_mutation,
        mixed_oracles,
    )?;
    let mut profile = profile(
        &members,
        fixtures,
        execution_digest,
        trust_digest,
        &hard_caps,
        mixed_oracles,
    )?;
    if let Some(mutation) = profile_mutation {
        mutate_profile(&mut profile, mutation)?;
    }
    let profile_digest = hash_contract("PiglorOS.ConformanceProfile.v1", &profile)?;
    let mut profile_fields = fields(profile)?;
    profile_fields.push(bytes(&profile_digest));
    members.insert(
        "profile/CPF1.cbor".to_owned(),
        (canonical(&array(profile_fields))?, 2),
    );
    let archive = archive(
        &signing_key,
        &members,
        profile_digest,
        execution_digest,
        mode,
        bundle_mutation,
    )?;
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
            "authority/execution-profiles/test-profile.epf1".to_owned(),
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
    signing_key: &SigningKey,
    execution: [u8; 32],
    trust: [u8; 32],
    expected: &[u8],
    release_mutation: Option<ReleaseMutation>,
    mixed_oracles: bool,
) -> TestResult<Vec<Value>> {
    (0_u64..=6)
        .map(|family| -> TestResult<Value> {
            let case_id = format!("case-{family}");
            let schema_path = format!("providers/test-provider/schema-{family}.json");
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
                let admission = release_admission(
                    signing_key,
                    &case_id,
                    execution,
                    trust,
                    &provider_key(2),
                    &provider_key(1),
                    release_mutation,
                )?;
                let digest = hash(&admission);
                if !matches!(release_mutation, Some(ReleaseMutation::MissingMember)) {
                    members.insert(
                        format!("authority/release-admissions/{case_id}.rad1"),
                        (admission.clone(), 16),
                    );
                }
                if matches!(release_mutation, Some(ReleaseMutation::ExtraMember)) {
                    members.insert(
                        "authority/release-admissions/extra.rad1".to_owned(),
                        (admission, 16),
                    );
                }
                if matches!(release_mutation, Some(ReleaseMutation::MissingBinding)) {
                    Value::Null
                } else {
                    bytes(&digest)
                }
            } else {
                Value::Null
            };
            let expectation =
                fixture_expectation(members, &evidence_path, &output_path, mixed_oracles, family)?;
            let mut fixture = vec![
                text(&case_id),
                Value::Bool(true),
                uint(0),
                uint(family),
                provider,
                uint(0),
                bytes(&execution),
                array(vec![uint(0), uint(1)]),
                descriptor(members, &schema_path)?,
                descriptor(members, &payload_path)?,
                expectation.auxiliary,
                expectation.oracle,
                expectation.expected_outcome,
                expectation.expected_error,
                uint(0),
                uint(0),
                array(vec![uint(100); 8]),
                array(vec![uint(1_000)]),
                array(vec![
                    Value::Bool(false),
                    array(vec![text("read-public-bundle")]),
                ]),
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

fn fixture_expectation(
    members: &BTreeMap<String, (Vec<u8>, u8)>,
    evidence_path: &str,
    output_path: &str,
    mixed_oracles: bool,
    family: u64,
) -> TestResult<FixtureExpectation> {
    let output_and_evidence = || -> TestResult<Value> {
        Ok(array(vec![
            descriptor(members, evidence_path)?,
            descriptor(members, output_path)?,
        ]))
    };
    Ok(match (mixed_oracles, family) {
        (true, 1) => FixtureExpectation {
            auxiliary: output_and_evidence()?,
            oracle: array(vec![
                uint(1),
                Value::Null,
                array(vec![text("test-provider"), text("1.0.0"), text("denied")]),
                Value::Null,
            ]),
            expected_outcome: uint(2),
            expected_error: array(vec![text("test-provider"), text("1.0.0"), text("denied")]),
        },
        (true, 2) => FixtureExpectation {
            auxiliary: output_and_evidence()?,
            oracle: array(vec![
                uint(2),
                Value::Null,
                Value::Null,
                array(vec![uint(2), bytes(&[1, 2])]),
            ]),
            expected_outcome: uint(1),
            expected_error: Value::Null,
        },
        _ => FixtureExpectation {
            auxiliary: array(vec![descriptor(members, evidence_path)?]),
            oracle: array(vec![
                uint(0),
                descriptor(members, output_path)?,
                Value::Null,
                Value::Null,
            ]),
            expected_outcome: uint(0),
            expected_error: Value::Null,
        },
    })
}

fn release_admission(
    signing_key: &SigningKey,
    case_id: &str,
    execution: [u8; 32],
    trust: [u8; 32],
    from: &Value,
    to: &Value,
    mutation: Option<ReleaseMutation>,
) -> TestResult<Vec<u8>> {
    let mut fields = vec![
        text("RAD1"),
        uint(1),
        uint(0),
        text(case_id),
        bytes(&execution),
        bytes(&trust),
        from.clone(),
        to.clone(),
        Value::Bool(false),
        text("test-key"),
    ];
    if let Some(mutation) = mutation {
        match mutation {
            ReleaseMutation::Magic => fields[0] = text("RAD0"),
            ReleaseMutation::Version => fields[1] = uint(2),
            ReleaseMutation::Lifecycle => fields[2] = uint(1),
            ReleaseMutation::CaseId => fields[3] = text("different-case"),
            ReleaseMutation::ExecutionDigest => fields[4] = bytes(&[8; 32]),
            ReleaseMutation::TrustDigest => fields[5] = bytes(&[8; 32]),
            ReleaseMutation::FromProvider => fields[6] = provider_key(3),
            ReleaseMutation::ToProvider => fields[7] = provider_key(0),
            ReleaseMutation::AllowFallback => fields[8] = Value::Bool(true),
            ReleaseMutation::SignerId => fields[9] = text("different-key"),
            ReleaseMutation::Signature
            | ReleaseMutation::MissingMember
            | ReleaseMutation::ExtraMember
            | ReleaseMutation::MissingBinding => {}
        }
    }
    let signature = signing_key
        .sign(&canonical(&array(fields.clone()))?)
        .to_bytes();
    fields.push(if matches!(mutation, Some(ReleaseMutation::Signature)) {
        bytes(&[0; 64])
    } else {
        bytes(&signature)
    });
    canonical(&array(fields))
}

fn add_provider_contracts(
    members: &mut BTreeMap<String, (Vec<u8>, u8)>,
    mutation: Option<ProfileMutation>,
) -> TestResult<()> {
    add_provider_artifacts(members);
    let schemas = provider_schemas(members)?;
    let mut package_fields = vec![
        text("FPP1"),
        uint(1),
        provider_key(1),
        uint(0),
        uint(0),
        array(schemas),
        descriptor(members, "providers/test-provider/LICENSE")?,
        descriptor(members, "providers/test-provider/NOTICE")?,
        descriptor(members, "providers/test-provider/sbom.json")?,
        descriptor(members, "providers/test-provider/provenance.json")?,
        descriptor(members, "providers/test-provider/limitations.md")?,
    ];
    if let Some(mutation) = mutation {
        mutate_provider_package(&mut package_fields, members, mutation)?;
    }
    let package_digest = hash_contract(
        "PiglorOS.Conformance.ProviderPackage.v1",
        &array(package_fields.clone()),
    )?;
    package_fields.push(
        if matches!(mutation, Some(ProfileMutation::PackageDigest)) {
            bytes(&[99; 32])
        } else {
            bytes(&package_digest)
        },
    );
    let package_path = "providers/test-provider/package.cbor";
    members.insert(
        package_path.to_owned(),
        (canonical(&array(package_fields))?, 13),
    );

    add_provider_registry(members, package_path, mutation)
}

fn add_provider_artifacts(members: &mut BTreeMap<String, (Vec<u8>, u8)>) {
    let support = [
        (
            "providers/test-provider/LICENSE",
            b"Apache-2.0".as_slice(),
            5,
        ),
        (
            "providers/test-provider/NOTICE",
            b"test notice".as_slice(),
            6,
        ),
        ("providers/test-provider/sbom.json", b"{}".as_slice(), 7),
        (
            "providers/test-provider/provenance.json",
            b"{}".as_slice(),
            8,
        ),
        (
            "providers/test-provider/limitations.md",
            b"none".as_slice(),
            9,
        ),
    ];
    for (path, contents, role) in support {
        members.insert(path.to_owned(), (contents.to_vec(), role));
    }
    for family in 0_u64..=6 {
        members.insert(
            format!("providers/test-provider/schema-{family}.json"),
            (format!("{{\"family\":{family}}}").into_bytes(), 4),
        );
    }
}

fn provider_schemas(members: &BTreeMap<String, (Vec<u8>, u8)>) -> TestResult<Vec<Value>> {
    (0_u64..=6)
        .map(|family| -> TestResult<Value> {
            Ok(array(vec![
                uint(family),
                descriptor(
                    members,
                    &format!("providers/test-provider/schema-{family}.json"),
                )?,
            ]))
        })
        .collect()
}

fn add_provider_registry(
    members: &mut BTreeMap<String, (Vec<u8>, u8)>,
    package_path: &str,
    mutation: Option<ProfileMutation>,
) -> TestResult<()> {
    let mut registry_fields = vec![
        text("FPR1"),
        uint(1),
        array(vec![array(vec![
            text("test-provider"),
            text("1.0.0"),
            uint(1),
            uint(1),
            uint(0),
            uint(0),
            descriptor_with_media(members, package_path, "application/cbor")?,
        ])]),
    ];
    if let Some(mutation) = mutation {
        mutate_provider_registry(&mut registry_fields, mutation);
    }
    let registry_digest = hash_contract(
        "PiglorOS.Conformance.ProviderRegistry.v1",
        &array(registry_fields.clone()),
    )?;
    registry_fields.push(
        if matches!(mutation, Some(ProfileMutation::RegistryDigest)) {
            bytes(&[99; 32])
        } else {
            bytes(&registry_digest)
        },
    );
    members.insert(
        "authority/fixture-provider-registry.cbor".to_owned(),
        (canonical(&array(registry_fields))?, 12),
    );
    Ok(())
}

fn mutate_provider_package(
    fields: &mut [Value],
    members: &BTreeMap<String, (Vec<u8>, u8)>,
    mutation: ProfileMutation,
) -> TestResult<()> {
    match mutation {
        ProfileMutation::RawPackageField(index) => {
            fields[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawPackageProviderField(index) => {
            array_fields_mut(&mut fields[2])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawPackageSchemaBindingField(index) => {
            let schemas = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut schemas[0])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawPackageSchemaDescriptorField(index) => {
            let schemas = array_fields_mut(&mut fields[5])?;
            let binding = array_fields_mut(&mut schemas[0])?;
            array_fields_mut(&mut binding[1])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawPackageSupportDescriptorField(index) => {
            array_fields_mut(&mut fields[6])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::PackageMagic => fields[0] = text("FPP0"),
        ProfileMutation::PackageVersion => fields[1] = uint(2),
        ProfileMutation::PackageProvider => fields[2] = provider_key(2),
        ProfileMutation::PackageClaimLayer => fields[3] = uint(1),
        ProfileMutation::PackageAdapter => fields[4] = uint(2),
        ProfileMutation::PackageSchemas => fields[5] = array(Vec::new()),
        ProfileMutation::PackageSupportRole => {
            fields[6] = descriptor(members, "providers/test-provider/NOTICE")?;
        }
        _ => {}
    }
    Ok(())
}

fn mutate_provider_registry(fields: &mut [Value], mutation: ProfileMutation) {
    match mutation {
        ProfileMutation::RawRegistryField(index) => {
            fields[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawRegistryRecordField(index) => {
            let Value::Array(providers) = &mut fields[2] else {
                return;
            };
            let Value::Array(record) = &mut providers[0] else {
                return;
            };
            record[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RegistryMagic => fields[0] = text("FPR0"),
        ProfileMutation::RegistryVersion => fields[1] = uint(2),
        ProfileMutation::RegistryProviders => fields[2] = array(Vec::new()),
        _ => {}
    }
}

fn profile(
    members: &BTreeMap<String, (Vec<u8>, u8)>,
    fixtures: Vec<Value>,
    execution: [u8; 32],
    trust: [u8; 32],
    hard_caps: &Value,
    mixed_oracles: bool,
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
                "authority/fixture-provider-registry.cbor",
                "application/cbor",
            )?,
            array(vec![provider_key(1)]),
        ]),
        array(fixtures),
        if mixed_oracles {
            array(vec![array(vec![uint(2), bytes(&[1, 2])])])
        } else {
            array(Vec::new())
        },
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

fn mutate_profile(profile: &mut Value, mutation: ProfileMutation) -> TestResult<()> {
    let profile_fields = array_fields_mut(profile)?;
    if mutate_profile_boundary(profile_fields, mutation)? {
        return Ok(());
    }
    match mutation {
        ProfileMutation::RawProfileField(index) => profile_fields[usize::from(index)] = Value::Null,
        ProfileMutation::RawProviderBindingField(index) => {
            array_fields_mut(&mut profile_fields[8])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawRequiredProviderField(index) => {
            let binding = array_fields_mut(&mut profile_fields[8])?;
            let providers = array_fields_mut(&mut binding[1])?;
            array_fields_mut(&mut providers[0])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawProtocolField(index) => {
            array_fields_mut(&mut profile_fields[11])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawHardCapField(index) => {
            let protocol = array_fields_mut(&mut profile_fields[11])?;
            array_fields_mut(&mut protocol[4])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawRequirementField(index) => {
            array_fields_mut(&mut profile_fields[12])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::Magic => profile_fields[0] = text("CPF0"),
        ProfileMutation::Version => profile_fields[1] = uint(2),
        ProfileMutation::ProfileId => profile_fields[2] = text("Invalid"),
        ProfileMutation::ProfileSemver => profile_fields[3] = text("01.0.0"),
        ProfileMutation::Lifecycle => profile_fields[4] = uint(1),
        ProfileMutation::NormativeDigest => profile_fields[5] = bytes(&[0; 32]),
        ProfileMutation::MatrixDigest => profile_fields[6] = bytes(&[0; 32]),
        ProfileMutation::FixturePolicyDigest => profile_fields[13] = bytes(&[0; 32]),
        ProfileMutation::LimitationsDigest => profile_fields[14] = bytes(&[0; 32]),
        ProfileMutation::PublicationDigest => profile_fields[15] = bytes(&[0; 32]),
        ProfileMutation::PreviousDigest => profile_fields[16] = bytes(&[0; 32]),
        ProfileMutation::ExecutionProfilesEmpty => profile_fields[7] = array(Vec::new()),
        ProfileMutation::ExecutionProfilesUnsorted => {
            profile_fields[7] = array(vec![bytes(&[2; 32]), bytes(&[1; 32])]);
        }
        ProfileMutation::ProvidersEmpty => {
            array_fields_mut(&mut profile_fields[8])?[1] = array(Vec::new());
        }
        ProfileMutation::ProvidersUnsorted => {
            let binding = array_fields_mut(&mut profile_fields[8])?;
            binding[1] = array(vec![provider_key(1), provider_key(1)]);
        }
        ProfileMutation::FixturesEmpty => profile_fields[9] = array(Vec::new()),
        ProfileMutation::FixturesUnsorted => {
            array_fields_mut(&mut profile_fields[9])?.swap(0, 1);
        }
        ProfileMutation::AllowedDivergenceUndeclared => {
            profile_fields[10] = array(vec![array(vec![uint(1), bytes(&[1, 2])])]);
        }
        ProfileMutation::AllowedDivergenceUnsorted => {
            profile_fields[10] = array(vec![
                array(vec![uint(2), bytes(&[2])]),
                array(vec![uint(1), bytes(&[1])]),
            ]);
        }
        ProfileMutation::AllowedDivergenceCoordinate => {
            profile_fields[10] = array(vec![array(vec![uint(1), bytes(&[])])]);
        }
        ProfileMutation::ProtocolId => {
            array_fields_mut(&mut profile_fields[11])?[0] = text("Invalid");
        }
        ProfileMutation::ProtocolDigest => {
            array_fields_mut(&mut profile_fields[11])?[1] = bytes(&[0; 32]);
        }
        ProfileMutation::ProtocolRequestDigest => {
            array_fields_mut(&mut profile_fields[11])?[2] = bytes(&[0; 32]);
        }
        ProfileMutation::ProtocolReportDigest => {
            array_fields_mut(&mut profile_fields[11])?[3] = bytes(&[0; 32]);
        }
        ProfileMutation::HardCapZero => {
            let protocol = array_fields_mut(&mut profile_fields[11])?;
            array_fields_mut(&mut protocol[4])?[0] = uint(0);
        }
        ProfileMutation::HardCapAboveMaximum => {
            let protocol = array_fields_mut(&mut profile_fields[11])?;
            array_fields_mut(&mut protocol[4])?[0] = uint(16 * 1024 * 1024 + 1);
        }
        ProfileMutation::RequirementDigest | ProfileMutation::RequirementDeclaration => {
            let index = usize::from(mutation == ProfileMutation::RequirementDeclaration) + 3;
            array_fields_mut(&mut profile_fields[12])?[index] = bytes(&[0; 32]);
        }
        remaining => mutate_fixture(profile_fields, remaining)?,
    }
    Ok(())
}

fn mutate_profile_boundary(
    profile_fields: &mut [Value],
    mutation: ProfileMutation,
) -> TestResult<bool> {
    match mutation {
        ProfileMutation::IdentifierBoundary(index) => {
            profile_fields[2] = text(&identifier_boundary(index));
        }
        ProfileMutation::SemanticVersionBoundary(index) => {
            profile_fields[3] = text(&semantic_version_boundary(index));
        }
        ProfileMutation::ProviderKeyNumericBoundary(index) => {
            let binding = array_fields_mut(&mut profile_fields[8])?;
            let providers = array_fields_mut(&mut binding[1])?;
            array_fields_mut(&mut providers[0])?[usize::from(index) + 2] = uint(65_536);
        }
        ProfileMutation::DivergenceCoordinateLong => {
            profile_fields[10] = array(vec![array(vec![uint(1), bytes(&[1; 129])])]);
        }
        ProfileMutation::SelectedCapBoundary(_) => {}
        _ => return Ok(false),
    }
    Ok(true)
}

fn mutate_fixture(profile_fields: &mut [Value], mutation: ProfileMutation) -> TestResult<()> {
    let fixtures = array_fields_mut(&mut profile_fields[9])?;
    let fixture_index = if matches!(mutation, ProfileMutation::RawFixtureTransitionField(_)) {
        5
    } else {
        0
    };
    let fixture = fixtures
        .get_mut(fixture_index)
        .ok_or_else(|| io::Error::other("test fixture is missing"))?;
    let fields = array_fields_mut(fixture)?;
    if !mutate_raw_fixture_field(fields, mutation)? && !mutate_fixture_boundary(fields, mutation)? {
        match mutation {
            ProfileMutation::FixtureModesEmpty => fields[7] = array(Vec::new()),
            ProfileMutation::FixtureModesUnsorted => fields[7] = array(vec![uint(1), uint(0)]),
            ProfileMutation::FixtureModeOutOfRange => fields[7] = array(vec![uint(4)]),
            ProfileMutation::FixtureAdapter => fields[5] = uint(9),
            ProfileMutation::FixtureProvider => {
                array_fields_mut(&mut fields[4])?[0] = text("Invalid");
            }
            ProfileMutation::FixtureCaseId => fields[0] = text("Invalid"),
            ProfileMutation::FixtureExecutionDigest => fields[6] = bytes(&[0; 32]),
            ProfileMutation::FixtureClaimLayer => fields[2] = uint(7),
            ProfileMutation::FixtureFamily => fields[3] = uint(7),
            ProfileMutation::FixtureOutcome => fields[12] = uint(6),
            ProfileMutation::FixtureReplay => fields[14] = uint(5),
            ProfileMutation::FixtureRedaction => fields[15] = uint(4),
            ProfileMutation::FixtureBudget => {
                array_fields_mut(&mut fields[16])?[0] = uint(0);
            }
            ProfileMutation::FixtureBudgetAboveCap => {
                array_fields_mut(&mut fields[16])?[0] = uint(101);
            }
            ProfileMutation::FixtureWatchdog => fields[17] = array(vec![uint(0)]),
            ProfileMutation::FixtureNetworkPlugin => {
                fields[5] = uint(2);
                array_fields_mut(&mut fields[18])?[0] = Value::Bool(true);
            }
            ProfileMutation::FixtureNetworkAirGapped => {
                array_fields_mut(&mut fields[18])?[0] = Value::Bool(true);
            }
            ProfileMutation::FixtureCapabilities => {
                array_fields_mut(&mut fields[18])?[1] = excessive_capabilities();
            }
            ProfileMutation::FixtureCapabilitiesUnsorted => {
                array_fields_mut(&mut fields[18])?[1] = array(vec![text("z"), text("a")]);
            }
            ProfileMutation::FixtureAuxiliaryTooMany => {
                let auxiliary = array_fields_mut(&mut fields[10])?;
                *auxiliary = vec![auxiliary[0].clone(); 65];
            }
            ProfileMutation::FixtureDuplicatePath => {
                let schema = fields[8].clone();
                array_fields_mut(&mut fields[10])?[0] = schema;
            }
            ProfileMutation::FixtureDescriptor => {
                fields[8] = invalid_descriptor("../schema", "application/json");
            }
            ProfileMutation::FixturePayloadDescriptor => {
                fields[9] = invalid_descriptor("fixtures//payload", "application/octet-stream");
            }
            ProfileMutation::FixtureOracle => {
                fields[11] = array(vec![uint(9), Value::Null, Value::Null, Value::Null]);
            }
            ProfileMutation::FixtureOracleOutputMissing => {
                fields[11] = array(vec![uint(0), Value::Null, Value::Null, Value::Null]);
            }
            ProfileMutation::FixtureOracleDivergenceCoordinate => {
                fields[11] = divergence_oracle(&[]);
            }
            ProfileMutation::FixtureUnexpectedVerificationError => {
                fields[13] = array(vec![text("pigloros.core"), text("1.0.0"), text("failure")]);
            }
            ProfileMutation::FixtureClaimMismatch => {
                fields[14] = uint(0);
                fields[15] = uint(1);
            }
            ProfileMutation::FixtureProvenance => fields[21] = invalid_provenance(),
            ProfileMutation::FixtureDowngradeBinding => fields[19] = bytes(&[1; 32]),
            ProfileMutation::FixtureDigest => fields[23] = bytes(&[99; 32]),
            _ => return Ok(()),
        }
    }
    if mutation != ProfileMutation::FixtureDigest {
        let digest = hash_contract(
            "PiglorOS.Conformance.Fixture.v1",
            &array(fields[..23].to_vec()),
        )?;
        fields[23] = bytes(&digest);
    }
    Ok(())
}

fn mutate_fixture_boundary(fields: &mut [Value], mutation: ProfileMutation) -> TestResult<bool> {
    match mutation {
        ProfileMutation::FixtureSemanticBoundary(index) => match index {
            0 => fields[2] = uint(1),
            1 => array_fields_mut(&mut fields[4])?[0] = text("a-provider"),
            2 => fields[6] = bytes(&[8; 32]),
            3 => fields[12] = uint(1),
            4 => {
                fields[13] = array(vec![text("pigloros.core"), text("1.0.0"), text("failure")]);
            }
            5 => array_fields_mut(&mut fields[18])?[0] = Value::Bool(true),
            6 => fields[19] = bytes(&[8; 32]),
            7 => fields[20] = bytes(&[8; 32]),
            _ => fields[22] = array(vec![provider_key(0), provider_key(1)]),
        },
        ProfileMutation::ProvenanceBoundary(index) => {
            let provenance = array_fields_mut(&mut fields[21])?;
            if index == 0 {
                provenance[0] = text("");
            } else if index == 1 {
                provenance[0] = text(&"a".repeat(129));
            } else {
                provenance[usize::from(index - 1)] = bytes(&[0; 32]);
            }
        }
        ProfileMutation::DescriptorValueBoundary(index) => {
            let descriptor = array_fields_mut(&mut fields[8])?;
            match index {
                0 => descriptor[2] = uint(0),
                1 => descriptor[2] = uint(64 * 1024 * 1024 + 1),
                _ => descriptor[3] = bytes(&[0; 32]),
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn mutate_raw_fixture_field(fields: &mut [Value], mutation: ProfileMutation) -> TestResult<bool> {
    match mutation {
        ProfileMutation::MemberPathBoundary(index) => {
            array_fields_mut(&mut fields[8])?[0] = text(&member_path_boundary(index));
        }
        ProfileMutation::MediaTypeBoundary(index) => {
            array_fields_mut(&mut fields[8])?[1] = text(&media_type_boundary(index));
        }
        ProfileMutation::RawFixtureField(index) => {
            fields[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawFixtureProviderField(index) => {
            array_fields_mut(&mut fields[4])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawFixtureSchemaField(index) => {
            array_fields_mut(&mut fields[8])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawFixturePayloadField(index) => {
            array_fields_mut(&mut fields[9])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawFixtureAuxiliaryField(index) => {
            let auxiliary = array_fields_mut(&mut fields[10])?;
            array_fields_mut(&mut auxiliary[0])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawFixtureOracleField(index) => {
            array_fields_mut(&mut fields[11])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawFixtureBudgetField(index) => {
            array_fields_mut(&mut fields[16])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawFixtureSafetyField(index) => {
            array_fields_mut(&mut fields[17])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawFixtureCapabilityField(index) => {
            array_fields_mut(&mut fields[18])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawFixtureProvenanceField(index) => {
            array_fields_mut(&mut fields[21])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawFixtureTransitionField(index) => {
            array_fields_mut(&mut fields[22])?[usize::from(index)] = Value::Null;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn excessive_capabilities() -> Value {
    array(
        (0..257)
            .map(|index| text(&format!("capability-{index:03}")))
            .collect(),
    )
}

fn identifier_boundary(index: u8) -> String {
    match index {
        0 => String::new(),
        1 => "a".repeat(129),
        2 => "café".to_owned(),
        3 => "Invalid".to_owned(),
        _ => "invalid@identifier".to_owned(),
    }
}

fn semantic_version_boundary(index: u8) -> String {
    match index {
        0 => String::new(),
        1 => "a".repeat(65),
        2 => "1.0.é".to_owned(),
        3 => "1.0.0+".to_owned(),
        4 => "1.0.0+a+b".to_owned(),
        5 => "1.0.0-".to_owned(),
        6 => "1.0".to_owned(),
        7 => "1.0.0.0".to_owned(),
        8 => ".0.0".to_owned(),
        9 => "01.0.0".to_owned(),
        10 => "a.0.0".to_owned(),
        11 => "1.0.0-alpha..one".to_owned(),
        12 => "1.0.0-alpha_".to_owned(),
        13 => "1.0.0-01".to_owned(),
        14 => "1.0.0+build..one".to_owned(),
        15 => "1.0.0+build_".to_owned(),
        _ => "12345678901.0.0".to_owned(),
    }
}

fn member_path_boundary(index: u8) -> String {
    match index {
        0 => String::new(),
        1 => "a".repeat(513),
        2 => "fixtures/café".to_owned(),
        3 => "/fixtures/value".to_owned(),
        4 => "fixtures/value/".to_owned(),
        5 => "fixtures\\value".to_owned(),
        6 => "fixtures/\0value".to_owned(),
        7 => (0..17).map(|_| "a").collect::<Vec<_>>().join("/"),
        8 => "fixtures//value".to_owned(),
        9 => "fixtures/./value".to_owned(),
        10 => "fixtures/../value".to_owned(),
        _ => format!("fixtures/{}", "a".repeat(129)),
    }
}

fn archive_path_boundary(index: u8) -> String {
    match index {
        0 => String::new(),
        1 => "a".repeat(513),
        2 => "fixtures/café".to_owned(),
        3 => "/fixtures/value".to_owned(),
        4 => "fixtures/value/".to_owned(),
        5 => "fixtures//value".to_owned(),
        6 => "fixtures/./value".to_owned(),
        _ => "fixtures/../value".to_owned(),
    }
}

fn media_type_boundary(index: u8) -> String {
    match index {
        0 => "a/".to_owned(),
        1 => format!("a/{}", "b".repeat(126)),
        2 => "application/café".to_owned(),
        3 => "application-json".to_owned(),
        4 => "application/json/value".to_owned(),
        5 => "/json".to_owned(),
        6 => "application/".to_owned(),
        7 => "Application/json".to_owned(),
        _ => "application/j@son".to_owned(),
    }
}

fn execution_list_boundary(index: u8) -> Value {
    match index {
        0 => array(Vec::new()),
        1 => array(
            (0..257)
                .map(|value| text(&format!("item-{value}")))
                .collect(),
        ),
        2 => array(vec![text("duplicate"), text("duplicate")]),
        _ => array(vec![text("Invalid")]),
    }
}

fn expiry_boundary(index: u8) -> String {
    match index {
        0 => String::new(),
        1 => "2".repeat(65),
        2 => "2099-01-01T00:00:00é".to_owned(),
        _ => "2099-01-01T00:00:00Z!".to_owned(),
    }
}

fn expected_case_boundary(index: u8) -> String {
    if index == 0 {
        String::new()
    } else {
        "a".repeat(129)
    }
}

fn invalid_descriptor(path: &str, media_type: &str) -> Value {
    array(vec![text(path), text(media_type), uint(1), bytes(&[1; 32])])
}

fn invalid_provenance() -> Value {
    array(vec![
        text("Apache-2.0"),
        bytes(&[0; 32]),
        bytes(&[1; 32]),
        bytes(&[1; 32]),
        bytes(&[1; 32]),
        bytes(&[1; 32]),
        bytes(&[1; 32]),
    ])
}

fn divergence_oracle(coordinate: &[u8]) -> Value {
    array(vec![
        uint(2),
        Value::Null,
        Value::Null,
        array(vec![uint(1), Value::Bytes(coordinate.to_vec())]),
    ])
}

fn array_fields_mut(value: &mut Value) -> TestResult<&mut Vec<Value>> {
    let Value::Array(fields) = value else {
        return Err(io::Error::other("test value is not an array").into());
    };
    Ok(fields)
}

fn archive(
    signing_key: &SigningKey,
    members: &BTreeMap<String, (Vec<u8>, u8)>,
    profile: [u8; 32],
    execution: [u8; 32],
    mode: u64,
    mutation: Option<BundleMutation>,
) -> TestResult<Vec<u8>> {
    let descriptors: Vec<Value> = members
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
    let archive_members: Vec<Value> = members
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
                uint(mode),
                text(&path),
                bytes(&member_hash(members, &path)?),
            ]);
            Ok((canonical(&value)?, value))
        })
        .collect::<TestResult<Vec<_>>>()?;
    let mut expected = expected;
    expected.sort_by(|left, right| left.0.cmp(&right.0));
    let expected: Vec<Value> = expected.into_iter().map(|(_, value)| value).collect();
    let mut manifest = array(vec![
        text("CFB1"),
        uint(0),
        uint(mode),
        bytes(&profile),
        array(descriptors),
        array(expected),
    ]);
    if let Some(mutation) = mutation {
        mutate_manifest(&mut manifest, mutation)?;
    }
    let signature = signing_key.sign(&canonical(&manifest)?).to_bytes();
    let mut root = array(vec![
        manifest,
        array(archive_members),
        bytes(&signing_key.verifying_key().to_bytes()),
        bytes(&signature),
    ]);
    if let Some(mutation) = mutation {
        mutate_archive_root(&mut root, mutation)?;
    }
    canonical(&root)
}

fn mutate_manifest(manifest: &mut Value, mutation: BundleMutation) -> TestResult<()> {
    let fields = array_fields_mut(manifest)?;
    match mutation {
        BundleMutation::PathBoundary(index) => {
            let descriptors = array_fields_mut(&mut fields[4])?;
            array_fields_mut(&mut descriptors[0])?[0] = text(&archive_path_boundary(index));
        }
        BundleMutation::ExpectedCaseBoundary(index) => {
            let expected = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut expected[0])?[0] = text(&expected_case_boundary(index));
        }
        BundleMutation::RawManifestField(index) => fields[usize::from(index)] = Value::Null,
        BundleMutation::RawDescriptorField(index) => {
            let descriptors = array_fields_mut(&mut fields[4])?;
            array_fields_mut(&mut descriptors[0])?[usize::from(index)] = Value::Null;
        }
        BundleMutation::RawExpectedField(index) => {
            let expected = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut expected[0])?[usize::from(index)] = Value::Null;
        }
        BundleMutation::Magic => fields[0] = text("CFB0"),
        BundleMutation::Version => fields[1] = uint(1),
        BundleMutation::Mode => fields[2] = uint(2),
        BundleMutation::ProfileDigest => fields[3] = bytes(&[0; 32]),
        BundleMutation::DescriptorOrder => array_fields_mut(&mut fields[4])?.swap(0, 1),
        BundleMutation::DescriptorDuplicate => {
            let descriptors = array_fields_mut(&mut fields[4])?;
            descriptors.push(descriptors[0].clone());
        }
        BundleMutation::DescriptorSize => {
            let descriptors = array_fields_mut(&mut fields[4])?;
            array_fields_mut(&mut descriptors[0])?[1] = uint(u64::MAX);
        }
        BundleMutation::DescriptorDigest => {
            let descriptors = array_fields_mut(&mut fields[4])?;
            array_fields_mut(&mut descriptors[0])?[2] = bytes(&[99; 32]);
        }
        BundleMutation::DescriptorRole => {
            let descriptors = array_fields_mut(&mut fields[4])?;
            array_fields_mut(&mut descriptors[0])?[3] = uint(19);
        }
        BundleMutation::ExpectedOrder => array_fields_mut(&mut fields[5])?.swap(0, 1),
        BundleMutation::ExpectedDuplicate => {
            let expected = array_fields_mut(&mut fields[5])?;
            expected.push(expected[0].clone());
        }
        BundleMutation::RawMemberField(_)
        | BundleMutation::RawArchiveField(_)
        | BundleMutation::MemberOrder
        | BundleMutation::MemberDuplicate
        | BundleMutation::MemberBytes
        | BundleMutation::Signer
        | BundleMutation::Signature
        | BundleMutation::ArchiveShape => {}
    }
    Ok(())
}

fn mutate_archive_root(root: &mut Value, mutation: BundleMutation) -> TestResult<()> {
    let fields = array_fields_mut(root)?;
    match mutation {
        BundleMutation::RawArchiveField(index) => fields[usize::from(index)] = Value::Null,
        BundleMutation::RawMemberField(index) => {
            let members = array_fields_mut(&mut fields[1])?;
            array_fields_mut(&mut members[0])?[usize::from(index)] = Value::Null;
        }
        BundleMutation::MemberOrder => array_fields_mut(&mut fields[1])?.swap(0, 1),
        BundleMutation::MemberDuplicate => {
            let members = array_fields_mut(&mut fields[1])?;
            members.push(members[0].clone());
        }
        BundleMutation::MemberBytes => {
            let members = array_fields_mut(&mut fields[1])?;
            array_fields_mut(&mut members[0])?[1] = Value::Bytes(vec![99]);
        }
        BundleMutation::Signer => fields[2] = bytes(&[8; 32]),
        BundleMutation::Signature => fields[3] = bytes(&[0; 64]),
        BundleMutation::ArchiveShape => {
            fields.pop();
        }
        _ => {}
    }
    Ok(())
}

fn trust_policy(
    signing_key: &SigningKey,
    mutation: Option<TrustMutation>,
    revoked_artifact: [u8; 32],
) -> TestResult<Vec<u8>> {
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
    if let Some(mutation) = mutation {
        mutate_trust_policy(&mut fields, mutation, revoked_artifact)?;
    }
    let signature = signing_key
        .sign(&canonical(&array(fields.clone()))?)
        .to_bytes();
    fields.push(if matches!(mutation, Some(TrustMutation::Signature)) {
        bytes(&[0; 64])
    } else {
        bytes(&signature)
    });
    canonical(&array(fields))
}

fn mutate_trust_policy(
    fields: &mut [Value],
    mutation: TrustMutation,
    revoked_artifact: [u8; 32],
) -> TestResult<()> {
    match mutation {
        TrustMutation::IdentifierBoundary(index) => {
            fields[2] = text(&identifier_boundary(index));
        }
        TrustMutation::SemanticVersionBoundary(index) => {
            let versions = array_fields_mut(&mut fields[8])?;
            array_fields_mut(&mut versions[0])?[1] = text(&semantic_version_boundary(index));
        }
        TrustMutation::ExpiryBoundary(index) => {
            fields[9] = text(&expiry_boundary(index));
        }
        TrustMutation::RawField(index) => fields[usize::from(index)] = Value::Null,
        TrustMutation::RawRootField(index) => {
            let roots = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut roots[0])?[usize::from(index)] = Value::Null;
        }
        TrustMutation::RawMinimumVersionField(index) => {
            let versions = array_fields_mut(&mut fields[8])?;
            array_fields_mut(&mut versions[0])?[usize::from(index)] = Value::Null;
        }
        TrustMutation::Magic => fields[0] = text("TPS0"),
        TrustMutation::Version => fields[1] = uint(2),
        TrustMutation::PolicyId => fields[2] = text("Invalid"),
        TrustMutation::Epoch => fields[3] = uint(0),
        TrustMutation::RootsEmpty => fields[5] = array(Vec::new()),
        TrustMutation::RootsMultiple => {
            let roots = array_fields_mut(&mut fields[5])?;
            roots.push(roots[0].clone());
        }
        TrustMutation::RootsTooMany => fields[5] = excessive_trust_roots(),
        TrustMutation::AdditionalRoot => add_secondary_root(fields, false)?,
        TrustMutation::Revocations => fields[6] = array(vec![text("test-key")]),
        TrustMutation::RevocationsTooMany => fields[6] = excessive_revocations(),
        TrustMutation::RevocationsOrder => {
            fields[6] = array(vec![text("z-key"), text("a-key")]);
        }
        TrustMutation::NonMatchingRevocations => {
            fields[6] = array(vec![text("retired-key")]);
            fields[7] = array(vec![bytes(&[7; 32])]);
        }
        TrustMutation::RevokedArtifact => fields[7] = array(vec![bytes(&revoked_artifact)]),
        TrustMutation::Replacements => fields[7] = array(vec![text("replacement")]),
        TrustMutation::ReplacementsTooMany => {
            fields[7] = array((0..4_097).map(|_| bytes(&[1; 32])).collect());
        }
        TrustMutation::ReplacementsOrder => {
            fields[7] = array(vec![bytes(&[2; 32]), bytes(&[1; 32])]);
        }
        TrustMutation::DuplicateRootKey => add_secondary_root(fields, true)?,
        TrustMutation::KeyId => {
            let roots = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut roots[0])?[0] = text("Invalid");
        }
        TrustMutation::KeyEpoch => {
            let roots = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut roots[0])?[1] = uint(0);
        }
        TrustMutation::Algorithm => {
            let roots = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut roots[0])?[2] = text("unknown");
        }
        TrustMutation::PublicKey => {
            let roots = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut roots[0])?[3] = bytes(&[8; 32]);
        }
        TrustMutation::VersionsEmpty => fields[8] = array(Vec::new()),
        TrustMutation::VersionsTooMany => fields[8] = excessive_minimum_versions(),
        TrustMutation::VersionsOrder => {
            fields[8] = array(vec![
                array(vec![text("z-contract"), text("1.0.0")]),
                array(vec![text("a-contract"), text("1.0.0")]),
            ]);
        }
        TrustMutation::Expiry => fields[9] = text("invalid expiry!"),
        TrustMutation::Previous => fields[10] = bytes(&[1; 32]),
        TrustMutation::PreviousInvalid => fields[10] = bytes(&[1; 31]),
        TrustMutation::Signature => {}
    }
    Ok(())
}

fn excessive_trust_roots() -> Value {
    array(
        (0_u8..65)
            .map(|index| {
                let key = SigningKey::from_bytes(&[index; 32]);
                array(vec![
                    text(&format!("key-{index:02}")),
                    uint(1),
                    text("Ed25519"),
                    bytes(&key.verifying_key().to_bytes()),
                ])
            })
            .collect(),
    )
}

fn excessive_revocations() -> Value {
    array(
        (0..4_097)
            .map(|index| text(&format!("key-{index:04}")))
            .collect(),
    )
}

fn excessive_minimum_versions() -> Value {
    array(
        (0..257)
            .map(|index| array(vec![text(&format!("kind-{index:03}")), text("1.0.0")]))
            .collect(),
    )
}

fn add_secondary_root(fields: &mut [Value], duplicate_key: bool) -> TestResult<()> {
    let roots = array_fields_mut(&mut fields[5])?;
    let public_key = if duplicate_key {
        array_fields_mut(&mut roots[0])?[3].clone()
    } else {
        bytes(&SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes())
    };
    roots.insert(
        0,
        array(vec![
            text("secondary-key"),
            uint(1),
            text("Ed25519"),
            public_key,
        ]),
    );
    Ok(())
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

fn execution_profile(mutation: Option<ProfileMutation>) -> TestResult<Vec<u8>> {
    let mut fields = vec![
        text("EPF1"),
        uint(1),
        text("test-profile"),
        text("1.0.0"),
        array(vec![uint(0), uint(1)]),
        array(vec![text("fixed-architecture")]),
        array(vec![text("integer-arithmetic")]),
        array(vec![text("canonical-driver-order")]),
        text("logical-ticks"),
        array(vec![text("explicit-schema-version")]),
        array(vec![text("digest-bound-artifacts")]),
        array(vec![Value::Bool(false), array(Vec::new())]),
        array(vec![uint(100); 8]),
        array(Vec::new()),
        array(vec![text("1.0.0"), text("1.0.0")]),
        Value::Null,
    ];
    if let Some(mutation) = mutation {
        mutate_execution_profile(&mut fields, mutation)?;
    }
    let digest = hash_contract("PiglorOS.ExecutionProfile.v1", &array(fields.clone()))?;
    fields.push(
        if matches!(mutation, Some(ProfileMutation::ExecutionDigest)) {
            bytes(&[99; 32])
        } else {
            bytes(&digest)
        },
    );
    canonical(&array(fields))
}

fn mutate_execution_profile(fields: &mut [Value], mutation: ProfileMutation) -> TestResult<()> {
    match mutation {
        ProfileMutation::ExecutionContractBoundary(index) => match index {
            0 => fields[2] = text("alternate-profile"),
            1 => fields[5] = array(Vec::new()),
            2 => fields[6] = array(Vec::new()),
            3 => fields[7] = array(Vec::new()),
            4 => fields[9] = array(Vec::new()),
            5 => fields[10] = array(Vec::new()),
            6 => fields[13] = array(vec![text("same"), text("same")]),
            7 => {
                array_fields_mut(&mut fields[11])?[1] = array(vec![text("same"), text("same")]);
            }
            8 => array_fields_mut(&mut fields[14])?[0] = text("invalid"),
            _ => array_fields_mut(&mut fields[14])?[1] = text("invalid"),
        },
        ProfileMutation::ExecutionListBoundary(index) => {
            fields[5] = execution_list_boundary(index);
        }
        ProfileMutation::RawExecutionField(index) => {
            fields[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawExecutionNetworkField(index) => {
            array_fields_mut(&mut fields[11])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawExecutionBudgetField(index) => {
            array_fields_mut(&mut fields[12])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawExecutionVersionField(index) => {
            array_fields_mut(&mut fields[14])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::ExecutionMagic => fields[0] = text("EPF0"),
        ProfileMutation::ExecutionVersion => fields[1] = uint(2),
        ProfileMutation::ExecutionId => fields[2] = text("Invalid"),
        ProfileMutation::ExecutionSemver => fields[3] = text("invalid"),
        ProfileMutation::ExecutionModes => fields[4] = array(vec![uint(1), uint(0)]),
        ProfileMutation::ExecutionArchitecture => fields[5] = array(Vec::new()),
        ProfileMutation::ExecutionNumerics => fields[6] = array(Vec::new()),
        ProfileMutation::ExecutionDriverOrder => fields[7] = array(Vec::new()),
        ProfileMutation::ExecutionTickPolicy => fields[8] = text("Invalid"),
        ProfileMutation::ExecutionSchemas => fields[9] = array(Vec::new()),
        ProfileMutation::ExecutionArtifacts => fields[10] = array(Vec::new()),
        ProfileMutation::ExecutionNetwork => {
            fields[11] = array(vec![Value::Bool(true), array(Vec::new())]);
        }
        ProfileMutation::ExecutionBudget => {
            array_fields_mut(&mut fields[12])?[0] = uint(0);
        }
        ProfileMutation::ExecutionCompatibility => {
            fields[14] = array(vec![text("invalid"), text("1.0.0")]);
        }
        ProfileMutation::ExecutionPrevious => fields[15] = bytes(&[1; 32]),
        _ => {}
    }
    Ok(())
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

fn select_hard_cap_boundary(hard_caps: &mut Value, index: u8) -> TestResult<()> {
    let cap_index = match index {
        0 => 1,
        1 => 2,
        2 => 3,
        3 => 4,
        4 => 5,
        5 => 7,
        _ => 9,
    };
    array_fields_mut(hard_caps)?[cap_index] = uint(u64::from(cap_index != 9));
    Ok(())
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

const fn array(values: Vec<Value>) -> Value {
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
