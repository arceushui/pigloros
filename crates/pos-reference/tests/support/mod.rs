use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::io::Write as _;
use std::path::Path;

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use flate2::write::GzEncoder;
use flate2::Compression;
use pos_reference::evaluator_build_identity::{
    verify_evaluator_build_identity, EvaluatorBuildEvidence, VerifiedEvaluatorBuildIdentity,
};
use pos_reference::evaluator_protocol::{
    EvaluationRequest, ImplementationIdentity, IndependenceEvidence, OutputCapability,
    SubjectAdapterKind,
};

pub struct Corpus {
    pub request: Vec<u8>,
    pub archive: Vec<u8>,
    pub trust_policy: Vec<u8>,
    pub subject_digest: [u8; 32],
    pub expected_output: Vec<u8>,
}

const SUBJECT_DIGEST: [u8; 32] = [41; 32];

/// Build and verify the current public test executable's evaluator evidence package.
///
/// # Errors
/// Returns an error when the temporary package cannot be written or verified.
pub fn verified_evaluator_identity() -> TestResult<VerifiedEvaluatorBuildIdentity> {
    verified_evaluator_identity_with(IndependenceEvidence {
        technical_independent: true,
        authorship_independent: true,
        organizational_independent: false,
        declaration_digest: [47; 32],
        shared_code_audit_digest: [64; 32],
        reviewer_ids: vec!["reviewer-one".to_owned()],
    })
}

/// Build and verify an evaluator evidence package with the supplied independence claims.
///
/// # Errors
/// Returns an error when the temporary package cannot be written or verified.
pub fn verified_evaluator_identity_with(
    independence: IndependenceEvidence,
) -> TestResult<VerifiedEvaluatorBuildIdentity> {
    let directory = tempfile::tempdir()?;
    write_evaluator_package(directory.path(), &std::env::current_exe()?)?;
    verify_evaluator_build_identity(
        &EvaluatorBuildEvidence::new(
            directory.path().join("source/pigloros-source.tar.gz"),
            directory.path().join("provenance.json"),
        ),
        independence,
        100,
    )
    .map_err(|error| -> Box<dyn Error> { Box::new(error) })
}

/// Prove that a corrupted canonical checksum inventory cannot authorize report emission.
///
/// # Errors
/// Returns an error when the temporary package cannot be prepared.
///
/// # Panics
/// Panics if the public verifier accepts the corrupted inventory.
pub fn evaluator_evidence_rejects_corrupted_checksum() -> TestResult<()> {
    let directory = tempfile::tempdir()?;
    write_evaluator_package(directory.path(), &std::env::current_exe()?)?;
    fs::write(directory.path().join("BLAKE3SUMS"), b"corrupted\n")?;
    let result = verify_evaluator_build_identity(
        &EvaluatorBuildEvidence::new(
            directory.path().join("source/pigloros-source.tar.gz"),
            directory.path().join("provenance.json"),
        ),
        IndependenceEvidence {
            technical_independent: true,
            authorship_independent: true,
            organizational_independent: false,
            declaration_digest: [47; 32],
            shared_code_audit_digest: [64; 32],
            reviewer_ids: vec!["reviewer-one".to_owned()],
        },
        100,
    );
    assert!(result.is_err());
    Ok(())
}

pub(crate) fn write_evaluator_package(directory: &Path, binary: &Path) -> TestResult<()> {
    fs::create_dir_all(directory.join("source"))?;
    fs::create_dir_all(directory.join("bin"))?;
    let source = source_archive("1111111111111111111111111111111111111111")?;
    fs::write(directory.join("source/pigloros-source.tar.gz"), &source)?;
    fs::copy(binary, directory.join("bin/pos-reference-evaluator"))?;
    fs::write(
        directory.join("Cargo.lock"),
        b"public test dependency lock\n",
    )?;
    fs::write(directory.join("sbom.cdx.json"), b"{}\n")?;
    fs::write(directory.join("licences.json"), b"{}\n")?;
    write_evaluator_provenance(directory, &source)?;
    write_checksum_inventory(directory)
}

pub(crate) fn write_evaluator_provenance(directory: &Path, source: &[u8]) -> TestResult<()> {
    let binary = fs::read(directory.join("bin/pos-reference-evaluator"))?;
    let lock = fs::read(directory.join("Cargo.lock"))?;
    let sbom = fs::read(directory.join("sbom.cdx.json"))?;
    let licences = fs::read(directory.join("licences.json"))?;
    let provenance = serde_json::json!({
        "build_target": "public-test-target",
        "cargo_locked": true,
        "dependency_lock_blake3": blake3::hash(&lock).to_hex().to_string(),
        "evaluator_binary_blake3": blake3::hash(&binary).to_hex().to_string(),
        "evaluator_source_blake3": blake3::hash(source).to_hex().to_string(),
        "licences_blake3": blake3::hash(&licences).to_hex().to_string(),
        "rust_toolchain": "rustc public-test-toolchain",
        "sbom_blake3": blake3::hash(&sbom).to_hex().to_string(),
        "schema": "PiglorOS.EvaluatorBuildProvenance.v1",
        "source_commit": "1111111111111111111111111111111111111111",
    });
    let mut bytes = serde_json::to_vec(&provenance)?;
    bytes.push(b'\n');
    fs::write(directory.join("provenance.json"), bytes)?;
    Ok(())
}

pub(crate) fn write_checksum_inventory(directory: &Path) -> TestResult<()> {
    let paths = [
        "Cargo.lock",
        "bin/pos-reference-evaluator",
        "licences.json",
        "provenance.json",
        "sbom.cdx.json",
        "source/pigloros-source.tar.gz",
    ];
    let mut inventory = String::new();
    for path in paths {
        writeln!(
            inventory,
            "{}  {path}",
            blake3::hash(&fs::read(directory.join(path))?).to_hex()
        )?;
    }
    fs::write(directory.join("BLAKE3SUMS"), inventory)?;
    Ok(())
}

pub(crate) fn source_archive(commit: &str) -> TestResult<Vec<u8>> {
    gzip_bytes(&source_tar(commit))
}

pub(crate) fn source_tar(commit: &str) -> Vec<u8> {
    let record = pax_record("comment", commit.as_bytes());
    let mut tar = Vec::new();
    tar.extend_from_slice(&tar_header("pax_global_header", record.len(), b'g'));
    tar.extend_from_slice(&record);
    tar.resize(tar.len().div_ceil(512) * 512, 0);
    for path in [
        "Cargo.lock",
        "Cargo.toml",
        "crates/pos-reference/Cargo.toml",
        "crates/pos-reference/src/bin/pos-reference-evaluator.rs",
    ] {
        tar.extend_from_slice(&tar_header(path, 0, b'0'));
    }
    tar.extend_from_slice(&[0; 1024]);
    tar
}

pub(crate) fn gzip_bytes(bytes: &[u8]) -> TestResult<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}

pub(crate) fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
    let mut body = Vec::from(key.as_bytes());
    body.push(b'=');
    body.extend_from_slice(value);
    body.push(b'\n');
    let mut length = body.len() + 2;
    loop {
        let prefix = format!("{length} ");
        let encoded_length = prefix.len() + body.len();
        if encoded_length == length {
            let mut record = Vec::from(prefix.as_bytes());
            record.extend_from_slice(&body);
            return record;
        }
        length = encoded_length;
    }
}

pub(crate) fn tar_header(name: &str, size: usize, kind: u8) -> [u8; 512] {
    let mut header = [0_u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    write_octal(&mut header[100..108], 0o644);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], size as u64);
    write_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = kind;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    write_tar_checksum(&mut header);
    header
}

pub(crate) fn write_tar_checksum(header: &mut [u8; 512]) {
    header[148..156].fill(b' ');
    let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    let encoded = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(encoded.as_bytes());
}

fn write_octal(field: &mut [u8], value: u64) {
    let encoded = format!("{:0width$o}\0", value, width = field.len() - 1);
    field.copy_from_slice(encoded.as_bytes());
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ProfileMutation {
    ArtifactEncoding(u8),
    ArtifactShape(u8),
    RecordShape(u8),
    ProviderKeyNumericBoundary(u8),
    DivergenceCoordinateLong,
    SelectedCapBoundary(u8),
    SelectedCompressionCapBoundary,
    SelectedProfileByteCapBoundary,
    SelectedProfileByteCapExact,
    SelectedClosureCapBoundary(u8),
    SelectedClosureCapExact(u8),
    ExecutionContractBoundary(u8),
    FixtureSemanticBoundary(u8),
    ProvenanceBoundary(u8),
    DescriptorValueBoundary(u8),
    RelationshipBoundary(u8),
    ProviderContractBoundary(u8),
    MemberClosureBoundary(u8),
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
    DeepTypeBoundary(u8),
    Magic,
    Version,
    ProfileId,
    ProfileSemver,
    Lifecycle(u8),
    NormativeDigest,
    MatrixDigest,
    MatrixContent,
    MatrixBoundary(u8),
    MatrixExecutedCase,
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
    OrganizationalIndependenceRequired,
    FixtureModesEmpty,
    FixtureModesUnsorted,
    FixtureModeOutOfRange,
    FixtureModeOverflow,
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
    FixtureBudgetAboveExecutionProfile,
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
    FixtureDivergenceCoordinateType,
    FixtureUnexpectedVerificationError,
    FixtureFailureVersion,
    FixtureClaimMismatch,
    FixtureClaimState(u8),
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

const MEMBER_CLOSURE_PATHS: [&str; 45] = [
    "authority/fixture-provider-registry.cbor",
    "authority/execution-profiles/test-profile.epf1",
    "providers/test-provider/package.cbor",
    "support/normative-requirements.md",
    "authority/execution-matrix.json",
    "support/fixture-family-contract.json",
    "support/limitations.md",
    "support/publication-review.json",
    "support/evaluator-protocol-v1.json",
    "support/evaluator-request-v1.cddl",
    "support/evaluator-report-v1.cddl",
    "providers/test-provider/LICENSE",
    "providers/test-provider/NOTICE",
    "providers/test-provider/sbom.json",
    "providers/test-provider/provenance.json",
    "providers/test-provider/limitations.md",
    "providers/test-provider/schema-0.json",
    "providers/test-provider/schema-1.json",
    "providers/test-provider/schema-2.json",
    "providers/test-provider/schema-3.json",
    "providers/test-provider/schema-4.json",
    "providers/test-provider/schema-5.json",
    "providers/test-provider/schema-6.json",
    "fixtures/case-0.input",
    "fixtures/case-0.evidence",
    "fixtures/case-0.expected",
    "fixtures/case-1.input",
    "fixtures/case-1.evidence",
    "fixtures/case-1.expected",
    "fixtures/case-2.input",
    "fixtures/case-2.evidence",
    "fixtures/case-2.expected",
    "fixtures/case-3.input",
    "fixtures/case-3.evidence",
    "fixtures/case-3.expected",
    "fixtures/case-4.input",
    "fixtures/case-4.evidence",
    "fixtures/case-4.expected",
    "fixtures/case-5.input",
    "fixtures/case-5.evidence",
    "fixtures/case-5.expected",
    "fixtures/case-6.input",
    "fixtures/case-6.evidence",
    "fixtures/case-6.expected",
    "authority/release-admissions/case-5.rad1",
];

pub const MEMBER_CLOSURE_BOUNDARY_COUNT: u8 = 94;

#[must_use]
pub fn member_closure_breaks_archive(index: u8) -> bool {
    MEMBER_CLOSURE_PATHS
        .get(usize::from(index))
        .is_some_and(|path| path.ends_with(".expected"))
}

#[derive(Clone, Copy)]
pub enum BundleMutation {
    Encoding,
    ManifestShape,
    DescriptorRecordShape,
    MemberRecordShape,
    ExpectedRecordShape,
    PathBoundary(u8),
    ExpectedCaseBoundary(u8),
    DescriptorEmpty,
    DescriptorRoleOverflow,
    DescriptorMissingPath,
    MemberEmpty,
    MemberRoleOverflow,
    MemberRoleAboveMaximum,
    MemberMissing,
    ExpectedClaimLayerOverflow,
    ExpectedModeOverflow,
    ExpectedClaimLayerAbove,
    ExpectedModeAbove,
    ExpectedMissingPath,
    ExpectedDigest,
    ExpectedPathType,
    ExpectedInvalidPath,
    ExpectedCountAboveMaximum,
    ProfileExpectedCount,
    ProfileExpectedCase,
    ProfileExpectedMode,
    ProfileExpectedBinding,
    RawManifestField(u8),
    RawDescriptorField(u8),
    RawMemberField(u8),
    RawExpectedField(u8),
    RawArchiveField(u8),
    Magic,
    Version,
    Mode,
    ModeOverflow,
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
    Encoding,
    Shape,
    RootRecordShape,
    MinimumVersionRecordShape,
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
    RevocationKeyType,
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
    SignatureType,
}

#[derive(Clone, Copy)]
pub enum ReleaseMutation {
    Encoding,
    Shape,
    RawField(u8),
    RawFromProviderField(u8),
    RawToProviderField(u8),
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

#[derive(Clone, Copy)]
struct CorpusOptions<'a> {
    mode: u64,
    claim_layer: u64,
    subject_adapter: SubjectAdapterKind,
    extra: Option<&'a [u8]>,
    release_mutation: Option<ReleaseMutation>,
    mixed_oracles: bool,
    failure_outcome: Option<u8>,
    profile_mutation: Option<ProfileMutation>,
    bundle_mutation: Option<BundleMutation>,
    trust_mutation: Option<TrustMutation>,
}

impl Default for CorpusOptions<'_> {
    fn default() -> Self {
        Self {
            mode: 0,
            claim_layer: 0,
            subject_adapter: SubjectAdapterKind::ExportedArtifact,
            extra: None,
            release_mutation: None,
            mixed_oracles: false,
            failure_outcome: None,
            profile_mutation: None,
            bundle_mutation: None,
            trust_mutation: None,
        }
    }
}

/// Build a complete independently signed public evaluator corpus.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn corpus() -> TestResult<Corpus> {
    corpus_for_options(CorpusOptions::default())
}

/// Build a complete corpus for one public subject adapter protocol.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn corpus_for_adapter(adapter: SubjectAdapterKind) -> TestResult<Corpus> {
    corpus_for_options(CorpusOptions {
        subject_adapter: adapter,
        ..CorpusOptions::default()
    })
}

/// Build a complete corpus for one CPF1 claim layer.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn corpus_for_claim_layer(claim_layer: u8) -> TestResult<Corpus> {
    corpus_for_options(CorpusOptions {
        claim_layer: u64::from(claim_layer),
        ..CorpusOptions::default()
    })
}

/// Build a signed corpus containing additional bytes for secret-scan tests.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn corpus_with_secret(secret: &[u8]) -> TestResult<Corpus> {
    corpus_for_options(CorpusOptions {
        extra: Some(secret),
        ..CorpusOptions::default()
    })
}

/// Build a complete Air-Gapped corpus with non-network capabilities.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn air_gapped_corpus() -> TestResult<Corpus> {
    corpus_for_options(CorpusOptions {
        mode: 1,
        ..CorpusOptions::default()
    })
}

/// Build a signed corpus whose downgrade admission enables fallback.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn corpus_with_invalid_release_admission() -> TestResult<Corpus> {
    corpus_for_options(CorpusOptions {
        release_mutation: Some(ReleaseMutation::AllowFallback),
        ..CorpusOptions::default()
    })
}

/// Build a signed corpus containing output, typed-failure, and divergence oracles.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn mixed_oracle_corpus() -> TestResult<Corpus> {
    corpus_for_options(CorpusOptions {
        mixed_oracles: true,
        ..CorpusOptions::default()
    })
}

/// Build a signed mixed-oracle corpus with one current typed failure outcome.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn mixed_oracle_corpus_with_failure_outcome(outcome: u8) -> TestResult<Corpus> {
    corpus_for_options(CorpusOptions {
        mixed_oracles: true,
        failure_outcome: Some(outcome),
        ..CorpusOptions::default()
    })
}

/// Build a cryptographically bound corpus with one invalid CPF1 contract field.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn corpus_with_profile_mutation(mutation: ProfileMutation) -> TestResult<Corpus> {
    corpus_for_options(CorpusOptions {
        profile_mutation: Some(mutation),
        ..CorpusOptions::default()
    })
}

/// Build a signed corpus that combines a selected-cap violation with secret material.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn corpus_with_selected_closure_cap_and_secret(
    cap_index: u8,
    secret: &[u8],
) -> TestResult<Corpus> {
    corpus_for_options(CorpusOptions {
        extra: Some(secret),
        profile_mutation: Some(ProfileMutation::SelectedClosureCapBoundary(cap_index)),
        ..CorpusOptions::default()
    })
}

/// Build a signed corpus combining a profile-local selected-cap violation with secret material.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn corpus_with_profile_mutation_and_secret(
    mutation: ProfileMutation,
    secret: &[u8],
) -> TestResult<Corpus> {
    corpus_for_options(CorpusOptions {
        extra: Some(secret),
        profile_mutation: Some(mutation),
        ..CorpusOptions::default()
    })
}

/// Build a request-bound corpus containing one signed CFB1 attack shape.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn corpus_with_bundle_mutation(mutation: BundleMutation) -> TestResult<Corpus> {
    corpus_for_options(CorpusOptions {
        bundle_mutation: Some(mutation),
        ..CorpusOptions::default()
    })
}

/// Build a request-bound corpus containing one invalid TPS1 authority contract.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn corpus_with_trust_mutation(mutation: TrustMutation) -> TestResult<Corpus> {
    corpus_for_options(CorpusOptions {
        trust_mutation: Some(mutation),
        ..CorpusOptions::default()
    })
}

/// Build a signed corpus containing one invalid RAD1 admission contract.
///
/// # Errors
/// Returns an error if canonical encoding or fixture construction fails.
pub fn corpus_with_release_mutation(mutation: ReleaseMutation) -> TestResult<Corpus> {
    corpus_for_options(CorpusOptions {
        release_mutation: Some(mutation),
        ..CorpusOptions::default()
    })
}

fn corpus_for_options(options: CorpusOptions<'_>) -> TestResult<Corpus> {
    let CorpusOptions {
        mode,
        claim_layer,
        subject_adapter,
        extra,
        release_mutation: _,
        mixed_oracles,
        failure_outcome: _,
        profile_mutation,
        bundle_mutation,
        trust_mutation,
    } = options;
    let signing_key = SigningKey::from_bytes(&[9; 32]);
    let execution_profile = execution_profile(profile_mutation)?;
    let execution_digest = hash(&execution_profile);
    let trust_policy = trust_policy(&signing_key, trust_mutation, execution_digest)?;
    let trust_digest = hash(&trust_policy);
    let expected_output = b"accepted".to_vec();
    let mut members = support_members(&trust_policy, &execution_profile);
    mutate_support_members(&mut members, profile_mutation)?;
    let evaluator_protocol_digest = member_hash(&members, "support/evaluator-protocol-v1.json")?;
    add_provider_contracts(&mut members, profile_mutation, subject_adapter, claim_layer)?;
    if let Some(bytes) = extra {
        members.insert("fixtures/prohibited.bin".to_owned(), (bytes.to_vec(), 0));
    }
    let mut hard_caps = hard_caps();
    if let Some(ProfileMutation::SelectedCapBoundary(index)) = profile_mutation {
        select_hard_cap_boundary(&mut hard_caps, index)?;
    }
    if matches!(
        profile_mutation,
        Some(ProfileMutation::SelectedCompressionCapBoundary)
    ) {
        array_fields_mut(&mut hard_caps)?[6] = uint(1);
    }
    if matches!(
        profile_mutation,
        Some(ProfileMutation::SelectedProfileByteCapBoundary)
    ) {
        array_fields_mut(&mut hard_caps)?[0] = uint(1);
    }
    let fixtures = fixtures(
        &mut members,
        &signing_key,
        execution_digest,
        trust_digest,
        &expected_output,
        options,
    )?;
    if let Some(ProfileMutation::SelectedClosureCapBoundary(index)) = profile_mutation {
        select_closure_cap_boundary(&mut hard_caps, &members, index)?;
    }
    if let Some(ProfileMutation::SelectedClosureCapExact(index)) = profile_mutation {
        select_closure_cap_exact(&mut hard_caps, &members, index)?;
    }
    let mut profile_value = profile_with_selected_closure_caps(
        &members,
        &fixtures,
        execution_digest,
        trust_digest,
        &mut hard_caps,
        mixed_oracles,
        profile_mutation,
    )?;
    let exact_profile_byte_cap = exact_profile_byte_cap(profile_mutation, &profile_value)?;
    if let Some(mutation) = profile_mutation {
        mutate_profile(&mut profile_value, mutation)?;
    }
    let profile_digest = hash_contract("PiglorOS.ConformanceProfile.v1", &profile_value)?;
    let mut profile_fields = fields(profile_value)?;
    profile_fields.push(bytes(&profile_digest));
    insert_profile_member(&mut members, profile_fields, profile_mutation)?;
    let archive = archive(
        &signing_key,
        &members,
        profile_digest,
        execution_digest,
        hash(&expected_output),
        mode,
        claim_layer,
        bundle_mutation,
    )?;
    let archive_digest = hash(&archive);
    let hard_caps_digest = hash_contract("PiglorOS.EvaluatorHardCaps.v1", &hard_caps)?;
    let mut request = evaluation_request(
        profile_digest,
        archive_digest,
        subject_adapter,
        execution_digest,
        trust_digest,
        evaluator_protocol_digest,
        hard_caps_digest,
    )?;
    bind_exact_profile_output_cap(&mut request, exact_profile_byte_cap)?;
    Ok(Corpus {
        request: request.to_canonical_cbor()?,
        archive,
        trust_policy,
        subject_digest: SUBJECT_DIGEST,
        expected_output,
    })
}

fn exact_profile_byte_cap(
    mutation: Option<ProfileMutation>,
    profile: &Value,
) -> TestResult<Option<u64>> {
    matches!(mutation, Some(ProfileMutation::SelectedProfileByteCapExact))
        .then(|| encoded_profile_length(profile))
        .transpose()
}

fn bind_exact_profile_output_cap(
    request: &mut EvaluationRequest,
    limit: Option<u64>,
) -> TestResult<()> {
    if let Some(limit) = limit {
        request.output_capability.report_bytes_limit = limit;
        request.output_capability.capability_digest =
            request.expected_output_capability_digest()?;
        request.request_digest = request.digest()?;
    }
    Ok(())
}

fn evaluation_request(
    profile_digest: [u8; 32],
    archive_digest: [u8; 32],
    subject_adapter: SubjectAdapterKind,
    execution_digest: [u8; 32],
    trust_digest: [u8; 32],
    evaluator_protocol_digest: [u8; 32],
    hard_caps_digest: [u8; 32],
) -> TestResult<EvaluationRequest> {
    let mut request = EvaluationRequest {
        request_id: [1; 16],
        profile_digest,
        fixture_bundle_digest: archive_digest,
        subject_adapter,
        subject_artifact_digest: SUBJECT_DIGEST,
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
        evaluator_protocol_digest,
        evaluator_hard_caps_digest: hard_caps_digest,
        request_digest: [1; 32],
    };
    request.output_capability.capability_digest = request.expected_output_capability_digest()?;
    request.request_digest = request.digest()?;
    Ok(request)
}

fn mutate_support_members(
    members: &mut BTreeMap<String, (Vec<u8>, u8)>,
    mutation: Option<ProfileMutation>,
) -> TestResult<()> {
    if matches!(mutation, Some(ProfileMutation::MatrixContent)) {
        members.insert(
            "authority/execution-matrix.json".to_owned(),
            (b"{}".to_vec(), 11),
        );
    }
    if let Some(ProfileMutation::MatrixBoundary(index)) = mutation {
        match index {
            45 => replace_matrix_bytes(members, b"{".to_vec())?,
            46 => replace_matrix_bytes(members, b"[]".to_vec())?,
            _ => mutate_execution_matrix(members, index)?,
        }
    }
    if matches!(mutation, Some(ProfileMutation::MatrixExecutedCase)) {
        mutate_execution_matrix(members, u8::MAX)?;
    }
    Ok(())
}

fn replace_matrix_bytes(
    members: &mut BTreeMap<String, (Vec<u8>, u8)>,
    replacement: Vec<u8>,
) -> TestResult<()> {
    let (bytes, _) = members
        .get_mut("authority/execution-matrix.json")
        .ok_or_else(|| io::Error::other("execution matrix member missing"))?;
    *bytes = replacement;
    Ok(())
}

fn mutate_execution_matrix(
    members: &mut BTreeMap<String, (Vec<u8>, u8)>,
    index: u8,
) -> TestResult<()> {
    let (bytes, _) = members
        .get_mut("authority/execution-matrix.json")
        .ok_or_else(|| io::Error::other("execution matrix member missing"))?;
    let mut matrix: serde_json::Value = serde_json::from_slice(bytes)?;
    let root = matrix
        .as_object_mut()
        .ok_or_else(|| io::Error::other("execution matrix root is not an object"))?;
    mutate_matrix_root(root, index)?;
    *bytes = serde_json::to_vec(&matrix)?;
    Ok(())
}

fn mutate_matrix_root(
    root: &mut serde_json::Map<String, serde_json::Value>,
    index: u8,
) -> TestResult<()> {
    match index {
        0 => drop_json_field(root, "magic"),
        1 => set_json(root, "extra", serde_json::json!(true)),
        2 => set_json(root, "magic", serde_json::json!(1)),
        3 => set_json(root, "magic", serde_json::json!("NIM0")),
        4 => set_json(root, "version", serde_json::json!("1")),
        5 => set_json(root, "version", serde_json::json!(2)),
        6 => set_json(root, "lifecycle", serde_json::json!("Candidate")),
        7 => set_json(root, "row_count", serde_json::json!(11)),
        8 => set_json(root, "variant_count", serde_json::json!(3)),
        9 => set_json(root, "mode_count", serde_json::json!(3)),
        10 => set_json(root, "case_count", serde_json::json!(191)),
        11 => set_json(root, "matrix_id", serde_json::json!("")),
        12 => set_json(root, "source", serde_json::json!("")),
        13 => set_json(root, "expected_result_policy", serde_json::json!("")),
        14 => set_json(root, "rows", serde_json::Value::Null),
        15 => truncate_json_array(root, "rows")?,
        16 => set_json(root, "equality_predicates", serde_json::Value::Null),
        17 => truncate_json_array(root, "equality_predicates")?,
        18 => set_json(root, "cases", serde_json::Value::Null),
        19 => truncate_json_array(root, "cases")?,
        20..=27 => mutate_matrix_row(root, index - 20)?,
        28..=31 => mutate_matrix_predicate(root, index - 28)?,
        32..=42 => mutate_matrix_case(root, index - 32)?,
        43 => set_json(root, "executed_case_count", serde_json::json!(1)),
        44 => set_nested_json(root, "rows", 0, "executed_case_count", serde_json::json!(1))?,
        47 => set_json(root, "lifecycle", serde_json::Value::Null),
        48 => set_json(root, "row_count", serde_json::json!("12")),
        49 => set_json(root, "variant_count", serde_json::json!("4")),
        50 => set_json(root, "mode_count", serde_json::json!("4")),
        51 => set_json(root, "case_count", serde_json::json!("192")),
        52 => set_json(root, "matrix_id", serde_json::Value::Null),
        53 => set_json(root, "source", serde_json::Value::Null),
        54 => set_json(root, "expected_result_policy", serde_json::Value::Null),
        55 => set_json(root, "executed_case_count", serde_json::Value::Null),
        56..=65 => mutate_matrix_row(root, index - 48)?,
        66..=72 => mutate_matrix_predicate(root, index - 62)?,
        73..=84 => mutate_matrix_case(root, index - 62)?,
        85 => mutate_matrix_row(root, 18)?,
        u8::MAX => make_first_matrix_case_executed(root)?,
        _ => return Err(io::Error::other("unknown execution matrix mutation").into()),
    }
    Ok(())
}

fn mutate_matrix_row(
    root: &mut serde_json::Map<String, serde_json::Value>,
    index: u8,
) -> TestResult<()> {
    match index {
        0 => set_json_array_value(root, "rows", 0, serde_json::Value::Null)?,
        1 => drop_nested_json_field(root, "rows", 0, "channel")?,
        2 => set_nested_json(root, "rows", 0, "fixture_id", serde_json::json!("wrong"))?,
        3 => set_nested_json(root, "rows", 0, "variants", serde_json::json!(["S", "D"]))?,
        4 => set_nested_json(root, "rows", 0, "modes", serde_json::json!(["L", "A"]))?,
        5 => set_nested_json(root, "rows", 0, "case_count", serde_json::json!(15))?,
        6 => set_nested_json(root, "rows", 0, "channel", serde_json::json!(""))?,
        7 => set_nested_json(
            root,
            "rows",
            0,
            "observable_surfaces",
            serde_json::json!([]),
        )?,
        8 => set_nested_json(root, "rows", 0, "fixture_id", serde_json::Value::Null)?,
        9 => set_nested_json(root, "rows", 0, "variants", serde_json::Value::Null)?,
        10 => set_nested_json(root, "rows", 0, "modes", serde_json::Value::Null)?,
        11 => set_nested_json(root, "rows", 0, "case_count", serde_json::json!("16"))?,
        12 => set_nested_json(root, "rows", 0, "classification", serde_json::json!(""))?,
        13 => set_nested_json(root, "rows", 0, "equality", serde_json::json!(""))?,
        14 => set_nested_json(
            root,
            "rows",
            0,
            "sole_unauthorized_delta",
            serde_json::json!(""),
        )?,
        15 => set_nested_json(
            root,
            "rows",
            0,
            "observable_surfaces",
            serde_json::Value::Null,
        )?,
        16 => set_nested_json(
            root,
            "rows",
            0,
            "executed_case_count",
            serde_json::json!("0"),
        )?,
        17 => set_nested_json(root, "rows", 0, "extra", serde_json::json!(true))?,
        18 => set_nested_json(root, "rows", 0, "classification", serde_json::Value::Null)?,
        _ => return Err(io::Error::other("unknown matrix row mutation").into()),
    }
    Ok(())
}

fn mutate_matrix_predicate(
    root: &mut serde_json::Map<String, serde_json::Value>,
    index: u8,
) -> TestResult<()> {
    match index {
        0 => set_json_array_value(root, "equality_predicates", 0, serde_json::Value::Null)?,
        1 => drop_nested_json_field(root, "equality_predicates", 0, "AuthEq")?,
        2 => set_nested_json(
            root,
            "equality_predicates",
            0,
            "fixture_id",
            serde_json::json!("wrong"),
        )?,
        3 => set_nested_json(
            root,
            "equality_predicates",
            0,
            "AuthEq",
            serde_json::json!(""),
        )?,
        4 => set_nested_json(
            root,
            "equality_predicates",
            0,
            "fixture_id",
            serde_json::Value::Null,
        )?,
        5 => set_nested_json(
            root,
            "equality_predicates",
            0,
            "AuthEq",
            serde_json::Value::Null,
        )?,
        6 => set_nested_json(
            root,
            "equality_predicates",
            0,
            "PublicEq",
            serde_json::json!(""),
        )?,
        7 => set_nested_json(
            root,
            "equality_predicates",
            0,
            "OpEq",
            serde_json::json!(""),
        )?,
        8 => set_nested_json(
            root,
            "equality_predicates",
            0,
            "PublicEq",
            serde_json::Value::Null,
        )?,
        9 => set_nested_json(
            root,
            "equality_predicates",
            0,
            "OpEq",
            serde_json::Value::Null,
        )?,
        10 => set_nested_json(
            root,
            "equality_predicates",
            0,
            "extra",
            serde_json::json!(true),
        )?,
        _ => return Err(io::Error::other("unknown matrix predicate mutation").into()),
    }
    Ok(())
}

fn mutate_matrix_case(
    root: &mut serde_json::Map<String, serde_json::Value>,
    index: u8,
) -> TestResult<()> {
    match index {
        0 => set_json_array_value(root, "cases", 0, serde_json::Value::Null)?,
        1 => drop_nested_json_field(root, "cases", 0, "case_id")?,
        2 => set_nested_json(root, "cases", 0, "executed", serde_json::json!("false"))?,
        3 => set_nested_json(root, "cases", 0, "case_id", serde_json::json!("wrong"))?,
        4 => set_nested_json(root, "cases", 0, "fixture_id", serde_json::json!("wrong"))?,
        5 => set_nested_json(root, "cases", 0, "variant", serde_json::json!("D"))?,
        6 => set_nested_json(root, "cases", 0, "mode", serde_json::json!("A"))?,
        7 => set_nested_json(
            root,
            "cases",
            0,
            "expected_result",
            serde_json::json!("accepted"),
        )?,
        8 => set_nested_json(
            root,
            "cases",
            0,
            "expected_result_digest",
            serde_json::json!("0".repeat(64)),
        )?,
        9 => set_executed_case(root, serde_json::Value::Null)?,
        10 => set_executed_case(root, serde_json::json!("invalid"))?,
        11 => set_nested_json(root, "cases", 0, "case_id", serde_json::Value::Null)?,
        12 => set_nested_json(root, "cases", 0, "fixture_id", serde_json::Value::Null)?,
        13 => set_nested_json(root, "cases", 0, "variant", serde_json::Value::Null)?,
        14 => set_nested_json(root, "cases", 0, "mode", serde_json::Value::Null)?,
        15 => set_nested_json(
            root,
            "cases",
            0,
            "authority_fixture_id",
            serde_json::json!("authority-case"),
        )?,
        16 => set_nested_json(
            root,
            "cases",
            0,
            "authority_result_digest",
            serde_json::json!("0".repeat(64)),
        )?,
        17 => set_executed_case_without_result(root)?,
        18 => set_executed_case(root, serde_json::json!(1))?,
        19 => set_executed_case(root, serde_json::json!("A".repeat(64)))?,
        20 => set_nested_json(root, "cases", 0, "extra", serde_json::json!(true))?,
        21 => drop_nested_json_field(root, "cases", 0, "expected_result")?,
        22 => drop_nested_json_field(root, "cases", 0, "expected_result_digest")?,
        _ => return Err(io::Error::other("unknown matrix case mutation").into()),
    }
    Ok(())
}

fn set_executed_case_without_result(
    root: &mut serde_json::Map<String, serde_json::Value>,
) -> TestResult<()> {
    set_nested_json(root, "cases", 0, "executed", serde_json::json!(true))?;
    set_nested_json(
        root,
        "cases",
        0,
        "expected_result_digest",
        serde_json::json!("0".repeat(64)),
    )
}

fn set_executed_case(
    root: &mut serde_json::Map<String, serde_json::Value>,
    digest: serde_json::Value,
) -> TestResult<()> {
    set_nested_json(root, "cases", 0, "executed", serde_json::json!(true))?;
    set_nested_json(
        root,
        "cases",
        0,
        "expected_result",
        serde_json::json!("accepted"),
    )?;
    set_nested_json(root, "cases", 0, "expected_result_digest", digest)
}

fn make_first_matrix_case_executed(
    root: &mut serde_json::Map<String, serde_json::Value>,
) -> TestResult<()> {
    set_executed_case(root, serde_json::json!("0".repeat(64)))?;
    set_nested_json(root, "rows", 0, "executed_case_count", serde_json::json!(1))?;
    set_json(root, "executed_case_count", serde_json::json!(1));
    Ok(())
}

fn set_json(
    object: &mut serde_json::Map<String, serde_json::Value>,
    field: &str,
    value: serde_json::Value,
) {
    object.insert(field.to_owned(), value);
}

fn drop_json_field(object: &mut serde_json::Map<String, serde_json::Value>, field: &str) {
    object.retain(|key, _| key != field);
}

fn truncate_json_array(
    root: &mut serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> TestResult<()> {
    json_array_mut(root, field)?.pop();
    Ok(())
}

fn set_json_array_value(
    root: &mut serde_json::Map<String, serde_json::Value>,
    array_field: &str,
    index: usize,
    value: serde_json::Value,
) -> TestResult<()> {
    *json_array_mut(root, array_field)?
        .get_mut(index)
        .ok_or_else(|| io::Error::other("execution matrix index missing"))? = value;
    Ok(())
}

fn set_nested_json(
    root: &mut serde_json::Map<String, serde_json::Value>,
    array_field: &str,
    index: usize,
    field: &str,
    value: serde_json::Value,
) -> TestResult<()> {
    nested_json_object_mut(root, array_field, index)?.insert(field.to_owned(), value);
    Ok(())
}

fn drop_nested_json_field(
    root: &mut serde_json::Map<String, serde_json::Value>,
    array_field: &str,
    index: usize,
    field: &str,
) -> TestResult<()> {
    nested_json_object_mut(root, array_field, index)?.retain(|key, _| key != field);
    Ok(())
}

fn nested_json_object_mut<'a>(
    root: &'a mut serde_json::Map<String, serde_json::Value>,
    array_field: &str,
    index: usize,
) -> TestResult<&'a mut serde_json::Map<String, serde_json::Value>> {
    json_array_mut(root, array_field)?
        .get_mut(index)
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| io::Error::other("execution matrix object missing").into())
}

fn json_array_mut<'a>(
    root: &'a mut serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> TestResult<&'a mut Vec<serde_json::Value>> {
    root.get_mut(field)
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| io::Error::other("execution matrix array missing").into())
}

fn insert_profile_member(
    members: &mut BTreeMap<String, (Vec<u8>, u8)>,
    mut profile_fields: Vec<Value>,
    mutation: Option<ProfileMutation>,
) -> TestResult<()> {
    match mutation {
        Some(ProfileMutation::DeepTypeBoundary(0)) => profile_fields[17] = Value::Null,
        Some(ProfileMutation::DeepTypeBoundary(1)) => profile_fields[17] = bytes(&[99; 32]),
        _ => {}
    }
    let profile_bytes = match mutation {
        Some(ProfileMutation::ArtifactEncoding(0)) => vec![0xff],
        Some(ProfileMutation::ArtifactShape(0)) => canonical(&Value::Null)?,
        _ => canonical(&array(profile_fields))?,
    };
    members.insert("profile/CPF1.cbor".to_owned(), (profile_bytes, 2));
    if let Some(ProfileMutation::MemberClosureBoundary(index)) = mutation {
        mutate_member_closure(members, index);
    }
    Ok(())
}

fn support_members(trust: &[u8], execution: &[u8]) -> BTreeMap<String, (Vec<u8>, u8)> {
    BTreeMap::from([
        (
            "authority/execution-matrix.json".to_owned(),
            (
                include_bytes!("../../../../fixtures/conformance/matrix/execution-matrix.json")
                    .to_vec(),
                11,
            ),
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
            (
                include_bytes!("../../../../fixtures/conformance/support/evaluator-report-v1.cddl")
                    .to_vec(),
                4,
            ),
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

fn mutate_member_closure(members: &mut BTreeMap<String, (Vec<u8>, u8)>, index: u8) {
    let index = usize::from(index);
    if index < MEMBER_CLOSURE_PATHS.len() {
        members.remove(MEMBER_CLOSURE_PATHS[index]);
    } else if index < MEMBER_CLOSURE_PATHS.len() * 2 {
        if let Some((_, role)) =
            members.get_mut(MEMBER_CLOSURE_PATHS[index - MEMBER_CLOSURE_PATHS.len()])
        {
            *role = if *role == 0 { 4 } else { 0 };
        }
    } else {
        match index - MEMBER_CLOSURE_PATHS.len() * 2 {
            0 => {
                if let Some((bytes, _)) = members.get_mut("fixtures/case-0.expected") {
                    *bytes = b"changed".to_vec();
                }
            }
            1 => {
                if let Some((bytes, _)) =
                    members.get_mut("authority/execution-profiles/test-profile.epf1")
                {
                    *bytes = vec![0xff];
                }
            }
            2 => {
                if let Some((bytes, _)) = members.get_mut("providers/test-provider/package.cbor") {
                    *bytes = vec![0xff];
                }
            }
            _ => {
                members.insert(
                    "providers/undeclared/package.cbor".to_owned(),
                    (b"undeclared".to_vec(), 13),
                );
            }
        }
    }
}

fn fixtures(
    members: &mut BTreeMap<String, (Vec<u8>, u8)>,
    signing_key: &SigningKey,
    execution: [u8; 32],
    trust: [u8; 32],
    expected: &[u8],
    options: CorpusOptions<'_>,
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
                    options.release_mutation,
                )?;
                let digest = hash(&admission);
                if !matches!(
                    options.release_mutation,
                    Some(ReleaseMutation::MissingMember)
                ) {
                    members.insert(
                        format!("authority/release-admissions/{case_id}.rad1"),
                        (admission.clone(), 16),
                    );
                }
                if matches!(options.release_mutation, Some(ReleaseMutation::ExtraMember)) {
                    members.insert(
                        "authority/release-admissions/extra.rad1".to_owned(),
                        (admission, 16),
                    );
                }
                if matches!(
                    options.release_mutation,
                    Some(ReleaseMutation::MissingBinding)
                ) {
                    Value::Null
                } else {
                    bytes(&digest)
                }
            } else {
                Value::Null
            };
            let expectation = fixture_expectation(
                members,
                &evidence_path,
                &output_path,
                options.mixed_oracles,
                options.failure_outcome,
                family,
            )?;
            let mut fixture = vec![
                text(&case_id),
                Value::Bool(true),
                uint(options.claim_layer),
                uint(family),
                provider,
                uint(adapter_code(options.subject_adapter)),
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
    failure_outcome: Option<u8>,
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
            expected_outcome: uint(u64::from(failure_outcome.unwrap_or(2))),
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
            ReleaseMutation::RawField(index) if index < 10 => {
                fields[usize::from(index)] = Value::Null;
            }
            ReleaseMutation::RawFromProviderField(index) => {
                array_fields_mut(&mut fields[6])?[usize::from(index)] = Value::Null;
            }
            ReleaseMutation::RawToProviderField(index) => {
                array_fields_mut(&mut fields[7])?[usize::from(index)] = Value::Null;
            }
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
            | ReleaseMutation::Encoding
            | ReleaseMutation::Shape
            | ReleaseMutation::RawField(_)
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
    } else if matches!(mutation, Some(ReleaseMutation::RawField(10))) {
        Value::Null
    } else {
        bytes(&signature)
    });
    match mutation {
        Some(ReleaseMutation::Encoding) => Ok(vec![0xff]),
        Some(ReleaseMutation::Shape) => canonical(&Value::Null),
        _ => canonical(&array(fields)),
    }
}

fn add_provider_contracts(
    members: &mut BTreeMap<String, (Vec<u8>, u8)>,
    mutation: Option<ProfileMutation>,
    subject_adapter: SubjectAdapterKind,
    claim_layer: u64,
) -> TestResult<()> {
    add_provider_artifacts(members);
    let schemas = provider_schemas(members)?;
    let mut package_fields = vec![
        text("FPP1"),
        uint(1),
        provider_key(1),
        uint(claim_layer),
        uint(adapter_code(subject_adapter)),
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
        } else if matches!(mutation, Some(ProfileMutation::DeepTypeBoundary(36))) {
            Value::Null
        } else {
            bytes(&package_digest)
        },
    );
    let package_path = "providers/test-provider/package.cbor";
    let package_bytes = match mutation {
        Some(ProfileMutation::ArtifactEncoding(3)) => vec![0xff],
        Some(ProfileMutation::ArtifactShape(3)) => canonical(&Value::Null)?,
        _ => canonical(&array(package_fields))?,
    };
    members.insert(package_path.to_owned(), (package_bytes, 13));

    add_provider_registry(
        members,
        package_path,
        mutation,
        subject_adapter,
        claim_layer,
    )
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
    subject_adapter: SubjectAdapterKind,
    claim_layer: u64,
) -> TestResult<()> {
    let mut registry_fields = vec![
        text("FPR1"),
        uint(1),
        array(vec![array(vec![
            text("test-provider"),
            text("1.0.0"),
            uint(1),
            uint(1),
            uint(claim_layer),
            uint(adapter_code(subject_adapter)),
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
        } else if matches!(mutation, Some(ProfileMutation::DeepTypeBoundary(37))) {
            Value::Null
        } else {
            bytes(&registry_digest)
        },
    );
    let registry_bytes = match mutation {
        Some(ProfileMutation::ArtifactEncoding(2)) => vec![0xff],
        Some(ProfileMutation::ArtifactShape(2)) => canonical(&Value::Null)?,
        _ => canonical(&array(registry_fields))?,
    };
    members.insert(
        "authority/fixture-provider-registry.cbor".to_owned(),
        (registry_bytes, 12),
    );
    Ok(())
}

const fn adapter_code(adapter: SubjectAdapterKind) -> u64 {
    match adapter {
        SubjectAdapterKind::ExportedArtifact => 0,
        SubjectAdapterKind::PublicGatewayProtocol => 1,
        SubjectAdapterKind::PublicPluginProtocol => 2,
    }
}

fn mutate_provider_package(
    fields: &mut [Value],
    members: &BTreeMap<String, (Vec<u8>, u8)>,
    mutation: ProfileMutation,
) -> TestResult<()> {
    match mutation {
        ProfileMutation::DeepTypeBoundary(28) => {
            array_fields_mut(&mut fields[5])?[0] = Value::Null;
        }
        ProfileMutation::DeepTypeBoundary(29) => {
            let schemas = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut schemas[0])?[0] = Value::Null;
        }
        ProfileMutation::DeepTypeBoundary(30) => {
            let schemas = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut schemas[0])?[1] = Value::Null;
        }
        ProfileMutation::DeepTypeBoundary(31) => fields[6] = Value::Null,
        ProfileMutation::DeepTypeBoundary(34) => fields[3] = Value::Null,
        ProfileMutation::DeepTypeBoundary(41) => {
            let schemas = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut schemas[0])?[1] =
                descriptor(members, "providers/test-provider/NOTICE")?;
        }
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
        ProfileMutation::ProviderContractBoundary(0) => fields[3] = uint(7),
        ProfileMutation::ProviderContractBoundary(2) => {
            let schemas = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut schemas[0])?[0] = uint(1);
        }
        ProfileMutation::ProviderContractBoundary(3) => {
            let schemas = array_fields_mut(&mut fields[5])?;
            let first_descriptor = array_fields_mut(&mut schemas[0])?[1].clone();
            array_fields_mut(&mut schemas[1])?[1] = first_descriptor;
        }
        ProfileMutation::ProviderContractBoundary(4) => fields[4] = uint(1),
        ProfileMutation::ProviderContractBoundary(5) | ProfileMutation::PackageClaimLayer => {
            fields[3] = uint(1);
        }
        ProfileMutation::ProviderContractBoundary(6) => {
            let schemas = array_fields_mut(&mut fields[5])?;
            let first = array_fields_mut(&mut schemas[0])?[1].clone();
            let second = array_fields_mut(&mut schemas[1])?[1].clone();
            array_fields_mut(&mut schemas[0])?[1] = second;
            array_fields_mut(&mut schemas[1])?[1] = first;
        }
        ProfileMutation::ProviderContractBoundary(7) => fields[4] = uint(3),
        ProfileMutation::PackageMagic => fields[0] = text("FPP0"),
        ProfileMutation::PackageVersion => fields[1] = uint(2),
        ProfileMutation::PackageProvider => fields[2] = provider_key(2),
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
        ProfileMutation::DeepTypeBoundary(32) => fields[2] = array(vec![Value::Null]),
        ProfileMutation::DeepTypeBoundary(33) => {
            let Value::Array(providers) = &mut fields[2] else {
                return;
            };
            let Value::Array(record) = &mut providers[0] else {
                return;
            };
            record[4] = Value::Null;
        }
        ProfileMutation::DeepTypeBoundary(38) => {
            let Value::Array(providers) = &mut fields[2] else {
                return;
            };
            let Value::Array(record) = &mut providers[0] else {
                return;
            };
            record[4] = uint(256);
        }
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
        ProfileMutation::ProviderContractBoundary(index) => {
            let Value::Array(providers) = &mut fields[2] else {
                return;
            };
            if index == 8 {
                providers.push(providers[0].clone());
                return;
            }
            let Value::Array(record) = &mut providers[0] else {
                return;
            };
            match index {
                0 => record[4] = uint(7),
                1 => {
                    let Value::Array(descriptor) = &mut record[6] else {
                        return;
                    };
                    descriptor[1] = text("application/json");
                }
                4 => record[5] = uint(1),
                5 => record[4] = uint(1),
                7 => record[5] = uint(3),
                _ => {}
            }
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
    if mutate_record_shape(profile_fields, mutation)? {
        return Ok(());
    }
    if mutate_profile_boundary(profile_fields, mutation)? {
        return Ok(());
    }
    if mutate_raw_profile_field(profile_fields, mutation)? {
        return Ok(());
    }
    if mutate_deep_profile_field(profile_fields, mutation)? {
        return Ok(());
    }
    match mutation {
        ProfileMutation::Magic => profile_fields[0] = text("CPF0"),
        ProfileMutation::Version => profile_fields[1] = uint(2),
        ProfileMutation::ProfileId => profile_fields[2] = text("Invalid"),
        ProfileMutation::ProfileSemver => profile_fields[3] = text("01.0.0"),
        ProfileMutation::Lifecycle(value) => profile_fields[4] = uint(u64::from(value)),
        ProfileMutation::NormativeDigest => profile_fields[5] = bytes(&[0; 32]),
        ProfileMutation::MatrixDigest => profile_fields[6] = bytes(&[0; 32]),
        ProfileMutation::MatrixContent
        | ProfileMutation::MatrixBoundary(_)
        | ProfileMutation::MatrixExecutedCase
        | ProfileMutation::ArtifactEncoding(_)
        | ProfileMutation::ArtifactShape(_) => {}
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
        ProfileMutation::RelationshipBoundary(3) => {
            let binding = array_fields_mut(&mut profile_fields[8])?;
            binding[1] = array(vec![provider_key(1), provider_key(2)]);
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
        ProfileMutation::OrganizationalIndependenceRequired => {
            array_fields_mut(&mut profile_fields[12])?[2] = Value::Bool(true);
        }
        remaining => mutate_fixture(profile_fields, remaining)?,
    }
    Ok(())
}

fn mutate_deep_profile_field(fields: &mut [Value], mutation: ProfileMutation) -> TestResult<bool> {
    let ProfileMutation::DeepTypeBoundary(index) = mutation else {
        return Ok(false);
    };
    match index {
        6 => {
            fields[10] = array(vec![array(vec![Value::Null, bytes(&[1])])]);
        }
        7 => {
            fields[10] = array(vec![array(vec![uint(1), Value::Null])]);
        }
        18 => {
            fields[7] = array(vec![Value::Null]);
        }
        22 => fields[16] = Value::Bool(false),
        26 => {
            let binding = array_fields_mut(&mut fields[8])?;
            array_fields_mut(&mut binding[0])?[2] = Value::Null;
        }
        27 => {
            let binding = array_fields_mut(&mut fields[8])?;
            let providers = array_fields_mut(&mut binding[1])?;
            array_fields_mut(&mut providers[0])?[2] = Value::Null;
        }
        40 => {
            let binding = array_fields_mut(&mut fields[8])?;
            array_fields_mut(&mut binding[0])?[1] = text("application/json");
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn mutate_raw_profile_field(fields: &mut [Value], mutation: ProfileMutation) -> TestResult<bool> {
    match mutation {
        ProfileMutation::RawProfileField(index) => fields[usize::from(index)] = Value::Null,
        ProfileMutation::RawProviderBindingField(index) => {
            array_fields_mut(&mut fields[8])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawRequiredProviderField(index) => {
            let binding = array_fields_mut(&mut fields[8])?;
            let providers = array_fields_mut(&mut binding[1])?;
            array_fields_mut(&mut providers[0])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawProtocolField(index) => {
            array_fields_mut(&mut fields[11])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawHardCapField(index) => {
            let protocol = array_fields_mut(&mut fields[11])?;
            array_fields_mut(&mut protocol[4])?[usize::from(index)] = Value::Null;
        }
        ProfileMutation::RawRequirementField(index) => {
            array_fields_mut(&mut fields[12])?[usize::from(index)] = Value::Null;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn mutate_record_shape(fields: &mut [Value], mutation: ProfileMutation) -> TestResult<bool> {
    let ProfileMutation::RecordShape(index) = mutation else {
        return Ok(false);
    };
    match index {
        0 => fields[8] = Value::Null,
        1 => array_fields_mut(&mut fields[8])?[1] = array(vec![Value::Null]),
        2 => fields[11] = Value::Null,
        3 => array_fields_mut(&mut fields[11])?[4] = Value::Null,
        4 => fields[12] = Value::Null,
        5 => array_fields_mut(&mut fields[9])?[0] = Value::Null,
        16 => fields[10] = array(vec![Value::Null]),
        _ => {
            mutate_fixture(fields, mutation)?;
        }
    }
    Ok(true)
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
        ProfileMutation::SelectedCapBoundary(_)
        | ProfileMutation::SelectedCompressionCapBoundary
        | ProfileMutation::SelectedProfileByteCapBoundary
        | ProfileMutation::SelectedProfileByteCapExact => {}
        _ => return Ok(false),
    }
    Ok(true)
}

fn mutate_fixture(profile_fields: &mut [Value], mutation: ProfileMutation) -> TestResult<()> {
    let fixtures = array_fields_mut(&mut profile_fields[9])?;
    let fixture_index = if matches!(
        mutation,
        ProfileMutation::RawFixtureTransitionField(_)
            | ProfileMutation::DeepTypeBoundary(5)
            | ProfileMutation::FixtureSemanticBoundary(8)
    ) {
        5
    } else {
        0
    };
    let fixture = fixtures
        .get_mut(fixture_index)
        .ok_or_else(|| io::Error::other("test fixture is missing"))?;
    let fields = array_fields_mut(fixture)?;
    if !mutate_raw_fixture_field(fields, mutation)?
        && !mutate_deep_fixture_field(fields, mutation)?
        && !mutate_fixture_boundary(fields, mutation)?
        && !mutate_fixture_relationship(fields, mutation)?
    {
        match mutation {
            ProfileMutation::FixtureModesEmpty => fields[7] = array(Vec::new()),
            ProfileMutation::FixtureModesUnsorted => fields[7] = array(vec![uint(1), uint(0)]),
            ProfileMutation::FixtureModeOutOfRange => fields[7] = array(vec![uint(4)]),
            ProfileMutation::FixtureModeOverflow => fields[7] = array(vec![uint(256)]),
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
                array_fields_mut(&mut fields[16])?[0] = uint(1024 * 1024 * 1024 + 1);
            }
            ProfileMutation::FixtureBudgetAboveExecutionProfile => {
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
    if matches!(mutation, ProfileMutation::DeepTypeBoundary(2)) {
        fields[23] = Value::Null;
    }
    Ok(())
}

fn mutate_deep_fixture_field(fields: &mut [Value], mutation: ProfileMutation) -> TestResult<bool> {
    let ProfileMutation::DeepTypeBoundary(index) = mutation else {
        return Ok(false);
    };
    match index {
        0..=2 | 6 | 7 | 18 | 22..=38 | 40 | 41 => {}
        3 => array_fields_mut(&mut fields[7])?[0] = Value::Null,
        4 => fields[19] = Value::Bool(false),
        5 => fields[20] = Value::Bool(false),
        8 => {
            fields[11] = array(vec![uint(0), Value::Bool(false), Value::Null, Value::Null]);
        }
        9 => {
            fields[11] = array(vec![uint(1), Value::Null, Value::Bool(false), Value::Null]);
        }
        10 => {
            fields[11] = array(vec![uint(2), Value::Null, Value::Null, Value::Null]);
        }
        11 => {
            fields[11] = array(vec![
                uint(2),
                Value::Null,
                Value::Null,
                array(vec![Value::Null, bytes(&[1])]),
            ]);
        }
        12 => array_fields_mut(&mut fields[8])?[2] = Value::Null,
        13 => array_fields_mut(&mut fields[8])?[3] = Value::Null,
        14 => fields[13] = Value::Bool(false),
        15 => {
            fields[13] = array(vec![Value::Null, text("1.0.0"), text("failure")]);
        }
        16 => {
            fields[13] = array(vec![text("owner"), Value::Null, text("failure")]);
        }
        17 => {
            fields[13] = array(vec![text("owner"), text("1.0.0"), Value::Null]);
        }
        19 => {
            let capability = array_fields_mut(&mut fields[18])?;
            array_fields_mut(&mut capability[1])?[0] = Value::Null;
        }
        20 => array_fields_mut(&mut fields[16])?[0] = Value::Bool(false),
        21 => array_fields_mut(&mut fields[17])?[0] = Value::Bool(false),
        39 => fields[2] = uint(256),
        _ => return Err(io::Error::other("unknown deep profile boundary").into()),
    }
    Ok(true)
}

fn mutate_fixture_relationship(
    fields: &mut [Value],
    mutation: ProfileMutation,
) -> TestResult<bool> {
    match mutation {
        ProfileMutation::FixtureOracleDivergenceCoordinate => {
            fields[11] = divergence_oracle(&[]);
        }
        ProfileMutation::FixtureDivergenceCoordinateType => {
            fields[11] = array(vec![
                uint(2),
                Value::Null,
                Value::Null,
                array(vec![uint(0), text("coordinate")]),
            ]);
        }
        ProfileMutation::FixtureUnexpectedVerificationError => {
            fields[13] = array(vec![text("pigloros.core"), text("1.0.0"), text("failure")]);
        }
        ProfileMutation::FixtureFailureVersion => {
            fields[13] = array(vec![text("pigloros.core"), text("01.0.0"), text("failure")]);
        }
        ProfileMutation::FixtureClaimMismatch => {
            fields[14] = uint(0);
            fields[15] = uint(1);
        }
        ProfileMutation::FixtureClaimState(state) => {
            fields[14] = uint(u64::from(state));
            fields[15] = uint(u64::from(state));
        }
        ProfileMutation::RelationshipBoundary(index) => match index {
            0 => fields[3] = uint(1),
            1 => {
                fields[11] = divergence_oracle(&[9]);
                fields[12] = uint(1);
            }
            2 => fields[7] = array(vec![uint(0)]),
            4 => {
                let evidence = array_fields_mut(&mut fields[10])?[0].clone();
                fields[11] = array(vec![uint(0), evidence, Value::Null, Value::Null]);
            }
            _ => {}
        },
        _ => return Ok(false),
    }
    Ok(true)
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
            8 => fields[22] = array(vec![provider_key(0), provider_key(1)]),
            _ => fields[7] = array(vec![uint(1)]),
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
        ProfileMutation::RecordShape(index) => match index {
            6 => fields[4] = Value::Null,
            7 => fields[8] = Value::Null,
            8 => fields[9] = Value::Null,
            9 => fields[10] = array(vec![Value::Null]),
            10 => fields[11] = Value::Null,
            11 => fields[16] = Value::Null,
            12 => fields[17] = Value::Null,
            13 => fields[18] = Value::Null,
            14 => fields[21] = Value::Null,
            15 => fields[22] = Value::Bool(false),
            _ => return Ok(false),
        },
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
    expected_output_digest: [u8; 32],
    mode: u64,
    claim_layer: u64,
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
                uint(claim_layer),
                bytes(&execution),
                uint(mode),
                text(&path),
                bytes(
                    &members
                        .get(&path)
                        .map_or(expected_output_digest, |(member, _)| hash(member)),
                ),
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
    if matches!(mutation, Some(BundleMutation::Encoding)) {
        Ok(vec![0xff])
    } else {
        canonical(&root)
    }
}

fn mutate_manifest(manifest: &mut Value, mutation: BundleMutation) -> TestResult<()> {
    let fields = array_fields_mut(manifest)?;
    if mutate_profile_expected_result(fields, mutation)? || mutate_archive_record(fields, mutation)?
    {
        return Ok(());
    }
    if mutate_manifest_boundary(fields, mutation)? {
        return Ok(());
    }
    if mutate_manifest_descriptor(fields, mutation)? {
        return Ok(());
    }
    match mutation {
        BundleMutation::ExpectedClaimLayerOverflow => {
            let expected = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut expected[0])?[1] = uint(256);
        }
        BundleMutation::ExpectedModeOverflow => {
            let expected = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut expected[0])?[3] = uint(256);
        }
        BundleMutation::ExpectedClaimLayerAbove => {
            let expected = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut expected[0])?[1] = uint(7);
        }
        BundleMutation::ExpectedModeAbove => {
            let expected = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut expected[0])?[3] = uint(2);
        }
        BundleMutation::ExpectedMissingPath => {
            let expected = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut expected[0])?[4] = text("fixtures/missing.expected");
        }
        BundleMutation::ExpectedDigest => {
            let expected = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut expected[0])?[5] = bytes(&[99; 32]);
        }
        BundleMutation::ExpectedPathType => {
            let expected = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut expected[0])?[4] = Value::Null;
        }
        BundleMutation::ExpectedInvalidPath => {
            let expected = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut expected[0])?[4] = text("../expected");
        }
        BundleMutation::ExpectedCountAboveMaximum => {
            let expected = array_fields_mut(&mut fields[5])?;
            *expected = vec![expected[0].clone(); 65_537];
        }
        BundleMutation::RawManifestField(index) => fields[usize::from(index)] = Value::Null,
        BundleMutation::RawExpectedField(index) => {
            let expected = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut expected[0])?[usize::from(index)] = Value::Null;
        }
        BundleMutation::Magic => fields[0] = text("CFB0"),
        BundleMutation::Version => fields[1] = uint(1),
        BundleMutation::Mode => fields[2] = uint(2),
        BundleMutation::ModeOverflow => fields[2] = uint(256),
        BundleMutation::ProfileDigest => fields[3] = bytes(&[0; 32]),
        BundleMutation::ExpectedOrder => array_fields_mut(&mut fields[5])?.swap(0, 1),
        BundleMutation::ExpectedDuplicate => {
            let expected = array_fields_mut(&mut fields[5])?;
            expected.push(expected[0].clone());
        }
        BundleMutation::RawMemberField(_)
        | BundleMutation::RawArchiveField(_)
        | BundleMutation::RawDescriptorField(_)
        | BundleMutation::PathBoundary(_)
        | BundleMutation::ExpectedCaseBoundary(_)
        | BundleMutation::DescriptorEmpty
        | BundleMutation::DescriptorRoleOverflow
        | BundleMutation::DescriptorMissingPath
        | BundleMutation::DescriptorOrder
        | BundleMutation::DescriptorDuplicate
        | BundleMutation::DescriptorSize
        | BundleMutation::DescriptorDigest
        | BundleMutation::DescriptorRole
        | BundleMutation::Encoding
        | BundleMutation::ManifestShape
        | BundleMutation::DescriptorRecordShape
        | BundleMutation::MemberRecordShape
        | BundleMutation::ExpectedRecordShape
        | BundleMutation::MemberEmpty
        | BundleMutation::MemberRoleOverflow
        | BundleMutation::MemberRoleAboveMaximum
        | BundleMutation::MemberMissing
        | BundleMutation::MemberOrder
        | BundleMutation::MemberDuplicate
        | BundleMutation::MemberBytes
        | BundleMutation::Signer
        | BundleMutation::Signature
        | BundleMutation::ArchiveShape
        | BundleMutation::ProfileExpectedCount
        | BundleMutation::ProfileExpectedCase
        | BundleMutation::ProfileExpectedMode
        | BundleMutation::ProfileExpectedBinding => {}
    }
    Ok(())
}

fn mutate_manifest_descriptor(fields: &mut [Value], mutation: BundleMutation) -> TestResult<bool> {
    let descriptors = match mutation {
        BundleMutation::DescriptorEmpty => {
            fields[4] = array(Vec::new());
            return Ok(true);
        }
        BundleMutation::RawDescriptorField(_)
        | BundleMutation::DescriptorRoleOverflow
        | BundleMutation::DescriptorMissingPath
        | BundleMutation::DescriptorOrder
        | BundleMutation::DescriptorDuplicate
        | BundleMutation::DescriptorSize
        | BundleMutation::DescriptorDigest
        | BundleMutation::DescriptorRole => array_fields_mut(&mut fields[4])?,
        _ => return Ok(false),
    };
    match mutation {
        BundleMutation::RawDescriptorField(index) => {
            array_fields_mut(&mut descriptors[0])?[usize::from(index)] = Value::Null;
        }
        BundleMutation::DescriptorRoleOverflow => {
            array_fields_mut(&mut descriptors[0])?[3] = uint(256);
        }
        BundleMutation::DescriptorMissingPath => {
            array_fields_mut(&mut descriptors[0])?[0] = text("aaa");
        }
        BundleMutation::DescriptorOrder => descriptors.swap(0, 1),
        BundleMutation::DescriptorDuplicate => descriptors.push(descriptors[0].clone()),
        BundleMutation::DescriptorSize => {
            array_fields_mut(&mut descriptors[0])?[1] = uint(u64::MAX);
        }
        BundleMutation::DescriptorDigest => {
            array_fields_mut(&mut descriptors[0])?[2] = bytes(&[99; 32]);
        }
        BundleMutation::DescriptorRole => {
            array_fields_mut(&mut descriptors[0])?[3] = uint(19);
        }
        _ => {}
    }
    Ok(true)
}

fn mutate_manifest_boundary(fields: &mut [Value], mutation: BundleMutation) -> TestResult<bool> {
    match mutation {
        BundleMutation::PathBoundary(index) => {
            let descriptors = array_fields_mut(&mut fields[4])?;
            array_fields_mut(&mut descriptors[0])?[0] = text(&archive_path_boundary(index));
        }
        BundleMutation::ExpectedCaseBoundary(index) => {
            let expected = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut expected[0])?[0] = text(&expected_case_boundary(index));
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn mutate_archive_record(fields: &mut [Value], mutation: BundleMutation) -> TestResult<bool> {
    let field = match mutation {
        BundleMutation::DescriptorRecordShape => &mut fields[4],
        BundleMutation::ExpectedRecordShape => &mut fields[5],
        _ => return Ok(false),
    };
    array_fields_mut(field)?[0] = Value::Null;
    Ok(true)
}

fn mutate_profile_expected_result(
    fields: &mut [Value],
    mutation: BundleMutation,
) -> TestResult<bool> {
    match mutation {
        BundleMutation::ProfileExpectedCount => {
            array_fields_mut(&mut fields[5])?
                .pop()
                .ok_or_else(|| io::Error::other("test expected result is missing"))?;
        }
        BundleMutation::ProfileExpectedCase => {
            let expected = array_fields_mut(&mut fields[5])?;
            let last = expected
                .last_mut()
                .ok_or_else(|| io::Error::other("test expected result is missing"))?;
            array_fields_mut(last)?[0] = text("case-7");
        }
        BundleMutation::ProfileExpectedMode => {
            let expected = array_fields_mut(&mut fields[5])?;
            array_fields_mut(&mut expected[0])?[3] = uint(1);
        }
        BundleMutation::ProfileExpectedBinding => {
            let expected = array_fields_mut(&mut fields[5])?;
            let result = array_fields_mut(&mut expected[0])?;
            result[4] = text("fixtures/case-0.evidence");
            result[5] = bytes(&hash(b"draft"));
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn mutate_archive_root(root: &mut Value, mutation: BundleMutation) -> TestResult<()> {
    let fields = array_fields_mut(root)?;
    match mutation {
        BundleMutation::RawArchiveField(index) => fields[usize::from(index)] = Value::Null,
        BundleMutation::ManifestShape => fields[0] = Value::Null,
        BundleMutation::MemberRecordShape => {
            array_fields_mut(&mut fields[1])?[0] = Value::Null;
        }
        BundleMutation::RawMemberField(index) => {
            let members = array_fields_mut(&mut fields[1])?;
            array_fields_mut(&mut members[0])?[usize::from(index)] = Value::Null;
        }
        BundleMutation::MemberEmpty => fields[1] = array(Vec::new()),
        BundleMutation::MemberRoleOverflow => {
            let members = array_fields_mut(&mut fields[1])?;
            array_fields_mut(&mut members[0])?[2] = uint(256);
        }
        BundleMutation::MemberRoleAboveMaximum => {
            let members = array_fields_mut(&mut fields[1])?;
            array_fields_mut(&mut members[0])?[2] = uint(20);
        }
        BundleMutation::MemberMissing => {
            array_fields_mut(&mut fields[1])?.pop();
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
    } else if matches!(mutation, Some(TrustMutation::SignatureType)) {
        Value::Null
    } else {
        bytes(&signature)
    });
    match mutation {
        Some(TrustMutation::Encoding) => Ok(vec![0xff]),
        Some(TrustMutation::Shape) => canonical(&Value::Null),
        _ => canonical(&array(fields)),
    }
}

fn mutate_trust_policy(
    fields: &mut [Value],
    mutation: TrustMutation,
    revoked_artifact: [u8; 32],
) -> TestResult<()> {
    match mutation {
        TrustMutation::RootRecordShape => {
            array_fields_mut(&mut fields[5])?[0] = Value::Null;
        }
        TrustMutation::MinimumVersionRecordShape => {
            array_fields_mut(&mut fields[8])?[0] = Value::Null;
        }
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
        TrustMutation::RevocationKeyType => fields[6] = array(vec![Value::Null]),
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
        TrustMutation::Encoding
        | TrustMutation::Shape
        | TrustMutation::Signature
        | TrustMutation::SignatureType => {}
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
        } else if matches!(mutation, Some(ProfileMutation::DeepTypeBoundary(35))) {
            Value::Null
        } else {
            bytes(&digest)
        },
    );
    match mutation {
        Some(ProfileMutation::ArtifactEncoding(1)) => Ok(vec![0xff]),
        Some(ProfileMutation::ArtifactShape(1)) => canonical(&Value::Null),
        _ => canonical(&array(fields)),
    }
}

fn mutate_execution_profile(fields: &mut [Value], mutation: ProfileMutation) -> TestResult<()> {
    match mutation {
        ProfileMutation::DeepTypeBoundary(23) => {
            array_fields_mut(&mut fields[5])?[0] = Value::Null;
        }
        ProfileMutation::DeepTypeBoundary(24) => {
            array_fields_mut(&mut fields[12])?[0] = Value::Bool(false);
        }
        ProfileMutation::DeepTypeBoundary(25) => {
            array_fields_mut(&mut fields[14])?[0] = Value::Null;
        }
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

fn select_closure_cap_boundary(
    hard_caps: &mut Value,
    members: &BTreeMap<String, (Vec<u8>, u8)>,
    index: u8,
) -> TestResult<()> {
    let measurements = closure_measurements(members)?;
    let (cap_index, value) = match index {
        0 => (2, measurements.member_count.saturating_sub(1)),
        1 => (3, measurements.maximum_path_bytes.saturating_sub(1)),
        2 => (4, measurements.maximum_member_bytes.saturating_sub(1)),
        _ => (5, measurements.member_bytes),
    };
    array_fields_mut(hard_caps)?[cap_index] = uint(value);
    Ok(())
}

fn select_closure_cap_exact(
    hard_caps: &mut Value,
    members: &BTreeMap<String, (Vec<u8>, u8)>,
    index: u8,
) -> TestResult<()> {
    let measurements = closure_measurements(members)?;
    let (cap_index, value) = match index {
        0 => (2, measurements.member_count),
        1 => (3, measurements.maximum_path_bytes),
        2 => (4, measurements.maximum_member_bytes),
        _ => return Ok(()),
    };
    array_fields_mut(hard_caps)?[cap_index] = uint(value);
    Ok(())
}

struct ClosureMeasurements {
    member_count: u64,
    maximum_path_bytes: u64,
    maximum_member_bytes: u64,
    member_bytes: u64,
}

fn closure_measurements(
    members: &BTreeMap<String, (Vec<u8>, u8)>,
) -> TestResult<ClosureMeasurements> {
    let maximum_path_bytes = members
        .keys()
        .map(String::len)
        .chain(std::iter::once("profile/CPF1.cbor".len()))
        .max()
        .ok_or_else(|| io::Error::other("test closure is empty"))?;
    let maximum_member_bytes = members
        .values()
        .map(|(bytes, _)| bytes.len())
        .max()
        .ok_or_else(|| io::Error::other("test closure is empty"))?;
    Ok(ClosureMeasurements {
        member_count: u64::try_from(members.len())?.saturating_add(1),
        maximum_path_bytes: u64::try_from(maximum_path_bytes)?,
        maximum_member_bytes: u64::try_from(maximum_member_bytes)?,
        member_bytes: closure_member_bytes(members)?,
    })
}

fn closure_member_bytes(members: &BTreeMap<String, (Vec<u8>, u8)>) -> TestResult<u64> {
    members.values().try_fold(0_u64, |total, (bytes, _)| {
        u64::try_from(bytes.len())
            .map(|length| total.saturating_add(length))
            .map_err(Into::into)
    })
}

fn profile_with_selected_closure_caps(
    members: &BTreeMap<String, (Vec<u8>, u8)>,
    fixtures: &[Value],
    execution_digest: [u8; 32],
    trust_digest: [u8; 32],
    hard_caps: &mut Value,
    mixed_oracles: bool,
    mutation: Option<ProfileMutation>,
) -> TestResult<Value> {
    let build_profile = |caps: &Value| {
        profile(
            members,
            fixtures.to_vec(),
            execution_digest,
            trust_digest,
            caps,
            mixed_oracles,
        )
    };
    let mut profile_value = build_profile(hard_caps)?;
    if matches!(mutation, Some(ProfileMutation::SelectedProfileByteCapExact)) {
        const MAX_CONVERGENCE_STEPS: usize = 8;
        for _ in 0..MAX_CONVERGENCE_STEPS {
            let profile_bytes = encoded_profile_length(&profile_value)?;
            array_fields_mut(hard_caps)?[0] = uint(profile_bytes);
            profile_value = build_profile(hard_caps)?;
            if encoded_profile_length(&profile_value)? == profile_bytes {
                return Ok(profile_value);
            }
        }
        return Err(io::Error::other("exact profile byte cap did not converge").into());
    }
    if matches!(mutation, Some(ProfileMutation::SelectedClosureCapExact(3))) {
        const MAX_CONVERGENCE_STEPS: usize = 8;
        for _ in 0..MAX_CONVERGENCE_STEPS {
            let profile_bytes = encoded_profile_length(&profile_value)?;
            let total_bytes = closure_member_bytes(members)?.saturating_add(profile_bytes);
            array_fields_mut(hard_caps)?[5] = uint(total_bytes);
            profile_value = build_profile(hard_caps)?;
            let encoded_total = closure_member_bytes(members)?
                .saturating_add(encoded_profile_length(&profile_value)?);
            if encoded_total == total_bytes {
                return Ok(profile_value);
            }
        }
        return Err(io::Error::other("exact closure cap did not converge").into());
    }
    Ok(profile_value)
}

fn encoded_profile_length(profile: &Value) -> TestResult<u64> {
    let mut fields = fields(profile.clone())?;
    fields.push(bytes(&[1; 32]));
    Ok(u64::try_from(canonical(&array(fields))?.len())?)
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
