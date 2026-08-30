//! Raw, codec-independent CFB1 archive verification.
//!
//! This module intentionally validates raw canonical CBOR without invoking the
//! typed CPF1, FPR1, or FPP1 codecs in its parent module.

use ciborium::value::Value;
use ed25519_dalek::Verifier;
use std::collections::{BTreeMap, BTreeSet};

use super::{
    array, array_values, bytes, decode, digest, digest_domain, draft_authority_verifying_key,
    encode, text, uint, BundleContractErrorV1, AUTHORITY_INVENTORY_BYTES_V1,
    AUTHORITY_INVENTORY_PATH, BUILD_PROVENANCE_PATH, CONFORMANCE_BUNDLE_MAGIC_V1,
    DRAFT_AUTHORITY_DECLARATION_BYTES_V1, DRAFT_AUTHORITY_EFFECTIVE_TIMELINE_POSITION,
    DRAFT_AUTHORITY_KEY_ID, DRAFT_AUTHORITY_OFFLINE_VALID_THROUGH,
    DRAFT_AUTHORITY_TRUST_POLICY_EPOCH, DRAFT_AUTHORITY_TRUST_POLICY_ID, DRAFT_EXECUTION_PROFILES,
    EVALUATOR_PROTOCOL_BYTES, EVALUATOR_PROTOCOL_PATH, EVALUATOR_REPORT_SCHEMA_BYTES,
    EVALUATOR_REPORT_SCHEMA_PATH, EVALUATOR_REQUEST_SCHEMA_BYTES, EVALUATOR_REQUEST_SCHEMA_PATH,
    EXECUTION_MATRIX_BYTES_V1, EXECUTION_MATRIX_PATH, FIXTURE_CONTRACT_POLICY_PATH,
    FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1, LIMITATIONS_PATH, MAX_CONFORMANCE_BUNDLE_LEN_V1,
    NORMATIVE_SPEC_PATH, NOTICE_PATH, PROFILE_PATH, PROFILE_SCHEMA_PATH, PUBLICATION_REVIEW_PATH,
    SBOM_PATH, SOURCE_PROVENANCE_PATH, SUPPORT_PACKAGE_MANIFEST_BYTES_V1,
    SUPPORT_PACKAGE_MANIFEST_PATH, TRUST_POLICY_SNAPSHOT_PATH,
};

/// Independently validate canonical CFB1, CPF1, FPR1, and FPP1 bytes without typed codecs.
///
/// # Errors
///
/// Returns a closed bundle error for malformed bytes or any failed archive-contract invariant.
pub fn verify_archive_independently(archive_bytes: &[u8]) -> Result<(), BundleContractErrorV1> {
    verify_archive_summary_independently(archive_bytes).map(|_| ())
}

fn verify_archive_summary_independently(
    archive_bytes: &[u8],
) -> Result<RawReleaseArchiveSummary, BundleContractErrorV1> {
    if archive_bytes.len() > MAX_CONFORMANCE_BUNDLE_LEN_V1 {
        return Err(BundleContractErrorV1::MemberOutOfBounds);
    }
    decode(archive_bytes).and_then(|value| {
        array(&value, 4).and_then(|fields| {
            array(&fields[0], 6).and_then(|manifest| {
                raw_manifest_header(manifest).and_then(|mode| {
                    raw_archive_body(fields, manifest, mode)
                        .and_then(|summary| raw_archive_signature(fields).map(|()| summary))
                })
            })
        })
    })
}

/// Independently validate the complete seven-profile, dual-mode release tree.
///
/// # Errors
///
/// Returns a closed bundle error if any archive is invalid, a profile mode pair
/// is incomplete, registries differ, or any registry provider is unreferenced.
pub fn verify_release_tree_independently(archives: &[&[u8]]) -> Result<(), BundleContractErrorV1> {
    let mut registry_bytes: Option<Vec<u8>> = None;
    let mut registry_providers: Option<BTreeSet<RawProviderKey>> = None;
    let mut profile_modes = BTreeMap::<
        [u8; 32],
        BTreeMap<RawArchiveMode, BTreeMap<RawExpectedResultKey, Vec<u8>>>,
    >::new();
    let mut claim_layers = BTreeSet::new();
    let mut referenced_providers = BTreeSet::new();

    archives
        .iter()
        .try_for_each(|archive| {
            verify_archive_summary_independently(archive).and_then(|summary| {
                if registry_bytes
                    .as_ref()
                    .is_some_and(|expected| expected != &summary.registry_bytes)
                {
                    return Err(BundleContractErrorV1::ProfileInvalid);
                }
                registry_bytes.get_or_insert(summary.registry_bytes);
                registry_providers.get_or_insert(summary.registry_providers);
                if profile_modes
                    .entry(summary.profile_digest)
                    .or_default()
                    .insert(summary.mode, summary.expected_results)
                    .is_some()
                {
                    return Err(BundleContractErrorV1::ModeParityMismatch);
                }
                claim_layers.insert(summary.claim_layer);
                referenced_providers.extend(summary.required_providers);
                Ok(())
            })
        })
        .and_then(|()| {
            if profile_modes.len() == 7
                && claim_layers
                    == BTreeSet::from([
                        RawClaimLayer(0),
                        RawClaimLayer(1),
                        RawClaimLayer(2),
                        RawClaimLayer(3),
                        RawClaimLayer(4),
                        RawClaimLayer(5),
                        RawClaimLayer(6),
                    ])
                && profile_modes.values().all(raw_mode_pair_has_parity)
                && registry_providers.as_ref() == Some(&referenced_providers)
            {
                Ok(())
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        })
}

fn raw_mode_pair_has_parity(
    modes: &BTreeMap<RawArchiveMode, BTreeMap<RawExpectedResultKey, Vec<u8>>>,
) -> bool {
    modes.len() == 2
        && modes
            .get(&RawArchiveMode::Local)
            .zip(modes.get(&RawArchiveMode::AirGapped))
            .is_some_and(|(local, air_gapped)| local == air_gapped)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RawArchiveMode {
    Local,
    AirGapped,
}

impl RawArchiveMode {
    const fn from_code(code: u64) -> Result<Self, BundleContractErrorV1> {
        match code {
            0 => Ok(Self::Local),
            1 => Ok(Self::AirGapped),
            _ => Err(BundleContractErrorV1::LifecycleInvalid),
        }
    }

    const fn code(self) -> u64 {
        match self {
            Self::Local => 0,
            Self::AirGapped => 1,
        }
    }

    const fn fixture_mode(self) -> RawFixtureMode {
        match self {
            Self::Local => RawFixtureMode(0),
            Self::AirGapped => RawFixtureMode(1),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RawMemberRole {
    FixtureInput,
    ExpectedResult,
    Profile,
    NormativeSpecification,
    Schema,
    Licence,
    Notice,
    Sbom,
    Provenance,
    Limitations,
    AuthorityInventory,
    ExecutionMatrix,
    FixtureProviderRegistry,
    FixtureProviderPackage,
    ExecutionProfile,
    TrustPolicySnapshot,
    ReleaseAdmission,
    EvidenceStatus,
    FixtureContractPolicy,
    AuthorityDeclaration,
}

impl RawMemberRole {
    fn from_value(value: &Value) -> Result<Self, BundleContractErrorV1> {
        uint(value).and_then(|code| match code {
            0 => Ok(Self::FixtureInput),
            1 => Ok(Self::ExpectedResult),
            2 => Ok(Self::Profile),
            3 => Ok(Self::NormativeSpecification),
            4 => Ok(Self::Schema),
            5 => Ok(Self::Licence),
            6 => Ok(Self::Notice),
            7 => Ok(Self::Sbom),
            8 => Ok(Self::Provenance),
            9 => Ok(Self::Limitations),
            10 => Ok(Self::AuthorityInventory),
            11 => Ok(Self::ExecutionMatrix),
            12 => Ok(Self::FixtureProviderRegistry),
            13 => Ok(Self::FixtureProviderPackage),
            14 => Ok(Self::ExecutionProfile),
            15 => Ok(Self::TrustPolicySnapshot),
            16 => Ok(Self::ReleaseAdmission),
            17 => Ok(Self::EvidenceStatus),
            18 => Ok(Self::FixtureContractPolicy),
            19 => Ok(Self::AuthorityDeclaration),
            _ => Err(BundleContractErrorV1::ProfileInvalid),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RawClaimLayer(u64);

impl RawClaimLayer {
    fn from_value(value: &Value) -> Result<Self, BundleContractErrorV1> {
        uint(value).and_then(|code| {
            if code <= 6 {
                Ok(Self(code))
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        })
    }

    const fn catalog_name(self) -> Result<&'static str, BundleContractErrorV1> {
        match self.0 {
            0 => Ok("artifact-integrity"),
            1 => Ok("replay-conformance"),
            2 => Ok("knowledge-non-interference"),
            3 => Ok("gateway-client-conformance"),
            4 => Ok("plugin-conformance"),
            5 => Ok("metric-conformance"),
            6 => Ok("empirical-evaluation"),
            _ => Err(BundleContractErrorV1::ProfileInvalid),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RawFixtureFamily {
    Positive,
    Denied,
    Malformed,
    ResourceExhaustion,
    DeletionRedaction,
    Downgrade,
    IndependentEvaluation,
}

impl RawFixtureFamily {
    fn from_value(value: &Value) -> Result<Self, BundleContractErrorV1> {
        uint(value).and_then(|code| match code {
            0 => Ok(Self::Positive),
            1 => Ok(Self::Denied),
            2 => Ok(Self::Malformed),
            3 => Ok(Self::ResourceExhaustion),
            4 => Ok(Self::DeletionRedaction),
            5 => Ok(Self::Downgrade),
            6 => Ok(Self::IndependentEvaluation),
            _ => Err(BundleContractErrorV1::ProfileInvalid),
        })
    }

    const fn index(self) -> usize {
        match self {
            Self::Positive => 0,
            Self::Denied => 1,
            Self::Malformed => 2,
            Self::ResourceExhaustion => 3,
            Self::DeletionRedaction => 4,
            Self::Downgrade => 5,
            Self::IndependentEvaluation => 6,
        }
    }

    const fn catalog_name(self) -> &'static str {
        match self {
            Self::Positive => "positive",
            Self::Denied => "denied",
            Self::Malformed => "malformed",
            Self::ResourceExhaustion => "resource-exhaustion",
            Self::DeletionRedaction => "deletion-redaction",
            Self::Downgrade => "downgrade",
            Self::IndependentEvaluation => "independent-evaluation",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RawSubjectAdapter(u64);

impl RawSubjectAdapter {
    fn from_value(value: &Value) -> Result<Self, BundleContractErrorV1> {
        uint(value).and_then(|code| {
            if code <= 2 {
                Ok(Self(code))
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        })
    }

    const fn prohibits_network(self) -> bool {
        self.0 == 2
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RawFixtureMode(u64);

impl RawFixtureMode {
    fn from_value(value: &Value) -> Result<Self, BundleContractErrorV1> {
        uint(value).and_then(|code| {
            if code <= 3 {
                Ok(Self(code))
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        })
    }

    const fn matches_archive(self, archive_mode: RawArchiveMode) -> bool {
        self.0 == archive_mode.code()
    }

    const fn is_air_gapped(self) -> bool {
        self.matches_archive(RawArchiveMode::AirGapped)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RawVerificationOutcome(u64);

impl RawVerificationOutcome {
    fn from_value(value: &Value) -> Result<Self, BundleContractErrorV1> {
        uint(value).and_then(|code| {
            if code <= 5 {
                Ok(Self(code))
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        })
    }

    const fn is_output(self) -> bool {
        self.0 == 0
    }

    const fn is_divergence(self) -> bool {
        self.0 == 1
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RawReplayClaim(u64);

impl RawReplayClaim {
    fn from_value(value: &Value) -> Result<Self, BundleContractErrorV1> {
        uint(value).and_then(|code| {
            if code <= 4 {
                Ok(Self(code))
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        })
    }

    const fn is_unrestricted(self) -> bool {
        self.0 == 4
    }

    const fn matches_redaction(self, redaction: RawRedactionState) -> bool {
        matches!((redaction.0, self.0), (0, _) | (1, 1) | (2, 2) | (3, 3))
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RawRedactionState(u64);

impl RawRedactionState {
    fn from_value(value: &Value) -> Result<Self, BundleContractErrorV1> {
        uint(value).and_then(|code| {
            if code <= 3 {
                Ok(Self(code))
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        })
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RawProviderKey {
    provider_id: String,
    contract_version: String,
    abi_major: u64,
    abi_minor: u64,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RawFailure {
    owner_id: String,
    contract_version: String,
    code_id: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RawDivergence {
    classification: u64,
    coordinate: Vec<u8>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RawFixtureTransition {
    from: RawProviderKey,
    to: RawProviderKey,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RawExpectedResultKey {
    case_id: String,
    claim_layer: RawClaimLayer,
    execution_profile_digest: [u8; 32],
}

struct RawReleaseArchiveSummary {
    profile_digest: [u8; 32],
    claim_layer: RawClaimLayer,
    mode: RawArchiveMode,
    registry_bytes: Vec<u8>,
    registry_providers: BTreeSet<RawProviderKey>,
    required_providers: BTreeSet<RawProviderKey>,
    expected_results: BTreeMap<RawExpectedResultKey, Vec<u8>>,
}

fn raw_manifest_header(manifest: &[Value]) -> Result<RawArchiveMode, BundleContractErrorV1> {
    text(&manifest[0]).and_then(|magic| {
        uint(&manifest[1]).and_then(|lifecycle| {
            uint(&manifest[2])
                .and_then(RawArchiveMode::from_code)
                .and_then(|mode| {
                    if magic == CONFORMANCE_BUNDLE_MAGIC_V1 && lifecycle == 0 {
                        Ok(mode)
                    } else {
                        Err(BundleContractErrorV1::LifecycleInvalid)
                    }
                })
        })
    })
}

fn raw_archive_body(
    fields: &[Value],
    manifest: &[Value],
    mode: RawArchiveMode,
) -> Result<RawReleaseArchiveSummary, BundleContractErrorV1> {
    array_values(&fields[1]).and_then(|member_values| {
        array_values(&manifest[4]).and_then(|descriptors| {
            if member_values.len() != descriptors.len() {
                return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
            }
            member_values
                .iter()
                .zip(descriptors)
                .map(|(member, descriptor)| raw_member_descriptor_pair(member, descriptor))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|members| {
                    if members.windows(2).any(|pair| pair[0].path >= pair[1].path) {
                        Err(BundleContractErrorV1::ArchiveEncodingInvalid)
                    } else {
                        raw_archive_profile(manifest, &members, mode)
                    }
                })
        })
    })
}

struct RawArchiveMember<'a> {
    path: &'a str,
    bytes: &'a [u8],
    role: RawMemberRole,
}

fn raw_member_descriptor_pair<'a>(
    member: &'a Value,
    descriptor: &Value,
) -> Result<RawArchiveMember<'a>, BundleContractErrorV1> {
    let (Ok(member_fields), Ok(descriptor_fields)) = (array(member, 3), array(descriptor, 4))
    else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    let (
        Ok(raw),
        Ok(member_path),
        Ok(descriptor_path),
        Ok(member_role),
        Ok(descriptor_role),
        Ok(descriptor_size),
        Ok(descriptor_digest),
    ) = (
        bytes(&member_fields[1]),
        text(&member_fields[0]),
        text(&descriptor_fields[0]),
        RawMemberRole::from_value(&member_fields[2]),
        RawMemberRole::from_value(&descriptor_fields[3]),
        uint(&descriptor_fields[1]),
        digest::<32>(&descriptor_fields[2]),
    )
    else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    let raw_size = u64::try_from(raw.len()).unwrap_or(u64::MAX);
    if member_path == descriptor_path
        && member_role == descriptor_role
        && raw_size == descriptor_size
        && *blake3::hash(raw).as_bytes() == descriptor_digest
    {
        Ok(RawArchiveMember {
            path: member_path,
            bytes: raw,
            role: member_role,
        })
    } else {
        Err(BundleContractErrorV1::MemberDigestMismatch)
    }
}

fn raw_archive_profile(
    manifest: &[Value],
    members: &[RawArchiveMember<'_>],
    mode: RawArchiveMode,
) -> Result<RawReleaseArchiveSummary, BundleContractErrorV1> {
    raw_member(members, PROFILE_PATH, RawMemberRole::Profile).and_then(|profile_member| {
        decode(profile_member.bytes).and_then(|profile| {
            array(&profile, 18).and_then(|profile_fields| {
                raw_cpf1_value(profile_fields).and_then(|raw_profile| {
                    if profile_fields[4] != manifest[1] {
                        return Err(BundleContractErrorV1::LifecycleInvalid);
                    }
                    raw_profile_digest(manifest, profile_fields).and_then(|profile_digest| {
                        raw_profile_support_members(&raw_profile, members).and_then(|()| {
                            raw_execution_authority_members(&raw_profile, members, mode).and_then(
                                |authority_paths| {
                                    raw_registry_and_packages(&raw_profile, members, mode).and_then(
                                        |registry| {
                                            raw_expected_results(
                                                &manifest[5],
                                                &raw_profile,
                                                members,
                                                mode,
                                            )
                                            .and_then(
                                                |expected_results| {
                                                    raw_member_closure(
                                                        &raw_profile.declared_paths,
                                                        &expected_results.member_paths,
                                                        &registry.declared_paths,
                                                        &authority_paths,
                                                        members,
                                                    )
                                                    .map(|()| RawReleaseArchiveSummary {
                                                        profile_digest,
                                                        claim_layer: raw_profile.claim_layer,
                                                        mode,
                                                        registry_bytes: registry.bytes,
                                                        registry_providers: registry.providers,
                                                        required_providers: registry
                                                            .required_providers,
                                                        expected_results: expected_results.results,
                                                    })
                                                },
                                            )
                                        },
                                    )
                                },
                            )
                        })
                    })
                })
            })
        })
    })
}

fn raw_profile_support_members(
    profile: &RawCpf1Summary,
    members: &[RawArchiveMember<'_>],
) -> Result<(), BundleContractErrorV1> {
    let bindings = [
        (NORMATIVE_SPEC_PATH, RawMemberRole::NormativeSpecification),
        (EXECUTION_MATRIX_PATH, RawMemberRole::ExecutionMatrix),
        (
            FIXTURE_CONTRACT_POLICY_PATH,
            RawMemberRole::FixtureContractPolicy,
        ),
        (LIMITATIONS_PATH, RawMemberRole::Limitations),
        (PUBLICATION_REVIEW_PATH, RawMemberRole::Provenance),
    ];
    bindings
        .into_iter()
        .zip(profile.support_digests)
        .try_for_each(|((path, role), expected_digest)| {
            raw_member(members, path, role).and_then(|member| {
                if *blake3::hash(member.bytes).as_bytes() == expected_digest {
                    Ok(())
                } else {
                    Err(BundleContractErrorV1::MemberDigestMismatch)
                }
            })
        })
        .and_then(|()| raw_evaluator_support_members(profile, members))
        .and_then(|()| raw_fixture_provenance_members(&profile.fixtures, members))
        .and_then(|()| {
            raw_authority_member_matches(
                members,
                EXECUTION_MATRIX_PATH,
                RawMemberRole::ExecutionMatrix,
                EXECUTION_MATRIX_BYTES_V1,
            )
        })
        .and_then(|()| {
            raw_authority_member_matches(
                members,
                AUTHORITY_INVENTORY_PATH,
                RawMemberRole::AuthorityInventory,
                AUTHORITY_INVENTORY_BYTES_V1,
            )
        })
        .and_then(|()| {
            raw_authority_member_matches(
                members,
                "support/draft-execution-authority.json",
                RawMemberRole::AuthorityDeclaration,
                DRAFT_AUTHORITY_DECLARATION_BYTES_V1,
            )
        })
        .and_then(|()| {
            raw_authority_member_matches(
                members,
                SUPPORT_PACKAGE_MANIFEST_PATH,
                RawMemberRole::Schema,
                SUPPORT_PACKAGE_MANIFEST_BYTES_V1,
            )
        })
}

fn raw_evaluator_support_members(
    profile: &RawCpf1Summary,
    members: &[RawArchiveMember<'_>],
) -> Result<(), BundleContractErrorV1> {
    [
        (
            EVALUATOR_PROTOCOL_PATH,
            profile.evaluator_artifact_digests[0],
            EVALUATOR_PROTOCOL_BYTES,
        ),
        (
            EVALUATOR_REQUEST_SCHEMA_PATH,
            profile.evaluator_artifact_digests[1],
            EVALUATOR_REQUEST_SCHEMA_BYTES,
        ),
        (
            EVALUATOR_REPORT_SCHEMA_PATH,
            profile.evaluator_artifact_digests[2],
            EVALUATOR_REPORT_SCHEMA_BYTES,
        ),
    ]
    .into_iter()
    .try_for_each(|(path, declared_digest, approved_bytes)| {
        raw_member(members, path, RawMemberRole::Schema).and_then(|member| {
            if member.bytes == approved_bytes
                && declared_digest == *blake3::hash(approved_bytes).as_bytes()
            {
                Ok(())
            } else {
                Err(BundleContractErrorV1::MemberDigestMismatch)
            }
        })
    })
}

fn raw_execution_authority_members(
    profile: &RawCpf1Summary,
    members: &[RawArchiveMember<'_>],
    mode: RawArchiveMode,
) -> Result<BTreeSet<String>, BundleContractErrorV1> {
    let mut paths = BTreeSet::new();
    let execution_members = members
        .iter()
        .filter(|member| member.role == RawMemberRole::ExecutionProfile)
        .collect::<Vec<_>>();
    let execution_profiles = execution_members
        .iter()
        .map(|member| {
            raw_execution_profile(member.path, member.bytes)
                .map(|profile_id| (profile_id, *blake3::hash(member.bytes).as_bytes()))
        })
        .collect::<Result<BTreeMap<_, _>, _>>();
    execution_profiles.and_then(|execution_profiles| {
        let declared_profiles = DRAFT_EXECUTION_PROFILES
            .iter()
            .map(|profile| profile.profile_id.to_owned())
            .collect::<BTreeSet<_>>();
        let execution_digests = execution_profiles
            .values()
            .copied()
            .collect::<BTreeSet<_>>();
        let execution_profile_ids = execution_profiles.keys().cloned().collect::<BTreeSet<_>>();
        if execution_digests != profile.execution_digests
            || execution_members.len() != profile.execution_digests.len()
            || execution_profiles.len() != profile.execution_digests.len()
            || execution_profile_ids != declared_profiles
        {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
        paths.extend(
            execution_members
                .iter()
                .map(|member| member.path.to_owned()),
        );
        raw_member(
            members,
            TRUST_POLICY_SNAPSHOT_PATH,
            RawMemberRole::TrustPolicySnapshot,
        )
        .and_then(|snapshot| {
            raw_trust_policy_snapshot(snapshot.bytes).and_then(|()| {
                if *blake3::hash(snapshot.bytes).as_bytes() == profile.trust_policy_snapshot_digest
                {
                    paths.insert(snapshot.path.to_owned());
                    profile
                        .fixtures
                        .iter()
                        .filter(|fixture| fixture.family == RawFixtureFamily::Downgrade)
                        .filter(|fixture| fixture.modes.contains(&mode.fixture_mode()))
                        .try_for_each(|fixture| {
                            fixture
                                .release_admission
                                .ok_or(BundleContractErrorV1::ProfileInvalid)
                                .and_then(|digest| {
                                    members
                                        .iter()
                                        .find(|member| {
                                            member.role == RawMemberRole::ReleaseAdmission
                                                && *blake3::hash(member.bytes).as_bytes() == digest
                                        })
                                        .ok_or(BundleContractErrorV1::MemberMissing)
                                })
                                .and_then(|member| {
                                    raw_release_admission(member.bytes, fixture).map(|()| {
                                        paths.insert(member.path.to_owned());
                                    })
                                })
                        })
                        .map(|()| paths)
                } else {
                    Err(BundleContractErrorV1::MemberDigestMismatch)
                }
            })
        })
    })
}

fn raw_execution_profile(path: &str, bytes: &[u8]) -> Result<String, BundleContractErrorV1> {
    decode(bytes).and_then(|value| {
        array(&value, 15).and_then(|fields| raw_execution_profile_fields(path, fields))
    })
}

fn raw_execution_profile_fields(
    path: &str,
    fields: &[Value],
) -> Result<String, BundleContractErrorV1> {
    let decoded = (
        text(&fields[0]),
        uint(&fields[1]),
        text(&fields[2]),
        text(&fields[3]),
        text(&fields[7]),
        text(&fields[8]),
        text(&fields[9]),
        text(&fields[10]),
        text(&fields[11]),
        digest::<32>(&fields[14]),
    );
    match decoded {
        (
            Ok(magic),
            Ok(version),
            Ok(profile_id),
            Ok(semantic_version),
            Ok(scheduler),
            Ok(numeric),
            Ok(schema),
            Ok(artifact),
            Ok(budget),
            Ok(profile_digest),
        ) => encode(&Value::Array(fields[..14].to_vec())).and_then(|unsigned| {
            let declaration = DRAFT_EXECUTION_PROFILES
                .iter()
                .find(|candidate| candidate.profile_id == profile_id)
                .ok_or(BundleContractErrorV1::ProfileInvalid)?;
            let classes = declaration
                .reproducibility_classes
                .iter()
                .copied()
                .map(|code| Value::Integer(code.into()))
                .collect::<Vec<_>>();
            let capabilities = declaration
                .capability_ids
                .iter()
                .map(|capability| Value::Text((*capability).to_owned()))
                .collect::<Vec<_>>();
            if magic == "EPF1"
                && version == 1
                && path == format!("authority/execution-profiles/{profile_id}.epf1")
                && semantic_version == declaration.semantic_version
                && fields[4] == Value::Array(classes)
                && fields[5] == Value::Bool(declaration.network_allowed)
                && fields[6] == Value::Array(capabilities)
                && scheduler == "fixture-scheduler-v1"
                && numeric == "fixture-numeric-v1"
                && schema == "fixture-schema-v1"
                && artifact == "fixture-artifact-v1"
                && budget == "fixture-budget-v1"
                && fields[12] == Value::Array(Vec::new())
                && fields[13] == Value::Null
                && profile_digest == digest_domain(b"PiglorOS.ExecutionProfile.v1\0", &unsigned)
            {
                Ok(profile_id.to_owned())
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        }),
        _ => Err(BundleContractErrorV1::ProfileInvalid),
    }
}

fn raw_trust_policy_snapshot(bytes: &[u8]) -> Result<(), BundleContractErrorV1> {
    decode(bytes).and_then(|value| array(&value, 13).and_then(raw_trust_policy_snapshot_fields))
}

fn raw_trust_policy_snapshot_fields(fields: &[Value]) -> Result<(), BundleContractErrorV1> {
    match (
        text(&fields[0]),
        uint(&fields[1]),
        text(&fields[2]),
        uint(&fields[3]),
        uint(&fields[4]),
        text(&fields[5]),
        digest::<32>(&fields[6]),
        text(&fields[10]),
        digest::<64>(&fields[12]),
    ) {
        (
            Ok(magic),
            Ok(version),
            Ok(policy_id),
            Ok(epoch),
            Ok(position),
            Ok(key_id),
            Ok(key),
            Ok(expiry),
            Ok(signature),
        ) => encode(&Value::Array(fields[..12].to_vec())).and_then(|unsigned| {
            let approved_key = crate::DRAFT_AUTHORITY_PUBLIC_KEY_BYTES;
            raw_fixture_authority_signature(&unsigned, &signature).and_then(|()| {
                if magic == "TPS1"
                    && version == 1
                    && policy_id == DRAFT_AUTHORITY_TRUST_POLICY_ID
                    && epoch == DRAFT_AUTHORITY_TRUST_POLICY_EPOCH
                    && position == DRAFT_AUTHORITY_EFFECTIVE_TIMELINE_POSITION
                    && key_id == DRAFT_AUTHORITY_KEY_ID
                    && key == approved_key
                    && fields[7] == Value::Array(Vec::new())
                    && fields[8] == Value::Array(Vec::new())
                    && fields[9] == Value::Array(Vec::new())
                    && expiry == DRAFT_AUTHORITY_OFFLINE_VALID_THROUGH
                    && fields[11] == Value::Null
                {
                    Ok(())
                } else {
                    Err(BundleContractErrorV1::ProfileInvalid)
                }
            })
        }),
        _ => Err(BundleContractErrorV1::ProfileInvalid),
    }
}

fn raw_release_admission(
    bytes: &[u8],
    fixture: &RawFixtureSummary,
) -> Result<(), BundleContractErrorV1> {
    fixture
        .trust_snapshot
        .ok_or(BundleContractErrorV1::ProfileInvalid)
        .and_then(|snapshot| {
            fixture
                .transition
                .as_ref()
                .ok_or(BundleContractErrorV1::ProfileInvalid)
                .and_then(|transition| {
                    decode(bytes).and_then(|value| {
                        array(&value, 11).and_then(|fields| {
                            raw_release_admission_fields(fields, fixture, snapshot, transition)
                        })
                    })
                })
        })
}

fn raw_release_admission_fields(
    fields: &[Value],
    fixture: &RawFixtureSummary,
    snapshot: [u8; 32],
    transition: &RawFixtureTransition,
) -> Result<(), BundleContractErrorV1> {
    match (
        text(&fields[0]),
        uint(&fields[1]),
        uint(&fields[2]),
        text(&fields[3]),
        digest::<32>(&fields[4]),
        digest::<32>(&fields[5]),
        raw_provider_key(&fields[6]),
        raw_provider_key(&fields[7]),
        text(&fields[9]),
        digest::<64>(&fields[10]),
    ) {
        (
            Ok(magic),
            Ok(version),
            Ok(lifecycle),
            Ok(case_id),
            Ok(execution),
            Ok(policy),
            Ok(from),
            Ok(to),
            Ok(key_id),
            Ok(signature),
        ) => encode(&Value::Array(fields[..10].to_vec())).and_then(|unsigned| {
            raw_fixture_authority_signature(&unsigned, &signature).and_then(|()| {
                if magic == "RAD1"
                    && version == 1
                    && lifecycle == 0
                    && case_id == fixture.case_id
                    && execution == fixture.execution
                    && policy == snapshot
                    && from == transition.from
                    && to == transition.to
                    && fields[8] == Value::Bool(false)
                    && key_id == DRAFT_AUTHORITY_KEY_ID
                {
                    Ok(())
                } else {
                    Err(BundleContractErrorV1::ProfileInvalid)
                }
            })
        }),
        _ => Err(BundleContractErrorV1::ProfileInvalid),
    }
}

fn raw_fixture_authority_signature(
    unsigned: &[u8],
    signature: &[u8; 64],
) -> Result<(), BundleContractErrorV1> {
    draft_authority_verifying_key().and_then(|key| {
        key.verify(unsigned, &ed25519_dalek::Signature::from_bytes(signature))
            .map_err(|_| BundleContractErrorV1::SignatureInvalid)
    })
}

fn raw_authority_member_matches(
    members: &[RawArchiveMember<'_>],
    path: &str,
    role: RawMemberRole,
    approved_bytes: &[u8],
) -> Result<(), BundleContractErrorV1> {
    raw_member(members, path, role).and_then(|member| {
        if member.bytes == approved_bytes {
            Ok(())
        } else {
            Err(BundleContractErrorV1::ProfileInvalid)
        }
    })
}

fn raw_fixture_provenance_members(
    fixtures: &[RawFixtureSummary],
    members: &[RawArchiveMember<'_>],
) -> Result<(), BundleContractErrorV1> {
    fixtures.iter().try_for_each(|fixture| {
        let bindings = [
            (NOTICE_PATH, RawMemberRole::Notice),
            (SBOM_PATH, RawMemberRole::Sbom),
            (SOURCE_PROVENANCE_PATH, RawMemberRole::Provenance),
            (BUILD_PROVENANCE_PATH, RawMemberRole::Provenance),
            (PUBLICATION_REVIEW_PATH, RawMemberRole::Provenance),
            (LIMITATIONS_PATH, RawMemberRole::Limitations),
        ];
        bindings.into_iter().zip(fixture.provenance).try_for_each(
            |((path, role), expected_digest)| {
                raw_member(members, path, role).and_then(|member| {
                    if *blake3::hash(member.bytes).as_bytes() == expected_digest {
                        Ok(())
                    } else {
                        Err(BundleContractErrorV1::MemberDigestMismatch)
                    }
                })
            },
        )
    })
}

fn raw_member_closure(
    profile_paths: &BTreeSet<String>,
    expected_paths: &BTreeSet<String>,
    provider_paths: &BTreeSet<String>,
    authority_paths: &BTreeSet<String>,
    members: &[RawArchiveMember<'_>],
) -> Result<(), BundleContractErrorV1> {
    let mut declared = [
        PROFILE_PATH,
        NORMATIVE_SPEC_PATH,
        EXECUTION_MATRIX_PATH,
        AUTHORITY_INVENTORY_PATH,
        PROFILE_SCHEMA_PATH,
        EVALUATOR_PROTOCOL_PATH,
        EVALUATOR_REQUEST_SCHEMA_PATH,
        EVALUATOR_REPORT_SCHEMA_PATH,
        SUPPORT_PACKAGE_MANIFEST_PATH,
        FIXTURE_CONTRACT_POLICY_PATH,
        "support/draft-execution-authority.json",
        LIMITATIONS_PATH,
        SOURCE_PROVENANCE_PATH,
        BUILD_PROVENANCE_PATH,
        PUBLICATION_REVIEW_PATH,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    declared.extend(profile_paths.iter().cloned());
    declared.extend(expected_paths.iter().cloned());
    declared.extend(provider_paths.iter().cloned());
    declared.extend(authority_paths.iter().cloned());
    let member_paths = members
        .iter()
        .map(|member| member.path.to_owned())
        .collect::<BTreeSet<_>>();
    if member_paths.len() == members.len() && member_paths.is_subset(&declared) {
        Ok(())
    } else {
        Err(BundleContractErrorV1::UndeclaredMember)
    }
}

fn raw_profile_digest(
    manifest: &[Value],
    profile: &[Value],
) -> Result<[u8; 32], BundleContractErrorV1> {
    digest::<32>(&profile[17]).and_then(|profile_digest| {
        length_bound(&Value::Array(profile[..17].to_vec())).and_then(|bound| {
            digest::<32>(&manifest[3]).and_then(|manifest_digest| {
                if profile_digest == digest_domain(b"PiglorOS.ConformanceProfile.v1\0", &bound)
                    && profile_digest == manifest_digest
                {
                    Ok(profile_digest)
                } else {
                    Err(BundleContractErrorV1::ProfileInvalid)
                }
            })
        })
    })
}

fn raw_archive_signature(fields: &[Value]) -> Result<(), BundleContractErrorV1> {
    digest::<32>(&fields[2]).and_then(|key| {
        digest::<64>(&fields[3]).and_then(|signature| {
            if key != crate::DRAFT_AUTHORITY_PUBLIC_KEY_BYTES {
                return Err(BundleContractErrorV1::SignatureInvalid);
            }
            ed25519_dalek::VerifyingKey::from_bytes(&key)
                .map_err(|_| BundleContractErrorV1::SignatureInvalid)
                .and_then(|verifying_key| {
                    encode(&fields[0]).and_then(|manifest| {
                        verifying_key
                            .verify(&manifest, &ed25519_dalek::Signature::from_bytes(&signature))
                            .map_err(|_| BundleContractErrorV1::SignatureInvalid)
                    })
                })
        })
    })
}
struct RawCpf1Summary {
    claim_layer: RawClaimLayer,
    declared_paths: BTreeSet<String>,
    required_providers: BTreeSet<RawProviderKey>,
    fixtures: Vec<RawFixtureSummary>,
    execution_digests: BTreeSet<[u8; 32]>,
    trust_policy_snapshot_digest: [u8; 32],
    support_digests: [[u8; 32]; 5],
    evaluator_artifact_digests: [[u8; 32]; 3],
    registry: RawArtifact,
}

fn raw_cpf1_value(profile_fields: &[Value]) -> Result<RawCpf1Summary, BundleContractErrorV1> {
    raw_cpf1_header(profile_fields).and_then(|support_digests| {
        raw_execution_digests(&profile_fields[7]).and_then(|executions| {
            raw_provider_binding(&profile_fields[8]).and_then(|(registry, required_providers)| {
                raw_protocol(&profile_fields[11]).and_then(|protocol| {
                    raw_fixtures(&profile_fields[9], &protocol.deterministic_caps).and_then(
                        |mut fixture_collection| {
                            let claim_layer = fixture_collection.fixtures[0].claim_layer;
                            fixture_collection
                                .declared_paths
                                .insert(registry.path.clone());
                            raw_allowed_divergences(&profile_fields[10]).and_then(|allowed| {
                                raw_profile_fixture_relationships(
                                    &required_providers,
                                    &executions,
                                    &fixture_collection.fixtures,
                                    &allowed,
                                    claim_layer,
                                )
                                .and_then(|()| raw_independence(&profile_fields[12]))
                                .and_then(
                                    |trust_policy_snapshot_digest| {
                                        raw_nullable_digest(&profile_fields[16]).map(|()| {
                                            RawCpf1Summary {
                                                claim_layer,
                                                declared_paths: fixture_collection.declared_paths,
                                                required_providers,
                                                fixtures: fixture_collection.fixtures,
                                                execution_digests: executions,
                                                trust_policy_snapshot_digest,
                                                support_digests,
                                                evaluator_artifact_digests: protocol
                                                    .artifact_digests,
                                                registry,
                                            }
                                        })
                                    },
                                )
                            })
                        },
                    )
                })
            })
        })
    })
}

fn raw_allowed_divergences(
    value: &Value,
) -> Result<BTreeSet<RawDivergence>, BundleContractErrorV1> {
    array_values(value).and_then(|divergences| {
        let mut allowed = BTreeSet::new();
        let mut previous = None;
        divergences
            .iter()
            .try_for_each(|divergence| {
                raw_divergence(divergence).and_then(|current| {
                    if previous.as_ref().is_some_and(|old| old >= &current) {
                        Err(BundleContractErrorV1::NonCanonicalOrder)
                    } else {
                        previous = Some(current.clone());
                        allowed.insert(current);
                        Ok(())
                    }
                })
            })
            .map(|()| allowed)
    })
}

fn raw_profile_fixture_relationships(
    required: &BTreeSet<RawProviderKey>,
    executions: &BTreeSet<[u8; 32]>,
    fixtures: &[RawFixtureSummary],
    allowed: &BTreeSet<RawDivergence>,
    claim_layer: RawClaimLayer,
) -> Result<(), BundleContractErrorV1> {
    raw_fixture_inventory(required, executions, fixtures)
        .and_then(|()| {
            fixtures.iter().try_for_each(|fixture| {
                if !required.contains(&fixture.provider) || !executions.contains(&fixture.execution)
                {
                    return Err(BundleContractErrorV1::ProfileInvalid);
                }
                raw_fixture_oracle_relationships(fixture, allowed)
                    .and_then(|()| raw_fixture_claim_relationship(fixture))
                    .and_then(|()| raw_fixture_downgrade_relationship(fixture))
            })
        })
        .and_then(|()| {
            if fixtures
                .iter()
                .all(|fixture| fixture.claim_layer == claim_layer)
            {
                Ok(())
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        })
}

fn raw_fixture_inventory(
    required: &BTreeSet<RawProviderKey>,
    executions: &BTreeSet<[u8; 32]>,
    fixtures: &[RawFixtureSummary],
) -> Result<(), BundleContractErrorV1> {
    let mut inventory =
        BTreeMap::<(RawProviderKey, [u8; 32], RawFixtureMode), BTreeSet<RawFixtureFamily>>::new();
    for fixture in fixtures {
        for mode in &fixture.modes {
            let coordinate = (fixture.provider.clone(), fixture.execution, *mode);
            if !inventory
                .entry(coordinate)
                .or_default()
                .insert(fixture.family)
            {
                return Err(BundleContractErrorV1::NonCanonicalOrder);
            }
        }
    }
    let required_families = BTreeSet::from([
        RawFixtureFamily::Positive,
        RawFixtureFamily::Denied,
        RawFixtureFamily::Malformed,
        RawFixtureFamily::ResourceExhaustion,
        RawFixtureFamily::DeletionRedaction,
        RawFixtureFamily::Downgrade,
        RawFixtureFamily::IndependentEvaluation,
    ]);
    let required_modes = [
        RawFixtureMode(RawArchiveMode::Local.code()),
        RawFixtureMode(RawArchiveMode::AirGapped.code()),
    ];
    for provider in required {
        for execution in executions {
            for mode in required_modes {
                if inventory
                    .get(&(provider.clone(), *execution, mode))
                    .is_none_or(|families| families != &required_families)
                {
                    return Err(BundleContractErrorV1::ProfileInvalid);
                }
            }
        }
    }
    Ok(())
}

fn raw_fixture_oracle_relationships(
    fixture: &RawFixtureSummary,
    allowed: &BTreeSet<RawDivergence>,
) -> Result<(), BundleContractErrorV1> {
    let result_is_valid = match &fixture.oracle {
        RawOracle::Output(_) => fixture.verification.is_output() && fixture.failure.is_none(),
        RawOracle::Failure(failure) => {
            !fixture.verification.is_output()
                && !fixture.verification.is_divergence()
                && fixture.failure.as_ref() == Some(failure)
        }
        RawOracle::Divergence(divergence) => {
            fixture.verification.is_divergence()
                && fixture.failure.is_none()
                && allowed.contains(divergence)
        }
    };
    if !result_is_valid {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    if let RawOracle::Failure(failure) = &fixture.oracle {
        if failure.owner_id != "pigloros.core"
            && (failure.owner_id != fixture.provider.provider_id
                || failure.contract_version != fixture.provider.contract_version)
        {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
    }
    Ok(())
}

const fn raw_fixture_claim_relationship(
    fixture: &RawFixtureSummary,
) -> Result<(), BundleContractErrorV1> {
    if fixture.replay.is_unrestricted() || fixture.replay.matches_redaction(fixture.redaction) {
        Ok(())
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn raw_fixture_downgrade_relationship(
    fixture: &RawFixtureSummary,
) -> Result<(), BundleContractErrorV1> {
    if fixture.family != RawFixtureFamily::Downgrade {
        return if fixture.trust_snapshot.is_none()
            && fixture.release_admission.is_none()
            && fixture.transition.is_none()
        {
            Ok(())
        } else {
            Err(BundleContractErrorV1::ProfileInvalid)
        };
    }
    if fixture.trust_snapshot.is_some_and(|value| value != [0; 32])
        && fixture
            .release_admission
            .is_some_and(|value| value != [0; 32])
        && fixture
            .transition
            .as_ref()
            .is_some_and(|transition| transition.from != transition.to)
    {
        Ok(())
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn raw_cpf1_header(fields: &[Value]) -> Result<[[u8; 32]; 5], BundleContractErrorV1> {
    let (
        Ok(magic),
        Ok(version),
        Ok(profile_id),
        Ok(semantic_version),
        Ok(lifecycle),
        Ok(normative_spec),
        Ok(execution_matrix),
        Ok(limitations),
        Ok(provenance),
        Ok(provider_registry),
    ) = (
        text(&fields[0]),
        uint(&fields[1]),
        text(&fields[2]),
        text(&fields[3]),
        uint(&fields[4]),
        digest::<32>(&fields[5]),
        digest::<32>(&fields[6]),
        digest::<32>(&fields[13]),
        digest::<32>(&fields[14]),
        digest::<32>(&fields[15]),
    )
    else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    if magic == "CPF1"
        && version == 1
        && raw_identifier(profile_id, 128)
        && raw_semver(semantic_version)
        && lifecycle <= 3
        && normative_spec != [0; 32]
        && execution_matrix != [0; 32]
        && limitations != [0; 32]
        && provenance != [0; 32]
        && provider_registry != [0; 32]
    {
        Ok([
            normative_spec,
            execution_matrix,
            limitations,
            provenance,
            provider_registry,
        ])
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn raw_execution_digests(value: &Value) -> Result<BTreeSet<[u8; 32]>, BundleContractErrorV1> {
    array_values(value).and_then(|executions| {
        raw_digests_ordered(executions).and_then(|ordered| {
            if !executions.is_empty() && executions.len() <= 64 && ordered {
                executions.iter().map(digest::<32>).collect()
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        })
    })
}

fn raw_provider_binding(
    value: &Value,
) -> Result<(RawArtifact, BTreeSet<RawProviderKey>), BundleContractErrorV1> {
    array(value, 2).and_then(|binding| {
        raw_artifact(&binding[0]).and_then(|registry| {
            array_values(&binding[1]).and_then(|provider_keys| {
                raw_provider_keys_ordered(provider_keys).and_then(|ordered| {
                    if provider_keys.is_empty() || !ordered {
                        return Err(BundleContractErrorV1::ProfileInvalid);
                    }
                    provider_keys
                        .iter()
                        .map(raw_provider_key)
                        .collect::<Result<BTreeSet<_>, _>>()
                        .map(|keys| (registry, keys))
                })
            })
        })
    })
}

fn raw_fixtures(
    value: &Value,
    deterministic_caps: &[u64; 8],
) -> Result<RawFixtureCollection, BundleContractErrorV1> {
    array_values(value).and_then(|fixtures| {
        raw_fixture_ordered(fixtures).and_then(|ordered| {
            if fixtures.is_empty() || fixtures.len() > 65_536 || !ordered {
                return Err(BundleContractErrorV1::ProfileInvalid);
            }
            fixtures.iter().try_fold(
                RawFixtureCollection::default(),
                |mut collection, fixture| {
                    raw_fixture(fixture, deterministic_caps).map(|summary| {
                        collection
                            .declared_paths
                            .extend(summary.artifact_paths.iter().cloned());
                        collection.fixtures.push(summary);
                        collection
                    })
                },
            )
        })
    })
}

#[derive(Default)]
struct RawFixtureCollection {
    fixtures: Vec<RawFixtureSummary>,
    declared_paths: BTreeSet<String>,
}

struct RawFixtureSummary {
    case_id: String,
    claim_layer: RawClaimLayer,
    family: RawFixtureFamily,
    provider: RawProviderKey,
    adapter: RawSubjectAdapter,
    execution: [u8; 32],
    modes: Vec<RawFixtureMode>,
    schema: RawArtifact,
    payload: RawArtifact,
    auxiliary: Vec<RawArtifact>,
    oracle: RawOracle,
    verification: RawVerificationOutcome,
    failure: Option<RawFailure>,
    replay: RawReplayClaim,
    redaction: RawRedactionState,
    trust_snapshot: Option<[u8; 32]>,
    release_admission: Option<[u8; 32]>,
    transition: Option<RawFixtureTransition>,
    provenance: [[u8; 32]; 6],
    artifact_paths: BTreeSet<String>,
}

fn raw_fixture(
    value: &Value,
    deterministic_caps: &[u64; 8],
) -> Result<RawFixtureSummary, BundleContractErrorV1> {
    array(value, 24).and_then(|fields| {
        raw_fixture_header(fields).and_then(|header| {
            raw_fixture_header_is_valid(&header).and_then(|()| {
                raw_fixture_artifacts(fields, deterministic_caps).and_then(|artifacts| {
                    raw_fixture_outcome(fields).and_then(|outcome| {
                        raw_fixture_digest(fields).map(|()| RawFixtureSummary {
                            case_id: header.case_id,
                            claim_layer: header.claim_layer,
                            family: header.family,
                            provider: header.provider,
                            adapter: header.adapter,
                            execution: header.execution,
                            modes: header.modes,
                            schema: artifacts.schema,
                            payload: artifacts.payload,
                            auxiliary: artifacts.auxiliary,
                            oracle: artifacts.oracle,
                            verification: outcome.verification,
                            failure: outcome.failure,
                            replay: outcome.replay,
                            redaction: outcome.redaction,
                            trust_snapshot: outcome.trust_snapshot,
                            release_admission: outcome.release_admission,
                            transition: outcome.transition,
                            provenance: outcome.provenance,
                            artifact_paths: artifacts.paths,
                        })
                    })
                })
            })
        })
    })
}

struct RawFixtureHeader {
    case_id: String,
    claim_layer: RawClaimLayer,
    family: RawFixtureFamily,
    provider: RawProviderKey,
    adapter: RawSubjectAdapter,
    execution: [u8; 32],
    modes: Vec<RawFixtureMode>,
    network_allowed: bool,
}

fn raw_fixture_header(fields: &[Value]) -> Result<RawFixtureHeader, BundleContractErrorV1> {
    let (Ok(case_id), Ok(claim_layer), Ok(family), Ok(adapter), Ok(execution)) = (
        text(&fields[0]),
        RawClaimLayer::from_value(&fields[2]),
        RawFixtureFamily::from_value(&fields[3]),
        RawSubjectAdapter::from_value(&fields[5]),
        digest::<32>(&fields[6]),
    ) else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    if !matches!(&fields[1], Value::Bool(_)) {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    raw_provider_key(&fields[4]).and_then(|provider| {
        array_values(&fields[7])
            .and_then(raw_ordered_modes)
            .and_then(|modes| {
                raw_capabilities(&fields[18]).map(|network_allowed| RawFixtureHeader {
                    case_id: case_id.to_owned(),
                    claim_layer,
                    family,
                    provider,
                    adapter,
                    execution,
                    modes,
                    network_allowed,
                })
            })
    })
}

fn raw_fixture_header_is_valid(header: &RawFixtureHeader) -> Result<(), BundleContractErrorV1> {
    if raw_identifier(&header.case_id, 128)
        && (!header.network_allowed
            || (!header.adapter.prohibits_network()
                && !header.modes.iter().any(|mode| mode.is_air_gapped())))
    {
        Ok(())
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

struct RawFixtureArtifacts {
    schema: RawArtifact,
    payload: RawArtifact,
    auxiliary: Vec<RawArtifact>,
    oracle: RawOracle,
    paths: BTreeSet<String>,
}

fn raw_fixture_artifacts(
    fields: &[Value],
    deterministic_caps: &[u64; 8],
) -> Result<RawFixtureArtifacts, BundleContractErrorV1> {
    raw_budget(&fields[16], deterministic_caps)
        .and_then(|()| raw_watchdog(&fields[17]))
        .and_then(|()| raw_artifact(&fields[8]))
        .and_then(|schema| {
            raw_artifact(&fields[9]).and_then(|payload| {
                array_values(&fields[10])
                    .and_then(raw_ordered_artifacts)
                    .and_then(|auxiliary| {
                        raw_oracle(&fields[11]).and_then(|oracle| {
                            raw_fixture_artifact_paths(&schema, &payload, &auxiliary, &oracle).map(
                                |paths| RawFixtureArtifacts {
                                    schema,
                                    payload,
                                    auxiliary,
                                    oracle,
                                    paths,
                                },
                            )
                        })
                    })
            })
        })
}

fn raw_fixture_artifact_paths(
    schema: &RawArtifact,
    payload: &RawArtifact,
    auxiliary: &[RawArtifact],
    oracle: &RawOracle,
) -> Result<BTreeSet<String>, BundleContractErrorV1> {
    if auxiliary.len() > 64 {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    let mut paths = [schema, payload]
        .into_iter()
        .chain(auxiliary)
        .map(|artifact| artifact.path.clone())
        .collect::<BTreeSet<_>>();
    if let RawOracle::Output(output) = oracle {
        paths.insert(output.path.clone());
    }
    let expected = auxiliary.len() + 2 + usize::from(matches!(oracle, RawOracle::Output(_)));
    if paths.len() == expected {
        Ok(paths)
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

struct RawFixtureOutcome {
    verification: RawVerificationOutcome,
    failure: Option<RawFailure>,
    replay: RawReplayClaim,
    redaction: RawRedactionState,
    trust_snapshot: Option<[u8; 32]>,
    release_admission: Option<[u8; 32]>,
    transition: Option<RawFixtureTransition>,
    provenance: [[u8; 32]; 6],
}

fn raw_fixture_outcome(fields: &[Value]) -> Result<RawFixtureOutcome, BundleContractErrorV1> {
    RawVerificationOutcome::from_value(&fields[12]).and_then(|verification| {
        raw_optional_failure(&fields[13]).and_then(|failure| {
            RawReplayClaim::from_value(&fields[14]).and_then(|replay| {
                RawRedactionState::from_value(&fields[15]).and_then(|redaction| {
                    raw_optional_digest(&fields[19]).and_then(|trust_snapshot| {
                        raw_optional_digest(&fields[20]).and_then(|release_admission| {
                            raw_provenance(&fields[21]).and_then(|provenance| {
                                raw_optional_transition(&fields[22]).map(|transition| {
                                    RawFixtureOutcome {
                                        verification,
                                        failure,
                                        replay,
                                        redaction,
                                        trust_snapshot,
                                        release_admission,
                                        transition,
                                        provenance,
                                    }
                                })
                            })
                        })
                    })
                })
            })
        })
    })
}

fn raw_fixture_digest(fields: &[Value]) -> Result<(), BundleContractErrorV1> {
    length_bound(&Value::Array(fields[..23].to_vec())).and_then(|bound| {
        digest::<32>(&fields[23]).and_then(|digest| {
            if digest == digest_domain(b"PiglorOS.Conformance.Fixture.v1\0", &bound) {
                Ok(())
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        })
    })
}

fn raw_nullable_digest(value: &Value) -> Result<(), BundleContractErrorV1> {
    raw_optional_digest(value).map(|_| ())
}

fn raw_optional_digest(value: &Value) -> Result<Option<[u8; 32]>, BundleContractErrorV1> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        digest::<32>(value).map(Some)
    }
}

fn raw_optional_failure(value: &Value) -> Result<Option<RawFailure>, BundleContractErrorV1> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        raw_failure(value).map(Some)
    }
}

fn raw_failure(value: &Value) -> Result<RawFailure, BundleContractErrorV1> {
    array(value, 3).and_then(|fields| {
        text(&fields[0]).and_then(|owner| {
            text(&fields[1]).and_then(|version| {
                text(&fields[2]).and_then(|code| {
                    if owner.is_empty() || version.is_empty() || code.is_empty() {
                        Err(BundleContractErrorV1::ProfileInvalid)
                    } else {
                        Ok(RawFailure {
                            owner_id: owner.to_owned(),
                            contract_version: version.to_owned(),
                            code_id: code.to_owned(),
                        })
                    }
                })
            })
        })
    })
}
fn raw_provenance(value: &Value) -> Result<[[u8; 32]; 6], BundleContractErrorV1> {
    array(value, 7).and_then(|fields| {
        text(&fields[0]).and_then(|licence| {
            if licence.is_empty() {
                return Err(BundleContractErrorV1::ProfileInvalid);
            }
            let mut digests = [[0; 32]; 6];
            digests
                .iter_mut()
                .zip(&fields[1..])
                .try_for_each(|(slot, value)| {
                    digest::<32>(value).and_then(|digest| {
                        if digest == [0; 32] {
                            Err(BundleContractErrorV1::ProfileInvalid)
                        } else {
                            *slot = digest;
                            Ok(())
                        }
                    })
                })
                .map(|()| digests)
        })
    })
}

fn raw_optional_transition(
    value: &Value,
) -> Result<Option<RawFixtureTransition>, BundleContractErrorV1> {
    if matches!(value, Value::Null) {
        return Ok(None);
    }
    array(value, 2).and_then(|fields| {
        raw_provider_key(&fields[0]).and_then(|from| {
            raw_provider_key(&fields[1]).map(|to| Some(RawFixtureTransition { from, to }))
        })
    })
}
struct RawEvaluatorProtocol {
    deterministic_caps: [u64; 8],
    artifact_digests: [[u8; 32]; 3],
}

fn raw_protocol(value: &Value) -> Result<RawEvaluatorProtocol, BundleContractErrorV1> {
    array(value, 5).and_then(|fields| {
        text(&fields[0]).and_then(|version| {
            if version.is_empty() {
                return Err(BundleContractErrorV1::ProfileInvalid);
            }
            let (Ok(protocol), Ok(request), Ok(report)) = (
                digest::<32>(&fields[1]),
                digest::<32>(&fields[2]),
                digest::<32>(&fields[3]),
            ) else {
                return Err(BundleContractErrorV1::ProfileInvalid);
            };
            if [protocol, request, report]
                .into_iter()
                .any(|digest| digest == [0; 32])
            {
                Err(BundleContractErrorV1::ProfileInvalid)
            } else {
                let artifact_digests = [protocol, request, report];
                array(&fields[4], 18).and_then(|caps| {
                    let maxima = [
                        16 * 1024 * 1024,
                        65_536,
                        65_536,
                        256,
                        64 * 1024 * 1024,
                        1024 * 1024 * 1024,
                        100,
                        32,
                        128,
                        1024 * 1024,
                        1024 * 1024 * 1024,
                        1_000_000_000,
                        1_000_000,
                        1_000_000,
                        64 * 1024 * 1024,
                        1024 * 1024 * 1024,
                        1_000_000_000,
                        86_400_000_000_000,
                    ];
                    caps.iter()
                        .map(uint)
                        .collect::<Result<Vec<_>, _>>()
                        .and_then(|values| {
                            let valid = values.iter().zip(maxima).enumerate().all(
                                |(index, (cap, maximum))| {
                                    *cap <= maximum && (index == 9 || *cap > 0)
                                },
                            );
                            if !valid {
                                return Err(BundleContractErrorV1::ProfileInvalid);
                            }
                            Ok(RawEvaluatorProtocol {
                                deterministic_caps: [
                                    values[10], values[11], values[12], values[13], values[14],
                                    values[15], values[16], values[17],
                                ],
                                artifact_digests,
                            })
                        })
                })
            }
        })
    })
}
fn raw_independence(value: &Value) -> Result<[u8; 32], BundleContractErrorV1> {
    array(value, 5).and_then(|fields| {
        digest::<32>(&fields[3]).and_then(|shared_code_audit| {
            digest::<32>(&fields[4]).and_then(|declaration| {
                if fields[..3]
                    .iter()
                    .all(|value| matches!(value, Value::Bool(_)))
                    && shared_code_audit != [0; 32]
                    && declaration != [0; 32]
                {
                    Ok(shared_code_audit)
                } else {
                    Err(BundleContractErrorV1::ProfileInvalid)
                }
            })
        })
    })
}

fn raw_member<'a, 'member>(
    members: &'a [RawArchiveMember<'member>],
    path: &str,
    role: RawMemberRole,
) -> Result<&'a RawArchiveMember<'member>, BundleContractErrorV1> {
    members
        .iter()
        .find(|member| member.path == path && member.role == role)
        .ok_or(BundleContractErrorV1::MemberMissing)
}

struct RawRegistrySummary {
    bytes: Vec<u8>,
    providers: BTreeSet<RawProviderKey>,
    required_providers: BTreeSet<RawProviderKey>,
    declared_paths: BTreeSet<String>,
}

struct RawProviderSummary {
    key: RawProviderKey,
    claim_layer: RawClaimLayer,
    adapter: RawSubjectAdapter,
    package: RawArtifact,
    schemas: Vec<RawArtifact>,
    declared_paths: BTreeSet<String>,
}

struct RawPackageSummary {
    schemas: Vec<RawArtifact>,
    declared_paths: BTreeSet<String>,
}

fn raw_registry_and_packages(
    profile: &RawCpf1Summary,
    members: &[RawArchiveMember<'_>],
    mode: RawArchiveMode,
) -> Result<RawRegistrySummary, BundleContractErrorV1> {
    if profile.registry.path != FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1 {
        return Err(BundleContractErrorV1::ProfileInvalid);
    }
    raw_member(
        members,
        FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1,
        RawMemberRole::FixtureProviderRegistry,
    )
    .and_then(|registry_member| {
        raw_artifact_matches_member(&profile.registry, registry_member).and_then(|()| {
            decode(registry_member.bytes).and_then(|registry| {
                array(&registry, 4).and_then(|fields| {
                    raw_registry_fields(fields, registry_member.bytes, profile, members, mode)
                })
            })
        })
    })
}

fn raw_registry_fields(
    fields: &[Value],
    registry_bytes: &[u8],
    profile: &RawCpf1Summary,
    members: &[RawArchiveMember<'_>],
    mode: RawArchiveMode,
) -> Result<RawRegistrySummary, BundleContractErrorV1> {
    text(&fields[0]).and_then(|magic| {
        uint(&fields[1]).and_then(|version| {
            array_values(&fields[2]).and_then(|providers| {
                raw_provider_entries_ordered(providers).and_then(|ordered| {
                    if magic != "FPR1" || version != 1 || providers.is_empty() || !ordered {
                        return Err(BundleContractErrorV1::ProfileInvalid);
                    }
                    raw_registry_digest(fields).and_then(|()| {
                        providers
                            .iter()
                            .map(|provider| raw_provider_package(provider, members))
                            .collect::<Result<Vec<_>, _>>()
                            .and_then(|provider_summaries| {
                                let provider_keys = provider_summaries
                                    .iter()
                                    .map(|provider| provider.key.clone())
                                    .collect::<BTreeSet<_>>();
                                if !profile.required_providers.is_subset(&provider_keys) {
                                    return Err(BundleContractErrorV1::ProfileInvalid);
                                }
                                raw_declared_packages(members, &provider_summaries)
                                    .and_then(|()| {
                                        raw_fixture_provider_bindings(
                                            &profile.fixtures,
                                            &provider_summaries,
                                            members,
                                            mode,
                                        )
                                    })
                                    .map(|()| RawRegistrySummary {
                                        bytes: registry_bytes.to_vec(),
                                        providers: provider_keys,
                                        required_providers: profile.required_providers.clone(),
                                        declared_paths: provider_summaries
                                            .iter()
                                            .flat_map(|provider| {
                                                provider.declared_paths.iter().cloned()
                                            })
                                            .collect(),
                                    })
                            })
                    })
                })
            })
        })
    })
}

fn raw_fixture_provider_bindings(
    fixtures: &[RawFixtureSummary],
    providers: &[RawProviderSummary],
    members: &[RawArchiveMember<'_>],
    mode: RawArchiveMode,
) -> Result<(), BundleContractErrorV1> {
    fixtures
        .iter()
        .filter(|fixture| {
            fixture
                .modes
                .iter()
                .any(|fixture_mode| fixture_mode.matches_archive(mode))
        })
        .try_for_each(|fixture| {
            providers
                .iter()
                .find(|candidate| {
                    (&candidate.key, candidate.claim_layer, candidate.adapter)
                        == (&fixture.provider, fixture.claim_layer, fixture.adapter)
                })
                .ok_or(BundleContractErrorV1::ProfileInvalid)
                .and_then(|provider| raw_fixture_schema_binding(fixture, provider))
                .and_then(|()| {
                    raw_member(members, &fixture.payload.path, RawMemberRole::FixtureInput)
                        .and_then(|payload| {
                            raw_artifact_matches_member(&fixture.payload, payload).and_then(|()| {
                                raw_validate_draft_evidence(fixture, payload, members)
                            })
                        })
                })
                .and_then(|()| {
                    fixture
                        .auxiliary
                        .iter()
                        .try_for_each(|artifact| raw_bound_raw_artifact_any(artifact, members))
                })
                .and_then(|()| match &fixture.oracle {
                    RawOracle::Output(output) => raw_bound_raw_artifact_any(output, members),
                    RawOracle::Failure(_) | RawOracle::Divergence(_) => Ok(()),
                })
        })
}

fn raw_validate_draft_evidence(
    fixture: &RawFixtureSummary,
    payload: &RawArchiveMember<'_>,
    members: &[RawArchiveMember<'_>],
) -> Result<(), BundleContractErrorV1> {
    let evidence = fixture
        .auxiliary
        .iter()
        .filter(|artifact| artifact.path.starts_with("evidence/"))
        .collect::<Vec<_>>();
    if evidence.len() != 1 {
        return Err(BundleContractErrorV1::ExpectedResultMismatch);
    }
    let expected_path = format!(
        "evidence/{}/{}.json",
        fixture.case_id,
        crate::hex_digest(&fixture.execution)
    );
    if evidence[0].path != expected_path {
        return Err(BundleContractErrorV1::ExpectedResultMismatch);
    }
    raw_member(members, &evidence[0].path, RawMemberRole::EvidenceStatus).and_then(|member| {
        raw_artifact_matches_member(evidence[0], member).and_then(|()| {
            fixture.claim_layer.catalog_name().and_then(|claim_layer| {
                raw_validate_draft_evidence_json(
                    member.bytes,
                    &fixture.case_id,
                    claim_layer,
                    fixture.family.catalog_name(),
                    *blake3::hash(payload.bytes).as_bytes(),
                )
            })
        })
    })
}

fn raw_validate_draft_evidence_json(
    bytes: &[u8],
    case_id: &str,
    claim_layer: &str,
    family: &str,
    input_digest: [u8; 32],
) -> Result<(), BundleContractErrorV1> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| BundleContractErrorV1::ExpectedResultMismatch)?;
    let object = value
        .as_object()
        .ok_or(BundleContractErrorV1::ExpectedResultMismatch)?;
    let required = [
        "case_id",
        "claim_layer",
        "executed_at",
        "execution_result",
        "family",
        "input_blake3_digest",
        "status",
    ];
    let input_digest = crate::hex_digest(&input_digest);
    let valid = object.len() == required.len()
        && required.iter().all(|key| object.contains_key(*key))
        && object.get("case_id").and_then(serde_json::Value::as_str) == Some(case_id)
        && object
            .get("claim_layer")
            .and_then(serde_json::Value::as_str)
            == Some(claim_layer)
        && object.get("family").and_then(serde_json::Value::as_str) == Some(family)
        && object
            .get("input_blake3_digest")
            .and_then(serde_json::Value::as_str)
            == Some(input_digest.as_str())
        && object.get("status").and_then(serde_json::Value::as_str) == Some("pending")
        && object
            .get("execution_result")
            .is_some_and(serde_json::Value::is_null)
        && object
            .get("executed_at")
            .is_some_and(serde_json::Value::is_null);
    if valid {
        Ok(())
    } else {
        Err(BundleContractErrorV1::ExpectedResultMismatch)
    }
}

fn raw_fixture_schema_binding(
    fixture: &RawFixtureSummary,
    provider: &RawProviderSummary,
) -> Result<(), BundleContractErrorV1> {
    let schema = &provider.schemas[fixture.family.index()];
    if schema.path == fixture.schema.path
        && schema.size == fixture.schema.size
        && schema.digest == fixture.schema.digest
    {
        Ok(())
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn raw_bound_raw_artifact_any(
    artifact: &RawArtifact,
    members: &[RawArchiveMember<'_>],
) -> Result<(), BundleContractErrorV1> {
    let role = if artifact.path.starts_with("evidence/") {
        RawMemberRole::EvidenceStatus
    } else {
        RawMemberRole::ExpectedResult
    };
    raw_bound_raw_artifact(artifact, members, role)
}

fn raw_bound_raw_artifact(
    artifact: &RawArtifact,
    members: &[RawArchiveMember<'_>],
    role: RawMemberRole,
) -> Result<(), BundleContractErrorV1> {
    raw_member(members, &artifact.path, role)
        .and_then(|member| raw_artifact_matches_member(artifact, member))
}

fn raw_artifact_matches_member(
    artifact: &RawArtifact,
    member: &RawArchiveMember<'_>,
) -> Result<(), BundleContractErrorV1> {
    if u64::try_from(member.bytes.len()).unwrap_or(u64::MAX) == artifact.size
        && *blake3::hash(member.bytes).as_bytes() == artifact.digest
    {
        Ok(())
    } else {
        Err(BundleContractErrorV1::MemberDigestMismatch)
    }
}

fn raw_registry_digest(fields: &[Value]) -> Result<(), BundleContractErrorV1> {
    length_bound(&Value::Array(fields[..3].to_vec())).and_then(|bound| {
        digest::<32>(&fields[3]).and_then(|recorded| {
            let computed = digest_domain(b"PiglorOS.Conformance.ProviderRegistry.v1\0", &bound);
            if computed == recorded {
                Ok(())
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        })
    })
}

fn raw_declared_packages(
    members: &[RawArchiveMember<'_>],
    providers: &[RawProviderSummary],
) -> Result<(), BundleContractErrorV1> {
    if members.iter().all(|member| {
        member.role != RawMemberRole::FixtureProviderPackage
            || providers
                .iter()
                .any(|provider| member.path == provider.package.path)
    }) {
        Ok(())
    } else {
        Err(BundleContractErrorV1::UndeclaredMember)
    }
}

fn raw_provider_package(
    provider: &Value,
    members: &[RawArchiveMember<'_>],
) -> Result<RawProviderSummary, BundleContractErrorV1> {
    array(provider, 7).and_then(|entry| {
        raw_provider_key(&Value::Array(entry[..4].to_vec())).and_then(|key| {
            RawClaimLayer::from_value(&entry[4]).and_then(|claim_layer| {
                RawSubjectAdapter::from_value(&entry[5]).and_then(|adapter| {
                    raw_artifact(&entry[6]).and_then(|package| {
                        raw_member(
                            members,
                            &package.path,
                            RawMemberRole::FixtureProviderPackage,
                        )
                        .and_then(|package_member| {
                            raw_artifact_matches_member(&package, package_member).and_then(|()| {
                                raw_fpp1(package_member.bytes, entry, members).map(
                                    |package_summary| {
                                        let mut declared_paths = package_summary.declared_paths;
                                        declared_paths.insert(package.path.clone());
                                        RawProviderSummary {
                                            key,
                                            claim_layer,
                                            adapter,
                                            package,
                                            schemas: package_summary.schemas,
                                            declared_paths,
                                        }
                                    },
                                )
                            })
                        })
                    })
                })
            })
        })
    })
}

fn raw_fpp1(
    bytes_value: &[u8],
    entry: &[Value],
    members: &[RawArchiveMember<'_>],
) -> Result<RawPackageSummary, BundleContractErrorV1> {
    decode(bytes_value).and_then(|value| {
        array(&value, 12).and_then(|fields| {
            raw_fpp1_header(fields, entry).and_then(|()| {
                raw_fpp1_paths(fields).and_then(|declared_paths| {
                    raw_fpp1_schemas(&fields[5], members).and_then(|schemas| {
                        raw_fpp1_support(&fields[6..11], members)
                            .and_then(|()| raw_fpp1_digest(fields))
                            .map(|()| RawPackageSummary {
                                schemas,
                                declared_paths,
                            })
                    })
                })
            })
        })
    })
}

fn raw_fpp1_paths(fields: &[Value]) -> Result<BTreeSet<String>, BundleContractErrorV1> {
    array_values(&fields[5]).and_then(|schemas| {
        let schema_paths = schemas.iter().map(|schema| {
            array(schema, 2)
                .and_then(|record| array(&record[1], 4).and_then(|descriptor| text(&descriptor[0])))
        });
        let support_paths = fields[6..11]
            .iter()
            .map(|descriptor| array(descriptor, 4).and_then(|record| text(&record[0])));
        schema_paths
            .chain(support_paths)
            .try_fold(BTreeSet::new(), |mut paths, path| {
                path.and_then(|path| {
                    if paths.insert(path.to_owned()) {
                        Ok(paths)
                    } else {
                        Err(BundleContractErrorV1::NonCanonicalOrder)
                    }
                })
            })
    })
}

fn raw_fpp1_header(fields: &[Value], entry: &[Value]) -> Result<(), BundleContractErrorV1> {
    text(&fields[0]).and_then(|magic| {
        uint(&fields[1]).and_then(|version| {
            if magic == "FPP1"
                && version == 1
                && fields[2] == Value::Array(entry[..4].to_vec())
                && fields[3] == entry[4]
                && fields[4] == entry[5]
            {
                Ok(())
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        })
    })
}

fn raw_fpp1_schemas(
    value: &Value,
    members: &[RawArchiveMember<'_>],
) -> Result<Vec<RawArtifact>, BundleContractErrorV1> {
    array_values(value).and_then(|schemas| {
        if schemas.len() != 7 {
            return Err(BundleContractErrorV1::ProfileInvalid);
        }
        schemas
            .iter()
            .enumerate()
            .map(|(index, schema)| {
                array(schema, 2).and_then(|record| {
                    RawFixtureFamily::from_value(&record[0]).and_then(|family| {
                        if family.index() != index {
                            return Err(BundleContractErrorV1::ProfileInvalid);
                        }
                        raw_artifact(&record[1]).and_then(|artifact| {
                            raw_bound_raw_artifact(&artifact, members, RawMemberRole::Schema)
                                .map(|()| artifact)
                        })
                    })
                })
            })
            .collect()
    })
}

fn raw_fpp1_support(
    values: &[Value],
    members: &[RawArchiveMember<'_>],
) -> Result<(), BundleContractErrorV1> {
    [
        RawMemberRole::Licence,
        RawMemberRole::Notice,
        RawMemberRole::Sbom,
        RawMemberRole::Provenance,
        RawMemberRole::Limitations,
    ]
    .into_iter()
    .zip(values)
    .try_for_each(|(role, descriptor)| raw_bound_artifact(descriptor, members, role))
}

fn raw_bound_artifact(
    value: &Value,
    members: &[RawArchiveMember<'_>],
    role: RawMemberRole,
) -> Result<(), BundleContractErrorV1> {
    raw_artifact(value).and_then(|artifact| raw_bound_raw_artifact(&artifact, members, role))
}

fn raw_fpp1_digest(fields: &[Value]) -> Result<(), BundleContractErrorV1> {
    length_bound(&Value::Array(fields[..11].to_vec())).and_then(|bound| {
        digest::<32>(&fields[11]).and_then(|recorded| {
            let computed = digest_domain(b"PiglorOS.Conformance.ProviderPackage.v1\0", &bound);
            if computed == recorded {
                Ok(())
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        })
    })
}

struct RawExpectedResults {
    results: BTreeMap<RawExpectedResultKey, Vec<u8>>,
    member_paths: BTreeSet<String>,
}

struct RawExpectedResult {
    key: RawExpectedResultKey,
    bytes: Vec<u8>,
    path: String,
    order_key: RawExpectedOrderKey,
}

fn raw_expected_results(
    value: &Value,
    profile: &RawCpf1Summary,
    members: &[RawArchiveMember<'_>],
    mode: RawArchiveMode,
) -> Result<RawExpectedResults, BundleContractErrorV1> {
    array_values(value).and_then(|expected| {
        let mut results = BTreeMap::new();
        let mut member_paths = BTreeSet::new();
        let mut previous = None;
        expected
            .iter()
            .try_for_each(|record| {
                raw_expected_result(record, profile, members, mode).and_then(|result| {
                    if previous
                        .as_ref()
                        .is_some_and(|old| old >= &result.order_key)
                    {
                        Err(BundleContractErrorV1::NonCanonicalOrder)
                    } else {
                        previous = Some(result.order_key);
                        results.insert(result.key, result.bytes);
                        member_paths.insert(result.path);
                        Ok(())
                    }
                })
            })
            .and_then(|()| {
                let selected = profile
                    .fixtures
                    .iter()
                    .filter(|fixture| {
                        fixture
                            .modes
                            .iter()
                            .any(|fixture_mode| fixture_mode.matches_archive(mode))
                    })
                    .count();
                if expected.len() == selected && results.len() == expected.len() {
                    Ok(RawExpectedResults {
                        results,
                        member_paths,
                    })
                } else {
                    Err(BundleContractErrorV1::ExpectedResultMismatch)
                }
            })
    })
}

fn raw_expected_result(
    value: &Value,
    profile: &RawCpf1Summary,
    members: &[RawArchiveMember<'_>],
    mode: RawArchiveMode,
) -> Result<RawExpectedResult, BundleContractErrorV1> {
    let Ok(fields) = array(value, 6) else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    let (
        Ok(case_id),
        Ok(claim_layer),
        Ok(execution),
        Ok(record_mode),
        Ok(path),
        Ok(recorded_digest),
    ) = (
        text(&fields[0]),
        RawClaimLayer::from_value(&fields[1]),
        digest::<32>(&fields[2]),
        uint(&fields[3]).and_then(RawArchiveMode::from_code),
        text(&fields[4]),
        digest::<32>(&fields[5]),
    )
    else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    if record_mode != mode {
        return Err(BundleContractErrorV1::ExpectedResultMismatch);
    }
    raw_member(members, path, RawMemberRole::ExpectedResult).and_then(|member| {
        let member_bytes = member.bytes;
        if *blake3::hash(member_bytes).as_bytes() != recorded_digest
            || !raw_expected_fixture_bound(
                &profile.fixtures,
                case_id,
                claim_layer,
                execution,
                path,
                recorded_digest,
                member_bytes.len(),
            )
        {
            Err(BundleContractErrorV1::ExpectedResultMismatch)
        } else {
            let case_id = case_id.to_owned();
            let path = path.to_owned();
            Ok(RawExpectedResult {
                key: RawExpectedResultKey {
                    case_id: case_id.clone(),
                    claim_layer,
                    execution_profile_digest: execution,
                },
                bytes: member_bytes.to_vec(),
                path: path.clone(),
                order_key: RawExpectedOrderKey {
                    case_id,
                    claim_layer,
                    execution,
                    mode: record_mode,
                    path,
                    digest: recorded_digest,
                },
            })
        }
    })
}

fn raw_expected_fixture_bound(
    fixtures: &[RawFixtureSummary],
    case_id: &str,
    claim_layer: RawClaimLayer,
    execution: [u8; 32],
    path: &str,
    digest: [u8; 32],
    member_size: usize,
) -> bool {
    let size = u64::try_from(member_size).unwrap_or(u64::MAX);
    fixtures.iter().any(|fixture| {
        fixture.case_id == case_id
            && fixture.claim_layer == claim_layer
            && fixture.execution == execution
            && (fixture
                .auxiliary
                .iter()
                .any(|artifact| raw_expected_artifact_bound(artifact, path, digest, size))
                || matches!(
                    &fixture.oracle,
                    RawOracle::Output(output)
                        if raw_expected_artifact_bound(output, path, digest, size)
                ))
    })
}

fn raw_expected_artifact_bound(
    artifact: &RawArtifact,
    path: &str,
    digest: [u8; 32],
    size: u64,
) -> bool {
    artifact.path == path && artifact.digest == digest && artifact.size == size
}

fn raw_ordered_artifacts(values: &[Value]) -> Result<Vec<RawArtifact>, BundleContractErrorV1> {
    values
        .iter()
        .try_fold(Vec::with_capacity(values.len()), |mut artifacts, value| {
            raw_artifact(value).and_then(|artifact| {
                if artifacts.last().is_some_and(|previous: &RawArtifact| {
                    previous.path.as_str() >= artifact.path.as_str()
                }) {
                    Err(BundleContractErrorV1::ProfileInvalid)
                } else {
                    artifacts.push(artifact);
                    Ok(artifacts)
                }
            })
        })
}
fn raw_digests_ordered(values: &[Value]) -> Result<bool, BundleContractErrorV1> {
    values
        .iter()
        .try_fold((None, true), |(previous, ordered), value| {
            digest::<32>(value).map(|current| {
                let is_ordered = ordered && previous.is_none_or(|old| old < current);
                (Some(current), is_ordered)
            })
        })
        .map(|(_, ordered)| ordered)
}
fn raw_ordered_modes(values: &[Value]) -> Result<Vec<RawFixtureMode>, BundleContractErrorV1> {
    values
        .iter()
        .try_fold(Vec::with_capacity(values.len()), |mut modes, value| {
            RawFixtureMode::from_value(value).and_then(|mode| {
                if modes.last().is_some_and(|previous| previous >= &mode) {
                    Err(BundleContractErrorV1::ProfileInvalid)
                } else {
                    modes.push(mode);
                    Ok(modes)
                }
            })
        })
        .and_then(|modes| {
            if modes.is_empty() {
                Err(BundleContractErrorV1::ProfileInvalid)
            } else {
                Ok(modes)
            }
        })
}
fn raw_provider_keys_ordered(values: &[Value]) -> Result<bool, BundleContractErrorV1> {
    values
        .iter()
        .try_fold((None, true), |(previous, ordered), value| {
            raw_provider_order_key(value).map(|current| {
                let next_ordered = ordered && previous.as_ref().is_none_or(|old| old < &current);
                (Some(current), next_ordered)
            })
        })
        .map(|(_, ordered)| ordered)
}

fn raw_provider_order_key(value: &Value) -> Result<RawProviderKey, BundleContractErrorV1> {
    raw_provider_key(value)
}
fn raw_provider_entries_ordered(values: &[Value]) -> Result<bool, BundleContractErrorV1> {
    values
        .iter()
        .try_fold((None, true), |(previous, ordered), value| {
            raw_provider_entry_key(value).map(|current| {
                let is_ordered = ordered && previous.as_ref().is_none_or(|old| old < &current);
                (Some(current), is_ordered)
            })
        })
        .map(|(_, ordered)| ordered)
}

fn raw_provider_entry_key(value: &Value) -> Result<RawProviderKey, BundleContractErrorV1> {
    array(value, 7).and_then(|fields| raw_provider_key(&Value::Array(fields[..4].to_vec())))
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RawFixtureOrderKey {
    provider: RawProviderKey,
    family: RawFixtureFamily,
    case_id: String,
    execution: [u8; 32],
    modes: Vec<RawFixtureMode>,
}

fn raw_fixture_order_key(value: &Value) -> Result<RawFixtureOrderKey, BundleContractErrorV1> {
    array(value, 24).and_then(|fields| {
        raw_provider_key(&fields[4]).and_then(|provider| {
            array_values(&fields[7])
                .and_then(raw_ordered_modes)
                .and_then(|modes| {
                    RawFixtureFamily::from_value(&fields[3]).and_then(|family| {
                        text(&fields[0]).and_then(|case_id| {
                            digest::<32>(&fields[6]).map(|execution| RawFixtureOrderKey {
                                provider,
                                family,
                                case_id: case_id.to_owned(),
                                execution,
                                modes,
                            })
                        })
                    })
                })
        })
    })
}

fn raw_fixture_ordered(values: &[Value]) -> Result<bool, BundleContractErrorV1> {
    values
        .iter()
        .try_fold((None, true), |(previous, ordered), value| {
            raw_fixture_order_key(value).map(|current| {
                let is_ordered = ordered && previous.as_ref().is_none_or(|old| old < &current);
                (Some(current), is_ordered)
            })
        })
        .map(|(_, ordered)| ordered)
}
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RawExpectedOrderKey {
    case_id: String,
    claim_layer: RawClaimLayer,
    execution: [u8; 32],
    mode: RawArchiveMode,
    path: String,
    digest: [u8; 32],
}
fn length_bound(value: &Value) -> Result<Vec<u8>, BundleContractErrorV1> {
    encode(value).map(|encoded| {
        let mut bound = u64::try_from(encoded.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes()
            .to_vec();
        bound.extend(encoded);
        bound
    })
}

fn raw_provider_key(value: &Value) -> Result<RawProviderKey, BundleContractErrorV1> {
    let Ok(fields) = array(value, 4) else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    let (Ok(provider_id), Ok(contract_version), Ok(abi_major), Ok(abi_minor)) = (
        text(&fields[0]),
        text(&fields[1]),
        uint(&fields[2]),
        uint(&fields[3]),
    ) else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    if raw_identifier(provider_id, 128)
        && raw_semver(contract_version)
        && u16::try_from(abi_major).is_ok()
        && u16::try_from(abi_minor).is_ok()
    {
        Ok(RawProviderKey {
            provider_id: provider_id.to_owned(),
            contract_version: contract_version.to_owned(),
            abi_major,
            abi_minor,
        })
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn raw_artifact(value: &Value) -> Result<RawArtifact, BundleContractErrorV1> {
    let Ok(fields) = array(value, 4) else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    let (Ok(member_path), Ok(media_type), Ok(byte_length), Ok(digest)) = (
        text(&fields[0]),
        text(&fields[1]),
        uint(&fields[2]),
        digest::<32>(&fields[3]),
    ) else {
        return Err(BundleContractErrorV1::ArchiveEncodingInvalid);
    };
    if raw_member_path(member_path)
        && raw_media_type(media_type)
        && (1..=64 * 1024 * 1024).contains(&byte_length)
        && digest != [0; 32]
    {
        Ok(RawArtifact {
            path: member_path.to_owned(),
            size: byte_length,
            digest,
        })
    } else {
        Err(BundleContractErrorV1::ProfileInvalid)
    }
}

fn raw_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.is_ascii()
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'/' | b'-')
        })
}
fn raw_member_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.is_ascii()
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.contains('\0')
        && value.split('/').count() <= 16
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".." && part.len() <= 128)
}
fn raw_media_type(value: &str) -> bool {
    (3..=127).contains(&value.len())
        && value.is_ascii()
        && value.bytes().filter(|byte| *byte == b'/').count() == 1
        && !value.starts_with('/')
        && !value.ends_with('/')
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-' | b'/'
                )
        })
}
fn raw_semver(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 || !value.is_ascii() {
        return false;
    }
    let (core_pre, build) = match value.split_once('+') {
        Some((left, right)) if !right.is_empty() && !right.contains('+') => (left, right),
        Some(_) => return false,
        None => (value, ""),
    };
    let (core, pre) = match core_pre.split_once('-') {
        Some((left, right)) if !right.is_empty() && !right.contains('-') => (left, right),
        Some(_) => return false,
        None => (core_pre, ""),
    };
    let mut parts = core.split('.');
    parts.next().is_some_and(raw_numeric_semver)
        && parts.next().is_some_and(raw_numeric_semver)
        && parts.next().is_some_and(raw_numeric_semver)
        && parts.next().is_none()
        && raw_semver_identifiers(pre, true)
        && raw_semver_identifiers(build, false)
}
fn raw_numeric_semver(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 10
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}
fn raw_semver_identifiers(value: &str, no_leading_zero: bool) -> bool {
    value.is_empty()
        || value.split('.').all(|item| {
            !item.is_empty()
                && item
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && (!no_leading_zero
                    || !item.bytes().all(|byte| byte.is_ascii_digit())
                    || raw_numeric_semver(item))
        })
}

#[derive(Clone)]
struct RawArtifact {
    path: String,
    size: u64,
    digest: [u8; 32],
}

enum RawOracle {
    Output(RawArtifact),
    Failure(RawFailure),
    Divergence(RawDivergence),
}

#[derive(Clone, Copy)]
enum RawOracleKind {
    Output,
    Failure,
    Divergence,
}

fn raw_oracle(value: &Value) -> Result<RawOracle, BundleContractErrorV1> {
    array(value, 4).and_then(|fields| {
        uint(&fields[0]).and_then(|kind| {
            let kind = match kind {
                0 => RawOracleKind::Output,
                1 => RawOracleKind::Failure,
                2 => RawOracleKind::Divergence,
                _ => return Err(BundleContractErrorV1::ProfileInvalid),
            };
            let active = match kind {
                RawOracleKind::Output => 1,
                RawOracleKind::Failure => 2,
                RawOracleKind::Divergence => 3,
            };
            if fields
                .iter()
                .enumerate()
                .skip(1)
                .any(|(index, field)| (index == active) != !matches!(field, Value::Null))
            {
                return Err(BundleContractErrorV1::ProfileInvalid);
            }
            match kind {
                RawOracleKind::Output => raw_artifact(&fields[active]).map(RawOracle::Output),
                RawOracleKind::Failure => raw_failure(&fields[active]).map(RawOracle::Failure),
                RawOracleKind::Divergence => {
                    raw_divergence(&fields[active]).map(RawOracle::Divergence)
                }
            }
        })
    })
}

fn raw_divergence(value: &Value) -> Result<RawDivergence, BundleContractErrorV1> {
    array(value, 2).and_then(|fields| {
        uint(&fields[0]).and_then(|classification| {
            bytes(&fields[1]).and_then(|coordinate| {
                if classification <= 6 && !coordinate.is_empty() && coordinate.len() <= 128 {
                    Ok(RawDivergence {
                        classification,
                        coordinate: coordinate.to_vec(),
                    })
                } else {
                    Err(BundleContractErrorV1::ProfileInvalid)
                }
            })
        })
    })
}

fn raw_budget(value: &Value, deterministic_caps: &[u64; 8]) -> Result<(), BundleContractErrorV1> {
    array(value, 8).and_then(|fields| {
        if fields
            .iter()
            .zip(deterministic_caps)
            .all(|(field, ceiling)| uint(field).is_ok_and(|limit| limit > 0 && limit <= *ceiling))
        {
            Ok(())
        } else {
            Err(BundleContractErrorV1::ProfileInvalid)
        }
    })
}

fn raw_watchdog(value: &Value) -> Result<(), BundleContractErrorV1> {
    array(value, 1).and_then(|fields| {
        uint(&fields[0]).and_then(|watchdog| {
            if watchdog == 0 {
                Err(BundleContractErrorV1::ProfileInvalid)
            } else {
                Ok(())
            }
        })
    })
}

fn raw_capabilities(value: &Value) -> Result<bool, BundleContractErrorV1> {
    array(value, 2).and_then(|fields| {
        let Value::Bool(network_allowed) = &fields[0] else {
            return Err(BundleContractErrorV1::ProfileInvalid);
        };
        array_values(&fields[1]).and_then(|ids| {
            if ids.len() <= 256
                && ids.windows(2).all(|pair| pair[0] < pair[1])
                && ids
                    .iter()
                    .all(|id| text(id).is_ok_and(|id| raw_identifier(id, 128)))
            {
                Ok(*network_allowed)
            } else {
                Err(BundleContractErrorV1::ProfileInvalid)
            }
        })
    })
}
