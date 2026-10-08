//! Strict PMF1 V1 decoding and OCI closure binding (ADR-061 revision 3).
//!
//! The only input is one verified ADR-102 release closure. Its `pmf1` member
//! is decoded under the strict deterministic CBOR profile, the descriptors it
//! carries are proved equal to the closure's members, every inner BLAKE3
//! digest is recomputed from the verified blob bytes, and the unsigned
//! manifest and release digests are recomputed before the ADR-103 release
//! projection exists. Artifact content (WIT archive, in-toto, SPDX, licence
//! text, schema JSON) is not validated here, and no signature is verified.

use std::collections::BTreeSet;

use pos_core::OwnerIdV1;
use pos_plugin_release::{BundleMemberV1, VerifiedReleaseBundleV1};
use thiserror::Error;

use crate::plugin_execution::{
    DeterministicBudgetV1, PluginAbiRequirementV1, PluginCapabilityDescriptorV1,
    PluginExecutionProjectionV1, COMMUNITY_PLUGIN_WORLD_V1, WASM_PAGE_BYTES_V1,
};
use crate::plugin_trust::ValidatedPluginManifestProjectionV1;
use crate::strict_cbor::{Reader, StrictCborError};

type Digest = [u8; 32];
type Pmf1Reader<'a> = Reader<'a, PluginManifestErrorV1>;
/// `(capability_id, operation, resource_pattern, purpose, audience)`.
type CapabilityKey<'a> = (&'a str, &'a str, &'a str, &'a str, &'a str);
/// Field 14: capability descriptors and field 15: the deterministic budget.
type ExecutionBounds<'a> = (Vec<Capability<'a>>, DeterministicBudgetV1);
/// `(dependency_id, release_digest32)`.
type Dependency<'a> = (&'a str, Digest);
/// Fields 17-20: dependency release digests, provenance and SBOM, licences.
type SupplyChain = (Vec<Digest>, [Artifact; 2], Vec<Artifact>);
/// An artifact with its position in PMF1 field order.
type Positioned = (usize, Artifact);

/// Maximum complete PMF1 size in bytes.
const MAX_PMF1_BYTES: usize = 1024 * 1024;
/// Error ordinal of the whole PMF1 document or its outer framing.
const DOCUMENT: u8 = 28;
const FIELD_COUNT: u64 = 28;
const MAX_ID_BYTES: usize = 128;
const MAX_SEMVER_BYTES: usize = 64;
const MAX_LIST: usize = 256;
const MAX_LICENCES: usize = 32;
const MAX_LABEL_BYTES: usize = 128;
const MAX_PATTERN_BYTES: usize = 512;
const MAX_U32: u64 = 4_294_967_295;
const MAX_CALLS: u64 = DeterministicBudgetV1::MAXIMA.host_calls;
const MAX_MESSAGE_BYTES: u64 = DeterministicBudgetV1::MAXIMA.event_bytes;
const MAX_BLOB_BYTES: u64 = 33_554_432;
const MAX_WIT_BYTES: u64 = 4_194_304;
const MAX_SCHEMA_BYTES: u64 = 1_048_576;
const MAX_INTERVAL_SECONDS: i128 = 31_622_400;
const MAGIC: &str = "PMF1";
const WORLD: &str = COMMUNITY_PLUGIN_WORLD_V1;
const MANIFEST_DOMAIN: &[u8] = b"PiglorOS.Plugin.Manifest.v1\0";
const RELEASE_DOMAIN: &[u8] = b"PiglorOS.Plugin.Release.v1\0";
/// Canonical head of the 25-element unsigned array of fields 0-24. The outer
/// 28-element head has the same two-byte width, so the unsigned encoding is
/// the complete PMF1 prefix through field 24 with this head substituted.
const UNSIGNED_HEAD: [u8; 2] = [0x98, 0x19];
const HEX: &[u8; 16] = b"0123456789abcdef";
/// `DeterministicBudgetV1` member bounds after `memory_bytes`, in field order.
const BUDGET: [(u64, u64); 7] = [
    (
        DeterministicBudgetV1::MINIMA.fuel,
        DeterministicBudgetV1::MAXIMA.fuel,
    ),
    (
        DeterministicBudgetV1::MINIMA.host_calls,
        DeterministicBudgetV1::MAXIMA.host_calls,
    ),
    (
        DeterministicBudgetV1::MINIMA.event_count,
        DeterministicBudgetV1::MAXIMA.event_count,
    ),
    (
        DeterministicBudgetV1::MINIMA.event_bytes,
        DeterministicBudgetV1::MAXIMA.event_bytes,
    ),
    (
        DeterministicBudgetV1::MINIMA.state_bytes,
        DeterministicBudgetV1::MAXIMA.state_bytes,
    ),
    (
        DeterministicBudgetV1::MINIMA.log_calls,
        DeterministicBudgetV1::MAXIMA.log_calls,
    ),
    (
        DeterministicBudgetV1::MINIMA.log_bytes,
        DeterministicBudgetV1::MAXIMA.log_bytes,
    ),
];

/// A closed PMF1 V1 projection failure (ADR-061 revision 3, section 8).
///
/// `ordinal` is the outermost PMF1 field (0-27); ordinal 28 denotes the whole
/// document or its outer framing. No variant carries text, bytes, or paths.
/// Decoding reports the first failure in pass order, then the closure, inner
/// digest, and manifest/release digest phases run in that order.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PluginManifestErrorV1 {
    /// Truncated, non-shortest, indefinite, wrongly typed, or wrongly shaped
    /// CBOR, an out-of-range signed integer, or trailing bytes.
    #[error("invalid PMF1 encoding at field {ordinal}")]
    InvalidEncoding {
        /// Outermost PMF1 field, or 28 for the document.
        ordinal: u8,
    },
    /// A collection count, text length, or artifact byte length exceeds its
    /// V1 maximum, or the document exceeds 1 MiB.
    #[error("PMF1 field {ordinal} exceeds a V1 bound")]
    BoundsExceeded {
        /// Outermost PMF1 field, or 28 for the document.
        ordinal: u8,
    },
    /// A well-typed value is outside its allowed value, grammar, range,
    /// order, or cross-field relation.
    #[error("invalid PMF1 field {ordinal}")]
    InvalidField {
        /// Outermost PMF1 field.
        ordinal: u8,
    },
    /// Field 1 names a PMF1 version other than 1.
    #[error("unsupported PMF1 version")]
    UnsupportedVersion,
    /// The PMF1-derived member list first differs from the verified closure
    /// at `index`, or one list is a strict prefix of the other.
    #[error("PMF1 closure differs from the release bundle at member {index}")]
    ClosureMismatch {
        /// Index into the PMF1-derived non-`pmf1` member list.
        index: usize,
    },
    /// A recomputed inner BLAKE3 digest differs from its descriptor.
    #[error("PMF1 field {ordinal} artifact digest differs from its bytes")]
    ArtifactDigestMismatch {
        /// Outermost PMF1 field holding the descriptor.
        ordinal: u8,
    },
    /// Field 25 differs from the recomputed unsigned manifest digest.
    #[error("PMF1 unsigned manifest digest differs")]
    UnsignedManifestDigestMismatch,
    /// Field 27 differs from the recomputed release digest.
    #[error("PMF1 release digest differs")]
    ReleaseDigestMismatch,
}

impl StrictCborError for PluginManifestErrorV1 {
    fn invalid_encoding(ordinal: u8) -> Self {
        Self::InvalidEncoding { ordinal }
    }

    fn bounds_exceeded(ordinal: u8) -> Self {
        Self::BoundsExceeded { ordinal }
    }
}

/// One ADR-102 member role carried by an `ArtifactDescriptorV1`.
struct Role {
    /// Exact OCI member annotation, or its prefix when `suffixed`.
    annotation: &'static str,
    /// Whether the annotation ends in the lowercase SHA-256 hex.
    suffixed: bool,
    media_type: &'static str,
    max_bytes: u64,
    /// Inner BLAKE3 domain, including its terminal NUL.
    domain: &'static [u8],
    /// ADR-102 layer rank.
    rank: u8,
}

static COMPONENT: Role = Role {
    annotation: "component",
    suffixed: false,
    media_type: "application/vnd.pigloros.plugin.component.v1+wasm",
    max_bytes: MAX_BLOB_BYTES,
    domain: b"PiglorOS.Plugin.Component.v1\0",
    rank: 1,
};
static WIT: Role = Role {
    annotation: "wit",
    suffixed: false,
    media_type: "application/vnd.pigloros.plugin.wit.v1+tar",
    max_bytes: MAX_WIT_BYTES,
    domain: b"PiglorOS.Plugin.WITArchive.v1\0",
    rank: 2,
};
static SCHEMA: Role = Role {
    annotation: "schema/",
    suffixed: true,
    media_type: "application/vnd.pigloros.plugin.schema.v1+json",
    max_bytes: MAX_SCHEMA_BYTES,
    domain: b"PiglorOS.Plugin.Schema.v1\0",
    rank: 3,
};
static PROVENANCE: Role = Role {
    annotation: "provenance",
    suffixed: false,
    media_type: "application/vnd.in-toto+json",
    max_bytes: MAX_BLOB_BYTES,
    domain: b"PiglorOS.Plugin.Provenance.v1\0",
    rank: 4,
};
static SBOM: Role = Role {
    annotation: "sbom",
    suffixed: false,
    media_type: "application/spdx+json",
    max_bytes: MAX_BLOB_BYTES,
    domain: b"PiglorOS.Plugin.SBOM.v1\0",
    rank: 5,
};
static LICENCE: Role = Role {
    annotation: "licence/",
    suffixed: true,
    media_type: "text/plain; charset=utf-8",
    max_bytes: MAX_BLOB_BYTES,
    domain: b"PiglorOS.Plugin.Licence.v1\0",
    rank: 6,
};

/// One decoded dual-digest `ArtifactDescriptorV1`.
#[derive(Clone, Copy)]
struct Artifact {
    ordinal: u8,
    role: &'static Role,
    byte_length: u64,
    blake3: Digest,
    sha256: Digest,
}

impl Artifact {
    /// The ADR-102 `sha256:<hex>` digest of the described blob.
    fn oci_digest(&self) -> String {
        format!("sha256:{}", lower_hex(&self.sha256))
    }

    /// Whether `member` has this descriptor's annotation, media type, size,
    /// and digest.
    fn matches(&self, member: &BundleMemberV1) -> bool {
        let annotation = if self.role.suffixed {
            format!("{}{}", self.role.annotation, lower_hex(&self.sha256))
        } else {
            self.role.annotation.to_owned()
        };
        let digest = self.oci_digest();
        let expected = (
            annotation.as_str(),
            self.role.media_type,
            self.byte_length,
            digest.as_str(),
        );
        let actual = (
            member.member(),
            member.media_type(),
            member.size(),
            member.digest(),
        );
        actual == expected
    }
}

/// One decoded `SchemaDescriptorV1`.
struct Schema {
    id: u64,
    artifact: Artifact,
}

/// One decoded `CapabilityDescriptorV1` borrowing its texts from PMF1.
struct Capability<'a> {
    key: CapabilityKey<'a>,
    required: bool,
    /// `max_calls`, `max_request_bytes`, `max_response_bytes`.
    limits: [u64; 3],
}

impl Capability<'_> {
    fn descriptor(&self) -> PluginCapabilityDescriptorV1 {
        let (capability_id, operation, resource_pattern, purpose, audience) = self.key;
        let [max_calls, max_request_bytes, max_response_bytes] = self.limits;
        PluginCapabilityDescriptorV1 {
            capability_id: capability_id.to_owned(),
            operation: operation.to_owned(),
            resource_pattern: resource_pattern.to_owned(),
            purpose: purpose.to_owned(),
            audience: audience.to_owned(),
            required: self.required,
            max_calls,
            max_request_bytes,
            max_response_bytes,
        }
    }
}

/// Fields 21-27 of a decoded PMF1.
struct SignedFields {
    owner: OwnerIdV1,
    not_before: i64,
    not_after: i64,
    previous: Option<Digest>,
    /// Offset just after field 24.
    unsigned_end: usize,
    manifest_digest: Digest,
    role: u64,
    epoch: u64,
    release_digest: Digest,
}

/// A PMF1 V1 that passed pass 1 decoding.
struct Pmf1<'a> {
    plugin_id: &'a str,
    abi: PluginAbiRequirementV1,
    component: Artifact,
    wit: Artifact,
    schemas: Vec<Schema>,
    capabilities: Vec<Capability<'a>>,
    budget: DeterministicBudgetV1,
    dependencies: Vec<Digest>,
    provenance: Artifact,
    sbom: Artifact,
    licences: Vec<Artifact>,
    signed: SignedFields,
}

/// Decode, bind, and project the `pmf1` member of one verified closure.
pub(crate) fn project_verified_bundle(
    bundle: &VerifiedReleaseBundleV1,
) -> Result<ValidatedPluginManifestProjectionV1, PluginManifestErrorV1> {
    validate_bundle(bundle).map(release_projection)
}

/// Run the same validation and keep the execution requirements instead.
pub(crate) fn project_execution(
    bundle: &VerifiedReleaseBundleV1,
) -> Result<PluginExecutionProjectionV1, PluginManifestErrorV1> {
    validate_bundle(bundle).map(execution_projection)
}

/// One PMF1 that passed every phase, with the values both projections bind.
struct ValidatedPmf1<'a> {
    pmf1: Pmf1<'a>,
    /// The PMF1-derived member list `E` in ADR-102 layer order.
    expected: Vec<Positioned>,
    /// Unkeyed BLAKE3-256 of the complete PMF1 bytes.
    pmf1_digest: Digest,
}

/// Every phase of one verified closure, in ADR-061 revision 3 order.
fn validate_bundle(
    bundle: &VerifiedReleaseBundleV1,
) -> Result<ValidatedPmf1<'_>, PluginManifestErrorV1> {
    let bytes = bundle.pmf1();
    let pmf1 = decode(bytes)?;
    check_relations(&pmf1)?;
    let expected = closure_order(&field_order(&pmf1));
    check_closure(&expected, bundle.members())?;
    check_inner_digests(&expected, bundle)?;
    check_signed_digests(bytes, &pmf1)?;
    Ok(ValidatedPmf1 {
        pmf1,
        expected,
        pmf1_digest: *blake3::hash(bytes).as_bytes(),
    })
}

/// The ADR-103 release projection of one validated PMF1.
fn release_projection(validated: ValidatedPmf1<'_>) -> ValidatedPluginManifestProjectionV1 {
    let ValidatedPmf1 {
        pmf1,
        expected,
        pmf1_digest,
    } = validated;
    let descriptor_digests = expected
        .iter()
        .flat_map(|(_, artifact)| [artifact.blake3, artifact.sha256])
        .chain(pmf1.dependencies.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    ValidatedPluginManifestProjectionV1 {
        pmf1_digest,
        plugin_id: pmf1.plugin_id.to_owned(),
        owner: pmf1.signed.owner,
        role: pmf1.signed.role,
        epoch: pmf1.signed.epoch,
        not_before: pmf1.signed.not_before,
        not_after: pmf1.signed.not_after,
        release_digest: pmf1.signed.release_digest,
        previous_release_digest: pmf1.signed.previous,
        descriptor_digests,
    }
}

/// The execution projection of one validated PMF1.
fn execution_projection(validated: ValidatedPmf1<'_>) -> PluginExecutionProjectionV1 {
    let pmf1 = validated.pmf1;
    PluginExecutionProjectionV1 {
        pmf1_digest: validated.pmf1_digest,
        release_digest: pmf1.signed.release_digest,
        plugin_id: pmf1.plugin_id.to_owned(),
        capabilities: pmf1
            .capabilities
            .iter()
            .map(Capability::descriptor)
            .collect(),
        abi: pmf1.abi,
        budget: pmf1.budget,
    }
}

/// The ADR-061 ID grammar: `[a-z0-9][a-z0-9._/-]*`, 1-128 bytes.
pub(crate) fn valid_id_text(value: &str) -> bool {
    let mut bytes = value.bytes();
    value.len() <= MAX_ID_BYTES
        && bytes
            .next()
            .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'/' | b'-')
        })
}

/// `<version core>[-<pre-release>]` from Semantic Versioning 2.0.0, without
/// build metadata.
fn valid_semver(value: &str) -> bool {
    let (core, pre_release) = value
        .split_once('-')
        .map_or((value, None), |(core, pre_release)| {
            (core, Some(pre_release))
        });
    core.split('.').count() == 3
        && core.split('.').all(numeric_identifier)
        && pre_release.is_none_or(valid_pre_release)
}

fn valid_pre_release(pre_release: &str) -> bool {
    pre_release.split('.').all(pre_release_identifier)
}

fn numeric_identifier(part: &str) -> bool {
    !part.is_empty()
        && part.bytes().all(|byte| byte.is_ascii_digit())
        && (part == "0" || !part.starts_with('0'))
}

fn pre_release_identifier(part: &str) -> bool {
    !part.is_empty()
        && part
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && (part.bytes().any(|byte| !byte.is_ascii_digit()) || numeric_identifier(part))
}

fn lower_hex(digest: &Digest) -> String {
    digest
        .iter()
        .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]])
        .map(char::from)
        .collect()
}

const fn require(reader: &Pmf1Reader<'_>, valid: bool) -> Result<(), PluginManifestErrorV1> {
    if valid {
        Ok(())
    } else {
        Err(PluginManifestErrorV1::InvalidField {
            ordinal: reader.ordinal(),
        })
    }
}

fn unsigned_in(
    reader: &mut Pmf1Reader<'_>,
    minimum: u64,
    maximum: u64,
) -> Result<u64, PluginManifestErrorV1> {
    let value = reader.unsigned()?;
    require(reader, (minimum..=maximum).contains(&value))?;
    Ok(value)
}

fn exact_text(reader: &mut Pmf1Reader<'_>, expected: &str) -> Result<(), PluginManifestErrorV1> {
    let exact = reader.exact_text(expected)?;
    require(reader, exact)
}

fn id_text<'a>(reader: &mut Pmf1Reader<'a>) -> Result<&'a str, PluginManifestErrorV1> {
    let value = reader.text(MAX_ID_BYTES)?;
    require(reader, valid_id_text(value))?;
    Ok(value)
}

/// Non-empty UTF-8 without a C0 or C1 control code point.
fn label<'a>(reader: &mut Pmf1Reader<'a>, max: usize) -> Result<&'a str, PluginManifestErrorV1> {
    let value = reader.text(max)?;
    let valid = !value.is_empty() && !value.chars().any(char::is_control);
    require(reader, valid)?;
    Ok(value)
}

/// Read an array of at most `max` items strictly increasing by `key`.
fn read_increasing<'a, T, K: Ord>(
    reader: &mut Pmf1Reader<'a>,
    max: usize,
    read: fn(&mut Pmf1Reader<'a>) -> Result<T, PluginManifestErrorV1>,
    key: fn(&T) -> K,
) -> Result<Vec<T>, PluginManifestErrorV1> {
    let count = reader.array(max)?;
    let mut items: Vec<T> = Vec::with_capacity(count);
    for _ in 0..count {
        let item = read(reader)?;
        let increasing = items.last().is_none_or(|last| key(last) < key(&item));
        require(reader, increasing)?;
        items.push(item);
    }
    Ok(items)
}

fn read_id_list<'a>(reader: &mut Pmf1Reader<'a>) -> Result<Vec<&'a str>, PluginManifestErrorV1> {
    read_increasing(reader, MAX_LIST, id_text, |id| *id)
}

fn read_artifact(
    reader: &mut Pmf1Reader<'_>,
    role: &'static Role,
) -> Result<Artifact, PluginManifestErrorV1> {
    reader.fixed_array(4)?;
    exact_text(reader, role.media_type)?;
    let byte_length = reader.unsigned()?;
    require(reader, byte_length != 0)?;
    if byte_length > role.max_bytes {
        return Err(reader.exceeded());
    }
    let blake3 = reader.bytes()?;
    let sha256 = reader.bytes()?;
    Ok(Artifact {
        ordinal: reader.ordinal(),
        role,
        byte_length,
        blake3,
        sha256,
    })
}

/// Fields 0-1 and the outer array header (pass 1a).
fn read_header(reader: &mut Pmf1Reader<'_>) -> Result<(), PluginManifestErrorV1> {
    reader.at(DOCUMENT);
    let (major, count) = reader.head()?;
    if major != 4 || count < 2 {
        return Err(reader.invalid());
    }
    reader.at(0);
    exact_text(reader, MAGIC)?;
    reader.at(1);
    if reader.unsigned()? != 1 {
        return Err(PluginManifestErrorV1::UnsupportedVersion);
    }
    reader.at(DOCUMENT);
    if count != FIELD_COUNT {
        return Err(reader.invalid());
    }
    Ok(())
}

/// Fields 2-8: Plugin ID, release, world, and ABI requirements.
fn read_compatibility<'a>(
    reader: &mut Pmf1Reader<'a>,
) -> Result<(&'a str, PluginAbiRequirementV1), PluginManifestErrorV1> {
    reader.at(2);
    let plugin_id = id_text(reader)?;
    reader.at(3);
    let release = reader.text(MAX_SEMVER_BYTES)?;
    require(reader, valid_semver(release))?;
    reader.at(4);
    exact_text(reader, WORLD)?;
    reader.at(5);
    let major = abi_u16_in(reader, 0, 0)?;
    reader.at(6);
    let minimum = abi_u16_in(reader, 0, u16::MAX)?;
    reader.at(7);
    let maximum = abi_u16_in(reader, minimum, u16::MAX)?;
    reader.at(8);
    let features = read_id_list(reader)?;
    let abi = PluginAbiRequirementV1 {
        major,
        min_minor: minimum,
        max_minor: maximum,
        required_features: features.into_iter().map(str::to_owned).collect(),
    };
    Ok((plugin_id, abi))
}

/// An unsigned `u16` ABI value in `minimum..=maximum`, else `InvalidField`.
fn abi_u16_in(
    reader: &mut Pmf1Reader<'_>,
    minimum: u16,
    maximum: u16,
) -> Result<u16, PluginManifestErrorV1> {
    let invalid = PluginManifestErrorV1::InvalidField {
        ordinal: reader.ordinal(),
    };
    let value = u16::try_from(reader.unsigned()?)
        .ok()
        .filter(|value| (minimum..=maximum).contains(value));
    value.ok_or(invalid)
}

fn read_schema(reader: &mut Pmf1Reader<'_>) -> Result<Schema, PluginManifestErrorV1> {
    reader.fixed_array(4)?;
    let id = unsigned_in(reader, 0, MAX_U32)?;
    unsigned_in(reader, 1, MAX_U32)?;
    let artifact = read_artifact(reader, &SCHEMA)?;
    unsigned_in(reader, 1, MAX_SCHEMA_BYTES)?;
    Ok(Schema { id, artifact })
}

/// Fields 11-13 in traversal order.
fn read_schemas(reader: &mut Pmf1Reader<'_>) -> Result<Vec<Schema>, PluginManifestErrorV1> {
    reader.at(11);
    let mut schemas = read_increasing(reader, MAX_LIST, read_schema, |schema| schema.id)?;
    reader.at(12);
    schemas.push(read_schema(reader)?);
    reader.at(13);
    if !reader.null() {
        schemas.push(read_schema(reader)?);
    }
    Ok(schemas)
}

fn read_capability<'a>(
    reader: &mut Pmf1Reader<'a>,
) -> Result<Capability<'a>, PluginManifestErrorV1> {
    reader.fixed_array(9)?;
    let key = (
        id_text(reader)?,
        id_text(reader)?,
        label(reader, MAX_PATTERN_BYTES)?,
        label(reader, MAX_LABEL_BYTES)?,
        label(reader, MAX_LABEL_BYTES)?,
    );
    let required = reader.boolean()?;
    let limits = [
        unsigned_in(reader, 0, MAX_CALLS)?,
        unsigned_in(reader, 0, MAX_MESSAGE_BYTES)?,
        unsigned_in(reader, 0, MAX_MESSAGE_BYTES)?,
    ];
    Ok(Capability {
        key,
        required,
        limits,
    })
}

/// Fields 14-16: capabilities, deterministic budget, and migrations.
fn read_execution_bounds<'a>(
    reader: &mut Pmf1Reader<'a>,
) -> Result<ExecutionBounds<'a>, PluginManifestErrorV1> {
    reader.at(14);
    let capabilities = read_increasing(reader, MAX_LIST, read_capability, |entry| entry.key)?;
    reader.at(15);
    let budget = read_budget(reader)?;
    // PMF1 V1 declares no migration; any other field 16 needs PMF1 version 2.
    reader.at(16);
    let migrations = reader.array(usize::MAX)?;
    require(reader, migrations == 0)?;
    Ok((capabilities, budget))
}

/// Field 15: one `DeterministicBudgetV1` within its PMF1 V1 member bounds.
fn read_budget(
    reader: &mut Pmf1Reader<'_>,
) -> Result<DeterministicBudgetV1, PluginManifestErrorV1> {
    reader.fixed_array(8)?;
    let memory_bytes = unsigned_in(
        reader,
        DeterministicBudgetV1::MINIMA.memory_bytes,
        DeterministicBudgetV1::MAXIMA.memory_bytes,
    )?;
    require(reader, memory_bytes.is_multiple_of(WASM_PAGE_BYTES_V1))?;
    let mut members = [0; BUDGET.len()];
    for (member, (minimum, maximum)) in members.iter_mut().zip(BUDGET) {
        *member = unsigned_in(reader, minimum, maximum)?;
    }
    let [fuel, host_calls, event_count, event_bytes, state_bytes, log_calls, log_bytes] = members;
    Ok(DeterministicBudgetV1 {
        memory_bytes,
        fuel,
        host_calls,
        event_count,
        event_bytes,
        state_bytes,
        log_calls,
        log_bytes,
    })
}

fn read_dependency<'a>(
    reader: &mut Pmf1Reader<'a>,
) -> Result<Dependency<'a>, PluginManifestErrorV1> {
    reader.fixed_array(9)?;
    let id = id_text(reader)?;
    let release_digest = reader.bytes()?;
    exact_text(reader, WORLD)?;
    unsigned_in(reader, 0, 0)?;
    let minimum = unsigned_in(reader, 0, u64::from(u16::MAX))?;
    unsigned_in(reader, minimum, u64::from(u16::MAX))?;
    read_id_list(reader)?;
    read_id_list(reader)?;
    unsigned_in(reader, 0, 4)?;
    Ok((id, release_digest))
}

/// Fields 17-20: dependencies, provenance, SBOM, and licences.
fn read_supply_chain(reader: &mut Pmf1Reader<'_>) -> Result<SupplyChain, PluginManifestErrorV1> {
    reader.at(17);
    let dependencies = read_increasing(reader, MAX_LIST, read_dependency, |entry| entry.0)?;
    reader.at(18);
    let provenance = read_artifact(reader, &PROVENANCE)?;
    reader.at(19);
    let sbom = read_artifact(reader, &SBOM)?;
    reader.at(20);
    let licences = read_increasing(
        reader,
        MAX_LICENCES,
        |reader| read_artifact(reader, &LICENCE),
        |licence| licence.sha256,
    )?;
    require(reader, !licences.is_empty())?;
    let dependency_digests = dependencies.iter().map(|(_, digest)| *digest).collect();
    Ok((dependency_digests, [provenance, sbom], licences))
}

/// Fields 21-27 and the end of the document.
fn read_signed_fields(reader: &mut Pmf1Reader<'_>) -> Result<SignedFields, PluginManifestErrorV1> {
    reader.at(21);
    let invalid_owner = PluginManifestErrorV1::InvalidField {
        ordinal: reader.ordinal(),
    };
    let owner = OwnerIdV1::new(reader.text(MAX_ID_BYTES)?).map_err(|_| invalid_owner)?;
    reader.at(22);
    let not_before = reader.signed()?;
    reader.at(23);
    let not_after = reader.signed()?;
    let duration = i128::from(not_after) - i128::from(not_before);
    require(reader, (1..=MAX_INTERVAL_SECONDS).contains(&duration))?;
    reader.at(24);
    let previous = reader.optional_bytes()?;
    let unsigned_end = reader.offset();
    reader.at(25);
    let manifest_digest = reader.bytes()?;
    reader.at(26);
    reader.fixed_array(4)?;
    unsigned_in(reader, 1, 1)?;
    let role = unsigned_in(reader, 3, 3)?;
    let epoch = unsigned_in(reader, 1, u64::MAX)?;
    reader.bytes::<64>()?;
    reader.at(27);
    let release_digest = reader.bytes()?;
    reader.at(DOCUMENT);
    reader.finish()?;
    Ok(SignedFields {
        owner,
        not_before,
        not_after,
        previous,
        unsigned_end,
        manifest_digest,
        role,
        epoch,
        release_digest,
    })
}

/// Phase 1 passes 1a and 1b: every field and intra-field rule in order.
fn decode(bytes: &[u8]) -> Result<Pmf1<'_>, PluginManifestErrorV1> {
    if bytes.len() > MAX_PMF1_BYTES {
        return Err(PluginManifestErrorV1::BoundsExceeded { ordinal: DOCUMENT });
    }
    let mut reader = Reader::new(bytes);
    read_header(&mut reader)?;
    let (plugin_id, abi) = read_compatibility(&mut reader)?;
    reader.at(9);
    let component = read_artifact(&mut reader, &COMPONENT)?;
    reader.at(10);
    let wit = read_artifact(&mut reader, &WIT)?;
    let schemas = read_schemas(&mut reader)?;
    let (capabilities, budget) = read_execution_bounds(&mut reader)?;
    let (dependencies, [provenance, sbom], licences) = read_supply_chain(&mut reader)?;
    let signed = read_signed_fields(&mut reader)?;
    Ok(Pmf1 {
        plugin_id,
        abi,
        component,
        wit,
        schemas,
        capabilities,
        budget,
        dependencies,
        provenance,
        sbom,
        licences,
        signed,
    })
}

/// Phase 1 pass 2: cross-field relations in ordinal order 11-13, 17, 24.
fn check_relations(pmf1: &Pmf1<'_>) -> Result<(), PluginManifestErrorV1> {
    let mut ids = BTreeSet::new();
    let mut digests = BTreeSet::new();
    for schema in &pmf1.schemas {
        if !ids.insert(schema.id) || !digests.insert(schema.artifact.sha256) {
            return Err(PluginManifestErrorV1::InvalidField {
                ordinal: schema.artifact.ordinal,
            });
        }
    }
    let release = pmf1.signed.release_digest;
    if pmf1.dependencies.contains(&release) {
        return Err(PluginManifestErrorV1::InvalidField { ordinal: 17 });
    }
    if pmf1.signed.previous == Some(release) {
        return Err(PluginManifestErrorV1::InvalidField { ordinal: 24 });
    }
    Ok(())
}

/// Every artifact descriptor in PMF1 order: 9, 10, 11-13, 18, 19, 20.
fn field_order(pmf1: &Pmf1<'_>) -> Vec<Artifact> {
    let mut artifacts = vec![pmf1.component, pmf1.wit];
    artifacts.extend(pmf1.schemas.iter().map(|schema| schema.artifact));
    artifacts.extend([pmf1.provenance, pmf1.sbom]);
    artifacts.extend(pmf1.licences.iter().copied());
    artifacts
}

/// The PMF1-derived member list `E` in ADR-102 layer order: role rank, then
/// digest order for repeated roles.
fn closure_order(artifacts: &[Artifact]) -> Vec<Positioned> {
    let mut expected = artifacts.iter().copied().enumerate().collect::<Vec<_>>();
    expected.sort_by_key(|(_, artifact)| (artifact.role.rank, artifact.sha256));
    expected
}

/// Phase 2: `E` equals the non-`pmf1` members.
fn check_closure(
    expected: &[Positioned],
    members: &[BundleMemberV1],
) -> Result<(), PluginManifestErrorV1> {
    let layers = members.len().saturating_sub(1);
    let shorter = expected.len().min(layers);
    let index = expected
        .iter()
        .zip(members.iter().skip(1))
        .position(|((_, artifact), member)| !artifact.matches(member))
        .unwrap_or(shorter);
    if index == expected.len() && index == layers {
        Ok(())
    } else {
        Err(PluginManifestErrorV1::ClosureMismatch { index })
    }
}

/// `BLAKE3(domain || u64be(len) || bytes)`.
fn role_digest(domain: &[u8], bytes: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

/// Phase 3: every inner BLAKE3 digest; the first mismatch in PMF1 field and
/// position order is reported. Phase 2 proved `E` equal to the layers.
fn check_inner_digests(
    expected: &[Positioned],
    bundle: &VerifiedReleaseBundleV1,
) -> Result<(), PluginManifestErrorV1> {
    expected
        .iter()
        .zip(bundle.member_bytes().skip(1))
        .filter(|((_, artifact), bytes)| {
            role_digest(artifact.role.domain, bytes) != artifact.blake3
        })
        .map(|((position, artifact), _)| (*position, artifact.ordinal))
        .min()
        .map_or(Ok(()), |(_, ordinal)| {
            Err(PluginManifestErrorV1::ArtifactDigestMismatch { ordinal })
        })
}

/// Phase 4: field 25, then field 27.
fn check_signed_digests(bytes: &[u8], pmf1: &Pmf1<'_>) -> Result<(), PluginManifestErrorV1> {
    let end = pmf1.signed.unsigned_end;
    let mut hasher = blake3::Hasher::new();
    hasher.update(MANIFEST_DOMAIN);
    hasher.update(&(end as u64).to_be_bytes());
    hasher.update(&UNSIGNED_HEAD);
    hasher.update(&bytes[UNSIGNED_HEAD.len()..end]);
    let unsigned = *hasher.finalize().as_bytes();
    if unsigned != pmf1.signed.manifest_digest {
        return Err(PluginManifestErrorV1::UnsignedManifestDigestMismatch);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(RELEASE_DOMAIN);
    hasher.update(&unsigned);
    hasher.update(&pmf1.component.blake3);
    hasher.update(&pmf1.wit.blake3);
    if *hasher.finalize().as_bytes() != pmf1.signed.release_digest {
        return Err(PluginManifestErrorV1::ReleaseDigestMismatch);
    }
    Ok(())
}
