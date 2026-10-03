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
use pos_plugin_release::{BlobV1, BundleMemberV1, VerifiedReleaseBundleV1};
use thiserror::Error;

use crate::strict_cbor::{Reader, StrictCborError};

type Digest = [u8; 32];
type Pmf1Reader<'a> = Reader<'a, PluginManifestErrorV1>;
/// `(capability_id, operation, resource_pattern, purpose, audience)`.
type CapabilityKey<'a> = (&'a str, &'a str, &'a str, &'a str, &'a str);
/// `(dependency_id, release_digest32)`.
type Dependency<'a> = (&'a str, Digest);

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
const MAX_MINOR: u64 = 65_535;
const MAX_U32: u64 = 4_294_967_295;
const MAX_CALLS: u64 = 1_000_000;
const MAX_MESSAGE_BYTES: u64 = 16_777_216;
const MAX_BLOB_BYTES: u64 = 33_554_432;
const MAX_WIT_BYTES: u64 = 4_194_304;
const MAX_SCHEMA_BYTES: u64 = 1_048_576;
const WASM_PAGE_BYTES: u64 = 65_536;
const MAX_MEMORY_BYTES: u64 = 4_294_967_296;
const MAX_INTERVAL_SECONDS: i128 = 31_622_400;
const MAGIC: &str = "PMF1";
const WORLD: &str = "pigloros:plugin/community-plugin@0.1.0";
const MANIFEST_DOMAIN: &[u8] = b"PiglorOS.Plugin.Manifest.v1\0";
const RELEASE_DOMAIN: &[u8] = b"PiglorOS.Plugin.Release.v1\0";
/// Canonical head of the 25-element unsigned array of fields 0-24. The outer
/// 28-element head has the same two-byte width, so the unsigned encoding is
/// the complete PMF1 prefix through field 24 with this head substituted.
const UNSIGNED_HEAD: [u8; 2] = [0x98, 0x19];
const HEX: &[u8; 16] = b"0123456789abcdef";
/// `DeterministicBudgetV1` member bounds after `memory_bytes`, in field order.
const BUDGET: [(u64, u64); 7] = [
    (1, u64::MAX),
    (0, MAX_CALLS),
    (0, 1_024),
    (0, MAX_MESSAGE_BYTES),
    (0, 1_048_576),
    (0, 64),
    (0, 16_384),
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
    component: Artifact,
    wit: Artifact,
    schemas: Vec<Schema>,
    dependencies: Vec<Digest>,
    provenance: Artifact,
    sbom: Artifact,
    licences: Vec<Artifact>,
    signed: SignedFields,
}

/// The facts of one complete, closure-bound PMF1 V1 (ADR-103 projection).
pub(crate) struct ManifestProjection {
    pub(crate) pmf1_digest: Digest,
    pub(crate) plugin_id: String,
    pub(crate) owner: OwnerIdV1,
    pub(crate) role: u64,
    pub(crate) epoch: u64,
    pub(crate) not_before: i64,
    pub(crate) not_after: i64,
    pub(crate) release_digest: Digest,
    pub(crate) descriptor_digests: Vec<Digest>,
}

/// Decode, bind, and project the `pmf1` member of one verified closure.
pub(crate) fn project_verified_bundle(
    bundle: &VerifiedReleaseBundleV1,
) -> Result<ManifestProjection, PluginManifestErrorV1> {
    let members = bundle.members();
    // ADR-102 places the sole `pmf1` member first and #425 verified its blob.
    let pmf1_digest = members.first().map_or("", BundleMemberV1::digest);
    let bytes = blob_bytes(bundle, pmf1_digest);
    let pmf1 = decode(bytes)?;
    check_relations(&pmf1)?;
    let artifacts = field_order(&pmf1);
    check_closure(&artifacts, members)?;
    check_inner_digests(&artifacts, bundle)?;
    check_signed_digests(bytes, &pmf1)?;
    let descriptor_digests = artifacts
        .iter()
        .flat_map(|artifact| [artifact.blake3, artifact.sha256])
        .chain(pmf1.dependencies.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(ManifestProjection {
        pmf1_digest: *blake3::hash(bytes).as_bytes(),
        plugin_id: pmf1.plugin_id.to_owned(),
        owner: pmf1.signed.owner,
        role: pmf1.signed.role,
        epoch: pmf1.signed.epoch,
        not_before: pmf1.signed.not_before,
        not_after: pmf1.signed.not_after,
        release_digest: pmf1.signed.release_digest,
        descriptor_digests,
    })
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

/// Verified blob bytes for an OCI digest, or no bytes when absent.
fn blob_bytes<'a>(bundle: &'a VerifiedReleaseBundleV1, digest: &str) -> &'a [u8] {
    let blobs = bundle.blobs();
    blobs
        .binary_search_by(|blob| blob.digest().cmp(digest))
        .ok()
        .and_then(|index| blobs.get(index))
        .map(BlobV1::bytes)
        .unwrap_or_default()
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
fn read_compatibility<'a>(reader: &mut Pmf1Reader<'a>) -> Result<&'a str, PluginManifestErrorV1> {
    reader.at(2);
    let plugin_id = id_text(reader)?;
    reader.at(3);
    let release = reader.text(MAX_SEMVER_BYTES)?;
    require(reader, valid_semver(release))?;
    reader.at(4);
    exact_text(reader, WORLD)?;
    reader.at(5);
    unsigned_in(reader, 0, 0)?;
    reader.at(6);
    let minimum = unsigned_in(reader, 0, MAX_MINOR)?;
    reader.at(7);
    unsigned_in(reader, minimum, MAX_MINOR)?;
    reader.at(8);
    read_id_list(reader)?;
    Ok(plugin_id)
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
) -> Result<CapabilityKey<'a>, PluginManifestErrorV1> {
    reader.fixed_array(9)?;
    let key = (
        id_text(reader)?,
        id_text(reader)?,
        label(reader, MAX_PATTERN_BYTES)?,
        label(reader, MAX_LABEL_BYTES)?,
        label(reader, MAX_LABEL_BYTES)?,
    );
    reader.boolean()?;
    unsigned_in(reader, 0, MAX_CALLS)?;
    unsigned_in(reader, 0, MAX_MESSAGE_BYTES)?;
    unsigned_in(reader, 0, MAX_MESSAGE_BYTES)?;
    Ok(key)
}

/// Fields 14-16: capabilities, deterministic budget, and migrations.
fn read_execution_bounds(reader: &mut Pmf1Reader<'_>) -> Result<(), PluginManifestErrorV1> {
    reader.at(14);
    read_increasing(reader, MAX_LIST, read_capability, |key| *key)?;
    reader.at(15);
    reader.fixed_array(8)?;
    let memory = unsigned_in(reader, WASM_PAGE_BYTES, MAX_MEMORY_BYTES)?;
    require(reader, memory % WASM_PAGE_BYTES == 0)?;
    for (minimum, maximum) in BUDGET {
        unsigned_in(reader, minimum, maximum)?;
    }
    // PMF1 V1 declares no migration; any other field 16 needs PMF1 version 2.
    reader.at(16);
    let migrations = reader.array(usize::MAX)?;
    require(reader, migrations == 0)
}

fn read_dependency<'a>(
    reader: &mut Pmf1Reader<'a>,
) -> Result<Dependency<'a>, PluginManifestErrorV1> {
    reader.fixed_array(9)?;
    let id = id_text(reader)?;
    let release_digest = reader.bytes()?;
    exact_text(reader, WORLD)?;
    unsigned_in(reader, 0, 0)?;
    let minimum = unsigned_in(reader, 0, MAX_MINOR)?;
    unsigned_in(reader, minimum, MAX_MINOR)?;
    read_id_list(reader)?;
    read_id_list(reader)?;
    unsigned_in(reader, 0, 4)?;
    Ok((id, release_digest))
}

/// Fields 17-20: dependencies, provenance, SBOM, and licences.
fn read_supply_chain(
    reader: &mut Pmf1Reader<'_>,
) -> Result<(Vec<Digest>, [Artifact; 2], Vec<Artifact>), PluginManifestErrorV1> {
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
    let invalid_owner = PluginManifestErrorV1::InvalidField { ordinal: 21 };
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
    let plugin_id = read_compatibility(&mut reader)?;
    reader.at(9);
    let component = read_artifact(&mut reader, &COMPONENT)?;
    reader.at(10);
    let wit = read_artifact(&mut reader, &WIT)?;
    let schemas = read_schemas(&mut reader)?;
    read_execution_bounds(&mut reader)?;
    let (dependencies, [provenance, sbom], licences) = read_supply_chain(&mut reader)?;
    let signed = read_signed_fields(&mut reader)?;
    Ok(Pmf1 {
        plugin_id,
        component,
        wit,
        schemas,
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

/// Phase 2: the PMF1-derived member list equals the non-`pmf1` members.
fn check_closure(
    artifacts: &[Artifact],
    members: &[BundleMemberV1],
) -> Result<(), PluginManifestErrorV1> {
    // ADR-102 layer order: role rank, then digest order for repeated roles.
    let mut expected = artifacts.to_vec();
    expected.sort_by_key(|artifact| (artifact.role.rank, artifact.sha256));
    let members = members.get(1..).unwrap_or_default();
    let shorter = expected.len().min(members.len());
    let index = expected
        .iter()
        .zip(members)
        .position(|(artifact, member)| !artifact.matches(member))
        .unwrap_or(shorter);
    if index == expected.len() && index == members.len() {
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

/// Phase 3: every inner BLAKE3 digest, in PMF1 field and position order.
fn check_inner_digests(
    artifacts: &[Artifact],
    bundle: &VerifiedReleaseBundleV1,
) -> Result<(), PluginManifestErrorV1> {
    for artifact in artifacts {
        let bytes = blob_bytes(bundle, &artifact.oci_digest());
        if role_digest(artifact.role.domain, bytes) != artifact.blake3 {
            return Err(PluginManifestErrorV1::ArtifactDigestMismatch {
                ordinal: artifact.ordinal,
            });
        }
    }
    Ok(())
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
