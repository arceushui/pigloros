//! ADR-061 revision 3 PMF1 V1 projection tests at the public seams.
//!
//! Every PMF1 here is encoded with `ciborium` and digested by this file's own
//! BLAKE3 and SHA-256 helpers, then published in an OCI release closure that
//! `pos_plugin_release::verify_oci_closure_v1` verifies. The only route to a
//! `ValidatedPluginManifestProjectionV1` is `from_verified_bundle`. The
//! independently generated golden closure is exercised by
//! `plugin_release_query_public.rs` and, with its Ed25519 signature, by the
//! encoder and signature-verification tests at the end of this file. Those
//! compare the encoder with the independent `Release` builder and the Python
//! generator, never with itself.

use std::collections::BTreeMap;

use pos_core::OwnerIdV1;
use pos_crypto::plugin_execution::{
    is_valid_id_v1, DeterministicBudgetV1, PluginAbiRequirementV1, PluginCapabilityDescriptorV1,
    PluginExecutionProjectionV1, WASM_PAGE_BYTES_V1,
};
use pos_crypto::plugin_manifest::{
    component_digest_v1, decode_plugin_release_signature_claim_v1,
    verify_plugin_release_signature_v1, PluginArtifactInputV1, PluginDependencyInputV1,
    PluginManifestErrorV1, PluginReleaseDraftV1, PluginReleaseSignatureErrorV1,
    PluginSchemaInputV1, VerifiedPluginReleaseSignatureV1,
};
use pos_crypto::plugin_trust::{
    verify_plugin_trust_v1, PluginTrustErrorV1, ResolvedPluginTrustAuthorizationV1,
    TrustedPluginRootAnchorV1, ValidatedPluginManifestProjectionV1, VerifiedPluginTrustEvidenceV1,
};
use pos_plugin_release::{
    verify_oci_closure_v1, BundleAddressV1, ReleaseSourceErrorV1, VerifiedReleaseBundleV1,
};
use sha2::{Digest as _, Sha256};

include!("support/plugin_trust_records.rs");
include!("support/pmf1_golden_vectors.rs");
include!("support/pmf1_signed_release_vectors.rs");

type BoxResult<T> = Result<T, Box<dyn std::error::Error>>;
type Projection = Result<ValidatedPluginManifestProjectionV1, PluginManifestErrorV1>;
type Execution = Result<PluginExecutionProjectionV1, PluginManifestErrorV1>;
type Bundle = Result<VerifiedReleaseBundleV1, ReleaseSourceErrorV1>;

const WORLD: &str = "pigloros:plugin/community-plugin@0.1.0";
const PMF1_MEDIA_TYPE: &str = "application/vnd.pigloros.plugin.manifest.v1+cbor";
const EMPTY_CONFIG_DIGEST: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
const MANIFEST_DOMAIN: &[u8] = b"PiglorOS.Plugin.Manifest.v1\0";
const RELEASE_DOMAIN: &[u8] = b"PiglorOS.Plugin.Release.v1\0";
const DEPENDENCY_RELEASE: [u8; 32] = [0x42; 32];
const COMPONENT_BYTES: &[u8] = b"\0asm component";
const WIT_BYTES: &[u8] = b"wit archive";
const EVENT_SCHEMA: &[u8] = br#"{"$id":"event"}"#;
const STATE_SCHEMA: &[u8] = br#"{"$id":"state"}"#;
const CONFIGURATION_SCHEMA: &[u8] = br#"{"$id":"configuration"}"#;
const PROVENANCE_BYTES: &[u8] = b"in-toto provenance";
const SBOM_BYTES: &[u8] = b"spdx sbom";
const LICENCE_BYTES: &[u8] = b"licence text";
/// Budget members with one-, two-, four-, and eight-byte CBOR heads.
const DEFAULT_BUDGET: [u64; 8] = [65_536, 1 << 40, 256, 24, 4_096, 4_096, 24, 256];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Role {
    Component,
    Wit,
    Schema,
    Provenance,
    Sbom,
    Licence,
    MigrationFixture,
}

impl Role {
    const fn media_type(self) -> &'static str {
        match self {
            Self::Component => "application/vnd.pigloros.plugin.component.v1+wasm",
            Self::Wit => "application/vnd.pigloros.plugin.wit.v1+tar",
            Self::Schema => "application/vnd.pigloros.plugin.schema.v1+json",
            Self::Provenance => "application/vnd.in-toto+json",
            Self::Sbom => "application/spdx+json",
            Self::Licence => "text/plain; charset=utf-8",
            Self::MigrationFixture => "application/vnd.pigloros.plugin.migration-fixture.v1+cbor",
        }
    }

    const fn domain(self) -> &'static [u8] {
        match self {
            Self::Component => b"PiglorOS.Plugin.Component.v1\0",
            Self::Wit => b"PiglorOS.Plugin.WITArchive.v1\0",
            Self::Schema => b"PiglorOS.Plugin.Schema.v1\0",
            Self::Provenance => b"PiglorOS.Plugin.Provenance.v1\0",
            Self::Sbom => b"PiglorOS.Plugin.SBOM.v1\0",
            Self::Licence => b"PiglorOS.Plugin.Licence.v1\0",
            Self::MigrationFixture => b"PiglorOS.Plugin.MigrationFixture.v1\0",
        }
    }

    fn annotation(self, digest: &str) -> String {
        let suffix = &digest["sha256:".len()..];
        match self {
            Self::Component => "component".to_owned(),
            Self::Wit => "wit".to_owned(),
            Self::Schema => format!("schema/{suffix}"),
            Self::Provenance => "provenance".to_owned(),
            Self::Sbom => "sbom".to_owned(),
            Self::Licence => format!("licence/{suffix}"),
            Self::MigrationFixture => format!("migration-fixture/{suffix}"),
        }
    }
}

/// One non-`pmf1` OCI layer.
#[derive(Clone)]
struct Member {
    role: Role,
    bytes: Vec<u8>,
}

impl Member {
    fn new(role: Role, bytes: &[u8]) -> Self {
        Self {
            role,
            bytes: bytes.to_vec(),
        }
    }
}

/// A PMF1 as 28 separately encoded fields plus its closure members.
#[derive(Clone)]
struct Release {
    fields: Vec<Vec<u8>>,
    members: Vec<Member>,
}

impl Release {
    /// A complete valid release: `plugin-a` by `publisher`, epoch 1, valid
    /// for UTC seconds 40..60.
    fn new() -> BoxResult<Self> {
        let fields = default_fields()
            .iter()
            .map(encode)
            .collect::<BoxResult<Vec<_>>>()?;
        let members = [
            (Role::Component, COMPONENT_BYTES),
            (Role::Wit, WIT_BYTES),
            (Role::Schema, EVENT_SCHEMA),
            (Role::Schema, STATE_SCHEMA),
            (Role::Provenance, PROVENANCE_BYTES),
            (Role::Sbom, SBOM_BYTES),
            (Role::Licence, LICENCE_BYTES),
        ];
        let mut release = Self {
            fields,
            members: members
                .into_iter()
                .map(|(role, blob)| Member::new(role, blob))
                .collect(),
        };
        release.seal()?;
        Ok(release)
    }

    /// A default release with one field replaced and not resealed.
    fn with(ordinal: usize, value: &Value) -> BoxResult<Self> {
        let mut release = Self::new()?;
        release.fields[ordinal] = encode(value)?;
        Ok(release)
    }

    /// A default release with one field replaced by raw bytes.
    fn with_raw(ordinal: usize, raw: &[u8]) -> BoxResult<Self> {
        let mut release = Self::new()?;
        raw.clone_into(&mut release.fields[ordinal]);
        Ok(release)
    }

    /// A default release with one field replaced, then resealed.
    fn sealed_with(ordinal: usize, value: &Value) -> BoxResult<Self> {
        let mut release = Self::with(ordinal, value)?;
        release.seal()?;
        Ok(release)
    }

    /// Recompute fields 25 and 27 from fields 0-24, 9, and 10.
    fn seal(&mut self) -> TestResult {
        let mut unsigned = vec![0x98, 0x19];
        unsigned.extend(self.fields[..25].concat());
        let manifest = domain_digest(MANIFEST_DOMAIN, &unsigned);
        let mut hasher = blake3::Hasher::new();
        hasher.update(RELEASE_DOMAIN);
        hasher.update(&manifest);
        hasher.update(&descriptor_blake3(&self.fields[9])?);
        hasher.update(&descriptor_blake3(&self.fields[10])?);
        self.fields[25] = encode(&bytes(manifest))?;
        self.fields[27] = encode(&bytes(*hasher.finalize().as_bytes()))?;
        Ok(())
    }

    fn pmf1(&self) -> Vec<u8> {
        let mut pmf1 = vec![0x98, 0x1c];
        pmf1.extend(self.fields.concat());
        pmf1
    }

    fn project(&self) -> BoxResult<Projection> {
        project_bytes(self.pmf1(), &self.members)
    }

    fn execution(&self) -> BoxResult<Execution> {
        let bundle = closure(self.pmf1(), &self.members)??;
        Ok(PluginExecutionProjectionV1::from_verified_bundle(&bundle))
    }

    fn release_digest(&self) -> BoxResult<[u8; 32]> {
        let value: Value = ciborium::from_reader(self.fields[27].as_slice())?;
        let digest = value.as_bytes().ok_or("field 27 is not a byte string")?;
        Ok(digest.as_slice().try_into()?)
    }
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn signed(value: i64) -> Value {
    Value::Integer(value.into())
}

const fn list(items: Vec<Value>) -> Value {
    Value::Array(items)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut digest = [0; 32];
    digest.copy_from_slice(&Sha256::digest(bytes));
    digest
}

fn oci_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut digest = String::from("sha256:");
    for byte in sha256(bytes) {
        digest.push(char::from(HEX[usize::from(byte >> 4)]));
        digest.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    digest
}

/// `BLAKE3(domain || u64be(len) || bytes)`.
fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn descriptor_blake3(field: &[u8]) -> BoxResult<[u8; 32]> {
    let value: Value = ciborium::from_reader(field)?;
    let digest = value
        .as_array()
        .and_then(|members| members.get(2))
        .and_then(Value::as_bytes)
        .ok_or("not an artifact descriptor")?;
    Ok(digest.as_slice().try_into()?)
}

/// `[media_type, byte_length, blake3_digest32, sha256_32]` for `bytes`.
fn descriptor(role: Role, bytes: &[u8]) -> Value {
    artifact(
        role.media_type(),
        unsigned(bytes.len() as u64),
        domain_digest(role.domain(), bytes),
        sha256(bytes),
    )
}

fn artifact(media_type: &str, byte_length: Value, blake3: [u8; 32], sha256: [u8; 32]) -> Value {
    list(vec![
        text(media_type),
        byte_length,
        bytes(blake3),
        bytes(sha256),
    ])
}

fn schema(id: u64, document: &[u8]) -> Value {
    list(vec![
        unsigned(id),
        unsigned(1),
        descriptor(Role::Schema, document),
        unsigned(65_536),
    ])
}

fn capability(id: &str, operation: &str) -> Value {
    list(vec![
        text(id),
        text(operation),
        text("state/*"),
        text("Read Plugin state"),
        text("plugin"),
        Value::Bool(true),
        unsigned(10),
        unsigned(1_024),
        unsigned(2_048),
    ])
}

fn budget(members: [u64; 8]) -> Value {
    list(members.into_iter().map(unsigned).collect())
}

fn dependency(id: &str, release: [u8; 32]) -> Value {
    list(vec![
        text(id),
        bytes(release),
        text(WORLD),
        unsigned(0),
        unsigned(0),
        unsigned(0),
        list(vec![text("clock")]),
        list(Vec::new()),
        unsigned(0),
    ])
}

fn signature(epoch: u64) -> Value {
    list(vec![
        unsigned(1),
        unsigned(3),
        unsigned(epoch),
        Value::Bytes(vec![0x5a; 64]),
    ])
}

fn default_fields() -> Vec<Value> {
    vec![
        text("PMF1"),
        unsigned(1),
        text("plugin-a"),
        text("1.0.0"),
        text(WORLD),
        unsigned(0),
        unsigned(0),
        unsigned(1),
        list(vec![text("clock")]),
        descriptor(Role::Component, COMPONENT_BYTES),
        descriptor(Role::Wit, WIT_BYTES),
        list(vec![schema(1, EVENT_SCHEMA)]),
        schema(2, STATE_SCHEMA),
        Value::Null,
        list(vec![capability("kv", "read")]),
        budget(DEFAULT_BUDGET),
        list(Vec::new()),
        list(vec![dependency("dep", DEPENDENCY_RELEASE)]),
        descriptor(Role::Provenance, PROVENANCE_BYTES),
        descriptor(Role::Sbom, SBOM_BYTES),
        list(vec![descriptor(Role::Licence, LICENCE_BYTES)]),
        text("publisher"),
        signed(40),
        signed(60),
        Value::Null,
        bytes([0; 32]),
        signature(1),
        bytes([0; 32]),
    ]
}

/// Publish `pmf1` and `members` in ADR-102 layer order and verify the closure.
fn closure(pmf1: Vec<u8>, members: &[Member]) -> BoxResult<Bundle> {
    let mut ordered = members
        .iter()
        .enumerate()
        .map(|(index, member)| (member.role, oci_digest(&member.bytes), index))
        .collect::<Vec<_>>();
    ordered.sort();
    let pmf1_digest = oci_digest(&pmf1);
    let mut layers = vec![layer("pmf1", PMF1_MEDIA_TYPE, &pmf1_digest, pmf1.len())];
    let mut blobs = BTreeMap::from([(EMPTY_CONFIG_DIGEST.to_owned(), b"{}".to_vec())]);
    blobs.insert(pmf1_digest, pmf1);
    for (role, oci, index) in ordered {
        let blob = members[index].bytes.clone();
        let annotation = role.annotation(&oci);
        layers.push(layer(&annotation, role.media_type(), &oci, blob.len()));
        blobs.insert(oci, blob);
    }
    let manifest = serde_json::to_vec(&serde_json::json!({
        "artifactType": "application/vnd.pigloros.plugin.release.v1",
        "config": {
            "digest": EMPTY_CONFIG_DIGEST,
            "mediaType": "application/vnd.oci.empty.v1+json",
            "size": 2,
        },
        "layers": layers,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "schemaVersion": 2,
    }))?;
    let address = BundleAddressV1::new(oci_digest(&manifest), u64::try_from(manifest.len())?)?;
    Ok(verify_oci_closure_v1(address, manifest, blobs))
}

fn layer(member: &str, media_type: &str, digest: &str, size: usize) -> serde_json::Value {
    serde_json::json!({
        "annotations": {"org.pigloros.plugin.member": member},
        "digest": digest,
        "mediaType": media_type,
        "size": size,
    })
}

fn project_bytes(pmf1: Vec<u8>, members: &[Member]) -> BoxResult<Projection> {
    let bundle = closure(pmf1, members)??;
    let projection = ValidatedPluginManifestProjectionV1::from_verified_bundle(&bundle);
    Ok(projection)
}

/// The index into the PMF1-derived member list of one member.
fn closure_index(members: &[Member], role: Role, document: &[u8]) -> BoxResult<usize> {
    let mut ordered = members
        .iter()
        .map(|member| (member.role, sha256(&member.bytes)))
        .collect::<Vec<_>>();
    ordered.sort_unstable();
    Ok(ordered
        .iter()
        .position(|entry| *entry == (role, sha256(document)))
        .ok_or("member is not in the closure")?)
}

const fn encoding(ordinal: u8) -> PluginManifestErrorV1 {
    PluginManifestErrorV1::InvalidEncoding { ordinal }
}

const fn bound(ordinal: u8) -> PluginManifestErrorV1 {
    PluginManifestErrorV1::BoundsExceeded { ordinal }
}

const fn invalid(ordinal: u8) -> PluginManifestErrorV1 {
    PluginManifestErrorV1::InvalidField { ordinal }
}

const fn mismatch(index: usize) -> PluginManifestErrorV1 {
    PluginManifestErrorV1::ClosureMismatch { index }
}

fn expect(release: &Release, error: PluginManifestErrorV1) -> TestResult {
    assert_eq!(release.project()?, Err(error));
    Ok(())
}

fn accepted(release: &Release) -> TestResult {
    let projection = release.project()?;
    assert!(projection.is_ok(), "{projection:?}");
    Ok(())
}

/// `count` distinct sorted ID-grammar texts of `width` bytes.
fn ids(count: usize, width: usize) -> Vec<Value> {
    (0..count)
        .map(|index| text(&format!("{index:0width$}")))
        .collect()
}

/// Evidence over `root()` (`plugin-a` granted to `publisher`, epoch 1) and
/// one PRV1 whose entries take effect at Tick 5, evaluated at UTC 50.
fn evidence(
    keys: Vec<Value>,
    artifacts: Vec<Value>,
    tick: u64,
) -> BoxResult<VerifiedPluginTrustEvidenceV1> {
    let ptr1 = root(1, None)?;
    let anchor = TrustedPluginRootAnchorV1::new("scope", digest(&ptr1))?;
    let prv1 = signed_record(
        revocation_fields(digest(&ptr1), 1, None, 5, keys, artifacts),
        REVOCATION_SIGNATURE_DOMAIN,
        &signer(),
    )?;
    verify_plugin_trust_v1(&anchor, &[&ptr1], &[&prv1], 50, tick).map_err(Into::into)
}

fn revoked_artifact(id: [u8; 32]) -> Value {
    list(vec![bytes(id), unsigned(5), unsigned(1), Value::Null])
}

fn authorize(
    evidence: &VerifiedPluginTrustEvidenceV1,
    release: &Release,
) -> BoxResult<Result<[u8; 32], PluginTrustErrorV1>> {
    Ok(evidence
        .authorize_release(&release.project()??)
        .map(|fact| fact.resolved_public_key()))
}

/// Project raw PMF1 bytes published with the default closure members.
fn project_raw(pmf1: Vec<u8>) -> BoxResult<Projection> {
    project_bytes(pmf1, &Release::new()?.members)
}

const DENIED: Result<[u8; 32], PluginTrustErrorV1> = Err(PluginTrustErrorV1::ArtifactRevoked);

#[test]
fn complete_release_resolves_exactly_one_publisher_key() -> TestResult {
    let release = Release::new()?;
    let projection = release.project()??;
    let fact = evidence(Vec::new(), Vec::new(), 4)?.authorize_release(&projection)?;
    assert_eq!(fact.resolved_public_key(), publisher_public());
    assert_eq!(fact.pmf1_digest(), digest(&release.pmf1()));
    assert_eq!(fact.evaluation_coordinates(), (50, 4));
    Ok(())
}

#[test]
fn every_descriptor_and_dependency_digest_is_revocable() -> TestResult {
    let mut release = Release::sealed_with(13, &schema(3, CONFIGURATION_SCHEMA))?;
    let configuration = Member::new(Role::Schema, CONFIGURATION_SCHEMA);
    release.members.push(configuration);
    let mut revocable = vec![release.release_digest()?, DEPENDENCY_RELEASE];
    for member in &release.members {
        revocable.push(sha256(&member.bytes));
        revocable.push(domain_digest(member.role.domain(), &member.bytes));
    }
    let clean = evidence(Vec::new(), Vec::new(), 5)?;
    assert_eq!(authorize(&clean, &release)?, Ok(publisher_public()));
    for revoked in revocable {
        let denied = evidence(Vec::new(), vec![revoked_artifact(revoked)], 5)?;
        assert_eq!(authorize(&denied, &release)?, DENIED);
        let not_yet = evidence(Vec::new(), vec![revoked_artifact(revoked)], 4)?;
        assert_eq!(authorize(&not_yet, &release)?, Ok(publisher_public()));
    }
    Ok(())
}

#[test]
fn authorization_accessors_carry_field_24_and_exact_plugin_id_from_real_pmf1() -> TestResult {
    let evidence = evidence(Vec::new(), Vec::new(), 4)?;
    let absent = Release::new()?;
    let fact = evidence.authorize_release(&absent.project()??)?;
    assert_eq!(fact.plugin_id(), "plugin-a");
    assert_eq!(fact.release_digest(), absent.release_digest()?);
    assert_eq!(fact.previous_release_digest(), None);
    assert!(!fact.descriptor_digests().is_empty());
    assert!(fact
        .descriptor_digests()
        .windows(2)
        .all(|pair| pair[0] < pair[1]));
    assert!(!fact.descriptor_digests().contains(&fact.release_digest()));
    let present = Release::sealed_with(24, &bytes([0x24; 32]))?;
    let linked = evidence.authorize_release(&present.project()??)?;
    assert_eq!(linked.previous_release_digest(), Some([0x24; 32]));
    assert_eq!(linked.release_digest(), present.release_digest()?);
    assert_ne!(linked.release_digest(), fact.release_digest());
    assert!(!linked.descriptor_digests().contains(&[0x24; 32]));
    Ok(())
}

#[test]
fn previous_manifest_framing_and_signature_digests_are_not_descriptors() -> TestResult {
    let release = Release::sealed_with(24, &bytes([0x24; 32]))?;
    let pmf1 = release.pmf1();
    let field_25: [u8; 32] = release.fields[25]
        .get(2..)
        .ok_or("short field 25")?
        .try_into()?;
    for excluded in [[0x24; 32], field_25, sha256(&pmf1), digest(&pmf1)] {
        let evidence = evidence(Vec::new(), vec![revoked_artifact(excluded)], 5)?;
        assert_eq!(authorize(&evidence, &release)?, Ok(publisher_public()));
    }
    Ok(())
}

#[test]
fn golden_trust_records_authorize_then_revoke_the_epoch_nine_key() -> TestResult {
    let mut release = Release::with(2, &text("alpha/plugin"))?;
    release.fields[22] = encode(&signed(-1))?;
    release.fields[23] = encode(&signed(1))?;
    release.fields[26] = encode(&signature(9))?;
    release.seal()?;
    let ptr1 = hex_bytes(PTR1_HEX)?;
    let prv1 = hex_bytes(PRV1_HEX)?;
    let anchor = TrustedPluginRootAnchorV1::new("trust.example", digest(&ptr1))?;
    let before = verify_plugin_trust_v1(&anchor, &[&ptr1], &[&prv1], 0, 9)?;
    let fact = before.authorize_release(&release.project()??)?;
    assert_eq!(fact.terminal_root(), (42, digest(&ptr1)));
    let after = verify_plugin_trust_v1(&anchor, &[&ptr1], &[&prv1], 0, 10)?;
    let revoked = Err(PluginTrustErrorV1::PublisherKeyRevoked);
    assert_eq!(authorize(&after, &release)?, revoked);
    Ok(())
}

#[test]
fn wrong_plugin_id_owner_epoch_or_grant_fails_closed() -> TestResult {
    let evidence = evidence(Vec::new(), Vec::new(), 4)?;
    let ungranted = Err(PluginTrustErrorV1::PluginIdNotGranted);
    let unknown = Err(PluginTrustErrorV1::UnknownPublisherKey);
    let cases = [
        (2, text("plugin-b"), ungranted),
        (21, text("other"), unknown),
        (26, signature(2), unknown),
    ];
    for (ordinal, value, error) in cases {
        let release = Release::sealed_with(ordinal, &value)?;
        assert_eq!(authorize(&evidence, &release)?, error);
    }
    let other_public = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    let publishers = vec![
        publisher_entry("other", 1, other_public),
        publisher_entry("publisher", 1, publisher_public()),
    ];
    let fields = root_fields(1, None, publishers, vec![grant("plugin-a", "other")]);
    let ptr1 = signed_record(fields, ROOT_SIGNATURE_DOMAIN, &signer())?;
    let anchor = TrustedPluginRootAnchorV1::new("scope", digest(&ptr1))?;
    let prv1 = revocation(digest(&ptr1), 1, None)?;
    let other_grant = verify_plugin_trust_v1(&anchor, &[&ptr1], &[&prv1], 50, 4)?;
    assert_eq!(authorize(&other_grant, &Release::new()?)?, ungranted);
    let other_owner = Release::sealed_with(21, &text("other"))?;
    assert_eq!(authorize(&other_grant, &other_owner)?, Ok(other_public));
    Ok(())
}

#[test]
fn manifest_interval_is_half_open_at_the_evidence_second() -> TestResult {
    let evidence = evidence(Vec::new(), Vec::new(), 4)?;
    let expired = Err(PluginTrustErrorV1::ManifestExpired);
    let authorized = Ok(publisher_public());
    let cases = [
        (51, 60, expired),
        (40, 50, expired),
        (50, 51, authorized),
        (-31_622_349, 51, authorized),
    ];
    for (not_before, not_after, expected) in cases {
        let mut release = Release::with(22, &signed(not_before))?;
        release.fields[23] = encode(&signed(not_after))?;
        release.seal()?;
        assert_eq!(authorize(&evidence, &release)?, expected);
    }
    Ok(())
}

/// A PRV1 revocation of the default publisher key, effective at Tick 5.
fn key() -> Vec<Value> {
    vec![list(vec![
        text("publisher"),
        unsigned(3),
        unsigned(1),
        bytes(publisher_public()),
        unsigned(5),
        unsigned(1),
        Value::Null,
    ])]
}

#[test]
fn publisher_key_revocation_denies_a_real_projection() -> TestResult {
    let release = Release::new()?;
    let before = evidence(key(), Vec::new(), 4)?;
    assert_eq!(authorize(&before, &release)?, Ok(publisher_public()));
    let after = evidence(key(), Vec::new(), 5)?;
    let revoked = Err(PluginTrustErrorV1::PublisherKeyRevoked);
    assert_eq!(authorize(&after, &release)?, revoked);
    Ok(())
}

#[test]
fn incomplete_trust_history_yields_no_evidence_to_authorize() -> TestResult {
    let genesis = root(1, None)?;
    let next = root(2, Some(digest(&genesis)))?;
    let anchor = TrustedPluginRootAnchorV1::new("scope", digest(&genesis))?;
    let terminal = revocation(digest(&next), 1, None)?;
    let suffix_only = verify_plugin_trust_v1(&anchor, &[&next], &[&terminal], 50, 4);
    assert_eq!(suffix_only.err(), Some(PluginTrustErrorV1::AnchorMismatch));
    let no_revocations = verify_plugin_trust_v1(&anchor, &[&genesis, &next], &[], 50, 4);
    let discontinuity = Some(PluginTrustErrorV1::ChainDiscontinuity);
    assert_eq!(no_revocations.err(), discontinuity);
    let roots = [genesis.as_slice(), next.as_slice()];
    let complete = verify_plugin_trust_v1(&anchor, &roots, &[&terminal], 50, 4)?;
    let release = Release::new()?;
    assert_eq!(authorize(&complete, &release)?, Ok(publisher_public()));
    Ok(())
}

#[test]
fn full_terminal_revocation_capacity_denies_a_real_projection() -> TestResult {
    let artifacts = (0..4096_u32)
        .map(|index| {
            let mut revoked = [0; 32];
            revoked[..4].copy_from_slice(&index.to_be_bytes());
            revoked_artifact(revoked)
        })
        .collect::<Vec<_>>();
    let full = evidence(Vec::new(), artifacts, 4)?;
    let exhausted = Err(PluginTrustErrorV1::RevocationCapacityExhausted);
    assert_eq!(authorize(&full, &Release::new()?)?, exhausted);
    Ok(())
}

#[test]
fn re_signing_with_a_later_epoch_keeps_the_release_digest() -> TestResult {
    let original = Release::new()?;
    let mut resigned = original.clone();
    resigned.fields[26] = encode(&signature(2))?;
    assert_eq!(resigned.release_digest()?, original.release_digest()?);
    let publishers = vec![publisher_entry("publisher", 2, publisher_public())];
    let fields = root_fields(1, None, publishers, vec![grant("plugin-a", "publisher")]);
    let ptr1 = signed_record(fields, ROOT_SIGNATURE_DOMAIN, &signer())?;
    let anchor = TrustedPluginRootAnchorV1::new("scope", digest(&ptr1))?;
    let artifacts = vec![revoked_artifact(original.release_digest()?)];
    let fields = revocation_fields(digest(&ptr1), 1, None, 5, Vec::new(), artifacts);
    let prv1 = signed_record(fields, REVOCATION_SIGNATURE_DOMAIN, &signer())?;
    let before = verify_plugin_trust_v1(&anchor, &[&ptr1], &[&prv1], 50, 4)?;
    let fact = before.authorize_release(&resigned.project()??)?;
    assert_eq!(fact.pmf1_digest(), digest(&resigned.pmf1()));
    assert_ne!(fact.pmf1_digest(), digest(&original.pmf1()));
    let after = verify_plugin_trust_v1(&anchor, &[&ptr1], &[&prv1], 50, 5)?;
    assert_eq!(authorize(&after, &resigned)?, DENIED);
    Ok(())
}

#[test]
fn malformed_or_unavailable_source_yields_no_projection() -> TestResult {
    let release = Release::new()?;
    let pmf1 = release.pmf1();
    let mut duplicate = release.members.clone();
    duplicate.push(Member::new(Role::Licence, &pmf1));
    let duplicated = closure(pmf1, &duplicate)?.err();
    assert_eq!(duplicated, Some(ReleaseSourceErrorV1::DuplicateMember));
    let mut missing = release.members;
    missing.retain(|member| member.role != Role::Sbom);
    let incomplete = closure(release.fields.concat(), &missing)?.err();
    assert_eq!(incomplete, Some(ReleaseSourceErrorV1::InvalidDescriptor));
    Ok(())
}

#[test]
fn document_size_and_outer_framing_fail_at_ordinal_28() -> TestResult {
    let pmf1 = Release::new()?.pmf1();
    let mut at_limit = pmf1.clone();
    at_limit.resize(1_048_576, 0);
    assert_eq!(project_raw(at_limit)?, Err(encoding(28)));
    let mut above_limit = pmf1.clone();
    above_limit.resize(1_048_577, 0);
    assert_eq!(project_raw(above_limit)?, Err(bound(28)));
    let framings: [&[u8]; 8] = [
        &[0x98],
        &[0x99, 0x00, 0x1c],
        &[0x9f, 0x64, b'P', b'M', b'F', b'1', 0x01, 0xff],
        &[0xa2, 0x64, b'P', b'M', b'F', b'1', 0x01],
        &[0x64, b'P', b'M', b'F', b'1'],
        &[0x80],
        &[0x81, 0x64, b'P', b'M', b'F', b'1'],
        &[0x82, 0x64, b'P', b'M', b'F', b'1', 0x01],
    ];
    for framing in framings {
        let projection = project_raw(framing.to_vec())?;
        assert_eq!(projection, Err(encoding(28)), "{framing:02x?}");
    }
    let mut trailing = pmf1;
    trailing.push(0xf6);
    assert_eq!(project_raw(trailing)?, Err(encoding(28)));
    Ok(())
}

#[test]
fn an_unsupported_version_stops_before_the_outer_count() -> TestResult {
    let unsupported = Err(PluginManifestErrorV1::UnsupportedVersion);
    let short = vec![0x82, 0x64, b'P', b'M', b'F', b'1', 0x02];
    assert_eq!(project_raw(short)?, unsupported);
    for version in [0, 2, u64::MAX] {
        let projection = Release::with(1, &unsigned(version))?.project()?;
        assert_eq!(projection, unsupported);
    }
    expect(&Release::with(1, &signed(-1))?, encoding(1))?;
    for count in [0x1b, 0x1d] {
        let mut pmf1 = Release::new()?.pmf1();
        pmf1[1] = count;
        assert_eq!(project_raw(pmf1)?, Err(encoding(28)));
    }
    Ok(())
}

#[test]
fn exact_value_fields_reject_any_other_text_as_invalid_fields() -> TestResult {
    let long = "x".repeat(4_096);
    for wrong in ["PMF2", "PMF", "PMF1 ", long.as_str()] {
        expect(&Release::with(0, &text(wrong))?, invalid(0))?;
    }
    let world = "pigloros:plugin/community-plugin@0.1.1";
    for wrong in [world, "", long.as_str()] {
        expect(&Release::with(4, &text(wrong))?, invalid(4))?;
    }
    let magic_bytes = Value::Bytes(b"PMF1".to_vec());
    expect(&Release::with(0, &magic_bytes)?, encoding(0))?;
    let truncated = vec![0x98, 0x1c, 0x64, b'P', b'M'];
    assert_eq!(project_raw(truncated)?, Err(encoding(0)));
    let not_utf8 = [0x64, b'P', b'M', b'F', 0xff];
    expect(&Release::with_raw(0, &not_utf8)?, invalid(0))?;
    let mut world_not_utf8 = vec![0x78, 0x26];
    world_not_utf8.extend_from_slice(&WORLD.as_bytes()[..37]);
    world_not_utf8.push(0xff);
    expect(&Release::with_raw(4, &world_not_utf8)?, invalid(4))?;
    expect(&Release::with(5, &unsigned(1))?, invalid(5))?;
    Ok(())
}

#[test]
fn every_field_rejects_malformed_cbor_at_its_ordinal() -> TestResult {
    let malformed: [&[u8]; 9] = [
        &[0xa0],
        &[0xc0, 0x00],
        &[0xf9, 0x00, 0x00],
        &[0xfa, 0x00, 0x00, 0x00, 0x00],
        &[0xf7],
        &[0xf8, 0x20],
        &[0x9f, 0xff],
        &[0x7f, 0xff],
        &[0x18, 0x01],
    ];
    for ordinal in 0..28_u8 {
        for item in malformed {
            let projection = Release::with_raw(usize::from(ordinal), item)?.project()?;
            assert_eq!(projection, Err(encoding(ordinal)), "{item:02x?}");
        }
    }
    Ok(())
}

#[test]
fn non_shortest_heads_fail_and_shortest_minimums_pass() -> TestResult {
    let non_shortest: [&[u8]; 5] = [
        &[0x18, 0x17],
        &[0x19, 0x00, 0xff],
        &[0x1a, 0x00, 0x00, 0xff, 0xff],
        &[0x1b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff],
        &[0x1c],
    ];
    for head in non_shortest {
        let mut epoch = vec![0x84, 0x01, 0x03];
        epoch.extend_from_slice(head);
        expect(&Release::with_raw(26, &epoch)?, encoding(26))?;
        let mut memory = vec![0x88];
        memory.extend_from_slice(head);
        expect(&Release::with_raw(15, &memory)?, encoding(15))?;
    }
    for epoch in [24, 0x100, 0x1_0000, 0x1_0000_0000, u64::MAX] {
        accepted(&Release::sealed_with(26, &signature(epoch))?)?;
    }
    Ok(())
}

#[test]
fn a_truncated_document_fails_at_the_first_missing_field() -> TestResult {
    let release = Release::new()?;
    for ordinal in 0..28_u8 {
        let mut pmf1 = vec![0x98, 0x1c];
        pmf1.extend(release.fields[..usize::from(ordinal)].concat());
        assert_eq!(project_raw(pmf1)?, Err(encoding(ordinal)));
    }
    let pmf1 = release.pmf1();
    for end in 1..pmf1.len() {
        let prefix = pmf1.get(..end).ok_or("short PMF1")?.to_vec();
        assert!(project_raw(prefix)?.is_err());
    }
    Ok(())
}

#[test]
fn plugin_id_has_the_exact_id_grammar_and_bound() -> TestResult {
    let longest = "a".repeat(128);
    for valid in ["0", "a", "0a._/-z9", longest.as_str()] {
        accepted(&Release::sealed_with(2, &text(valid))?)?;
    }
    for wrong in ["", "-a", ".a", "_a", "/a", "A", "aB", "a b", "a+b", "é"] {
        expect(&Release::with(2, &text(wrong))?, invalid(2))?;
    }
    expect(&Release::with(2, &text(&"a".repeat(129)))?, bound(2))?;
    expect(&Release::with_raw(2, &[0x62, 0xff, 0xfe])?, encoding(2))?;
    Ok(())
}

#[test]
fn release_version_is_semver_without_build_metadata() -> TestResult {
    let longest = format!("1.0.0-{}", "a".repeat(58));
    let valid = [
        "0.0.0",
        "1.2.3",
        "10.20.30",
        "1.0.0-0",
        "1.0.0-rc.1",
        "1.0.0-x-y.0a.-",
        "1.0.0-alpha.beta.10",
        longest.as_str(),
    ];
    for version in valid {
        accepted(&Release::sealed_with(3, &text(version))?)?;
    }
    let wrong = [
        "",
        "1",
        "1.0",
        "1.0.0.0",
        "01.0.0",
        "1.00.0",
        "1.0.01",
        "1..0",
        "1.a.0",
        "v1.0.0",
        "1.0.0-",
        "1.0.0-a..b",
        "1.0.0-01",
        "1.0.0-x_y",
        "1.0.0+build",
        "1.0.0-a+b",
        "1.0.0-\u{e9}",
        " 1.0.0",
    ];
    for version in wrong {
        expect(&Release::with(3, &text(version))?, invalid(3))?;
    }
    let too_long = format!("{longest}a");
    expect(&Release::with(3, &text(&too_long))?, bound(3))?;
    Ok(())
}

#[test]
fn abi_fields_are_exact_and_minor_bounds_are_ordered() -> TestResult {
    for (minimum, maximum) in [(0, 0), (7, 7), (0, 65_535), (65_535, 65_535)] {
        let mut release = Release::with(6, &unsigned(minimum))?;
        release.fields[7] = encode(&unsigned(maximum))?;
        release.seal()?;
        accepted(&release)?;
    }
    expect(&Release::with(6, &unsigned(65_536))?, invalid(6))?;
    expect(&Release::with(7, &unsigned(65_536))?, invalid(7))?;
    let mut reversed = Release::with(6, &unsigned(2))?;
    reversed.fields[7] = encode(&unsigned(1))?;
    expect(&reversed, invalid(7))?;
    expect(&Release::with(6, &text("0"))?, encoding(6))?;
    Ok(())
}

#[test]
fn required_feature_ids_are_bounded_strictly_increasing_ids() -> TestResult {
    accepted(&Release::sealed_with(8, &list(Vec::new()))?)?;
    accepted(&Release::sealed_with(8, &list(ids(256, 3)))?)?;
    expect(&Release::with(8, &list(ids(257, 3)))?, bound(8))?;
    for wrong in [["b", "a"], ["a", "a"], ["a", "B"]] {
        let features = list(wrong.into_iter().map(text).collect());
        expect(&Release::with(8, &features)?, invalid(8))?;
    }
    let too_long = list(vec![text(&"a".repeat(129))]);
    expect(&Release::with(8, &too_long)?, bound(8))?;
    expect(&Release::with(8, &list(vec![unsigned(1)]))?, encoding(8))?;
    Ok(())
}

/// A descriptor of `role`'s media type with explicit size and digests.
fn fake(role: Role, byte_length: u64) -> Value {
    artifact(role.media_type(), unsigned(byte_length), [1; 32], [2; 32])
}

#[test]
fn artifact_descriptors_have_exact_shape_media_type_and_caps() -> TestResult {
    let cases = [
        (9, Role::Component, 33_554_432, 0),
        (10, Role::Wit, 4_194_304, 1),
        (18, Role::Provenance, 33_554_432, 4),
        (19, Role::Sbom, 33_554_432, 5),
    ];
    for (ordinal, role, cap, index) in cases {
        let field = usize::from(ordinal);
        let at_cap = fake(role, cap);
        expect(&Release::with(field, &at_cap)?, mismatch(index))?;
        let above_cap = fake(role, cap + 1);
        expect(&Release::with(field, &above_cap)?, bound(ordinal))?;
        expect(&Release::with(field, &fake(role, 0))?, invalid(ordinal))?;
        let licence_type = fake(Role::Licence, 1);
        expect(&Release::with(field, &licence_type)?, invalid(ordinal))?;
        let long_type = artifact(&"x".repeat(1_024), unsigned(1), [1; 32], [2; 32]);
        expect(&Release::with(field, &long_type)?, invalid(ordinal))?;
        let media_type = text(role.media_type());
        let shapes = [
            vec![media_type.clone(), unsigned(1), bytes([1; 32])],
            vec![
                media_type.clone(),
                unsigned(1),
                bytes([1; 32]),
                bytes([2; 32]),
                Value::Null,
            ],
            vec![
                media_type.clone(),
                unsigned(1),
                Value::Bytes(vec![1; 31]),
                bytes([2; 32]),
            ],
            vec![media_type, unsigned(1), bytes([1; 32]), text("sha256")],
        ];
        for shape in shapes {
            expect(&Release::with(field, &list(shape))?, encoding(ordinal))?;
        }
    }
    Ok(())
}

#[test]
fn a_component_at_the_32_mib_blob_cap_projects() -> TestResult {
    let component = vec![0x5a; 33_554_432];
    let mut release = Release::with(9, &descriptor(Role::Component, &component))?;
    release.members[0] = Member {
        role: Role::Component,
        bytes: component,
    };
    release.seal()?;
    accepted(&release)
}

/// A schema descriptor with explicit members around an artifact.
fn schema_with(id: u64, version: u64, artifact: Value, max_bytes: u64) -> Value {
    list(vec![
        unsigned(id),
        unsigned(version),
        artifact,
        unsigned(max_bytes),
    ])
}

#[test]
fn schema_descriptors_bound_ids_versions_artifacts_and_sizes() -> TestResult {
    let event = || descriptor(Role::Schema, EVENT_SCHEMA);
    let largest = 4_294_967_295;
    for valid in [
        schema_with(0, 1, event(), 1),
        schema_with(largest, largest, event(), 1_048_576),
    ] {
        accepted(&Release::sealed_with(11, &list(vec![valid]))?)?;
    }
    // The fabricated SHA-256 sorts before both real schema digests.
    let at_cap = schema_with(1, 1, fake(Role::Schema, 1_048_576), 1);
    expect(&Release::with(11, &list(vec![at_cap]))?, mismatch(2))?;
    let above_cap = schema_with(1, 1, fake(Role::Schema, 1_048_577), 1);
    expect(&Release::with(11, &list(vec![above_cap]))?, bound(11))?;
    let licence_type = descriptor(Role::Licence, EVENT_SCHEMA);
    let short = list(vec![unsigned(1), unsigned(1), event()]);
    for wrong in [
        schema_with(largest + 1, 1, event(), 1),
        schema_with(1, 0, event(), 1),
        schema_with(1, largest + 1, event(), 1),
        schema_with(1, 1, event(), 0),
        schema_with(1, 1, event(), 1_048_577),
        schema_with(1, 1, licence_type, 1),
    ] {
        expect(&Release::with(11, &list(vec![wrong]))?, invalid(11))?;
    }
    expect(&Release::with(11, &list(vec![short]))?, encoding(11))?;
    Ok(())
}

#[test]
fn event_schemas_are_bounded_and_strictly_increasing_by_id() -> TestResult {
    let many = (0..256)
        .map(|id| schema(id + 10, format!("{{\"$id\":{id}}}").as_bytes()))
        .collect::<Vec<_>>();
    let decoded = Release::with(11, &list(many.clone()))?.project()?;
    assert!(matches!(
        decoded,
        Err(PluginManifestErrorV1::ClosureMismatch { .. })
    ));
    let mut too_many = many;
    too_many.push(schema(300, EVENT_SCHEMA));
    expect(&Release::with(11, &list(too_many))?, bound(11))?;
    for [first, second] in [[5, 4], [5, 5]] {
        let events = vec![schema(first, EVENT_SCHEMA), schema(second, STATE_SCHEMA)];
        expect(&Release::with(11, &list(events))?, invalid(11))?;
    }
    let events = vec![schema(1, EVENT_SCHEMA), schema(7, CONFIGURATION_SCHEMA)];
    let mut ordered = Release::sealed_with(11, &list(events))?;
    let configuration = Member::new(Role::Schema, CONFIGURATION_SCHEMA);
    ordered.members.push(configuration);
    accepted(&ordered)?;
    expect(&Release::with(11, &schema(1, EVENT_SCHEMA))?, encoding(11))?;
    Ok(())
}

#[test]
fn state_and_configuration_schemas_have_exact_shapes() -> TestResult {
    expect(&Release::with(12, &Value::Null)?, encoding(12))?;
    let wrapped = list(vec![schema(2, STATE_SCHEMA)]);
    expect(&Release::with(12, &wrapped)?, encoding(12))?;
    let unversioned = schema_with(2, 0, descriptor(Role::Schema, STATE_SCHEMA), 1);
    expect(&Release::with(12, &unversioned)?, invalid(12))?;
    let mut configured = Release::sealed_with(13, &schema(3, CONFIGURATION_SCHEMA))?;
    let configuration = Member::new(Role::Schema, CONFIGURATION_SCHEMA);
    configured.members.push(configuration);
    accepted(&configured)?;
    let artifact = descriptor(Role::Schema, CONFIGURATION_SCHEMA);
    let unbounded = schema_with(3, 1, artifact, 0);
    expect(&Release::with(13, &unbounded)?, invalid(13))?;
    expect(&Release::with(13, &Value::Bool(false))?, encoding(13))?;
    expect(&Release::with(13, &list(Vec::new()))?, encoding(13))?;
    Ok(())
}

const CAPABILITY: [&str; 5] = ["kv", "read", "state/*", "purpose", "plugin"];

/// A capability descriptor with explicit members.
fn capability_with(texts: [&str; 5], required: Value, limits: [u64; 3]) -> Value {
    let mut members = texts.into_iter().map(text).collect::<Vec<_>>();
    members.push(required);
    members.extend(limits.into_iter().map(unsigned));
    list(members)
}

/// `CAPABILITY` with member `index` replaced by `value`.
fn capability_text(index: usize, value: &str) -> Value {
    let mut texts = CAPABILITY;
    texts[index] = value;
    capability_with(texts, Value::Bool(true), [0, 0, 0])
}

#[test]
fn capability_members_have_grammars_labels_booleans_and_limits() -> TestResult {
    let pattern = "p".repeat(512);
    let label = "l".repeat(128);
    let maxima = [1_000_000, 16_777_216, 16_777_216];
    let longest: [&str; 5] = ["k", "r", &pattern, &label, &label];
    let unicode = ["kv", "read", "\u{a0}", "\u{e9}t\u{e9}", "a b"];
    let valid = [
        capability_with(CAPABILITY, Value::Bool(false), maxima),
        capability_with(longest, Value::Bool(true), maxima),
        capability_with(unicode, Value::Bool(true), maxima),
    ];
    for capability in valid {
        accepted(&Release::sealed_with(14, &list(vec![capability]))?)?;
    }
    let long_pattern = "p".repeat(513);
    let long_label = "l".repeat(129);
    let long_id = "k".repeat(129);
    let too_long = [
        (0, &long_id),
        (2, &long_pattern),
        (3, &long_label),
        (4, &long_label),
    ];
    for (index, value) in too_long {
        let wrong = list(vec![capability_text(index, value)]);
        expect(&Release::with(14, &wrong)?, bound(14))?;
    }
    let invalid_texts = [
        (0, "Kv"),
        (1, "-read"),
        (2, ""),
        (3, ""),
        (4, ""),
        (2, "a\u{0}"),
        (3, "line\u{1f}"),
        (4, "\u{7f}"),
        (3, "next\u{85}line"),
        (2, "\u{9f}"),
    ];
    for (index, value) in invalid_texts {
        let wrong = list(vec![capability_text(index, value)]);
        expect(&Release::with(14, &wrong)?, invalid(14))?;
    }
    for limits in [[1_000_001, 0, 0], [0, 16_777_217, 0], [0, 0, 16_777_217]] {
        let wrong = capability_with(CAPABILITY, Value::Bool(true), limits);
        expect(&Release::with(14, &list(vec![wrong]))?, invalid(14))?;
    }
    for required in [unsigned(1), Value::Null, text("true")] {
        let wrong = capability_with(CAPABILITY, required, [0, 0, 0]);
        expect(&Release::with(14, &list(vec![wrong]))?, encoding(14))?;
    }
    let mut eight = capability_text(0, "kv");
    if let Value::Array(members) = &mut eight {
        members.truncate(8);
    }
    expect(&Release::with(14, &list(vec![eight]))?, encoding(14))?;
    Ok(())
}

#[test]
fn capabilities_are_bounded_and_strictly_increasing_by_their_key() -> TestResult {
    let many = (0..256)
        .map(|index| capability(&format!("{index:03}"), "read"))
        .collect::<Vec<_>>();
    accepted(&Release::sealed_with(14, &list(many.clone()))?)?;
    let mut too_many = many;
    too_many.push(capability("999", "read"));
    expect(&Release::with(14, &list(too_many))?, bound(14))?;
    let ordered = [
        ["kv", "read", "a", "purpose", "plugin"],
        ["kv", "read", "a", "purpose", "plugins"],
        ["kv", "read", "a", "purposes", "plugin"],
        ["kv", "read", "b", "purpose", "plugin"],
        ["kv", "write", "a", "purpose", "plugin"],
        ["kw", "read", "a", "purpose", "plugin"],
    ];
    let as_values = |keys: &[[&str; 5]]| {
        let capabilities = keys
            .iter()
            .map(|texts| capability_with(*texts, Value::Bool(true), [0, 0, 0]))
            .collect();
        list(capabilities)
    };
    accepted(&Release::sealed_with(14, &as_values(&ordered))?)?;
    for pair in ordered.windows(2) {
        let reversed = as_values(&[pair[1], pair[0]]);
        expect(&Release::with(14, &reversed)?, invalid(14))?;
        let repeated = as_values(&[pair[0], pair[0]]);
        expect(&Release::with(14, &repeated)?, invalid(14))?;
    }
    Ok(())
}

#[test]
fn deterministic_budget_members_have_v1_protocol_maxima() -> TestResult {
    let maxima = [
        4_294_967_296,
        u64::MAX,
        1_000_000,
        1_024,
        16_777_216,
        1_048_576,
        64,
        16_384,
    ];
    accepted(&Release::sealed_with(15, &budget(maxima))?)?;
    let minima = [65_536, 1, 0, 0, 0, 0, 0, 0];
    accepted(&Release::sealed_with(15, &budget(minima))?)?;
    for member in [0, 2, 3, 4, 5, 6, 7] {
        let mut above = maxima;
        above[member] += if member == 0 { 65_536 } else { 1 };
        expect(&Release::with(15, &budget(above))?, invalid(15))?;
    }
    for memory in [0, 65_535, 98_304, 4_294_901_761] {
        let mut wrong = DEFAULT_BUDGET;
        wrong[0] = memory;
        expect(&Release::with(15, &budget(wrong))?, invalid(15))?;
    }
    let mut no_fuel = DEFAULT_BUDGET;
    no_fuel[1] = 0;
    expect(&Release::with(15, &budget(no_fuel))?, invalid(15))?;
    let seven = list(DEFAULT_BUDGET[..7].iter().copied().map(unsigned).collect());
    expect(&Release::with(15, &seven)?, encoding(15))?;
    let mut negative = budget(DEFAULT_BUDGET);
    if let Value::Array(members) = &mut negative {
        members[4] = signed(-1);
    }
    expect(&Release::with(15, &negative)?, encoding(15))?;
    Ok(())
}

#[test]
fn pmf1_v1_declares_no_migration() -> TestResult {
    for count in [1, 64, 65] {
        let migrations = list(vec![Value::Null; count]);
        expect(&Release::with(16, &migrations)?, invalid(16))?;
    }
    expect(&Release::with_raw(16, &[0x98, 0x00])?, encoding(16))?;
    expect(&Release::with(16, &Value::Null)?, encoding(16))?;
    Ok(())
}

/// The default dependency with member `index` replaced by `value`.
fn dependency_with(index: usize, value: Value) -> Value {
    let mut changed = dependency("dep", DEPENDENCY_RELEASE);
    if let Value::Array(members) = &mut changed {
        members[index] = value;
    }
    list(vec![changed])
}

#[test]
fn dependency_members_have_exact_values_and_bounds() -> TestResult {
    let valid = [
        (5, unsigned(65_535)),
        (6, list(ids(256, 3))),
        (7, list(ids(256, 3))),
        (8, unsigned(4)),
        (0, text(&"d".repeat(128))),
    ];
    for (index, value) in valid {
        let changed = dependency_with(index, value);
        accepted(&Release::sealed_with(17, &changed)?)?;
    }
    let other_world = text("pigloros:plugin/community-plugin@0.2.0");
    let invalid_members = [
        (0, text("Dep")),
        (2, other_world),
        (3, unsigned(1)),
        (4, unsigned(65_536)),
        (4, unsigned(1)),
        (5, unsigned(65_536)),
        (6, list(vec![text("b"), text("a")])),
        (7, list(vec![text("a"), text("a")])),
        (8, unsigned(5)),
    ];
    for (index, value) in invalid_members {
        let wrong = dependency_with(index, value);
        expect(&Release::with(17, &wrong)?, invalid(17))?;
    }
    let over_bound = [(0, text(&"d".repeat(129))), (7, list(ids(257, 3)))];
    for (index, value) in over_bound {
        let wrong = dependency_with(index, value);
        expect(&Release::with(17, &wrong)?, bound(17))?;
    }
    let malformed = [(1, Value::Bytes(vec![0x42; 31])), (8, signed(-1))];
    for (index, value) in malformed {
        let wrong = dependency_with(index, value);
        expect(&Release::with(17, &wrong)?, encoding(17))?;
    }
    let mut eight = dependency("dep", DEPENDENCY_RELEASE);
    if let Value::Array(members) = &mut eight {
        members.truncate(8);
    }
    expect(&Release::with(17, &list(vec![eight]))?, encoding(17))?;
    Ok(())
}

#[test]
fn dependencies_are_bounded_and_unique_by_dependency_id() -> TestResult {
    let many = (0..256)
        .map(|index| dependency(&format!("{index:03}"), [0x42; 32]))
        .collect::<Vec<_>>();
    accepted(&Release::sealed_with(17, &list(many.clone()))?)?;
    let mut too_many = many;
    too_many.push(dependency("999", [0x42; 32]));
    expect(&Release::with(17, &list(too_many))?, bound(17))?;
    let orders = [
        (("b", 1), ("a", 2)),
        (("a", 1), ("a", 2)),
        (("a", 2), ("a", 1)),
    ];
    for (first, second) in orders {
        let pair = vec![
            dependency(first.0, [first.1; 32]),
            dependency(second.0, [second.1; 32]),
        ];
        expect(&Release::with(17, &list(pair))?, invalid(17))?;
    }
    Ok(())
}

/// A field 20 value describing `licences` in the given order.
fn licence_list(licences: &[Vec<u8>]) -> Value {
    let descriptors = licences
        .iter()
        .map(|blob| descriptor(Role::Licence, blob))
        .collect();
    list(descriptors)
}

#[test]
fn licences_are_one_to_thirty_two_strictly_increasing_descriptors() -> TestResult {
    let mut sorted = (0..33)
        .map(|index| format!("licence {index}").into_bytes())
        .collect::<Vec<_>>();
    sorted.sort_by_key(|licence| sha256(licence));
    let mut thirty_two = Release::sealed_with(20, &licence_list(&sorted[..32]))?;
    thirty_two
        .members
        .retain(|member| member.role != Role::Licence);
    for licence in &sorted[..32] {
        let member = Member::new(Role::Licence, licence);
        thirty_two.members.push(member);
    }
    accepted(&thirty_two)?;
    expect(&Release::with(20, &licence_list(&sorted))?, bound(20))?;
    expect(&Release::with(20, &list(Vec::new()))?, invalid(20))?;
    let reversed = [sorted[1].clone(), sorted[0].clone()];
    expect(&Release::with(20, &licence_list(&reversed))?, invalid(20))?;
    let repeated = [sorted[0].clone(), sorted[0].clone()];
    expect(&Release::with(20, &licence_list(&repeated))?, invalid(20))?;
    let above_cap = list(vec![fake(Role::Licence, 33_554_433)]);
    expect(&Release::with(20, &above_cap)?, bound(20))?;
    let sbom_type = list(vec![descriptor(Role::Sbom, LICENCE_BYTES)]);
    expect(&Release::with(20, &sbom_type)?, invalid(20))?;
    Ok(())
}

#[test]
fn publisher_owner_is_one_to_128_bytes() -> TestResult {
    accepted(&Release::sealed_with(21, &text(&"o".repeat(128)))?)?;
    accepted(&Release::sealed_with(21, &text("Publisher Name \u{e9}"))?)?;
    expect(&Release::with(21, &text(""))?, invalid(21))?;
    expect(&Release::with(21, &text(&"o".repeat(129)))?, bound(21))?;
    expect(&Release::with(21, &unsigned(1))?, encoding(21))?;
    Ok(())
}

/// A default release with fields 22 and 23 replaced.
fn interval(not_before: i64, not_after: i64) -> BoxResult<Release> {
    let mut release = Release::with(22, &signed(not_before))?;
    release.fields[23] = encode(&signed(not_after))?;
    Ok(release)
}

#[test]
fn validity_interval_is_ordered_bounded_and_i64() -> TestResult {
    for (not_before, not_after) in [(-1, 0), (0, 31_622_400), (i64::MIN, i64::MIN + 1)] {
        let mut release = interval(not_before, not_after)?;
        release.seal()?;
        accepted(&release)?;
    }
    let wrong = [
        (60, 60),
        (61, 60),
        (0, 31_622_401),
        (i64::MIN, i64::MAX),
        (i64::MAX, i64::MIN),
    ];
    for (not_before, not_after) in wrong {
        expect(&interval(not_before, not_after)?, invalid(23))?;
    }
    let below_i64 = [0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0];
    let above_i64 = [0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0];
    expect(&Release::with_raw(22, &below_i64)?, encoding(22))?;
    expect(&Release::with_raw(23, &above_i64)?, encoding(23))?;
    expect(&Release::with(22, &text("40"))?, encoding(22))?;
    Ok(())
}

#[test]
fn signature_descriptor_and_digest_fields_have_exact_shapes() -> TestResult {
    let descriptor = |algorithm, role, epoch, signature: usize| {
        let signature = Value::Bytes(vec![0; signature]);
        list(vec![algorithm, role, epoch, signature])
    };
    let invalid_members = [
        descriptor(unsigned(2), unsigned(3), unsigned(1), 64),
        descriptor(unsigned(1), unsigned(2), unsigned(1), 64),
        descriptor(unsigned(1), unsigned(3), unsigned(0), 64),
    ];
    for wrong in invalid_members {
        expect(&Release::with(26, &wrong)?, invalid(26))?;
    }
    let short_signature = descriptor(unsigned(1), unsigned(3), unsigned(1), 63);
    expect(&Release::with(26, &short_signature)?, encoding(26))?;
    let three = list(vec![unsigned(1), unsigned(3), unsigned(1)]);
    expect(&Release::with(26, &three)?, encoding(26))?;
    for ordinal in [24_u8, 25, 27] {
        let field = usize::from(ordinal);
        for length in [31, 33] {
            let wrong = Value::Bytes(vec![0; length]);
            expect(&Release::with(field, &wrong)?, encoding(ordinal))?;
        }
    }
    Ok(())
}

#[test]
fn schema_ids_and_blobs_are_distinct_across_fields_11_to_13() -> TestResult {
    let event = || list(vec![schema(1, EVENT_SCHEMA)]);
    let cases = [
        (12, list(vec![schema(2, EVENT_SCHEMA)]), Value::Null),
        (12, list(vec![schema(1, STATE_SCHEMA)]), Value::Null),
        (13, event(), schema(1, CONFIGURATION_SCHEMA)),
        (13, event(), schema(2, CONFIGURATION_SCHEMA)),
        (13, event(), schema(3, STATE_SCHEMA)),
        (13, event(), schema(1, EVENT_SCHEMA)),
    ];
    for (ordinal, events, configuration) in cases {
        let mut release = Release::with(11, &events)?;
        release.fields[13] = encode(&configuration)?;
        expect(&release, invalid(ordinal))?;
    }
    let same_blob = list(vec![schema(1, EVENT_SCHEMA), schema(5, EVENT_SCHEMA)]);
    expect(&Release::with(11, &same_blob)?, invalid(11))?;
    Ok(())
}

#[test]
fn cross_field_relations_follow_intra_field_errors_and_ordinal_order() -> TestResult {
    let mut later = Release::with(11, &list(vec![schema(2, EVENT_SCHEMA)]))?;
    later.fields[20] = encode(&list(Vec::new()))?;
    expect(&later, invalid(20))?;
    let release = Release::new()?;
    let field_27 = bytes(release.release_digest()?);
    let self_dependency = list(vec![dependency("dep", release.release_digest()?)]);
    let mut both = release.clone();
    both.fields[17] = encode(&self_dependency)?;
    both.fields[24] = encode(&field_27)?;
    expect(&both, invalid(17))?;
    let mut previous = release;
    previous.fields[24] = encode(&field_27)?;
    expect(&previous, invalid(24))?;
    let mut schema_first = Release::with(12, &schema(1, STATE_SCHEMA))?;
    schema_first.fields[24] = encode(&field_27)?;
    expect(&schema_first, invalid(12))?;
    Ok(())
}

#[test]
fn closure_members_must_equal_the_pmf1_descriptors_in_order() -> TestResult {
    let release = Release::new()?;
    let last = closure_index(&release.members, Role::Licence, LICENCE_BYTES)?;
    let undeclared: &[u8] = b"undeclared licence";
    let mut extra = release.clone();
    extra.members.push(Member::new(Role::Licence, undeclared));
    let extra_index = closure_index(&extra.members, Role::Licence, undeclared)?;
    expect(&extra, mismatch(extra_index.min(last + 1)))?;
    let mut fixture = release.clone();
    let migration_fixture = Member::new(Role::MigrationFixture, b"migration fixture");
    fixture.members.push(migration_fixture);
    expect(&fixture, mismatch(last + 1))?;
    let state = closure_index(&release.members, Role::Schema, STATE_SCHEMA)?;
    let mut missing = release;
    missing
        .members
        .retain(|member| member.bytes != STATE_SCHEMA);
    expect(&missing, mismatch(state))?;
    let second: &[u8] = b"second licence";
    let mut declared = [LICENCE_BYTES.to_vec(), second.to_vec()];
    declared.sort_by_key(|licence| sha256(licence));
    let mut trailing = Release::sealed_with(20, &licence_list(&declared))?;
    let member = Member::new(Role::Licence, second);
    trailing.members.push(member);
    accepted(&trailing)?;
    let dropped = closure_index(&trailing.members, Role::Licence, second)?;
    trailing.members.retain(|member| member.bytes != second);
    expect(&trailing, mismatch(dropped))?;
    Ok(())
}

#[test]
fn a_changed_or_duplicated_descriptor_breaks_closure_equality() -> TestResult {
    let release = Release::new()?;
    let provenance = closure_index(&release.members, Role::Provenance, PROVENANCE_BYTES)?;
    let component_length = COMPONENT_BYTES.len() as u64;
    let longer = artifact(
        Role::Component.media_type(),
        unsigned(component_length + 1),
        domain_digest(Role::Component.domain(), COMPONENT_BYTES),
        sha256(COMPONENT_BYTES),
    );
    expect(&Release::with(9, &longer)?, mismatch(0))?;
    let other_digest = artifact(
        Role::Wit.media_type(),
        unsigned(WIT_BYTES.len() as u64),
        domain_digest(Role::Wit.domain(), WIT_BYTES),
        sha256(b"other WIT archive"),
    );
    expect(&Release::with(10, &other_digest)?, mismatch(1))?;
    let duplicate = artifact(
        Role::Provenance.media_type(),
        unsigned(LICENCE_BYTES.len() as u64),
        domain_digest(Role::Provenance.domain(), LICENCE_BYTES),
        sha256(LICENCE_BYTES),
    );
    expect(&Release::with(18, &duplicate)?, mismatch(provenance))?;
    let mut changed_bytes = release;
    changed_bytes.members[0] = Member::new(Role::Component, b"\0asm other component");
    expect(&changed_bytes, mismatch(0))?;
    Ok(())
}

/// A descriptor whose BLAKE3 value uses the reserved migration-fixture domain.
fn wrong_blake3(role: Role, blob: &[u8]) -> Value {
    artifact(
        role.media_type(),
        unsigned(blob.len() as u64),
        domain_digest(Role::MigrationFixture.domain(), blob),
        sha256(blob),
    )
}

const fn digest_mismatch(ordinal: u8) -> PluginManifestErrorV1 {
    PluginManifestErrorV1::ArtifactDigestMismatch { ordinal }
}

#[test]
fn every_inner_blake3_digest_is_recomputed_in_field_order() -> TestResult {
    let release = Release::new()?;
    let event = schema_with(1, 1, wrong_blake3(Role::Schema, EVENT_SCHEMA), 1);
    let state = schema_with(2, 1, wrong_blake3(Role::Schema, STATE_SCHEMA), 1);
    let cases = [
        (9, wrong_blake3(Role::Component, COMPONENT_BYTES)),
        (10, wrong_blake3(Role::Wit, WIT_BYTES)),
        (11, list(vec![event])),
        (12, state),
        (18, wrong_blake3(Role::Provenance, PROVENANCE_BYTES)),
        (19, wrong_blake3(Role::Sbom, SBOM_BYTES)),
        (20, list(vec![wrong_blake3(Role::Licence, LICENCE_BYTES)])),
    ];
    for (ordinal, wrong) in cases {
        let mut mismatched = release.clone();
        mismatched.fields[usize::from(ordinal)] = encode(&wrong)?;
        expect(&mismatched, digest_mismatch(ordinal))?;
    }
    let artifact = wrong_blake3(Role::Schema, CONFIGURATION_SCHEMA);
    let mut configuration = Release::with(13, &schema_with(3, 1, artifact, 1))?;
    let member = Member::new(Role::Schema, CONFIGURATION_SCHEMA);
    configuration.members.push(member);
    expect(&configuration, digest_mismatch(13))?;
    let mut first_wins = release;
    first_wins.fields[10] = encode(&wrong_blake3(Role::Wit, WIT_BYTES))?;
    first_wins.fields[18] = encode(&wrong_blake3(Role::Provenance, PROVENANCE_BYTES))?;
    expect(&first_wins, digest_mismatch(10))?;
    Ok(())
}

#[test]
fn inner_digests_are_domain_separated_and_length_prefixed() -> TestResult {
    let mut hasher = blake3::Hasher::new();
    hasher.update(Role::Component.domain());
    hasher.update(COMPONENT_BYTES);
    let without_length = *hasher.finalize().as_bytes();
    let under_wit = domain_digest(Role::Wit.domain(), COMPONENT_BYTES);
    let length = unsigned(COMPONENT_BYTES.len() as u64);
    for wrong in [without_length, under_wit, digest(COMPONENT_BYTES)] {
        let media_type = Role::Component.media_type();
        let component = artifact(media_type, length.clone(), wrong, sha256(COMPONENT_BYTES));
        expect(&Release::with(9, &component)?, digest_mismatch(9))?;
    }
    Ok(())
}

#[test]
fn manifest_and_release_digests_are_recomputed_in_order() -> TestResult {
    let unsigned_mismatch = PluginManifestErrorV1::UnsignedManifestDigestMismatch;
    let release_mismatch = PluginManifestErrorV1::ReleaseDigestMismatch;
    let release = Release::new()?;
    let mut both_changed = release.clone();
    both_changed.fields[25] = encode(&bytes([0; 32]))?;
    both_changed.fields[27] = encode(&bytes([0; 32]))?;
    expect(&both_changed, unsigned_mismatch)?;
    let mut release_changed = release.clone();
    release_changed.fields[27] = encode(&bytes([0; 32]))?;
    expect(&release_changed, release_mismatch)?;
    let mut stale = release;
    stale.fields[3] = encode(&text("1.0.1"))?;
    expect(&stale, unsigned_mismatch)?;
    let mut sha256_inputs = stale;
    sha256_inputs.seal()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(RELEASE_DOMAIN);
    hasher.update(sha256_inputs.fields[25].get(2..).ok_or("short field 25")?);
    hasher.update(&sha256(COMPONENT_BYTES));
    hasher.update(&sha256(WIT_BYTES));
    sha256_inputs.fields[27] = encode(&bytes(*hasher.finalize().as_bytes()))?;
    expect(&sha256_inputs, release_mismatch)?;
    Ok(())
}

#[test]
fn inner_digest_mismatches_follow_pmf1_field_order_not_layer_order() -> TestResult {
    let mut documents = [EVENT_SCHEMA, STATE_SCHEMA];
    documents.sort_by_key(|document| std::cmp::Reverse(sha256(document)));
    let [later_layer, earlier_layer] = documents;
    let event = schema_with(1, 1, wrong_blake3(Role::Schema, later_layer), 1);
    let mut release = Release::with(11, &list(vec![event]))?;
    let state = schema_with(2, 1, wrong_blake3(Role::Schema, earlier_layer), 1);
    release.fields[12] = encode(&state)?;
    expect(&release, digest_mismatch(11))
}

/// The verified OCI closure of the independently generated golden release.
fn golden_bundle() -> BoxResult<VerifiedReleaseBundleV1> {
    let manifest = GOLDEN_OCI_MANIFEST.as_bytes().to_vec();
    let size = u64::try_from(manifest.len())?;
    let address = BundleAddressV1::new(GOLDEN_OCI_MANIFEST_DIGEST.to_owned(), size)?;
    let mut blobs = BTreeMap::new();
    for (oci, hex) in GOLDEN_BLOBS_HEX {
        blobs.insert(oci.to_owned(), hex_bytes(hex)?);
    }
    Ok(verify_oci_closure_v1(address, manifest, blobs)?)
}

fn golden_digest(hex: &str) -> BoxResult<[u8; 32]> {
    Ok(hex_bytes(hex)?.as_slice().try_into()?)
}

/// Authorize `projection` (`alpha/plugin`, epoch 9) with one revoked digest.
fn authorize_with_revoked(
    ptr1: &[u8],
    projection: &ValidatedPluginManifestProjectionV1,
    revoked: [u8; 32],
) -> BoxResult<Result<[u8; 32], PluginTrustErrorV1>> {
    let anchor = TrustedPluginRootAnchorV1::new("scope", digest(ptr1))?;
    let artifacts = vec![revoked_artifact(revoked)];
    let fields = revocation_fields(digest(ptr1), 1, None, 5, Vec::new(), artifacts);
    let prv1 = signed_record(fields, REVOCATION_SIGNATURE_DOMAIN, &signer())?;
    let evidence = verify_plugin_trust_v1(&anchor, &[ptr1], &[&prv1], 50, 5)?;
    Ok(evidence
        .authorize_release(projection)
        .map(|fact| fact.resolved_public_key()))
}

#[test]
fn independent_golden_closure_projects_and_binds_its_digests() -> TestResult {
    let bundle = golden_bundle()?;
    let pmf1 = hex_bytes(GOLDEN_PMF1_HEX)?;
    assert_eq!(bundle.pmf1(), pmf1.as_slice());
    assert_eq!(digest(&pmf1), golden_digest(GOLDEN_PMF1_DIGEST_HEX)?);
    let projection = ValidatedPluginManifestProjectionV1::from_verified_bundle(&bundle)?;
    let publishers = vec![publisher_entry("publisher", 9, publisher_public())];
    let fields = root_fields(
        1,
        None,
        publishers,
        vec![grant("alpha/plugin", "publisher")],
    );
    let ptr1 = signed_record(fields, ROOT_SIGNATURE_DOMAIN, &signer())?;
    let mut denied = vec![golden_digest(GOLDEN_RELEASE_DIGEST_HEX)?];
    for hex in GOLDEN_DESCRIPTOR_DIGESTS_HEX {
        denied.push(golden_digest(hex)?);
    }
    for revoked in denied {
        assert_eq!(authorize_with_revoked(&ptr1, &projection, revoked)?, DENIED);
    }
    let field_24 = golden_digest(GOLDEN_PREVIOUS_RELEASE_HEX)?;
    let field_25 = golden_digest(GOLDEN_UNSIGNED_MANIFEST_DIGEST_HEX)?;
    for carried in [field_24, field_25] {
        assert!(pmf1.windows(32).any(|window| window == carried.as_slice()));
    }
    for excluded in [field_24, field_25, sha256(&pmf1), digest(&pmf1)] {
        let authorized = authorize_with_revoked(&ptr1, &projection, excluded)?;
        assert_eq!(authorized, Ok(publisher_public()));
    }
    Ok(())
}

/// The projected form of `capability_with(texts, required, limits)`.
fn projected_capability(
    texts: [&str; 5],
    required: bool,
    limits: [u64; 3],
) -> PluginCapabilityDescriptorV1 {
    PluginCapabilityDescriptorV1 {
        capability_id: texts[0].to_owned(),
        operation: texts[1].to_owned(),
        resource_pattern: texts[2].to_owned(),
        purpose: texts[3].to_owned(),
        audience: texts[4].to_owned(),
        required,
        max_calls: limits[0],
        max_request_bytes: limits[1],
        max_response_bytes: limits[2],
    }
}

/// The projected form of `budget(members)`.
const fn projected_budget(members: [u64; 8]) -> DeterministicBudgetV1 {
    DeterministicBudgetV1 {
        memory_bytes: members[0],
        fuel: members[1],
        host_calls: members[2],
        event_count: members[3],
        event_bytes: members[4],
        state_bytes: members[5],
        log_calls: members[6],
        log_bytes: members[7],
    }
}

#[test]
fn default_release_projects_its_execution_requirements() -> TestResult {
    let release = Release::new()?;
    let execution = release.execution()??;
    let manifest = release.project()??;
    assert!(execution.is_bound_to(&manifest));
    assert_eq!(execution.pmf1_digest(), digest(&release.pmf1()));
    assert_eq!(execution.release_digest(), release.release_digest()?);
    assert_eq!(execution.plugin_id(), "plugin-a");
    let abi = PluginAbiRequirementV1 {
        major: 0,
        min_minor: 0,
        max_minor: 1,
        required_features: vec!["clock".to_owned()],
    };
    assert_eq!(execution.abi(), &abi);
    let texts = ["kv", "read", "state/*", "Read Plugin state", "plugin"];
    let capability = projected_capability(texts, true, [10, 1_024, 2_048]);
    assert_eq!(execution.capabilities(), [capability].as_slice());
    assert_eq!(execution.budget(), projected_budget(DEFAULT_BUDGET));
    Ok(())
}

#[test]
fn execution_projection_keeps_every_member_at_its_extremes() -> TestResult {
    let maxima = [
        1 << 32,
        u64::MAX,
        1_000_000,
        1_024,
        1 << 24,
        1 << 20,
        64,
        16_384,
    ];
    let optional = ["kv", "write", "state/*", "purpose", "plugin"];
    let capabilities = list(vec![
        capability_with(CAPABILITY, Value::Bool(true), [1, 2, 3]),
        capability_with(optional, Value::Bool(false), [1_000_000, 0, 16_777_216]),
    ]);
    let mut release = Release::with(6, &unsigned(7))?;
    release.fields[7] = encode(&unsigned(65_535))?;
    release.fields[8] = encode(&list(vec![text("a"), text("b.c")]))?;
    release.fields[14] = encode(&capabilities)?;
    release.fields[15] = encode(&budget(maxima))?;
    release.seal()?;
    let execution = release.execution()??;
    let abi = PluginAbiRequirementV1 {
        major: 0,
        min_minor: 7,
        max_minor: 65_535,
        required_features: vec!["a".to_owned(), "b.c".to_owned()],
    };
    assert_eq!(execution.abi(), &abi);
    let expected = [
        projected_capability(CAPABILITY, true, [1, 2, 3]),
        projected_capability(optional, false, [1_000_000, 0, 16_777_216]),
    ];
    assert_eq!(execution.capabilities(), expected.as_slice());
    assert_eq!(execution.budget(), projected_budget(maxima));
    let minima = [65_536, 1, 0, 0, 0, 0, 0, 0];
    let mut smallest = Release::sealed_with(15, &budget(minima))?;
    smallest.fields[14] = encode(&list(Vec::new()))?;
    smallest.fields[8] = encode(&list(Vec::new()))?;
    smallest.seal()?;
    let execution = smallest.execution()??;
    assert!(execution.capabilities().is_empty());
    assert!(execution.abi().required_features.is_empty());
    assert_eq!(execution.budget(), projected_budget(minima));
    Ok(())
}

#[test]
fn execution_projection_fails_exactly_as_the_release_projection() -> TestResult {
    let mut reversed = Release::with(6, &unsigned(2))?;
    reversed.fields[7] = encode(&unsigned(1))?;
    let mut unsealed = Release::new()?;
    unsealed.fields[15] = encode(&budget([131_072, 1, 0, 0, 0, 0, 0, 0]))?;
    let failures = [
        (Release::with(5, &unsigned(1))?, invalid(5)),
        (reversed, invalid(7)),
        (
            Release::with(15, &budget([65_537, 1, 0, 0, 0, 0, 0, 0]))?,
            invalid(15),
        ),
        (Release::with(16, &list(vec![unsigned(0)]))?, invalid(16)),
        (
            unsealed,
            PluginManifestErrorV1::UnsignedManifestDigestMismatch,
        ),
    ];
    for (release, error) in failures {
        assert_eq!(release.execution()?, Err(error));
        assert_eq!(release.project()?, Err(error));
    }
    Ok(())
}

#[test]
fn a_re_signed_release_binds_only_its_own_trust_projection() -> TestResult {
    let original = Release::new()?;
    let mut resigned = original.clone();
    resigned.fields[26] = encode(&signature(2))?;
    let execution = resigned.execution()??;
    assert_eq!(execution.release_digest(), original.release_digest()?);
    assert!(execution.is_bound_to(&resigned.project()??));
    assert!(!execution.is_bound_to(&original.project()??));
    Ok(())
}

#[test]
fn exported_bounds_and_id_grammar_are_the_codec_rules() -> TestResult {
    let minima = DeterministicBudgetV1::MINIMA;
    let maxima = DeterministicBudgetV1::MAXIMA;
    assert_eq!(minima.memory_bytes, WASM_PAGE_BYTES_V1);
    let smallest = Release::sealed_with(15, &budget(budget_members(minima)))?;
    assert_eq!(smallest.execution()??.budget(), minima);
    let largest = Release::sealed_with(15, &budget(budget_members(maxima)))?;
    assert_eq!(largest.execution()??.budget(), maxima);
    for (member, value) in budget_members(maxima).into_iter().enumerate() {
        let mut members = budget_members(maxima);
        members[member] = value.saturating_add(1);
        if value < u64::MAX {
            expect(&Release::with(15, &budget(members))?, invalid(15))?;
        }
    }
    for valid in ["a", "0.x_y/z-1", &"a".repeat(128)] {
        assert!(is_valid_id_v1(valid), "{valid}");
    }
    for invalid_id in ["", "A", "-a", "a b", &"a".repeat(129)] {
        assert!(!is_valid_id_v1(invalid_id), "{invalid_id}");
    }
    Ok(())
}

/// The eight members of `budget` in field 15 order.
const fn budget_members(budget: DeterministicBudgetV1) -> [u64; 8] {
    [
        budget.memory_bytes,
        budget.fuel,
        budget.host_calls,
        budget.event_count,
        budget.event_bytes,
        budget.state_bytes,
        budget.log_calls,
        budget.log_bytes,
    ]
}

// --- PMF1 V1 encoder -------------------------------------------------------

type Draft<'a> = PluginReleaseDraftV1<'a>;
type Encoded = Result<Vec<u8>, PluginManifestErrorV1>;
type Verification = Result<VerifiedPluginReleaseSignatureV1, PluginReleaseSignatureErrorV1>;

fn owner(value: &str) -> BoxResult<OwnerIdV1> {
    Ok(OwnerIdV1::new(value)?)
}

fn input(bytes: &[u8]) -> PluginArtifactInputV1<'_> {
    PluginArtifactInputV1 {
        bytes,
        sha256: sha256(bytes),
    }
}

fn schema_input(id: u32, version: u32, document: &[u8], max_bytes: u32) -> PluginSchemaInputV1<'_> {
    PluginSchemaInputV1 {
        id,
        version,
        artifact: input(document),
        max_bytes,
    }
}

const fn budget_struct(members: [u64; 8]) -> DeterministicBudgetV1 {
    DeterministicBudgetV1 {
        memory_bytes: members[0],
        fuel: members[1],
        host_calls: members[2],
        event_count: members[3],
        event_bytes: members[4],
        state_bytes: members[5],
        log_calls: members[6],
        log_bytes: members[7],
    }
}

fn capability_input(id: &str, operation: &str) -> PluginCapabilityDescriptorV1 {
    PluginCapabilityDescriptorV1 {
        capability_id: id.to_owned(),
        operation: operation.to_owned(),
        resource_pattern: "state/*".to_owned(),
        purpose: "Read Plugin state".to_owned(),
        audience: "plugin".to_owned(),
        required: true,
        max_calls: 10,
        max_request_bytes: 1_024,
        max_response_bytes: 2_048,
    }
}

fn dependency_input(id: &str) -> PluginDependencyInputV1 {
    PluginDependencyInputV1 {
        dependency_id: id.to_owned(),
        release_digest: DEPENDENCY_RELEASE,
        min_minor: 0,
        max_minor: 0,
        required_features: vec!["clock".to_owned()],
        capability_ids: Vec::new(),
        class: 0,
    }
}

/// The draft of the independent builder's default release (`Release::new`).
fn default_draft<'a>() -> BoxResult<Draft<'a>> {
    Ok(PluginReleaseDraftV1 {
        plugin_id: "plugin-a".to_owned(),
        release_version: "1.0.0".to_owned(),
        abi: PluginAbiRequirementV1 {
            major: 0,
            min_minor: 0,
            max_minor: 1,
            required_features: vec!["clock".to_owned()],
        },
        component: input(COMPONENT_BYTES),
        wit: input(WIT_BYTES),
        event_schemas: vec![schema_input(1, 1, EVENT_SCHEMA, 65_536)],
        state_schema: schema_input(2, 1, STATE_SCHEMA, 65_536),
        configuration_schema: None,
        capabilities: vec![capability_input("kv", "read")],
        budget: budget_struct(DEFAULT_BUDGET),
        dependencies: vec![dependency_input("dep")],
        provenance: input(PROVENANCE_BYTES),
        sbom: input(SBOM_BYTES),
        licences: vec![input(LICENCE_BYTES)],
        owner: owner("publisher")?,
        not_before: 40,
        not_after: 60,
        previous_release_digest: None,
    })
}

fn encode_draft(draft: &Draft<'_>, epoch: u64, signature: [u8; 64]) -> Encoded {
    draft
        .unsigned()
        .and_then(|unsigned| unsigned.with_signature(epoch, signature))
}

#[test]
fn encoder_output_equals_the_independent_builder_for_the_default_release() -> TestResult {
    let encoded = encode_draft(&default_draft()?, 1, [0x5a; 64]);
    assert_eq!(encoded, Ok(Release::new()?.pmf1()));
    let unsigned = default_draft()?.unsigned()?;
    let release = Release::new()?;
    assert_eq!(unsigned.release_digest(), release.release_digest()?);
    assert_eq!(unsigned.owner(), owner("publisher")?);
    assert_eq!(unsigned.unsigned_bytes().first(), Some(&0x98));
    assert_eq!(unsigned.unsigned_bytes().get(1), Some(&0x19));
    let mut manifest = domain_digest(MANIFEST_DOMAIN, unsigned.unsigned_bytes());
    assert_eq!(unsigned.unsigned_manifest_digest(), manifest);
    manifest[0] ^= 1;
    assert_ne!(unsigned.unsigned_manifest_digest(), manifest);
    assert_eq!(default_draft()?.unsigned()?, unsigned);
    Ok(())
}

#[test]
fn encoder_matches_the_independent_builder_at_every_cbor_width() -> TestResult {
    let intervals = [
        (-1, 0),
        (-24, 0),
        (-25, 1),
        (-256, -255),
        (-257, 0),
        (0, 24),
        (23, 24),
        (255, 256),
        (65_535, 65_536),
        (4_294_967_295, 4_294_967_296),
        (-5_000_000_000, -4_999_999_999),
        (i64::MAX - 1, i64::MAX),
        (i64::MIN, i64::MIN + 1),
        (0, 31_622_400),
    ];
    for (not_before, not_after) in intervals {
        let mut draft = default_draft()?;
        draft.not_before = not_before;
        draft.not_after = not_after;
        let mut release = interval(not_before, not_after)?;
        release.seal()?;
        let encoded = encode_draft(&draft, 1, [0x5a; 64]);
        assert_eq!(encoded, Ok(release.pmf1()), "{not_before}..{not_after}");
    }
    for members in [
        budget_members(DeterministicBudgetV1::MINIMA),
        budget_members(DeterministicBudgetV1::MAXIMA),
        [65_536, 256, 65_535, 255, 65_536, 65_535, 23, 24],
        [
            4_294_967_296,
            4_294_967_295,
            1_000_000,
            1_024,
            16_777_216,
            1_048_576,
            64,
            16_384,
        ],
    ] {
        let mut draft = default_draft()?;
        draft.budget = budget_struct(members);
        let mut release = Release::with(15, &budget(members))?;
        release.seal()?;
        assert_eq!(encode_draft(&draft, 1, [0x5a; 64]), Ok(release.pmf1()));
    }
    for epoch in [1, 23, 24, 255, 256, 65_535, 65_536, 4_294_967_296, u64::MAX] {
        let mut release = Release::new()?;
        release.fields[26] = encode(&signature(epoch))?;
        let encoded = encode_draft(&default_draft()?, epoch, [0x5a; 64]);
        assert_eq!(encoded, Ok(release.pmf1()), "epoch {epoch}");
    }
    let mut draft = default_draft()?;
    draft.previous_release_digest = Some([7; 32]);
    let mut release = Release::new()?;
    release.fields[24] = encode(&bytes([7; 32]))?;
    release.seal()?;
    assert_eq!(encode_draft(&draft, 1, [0x5a; 64]), Ok(release.pmf1()));
    Ok(())
}

#[test]
fn encoder_matches_the_independent_builder_for_every_optional_member() -> TestResult {
    let mut draft = default_draft()?;
    draft.configuration_schema = Some(schema_input(3, 1, CONFIGURATION_SCHEMA, 65_536));
    draft.capabilities.push(capability_input("kv", "write"));
    draft.dependencies.push(dependency_input("dep2"));
    let mut release = Release::with(13, &schema(3, CONFIGURATION_SCHEMA))?;
    release.fields[14] = encode(&list(vec![
        capability("kv", "read"),
        capability("kv", "write"),
    ]))?;
    release.fields[17] = encode(&list(vec![
        dependency("dep", DEPENDENCY_RELEASE),
        dependency("dep2", DEPENDENCY_RELEASE),
    ]))?;
    release.seal()?;
    assert_eq!(encode_draft(&draft, 1, [0x5a; 64]), Ok(release.pmf1()));
    let mut features = default_draft()?;
    features.abi.required_features = vec!["a".to_owned(), "b".to_owned()];
    features.dependencies[0].capability_ids = vec!["kv".to_owned()];
    features.dependencies[0].class = 4;
    features.dependencies[0].min_minor = 1;
    features.dependencies[0].max_minor = 65_535;
    let mut release = Release::with(8, &list(vec![text("a"), text("b")]))?;
    let mut dependency = dependency("dep", DEPENDENCY_RELEASE);
    if let Value::Array(members) = &mut dependency {
        members[4] = unsigned(1);
        members[5] = unsigned(65_535);
        members[7] = list(vec![text("kv")]);
        members[8] = unsigned(4);
    }
    release.fields[17] = encode(&list(vec![dependency]))?;
    release.seal()?;
    assert_eq!(encode_draft(&features, 1, [0x5a; 64]), Ok(release.pmf1()));
    Ok(())
}

#[test]
fn licences_are_emitted_in_sha256_order_whatever_the_draft_order() -> TestResult {
    let first: &[u8] = b"licence one";
    let second: &[u8] = b"licence two";
    let mut forward = default_draft()?;
    forward.licences = vec![input(first), input(second)];
    let mut backward = default_draft()?;
    backward.licences = vec![input(second), input(first)];
    let forward = encode_draft(&forward, 1, [1; 64]);
    assert_eq!(forward, encode_draft(&backward, 1, [1; 64]));
    let mut sorted = [first.to_vec(), second.to_vec()];
    sorted.sort_by_key(|licence| sha256(licence));
    let mut release = Release::with(20, &licence_list(&sorted))?;
    release.fields[26] = encode(&list(vec![
        unsigned(1),
        unsigned(3),
        unsigned(1),
        Value::Bytes(vec![1; 64]),
    ]))?;
    release.seal()?;
    assert_eq!(forward, Ok(release.pmf1()));
    Ok(())
}

#[test]
fn encoded_release_decodes_projects_and_binds_the_draft() -> TestResult {
    let draft = default_draft()?;
    let release = Release::new()?;
    let pmf1 = encode_draft(&draft, 1, [0x5a; 64])?;
    let bundle = closure(pmf1.clone(), &release.members)??;
    let projection = ValidatedPluginManifestProjectionV1::from_verified_bundle(&bundle)?;
    assert_eq!(projection, release.project()??);
    let execution = PluginExecutionProjectionV1::from_verified_bundle(&bundle)?;
    assert_eq!(execution.plugin_id(), draft.plugin_id);
    assert_eq!(execution.abi(), &draft.abi);
    assert_eq!(execution.budget(), draft.budget);
    assert_eq!(execution.capabilities(), draft.capabilities.as_slice());
    assert_eq!(execution.pmf1_digest(), digest(&pmf1));
    assert_eq!(
        execution.release_digest(),
        draft.unsigned()?.release_digest()
    );
    Ok(())
}

/// Assert that `change` makes the encoder fail exactly as the decoder would.
fn rejected(change: impl FnOnce(&mut Draft<'_>), error: PluginManifestErrorV1) -> TestResult {
    let mut draft = default_draft()?;
    change(&mut draft);
    assert_eq!(draft.unsigned().err(), Some(error));
    Ok(())
}

/// Assert that `change` leaves a draft the encoder accepts.
fn accepted_draft(change: impl FnOnce(&mut Draft<'_>)) -> TestResult {
    let mut draft = default_draft()?;
    change(&mut draft);
    assert!(draft.unsigned().is_ok());
    Ok(())
}

#[test]
fn encoder_rejects_every_invalid_draft_field_like_the_decoder() -> TestResult {
    rejected(|draft| draft.plugin_id = "Bad".to_owned(), invalid(2))?;
    rejected(|draft| draft.plugin_id = String::new(), invalid(2))?;
    rejected(|draft| draft.release_version = "1.0".to_owned(), invalid(3))?;
    rejected(
        |draft| draft.release_version = "01.0.0".to_owned(),
        invalid(3),
    )?;
    rejected(
        |draft| draft.release_version = "1.0.0+build".to_owned(),
        invalid(3),
    )?;
    rejected(|draft| draft.abi.major = 1, invalid(5))?;
    rejected(|draft| draft.abi.min_minor = 2, invalid(7))?;
    rejected(
        |draft| draft.abi.required_features = vec!["b".to_owned(), "a".to_owned()],
        invalid(8),
    )?;
    rejected(|draft| draft.component = input(b""), invalid(9))?;
    rejected(|draft| draft.wit = input(b""), invalid(10))?;
    rejected(
        |draft| draft.event_schemas = vec![schema_input(1, 0, EVENT_SCHEMA, 1)],
        invalid(11),
    )?;
    rejected(
        |draft| {
            draft
                .event_schemas
                .push(schema_input(1, 1, STATE_SCHEMA, 1));
        },
        invalid(11),
    )?;
    rejected(
        |draft| draft.state_schema = schema_input(1, 1, STATE_SCHEMA, 1),
        invalid(12),
    )?;
    rejected(
        |draft| draft.state_schema = schema_input(2, 1, EVENT_SCHEMA, 1),
        invalid(12),
    )?;
    rejected(
        |draft| draft.state_schema = schema_input(2, 0, STATE_SCHEMA, 1),
        invalid(12),
    )?;
    rejected(
        |draft| draft.state_schema = schema_input(2, 1, STATE_SCHEMA, 0),
        invalid(12),
    )?;
    rejected(
        |draft| draft.state_schema = schema_input(2, 1, STATE_SCHEMA, 1_048_577),
        invalid(12),
    )?;
    rejected(
        |draft| draft.configuration_schema = Some(schema_input(2, 1, CONFIGURATION_SCHEMA, 1)),
        invalid(13),
    )?;
    rejected(
        |draft| draft.configuration_schema = Some(schema_input(3, 1, STATE_SCHEMA, 1)),
        invalid(13),
    )?;
    rejected(
        |draft| {
            draft
                .capabilities
                .insert(0, capability_input("kv", "write"));
        },
        invalid(14),
    )?;
    rejected(
        |draft| draft.capabilities[0].capability_id = "KV".to_owned(),
        invalid(14),
    )?;
    rejected(
        |draft| draft.capabilities[0].resource_pattern = String::new(),
        invalid(14),
    )?;
    rejected(
        |draft| draft.capabilities[0].max_calls = 1_000_001,
        invalid(14),
    )?;
    rejected(
        |draft| draft.capabilities[0].max_request_bytes = 16_777_217,
        invalid(14),
    )?;
    rejected(
        |draft| draft.capabilities[0].max_response_bytes = 16_777_217,
        invalid(14),
    )?;
    Ok(())
}

#[test]
fn encoder_rejects_invalid_budget_dependency_licence_and_interval_like_the_decoder() -> TestResult {
    rejected(|draft| draft.budget.memory_bytes = 65_535, invalid(15))?;
    rejected(|draft| draft.budget.memory_bytes = 65_537, invalid(15))?;
    rejected(|draft| draft.budget.fuel = 0, invalid(15))?;
    rejected(|draft| draft.budget.state_bytes = 1_048_577, invalid(15))?;
    rejected(
        |draft| draft.dependencies.insert(0, dependency_input("e")),
        invalid(17),
    )?;
    rejected(|draft| draft.dependencies[0].class = 5, invalid(17))?;
    rejected(|draft| draft.dependencies[0].min_minor = 1, invalid(17))?;
    rejected(|draft| draft.licences = Vec::new(), invalid(20))?;
    rejected(
        |draft| draft.licences.push(input(LICENCE_BYTES)),
        invalid(20),
    )?;
    rejected(|draft| draft.not_after = 40, invalid(23))?;
    rejected(|draft| draft.not_after = 31_622_441, invalid(23))?;
    Ok(())
}

#[test]
fn encoder_accepts_each_boundary_value_beside_its_rejected_neighbour() -> TestResult {
    accepted_draft(|draft| draft.not_after = 41)?;
    accepted_draft(|draft| draft.not_after = 31_622_440)?;
    accepted_draft(|draft| draft.state_schema.max_bytes = 1)?;
    accepted_draft(|draft| draft.state_schema.max_bytes = 1_048_576)?;
    accepted_draft(|draft| draft.capabilities[0].max_calls = 1_000_000)?;
    accepted_draft(|draft| draft.capabilities[0].max_request_bytes = 16_777_216)?;
    accepted_draft(|draft| draft.capabilities[0].max_response_bytes = 0)?;
    accepted_draft(|draft| draft.budget.memory_bytes = 65_536)?;
    accepted_draft(|draft| draft.budget.memory_bytes = 4_294_967_296)?;
    accepted_draft(|draft| draft.budget.fuel = u64::MAX)?;
    accepted_draft(|draft| draft.budget.state_bytes = 1_048_576)?;
    accepted_draft(|draft| draft.dependencies[0].class = 4)?;
    accepted_draft(|draft| draft.abi.max_minor = 65_535)?;
    accepted_draft(|draft| draft.abi.required_features = Vec::new())?;
    accepted_draft(|draft| draft.owner = OwnerIdV1::from_static("o"))?;
    let epoch_zero = default_draft()?.unsigned()?.with_signature(0, [0x5a; 64]);
    assert_eq!(epoch_zero, Err(invalid(26)));
    Ok(())
}

#[test]
fn encoder_bounds_collections_texts_and_artifact_sizes_exactly() -> TestResult {
    let features = |count: usize| {
        ids(count, 3)
            .iter()
            .filter_map(|value| value.as_text().map(str::to_owned))
            .collect::<Vec<_>>()
    };
    let mut draft = default_draft()?;
    draft.abi.required_features = features(256);
    assert!(draft.unsigned().is_ok());
    draft.abi.required_features = features(257);
    assert_eq!(draft.unsigned().err(), Some(bound(8)));
    let documents = (0..258)
        .map(|index| format!("{{\"$id\":\"event-{index:04}\"}}").into_bytes())
        .collect::<Vec<_>>();
    let schemas = |count: usize| {
        let ids = 10..;
        documents
            .iter()
            .zip(ids)
            .take(count)
            .map(|(document, id)| schema_input(id, 1, document, 1))
            .collect::<Vec<_>>()
    };
    let mut draft = default_draft()?;
    draft.event_schemas = schemas(256);
    assert!(draft.unsigned().is_ok());
    draft.event_schemas = schemas(257);
    assert_eq!(draft.unsigned().err(), Some(bound(11)));
    let licences = (0..33)
        .map(|index| format!("licence {index}").into_bytes())
        .collect::<Vec<_>>();
    let mut draft = default_draft()?;
    draft.licences = licences[..32]
        .iter()
        .map(|licence| input(licence))
        .collect();
    assert!(draft.unsigned().is_ok());
    draft.licences = licences.iter().map(|licence| input(licence)).collect();
    assert_eq!(draft.unsigned().err(), Some(bound(20)));
    let wit = vec![0; 4_194_304];
    let too_large = vec![0; 4_194_305];
    let mut draft = default_draft()?;
    draft.wit = input(&wit);
    assert!(draft.unsigned().is_ok());
    draft.wit = input(&too_large);
    assert_eq!(draft.unsigned().err(), Some(bound(10)));
    let mut draft = default_draft()?;
    draft.plugin_id = "a".repeat(128);
    assert!(draft.unsigned().is_ok());
    draft.plugin_id = "a".repeat(129);
    assert_eq!(draft.unsigned().err(), Some(bound(2)));
    let mut draft = default_draft()?;
    draft.release_version = format!("1.0.0-{}", "a".repeat(58));
    assert!(draft.unsigned().is_ok());
    draft.release_version = format!("1.0.0-{}", "a".repeat(59));
    assert_eq!(draft.unsigned().err(), Some(bound(3)));
    Ok(())
}

// --- Independent golden signing vectors ------------------------------------

fn golden_signature() -> BoxResult<[u8; 64]> {
    hex_bytes(GOLDEN_SIGNATURE_HEX)?
        .try_into()
        .map_err(|_| "golden signature is not 64 bytes".into())
}

fn golden_capability(
    operation: &str,
    required: bool,
    limits: [u64; 3],
) -> PluginCapabilityDescriptorV1 {
    let mut capability = capability_input("kv", operation);
    capability.purpose = format!("{} Plugin state", if required { "Read" } else { "Write" });
    capability.required = required;
    [
        capability.max_calls,
        capability.max_request_bytes,
        capability.max_response_bytes,
    ] = limits;
    capability
}

/// The golden draft with licences in the given order, over `blobs`.
fn golden_draft<'a>(
    blobs: &'a BTreeMap<&'static str, Vec<u8>>,
    licences: [&str; 2],
) -> BoxResult<Draft<'a>> {
    let blob = |name: &str| -> BoxResult<&'a [u8]> {
        Ok(blobs.get(name).ok_or("unknown golden artifact")?.as_slice())
    };
    Ok(PluginReleaseDraftV1 {
        plugin_id: "alpha/plugin".to_owned(),
        release_version: "1.2.3-rc.1".to_owned(),
        abi: PluginAbiRequirementV1 {
            major: 0,
            min_minor: 1,
            max_minor: 3,
            required_features: vec!["clock.v1".to_owned(), "log".to_owned()],
        },
        component: input(blob("component")?),
        wit: input(blob("wit")?),
        event_schemas: vec![
            schema_input(1, 1, blob("event-a")?, 4_096),
            schema_input(7, 2, blob("event-b")?, 4_096),
        ],
        state_schema: schema_input(100, 1, blob("state")?, 65_536),
        configuration_schema: Some(schema_input(200, 1, blob("configuration")?, 1_024)),
        capabilities: vec![
            golden_capability("read", true, [24, 1_024, 2_048]),
            golden_capability("write", false, [10, 2_048, 0]),
        ],
        budget: budget_struct([1_048_576, 1 << 40, 1_000, 16, 4_096, 65_536, 24, 2_048]),
        dependencies: vec![PluginDependencyInputV1 {
            dependency_id: "beta/lib".to_owned(),
            release_digest: [0x42; 32],
            min_minor: 0,
            max_minor: 2,
            required_features: vec!["clock.v1".to_owned()],
            capability_ids: vec!["kv".to_owned()],
            class: 1,
        }],
        provenance: input(blob("provenance")?),
        sbom: input(blob("sbom")?),
        licences: vec![input(blob(licences[0])?), input(blob(licences[1])?)],
        owner: owner(GOLDEN_SIGNER_OWNER)?,
        not_before: -100,
        not_after: 100,
        previous_release_digest: Some([0x24; 32]),
    })
}

fn golden_blobs() -> BoxResult<BTreeMap<&'static str, Vec<u8>>> {
    let mut blobs = BTreeMap::new();
    for (name, hex) in GOLDEN_ARTIFACT_BYTES_HEX {
        blobs.insert(name, hex_bytes(hex)?);
    }
    Ok(blobs)
}

#[test]
fn encoder_reproduces_the_independent_golden_pmf1_byte_for_byte() -> TestResult {
    let blobs = golden_blobs()?;
    let signature = golden_signature()?;
    for licences in [["licence-a", "licence-b"], ["licence-b", "licence-a"]] {
        let unsigned = golden_draft(&blobs, licences)?.unsigned()?;
        let fields = hex_bytes(GOLDEN_UNSIGNED_FIELDS_HEX)?;
        assert_eq!(unsigned.unsigned_bytes(), fields.as_slice());
        let manifest = golden_digest(GOLDEN_UNSIGNED_MANIFEST_DIGEST_HEX)?;
        assert_eq!(unsigned.unsigned_manifest_digest(), manifest);
        let release = golden_digest(GOLDEN_RELEASE_DIGEST_HEX)?;
        assert_eq!(unsigned.release_digest(), release);
        let pmf1 = unsigned.with_signature(GOLDEN_SIGNER_EPOCH, signature)?;
        assert_eq!(pmf1, hex_bytes(GOLDEN_PMF1_HEX)?);
        assert_eq!(digest(&pmf1), golden_digest(GOLDEN_PMF1_DIGEST_HEX)?);
    }
    Ok(())
}

#[test]
fn the_golden_signature_is_the_adr_065_message_signed_by_the_golden_key() -> TestResult {
    let release = golden_digest(GOLDEN_RELEASE_DIGEST_HEX)?;
    let message = role_message(GOLDEN_SIGNER_OWNER, 3, GOLDEN_SIGNER_EPOCH, &release)?;
    assert_eq!(message, hex_bytes(GOLDEN_ROLE_MESSAGE_HEX)?);
    let seed = [GOLDEN_SIGNING_SEED_BYTE; 32];
    let signer = SigningKey::from_bytes(&seed);
    assert_eq!(signer.verifying_key().to_bytes(), publisher_public());
    assert_eq!(
        signer.verifying_key().to_bytes().as_slice(),
        hex_bytes(GOLDEN_SIGNER_PUBLIC_HEX)?.as_slice()
    );
    assert_eq!(signer.sign(&message).to_bytes(), golden_signature()?);
    Ok(())
}

/// Evidence granting `plugin` to `publisher` under exactly `epoch` and `key`.
fn trust_for(plugin: &str, epoch: u64, key: [u8; 32]) -> BoxResult<VerifiedPluginTrustEvidenceV1> {
    let publishers = vec![publisher_entry("publisher", epoch, key)];
    let fields = root_fields(1, None, publishers, vec![grant(plugin, "publisher")]);
    let ptr1 = signed_record(fields, ROOT_SIGNATURE_DOMAIN, &signer())?;
    let anchor = TrustedPluginRootAnchorV1::new("scope", digest(&ptr1))?;
    let prv1 = revocation(digest(&ptr1), 1, None)?;
    Ok(verify_plugin_trust_v1(&anchor, &[&ptr1], &[&prv1], 50, 4)?)
}

fn authorization(
    bundle: &VerifiedReleaseBundleV1,
    evidence: &VerifiedPluginTrustEvidenceV1,
) -> BoxResult<ResolvedPluginTrustAuthorizationV1> {
    let projection = ValidatedPluginManifestProjectionV1::from_verified_bundle(bundle)?;
    Ok(evidence.authorize_release(&projection)?)
}

#[test]
fn the_golden_release_signature_verifies_under_its_resolved_key() -> TestResult {
    let bundle = golden_bundle()?;
    let evidence = trust_for("alpha/plugin", GOLDEN_SIGNER_EPOCH, publisher_public())?;
    let fact = authorization(&bundle, &evidence)?;
    let verified = verify_plugin_release_signature_v1(&bundle, &fact)?;
    assert_eq!(
        verified.pmf1_digest(),
        golden_digest(GOLDEN_PMF1_DIGEST_HEX)?
    );
    assert_eq!(
        verified.release_digest(),
        golden_digest(GOLDEN_RELEASE_DIGEST_HEX)?
    );
    assert_eq!(verified.owner(), owner(GOLDEN_SIGNER_OWNER)?);
    assert_eq!(verified.epoch(), GOLDEN_SIGNER_EPOCH);
    assert_eq!(verified.public_key(), publisher_public());
    assert_eq!(verified.public_key(), fact.resolved_public_key());
    Ok(())
}

// --- Release-signature verification ----------------------------------------

/// The ADR-065 preimage written out byte by byte from the ADR text.
fn role_message(owner: &str, role: u8, epoch: u64, payload: &[u8]) -> BoxResult<Vec<u8>> {
    let mut message = b"pigloros/role-signature/v1".to_vec();
    message.extend_from_slice(&u32::try_from(owner.len())?.to_be_bytes());
    message.extend_from_slice(owner.as_bytes());
    message.push(role);
    message.extend_from_slice(&epoch.to_be_bytes());
    message.extend_from_slice(payload);
    Ok(message)
}

/// An Ed25519 signature by the key whose seed is `[seed; 32]`.
fn ed25519(seed: u8, message: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(&[seed; 32]).sign(message).to_bytes()
}

impl Release {
    /// This release with field 26 set to `[1, 3, epoch, signature]`.
    fn signed_as(&self, epoch: u64, signature: &[u8]) -> BoxResult<Self> {
        let mut release = self.clone();
        let field = list(vec![
            unsigned(1),
            unsigned(3),
            unsigned(epoch),
            Value::Bytes(signature.to_vec()),
        ]);
        release.fields[26] = encode(&field)?;
        Ok(release)
    }

    /// This release honestly signed by the publisher key at `epoch`.
    fn honest(&self, epoch: u64) -> BoxResult<Self> {
        let payload = self.release_digest()?;
        let message = role_message("publisher", 3, epoch, &payload)?;
        self.signed_as(epoch, &ed25519(8, &message))
    }
}

/// Verify `release` under a fact resolved for that same release.
fn verify_own(
    release: &Release,
    evidence: &VerifiedPluginTrustEvidenceV1,
) -> BoxResult<Verification> {
    let bundle = closure(release.pmf1(), &release.members)??;
    let fact = authorization(&bundle, evidence)?;
    Ok(verify_plugin_release_signature_v1(&bundle, &fact))
}

/// Verify `release` under a fact resolved for `authorized`.
fn verify_against(
    release: &Release,
    authorized: &Release,
    evidence: &VerifiedPluginTrustEvidenceV1,
) -> BoxResult<Verification> {
    let fact = authorization(&closure(authorized.pmf1(), &authorized.members)??, evidence)?;
    let bundle = closure(release.pmf1(), &release.members)??;
    Ok(verify_plugin_release_signature_v1(&bundle, &fact))
}

const INVALID_SIGNATURE: Result<VerifiedPluginReleaseSignatureV1, PluginReleaseSignatureErrorV1> =
    Err(PluginReleaseSignatureErrorV1::InvalidSignature);

#[test]
fn an_honest_signature_verifies_at_every_epoch_encoding_width() -> TestResult {
    for epoch in [1, 2, 23, 24, 255, 256, 65_536, 4_294_967_296, u64::MAX] {
        let release = Release::new()?.honest(epoch)?;
        let evidence = trust_for("plugin-a", epoch, publisher_public())?;
        let verified = verify_own(&release, &evidence)??;
        assert_eq!(verified.pmf1_digest(), digest(&release.pmf1()));
        assert_eq!(verified.release_digest(), release.release_digest()?);
        assert_eq!(verified.owner(), owner("publisher")?);
        assert_eq!(verified.epoch(), epoch);
        assert_eq!(verified.public_key(), publisher_public());
    }
    Ok(())
}

#[test]
fn an_encoded_and_signed_release_verifies_end_to_end() -> TestResult {
    let draft = default_draft()?;
    let unsigned = draft.unsigned()?;
    let message = role_message("publisher", 3, 5, &unsigned.release_digest())?;
    let pmf1 = unsigned.with_signature(5, ed25519(8, &message))?;
    let release = Release::new()?;
    let bundle = closure(pmf1, &release.members)??;
    let evidence = trust_for("plugin-a", 5, publisher_public())?;
    let fact = authorization(&bundle, &evidence)?;
    let verified = verify_plugin_release_signature_v1(&bundle, &fact)?;
    assert_eq!(verified.release_digest(), unsigned.release_digest());
    assert_eq!(verified.epoch(), 5);
    Ok(())
}

#[test]
fn the_signature_claim_decodes_from_the_closure_alone() -> TestResult {
    let draft = default_draft()?;
    let unsigned = draft.unsigned()?;
    let signature = ed25519(
        8,
        &role_message("publisher", 3, 5, &unsigned.release_digest())?,
    );
    let pmf1 = unsigned.with_signature(5, signature)?;
    let digest = *blake3::hash(&pmf1).as_bytes();
    let release = Release::new()?;
    let bundle = closure(pmf1.clone(), &release.members)??;
    let claim = decode_plugin_release_signature_claim_v1(&bundle)?;
    assert_eq!(claim.pmf1_digest(), digest);
    assert_eq!(claim.release_digest(), unsigned.release_digest());
    assert_eq!(claim.owner(), OwnerIdV1::new("publisher")?);
    assert_eq!(claim.epoch(), 5);
    assert_eq!(claim.signature(), signature);
    // A claim is not a verification: a wrong signature still decodes.
    let wrong = unsigned.with_signature(5, [0; 64])?;
    let wrong_claim =
        decode_plugin_release_signature_claim_v1(&closure(wrong, &release.members)??)?;
    assert_eq!(wrong_claim.signature(), [0; 64]);
    // A tampered release digest (the last byte of field 27) is a decode error.
    let mut tampered = pmf1;
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let tampered_bundle = closure(tampered, &release.members)??;
    assert!(decode_plugin_release_signature_claim_v1(&tampered_bundle).is_err());
    Ok(())
}

#[test]
fn re_signing_keeps_the_release_digest_and_changes_the_signed_evidence() -> TestResult {
    let base = Release::new()?;
    let first = base.honest(1)?;
    let second = base.honest(2)?;
    let first = verify_own(&first, &trust_for("plugin-a", 1, publisher_public())?)??;
    let second = verify_own(&second, &trust_for("plugin-a", 2, publisher_public())?)??;
    assert_eq!(first.release_digest(), second.release_digest());
    assert_ne!(first.pmf1_digest(), second.pmf1_digest());
    assert_ne!(first.epoch(), second.epoch());
    Ok(())
}

#[test]
fn any_change_to_the_signed_message_fails_verification() -> TestResult {
    let base = Release::new()?;
    let payload = base.release_digest()?;
    let manifest: [u8; 32] = byte_string_field(&base, 25)?
        .try_into()
        .map_err(|_| "field 25 is not 32 bytes")?;
    let evidence = trust_for("plugin-a", 1, publisher_public())?;
    let owner_prefix = "publishe";
    let mut without_length = b"pigloros/role-signature/v1".to_vec();
    without_length.extend_from_slice(b"publisher");
    without_length.push(3);
    without_length.extend_from_slice(&1_u64.to_be_bytes());
    without_length.extend_from_slice(&payload);
    let full = role_message("publisher", 3, 1, &payload)?;
    let without_domain = full["pigloros/role-signature/v1".len()..].to_vec();
    let mut flipped_domain = full;
    flipped_domain[0] ^= 1;
    let messages = [
        role_message("other", 3, 1, &payload)?,
        role_message(owner_prefix, 3, 1, &payload)?,
        role_message("publisher2", 3, 1, &payload)?,
        role_message("Publisher", 3, 1, &payload)?,
        role_message("publisher", 0, 1, &payload)?,
        role_message("publisher", 2, 1, &payload)?,
        role_message("publisher", 4, 1, &payload)?,
        role_message("publisher", 3, 0, &payload)?,
        role_message("publisher", 3, 2, &payload)?,
        role_message("publisher", 3, 256, &payload)?,
        role_message("publisher", 3, 1, &manifest)?,
        role_message("publisher", 3, 1, &payload[..31])?,
        role_message("publisher", 3, 1, &[payload.as_slice(), &[0]].concat())?,
        role_message("publisher", 3, 1, &[0; 32])?,
        role_message("publisher", 3, 1, &digest(&payload))?,
        without_length,
        without_domain,
        flipped_domain,
    ];
    for (index, message) in messages.iter().enumerate() {
        let release = base.signed_as(1, &ed25519(8, message))?;
        assert_eq!(
            verify_own(&release, &evidence)?,
            INVALID_SIGNATURE,
            "message {index}"
        );
    }
    let control = role_message("publisher", 3, 1, &payload)?;
    let honest = base.signed_as(1, &ed25519(8, &control))?;
    assert!(verify_own(&honest, &evidence)?.is_ok());
    let wrong_key = base.signed_as(1, &ed25519(9, &control))?;
    assert_eq!(verify_own(&wrong_key, &evidence)?, INVALID_SIGNATURE);
    Ok(())
}

/// The content of byte-string field `ordinal` of `release`.
fn byte_string_field(release: &Release, ordinal: usize) -> BoxResult<Vec<u8>> {
    let value: Value = ciborium::from_reader(release.fields[ordinal].as_slice())?;
    Ok(value.as_bytes().ok_or("not a byte string")?.clone())
}

#[test]
fn a_signature_by_another_epoch_owner_or_key_is_not_accepted() -> TestResult {
    let base = Release::new()?;
    let payload = base.release_digest()?;
    let message = role_message("publisher", 3, 2, &payload)?;
    let signed_for_two = base.signed_as(1, &ed25519(8, &message))?;
    let evidence = trust_for("plugin-a", 1, publisher_public())?;
    assert_eq!(verify_own(&signed_for_two, &evidence)?, INVALID_SIGNATURE);
    let for_epoch_one = role_message("publisher", 3, 1, &payload)?;
    let signed_for_one = base.signed_as(2, &ed25519(8, &for_epoch_one))?;
    let evidence = trust_for("plugin-a", 2, publisher_public())?;
    assert_eq!(verify_own(&signed_for_one, &evidence)?, INVALID_SIGNATURE);
    let other_key = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    let evidence = trust_for("plugin-a", 1, other_key)?;
    let honest = base.honest(1)?;
    assert_eq!(verify_own(&honest, &evidence)?, INVALID_SIGNATURE);
    Ok(())
}

#[test]
fn every_flipped_signature_bit_and_degenerate_signature_fails() -> TestResult {
    let base = Release::new()?;
    let payload = base.release_digest()?;
    let signature = ed25519(8, &role_message("publisher", 3, 1, &payload)?);
    let evidence = trust_for("plugin-a", 1, publisher_public())?;
    for index in [0, 1, 31, 32, 33, 62, 63] {
        for bit in [0x01, 0x80] {
            let mut tampered = signature;
            tampered[index] ^= bit;
            let release = base.signed_as(1, &tampered)?;
            assert_eq!(
                verify_own(&release, &evidence)?,
                INVALID_SIGNATURE,
                "{index}/{bit}"
            );
        }
    }
    for degenerate in [[0; 64], [0xff; 64], [0x5a; 64]] {
        let release = base.signed_as(1, &degenerate)?;
        assert_eq!(verify_own(&release, &evidence)?, INVALID_SIGNATURE);
    }
    Ok(())
}

#[test]
fn an_authorization_for_other_pmf1_bytes_is_rejected_before_the_signature() -> TestResult {
    let base = Release::new()?;
    let authorized = base.honest(1)?;
    let evidence = trust_for("plugin-a", 1, publisher_public())?;
    let mismatch = Err(PluginReleaseSignatureErrorV1::AuthorizationMismatch);
    let resigned = base.honest(2)?;
    assert_eq!(verify_against(&resigned, &authorized, &evidence)?, mismatch);
    let unsigned = base.signed_as(1, &[0; 64])?;
    assert_eq!(verify_against(&unsigned, &authorized, &evidence)?, mismatch);
    let changed = Release::sealed_with(3, &text("1.0.1"))?.honest(1)?;
    assert_eq!(verify_against(&changed, &authorized, &evidence)?, mismatch);
    assert!(verify_against(&authorized, &authorized, &evidence)?.is_ok());
    Ok(())
}

#[test]
fn a_bundle_that_fails_decoding_yields_the_decoder_error_not_a_verdict() -> TestResult {
    let base = Release::new()?.honest(1)?;
    let evidence = trust_for("plugin-a", 1, publisher_public())?;
    let wrong_shape = |value: Value| -> BoxResult<Release> { Release::with(26, &value) };
    let descriptor = |algorithm: u64, role: u64, epoch: u64, signature: Value| {
        list(vec![
            unsigned(algorithm),
            unsigned(role),
            unsigned(epoch),
            signature,
        ])
    };
    let unsigned_mismatch = PluginManifestErrorV1::UnsignedManifestDigestMismatch;
    let mut cases = vec![
        (Release::with(2, &text("plugin-a2"))?, unsigned_mismatch),
        (
            Release::with(1, &unsigned(2))?,
            PluginManifestErrorV1::UnsupportedVersion,
        ),
        (wrong_shape(Value::Null)?, encoding(26)),
        (
            wrong_shape(descriptor(1, 3, 1, Value::Bytes(vec![0; 63])))?,
            encoding(26),
        ),
        (
            wrong_shape(descriptor(1, 3, 1, Value::Bytes(vec![0; 65])))?,
            encoding(26),
        ),
        (wrong_shape(descriptor(1, 3, 1, Value::Null))?, encoding(26)),
        (
            wrong_shape(descriptor(2, 3, 1, Value::Bytes(vec![0; 64])))?,
            invalid(26),
        ),
        (
            wrong_shape(descriptor(1, 2, 1, Value::Bytes(vec![0; 64])))?,
            invalid(26),
        ),
        (
            wrong_shape(descriptor(1, 3, 0, Value::Bytes(vec![0; 64])))?,
            invalid(26),
        ),
    ];
    let mut digest_changed = base.clone();
    digest_changed.fields[27] = encode(&bytes([0; 32]))?;
    cases.push((digest_changed, PluginManifestErrorV1::ReleaseDigestMismatch));
    let mut component_changed = base.clone();
    component_changed.members[0] = Member::new(Role::Component, b"\0asm other");
    cases.push((component_changed, mismatch(0)));
    for (index, (release, error)) in cases.into_iter().enumerate() {
        let verdict = verify_against(&release, &base, &evidence);
        let expected = Err(PluginReleaseSignatureErrorV1::Manifest(error));
        assert_eq!(verdict?, expected, "case {index}");
    }
    Ok(())
}

#[test]
fn the_component_digest_is_the_domain_separated_length_prefixed_blake3() {
    let domain = b"PiglorOS.Plugin.Component.v1\0";
    for bytes in [&b""[..], b"\0asm component", &[0xa5; 300]] {
        assert_eq!(component_digest_v1(bytes), domain_digest(domain, bytes));
    }
}
