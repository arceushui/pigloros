use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest as _, Sha256};

const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const ARTIFACT_TYPE: &str = "application/vnd.pigloros.plugin.release.v1";
const EMPTY_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.empty.v1+json";
const EMPTY_CONFIG_DIGEST: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
const EMPTY_CONFIG_BYTES: &[u8] = b"{}";
const MAX_MANIFEST_BYTES: usize = crate::MAX_JCS_BYTES;
const MAX_BLOB_BYTES: usize = 32 * 1024 * 1024;
pub(super) const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_STORED_BLOBS: usize = 359;
const MAX_SCHEMAS: usize = 256;
const MAX_LICENCES: usize = 32;
const MAX_MIGRATION_FIXTURES: usize = 64;

/// An immutable OCI manifest descriptor, without mutable tags or locations.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BundleAddressV1 {
    digest: String,
    size: u64,
}

impl BundleAddressV1 {
    /// Create one validated V1 OCI manifest address.
    ///
    /// # Errors
    /// Returns `InvalidAddress` when the descriptor is not the exact V1
    /// manifest address grammar.
    pub fn new(digest: String, size: u64) -> Result<Self, ReleaseSourceErrorV1> {
        if !valid_sha256_digest(&digest)
            || size == 0
            || usize::try_from(size).map_or(true, |size| size > MAX_MANIFEST_BYTES)
        {
            return Err(ReleaseSourceErrorV1::InvalidAddress);
        }
        Ok(Self { digest, size })
    }

    /// Return the fixed OCI manifest media type.
    #[must_use]
    pub const fn media_type(&self) -> &'static str {
        MANIFEST_MEDIA_TYPE
    }

    /// Return the validated lowercase OCI digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Return the exact manifest byte size.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }
}

/// One descriptor-addressed byte member in a verified release closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobV1 {
    digest: String,
    bytes: Vec<u8>,
}

impl BlobV1 {
    /// Return the OCI digest of these verified bytes.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Return the immutable verified bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A verified ordered OCI layer descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleMemberV1 {
    member: String,
    media_type: String,
    digest: String,
    size: u64,
}

impl BundleMemberV1 {
    /// Return the exact OCI member annotation.
    #[must_use]
    pub fn member(&self) -> &str {
        &self.member
    }

    /// Return the exact registered media type.
    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Return the layer digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Return the descriptor byte size.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }
}

/// A complete, validated OCI closure available to any release source consumer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedReleaseBundleV1 {
    address: BundleAddressV1,
    manifest: BlobV1,
    blobs: Vec<BlobV1>,
    members: Vec<BundleMemberV1>,
}

impl VerifiedReleaseBundleV1 {
    /// Return the immutable transport address.
    #[must_use]
    pub const fn address(&self) -> &BundleAddressV1 {
        &self.address
    }

    /// Return the exact JCS manifest bytes.
    #[must_use]
    pub fn manifest(&self) -> &[u8] {
        self.manifest.bytes()
    }

    /// Return all non-manifest blobs in digest order.
    #[must_use]
    pub fn blobs(&self) -> &[BlobV1] {
        &self.blobs
    }

    /// Return the layer descriptors in their required semantic order.
    #[must_use]
    pub fn members(&self) -> &[BundleMemberV1] {
        &self.members
    }
}

/// A source-neutral verified release reader.
pub trait ReleaseSourceV1 {
    /// Read one complete verified transport closure.
    ///
    /// # Errors
    /// Returns a closed transport error without exposing a partial bundle.
    fn read_verified(
        &self,
        address: &BundleAddressV1,
    ) -> Result<VerifiedReleaseBundleV1, ReleaseSourceErrorV1>;
}

/// Closed failures for a release source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReleaseSourceErrorV1 {
    #[error("release address is invalid")]
    InvalidAddress,
    #[error("release was not found")]
    NotFound,
    #[error("release exceeds a V1 resource bound")]
    BoundsExceeded,
    #[error("release layout is invalid")]
    InvalidLayout,
    #[error("release descriptor is invalid")]
    InvalidDescriptor,
    #[error("release digest does not match its bytes")]
    DigestMismatch,
    #[error("release descriptor size does not match its bytes")]
    SizeMismatch,
    #[error("release closure contains a duplicate member")]
    DuplicateMember,
    #[error("release member media type is unsupported")]
    UnsupportedMediaType,
    #[error("release is not durably committed")]
    Uncommitted,
    #[error("release I/O failed")]
    Io,
    #[error("release lock is unavailable")]
    LockUnavailable,
    #[error("release recovery is required")]
    RecoveryRequired,
}

/// Verify one OCI artifact manifest and all descriptor-addressed bytes.
///
/// `manifest` and every supplied blob must be exactly the descriptor bytes;
/// callers cannot provide URLs, tags, paths, or PMF1 semantics through this
/// API.
///
/// # Errors
/// Returns a closed error before constructing a partial verified bundle.
pub fn verify_oci_closure_v1(
    address: BundleAddressV1,
    manifest: Vec<u8>,
    mut supplied_blobs: BTreeMap<String, Vec<u8>>,
) -> Result<VerifiedReleaseBundleV1, ReleaseSourceErrorV1> {
    if manifest.len() > MAX_MANIFEST_BYTES {
        return Err(ReleaseSourceErrorV1::BoundsExceeded);
    }
    verify_descriptor_bytes(&address.digest, address.size, &manifest)?;
    let value = crate::parse_jcs_object(&manifest)?;
    let object = value
        .as_object()
        .ok_or(ReleaseSourceErrorV1::InvalidDescriptor)?;
    require_keys(
        object,
        &[
            "artifactType",
            "config",
            "layers",
            "mediaType",
            "schemaVersion",
        ],
    )?;
    if object
        .get("artifactType")
        .and_then(serde_json::Value::as_str)
        != Some(ARTIFACT_TYPE)
        || object.get("mediaType").and_then(serde_json::Value::as_str) != Some(MANIFEST_MEDIA_TYPE)
        || object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_u64)
            != Some(2)
    {
        return Err(ReleaseSourceErrorV1::InvalidDescriptor);
    }
    let config = object
        .get("config")
        .and_then(serde_json::Value::as_object)
        .ok_or(ReleaseSourceErrorV1::InvalidDescriptor)?;
    require_keys(config, &["digest", "mediaType", "size"])?;
    if config.get("digest").and_then(serde_json::Value::as_str) != Some(EMPTY_CONFIG_DIGEST)
        || config.get("mediaType").and_then(serde_json::Value::as_str)
            != Some(EMPTY_CONFIG_MEDIA_TYPE)
        || config.get("size").and_then(serde_json::Value::as_u64) != Some(2)
    {
        return Err(ReleaseSourceErrorV1::InvalidDescriptor);
    }
    let mut expected = BTreeMap::new();
    expected.insert(EMPTY_CONFIG_DIGEST.to_owned(), 2_u64);
    let layers = object
        .get("layers")
        .and_then(serde_json::Value::as_array)
        .ok_or(ReleaseSourceErrorV1::InvalidDescriptor)?;
    let members = parse_layers(layers, &mut expected)?;
    if expected.len() + 1 > MAX_STORED_BLOBS
        || supplied_blobs.len() != expected.len()
        || supplied_blobs
            .keys()
            .any(|digest| !expected.contains_key(digest))
    {
        return Err(ReleaseSourceErrorV1::BoundsExceeded);
    }
    let mut blobs = Vec::with_capacity(expected.len());
    for (digest, size) in expected {
        let bytes = supplied_blobs
            .remove(&digest)
            .ok_or(ReleaseSourceErrorV1::NotFound)?;
        if bytes.len() > MAX_BLOB_BYTES {
            return Err(ReleaseSourceErrorV1::BoundsExceeded);
        }
        verify_descriptor_bytes(&digest, size, &bytes)?;
        if digest == EMPTY_CONFIG_DIGEST && bytes != EMPTY_CONFIG_BYTES {
            return Err(ReleaseSourceErrorV1::DigestMismatch);
        }
        blobs.push(BlobV1 { digest, bytes });
    }
    if blobs.iter().map(|blob| blob.bytes.len()).sum::<usize>() + manifest.len() > MAX_TOTAL_BYTES {
        return Err(ReleaseSourceErrorV1::BoundsExceeded);
    }
    Ok(VerifiedReleaseBundleV1 {
        manifest: BlobV1 {
            digest: address.digest.clone(),
            bytes: manifest,
        },
        address,
        blobs,
        members,
    })
}

fn parse_layers(
    layers: &[serde_json::Value],
    expected: &mut BTreeMap<String, u64>,
) -> Result<Vec<BundleMemberV1>, ReleaseSourceErrorV1> {
    let mut members = Vec::with_capacity(layers.len());
    let mut roles = BTreeMap::<String, usize>::new();
    let mut seen_digests = BTreeSet::new();
    for layer in layers {
        let object = layer
            .as_object()
            .ok_or(ReleaseSourceErrorV1::InvalidDescriptor)?;
        require_keys(object, &["annotations", "digest", "mediaType", "size"])?;
        let annotations = object
            .get("annotations")
            .and_then(serde_json::Value::as_object)
            .ok_or(ReleaseSourceErrorV1::InvalidDescriptor)?;
        require_keys(annotations, &["org.pigloros.plugin.member"])?;
        let member = annotations
            .get("org.pigloros.plugin.member")
            .and_then(serde_json::Value::as_str)
            .ok_or(ReleaseSourceErrorV1::InvalidDescriptor)?;
        let digest = object
            .get("digest")
            .and_then(serde_json::Value::as_str)
            .ok_or(ReleaseSourceErrorV1::InvalidDescriptor)?;
        let media_type = object
            .get("mediaType")
            .and_then(serde_json::Value::as_str)
            .ok_or(ReleaseSourceErrorV1::InvalidDescriptor)?;
        let size = object
            .get("size")
            .and_then(serde_json::Value::as_u64)
            .ok_or(ReleaseSourceErrorV1::InvalidDescriptor)?;
        if size == 0
            || usize::try_from(size).map_or(true, |size| size > MAX_BLOB_BYTES)
            || !valid_sha256_digest(digest)
        {
            return Err(ReleaseSourceErrorV1::InvalidDescriptor);
        }
        if !seen_digests.insert(digest.to_owned()) {
            return Err(ReleaseSourceErrorV1::DuplicateMember);
        }
        let role = layer_role(member, digest, media_type)?;
        *roles.entry(role.to_owned()).or_default() += 1;
        if expected.insert(digest.to_owned(), size).is_some() {
            return Err(ReleaseSourceErrorV1::DuplicateMember);
        }
        members.push(BundleMemberV1 {
            member: member.to_owned(),
            media_type: media_type.to_owned(),
            digest: digest.to_owned(),
            size,
        });
    }
    validate_layer_order_and_counts(&members, &roles)?;
    Ok(members)
}

fn layer_role<'a>(
    member: &'a str,
    digest: &str,
    media_type: &str,
) -> Result<&'a str, ReleaseSourceErrorV1> {
    let fixed = match member {
        "pmf1" => Some(("pmf1", "application/vnd.pigloros.plugin.manifest.v1+cbor")),
        "component" => Some((
            "component",
            "application/vnd.pigloros.plugin.component.v1+wasm",
        )),
        "wit" => Some(("wit", "application/vnd.pigloros.plugin.wit.v1+tar")),
        "provenance" => Some(("provenance", "application/vnd.in-toto+json")),
        "sbom" => Some(("sbom", "application/spdx+json")),
        _ => None,
    };
    if let Some((role, required_media_type)) = fixed {
        return if media_type == required_media_type {
            Ok(role)
        } else {
            Err(ReleaseSourceErrorV1::UnsupportedMediaType)
        };
    }
    for (prefix, role, required_media_type) in [
        (
            "schema/",
            "schema",
            "application/vnd.pigloros.plugin.schema.v1+json",
        ),
        ("licence/", "licence", "text/plain; charset=utf-8"),
        (
            "migration-fixture/",
            "migration-fixture",
            "application/vnd.pigloros.plugin.migration-fixture.v1+cbor",
        ),
    ] {
        if let Some(suffix) = member.strip_prefix(prefix) {
            return if suffix == &digest["sha256:".len()..] && media_type == required_media_type {
                Ok(role)
            } else {
                Err(ReleaseSourceErrorV1::InvalidDescriptor)
            };
        }
    }
    Err(ReleaseSourceErrorV1::InvalidDescriptor)
}

fn validate_layer_order_and_counts(
    members: &[BundleMemberV1],
    roles: &BTreeMap<String, usize>,
) -> Result<(), ReleaseSourceErrorV1> {
    for role in ["pmf1", "component", "wit", "provenance", "sbom"] {
        if roles.get(role) != Some(&1) {
            return Err(ReleaseSourceErrorV1::InvalidDescriptor);
        }
    }
    if !(1..=MAX_LICENCES).contains(roles.get("licence").unwrap_or(&0))
        || roles.get("schema").copied().unwrap_or(0) > MAX_SCHEMAS
        || roles.get("migration-fixture").copied().unwrap_or(0) > MAX_MIGRATION_FIXTURES
    {
        return Err(ReleaseSourceErrorV1::BoundsExceeded);
    }
    let ranks = members
        .iter()
        .map(|member| layer_role(&member.member, &member.digest, &member.media_type).map(rank))
        .collect::<Result<Vec<_>, _>>()?;
    if !ranks.windows(2).all(|pair| pair[0] <= pair[1]) {
        return Err(ReleaseSourceErrorV1::InvalidDescriptor);
    }
    for window in members.windows(2) {
        let left = layer_role(&window[0].member, &window[0].digest, &window[0].media_type)?;
        let right = layer_role(&window[1].member, &window[1].digest, &window[1].media_type)?;
        if left == right && left != "pmf1" && window[0].digest >= window[1].digest {
            return Err(ReleaseSourceErrorV1::InvalidDescriptor);
        }
    }
    Ok(())
}

fn rank(role: &str) -> u8 {
    match role {
        "pmf1" => 0,
        "component" => 1,
        "wit" => 2,
        "schema" => 3,
        "provenance" => 4,
        "sbom" => 5,
        "licence" => 6,
        "migration-fixture" => 7,
        _ => u8::MAX,
    }
}

fn verify_descriptor_bytes(
    digest: &str,
    size: u64,
    bytes: &[u8],
) -> Result<(), ReleaseSourceErrorV1> {
    if bytes.len() as u64 != size {
        return Err(ReleaseSourceErrorV1::SizeMismatch);
    }
    if sha256_digest(bytes) != digest {
        return Err(ReleaseSourceErrorV1::DigestMismatch);
    }
    Ok(())
}

fn require_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Result<(), ReleaseSourceErrorV1> {
    if object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key)) {
        Ok(())
    } else {
        Err(ReleaseSourceErrorV1::InvalidDescriptor)
    }
}

fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value["sha256:".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::from("sha256:");
    for byte in Sha256::digest(bytes) {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(bytes: &[u8]) -> String {
        sha256_digest(bytes)
    }

    fn layer(member: &str, media_type: &str, bytes: &[u8]) -> serde_json::Value {
        let digest = digest(bytes);
        serde_json::json!({
            "annotations": {"org.pigloros.plugin.member": member},
            "digest": digest,
            "mediaType": media_type,
            "size": bytes.len(),
        })
    }

    type ClosureFixture = (BundleAddressV1, Vec<u8>, BTreeMap<String, Vec<u8>>);

    fn closure() -> Result<ClosureFixture, Box<dyn std::error::Error>> {
        let pmf1 = b"pmf1".to_vec();
        let component = b"component".to_vec();
        let wit = b"wit".to_vec();
        let provenance = b"provenance".to_vec();
        let sbom = b"sbom".to_vec();
        let licence = b"licence".to_vec();
        let licence_digest = digest(&licence);
        let layers = vec![
            layer(
                "pmf1",
                "application/vnd.pigloros.plugin.manifest.v1+cbor",
                &pmf1,
            ),
            layer(
                "component",
                "application/vnd.pigloros.plugin.component.v1+wasm",
                &component,
            ),
            layer("wit", "application/vnd.pigloros.plugin.wit.v1+tar", &wit),
            layer("provenance", "application/vnd.in-toto+json", &provenance),
            layer("sbom", "application/spdx+json", &sbom),
            layer(
                &format!("licence/{}", &licence_digest[7..]),
                "text/plain; charset=utf-8",
                &licence,
            ),
        ];
        let manifest = serde_json::to_vec(&serde_json::json!({
            "artifactType": ARTIFACT_TYPE,
            "config": {"digest": EMPTY_CONFIG_DIGEST, "mediaType": EMPTY_CONFIG_MEDIA_TYPE, "size": 2},
            "layers": layers,
            "mediaType": MANIFEST_MEDIA_TYPE,
            "schemaVersion": 2,
        }))?;
        let address = BundleAddressV1::new(digest(&manifest), manifest.len() as u64)?;
        let mut blobs = BTreeMap::new();
        for bytes in [
            EMPTY_CONFIG_BYTES.to_vec(),
            pmf1,
            component,
            wit,
            provenance,
            sbom,
            licence,
        ] {
            blobs.insert(digest(&bytes), bytes);
        }
        Ok((address, manifest, blobs))
    }

    #[test]
    fn verifies_complete_public_oci_closure() -> Result<(), Box<dyn std::error::Error>> {
        let (address, manifest, blobs) = closure()?;
        let verified = verify_oci_closure_v1(address.clone(), manifest, blobs)?;
        assert_eq!(verified.address(), &address);
        assert_eq!(verified.members().len(), 6);
        assert_eq!(verified.blobs().len(), 7);
        assert_eq!(verified.manifest().len() as u64, address.size());
        for blob in verified.blobs() {
            assert_eq!(sha256_digest(blob.bytes()), blob.digest());
        }
        for member in verified.members() {
            assert!(!member.member().is_empty());
            assert!(!member.media_type().is_empty());
            assert!(member.digest().starts_with("sha256:"));
            assert!(member.size() > 0);
        }
        Ok(())
    }

    fn verify_value(
        value: &serde_json::Value,
        blobs: BTreeMap<String, Vec<u8>>,
    ) -> Result<VerifiedReleaseBundleV1, ReleaseSourceErrorV1> {
        let manifest =
            serde_json::to_vec(value).map_err(|_| ReleaseSourceErrorV1::InvalidDescriptor)?;
        let address = BundleAddressV1::new(digest(&manifest), manifest.len() as u64)?;
        verify_oci_closure_v1(address, manifest, blobs)
    }

    #[test]
    fn rejects_malformed_public_manifest_json() -> Result<(), Box<dyn std::error::Error>> {
        for manifest in [
            b"0".as_slice(),
            b"true",
            b"false",
            b"null",
            b"[]",
            b"{}",
            b"{\"x\":1,\"x\":2}",
            b"{\"x\":}",
            b"{\"x\":1,}",
            b"{\"x\" 1}",
            b"{\"x\":\"\\q\"}",
            b"{\"x\":\"bad\n\"}",
            b"{\"x\":\"unfinished",
            b"{\"x\":tru}",
            b"{\"x\":flse}",
            b"{\"x\":nul}",
            b"{\"x\":01}",
            b"{\"x\":+1}",
            b"{\"x\":[1,2]}",
            b"{\"x\":[]}",
            b"{\"x\":{}}",
            b"{}x",
            b" { } ",
        ] {
            let address = BundleAddressV1::new(digest(manifest), manifest.len() as u64)?;
            assert_eq!(
                verify_oci_closure_v1(address, manifest.to_vec(), BTreeMap::new()),
                Err(ReleaseSourceErrorV1::InvalidDescriptor),
                "{manifest:?}"
            );
        }
        let invalid_utf8 = b"{\"x\":\"\xff\"}";
        let address = BundleAddressV1::new(digest(invalid_utf8), invalid_utf8.len() as u64)?;
        assert_eq!(
            verify_oci_closure_v1(address, invalid_utf8.to_vec(), BTreeMap::new()),
            Err(ReleaseSourceErrorV1::InvalidDescriptor)
        );
        Ok(())
    }

    #[test]
    fn rejects_wrong_top_level_and_config_descriptors() -> Result<(), Box<dyn std::error::Error>> {
        let (_, manifest, blobs) = closure()?;
        let valid: serde_json::Value = serde_json::from_slice(&manifest)?;
        for (field, bad) in [
            ("artifactType", serde_json::json!("other")),
            ("mediaType", serde_json::json!("other")),
            ("schemaVersion", serde_json::json!(3)),
            ("config", serde_json::json!([])),
            ("layers", serde_json::json!({})),
        ] {
            let mut changed = valid.clone();
            changed[field] = bad;
            assert_eq!(
                verify_value(&changed, blobs.clone()),
                Err(ReleaseSourceErrorV1::InvalidDescriptor),
                "{field}"
            );
        }
        let mut changed = valid.clone();
        changed["extra"] = serde_json::json!(true);
        assert_eq!(
            verify_value(&changed, blobs.clone()),
            Err(ReleaseSourceErrorV1::InvalidDescriptor)
        );
        for (field, bad) in [
            ("digest", serde_json::json!("sha256:bad")),
            ("mediaType", serde_json::json!("wrong")),
            ("size", serde_json::json!(3)),
        ] {
            let mut changed = valid.clone();
            changed["config"][field] = bad;
            assert_eq!(
                verify_value(&changed, blobs.clone()),
                Err(ReleaseSourceErrorV1::InvalidDescriptor),
                "{field}"
            );
        }
        let mut changed = valid;
        changed["config"]["extra"] = serde_json::json!(true);
        assert_eq!(
            verify_value(&changed, blobs),
            Err(ReleaseSourceErrorV1::InvalidDescriptor)
        );
        Ok(())
    }

    #[test]
    fn rejects_invalid_layer_shapes_and_order() -> Result<(), Box<dyn std::error::Error>> {
        let (_, manifest, blobs) = closure()?;
        let valid: serde_json::Value = serde_json::from_slice(&manifest)?;
        let bad_first_layers = [
            serde_json::json!(null),
            serde_json::json!({"digest": digest(b"pmf1")}),
            serde_json::json!({"annotations": [], "digest": digest(b"pmf1"), "mediaType": "x", "size": 4}),
            serde_json::json!({"annotations": {}, "digest": digest(b"pmf1"), "mediaType": "x", "size": 4}),
        ];
        for bad in bad_first_layers {
            let mut changed = valid.clone();
            changed["layers"][0] = bad;
            assert_eq!(
                verify_value(&changed, blobs.clone()),
                Err(ReleaseSourceErrorV1::InvalidDescriptor)
            );
        }
        for (field, bad) in [
            ("digest", serde_json::json!(42)),
            ("digest", serde_json::json!("sha256:bad")),
            ("mediaType", serde_json::json!(42)),
            ("size", serde_json::json!(-1)),
            ("size", serde_json::json!(0)),
            ("size", serde_json::json!(MAX_BLOB_BYTES + 1)),
        ] {
            let mut changed = valid.clone();
            changed["layers"][0][field] = bad;
            assert_eq!(
                verify_value(&changed, blobs.clone()),
                Err(ReleaseSourceErrorV1::InvalidDescriptor),
                "{field}"
            );
        }
        for (member, media_type) in [
            (
                "unknown",
                "application/vnd.pigloros.plugin.manifest.v1+cbor",
            ),
            ("pmf1", "wrong"),
            ("licence/wrong", "text/plain; charset=utf-8"),
        ] {
            let mut changed = valid.clone();
            changed["layers"][0]["annotations"]["org.pigloros.plugin.member"] =
                serde_json::json!(member);
            changed["layers"][0]["mediaType"] = serde_json::json!(media_type);
            let expected = if member == "pmf1" {
                ReleaseSourceErrorV1::UnsupportedMediaType
            } else {
                ReleaseSourceErrorV1::InvalidDescriptor
            };
            assert_eq!(verify_value(&changed, blobs.clone()), Err(expected));
        }
        let mut changed = valid.clone();
        changed["layers"][0]["annotations"]["org.pigloros.plugin.member"] = serde_json::json!(5);
        assert_eq!(
            verify_value(&changed, blobs.clone()),
            Err(ReleaseSourceErrorV1::InvalidDescriptor)
        );
        let mut changed = valid.clone();
        changed["layers"][0]["annotations"]["extra"] = serde_json::json!(true);
        assert_eq!(
            verify_value(&changed, blobs.clone()),
            Err(ReleaseSourceErrorV1::InvalidDescriptor)
        );
        let mut changed = valid.clone();
        changed["layers"][0]["extra"] = serde_json::json!(true);
        assert_eq!(
            verify_value(&changed, blobs.clone()),
            Err(ReleaseSourceErrorV1::InvalidDescriptor)
        );
        let mut changed = valid.clone();
        let duplicate_digest = changed["layers"][0]["digest"].clone();
        changed["layers"][1]["digest"] = duplicate_digest;
        assert_eq!(
            verify_value(&changed, blobs.clone()),
            Err(ReleaseSourceErrorV1::DuplicateMember)
        );
        let mut changed = valid.clone();
        changed["layers"]
            .as_array_mut()
            .ok_or("fixture layers")?
            .swap(0, 1);
        assert_eq!(
            verify_value(&changed, blobs.clone()),
            Err(ReleaseSourceErrorV1::InvalidDescriptor)
        );
        let mut changed = valid.clone();
        changed["layers"]
            .as_array_mut()
            .ok_or("fixture layers")?
            .remove(0);
        assert_eq!(
            verify_value(&changed, blobs.clone()),
            Err(ReleaseSourceErrorV1::InvalidDescriptor)
        );
        let mut changed = valid;
        changed["layers"]
            .as_array_mut()
            .ok_or("fixture layers")?
            .pop();
        assert_eq!(
            verify_value(&changed, blobs),
            Err(ReleaseSourceErrorV1::BoundsExceeded)
        );
        Ok(())
    }

    #[test]
    fn rejects_mismatched_public_descriptor_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let (address, manifest, blobs) = closure()?;
        let shorter = BundleAddressV1::new(address.digest().to_owned(), address.size() - 1)?;
        assert_eq!(
            verify_oci_closure_v1(shorter, manifest.clone(), blobs.clone()),
            Err(ReleaseSourceErrorV1::SizeMismatch)
        );
        let wrong_digest =
            BundleAddressV1::new(format!("sha256:{}", "0".repeat(64)), address.size())?;
        assert_eq!(
            verify_oci_closure_v1(wrong_digest, manifest.clone(), blobs.clone()),
            Err(ReleaseSourceErrorV1::DigestMismatch)
        );
        let oversized = vec![b'0'; MAX_MANIFEST_BYTES + 1];
        assert_eq!(
            verify_oci_closure_v1(address.clone(), oversized, blobs.clone()),
            Err(ReleaseSourceErrorV1::BoundsExceeded)
        );
        let mut extra = blobs.clone();
        extra.insert(digest(b"extra"), b"extra".to_vec());
        assert_eq!(
            verify_oci_closure_v1(address.clone(), manifest.clone(), extra),
            Err(ReleaseSourceErrorV1::BoundsExceeded)
        );
        let mut wrong_size = blobs.clone();
        let member = digest(b"component");
        wrong_size.insert(member.clone(), b"short".to_vec());
        assert_eq!(
            verify_oci_closure_v1(address.clone(), manifest.clone(), wrong_size),
            Err(ReleaseSourceErrorV1::SizeMismatch)
        );
        let mut wrong_digest = blobs;
        wrong_digest.insert(member, b"xxxxxxxxx".to_vec());
        assert_eq!(
            verify_oci_closure_v1(address, manifest, wrong_digest),
            Err(ReleaseSourceErrorV1::DigestMismatch)
        );
        Ok(())
    }

    #[test]
    fn accepts_ordered_schema_and_migration_members() -> Result<(), Box<dyn std::error::Error>> {
        let (_, manifest, mut blobs) = closure()?;
        let mut value: serde_json::Value = serde_json::from_slice(&manifest)?;
        let schema = b"schema".to_vec();
        let migration = b"migration".to_vec();
        let schema_digest = digest(&schema);
        let migration_digest = digest(&migration);
        value["layers"]
            .as_array_mut()
            .ok_or("fixture layers")?
            .insert(
                3,
                layer(
                    &format!("schema/{}", &schema_digest[7..]),
                    "application/vnd.pigloros.plugin.schema.v1+json",
                    &schema,
                ),
            );
        value["layers"]
            .as_array_mut()
            .ok_or("fixture layers")?
            .push(layer(
                &format!("migration-fixture/{}", &migration_digest[7..]),
                "application/vnd.pigloros.plugin.migration-fixture.v1+cbor",
                &migration,
            ));
        blobs.insert(schema_digest, schema);
        blobs.insert(migration_digest, migration);
        let verified = verify_value(&value, blobs)?;
        assert_eq!(verified.members().len(), 8);
        Ok(())
    }

    #[test]
    fn rejects_missing_closure_blob() -> Result<(), Box<dyn std::error::Error>> {
        let (address, manifest, mut blobs) = closure()?;
        let removed = blobs.keys().next().cloned().ok_or("no fixture blob")?;
        blobs.remove(&removed);
        assert_eq!(
            verify_oci_closure_v1(address, manifest, blobs),
            Err(ReleaseSourceErrorV1::BoundsExceeded)
        );
        Ok(())
    }

    #[test]
    fn rejects_noncanonical_address() {
        assert_eq!(
            BundleAddressV1::new("sha256:ABC".to_owned(), 1),
            Err(ReleaseSourceErrorV1::InvalidAddress)
        );
    }
}
