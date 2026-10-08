//! The producer half of the ADR-102 OCI closure: the inverse of
//! [`verify_oci_closure_v1()`].
//!
//! The builder lays the supplied role-labelled byte strings out in the exact
//! layer order, annotations, media types and canonical JSON the verifier
//! accepts, then hands the result to [`verify_oci_closure_v1()`]. A closure
//! is therefore returned only if the verifier accepted it, so a closure the
//! verifier would reject cannot be built. The builder knows no PMF1 semantics:
//! `pmf1` is one opaque layer.

use std::collections::BTreeMap;

use crate::oci::{
    verify_oci_closure_v1, BundleAddressV1, ReleaseSourceErrorV1, VerifiedReleaseBundleV1,
};
use crate::{
    sha256_digest, ARTIFACT_TYPE, COMPONENT_MEDIA_TYPE, EMPTY_CONFIG_BYTES, EMPTY_CONFIG_DIGEST,
    EMPTY_CONFIG_MEDIA_TYPE, LICENCE_MEDIA_TYPE, MANIFEST_MEDIA_TYPE, MIGRATION_FIXTURE_MEDIA_TYPE,
    PMF1_MEDIA_TYPE, PROVENANCE_MEDIA_TYPE, SBOM_MEDIA_TYPE, SCHEMA_MEDIA_TYPE, WIT_MEDIA_TYPE,
};

/// The exact bytes of every member of one release closure, by role.
///
/// Members of a role whose OCI annotation embeds the digest (`schemas`,
/// `licences`, `migration_fixtures`) may be given in any order; the builder
/// orders them by digest as ADR-102 requires.
///
/// The struct is deliberately exhaustive: this product is unreleased, so adding
/// a role is a deliberate breaking change until release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseClosureInputV1<'a> {
    /// The opaque `pmf1` layer.
    pub pmf1: &'a [u8],
    /// The `component` layer.
    pub component: &'a [u8],
    /// The `wit` layer.
    pub wit: &'a [u8],
    /// Every `schema/<sha256>` layer.
    pub schemas: Vec<&'a [u8]>,
    /// The `provenance` layer.
    pub provenance: &'a [u8],
    /// The `sbom` layer.
    pub sbom: &'a [u8],
    /// Every `licence/<sha256>` layer.
    pub licences: Vec<&'a [u8]>,
    /// Every `migration-fixture/<sha256>` layer.
    pub migration_fixtures: Vec<&'a [u8]>,
}

/// One planned layer: its member annotation, media type and bytes.
struct Layer<'a> {
    member: String,
    media_type: &'static str,
    bytes: &'a [u8],
}

/// Build the OCI manifest, its address and every blob of one release closure
/// and return the closure [`verify_oci_closure_v1()`] verified.
///
/// The manifest is the canonical (JCS) JSON the verifier requires: sorted
/// keys, no whitespace, the fixed empty config, and layers in role order with
/// digest-addressed roles ordered by digest.
///
/// # Errors
/// Returns the verifier's closed error for a closure it would reject: an empty
/// or oversized member, a duplicate digest (including identical bytes under two
/// roles), a role count outside its V1 bound, or a closure whose manifest or
/// total size exceeds a V1 bound.
pub fn build_oci_closure_v1(
    input: &ReleaseClosureInputV1<'_>,
) -> Result<VerifiedReleaseBundleV1, ReleaseSourceErrorV1> {
    let mut layers = vec![
        fixed("pmf1", PMF1_MEDIA_TYPE, input.pmf1),
        fixed("component", COMPONENT_MEDIA_TYPE, input.component),
        fixed("wit", WIT_MEDIA_TYPE, input.wit),
    ];
    layers.extend(addressed("schema/", SCHEMA_MEDIA_TYPE, &input.schemas));
    layers.push(fixed("provenance", PROVENANCE_MEDIA_TYPE, input.provenance));
    layers.push(fixed("sbom", SBOM_MEDIA_TYPE, input.sbom));
    layers.extend(addressed("licence/", LICENCE_MEDIA_TYPE, &input.licences));
    layers.extend(addressed(
        "migration-fixture/",
        MIGRATION_FIXTURE_MEDIA_TYPE,
        &input.migration_fixtures,
    ));
    let mut blobs = BTreeMap::new();
    blobs.insert(EMPTY_CONFIG_DIGEST.to_owned(), EMPTY_CONFIG_BYTES.to_vec());
    let mut descriptors = Vec::with_capacity(layers.len());
    for layer in layers {
        let digest = sha256_digest(layer.bytes);
        descriptors.push(serde_json::json!({
            "annotations": {"org.pigloros.plugin.member": layer.member},
            "digest": digest,
            "mediaType": layer.media_type,
            "size": layer.bytes.len(),
        }));
        blobs.insert(digest, layer.bytes.to_vec());
    }
    // `Value::to_string` is the verifier's own canonical serialization.
    let manifest = serde_json::json!({
        "artifactType": ARTIFACT_TYPE,
        "config": {
            "digest": EMPTY_CONFIG_DIGEST,
            "mediaType": EMPTY_CONFIG_MEDIA_TYPE,
            "size": EMPTY_CONFIG_BYTES.len(),
        },
        "layers": descriptors,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "schemaVersion": 2,
    })
    .to_string()
    .into_bytes();
    let address = BundleAddressV1::new(sha256_digest(&manifest), manifest.len() as u64)?;
    verify_oci_closure_v1(address, manifest, blobs)
}

fn fixed<'a>(member: &str, media_type: &'static str, bytes: &'a [u8]) -> Layer<'a> {
    Layer {
        member: member.to_owned(),
        media_type,
        bytes,
    }
}

/// The layers of one digest-addressed role, ordered by digest.
fn addressed<'a>(prefix: &str, media_type: &'static str, members: &[&'a [u8]]) -> Vec<Layer<'a>> {
    let mut layers = members
        .iter()
        .map(|&bytes| (sha256_digest(bytes), bytes))
        .collect::<Vec<_>>();
    layers.sort_by(|left, right| left.0.cmp(&right.0));
    layers
        .into_iter()
        .map(|(digest, bytes)| Layer {
            member: format!("{prefix}{}", &digest["sha256:".len()..]),
            media_type,
            bytes,
        })
        .collect()
}
