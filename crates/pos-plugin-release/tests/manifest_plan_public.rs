use std::collections::BTreeMap;

use pos_plugin_release::{verify_oci_closure_v1, BundleAddressV1, ReleaseSourceErrorV1};
use sha2::{Digest as _, Sha256};

type Fixture = (serde_json::Value, BTreeMap<String, Vec<u8>>);

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn fixture() -> Fixture {
    let mut blobs = BTreeMap::from([(digest(b"{}"), b"{}".to_vec())]);
    let mut layers = Vec::new();
    for (member, media_type, bytes) in [
        (
            "pmf1",
            "application/vnd.pigloros.plugin.manifest.v1+cbor",
            &b"manifest"[..],
        ),
        (
            "component",
            "application/vnd.pigloros.plugin.component.v1+wasm",
            &b"component"[..],
        ),
        (
            "wit",
            "application/vnd.pigloros.plugin.wit.v1+tar",
            &b"wit"[..],
        ),
        (
            "provenance",
            "application/vnd.in-toto+json",
            &b"provenance"[..],
        ),
        ("sbom", "application/spdx+json", &b"sbom"[..]),
        ("licence", "text/plain; charset=utf-8", &b"licence"[..]),
    ] {
        let hash = digest(bytes);
        let member = if member == "licence" {
            format!("licence/{}", &hash[7..])
        } else {
            member.to_owned()
        };
        layers.push(serde_json::json!({
            "annotations": {"org.pigloros.plugin.member": member},
            "digest": hash,
            "mediaType": media_type,
            "size": bytes.len(),
        }));
        blobs.insert(hash, bytes.to_vec());
    }
    (
        serde_json::json!({
            "artifactType": "application/vnd.pigloros.plugin.release.v1",
            "config": {"digest": digest(b"{}"), "mediaType": "application/vnd.oci.empty.v1+json", "size": 2},
            "layers": layers,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "schemaVersion": 2,
        }),
        blobs,
    )
}

#[test]
fn complete_transport_closure_preserves_members_and_bytes() -> Result<(), Box<dyn std::error::Error>>
{
    let (manifest, blobs) = fixture();
    let manifest = serde_json::to_vec(&manifest)?;
    let address = BundleAddressV1::new(digest(&manifest), u64::try_from(manifest.len())?)?;
    let verified = verify_oci_closure_v1(address.clone(), manifest.clone(), blobs.clone())?;
    assert_eq!(verified.address(), &address);
    assert_eq!(verified.manifest(), manifest);
    assert_eq!(verified.members().len(), 6);
    let actual: BTreeMap<_, _> = verified
        .blobs()
        .iter()
        .map(|blob| (blob.digest().to_owned(), blob.bytes().to_vec()))
        .collect();
    assert_eq!(actual, blobs);
    Ok(())
}

#[test]
fn declared_closure_budget_includes_manifest_and_accepts_exact_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    const MAX_BYTES: u64 = 64 * 1024 * 1024;
    for (declared_total, expected) in [
        (MAX_BYTES - 1, ReleaseSourceErrorV1::SizeMismatch),
        (MAX_BYTES, ReleaseSourceErrorV1::SizeMismatch),
        (MAX_BYTES + 1, ReleaseSourceErrorV1::BoundsExceeded),
    ] {
        let (mut manifest, blobs) = fixture();
        manifest["layers"][1]["size"] = (32_u64 * 1024 * 1024).into();
        manifest["layers"][2]["size"] = (32_u64 * 1024 * 1024).into();
        let manifest_len = serde_json::to_vec(&manifest)?.len();
        let other_bytes =
            blobs.values().map(Vec::len).sum::<usize>() - b"component".len() - b"wit".len();
        manifest["layers"][2]["size"] =
            (declared_total - u64::try_from(manifest_len + other_bytes)? - 32 * 1024 * 1024).into();
        let manifest = serde_json::to_vec(&manifest)?;
        assert_eq!(manifest.len(), manifest_len);
        let address = BundleAddressV1::new(digest(&manifest), u64::try_from(manifest.len())?)?;
        // Tiny supplied blobs deliberately disagree with the large descriptors.
        // Only an over-budget declaration must fail before blob-size checking.
        assert_eq!(
            verify_oci_closure_v1(address, manifest, blobs),
            Err(expected)
        );
    }
    Ok(())
}

#[test]
fn unverified_manifest_cannot_reach_declared_budget_check() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut manifest, blobs) = fixture();
    let original_digest = digest(&serde_json::to_vec(&manifest)?);
    manifest["layers"][1]["size"] = (32_u64 * 1024 * 1024).into();
    manifest["layers"][2]["size"] = (32_u64 * 1024 * 1024).into();
    let manifest = serde_json::to_vec(&manifest)?;
    let address = BundleAddressV1::new(original_digest, u64::try_from(manifest.len())?)?;
    assert_eq!(
        verify_oci_closure_v1(address, manifest, blobs),
        Err(ReleaseSourceErrorV1::DigestMismatch),
    );
    Ok(())
}
