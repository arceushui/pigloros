#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use pos_plugin_release::{
    verify_oci_closure_v1, BundleAddressV1, LocalOciPublicationErrorV1, LocalOciPublisherV1,
    PublishOutcomeV1, ReleaseSourceErrorV1, ReleaseSourceV1, VerifiedReleaseBundleV1,
};
use sha2::{Digest as _, Sha256};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct PrivateRoot(PathBuf);

impl PrivateRoot {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "pigloros-oci-public-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        Ok(Self(root))
    }
}

impl Drop for PrivateRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::from("sha256:");
    for byte in Sha256::digest(bytes) {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

fn layer(member: &str, media_type: &str, bytes: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "annotations": {"org.pigloros.plugin.member": member},
        "digest": digest(bytes),
        "mediaType": media_type,
        "size": bytes.len(),
    })
}

fn bundle() -> Result<VerifiedReleaseBundleV1, Box<dyn std::error::Error>> {
    let pmf1 = b"pmf1".to_vec();
    let component = b"component".to_vec();
    let wit = b"wit".to_vec();
    let provenance = b"provenance".to_vec();
    let sbom = b"sbom".to_vec();
    let licence = b"licence".to_vec();
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
            &format!("licence/{}", &digest(&licence)[7..]),
            "text/plain; charset=utf-8",
            &licence,
        ),
    ];
    let manifest = serde_json::to_vec(&serde_json::json!({
        "artifactType": "application/vnd.pigloros.plugin.release.v1",
        "config": {
            "digest": digest(b"{}"),
            "mediaType": "application/vnd.oci.empty.v1+json",
            "size": 2,
        },
        "layers": layers,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "schemaVersion": 2,
    }))?;
    let address = BundleAddressV1::new(digest(&manifest), u64::try_from(manifest.len())?)?;
    let mut blobs = BTreeMap::new();
    for bytes in [
        b"{}".to_vec(),
        pmf1,
        component,
        wit,
        provenance,
        sbom,
        licence,
    ] {
        blobs.insert(digest(&bytes), bytes);
    }
    Ok(verify_oci_closure_v1(address, manifest, blobs)?)
}

fn create_private_dir(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn write_private_file(
    path: &std::path::Path,
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[test]
fn local_publication_roundtrip_and_index_shape() -> Result<(), Box<dyn std::error::Error>> {
    let root = PrivateRoot::new()?;
    let publisher = LocalOciPublisherV1::open(&root.0)?;
    let bundle = bundle()?;
    let address = bundle.address().clone();
    assert_eq!(
        publisher.read_verified(&address),
        Err(ReleaseSourceErrorV1::NotFound)
    );
    assert_eq!(
        publisher.publish(&bundle)?,
        PublishOutcomeV1::Published(address.clone())
    );
    assert_eq!(publisher.read_verified(&address)?, bundle);
    assert_eq!(
        publisher.publish(&bundle)?,
        PublishOutcomeV1::AlreadyPublished(address.clone())
    );

    let index_path = root.0.join("published.json");
    let valid = fs::read(&index_path)?;
    let entry = serde_json::json!({
        "digest": address.digest(),
        "mediaType": address.media_type(),
        "size": address.size(),
    });
    let malformed = [
        serde_json::json!({"addresses": [], "extra": 1, "version": 1}),
        serde_json::json!({"addresses": [], "version": 2}),
        serde_json::json!({"addresses": [{"digest": address.digest(), "mediaType": "bad", "size": address.size()}], "version": 1}),
        serde_json::json!({"addresses": [entry.clone(), entry], "version": 1}),
    ];
    for value in malformed {
        fs::write(&index_path, serde_json::to_vec(&value)?)?;
        assert_eq!(
            publisher.read_verified(&address),
            Err(ReleaseSourceErrorV1::InvalidLayout)
        );
    }
    fs::write(&index_path, valid)?;
    assert_eq!(publisher.read_verified(&address)?, bundle);
    fs::set_permissions(&index_path, fs::Permissions::from_mode(0o644))?;
    assert_eq!(
        publisher.read_verified(&address),
        Err(ReleaseSourceErrorV1::InvalidLayout)
    );
    fs::set_permissions(&index_path, fs::Permissions::from_mode(0o600))?;
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o755))?;
    assert_eq!(
        publisher.recover_all(),
        Err(LocalOciPublicationErrorV1::InvalidLayout)
    );
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[test]
fn recovery_revalidates_indexed_and_unindexed_finals() -> Result<(), Box<dyn std::error::Error>> {
    let root = PrivateRoot::new()?;
    let publisher = LocalOciPublisherV1::open(&root.0)?;
    let bundle = bundle()?;
    let address = bundle.address().clone();
    assert_eq!(
        publisher.publish(&bundle)?,
        PublishOutcomeV1::Published(address.clone())
    );

    let final_path = root.0.join("releases").join(&address.digest()[7..]);
    let layout = final_path.join("oci-layout");
    fs::write(&layout, b"bad")?;
    assert_eq!(
        publisher.read_verified(&address),
        Err(ReleaseSourceErrorV1::InvalidLayout)
    );
    assert_eq!(
        publisher.recover_all(),
        Err(LocalOciPublicationErrorV1::RecoveryRequired)
    );
    fs::write(&layout, b"{\"imageLayoutVersion\":\"1.0.0\"}\n")?;

    let release_index = final_path.join("index.json");
    let valid_release_index = fs::read(&release_index)?;
    fs::write(&release_index, b"{}")?;
    assert_eq!(
        publisher.read_verified(&address),
        Err(ReleaseSourceErrorV1::InvalidLayout)
    );
    assert_eq!(
        publisher.recover_all(),
        Err(LocalOciPublicationErrorV1::RecoveryRequired)
    );
    fs::write(&release_index, valid_release_index)?;

    let owner_marker = final_path.join("OWNER");
    let valid_owner = fs::read(&owner_marker)?;
    fs::write(&owner_marker, b"bad owner")?;
    assert_eq!(
        publisher.read_verified(&address),
        Err(ReleaseSourceErrorV1::InvalidLayout)
    );
    assert_eq!(
        publisher.recover_all(),
        Err(LocalOciPublicationErrorV1::RecoveryRequired)
    );
    fs::write(&owner_marker, valid_owner)?;

    let root_index = root.0.join("published.json");
    fs::write(&root_index, b"{\"addresses\":[],\"version\":1}")?;
    let report = publisher.recover_all()?;
    assert_eq!(report.committed, vec![address.clone()]);
    assert_eq!(publisher.read_verified(&address)?, bundle);
    Ok(())
}

#[test]
fn partial_owned_staging_is_removed_and_bad_owner_is_quarantined(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = PrivateRoot::new()?;
    let publisher = LocalOciPublisherV1::open(&root.0)?;
    let address = bundle()?.address().clone();
    let nonce = "0123456789abcdef0123456789abcdef";
    let staging = root
        .0
        .join("releases")
        .join(format!(".{}.staging.{nonce}", &address.digest()[7..]));
    create_private_dir(&staging)?;
    write_private_file(
        &staging.join("OWNER"),
        format!("pigloros-local-oci-staging-v1\n{nonce}\n").as_bytes(),
    )?;
    let blobs = staging.join("blobs");
    create_private_dir(&blobs)?;
    let sha256 = blobs.join("sha256");
    create_private_dir(&sha256)?;
    write_private_file(&sha256.join("0".repeat(64)), b"partial")?;
    let report = publisher.recover_all()?;
    assert_eq!(report.removed_staging, 1);
    assert!(!staging.exists());

    create_private_dir(&staging)?;
    write_private_file(&staging.join("OWNER"), b"wrong owner")?;
    assert_eq!(
        publisher.recover_all(),
        Err(LocalOciPublicationErrorV1::RecoveryRequired)
    );
    assert_eq!(
        publisher.read_verified(&address),
        Err(ReleaseSourceErrorV1::RecoveryRequired)
    );
    let quarantine = root.0.join("quarantine");
    let mut retained = fs::read_dir(&quarantine)?;
    let retained_path = retained
        .next()
        .ok_or("missing quarantined staging")??
        .path();
    assert!(retained.next().is_none());
    fs::remove_dir_all(retained_path)?;
    assert_eq!(publisher.recover_all()?.removed_staging, 0);
    assert_eq!(
        publisher.read_verified(&address),
        Err(ReleaseSourceErrorV1::NotFound)
    );
    Ok(())
}
