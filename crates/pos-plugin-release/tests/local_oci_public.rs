#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use pos_plugin_release::{
    verify_oci_closure_v1, BundleAddressV1, LocalOciPublicationErrorV1, LocalOciPublisherV1,
    PublishOutcomeV1, RecoveryOutcomeV1, ReleaseSourceErrorV1, ReleaseSourceV1,
    VerifiedReleaseBundleV1,
};
use sha2::{Digest as _, Sha256};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
const TMPFS_MAGIC: u64 = 0x0102_1994;

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
        drop(fs::remove_dir_all(&self.0));
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
    bundle_with_component(b"component")
}

fn bundle_with_component(
    component: &[u8],
) -> Result<VerifiedReleaseBundleV1, Box<dyn std::error::Error>> {
    let pmf1 = b"pmf1".to_vec();
    let component = component.to_vec();
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

fn assert_one_quarantined(root: &PrivateRoot) -> Result<(), Box<dyn std::error::Error>> {
    let mut entries = fs::read_dir(root.0.join("quarantine"))?;
    assert!(entries.next().is_some());
    assert!(entries.next().is_none());
    Ok(())
}

#[test]
fn open_rejects_a_symlinked_root() -> Result<(), Box<dyn std::error::Error>> {
    let root = PrivateRoot::new()?;
    let link = root.0.join("root-link");
    std::os::unix::fs::symlink(&root.0, &link)?;

    assert!(matches!(
        LocalOciPublisherV1::open(&link),
        Err(LocalOciPublicationErrorV1::InvalidLayout)
    ));
    assert_eq!(fs::read_dir(&root.0)?.count(), 1);
    Ok(())
}

#[test]
fn open_rejects_an_unsupported_filesystem_before_initialization(
) -> Result<(), Box<dyn std::error::Error>> {
    let mount = std::path::Path::new("/dev/shm");
    let Ok(mount) = File::open(mount) else {
        return Ok(());
    };
    // `/dev/shm` is conventional, but runners may mount or restrict it differently.
    let Ok(filesystem) = rustix::fs::fstatfs(&mount) else {
        return Ok(());
    };
    if u64::try_from(filesystem.f_type).ok() != Some(TMPFS_MAGIC) {
        return Ok(());
    }
    let root = std::path::Path::new("/dev/shm").join(format!(
        "pigloros-oci-public-unsupported-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    if fs::create_dir(&root).is_err() {
        return Ok(());
    }
    if fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).is_err() {
        let _ = fs::remove_dir(&root);
        return Ok(());
    }

    let opened = LocalOciPublisherV1::open(&root);
    let entries = fs::read_dir(&root)?.count();
    fs::remove_dir(&root)?;

    assert!(matches!(
        opened,
        Err(LocalOciPublicationErrorV1::InvalidLayout)
    ));
    assert_eq!(entries, 0);
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
        publisher.recover(&address)?,
        RecoveryOutcomeV1::Unpublished(address.clone())
    );
    assert_eq!(
        publisher.publish(&bundle)?,
        PublishOutcomeV1::Published(address.clone())
    );
    assert_eq!(publisher.read_verified(&address)?, bundle);
    assert_eq!(
        publisher.recover(&address)?,
        RecoveryOutcomeV1::Committed(address.clone())
    );
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
fn recovery_quarantines_malformed_indexed_and_unindexed_finals(
) -> Result<(), Box<dyn std::error::Error>> {
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
    assert_one_quarantined(&root)?;

    let root = PrivateRoot::new()?;
    let publisher = LocalOciPublisherV1::open(&root.0)?;
    let bundle = self::bundle()?;
    let address = bundle.address().clone();
    assert_eq!(
        publisher.publish(&bundle)?,
        PublishOutcomeV1::Published(address.clone())
    );
    let root_index = root.0.join("published.json");
    fs::write(&root_index, b"{\"addresses\":[],\"version\":1}")?;
    let final_path = root.0.join("releases").join(&address.digest()[7..]);
    fs::write(final_path.join("oci-layout"), b"bad")?;
    assert_eq!(
        publisher.recover_all(),
        Err(LocalOciPublicationErrorV1::RecoveryRequired)
    );
    assert_one_quarantined(&root)?;
    Ok(())
}

#[test]
fn recovery_quarantines_malformed_and_unowned_next_indexes(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = PrivateRoot::new()?;
    let publisher = LocalOciPublisherV1::open(&root.0)?;
    write_private_file(&root.0.join(".published.bad.next"), b"next")?;
    assert_eq!(
        publisher.recover_all(),
        Err(LocalOciPublicationErrorV1::RecoveryRequired)
    );
    assert_one_quarantined(&root)?;

    let root = PrivateRoot::new()?;
    let publisher = LocalOciPublisherV1::open(&root.0)?;
    let next = root
        .0
        .join(".published.0123456789abcdef0123456789abcdef.next");
    write_private_file(&next, b"next")?;
    fs::set_permissions(&next, fs::Permissions::from_mode(0o644))?;
    assert_eq!(
        publisher.recover_all(),
        Err(LocalOciPublicationErrorV1::RecoveryRequired)
    );
    assert_one_quarantined(&root)?;
    Ok(())
}

#[test]
fn recovery_removes_owned_next_index_after_validation() -> Result<(), Box<dyn std::error::Error>> {
    let root = PrivateRoot::new()?;
    let publisher = LocalOciPublisherV1::open(&root.0)?;
    let next = root
        .0
        .join(".published.0123456789abcdef0123456789abcdef.next");
    write_private_file(&next, b"next")?;
    let report = publisher.recover_all()?;
    assert!(report.removed_next_index);
    assert!(!next.exists());
    Ok(())
}

#[test]
fn read_fails_closed_when_a_different_indexed_final_is_invalid(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = PrivateRoot::new()?;
    let publisher = LocalOciPublisherV1::open(&root.0)?;
    let requested = bundle()?;
    let invalid = bundle_with_component(b"different component")?;
    let requested_address = requested.address().clone();
    let invalid_address = invalid.address().clone();
    publisher.publish(&requested)?;
    publisher.publish(&invalid)?;
    let invalid_layout = root
        .0
        .join("releases")
        .join(&invalid_address.digest()[7..])
        .join("oci-layout");
    fs::write(invalid_layout, b"bad")?;
    assert_eq!(
        publisher.read_verified(&requested_address),
        Err(ReleaseSourceErrorV1::RecoveryRequired)
    );
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

#[test]
fn indexed_release_rejects_mutated_evidence_and_extra_members(
) -> Result<(), Box<dyn std::error::Error>> {
    for (relative, bytes, expected) in [
        (
            "OWNER".to_owned(),
            b"wrong owner".to_vec(),
            ReleaseSourceErrorV1::InvalidLayout,
        ),
        (
            "OWNER".to_owned(),
            b"pigloros-local-oci-staging-v1\nnot-a-nonce\n".to_vec(),
            ReleaseSourceErrorV1::InvalidLayout,
        ),
        (
            "OWNER".to_owned(),
            vec![b'x'; 129],
            ReleaseSourceErrorV1::BoundsExceeded,
        ),
        (
            "READY".to_owned(),
            b"not ready".to_vec(),
            ReleaseSourceErrorV1::Uncommitted,
        ),
        (
            "READY".to_owned(),
            vec![b'x'; 257],
            ReleaseSourceErrorV1::BoundsExceeded,
        ),
        (
            "index.json".to_owned(),
            b"not the descriptor".to_vec(),
            ReleaseSourceErrorV1::InvalidLayout,
        ),
        (
            "oci-layout".to_owned(),
            vec![b'x'; 65],
            ReleaseSourceErrorV1::BoundsExceeded,
        ),
        (
            format!("blobs/sha256/{}", &digest(b"component")[7..]),
            b"xxxxxxxxx".to_vec(),
            ReleaseSourceErrorV1::DigestMismatch,
        ),
    ] {
        let root = PrivateRoot::new()?;
        let publisher = LocalOciPublisherV1::open(&root.0)?;
        let bundle = bundle()?;
        let address = bundle.address().clone();
        publisher.publish(&bundle)?;
        let final_path = root.0.join("releases").join(&address.digest()[7..]);
        fs::write(final_path.join(relative), bytes)?;
        assert_eq!(publisher.read_verified(&address), Err(expected));
        assert_eq!(
            publisher.recover_all(),
            Err(LocalOciPublicationErrorV1::RecoveryRequired)
        );
        assert_one_quarantined(&root)?;
    }
    let root = PrivateRoot::new()?;
    let publisher = LocalOciPublisherV1::open(&root.0)?;
    let bundle = bundle()?;
    let address = bundle.address().clone();
    publisher.publish(&bundle)?;
    let final_path = root.0.join("releases").join(&address.digest()[7..]);
    write_private_file(&final_path.join("unexpected"), b"extra")?;
    assert_eq!(
        publisher.read_verified(&address),
        Err(ReleaseSourceErrorV1::InvalidLayout)
    );
    Ok(())
}

#[test]
fn unindexed_final_recovery_quarantines_bad_ready_evidence(
) -> Result<(), Box<dyn std::error::Error>> {
    for ready in [
        b"bad header\nsha256:bad\n1\n".as_slice(),
        b"pigloros-local-oci-ready-v1\n",
        b"pigloros-local-oci-ready-v1\nsha256:bad\n",
        b"pigloros-local-oci-ready-v1\nsha256:bad\nnot-a-size\n",
        b"pigloros-local-oci-ready-v1\nsha256:bad\n1\nextra\n",
        b"pigloros-local-oci-ready-v1\nsha256:bad\n1\n",
        b"pigloros-local-oci-ready-v1\nsha256:bad\n0\n",
        b"\xff",
    ] {
        let root = PrivateRoot::new()?;
        let publisher = LocalOciPublisherV1::open(&root.0)?;
        let bundle = bundle()?;
        let address = bundle.address().clone();
        publisher.publish(&bundle)?;
        fs::write(
            root.0.join("published.json"),
            b"{\"addresses\":[],\"version\":1}",
        )?;
        let final_path = root.0.join("releases").join(&address.digest()[7..]);
        fs::write(final_path.join("READY"), ready)?;
        assert_eq!(
            publisher.recover_all(),
            Err(LocalOciPublicationErrorV1::RecoveryRequired)
        );
        assert_one_quarantined(&root)?;
    }
    Ok(())
}

#[test]
fn root_discovery_index_rejects_noncanonical_and_malformed_entries(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = PrivateRoot::new()?;
    let publisher = LocalOciPublisherV1::open(&root.0)?;
    let address = bundle()?.address().clone();
    let entry = serde_json::json!({
        "digest": address.digest(),
        "mediaType": address.media_type(),
        "size": address.size(),
    });
    let invalid = [
        (serde_json::json!([]), ReleaseSourceErrorV1::InvalidLayout),
        (
            serde_json::json!({"version": 1}),
            ReleaseSourceErrorV1::InvalidLayout,
        ),
        (
            serde_json::json!({"addresses": 1, "version": 1}),
            ReleaseSourceErrorV1::InvalidLayout,
        ),
        (
            serde_json::json!({"addresses": [null], "version": 1}),
            ReleaseSourceErrorV1::InvalidLayout,
        ),
        (
            serde_json::json!({"addresses": [{"digest": address.digest(), "mediaType": "wrong", "size": address.size()}], "version": 1}),
            ReleaseSourceErrorV1::InvalidLayout,
        ),
        (
            serde_json::json!({"addresses": [{"digest": "sha256:bad", "mediaType": address.media_type(), "size": address.size()}], "version": 1}),
            ReleaseSourceErrorV1::InvalidLayout,
        ),
        (
            serde_json::json!({"addresses": [{"digest": address.digest(), "mediaType": address.media_type(), "size": "bad"}], "version": 1}),
            ReleaseSourceErrorV1::InvalidLayout,
        ),
        (
            serde_json::json!({"addresses": [&entry, &entry], "version": 1}),
            ReleaseSourceErrorV1::InvalidLayout,
        ),
        (
            serde_json::json!({"addresses": vec![&entry; 257], "version": 1}),
            ReleaseSourceErrorV1::BoundsExceeded,
        ),
    ];
    for (value, expected) in invalid {
        fs::write(root.0.join("published.json"), serde_json::to_vec(&value)?)?;
        assert_eq!(publisher.read_verified(&address), Err(expected), "{value}");
    }
    fs::write(
        root.0.join("published.json"),
        b"{\"addresses\":[],\"version\":1} ",
    )?;
    assert_eq!(
        publisher.read_verified(&address),
        Err(ReleaseSourceErrorV1::InvalidLayout)
    );
    fs::write(
        root.0.join("published.json"),
        b"{\"addresses\":[],\"addresses\":[],\"version\":1}",
    )?;
    assert_eq!(
        publisher.read_verified(&address),
        Err(ReleaseSourceErrorV1::InvalidLayout)
    );
    Ok(())
}

#[test]
fn recovery_enforces_bounded_inventory_before_adopting_any_final(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = PrivateRoot::new()?;
    let publisher = LocalOciPublisherV1::open(&root.0)?;
    for index in 0..257_u16 {
        create_private_dir(&root.0.join("releases").join(format!("{index:064x}")))?;
    }
    assert_eq!(
        publisher.recover_all(),
        Err(LocalOciPublicationErrorV1::BoundsExceeded)
    );

    let root = PrivateRoot::new()?;
    let publisher = LocalOciPublisherV1::open(&root.0)?;
    create_private_dir(&root.0.join("releases").join(".first"))?;
    create_private_dir(&root.0.join("releases").join(".second"))?;
    assert_eq!(
        publisher.recover_all(),
        Err(LocalOciPublicationErrorV1::BoundsExceeded)
    );

    let root = PrivateRoot::new()?;
    let publisher = LocalOciPublisherV1::open(&root.0)?;
    write_private_file(
        &root
            .0
            .join(".published.00000000000000000000000000000000.next"),
        b"next",
    )?;
    write_private_file(
        &root
            .0
            .join(".published.11111111111111111111111111111111.next"),
        b"next",
    )?;
    assert_eq!(
        publisher.recover_all(),
        Err(LocalOciPublicationErrorV1::RecoveryRequired)
    );
    Ok(())
}

#[test]
fn owned_staging_with_unrecognized_members_is_quarantined() -> Result<(), Box<dyn std::error::Error>>
{
    for defect in ["unexpected", "bad-blob-group", "bad-blob-name"] {
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
        match defect {
            "unexpected" => write_private_file(&staging.join("unexpected"), b"x")?,
            "bad-blob-group" => {
                create_private_dir(&staging.join("blobs"))?;
                create_private_dir(&staging.join("blobs").join("other"))?;
            }
            "bad-blob-name" => {
                create_private_dir(&staging.join("blobs"))?;
                create_private_dir(&staging.join("blobs").join("sha256"))?;
                write_private_file(&staging.join("blobs").join("sha256").join("bad"), b"x")?;
            }
            _ => return Err("unknown fixture defect".into()),
        }
        assert_eq!(
            publisher.recover_all(),
            Err(LocalOciPublicationErrorV1::RecoveryRequired)
        );
        assert_one_quarantined(&root)?;
    }
    Ok(())
}

#[test]
fn indexed_release_rejects_excess_declared_closure_before_blob_reads(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = PrivateRoot::new()?;
    let publisher = LocalOciPublisherV1::open(&root.0)?;
    let bundle = bundle()?;
    let address = bundle.address().clone();
    publisher.publish(&bundle)?;
    let manifest_path = root
        .0
        .join("releases")
        .join(&address.digest()[7..])
        .join("blobs")
        .join("sha256")
        .join(&address.digest()[7..]);
    let mut malformed: serde_json::Value = serde_json::from_slice(bundle.manifest())?;
    malformed["layers"][0]["size"] = serde_json::json!(32 * 1024 * 1024);
    malformed["layers"][1]["size"] = serde_json::json!(32 * 1024 * 1024);
    fs::write(manifest_path, serde_json::to_vec(&malformed)?)?;
    assert_eq!(
        publisher.read_verified(&address),
        Err(ReleaseSourceErrorV1::BoundsExceeded)
    );
    assert_eq!(
        publisher.recover_all(),
        Err(LocalOciPublicationErrorV1::RecoveryRequired)
    );
    assert_one_quarantined(&root)?;
    Ok(())
}
