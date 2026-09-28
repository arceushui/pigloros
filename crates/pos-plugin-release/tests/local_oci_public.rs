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
type ClosureInput = (BundleAddressV1, Vec<u8>, BTreeMap<String, Vec<u8>>);

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

fn maximum_layer_closure(
    licence_count: usize,
    schema_count: usize,
    migration_count: usize,
    pmf1_size: usize,
) -> Result<ClosureInput, Box<dyn std::error::Error>> {
    let mut next_byte = 0_u8;
    let mut next_blob = |size: usize| {
        let byte = next_byte;
        next_byte = next_byte.checked_add(1).ok_or("fixture byte exhausted")?;
        Ok::<_, Box<dyn std::error::Error>>(vec![byte; size])
    };
    let pmf1 = next_blob(pmf1_size)?;
    let component = next_blob(2)?;
    let wit = next_blob(2)?;
    let provenance = next_blob(2)?;
    let sbom = next_blob(2)?;
    let mut schemas = (0..schema_count)
        .map(|_| next_blob(2).map(|bytes| (digest(&bytes), bytes)))
        .collect::<Result<Vec<_>, _>>()?;
    let mut licences = (0..licence_count)
        .map(|_| next_blob(2).map(|bytes| (digest(&bytes), bytes)))
        .collect::<Result<Vec<_>, _>>()?;
    let mut migrations = (0..migration_count)
        .map(|_| next_blob(2).map(|bytes| (digest(&bytes), bytes)))
        .collect::<Result<Vec<_>, _>>()?;
    schemas.sort_by(|left, right| left.0.cmp(&right.0));
    licences.sort_by(|left, right| left.0.cmp(&right.0));
    migrations.sort_by(|left, right| left.0.cmp(&right.0));

    let mut layers = vec![
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
    ];
    for (digest, bytes) in &schemas {
        layers.push(layer(
            &format!("schema/{}", &digest[7..]),
            "application/vnd.pigloros.plugin.schema.v1+json",
            bytes,
        ));
    }
    layers.push(layer(
        "provenance",
        "application/vnd.in-toto+json",
        &provenance,
    ));
    layers.push(layer("sbom", "application/spdx+json", &sbom));
    for (digest, bytes) in &licences {
        layers.push(layer(
            &format!("licence/{}", &digest[7..]),
            "text/plain; charset=utf-8",
            bytes,
        ));
    }
    for (digest, bytes) in &migrations {
        layers.push(layer(
            &format!("migration-fixture/{}", &digest[7..]),
            "application/vnd.pigloros.plugin.migration-fixture.v1+cbor",
            bytes,
        ));
    }
    let manifest = serde_json::to_vec(&serde_json::json!({
        "artifactType": "application/vnd.pigloros.plugin.release.v1",
        "config": {
            "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            "mediaType": "application/vnd.oci.empty.v1+json",
            "size": 2,
        },
        "layers": layers,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "schemaVersion": 2,
    }))?;
    // Oversized fixtures use a bounded address so the verifier's independent
    // input-byte bound is exercised before descriptor matching.
    let address = BundleAddressV1::new(
        digest(&manifest),
        u64::try_from(manifest.len().min(64 * 1024))?,
    )?;
    let mut blobs = BTreeMap::new();
    for bytes in [pmf1, component, wit, provenance, sbom] {
        blobs.insert(digest(&bytes), bytes);
    }
    for (_, bytes) in schemas.into_iter().chain(licences).chain(migrations) {
        blobs.insert(digest(&bytes), bytes);
    }
    blobs.insert(
        "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a".to_owned(),
        b"{}".to_vec(),
    );
    Ok((address, manifest, blobs))
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

fn closure_input() -> Result<ClosureInput, Box<dyn std::error::Error>> {
    let verified = bundle()?;
    let blobs = verified
        .blobs()
        .iter()
        .map(|blob| (blob.digest().to_owned(), blob.bytes().to_vec()))
        .collect();
    Ok((
        verified.address().clone(),
        verified.manifest().to_vec(),
        blobs,
    ))
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

    assert_eq!(
        LocalOciPublisherV1::open(&link).err(),
        Some(LocalOciPublicationErrorV1::InvalidLayout)
    );
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
        drop(fs::remove_dir(&root));
        return Ok(());
    }

    let opened = LocalOciPublisherV1::open(&root);
    let entries = fs::read_dir(&root)?.count();
    fs::remove_dir(&root)?;

    assert_eq!(
        opened.err(),
        Some(LocalOciPublicationErrorV1::InvalidLayout)
    );
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
fn oversized_inventory_preserves_owned_staging_and_root_index(
) -> Result<(), Box<dyn std::error::Error>> {
    for final_count in [257_u16, 258] {
        let root = PrivateRoot::new()?;
        let publisher = LocalOciPublisherV1::open(&root.0)?;
        let nonce = "0123456789abcdef0123456789abcdef";
        let staging = root
            .0
            .join("releases")
            .join(format!(".{}.staging.{nonce}", "f".repeat(64)));
        create_private_dir(&staging)?;
        write_private_file(
            &staging.join("OWNER"),
            format!("pigloros-local-oci-staging-v1\n{nonce}\n").as_bytes(),
        )?;
        for index in 0..final_count {
            create_private_dir(&root.0.join("releases").join(format!("{index:064x}")))?;
        }
        let index_before = fs::read(root.0.join("published.json"))?;
        assert_eq!(
            publisher.recover_all(),
            Err(LocalOciPublicationErrorV1::BoundsExceeded)
        );
        assert!(staging.join("OWNER").is_file());
        assert_eq!(
            fs::read_dir(root.0.join("releases"))?.count(),
            usize::from(final_count) + 1
        );
        assert_eq!(fs::read(root.0.join("published.json"))?, index_before);
        assert_eq!(fs::read_dir(root.0.join("quarantine"))?.count(), 0);
    }
    Ok(())
}

#[test]
fn unrelated_root_entry_requires_operator_recovery_without_deleting_it(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = PrivateRoot::new()?;
    let publisher = LocalOciPublisherV1::open(&root.0)?;
    let release = bundle()?;
    write_private_file(&root.0.join("unrelated"), b"operator-owned")?;
    assert_eq!(
        publisher.recover_all(),
        Err(LocalOciPublicationErrorV1::RecoveryRequired)
    );
    assert_eq!(
        publisher.recover(release.address()),
        Err(LocalOciPublicationErrorV1::RecoveryRequired)
    );
    assert_eq!(
        publisher.publish(&release),
        Err(LocalOciPublicationErrorV1::RecoveryRequired)
    );
    assert_eq!(fs::read(root.0.join("unrelated"))?, b"operator-owned");
    assert_eq!(fs::read_dir(root.0.join("releases"))?.count(), 0);
    fs::remove_file(root.0.join("unrelated"))?;
    assert_eq!(
        publisher.publish(&release)?,
        PublishOutcomeV1::Published(release.address().clone())
    );
    Ok(())
}

#[test]
fn enforces_reachable_layer_and_manifest_byte_limits() -> Result<(), Box<dyn std::error::Error>> {
    // The accepted 241-layer profile is five required non-licence roles,
    // 27 licences, 204 schemas, and five migration fixtures. The root
    // descriptor binds PMF1; this transport fixture intentionally has no
    // PMF1-internal descriptor list to self-reference that layer.
    let (address, manifest, blobs) = maximum_layer_closure(27, 204, 5, 2)?;
    assert_eq!(manifest.len(), 65_535);
    let verified = verify_oci_closure_v1(address, manifest, blobs)?;
    assert_eq!(verified.members().len(), 241);
    assert_eq!(verified.blobs().len() + 1, 243);
    let root = PrivateRoot::new()?;
    let publisher = LocalOciPublisherV1::open(&root.0)?;
    publisher.publish(&verified)?;
    drop(publisher);
    let reopened = LocalOciPublisherV1::open(&root.0)?;
    assert_eq!(reopened.read_verified(verified.address())?, verified);
    assert_eq!(
        reopened.recover(verified.address())?,
        RecoveryOutcomeV1::Committed(verified.address().clone())
    );

    let (address, manifest, blobs) = maximum_layer_closure(27, 204, 5, 10)?;
    assert_eq!(manifest.len(), 65_536);
    let verified = verify_oci_closure_v1(address, manifest, blobs)?;
    assert_eq!(verified.members().len(), 241);
    assert_eq!(verified.blobs().len() + 1, 243);

    let (address, manifest, blobs) = maximum_layer_closure(27, 204, 5, 100)?;
    assert_eq!(manifest.len(), 65_537);
    assert_eq!(
        verify_oci_closure_v1(address, manifest, blobs),
        Err(ReleaseSourceErrorV1::BoundsExceeded)
    );

    let (address, manifest, blobs) = maximum_layer_closure(32, 205, 0, 2)?;
    assert_eq!(manifest.len(), 65_599);
    assert_eq!(
        verify_oci_closure_v1(address, manifest, blobs),
        Err(ReleaseSourceErrorV1::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn rejects_noncanonical_and_deeply_nested_json_at_public_verifier(
) -> Result<(), Box<dyn std::error::Error>> {
    for manifest in [
        b"{\"b\":0,\"a\":0}".to_vec(),
        b"[".to_vec(),
        b"[0".to_vec(),
        b"{\"a\":false".to_vec(),
        b"{\"a\":}".to_vec(),
        b"{\"a\": [0,]}".to_vec(),
        format!("{}0{}", "[".repeat(129), "]".repeat(129)).into_bytes(),
    ] {
        let address = BundleAddressV1::new(digest(&manifest), u64::try_from(manifest.len())?)?;
        assert_eq!(
            verify_oci_closure_v1(address, manifest, BTreeMap::new()),
            Err(ReleaseSourceErrorV1::InvalidDescriptor)
        );
    }
    Ok(())
}

#[test]
fn reader_bounds_actual_blob_bytes_by_the_declared_size() -> Result<(), Box<dyn std::error::Error>>
{
    let root = PrivateRoot::new()?;
    let publisher = LocalOciPublisherV1::open(&root.0)?;
    let release = bundle()?;
    publisher.publish(&release)?;
    let member = &release.blobs()[0];
    let path = root
        .0
        .join("releases")
        .join(&release.address().digest()[7..])
        .join("blobs/sha256")
        .join(&member.digest()[7..]);
    let mut enlarged = member.bytes().to_vec();
    enlarged.push(0);
    fs::write(path, enlarged)?;
    assert_eq!(
        publisher.read_verified(release.address()),
        Err(ReleaseSourceErrorV1::BoundsExceeded)
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
fn recovery_removes_empty_staging_and_bounds_staging_blob_members(
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
    assert_eq!(publisher.recover_all()?.removed_staging, 1);
    assert!(!staging.exists());

    create_private_dir(&staging)?;
    write_private_file(
        &staging.join("OWNER"),
        format!("pigloros-local-oci-staging-v1\n{nonce}\n").as_bytes(),
    )?;
    create_private_dir(&staging.join("blobs"))?;
    create_private_dir(&staging.join("blobs").join("sha256"))?;
    for member in 0..360_u16 {
        write_private_file(
            &staging
                .join("blobs")
                .join("sha256")
                .join(format!("{member:064x}")),
            b"x",
        )?;
    }
    assert_eq!(
        publisher.recover_all(),
        Err(LocalOciPublicationErrorV1::RecoveryRequired)
    );
    assert_one_quarantined(&root)?;
    Ok(())
}

#[test]
fn public_verifier_rejects_descriptor_collisions_and_reversed_schema_digests(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_, manifest, blobs) = closure_input()?;
    let mut collision: serde_json::Value = serde_json::from_slice(&manifest)?;
    collision["layers"][0]["digest"] = serde_json::json!(digest(b"{}"));
    let collision = serde_json::to_vec(&collision)?;
    let collision_address =
        BundleAddressV1::new(digest(&collision), u64::try_from(collision.len())?)?;
    assert_eq!(
        verify_oci_closure_v1(collision_address, collision, blobs.clone()),
        Err(ReleaseSourceErrorV1::DuplicateMember)
    );

    let mut disordered: serde_json::Value = serde_json::from_slice(&manifest)?;
    let mut schemas = [b"schema-a".to_vec(), b"schema-b".to_vec()];
    schemas.sort_by_key(|bytes| std::cmp::Reverse(digest(bytes)));
    for (offset, schema) in schemas.iter().enumerate() {
        let schema_digest = digest(schema);
        disordered["layers"]
            .as_array_mut()
            .ok_or("layers must be an array")?
            .insert(
                3 + offset,
                layer(
                    &format!("schema/{}", &schema_digest[7..]),
                    "application/vnd.pigloros.plugin.schema.v1+json",
                    schema,
                ),
            );
    }
    let disordered = serde_json::to_vec(&disordered)?;
    let disordered_address =
        BundleAddressV1::new(digest(&disordered), u64::try_from(disordered.len())?)?;
    let mut blobs = blobs;
    for schema in schemas {
        blobs.insert(digest(&schema), schema);
    }
    assert_eq!(
        verify_oci_closure_v1(disordered_address, disordered, blobs),
        Err(ReleaseSourceErrorV1::InvalidDescriptor)
    );
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
