use std::os::unix::fs::{symlink, PermissionsExt};

use ed25519_dalek::SigningKey;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn bytes(value: [u8; 32]) -> Value {
    Value::Bytes(value.to_vec())
}

fn integer(value: u64) -> Value {
    Value::Integer(value.into())
}

fn object(code: u8) -> Value {
    let content = *blake3::hash(&[code; 32]).as_bytes();
    let identity = if code >= 10 { content } else { [code + 1; 32] };
    Value::Array(vec![
        integer(u64::from(code)),
        bytes(identity),
        bytes(content),
        integer(32),
    ])
}

fn unsigned() -> Vec<Value> {
    vec![
        Value::Text("SIC1".to_owned()),
        integer(1),
        Value::Text("offline-root".to_owned()),
        bytes(SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes()),
        bytes([1; 32]),
        bytes([2; 32]),
        bytes([3; 32]),
        Value::Text("/run/pigloros/execute.sock".to_owned()),
        Value::Text("/run/pigloros/control.sock".to_owned()),
        Value::Array(vec![
            Value::Text("a".to_owned()),
            Value::Text("bb".to_owned()),
        ]),
        Value::Array((0..16).map(object).collect()),
    ]
}

fn manifest_bytes(fields: Vec<Value>) -> Result<Vec<u8>, ProtocolError> {
    let unsigned = Value::Array(fields);
    let mut hasher = blake3::Hasher::new();
    hasher.update(MANIFEST_DOMAIN);
    hasher.update(&encode(&unsigned)?);
    encode(&Value::Array(vec![
        unsigned,
        bytes(*hasher.finalize().as_bytes()),
    ]))
}

#[test]
fn manifest_exposes_exact_typed_installation_without_minting_admission() -> TestResult {
    let encoded = manifest_bytes(unsigned())?;
    let manifest = InstallationManifest::from_cbor(&encoded)?;
    assert_ne!(manifest.digest(), [0; 32]);
    assert_eq!(
        manifest.offline_root(),
        (
            "offline-root",
            SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes()
        )
    );
    assert_eq!(manifest.authority_digests(), [[1; 32], [2; 32], [3; 32]]);
    assert_eq!(
        manifest.provider_sockets(),
        (
            Path::new("/run/pigloros/execute.sock"),
            Path::new("/run/pigloros/control.sock")
        )
    );
    assert_eq!(manifest.required_features(), ["a", "bb"]);
    assert_eq!(manifest.objects().len(), 16);
    for code in 0..16 {
        let kind = InstallationObjectKind::from_code(code)?;
        assert_eq!(kind.code(), code);
        let content = *blake3::hash(&[code; 32]).as_bytes();
        let identity = if code >= 10 { content } else { [code + 1; 32] };
        let entry = manifest.object(kind, identity)?;
        assert_eq!(entry.kind(), kind);
        assert_eq!(entry.identity(), identity);
        assert_eq!(entry.content_digest(), content);
        assert_eq!(entry.length(), 32);
        assert!(manifest.object(kind, [255; 32]).is_err());
    }
    for code in 16..=255 {
        assert!(InstallationObjectKind::from_code(code).is_err());
    }
    Ok(())
}

#[test]
fn manifest_rejects_every_truncated_prefix_and_trailing_data() -> TestResult {
    let encoded = manifest_bytes(unsigned())?;
    for end in 0..encoded.len() {
        assert!(
            InstallationManifest::from_cbor(&encoded[..end]).is_err(),
            "prefix {end}"
        );
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(InstallationManifest::from_cbor(&trailing).is_err());
    let mut wrong_digest = encoded.clone();
    let last = wrong_digest.last_mut().ok_or("empty encoding")?;
    *last ^= 1;
    assert!(InstallationManifest::from_cbor(&wrong_digest).is_err());
    // The unsigned array's preferred one-byte width cannot be overlong.
    let mut noncanonical = vec![0x82, 0x98, 11];
    noncanonical.extend_from_slice(&encoded[2..]);
    assert!(InstallationManifest::from_cbor(&noncanonical).is_err());
    assert!(InstallationManifest::from_cbor(&vec![0; 16 * 1024 * 1024 + 1]).is_err());
    Ok(())
}

#[test]
fn manifest_rejects_wrong_schema_keys_digests_and_container_types() -> TestResult {
    for (index, replacement) in [
        (0, Value::Text("SIC2".to_owned())),
        (0, integer(1)),
        (1, integer(0)),
        (1, integer(2)),
        (1, Value::Text("1".to_owned())),
        (2, Value::Text(String::new())),
        (2, Value::Text("a".repeat(129))),
        (3, Value::Bytes(vec![1; 31])),
        (4, bytes([0; 32])),
        (5, bytes([0; 32])),
        (6, bytes([0; 32])),
        (4, bytes([77; 32])),
        (5, bytes([77; 32])),
        (6, bytes([77; 32])),
        (9, integer(0)),
        (9, Value::Array(vec![integer(0)])),
        (
            9,
            Value::Array(vec![
                Value::Text("a".to_owned()),
                Value::Text("a".to_owned()),
            ]),
        ),
        (
            9,
            Value::Array(vec![
                Value::Text("bb".to_owned()),
                Value::Text("a".to_owned()),
            ]),
        ),
        (10, integer(0)),
        (10, Value::Array(Vec::new())),
    ] {
        let mut fields = unsigned();
        fields[index] = replacement;
        assert!(
            InstallationManifest::from_cbor(&manifest_bytes(fields)?).is_err(),
            "field {index}"
        );
    }
    let mut fields = unsigned();
    fields.pop();
    assert!(InstallationManifest::from_cbor(&manifest_bytes(fields)?).is_err());
    for wrapper in [
        Value::Null,
        Value::Array(Vec::new()),
        Value::Array(vec![Value::Array(unsigned()), bytes([0; 32])]),
    ] {
        assert!(InstallationManifest::from_cbor(&encode(&wrapper)?).is_err());
    }
    Ok(())
}

#[test]
fn manifest_rejects_socket_aliases_and_unsafe_components() -> TestResult {
    for socket in [
        "",
        "relative.sock",
        "/run/elsewhere/a.sock",
        "/run/pigloros/",
        "/run/pigloros/a/",
        "/run/pigloros//a.sock",
        "/run/pigloros/./a.sock",
        "/run/pigloros/../a.sock",
        "/run/pigloros/a\0.sock",
        super::super::SANDBOX_SELECTOR_SOCKET,
        SANDBOX_ADMIN_SOCKET,
        &format!("/run/pigloros/{}", "x".repeat(95)),
    ] {
        for index in [7, 8] {
            let mut fields = unsigned();
            fields[index] = Value::Text(socket.to_owned());
            assert!(
                InstallationManifest::from_cbor(&manifest_bytes(fields)?).is_err(),
                "socket {socket:?}"
            );
        }
    }
    let mut fields = unsigned();
    fields[8] = fields[7].clone();
    assert!(InstallationManifest::from_cbor(&manifest_bytes(fields)?).is_err());
    let mut fields = unsigned();
    fields[7] = Value::Text(format!("/run/pigloros/{}", "x".repeat(94)));
    assert!(InstallationManifest::from_cbor(&manifest_bytes(fields)?).is_ok());
    Ok(())
}

#[test]
fn manifest_enforces_closed_typed_index_and_raw_digest_roles() -> TestResult {
    for (index, replacement) in [
        (0, integer(16)),
        (0, integer(256)),
        (0, Value::Text("0".to_owned())),
        (1, bytes([0; 32])),
        (2, bytes([0; 32])),
        (3, integer(0)),
        (3, integer(OBJECT_LIMIT + 1)),
        (3, Value::Null),
    ] {
        let mut fields = unsigned();
        let mut entries: Vec<_> = (0..16).map(object).collect();
        let mut first = array(&entries[0], 4)?.to_vec();
        first[index] = replacement;
        entries[0] = Value::Array(first);
        fields[10] = Value::Array(entries);
        assert!(InstallationManifest::from_cbor(&manifest_bytes(fields)?).is_err());
    }
    for code in 10..16 {
        let mut fields = unsigned();
        let mut entries: Vec<_> = (0..16).map(object).collect();
        let mut changed = array(&entries[usize::from(code)], 4)?.to_vec();
        changed[1] = bytes([99; 32]);
        entries[usize::from(code)] = Value::Array(changed);
        fields[10] = Value::Array(entries);
        assert!(InstallationManifest::from_cbor(&manifest_bytes(fields)?).is_err());
    }
    for bad_entries in [
        vec![object(0), object(0), object(1), object(2)],
        vec![object(1), object(0), object(2)],
        vec![object(0), object(1), Value::Null],
        vec![object(0), object(1), Value::Array(Vec::new())],
    ] {
        let mut fields = unsigned();
        fields[10] = Value::Array(bad_entries);
        assert!(InstallationManifest::from_cbor(&manifest_bytes(fields)?).is_err());
    }
    Ok(())
}

struct InstallationFixture {
    directory: tempfile::TempDir,
    root: File,
    owner: u32,
}

impl InstallationFixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = File::open(directory.path())?;
        let owner = root.metadata()?.uid();
        for name in ["authority", "providers", "images"] {
            std::fs::create_dir(directory.path().join(name))?;
        }
        for code in 0..16 {
            let kind = InstallationObjectKind::from_code(code)?;
            let content = [code; 32];
            let name = digest_name(*blake3::hash(&content).as_bytes());
            let path = directory.path().join(kind.directory()).join(name);
            std::fs::write(&path, content)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(kind.mode()))?;
        }
        let manifest = directory.path().join(MANIFEST_NAME);
        std::fs::write(&manifest, manifest_bytes(unsigned())?)?;
        std::fs::set_permissions(manifest, std::fs::Permissions::from_mode(0o400))?;
        Ok(Self {
            directory,
            root,
            owner,
        })
    }

    fn object_path(&self, code: u8) -> Result<std::path::PathBuf, ProtocolError> {
        let kind = InstallationObjectKind::from_code(code)?;
        Ok(self
            .directory
            .path()
            .join(kind.directory())
            .join(digest_name(*blake3::hash(&[code; 32]).as_bytes())))
    }

    fn load(&self) -> Result<InstalledSelectorObjects, SelectorBoundaryError> {
        InstalledSelectorObjects::open_at(&self.root, self.owner)
    }
}

#[test]
fn installed_objects_retain_all_roles_across_path_replacement() -> TestResult {
    let fixture = InstallationFixture::new()?;
    let installed = fixture.load()?;
    assert_eq!(installed.manifest_bytes(), manifest_bytes(unsigned())?);
    assert_eq!(installed.manifest_file().metadata()?.mode() & 0o7777, 0o400);
    assert_eq!(installed.manifest().objects().len(), 16);
    for code in 0..16 {
        let kind = InstallationObjectKind::from_code(code)?;
        let content = *blake3::hash(&[code; 32]).as_bytes();
        let identity = if code >= 10 { content } else { [code + 1; 32] };
        let artifact = installed.artifact(kind, identity)?;
        assert_eq!(artifact.digest(), content);
        assert_eq!(artifact.length(), 32);
        let path = fixture.object_path(code)?;
        std::fs::rename(&path, path.with_extension("old"))?;
        std::fs::write(&path, [77; 32])?;
        assert_eq!(artifact.read_bytes()?, [code; 32]);
    }
    assert!(installed
        .artifact(InstallationObjectKind::from_code(0)?, [255; 32])
        .is_err());
    assert!(fixture.load().is_err());
    Ok(())
}

#[test]
fn installation_loader_rejects_wrong_owner_unsafe_modes_and_links() -> TestResult {
    let fixture = InstallationFixture::new()?;
    assert!(
        InstalledSelectorObjects::open_at(&fixture.root, fixture.owner.wrapping_add(1)).is_err()
    );
    for mode in [0o777, 0o720, 0o702] {
        fixture
            .root
            .set_permissions(std::fs::Permissions::from_mode(mode))?;
        assert!(fixture.load().is_err());
    }
    fixture
        .root
        .set_permissions(std::fs::Permissions::from_mode(0o700))?;
    for code in 0..16 {
        let path = fixture.object_path(code)?;
        let original_mode = InstallationObjectKind::from_code(code)?.mode();
        for mode in [0o600, 0o440, 0o444, 0o4500] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
            assert!(fixture.load().is_err(), "role {code}, mode {mode:o}");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(original_mode))?;
        let alias = path.with_extension("alias");
        std::fs::hard_link(&path, &alias)?;
        assert!(fixture.load().is_err());
        std::fs::remove_file(&alias)?;
        std::fs::rename(&path, &alias)?;
        symlink(&alias, &path)?;
        assert!(fixture.load().is_err());
        std::fs::remove_file(&path)?;
        std::fs::rename(&alias, &path)?;
    }
    assert!(fixture.load().is_ok());
    Ok(())
}

#[test]
fn installation_loader_rejects_bad_manifest_and_object_content() -> TestResult {
    for replacement in [Vec::new(), vec![0; 31], vec![0; 32], vec![0; 33]] {
        let fixture = InstallationFixture::new()?;
        let path = fixture.object_path(1)?;
        std::fs::remove_file(&path)?;
        std::fs::write(&path, replacement)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
        assert!(fixture.load().is_err());
    }
    for replacement in [
        Vec::new(),
        vec![0],
        manifest_bytes({
            let mut fields = unsigned();
            fields[4] = bytes([33; 32]);
            fields
        })?,
    ] {
        let fixture = InstallationFixture::new()?;
        let path = fixture.directory.path().join(MANIFEST_NAME);
        std::fs::remove_file(&path)?;
        std::fs::write(&path, replacement)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
        assert!(fixture.load().is_err());
    }
    let fixture = InstallationFixture::new()?;
    std::fs::remove_file(fixture.object_path(2)?)?;
    assert!(fixture.load().is_err());
    Ok(())
}

#[test]
fn installation_loader_checks_every_held_directory() -> TestResult {
    for name in ["authority", "providers", "images"] {
        let fixture = InstallationFixture::new()?;
        let path = fixture.directory.path().join(name);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777))?;
        assert!(fixture.load().is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        let moved = path.with_extension("old");
        std::fs::rename(&path, &moved)?;
        symlink(&moved, &path)?;
        assert!(fixture.load().is_err());
    }
    let fixture = InstallationFixture::new()?;
    for relative in ["../escape", "/absolute", "."] {
        assert!(open_directory_chain(
            fixture.root.try_clone()?,
            Path::new(relative),
            fixture.owner
        )
        .is_err());
    }
    let file = File::open(fixture.object_path(0)?)?;
    assert!(InstalledSelectorObjects::open_at(&file, fixture.owner).is_err());
    Ok(())
}
