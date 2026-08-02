//! Private `OwnTracks` enrollment material helpers.
//!
//! This module deliberately owns local credentials only. It does not open a
//! store, register an HTTP route, or append Timeline Events.

use pos_core::{
    EntityId, GeoLocationAdmissionFenceV1, OwnTracksEnrollmentRequestV1,
    OwnTracksEnrollmentStatusV1, OwnTracksEnrollmentStore, TimelineId,
};
use pos_store::open_owntracks_enrollment_store;
use rand::Rng;
use serde::Deserialize;
use std::path::Path;
use thiserror::Error;
use ulid::Ulid;

const OWNER_KEY_BYTES: usize = 32;
const CREDENTIAL_BYTES: usize = 32;
const VERIFIER_DOMAIN: &[u8] = b"pigloros/owntracks/verifier/v1\0";
const CONSENT_DOMAIN: &[u8] = b"pigloros/owntracks/consent/v1\0";

/// A local owner key, never printable by this module.
pub(crate) type OwnerKey = [u8; OWNER_KEY_BYTES];

/// The plaintext enrollment material displayed exactly once by the CLI layer.
#[derive(PartialEq, Eq)]
pub(crate) struct PairingCredential {
    handle: [u8; CREDENTIAL_BYTES],
    secret: [u8; CREDENTIAL_BYTES],
}

impl PairingCredential {
    #[must_use]
    pub(crate) fn handle(&self) -> &[u8; CREDENTIAL_BYTES] {
        &self.handle
    }

    #[must_use]
    pub(crate) fn secret(&self) -> &[u8; CREDENTIAL_BYTES] {
        &self.secret
    }

    /// Render the only intended plaintext representation for the local CLI.
    #[must_use]
    pub(crate) fn terminal_display(&self) -> String {
        format!(
            "OwnTracks handle: {}\nOwnTracks secret: {}\nStore these values securely; the secret is shown only once.",
            hex(self.handle()),
            hex(self.secret())
        )
    }
}

/// Fail-closed local owner-key errors. No variant carries credential bytes.
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum OwnTracksMaterialError {
    /// Unix owner-only filesystem guarantees are unavailable.
    #[cfg(not(unix))]
    #[error("OwnTracks owner-key files require Unix owner-only permissions")]
    UnsupportedPlatform,
    /// The path or a path component violates the owner-key safety policy.
    #[error("OwnTracks owner-key path is unsafe")]
    UnsafeOwnerKeyPath,
    /// A durable owner key cannot be read or written safely.
    #[error("OwnTracks owner-key file operation failed")]
    OwnerKeyIo,
    /// A pre-existing owner key is not exactly 32 bytes.
    #[error("OwnTracks owner-key file has an invalid length")]
    InvalidOwnerKeyLength,
    /// An operation requiring the existing owner key cannot find one.
    #[error("OwnTracks owner-key file is unavailable")]
    MissingOwnerKey,
}

/// Bounded local-command errors that never include key or credential material.
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum OwnTracksCommandError {
    /// The supplied command arguments do not match the accepted local surface.
    #[error("Usage: piglor-gateway owntracks <pair|status|rotate|revoke> ...")]
    Usage,
    /// A pair argument did not identify a valid core object.
    #[error("OwnTracks pair requires valid timeline and entity identifiers")]
    InvalidPairTarget,
    /// Pairing cannot proceed without an approved policy/consent source.
    #[error("OwnTracks policy configuration is unavailable")]
    PolicyConfigurationUnavailable,
    /// The current durable enrollment does not permit the requested transition.
    #[error("OwnTracks enrollment transition is unavailable")]
    EnrollmentTransitionUnavailable,
    /// The durable enrollment state cannot be opened or read.
    #[error("OwnTracks enrollment state is unavailable")]
    EnrollmentStateUnavailable,
    /// Owner-key material failed a fail-closed safety check.
    #[error(transparent)]
    OwnerKey(#[from] OwnTracksMaterialError),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsentPolicyToml {
    schema_version: u8,
    consent_identity: String,
    consent_revision: u64,
    policy_version: u32,
    binding_revision: u64,
    withdrawn: bool,
    purpose: String,
    precision: String,
    source_time_bucket: String,
    visibility: String,
}

struct ConsentPolicyV1 {
    consent_identity: [u8; 32],
    consent_revision: u64,
    policy_version: u32,
    binding_revision: u64,
    consent_hash: [u8; 32],
}

fn parse_consent_policy(text: &str) -> Result<ConsentPolicyV1, OwnTracksCommandError> {
    let raw: ConsentPolicyToml =
        toml::from_str(text).map_err(|_| OwnTracksCommandError::PolicyConfigurationUnavailable)?;
    if raw.schema_version != 1
        || raw.consent_revision == 0
        || raw.policy_version == 0
        || raw.binding_revision == 0
        || raw.withdrawn
        || raw.purpose != "local_pairing"
        || raw.precision != "exact"
        || raw.source_time_bucket != "minute"
        || raw.visibility != "paired_devices_only"
    {
        return Err(OwnTracksCommandError::PolicyConfigurationUnavailable);
    }
    let consent_identity = decode_lower_hex_32(&raw.consent_identity)?;
    let canonical = format!(
        "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        raw.consent_identity,
        raw.consent_revision,
        raw.policy_version,
        raw.binding_revision,
        raw.purpose,
        raw.precision,
        raw.source_time_bucket,
        raw.visibility
    );
    Ok(ConsentPolicyV1 {
        consent_identity,
        consent_revision: raw.consent_revision,
        policy_version: raw.policy_version,
        binding_revision: raw.binding_revision,
        consent_hash: *blake3::hash(&[CONSENT_DOMAIN, canonical.as_bytes()].concat()).as_bytes(),
    })
}

fn decode_lower_hex_32(value: &str) -> Result<[u8; 32], OwnTracksCommandError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(OwnTracksCommandError::PolicyConfigurationUnavailable);
    }
    let mut decoded = [0; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Ok(decoded)
}

fn hex_nibble(byte: u8) -> Result<u8, OwnTracksCommandError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(OwnTracksCommandError::PolicyConfigurationUnavailable),
    }
}

/// Execute one local `OwnTracks` administration command and return safe terminal output.
pub(crate) fn execute(arguments: &[String]) -> Result<String, OwnTracksCommandError> {
    match arguments {
        [command, sqlite_path, owner_key_path, option, policy_path, timeline, entity]
            if command == "pair" && option == "--consent-policy" =>
        {
            let (timeline, entity) = parse_pair_target(timeline, entity)?;
            let policy_text = std::fs::read_to_string(policy_path)
                .map_err(|_| OwnTracksCommandError::PolicyConfigurationUnavailable)?;
            let policy = parse_consent_policy(&policy_text)?;
            let mut store = enrollment_store(sqlite_path)?;
            if store
                .owntracks_enrollment_status()
                .map_err(|_| OwnTracksCommandError::EnrollmentTransitionUnavailable)?
                .status()
                == OwnTracksEnrollmentStatusV1::Active
            {
                return Err(OwnTracksCommandError::EnrollmentTransitionUnavailable);
            }
            let owner_key = create_or_load_owner_key(Path::new(owner_key_path))?;
            let credential = generate_pairing_credential();
            let request = OwnTracksEnrollmentRequestV1::new(
                timeline,
                entity,
                GeoLocationAdmissionFenceV1::new(
                    policy.binding_revision,
                    (
                        policy.consent_identity,
                        policy.consent_revision,
                        policy.consent_hash,
                    ),
                    (policy.policy_version, false, 1),
                ),
                derive_owntracks_verifier(&owner_key, &credential),
            );
            store
                .pair_owntracks_enrollment(request)
                .map_err(|_| OwnTracksCommandError::EnrollmentTransitionUnavailable)?;
            Ok(credential.terminal_display())
        }
        [command, sqlite_path] if command == "status" => {
            let store = enrollment_store(sqlite_path)?;
            let status = store
                .owntracks_enrollment_status()
                .map_err(|_| OwnTracksCommandError::EnrollmentStateUnavailable)?;
            Ok(format!(
                "OwnTracks status: {}\nPolicy version: {}",
                status_label(status.status()),
                status
                    .policy_version()
                    .map_or_else(|| "none".to_owned(), |version| version.to_string())
            ))
        }
        [command, sqlite_path, owner_key_path] if command == "rotate" => {
            let mut store = enrollment_store(sqlite_path)?;
            let status = store
                .owntracks_enrollment_status()
                .map_err(|_| OwnTracksCommandError::EnrollmentStateUnavailable)?;
            if status.status() != OwnTracksEnrollmentStatusV1::Active {
                return Err(OwnTracksCommandError::EnrollmentTransitionUnavailable);
            }
            let owner_key = load_owner_key(Path::new(owner_key_path))?;
            let credential = generate_pairing_credential();
            store
                .rotate_owntracks_enrollment_verifier(derive_owntracks_verifier(
                    &owner_key,
                    &credential,
                ))
                .map_err(|_| OwnTracksCommandError::EnrollmentTransitionUnavailable)?;
            Ok(credential.terminal_display())
        }
        [command, sqlite_path] if command == "revoke" => {
            let mut store = enrollment_store(sqlite_path)?;
            store
                .revoke_owntracks_enrollment()
                .map_err(|_| OwnTracksCommandError::EnrollmentTransitionUnavailable)?;
            Ok("OwnTracks enrollment revoked".to_owned())
        }
        _ => Err(OwnTracksCommandError::Usage),
    }
}

fn parse_pair_target(
    timeline: &str,
    entity: &str,
) -> Result<(TimelineId, EntityId), OwnTracksCommandError> {
    let timeline = Ulid::from_string(timeline)
        .map(TimelineId::from_ulid)
        .map_err(|_| OwnTracksCommandError::InvalidPairTarget)?;
    let entity = Ulid::from_string(entity)
        .map(EntityId::from_ulid)
        .map_err(|_| OwnTracksCommandError::InvalidPairTarget)?;
    Ok((timeline, entity))
}

fn enrollment_store(
    sqlite_path: &str,
) -> Result<Box<dyn OwnTracksEnrollmentStore>, OwnTracksCommandError> {
    open_owntracks_enrollment_store(sqlite_path)
        .map_err(|_| OwnTracksCommandError::EnrollmentStateUnavailable)
}

const fn status_label(status: OwnTracksEnrollmentStatusV1) -> &'static str {
    match status {
        OwnTracksEnrollmentStatusV1::Absent => "unpaired",
        OwnTracksEnrollmentStatusV1::Active => "active",
        OwnTracksEnrollmentStatusV1::Revoked => "revoked",
    }
}

/// Load an existing safe owner key or create a fresh one at a new safe path.
///
/// On Unix, creation follows the established signing-key policy: every path
/// component is checked, output creation is atomic and owner-only, and both the
/// file and containing directory are synchronized before success.
pub(crate) fn create_or_load_owner_key(path: &Path) -> Result<OwnerKey, OwnTracksMaterialError> {
    create_or_load_owner_key_platform(path)
}

/// Load an existing safe owner key without generating replacement material.
pub(crate) fn load_owner_key(path: &Path) -> Result<OwnerKey, OwnTracksMaterialError> {
    load_owner_key_platform(path)
}

/// Generate independent Basic handle and secret values from the operating-system RNG.
#[must_use]
pub(crate) fn generate_pairing_credential() -> PairingCredential {
    let mut handle = [0_u8; CREDENTIAL_BYTES];
    let mut secret = [0_u8; CREDENTIAL_BYTES];
    let mut rng = rand::rng();
    rng.fill(&mut handle);
    rng.fill(&mut secret);
    PairingCredential { handle, secret }
}

/// Derive the durable verifier; plaintext credential values are not persisted.
#[must_use]
pub(crate) fn derive_owntracks_verifier(
    owner_key: &OwnerKey,
    credential: &PairingCredential,
) -> [u8; CREDENTIAL_BYTES] {
    let mut material = [0_u8; VERIFIER_DOMAIN.len() + (CREDENTIAL_BYTES * 2)];
    material[..VERIFIER_DOMAIN.len()].copy_from_slice(VERIFIER_DOMAIN);
    material[VERIFIER_DOMAIN.len()..VERIFIER_DOMAIN.len() + CREDENTIAL_BYTES]
        .copy_from_slice(credential.handle());
    material[VERIFIER_DOMAIN.len() + CREDENTIAL_BYTES..].copy_from_slice(credential.secret());
    *blake3::keyed_hash(owner_key, &material).as_bytes()
}

#[cfg(unix)]
fn create_or_load_owner_key_platform(path: &Path) -> Result<OwnerKey, OwnTracksMaterialError> {
    let absolute = validated_owner_key_path(path)?;
    match std::fs::symlink_metadata(&absolute) {
        Ok(metadata) => load_existing_owner_key(&absolute, &metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_owner_key(&absolute),
        Err(_) => Err(OwnTracksMaterialError::OwnerKeyIo),
    }
}

#[cfg(unix)]
fn load_owner_key_platform(path: &Path) -> Result<OwnerKey, OwnTracksMaterialError> {
    let absolute = validated_owner_key_path(path)?;
    match std::fs::symlink_metadata(&absolute) {
        Ok(metadata) => load_existing_owner_key(&absolute, &metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(OwnTracksMaterialError::MissingOwnerKey)
        }
        Err(_) => Err(OwnTracksMaterialError::OwnerKeyIo),
    }
}

#[cfg(not(unix))]
fn create_or_load_owner_key_platform(_path: &Path) -> Result<OwnerKey, OwnTracksMaterialError> {
    Err(OwnTracksMaterialError::UnsupportedPlatform)
}

#[cfg(not(unix))]
fn load_owner_key_platform(_path: &Path) -> Result<OwnerKey, OwnTracksMaterialError> {
    Err(OwnTracksMaterialError::UnsupportedPlatform)
}

#[cfg(unix)]
fn validated_owner_key_path(path: &Path) -> Result<std::path::PathBuf, OwnTracksMaterialError> {
    let absolute = absolute_path(path)?;
    let parent = absolute
        .parent()
        .ok_or(OwnTracksMaterialError::UnsafeOwnerKeyPath)?;
    validate_ancestors(parent)?;
    Ok(absolute)
}

#[cfg(unix)]
fn absolute_path(path: &Path) -> Result<std::path::PathBuf, OwnTracksMaterialError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|_| OwnTracksMaterialError::OwnerKeyIo)
    }
}

#[cfg(unix)]
fn validate_ancestors(parent: &Path) -> Result<(), OwnTracksMaterialError> {
    use std::os::unix::fs::MetadataExt;

    for (distance, ancestor) in parent.ancestors().enumerate() {
        let metadata =
            std::fs::symlink_metadata(ancestor).map_err(|_| OwnTracksMaterialError::OwnerKeyIo)?;
        let mode = metadata.mode();
        let writable_by_group_or_other = mode & 0o022 != 0;
        let sticky = mode & 0o1000 != 0;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (writable_by_group_or_other && (distance == 0 || !sticky))
        {
            return Err(OwnTracksMaterialError::UnsafeOwnerKeyPath);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn load_existing_owner_key(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<OwnerKey, OwnTracksMaterialError> {
    use std::os::unix::fs::MetadataExt;

    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.mode() & 0o077 != 0 {
        return Err(OwnTracksMaterialError::UnsafeOwnerKeyPath);
    }
    if metadata.len() != OWNER_KEY_BYTES as u64 {
        return Err(OwnTracksMaterialError::InvalidOwnerKeyLength);
    }
    let bytes = std::fs::read(path).map_err(|_| OwnTracksMaterialError::OwnerKeyIo)?;
    bytes
        .try_into()
        .map_err(|_| OwnTracksMaterialError::InvalidOwnerKeyLength)
}

#[cfg(unix)]
fn create_owner_key(path: &Path) -> Result<OwnerKey, OwnTracksMaterialError> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let parent = path
        .parent()
        .ok_or(OwnTracksMaterialError::UnsafeOwnerKeyPath)?;
    let parent_file =
        std::fs::File::open(parent).map_err(|_| OwnTracksMaterialError::OwnerKeyIo)?;
    let mut owner_key = [0_u8; OWNER_KEY_BYTES];
    rand::rng().fill(&mut owner_key);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| OwnTracksMaterialError::OwnerKeyIo)?;
    let Ok(created) = file.metadata() else {
        drop(file);
        cleanup_owner_key(path, &parent_file);
        return Err(OwnTracksMaterialError::OwnerKeyIo);
    };
    if !created.is_file() || created.mode() & 0o077 != 0 {
        drop(file);
        cleanup_owner_key(path, &parent_file);
        return Err(OwnTracksMaterialError::UnsafeOwnerKeyPath);
    }
    if file
        .write_all(&owner_key)
        .and_then(|()| file.sync_all())
        .is_err()
    {
        drop(file);
        cleanup_owner_key(path, &parent_file);
        return Err(OwnTracksMaterialError::OwnerKeyIo);
    }
    drop(file);
    if parent_file.sync_all().is_err() {
        cleanup_owner_key(path, &parent_file);
        return Err(OwnTracksMaterialError::OwnerKeyIo);
    }
    Ok(owner_key)
}

#[cfg(unix)]
fn cleanup_owner_key(path: &Path, parent: &std::fs::File) {
    let _ = std::fs::remove_file(path);
    let _ = parent.sync_all();
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::{create_or_load_owner_key, derive_owntracks_verifier, generate_pairing_credential};
    use pos_core::{
        EntityId, EventStore, GeoLocationAdmissionFenceV1, OwnTracksEnrollmentRequestV1,
        OwnTracksEnrollmentStore, TimelineId,
    };
    use pos_store::sqlite::SqliteStore;
    use std::os::unix::fs::{symlink, MetadataExt};

    fn temporary_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "piglor-gateway-owntracks-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock after Unix epoch")
                .as_nanos()
        ))
    }

    #[cfg(unix)]
    #[test]
    fn creates_a_32_byte_owner_only_key_and_rejects_unsafe_existing_paths() {
        let directory = temporary_path("owner-key");
        std::fs::create_dir(&directory).expect("create private temporary directory");
        let key_path = directory.join("owner.key");

        let key = create_or_load_owner_key(&key_path).expect("create owner key");
        assert_eq!(key.len(), 32);
        let metadata = std::fs::metadata(&key_path).expect("inspect created owner key");
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&key_path).expect("read owner key"), key);

        std::fs::write(directory.join("bad.key"), b"not-a-32-byte-owner-key")
            .expect("write malformed existing key");
        let existing_error = create_or_load_owner_key(&directory.join("bad.key"))
            .expect_err("malformed existing key is rejected");
        assert!(!existing_error
            .to_string()
            .contains("not-a-32-byte-owner-key"));

        symlink(&key_path, directory.join("link.key")).expect("create owner key symlink");
        let symlink_error = create_or_load_owner_key(&directory.join("link.key"))
            .expect_err("symlink owner key is rejected");
        assert!(!symlink_error.to_string().contains("owner.key"));

        std::fs::remove_dir_all(directory).expect("remove temporary directory");
    }

    #[test]
    fn credentials_are_independent_and_only_the_terminal_renderer_exposes_plaintext() {
        let owner_key = [17; 32];
        let first = generate_pairing_credential();
        let second = generate_pairing_credential();

        assert_ne!(first.handle(), first.secret());
        assert_ne!(first.handle(), second.handle());
        assert_ne!(first.secret(), second.secret());
        assert_ne!(
            derive_owntracks_verifier(&owner_key, &first),
            derive_owntracks_verifier(&owner_key, &second)
        );
        let terminal = first.terminal_display();
        assert!(terminal.contains("OwnTracks handle:"));
        assert!(terminal.contains("OwnTracks secret:"));
        assert!(!terminal.contains("verifier"));
    }

    #[test]
    fn consent_policy_is_strict_and_its_hash_is_domain_separated() {
        let policy = "schema_version = 1\nconsent_identity = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\nconsent_revision = 1\npolicy_version = 1\nbinding_revision = 1\nwithdrawn = false\npurpose = \"local_pairing\"\nprecision = \"exact\"\nsource_time_bucket = \"minute\"\nvisibility = \"paired_devices_only\"\n";
        let parsed = super::parse_consent_policy(policy).expect("parse V1 consent policy");
        assert_ne!(parsed.consent_hash, [0; 32]);
        assert!(super::parse_consent_policy(&format!("{policy}extra = 1\n")).is_err());
        assert!(super::parse_consent_policy(
            &policy.replace("withdrawn = false", "withdrawn = true")
        )
        .is_err());
        for invalid in [
            policy.replace("consent_revision = 1", "consent_revision = 0"),
            policy.replace("policy_version = 1", "policy_version = 0"),
            policy.replace("binding_revision = 1", "binding_revision = 0"),
            policy.replace("purpose = \"local_pairing\"", "purpose = \"other\""),
            policy.replace("precision = \"exact\"", "precision = \"coarse\""),
            policy.replace(
                "source_time_bucket = \"minute\"",
                "source_time_bucket = \"hour\"",
            ),
            policy.replace(
                "visibility = \"paired_devices_only\"",
                "visibility = \"public\"",
            ),
            policy.replace("0123456789abcdef", "0123456789ABCDEF"),
        ] {
            assert!(super::parse_consent_policy(&invalid).is_err());
        }
        assert_ne!(
            parsed.consent_hash,
            super::parse_consent_policy(
                &policy.replace("consent_revision = 1", "consent_revision = 2")
            )
            .expect("parse changed policy")
            .consent_hash
        );
    }

    #[test]
    fn local_commands_are_bounded_and_pair_fails_before_creating_material_without_policy() {
        let directory = temporary_path("commands");
        std::fs::create_dir(&directory).expect("create private temporary directory");
        let database = directory.join("owntracks.db");
        let key_path = directory.join("owner.key");
        let policy_path = directory.join("invalid-consent.toml");
        std::fs::write(&policy_path, "schema_version = 1\ninvalid = true\n")
            .expect("write invalid policy");
        let database = database.to_str().expect("UTF-8 database path").to_owned();
        let key_path = key_path.to_str().expect("UTF-8 owner key path").to_owned();
        let timeline = TimelineId::new().to_string();
        let entity = EntityId::new().to_string();

        let status = super::execute(&["status".to_owned(), database.clone()])
            .expect("status command succeeds");
        assert_eq!(status, "OwnTracks status: unpaired\nPolicy version: none");

        let pair_error = super::execute(&[
            "pair".to_owned(),
            database,
            key_path.clone(),
            "--consent-policy".to_owned(),
            policy_path.display().to_string(),
            timeline,
            entity,
        ])
        .expect_err("invalid policy is rejected before creating material");
        assert_eq!(
            pair_error.to_string(),
            "OwnTracks policy configuration is unavailable"
        );
        assert!(!std::path::Path::new(&key_path).exists());

        let target_error = super::execute(&[
            "pair".to_owned(),
            "unused.db".to_owned(),
            key_path.clone(),
            "--consent-policy".to_owned(),
            "missing-consent.toml".to_owned(),
            "not-a-timeline".to_owned(),
            "not-an-entity".to_owned(),
        ])
        .expect_err("invalid pair target is rejected before policy lookup");
        assert_eq!(
            target_error.to_string(),
            "OwnTracks pair requires valid timeline and entity identifiers"
        );

        let usage = super::execute(&["rotate".to_owned()])
            .expect_err("missing rotate arguments are rejected");
        assert!(usage.to_string().contains("Usage:"));

        std::fs::remove_dir_all(directory).expect("remove temporary directory");
    }

    #[test]
    fn pair_validated_policy_creates_one_active_enrollment() {
        let directory = temporary_path("pair");
        std::fs::create_dir(&directory).expect("create private temporary directory");
        let database = directory.join("owntracks.db");
        let owner_key = directory.join("owner.key");
        let policy = directory.join("consent.toml");
        let timeline = {
            let mut store = SqliteStore::open(database.to_str().expect("UTF-8 database path"))
                .expect("open fixture store");
            store
                .create_timeline("OwnTracks pair fixture")
                .expect("create fixture timeline")
                .id()
        };
        std::fs::write(&policy, "schema_version = 1\nconsent_identity = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\nconsent_revision = 1\npolicy_version = 1\nbinding_revision = 1\nwithdrawn = false\npurpose = \"local_pairing\"\nprecision = \"exact\"\nsource_time_bucket = \"minute\"\nvisibility = \"paired_devices_only\"\n").expect("write policy");
        let output = super::execute(&[
            "pair".to_owned(),
            database.display().to_string(),
            owner_key.display().to_string(),
            "--consent-policy".to_owned(),
            policy.display().to_string(),
            timeline.to_string(),
            EntityId::new().to_string(),
        ])
        .expect("pair");
        assert!(output.contains("OwnTracks secret:"));
        assert!(owner_key.is_file());
        assert_eq!(
            super::execute(&["status".to_owned(), database.display().to_string()]).expect("status"),
            "OwnTracks status: active\nPolicy version: 1"
        );
        let second_pair = super::execute(&[
            "pair".to_owned(),
            database.display().to_string(),
            owner_key.display().to_string(),
            "--consent-policy".to_owned(),
            policy.display().to_string(),
            timeline.to_string(),
            EntityId::new().to_string(),
        ])
        .expect_err("active enrollment rejects a replacement pair");
        assert_eq!(
            second_pair.to_string(),
            "OwnTracks enrollment transition is unavailable"
        );
        std::fs::remove_dir_all(directory).expect("remove temporary directory");
    }

    #[test]
    fn rotate_and_revoke_use_only_the_enrollment_capability() {
        let directory = temporary_path("rotate-revoke");
        std::fs::create_dir(&directory).expect("create private temporary directory");
        let database_path = directory.join("owntracks.db");
        let database = database_path
            .to_str()
            .expect("UTF-8 database path")
            .to_owned();
        let owner_key = directory.join("owner.key");
        let owner_key = owner_key.to_str().expect("UTF-8 owner key path").to_owned();

        let mut store = SqliteStore::open(&database).expect("open fixture store");
        let timeline = store
            .create_timeline("OwnTracks fixture")
            .expect("create timeline");
        let entity = EntityId::new();
        store
            .pair_owntracks_enrollment(OwnTracksEnrollmentRequestV1::new(
                timeline.id(),
                entity,
                GeoLocationAdmissionFenceV1::new(1, ([1; 32], 1, [2; 32]), (1, false, 1)),
                [3; 32],
            ))
            .expect("seed active enrollment");
        drop(store);

        assert_eq!(
            super::execute(&["rotate".to_owned(), database.clone(), owner_key.clone(),])
                .expect_err("rotation cannot replace a missing owner key")
                .to_string(),
            "OwnTracks owner-key file is unavailable"
        );
        assert!(!std::path::Path::new(&owner_key).exists());
        create_or_load_owner_key(std::path::Path::new(&owner_key))
            .expect("create fixture owner key");

        let rotation = super::execute(&["rotate".to_owned(), database.clone(), owner_key.clone()])
            .expect("rotate active enrollment");
        assert!(rotation.contains("OwnTracks handle:"));
        assert!(rotation.contains("OwnTracks secret:"));
        assert!(std::path::Path::new(&owner_key).is_file());

        let second_rotation =
            super::execute(&["rotate".to_owned(), database.clone(), owner_key.clone()])
                .expect("rotate with existing owner key");
        assert_ne!(rotation, second_rotation);

        let revoke = super::execute(&["revoke".to_owned(), database.clone()])
            .expect("revoke active enrollment");
        assert_eq!(revoke, "OwnTracks enrollment revoked");
        let status = super::execute(&["status".to_owned(), database.clone()])
            .expect("read revoked enrollment status");
        assert_eq!(status, "OwnTracks status: revoked\nPolicy version: 1");
        assert_eq!(
            super::execute(&["rotate".to_owned(), database, owner_key])
                .expect_err("revoked enrollment cannot rotate")
                .to_string(),
            "OwnTracks enrollment transition is unavailable"
        );

        std::fs::remove_dir_all(directory).expect("remove temporary directory");
    }

    #[test]
    fn command_module_cannot_activate_ingress_or_generic_timeline_mutation() {
        let source = include_str!("owntracks.rs");
        assert!(!source.contains(&["admit", "_geo_location"].concat()));
        assert!(!source.contains(&[".", "append", "("].concat()));
        assert!(!source.contains(&["router", "("].concat()));
        assert!(!source.contains(&["geo", ".location"].concat()));
    }
}
