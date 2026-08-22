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
pub type OwnerKey = [u8; OWNER_KEY_BYTES];

/// The plaintext enrollment material displayed exactly once by the CLI layer.
#[derive(PartialEq, Eq)]
pub struct PairingCredential {
    handle: [u8; CREDENTIAL_BYTES],
    secret: [u8; CREDENTIAL_BYTES],
}

impl PairingCredential {
    #[must_use]
    pub const fn handle(&self) -> &[u8; CREDENTIAL_BYTES] {
        &self.handle
    }

    #[must_use]
    pub const fn secret(&self) -> &[u8; CREDENTIAL_BYTES] {
        &self.secret
    }

    /// Render the only intended plaintext representation for the local CLI.
    #[must_use]
    pub fn terminal_display(&self) -> String {
        format!(
            "OwnTracks handle: {}\nOwnTracks secret: {}\nStore these values securely; the secret is shown only once.",
            hex(self.handle()),
            hex(self.secret())
        )
    }
}

/// Fail-closed local owner-key errors. No variant carries credential bytes.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OwnTracksMaterialError {
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
pub enum OwnTracksCommandError {
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
        || raw.policy_version != 1
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
        decoded[index] = (hex_nibble(chunk[0]) << 4) | hex_nibble(chunk[1]);
    }
    Ok(decoded)
}

// Callers pre-validate that byte is in b'0'..=b'9' or b'a'..=b'f'.
const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        _ => byte - b'a' + 10,
    }
}

/// Execute one local `OwnTracks` administration command and return safe terminal output.
///
/// # Errors
///
/// Returns an error when the command arguments, policy, store, or local key
/// material cannot be validated.
pub fn execute(arguments: &[String]) -> Result<String, OwnTracksCommandError> {
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
/// Create or load the owner-only key at `path`.
///
/// # Errors
///
/// Returns an error when the path is unsafe or the key cannot be read or
/// created with the required owner-only guarantees.
pub fn create_or_load_owner_key(path: &Path) -> Result<OwnerKey, OwnTracksMaterialError> {
    create_or_load_owner_key_platform(path)
}

/// Load an existing safe owner key without generating replacement material.
/// Load an existing owner-only key from `path`.
///
/// # Errors
///
/// Returns an error when the path is unsafe, missing, malformed, or cannot be
/// read with the required owner-only guarantees.
pub fn load_owner_key(path: &Path) -> Result<OwnerKey, OwnTracksMaterialError> {
    load_owner_key_platform(path)
}

/// Generate independent Basic handle and secret values from the operating-system RNG.
#[must_use]
pub fn generate_pairing_credential() -> PairingCredential {
    let mut handle = [0_u8; CREDENTIAL_BYTES];
    let mut secret = [0_u8; CREDENTIAL_BYTES];
    let mut rng = rand::rng();
    rng.fill(&mut handle);
    rng.fill(&mut secret);
    PairingCredential { handle, secret }
}

/// Derive the durable verifier; plaintext credential values are not persisted.
#[must_use]
pub fn derive_owntracks_verifier(
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
    drop(std::fs::remove_file(path));
    drop(parent.sync_all());
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
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    trait TestResultExt<T, E> {
        fn test_ok(self) -> Result<T, Box<dyn std::error::Error>>;
        fn test_err(self) -> Result<E, Box<dyn std::error::Error>>;
    }

    impl<T, E: std::fmt::Debug> TestResultExt<T, E> for Result<T, E> {
        fn test_ok(self) -> Result<T, Box<dyn std::error::Error>> {
            self.map_err(|error| format!("unexpected error: {error:?}").into())
        }

        fn test_err(self) -> Result<E, Box<dyn std::error::Error>> {
            self.err().ok_or_else(|| "expected an error".into())
        }
    }

    trait TestOptionExt<T> {
        fn test_ok(self) -> Result<T, Box<dyn std::error::Error>>;
    }

    impl<T> TestOptionExt<T> for Option<T> {
        fn test_ok(self) -> Result<T, Box<dyn std::error::Error>> {
            self.ok_or_else(|| "expected a value".into())
        }
    }

    use super::{
        create_or_load_owner_key, derive_owntracks_verifier, generate_pairing_credential,
        load_owner_key, OwnTracksMaterialError,
    };
    use pos_core::{
        EntityId, EventStore, GeoLocationAdmissionFenceV1, OwnTracksEnrollmentRequestV1,
        OwnTracksEnrollmentStore, TimelineId,
    };
    use pos_store::sqlite::SqliteStore;
    use std::{
        os::unix::fs::{symlink, MetadataExt},
        path::Path,
    };

    fn temporary_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "piglor-gateway-owntracks-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    #[cfg(unix)]
    #[test]
    fn creates_a_32_byte_owner_only_key_and_rejects_unsafe_existing_paths(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = temporary_path("owner-key");
        std::fs::create_dir(&directory).test_ok()?;
        let key_path = directory.join("owner.key");

        let key = create_or_load_owner_key(&key_path).test_ok()?;
        assert_eq!(key.len(), 32);
        let metadata = std::fs::metadata(&key_path).test_ok()?;
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&key_path).test_ok()?, key);

        std::fs::write(directory.join("bad.key"), b"not-a-32-byte-owner-key").test_ok()?;
        let existing_error = create_or_load_owner_key(&directory.join("bad.key")).test_err()?;
        assert!(!existing_error
            .to_string()
            .contains("not-a-32-byte-owner-key"));

        symlink(&key_path, directory.join("link.key")).test_ok()?;
        let symlink_error = create_or_load_owner_key(&directory.join("link.key")).test_err()?;
        assert!(!symlink_error.to_string().contains("owner.key"));

        std::fs::remove_dir_all(directory).test_ok()?;

        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn owner_key_paths_cover_relative_and_io_error_branches(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let relative = super::absolute_path(Path::new("relative-owner.key")).test_ok()?;
        assert!(relative.is_absolute());

        let directory = temporary_path("invalid-owner-key");
        std::fs::create_dir(&directory).test_ok()?;
        let invalid_path = directory.join("owner\0.key");
        let create_result = create_or_load_owner_key(&invalid_path);
        assert!(matches!(
            create_result,
            Err(OwnTracksMaterialError::OwnerKeyIo)
        ));
        assert!(matches!(
            load_owner_key(&invalid_path),
            Err(OwnTracksMaterialError::OwnerKeyIo)
        ));
        std::fs::remove_dir_all(directory).test_ok()?;

        Ok(())
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
    fn consent_policy_is_strict_and_its_hash_is_domain_separated(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let policy = "schema_version = 1\nconsent_identity = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\nconsent_revision = 1\npolicy_version = 1\nbinding_revision = 1\nwithdrawn = false\npurpose = \"local_pairing\"\nprecision = \"exact\"\nsource_time_bucket = \"minute\"\nvisibility = \"paired_devices_only\"\n";
        let parsed = super::parse_consent_policy(policy).test_ok()?;
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
            .test_ok()?
            .consent_hash
        );

        Ok(())
    }

    #[test]
    fn local_commands_are_bounded_and_pair_fails_before_creating_material_without_policy(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = temporary_path("commands");
        std::fs::create_dir(&directory).test_ok()?;
        let database = directory.join("owntracks.db");
        let key_path = directory.join("owner.key");
        let policy_path = directory.join("invalid-consent.toml");
        std::fs::write(&policy_path, "schema_version = 1\ninvalid = true\n").test_ok()?;
        let database = database.to_str().test_ok()?.to_owned();
        let key_path = key_path.to_str().test_ok()?.to_owned();
        let timeline = TimelineId::new().to_string();
        let entity = EntityId::new().to_string();

        let status = super::execute(&["status".to_owned(), database.clone()]).test_ok()?;
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
        .test_err()?;
        assert_eq!(
            pair_error.to_string(),
            "OwnTracks policy configuration is unavailable"
        );
        assert!(!std::path::Path::new(&key_path).exists());

        let target_error = super::execute(&[
            "pair".to_owned(),
            "unused.db".to_owned(),
            key_path,
            "--consent-policy".to_owned(),
            "missing-consent.toml".to_owned(),
            "not-a-timeline".to_owned(),
            "not-an-entity".to_owned(),
        ])
        .test_err()?;
        assert_eq!(
            target_error.to_string(),
            "OwnTracks pair requires valid timeline and entity identifiers"
        );

        let usage = super::execute(&["rotate".to_owned()]).test_err()?;
        assert!(usage.to_string().contains("Usage:"));

        std::fs::remove_dir_all(directory).test_ok()?;

        Ok(())
    }

    #[test]
    fn pair_validated_policy_creates_one_active_enrollment(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = temporary_path("pair");
        std::fs::create_dir(&directory).test_ok()?;
        let database = directory.join("owntracks.db");
        let owner_key = directory.join("owner.key");
        let policy = directory.join("consent.toml");
        let timeline = {
            let mut store = SqliteStore::open(database.to_str().test_ok()?).test_ok()?;
            store
                .create_timeline("OwnTracks pair fixture")
                .test_ok()?
                .id()
        };
        std::fs::write(&policy, "schema_version = 1\nconsent_identity = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\nconsent_revision = 1\npolicy_version = 1\nbinding_revision = 1\nwithdrawn = false\npurpose = \"local_pairing\"\nprecision = \"exact\"\nsource_time_bucket = \"minute\"\nvisibility = \"paired_devices_only\"\n").test_ok()?;
        let output = super::execute(&[
            "pair".to_owned(),
            database.display().to_string(),
            owner_key.display().to_string(),
            "--consent-policy".to_owned(),
            policy.display().to_string(),
            timeline.to_string(),
            EntityId::new().to_string(),
        ])
        .test_ok()?;
        assert!(output.contains("OwnTracks secret:"));
        assert!(owner_key.is_file());
        assert_eq!(
            super::execute(&["status".to_owned(), database.display().to_string()]).test_ok()?,
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
        .test_err()?;
        assert_eq!(
            second_pair.to_string(),
            "OwnTracks enrollment transition is unavailable"
        );
        std::fs::remove_dir_all(directory).test_ok()?;

        Ok(())
    }

    #[test]
    fn rotate_and_revoke_use_only_the_enrollment_capability(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = temporary_path("rotate-revoke");
        std::fs::create_dir(&directory).test_ok()?;
        let database_path = directory.join("owntracks.db");
        let database = database_path.to_str().test_ok()?.to_owned();
        let owner_key = directory.join("owner.key");
        let owner_key = owner_key.to_str().test_ok()?.to_owned();

        let mut store = SqliteStore::open(&database).test_ok()?;
        let timeline = store.create_timeline("OwnTracks fixture").test_ok()?;
        let entity = EntityId::new();
        store
            .pair_owntracks_enrollment(OwnTracksEnrollmentRequestV1::new(
                timeline.id(),
                entity,
                GeoLocationAdmissionFenceV1::new(1, ([1; 32], 1, [2; 32]), (1, false, 1)),
                [3; 32],
            ))
            .test_ok()?;
        drop(store);

        assert_eq!(
            super::execute(&["rotate".to_owned(), database.clone(), owner_key.clone(),])
                .test_err()?
                .to_string(),
            "OwnTracks owner-key file is unavailable"
        );
        assert!(!std::path::Path::new(&owner_key).exists());
        create_or_load_owner_key(std::path::Path::new(&owner_key)).test_ok()?;

        let rotation = super::execute(&["rotate".to_owned(), database.clone(), owner_key.clone()])
            .test_ok()?;
        assert!(rotation.contains("OwnTracks handle:"));
        assert!(rotation.contains("OwnTracks secret:"));
        assert!(std::path::Path::new(&owner_key).is_file());

        let second_rotation =
            super::execute(&["rotate".to_owned(), database.clone(), owner_key.clone()])
                .test_ok()?;
        assert_ne!(rotation, second_rotation);

        let revoke = super::execute(&["revoke".to_owned(), database.clone()]).test_ok()?;
        assert_eq!(revoke, "OwnTracks enrollment revoked");
        let status = super::execute(&["status".to_owned(), database.clone()]).test_ok()?;
        assert_eq!(status, "OwnTracks status: revoked\nPolicy version: 1");
        assert_eq!(
            super::execute(&["rotate".to_owned(), database, owner_key])
                .test_err()?
                .to_string(),
            "OwnTracks enrollment transition is unavailable"
        );

        std::fs::remove_dir_all(directory).test_ok()?;

        Ok(())
    }

    #[test]
    fn cover_parse_consent_policy_error_paths() {
        // Invalid TOML
        drop(super::parse_consent_policy("not-valid-toml[[["));
        // Wrong schema_version
        drop(super::parse_consent_policy(
            "schema_version = 2\nconsent_revision = 1\npolicy_version = 1\n\
             binding_revision = 1\nwithdrawn = false\npurpose = \"local_pairing\"\n\
             precision = \"exact\"\nsource_time_bucket = \"minute\"\n\
             visibility = \"paired_devices_only\"\nconsent_identity = \"\
             0000000000000000000000000000000000000000000000000000000000000000\"",
        ));
        // consent_revision == 0 (schema_version=1 passes, this fails)
        drop(super::parse_consent_policy(
            "schema_version = 1\nconsent_revision = 0\npolicy_version = 1\n\
             binding_revision = 1\nwithdrawn = false\npurpose = \"local_pairing\"\n\
             precision = \"exact\"\nsource_time_bucket = \"minute\"\n\
             visibility = \"paired_devices_only\"\nconsent_identity = \"\
             0000000000000000000000000000000000000000000000000000000000000000\"",
        ));
        // withdrawn = true
        drop(super::parse_consent_policy(
            "schema_version = 1\nconsent_revision = 1\npolicy_version = 1\n\
             binding_revision = 1\nwithdrawn = true\npurpose = \"local_pairing\"\n\
             precision = \"exact\"\nsource_time_bucket = \"minute\"\n\
             visibility = \"paired_devices_only\"\nconsent_identity = \"\
             0000000000000000000000000000000000000000000000000000000000000000\"",
        ));
        // wrong purpose
        drop(super::parse_consent_policy(
            "schema_version = 1\nconsent_revision = 1\npolicy_version = 1\n\
             binding_revision = 1\nwithdrawn = false\npurpose = \"other\"\n\
             precision = \"exact\"\nsource_time_bucket = \"minute\"\n\
             visibility = \"paired_devices_only\"\nconsent_identity = \"\
             0000000000000000000000000000000000000000000000000000000000000000\"",
        ));
        // invalid consent_identity (not 64 hex chars)
        drop(super::parse_consent_policy(
            "schema_version = 1\nconsent_revision = 1\npolicy_version = 1\n\
             binding_revision = 1\nwithdrawn = false\npurpose = \"local_pairing\"\n\
             precision = \"exact\"\nsource_time_bucket = \"minute\"\n\
             visibility = \"paired_devices_only\"\nconsent_identity = \"notvalidhex\"",
        ));
    }

    #[test]
    fn cover_decode_lower_hex_32_error_paths() {
        // Wrong length
        drop(super::decode_lower_hex_32("abc"));
        // Correct length but invalid char (uppercase not in a-f)
        drop(super::decode_lower_hex_32(&"A".repeat(64)));
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod coverage_tests {
    trait TestResultExt<T, E> {
        fn test_ok(self) -> Result<T, Box<dyn std::error::Error>>;
    }

    impl<T, E: std::fmt::Debug> TestResultExt<T, E> for Result<T, E> {
        fn test_ok(self) -> Result<T, Box<dyn std::error::Error>> {
            self.map_err(|error| format!("unexpected error: {error:?}").into())
        }
    }

    use super::{create_or_load_owner_key, OwnTracksMaterialError};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn unsafe_ancestor_and_existing_key_lengths_fail_closed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = std::env::temp_dir().join(format!(
            "piglor-gateway-owntracks-coverage-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .test_ok()?
                .as_nanos()
        ));
        std::fs::create_dir(&directory).test_ok()?;
        let mut permissions = std::fs::metadata(&directory).test_ok()?.permissions();
        permissions.set_mode(0o777);
        std::fs::set_permissions(&directory, permissions).test_ok()?;
        let unsafe_result = create_or_load_owner_key(&directory.join("owner.key"));
        assert!(matches!(
            unsafe_result,
            Err(OwnTracksMaterialError::UnsafeOwnerKeyPath)
        ));

        let mut permissions = std::fs::metadata(&directory).test_ok()?.permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&directory, permissions).test_ok()?;
        let malformed = directory.join("malformed.key");
        std::fs::write(&malformed, [0_u8; 31]).test_ok()?;
        let mut permissions = std::fs::metadata(&malformed).test_ok()?.permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&malformed, permissions).test_ok()?;
        assert!(matches!(
            create_or_load_owner_key(&malformed),
            Err(OwnTracksMaterialError::InvalidOwnerKeyLength)
        ));
        std::fs::remove_dir_all(directory).test_ok()?;

        Ok(())
    }
}

#[cfg(test)]
mod coverage_entrypoints {
    use super::*;

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected coverage error: {error:?}")))
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn expect_err<T, E: std::fmt::Debug>(result: Result<T, E>) {
        if result.is_ok() {
            std::panic::resume_unwind(Box::new("expected a fail-closed error"));
        }
        std::mem::drop(result);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn expect_equal<T: PartialEq + std::fmt::Debug>(left: T, right: T) {
        let equal = left == right;
        if !equal {
            std::panic::resume_unwind(Box::new(format!(
                "coverage fixture values differed: {left:?} != {right:?}"
            )));
        }
        std::mem::drop((left, right));
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn temporary_directory(label: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "piglor-gateway-owntracks-entry-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        test_ok(std::fs::create_dir(&path));
        path
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn policy_text() -> &'static str {
        "schema_version = 1\nconsent_identity = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\nconsent_revision = 1\npolicy_version = 1\nbinding_revision = 1\nwithdrawn = false\npurpose = \"local_pairing\"\nprecision = \"exact\"\nsource_time_bucket = \"minute\"\nvisibility = \"paired_devices_only\"\n"
    }

    #[test]
    fn command_entrypoints_fail_closed_at_each_local_boundary() {
        let directory = temporary_directory("commands");
        let database = directory.join("enrollment.db");
        let policy = directory.join("consent.toml");
        test_ok(std::fs::write(&policy, policy_text()));
        let timeline = TimelineId::new().to_string();
        let entity = EntityId::new().to_string();

        expect_err(execute(&[
            "pair".to_owned(),
            database.display().to_string(),
            directory.join("owner.key").display().to_string(),
            "--consent-policy".to_owned(),
            directory.join("missing.toml").display().to_string(),
            timeline.clone(),
            entity.clone(),
        ]));
        expect_err(execute(&[
            "pair".to_owned(),
            database.display().to_string(),
            directory.join("owner.key").display().to_string(),
            "--consent-policy".to_owned(),
            policy.display().to_string(),
            "bad-timeline".to_owned(),
            entity.clone(),
        ]));
        expect_err(execute(&[
            "pair".to_owned(),
            database.display().to_string(),
            directory.join("owner.key").display().to_string(),
            "--consent-policy".to_owned(),
            policy.display().to_string(),
            timeline.clone(),
            "bad-entity".to_owned(),
        ]));

        let unsafe_parent = directory.join("unsafe");
        test_ok(std::fs::create_dir(&unsafe_parent));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = test_ok(std::fs::metadata(&unsafe_parent)).permissions();
            permissions.set_mode(0o777);
            test_ok(std::fs::set_permissions(&unsafe_parent, permissions));
        }
        expect_err(execute(&[
            "pair".to_owned(),
            database.display().to_string(),
            unsafe_parent.join("owner.key").display().to_string(),
            "--consent-policy".to_owned(),
            policy.display().to_string(),
            timeline.clone(),
            entity.clone(),
        ]));

        let directory_path = directory.join("database-directory");
        test_ok(std::fs::create_dir(&directory_path));
        expect_err(execute(&[
            "status".to_owned(),
            directory_path.display().to_string(),
        ]));
        expect_err(execute(&[
            "pair".to_owned(),
            directory_path.display().to_string(),
            directory.join("owner.key").display().to_string(),
            "--consent-policy".to_owned(),
            policy.display().to_string(),
            timeline,
            entity,
        ]));
        expect_err(execute(&[
            "rotate".to_owned(),
            database.display().to_string(),
            directory.join("missing.key").display().to_string(),
        ]));
        expect_err(execute(&[
            "revoke".to_owned(),
            database.display().to_string(),
        ]));
        expect_err(execute(&["unknown".to_owned()]));

        test_ok(std::fs::remove_dir_all(directory));
    }

    #[test]
    fn active_enrollment_commands_cover_terminal_states() {
        let directory = temporary_directory("active");
        let database = directory.join("enrollment.db");
        let policy = directory.join("consent.toml");
        let owner_key = directory.join("owner.key");
        test_ok(std::fs::write(&policy, policy_text()));
        let mut store = test_ok(pos_store::sqlite::SqliteStore::open(
            &database.display().to_string(),
        ));
        let timeline = test_ok(pos_core::EventStore::create_timeline(
            &mut store,
            "active-enrollment",
        ));
        test_ok(
            pos_core::OwnTracksEnrollmentStore::pair_owntracks_enrollment(
                &mut store,
                pos_core::OwnTracksEnrollmentRequestV1::new(
                    timeline.id(),
                    pos_core::EntityId::new(),
                    pos_core::GeoLocationAdmissionFenceV1::new(
                        1,
                        ([1; 32], 1, [2; 32]),
                        (1, false, 1),
                    ),
                    [3; 32],
                ),
            ),
        );
        drop(store);

        expect_err(execute(&[
            "pair".to_owned(),
            database.display().to_string(),
            owner_key.display().to_string(),
            "--consent-policy".to_owned(),
            policy.display().to_string(),
            timeline.id().to_string(),
            pos_core::EntityId::new().to_string(),
        ]));
        let _ = test_ok(execute(&[
            "status".to_owned(),
            database.display().to_string(),
        ]));
        test_ok(create_or_load_owner_key(&owner_key));
        let _ = test_ok(execute(&[
            "rotate".to_owned(),
            database.display().to_string(),
            owner_key.display().to_string(),
        ]));
        let _ = test_ok(execute(&[
            "revoke".to_owned(),
            database.display().to_string(),
        ]));
        let _ = test_ok(execute(&[
            "status".to_owned(),
            database.display().to_string(),
        ]));
        expect_err(execute(&[
            "rotate".to_owned(),
            database.display().to_string(),
            owner_key.display().to_string(),
        ]));

        test_ok(std::fs::remove_dir_all(directory));
    }

    #[cfg(unix)]
    #[test]
    fn owner_key_entrypoints_cover_missing_malformed_and_unsafe_paths() {
        use std::os::unix::fs::PermissionsExt;

        let directory = temporary_directory("keys");
        let key_path = directory.join("owner.key");
        let key = test_ok(create_or_load_owner_key(&key_path));
        expect_equal(test_ok(load_owner_key(&key_path)), key);
        expect_err(load_owner_key(&directory.join("missing.key")));

        let malformed = directory.join("malformed.key");
        test_ok(std::fs::write(&malformed, [0_u8; 31]));
        let mut permissions = test_ok(std::fs::metadata(&malformed)).permissions();
        permissions.set_mode(0o600);
        test_ok(std::fs::set_permissions(&malformed, permissions));
        expect_err(load_owner_key(&malformed));

        let unsafe_parent = directory.join("unsafe");
        test_ok(std::fs::create_dir(&unsafe_parent));
        let mut permissions = test_ok(std::fs::metadata(&unsafe_parent)).permissions();
        permissions.set_mode(0o777);
        test_ok(std::fs::set_permissions(&unsafe_parent, permissions));
        expect_err(create_or_load_owner_key(&unsafe_parent.join("owner.key")));
        expect_err(create_or_load_owner_key(
            &directory.join("missing-parent").join("owner.key"),
        ));

        test_ok(std::fs::remove_dir_all(directory));
    }

    #[cfg(unix)]
    #[test]
    fn owner_key_filesystem_boundaries_fail_closed() {
        let directory = temporary_directory("filesystem-errors");
        let target_directory = directory.join("target-directory");
        test_ok(std::fs::create_dir(&target_directory));
        expect_err(create_or_load_owner_key(&target_directory));

        let missing_parent = directory.join("missing-parent").join("owner.key");
        expect_err(super::create_owner_key(&missing_parent));

        let existing = directory.join("existing.key");
        test_ok(std::fs::write(&existing, [0_u8; 32]));
        expect_err(super::create_owner_key(&existing));

        let removed = directory.join("removed.key");
        test_ok(std::fs::write(&removed, [0_u8; 32]));
        let metadata = test_ok(std::fs::metadata(&removed));
        test_ok(std::fs::remove_file(&removed));
        expect_err(super::load_existing_owner_key(&removed, &metadata));

        test_ok(std::fs::remove_dir_all(directory));
    }
}
