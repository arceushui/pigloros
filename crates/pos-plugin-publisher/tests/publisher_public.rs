//! Registry-authorized Plugin release publication at the public seam.
//!
//! Every published PMF1 is decoded here with `ciborium` and its digests,
//! release digest and role-bound Ed25519 signature are recomputed with this
//! file's own BLAKE3 formulas and hand-built ADR-065 preimage, never with the
//! publisher's code. Failure paths use a real `KeyRegistryStateV1` and a real
//! local OCI store.
#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ciborium::value::Value;
use pos_core::{
    CanonicalBytes, Hash, KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1,
    KeyRegistryErrorV1, KeyRegistryStateV1, KeyRoleV1, OwnerIdV1, PublicKey, Signature,
};
use pos_crypto::key_roles::{
    destroy_registered_signing_key, sign_for_registered_role, SigningKeyMaterial,
};
use pos_crypto::plugin_execution::{
    DeterministicBudgetV1, PluginAbiRequirementV1, PluginCapabilityDescriptorV1,
};
use pos_crypto::plugin_manifest::{
    PluginArtifactInputV1, PluginDependencyInputV1, PluginReleaseDraftV1, PluginSchemaInputV1,
};
use pos_crypto::plugin_trust::ValidatedPluginManifestProjectionV1;
use pos_crypto::signing::{generate_keypair, verify, verifying_key_from_public_key};
use pos_plugin_publisher::{
    publish_plugin_release_v1, publish_signed_plugin_release_v1, sign_plugin_release_v1,
    PluginReleasePublishErrorV1, PluginReleaseSignatureV1, PublishedPluginReleaseV1,
};
use pos_plugin_release::{
    BundleAddressV1, LocalOciPublicationErrorV1, LocalOciPublisherV1, PublishOutcomeV1,
    ReleaseSourceErrorV1, ReleaseSourceV1,
};
use sha2::{Digest as _, Sha256};

type BoxResult<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = BoxResult<()>;
type Draft<'a> = PluginReleaseDraftV1<'a>;
type Published = Result<PublishedPluginReleaseV1, PluginReleasePublishErrorV1>;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

const OWNER: &str = "publisher";
const COMPONENT_BYTES: &[u8] = b"\0asm component";
const WIT_BYTES: &[u8] = b"wit archive";
const EVENT_SCHEMA: &[u8] = br#"{"$id":"event"}"#;
const STATE_SCHEMA: &[u8] = br#"{"$id":"state"}"#;
const PROVENANCE_BYTES: &[u8] = b"in-toto provenance";
const SBOM_BYTES: &[u8] = b"spdx sbom";
const LICENCE_BYTES: &[u8] = b"licence text";
const MANIFEST_DOMAIN: &[u8] = b"PiglorOS.Plugin.Manifest.v1\0";
const RELEASE_DOMAIN: &[u8] = b"PiglorOS.Plugin.Release.v1\0";
const COMPONENT_DOMAIN: &[u8] = b"PiglorOS.Plugin.Component.v1\0";
const WIT_DOMAIN: &[u8] = b"PiglorOS.Plugin.WITArchive.v1\0";
const ROLE_DOMAIN: &[u8] = b"pigloros/role-signature/v1";
const MAX_INTERVAL: i64 = 31_622_400;

struct PrivateRoot(PathBuf);

impl PrivateRoot {
    fn new() -> BoxResult<Self> {
        let root = std::env::temp_dir().join(format!(
            "pigloros-publisher-public-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        Ok(Self(root))
    }

    fn store(&self) -> BoxResult<LocalOciPublisherV1> {
        Ok(LocalOciPublisherV1::open(&self.0)?)
    }

    fn chmod(&self, mode: u32) -> TestResult {
        Ok(fs::set_permissions(
            &self.0,
            fs::Permissions::from_mode(mode),
        )?)
    }
}

impl Drop for PrivateRoot {
    fn drop(&mut self) {
        drop(fs::set_permissions(
            &self.0,
            fs::Permissions::from_mode(0o700),
        ));
        drop(fs::remove_dir_all(&self.0));
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut digest = [0; 32];
    digest.copy_from_slice(&Sha256::digest(bytes));
    digest
}

fn input(bytes: &[u8]) -> PluginArtifactInputV1<'_> {
    PluginArtifactInputV1 {
        bytes,
        sha256: sha256(bytes),
    }
}

fn schema(id: u32, document: &[u8]) -> PluginSchemaInputV1<'_> {
    PluginSchemaInputV1 {
        id,
        version: 1,
        artifact: input(document),
        max_bytes: 65_536,
    }
}

/// A valid draft by `owner`, valid for UTC seconds `[not_before, not_after)`.
fn make_draft<'a>(owner: &str, not_before: i64, not_after: i64) -> BoxResult<Draft<'a>> {
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
        event_schemas: vec![schema(1, EVENT_SCHEMA)],
        state_schema: schema(2, STATE_SCHEMA),
        configuration_schema: None,
        capabilities: vec![PluginCapabilityDescriptorV1 {
            capability_id: "kv".to_owned(),
            operation: "read".to_owned(),
            resource_pattern: "state/*".to_owned(),
            purpose: "Read Plugin state".to_owned(),
            audience: "plugin".to_owned(),
            required: true,
            max_calls: 10,
            max_request_bytes: 1_024,
            max_response_bytes: 2_048,
        }],
        budget: DeterministicBudgetV1 {
            memory_bytes: 65_536,
            fuel: 1 << 40,
            host_calls: 256,
            event_count: 24,
            event_bytes: 4_096,
            state_bytes: 4_096,
            log_calls: 24,
            log_bytes: 256,
        },
        dependencies: vec![PluginDependencyInputV1 {
            dependency_id: "dep".to_owned(),
            release_digest: [0x42; 32],
            min_minor: 0,
            max_minor: 0,
            required_features: vec!["clock".to_owned()],
            capability_ids: Vec::new(),
            class: 0,
        }],
        provenance: input(PROVENANCE_BYTES),
        sbom: input(SBOM_BYTES),
        licences: vec![input(LICENCE_BYTES)],
        owner: OwnerIdV1::new(owner)?,
        not_before,
        not_after,
        previous_release_digest: None,
    })
}

fn default_draft<'a>() -> BoxResult<Draft<'a>> {
    make_draft(OWNER, 40, 60)
}

fn identity(owner: &str, role: KeyRoleV1, epoch: u64) -> BoxResult<KeyIdentityV1> {
    Ok(KeyIdentityV1::new(OwnerIdV1::new(owner)?, role, epoch))
}

/// Register a fresh signing key for `(owner, role, epoch)`.
fn register(
    registry: &mut KeyRegistryStateV1,
    owner: &str,
    role: KeyRoleV1,
    epoch: u64,
) -> BoxResult<SigningKeyMaterial> {
    let (signing_key, _verifying_key) = generate_keypair();
    let material = SigningKeyMaterial::new(signing_key);
    registry.register_key(KeyRegistrationV1::new(
        identity(owner, role, epoch)?,
        material.material_digest(),
        Some(material.public_verification_key()),
    ))?;
    Ok(material)
}

/// A registry with the publisher's epoch-1 `PluginReleaseSigning` key.
fn publisher_registry() -> BoxResult<(KeyRegistryStateV1, SigningKeyMaterial)> {
    let mut registry = KeyRegistryStateV1::new();
    let material = register(&mut registry, OWNER, KeyRoleV1::PluginReleaseSigning, 1)?;
    Ok((registry, material))
}

const fn not_found() -> Published {
    Err(PluginReleasePublishErrorV1::Authorization(
        KeyRegistryErrorV1::NotFound,
    ))
}

const fn invalid_signature() -> Published {
    Err(PluginReleasePublishErrorV1::InvalidSignature)
}

/// Publish the default draft at `epoch`.
fn attempt(
    registry: &mut KeyRegistryStateV1,
    material: &SigningKeyMaterial,
    epoch: u64,
    store: &LocalOciPublisherV1,
) -> BoxResult<Published> {
    Ok(publish_plugin_release_v1(
        registry,
        material,
        epoch,
        &default_draft()?,
        store,
    ))
}

/// The address `epoch`'s signature of `draft` publishes at, in a scratch store.
fn reference_address(
    registry: &mut KeyRegistryStateV1,
    material: &SigningKeyMaterial,
    epoch: u64,
    draft: &Draft<'_>,
) -> BoxResult<BundleAddressV1> {
    let scratch = PrivateRoot::new()?;
    let store = scratch.store()?;
    let published = publish_plugin_release_v1(registry, material, epoch, draft, &store)?;
    Ok(published.address().clone())
}

/// Nothing discoverable: no committed release at `address`, nothing left to
/// recover, and an empty recovery report.
fn assert_not_published(store: &LocalOciPublisherV1, address: &BundleAddressV1) -> TestResult {
    assert_eq!(
        store.read_verified(address),
        Err(ReleaseSourceErrorV1::NotFound)
    );
    let report = store.recover_all()?;
    assert!(report.committed.is_empty());
    assert_eq!(report.removed_staging, 0);
    assert!(!report.removed_next_index);
    Ok(())
}

/// `BLAKE3(domain || u64be(len) || bytes)`.
fn domain_digest(domain: &[u8], bytes: &[u8]) -> BoxResult<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&u64::try_from(bytes.len())?.to_be_bytes());
    hasher.update(bytes);
    Ok(*hasher.finalize().as_bytes())
}

/// The 28 top-level PMF1 fields, decoded with `ciborium`.
fn fields(pmf1: &[u8]) -> BoxResult<Vec<Value>> {
    let value: Value = ciborium::from_reader(pmf1)?;
    match value {
        Value::Array(fields) => Ok(fields),
        _ => Err("PMF1 is not an array".into()),
    }
}

fn uint(value: &Value) -> BoxResult<u64> {
    Ok(u64::try_from(value.as_integer().ok_or("not an integer")?)?)
}

fn byte_array<const N: usize>(value: &Value) -> BoxResult<[u8; N]> {
    let bytes = value.as_bytes().ok_or("not a byte string")?;
    Ok(bytes.as_slice().try_into()?)
}

/// The inner BLAKE3 of an `ArtifactDescriptorV1`.
fn descriptor_blake3(descriptor: &Value) -> BoxResult<[u8; 32]> {
    byte_array(
        descriptor
            .as_array()
            .and_then(|items| items.get(2))
            .ok_or("descriptor has no BLAKE3 digest")?,
    )
}

/// The encoded size of a CBOR unsigned integer.
const fn uint_len(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// Recompute every digest and the role-bound signature of `pmf1` with this
/// file's own formulas and check them against what the PMF1 carries.
fn assert_independent(pmf1: &[u8], epoch: u64, public_key: &PublicKey) -> TestResult {
    let fields = fields(pmf1)?;
    assert_eq!(fields.len(), 28);
    assert_eq!(fields[2].as_text(), Some("plugin-a"));
    assert_eq!(fields[21].as_text(), Some(OWNER));
    // Fields 25, 26 and 27 follow the unsigned fields 0-24.
    let tail = 34 + (69 + uint_len(epoch)) + 34;
    let mut unsigned = vec![0x98, 0x19];
    unsigned.extend_from_slice(&pmf1[2..pmf1.len() - tail]);
    let manifest = domain_digest(MANIFEST_DOMAIN, &unsigned)?;
    assert_eq!(byte_array::<32>(&fields[25])?, manifest);
    let component = domain_digest(COMPONENT_DOMAIN, COMPONENT_BYTES)?;
    let wit = domain_digest(WIT_DOMAIN, WIT_BYTES)?;
    assert_eq!(descriptor_blake3(&fields[9])?, component);
    assert_eq!(descriptor_blake3(&fields[10])?, wit);
    let mut hasher = blake3::Hasher::new();
    hasher.update(RELEASE_DOMAIN);
    hasher.update(&manifest);
    hasher.update(&component);
    hasher.update(&wit);
    let release_digest = *hasher.finalize().as_bytes();
    assert_eq!(byte_array::<32>(&fields[27])?, release_digest);
    let signature = fields[26].as_array().ok_or("field 26 is not an array")?;
    assert_eq!(signature.len(), 4);
    assert_eq!(uint(&signature[0])?, 1);
    assert_eq!(uint(&signature[1])?, 3);
    assert_eq!(uint(&signature[2])?, epoch);
    let mut preimage = ROLE_DOMAIN.to_vec();
    preimage.extend_from_slice(&u32::try_from(OWNER.len())?.to_be_bytes());
    preimage.extend_from_slice(OWNER.as_bytes());
    preimage.push(3);
    preimage.extend_from_slice(&epoch.to_be_bytes());
    preimage.extend_from_slice(&release_digest);
    verify(
        &verifying_key_from_public_key(public_key)?,
        &CanonicalBytes::from_vec(preimage),
        &Signature::from_bytes(byte_array::<64>(&signature[3])?),
    )?;
    Ok(())
}

#[test]
fn publishes_a_signed_release_that_reads_back_and_decodes_independently() -> TestResult {
    let root = PrivateRoot::new()?;
    let store = root.store()?;
    let (mut registry, material) = publisher_registry()?;
    let draft = default_draft()?;
    let published = publish_plugin_release_v1(&mut registry, &material, 1, &draft, &store)?;
    assert!(matches!(
        published.outcome(),
        PublishOutcomeV1::Published(_)
    ));
    assert_eq!(
        published.identity(),
        identity(OWNER, KeyRoleV1::PluginReleaseSigning, 1)?
    );
    let bundle = store.read_verified(published.address())?;
    assert_eq!(bundle.members().len(), 8);
    assert!(bundle.member_bytes().any(|bytes| bytes == COMPONENT_BYTES));
    assert_independent(bundle.pmf1(), 1, &material.public_verification_key())?;
    let release_digest = draft.unsigned()?.release_digest();
    assert_eq!(published.release_digest(), release_digest);
    let projection = ValidatedPluginManifestProjectionV1::from_verified_bundle(&bundle);
    assert!(projection.is_ok());
    Ok(())
}

#[test]
fn republishing_the_same_signed_release_is_idempotent() -> TestResult {
    let root = PrivateRoot::new()?;
    let store = root.store()?;
    let (mut registry, material) = publisher_registry()?;
    let draft = default_draft()?;
    let first = publish_plugin_release_v1(&mut registry, &material, 1, &draft, &store)?;
    let second = publish_plugin_release_v1(&mut registry, &material, 1, &draft, &store)?;
    assert_eq!(
        second.outcome(),
        &PublishOutcomeV1::AlreadyPublished(first.address().clone())
    );
    assert_eq!(second.address(), first.address());
    Ok(())
}

#[test]
fn resigning_at_a_later_epoch_keeps_the_release_digest_and_changes_the_evidence() -> TestResult {
    let (mut registry, first_key) = publisher_registry()?;
    let draft = default_draft()?;
    let first = sign_plugin_release_v1(&mut registry, &first_key, 1, &draft)?;
    let second_key = register(&mut registry, OWNER, KeyRoleV1::PluginReleaseSigning, 2)?;
    let second = sign_plugin_release_v1(&mut registry, &second_key, 2, &draft)?;
    assert_ne!(first.signature(), second.signature());
    let root = PrivateRoot::new()?;
    let store = root.store()?;
    let first_key_public = first_key.public_verification_key();
    let second_key_public = second_key.public_verification_key();
    let at_first = publish_signed_plugin_release_v1(&draft, &first, &first_key_public, &store)?;
    let at_second = publish_signed_plugin_release_v1(&draft, &second, &second_key_public, &store)?;
    assert_ne!(at_first.address(), at_second.address());
    assert_eq!(at_first.release_digest(), at_second.release_digest());
    let first_bundle = store.read_verified(at_first.address())?;
    let second_bundle = store.read_verified(at_second.address())?;
    assert_independent(first_bundle.pmf1(), 1, &first_key_public)?;
    assert_independent(second_bundle.pmf1(), 2, &second_key_public)?;
    let first_fields = fields(first_bundle.pmf1())?;
    let second_fields = fields(second_bundle.pmf1())?;
    assert_eq!(first_fields[25], second_fields[25]);
    assert_eq!(first_fields[27], second_fields[27]);
    assert_ne!(first_fields[26], second_fields[26]);
    Ok(())
}

#[test]
fn a_registry_without_the_exact_owner_role_and_epoch_denies_signing() -> TestResult {
    let root = PrivateRoot::new()?;
    let store = root.store()?;
    // Wrong owner.
    let mut registry = KeyRegistryStateV1::new();
    let other = register(
        &mut registry,
        "someone-else",
        KeyRoleV1::PluginReleaseSigning,
        1,
    )?;
    assert_eq!(attempt(&mut registry, &other, 1, &store)?, not_found());
    // Wrong role.
    let mut registry = KeyRegistryStateV1::new();
    let timeline = register(&mut registry, OWNER, KeyRoleV1::TimelineIntegritySigning, 1)?;
    assert_eq!(attempt(&mut registry, &timeline, 1, &store)?, not_found());
    // Wrong epoch.
    let (mut registry, material) = publisher_registry()?;
    assert_eq!(attempt(&mut registry, &material, 2, &store)?, not_found());
    assert!(matches!(
        attempt(&mut registry, &material, 0, &store)?,
        Err(PluginReleasePublishErrorV1::Manifest(_))
    ));
    // Right identity, wrong key material.
    let (_registry, stranger) = publisher_registry()?;
    assert_eq!(
        attempt(&mut registry, &stranger, 1, &store)?,
        Err(PluginReleasePublishErrorV1::Authorization(
            KeyRegistryErrorV1::SigningKeyMismatch
        ))
    );
    assert!(store.recover_all()?.committed.is_empty());
    Ok(())
}

#[test]
fn a_rotated_out_epoch_cannot_sign_and_leaves_nothing_discoverable() -> TestResult {
    let (mut registry, old_key) = publisher_registry()?;
    let draft = default_draft()?;
    let would_be = reference_address(&mut registry, &old_key, 1, &draft)?;
    register(&mut registry, OWNER, KeyRoleV1::PluginReleaseSigning, 2)?;
    // The registry also refuses to register the stale epoch again.
    assert!(register(&mut registry, OWNER, KeyRoleV1::PluginReleaseSigning, 1).is_err());
    let root = PrivateRoot::new()?;
    let store = root.store()?;
    assert_eq!(
        publish_plugin_release_v1(&mut registry, &old_key, 1, &draft, &store),
        Err(PluginReleasePublishErrorV1::Authorization(
            KeyRegistryErrorV1::InactiveKey
        ))
    );
    assert_not_published(&store, &would_be)
}

#[test]
fn a_pending_destruction_denies_signing() -> TestResult {
    let (mut registry, material) = publisher_registry()?;
    let draft = default_draft()?;
    let would_be = reference_address(&mut registry, &material, 1, &draft)?;
    registry.begin_key_destruction(KeyDestructionRequestV1::new(
        identity(OWNER, KeyRoleV1::PluginReleaseSigning, 1)?,
        material.material_digest(),
        Hash::from_bytes([7; 32]),
    ))?;
    let root = PrivateRoot::new()?;
    let store = root.store()?;
    assert_eq!(
        publish_plugin_release_v1(&mut registry, &material, 1, &draft, &store),
        Err(PluginReleasePublishErrorV1::Authorization(
            KeyRegistryErrorV1::DestructionPending
        ))
    );
    assert_not_published(&store, &would_be)
}

#[test]
fn a_signature_made_before_key_destruction_may_be_published_afterwards() -> TestResult {
    let (mut registry, mut material) = publisher_registry()?;
    let draft = default_draft()?;
    let signature = sign_plugin_release_v1(&mut registry, &material, 1, &draft)?;
    let key_identity = identity(OWNER, KeyRoleV1::PluginReleaseSigning, 1)?;
    let material_digest = material.material_digest();
    destroy_registered_signing_key(
        &mut material,
        KeyDestructionRequestV1::new(key_identity, material_digest, Hash::from_bytes([7; 32])),
        &mut registry,
    )?;
    let root = PrivateRoot::new()?;
    let store = root.store()?;
    // New signing is denied for good ...
    let denied = publish_plugin_release_v1(&mut registry, &material, 1, &draft, &store);
    assert_eq!(
        denied,
        Err(PluginReleasePublishErrorV1::Authorization(
            KeyRegistryErrorV1::Destroyed
        ))
    );
    assert!(store.recover_all()?.committed.is_empty());
    // ... but the retained signature publishes under the retained key.
    let retained = registry
        .key_record(key_identity)
        .and_then(|record| record.public_verification_key)
        .ok_or("the registry retains the public key")?;
    let published = publish_signed_plugin_release_v1(&draft, &signature, &retained, &store)?;
    assert!(matches!(
        published.outcome(),
        PublishOutcomeV1::Published(_)
    ));
    let bundle = store.read_verified(published.address())?;
    assert_independent(bundle.pmf1(), 1, &retained)?;
    Ok(())
}

#[test]
fn a_retained_signature_must_match_the_exact_draft_epoch_and_key() -> TestResult {
    let (mut registry, material) = publisher_registry()?;
    let draft = default_draft()?;
    let signature = sign_plugin_release_v1(&mut registry, &material, 1, &draft)?;
    let key = material.public_verification_key();
    let root = PrivateRoot::new()?;
    let store = root.store()?;
    let would_be = reference_address(&mut registry, &material, 1, &draft)?;
    // A corrupted signature.
    let mut bytes = *signature.signature();
    bytes[63] ^= 1;
    let corrupted = PluginReleaseSignatureV1::new(1, bytes);
    assert_eq!(
        publish_signed_plugin_release_v1(&draft, &corrupted, &key, &store),
        invalid_signature()
    );
    // The same signature claimed for another epoch; epoch zero is no PMF1 at all.
    assert_eq!(signature.epoch(), 1);
    let moved = PluginReleaseSignatureV1::new(2, *signature.signature());
    assert_eq!(
        publish_signed_plugin_release_v1(&draft, &moved, &key, &store),
        invalid_signature()
    );
    let zero = PluginReleaseSignatureV1::new(0, *signature.signature());
    assert!(matches!(
        publish_signed_plugin_release_v1(&draft, &zero, &key, &store),
        Err(PluginReleasePublishErrorV1::Manifest(_))
    ));
    // An invalid draft is rejected before any signature check.
    let empty = make_draft(OWNER, 60, 60)?;
    assert!(matches!(
        publish_signed_plugin_release_v1(&empty, &signature, &key, &store),
        Err(PluginReleasePublishErrorV1::Manifest(_))
    ));
    // A key that is not a curve point (y = 2 has no x).
    let mut off_curve = [0; 32];
    off_curve[0] = 2;
    let off_curve = PublicKey::from_bytes(off_curve);
    assert_eq!(
        publish_signed_plugin_release_v1(&draft, &signature, &off_curve, &store),
        invalid_signature()
    );
    // Another key.
    let (_other_registry, other) = publisher_registry()?;
    let other_key = other.public_verification_key();
    assert_eq!(
        publish_signed_plugin_release_v1(&draft, &signature, &other_key, &store),
        invalid_signature()
    );
    // A mutated release: another interval, another owner.
    let later = make_draft(OWNER, 40, 61)?;
    assert_eq!(
        publish_signed_plugin_release_v1(&later, &signature, &key, &store),
        invalid_signature()
    );
    let other_owner = make_draft("someone-else", 40, 60)?;
    assert_eq!(
        publish_signed_plugin_release_v1(&other_owner, &signature, &key, &store),
        invalid_signature()
    );
    assert_not_published(&store, &would_be)
}

#[test]
fn a_failed_store_publication_leaves_no_release_and_a_retry_succeeds() -> TestResult {
    let (mut registry, material) = publisher_registry()?;
    let draft = default_draft()?;
    let would_be = reference_address(&mut registry, &material, 1, &draft)?;
    let root = PrivateRoot::new()?;
    let store = root.store()?;
    // A store root that stops being private refuses publication.
    root.chmod(0o755)?;
    assert_eq!(
        publish_plugin_release_v1(&mut registry, &material, 1, &draft, &store),
        Err(PluginReleasePublishErrorV1::Publication(
            LocalOciPublicationErrorV1::InvalidLayout
        ))
    );
    assert!(store.read_verified(&would_be).is_err());
    root.chmod(0o700)?;
    assert_not_published(&store, &would_be)?;
    let published = publish_plugin_release_v1(&mut registry, &material, 1, &draft, &store)?;
    assert_eq!(published.address(), &would_be);
    assert!(store.read_verified(&would_be).is_ok());
    Ok(())
}

#[test]
fn an_unpublishable_draft_is_rejected_before_any_signature_or_store_write() -> TestResult {
    let root = PrivateRoot::new()?;
    let store = root.store()?;
    let (mut registry, material) = publisher_registry()?;
    // An empty interval.
    let empty = make_draft(OWNER, 60, 60)?;
    assert!(matches!(
        publish_plugin_release_v1(&mut registry, &material, 1, &empty, &store),
        Err(PluginReleasePublishErrorV1::Manifest(_))
    ));
    assert!(matches!(
        sign_plugin_release_v1(&mut registry, &material, 1, &empty),
        Err(PluginReleasePublishErrorV1::Manifest(_))
    ));
    // A caller-supplied SHA-256 that does not match the artifact bytes.
    let mut wrong = default_draft()?;
    wrong.component.sha256 = [0; 32];
    assert!(matches!(
        publish_plugin_release_v1(&mut registry, &material, 1, &wrong, &store),
        Err(PluginReleasePublishErrorV1::Manifest(_))
    ));
    assert!(store.recover_all()?.committed.is_empty());
    Ok(())
}

#[test]
fn the_validity_interval_is_explicit_and_bounded() -> TestResult {
    let root = PrivateRoot::new()?;
    let store = root.store()?;
    let (mut registry, material) = publisher_registry()?;
    let longest = make_draft(OWNER, -100, -100 + MAX_INTERVAL)?;
    let published = publish_plugin_release_v1(&mut registry, &material, 1, &longest, &store)?;
    let bundle = store.read_verified(published.address())?;
    let fields = fields(bundle.pmf1())?;
    let signed = |field: &Value| -> BoxResult<i128> {
        Ok(field.as_integer().map(i128::from).ok_or("not an integer")?)
    };
    assert_eq!(signed(&fields[22])?, -100);
    assert_eq!(signed(&fields[23])?, i128::from(MAX_INTERVAL - 100));
    let too_long = make_draft(OWNER, -100, -99 + MAX_INTERVAL)?;
    assert!(matches!(
        publish_plugin_release_v1(&mut registry, &material, 1, &too_long, &store),
        Err(PluginReleasePublishErrorV1::Manifest(_))
    ));
    Ok(())
}

#[test]
fn the_largest_epoch_signs_and_publishes() -> TestResult {
    let root = PrivateRoot::new()?;
    let store = root.store()?;
    let mut registry = KeyRegistryStateV1::new();
    let material = register(
        &mut registry,
        OWNER,
        KeyRoleV1::PluginReleaseSigning,
        u64::MAX,
    )?;
    let draft = default_draft()?;
    let epoch = u64::MAX;
    let published = publish_plugin_release_v1(&mut registry, &material, epoch, &draft, &store)?;
    let bundle = store.read_verified(published.address())?;
    assert_independent(bundle.pmf1(), epoch, &material.public_verification_key())
}

#[test]
fn a_draft_whose_artifacts_cannot_form_a_closure_is_rejected() -> TestResult {
    let root = PrivateRoot::new()?;
    let store = root.store()?;
    let (mut registry, material) = publisher_registry()?;
    // The SBOM and the licence share bytes, so their OCI digests collide.
    let mut shared = default_draft()?;
    shared.licences = vec![input(SBOM_BYTES)];
    assert_eq!(
        sign_plugin_release_v1(&mut registry, &material, 1, &shared),
        Err(PluginReleasePublishErrorV1::Closure(
            ReleaseSourceErrorV1::DuplicateMember
        ))
    );
    // A wrong caller SHA-256 only fails once the closure is decoded, even when a
    // signature over that exact draft exists.
    let mut wrong = default_draft()?;
    wrong.component.sha256 = [0; 32];
    let digest = wrong.unsigned()?.release_digest();
    let key_identity = identity(OWNER, KeyRoleV1::PluginReleaseSigning, 1)?;
    let signed = sign_for_registered_role(
        &mut registry,
        &material,
        key_identity,
        &CanonicalBytes::from_vec(digest.to_vec()),
    )?;
    let signature = PluginReleaseSignatureV1::new(1, *signed.as_bytes());
    let key = material.public_verification_key();
    assert!(matches!(
        publish_signed_plugin_release_v1(&wrong, &signature, &key, &store),
        Err(PluginReleasePublishErrorV1::Manifest(_))
    ));
    assert!(store.recover_all()?.committed.is_empty());
    Ok(())
}
