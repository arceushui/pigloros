//! Retained historical Plugin release verification at the public seam.
//!
//! Releases are built in memory with the #570 encoder and the OCI closure
//! builder, and judged against a real in-memory `KeyRegistryStateV1`. The
//! signature math is cross-checked here against a hand-built ADR-065
//! preimage, never against the verifier's own code.
#![cfg(target_os = "linux")]

use pos_core::{
    CanonicalBytes, Hash, KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1,
    KeyRegistryStateV1, KeyRoleV1, OwnerIdV1, PublicKey, Signature,
};
use pos_crypto::key_roles::{
    destroy_registered_signing_key, sign_for_registered_role, SigningKeyMaterial,
};
use pos_crypto::plugin_execution::{
    DeterministicBudgetV1, PluginAbiRequirementV1, PluginCapabilityDescriptorV1,
};
use pos_crypto::plugin_manifest::{
    PluginArtifactInputV1, PluginDependencyInputV1, PluginManifestErrorV1, PluginReleaseDraftV1,
    PluginSchemaInputV1,
};
use pos_crypto::signing::{generate_keypair, verify, verifying_key_from_public_key};
use pos_plugin_publisher::{
    sign_plugin_release_v1, verify_plugin_release_historical_v1, CurrentAdmissionV1,
    HistoricalReleaseVerificationV1, ReleaseSignatureMathV1, SigningKeyStateV1,
};
use pos_plugin_release::{build_oci_closure_v1, ReleaseClosureInputV1, VerifiedReleaseBundleV1};
use sha2::{Digest as _, Sha256};

type BoxResult<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = BoxResult<()>;
type Draft<'a> = PluginReleaseDraftV1<'a>;
type Verification = Result<HistoricalReleaseVerificationV1, PluginManifestErrorV1>;

const OWNER: &str = "publisher";
const COMPONENT_BYTES: &[u8] = b"\0asm component";
const WIT_BYTES: &[u8] = b"wit archive";
const EVENT_SCHEMA: &[u8] = br#"{"$id":"event"}"#;
const STATE_SCHEMA: &[u8] = br#"{"$id":"state"}"#;
const PROVENANCE_BYTES: &[u8] = b"in-toto provenance";
const SBOM_BYTES: &[u8] = b"spdx sbom";
const LICENCE_BYTES: &[u8] = b"licence text";
const ROLE_DOMAIN: &[u8] = b"pigloros/role-signature/v1";
const MAX_INTERVAL: i64 = 31_622_400;

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
fn draft<'a>(owner: &str, not_before: i64, not_after: i64) -> BoxResult<Draft<'a>> {
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
    draft(OWNER, 40, 60)
}

fn identity(owner: &str, role: KeyRoleV1, epoch: u64) -> BoxResult<KeyIdentityV1> {
    Ok(KeyIdentityV1::new(OwnerIdV1::new(owner)?, role, epoch))
}

fn release_identity(epoch: u64) -> BoxResult<KeyIdentityV1> {
    identity(OWNER, KeyRoleV1::PluginReleaseSigning, epoch)
}

fn new_material() -> SigningKeyMaterial {
    let (signing_key, _verifying_key) = generate_keypair();
    SigningKeyMaterial::new(signing_key)
}

/// Register `material` for `(owner, role, epoch)`.
fn register_material(
    registry: &mut KeyRegistryStateV1,
    material: &SigningKeyMaterial,
    owner: &str,
    role: KeyRoleV1,
    epoch: u64,
) -> TestResult {
    registry.register_key(KeyRegistrationV1::new(
        identity(owner, role, epoch)?,
        material.material_digest(),
        Some(material.public_verification_key()),
    ))?;
    Ok(())
}

/// A fresh registry holding only `material` at `(owner, role, epoch)`.
fn registry_with(
    material: &SigningKeyMaterial,
    owner: &str,
    role: KeyRoleV1,
    epoch: u64,
) -> BoxResult<KeyRegistryStateV1> {
    let mut registry = KeyRegistryStateV1::new();
    register_material(&mut registry, material, owner, role, epoch)?;
    Ok(registry)
}

/// The publisher's epoch-1 key in a fresh registry.
fn publisher_registry() -> BoxResult<(KeyRegistryStateV1, SigningKeyMaterial)> {
    let material = new_material();
    let registry = registry_with(&material, OWNER, KeyRoleV1::PluginReleaseSigning, 1)?;
    Ok((registry, material))
}

/// Assemble the OCI closure of `pmf1` and `draft`'s artifacts, with the given
/// component bytes (the draft's own bytes unless a test mismatches them).
fn closure(draft: &Draft<'_>, pmf1: &[u8], component: &[u8]) -> BoxResult<VerifiedReleaseBundleV1> {
    let mut schemas = vec![draft.event_schemas[0].artifact.bytes];
    schemas.push(draft.state_schema.artifact.bytes);
    Ok(build_oci_closure_v1(&ReleaseClosureInputV1 {
        pmf1,
        component,
        wit: draft.wit.bytes,
        schemas,
        provenance: draft.provenance.bytes,
        sbom: draft.sbom.bytes,
        licences: vec![draft.licences[0].bytes],
        migration_fixtures: Vec::new(),
    })?)
}

/// The closure of `draft` carrying `signature` claimed for `epoch`.
fn release(
    draft: &Draft<'_>,
    epoch: u64,
    signature: [u8; 64],
) -> BoxResult<VerifiedReleaseBundleV1> {
    let pmf1 = draft.unsigned()?.with_signature(epoch, signature)?;
    closure(draft, &pmf1, draft.component.bytes)
}

/// The real registry signature of `draft` at `epoch`.
fn sign(
    registry: &mut KeyRegistryStateV1,
    material: &SigningKeyMaterial,
    epoch: u64,
    draft: &Draft<'_>,
) -> BoxResult<[u8; 64]> {
    Ok(*sign_plugin_release_v1(registry, material, epoch, draft)?.signature())
}

/// A signature of `draft`'s release digest by `material` under another
/// owner, role or epoch than the release claims.
fn sign_as(
    material: &SigningKeyMaterial,
    owner: &str,
    role: KeyRoleV1,
    epoch: u64,
    draft: &Draft<'_>,
) -> BoxResult<[u8; 64]> {
    let mut registry = registry_with(material, owner, role, epoch)?;
    let payload = CanonicalBytes::from_vec(draft.unsigned()?.release_digest().to_vec());
    let signature = sign_for_registered_role(
        &mut registry,
        material,
        identity(owner, role, epoch)?,
        &payload,
    )?;
    Ok(*signature.as_bytes())
}

/// The ADR-065 verification written out by hand: the domain, the owner length
/// and bytes, the role code 3, the big-endian epoch and the 32 raw bytes.
fn hand_verifies(
    owner: &str,
    epoch: u64,
    release_digest: [u8; 32],
    signature: [u8; 64],
    key: &PublicKey,
) -> BoxResult<bool> {
    let mut preimage = ROLE_DOMAIN.to_vec();
    preimage.extend_from_slice(&u32::try_from(owner.len())?.to_be_bytes());
    preimage.extend_from_slice(owner.as_bytes());
    preimage.push(3);
    preimage.extend_from_slice(&epoch.to_be_bytes());
    preimage.extend_from_slice(&release_digest);
    Ok(verify(
        &verifying_key_from_public_key(key)?,
        &CanonicalBytes::from_vec(preimage),
        &Signature::from_bytes(signature),
    )
    .is_ok())
}

fn historical(bundle: &VerifiedReleaseBundleV1, registry: &KeyRegistryStateV1) -> Verification {
    verify_plugin_release_historical_v1(bundle, registry)
}

/// Assert both registry-dependent facts at once; admission is always unevaluated.
fn assert_facts(
    report: &HistoricalReleaseVerificationV1,
    math: ReleaseSignatureMathV1,
    state: SigningKeyStateV1,
) {
    assert_eq!(report.signature(), math);
    assert_eq!(report.key_state(), state);
    assert_eq!(report.current_admission(), CurrentAdmissionV1::NotEvaluated);
}

fn destroy(
    registry: &mut KeyRegistryStateV1,
    material: &mut SigningKeyMaterial,
    epoch: u64,
) -> TestResult {
    let request = KeyDestructionRequestV1::new(
        release_identity(epoch)?,
        material.material_digest(),
        Hash::from_bytes([7; 32]),
    );
    destroy_registered_signing_key(material, request, registry)?;
    Ok(())
}

#[test]
fn an_active_key_verifies_and_the_report_binds_the_closure_own_values() -> TestResult {
    let (mut registry, material) = publisher_registry()?;
    let draft = default_draft()?;
    let signature = sign(&mut registry, &material, 1, &draft)?;
    let bundle = release(&draft, 1, signature)?;
    let report = historical(&bundle, &registry)?;
    assert_facts(
        &report,
        ReleaseSignatureMathV1::Valid,
        SigningKeyStateV1::Active,
    );
    assert_eq!(report.identity(), release_identity(1)?);
    assert_eq!(report.release_digest(), draft.unsigned()?.release_digest());
    assert_eq!(
        report.pmf1_digest(),
        *blake3::hash(bundle.pmf1()).as_bytes()
    );
    // The hand-built ADR-065 preimage agrees.
    let key = material.public_verification_key();
    assert!(hand_verifies(
        OWNER,
        1,
        report.release_digest(),
        signature,
        &key
    )?);
    Ok(())
}

#[test]
fn a_valid_signature_stays_valid_after_the_key_is_destroyed() -> TestResult {
    let (mut registry, mut material) = publisher_registry()?;
    let draft = default_draft()?;
    let signature = sign(&mut registry, &material, 1, &draft)?;
    let bundle = release(&draft, 1, signature)?;
    destroy(&mut registry, &mut material, 1)?;
    assert!(material.is_destroyed());
    let report = historical(&bundle, &registry)?;
    assert_facts(
        &report,
        ReleaseSignatureMathV1::Valid,
        SigningKeyStateV1::Destroyed,
    );
    Ok(())
}

#[test]
fn a_valid_signature_stays_valid_after_rotation() -> TestResult {
    let (mut registry, material) = publisher_registry()?;
    let draft = default_draft()?;
    let old_signature = sign(&mut registry, &material, 1, &draft)?;
    let old = release(&draft, 1, old_signature)?;
    let next = new_material();
    register_material(
        &mut registry,
        &next,
        OWNER,
        KeyRoleV1::PluginReleaseSigning,
        2,
    )?;
    let rotated = historical(&old, &registry)?;
    assert_facts(
        &rotated,
        ReleaseSignatureMathV1::Valid,
        SigningKeyStateV1::Rotated,
    );
    // The new epoch signs the same release, and the two reports differ only
    // in identity, digest of the PMF1 and key state.
    let new_signature = sign(&mut registry, &next, 2, &draft)?;
    let current = historical(&release(&draft, 2, new_signature)?, &registry)?;
    assert_facts(
        &current,
        ReleaseSignatureMathV1::Valid,
        SigningKeyStateV1::Active,
    );
    assert_eq!(current.release_digest(), rotated.release_digest());
    assert_ne!(current.pmf1_digest(), rotated.pmf1_digest());
    assert_eq!(current.identity(), release_identity(2)?);
    Ok(())
}

#[test]
fn a_rotated_then_destroyed_key_still_verifies() -> TestResult {
    let (mut registry, mut material) = publisher_registry()?;
    let draft = default_draft()?;
    let signature = sign(&mut registry, &material, 1, &draft)?;
    let bundle = release(&draft, 1, signature)?;
    register_material(
        &mut registry,
        &new_material(),
        OWNER,
        KeyRoleV1::PluginReleaseSigning,
        2,
    )?;
    destroy(&mut registry, &mut material, 1)?;
    let report = historical(&bundle, &registry)?;
    assert_facts(
        &report,
        ReleaseSignatureMathV1::Valid,
        SigningKeyStateV1::Destroyed,
    );
    Ok(())
}

#[test]
fn a_pending_destruction_is_reported_apart_from_destroyed_and_rotated() -> TestResult {
    let (mut registry, material) = publisher_registry()?;
    let draft = default_draft()?;
    let signature = sign(&mut registry, &material, 1, &draft)?;
    let bundle = release(&draft, 1, signature)?;
    registry.begin_key_destruction(KeyDestructionRequestV1::new(
        release_identity(1)?,
        material.material_digest(),
        Hash::from_bytes([7; 32]),
    ))?;
    let report = historical(&bundle, &registry)?;
    assert_facts(
        &report,
        ReleaseSignatureMathV1::Valid,
        SigningKeyStateV1::DestructionPending,
    );
    Ok(())
}

#[test]
fn a_signature_that_does_not_match_the_exact_identity_or_digest_is_invalid() -> TestResult {
    let (mut registry, material) = publisher_registry()?;
    let draft = default_draft()?;
    let good = sign(&mut registry, &material, 1, &draft)?;
    let role = KeyRoleV1::PluginReleaseSigning;
    // Wrong owner, wrong role and wrong epoch: the same key signed another
    // role-bound preimage of the same release digest.
    let wrong_owner = sign_as(&material, "someone-else", role, 1, &draft)?;
    let wrong_role = sign_as(
        &material,
        OWNER,
        KeyRoleV1::TimelineIntegritySigning,
        1,
        &draft,
    )?;
    let attribution_role = sign_as(
        &material,
        OWNER,
        KeyRoleV1::SubjectAttributionSigning,
        1,
        &draft,
    )?;
    let wrong_epoch = sign_as(&material, OWNER, role, 2, &draft)?;
    for signature in [wrong_owner, wrong_role, attribution_role, wrong_epoch] {
        assert_ne!(signature, good);
        let report = historical(&release(&draft, 1, signature)?, &registry)?;
        assert_facts(
            &report,
            ReleaseSignatureMathV1::Invalid,
            SigningKeyStateV1::Active,
        );
    }
    // The good signature claimed for another epoch whose record holds the
    // same key: the claimed epoch is part of the preimage.
    let moved = registry_with(&material, OWNER, role, 2)?;
    let report = historical(&release(&draft, 2, good)?, &moved)?;
    assert_facts(
        &report,
        ReleaseSignatureMathV1::Invalid,
        SigningKeyStateV1::Active,
    );
    // ... and a registry that holds the key under another owner's name.
    let other_owner = registry_with(&material, "someone-else", role, 1)?;
    let report = historical(&release(&draft, 1, good)?, &other_owner)?;
    assert_facts(
        &report,
        ReleaseSignatureMathV1::Unverifiable,
        SigningKeyStateV1::Unknown,
    );
    // The hand-built preimage rejects exactly what the verifier rejects.
    let key = material.public_verification_key();
    let digest = draft.unsigned()?.release_digest();
    assert!(hand_verifies(OWNER, 1, digest, good, &key)?);
    assert!(!hand_verifies(OWNER, 2, digest, good, &key)?);
    assert!(!hand_verifies(OWNER, 1, digest, wrong_role, &key)?);
    Ok(())
}

#[test]
fn a_wrong_key_is_invalid() -> TestResult {
    let (mut registry, material) = publisher_registry()?;
    let draft = default_draft()?;
    let signature = sign(&mut registry, &material, 1, &draft)?;
    let bundle = release(&draft, 1, signature)?;
    let (other_registry, _other) = publisher_registry()?;
    let report = historical(&bundle, &other_registry)?;
    assert_facts(
        &report,
        ReleaseSignatureMathV1::Invalid,
        SigningKeyStateV1::Active,
    );
    Ok(())
}

#[test]
fn a_tampered_release_digest_is_invalid() -> TestResult {
    let (mut registry, material) = publisher_registry()?;
    let signed = default_draft()?;
    let signature = sign(&mut registry, &material, 1, &signed)?;
    // Every one of these changes the release digest the closure carries.
    let later = draft(OWNER, 40, 61)?;
    let earlier = draft(OWNER, 39, 60)?;
    let other_owner = draft("someone-else", 40, 60)?;
    for tampered in [&later, &earlier, &other_owner] {
        assert_ne!(
            tampered.unsigned()?.release_digest(),
            signed.unsigned()?.release_digest()
        );
        let report = historical(&release(tampered, 1, signature)?, &registry)?;
        let expected = if tampered.owner == signed.owner {
            ReleaseSignatureMathV1::Invalid
        } else {
            // The registry holds no key for the other owner.
            ReleaseSignatureMathV1::Unverifiable
        };
        assert_eq!(report.signature(), expected);
        assert_eq!(report.current_admission(), CurrentAdmissionV1::NotEvaluated);
    }
    Ok(())
}

#[test]
fn every_single_bit_flip_of_the_signature_is_invalid() -> TestResult {
    let (mut registry, material) = publisher_registry()?;
    let draft = default_draft()?;
    let signature = sign(&mut registry, &material, 1, &draft)?;
    for byte in 0..64 {
        for bit in [0_u8, 7] {
            let mut flipped = signature;
            flipped[byte] ^= 1 << bit;
            let report = historical(&release(&draft, 1, flipped)?, &registry)?;
            assert_facts(
                &report,
                ReleaseSignatureMathV1::Invalid,
                SigningKeyStateV1::Active,
            );
        }
    }
    // An all-zero signature is a signature of nothing.
    let report = historical(&release(&draft, 1, [0; 64])?, &registry)?;
    assert_eq!(report.signature(), ReleaseSignatureMathV1::Invalid);
    Ok(())
}

#[test]
fn an_unparseable_retained_key_is_invalid_not_unverifiable() -> TestResult {
    // 32 bytes that are not a curve point, retained as the epoch-1 key.
    let (mut registry, material) = publisher_registry()?;
    let draft = default_draft()?;
    let signature = sign(&mut registry, &material, 1, &draft)?;
    let mut bad = KeyRegistryStateV1::new();
    let broken = new_material();
    bad.register_key(KeyRegistrationV1::new(
        release_identity(1)?,
        broken.material_digest(),
        Some(PublicKey::from_bytes([0xFF; 32])),
    ))?;
    let report = historical(&release(&draft, 1, signature)?, &bad)?;
    assert_facts(
        &report,
        ReleaseSignatureMathV1::Invalid,
        SigningKeyStateV1::Active,
    );
    Ok(())
}

#[test]
fn a_missing_key_is_unverifiable_and_never_invalid() -> TestResult {
    let (mut registry, material) = publisher_registry()?;
    let draft = default_draft()?;
    let signature = sign(&mut registry, &material, 1, &draft)?;
    let bundle = release(&draft, 1, signature)?;
    // An empty registry.
    let empty = KeyRegistryStateV1::new();
    let report = historical(&bundle, &empty)?;
    assert_facts(
        &report,
        ReleaseSignatureMathV1::Unverifiable,
        SigningKeyStateV1::Unknown,
    );
    // Only a later epoch of the same owner and role.
    let later = registry_with(&material, OWNER, KeyRoleV1::PluginReleaseSigning, 2)?;
    let report = historical(&bundle, &later)?;
    assert_facts(
        &report,
        ReleaseSignatureMathV1::Unverifiable,
        SigningKeyStateV1::Unknown,
    );
    // Only the same owner and epoch under another role.
    let role = registry_with(&material, OWNER, KeyRoleV1::TimelineIntegritySigning, 1)?;
    let report = historical(&bundle, &role)?;
    assert_facts(
        &report,
        ReleaseSignatureMathV1::Unverifiable,
        SigningKeyStateV1::Unknown,
    );
    // A bad signature with no key is still only unverifiable.
    let junk = historical(&release(&draft, 1, [9; 64])?, &empty)?;
    assert_eq!(junk.signature(), ReleaseSignatureMathV1::Unverifiable);
    Ok(())
}

#[test]
fn the_three_facts_are_reported_independently() -> TestResult {
    use ReleaseSignatureMathV1::{Invalid, Unverifiable, Valid};
    use SigningKeyStateV1::{Active, Destroyed, Rotated, Unknown};
    let (mut registry, mut material) = publisher_registry()?;
    let draft = default_draft()?;
    let signature = sign(&mut registry, &material, 1, &draft)?;
    let good = release(&draft, 1, signature)?;
    let mut flipped = signature;
    flipped[0] ^= 1;
    let bad = release(&draft, 1, flipped)?;
    let mut seen = Vec::new();
    let mut observe = |registry: &KeyRegistryStateV1| -> TestResult {
        for bundle in [&good, &bad] {
            let report = historical(bundle, registry)?;
            seen.push((report.signature(), report.key_state()));
            assert_eq!(report.current_admission(), CurrentAdmissionV1::NotEvaluated);
        }
        Ok(())
    };
    observe(&registry)?;
    register_material(
        &mut registry,
        &new_material(),
        OWNER,
        KeyRoleV1::PluginReleaseSigning,
        2,
    )?;
    observe(&registry)?;
    destroy(&mut registry, &mut material, 1)?;
    observe(&registry)?;
    observe(&KeyRegistryStateV1::new())?;
    assert_eq!(
        seen,
        [
            (Valid, Active),
            (Invalid, Active),
            (Valid, Rotated),
            (Invalid, Rotated),
            (Valid, Destroyed),
            (Invalid, Destroyed),
            (Unverifiable, Unknown),
            (Unverifiable, Unknown),
        ]
    );
    Ok(())
}

#[test]
fn current_admission_is_never_evaluated_and_cannot_become_an_install_decision() -> TestResult {
    // The verifier takes a closure and a registry: no clock, trust policy,
    // revocation record or interval. Its signature is checked by type.
    let _: fn(&VerifiedReleaseBundleV1, &KeyRegistryStateV1) -> Verification =
        verify_plugin_release_historical_v1;
    // `NotEvaluated` is the only admission value: an exhaustive match has one
    // arm, so no report can say admitted or installable.
    let admission = |report: &HistoricalReleaseVerificationV1| match report.current_admission() {
        CurrentAdmissionV1::NotEvaluated => "not evaluated",
    };
    let (mut registry, material) = publisher_registry()?;
    // Expired, far-future and widest-interval releases verify identically:
    // the validity interval is not consulted.
    let intervals = [
        (0, 1),
        (40, 60),
        (4_000_000_000, 4_000_000_001),
        (0, MAX_INTERVAL),
    ];
    for (not_before, not_after) in intervals {
        let draft = draft(OWNER, not_before, not_after)?;
        let signature = sign(&mut registry, &material, 1, &draft)?;
        let report = historical(&release(&draft, 1, signature)?, &registry)?;
        assert_facts(
            &report,
            ReleaseSignatureMathV1::Valid,
            SigningKeyStateV1::Active,
        );
        assert_eq!(admission(&report), "not evaluated");
    }
    Ok(())
}

#[test]
fn the_largest_epoch_verifies() -> TestResult {
    let material = new_material();
    let mut registry = registry_with(&material, OWNER, KeyRoleV1::PluginReleaseSigning, u64::MAX)?;
    let draft = default_draft()?;
    let signature = sign(&mut registry, &material, u64::MAX, &draft)?;
    let report = historical(&release(&draft, u64::MAX, signature)?, &registry)?;
    assert_facts(
        &report,
        ReleaseSignatureMathV1::Valid,
        SigningKeyStateV1::Active,
    );
    assert_eq!(report.identity(), release_identity(u64::MAX)?);
    // One epoch below it is not the signed epoch.
    let report = historical(&release(&draft, u64::MAX - 1, signature)?, &registry)?;
    assert_eq!(report.signature(), ReleaseSignatureMathV1::Unverifiable);
    Ok(())
}

#[test]
fn a_closure_that_does_not_decode_or_bind_is_an_error_not_a_report() -> TestResult {
    let (mut registry, material) = publisher_registry()?;
    let draft = default_draft()?;
    let signature = sign(&mut registry, &material, 1, &draft)?;
    let pmf1 = draft.unsigned()?.with_signature(1, signature)?;
    // Not a PMF1 at all.
    let junk = closure(&draft, b"not a pmf1", draft.component.bytes)?;
    assert!(historical(&junk, &registry).is_err());
    // A well-formed PMF1 over a closure whose component is other bytes.
    let mismatched = closure(&draft, &pmf1, b"other component")?;
    assert!(historical(&mismatched, &registry).is_err());
    // A truncated PMF1.
    let truncated = closure(&draft, &pmf1[..pmf1.len() - 1], draft.component.bytes)?;
    assert!(historical(&truncated, &registry).is_err());
    Ok(())
}
