//! Public regression coverage for CFB1/CPF1 rejection boundaries.

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_conformance::{
    verify_archive_independently, BundleContractErrorV1, BundleMemberRoleV1, ConformanceBundleV1,
};
use sha2::{Digest as Sha2Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const PROFILE_PATH: &str = "profile/CPF1.cbor";
const SIGNING_KEY: [u8; 32] = [7; 32];

struct TemporaryOutput(PathBuf);

impl Drop for TemporaryOutput {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.0));
    }
}

fn temporary_root() -> TestResult<PathBuf> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!(
        "pigloros-bundle-contract-coverage-{}-{nonce}",
        std::process::id()
    )))
}

fn source_inventory_address() -> String {
    let digest: [u8; 32] =
        Sha256::digest(include_bytes!("../../../fixtures/conformance/SHA256SUMS")).into();
    pos_conformance::hex_digest(&digest)
}

fn release_files(root: &Path) -> TestResult<Vec<PathBuf>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

fn current_archive() -> TestResult<Vec<u8>> {
    let root = temporary_root()?;
    let _cleanup = TemporaryOutput(root.clone());
    fs::create_dir_all(&root)?;
    let publication = root.join(source_inventory_address());
    let materializer = std::env::var_os("CARGO_BIN_EXE_materialize-conformance-bundles")
        .ok_or("materializer binary path is unavailable")?;
    let status = Command::new(materializer)
        .current_dir(&root)
        .env(
            "PIGLOROS_CONFORMANCE_SIGNING_KEY",
            "0707070707070707070707070707070707070707070707070707070707070707",
        )
        .arg(&publication)
        .status()?;
    if !status.success() {
        return Err("materializer did not publish a public archive".into());
    }
    let archive = release_files(&publication)?
        .into_iter()
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "cfb1")
        })
        .ok_or("materializer did not publish a CFB1 archive")?;
    Ok(fs::read(archive)?)
}

fn encode(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn contract_digest(domain: &[u8], fields: &[Value]) -> TestResult<[u8; 32]> {
    let bytes = encode(&Value::Array(fields.to_vec()))?;
    let mut preimage = Vec::with_capacity(domain.len() + bytes.len() + 9);
    preimage.extend_from_slice(domain);
    preimage.push(0);
    preimage.extend_from_slice(&u64::try_from(bytes.len())?.to_be_bytes());
    preimage.extend_from_slice(&bytes);
    Ok(*blake3::hash(&preimage).as_bytes())
}

fn array_mut<'a>(value: &'a mut Value, name: &str) -> TestResult<&'a mut Vec<Value>> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err(format!("{name} is not an array").into()),
    }
}

fn array_field<'a>(
    fields: &'a mut [Value],
    index: usize,
    name: &str,
) -> TestResult<&'a mut Vec<Value>> {
    match fields.get_mut(index) {
        Some(Value::Array(values)) => Ok(values),
        _ => Err(format!("{name} is not an array").into()),
    }
}

fn member_bytes(archive: &Value, path: &str) -> TestResult<Vec<u8>> {
    let Value::Array(archive_fields) = archive else {
        return Err("archive is not an array".into());
    };
    let Some(Value::Array(members)) = archive_fields.get(1) else {
        return Err("archive members are not an array".into());
    };
    let member = members
        .iter()
        .find(|member| {
            matches!(member, Value::Array(fields) if matches!(fields.first(), Some(Value::Text(member_path)) if member_path == path))
        })
        .ok_or_else(|| format!("archive member {path} is absent"))?;
    match member {
        Value::Array(fields) => match fields.get(1) {
            Some(Value::Bytes(bytes)) => Ok(bytes.clone()),
            _ => Err("archive member bytes are absent".into()),
        },
        _ => Err("archive member is not an array".into()),
    }
}

fn member_path_by_role(archive: &Value, role: u64) -> TestResult<String> {
    let Value::Array(archive_fields) = archive else {
        return Err("archive is not an array".into());
    };
    let Some(Value::Array(members)) = archive_fields.get(1) else {
        return Err("archive members are not an array".into());
    };
    let member = members
        .iter()
        .find(|member| {
            matches!(member, Value::Array(fields) if fields.get(2) == Some(&Value::Integer(role.into())))
        })
        .ok_or_else(|| format!("archive member role {role} is absent"))?;
    match member {
        Value::Array(fields) => match fields.first() {
            Some(Value::Text(path)) => Ok(path.clone()),
            _ => Err("archive member path is absent".into()),
        },
        _ => Err("archive member is not an array".into()),
    }
}

fn member_fields<'a>(archive: &'a mut [Value], path: &str) -> TestResult<&'a mut Vec<Value>> {
    let members = array_field(archive, 1, "archive members")?;
    let member = members
        .iter_mut()
        .find(|member| {
            matches!(member, Value::Array(fields) if matches!(fields.first(), Some(Value::Text(member_path)) if member_path == path))
        })
        .ok_or_else(|| format!("archive member {path} is absent"))?;
    array_mut(member, "archive member")
}

fn descriptor_fields<'a>(archive: &'a mut [Value], path: &str) -> TestResult<&'a mut Vec<Value>> {
    let manifest = array_field(archive, 0, "manifest")?;
    let descriptors = array_field(manifest, 4, "member descriptors")?;
    let descriptor = descriptors
        .iter_mut()
        .find(|descriptor| {
            matches!(descriptor, Value::Array(fields) if matches!(fields.first(), Some(Value::Text(descriptor_path)) if descriptor_path == path))
        })
        .ok_or_else(|| format!("archive descriptor {path} is absent"))?;
    array_mut(descriptor, "archive descriptor")
}

fn replace_member_bytes(archive: &mut [Value], path: &str, bytes: &[u8]) -> TestResult {
    {
        let member = member_fields(archive, path)?;
        member[1] = Value::Bytes(bytes.to_owned());
    }
    let descriptor = descriptor_fields(archive, path)?;
    descriptor[1] = Value::Integer(u64::try_from(bytes.len())?.into());
    descriptor[2] = Value::Bytes(blake3::hash(bytes).as_bytes().to_vec());
    Ok(())
}

fn resign_archive(archive: &mut Value) -> TestResult {
    let manifest = {
        let fields = array_mut(archive, "archive")?;
        encode(&fields[0])?
    };
    let key = SigningKey::from_bytes(&SIGNING_KEY);
    let fields = array_mut(archive, "archive")?;
    fields[2] = Value::Bytes(key.verifying_key().to_bytes().to_vec());
    fields[3] = Value::Bytes(key.sign(&manifest).to_bytes().to_vec());
    Ok(())
}

fn mutate_archive(
    original: &[u8],
    mutate: impl FnOnce(&mut [Value]) -> TestResult,
) -> TestResult<Vec<u8>> {
    let mut archive: Value = ciborium::from_reader(original)?;
    mutate(array_mut(&mut archive, "archive")?)?;
    resign_archive(&mut archive)?;
    encode(&archive)
}

fn mutate_member(
    original: &[u8],
    path: &str,
    mutate: impl FnOnce(&mut Vec<Value>) -> TestResult,
) -> TestResult<Vec<u8>> {
    let mut archive: Value = ciborium::from_reader(original)?;
    let member_bytes = member_bytes(&archive, path)?;
    let mut value: Value = ciborium::from_reader(member_bytes.as_slice())?;
    mutate(array_mut(&mut value, "authority member")?)?;
    let updated = encode(&value)?;
    replace_member_bytes(array_mut(&mut archive, "archive")?, path, &updated)?;
    resign_archive(&mut archive)?;
    encode(&archive)
}

fn refresh_fixture_digests(profile: &mut [Value]) -> TestResult {
    let fixtures = array_field(profile, 9, "profile fixtures")?;
    for fixture in fixtures {
        let fields = array_mut(fixture, "fixture")?;
        if fields.len() != 24 {
            return Err("fixture does not have the CPF1 field count".into());
        }
        fields[23] = Value::Bytes(
            contract_digest(b"PiglorOS.Conformance.Fixture.v1", &fields[..23])?.to_vec(),
        );
    }
    Ok(())
}

fn mutate_profile(
    original: &[u8],
    mutate: impl FnOnce(&mut [Value]) -> TestResult,
) -> TestResult<Vec<u8>> {
    let mut archive: Value = ciborium::from_reader(original)?;
    let profile_bytes = member_bytes(&archive, PROFILE_PATH)?;
    let mut profile: Value = ciborium::from_reader(profile_bytes.as_slice())?;
    let profile_digest = {
        let fields = array_mut(&mut profile, "profile")?;
        mutate(fields)?;
        refresh_fixture_digests(fields)?;
        fields[17] = Value::Bytes(
            contract_digest(b"PiglorOS.ConformanceProfile.v1", &fields[..17])?.to_vec(),
        );
        match &fields[17] {
            Value::Bytes(digest) => digest.clone(),
            _ => return Err("profile digest is not bytes".into()),
        }
    };
    let updated_profile = encode(&profile)?;
    replace_member_bytes(
        array_mut(&mut archive, "archive")?,
        PROFILE_PATH,
        &updated_profile,
    )?;
    array_field(array_mut(&mut archive, "archive")?, 0, "manifest")?[3] =
        Value::Bytes(profile_digest);
    resign_archive(&mut archive)?;
    encode(&archive)
}

fn assert_independent_rejects(archive: &[u8], scenario: &str) -> TestResult {
    if verify_archive_independently(archive).is_ok() {
        return Err(format!("independent verifier accepted {scenario}").into());
    }
    Ok(())
}

fn update_typed_member(
    bundle: &mut ConformanceBundleV1,
    role: BundleMemberRoleV1,
    bytes: Vec<u8>,
) -> TestResult {
    let member = bundle
        .members
        .iter_mut()
        .find(|member| member.role == role)
        .ok_or("bundle member is absent")?;
    member.bytes = bytes;
    member.digest = *blake3::hash(&member.bytes).as_bytes();
    let member_path = member.path.clone();
    let descriptor = bundle
        .manifest
        .members
        .iter_mut()
        .find(|descriptor| descriptor.path == member_path)
        .ok_or("bundle member descriptor is absent")?;
    descriptor.size_bytes = u64::try_from(member.bytes.len())?;
    descriptor.digest = member.digest;
    Ok(())
}

#[test]
fn public_typed_bundle_rejects_missing_or_malformed_authority() -> TestResult {
    let archive = current_archive()?;
    let valid = ConformanceBundleV1::from_canonical_cbor(&archive)?;
    let archive_value: Value = ciborium::from_reader(archive.as_slice())?;

    for role in [
        BundleMemberRoleV1::TrustPolicySnapshot,
        BundleMemberRoleV1::ReleaseAdmission,
        BundleMemberRoleV1::ExecutionProfile,
    ] {
        let mut bundle = valid.clone();
        bundle.members.retain(|member| member.role != role);
        bundle
            .manifest
            .members
            .retain(|descriptor| descriptor.role != role);
        assert_eq!(
            bundle.validate(),
            Err(BundleContractErrorV1::ProfileInvalid)
        );
    }

    for (role, member_path, field) in [
        (
            BundleMemberRoleV1::ExecutionProfile,
            "authority/execution-profiles/deterministic-local-v1.epf1",
            0,
        ),
        (
            BundleMemberRoleV1::TrustPolicySnapshot,
            "authority/trust-policy-snapshot.tps1",
            0,
        ),
    ] {
        let mut bundle = valid.clone();
        let bytes = member_bytes(&archive_value, member_path)?;
        let mut value: Value = ciborium::from_reader(bytes.as_slice())?;
        array_mut(&mut value, "authority member")?[field] = Value::Integer(0_u64.into());
        update_typed_member(&mut bundle, role, encode(&value)?)?;
        assert_eq!(
            bundle.validate(),
            Err(BundleContractErrorV1::ProfileInvalid)
        );
    }

    Ok(())
}

#[test]
fn public_cfb1_decoders_reject_invalid_member_roles() -> TestResult {
    let archive = current_archive()?;
    let invalid_manifest_role = mutate_archive(&archive, |fields| {
        let descriptor = array_field(array_field(fields, 0, "manifest")?, 4, "member descriptors")?
            .first_mut()
            .ok_or("manifest descriptor is absent")?;
        array_mut(descriptor, "manifest descriptor")?[3] = Value::Integer(99_u64.into());
        Ok(())
    })?;
    assert_eq!(
        ConformanceBundleV1::from_canonical_cbor(&invalid_manifest_role),
        Err(BundleContractErrorV1::ArchiveEncodingInvalid)
    );

    let invalid_member_role = mutate_archive(&archive, |fields| {
        array_field(fields, 1, "archive members")?[0] = Value::Array(vec![
            Value::Text("invalid".to_owned()),
            Value::Bytes(vec![1]),
            Value::Integer(99_u64.into()),
        ]);
        Ok(())
    })?;
    assert_independent_rejects(&invalid_member_role, "an invalid member role")
}

#[test]
fn public_independent_verifier_rejects_malformed_authority() -> TestResult {
    let archive = current_archive()?;
    let archive_value: Value = ciborium::from_reader(archive.as_slice())?;
    let release_admission_path = member_path_by_role(&archive_value, 16)?;

    for (path, field) in [
        (
            "authority/execution-profiles/deterministic-local-v1.epf1",
            0,
        ),
        ("authority/trust-policy-snapshot.tps1", 0),
    ] {
        let malformed = mutate_member(&archive, path, |fields| {
            fields[field] = Value::Integer(0_u64.into());
            Ok(())
        })?;
        assert_independent_rejects(&malformed, "a malformed authority record")?;
    }

    let malformed_release_admission = mutate_member(&archive, &release_admission_path, |fields| {
        fields[0] = Value::Integer(0_u64.into());
        Ok(())
    })?;
    assert_independent_rejects(
        &malformed_release_admission,
        "a malformed release admission",
    )?;

    let invalid_release_admission = mutate_member(&archive, &release_admission_path, |fields| {
        fields[0] = Value::Text("RAD0".to_owned());
        let unsigned = encode(&Value::Array(fields[..10].to_vec()))?;
        fields[10] = Value::Bytes(
            SigningKey::from_bytes(&SIGNING_KEY)
                .sign(&unsigned)
                .to_bytes()
                .to_vec(),
        );
        Ok(())
    })?;
    assert_independent_rejects(&invalid_release_admission, "a re-signed invalid admission")?;

    Ok(())
}

fn assert_provider_binding_rejections(archive: &[u8]) -> TestResult {
    let unknown_provider = mutate_profile(archive, |profile| {
        let fixtures = array_field(profile, 9, "profile fixtures")?;
        array_mut(&mut fixtures[0], "fixture")?[4] = Value::Array(vec![
            Value::Text("a.provider".to_owned()),
            Value::Text("1.0.0".to_owned()),
            Value::Integer(1_u64.into()),
            Value::Integer(0_u64.into()),
        ]);
        Ok(())
    })?;
    assert_eq!(
        ConformanceBundleV1::from_canonical_cbor(&unknown_provider),
        Err(BundleContractErrorV1::ProfileInvalid)
    );
    assert_independent_rejects(&unknown_provider, "an undeclared fixture provider")?;

    let provider_absent_from_registry = mutate_profile(archive, |profile| {
        let provider = Value::Array(vec![
            Value::Text("a.provider".to_owned()),
            Value::Text("1.0.0".to_owned()),
            Value::Integer(1_u64.into()),
            Value::Integer(0_u64.into()),
        ]);
        array_field(profile, 8, "provider registry binding")?[1] =
            Value::Array(vec![provider.clone()]);
        for fixture in array_field(profile, 9, "profile fixtures")? {
            array_mut(fixture, "fixture")?[4] = provider.clone();
        }
        Ok(())
    })?;
    assert_eq!(
        ConformanceBundleV1::from_canonical_cbor(&provider_absent_from_registry),
        Err(BundleContractErrorV1::ProfileInvalid)
    );
    assert_independent_rejects(
        &provider_absent_from_registry,
        "a required provider absent from the registry",
    )
}

fn assert_raw_inventory_boundary_rejections(archive: &[u8]) -> TestResult {
    let extra_provider_coordinate = mutate_profile(archive, |profile| {
        let fixtures = array_field(profile, 9, "profile fixtures")?;
        let mut extra = fixtures
            .last()
            .cloned()
            .ok_or("profile fixture is absent")?;
        array_mut(&mut extra, "fixture")?[4] = Value::Array(vec![
            Value::Text("zz.provider".to_owned()),
            Value::Text("1.0.0".to_owned()),
            Value::Integer(1_u64.into()),
            Value::Integer(0_u64.into()),
        ]);
        fixtures.push(extra);
        Ok(())
    })?;
    assert_independent_rejects(
        &extra_provider_coordinate,
        "an undeclared provider inventory coordinate",
    )?;

    let undeclared_execution_coordinate = mutate_profile(archive, |profile| {
        array_field(profile, 7, "execution profile digests")?.insert(0, Value::Bytes(vec![2; 32]));
        let originals = array_field(profile, 9, "profile fixtures")?.clone();
        let mut expanded = Vec::with_capacity(originals.len() * 2);
        for original in originals {
            let mut additional = original.clone();
            array_mut(&mut additional, "fixture")?[6] = Value::Bytes(vec![2; 32]);
            expanded.push(additional);
            expanded.push(original);
        }
        *array_field(profile, 9, "profile fixtures")? = expanded;
        Ok(())
    })?;
    assert_independent_rejects(
        &undeclared_execution_coordinate,
        "a complete but undeclared execution inventory coordinate",
    )
}

#[test]
fn public_independent_verifier_rejects_profile_invariants() -> TestResult {
    let archive = current_archive()?;
    let undeclared_member = mutate_archive(&archive, |fields| {
        array_field(fields, 1, "archive members")?.push(Value::Array(vec![
            Value::Text("zzzz/undeclared.bin".to_owned()),
            Value::Bytes(vec![1]),
            Value::Integer(0_u64.into()),
        ]));
        array_field(array_field(fields, 0, "manifest")?, 4, "member descriptors")?.push(
            Value::Array(vec![
                Value::Text("zzzz/undeclared.bin".to_owned()),
                Value::Integer(1_u64.into()),
                Value::Bytes(blake3::hash(&[1]).as_bytes().to_vec()),
                Value::Integer(0_u64.into()),
            ]),
        );
        Ok(())
    })?;
    assert_independent_rejects(&undeclared_member, "an undeclared member")?;

    let invalid_mode = mutate_profile(&archive, |profile| {
        let fixtures = array_field(profile, 9, "profile fixtures")?;
        array_mut(&mut fixtures[0], "fixture")?[7] =
            Value::Array(vec![Value::Integer(99_u64.into())]);
        Ok(())
    })?;
    assert_independent_rejects(&invalid_mode, "an invalid fixture mode")?;

    let missing_execution_authority = mutate_profile(&archive, |profile| {
        let digests = array_field(profile, 7, "execution profile digests")?;
        digests.push(Value::Bytes(vec![0xff; 32]));
        Ok(())
    })?;
    assert_independent_rejects(
        &missing_execution_authority,
        "a missing execution authority",
    )?;

    let mismatched_snapshot = mutate_profile(&archive, |profile| {
        array_field(profile, 12, "independence requirements")?[3] = Value::Bytes(vec![9; 32]);
        Ok(())
    })?;
    assert_eq!(
        ConformanceBundleV1::from_canonical_cbor(&mismatched_snapshot),
        Err(BundleContractErrorV1::MemberDigestMismatch)
    );
    assert_independent_rejects(&mismatched_snapshot, "a mismatched trust-policy snapshot")?;

    assert_provider_binding_rejections(&archive)?;
    assert_raw_inventory_boundary_rejections(&archive)?;

    let unordered_artifacts = mutate_profile(&archive, |profile| {
        let fixtures = array_field(profile, 9, "profile fixtures")?;
        let auxiliary = array_field(array_mut(&mut fixtures[0], "fixture")?, 10, "auxiliary")?;
        let duplicate = auxiliary
            .first()
            .cloned()
            .ok_or("fixture auxiliary artifacts are absent")?;
        auxiliary.push(duplicate);
        Ok(())
    })?;
    assert_independent_rejects(&unordered_artifacts, "unordered fixture artifacts")?;

    let invalid_identifier = mutate_profile(&archive, |profile| {
        let fixtures = array_field(profile, 9, "profile fixtures")?;
        array_field(array_mut(&mut fixtures[0], "fixture")?, 4, "provider key")?[0] =
            Value::Text("INVALID".to_owned());
        Ok(())
    })?;
    assert_independent_rejects(&invalid_identifier, "an invalid provider identifier")
}
