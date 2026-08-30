//! Public regression coverage for CFB1/CPF1 rejection boundaries.

pub mod support;

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_conformance::{BundleContractErrorV1, BundleMemberRoleV1, ConformanceBundleV1};
use support::{
    array_field, array_mut, assert_independent_rejects, current_archive as materialized_archive,
    encode_value as encode, member_bytes, member_path_by_role, mutate_archive, mutate_member,
    mutate_profile, mutate_release_admission, replace_archive_member_bytes as replace_member_bytes,
    update_typed_member,
};
use support::{
    ArchiveField, DescriptorField, FixtureField, IndependenceRequirementField, ManifestField,
    MemberField, ProfileField, ProviderBindingField, ProviderKeyField, RecordField,
    ReleaseAdmissionField, TestResult, ARCHIVE_SIGNING_KEY,
};

fn current_archive() -> TestResult<Vec<u8>> {
    materialized_archive("bundle-contract-coverage")
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

    for (role, member_path) in [
        (
            BundleMemberRoleV1::ExecutionProfile,
            "authority/execution-profiles/deterministic-local-v1.epf1",
        ),
        (
            BundleMemberRoleV1::TrustPolicySnapshot,
            "authority/trust-policy-snapshot.tps1",
        ),
    ] {
        let mut bundle = valid.clone();
        let bytes = member_bytes(&archive_value, member_path)?;
        let mut value: Value = ciborium::from_reader(bytes.as_slice())?;
        array_mut(&mut value, "authority member")?[RecordField::Magic.index()] =
            Value::Integer(0_u64.into());
        update_typed_member(&mut bundle, role, encode(&value)?)?;
        assert_eq!(
            bundle.validate(),
            Err(BundleContractErrorV1::ProfileInvalid)
        );
    }

    Ok(())
}

#[test]
fn public_independent_verifier_rejects_partial_execution_authority_closure() -> TestResult {
    let archive = current_archive()?;
    let omitted_path = "authority/execution-profiles/deterministic-air-gapped-v1.epf1";
    let archive_value: Value = ciborium::from_reader(archive.as_slice())?;
    let omitted_digest = blake3::hash(&member_bytes(&archive_value, omitted_path)?)
        .as_bytes()
        .to_vec();
    let omitted_digest_value = Value::Bytes(omitted_digest);
    let reduced_profile = mutate_profile(&archive, |profile| {
        array_field(
            profile,
            ProfileField::ExecutionProfileDigests.index(),
            "execution profile digests",
        )?
        .retain(|digest| digest != &omitted_digest_value);
        array_field(profile, ProfileField::Fixtures.index(), "profile fixtures")?.retain(
            |fixture| match fixture {
                Value::Array(fields) => {
                    fields.get(FixtureField::ExecutionProfileDigest.index())
                        != Some(&omitted_digest_value)
                }
                _ => true,
            },
        );
        Ok(())
    })?;
    let omitted_path_value = Value::Text(omitted_path.to_owned());
    let partial_archive = mutate_archive(&reduced_profile, |archive_fields| {
        array_field(
            archive_fields,
            ArchiveField::Members.index(),
            "archive members",
        )?
        .retain(|member| match member {
            Value::Array(fields) => {
                fields.get(MemberField::Path.index()) != Some(&omitted_path_value)
            }
            _ => true,
        });
        let manifest = array_field(archive_fields, ArchiveField::Manifest.index(), "manifest")?;
        array_field(
            manifest,
            ManifestField::MemberDescriptors.index(),
            "member descriptors",
        )?
        .retain(|descriptor| match descriptor {
            Value::Array(fields) => {
                fields.get(DescriptorField::Path.index()) != Some(&omitted_path_value)
            }
            _ => true,
        });
        Ok(())
    })?;
    assert_independent_rejects(
        &partial_archive,
        "a self-consistent partial execution authority closure",
    )
}

#[test]
fn public_independent_verifier_pins_canonical_authority_sources() -> TestResult {
    let archive = current_archive()?;
    for (path, profile_digest_field) in [
        (
            "authority/execution-matrix.json",
            Some(ProfileField::ExecutionMatrixDigest.index()),
        ),
        ("authority/expected-authority-inventory.json", None),
    ] {
        let archive_value: Value = ciborium::from_reader(archive.as_slice())?;
        let mut changed_bytes = member_bytes(&archive_value, path)?;
        changed_bytes.push(b' ');
        let changed_digest = blake3::hash(&changed_bytes).as_bytes().to_vec();
        let profile_bound = if let Some(field) = profile_digest_field {
            mutate_profile(&archive, |profile| {
                profile[field] = Value::Bytes(changed_digest);
                Ok(())
            })?
        } else {
            archive.clone()
        };
        let changed = mutate_archive(&profile_bound, |archive_fields| {
            replace_member_bytes(archive_fields, path, &changed_bytes)
        })?;
        assert_independent_rejects(&changed, "noncanonical authority source bytes")?;
    }
    Ok(())
}

#[test]
fn public_cfb1_decoders_reject_invalid_member_roles() -> TestResult {
    let archive = current_archive()?;
    let invalid_manifest_role = mutate_archive(&archive, |fields| {
        let descriptor = array_field(
            array_field(fields, ArchiveField::Manifest.index(), "manifest")?,
            ManifestField::MemberDescriptors.index(),
            "member descriptors",
        )?
        .first_mut()
        .ok_or("manifest descriptor is absent")?;
        array_mut(descriptor, "manifest descriptor")?[DescriptorField::Role.index()] =
            Value::Integer(99_u64.into());
        Ok(())
    })?;
    assert_eq!(
        ConformanceBundleV1::from_canonical_cbor(&invalid_manifest_role),
        Err(BundleContractErrorV1::ArchiveEncodingInvalid)
    );

    let invalid_member_role = mutate_archive(&archive, |fields| {
        *array_field(fields, ArchiveField::Members.index(), "archive members")?
            .first_mut()
            .ok_or("archive member is absent")? = Value::Array(vec![
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
            fields[RecordField::Magic.index()] = Value::Integer(0_u64.into());
            Ok(())
        })?;
        assert_independent_rejects(&malformed, "a malformed authority record")?;
    }

    let malformed_release_admission =
        mutate_release_admission(&archive, &release_admission_path, |fields| {
            fields[ReleaseAdmissionField::Magic.index()] = Value::Integer(0_u64.into());
            Ok(())
        })?;
    assert_eq!(
        ConformanceBundleV1::from_canonical_cbor(&malformed_release_admission),
        Err(BundleContractErrorV1::ProfileInvalid)
    );
    assert_independent_rejects(
        &malformed_release_admission,
        "a malformed release admission",
    )?;

    let invalid_release_admission =
        mutate_release_admission(&archive, &release_admission_path, |fields| {
            fields[ReleaseAdmissionField::Magic.index()] = Value::Text("RAD0".to_owned());
            let unsigned = encode(&Value::Array(
                fields[..ReleaseAdmissionField::Signature.index()].to_vec(),
            ))?;
            fields[ReleaseAdmissionField::Signature.index()] = Value::Bytes(
                SigningKey::from_bytes(&ARCHIVE_SIGNING_KEY)
                    .sign(&unsigned)
                    .to_bytes()
                    .to_vec(),
            );
            Ok(())
        })?;
    assert_eq!(
        ConformanceBundleV1::from_canonical_cbor(&invalid_release_admission),
        Err(BundleContractErrorV1::ProfileInvalid)
    );
    assert_independent_rejects(&invalid_release_admission, "a re-signed invalid admission")?;

    Ok(())
}

fn assert_provider_binding_rejections(archive: &[u8]) -> TestResult {
    let unknown_provider = mutate_profile(archive, |profile| {
        let fixtures = array_field(profile, ProfileField::Fixtures.index(), "profile fixtures")?;
        array_mut(&mut fixtures[0], "fixture")?[FixtureField::ProviderKey.index()] =
            Value::Array(vec![
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
        array_field(
            profile,
            ProfileField::ProviderRegistryBinding.index(),
            "provider registry binding",
        )?[ProviderBindingField::RequiredProviders.index()] = Value::Array(vec![provider.clone()]);
        for fixture in array_field(profile, ProfileField::Fixtures.index(), "profile fixtures")? {
            array_mut(fixture, "fixture")?[FixtureField::ProviderKey.index()] = provider.clone();
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
        let fixtures = array_field(profile, ProfileField::Fixtures.index(), "profile fixtures")?;
        let mut extra = fixtures
            .last()
            .cloned()
            .ok_or("profile fixture is absent")?;
        array_mut(&mut extra, "fixture")?[FixtureField::ProviderKey.index()] = Value::Array(vec![
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
        array_field(
            profile,
            ProfileField::ExecutionProfileDigests.index(),
            "execution profile digests",
        )?
        .insert(0, Value::Bytes(vec![2; 32]));
        let originals =
            array_field(profile, ProfileField::Fixtures.index(), "profile fixtures")?.clone();
        let mut expanded = Vec::with_capacity(originals.len() * 2);
        for original in originals {
            let mut additional = original.clone();
            array_mut(&mut additional, "fixture")?[FixtureField::ExecutionProfileDigest.index()] =
                Value::Bytes(vec![2; 32]);
            expanded.push(additional);
            expanded.push(original);
        }
        *array_field(profile, ProfileField::Fixtures.index(), "profile fixtures")? = expanded;
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
        array_field(fields, ArchiveField::Members.index(), "archive members")?.push(Value::Array(
            vec![
                Value::Text("zzzz/undeclared.bin".to_owned()),
                Value::Bytes(vec![1]),
                Value::Integer(0_u64.into()),
            ],
        ));
        array_field(
            array_field(fields, ArchiveField::Manifest.index(), "manifest")?,
            ManifestField::MemberDescriptors.index(),
            "member descriptors",
        )?
        .push(Value::Array(vec![
            Value::Text("zzzz/undeclared.bin".to_owned()),
            Value::Integer(1_u64.into()),
            Value::Bytes(blake3::hash(&[1]).as_bytes().to_vec()),
            Value::Integer(0_u64.into()),
        ]));
        Ok(())
    })?;
    assert_independent_rejects(&undeclared_member, "an undeclared member")?;

    let invalid_mode = mutate_profile(&archive, |profile| {
        let fixtures = array_field(profile, ProfileField::Fixtures.index(), "profile fixtures")?;
        array_mut(&mut fixtures[0], "fixture")?[FixtureField::Modes.index()] =
            Value::Array(vec![Value::Integer(99_u64.into())]);
        Ok(())
    })?;
    assert_independent_rejects(&invalid_mode, "an invalid fixture mode")?;

    let missing_execution_authority = mutate_profile(&archive, |profile| {
        let digests = array_field(
            profile,
            ProfileField::ExecutionProfileDigests.index(),
            "execution profile digests",
        )?;
        digests.push(Value::Bytes(vec![0xff; 32]));
        Ok(())
    })?;
    assert_independent_rejects(
        &missing_execution_authority,
        "a missing execution authority",
    )?;

    let mismatched_snapshot = mutate_profile(&archive, |profile| {
        array_field(
            profile,
            ProfileField::IndependenceRequirements.index(),
            "independence requirements",
        )?[IndependenceRequirementField::TrustPolicySnapshotDigest.index()] =
            Value::Bytes(vec![9; 32]);
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
        let fixtures = array_field(profile, ProfileField::Fixtures.index(), "profile fixtures")?;
        let auxiliary = array_field(
            array_mut(&mut fixtures[0], "fixture")?,
            FixtureField::Auxiliary.index(),
            "auxiliary",
        )?;
        let duplicate = auxiliary
            .first()
            .cloned()
            .ok_or("fixture auxiliary artifacts are absent")?;
        auxiliary.push(duplicate);
        Ok(())
    })?;
    assert_independent_rejects(&unordered_artifacts, "unordered fixture artifacts")?;

    let invalid_identifier = mutate_profile(&archive, |profile| {
        let fixtures = array_field(profile, ProfileField::Fixtures.index(), "profile fixtures")?;
        array_field(
            array_mut(&mut fixtures[0], "fixture")?,
            FixtureField::ProviderKey.index(),
            "provider key",
        )?[ProviderKeyField::ProviderId.index()] = Value::Text("INVALID".to_owned());
        Ok(())
    })?;
    assert_independent_rejects(&invalid_identifier, "an invalid provider identifier")
}
