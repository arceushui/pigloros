use ciborium::value::Value;
use pos_conformance::{
    ArtifactDescriptorV1, ClaimLayerV1, FixtureFamilyV1, FixtureProviderEntryV1,
    FixtureProviderKeyV1, FixtureProviderPackageV1, FixtureProviderRegistryBindingV1,
    FixtureProviderRegistryV1, ProviderContractErrorV1, ProviderFamilySchemaV1,
    SubjectAdapterKindV1, FIXTURE_PROVIDER_PACKAGE_MAGIC_V1, FIXTURE_PROVIDER_REGISTRY_MAGIC_V1,
    FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1, MAX_PROVIDER_ARTIFACT_BYTES_V1,
};
use std::error::Error;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const fn digest(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn descriptor(path: &str, media_type: &str, byte_length: u64, seed: u8) -> ArtifactDescriptorV1 {
    ArtifactDescriptorV1 {
        member_path: path.to_owned(),
        media_type: media_type.to_owned(),
        byte_length,
        blake3_digest: digest(seed),
    }
}

fn provider_key(provider_id: &str) -> FixtureProviderKeyV1 {
    FixtureProviderKeyV1 {
        provider_id: provider_id.to_owned(),
        contract_version: "1.2.3-rc.1+build.9".to_owned(),
        abi_major: 1,
        abi_minor: 0,
    }
}

const fn fixture_families() -> [FixtureFamilyV1; 7] {
    [
        FixtureFamilyV1::Positive,
        FixtureFamilyV1::Denied,
        FixtureFamilyV1::Malformed,
        FixtureFamilyV1::ResourceExhaustion,
        FixtureFamilyV1::DeletionRedaction,
        FixtureFamilyV1::Downgrade,
        FixtureFamilyV1::IndependentEvaluation,
    ]
}

fn package() -> TestResult<FixtureProviderPackageV1> {
    let family_schemas = fixture_families()
        .into_iter()
        .enumerate()
        .map(|(index, family)| {
            Ok(ProviderFamilySchemaV1 {
                family,
                schema_descriptor: descriptor(
                    &format!("schemas/{index}.cddl"),
                    "application/cddl",
                    32,
                    u8::try_from(index + 1)?,
                ),
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    seal_package(FixtureProviderPackageV1 {
        provider_key: provider_key("pigloros.fixture.example"),
        claim_layer: ClaimLayerV1::ArtifactIntegrity,
        subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
        family_schemas,
        licence_descriptor: descriptor("support/license.txt", "text/plain", 128, 8),
        notices_descriptor: descriptor("support/notices.txt", "text/plain", 129, 9),
        sbom_descriptor: descriptor(
            "support/sbom.cdx.json",
            "application/vnd.cyclonedx+json",
            130,
            10,
        ),
        source_provenance_descriptor: descriptor(
            "support/source-provenance.json",
            "application/json",
            131,
            11,
        ),
        limitations_descriptor: descriptor("support/limitations.md", "text/markdown", 132, 12),
        package_digest: [0; 32],
    })
}

fn seal_package(mut value: FixtureProviderPackageV1) -> TestResult<FixtureProviderPackageV1> {
    value.package_digest = value.digest()?;
    Ok(value)
}

fn package_descriptor(package_bytes: &[u8], path: &str) -> TestResult<ArtifactDescriptorV1> {
    Ok(ArtifactDescriptorV1 {
        member_path: path.to_owned(),
        media_type: "application/cbor".to_owned(),
        byte_length: u64::try_from(package_bytes.len())?,
        blake3_digest: *blake3::hash(package_bytes).as_bytes(),
    })
}

fn provider_entry(
    key: FixtureProviderKeyV1,
    package_bytes: &[u8],
    path: &str,
) -> TestResult<FixtureProviderEntryV1> {
    Ok(FixtureProviderEntryV1 {
        provider_key: key,
        claim_layer: ClaimLayerV1::ArtifactIntegrity,
        subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
        provider_package_descriptor: package_descriptor(package_bytes, path)?,
    })
}

fn registry(package_bytes: &[u8]) -> TestResult<FixtureProviderRegistryV1> {
    seal_registry(FixtureProviderRegistryV1 {
        providers: vec![provider_entry(
            provider_key("pigloros.fixture.example"),
            package_bytes,
            "providers/example.cbor",
        )?],
        registry_digest: [0; 32],
    })
}

fn seal_registry(mut value: FixtureProviderRegistryV1) -> TestResult<FixtureProviderRegistryV1> {
    value.registry_digest = value.digest()?;
    Ok(value)
}

fn registry_binding(registry_bytes: &[u8]) -> TestResult<FixtureProviderRegistryBindingV1> {
    Ok(FixtureProviderRegistryBindingV1 {
        registry_artifact: ArtifactDescriptorV1 {
            member_path: FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1.to_owned(),
            media_type: "application/cbor".to_owned(),
            byte_length: u64::try_from(registry_bytes.len())?,
            blake3_digest: *blake3::hash(registry_bytes).as_bytes(),
        },
        required_provider_keys: vec![provider_key("pigloros.fixture.example")],
    })
}

fn encode(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> TestResult<Value> {
    Ok(ciborium::from_reader(bytes)?)
}

fn mutate_record(
    bytes: &[u8],
    mutate: impl FnOnce(&mut Vec<Value>) -> TestResult,
) -> TestResult<Vec<u8>> {
    let mut value = decode(bytes)?;
    let Value::Array(fields) = &mut value else {
        return Err("provider record must be an array".into());
    };
    mutate(fields)?;
    encode(&value)
}

fn independent_self_digest(bytes: &[u8], domain: &[u8]) -> TestResult<[u8; 32]> {
    let mut value = decode(bytes)?;
    let Value::Array(fields) = &mut value else {
        return Err("provider record must be an array".into());
    };
    fields
        .pop()
        .ok_or("provider record must contain a self-digest")?;
    let fields_bytes = encode(&value)?;
    let mut preimage = domain.to_vec();
    preimage.extend_from_slice(&u64::try_from(fields_bytes.len())?.to_be_bytes());
    preimage.extend_from_slice(&fields_bytes);
    Ok(*blake3::hash(&preimage).as_bytes())
}

const fn support_descriptor_mut(
    value: &mut FixtureProviderPackageV1,
    index: usize,
) -> Option<&mut ArtifactDescriptorV1> {
    match index {
        0 => Some(&mut value.licence_descriptor),
        1 => Some(&mut value.notices_descriptor),
        2 => Some(&mut value.sbom_descriptor),
        3 => Some(&mut value.source_provenance_descriptor),
        4 => Some(&mut value.limitations_descriptor),
        _ => None,
    }
}

#[test]
fn canonical_fpp1_and_fpr1_round_trip_with_independent_self_digests() -> TestResult {
    let package = package()?;
    let package_bytes = package.to_canonical_cbor()?;
    assert_eq!(
        package.package_digest,
        independent_self_digest(&package_bytes, b"PiglorOS.Conformance.ProviderPackage.v1\0")?
    );
    assert_eq!(
        FixtureProviderPackageV1::from_canonical_cbor(&package_bytes),
        Ok(package.clone())
    );

    let registry = registry(&package_bytes)?;
    let registry_bytes = registry.to_canonical_cbor()?;
    assert_eq!(
        registry.registry_digest,
        independent_self_digest(
            &registry_bytes,
            b"PiglorOS.Conformance.ProviderRegistry.v1\0"
        )?
    );
    assert_eq!(
        FixtureProviderRegistryV1::from_canonical_cbor(&registry_bytes),
        Ok(registry.clone())
    );
    assert_eq!(
        package.validate_registry_binding(&registry.providers[0], &package_bytes),
        Ok(())
    );

    let binding = registry_binding(&registry_bytes)?;
    let binding_bytes = binding.to_canonical_cbor()?;
    assert_eq!(
        FixtureProviderRegistryBindingV1::from_canonical_cbor(&binding_bytes),
        Ok(binding)
    );
    Ok(())
}

#[test]
fn package_exposes_every_fixture_family_wire_code_in_canonical_order() -> TestResult {
    let package = package()?;
    let bytes = package.to_canonical_cbor()?;
    let Value::Array(fields) = decode(&bytes)? else {
        return Err("FPP1 must be an array".into());
    };
    let Value::Array(schema_values) = &fields[5] else {
        return Err("FPP1 family schemas must be an array".into());
    };
    let codes = schema_values
        .iter()
        .map(|value| {
            let Value::Array(schema_fields) = value else {
                return Err("family schema must be an array".into());
            };
            let Value::Integer(code) = &schema_fields[0] else {
                return Err("family wire code must be an integer".into());
            };
            Ok(u64::try_from(*code)?)
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(codes, vec![0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(
        FixtureProviderPackageV1::from_canonical_cbor(&bytes)?
            .family_schemas
            .into_iter()
            .map(|schema| schema.family)
            .collect::<Vec<_>>(),
        fixture_families()
    );
    Ok(())
}

#[test]
fn decoders_reject_wrong_magic_and_version_for_both_records() -> TestResult {
    let package = package()?;
    let package_bytes = package.to_canonical_cbor()?;
    for replacement in [
        Value::Text(FIXTURE_PROVIDER_REGISTRY_MAGIC_V1.to_owned()),
        Value::Text("BAD1".to_owned()),
    ] {
        let bytes = mutate_record(&package_bytes, |fields| {
            fields[0] = replacement;
            Ok(())
        })?;
        assert_eq!(
            FixtureProviderPackageV1::from_canonical_cbor(&bytes),
            Err(ProviderContractErrorV1::UnsupportedVersion)
        );
    }
    let wrong_package_version = mutate_record(&package_bytes, |fields| {
        fields[1] = Value::Integer(2.into());
        Ok(())
    })?;
    assert_eq!(
        FixtureProviderPackageV1::from_canonical_cbor(&wrong_package_version),
        Err(ProviderContractErrorV1::UnsupportedVersion)
    );

    let registry = registry(&package_bytes)?;
    let registry_bytes = registry.to_canonical_cbor()?;
    for replacement in [
        Value::Text(FIXTURE_PROVIDER_PACKAGE_MAGIC_V1.to_owned()),
        Value::Text("BAD1".to_owned()),
    ] {
        let bytes = mutate_record(&registry_bytes, |fields| {
            fields[0] = replacement;
            Ok(())
        })?;
        assert_eq!(
            FixtureProviderRegistryV1::from_canonical_cbor(&bytes),
            Err(ProviderContractErrorV1::UnsupportedVersion)
        );
    }
    let wrong_registry_version = mutate_record(&registry_bytes, |fields| {
        fields[1] = Value::Integer(2.into());
        Ok(())
    })?;
    assert_eq!(
        FixtureProviderRegistryV1::from_canonical_cbor(&wrong_registry_version),
        Err(ProviderContractErrorV1::UnsupportedVersion)
    );
    Ok(())
}

#[test]
fn registry_and_binding_reject_empty_duplicate_and_noncanonical_keys() -> TestResult {
    let package_bytes = package()?.to_canonical_cbor()?;
    let first = provider_entry(
        provider_key("pigloros.fixture.a"),
        &package_bytes,
        "providers/a.cbor",
    )?;
    let mut second = provider_entry(
        provider_key("pigloros.fixture.b"),
        &package_bytes,
        "providers/b.cbor",
    )?;
    second.provider_key.contract_version = "2.0.0".to_owned();
    let ordered = seal_registry(FixtureProviderRegistryV1 {
        providers: vec![first.clone(), second.clone()],
        registry_digest: [0; 32],
    })?;
    assert_eq!(ordered.validate(), Ok(()));

    let empty = FixtureProviderRegistryV1 {
        providers: Vec::new(),
        registry_digest: [0; 32],
    };
    assert_eq!(
        empty.validate(),
        Err(ProviderContractErrorV1::FieldOutOfBounds)
    );
    for providers in [vec![first.clone(), first.clone()], vec![second, first]] {
        let invalid = FixtureProviderRegistryV1 {
            providers,
            registry_digest: [0; 32],
        };
        assert_eq!(
            invalid.validate(),
            Err(ProviderContractErrorV1::NonCanonicalOrder)
        );
    }

    let registry_bytes = registry(&package_bytes)?.to_canonical_cbor()?;
    let mut binding = registry_binding(&registry_bytes)?;
    binding.required_provider_keys.clear();
    assert_eq!(
        binding.validate(),
        Err(ProviderContractErrorV1::FieldOutOfBounds)
    );

    let key_a = provider_key("pigloros.fixture.a");
    let key_b = provider_key("pigloros.fixture.b");
    for keys in [vec![key_a.clone(), key_a.clone()], vec![key_b, key_a]] {
        let mut binding = registry_binding(&registry_bytes)?;
        binding.required_provider_keys = keys;
        assert_eq!(
            binding.validate(),
            Err(ProviderContractErrorV1::NonCanonicalOrder)
        );
    }
    Ok(())
}

#[test]
fn provider_keys_enforce_nonempty_identifiers_and_exact_semantic_versions() -> TestResult {
    for provider_id in ["", "Provider", "-provider", "provider@example"] {
        let mut invalid = package()?;
        invalid.provider_key.provider_id = provider_id.to_owned();
        assert_eq!(
            invalid.validate(),
            Err(ProviderContractErrorV1::InvalidIdentifier)
        );
    }
    for version in [
        "",
        "1",
        "1.0",
        "01.0.0",
        "1.0.0-",
        "1.0.0+",
        "1.0.0-01",
        "1.0.0-alpha..beta",
        "1.0.0-alpha!",
        "1.0.0+build!",
    ] {
        let mut invalid = package()?;
        invalid.provider_key.contract_version = version.to_owned();
        assert_eq!(
            invalid.validate(),
            Err(ProviderContractErrorV1::InvalidContractVersion)
        );
    }

    let mut boundary = package()?;
    boundary.provider_key.provider_id = format!("a{}", "b".repeat(127));
    boundary.provider_key.contract_version = format!("1.0.0+{}", "b".repeat(58));
    boundary.provider_key.abi_major = u16::MAX;
    boundary.provider_key.abi_minor = u16::MAX;
    boundary = seal_package(boundary)?;
    assert_eq!(boundary.validate(), Ok(()));
    Ok(())
}

#[test]
fn descriptors_enforce_path_media_length_and_digest_boundaries() -> TestResult {
    for path in [
        "",
        "/absolute/file.cbor",
        "relative\\file.cbor",
        "a//b.cbor",
        "a/./b.cbor",
        "a/../b.cbor",
        "nul\0byte.cbor",
    ] {
        let mut invalid = package()?;
        invalid.licence_descriptor.member_path = path.to_owned();
        assert_eq!(
            invalid.validate(),
            Err(ProviderContractErrorV1::InvalidMemberPath)
        );
    }
    let mut too_many_components = package()?;
    too_many_components.licence_descriptor.member_path = vec!["a"; 17].join("/");
    assert_eq!(
        too_many_components.validate(),
        Err(ProviderContractErrorV1::InvalidMemberPath)
    );
    let mut oversized_component = package()?;
    oversized_component.licence_descriptor.member_path = format!("{}.cbor", "a".repeat(129));
    assert_eq!(
        oversized_component.validate(),
        Err(ProviderContractErrorV1::InvalidMemberPath)
    );

    for media_type in [
        "",
        "application",
        "Application/cbor",
        "/cbor",
        "application/",
        "application/cbor/extra",
        "application/cbor;profile=x",
    ] {
        let mut invalid = package()?;
        invalid.licence_descriptor.media_type = media_type.to_owned();
        assert_eq!(
            invalid.validate(),
            Err(ProviderContractErrorV1::InvalidMediaType)
        );
    }

    let mut zero_length = package()?;
    zero_length.licence_descriptor.byte_length = 0;
    assert_eq!(
        zero_length.validate(),
        Err(ProviderContractErrorV1::FieldOutOfBounds)
    );
    let mut excessive_length = package()?;
    excessive_length.licence_descriptor.byte_length = MAX_PROVIDER_ARTIFACT_BYTES_V1 + 1;
    assert_eq!(
        excessive_length.validate(),
        Err(ProviderContractErrorV1::FieldOutOfBounds)
    );
    let mut zero_digest = package()?;
    zero_digest.licence_descriptor.blake3_digest = [0; 32];
    assert_eq!(
        zero_digest.validate(),
        Err(ProviderContractErrorV1::DigestMismatch)
    );

    let mut boundary = package()?;
    boundary.licence_descriptor.member_path = [
        "a".repeat(128),
        "b".repeat(128),
        "c".repeat(128),
        "d".repeat(125),
    ]
    .join("/");
    assert_eq!(boundary.licence_descriptor.member_path.len(), 512);
    boundary.licence_descriptor.media_type =
        format!("application/{}", "x".repeat(127 - "application/".len()));
    assert_eq!(boundary.licence_descriptor.media_type.len(), 127);
    boundary.licence_descriptor.byte_length = MAX_PROVIDER_ARTIFACT_BYTES_V1;
    boundary.licence_descriptor.blake3_digest = [u8::MAX; 32];
    boundary = seal_package(boundary)?;
    assert_eq!(boundary.validate(), Ok(()));
    Ok(())
}

#[test]
fn decoder_requires_exactly_32_nonzero_descriptor_digest_bytes() -> TestResult {
    let bytes = package()?.to_canonical_cbor()?;
    for digest_length in [31, 33] {
        let malformed = mutate_record(&bytes, |fields| {
            let Value::Array(descriptor_fields) = &mut fields[6] else {
                return Err("license descriptor must be an array".into());
            };
            descriptor_fields[3] = Value::Bytes(vec![7; digest_length]);
            Ok(())
        })?;
        assert_eq!(
            FixtureProviderPackageV1::from_canonical_cbor(&malformed),
            Err(ProviderContractErrorV1::InvalidEncoding)
        );
    }
    Ok(())
}

#[test]
fn package_requires_the_exact_family_schema_set_and_order() -> TestResult {
    let mut missing = package()?;
    missing.family_schemas.pop();
    assert_eq!(
        missing.validate(),
        Err(ProviderContractErrorV1::FamilyInventoryInvalid)
    );

    let mut duplicate = package()?;
    duplicate.family_schemas[6].family = FixtureFamilyV1::Downgrade;
    assert_eq!(
        duplicate.validate(),
        Err(ProviderContractErrorV1::FamilyInventoryInvalid)
    );

    let mut reordered = package()?;
    reordered.family_schemas.swap(0, 1);
    assert_eq!(
        reordered.validate(),
        Err(ProviderContractErrorV1::FamilyInventoryInvalid)
    );

    let bytes = package()?.to_canonical_cbor()?;
    let unknown_code = mutate_record(&bytes, |fields| {
        let Value::Array(schemas) = &mut fields[5] else {
            return Err("family schemas must be an array".into());
        };
        let Value::Array(schema) = &mut schemas[6] else {
            return Err("family schema must be an array".into());
        };
        schema[0] = Value::Integer(7.into());
        Ok(())
    })?;
    assert_eq!(
        FixtureProviderPackageV1::from_canonical_cbor(&unknown_code),
        Err(ProviderContractErrorV1::FamilyInventoryInvalid)
    );
    Ok(())
}

#[test]
fn every_package_artifact_path_is_validated_and_unique() -> TestResult {
    for index in 0..5 {
        let mut invalid = package()?;
        support_descriptor_mut(&mut invalid, index)
            .ok_or("support descriptor index is out of range")?
            .member_path = "/invalid".to_owned();
        assert_eq!(
            invalid.validate(),
            Err(ProviderContractErrorV1::InvalidMemberPath)
        );
    }

    let mut duplicate = package()?;
    duplicate.notices_descriptor.member_path = duplicate.licence_descriptor.member_path.clone();
    assert_eq!(
        duplicate.validate(),
        Err(ProviderContractErrorV1::NonCanonicalOrder)
    );

    let mut schema_support_collision = package()?;
    schema_support_collision.licence_descriptor.member_path = schema_support_collision
        .family_schemas
        .first()
        .ok_or("provider package must contain a family schema")?
        .schema_descriptor
        .member_path
        .clone();
    assert_eq!(
        schema_support_collision.validate(),
        Err(ProviderContractErrorV1::NonCanonicalOrder)
    );
    Ok(())
}

#[test]
fn package_and_registry_self_digests_reject_tampering() -> TestResult {
    let mut package = package()?;
    package.package_digest[0] ^= 1;
    assert_eq!(
        package.validate(),
        Err(ProviderContractErrorV1::DigestMismatch)
    );

    let package_bytes = seal_package(package)?.to_canonical_cbor()?;
    let mut registry = registry(&package_bytes)?;
    registry.registry_digest[0] ^= 1;
    assert_eq!(
        registry.validate(),
        Err(ProviderContractErrorV1::DigestMismatch)
    );
    Ok(())
}

#[test]
fn registry_binding_rejects_wrong_artifact_path_and_invalid_required_key() -> TestResult {
    let package_bytes = package()?.to_canonical_cbor()?;
    let registry_bytes = registry(&package_bytes)?.to_canonical_cbor()?;

    let mut wrong_path = registry_binding(&registry_bytes)?;
    wrong_path.registry_artifact.member_path = "authority/registry.cbor".to_owned();
    assert_eq!(
        wrong_path.validate(),
        Err(ProviderContractErrorV1::InvalidMemberPath)
    );

    let mut invalid_key = registry_binding(&registry_bytes)?;
    invalid_key.required_provider_keys[0].provider_id.clear();
    assert_eq!(
        invalid_key.validate(),
        Err(ProviderContractErrorV1::InvalidIdentifier)
    );
    Ok(())
}

#[test]
fn package_registry_binding_rejects_every_mismatch_dimension() -> TestResult {
    let package = package()?;
    let package_bytes = package.to_canonical_cbor()?;
    let entry = registry(&package_bytes)?
        .providers
        .into_iter()
        .next()
        .ok_or("registry must contain its provider entry")?;

    let mut wrong_key = entry.clone();
    wrong_key.provider_key.provider_id = "pigloros.fixture.other".to_owned();
    assert_eq!(
        package.validate_registry_binding(&wrong_key, &package_bytes),
        Err(ProviderContractErrorV1::PackageBindingMismatch)
    );

    let mut wrong_layer = entry.clone();
    wrong_layer.claim_layer = ClaimLayerV1::ReplayConformance;
    assert_eq!(
        package.validate_registry_binding(&wrong_layer, &package_bytes),
        Err(ProviderContractErrorV1::PackageBindingMismatch)
    );

    let mut wrong_adapter = entry.clone();
    wrong_adapter.subject_adapter = SubjectAdapterKindV1::PublicPluginProtocol;
    assert_eq!(
        package.validate_registry_binding(&wrong_adapter, &package_bytes),
        Err(ProviderContractErrorV1::PackageBindingMismatch)
    );

    let mut wrong_length = entry.clone();
    wrong_length.provider_package_descriptor.byte_length += 1;
    assert_eq!(
        package.validate_registry_binding(&wrong_length, &package_bytes),
        Err(ProviderContractErrorV1::PackageBindingMismatch)
    );

    let mut wrong_digest = entry.clone();
    wrong_digest.provider_package_descriptor.blake3_digest = digest(99);
    assert_eq!(
        package.validate_registry_binding(&wrong_digest, &package_bytes),
        Err(ProviderContractErrorV1::PackageBindingMismatch)
    );

    let mut changed_bytes = package_bytes;
    let last = changed_bytes
        .last_mut()
        .ok_or("canonical FPP1 must contain at least one byte")?;
    *last ^= 1;
    assert_eq!(
        package.validate_registry_binding(&entry, &changed_bytes),
        Err(ProviderContractErrorV1::PackageBindingMismatch)
    );

    let unrelated_bytes = b"different canonical package bytes";
    let unrelated_entry = provider_entry(
        package.provider_key.clone(),
        unrelated_bytes,
        "providers/example.cbor",
    )?;
    assert_eq!(
        package.validate_registry_binding(&unrelated_entry, unrelated_bytes),
        Err(ProviderContractErrorV1::PackageBindingMismatch)
    );
    Ok(())
}

#[test]
fn decoders_reject_trailing_noncanonical_malformed_and_wrong_shape_cbor() -> TestResult {
    let package_bytes = package()?.to_canonical_cbor()?;
    let mut trailing = package_bytes.clone();
    trailing.push(0);
    assert_eq!(
        FixtureProviderPackageV1::from_canonical_cbor(&trailing),
        Err(ProviderContractErrorV1::InvalidEncoding)
    );

    let marker = [0x64, b'F', b'P', b'P', b'1', 0x01];
    let version_index = package_bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .map(|index| index + marker.len() - 1)
        .ok_or("canonical FPP1 version marker must exist")?;
    let mut noncanonical = package_bytes.clone();
    noncanonical.splice(version_index..=version_index, [0x18, 0x01]);
    assert_eq!(
        FixtureProviderPackageV1::from_canonical_cbor(&noncanonical),
        Err(ProviderContractErrorV1::InvalidEncoding)
    );

    for malformed in [
        vec![0xff],
        vec![0x9f, 0xff],
        vec![0xa0],
        vec![0x82, 0x64, b'F', b'P', b'P', b'1'],
    ] {
        assert_eq!(
            FixtureProviderPackageV1::from_canonical_cbor(&malformed),
            Err(ProviderContractErrorV1::InvalidEncoding)
        );
    }

    let registry_bytes = registry(&package_bytes)?.to_canonical_cbor()?;
    let mut trailing_registry = registry_bytes;
    trailing_registry.push(0);
    assert_eq!(
        FixtureProviderRegistryV1::from_canonical_cbor(&trailing_registry),
        Err(ProviderContractErrorV1::InvalidEncoding)
    );
    Ok(())
}

fn assert_package_shape_rejections(package_bytes: &[u8]) -> TestResult {
    let malformed_package_fields = [
        (0, Value::Null, ProviderContractErrorV1::InvalidEncoding),
        (1, Value::Null, ProviderContractErrorV1::InvalidEncoding),
        (
            3,
            Value::Integer(256.into()),
            ProviderContractErrorV1::FieldOutOfBounds,
        ),
        (
            4,
            Value::Integer(3.into()),
            ProviderContractErrorV1::FieldOutOfBounds,
        ),
        (5, Value::Null, ProviderContractErrorV1::InvalidEncoding),
        (6, Value::Null, ProviderContractErrorV1::InvalidEncoding),
        (11, Value::Null, ProviderContractErrorV1::InvalidEncoding),
    ];
    for (index, replacement, expected) in malformed_package_fields {
        let malformed = mutate_record(package_bytes, |fields| {
            fields[index] = replacement;
            Ok(())
        })?;
        assert_eq!(
            FixtureProviderPackageV1::from_canonical_cbor(&malformed),
            Err(expected)
        );
    }

    for (field, replacement, expected) in [
        (0, Value::Null, ProviderContractErrorV1::InvalidEncoding),
        (1, Value::Null, ProviderContractErrorV1::InvalidEncoding),
        (
            2,
            Value::Integer(65_536_u64.into()),
            ProviderContractErrorV1::FieldOutOfBounds,
        ),
        (
            3,
            Value::Integer(65_536_u64.into()),
            ProviderContractErrorV1::FieldOutOfBounds,
        ),
    ] {
        let malformed = mutate_record(package_bytes, |fields| {
            let Value::Array(provider_key) = &mut fields[2] else {
                return Err("provider key must be an array".into());
            };
            provider_key[field] = replacement;
            Ok(())
        })?;
        assert_eq!(
            FixtureProviderPackageV1::from_canonical_cbor(&malformed),
            Err(expected)
        );
    }

    for (field, replacement, expected) in [
        (0, Value::Null, ProviderContractErrorV1::InvalidEncoding),
        (1, Value::Null, ProviderContractErrorV1::InvalidEncoding),
    ] {
        let malformed_schema = mutate_record(package_bytes, |fields| {
            let Value::Array(schemas) = &mut fields[5] else {
                return Err("family schemas must be an array".into());
            };
            let Value::Array(schema) = &mut schemas[0] else {
                return Err("family schema must be an array".into());
            };
            schema[field] = replacement;
            Ok(())
        })?;
        assert_eq!(
            FixtureProviderPackageV1::from_canonical_cbor(&malformed_schema),
            Err(expected)
        );
    }
    Ok(())
}

fn assert_descriptor_registry_and_binding_rejections(package_bytes: &[u8]) -> TestResult {
    for (field, replacement) in [
        (0, Value::Null),
        (1, Value::Null),
        (2, Value::Integer((-1).into())),
        (3, Value::Null),
    ] {
        let malformed = mutate_record(package_bytes, |fields| {
            let Value::Array(descriptor) = &mut fields[6] else {
                return Err("licence descriptor must be an array".into());
            };
            descriptor[field] = replacement;
            Ok(())
        })?;
        assert_eq!(
            FixtureProviderPackageV1::from_canonical_cbor(&malformed),
            Err(ProviderContractErrorV1::InvalidEncoding)
        );
    }

    for descriptor_index in 7..=10 {
        let malformed = mutate_record(package_bytes, |fields| {
            fields[descriptor_index] = Value::Null;
            Ok(())
        })?;
        assert_eq!(
            FixtureProviderPackageV1::from_canonical_cbor(&malformed),
            Err(ProviderContractErrorV1::InvalidEncoding)
        );
    }

    let registry_bytes = registry(package_bytes)?.to_canonical_cbor()?;
    let malformed_registry = mutate_record(&registry_bytes, |fields| {
        fields[2] = Value::Null;
        Ok(())
    })?;
    assert_eq!(
        FixtureProviderRegistryV1::from_canonical_cbor(&malformed_registry),
        Err(ProviderContractErrorV1::InvalidEncoding)
    );
    let oversized_registry = mutate_record(&registry_bytes, |fields| {
        fields[2] = Value::Array(vec![Value::Null; 4097]);
        Ok(())
    })?;
    assert_eq!(
        FixtureProviderRegistryV1::from_canonical_cbor(&oversized_registry),
        Err(ProviderContractErrorV1::FieldOutOfBounds)
    );
    assert_registry_entry_rejections(&registry_bytes)?;

    let binding_bytes = registry_binding(&registry_bytes)?.to_canonical_cbor()?;
    let malformed_binding = mutate_record(&binding_bytes, |fields| {
        fields[1] = Value::Null;
        Ok(())
    })?;
    assert_eq!(
        FixtureProviderRegistryBindingV1::from_canonical_cbor(&malformed_binding),
        Err(ProviderContractErrorV1::InvalidEncoding)
    );
    let oversized_binding = mutate_record(&binding_bytes, |fields| {
        fields[1] = Value::Array(vec![Value::Null; 4097]);
        Ok(())
    })?;
    assert_eq!(
        FixtureProviderRegistryBindingV1::from_canonical_cbor(&oversized_binding),
        Err(ProviderContractErrorV1::FieldOutOfBounds)
    );
    assert_required_provider_key_rejections(&binding_bytes)
}

fn assert_registry_entry_rejections(registry_bytes: &[u8]) -> TestResult {
    for (field, replacement, expected) in [
        (0, Value::Null, ProviderContractErrorV1::InvalidEncoding),
        (1, Value::Null, ProviderContractErrorV1::InvalidEncoding),
        (
            2,
            Value::Integer(65_536_u64.into()),
            ProviderContractErrorV1::FieldOutOfBounds,
        ),
        (
            3,
            Value::Integer(65_536_u64.into()),
            ProviderContractErrorV1::FieldOutOfBounds,
        ),
        (
            4,
            Value::Integer(256_u64.into()),
            ProviderContractErrorV1::FieldOutOfBounds,
        ),
        (
            5,
            Value::Integer(3_u64.into()),
            ProviderContractErrorV1::FieldOutOfBounds,
        ),
        (6, Value::Null, ProviderContractErrorV1::InvalidEncoding),
    ] {
        let malformed = mutate_record(registry_bytes, |fields| {
            let Value::Array(providers) = &mut fields[2] else {
                return Err("provider registry entries must be an array".into());
            };
            let Value::Array(entry) = &mut providers[0] else {
                return Err("provider registry entry must be an array".into());
            };
            entry[field] = replacement;
            Ok(())
        })?;
        assert_eq!(
            FixtureProviderRegistryV1::from_canonical_cbor(&malformed),
            Err(expected)
        );
    }
    Ok(())
}

fn assert_required_provider_key_rejections(binding_bytes: &[u8]) -> TestResult {
    for field in 0..4 {
        let malformed = mutate_record(binding_bytes, |fields| {
            let Value::Array(required) = &mut fields[1] else {
                return Err("required provider keys must be an array".into());
            };
            let Value::Array(key) = &mut required[0] else {
                return Err("required provider key must be an array".into());
            };
            key[field] = Value::Null;
            Ok(())
        })?;
        assert_eq!(
            FixtureProviderRegistryBindingV1::from_canonical_cbor(&malformed),
            Err(ProviderContractErrorV1::InvalidEncoding)
        );
    }
    Ok(())
}

fn mutate_nested_record(package_bytes: &[u8], path: &[usize]) -> TestResult<Vec<u8>> {
    mutate_record(package_bytes, |fields| {
        let (field, parents) = path.split_last().ok_or("record path must not be empty")?;
        let mut selected = fields;
        for index in parents {
            let Value::Array(nested) = selected
                .get_mut(*index)
                .ok_or("record path is out of bounds")?
            else {
                return Err("record path must select arrays".into());
            };
            selected = nested;
        }
        selected[*field] = Value::Map(Vec::new());
        Ok(())
    })
}

#[test]
fn public_decoders_reject_wrong_types_at_every_provider_record_path() -> TestResult {
    let package_bytes = package()?.to_canonical_cbor()?;
    let mut package_paths = (0..12).map(|field| vec![field]).collect::<Vec<_>>();
    package_paths.extend((0..4).map(|field| vec![2, field]));
    package_paths.push(vec![5, 0]);
    package_paths.extend((0..2).map(|field| vec![5, 0, field]));
    package_paths.extend((0..4).map(|field| vec![5, 0, 1, field]));
    for descriptor in 6..=10 {
        package_paths.extend((0..4).map(|field| vec![descriptor, field]));
    }
    for path in package_paths {
        let malformed = mutate_nested_record(&package_bytes, &path)?;
        assert!(
            FixtureProviderPackageV1::from_canonical_cbor(&malformed).is_err(),
            "package field {path:?} unexpectedly decoded"
        );
    }

    let registry_bytes = registry(&package_bytes)?.to_canonical_cbor()?;
    let mut registry_paths = (0..4).map(|field| vec![field]).collect::<Vec<_>>();
    registry_paths.push(vec![2, 0]);
    registry_paths.extend((0..7).map(|field| vec![2, 0, field]));
    registry_paths.extend((0..4).map(|field| vec![2, 0, 6, field]));
    for path in registry_paths {
        let malformed = mutate_nested_record(&registry_bytes, &path)?;
        assert!(
            FixtureProviderRegistryV1::from_canonical_cbor(&malformed).is_err(),
            "registry field {path:?} unexpectedly decoded"
        );
    }

    let binding_bytes = registry_binding(&registry_bytes)?.to_canonical_cbor()?;
    let mut binding_paths = (0..2).map(|field| vec![field]).collect::<Vec<_>>();
    binding_paths.extend((0..4).map(|field| vec![0, field]));
    binding_paths.push(vec![1, 0]);
    binding_paths.extend((0..4).map(|field| vec![1, 0, field]));
    for path in binding_paths {
        let malformed = mutate_nested_record(&binding_bytes, &path)?;
        assert!(
            FixtureProviderRegistryBindingV1::from_canonical_cbor(&malformed).is_err(),
            "binding field {path:?} unexpectedly decoded"
        );
    }
    Ok(())
}

#[test]
fn public_decoders_reject_every_provider_record_type_and_bound_violation() -> TestResult {
    let package_bytes = package()?.to_canonical_cbor()?;
    assert_package_shape_rejections(&package_bytes)?;
    assert_descriptor_registry_and_binding_rejections(&package_bytes)
}

#[test]
fn public_decoders_enforce_raw_cbor_size_depth_and_collection_caps() {
    let oversized_record = vec![0_u8; 16 * 1024 * 1024 + 1];
    assert_eq!(
        FixtureProviderPackageV1::from_canonical_cbor(&oversized_record),
        Err(ProviderContractErrorV1::FieldOutOfBounds)
    );

    let mut over_nested = vec![0x81; 33];
    over_nested.push(0);
    assert_eq!(
        FixtureProviderPackageV1::from_canonical_cbor(&over_nested),
        Err(ProviderContractErrorV1::FieldOutOfBounds)
    );

    for malformed in [
        vec![],
        vec![0x58],
        vec![0x58, 0x01],
        vec![0x41],
        vec![0x61, 0xff],
        vec![0x5f],
        vec![0x5b, 0, 0, 0, 0, 0, 0, 0, 1],
        vec![0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        vec![0xfa, 0, 0, 0, 0],
        vec![0x9a, 0, 0, 0x10, 0x01],
        vec![0x9a, 0, 1, 0, 1],
    ] {
        let error = FixtureProviderPackageV1::from_canonical_cbor(&malformed)
            .expect_err("malformed provider package must be rejected");
        assert!([
            ProviderContractErrorV1::InvalidEncoding,
            ProviderContractErrorV1::FieldOutOfBounds,
        ]
        .contains(&error));
    }
}
