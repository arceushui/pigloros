use ciborium::value::Value;
use pos_conformance::{
    ArtifactDescriptorV1, ClaimLayerV1, FixtureFamilyV1, FixtureProviderEntryV1,
    FixtureProviderKeyV1, FixtureProviderPackageV1, FixtureProviderRegistryBindingV1,
    FixtureProviderRegistryV1, ProviderContractErrorV1, ProviderFamilySchemaV1,
    SubjectAdapterKindV1, FIXTURE_PROVIDER_PACKAGE_MAGIC_V1, FIXTURE_PROVIDER_REGISTRY_MAGIC_V1,
    FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1, MAX_PROVIDER_ARTIFACT_BYTES_V1,
};

fn digest(seed: u8) -> [u8; 32] {
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

fn fixture_families() -> [FixtureFamilyV1; 7] {
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

fn package() -> FixtureProviderPackageV1 {
    let family_schemas = fixture_families()
        .into_iter()
        .enumerate()
        .map(|(index, family)| ProviderFamilySchemaV1 {
            family,
            schema_descriptor: descriptor(
                &format!("schemas/{index}.cddl"),
                "application/cddl",
                32,
                u8::try_from(index + 1).expect("seven schema digest seeds fit in u8"),
            ),
        })
        .collect();
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

fn seal_package(mut value: FixtureProviderPackageV1) -> FixtureProviderPackageV1 {
    value.package_digest = value.digest().expect("valid package fields are digestible");
    value
}

fn package_descriptor(package_bytes: &[u8], path: &str) -> ArtifactDescriptorV1 {
    ArtifactDescriptorV1 {
        member_path: path.to_owned(),
        media_type: "application/cbor".to_owned(),
        byte_length: u64::try_from(package_bytes.len()).expect("package length fits in u64"),
        blake3_digest: *blake3::hash(package_bytes).as_bytes(),
    }
}

fn provider_entry(
    key: FixtureProviderKeyV1,
    package_bytes: &[u8],
    path: &str,
) -> FixtureProviderEntryV1 {
    FixtureProviderEntryV1 {
        provider_key: key,
        claim_layer: ClaimLayerV1::ArtifactIntegrity,
        subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
        provider_package_descriptor: package_descriptor(package_bytes, path),
    }
}

fn registry(package_bytes: &[u8]) -> FixtureProviderRegistryV1 {
    seal_registry(FixtureProviderRegistryV1 {
        providers: vec![provider_entry(
            provider_key("pigloros.fixture.example"),
            package_bytes,
            "providers/example.cbor",
        )],
        registry_digest: [0; 32],
    })
}

fn seal_registry(mut value: FixtureProviderRegistryV1) -> FixtureProviderRegistryV1 {
    value.registry_digest = value
        .digest()
        .expect("valid registry fields are digestible");
    value
}

fn registry_binding(registry_bytes: &[u8]) -> FixtureProviderRegistryBindingV1 {
    FixtureProviderRegistryBindingV1 {
        registry_artifact: ArtifactDescriptorV1 {
            member_path: FIXTURE_PROVIDER_REGISTRY_MEMBER_PATH_V1.to_owned(),
            media_type: "application/cbor".to_owned(),
            byte_length: u64::try_from(registry_bytes.len()).expect("registry length fits in u64"),
            blake3_digest: *blake3::hash(registry_bytes).as_bytes(),
        },
        required_provider_keys: vec![provider_key("pigloros.fixture.example")],
    }
}

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).expect("test CBOR value is encodable");
    bytes
}

fn decode(bytes: &[u8]) -> Value {
    ciborium::from_reader(bytes).expect("canonical provider record is decodable")
}

fn mutate_record(bytes: &[u8], mutate: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
    let mut value = decode(bytes);
    let Value::Array(fields) = &mut value else {
        panic!("provider record must be an array");
    };
    mutate(fields);
    encode(&value)
}

fn independent_self_digest(bytes: &[u8], domain: &[u8]) -> [u8; 32] {
    let mut value = decode(bytes);
    let Value::Array(fields) = &mut value else {
        panic!("provider record must be an array");
    };
    fields.pop().expect("provider record has a self-digest");
    let fields_bytes = encode(&value);
    let mut preimage = domain.to_vec();
    preimage.extend_from_slice(
        &u64::try_from(fields_bytes.len())
            .expect("encoded field length fits in u64")
            .to_be_bytes(),
    );
    preimage.extend_from_slice(&fields_bytes);
    *blake3::hash(&preimage).as_bytes()
}

fn support_descriptor_mut(
    value: &mut FixtureProviderPackageV1,
    index: usize,
) -> &mut ArtifactDescriptorV1 {
    match index {
        0 => &mut value.licence_descriptor,
        1 => &mut value.notices_descriptor,
        2 => &mut value.sbom_descriptor,
        3 => &mut value.source_provenance_descriptor,
        4 => &mut value.limitations_descriptor,
        _ => panic!("support descriptor index is out of range"),
    }
}

#[test]
fn canonical_fpp1_and_fpr1_round_trip_with_independent_self_digests() {
    let package = package();
    let package_bytes = package.to_canonical_cbor().expect("valid FPP1");
    assert_eq!(
        package.package_digest,
        independent_self_digest(&package_bytes, b"PiglorOS.Conformance.ProviderPackage.v1\0")
    );
    assert_eq!(
        FixtureProviderPackageV1::from_canonical_cbor(&package_bytes),
        Ok(package.clone())
    );

    let registry = registry(&package_bytes);
    let registry_bytes = registry.to_canonical_cbor().expect("valid FPR1");
    assert_eq!(
        registry.registry_digest,
        independent_self_digest(
            &registry_bytes,
            b"PiglorOS.Conformance.ProviderRegistry.v1\0"
        )
    );
    assert_eq!(
        FixtureProviderRegistryV1::from_canonical_cbor(&registry_bytes),
        Ok(registry.clone())
    );
    assert_eq!(
        package.validate_registry_binding(&registry.providers[0], &package_bytes),
        Ok(())
    );

    let binding = registry_binding(&registry_bytes);
    let binding_bytes = binding.to_canonical_cbor().expect("valid CPF1 binding");
    assert_eq!(
        FixtureProviderRegistryBindingV1::from_canonical_cbor(&binding_bytes),
        Ok(binding)
    );
}

#[test]
fn package_exposes_every_fixture_family_wire_code_in_canonical_order() {
    let package = package();
    let bytes = package.to_canonical_cbor().expect("valid FPP1");
    let Value::Array(fields) = decode(&bytes) else {
        panic!("FPP1 must be an array");
    };
    let Value::Array(schema_values) = &fields[5] else {
        panic!("FPP1 family schemas must be an array");
    };
    let codes = schema_values
        .iter()
        .map(|value| {
            let Value::Array(schema_fields) = value else {
                panic!("family schema must be an array");
            };
            let Value::Integer(code) = &schema_fields[0] else {
                panic!("family wire code must be an integer");
            };
            u64::try_from(*code).expect("family wire code is unsigned")
        })
        .collect::<Vec<_>>();
    assert_eq!(codes, vec![0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(
        FixtureProviderPackageV1::from_canonical_cbor(&bytes)
            .expect("all family codes decode")
            .family_schemas
            .into_iter()
            .map(|schema| schema.family)
            .collect::<Vec<_>>(),
        fixture_families()
    );
}

#[test]
fn decoders_reject_wrong_magic_and_version_for_both_records() {
    let package = package();
    let package_bytes = package.to_canonical_cbor().expect("valid FPP1");
    for replacement in [
        Value::Text(FIXTURE_PROVIDER_REGISTRY_MAGIC_V1.to_owned()),
        Value::Text("BAD1".to_owned()),
    ] {
        let bytes = mutate_record(&package_bytes, |fields| fields[0] = replacement);
        assert_eq!(
            FixtureProviderPackageV1::from_canonical_cbor(&bytes),
            Err(ProviderContractErrorV1::UnsupportedVersion)
        );
    }
    let wrong_package_version = mutate_record(&package_bytes, |fields| {
        fields[1] = Value::Integer(2.into())
    });
    assert_eq!(
        FixtureProviderPackageV1::from_canonical_cbor(&wrong_package_version),
        Err(ProviderContractErrorV1::UnsupportedVersion)
    );

    let registry = registry(&package_bytes);
    let registry_bytes = registry.to_canonical_cbor().expect("valid FPR1");
    for replacement in [
        Value::Text(FIXTURE_PROVIDER_PACKAGE_MAGIC_V1.to_owned()),
        Value::Text("BAD1".to_owned()),
    ] {
        let bytes = mutate_record(&registry_bytes, |fields| fields[0] = replacement);
        assert_eq!(
            FixtureProviderRegistryV1::from_canonical_cbor(&bytes),
            Err(ProviderContractErrorV1::UnsupportedVersion)
        );
    }
    let wrong_registry_version = mutate_record(&registry_bytes, |fields| {
        fields[1] = Value::Integer(2.into())
    });
    assert_eq!(
        FixtureProviderRegistryV1::from_canonical_cbor(&wrong_registry_version),
        Err(ProviderContractErrorV1::UnsupportedVersion)
    );
}

#[test]
fn registry_and_binding_reject_empty_duplicate_and_noncanonical_keys() {
    let package_bytes = package().to_canonical_cbor().expect("valid FPP1");
    let first = provider_entry(
        provider_key("pigloros.fixture.a"),
        &package_bytes,
        "providers/a.cbor",
    );
    let mut second = provider_entry(
        provider_key("pigloros.fixture.b"),
        &package_bytes,
        "providers/b.cbor",
    );
    second.provider_key.contract_version = "2.0.0".to_owned();
    let ordered = seal_registry(FixtureProviderRegistryV1 {
        providers: vec![first.clone(), second.clone()],
        registry_digest: [0; 32],
    });
    assert_eq!(ordered.validate(), Ok(()));

    let empty = FixtureProviderRegistryV1 {
        providers: Vec::new(),
        registry_digest: [0; 32],
    };
    assert_eq!(
        empty.validate(),
        Err(ProviderContractErrorV1::FieldOutOfBounds)
    );
    for providers in [
        vec![first.clone(), first.clone()],
        vec![second, first.clone()],
    ] {
        let invalid = FixtureProviderRegistryV1 {
            providers,
            registry_digest: [0; 32],
        };
        assert_eq!(
            invalid.validate(),
            Err(ProviderContractErrorV1::NonCanonicalOrder)
        );
    }

    let registry_bytes = registry(&package_bytes)
        .to_canonical_cbor()
        .expect("valid FPR1");
    let mut binding = registry_binding(&registry_bytes);
    binding.required_provider_keys.clear();
    assert_eq!(
        binding.validate(),
        Err(ProviderContractErrorV1::FieldOutOfBounds)
    );

    let key_a = provider_key("pigloros.fixture.a");
    let key_b = provider_key("pigloros.fixture.b");
    for keys in [vec![key_a.clone(), key_a.clone()], vec![key_b, key_a]] {
        let mut binding = registry_binding(&registry_bytes);
        binding.required_provider_keys = keys;
        assert_eq!(
            binding.validate(),
            Err(ProviderContractErrorV1::NonCanonicalOrder)
        );
    }
}

#[test]
fn provider_keys_enforce_nonempty_identifiers_and_exact_semantic_versions() {
    for provider_id in ["", "Provider", "-provider", "provider@example"] {
        let mut invalid = package();
        invalid.provider_key.provider_id = provider_id.to_owned();
        assert_eq!(
            invalid.validate(),
            Err(ProviderContractErrorV1::InvalidIdentifier)
        );
    }
    for version in ["", "1", "1.0", "01.0.0", "1.0.0-", "1.0.0+"] {
        let mut invalid = package();
        invalid.provider_key.contract_version = version.to_owned();
        assert_eq!(
            invalid.validate(),
            Err(ProviderContractErrorV1::InvalidContractVersion)
        );
    }

    let mut boundary = package();
    boundary.provider_key.provider_id = format!("a{}", "b".repeat(127));
    boundary.provider_key.contract_version = format!("1.0.0+{}", "b".repeat(58));
    boundary.provider_key.abi_major = u16::MAX;
    boundary.provider_key.abi_minor = u16::MAX;
    boundary = seal_package(boundary);
    assert_eq!(boundary.validate(), Ok(()));
}

#[test]
fn descriptors_enforce_path_media_length_and_digest_boundaries() {
    for path in [
        "",
        "/absolute/file.cbor",
        "relative\\file.cbor",
        "a//b.cbor",
        "a/./b.cbor",
        "a/../b.cbor",
        "nul\0byte.cbor",
    ] {
        let mut invalid = package();
        invalid.licence_descriptor.member_path = path.to_owned();
        assert_eq!(
            invalid.validate(),
            Err(ProviderContractErrorV1::InvalidMemberPath)
        );
    }
    let mut too_many_components = package();
    too_many_components.licence_descriptor.member_path = vec!["a"; 17].join("/");
    assert_eq!(
        too_many_components.validate(),
        Err(ProviderContractErrorV1::InvalidMemberPath)
    );
    let mut oversized_component = package();
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
        let mut invalid = package();
        invalid.licence_descriptor.media_type = media_type.to_owned();
        assert_eq!(
            invalid.validate(),
            Err(ProviderContractErrorV1::InvalidMediaType)
        );
    }

    let mut zero_length = package();
    zero_length.licence_descriptor.byte_length = 0;
    assert_eq!(
        zero_length.validate(),
        Err(ProviderContractErrorV1::FieldOutOfBounds)
    );
    let mut excessive_length = package();
    excessive_length.licence_descriptor.byte_length = MAX_PROVIDER_ARTIFACT_BYTES_V1 + 1;
    assert_eq!(
        excessive_length.validate(),
        Err(ProviderContractErrorV1::FieldOutOfBounds)
    );
    let mut zero_digest = package();
    zero_digest.licence_descriptor.blake3_digest = [0; 32];
    assert_eq!(
        zero_digest.validate(),
        Err(ProviderContractErrorV1::DigestMismatch)
    );

    let mut boundary = package();
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
    boundary = seal_package(boundary);
    assert_eq!(boundary.validate(), Ok(()));
}

#[test]
fn decoder_requires_exactly_32_nonzero_descriptor_digest_bytes() {
    let bytes = package().to_canonical_cbor().expect("valid FPP1");
    for digest_length in [31, 33] {
        let malformed = mutate_record(&bytes, |fields| {
            let Value::Array(descriptor_fields) = &mut fields[6] else {
                panic!("license descriptor must be an array");
            };
            descriptor_fields[3] = Value::Bytes(vec![7; digest_length]);
        });
        assert_eq!(
            FixtureProviderPackageV1::from_canonical_cbor(&malformed),
            Err(ProviderContractErrorV1::InvalidEncoding)
        );
    }
}

#[test]
fn package_requires_the_exact_family_schema_set_and_order() {
    let mut missing = package();
    missing.family_schemas.pop();
    assert_eq!(
        missing.validate(),
        Err(ProviderContractErrorV1::FamilyInventoryInvalid)
    );

    let mut duplicate = package();
    duplicate.family_schemas[6].family = FixtureFamilyV1::Downgrade;
    assert_eq!(
        duplicate.validate(),
        Err(ProviderContractErrorV1::FamilyInventoryInvalid)
    );

    let mut reordered = package();
    reordered.family_schemas.swap(0, 1);
    assert_eq!(
        reordered.validate(),
        Err(ProviderContractErrorV1::FamilyInventoryInvalid)
    );

    let bytes = package().to_canonical_cbor().expect("valid FPP1");
    let unknown_code = mutate_record(&bytes, |fields| {
        let Value::Array(schemas) = &mut fields[5] else {
            panic!("family schemas must be an array");
        };
        let Value::Array(schema) = &mut schemas[6] else {
            panic!("family schema must be an array");
        };
        schema[0] = Value::Integer(7.into());
    });
    assert_eq!(
        FixtureProviderPackageV1::from_canonical_cbor(&unknown_code),
        Err(ProviderContractErrorV1::FamilyInventoryInvalid)
    );
}

#[test]
fn every_support_descriptor_is_validated_and_support_paths_are_unique() {
    for index in 0..5 {
        let mut invalid = package();
        support_descriptor_mut(&mut invalid, index).member_path = "/invalid".to_owned();
        assert_eq!(
            invalid.validate(),
            Err(ProviderContractErrorV1::InvalidMemberPath)
        );
    }

    let mut duplicate = package();
    duplicate.notices_descriptor.member_path = duplicate.licence_descriptor.member_path.clone();
    assert_eq!(
        duplicate.validate(),
        Err(ProviderContractErrorV1::NonCanonicalOrder)
    );
}

#[test]
fn package_and_registry_self_digests_reject_tampering() {
    let mut package = package();
    package.package_digest[0] ^= 1;
    assert_eq!(
        package.validate(),
        Err(ProviderContractErrorV1::DigestMismatch)
    );

    let package_bytes = seal_package(package.clone())
        .to_canonical_cbor()
        .expect("valid FPP1");
    let mut registry = registry(&package_bytes);
    registry.registry_digest[0] ^= 1;
    assert_eq!(
        registry.validate(),
        Err(ProviderContractErrorV1::DigestMismatch)
    );
}

#[test]
fn registry_binding_rejects_wrong_artifact_path_and_invalid_required_key() {
    let package_bytes = package().to_canonical_cbor().expect("valid FPP1");
    let registry_bytes = registry(&package_bytes)
        .to_canonical_cbor()
        .expect("valid FPR1");

    let mut wrong_path = registry_binding(&registry_bytes);
    wrong_path.registry_artifact.member_path = "authority/registry.cbor".to_owned();
    assert_eq!(
        wrong_path.validate(),
        Err(ProviderContractErrorV1::InvalidMemberPath)
    );

    let mut invalid_key = registry_binding(&registry_bytes);
    invalid_key.required_provider_keys[0].provider_id.clear();
    assert_eq!(
        invalid_key.validate(),
        Err(ProviderContractErrorV1::InvalidIdentifier)
    );
}

#[test]
fn package_registry_binding_rejects_every_mismatch_dimension() {
    let package = package();
    let package_bytes = package.to_canonical_cbor().expect("valid FPP1");
    let entry = registry(&package_bytes)
        .providers
        .into_iter()
        .next()
        .expect("registry contains its provider entry");

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

    let mut changed_bytes = package_bytes.clone();
    let last = changed_bytes
        .last_mut()
        .expect("canonical FPP1 contains at least one byte");
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
    );
    assert_eq!(
        package.validate_registry_binding(&unrelated_entry, unrelated_bytes),
        Err(ProviderContractErrorV1::PackageBindingMismatch)
    );
}

#[test]
fn decoders_reject_trailing_noncanonical_malformed_and_wrong_shape_cbor() {
    let package_bytes = package().to_canonical_cbor().expect("valid FPP1");
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
        .expect("canonical FPP1 version marker exists");
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

    let registry_bytes = registry(&package_bytes)
        .to_canonical_cbor()
        .expect("valid FPR1");
    let mut trailing_registry = registry_bytes;
    trailing_registry.push(0);
    assert_eq!(
        FixtureProviderRegistryV1::from_canonical_cbor(&trailing_registry),
        Err(ProviderContractErrorV1::InvalidEncoding)
    );
}
