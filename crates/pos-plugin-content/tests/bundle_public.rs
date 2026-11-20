//! Complete checks use verified real closures; no unchecked content proof exists.

mod cases {
    mod content_negatives;
    mod fixture;

    use fixture::{bytes, Fixture, TestResult};
    use pos_crypto::plugin_execution::PluginExecutionProjectionV1;
    use pos_plugin_content::{
        validate_plugin_bundle_content_v1 as validate, PluginBundleContentArtifactV1 as Artifact,
        PluginBundleContentErrorV1 as Error,
    };
    use serde_json::json;

    fn result(fixture: &Fixture) -> TestResult<Result<(), Error>> {
        Ok(validate(&fixture.bundle()?).map(|_| ()))
    }

    #[test]
    fn checks_a_genuine_closure_and_binds_both_digests_without_signature_authority() -> TestResult {
        let fixture = Fixture::new();
        let bundle = fixture.bundle()?;
        let proof = validate(&bundle)?;
        let projection = PluginExecutionProjectionV1::from_verified_bundle(&bundle)?;
        assert_eq!(proof.pmf1_digest(), projection.pmf1_digest());
        assert_eq!(proof.release_digest(), projection.release_digest());
        assert_eq!(proof.rule(), "BasicPackageV1");
        assert_eq!(proof.clone(), proof);
        assert!(!format!("{proof:?}").contains("example.invalid"));
        Ok(())
    }

    #[test]
    fn malformed_pmf1_is_refused_before_any_content_claim() -> TestResult {
        let mut fixture = Fixture::new();
        fixture.provenance = b"not JSON".to_vec();
        let bundle = fixture.bundle_with_invalid_manifest()?;
        assert!(matches!(validate(&bundle), Err(Error::Manifest(_))));
        Ok(())
    }

    #[test]
    fn reuses_wit_checks_before_any_json_artifact() -> TestResult {
        let mut fixture = Fixture::new();
        fixture.wit = b"not tar".to_vec();
        fixture.provenance = b"not JSON".to_vec();
        assert_eq!(
            result(&fixture)?,
            Err(Error::Malformed {
                artifact: Artifact::Wit
            })
        );
        Ok(())
    }

    #[test]
    fn rejects_duplicate_decoded_keys_trailing_data_bad_utf8_and_wrong_json_roots() -> TestResult {
        for data in [
            br#"{"type":"object","\u0074ype":"string"}"#.as_slice(),
            b"true false",
            &[0xff],
            b"[true]",
            b"null",
            b"42",
        ] {
            let mut fixture = Fixture::new();
            fixture.schemas[0] = data.to_vec();
            assert_eq!(
                result(&fixture)?,
                Err(Error::Malformed {
                    artifact: Artifact::Schema { index: 0 }
                })
            );
        }
        Ok(())
    }

    #[test]
    fn keeps_annotation_values_inert_and_never_compiles_the_plugins_regex() -> TestResult {
        let mut fixture = Fixture::new();
        fixture.schemas[0] = bytes(&json!({
            "type": "string", "pattern": "([a-z]+)+$",
            "examples": [{"$ref": "https://offline.invalid/not-a-schema"}],
            "default": {"$id": "https://offline.invalid/data", "$ref": "file:///not-read"}
        }));
        assert_eq!(result(&fixture)?, Ok(()));
        fixture.schemas[0] = bytes(&json!({"$ref": "#/examples/0", "examples": [{}]}));
        assert_eq!(
            result(&fixture)?,
            Err(Error::ReferenceMismatch {
                artifact: Artifact::Schema { index: 0 }
            })
        );
        Ok(())
    }

    #[test]
    fn resolves_declared_cross_resource_dynamic_anchors_and_cycles() -> TestResult {
        let mut fixture = Fixture::new();
        fixture.schemas = vec![
            bytes(
                &json!({"$id":"https://schema.invalid/first", "$dynamicAnchor":"node", "$dynamicRef":"second#node"}),
            ),
            bytes(
                &json!({"$id":"https://schema.invalid/second", "$dynamicAnchor":"node", "$ref":"first#node"}),
            ),
        ];
        assert_eq!(result(&fixture)?, Ok(()));
        Ok(())
    }

    #[test]
    fn rejects_unknown_dialects_vocabularies_resources_and_duplicate_identifiers() -> TestResult {
        for value in [
            json!({"$schema":"https://json-schema.org/draft-07/schema"}),
            json!({"$vocabulary":{"https://unknown.invalid/vocab":true}}),
        ] {
            let mut fixture = Fixture::new();
            fixture.schemas[0] = bytes(&value);
            assert_eq!(
                result(&fixture)?,
                Err(Error::UnsupportedFormat {
                    artifact: Artifact::Schema { index: 0 }
                })
            );
        }
        for value in [
            json!({"$ref":"file:///not-read"}),
            json!({"$ref":"#/missing"}),
            json!({"$id":"https://schema.invalid/root", "$defs":{"child":{"$id":"https://schema.invalid/root"}}}),
            json!({"$anchor":"same", "$defs":{"child":{"$anchor":"same"}}}),
        ] {
            let mut fixture = Fixture::new();
            fixture.schemas[0] = bytes(&value);
            assert_eq!(
                result(&fixture)?,
                Err(Error::ReferenceMismatch {
                    artifact: Artifact::Schema { index: 0 }
                })
            );
        }
        Ok(())
    }

    #[test]
    fn binds_provenance_by_component_subject_and_checks_required_structure() -> TestResult {
        let mut fixture = Fixture::new();
        fixture
            .provenance(|value| value["subject"][0]["digest"]["sha256"] = json!("0".repeat(64)))?;
        assert_eq!(
            result(&fixture)?,
            Err(Error::ReferenceMismatch {
                artifact: Artifact::Provenance
            })
        );
        for pointer in [
            "/predicate/buildDefinition/buildType",
            "/predicate/runDetails/builder/id",
        ] {
            let mut fixture = Fixture::new();
            fixture.provenance(|value| {
                assert!(value
                    .pointer_mut(pointer)
                    .map(|field| *field = json!(" "))
                    .is_some());
            })?;
            assert_eq!(
                result(&fixture)?,
                Err(Error::Malformed {
                    artifact: Artifact::Provenance
                })
            );
        }
        let mut fixture = Fixture::new();
        fixture.provenance(|value| {
            value["predicate"]["buildDefinition"]["internalParameters"] = json!(null);
        })?;
        assert_eq!(result(&fixture)?, Ok(()));
        Ok(())
    }

    #[test]
    fn accepts_each_direct_spdx_description_form_and_refuses_indirect_only_binding() -> TestResult {
        for inverse in [false, true] {
            let mut fixture = Fixture::new();
            fixture.sbom(|value|{
            assert!(value.as_object_mut().and_then(|object| object.remove("documentDescribes")).is_some());
            value["relationships"]=if inverse { json!([{"spdxElementId":"SPDXRef-component","relationshipType":"DESCRIBED_BY","relatedSpdxElement":"SPDXRef-DOCUMENT"}]) }
                else { json!([{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-component"}]) };
        })?;
            assert_eq!(result(&fixture)?, Ok(()));
        }
        let mut fixture = Fixture::new();
        fixture.sbom(|value|{
        let mut parent=value["packages"][0].clone(); parent["SPDXID"]=json!("SPDXRef-parent");
        assert!(parent.as_object_mut().and_then(|object| object.remove("checksums")).is_some());
        value["packages"]=json!([value["packages"][0].clone(), parent]);
        value["documentDescribes"]=json!(["SPDXRef-parent"]);
        value["relationships"]=json!([{"spdxElementId":"SPDXRef-parent","relationshipType":"CONTAINS","relatedSpdxElement":"SPDXRef-component"}]);
    })?;
        assert_eq!(
            result(&fixture)?,
            Err(Error::ReferenceMismatch {
                artifact: Artifact::Sbom
            })
        );
        Ok(())
    }

    #[test]
    fn rejects_spdx_identity_reference_and_checksum_substitution() -> TestResult {
        for (pointer, value) in [
            ("/documentDescribes/0", json!("SPDXRef-missing")),
            (
                "/packages/0/checksums/0/checksumValue",
                json!("0".repeat(64)),
            ),
        ] {
            let mut fixture = Fixture::new();
            fixture.sbom(|sbom| {
                assert!(sbom
                    .pointer_mut(pointer)
                    .map(|field| *field = value)
                    .is_some());
            })?;
            assert_eq!(
                result(&fixture)?,
                Err(Error::ReferenceMismatch {
                    artifact: Artifact::Sbom
                })
            );
        }
        let mut fixture = Fixture::new();
        fixture.sbom(|sbom| {
            let duplicate = sbom["packages"][0].clone();
            sbom["packages"] = json!([duplicate.clone(), duplicate]);
        })?;
        assert_eq!(
            result(&fixture)?,
            Err(Error::ReferenceMismatch {
                artifact: Artifact::Sbom
            })
        );
        Ok(())
    }

    #[test]
    fn checks_licence_text_without_an_allowlist_and_resolves_extracted_licences() -> TestResult {
        for text in [b" \n\t".as_slice(), &[0xff], b"text\0hidden"] {
            let mut fixture = Fixture::new();
            fixture.licences = vec![text.to_vec()];
            assert_eq!(
                result(&fixture)?,
                Err(Error::Malformed {
                    artifact: Artifact::Licence { index: 0 }
                })
            );
        }
        let mut fixture = Fixture::new();
        fixture
            .sbom(|value| value["packages"][0]["licenseDeclared"] = json!("LicenseRef-local"))?;
        assert_eq!(
            result(&fixture)?,
            Err(Error::ReferenceMismatch {
                artifact: Artifact::Sbom
            })
        );
        fixture.sbom(|value| {
        value["hasExtractedLicensingInfos"] =
            json!([{"licenseId":"LicenseRef-local","extractedText":"A local custom licence"}]);
    })?;
        assert_eq!(result(&fixture)?, Ok(()));
        Ok(())
    }

    #[test]
    fn enforces_json_depth_while_decoding_including_empty_final_containers() -> TestResult {
        for (arrays, expected) in [
            (63, Ok(())),
            (
                64,
                Err(Error::BoundsExceeded {
                    artifact: Artifact::Provenance,
                }),
            ),
        ] {
            let mut fixture = Fixture::new();
            fixture.provenance(|value| {
                let mut nested = json!(null);
                for _ in 0..arrays {
                    nested = json!([nested]);
                }
                value["extension"] = nested;
            })?;
            assert_eq!(result(&fixture)?, expected);
        }
        let mut fixture = Fixture::new();
        fixture.provenance(|value| {
            let mut nested = json!([]);
            for _ in 0..63 {
                nested = json!([nested]);
            }
            value["extension"] = nested;
        })?;
        assert_eq!(
            result(&fixture)?,
            Err(Error::BoundsExceeded {
                artifact: Artifact::Provenance
            })
        );
        Ok(())
    }

    #[test]
    fn enforces_the_exact_json_node_boundary_before_retaining_an_extra_value() -> TestResult {
        // Independent literal count: the fixed provenance contributes fourteen
        // value nodes, and the extension array contributes one container.
        for (leaves, expected) in [
            (262_129, Ok(())),
            (
                262_130,
                Err(Error::BoundsExceeded {
                    artifact: Artifact::Provenance,
                }),
            ),
        ] {
            let mut fixture = Fixture::new();
            fixture.provenance(|value| value["extension"] = json!(vec![false; leaves]))?;
            assert_eq!(result(&fixture)?, expected);
        }
        Ok(())
    }

    #[test]
    fn spdx_schema_is_the_exact_attributed_upstream_resource() {
        use sha2::{Digest as _, Sha256};
        let schema = include_bytes!("../resources/spdx-schema-2.3.1.json");
        assert_eq!(
            fixture::hex(&Sha256::digest(schema)),
            "4126dc29f15e92feec92e9622f4939131ad58b125d6f578aa93e980a6e6f3212"
        );
    }

    #[test]
    fn refuses_missing_spdx_creation_metadata_and_wrong_document_constants() -> TestResult {
        for (pointer, value) in [
            ("/creationInfo/creators", json!([])),
            ("/creationInfo/creators/0", json!("")),
            ("/creationInfo/created", json!("invalid date")),
            ("/documentNamespace", json!("")),
            ("/name", json!(" ")),
            ("/SPDXID", json!("SPDXRef-other-document")),
            ("/dataLicense", json!("MIT")),
        ] {
            let mut fixture = Fixture::new();
            fixture.sbom(|value_json| {
                assert!(value_json
                    .pointer_mut(pointer)
                    .map(|field| *field = value)
                    .is_some());
            })?;
            assert_eq!(
                result(&fixture)?,
                Err(Error::Malformed {
                    artifact: Artifact::Sbom
                })
            );
        }
        Ok(())
    }

    #[test]
    fn preserves_optional_vocabulary_annotations_and_all_json_scalar_kinds() -> TestResult {
        let mut fixture = Fixture::new();
        fixture.schemas[0] = bytes(&json!({
            "$vocabulary": {"https://unknown.invalid/annotation": false},
            "examples": [null, true, -1, 1, 1.25, "escaped\ntext"]
        }));
        assert_eq!(result(&fixture)?, Ok(()));
        Ok(())
    }

    #[test]
    fn changes_the_bound_evidence_when_another_licence_closure_is_checked() -> TestResult {
        let mut fixture = Fixture::new();
        let first = validate(&fixture.bundle()?)?;
        fixture.licences =
            vec![b"An alternative local licence with no allowlist classification".to_vec()];
        let second = validate(&fixture.bundle()?)?;
        assert_ne!(first.pmf1_digest(), second.pmf1_digest());
        assert_ne!(first.release_digest(), second.release_digest());
        assert_ne!(first, second);
        Ok(())
    }
}
