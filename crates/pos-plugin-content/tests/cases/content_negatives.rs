//! Artifact-format and local-reference refusals through the whole-bundle seam.

use serde_json::{json, Value};

use super::{bytes, fixture, result, Artifact, Error, Fixture, TestResult};

fn replace(value: &mut Value, pointer: &str, replacement: Value) {
    assert!(value
        .pointer_mut(pointer)
        .map(|field| *field = replacement)
        .is_some());
}

#[test]
fn whole_bundle_preserves_each_wit_refusal_class() -> TestResult {
    let mut fixture = Fixture::new();
    fixture.wit[..100].fill(0);
    let path = format!("{}main.wit", "d/".repeat(32));
    fixture.wit[..path.len()].copy_from_slice(path.as_bytes());
    checksum_wit_header(&mut fixture.wit);
    assert_eq!(
        result(&fixture)?,
        Err(Error::BoundsExceeded {
            artifact: Artifact::Wit
        })
    );

    let mut fixture = Fixture::new();
    fixture.wit[156] = b'2';
    checksum_wit_header(&mut fixture.wit);
    assert_eq!(
        result(&fixture)?,
        Err(Error::UnsupportedFormat {
            artifact: Artifact::Wit
        })
    );

    let mut fixture = Fixture::new();
    let original = b"community-plugin";
    let replacement = b"different-plugin";
    let position = fixture
        .wit
        .windows(original.len())
        .position(|part| part == original)
        .ok_or("world missing")?;
    fixture.wit[position..position + original.len()].copy_from_slice(replacement);
    assert_eq!(
        result(&fixture)?,
        Err(Error::ReferenceMismatch {
            artifact: Artifact::Wit
        })
    );
    Ok(())
}

fn checksum_wit_header(archive: &mut [u8]) {
    archive[148..156].fill(b' ');
    let sum: usize = archive[..512].iter().map(|byte| usize::from(*byte)).sum();
    archive[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

#[test]
fn provenance_required_fields_fail_with_their_closed_artifact_error() -> TestResult {
    for root in [json!(null), json!([]), json!(false)] {
        let mut fixture = Fixture::new();
        fixture.provenance = bytes(&root);
        assert_eq!(
            result(&fixture)?,
            Err(Error::Malformed {
                artifact: Artifact::Provenance
            })
        );
    }
    for (pointer, replacement) in [
        ("/_type", json!(null)),
        ("/predicateType", json!(false)),
        ("/subject", json!({})),
        ("/subject/0/digest", json!([])),
        ("/subject/0/digest", json!({})),
        ("/subject/0/digest/sha256", json!(null)),
        ("/subject/0/digest/sha256", json!("")),
        ("/predicate", json!(null)),
        ("/predicate/buildDefinition", json!([])),
        ("/predicate/runDetails", json!(false)),
        ("/predicate/runDetails/builder", json!(null)),
        ("/predicate/buildDefinition/buildType", json!([])),
        ("/predicate/buildDefinition/externalParameters", json!([])),
    ] {
        let mut fixture = Fixture::new();
        fixture.provenance(|value| replace(value, pointer, replacement))?;
        assert_eq!(
            result(&fixture)?,
            Err(Error::Malformed {
                artifact: Artifact::Provenance
            })
        );
    }
    for (pointer, value) in [
        ("/_type", "https://in-toto.io/Statement/v0.1"),
        ("/predicateType", "https://slsa.dev/provenance/v0.2"),
    ] {
        let mut fixture = Fixture::new();
        fixture.provenance(|document| replace(document, pointer, json!(value)))?;
        assert_eq!(
            result(&fixture)?,
            Err(Error::UnsupportedFormat {
                artifact: Artifact::Provenance
            })
        );
    }
    for field in ["internalParameters", "resolvedDependencies"] {
        let mut fixture = Fixture::new();
        fixture
            .provenance(|document| document["predicate"]["buildDefinition"][field] = json!(true))?;
        assert_eq!(
            result(&fixture)?,
            Err(Error::Malformed {
                artifact: Artifact::Provenance
            })
        );
    }
    let mut fixture = Fixture::new();
    fixture.provenance(|document| document["subject"][0]["name"] = json!(0))?;
    assert_eq!(
        result(&fixture)?,
        Err(Error::Malformed {
            artifact: Artifact::Provenance
        })
    );
    Ok(())
}

#[test]
fn invalid_schema_uri_references_are_refused_without_retrieval() -> TestResult {
    for keyword in ["$id", "$ref"] {
        let mut schema = serde_json::Map::new();
        schema.insert(keyword.to_owned(), json!("https://example.invalid/%zz"));
        let mut fixture = Fixture::new();
        fixture.schemas = vec![bytes(&Value::Object(schema))];
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
fn provenance_allows_metadata_without_fetching_and_requires_one_exact_subject() -> TestResult {
    for subjects in [
        json!([]),
        json!([{"digest":{"sha256":"f".repeat(63)}}]),
        json!([{"digest":{"sha512":"metadata"},"name":"extra"}]),
    ] {
        let mut fixture = Fixture::new();
        fixture.provenance(|value| value["subject"] = subjects)?;
        assert_eq!(
            result(&fixture)?,
            Err(Error::ReferenceMismatch {
                artifact: Artifact::Provenance
            })
        );
    }
    let mut fixture = Fixture::new();
    fixture.provenance(|value| {
        value["subject"] = json!([
            {"name":"metadata only", "digest":{"sha512":"not an authenticated input"}},
            {"name":"component", "digest":{"sha256":fixture::component_digest().to_uppercase()}}
        ]);
        value["predicate"]["buildDefinition"]["externalParameters"] = json!(null);
        value["predicate"]["buildDefinition"]["internalParameters"] =
            json!({"source":"file:///never-fetch"});
        value["predicate"]["buildDefinition"]["resolvedDependencies"] = json!([]);
    })?;
    assert_eq!(result(&fixture)?, Ok(()));
    fixture.provenance(|value| {
        value["predicate"]["buildDefinition"]["resolvedDependencies"] = json!(null);
    })?;
    assert_eq!(result(&fixture)?, Ok(()));
    Ok(())
}

fn external_document() -> Value {
    json!({"externalDocumentId":"DocumentRef-other", "spdxDocument":"https://example.invalid/never-fetch", "checksum":{"algorithm":"SHA256","checksumValue":"a".repeat(64)}})
}

fn references_fixture() -> TestResult<Fixture> {
    let mut fixture = Fixture::new();
    fixture.sbom(|value| {
        value["externalDocumentRefs"] = json!([external_document()]);
        value["documentDescribes"] = json!(["SPDXRef-DOCUMENT", "SPDXRef-a-snippet", "SPDXRef-file", "DocumentRef-other:SPDXRef-external"]);
        value["packages"][0]["hasFiles"] = json!(["SPDXRef-file", "NONE", "NOASSERTION", "DocumentRef-other:SPDXRef-external"]);
        value["packages"][0]["licenseDeclared"] = json!("DocumentRef-other:LicenseRef-external AND LicenseRef-local");
        value["files"] = json!([{
            "SPDXID":"SPDXRef-file", "fileName":"component.wasm",
            "checksums":[{"algorithm":"SHA1","checksumValue":"a".repeat(40)}, {"algorithm":"SHA256","checksumValue":"0".repeat(64)}, {"algorithm":"SHA256","checksumValue":fixture::component_digest().to_uppercase()}],
            "fileDependencies":["SPDXRef-component"], "licenseInfoInFiles":["MIT", "LicenseRef-local"], "licenseConcluded":"MIT"
        }]);
        value["snippets"] = json!([{
            "SPDXID":"SPDXRef-a-snippet", "snippetFromFile":"SPDXRef-file",
            "ranges":[{"startPointer":{"reference":"SPDXRef-file","offset":0},"endPointer":{"reference":"SPDXRef-file","offset":7}}],
            "licenseInfoInSnippets":["LicenseRef-local"]
        }]);
        value["hasExtractedLicensingInfos"] = json!([{"licenseId":"LicenseRef-local", "extractedText":"A local custom licence"}]);
        value["relationships"] = json!([{"spdxElementId":"DocumentRef-other:SPDXRef-external", "relationshipType":"OTHER", "relatedSpdxElement":"NONE"}]);
    })?;
    Ok(fixture)
}

fn set_external_document(value: &mut Value, document: &str) {
    value["externalDocumentRefs"][0]["externalDocumentId"] = json!(document);
    let element = format!("{document}:SPDXRef-external");
    value["documentDescribes"][3] = json!(element);
    value["packages"][0]["hasFiles"][3] = json!(element);
    value["relationships"][0]["spdxElementId"] = json!(element);
    value["packages"][0]["licenseDeclared"] = json!(format!(
        "{document}:LicenseRef-external AND LicenseRef-local"
    ));
}

#[test]
fn spdx_external_identifiers_follow_the_declared_syntax() -> TestResult {
    for document in ["bad", "DocumentRef-", "DocumentRef-bad@"] {
        let mut fixture = references_fixture()?;
        fixture.sbom(|value| set_external_document(value, document))?;
        assert_eq!(
            result(&fixture)?,
            Err(Error::Malformed {
                artifact: Artifact::Sbom
            })
        );
    }
    let mut fixture = references_fixture()?;
    fixture.sbom(|value| {
        value["relationships"][0]["spdxElementId"] = json!("DocumentRef-other:SPDXRef-bad@");
    })?;
    assert_eq!(
        result(&fixture)?,
        Err(Error::ReferenceMismatch {
            artifact: Artifact::Sbom
        })
    );

    let mut fixture = references_fixture()?;
    fixture.sbom(|value| set_external_document(value, "DocumentRef-a+b.1"))?;
    assert_eq!(result(&fixture)?, Ok(()));
    Ok(())
}

#[test]
fn schema_failure_reports_the_first_closure_member_across_phases() -> TestResult {
    for (first, expected) in [
        (
            br#"{"$vocabulary":{"https://unknown.invalid/vocab":true}}"#.as_slice(),
            Error::UnsupportedFormat {
                artifact: Artifact::Schema { index: 0 },
            },
        ),
        (
            br#"{"$ref":"urn:missing"}"#.as_slice(),
            Error::ReferenceMismatch {
                artifact: Artifact::Schema { index: 0 },
            },
        ),
    ] {
        let mut fixture = Fixture::new();
        fixture.schemas = vec![first.to_vec(), b"null".to_vec()];
        assert_eq!(result(&fixture)?, Err(expected));
    }
    Ok(())
}

#[test]
fn earlier_schema_failure_precedes_later_json_node_exhaustion() -> TestResult {
    let mut fixture = Fixture::new();
    let mut later = br#"{"examples":["#.to_vec();
    later.extend(
        std::iter::repeat_n(b"0,".as_slice(), 262_143)
            .flatten()
            .copied(),
    );
    later.extend_from_slice(br#"0],"title":"2"}"#);
    fixture.schemas = vec![
        br#"{"$vocabulary":{"https://unknown.invalid/vocab":true}}"#.to_vec(),
        later,
    ];
    assert_eq!(
        result(&fixture)?,
        Err(Error::UnsupportedFormat {
            artifact: Artifact::Schema { index: 0 }
        })
    );
    Ok(())
}

#[test]
fn spdx_checks_direct_files_snippets_and_declared_external_metadata() -> TestResult {
    let fixture = references_fixture()?;
    assert_eq!(result(&fixture)?, Ok(()));
    for (pointer, replacement) in [
        ("/packages/0/hasFiles/0", json!("SPDXRef-missing")),
        ("/files/0/fileDependencies/0", json!("SPDXRef-missing")),
        ("/snippets/0/snippetFromFile", json!("SPDXRef-missing")),
        ("/relationships/0/spdxElementId", json!("SPDXRef-missing")),
        (
            "/relationships/0/relatedSpdxElement",
            json!("SPDXRef-missing"),
        ),
        (
            "/relationships/0/relatedSpdxElement",
            json!("DocumentRef-absent:SPDXRef-element"),
        ),
        (
            "/relationships/0/relatedSpdxElement",
            json!("DocumentRef-other:Wrong-element"),
        ),
        (
            "/relationships/0/relatedSpdxElement",
            json!("DocumentRef-other:SPDXRef-"),
        ),
        (
            "/packages/0/licenseDeclared",
            json!("DocumentRef-absent:LicenseRef-external"),
        ),
    ] {
        let mut fixture = references_fixture()?;
        fixture.sbom(|value| replace(value, pointer, replacement))?;
        assert_eq!(
            result(&fixture)?,
            Err(Error::ReferenceMismatch {
                artifact: Artifact::Sbom
            })
        );
    }
    Ok(())
}

#[test]
fn spdx_refuses_duplicate_external_documents_and_extracted_licences() -> TestResult {
    let mut fixture = references_fixture()?;
    fixture.sbom(|value| {
        value["externalDocumentRefs"] = json!([external_document(), external_document()]);
    })?;
    assert_eq!(
        result(&fixture)?,
        Err(Error::ReferenceMismatch {
            artifact: Artifact::Sbom
        })
    );
    let mut fixture = references_fixture()?;
    fixture.sbom(|value| {
        let licence = value["hasExtractedLicensingInfos"][0].clone();
        value["hasExtractedLicensingInfos"] = json!([licence.clone(), licence]);
    })?;
    assert_eq!(
        result(&fixture)?,
        Err(Error::ReferenceMismatch {
            artifact: Artifact::Sbom
        })
    );
    for (pointer, replacement) in [
        ("/externalDocumentRefs/0/externalDocumentId", json!(" ")),
        ("/hasExtractedLicensingInfos/0/extractedText", json!(" ")),
        ("/hasExtractedLicensingInfos/0/licenseId", json!(" ")),
        ("/packages/0/licenseDeclared", json!(" ")),
    ] {
        let mut fixture = references_fixture()?;
        fixture.sbom(|value| replace(value, pointer, replacement))?;
        assert_eq!(
            result(&fixture)?,
            Err(Error::Malformed {
                artifact: Artifact::Sbom
            })
        );
    }
    let mut fixture = Fixture::new();
    fixture.sbom(|value| value["spdxVersion"] = json!("SPDX-2.2"))?;
    assert_eq!(
        result(&fixture)?,
        Err(Error::UnsupportedFormat {
            artifact: Artifact::Sbom
        })
    );
    Ok(())
}

#[test]
fn spdx_rejects_blank_version_and_reference_fields() -> TestResult {
    for (pointer, replacement) in [
        ("/spdxVersion", json!(" ")),
        ("/documentDescribes/0", json!(" ")),
        ("/relationships/0/spdxElementId", json!(" ")),
        ("/relationships/0/relatedSpdxElement", json!(" ")),
        ("/packages/0/hasFiles/0", json!(" ")),
        ("/snippets/0/snippetFromFile", json!(" ")),
    ] {
        let mut fixture = references_fixture()?;
        fixture.sbom(|value| replace(value, pointer, replacement))?;
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
fn malformed_nested_json_and_map_depth_are_refused_before_content_checks() -> TestResult {
    for bytes in [b"{1:true}".as_slice(), b"{\"x\":]}", b"[true,]"] {
        let mut fixture = Fixture::new();
        fixture.provenance = bytes.to_vec();
        assert_eq!(
            result(&fixture)?,
            Err(Error::Malformed {
                artifact: Artifact::Provenance
            })
        );
    }
    let mut fixture = Fixture::new();
    fixture.provenance = [b"{\"x\":".repeat(64), b"{}".to_vec(), b"}".repeat(64)].concat();
    assert_eq!(
        result(&fixture)?,
        Err(Error::BoundsExceeded {
            artifact: Artifact::Provenance
        })
    );
    for (schema, expected) in [
        (
            json!({"$id":"https://example.invalid/schema#fragment"}),
            Error::Malformed {
                artifact: Artifact::Schema { index: 0 },
            },
        ),
        (
            json!({"$defs":{"nested":{"$id":"https://example.invalid/schema#fragment"}}}),
            Error::Malformed {
                artifact: Artifact::Schema { index: 0 },
            },
        ),
        (
            json!({"$defs":{"nested":{"$schema":"https://json-schema.org/draft/2019-09/schema"}}}),
            Error::UnsupportedFormat {
                artifact: Artifact::Schema { index: 0 },
            },
        ),
    ] {
        let mut fixture = Fixture::new();
        fixture.schemas = vec![bytes(&schema)];
        assert_eq!(result(&fixture)?, Err(expected));
    }
    Ok(())
}

#[test]
fn schema_vocabularies_and_global_index_budgets_are_explicit() -> TestResult {
    let mut vocabulary = serde_json::Map::new();
    for name in [
        "core",
        "applicator",
        "validation",
        "unevaluated",
        "meta-data",
        "format-annotation",
        "format-assertion",
        "content",
    ] {
        vocabulary.insert(
            format!("https://json-schema.org/draft/2020-12/vocab/{name}"),
            json!(true),
        );
    }
    let mut fixture = Fixture::new();
    fixture.schemas = vec![bytes(&json!({"$vocabulary":vocabulary}))];
    assert_eq!(result(&fixture)?, Ok(()));

    fixture.schemas = vec![bytes(&json!({"$defs":{"nested":{
        "$schema":"https://json-schema.org/draft/2020-12/schema"
    }}}))];
    assert_eq!(result(&fixture)?, Ok(()));

    for count in [65_536, 65_537] {
        let mut fixture = Fixture::new();
        fixture.schemas = vec![bytes(&json!({"allOf":vec![json!({"$ref":"#"});count]}))];
        if count == 65_536 {
            assert_eq!(result(&fixture)?, Ok(()));
        } else {
            assert_eq!(
                result(&fixture)?,
                Err(Error::BoundsExceeded {
                    artifact: Artifact::Schema { index: 0 }
                })
            );
        }
    }
    let mut fixture = Fixture::new();
    fixture.schemas = (0..4).map(|resource| {
        let definitions: serde_json::Map<_, _> = (0..20_000).map(|number| (format!("a{number}"), json!({"$anchor":format!("a{number}")}))).collect();
        bytes(&json!({"$id":format!("urn:pigloros:test:resource:{resource}"), "$defs":definitions}))
    }).collect();
    assert_eq!(
        result(&fixture)?,
        Err(Error::BoundsExceeded {
            artifact: Artifact::Schema { index: 3 }
        })
    );
    Ok(())
}

#[test]
fn explicit_schema_id_cannot_collide_with_a_later_implicit_base() -> TestResult {
    use sha2::{Digest as _, Sha256};
    let second = b"true".to_vec();
    let digest = fixture::hex(&Sha256::digest(&second));
    let mut fixture = Fixture::new();
    fixture.schemas = vec![
        bytes(&json!({"$id": format!("urn:pigloros:plugin-schema:sha256:{digest}")})),
        second,
    ];
    assert_eq!(
        result(&fixture)?,
        Err(Error::ReferenceMismatch {
            artifact: Artifact::Schema { index: 1 }
        })
    );
    Ok(())
}

#[test]
fn second_licence_refusal_reports_its_index() -> TestResult {
    let mut fixture = Fixture::new();
    fixture.licences.push(b" \n".to_vec());
    assert_eq!(
        result(&fixture)?,
        Err(Error::Malformed {
            artifact: Artifact::Licence { index: 1 }
        })
    );
    Ok(())
}

#[test]
fn explicit_current_dialect_and_negative_schema_numbers_are_preserved() -> TestResult {
    let mut fixture = Fixture::new();
    fixture.schemas = vec![bytes(
        &json!({"$schema":"https://json-schema.org/draft/2020-12/schema", "minimum":-1}),
    )];
    assert_eq!(result(&fixture)?, Ok(()));
    Ok(())
}

#[test]
fn null_values_count_toward_the_json_node_limit() -> TestResult {
    for (count, expected) in [
        (262_141, Ok(())),
        (
            262_142,
            Err(Error::BoundsExceeded {
                artifact: Artifact::Schema { index: 0 },
            }),
        ),
    ] {
        let mut fixture = Fixture::new();
        let mut examples = vec![json!(0); count];
        examples.push(Value::Null);
        fixture.schemas = vec![bytes(&json!({"examples": examples}))];
        assert_eq!(result(&fixture)?, expected);
    }
    Ok(())
}

#[test]
fn spdx_description_relationship_requires_the_document_endpoint() -> TestResult {
    for inverse in [false, true] {
        let mut fixture = Fixture::new();
        fixture.sbom(|value| {
            let mut parent = value["packages"][0].clone();
            parent["SPDXID"] = json!("SPDXRef-parent");
            assert!(parent.as_object_mut().and_then(|object| object.remove("checksums")).is_some());
            value["packages"] = json!([value["packages"][0].clone(), parent]);
            assert!(value.as_object_mut().and_then(|object| object.remove("documentDescribes")).is_some());
            value["relationships"] = if inverse {
                json!([{"spdxElementId":"SPDXRef-component", "relationshipType":"DESCRIBED_BY", "relatedSpdxElement":"SPDXRef-parent"}])
            } else {
                json!([{"spdxElementId":"SPDXRef-parent", "relationshipType":"DESCRIBES", "relatedSpdxElement":"SPDXRef-component"}])
            };
        })?;
        assert_eq!(
            result(&fixture)?,
            Err(Error::ReferenceMismatch {
                artifact: Artifact::Sbom
            })
        );
    }
    Ok(())
}
