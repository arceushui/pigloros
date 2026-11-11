//! Pinned SPDX document validation, local references and Component binding.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use serde_json::Value;

use super::provenance::nonempty;
use crate::bundle::Refusal;

fn validator() -> Result<&'static jsonschema::Validator, Refusal> {
    static VALIDATOR: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();
    VALIDATOR
        .get_or_init(|| {
            // Immutable, attributed SPDX 2.3.1 source, independently digest-pinned
            // by the public fixtures. No Plugin-provided schema is compiled here.
            serde_json::from_slice::<Value>(include_bytes!(
                "../../resources/spdx-schema-2.3.1.json"
            ))
            .ok()
            .and_then(|schema| {
                jsonschema::draft201909::options()
                    .with_retriever(super::schema::Offline)
                    .should_validate_formats(true)
                    .build(&schema)
                    .ok()
            })
        })
        .as_ref()
        .ok_or(Refusal::Malformed)
}

pub(super) fn validate(value: &Value, component: &str) -> Result<(), Refusal> {
    if nonempty(value.get("spdxVersion"))? != "SPDX-2.3" {
        return Err(Refusal::UnsupportedFormat);
    }
    if !validator().is_ok_and(|validator| validator.is_valid(value))
        || value.get("SPDXID").and_then(Value::as_str) != Some("SPDXRef-DOCUMENT")
        || value.get("dataLicense").and_then(Value::as_str) != Some("CC0-1.0")
    {
        return Err(Refusal::Malformed);
    }
    for field in ["name", "documentNamespace"] {
        nonempty(value.get(field))?;
    }
    let creation = &value["creationInfo"];
    // The pinned schema requires the timestamp and a nonempty creator array.
    // Its string items may still be blank, which this profile rejects.
    for creator in items(creation, "creators") {
        nonempty(Some(creator))?;
    }
    let initial = BTreeMap::from([("SPDXRef-DOCUMENT", (value, false))]);
    ["packages", "files", "snippets"]
        .into_iter()
        .flat_map(|field| items(value, field).map(move |element| (field, element)))
        .try_fold(initial, |mut elements, (field, element)| {
            nonempty(element.get("SPDXID")).and_then(|id| {
                if elements
                    .insert(id, (element, field != "snippets"))
                    .is_some()
                {
                    Err(Refusal::ReferenceMismatch)
                } else {
                    Ok(elements)
                }
            })
        })
        .and_then(|elements| {
            let external: BTreeSet<_> = items(value, "externalDocumentRefs")
                .map(|document| {
                    let id = nonempty(document.get("externalDocumentId"))?;
                    if !identifier(id, "DocumentRef-", true) {
                        return Err(Refusal::Malformed);
                    }
                    Ok(id)
                })
                .collect::<Result<_, _>>()?;
            if external.len() != items(value, "externalDocumentRefs").count() {
                return Err(Refusal::ReferenceMismatch);
            }
            let described = described_targets(value, &elements, &external)?;
            licences(value, &external)?;
            bind_component(&described, &elements, component)
        })
}

fn described_targets<'a>(
    value: &'a Value,
    elements: &BTreeMap<&'a str, (&'a Value, bool)>,
    external: &BTreeSet<&'a str>,
) -> Result<BTreeSet<&'a str>, Refusal> {
    let mut described = BTreeSet::new();
    for target in items(value, "documentDescribes") {
        let target = nonempty(Some(target))?;
        reference(target, elements, external)?;
        described.insert(target);
    }
    for relationship in items(value, "relationships") {
        let from = nonempty(relationship.get("spdxElementId"))?;
        let to = nonempty(relationship.get("relatedSpdxElement"))?;
        reference(from, elements, external)?;
        reference(to, elements, external)?;
        match relationship.get("relationshipType").and_then(Value::as_str) {
            Some("DESCRIBES") if from == "SPDXRef-DOCUMENT" => {
                described.insert(to);
            }
            Some("DESCRIBED_BY") if to == "SPDXRef-DOCUMENT" => {
                described.insert(from);
            }
            _ => {}
        }
    }
    for (element, _) in elements.values() {
        for field in ["hasFiles", "fileDependencies"] {
            for target in items(element, field) {
                reference(nonempty(Some(target))?, elements, external)?;
            }
        }
        if let Some(target) = element.get("snippetFromFile") {
            reference(nonempty(Some(target))?, elements, external)?;
        }
    }
    Ok(described)
}

fn bind_component(
    described: &BTreeSet<&str>,
    elements: &BTreeMap<&str, (&Value, bool)>,
    component: &str,
) -> Result<(), Refusal> {
    if described.iter().any(|id| {
        elements.get(id).is_some_and(|(element, eligible)| {
            *eligible
                && items(element, "checksums").any(|checksum| {
                    checksum.get("algorithm").and_then(Value::as_str) == Some("SHA256")
                        && checksum
                            .get("checksumValue")
                            .and_then(Value::as_str)
                            .is_some_and(|digest| {
                                digest.len() == 64 && digest.eq_ignore_ascii_case(component)
                            })
                })
        })
    }) {
        Ok(())
    } else {
        Err(Refusal::ReferenceMismatch)
    }
}

fn items<'a>(value: &'a Value, field: &str) -> impl Iterator<Item = &'a Value> + use<'a> {
    value
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn reference(
    target: &str,
    local: &BTreeMap<&str, (&Value, bool)>,
    external: &BTreeSet<&str>,
) -> Result<(), Refusal> {
    let valid = local.contains_key(target)
        || matches!(target, "NONE" | "NOASSERTION")
        || target.split_once(':').is_some_and(|(document, element)| {
            external.contains(document) && identifier(element, "SPDXRef-", false)
        });
    if valid {
        Ok(())
    } else {
        Err(Refusal::ReferenceMismatch)
    }
}

fn identifier(value: &str, prefix: &str, plus: bool) -> bool {
    value.strip_prefix(prefix).is_some_and(|id| {
        !id.is_empty()
            && id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'-')
                    || (plus && byte == b'+')
            })
    })
}

fn licences(value: &Value, external: &BTreeSet<&str>) -> Result<(), Refusal> {
    let mut extracted = BTreeSet::new();
    for licence in items(value, "hasExtractedLicensingInfos") {
        let id = nonempty(licence.get("licenseId"))?;
        nonempty(licence.get("extractedText"))?;
        if !extracted.insert(id) {
            return Err(Refusal::ReferenceMismatch);
        }
    }
    for field in ["packages", "files", "snippets"] {
        for element in items(value, field) {
            for field in [
                "licenseDeclared",
                "licenseConcluded",
                "licenseInfoInFiles",
                "licenseInfoFromFiles",
                "licenseInfoInSnippets",
            ] {
                if let Some(metadata) = element.get(field) {
                    let texts: Vec<_> = metadata
                        .as_array()
                        .map_or_else(|| vec![metadata], |array| array.iter().collect());
                    for text in texts {
                        for token in nonempty(Some(text))?
                            .split(|c: char| !(c.is_ascii_alphanumeric() || "-.:+".contains(c)))
                        {
                            if token.starts_with("LicenseRef-") && !extracted.contains(token) {
                                return Err(Refusal::ReferenceMismatch);
                            }
                            if let Some((document, licence)) = token.split_once(':') {
                                if licence.starts_with("LicenseRef-")
                                    && !external.contains(document)
                                {
                                    return Err(Refusal::ReferenceMismatch);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
