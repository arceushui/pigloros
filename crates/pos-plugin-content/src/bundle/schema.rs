//! Schema-document validation and bounded, retrieval-free reference indexing.

use std::collections::BTreeSet;

use jsonschema::{uri, Draft, Registry, Retrieve, Uri};
use serde_json::Value;

use crate::bundle::Refusal;

const DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";
const MAX_IDENTIFIERS: usize = 65_536;
const MAX_REFERENCES: usize = 65_536;

pub(super) struct Offline;

impl Retrieve for Offline {
    fn retrieve(&self, _: &Uri<String>) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        Err(std::io::Error::other("external schema retrieval is forbidden").into())
    }
}

pub(super) struct Document {
    pub(super) index: u16,
    pub(super) base: Uri<String>,
    pub(super) value: Value,
}

impl Document {
    pub(super) fn read(index: u16, digest: &str, bytes: &[u8]) -> Result<Self, Refusal> {
        let value = super::json::read(bytes)?;
        if value
            .get("$schema")
            .is_some_and(|dialect| dialect.as_str() != Some(DIALECT))
        {
            return Err(Refusal::UnsupportedFormat);
        }
        if !jsonschema::draft202012::meta::is_valid(&value) {
            return Err(Refusal::Malformed);
        }
        let base = uri::from_str(&format!("urn:pigloros:plugin-schema:sha256:{digest}"))
            .map_err(|_| Refusal::Malformed)?;
        Ok(Self { index, base, value })
    }
}

struct Reference {
    index: u16,
    base: Uri<String>,
    target: String,
}

struct Index {
    identifiers: BTreeSet<String>,
    references: Vec<Reference>,
    identifier_limit: usize,
    reference_limit: usize,
    // Registry inputs borrow these same immutable Values. Membership only:
    // addresses never affect traversal, ordering, serialization or a digest.
    // This rejects a JSON Pointer into instance data such as `examples` even
    // when its object happens to look like a schema elsewhere in the document.
    locations: BTreeSet<*const Value>,
}

impl Index {
    const fn new(identifier_limit: usize, reference_limit: usize) -> Self {
        Self {
            identifiers: BTreeSet::new(),
            references: Vec::new(),
            locations: BTreeSet::new(),
            identifier_limit,
            reference_limit,
        }
    }

    fn identifier(&mut self, identifier: String) -> Result<(), Refusal> {
        if self.identifiers.len() == self.identifier_limit {
            return Err(Refusal::BoundsExceeded);
        }
        if !self.identifiers.insert(identifier) {
            return Err(Refusal::ReferenceMismatch);
        }
        Ok(())
    }

    fn visit(
        &mut self,
        value: &Value,
        mut base: Uri<String>,
        index: u16,
        root: bool,
    ) -> Result<(), Refusal> {
        self.locations.insert(std::ptr::from_ref(value));
        if let Some(dialect) = value.get("$schema") {
            if dialect.as_str() != Some(DIALECT) {
                return Err(Refusal::UnsupportedFormat);
            }
        }
        if let Some(id) = value.get("$id").and_then(Value::as_str) {
            base =
                uri::resolve_against(&base.borrow(), id).map_err(|_| Refusal::ReferenceMismatch)?;
            // The pinned 2020-12 meta-schema rejects nonempty `$id` fragments
            // in every schema-valued location before this traversal.
            base.set_fragment(None);
            self.identifier(base.as_str().to_owned())?;
        } else if root {
            self.identifier(base.as_str().to_owned())?;
        }
        if let Some(vocabulary) = value.get("$vocabulary").and_then(Value::as_object) {
            for (name, required) in vocabulary {
                let known = name
                    .strip_prefix("https://json-schema.org/draft/2020-12/vocab/")
                    .is_some_and(|kind| {
                        matches!(
                            kind,
                            "core"
                                | "applicator"
                                | "validation"
                                | "unevaluated"
                                | "meta-data"
                                | "format-annotation"
                                | "format-assertion"
                                | "content"
                        )
                    });
                if required.as_bool() == Some(true) && !known {
                    return Err(Refusal::UnsupportedFormat);
                }
            }
        }
        for keyword in ["$anchor", "$dynamicAnchor"] {
            if let Some(anchor) = value.get(keyword).and_then(Value::as_str) {
                self.identifier(format!("{}#{anchor}", base.as_str()))?;
            }
        }
        for keyword in ["$ref", "$dynamicRef"] {
            if let Some(target) = value.get(keyword).and_then(Value::as_str) {
                if self.references.len() == self.reference_limit {
                    return Err(Refusal::BoundsExceeded);
                }
                self.references.push(Reference {
                    index,
                    base: base.clone(),
                    target: target.to_owned(),
                });
            }
        }
        // The pinned dialect supplies schema-valued locations. Examples,
        // defaults and arbitrary annotation payloads are never walked as schemas.
        for child in Draft::Draft202012.subresources_of(value) {
            self.visit(child, base.clone(), index, false)?;
        }
        Ok(())
    }
}

pub(super) fn validate(inputs: &[(u16, &str, &[u8])]) -> Result<(), (u16, Refusal)> {
    let mut index = Index::new(MAX_IDENTIFIERS, MAX_REFERENCES);
    let mut first_error: Option<(u16, Refusal)> = None;
    let mut identifiers_used = 0;
    let mut references_used = 0;
    // The fixed capacity keeps document addresses stable for location checks.
    let mut documents = Vec::with_capacity(inputs.len());
    for &(ordinal, digest, bytes) in inputs {
        let document = match Document::read(ordinal, digest, bytes) {
            Ok(document) => document,
            Err(error) => {
                if matches!(error, Refusal::BoundsExceeded) {
                    return Err(first_error.unwrap_or((ordinal, error)));
                }
                first_error.get_or_insert((ordinal, error));
                continue;
            }
        };
        documents.push(document);
        let document = &documents[documents.len() - 1];
        let mut local = Index::new(
            MAX_IDENTIFIERS - identifiers_used,
            MAX_REFERENCES - references_used,
        );
        let result = local.visit(&document.value, document.base.clone(), document.index, true);
        identifiers_used += local.identifiers.len();
        references_used += local.references.len();
        if let Err(error) = result {
            if matches!(error, Refusal::BoundsExceeded) {
                return Err(first_error.unwrap_or((document.index, error)));
            }
            first_error.get_or_insert((document.index, error));
            drop(documents.pop());
            continue;
        }
        if local
            .identifiers
            .iter()
            .any(|id| index.identifiers.contains(id))
        {
            first_error.get_or_insert((document.index, Refusal::ReferenceMismatch));
            drop(documents.pop());
            continue;
        }
        index.identifiers.extend(local.identifiers);
        index.references.extend(local.references);
        index.locations.extend(local.locations);
    }
    let mut registry = Registry::new().draft(Draft::Draft202012).retriever(Offline);
    for document in &documents {
        registry = registry
            .add(document.base.as_str(), &document.value)
            .map_err(|_| (document.index, Refusal::ReferenceMismatch))?;
    }
    // Resolve target resource URIs in artifact order before the registry's
    // aggregate preparation, so a missing external resource names its owner.
    for reference in &index.references {
        let Ok(mut target) = uri::resolve_against(&reference.base.borrow(), &reference.target)
        else {
            if first_error.is_none_or(|(first, _)| reference.index < first) {
                first_error = Some((reference.index, Refusal::ReferenceMismatch));
            }
            continue;
        };
        target.set_fragment(None);
        if !index.identifiers.contains(target.as_str())
            && first_error.is_none_or(|(first, _)| reference.index < first)
        {
            first_error = Some((reference.index, Refusal::ReferenceMismatch));
        }
    }
    // Only borrowed declared resources enter this registry. Its retriever
    // refuses even if another workspace consumer enables retrieval features.
    let registry = registry
        .prepare()
        .map_err(|_| (0, Refusal::ReferenceMismatch))?;
    for reference in index.references {
        let resolved = registry.resolver(reference.base).lookup(&reference.target);
        if resolved.as_ref().map_or(true, |resolved| {
            !index
                .locations
                .contains(&std::ptr::from_ref(resolved.contents()))
        }) && first_error.is_none_or(|(first, _)| reference.index < first)
        {
            first_error = Some((reference.index, Refusal::ReferenceMismatch));
        }
    }
    first_error.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use jsonschema::{uri, Retrieve};

    use super::Offline;

    #[test]
    fn offline_retriever_refuses_even_when_called_directly(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let target = uri::from_str("https://example.invalid/never-fetch")?;
        assert!(Offline.retrieve(&target).is_err());
        Ok(())
    }
}
