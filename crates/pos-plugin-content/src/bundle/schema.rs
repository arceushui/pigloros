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

#[derive(Default)]
struct Index {
    identifiers: BTreeSet<String>,
    references: Vec<Reference>,
    // Registry inputs borrow these same immutable Values. Membership only:
    // addresses never affect traversal, ordering, serialization or a digest.
    // This rejects a JSON Pointer into instance data such as `examples` even
    // when its object happens to look like a schema elsewhere in the document.
    locations: BTreeSet<*const Value>,
}

impl Index {
    fn identifier(&mut self, identifier: String) -> Result<(), Refusal> {
        if self.identifiers.len() == MAX_IDENTIFIERS {
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
                if self.references.len() == MAX_REFERENCES {
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

pub(super) fn validate(documents: &[Document]) -> Result<(), (u16, Refusal)> {
    let mut index = Index::default();
    let mut registry = Registry::new().draft(Draft::Draft202012).retriever(Offline);
    for document in documents {
        index
            .visit(&document.value, document.base.clone(), document.index, true)
            .map_err(|error| (document.index, error))?;
        registry = registry
            .add(document.base.as_str(), &document.value)
            .map_err(|_| (document.index, Refusal::ReferenceMismatch))?;
    }
    // Resolve target resource URIs in artifact order before the registry's
    // aggregate preparation, so a missing external resource names its owner.
    for reference in &index.references {
        let mut target = uri::resolve_against(&reference.base.borrow(), &reference.target)
            .map_err(|_| (reference.index, Refusal::ReferenceMismatch))?;
        target.set_fragment(None);
        if !index.identifiers.contains(target.as_str()) {
            return Err((reference.index, Refusal::ReferenceMismatch));
        }
    }
    // Only borrowed declared resources enter this registry. Its retriever
    // refuses even if another workspace consumer enables retrieval features.
    let registry = registry
        .prepare()
        .map_err(|_| (0, Refusal::ReferenceMismatch))?;
    for reference in index.references {
        let resolved = registry
            .resolver(reference.base)
            .lookup(&reference.target)
            .map_err(|_| (reference.index, Refusal::ReferenceMismatch))?;
        if !index
            .locations
            .contains(&std::ptr::from_ref(resolved.contents()))
        {
            return Err((reference.index, Refusal::ReferenceMismatch));
        }
    }
    Ok(())
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
