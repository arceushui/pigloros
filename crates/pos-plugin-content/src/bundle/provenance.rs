//! Basic in-toto/SLSA structure and exact Component subject binding.

use serde_json::Value;

use crate::bundle::Refusal;

pub(super) fn validate(value: &Value, component: &str) -> Result<(), Refusal> {
    let object = value.as_object().ok_or(Refusal::Malformed)?;
    if nonempty(object.get("_type"))? != "https://in-toto.io/Statement/v1"
        || nonempty(object.get("predicateType"))? != "https://slsa.dev/provenance/v1"
    {
        return Err(Refusal::UnsupportedFormat);
    }
    let subjects = value
        .get("subject")
        .and_then(Value::as_array)
        .ok_or(Refusal::Malformed)?;
    let mut bound = false;
    for subject in subjects {
        let digests = subject
            .get("digest")
            .and_then(Value::as_object)
            .ok_or(Refusal::Malformed)?;
        if digests.is_empty()
            || digests
                .values()
                .any(|digest| digest.as_str().is_none_or(str::is_empty))
        {
            return Err(Refusal::Malformed);
        }
        if subject.get("name").is_some_and(|name| !name.is_string()) {
            return Err(Refusal::Malformed);
        }
        bound |= digests
            .get("sha256")
            .and_then(Value::as_str)
            .is_some_and(|digest| digest.len() == 64 && digest.eq_ignore_ascii_case(component));
    }
    let predicate = value
        .get("predicate")
        .and_then(Value::as_object)
        .ok_or(Refusal::Malformed)?;
    let definition = predicate
        .get("buildDefinition")
        .and_then(Value::as_object)
        .ok_or(Refusal::Malformed)?;
    let run = predicate
        .get("runDetails")
        .and_then(Value::as_object)
        .ok_or(Refusal::Malformed)?;
    nonempty(definition.get("buildType"))?;
    nonempty(run.get("builder").and_then(|builder| builder.get("id")))?;
    for keyword in ["externalParameters", "internalParameters"] {
        if definition
            .get(keyword)
            .is_some_and(|parameters| !parameters.is_null() && !parameters.is_object())
        {
            return Err(Refusal::Malformed);
        }
    }
    if definition
        .get("resolvedDependencies")
        .is_some_and(|dependencies| !dependencies.is_null() && !dependencies.is_array())
    {
        return Err(Refusal::Malformed);
    }
    if bound {
        Ok(())
    } else {
        Err(Refusal::ReferenceMismatch)
    }
}

pub(super) fn nonempty(value: Option<&Value>) -> Result<&str, Refusal> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .ok_or(Refusal::Malformed)
}
