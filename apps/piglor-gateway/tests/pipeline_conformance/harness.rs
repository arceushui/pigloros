//! Fail-closed runner for the versioned pipeline conformance profile.
//!
//! The profile manifest is data: it names every case, whether it is
//! mandatory and applicable, the stores it runs on, the scheduled
//! observation profile its evidence must carry, and the exact observations
//! each run must capture. The harness never derives an expected value from
//! the implementation under test.
//!
//! Every deviation is a failure: an unknown magic, version or field, a
//! mandatory case without a runner, a runner without a case, a runner that
//! panics, a missing or unexpected capture, a diverging value, and evidence
//! whose observation profile differs from the one the case declares.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Magic of a pipeline conformance profile manifest.
pub(super) const PROFILE_MAGIC: &str = "PPC1";
/// The only supported profile manifest version.
pub(super) const PROFILE_VERSION: u64 = 1;
/// Capture key every profile-tagged case records once per store.
pub(super) const PROFILE_KEY: &str = "observation-profile";

const STORES: [&str; 3] = ["memory", "sqlite", "none"];
const PROFILES: [&str; 2] = ["non-participant", "participant-bound"];
const TOP_LEVEL_FIELDS: [&str; 6] = [
    "cases",
    "exclusions",
    "magic",
    "sources",
    "suite",
    "version",
];
const CASE_FIELDS: [&str; 8] = [
    "applicability",
    "expected",
    "id",
    "mandatory",
    "observation_profile",
    "sources",
    "stores",
    "title",
];
const EXCLUSION_FIELDS: [&str; 3] = ["id", "owner", "reason"];

/// A closed conformance failure. None of them is ever a pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ConformanceError {
    DigestMismatch {
        expected: String,
        actual: String,
    },
    InvalidManifest(String),
    UnsupportedVersion(String),
    UnknownField {
        at: String,
        field: String,
    },
    DuplicateCase(String),
    UnknownRunner(String),
    SkippedMandatoryCase(String),
    InapplicableCaseExecuted(String),
    RunnerPanicked {
        case: String,
        message: String,
    },
    MissingCapture {
        case: String,
        key: String,
    },
    UnexpectedCapture {
        case: String,
        key: String,
        value: String,
    },
    Divergence {
        case: String,
        key: String,
        expected: String,
        actual: String,
    },
    ProfileTagMismatch {
        case: String,
        key: String,
        declared: String,
        captured: String,
    },
}

/// Whether a case runs under this profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Applicability {
    Applicable,
    /// Recorded rather than silently omitted (ADR-021 Revision 3).
    ProfileInapplicable {
        reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Case {
    pub(super) id: String,
    pub(super) mandatory: bool,
    pub(super) applicability: Applicability,
    pub(super) stores: Vec<String>,
    pub(super) observation_profile: Option<String>,
    pub(super) expected: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Manifest {
    pub(super) suite: String,
    pub(super) cases: Vec<Case>,
    pub(super) exclusions: Vec<String>,
}

/// Observations one runner captured, keyed `<store>/<key>`.
#[derive(Debug, Default)]
pub(super) struct Capture {
    values: BTreeMap<String, String>,
}

impl Capture {
    /// Record one observation. Recording a key twice with another value
    /// keeps both, so the comparison fails rather than picking one.
    pub(super) fn record(&mut self, store: &str, key: &str, value: impl std::fmt::Display) {
        let value = value.to_string();
        self.values
            .entry(format!("{store}/{key}"))
            .and_modify(|existing| {
                if *existing != value {
                    *existing = format!("{existing} | {value}");
                }
            })
            .or_insert(value);
    }
}

/// One case runner. A runner covers every store its case names.
pub(super) type Runner = fn() -> Capture;

/// Ordered outcome of one profile run.
#[derive(Debug, Default)]
pub(super) struct SuiteReport {
    pub(super) passed: Vec<String>,
    pub(super) not_applicable: Vec<String>,
    pub(super) skipped_optional: Vec<String>,
    pub(super) failures: Vec<ConformanceError>,
}

/// Lower-case hexadecimal SHA-256 of `bytes`.
pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Require the exact immutable fixture bytes pinned by the suite.
pub(super) fn verify_pinned(bytes: &[u8], pinned_sha256: &str) -> Result<(), ConformanceError> {
    let actual = sha256_hex(bytes);
    if actual == pinned_sha256 {
        Ok(())
    } else {
        Err(ConformanceError::DigestMismatch {
            expected: pinned_sha256.to_owned(),
            actual,
        })
    }
}

fn invalid(message: impl Into<String>) -> ConformanceError {
    ConformanceError::InvalidManifest(message.into())
}

/// Reject any field outside the closed set for one object.
pub(super) fn closed_object<'a>(
    value: &'a Value,
    at: &str,
    fields: &[&str],
) -> Result<&'a Map<String, Value>, ConformanceError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{at} is not an object")))?;
    if let Some(field) = object.keys().find(|key| !fields.contains(&key.as_str())) {
        return Err(ConformanceError::UnknownField {
            at: at.to_owned(),
            field: field.clone(),
        });
    }
    if let Some(missing) = fields.iter().find(|field| !object.contains_key(**field)) {
        return Err(invalid(format!("{at} is missing {missing}")));
    }
    Ok(object)
}

fn string_field(
    object: &Map<String, Value>,
    at: &str,
    field: &str,
) -> Result<String, ConformanceError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid(format!("{at}.{field} is not a non-empty string")))
}

fn string_list(
    object: &Map<String, Value>,
    at: &str,
    field: &str,
) -> Result<Vec<String>, ConformanceError> {
    object
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(format!("{at}.{field} is not an array")))?
        .iter()
        .map(|item| {
            item.as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| invalid(format!("{at}.{field} holds a non-string")))
        })
        .collect()
}

/// Read the magic and version first, so an unknown version fails closed
/// before any other field is interpreted.
pub(super) fn require_version(
    root: &Map<String, Value>,
    magic: &str,
    version: u64,
) -> Result<(), ConformanceError> {
    let found_magic = root
        .get("magic")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let found_version = root.get("version").and_then(Value::as_u64);
    if found_magic == magic && found_version == Some(version) {
        Ok(())
    } else {
        Err(ConformanceError::UnsupportedVersion(format!(
            "{found_magic}/{}",
            root.get("version")
                .map_or_else(String::new, Value::to_string)
        )))
    }
}

fn parse_applicability(value: &Value, at: &str) -> Result<Applicability, ConformanceError> {
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{at}.applicability has no status")))?;
    match status {
        "applicable" => closed_object(value, &format!("{at}.applicability"), &["status"])
            .map(|_| Applicability::Applicable),
        "profile-inapplicable" => {
            closed_object(value, &format!("{at}.applicability"), &["reason", "status"]).and_then(
                |object| {
                    string_field(object, &format!("{at}.applicability"), "reason")
                        .map(|reason| Applicability::ProfileInapplicable { reason })
                },
            )
        }
        other => Err(invalid(format!(
            "{at}.applicability status {other} is unknown"
        ))),
    }
}

fn parse_expected(value: &Value, at: &str) -> Result<BTreeMap<String, String>, ConformanceError> {
    value
        .as_object()
        .ok_or_else(|| invalid(format!("{at}.expected is not an object")))?
        .iter()
        .map(|(key, value)| {
            if key == PROFILE_KEY {
                return Err(invalid(format!(
                    "{at}.expected must not name {PROFILE_KEY}"
                )));
            }
            value
                .as_str()
                .map(|value| (key.clone(), value.to_owned()))
                .ok_or_else(|| invalid(format!("{at}.expected.{key} is not a string")))
        })
        .collect()
}

fn parse_case(value: &Value, index: usize) -> Result<Case, ConformanceError> {
    let at = format!("cases[{index}]");
    let object = closed_object(value, &at, &CASE_FIELDS)?;
    let id = string_field(object, &at, "id")?;
    string_field(object, &at, "title")?;
    string_list(object, &at, "sources")?;
    let mandatory = object
        .get("mandatory")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid(format!("{at}.mandatory is not a boolean")))?;
    let applicability = parse_applicability(&object["applicability"], &at)?;
    let stores = string_list(object, &at, "stores")?;
    if let Some(store) = stores
        .iter()
        .find(|store| !STORES.contains(&store.as_str()))
    {
        return Err(invalid(format!("{at} names unknown store {store}")));
    }
    if stores.iter().collect::<BTreeSet<_>>().len() != stores.len() {
        return Err(invalid(format!("{at} repeats a store")));
    }
    let observation_profile = match &object["observation_profile"] {
        Value::Null => None,
        Value::String(profile) if PROFILES.contains(&profile.as_str()) => Some(profile.clone()),
        other => {
            return Err(invalid(format!(
                "{at}.observation_profile {other} is unknown"
            )))
        }
    };
    let expected = parse_expected(&object["expected"], &at)?;
    let applicable = applicability == Applicability::Applicable;
    if applicable == stores.is_empty() {
        return Err(invalid(format!(
            "{at} must name stores exactly when it is applicable"
        )));
    }
    if !applicable && (!expected.is_empty() || observation_profile.is_some()) {
        return Err(invalid(format!(
            "{at} is inapplicable but declares results"
        )));
    }
    Ok(Case {
        id,
        mandatory,
        applicability,
        stores,
        observation_profile,
        expected,
    })
}

/// Parse a profile manifest, failing closed on every structural deviation.
pub(super) fn load_manifest(bytes: &[u8]) -> Result<Manifest, ConformanceError> {
    let root: Value =
        serde_json::from_slice(bytes).map_err(|error| invalid(format!("not JSON: {error}")))?;
    let object = root
        .as_object()
        .ok_or_else(|| invalid("the manifest is not an object"))?;
    require_version(object, PROFILE_MAGIC, PROFILE_VERSION)?;
    let object = closed_object(&root, "manifest", &TOP_LEVEL_FIELDS)?;
    let suite = string_field(object, "manifest", "suite")?;
    string_list(object, "manifest", "sources")?;
    let cases = object["cases"]
        .as_array()
        .ok_or_else(|| invalid("manifest.cases is not an array"))?
        .iter()
        .enumerate()
        .map(|(index, case)| parse_case(case, index))
        .collect::<Result<Vec<_>, _>>()?;
    let exclusions = object["exclusions"]
        .as_array()
        .ok_or_else(|| invalid("manifest.exclusions is not an array"))?
        .iter()
        .enumerate()
        .map(|(index, exclusion)| {
            let at = format!("exclusions[{index}]");
            closed_object(exclusion, &at, &EXCLUSION_FIELDS).and_then(|fields| {
                string_field(fields, &at, "reason")
                    .and_then(|_| string_field(fields, &at, "owner"))
                    .and_then(|_| string_field(fields, &at, "id"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut seen = BTreeSet::new();
    if let Some(duplicate) = cases
        .iter()
        .map(|case| case.id.as_str())
        .chain(exclusions.iter().map(String::as_str))
        .find(|id| !seen.insert(*id))
    {
        return Err(ConformanceError::DuplicateCase(duplicate.to_owned()));
    }
    Ok(Manifest {
        suite,
        cases,
        exclusions,
    })
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&str>()
                .map(|message| (*message).to_owned())
        })
        .unwrap_or_else(|| "non-string panic payload".to_owned())
}

/// Compare one case's capture with its declared expectations.
fn compare(case: &Case, capture: &Capture, failures: &mut Vec<ConformanceError>) {
    let mut expected = BTreeMap::new();
    for store in &case.stores {
        for (key, value) in &case.expected {
            expected.insert(format!("{store}/{key}"), value.clone());
        }
    }
    let profile_keys: BTreeMap<String, &String> = case
        .observation_profile
        .iter()
        .flat_map(|profile| {
            case.stores
                .iter()
                .map(move |store| (format!("{store}/{PROFILE_KEY}"), profile))
        })
        .collect();
    for (key, declared) in &profile_keys {
        match capture.values.get(key) {
            Some(captured) if captured != *declared => {
                failures.push(ConformanceError::ProfileTagMismatch {
                    case: case.id.clone(),
                    key: key.clone(),
                    declared: (*declared).clone(),
                    captured: captured.clone(),
                });
            }
            Some(_) => {}
            None => failures.push(ConformanceError::MissingCapture {
                case: case.id.clone(),
                key: key.clone(),
            }),
        }
    }
    for (key, value) in &expected {
        match capture.values.get(key) {
            Some(actual) if actual != value => failures.push(ConformanceError::Divergence {
                case: case.id.clone(),
                key: key.clone(),
                expected: value.clone(),
                actual: actual.clone(),
            }),
            Some(_) => {}
            None => failures.push(ConformanceError::MissingCapture {
                case: case.id.clone(),
                key: key.clone(),
            }),
        }
    }
    for (key, value) in &capture.values {
        if !expected.contains_key(key) && !profile_keys.contains_key(key) {
            failures.push(ConformanceError::UnexpectedCapture {
                case: case.id.clone(),
                key: key.clone(),
                value: value.clone(),
            });
        }
    }
}

/// Run every case of `manifest` with the matching runner.
#[must_use]
pub(super) fn run_suite(manifest: &Manifest, runners: &[(&str, Runner)]) -> SuiteReport {
    let mut report = SuiteReport::default();
    let mut table = BTreeMap::new();
    for (id, runner) in runners {
        if table.insert(*id, *runner).is_some() {
            report
                .failures
                .push(ConformanceError::DuplicateCase((*id).to_owned()));
        }
    }
    let declared: BTreeSet<&str> = manifest.cases.iter().map(|case| case.id.as_str()).collect();
    for id in table.keys().filter(|id| !declared.contains(**id)) {
        report
            .failures
            .push(ConformanceError::UnknownRunner((*id).to_owned()));
    }
    for case in &manifest.cases {
        let runner = table.get(case.id.as_str());
        match (&case.applicability, runner) {
            (Applicability::ProfileInapplicable { .. }, None) => {
                report.not_applicable.push(case.id.clone());
            }
            (Applicability::ProfileInapplicable { .. }, Some(_)) => report
                .failures
                .push(ConformanceError::InapplicableCaseExecuted(case.id.clone())),
            (Applicability::Applicable, None) if case.mandatory => report
                .failures
                .push(ConformanceError::SkippedMandatoryCase(case.id.clone())),
            (Applicability::Applicable, None) => report.skipped_optional.push(case.id.clone()),
            (Applicability::Applicable, Some(runner)) => match std::panic::catch_unwind(*runner) {
                Ok(capture) => {
                    let failures = report.failures.len();
                    compare(case, &capture, &mut report.failures);
                    if report.failures.len() == failures {
                        report.passed.push(case.id.clone());
                    }
                }
                Err(payload) => report.failures.push(ConformanceError::RunnerPanicked {
                    case: case.id.clone(),
                    message: panic_message(payload.as_ref()),
                }),
            },
        }
    }
    report
}
