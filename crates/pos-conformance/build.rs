use serde_json::Value;
use std::collections::BTreeSet;
use std::env;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

const PROFILE_COUNT: usize = 7;
const FIXTURES_PER_PROFILE: usize = 7;

struct CatalogRoot {
    source: PathBuf,
    canonical: PathBuf,
}

struct FixturePaths {
    schema: FixtureAsset,
    input: FixtureAsset,
    expected: FixtureAsset,
    oracle: FixtureAsset,
}

struct FixtureAsset {
    relative: String,
    bytes: Vec<u8>,
}

struct ProfilePaths {
    wire_code: u64,
    profile: String,
    profile_record: Vec<u8>,
    provider: FixtureAsset,
    fixtures: Vec<FixturePaths>,
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn non_symlink_directory(path: &Path, description: &str) -> Result<(), io::Error> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        invalid_data(format!(
            "{description} is unavailable at {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(invalid_data(format!(
            "{description} must not be a symlink: {}",
            path.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(invalid_data(format!(
            "{description} must be a directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn catalog_root(manifest_dir: &Path) -> Result<CatalogRoot, io::Error> {
    let source = manifest_dir.join("../../fixtures/conformance");
    non_symlink_directory(&source, "conformance fixture root")?;
    let canonical = fs::canonicalize(&source).map_err(|error| {
        invalid_data(format!(
            "conformance fixture root cannot be canonicalized at {}: {error}",
            source.display()
        ))
    })?;
    Ok(CatalogRoot { source, canonical })
}

fn relative_components<'a>(
    relative: &'a str,
    description: &str,
) -> Result<Vec<&'a std::ffi::OsStr>, io::Error> {
    if relative.is_empty() {
        return Err(invalid_data(format!("{description} must not be empty")));
    }
    Path::new(relative)
        .components()
        .map(|component| match component {
            Component::Normal(value) => Ok(value),
            _ => Err(invalid_data(format!(
                "{description} must be a relative path without traversal: {relative}"
            ))),
        })
        .collect()
}

fn non_symlink_relative_path(
    root: &CatalogRoot,
    relative: &str,
    description: &str,
    final_is_directory: bool,
) -> Result<PathBuf, io::Error> {
    let components = relative_components(relative, description)?;
    let mut candidate = root.canonical.clone();
    let final_index = components.len() - 1;
    for (index, component) in components.iter().enumerate() {
        candidate.push(component);
        let component_description = format!("{description} path component");
        let metadata = fs::symlink_metadata(&candidate).map_err(|error| {
            invalid_data(format!(
                "{component_description} is unavailable at {}: {error}",
                candidate.display()
            ))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(invalid_data(format!(
                "{component_description} must not be a symlink: {}",
                candidate.display()
            )));
        }
        let is_final_component = index == final_index;
        if is_final_component && final_is_directory {
            if !metadata.is_dir() {
                return Err(invalid_data(format!(
                    "{description} must be a directory: {}",
                    candidate.display()
                )));
            }
        } else if is_final_component {
            if !metadata.is_file() {
                return Err(invalid_data(format!(
                    "{description} must be a regular file: {}",
                    candidate.display()
                )));
            }
        } else if !metadata.is_dir() {
            return Err(invalid_data(format!(
                "{component_description} must be a directory: {}",
                candidate.display()
            )));
        }
    }
    let canonical = fs::canonicalize(&candidate).map_err(|error| {
        invalid_data(format!(
            "{description} cannot be canonicalized at {}: {error}",
            candidate.display()
        ))
    })?;
    if !canonical.starts_with(&root.canonical) {
        return Err(invalid_data(format!(
            "{description} escapes the conformance fixture root: {}",
            candidate.display()
        )));
    }
    Ok(canonical)
}

fn json_field<'a>(value: &'a Value, field: &str) -> Result<&'a Value, io::Error> {
    value
        .get(field)
        .ok_or_else(|| invalid_data(format!("profile catalog is missing {field}")))
}

fn json_text(value: &Value, field: &str) -> Result<String, io::Error> {
    json_field(value, field)?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| invalid_data(format!("profile catalog {field} must be text")))
}

fn json_u64(value: &Value, field: &str) -> Result<u64, io::Error> {
    json_field(value, field)?
        .as_u64()
        .ok_or_else(|| invalid_data(format!("profile catalog {field} must be unsigned")))
}

fn validate_fixture_provider(
    provider: &Value,
    claim_layer: &str,
    subject_adapter: &str,
) -> Result<(), io::Error> {
    let schemas = json_field(provider, "schemas")?.as_object();
    let operations = json_field(provider, "fixture_operations")?.as_object();
    let payloads = json_field(provider, "fixture_payloads")?.as_object();
    let contracts = json_field(provider, "fixture_contracts")?.as_object();
    let contracts_match_families = schemas
        .zip(operations)
        .zip(payloads)
        .zip(contracts)
        .is_some_and(|(((schemas, operations), payloads), contracts)| {
            let schema_families = schemas.keys().collect::<BTreeSet<_>>();
            let operation_families = operations.keys().collect::<BTreeSet<_>>();
            let payload_families = payloads.keys().collect::<BTreeSet<_>>();
            let contract_families = contracts.keys().collect::<BTreeSet<_>>();
            schemas.len() == FIXTURES_PER_PROFILE
                && operations.len() == FIXTURES_PER_PROFILE
                && payloads.len() == FIXTURES_PER_PROFILE
                && contracts.len() == FIXTURES_PER_PROFILE
                && schema_families == operation_families
                && schema_families == payload_families
                && schema_families == contract_families
        });
    let valid = !json_text(provider, "provider_id")?.is_empty()
        && !json_text(provider, "contract_version")?.is_empty()
        && u16::try_from(json_u64(provider, "abi_major")?).is_ok()
        && u16::try_from(json_u64(provider, "abi_minor")?).is_ok()
        && !json_text(provider, "package_path")?.is_empty()
        && json_text(provider, "claim_layer")? == claim_layer
        && json_text(provider, "subject_adapter")? == subject_adapter
        && contracts_match_families;
    if valid {
        Ok(())
    } else {
        Err(invalid_data(format!(
            "provider manifest does not match profile claim layer {claim_layer}"
        )))
    }
}

fn validate_fixture_records(
    fixture: &Value,
    provider: &Value,
    paths: &FixturePaths,
    claim_layer: &str,
    subject_adapter: &str,
) -> Result<(), io::Error> {
    let case_id = json_text(fixture, "case_id")?;
    let family = json_text(fixture, "family")?;
    if json_text(fixture, "claim_layer")? != claim_layer {
        return Err(invalid_data(format!(
            "fixture {case_id} claim layer does not match its profile"
        )));
    }
    let input: Value = serde_json::from_slice(&paths.input.bytes)
        .map_err(|error| invalid_data(format!("fixture {case_id} input is invalid: {error}")))?;
    let evidence: Value = serde_json::from_slice(&paths.expected.bytes).map_err(|error| {
        invalid_data(format!(
            "fixture {case_id} evidence status is invalid: {error}"
        ))
    })?;
    let oracle: Value = serde_json::from_slice(&paths.oracle.bytes)
        .map_err(|error| invalid_data(format!("fixture {case_id} oracle is invalid: {error}")))?;
    let provider_contract = format!(
        "{}@{}",
        json_text(provider, "provider_id")?,
        json_text(provider, "contract_version")?
    );
    let operation = json_field(provider, "fixture_operations")?
        .get(&family)
        .ok_or_else(|| invalid_data(format!("provider omits operation for {family}")))?;
    let actual_operation = input.pointer("/stimulus/operation");
    let operation_matches = match operation {
        Value::Null => actual_operation.is_none(),
        Value::String(expected) => actual_operation.and_then(Value::as_str) == Some(expected),
        _ => false,
    };
    let input_digest = blake3::hash(&paths.input.bytes).to_hex().to_string();
    let identity_matches = json_text(&input, "case_id")? == case_id
        && json_text(&input, "claim_layer")? == claim_layer
        && json_text(&input, "family")? == family
        && json_text(&input, "provider_contract")? == provider_contract
        && json_text(&input, "subject_adapter")? == subject_adapter
        && json_text(&evidence, "case_id")? == case_id
        && json_text(&evidence, "claim_layer")? == claim_layer
        && json_text(&evidence, "family")? == family
        && json_text(&evidence, "input_blake3_digest")? == input_digest
        && json_text(&evidence, "status")? == "pending"
        && evidence.get("execution_result") == Some(&Value::Null)
        && evidence.get("executed_at") == Some(&Value::Null)
        && json_text(&oracle, "case_id")? == case_id
        && json_text(&oracle, "claim_layer")? == claim_layer
        && json_text(&oracle, "family")? == family;
    if operation_matches && identity_matches {
        Ok(())
    } else {
        Err(invalid_data(format!(
            "fixture {case_id} does not match its profile/provider identity"
        )))
    }
}

fn relative_asset(
    root: &CatalogRoot,
    value: &Value,
    field: &str,
) -> Result<FixtureAsset, io::Error> {
    let relative = json_text(value, field)?;
    let description = format!("profile catalog {field}");
    let canonical = non_symlink_relative_path(root, &relative, &description, false)?;
    let bytes = fs::read(&canonical).map_err(|error| {
        invalid_data(format!(
            "{description} cannot be read at {}: {error}",
            canonical.display()
        ))
    })?;
    Ok(FixtureAsset { relative, bytes })
}

fn profile_paths(root: &CatalogRoot, profile: String) -> Result<ProfilePaths, Box<dyn Error>> {
    let canonical_profile = non_symlink_relative_path(root, &profile, "profile manifest", false)?;
    let profile_record = fs::read(&canonical_profile).map_err(|error| {
        invalid_data(format!(
            "profile manifest cannot be read at {}: {error}",
            canonical_profile.display()
        ))
    })?;
    let profile_value: Value = serde_json::from_slice(&profile_record)?;
    let claim_layer = json_text(&profile_value, "claim_layer")?;
    let subject_adapter = json_text(&profile_value, "subject_adapter")?;
    let fixture_root = json_text(&profile_value, "fixture_root")?;
    let provider = relative_asset(root, &profile_value, "fixture_provider_manifest")?;
    let provider_value: Value = serde_json::from_slice(&provider.bytes)?;
    validate_fixture_provider(&provider_value, &claim_layer, &subject_adapter)?;
    let provider_schemas = json_field(&provider_value, "schemas")?
        .as_object()
        .ok_or_else(|| invalid_data("provider manifest schemas must be an object"))?;
    let wire_code = json_field(&profile_value, "wire_code")?
        .as_u64()
        .ok_or_else(|| invalid_data("profile catalog wire_code must be unsigned"))?;
    let fixtures = json_field(&profile_value, "fixtures")?
        .as_array()
        .ok_or_else(|| invalid_data("profile catalog fixtures must be an array"))?
        .iter()
        .map(|fixture| {
            let family = json_text(fixture, "family")?;
            let schema = relative_asset(root, fixture, "schema")?;
            let expected_schema = provider_schemas
                .get(&family)
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    invalid_data(format!("provider manifest is missing schema {family}"))
                })?;
            if schema.relative != expected_schema {
                return Err(invalid_data(format!(
                    "profile fixture schema does not match family {family}"
                )));
            }
            let paths = FixturePaths {
                schema,
                input: relative_asset(root, fixture, "input")?,
                expected: relative_asset(root, fixture, "expected")?,
                oracle: relative_asset(root, fixture, "oracle")?,
            };
            validate_fixture_records(
                fixture,
                &provider_value,
                &paths,
                &claim_layer,
                &subject_adapter,
            )?;
            Ok(paths)
        })
        .collect::<Result<Vec<_>, io::Error>>()?;
    let expected_wire_code = match claim_layer.as_str() {
        "artifact-integrity" => 0,
        "replay-conformance" => 1,
        "knowledge-non-interference" => 2,
        "gateway-client-conformance" => 3,
        "plugin-conformance" => 4,
        "metric-conformance" => 5,
        "empirical-evaluation" => 6,
        _ => u64::MAX,
    };
    let bundle_modes = json_field(&profile_value, "bundle_modes")?;
    let execution_profiles = json_field(&profile_value, "execution_profiles")?;
    if fixtures.len() != FIXTURES_PER_PROFILE
        || fixture_root != claim_layer
        || wire_code != expected_wire_code
        || bundle_modes != &serde_json::json!(["local", "air-gapped"])
        || execution_profiles
            != &serde_json::json!(["deterministic-local-v1", "deterministic-air-gapped-v1"])
    {
        return Err(invalid_data(format!(
            "profile manifest {profile} must declare exactly {FIXTURES_PER_PROFILE} fixtures, found {}",
            fixtures.len()
        ))
        .into());
    }
    Ok(ProfilePaths {
        wire_code,
        profile,
        profile_record,
        provider,
        fixtures,
    })
}

fn discover_profiles(root: &CatalogRoot) -> Result<Vec<ProfilePaths>, Box<dyn Error>> {
    let profiles_directory = non_symlink_relative_path(root, "profiles", "profile root", true)?;
    let mut profile_manifests = Vec::new();
    for entry in fs::read_dir(&profiles_directory)? {
        let entry = entry?;
        let entry_name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid_data("profile directory name must be UTF-8"))?;
        let entry_path = profiles_directory.join(&entry_name);
        non_symlink_directory(&entry_path, "profile directory")?;
        profile_manifests.push(format!("profiles/{entry_name}/profile.json"));
    }
    if profile_manifests.len() != PROFILE_COUNT {
        return Err(invalid_data(format!(
            "profile root must contain exactly {PROFILE_COUNT} profile directories, found {}",
            profile_manifests.len()
        ))
        .into());
    }
    let mut profiles = profile_manifests
        .into_iter()
        .map(|profile| profile_paths(root, profile))
        .collect::<Result<Vec<_>, _>>()?;
    profiles.sort_unstable_by_key(|profile| profile.wire_code);
    if profiles
        .windows(2)
        .any(|pair| pair[0].wire_code >= pair[1].wire_code)
    {
        return Err(invalid_data(
            "profile catalog wire codes must be unique and strictly increasing",
        )
        .into());
    }
    Ok(profiles)
}

fn emit_catalog(profiles: &[ProfilePaths]) -> Result<String, std::fmt::Error> {
    let mut generated = String::from("const LAYER_SOURCES: &[LayerSource] = &[\n");
    for profile in profiles {
        writeln!(generated, "    LayerSource {{")?;
        writeln!(
            generated,
            "        profile_record: &{:?},",
            profile.profile_record
        )?;
        writeln!(
            generated,
            "        provider_record: &{:?},",
            profile.provider.bytes
        )?;
        writeln!(generated, "        fixtures: &[")?;
        for fixture in &profile.fixtures {
            writeln!(generated, "            FixtureSource {{")?;
            writeln!(
                generated,
                "                schema: &{:?},",
                fixture.schema.bytes
            )?;
            writeln!(
                generated,
                "                input: &{:?},",
                fixture.input.bytes
            )?;
            writeln!(
                generated,
                "                expected: &{:?},",
                fixture.expected.bytes
            )?;
            writeln!(
                generated,
                "                oracle: &{:?},",
                fixture.oracle.bytes
            )?;
            writeln!(generated, "            }},")?;
        }
        writeln!(generated, "        ],")?;
        writeln!(generated, "    }},")?;
    }
    generated.push_str("];\n");
    Ok(generated)
}

fn emit_rerun_directives(root: &CatalogRoot, profiles: &[ProfilePaths]) {
    let mut paths = BTreeSet::from([root.source.join("profiles")]);
    for profile in profiles {
        let profile_path = root.source.join(&profile.profile);
        if let Some(profile_directory) = profile_path.parent() {
            paths.insert(profile_directory.to_owned());
        }
        paths.insert(profile_path);
        paths.insert(root.source.join(&profile.provider.relative));
        for fixture in &profile.fixtures {
            paths.insert(root.source.join(&fixture.schema.relative));
            paths.insert(root.source.join(&fixture.input.relative));
            paths.insert(root.source.join(&fixture.expected.relative));
            paths.insert(root.source.join(&fixture.oracle.relative));
        }
    }
    for path in paths {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
            .ok_or_else(|| invalid_data("CARGO_MANIFEST_DIR is unavailable"))?,
    );
    let root = catalog_root(&manifest_dir)?;
    let profiles = discover_profiles(&root)?;
    emit_rerun_directives(&root, &profiles);
    let out_dir = PathBuf::from(
        env::var_os("OUT_DIR").ok_or_else(|| invalid_data("OUT_DIR is unavailable"))?,
    );
    fs::write(
        out_dir.join("conformance_fixture_catalog.rs"),
        emit_catalog(&profiles)?,
    )?;
    Ok(())
}
