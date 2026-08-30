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
}

struct FixtureAsset {
    relative: String,
    bytes: Vec<u8>,
}

struct ProfilePaths {
    wire_code: u64,
    profile: String,
    profile_record: Vec<u8>,
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

fn validate_fixture_provider(profile: &Value, claim_layer: &str) -> Result<(), io::Error> {
    let provider = json_field(profile, "fixture_provider")?;
    let expected_provider_id = format!("pigloros.fixture.{claim_layer}");
    let expected_package_path = format!("authority/providers/{claim_layer}.cbor");
    let valid = json_text(provider, "provider_id")? == expected_provider_id
        && json_text(provider, "contract_version")? == "1.0.0"
        && json_u64(provider, "abi_major")? == 1
        && json_u64(provider, "abi_minor")? == 0
        && json_text(provider, "package_path")? == expected_package_path;
    if valid {
        Ok(())
    } else {
        Err(invalid_data(format!(
            "profile catalog fixture_provider does not match claim layer {claim_layer}"
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
    validate_fixture_provider(&profile_value, &claim_layer)?;
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
            let expected_schema = format!("support/schemas/{family}.schema.json");
            if schema.relative != expected_schema {
                return Err(invalid_data(format!(
                    "profile fixture schema does not match family {family}"
                )));
            }
            Ok(FixturePaths {
                schema,
                input: relative_asset(root, fixture, "input")?,
                expected: relative_asset(root, fixture, "expected")?,
            })
        })
        .collect::<Result<Vec<_>, io::Error>>()?;
    if fixtures.len() != FIXTURES_PER_PROFILE {
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
        for fixture in &profile.fixtures {
            paths.insert(root.source.join(&fixture.schema.relative));
            paths.insert(root.source.join(&fixture.input.relative));
            paths.insert(root.source.join(&fixture.expected.relative));
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
