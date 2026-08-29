use serde_json::Value;
use std::env;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

struct FixturePaths {
    input: String,
    expected: String,
}

struct ProfilePaths {
    wire_code: u64,
    profile: String,
    fixtures: Vec<FixturePaths>,
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
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

fn relative_asset(root: &Path, value: &Value, field: &str) -> Result<String, io::Error> {
    let relative = json_text(value, field)?;
    let path = Path::new(&relative);
    if relative.is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || !root.join(path).is_file()
    {
        return Err(invalid_data(format!(
            "profile catalog {field} is not an existing relative asset: {relative}"
        )));
    }
    Ok(relative)
}

fn profile_paths(root: &Path, profile_path: &Path) -> Result<ProfilePaths, Box<dyn Error>> {
    let bytes = fs::read(profile_path)?;
    let profile: Value = serde_json::from_slice(&bytes)?;
    let wire_code = json_field(&profile, "wire_code")?
        .as_u64()
        .ok_or_else(|| invalid_data("profile catalog wire_code must be unsigned"))?;
    let fixtures = json_field(&profile, "fixtures")?
        .as_array()
        .ok_or_else(|| invalid_data("profile catalog fixtures must be an array"))?
        .iter()
        .map(|fixture| {
            Ok(FixturePaths {
                input: relative_asset(root, fixture, "input")?,
                expected: relative_asset(root, fixture, "expected")?,
            })
        })
        .collect::<Result<Vec<_>, io::Error>>()?;
    let relative_profile = profile_path
        .strip_prefix(root)?
        .to_str()
        .ok_or_else(|| invalid_data("profile catalog path must be UTF-8"))?
        .to_owned();
    Ok(ProfilePaths {
        wire_code,
        profile: relative_profile,
        fixtures,
    })
}

fn discover_profiles(root: &Path) -> Result<Vec<ProfilePaths>, Box<dyn Error>> {
    let mut profiles = fs::read_dir(root.join("profiles"))?
        .map(|entry| entry.map(|value| value.path().join("profile.json")))
        .collect::<Result<Vec<_>, _>>()?;
    profiles.retain(|path| path.is_file());
    let mut profiles = profiles
        .iter()
        .map(|path| profile_paths(root, path))
        .collect::<Result<Vec<_>, _>>()?;
    profiles.sort_unstable_by_key(|profile| profile.wire_code);
    if profiles.is_empty()
        || profiles
            .windows(2)
            .any(|pair| pair[0].wire_code >= pair[1].wire_code)
    {
        return Err(invalid_data("profile catalog wire codes must be unique").into());
    }
    Ok(profiles)
}

fn emit_catalog(profiles: &[ProfilePaths]) -> Result<String, std::fmt::Error> {
    let mut generated = String::from("const LAYER_SOURCES: &[LayerSource] = &[\n");
    for profile in profiles {
        writeln!(generated, "    LayerSource {{")?;
        writeln!(
            generated,
            "        profile_record: include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/../../fixtures/conformance/\", {:?})),",
            profile.profile
        )?;
        writeln!(generated, "        fixtures: &[")?;
        for fixture in &profile.fixtures {
            writeln!(generated, "            FixtureSource {{")?;
            writeln!(
                generated,
                "                input: include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/../../fixtures/conformance/\", {:?})),",
                fixture.input
            )?;
            writeln!(
                generated,
                "                expected: include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/../../fixtures/conformance/\", {:?})),",
                fixture.expected
            )?;
            writeln!(generated, "            }},")?;
        }
        writeln!(generated, "        ],")?;
        writeln!(generated, "    }},")?;
    }
    generated.push_str("];\n");
    Ok(generated)
}

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
            .ok_or_else(|| invalid_data("CARGO_MANIFEST_DIR is unavailable"))?,
    );
    let root = manifest_dir.join("../../fixtures/conformance");
    println!("cargo:rerun-if-changed={}", root.join("profiles").display());
    let profiles = discover_profiles(&root)?;
    for profile in &profiles {
        println!(
            "cargo:rerun-if-changed={}",
            root.join(&profile.profile).display()
        );
        for fixture in &profile.fixtures {
            println!(
                "cargo:rerun-if-changed={}",
                root.join(&fixture.input).display()
            );
            println!(
                "cargo:rerun-if-changed={}",
                root.join(&fixture.expected).display()
            );
        }
    }
    let out_dir = PathBuf::from(
        env::var_os("OUT_DIR").ok_or_else(|| invalid_data("OUT_DIR is unavailable"))?,
    );
    fs::write(
        out_dir.join("conformance_fixture_catalog.rs"),
        emit_catalog(&profiles)?,
    )?;
    Ok(())
}
