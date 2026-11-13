//! Compile the reviewed Gateway execution-mode profile declaration into the
//! crate-private GMP1 table (ADR-134 §3).
//!
//! The only input is the public declaration under `contracts/gateway/v1/`.
//! No feature, environment variable, argument or request can add, replace or
//! patch an entry: the build rejects any declaration that is not exactly the
//! reviewed two-profile table.

use std::{env, error::Error, fmt::Write as _, fs, path::PathBuf};

// The crate's own GMP1 codec and declaration compiler, shared with the
// crate's tests.
#[path = "src/mode_profile/compiler.rs"]
pub mod compiler;

const DECLARATION: &str = "../../contracts/gateway/v1/execution-mode-profiles.json";

fn main() -> Result<(), Box<dyn Error>> {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let declaration_path = manifest.join(DECLARATION);
    println!("cargo:rerun-if-changed={}", declaration_path.display());
    println!("cargo:rerun-if-changed=src/mode_profile/declaration.rs");
    println!("cargo:rerun-if-changed=src/mode_profile/gmp1.rs");
    println!("cargo:rerun-if-changed=src/mode_profile/compiler.rs");
    let json = fs::read_to_string(&declaration_path)?;
    let compiled = compiler::compile(&json)?;
    let mut source = String::new();
    for (mode_profile_id, bytes) in &compiled {
        let name = mode_profile_id.replace('-', "_").to_uppercase();
        let literal = bytes
            .iter()
            .map(|byte| format!("0x{byte:02x}"))
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(
            source,
            "/// Canonical GMP1 bytes of `{mode_profile_id}`.\npub(super) const {name}: &[u8] = &[{literal}];"
        )?;
    }
    fs::write(
        PathBuf::from(env::var("OUT_DIR")?).join("gateway_mode_profiles.rs"),
        source,
    )?;
    Ok(())
}
