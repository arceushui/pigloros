//! The build script's root of the crate's GMP1 codec and declaration
//! compiler (`build.rs` loads this file; the crate itself compiles the same
//! two modules under `mode_profile`).

mod declaration;
mod gmp1;

/// Compile the reviewed declaration into canonical GMP1 records.
///
/// # Errors
/// Returns a description of the first rejected rule.
pub fn compile(json: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
    declaration::compile_declaration_v1(json)
}
