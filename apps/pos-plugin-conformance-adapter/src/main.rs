#![forbid(unsafe_code)]

//! `pos-plugin-conformance-adapter`: the EAI1/EAO1 subject adapter of the community Plugin host.
//!
//! All logic lives in the library; this entry point only wires the process's streams to it. It
//! reads one EAI1 attempt from standard input and writes one EAO1 observation to standard
//! output, or writes nothing and exits non-zero. R8-A7 runs it. On other platforms than Linux
//! the adapter is empty.

/// The composition-root seal (ADR-129 A5.9, #1374), minted once here: the adapter is the
/// trusted composition root of its evaluation worlds.
#[cfg(target_os = "linux")]
static AUTHORITY_TRUST_ROOT: pos_core::AuthorityTrustRootSealV1 =
    pos_core::AuthorityTrustRootSealV1::for_composition_root();

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let result = pos_plugin_conformance_adapter::run(
        &AUTHORITY_TRUST_ROOT,
        std::io::stdin().lock(),
        std::io::stdout().lock(),
    );
    pos_plugin_conformance_adapter::exit_code(result)
}

#[cfg(not(target_os = "linux"))]
fn main() {}
