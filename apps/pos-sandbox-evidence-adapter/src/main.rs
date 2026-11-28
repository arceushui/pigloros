#![forbid(unsafe_code)]

//! `pos-sandbox-evidence-adapter`: the adapter of the #444 evidence DDI.
//!
//! All logic lives in the library; this entry point only wires the process's
//! arguments and streams to it. It reads one EAI1 attempt from standard input
//! and writes one EAO1 observation to standard output, or exits non-zero. The
//! adapter runs only in the Linux evidence guest, so the library and this
//! entry point are Linux-only.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let result = pos_sandbox_evidence_adapter::run(
        std::env::args_os().skip(1),
        std::io::stdin().lock(),
        std::io::stdout().lock(),
    );
    pos_sandbox_evidence_adapter::exit_code(result)
}

// A macro keeps this stub out of the mutation scope: it is never compiled, and
// so never tested, on the guest target.
#[cfg(not(target_os = "linux"))]
macro_rules! unsupported_platform_main {
    () => {
        fn main() -> std::process::ExitCode {
            use std::io::Write;
            writeln!(
                std::io::stderr(),
                "pos-sandbox-evidence-adapter runs only in the #444 Linux evidence guest"
            )
            .ok();
            std::process::ExitCode::FAILURE
        }
    };
}

#[cfg(not(target_os = "linux"))]
unsupported_platform_main!();
