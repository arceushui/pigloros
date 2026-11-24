#![forbid(unsafe_code)]

//! `pos-sandbox-evidence-adapter`: the adapter of the #444 evidence DDI.
//!
//! All logic lives in the library; this entry point only wires the process's
//! arguments and streams to it. It reads one EAI1 attempt from standard input
//! and writes one EAO1 observation to standard output, or writes nothing and
//! exits non-zero.

fn main() -> std::process::ExitCode {
    let result = pos_sandbox_evidence_adapter::run(
        std::env::args_os().skip(1),
        std::io::stdin().lock(),
        std::io::stdout().lock(),
    );
    pos_sandbox_evidence_adapter::exit_code(result)
}
