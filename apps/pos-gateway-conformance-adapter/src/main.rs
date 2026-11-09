#![forbid(unsafe_code)]

//! `pos-gateway-conformance-adapter`: the gateway-client-conformance subject adapter of
//! apps/piglor-gateway.
//!
//! All logic lives in the library; this entry point only wires the process's streams to it. It
//! reads one EAI1 attempt from standard input and writes one EAO1 observation to standard
//! output, or writes nothing and exits non-zero.

fn main() -> std::process::ExitCode {
    let result =
        pos_gateway_conformance_adapter::run(std::io::stdin().lock(), std::io::stdout().lock());
    pos_gateway_conformance_adapter::exit_code(result)
}
