#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! `pos-plugin-worker`: runs one community Plugin Component invocation.
//!
//! Launched only by the `pos-plugin-supervisor` crate, once per invocation.

#[cfg_attr(coverage_nightly, coverage(off))]
fn main() -> std::process::ExitCode {
    pos_plugin_worker::run_worker(
        std::env::args_os(),
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
    )
}
