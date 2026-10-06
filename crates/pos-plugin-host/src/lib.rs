#![forbid(unsafe_code)]
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

//! Community Plugin Component host for ADR-061 revision 4.
//!
//! This is slice 1 (#539) of the #538 host: the exact Wasmtime pin, a
//! deterministic engine configuration and a linker that provides only the
//! `host-v1` imports of the `pigloros:plugin/community-plugin@0.1.0` world.
//! It carries the compatibility prototype evidence recorded in
//! `docs/evidence/adr-061-r4-prototype.md`.
//!
//! Later slices build on it:
//! - #540 negotiates the PMF1 execution projection and the execution profile;
//! - #541 completes the in-worker engine (trap classes, host-call counters,
//!   output validation);
//! - #542 runs it in a supervised worker process;
//! - #543 commits approved output atomically at the Tick Boundary.
//!
//! The host never commits anything. Every invocation runs in a fresh store, and
//! a failed invocation returns only a closed [`InvocationFailure`]: the guest's
//! output and operational logs are dropped with that store.
//!
//! The prototype passes guest arguments and results as Wasmtime's dynamic
//! `Val`, and reports other traps as the raw Wasmtime `Trap`. #541 replaces
//! both with validated host types and the revision 4 trap-class table.

mod engine;
mod host_v1;
mod outcome;

pub use engine::{ComponentHost, GuestExport, InvocationLimits, LoadedComponent};
pub use host_v1::{HostInputs, OperationalLogRecord};
pub use outcome::{InvocationFailure, InvocationReport, LoadError};
pub use wasmtime::{component::Val, Trap};

/// Exact Wasmtime release of the host (ADR-061 revision 4, decision 2).
///
/// A new pin is a new execution-profile version.
pub const WASMTIME_VERSION: &str = "49.0.2";

/// Pinned Wasm stack ceiling, in bytes, for every invocation.
///
/// A deeper guest call stack traps with `StackOverflow`.
pub const MAX_WASM_STACK_BYTES: usize = 512 * 1024;
