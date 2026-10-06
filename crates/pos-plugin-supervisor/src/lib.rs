#![forbid(unsafe_code)]
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

//! Community Plugin worker supervisor (ADR-061 revision 4, #542).
//!
//! The supervisor runs every community Plugin Component invocation in one
//! fresh worker subprocess that it launches directly: the revision 4 decision
//! 1 Local relaxation. The core never loads a Component in-process, and this
//! crate does not link the Wasmtime runtime; only the worker program does.
//!
//! What the relaxation provides:
//! - a dedicated worker process per invocation, inside the Wasmtime sandbox;
//! - a cleared environment and no inherited descriptor other than the two IPC
//!   pipes ([`launch`], [`worker_process`]);
//! - CPU, data (memory), file-size and core rlimit ceilings;
//! - kill-on-supervisor-exit through `PR_SET_PDEATHSIG`;
//! - bounded, length-prefixed canonical CBOR IPC ([`frame`], [`ipc`]);
//! - a wall-time watchdog that kills the worker ([`supervisor`]).
//!
//! What it deliberately omits: a denied network namespace and job-level
//! (cgroup) CPU, memory and output ceilings. This crate adds no namespace,
//! cgroup or seccomp layer of its own (ADR-072). A worker compromised through
//! a Wasmtime defect is therefore not network-denied.
//!
//! Results are engineering evidence only. The Local relaxation is not a
//! hosted, Candidate or Stable execution boundary and claims no hosted
//! conformance; hosted execution waits for Sandbox Provider launch in a later
//! accepted revision.
//!
//! The supervisor and worker are Linux-only: they rely on `prlimit`,
//! `PR_SET_PDEATHSIG` and `/proc/self/fd`.

// Public modules keep crate-only items compatible with both `unreachable_pub`
// and Clippy's `redundant_pub_crate`.
pub mod frame;
pub mod ipc;
pub mod launch;
pub mod supervisor;
mod verify;
pub mod worker_process;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod fixtures;

pub use frame::{FrameFaultV1, WorkerFrameLimitsV1};
pub use launch::{WorkerProgramV1, WorkerResourceCeilingsV1, FORWARDED_ENVIRONMENT};
pub use ipc::{WorkerCallV1, WorkerEnvelopeErrorV1, WorkerOutcomeV1, WorkerRequestV1, WorkerReturnV1};
pub use supervisor::{CommunityPluginSupervisorV1, MAX_WORKER_WATCHDOG};
pub use worker_process::{
    open_descriptors, prepare_worker_process, read_request, write_response, WorkerProcessErrorV1,
};
