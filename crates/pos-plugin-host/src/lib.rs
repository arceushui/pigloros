#![forbid(unsafe_code)]
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

//! In-worker community Plugin Component engine for ADR-061 revisions 4, 5 and 6.
//!
//! This crate runs one Component of the `pigloros:plugin/community-plugin@0.1.0`
//! world on the exact Wasmtime pin:
//! - [`runtime`] records the pin, its resolved features, the Engine
//!   configuration and the trap table that execution profiles carry;
//! - [`ComponentHost::load`] compiles a Component and refuses, before any
//!   execution, every import that is not a `host-v1` function with its exact
//!   type, and any Component without the `describe`, `reduce` and `drive`
//!   exports;
//! - [`ComponentHost::describe`], [`ComponentHost::reduce`] and
//!   [`ComponentHost::drive`] run one export in a fresh store under the
//!   negotiated effective limits: fuel, linear memory, host calls,
//!   operational log calls and bytes, and the `EventDraft`, state and output
//!   bounds. `migrate-state` is never invoked.
//!
//! Execution needs a [`PinnedExecutionV1`]: a negotiated release
//! (`pos-runtime`'s `NegotiatedCommunityPluginV1`) whose execution profile
//! pins exactly this engine's runtime.
//!
//! The engine never commits anything. A failed invocation returns only the
//! closed `CommunityPluginHostErrorV1`; the guest's output and operational
//! logs are dropped with its store, and raw runtime messages and backtraces
//! never leave the engine. A completed invocation returns the fully validated
//! output, or the guest's own validated `plugin-error`, for the supervisor to
//! approve and commit at the Tick Boundary.
//!
//! The evidence for the pin and the compatibility gates is in
//! `docs/evidence/adr-061-r4-prototype.md`. Later slices build on this crate:
//! #542 runs it in a supervised worker process, and #543 commits approved
//! output atomically at the Tick Boundary.

// Public modules keep crate-only items compatible with both `unreachable_pub`
// and Clippy's `redundant_pub_crate`.
pub mod contract;
pub mod describe;
pub mod digest;
pub mod engine;
pub mod host_v1;
pub mod imports;
pub mod lift;
pub mod outcome;
pub mod output;
pub mod runtime;

pub use contract::{
    ArtifactRefV1, EventDraftV1, FieldRefV1, GuestPluginErrorV1, PluginDescriptorV1,
    PluginErrorCodeV1, PluginInvocationV1, PluginOutputV1, TimelinePositionV1, TraceAnnotationV1,
    MAX_OBSERVATION_BYTES_V1, MAX_STATE_BYTES_V1,
};
pub use digest::{plugin_output_digest_v1, PLUGIN_OUTPUT_DIGEST_DOMAIN_V1};
pub use engine::{ComponentHost, GuestExport, LoadedComponent, PinnedExecutionV1};
pub use host_v1::{HostInputs, OperationalLogRecord};
pub use outcome::{GuestReturnV1, InvocationReportV1, LoadError, MeteringV1, RuntimeNotPinnedV1};
pub use runtime::{
    pinned_runtime, MAX_WASM_STACK_BYTES, PINNED_ENGINE_CONFIG, RESOLVED_WASMTIME_FEATURES,
    WASMTIME_VERSION,
};
