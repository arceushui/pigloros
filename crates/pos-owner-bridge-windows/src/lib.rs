#![cfg(windows)]

//! Windows-specific owner-bridge adapter boundary.
//!
//! Native Win32 operations are confined to inventoried `ffi` modules. The
//! process probe preserves inspection failure as an indeterminate observation.
//!
//! This crate root deliberately carries no crate-wide `#![forbid(unsafe_code)]`:
//! an inner forbid at the root cannot be relaxed in `ffi`. Every non-ffi `mod`
//! declared here carries `#[forbid(unsafe_code)]` instead, and the policy
//! checker enforces it.

mod ffi;
#[forbid(unsafe_code)]
mod process;

pub use process::{process_identity, WindowsProcessProbe};
