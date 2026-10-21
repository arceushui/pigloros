#![cfg(windows)]

//! Windows-specific owner-bridge adapter boundary.
//!
//! Native WebView2 and Win32 operations arrive in `ffi` modules only. This
//! initial policy-only slice deliberately exposes no surface before those
//! operations and their hosted lifecycle fixtures exist.
//!
//! This crate root deliberately carries no crate-wide `#![forbid(unsafe_code)]`:
//! an inner forbid at the root cannot be relaxed in `ffi`. Every non-ffi `mod`
//! declared here carries `#[forbid(unsafe_code)]` instead, and the policy
//! checker enforces it.
