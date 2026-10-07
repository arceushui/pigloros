#![cfg(windows)]
#![forbid(unsafe_code)]

//! Windows-specific owner-bridge adapter boundary.
//!
//! Native WebView2 and Win32 operations arrive in `ffi` modules only. This
//! initial policy-only slice deliberately exposes no surface before those
//! operations and their hosted lifecycle fixtures exist.
