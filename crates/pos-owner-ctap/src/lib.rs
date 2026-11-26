#![cfg(any(test, feature = "test-support"))]
//! The ADR-110 E20 Linux owner surface: a native CTAP2 client (Redmine #1475, slice S1).
//!
//! On Linux the owner process is itself the `WebAuthn` client. [`client::CtapAuthenticator`]
//! implements the bridge's `OwnerAuthenticatorPort` over a CTAPHID [`hid::HidTransport`] and a
//! [`prompt::PinPrompt`]: CTAPHID framing, the CTAP2 commands, PIN/UV auth protocol 2 with
//! in-repo AES-256-CBC, `hmac-secret` with the `WebAuthn` PRF salt, the capability check before
//! any credential is created, built-in UV first with the PIN as fallback, and one token per CTAP
//! command. The Linux hidraw transport ([`hidraw::HidrawTransport`]), the terminal prompt
//! ([`tty::TtyPrompt`]) and the process hardening ([`hardening::harden_process`]) are slice S2
//! (Redmine #1476): safe Rust over `rustix`, with the U-tier uhid job as their hosted evidence.
//!
//! The whole crate is `forbid(unsafe_code)` through the workspace lints, and stays behind
//! `test-support` until the Linux activation (Redmine #1438). [`soft::SoftAuthenticator`] and
//! [`memory::MemoryHid`] are the in-process authenticator and device of the P-tier tests.

pub mod cbc;
// Public module reachability keeps these crate-only helpers compatible with both
// `unreachable_pub` and Clippy's `redundant_pub_crate` lint.
#[doc(hidden)]
pub mod cbor;
pub mod client;
pub mod ctap;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod fdwait;
#[cfg(target_os = "linux")]
pub mod hardening;
pub mod hid;
#[cfg(target_os = "linux")]
pub mod hidraw;
pub mod info;
pub mod memory;
pub mod pin;
pub mod prompt;
pub mod soft;
#[cfg(target_os = "linux")]
pub mod tty;
#[cfg(test)]
#[doc(hidden)]
pub mod vectors;
pub mod webauthn;

pub use client::CtapAuthenticator;
#[cfg(target_os = "linux")]
pub use hardening::{harden_process, HardeningError};
pub use hid::{HidTransport, TransportError};
#[cfg(target_os = "linux")]
pub use hidraw::HidrawTransport;
pub use memory::MemoryHid;
pub use prompt::{Notice, PinBuffer, PinPrompt};
pub use soft::{Drbg, SoftAuthenticator};
#[cfg(target_os = "linux")]
pub use tty::TtyPrompt;
