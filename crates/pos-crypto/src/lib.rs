#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-crypto` — canonical CBOR encoding, BLAKE3 hash chain, Ed25519 sign/verify.
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

pub mod canonical;
pub mod chain;
pub mod key_roles;
pub mod signing;
