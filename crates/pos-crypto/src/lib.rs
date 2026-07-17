#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-crypto` — canonical CBOR encoding, BLAKE3 hash chain, Ed25519 sign/verify.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod canonical;
pub mod chain;
pub mod signing;
