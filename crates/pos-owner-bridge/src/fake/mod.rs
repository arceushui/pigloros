//! Deterministic fakes: a scripted page, `FakeSurface`, a fixture authenticator, and the host
//! ports.
//!
//! Everything here is behind the `test-support` feature and must never reach a deployable graph.

pub mod buffers;
pub mod clock;
pub mod honest;
pub mod host;
pub mod prf_item;
pub mod signer;
pub mod stepper;
pub mod surface;
