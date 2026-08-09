#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod fixture;
pub mod projection;
#[cfg(feature = "runtime")]
pub mod shell;

pub use fixture::{decode_fixture, fixture_bytes, ClientError};
pub use projection::{project_fixture, ProjectionDigest};
#[cfg(feature = "runtime")]
pub use shell::{build_app, run_native};
