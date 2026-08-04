#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod fixture;
pub mod projection;

pub use fixture::{decode_fixture, fixture_bytes, ClientError};
pub use projection::{project_fixture, ProjectionDigest};
