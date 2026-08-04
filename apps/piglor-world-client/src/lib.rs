#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod fixture;

pub use fixture::{decode_fixture, fixture_bytes, ClientError};
