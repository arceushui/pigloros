#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-store` — `EventStore` implementations: in-memory and `SQLite` WAL.

pub mod memory;
pub mod sqlite;
