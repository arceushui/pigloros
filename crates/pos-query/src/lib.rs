#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-query` — event query builder and graph/causal traversal utilities.
//!
//! # Overview
//!
//! This crate provides two main capabilities:
//!
//! - [`EventQuery`]: a fluent builder for filtering events from a timeline.
//! - Traversal helpers in [`traversal`]: relationship tracing and causal-chain walking.

pub mod query;
pub mod traversal;

pub use query::EventQuery;
