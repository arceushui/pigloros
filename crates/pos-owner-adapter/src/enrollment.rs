#![cfg(any(test, feature = "test-support"))]
//! The ADR-091 owner adapter's enrollment side (ADR-110 §8, ADR-137 P3).
//!
//! This holds the store seam that enrollment reaches the ADR-137 P3 store
//! steps through, and the test-support store behind it.

mod store;

pub use store::{EnrollmentStore, SubjectKeyRegistration, VolatileEnrollmentStore};
