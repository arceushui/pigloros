//! The pinned digests of the schema members of the seven families (ADR-061 revision 8
//! decision 2, interpretation I-12).
//!
//! The digest of the schema member (role 0) of an attempt must equal the digest pinned here for
//! its family; a mismatch is a non-executed outcome (ADR-068 section 3). These are the S2 test
//! values: the BLAKE3 of a placeholder schema text per family. S3b1 replaces this file, in the
//! same slice as the schema members, by a file that the fixture generator writes and its
//! `--check` verifies, and R8-F4 asserts its equality with the checked-in schemas.

use pos_reference::evaluator_domain::FixtureFamily;

/// The placeholder schema text whose BLAKE3 is the pinned digest of `family`.
#[must_use]
pub const fn placeholder_schema(family: FixtureFamily) -> &'static [u8] {
    match family {
        FixtureFamily::Positive => b"pigloros.plugin-conformance.case.v2 positive",
        FixtureFamily::Denied => b"pigloros.plugin-conformance.case.v2 denied",
        FixtureFamily::Malformed => b"pigloros.plugin-conformance.case.v2 malformed",
        FixtureFamily::ResourceExhaustion => {
            b"pigloros.plugin-conformance.case.v2 resource-exhaustion"
        }
        FixtureFamily::DeletionRedaction => {
            b"pigloros.plugin-conformance.case.v2 deletion-redaction"
        }
        FixtureFamily::Downgrade => b"pigloros.plugin-conformance.case.v2 downgrade",
        FixtureFamily::IndependentEvaluation => {
            b"pigloros.plugin-conformance.case.v2 independent-evaluation"
        }
    }
}

/// The pinned digest of the schema member of `family`.
#[must_use]
pub fn pinned_digest(family: FixtureFamily) -> [u8; 32] {
    *blake3::hash(placeholder_schema(family)).as_bytes()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
