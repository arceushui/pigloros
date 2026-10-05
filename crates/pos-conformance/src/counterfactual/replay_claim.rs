//! Wire codes for [`ReplayClaimV1`] shared by the CFP1 plan and CFR1 result
//! codecs and the nested evidence codec, so every record encodes a replay
//! claim identically through this one table.

use crate::ReplayClaimV1;

/// Every replay claim, indexed by its wire code.
pub(crate) const REPLAY_CLAIMS: [ReplayClaimV1; 5] = [
    ReplayClaimV1::Exact,
    ReplayClaimV1::ExactAuthoritativeWithRedactedViews,
    ReplayClaimV1::StructuralOnly,
    ReplayClaimV1::UnverifiableArtifactsMissing,
    ReplayClaimV1::IncompatibleProfile,
];

/// The wire code of one replay claim; the inverse of indexing [`REPLAY_CLAIMS`].
pub(crate) const fn replay_claim_code(claim: ReplayClaimV1) -> u64 {
    match claim {
        ReplayClaimV1::Exact => 0,
        ReplayClaimV1::ExactAuthoritativeWithRedactedViews => 1,
        ReplayClaimV1::StructuralOnly => 2,
        ReplayClaimV1::UnverifiableArtifactsMissing => 3,
        ReplayClaimV1::IncompatibleProfile => 4,
    }
}
