//! Closed arithmetic error for the native owners' checked length queries.

/// Failure to represent one canonical encoding's length.
///
/// This is an arithmetic result, never a validity or authority decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CanonicalLengthErrorV1 {
    /// Checked accumulation cannot fit the target's `usize`.
    #[error("canonical length overflow")]
    LengthOverflow,
}
