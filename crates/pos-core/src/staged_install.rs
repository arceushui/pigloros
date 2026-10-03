//! Prepared protected Projection installs (ADR-113 §2 and §9).
//!
//! A protected Replay or Compare folds its Projection State on a staged
//! executor, checks and allocates the whole install before ADR-112's final
//! trusted sample `t_f`, and then moves it into the visible registry only
//! through [`crate::trusted_clock::handoff_checked`]. The move is the
//! infallible [`ProtectedHandoffTargetV1::commit`] of [`PreparedInstallV1`]
//! or [`PreparedInstallPairV1`]: it only swaps prebuilt maps and source
//! fields. These targets sit beside ADR-112's seal, which keeps every
//! implementor of the handoff trait in this crate.
//!
//! A prepared install cannot be committed without a token:
//!
//! ```compile_fail,E0061
//! use pos_core::staged_install::{PreparedInstallV1, ProjectionSourceV1};
//! use pos_core::trusted_clock::ProtectedHandoffTargetV1;
//! let mut source = ProjectionSourceV1::default();
//! let prepared = PreparedInstallV1::new(Vec::new(), &mut source, ProjectionSourceV1::default());
//! let _displaced = prepared.commit();
//! ```
//!
//! A staged prepared install exposes no bare value:
//!
//! ```compile_fail,E0616
//! use pos_core::staged_install::{PreparedInstallV1, ProjectionSourceV1};
//! use pos_core::trusted_clock::StagedProtectedOutputV1;
//! let mut source = ProjectionSourceV1::default();
//! let prepared = PreparedInstallV1::new(Vec::new(), &mut source, ProjectionSourceV1::default());
//! let staged = StagedProtectedOutputV1::stage(prepared);
//! let _bare = staged.value;
//! ```
//!
//! One Compare arm cannot be taken out of a prepared pair:
//!
//! ```compile_fail,E0616
//! use pos_core::staged_install::{PreparedInstallPairV1, PreparedInstallV1, ProjectionSourceV1};
//! let (mut a, mut b) = (ProjectionSourceV1::default(), ProjectionSourceV1::default());
//! let pair = PreparedInstallPairV1::new(
//!     PreparedInstallV1::new(Vec::new(), &mut a, ProjectionSourceV1::default()),
//!     PreparedInstallV1::new(Vec::new(), &mut b, ProjectionSourceV1::default()),
//! );
//! let _arm = pair.arm_a;
//! ```

use crate::trusted_clock::{sealed, HandoffTokenV1, ProtectedHandoffTargetV1};
use crate::{ErasureReferenceV1, StateRegistry, TimelineId};

/// The source a registry's Projection State was folded from.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ProjectionSourceV1 {
    /// Not bound to any Timeline; the registry holds no folded State.
    #[default]
    Unbound,
    /// Bound to one Timeline at one erasure-inventory generation, or at none
    /// when no erasure gate is bound.
    Bound {
        /// The Timeline the State was folded from.
        timeline: TimelineId,
        /// The inventory generation bound with the Timeline.
        generation: Option<ErasureReferenceV1>,
    },
    /// Mixed Timelines or generations; never valid, and it holds no State.
    Mixed,
}

impl ProjectionSourceV1 {
    /// A source bound to one Timeline at one inventory generation.
    #[must_use]
    pub const fn bound(timeline: TimelineId, generation: Option<ErasureReferenceV1>) -> Self {
        Self::Bound {
            timeline,
            generation,
        }
    }

    /// A source that mixed Timelines or generations; it holds no State.
    #[must_use]
    pub const fn mixed() -> Self {
        Self::Mixed
    }

    /// The bound Timeline, if any.
    #[must_use]
    pub const fn timeline(&self) -> Option<TimelineId> {
        match self {
            Self::Bound { timeline, .. } => Some(*timeline),
            Self::Unbound | Self::Mixed => None,
        }
    }

    /// The inventory generation bound with the Timeline.
    #[must_use]
    pub const fn generation(&self) -> Option<ErasureReferenceV1> {
        match self {
            Self::Bound { generation, .. } => *generation,
            Self::Unbound | Self::Mixed => None,
        }
    }

    /// Whether the source mixed Timelines or generations.
    #[must_use]
    pub const fn is_mixed(&self) -> bool {
        matches!(self, Self::Mixed)
    }
}

/// The visible maps and source a commit displaced. The caller drops it after
/// the handoff returns, outside the check-to-move gap.
#[derive(Debug)]
pub struct DisplacedStateV1 {
    maps: Vec<StateRegistry>,
    source: ProjectionSourceV1,
}

impl DisplacedStateV1 {
    /// The displaced per-slot maps, in slot order.
    #[must_use]
    pub fn maps(&self) -> &[StateRegistry] {
        &self.maps
    }

    /// The displaced source binding.
    #[must_use]
    pub const fn source(&self) -> ProjectionSourceV1 {
        self.source
    }
}

/// One registry's checked install: borrowed visible slot maps, the prebuilt
/// staged maps and the new source. Nothing is pending but the swap.
#[derive(Debug)]
pub struct PreparedInstallV1<'r> {
    live: Vec<&'r mut StateRegistry>,
    staged: Vec<StateRegistry>,
    source: &'r mut ProjectionSourceV1,
    staged_source: ProjectionSourceV1,
}

impl<'r> PreparedInstallV1<'r> {
    /// Pair each visible slot map with its prebuilt replacement.
    ///
    /// The caller has already checked the slot mapping; all allocation
    /// happens here, before the handoff.
    #[must_use]
    pub fn new(
        slots: Vec<(&'r mut StateRegistry, StateRegistry)>,
        source: &'r mut ProjectionSourceV1,
        staged_source: ProjectionSourceV1,
    ) -> Self {
        let (live, staged) = slots.into_iter().unzip();
        Self {
            live,
            staged,
            source,
            staged_source,
        }
    }

    fn swap(mut self) -> DisplacedStateV1 {
        for (live, staged) in self.live.into_iter().zip(self.staged.iter_mut()) {
            std::mem::swap(live, staged);
        }
        std::mem::swap(self.source, &mut self.staged_source);
        DisplacedStateV1 {
            maps: self.staged,
            source: self.staged_source,
        }
    }
}

impl sealed::Sealed for PreparedInstallV1<'_> {}

impl ProtectedHandoffTargetV1 for PreparedInstallV1<'_> {
    type Committed = DisplacedStateV1;

    /// Swap the prebuilt maps and source in. No I/O, allocation, lock or
    /// callback runs here.
    fn commit(self, _token: HandoffTokenV1) -> DisplacedStateV1 {
        self.swap()
    }
}

/// Both Compare arms' checked installs over two distinct registries. They
/// commit together under one token; no partial commit is possible.
#[derive(Debug)]
pub struct PreparedInstallPairV1<'a, 'b> {
    arm_a: PreparedInstallV1<'a>,
    arm_b: PreparedInstallV1<'b>,
}

impl<'a, 'b> PreparedInstallPairV1<'a, 'b> {
    /// Join two prepared arms.
    #[must_use]
    pub const fn new(arm_a: PreparedInstallV1<'a>, arm_b: PreparedInstallV1<'b>) -> Self {
        Self { arm_a, arm_b }
    }
}

impl sealed::Sealed for PreparedInstallPairV1<'_, '_> {}

impl ProtectedHandoffTargetV1 for PreparedInstallPairV1<'_, '_> {
    type Committed = (DisplacedStateV1, DisplacedStateV1);

    /// Swap both arms in under one token.
    fn commit(self, _token: HandoffTokenV1) -> (DisplacedStateV1, DisplacedStateV1) {
        (self.arm_a.swap(), self.arm_b.swap())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn sources_report_their_binding() {
        let timeline = TimelineId::new();
        let generation = Some(ErasureReferenceV1::from_digest([3; 32]));
        let bound = ProjectionSourceV1::bound(timeline, generation);
        assert_eq!(bound.timeline(), Some(timeline));
        assert_eq!(bound.generation(), generation);
        assert!(!bound.is_mixed());
        let mixed = ProjectionSourceV1::mixed();
        assert!(mixed.is_mixed());
        assert_eq!(mixed.timeline(), None);
        assert_eq!(mixed.generation(), None);
        let unbound = ProjectionSourceV1::default();
        assert_eq!(unbound, ProjectionSourceV1::Unbound);
        assert_eq!(unbound.timeline(), None);
        assert_eq!(unbound.generation(), None);
        assert!(!unbound.is_mixed());
    }
}
