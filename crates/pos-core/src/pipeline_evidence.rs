//! Post-commit ADR-021 evidence that binds a committed Event range to the
//! Projection cut that folded it (#320).
//!
//! A [`PipelineCommitReceiptV1`] names only the Events one admitted attempt
//! committed; it never claims that the resulting state was folded. A
//! [`PipelineCommitEvidenceV1`] starts from that receipt and gains a
//! [`PipelineProjectionCutV1`] only once the Tick Boundary owner reports a
//! completed fold that contains the complete committed range. State-dependent
//! evaluation therefore waits for, and names, that cut.
//!
//! Neither value carries an append, approval, or policy capability, and
//! neither has a serialization contract:
//!
//! ```compile_fail
//! fn assert_serializable<T: serde::Serialize>() {}
//! assert_serializable::<pos_core::PipelineCommitEvidenceV1>();
//! ```

use crate::{PipelineCommitReceiptV1, PipelineIngressV1, Seq, TimelineId};

/// The contiguous Timeline Order range one committed attempt was assigned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipelineCommittedRangeV1 {
    timeline_id: TimelineId,
    first: Seq,
    last: Seq,
}

impl PipelineCommittedRangeV1 {
    /// Derive the committed range named by one receipt.
    ///
    /// A receipt is validated as a non-empty contiguous range when the store
    /// builds it, so its first and last Events bound the range exactly.
    #[must_use]
    pub fn of_receipt(receipt: &PipelineCommitReceiptV1) -> Self {
        let events = receipt.committed_events();
        let seq_of = |event: Option<&crate::CommittedPipelineEventV1>| {
            event.map_or(Seq::ZERO, |event| event.seq())
        };
        Self {
            timeline_id: receipt.timeline_id(),
            first: seq_of(events.first()),
            last: seq_of(events.last()),
        }
    }

    #[must_use]
    pub const fn timeline_id(self) -> TimelineId {
        self.timeline_id
    }

    #[must_use]
    pub const fn first(self) -> Seq {
        self.first
    }

    #[must_use]
    pub const fn last(self) -> Seq {
        self.last
    }

    /// Whether the range ends at or before `seq`.
    fn ends_by(self, seq: Seq) -> bool {
        self.last <= seq
    }
}

/// A completed Projection fold: every Event of `timeline_id` through
/// `folded_through` was folded at one Tick Boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipelineProjectionCutV1 {
    timeline_id: TimelineId,
    folded_through: Seq,
}

impl PipelineProjectionCutV1 {
    /// Name the completed fold cursor of one Timeline.
    #[must_use]
    pub const fn new(timeline_id: TimelineId, folded_through: Seq) -> Self {
        Self {
            timeline_id,
            folded_through,
        }
    }

    #[must_use]
    pub const fn timeline_id(self) -> TimelineId {
        self.timeline_id
    }

    #[must_use]
    pub const fn folded_through(self) -> Seq {
        self.folded_through
    }

    /// Whether this cut folded every Event of `range`.
    #[must_use]
    pub fn contains(self, range: PipelineCommittedRangeV1) -> bool {
        self.timeline_id == range.timeline_id && range.ends_by(self.folded_through)
    }
}

/// One committed attempt, its ingress path, and, once folded, the first
/// completed Projection cut that contains its complete committed range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipelineCommitEvidenceV1 {
    ingress: PipelineIngressV1,
    receipt: PipelineCommitReceiptV1,
    committed_range: PipelineCommittedRangeV1,
    projection_cut: Option<PipelineProjectionCutV1>,
}

impl PipelineCommitEvidenceV1 {
    /// Record a committed attempt whose resulting state is not yet folded.
    #[must_use]
    pub fn committed(ingress: PipelineIngressV1, receipt: PipelineCommitReceiptV1) -> Self {
        let committed_range = PipelineCommittedRangeV1::of_receipt(&receipt);
        Self {
            ingress,
            receipt,
            committed_range,
            projection_cut: None,
        }
    }

    /// Bind the first completed fold that contains the complete committed
    /// range.
    ///
    /// A cut of another Timeline, or one that precedes the end of the range,
    /// leaves the evidence awaiting its fold. Evidence that already names a
    /// cut keeps it: a later fold is not the cut that first folded the range.
    #[must_use]
    pub fn with_completed_fold(self, cut: PipelineProjectionCutV1) -> Self {
        if self.projection_cut.is_some() || !cut.contains(self.committed_range) {
            self
        } else {
            Self {
                projection_cut: Some(cut),
                ..self
            }
        }
    }

    #[must_use]
    pub const fn ingress(&self) -> PipelineIngressV1 {
        self.ingress
    }

    #[must_use]
    pub const fn receipt(&self) -> &PipelineCommitReceiptV1 {
        &self.receipt
    }

    #[must_use]
    pub const fn committed_range(&self) -> PipelineCommittedRangeV1 {
        self.committed_range
    }

    /// The completed Projection cut, or `None` while the range awaits its fold.
    #[must_use]
    pub const fn projection_cut(&self) -> Option<PipelineProjectionCutV1> {
        self.projection_cut
    }
}
