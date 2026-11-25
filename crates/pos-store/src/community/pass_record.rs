//! The Memory domain's pass records and their CRI1 index (#560 A4c-3;
//! ADR-129 revisions 8, 10, 13 and 14).
//!
//! A Reserve that applies inserts one [`CommunityPassRecordV1`] under
//! `(T, reservation_operation_id)`, the CRI1 index of R8.1(7). The record
//! keeps the CPR1 fields, the quote maxima Seal compares against (R10.3(7)),
//! the counters the quote was built over, the materialization's additions and
//! the pass's status. Seal, Commit and Abort resolve against it. Nothing
//! here has a wire form.

use pos_core::community_lifecycle::{CommunityReservationInputV1, CommunitySharedCountsV1};
use pos_core::{AuthorityTrustRootSealV1, Hash, TimelineId};

use super::memory_domain::MemoryCommunityDomainV1;

/// Where a pass stands (annex "Exact pass and retained result records").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommunityPassStatusV1 {
    /// A CPR1 exists and no CPS1 does.
    Reserved,
    /// A CPS1 exists and no terminal record does.
    Sealed,
    /// A CPC1 exists.
    Committed,
    /// A CAB1 exists.
    Aborted,
}

impl CommunityPassStatusV1 {
    /// Reserved and Sealed passes are unresolved (code 7 for another pass).
    pub(super) const fn unresolved(self) -> bool {
        matches!(self, Self::Reserved | Self::Sealed)
    }
}

/// One due member's commitments a failure Abort needs, in roster order
/// (R15.3(2)).
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityPassMemberDigestsV1 {
    /// The member's index in the installed CDP1 roster: its stable entry
    /// and IMK1, for the CQK1, come from that row.
    pub roster_index: usize,
    /// `H(CMB1)` of the member's binding.
    pub cmb1_digest: Hash,
    /// `H(CIN1)` of the member's prepared invocation.
    pub cin1_digest: Hash,
    /// The member's trust-policy snapshot digest.
    pub trust_policy_snapshot_digest: Hash,
}

/// The counters a pass's quote was built over and its materialization's
/// actual additions.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityPassCountsV1 {
    /// The counters the quote was built over (R10.3(6)).
    pub prior: CommunitySharedCountsV1,
    /// The minted materialization's actual additions, if the pass minted one.
    pub materialization: Option<CommunitySharedCountsV1>,
}

/// The facts a Reserve retains about its pass.
#[derive(Clone, PartialEq, Eq)]
pub struct CommunityReservedPassV1 {
    /// The CPR1 fields, the CPK1 and `H(CRI1)` included.
    pub reservation: CommunityReservationInputV1,
    /// `H(CBQ1)`, the pass quote.
    pub cbq1_digest: Hash,
    /// The quote's maximum required nodes, edges and bytes.
    pub quote_maxima: [u64; 3],
    /// The trace rows held in the pass's entry: `n_due + 1`, the `F_p`
    /// share (R15.5), the most Seal's annotations may take.
    pub trace_rows: u64,
    /// Each due member's digests, in roster order: what a failure Abort
    /// re-derives its CFO1 from once the CIN1 bytes are dropped (R15.3(2)).
    pub members: Vec<CommunityPassMemberDigestsV1>,
    /// The protection ID of the pass's one metadata key, which seals the
    /// pass's CNE1 records, Abort's included (R13.2(1), R15.1(2)).
    ///
    /// The Reserve must leave it encryption-open: Abort and Commit seal
    /// under it and then close it, so a key the Reserve closed makes every
    /// Abort give 14. Every record is sealed under one CSM1 cover: the CMA1
    /// anchor `(T, G)`, this protection ID, no scope members and the NMP1
    /// `metadata_not_after_micros`.
    pub metadata_key: [u8; 16],
    /// The protection ID of the failure cohort key (R15.1(3)), provisioned
    /// with the Reserve's State keys.
    pub failure_cohort_key: [u8; 16],
    /// `H_g`, the horizon of the records a selected State needs (R13.2).
    pub generation_horizon_micros: u64,
    /// `H_r`, the horizon of the outcome evidence, at most `H_g` (R13.2).
    pub outcome_horizon_micros: u64,
}

/// One pass in the CRI1 index.
#[derive(Clone)]
pub(super) struct CommunityPassRecordV1 {
    pub(super) reserved: CommunityReservedPassV1,
    /// The counters the quote was built over (R10.3(6)).
    pub(super) prior_shared_counts: CommunitySharedCountsV1,
    /// The minted materialization's actual additions, if the pass minted one.
    pub(super) materialization: Option<CommunitySharedCountsV1>,
    pub(super) status: CommunityPassStatusV1,
    /// `H(CPS1)` of the sealed result a Seal latched (R8.4): a later Seal
    /// of the pass must be that result again.
    pub(super) sealed_result_digest: Option<Hash>,
    /// Whether the `run_pass` call that reserved the pass is still running
    /// (R8.3(3): another call gets 15).
    pub(super) live: bool,
}

impl MemoryCommunityDomainV1 {
    /// The pass reserved under `(T, reservation_operation_id)`, in any status.
    ///
    /// Records stay in the index for ever, so `unresolved_pass` scans every
    /// pass of T: O(passes of T), to revisit in A5.
    pub(super) fn pass_record(
        &self,
        timeline: TimelineId,
        reservation_operation_id: [u8; 16],
    ) -> Option<&CommunityPassRecordV1> {
        self.pass_records.get(&(timeline, reservation_operation_id))
    }

    /// T's Reserved or Sealed pass, if any: code 7 gives at most one.
    pub(super) fn unresolved_pass(&self, timeline: TimelineId) -> Option<&CommunityPassRecordV1> {
        self.pass_records
            .range((timeline, [0; 16])..=(timeline, [0xff; 16]))
            .map(|(_, record)| record)
            .find(|record| record.status.unresolved())
    }

    /// The status of the pass reserved under `(T, reservation_operation_id)`.
    #[must_use]
    pub fn pass_status(
        &self,
        timeline: TimelineId,
        reservation_operation_id: [u8; 16],
    ) -> Option<CommunityPassStatusV1> {
        self.pass_record(timeline, reservation_operation_id)
            .map(|record| record.status)
    }

    /// The CPR1 fields of the pass reserved under `(T, reservation_operation_id)`.
    #[must_use]
    pub fn pass_reservation(
        &self,
        timeline: TimelineId,
        reservation_operation_id: [u8; 16],
    ) -> Option<CommunityReservationInputV1> {
        self.pass_record(timeline, reservation_operation_id)
            .map(|record| record.reserved.reservation)
    }

    /// The counters the pass's quote was built over and the actual
    /// additions of the materialization it minted, if any.
    #[must_use]
    pub fn pass_counters(
        &self,
        timeline: TimelineId,
        reservation_operation_id: [u8; 16],
    ) -> Option<CommunityPassCountsV1> {
        self.pass_record(timeline, reservation_operation_id)
            .map(|record| CommunityPassCountsV1 {
                prior: record.prior_shared_counts,
                materialization: record.materialization,
            })
    }

    /// Whether the `run_pass` call that reserved the pass is still running.
    #[must_use]
    pub fn pass_is_live(&self, timeline: TimelineId, reservation_operation_id: [u8; 16]) -> bool {
        self.pass_record(timeline, reservation_operation_id)
            .is_some_and(|record| record.live)
    }

    /// End the `run_pass` call that reserved the pass; it stays unresolved
    /// until a terminal transition.
    pub fn end_live_call(
        &mut self,
        _seal: &'static AuthorityTrustRootSealV1,
        timeline: TimelineId,
        reservation_operation_id: [u8; 16],
    ) {
        if let Some(record) = self
            .pass_records
            .get_mut(&(timeline, reservation_operation_id))
        {
            record.live = false;
        }
    }

    /// Move a pass to `status`; only the transitions of the pass life cycle
    /// are allowed (Reserved to Sealed, Reserved or Sealed to a terminal
    /// status). Returns whether it moved.
    pub(super) fn set_pass_status(
        &mut self,
        timeline: TimelineId,
        reservation_operation_id: [u8; 16],
        status: CommunityPassStatusV1,
    ) -> bool {
        self.pass_records
            .get_mut(&(timeline, reservation_operation_id))
            .is_some_and(|record| {
                let allowed = match (record.status, status) {
                    (CommunityPassStatusV1::Reserved, CommunityPassStatusV1::Sealed) => true,
                    (from, CommunityPassStatusV1::Committed | CommunityPassStatusV1::Aborted) => {
                        from.unresolved()
                    }
                    _ => false,
                };
                if allowed {
                    record.status = status;
                    // The call outlives Seal; a terminal status ends it.
                    record.live &= status == CommunityPassStatusV1::Sealed;
                }
                allowed
            })
    }
}
