//! ADR-081 Revision 2 zero-Event WCB1 closures bound into one local cut.
//!
//! The installed local-cut owner derives one WCB1 per owned Timeline from the
//! stored admission facts before it builds LCC1, and records it with a WCR1
//! naming the cut's LCQ1 receipt. Every such closure contains unavailable
//! reference leaves, so it records structure and lineage only: no WCB1 here
//! supports an Exact Replay claim.

use crate::local_cut_commit::LocalCutReceiptV1;
use crate::local_cut_heads::{LocalCutExpectedHeadRowV1, LocalCutResultHeadRowV1};
use crate::local_cut_owner::{
    LocalCutOwnerCommitV1, LocalCutOwnerErrorV1, LocalCutOwnerRequestV1, LocalCutOwnerVerifierV1,
    LocalCutRecordingContextRowV1, PreparedLocalCutOwnerCommitV1,
};
use crate::local_cut_seal::LocalCutSealV2;
use crate::manifest_owner_admission::ManifestOwnerAdmissionSnapshotV1;
use crate::world_dependency_packing::WorldDependencyDirectoryV1;
use crate::{
    Hash, TimelineId, WorldArtifactKindV1, WorldClosureBindingInputV1, WorldClosureBindingV1,
    WorldClosureCutCoordinateV1, WorldRecordingReceiptInputV1, WorldRecordingReceiptV1,
};

/// Stored admission facts and cut inputs behind one Timeline's zero-Event WCB1.
#[derive(Clone, Copy)]
pub struct LocalCutWorldClosureSourceV1<'a> {
    /// Local-cut operation identity recorded in the WCB1.
    pub operation_id: Hash,
    /// LCS2 seal whose cut identity and digest form the cut coordinate.
    pub seal: &'a LocalCutSealV2,
    /// Current admission snapshot of the Timeline at the sealed generation.
    pub admission: &'a ManifestOwnerAdmissionSnapshotV1,
    /// Table kind-8 RLS1 digest; it must be the scope's recorded lease.
    pub retention_lease_hash: Hash,
    /// WCB1 of the last visible cut containing the Timeline, if any.
    pub predecessor_binding_hash: Option<Hash>,
    /// Genesis chain hash of the source owner's pinned Hasher.
    pub genesis_hash: Hash,
}

/// One Timeline's derived zero-Event WCB1 and the WDB1 directory it binds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalCutWorldClosureV1 {
    binding: WorldClosureBindingV1,
    directory: WorldDependencyDirectoryV1,
}

impl LocalCutWorldClosureV1 {
    /// Borrow the derived WCB1 binding.
    #[must_use]
    pub const fn binding(&self) -> &WorldClosureBindingV1 {
        &self.binding
    }

    /// Borrow the packed WDB1 directory whose root the binding names.
    #[must_use]
    pub const fn directory(&self) -> &WorldDependencyDirectoryV1 {
        &self.directory
    }
}

/// One owned Timeline's WCB1 and WCR1 recorded with a visible local cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalCutWorldRecordingV1 {
    /// ADR-081 scope of the Timeline's admitted closure.
    pub scope: Hash,
    /// WCB1 authenticated through the cut's signed kind-5 result-head row.
    pub binding: WorldClosureBindingV1,
    /// WCR1 linking the binding to the cut's LCQ1 receipt and inventory.
    pub receipt: WorldRecordingReceiptV1,
}

/// Derive one Timeline's zero-Event WCB1 from its stored admission facts.
///
/// The dependency root packs every member and reference leaf recorded for the
/// scope with each admitted EOP1/OPC1 leaf: the kind-3 lease, kind-7/8/9
/// consumer references and Required policy seeds, plus every leaf reachable
/// from them through the ADR-081 Revision 2 native edges. The coordinate is
/// `[LCS2.cut_id, 0, LCS2 digest]`; the head is empty at the genesis hash.
///
/// # Errors
/// Returns `Conflict` when the lease is not the scope's recorded RLS1,
/// `BoundExceeded` when the closure exceeds the generation's recorded read
/// limits, and `InvalidBatch` for a WCB1 that cannot be formed, such as a
/// zero predecessor.
pub fn derive_local_cut_world_closure_v1(
    source: &LocalCutWorldClosureSourceV1<'_>,
) -> Result<LocalCutWorldClosureV1, LocalCutOwnerErrorV1> {
    let timeline = &source.admission.timeline;
    let lease_leaf = timeline
        .members
        .leaves
        .iter()
        .map(|member| &member.leaf)
        .find(|leaf| {
            leaf.as_input().kind == WorldArtifactKindV1::RetentionLease
                && leaf.as_input().native_digest == source.retention_lease_hash
        })
        .ok_or(LocalCutOwnerErrorV1::Conflict)?;
    let leaves = timeline
        .members
        .leaves
        .iter()
        .map(|member| member.leaf.clone())
        .chain(
            timeline
                .policy_copies
                .iter()
                .flat_map(|copy| [copy.eop1_leaf.clone(), copy.opc1_leaf.clone()]),
        )
        .collect();
    let read_limits = source.admission.read_limits;
    let dependencies = WorldDependencyDirectoryV1::pack(timeline.scope, leaves, read_limits)
        .map_err(|_| LocalCutOwnerErrorV1::BoundExceeded)?;
    let binding = WorldClosureBindingV1::new(WorldClosureBindingInputV1 {
        timeline_id: timeline.timeline_id,
        operation_id: source.operation_id,
        cut_coordinate: cut_coordinate(source.seal),
        logical_head: 0,
        stitched_head_hash: source.genesis_hash,
        retention_lease_leaf_hash: lease_leaf.digest(),
        consumer_set_hash: timeline.wcs1.digest(),
        dependency_root_hash: dependencies.root_hash(),
        history_root_hash: None,
        predecessor_binding_hash: source.predecessor_binding_hash,
        parent_lineage_reference: None,
        read_limits,
    })
    .map_err(|_| LocalCutOwnerErrorV1::InvalidBatch)?;
    Ok(LocalCutWorldClosureV1 {
        binding,
        directory: dependencies,
    })
}

/// Check every retained recording against the request whose cut it records.
///
/// Each WCB1 must be the successor named by the matching kind-5 row and carry
/// the scope of the matching kind-14 row, so a visible cut never lacks or
/// substitutes one of its recordings.
///
/// # Errors
/// Returns `CorruptState` for a missing, extra or substituted recording.
pub fn validate_local_cut_owner_recordings_v1(
    request: &LocalCutOwnerRequestV1,
    result: &LocalCutOwnerCommitV1,
) -> Result<(), LocalCutOwnerErrorV1> {
    let rows = request
        .result_head_rows
        .iter()
        .zip(request.manifest_binding_table.rows());
    if result.recordings.len() != request.result_head_rows.len()
        || result
            .recordings
            .iter()
            .zip(rows)
            .any(|(recording, (heads, binding))| {
                recording.binding.digest() != heads.successor_wcb_hash
                    || recording.scope != binding.scope
            })
    {
        return Err(LocalCutOwnerErrorV1::CorruptState);
    }
    Ok(())
}

/// Require each recorded predecessor to be its Timeline's latest stored WCB1.
///
/// `latest_binding` reads, inside the commit transaction, the WCB1 digest of
/// the owner's last visible cut that contained the Timeline. A Timeline that
/// was removed and later re-added still chains to that binding.
///
/// # Errors
/// Returns `Conflict` when a predecessor is not the latest stored binding and
/// forwards any `latest_binding` failure.
pub fn validate_local_cut_owner_predecessors_v1(
    batch: &PreparedLocalCutOwnerCommitV1,
    mut latest_binding: impl FnMut(TimelineId) -> Result<Option<Hash>, LocalCutOwnerErrorV1>,
) -> Result<(), LocalCutOwnerErrorV1> {
    for recording in batch.recordings() {
        let binding = recording.binding.as_input();
        if latest_binding(binding.timeline_id)? != binding.predecessor_binding_hash {
            return Err(LocalCutOwnerErrorV1::Conflict);
        }
    }
    Ok(())
}

/// Derive and check every owned Timeline's zero-Event WCB1 before LCC1.
///
/// The request already matched its kind-4/kind-5 rows to their table
/// references and its kind-8 rows to the admitted Timelines in order.
pub(crate) fn derive_cut_closures(
    request: &LocalCutOwnerRequestV1,
    admissions: &[ManifestOwnerAdmissionSnapshotV1],
    verifier: &dyn LocalCutOwnerVerifierV1,
) -> Result<Vec<LocalCutWorldClosureV1>, LocalCutOwnerErrorV1> {
    let timelines = admissions
        .iter()
        .map(|admission| admission.timeline.timeline_id);
    let expected = request.expected_head_rows.iter().map(|row| row.timeline_id);
    let result = request.result_head_rows.iter().map(|row| row.timeline_id);
    if expected.ne(timelines.clone()) || result.ne(timelines) {
        return Err(LocalCutOwnerErrorV1::InvalidBatch);
    }
    let heads = request
        .expected_head_rows
        .iter()
        .zip(&request.result_head_rows);
    admissions
        .iter()
        .zip(&request.recording_context_rows)
        .zip(heads)
        .map(|((admission, context), heads)| {
            derive_cut_closure(request, admission, context, heads, verifier)
        })
        .collect()
}

/// Record each derived WCB1 with a WCR1 naming the signed LCQ1 receipt.
pub(crate) fn record_cut_closures(
    request: &LocalCutOwnerRequestV1,
    closures: &[LocalCutWorldClosureV1],
    receipt: &LocalCutReceiptV1,
) -> Vec<LocalCutWorldRecordingV1> {
    let actual_commit_receipt_digest = receipt.digest();
    closures
        .iter()
        .map(|closure| LocalCutWorldRecordingV1 {
            scope: closure.directory.scope(),
            binding: closure.binding,
            receipt: WorldRecordingReceiptV1::from_owner_digests(WorldRecordingReceiptInputV1 {
                binding_hash: closure.binding.digest(),
                operation_id: request.operation_id,
                actual_commit_receipt_digest,
                installed_inventory_generation: request.result_inventory_generation,
            }),
        })
        .collect()
}

/// Check the cut-level links of every retained WCB1/WCR1 pair.
///
/// A visible cut records exactly one pair per kind-8 row; each binding names
/// the cut coordinate, and each receipt names its binding, operation, the
/// cut's LCQ1 digest and its result inventory generation.
pub(crate) fn validate_recorded_closures(
    result: &LocalCutOwnerCommitV1,
) -> Result<(), LocalCutOwnerErrorV1> {
    let coordinate = cut_coordinate(&result.seal);
    let receipt_digest = result.receipt.digest();
    let inventory = result.commit.as_input().result_inventory_generation;
    let recording_rows = result.seal.as_input().recording_context_table.row_count();
    if result.recordings.len() as u64 != recording_rows
        || result.recordings.iter().any(|recording| {
            let binding = recording.binding.as_input();
            let receipt = recording.receipt.as_input();
            binding.cut_coordinate != coordinate
                || receipt.binding_hash != recording.binding.digest()
                || receipt.operation_id != binding.operation_id
                || receipt.actual_commit_receipt_digest != receipt_digest
                || receipt.installed_inventory_generation != inventory
        })
    {
        return Err(LocalCutOwnerErrorV1::CorruptState);
    }
    Ok(())
}

fn cut_coordinate(seal: &LocalCutSealV2) -> WorldClosureCutCoordinateV1 {
    WorldClosureCutCoordinateV1 {
        cut_id: seal.as_input().cut_id,
        partition_id: 0,
        reservation_identity: *seal.digest().as_bytes(),
    }
}

fn derive_cut_closure(
    request: &LocalCutOwnerRequestV1,
    admission: &ManifestOwnerAdmissionSnapshotV1,
    context: &LocalCutRecordingContextRowV1,
    (expected, result): (&LocalCutExpectedHeadRowV1, &LocalCutResultHeadRowV1),
    verifier: &dyn LocalCutOwnerVerifierV1,
) -> Result<LocalCutWorldClosureV1, LocalCutOwnerErrorV1> {
    let genesis_hash = verifier.source_genesis_hash(context.timeline_id)?;
    if !is_zero_event_profile(context.timeline_id, expected, result, genesis_hash) {
        return Err(LocalCutOwnerErrorV1::OwnerRejected);
    }
    if expected.predecessor_wcb_hash != context.predecessor_wcb_hash {
        return Err(LocalCutOwnerErrorV1::InvalidBatch);
    }
    let closure = derive_local_cut_world_closure_v1(&LocalCutWorldClosureSourceV1 {
        operation_id: request.operation_id,
        seal: &request.seal,
        admission,
        retention_lease_hash: context.retention_lease_hash,
        predecessor_binding_hash: context.predecessor_wcb_hash,
        genesis_hash,
    })?;
    if closure.binding.digest() == result.successor_wcb_hash {
        Ok(closure)
    } else {
        Err(LocalCutOwnerErrorV1::InvalidBatch)
    }
}

/// Whether both head rows describe an empty, non-Fork history at genesis.
fn is_zero_event_profile(
    timeline_id: TimelineId,
    expected: &LocalCutExpectedHeadRowV1,
    result: &LocalCutResultHeadRowV1,
    genesis_hash: Hash,
) -> bool {
    expected.logical_head == 0
        && expected.logical_prefix == 0
        && expected.lineage_proof_hash.is_none()
        && expected.source_timeline_id == timeline_id
        && expected.source_segment_head == 0
        && expected.source_chain_hash == genesis_hash
        && expected.stitched_chain_hash == genesis_hash
        && result.result_logical_head == 0
        && result.event_count == 0
        && result.result_source_segment_head == 0
        && result.result_source_chain_hash == genesis_hash
        && result.result_stitched_hash == genesis_hash
}
