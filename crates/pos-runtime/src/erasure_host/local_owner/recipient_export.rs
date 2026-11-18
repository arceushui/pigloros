//! The `export-recipient` owner of the single-host erasure executor: the
//! ADR-138 recipient-export withdrawal (§5 and §7; ticket #1446).
//!
//! One dispatched command resolves its `ELXR1` target to one publication
//! through the request's effective scope Timelines, then runs T1, the owner
//! step with T2, and T3 through the store port. A positive outcome is an
//! ELO1 bound to the withdrawal's ELXW1 disposition; every other outcome is
//! the permanent negative `ArtifactDeletionFailed`.
//!
//! The signer re-derives a positive ELO1 from the withdrawn row a snapshot
//! returns for the command's target, with the ELXW1 retained at its
//! recorded disposition.

use std::collections::BTreeMap;

use pos_core::{
    local_erasure_export_recipient_v1, ErasureErrorV1, ErasureHostErrorV1, ErasureOwnerCommandV1,
    ErasureOwnerResultV1, ErasureRecoveryLimitsV1, ErasureReferenceV1,
    LocalErasureRecipientExportWithdrawalV1, LocalOwnerEffectV1, OwnerIdV1,
    RecipientExportPublicationRowV1, RecipientExportWithdrawalBindingV1,
    RecipientExportWithdrawalStateV1, TimelineId, ERASURE_MAX_OBLIGATIONS_PER_CATEGORY,
};

use super::super::{map_erasure_error, ErasureHostStore};
use super::{committed, negative, owner_work, scope_timelines, OwnerWorkV1};

/// The capture status of a retracted row whose objects are captured
/// (ADR-138 §3).
const CAPTURED: u8 = 0;

/// The visible and retracted recipient-export publications by their `ELXR1`
/// target, with the scope Timelines they were scanned for.
///
/// One command sender keeps one such scan; the executor's replay and each
/// driver step use one sender, so a replay pass scans its scope once.
pub(in crate::erasure_host) type ExportPublicationsV1 = (
    Vec<TimelineId>,
    BTreeMap<ErasureReferenceV1, RecipientExportPublicationRowV1>,
);

/// The withdrawn row of one `ELXR1` target with the ELXW1 retained at its
/// recorded disposition.
pub(super) struct RecordedWithdrawalV1 {
    /// `CA("ELXR1", [export_id, grantee_owner])` of the row.
    pub(super) target: ErasureReferenceV1,
    /// `CA(ELO1)` of the withdrawal's first commit.
    pub(super) committed_elo1: Option<ErasureReferenceV1>,
    /// The decoded ELXW1.
    pub(super) record: LocalErasureRecipientExportWithdrawalV1,
    /// The canonical ELXW1 bytes.
    pub(super) elxw1: Vec<u8>,
}

/// ADR-138 §5 steps 0 to 3 for `command`, inside the Erasure Host Timeline
/// fence, with the sender's publication scan in `publications`.
///
/// A scope that cannot be read is a host error, never a permanent
/// negative: a dispatched request's scope is committed, so this is a store
/// that cannot be read, as for `registered_dependencies`.
///
/// # Errors
/// [`ErasureHostErrorV1::Conflict`] unless `command` is a dispatched
/// `export-recipient` command; otherwise the payload-free error of a scope
/// that cannot be read or an owner result that could not be made durable.
pub(super) fn withdrawn_export(
    store: &mut dyn ErasureHostStore,
    command: &ErasureOwnerCommandV1,
    publications: &mut Option<ExportPublicationsV1>,
) -> Result<ErasureOwnerResultV1, ErasureHostErrorV1> {
    owner_work(store, command)
        .and_then(|(work, _)| {
            (work == OwnerWorkV1::RecipientExportWithdrawal)
                .then_some(())
                .ok_or(ErasureHostErrorV1::Conflict)
        })
        .and_then(|()| scope_timelines(store, command.request))
        .and_then(|timelines| {
            let target = command.destruction.target.artifact_digest;
            let Some((export_id, grantee_owner)) =
                resolved_export(store, target, &timelines, publications)
            else {
                return negative(store, command, ErasureErrorV1::ArtifactDeletionFailed);
            };
            withdrawal_steps(store, command, export_id, &grantee_owner)
        })
}

/// Step 0: the export identity and grantee owner of the publication
/// `target` names among `timelines`, or `None`.
///
/// The sender scans the publications of `timelines` once into
/// `publications`, keyed by that scope; every later target of the same
/// scope resolves from that one map, and another scope scans again. Every
/// mapped row is a publication of the scope. A target the map does not
/// hold, a withdrawn publication whose catalog row is gone or a target
/// outside the scope, falls back to `recipient_export_by_target`, the
/// indexed withdrawal row first. A failed scan is not kept, so the next
/// target scans again; a failed lookup, a malformed row or an over-bound
/// scan included, resolves nothing: the command is then the permanent
/// negative (#1446 journal).
pub(in crate::erasure_host) fn resolved_export(
    store: &mut dyn ErasureHostStore,
    target: ErasureReferenceV1,
    timelines: &[TimelineId],
    publications: &mut Option<ExportPublicationsV1>,
) -> Option<([u8; 16], OwnerIdV1)> {
    if publications
        .as_ref()
        .is_none_or(|(scope, _)| scope.as_slice() != timelines)
    {
        *publications =
            scanned_publications(store, timelines).map(|scanned| (timelines.to_vec(), scanned));
    }
    publications
        .as_ref()
        .and_then(|(_, scanned)| scanned.get(&target))
        .map(|row| (row.export_id, row.grantee_owner))
        .or_else(|| {
            store
                .recipient_export_by_target(target, timelines)
                .ok()
                .flatten()
        })
}

/// The publications of `timelines` by `ELXR1` target, at most one
/// category's worth (ADR-138 §5); `None` when the scan fails.
fn scanned_publications(
    store: &mut dyn ErasureHostStore,
    timelines: &[TimelineId],
) -> Option<BTreeMap<ErasureReferenceV1, RecipientExportPublicationRowV1>> {
    store
        .recipient_export_publications(timelines, ERASURE_MAX_OBLIGATIONS_PER_CATEGORY)
        .ok()
        .map(|rows| {
            rows.into_iter()
                .filter_map(|row| {
                    local_erasure_export_recipient_v1(row.export_id, &row.grantee_owner)
                        .ok()
                        .map(|target| (target, row))
                })
                .collect()
        })
}

/// Steps 1 to 3 for the resolved publication `export_id` of
/// `grantee_owner` (ADR-138 §5 and §7).
fn withdrawal_steps(
    store: &mut dyn ErasureHostStore,
    command: &ErasureOwnerCommandV1,
    export_id: [u8; 16],
    grantee_owner: &OwnerIdV1,
) -> Result<ErasureOwnerResultV1, ErasureHostErrorV1> {
    match store.begin_recipient_export_withdrawal(export_id, grantee_owner) {
        Ok(RecipientExportWithdrawalStateV1::Withdrawn { elxw1, .. }) => committed(
            store,
            command,
            None,
            LocalOwnerEffectV1::RecipientExportWithdrawal(elxw1),
        ),
        Ok(RecipientExportWithdrawalStateV1::Retracted {
            capture_status: CAPTURED,
            ..
        }) => match store.delete_recipient_export_ciphertext(export_id) {
            // The binding's fields were validated when the row was read, so
            // its ELXW1 always encodes; an encoding error would be a host
            // error that commits nothing, never a positive.
            Ok(binding) => withdrawal_record(command, &binding)
                .map_err(map_erasure_error)
                .and_then(|effect| committed(store, command, None, effect)),
            Err(_) => negative(store, command, ErasureErrorV1::ArtifactDeletionFailed),
        },
        Ok(RecipientExportWithdrawalStateV1::Retracted { .. }) | Err(_) => {
            negative(store, command, ErasureErrorV1::ArtifactDeletionFailed)
        }
    }
}

/// The ELXW1 of `command` over the captured `binding` of the deleted
/// objects.
fn withdrawal_record(
    command: &ErasureOwnerCommandV1,
    binding: &RecipientExportWithdrawalBindingV1,
) -> Result<LocalOwnerEffectV1, ErasureErrorV1> {
    LocalErasureRecipientExportWithdrawalV1 {
        request: command.request,
        command: command.destruction.command,
        export_id: binding.export_id,
        timeline_id: binding.timeline_id,
        grantee_owner: binding.grantee_owner,
        ciphertext_digest: binding.ciphertext_digest,
        ciphertext_length: binding.ciphertext_length,
        directory_identity: binding.directory_identity,
        final_identity: binding.final_identity,
    }
    .to_canonical_cbor()
    .map(LocalOwnerEffectV1::RecipientExportWithdrawal)
}

/// The withdrawn rows of `targets` in one snapshot, each with the ELXW1
/// retained at its disposition. A disposition that addresses no retained,
/// canonical ELXW1 of exactly that address is no withdrawal evidence.
///
/// # Errors
/// The payload-free error of a snapshot that cannot be read.
pub(super) fn recorded_withdrawals(
    store: &mut dyn ErasureHostStore,
    limits: ErasureRecoveryLimitsV1,
    targets: &[ErasureReferenceV1],
) -> Result<Vec<RecordedWithdrawalV1>, ErasureHostErrorV1> {
    store
        .erasure_authority_snapshot_with_limits(limits, targets)
        .map_err(map_erasure_error)
        .map(|snapshot| {
            snapshot
                .recipient_export_withdrawals()
                .iter()
                .filter_map(|row| {
                    row.disposition
                        .and_then(|disposition| retained_withdrawal(&*store, disposition))
                        .map(|(record, elxw1)| RecordedWithdrawalV1 {
                            target: row.target,
                            committed_elo1: row.committed_elo1,
                            record,
                            elxw1,
                        })
                })
                .collect()
        })
}

/// The canonical ELXW1 retained at `disposition`, when its content address
/// is `disposition`.
fn retained_withdrawal(
    store: &dyn ErasureHostStore,
    disposition: ErasureReferenceV1,
) -> Option<(LocalErasureRecipientExportWithdrawalV1, Vec<u8>)> {
    store.read_object(disposition).ok().and_then(|elxw1| {
        LocalErasureRecipientExportWithdrawalV1::from_canonical_cbor(&elxw1)
            .ok()
            .filter(|record| record.reference() == Ok(disposition))
            .map(|record| (record, elxw1))
    })
}

/// ADR-138 §7's signer rules for the positive ELO1 `owner_result` of
/// `command` bound to `recorded`'s disposition: the ELXW1's recomputed
/// `ELXR1` is the row's target, which the snapshot selected as the
/// obligation's target; its Timeline lies in the request's effective scope
/// `timelines`, the ERSC1 Timelines and its ERSE1 children; and, only for
/// the ELO1 that first committed the withdrawal, its command is the
/// ELXW1's. A later command's or another request's ELO1 bound to the same
/// disposition carries its own command.
pub(super) fn withdrawal_bound(
    recorded: &RecordedWithdrawalV1,
    command: &ErasureOwnerCommandV1,
    owner_result: ErasureReferenceV1,
    timelines: &[TimelineId],
) -> bool {
    let record = &recorded.record;
    local_erasure_export_recipient_v1(record.export_id, &record.grantee_owner)
        == Ok(recorded.target)
        && timelines.contains(&record.timeline_id)
        && (recorded.committed_elo1 != Some(owner_result)
            || record.command == command.destruction.command)
}
