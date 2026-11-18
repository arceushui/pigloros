//! The attempts and receipts `LocalErasureDriverV1` drives (ADR-136 §6;
//! owner decisions Q10 and Q11 of 2026-11-17 on #1431).
//!
//! Each value is a pure function of the bundle, the compiled ELP1, the
//! host-built view and the request's verified progress. The driver submits
//! what these functions build, and the signer re-derives the same values
//! before it signs, so the driver cannot choose any of them.

use pos_core::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceV1,
    ErasureArtifactTransitionV1, ErasureErrorV1, ErasureInventoryCategoryV1,
    ErasureInventoryResultV1, ErasureLifecycleV1, ErasureObligationV1, ErasureReceiptInputV1,
    ErasureReceiptInventoriesV1, ErasureRecordedProgressV1, ErasureReferenceV1,
    ErasureReplayClaimV1, ErasureRequestV1, ErasureRetryAdmissionInputV1, ErasureRetryAdmissionV1,
    LocalErasureDisclosureV1, LocalErasureOwnerResultV1, LocalErasureSignatureV1,
    LOCAL_ERASURE_ATTEMPT_WINDOW_V1,
};

use super::authority::LocalErasureAuthorityV1;
use super::freeze::LOCAL_FREEZE_POSITION;
use super::{LOCAL_ERASURE_AUTO_RETRY_MAX_V1, LOCAL_ERASURE_POLICY_REFERENCE_V1};
use crate::ErasureAuthorityReadViewV1;

/// A component a driver-built receipt input leaves to core, which fills it
/// from the committed record before the receipt is previewed or admitted.
const CORE_FILLED: ErasureReferenceV1 = ErasureReferenceV1::from_digest([0; 32]);

/// Whether the effective acknowledgement inventory of `progress` holds a
/// positive acknowledgement of `obligation`.
fn positively_acknowledged(
    progress: &ErasureRecordedProgressV1,
    obligation: ErasureReferenceV1,
) -> bool {
    progress.effective.iter().any(|acknowledgement| {
        acknowledgement.obligation() == obligation
            && acknowledgement.outcome() == ErasureAcknowledgementOutcomeV1::Acknowledged
    })
}

/// Whether the latest attempt of `progress` has a transient negative owner
/// result (Q10).
///
/// The effective inventory holds every acknowledgement of the latest
/// attempt and only the positive ones of earlier attempts, so each negative
/// acknowledgement in it is the latest attempt's. The only transient code
/// the Local executor emits is `ReplicaTimeout`; every other negative is
/// permanent and never retried automatically.
fn has_transient_negative(
    view: &dyn ErasureAuthorityReadViewV1,
    progress: &ErasureRecordedProgressV1,
) -> bool {
    progress
        .effective
        .iter()
        .filter(|acknowledgement| {
            acknowledgement.outcome() == ErasureAcknowledgementOutcomeV1::Negative
        })
        .any(|acknowledgement| {
            view.retained_object(acknowledgement.evidence())
                .and_then(|bytes| LocalErasureSignatureV1::from_canonical_cbor(&bytes).ok())
                .and_then(|signature| view.retained_object(signature.signed_digest))
                .and_then(|bytes| LocalErasureOwnerResultV1::from_canonical_cbor(&bytes).ok())
                .is_some_and(|result| result.error == Some(ErasureErrorV1::ReplicaTimeout))
        })
}

/// The replay claim a positive owner result leaves its target with: a
/// destroyed key leaves the artifacts it encrypted missing, a redacted
/// artifact or a committed cache generation leaves only redacted views,
/// and a purged local replica changes no replay claim.
const fn claim_after(category: ErasureInventoryCategoryV1) -> ErasureReplayClaimV1 {
    match category {
        ErasureInventoryCategoryV1::Key => ErasureReplayClaimV1::UnverifiableArtifactsMissing,
        ErasureInventoryCategoryV1::Artifact => {
            ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews
        }
        ErasureInventoryCategoryV1::Replica | ErasureInventoryCategoryV1::Backup => {
            ErasureReplayClaimV1::Exact
        }
    }
}

impl LocalErasureAuthorityV1 {
    /// The attempt of `erq1` due after the completed attempts of
    /// `progress`, which has no active attempt, with the ELB1 it pins.
    ///
    /// Attempt 0 is always due. A retry is due only after a partial failure
    /// whose latest attempt has a transient negative, and only up to
    /// `auto_retry_max` retries, ordinals 1 to 3 (Q10); a permanent
    /// negative is never retried automatically, and V1 has no manual retry.
    /// The attempt carries every obligation without a positive
    /// acknowledgement, the ADR-136 §6 positions, the request's ERAZ1 and
    /// ELP1, and the bundle current now, which `admit_attempt` requires to
    /// be retained.
    ///
    /// # Errors
    /// `PolicyConflict` when the positions overflow; otherwise the closed
    /// encoding error of the attempt or bundle.
    pub(super) fn next_attempt(
        &self,
        view: &dyn ErasureAuthorityReadViewV1,
        erq1: &ErasureRequestV1,
        progress: &ErasureRecordedProgressV1,
    ) -> Result<Option<(ErasureRetryAdmissionV1, Vec<u8>)>, ErasureErrorV1> {
        let ordinal = progress.completed_attempt_count;
        if ordinal != 0
            && (ordinal > LOCAL_ERASURE_AUTO_RETRY_MAX_V1
                || !has_transient_negative(view, progress))
        {
            return Ok(None);
        }
        let unresolved = progress
            .obligations
            .iter()
            .filter(|obligation| !positively_acknowledged(progress, obligation.reference()))
            .copied()
            .collect::<Vec<_>>();
        progress
            .latest_receipt
            .as_ref()
            .map_or(
                Some((LOCAL_FREEZE_POSITION + 1, erq1.horizon_position())),
                |receipt| {
                    receipt
                        .issue_position()
                        .checked_add(1)
                        .and_then(|admitted| {
                            admitted
                                .checked_add(LOCAL_ERASURE_ATTEMPT_WINDOW_V1)
                                .map(|deadline| (admitted, deadline))
                        })
                },
            )
            .zip(self.bundle_reference)
            .ok_or(ErasureErrorV1::PolicyConflict)
            .and_then(|((admitted_position, deadline_position), trust)| {
                ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
                    request: erq1.reference(),
                    attempt_ordinal: ordinal,
                    source_receipt: progress
                        .latest_receipt
                        .as_ref()
                        .map(pos_core::ErasureReceiptV1::receipt_digest),
                    unresolved_obligations: unresolved
                        .iter()
                        .map(ErasureObligationV1::reference)
                        .collect(),
                    command_identities: unresolved
                        .iter()
                        .map(ErasureObligationV1::command_identity)
                        .collect(),
                    policy: erq1.policy(),
                    trust,
                    admitted_position,
                    deadline_position,
                    authorization_provenance: erq1.authorization(),
                })
            })
            .and_then(|admission| {
                self.bundle
                    .to_canonical_cbor()
                    .map(|bundle| Some((admission, bundle)))
            })
    }

    /// The receipt input that closes the active attempt of `progress` once
    /// every command of it is acknowledged, and its ELD1 disclosures.
    ///
    /// The attempt is complete when every frozen obligation has a positive
    /// acknowledgement; its receipt then issues at the position its
    /// executed obligations reach, otherwise a partial failure issues at
    /// the attempt's deadline (ADR-136 §6). Every frozen obligation is one
    /// inventory row, from `Exact` to the claim its positive result leaves
    /// (`claim_after`) or unchanged, carrying its command as reason, its
    /// acknowledgement evidence and its own address as provenance, and
    /// `CA(ELD1)` of its acknowledgement class as its retained disclosure.
    /// Core fills every other field from the committed record.
    ///
    /// # Errors
    /// `PolicyConflict` without an active attempt, `ScopeInvalid` for an
    /// obligation whose owner the bundle does not name, otherwise the
    /// closed encoding error of a disclosure.
    pub(super) fn receipt_input(
        &self,
        progress: &ErasureRecordedProgressV1,
    ) -> Result<(ErasureReceiptInputV1, Vec<Vec<u8>>), ErasureErrorV1> {
        progress
            .active
            .as_ref()
            .ok_or(ErasureErrorV1::PolicyConflict)
            .and_then(|attempt| {
                progress
                    .obligations
                    .iter()
                    .map(|obligation| self.inventory_row(progress, obligation))
                    .collect::<Result<Vec<_>, _>>()
                    .map(|rows| {
                        let complete = progress.obligations.iter().all(|obligation| {
                            positively_acknowledged(progress, obligation.reference())
                        });
                        let executed = u64::try_from(attempt.unresolved_obligations().len())
                            .unwrap_or(u64::MAX);
                        let (lifecycle, issue_position) = if complete {
                            (
                                ErasureLifecycleV1::Complete,
                                attempt.admitted_position().saturating_add(executed),
                            )
                        } else {
                            (
                                ErasureLifecycleV1::PartialFailure,
                                attempt.deadline_position(),
                            )
                        };
                        receipt_of(rows, lifecycle, issue_position)
                    })
            })
    }

    /// The inventory row of one frozen obligation and its ELD1 bytes.
    fn inventory_row(
        &self,
        progress: &ErasureRecordedProgressV1,
        obligation: &ErasureObligationV1,
    ) -> Result<(ErasureInventoryResultV1, Vec<u8>), ErasureErrorV1> {
        let acknowledgement = progress
            .effective
            .iter()
            .find(|acknowledgement| acknowledgement.obligation() == obligation.reference());
        let to = if positively_acknowledged(progress, obligation.reference()) {
            claim_after(obligation.category())
        } else {
            ErasureReplayClaimV1::Exact
        };
        self.bundle
            .owners
            .iter()
            .find(|row| row.owner_ref == obligation.owner())
            .ok_or(ErasureErrorV1::ScopeInvalid)
            .and_then(|row| {
                let disclosure = LocalErasureDisclosureV1 {
                    ack_class: row.ack_class.clone(),
                    policy: LOCAL_ERASURE_POLICY_REFERENCE_V1,
                };
                disclosure.to_canonical_cbor().and_then(|bytes| {
                    disclosure
                        .reference()
                        .map(|retained_disclosure| (retained_disclosure, bytes))
                })
            })
            .map(|(retained_disclosure, bytes)| {
                (
                    ErasureInventoryResultV1 {
                        category: obligation.category(),
                        target: obligation.target(),
                        transition: ErasureArtifactTransitionV1 {
                            from: ErasureReplayClaimV1::Exact,
                            to,
                            reason: obligation.command_identity(),
                            owner: obligation.owner(),
                            acknowledgements: acknowledgement
                                .map_or(CORE_FILLED, ErasureAcknowledgementProvenanceV1::evidence),
                            provenance: obligation.reference(),
                        },
                        retained_disclosure,
                    },
                    bytes,
                )
            })
    }
}

/// The receipt input of `rows`, each with its ELD1 bytes, and the distinct
/// disclosures to retain.
fn receipt_of(
    rows: Vec<(ErasureInventoryResultV1, Vec<u8>)>,
    lifecycle: ErasureLifecycleV1,
    issue_position: u64,
) -> (ErasureReceiptInputV1, Vec<Vec<u8>>) {
    let mut inventories = ErasureReceiptInventoriesV1 {
        artifacts: Vec::new(),
        keys: Vec::new(),
        replicas: Vec::new(),
        backups: Vec::new(),
    };
    let mut disclosures = Vec::new();
    for (row, disclosure) in rows {
        match row.category {
            ErasureInventoryCategoryV1::Artifact => inventories.artifacts.push(row),
            ErasureInventoryCategoryV1::Key => inventories.keys.push(row),
            ErasureInventoryCategoryV1::Replica => inventories.replicas.push(row),
            ErasureInventoryCategoryV1::Backup => inventories.backups.push(row),
        }
        disclosures.push(disclosure);
    }
    disclosures.sort_unstable();
    disclosures.dedup();
    (
        ErasureReceiptInputV1 {
            request: CORE_FILLED,
            terminal_state: CORE_FILLED,
            coordinator: CORE_FILLED,
            lifecycle,
            freeze_position: 0,
            acknowledgements: Vec::new(),
            frozen_targets: Vec::new(),
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            inventories,
            replay_claim: ErasureReplayClaimV1::Exact,
            policy: CORE_FILLED,
            trust: CORE_FILLED,
            provenance: CORE_FILLED,
            issue_position,
            signature: CORE_FILLED,
            receipt_digest: CORE_FILLED,
        },
        disclosures,
    )
}
