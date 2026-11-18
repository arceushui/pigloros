//! The attempts and receipts `LocalErasureDriverV1` drives (ADR-136 §6;
//! owner decisions Q10 and Q11 of 2026-11-17 on #1431).
//!
//! Each value is a pure function of the bundle, the compiled ELP1, the
//! host-built view and the request's verified progress. The driver submits
//! what these functions build, and the signer re-derives the same values
//! before it signs, so the driver cannot choose any of them.

use pos_core::{
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceV1,
    ErasureArtifactTransitionV1, ErasureErrorV1, ErasureInventoryCategoryV1,
    ErasureInventoryResultV1, ErasureLifecycleV1, ErasureObligationV1, ErasureReceiptInputV1,
    ErasureReceiptInventoriesV1, ErasureRecordedProgressV1, ErasureReferenceV1,
    ErasureReplayClaimV1, ErasureRequestV1, ErasureRetryAdmissionInputV1, ErasureRetryAdmissionV1,
    LocalErasureDisclosureV1, LocalErasureOwnerResultV1, LocalErasureSignatureV1,
    RegisteredArtifactV1, ReplayClaimEvaluatorV1, LOCAL_ERASURE_ATTEMPT_WINDOW_V1,
};

use super::authority::LocalErasureAuthorityV1;
use super::freeze::{data_class, LOCAL_FREEZE_POSITION};
use super::{LOCAL_ERASURE_AUTO_RETRY_MAX_V1, LOCAL_ERASURE_POLICY_REFERENCE_V1};
use crate::ErasureAuthorityReadViewV1;

/// A component a driver-built receipt input leaves to core, which fills it
/// from the committed record before the receipt is previewed or admitted.
const CORE_FILLED: ErasureReferenceV1 = ErasureReferenceV1::from_digest([0; 32]);

/// The retained disclosure of a row that discloses nothing (ADR-136 §7:
/// only backup and timeline-payload rows carry `CA(ELD1)`).
const NO_DISCLOSURE: ErasureReferenceV1 = ErasureReferenceV1::from_digest([0; 32]);

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

/// The transition rule each acknowledgement class of the compiled ELP1
/// registers for its target before erasure, and whether its rows carry
/// `CA(ELD1)` as their retained disclosure (ADR-136 §5 and §7), or `None`
/// for a class the compiled ELP1 does not name.
///
/// A destroyed key removes the evidence it encrypted; a redacted artifact
/// or a committed cache generation redacts its views; a purged local replica
/// and the classes that are always negative preserve the exact claim. Only
/// the backup and timeline-payload rows disclose their retained class.
fn class_rule(ack_class: &str) -> Option<(ArtifactTransitionRuleV1, bool)> {
    match ack_class {
        "key-registry" => Some((ArtifactTransitionRuleV1::Remove, false)),
        "artifact-store" | "managed-report" | "client-cache-signal" => {
            Some((ArtifactTransitionRuleV1::RedactViews, false))
        }
        "export-recipient" | "local-replica" => {
            Some((ArtifactTransitionRuleV1::PreserveExact, false))
        }
        "timeline-payload" | "local-backup-inventory" => {
            Some((ArtifactTransitionRuleV1::PreserveExact, true))
        }
        _ => None,
    }
}

/// Whether attempt `ordinal` is due (owner decision Q10 on #1431): attempt
/// 0 always; a retry only after a latest attempt with a `transient`
/// negative, and only up to `auto_retry_max` retries, ordinals 1 to 3.
const fn attempt_due(ordinal: u64, transient: bool) -> bool {
    ordinal == 0 || (ordinal <= LOCAL_ERASURE_AUTO_RETRY_MAX_V1 && transient)
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
        let transient = ordinal != 0 && has_transient_negative(view, progress);
        if !attempt_due(ordinal, transient) {
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
            .map_or_else(
                || Some((LOCAL_FREEZE_POSITION + 1, erq1.horizon_position())),
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
    /// every command of `erq1`'s attempt is acknowledged, and its ELD1
    /// disclosures.
    ///
    /// The attempt is complete when every frozen obligation has a positive
    /// acknowledgement; its receipt then issues at the position its
    /// executed obligations reach, otherwise a partial failure issues at
    /// the attempt's deadline (ADR-136 §6). Every frozen obligation is one
    /// inventory row whose replay claim the #185 `ReplayClaimEvaluatorV1`
    /// derives (ADR-136 §7): its target registered as a required artifact
    /// of the request's data class under its class's transition rule
    /// (`class_rule`), applied when the obligation has a positive
    /// acknowledgement and retained otherwise, from `Exact`. A row carries
    /// its command as reason, its acknowledgement evidence and its own
    /// address as provenance, and, for a backup or timeline-payload row
    /// only, `CA(ELD1)` of its class as its retained disclosure. Core fills
    /// every other field from the committed record.
    ///
    /// # Errors
    /// `PolicyConflict` without an active attempt, `ScopeInvalid` for an
    /// obligation whose owner the bundle does not name or whose class the
    /// compiled ELP1 does not name, otherwise the
    /// closed evaluation or encoding error of a row.
    pub(super) fn receipt_input(
        &self,
        erq1: &ErasureRequestV1,
        progress: &ErasureRecordedProgressV1,
    ) -> Result<(ErasureReceiptInputV1, Vec<Vec<u8>>), ErasureErrorV1> {
        let data_class = data_class(erq1.scope());
        progress
            .active
            .as_ref()
            .ok_or(ErasureErrorV1::PolicyConflict)
            .and_then(|attempt| {
                progress
                    .obligations
                    .iter()
                    .map(|obligation| self.inventory_row(progress, obligation, data_class))
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

    /// The inventory row of one frozen obligation, and its ELD1 bytes when
    /// it carries one.
    fn inventory_row(
        &self,
        progress: &ErasureRecordedProgressV1,
        obligation: &ErasureObligationV1,
        data_class: ArtifactDataClassV1,
    ) -> Result<(ErasureInventoryResultV1, Option<Vec<u8>>), ErasureErrorV1> {
        let acknowledgement = progress
            .effective
            .iter()
            .find(|acknowledgement| acknowledgement.obligation() == obligation.reference());
        let target = obligation.target();
        let state = if positively_acknowledged(progress, obligation.reference()) {
            ArtifactStateV1::TransitionApplied
        } else {
            ArtifactStateV1::Retained
        };
        self.bundle
            .owners
            .iter()
            .find(|row| row.owner_ref == obligation.owner())
            .and_then(|row| class_rule(&row.ack_class).map(|rule| (row, rule)))
            .ok_or(ErasureErrorV1::ScopeInvalid)
            .and_then(|(row, (transition_rule, discloses))| {
                ReplayClaimEvaluatorV1::evaluate(
                    ErasureReplayClaimV1::Exact,
                    &[ArtifactClaimInputV1 {
                        registration: RegisteredArtifactV1::new(
                            target.artifact_class,
                            obligation.reference(),
                            data_class,
                            // `evaluate` reads no key role; only the
                            // destruction diagnostic weighs key dependencies.
                            None,
                            obligation.owner(),
                            ArtifactOptionalityV1::Required,
                            transition_rule,
                        ),
                        current_claim: ErasureReplayClaimV1::Exact,
                        state,
                    }],
                )
                .and_then(|evaluation| {
                    discloses
                        .then(|| LocalErasureDisclosureV1 {
                            ack_class: row.ack_class.clone(),
                            policy: LOCAL_ERASURE_POLICY_REFERENCE_V1,
                        })
                        .map(|disclosure| {
                            disclosure.to_canonical_cbor().and_then(|bytes| {
                                disclosure.reference().map(|reference| (reference, bytes))
                            })
                        })
                        .transpose()
                        .map(|disclosure| (evaluation.replay_claim(), disclosure))
                })
            })
            .map(|(to, disclosure)| {
                (
                    ErasureInventoryResultV1 {
                        category: obligation.category(),
                        target,
                        transition: ErasureArtifactTransitionV1 {
                            from: ErasureReplayClaimV1::Exact,
                            to,
                            reason: obligation.command_identity(),
                            owner: obligation.owner(),
                            acknowledgements: acknowledgement
                                .map_or(CORE_FILLED, ErasureAcknowledgementProvenanceV1::evidence),
                            provenance: obligation.reference(),
                        },
                        retained_disclosure: disclosure
                            .as_ref()
                            .map_or(NO_DISCLOSURE, |(reference, _)| *reference),
                    },
                    disclosure.map(|(_, bytes)| bytes),
                )
            })
    }
}

/// The receipt input of `rows`, each with its ELD1 bytes, and the distinct
/// disclosures to retain.
fn receipt_of(
    rows: Vec<(ErasureInventoryResultV1, Option<Vec<u8>>)>,
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
        disclosures.extend(disclosure);
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::erasure_local_authority::LOCAL_ERASURE_CLASSIFICATION_V1;

    #[test]
    fn every_classified_acknowledgement_class_has_a_rule() {
        for (_, _, _, ack_class) in LOCAL_ERASURE_CLASSIFICATION_V1 {
            assert!(class_rule(ack_class).is_some(), "{ack_class}");
        }
        assert_eq!(
            class_rule("key-registry"),
            Some((ArtifactTransitionRuleV1::Remove, false))
        );
        assert_eq!(
            class_rule("local-backup-inventory"),
            Some((ArtifactTransitionRuleV1::PreserveExact, true))
        );
        assert_eq!(class_rule("unclassified"), None);
    }

    #[test]
    fn only_attempt_0_and_three_transient_retries_are_due() {
        assert!(attempt_due(0, false));
        for ordinal in 1..=LOCAL_ERASURE_AUTO_RETRY_MAX_V1 {
            assert!(attempt_due(ordinal, true), "{ordinal}");
            // A permanent negative is never retried automatically.
            assert!(!attempt_due(ordinal, false), "{ordinal}");
        }
        assert_eq!(LOCAL_ERASURE_AUTO_RETRY_MAX_V1, 3);
        assert!(!attempt_due(LOCAL_ERASURE_AUTO_RETRY_MAX_V1 + 1, true));
    }
}
