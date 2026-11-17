//! ADR-136 §4a and §5 core seams (#1428): the recorded progress read, the
//! receipt preview that shares finalize's normalization, and the execution
//! port that turns one dispatched command into a durable ELO1 owner result.

#[path = "support/coordinator.rs"]
pub mod coordinator_support;
#[path = "support/erasure.rs"]
pub mod erasure_support;

use coordinator_support::{PublicCoordinatorPort as PublicPort, PublicCoordinatorPortConfig};
use erasure_support::{
    obligation as fixture_obligation, reference, replay_target, request as fixture_request,
    retry_admission as fixture_retry_admission, RequestFixtureInput, RetryAdmissionFixture,
};
use pos_core::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementV1, ErasureArtifactTransitionV1,
    ErasureAuthorityExecutionV1, ErasureCoordinatorStateMachineV1, ErasureDestructionCommandV1,
    ErasureErrorV1, ErasureInventoryCategoryV1, ErasureInventoryResultV1, ErasureLifecycleV1,
    ErasureObligationV1, ErasureOwnerCommandV1, ErasureOwnerResultV1, ErasurePersistencePortV1,
    ErasureReceiptInputV1, ErasureReceiptInventoriesV1, ErasureReceiptV1,
    ErasureRecordedProgressReadV1, ErasureRecordedProgressV1, ErasureReferenceV1,
    ErasureReplayClaimV1, ErasureRequestV1, ErasureRequiredTargetV1, ErasureRetryAdmissionV1,
    ErasureScopeV1, ErasureStateTransitionV1, LocalErasureNegativeResultV1,
    LocalErasureOwnerResultV1, LocalOwnerEffectV1, PreparedLocalOwnerEffectV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Coordinator = ErasureCoordinatorStateMachineV1<PublicPort>;

const ATTEMPT_DEADLINE: u64 = 20;
const RETRY_DEADLINE: u64 = 30;

fn request() -> Result<ErasureRequestV1, ErasureErrorV1> {
    fixture_request(RequestFixtureInput {
        request: reference(1),
        subject: reference(2),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors: vec![reference(7)],
        requester: reference(3),
        authorization: reference(4),
        policy: reference(5),
        request_position: 9,
        horizon_position: 10,
        provenance: reference(6),
    })
}

fn targets() -> Vec<ErasureRequiredTargetV1> {
    let mut targets = vec![replay_target(10), replay_target(20)];
    targets.sort_unstable();
    targets
}

/// One obligation per target, ordered by reference as ERRA1 lists them.
fn obligations(request: ErasureReferenceV1) -> Result<Vec<ErasureObligationV1>, ErasureErrorV1> {
    targets()
        .into_iter()
        .map(|target| fixture_obligation(request, target))
        .collect::<Result<Vec<_>, _>>()
        .map(|mut obligations| {
            obligations.sort_by_key(ErasureObligationV1::reference);
            obligations
        })
}

fn adapter_config() -> PublicCoordinatorPortConfig {
    PublicCoordinatorPortConfig {
        targets: targets(),
        fail_commits: false,
        policy: reference(5),
        trust: reference(3),
        scope_member: reference(7),
        freeze_evidence: reference(9),
        lineage_rule: None,
        freeze_rejection: None,
        operation_fault: None,
        attempt_reservation_admission: None,
    }
}

/// A coordinator over a fresh public port, frozen with one obligation per
/// target, and an adapter handle sharing its storage.
fn frozen(request: &ErasureRequestV1) -> Result<(Coordinator, PublicPort), ErasureErrorV1> {
    let port = PublicPort::new(adapter_config());
    let adapter = port.clone();
    let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
    coordinator.submit(request.clone(), request.provenance())?;
    coordinator.authorize(request.reference(), reference(9))?;
    coordinator.freeze_inventory(
        request.reference(),
        &ErasureStateTransitionV1 {
            lifecycle: ErasureLifecycleV1::AccessFrozen,
            freeze_position: Some(10),
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            acknowledged_targets: Vec::new(),
            replay_claim: ErasureReplayClaimV1::Exact,
            provenance: reference(9),
        },
    )?;
    Ok((coordinator, adapter))
}

fn admission(
    request: ErasureReferenceV1,
    ordinal: u64,
    source: Option<&ErasureReceiptV1>,
    unresolved: &[ErasureObligationV1],
) -> Result<ErasureRetryAdmissionV1, ErasureErrorV1> {
    let (admitted_position, deadline_position) = if ordinal == 0 {
        (11, ATTEMPT_DEADLINE)
    } else {
        (ATTEMPT_DEADLINE + 1, RETRY_DEADLINE)
    };
    fixture_retry_admission(RetryAdmissionFixture {
        request,
        attempt_ordinal: ordinal,
        source_receipt: source.map(ErasureReceiptV1::receipt_digest),
        obligations: unresolved,
        policy: reference(5),
        trust: reference(3),
        admitted_position,
        deadline_position,
        authorization_provenance: reference(9),
    })
}

fn receipt_input(issue_position: u64, signature: ErasureReferenceV1) -> ErasureReceiptInputV1 {
    let artifacts = targets()
        .into_iter()
        .map(|target| ErasureInventoryResultV1 {
            category: ErasureInventoryCategoryV1::Artifact,
            target,
            transition: ErasureArtifactTransitionV1 {
                from: ErasureReplayClaimV1::Exact,
                to: ErasureReplayClaimV1::StructuralOnly,
                reason: reference(30),
                owner: target.replica_id,
                acknowledgements: reference(31),
                provenance: reference(32),
            },
            retained_disclosure: reference(33),
        })
        .collect();
    ErasureReceiptInputV1 {
        request: reference(0),
        terminal_state: reference(0),
        coordinator: reference(0),
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: 0,
        acknowledgements: Vec::new(),
        frozen_targets: Vec::new(),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        inventories: ErasureReceiptInventoriesV1 {
            artifacts,
            keys: Vec::new(),
            replicas: Vec::new(),
            backups: Vec::new(),
        },
        // The claim the inventories reach, as an exact retry re-sends it.
        replay_claim: ErasureReplayClaimV1::StructuralOnly,
        policy: reference(0),
        trust: reference(0),
        provenance: reference(0),
        issue_position,
        signature,
        receipt_digest: reference(0),
    }
}

const fn acknowledgement(
    obligation: &ErasureObligationV1,
    evidence: ErasureReferenceV1,
    outcome: ErasureAcknowledgementOutcomeV1,
) -> ErasureAcknowledgementV1 {
    ErasureAcknowledgementV1 {
        obligation: obligation.reference(),
        target: obligation.target(),
        owner: obligation.owner(),
        evidence,
        outcome,
    }
}

/// The verified progress, read as a host reads it: through the persistence
/// port as a trait object, under the host's own verifiers.
fn progress(
    adapter: &PublicPort,
    request: ErasureReferenceV1,
) -> Result<Option<ErasureRecordedProgressV1>, ErasureErrorV1> {
    let port: &dyn ErasurePersistencePortV1 = adapter;
    port.recorded_progress(adapter, adapter, request)
}

fn recorded(
    adapter: &PublicPort,
    request: ErasureReferenceV1,
) -> Result<ErasureRecordedProgressV1, Box<dyn std::error::Error>> {
    Ok(progress(adapter, request)?.ok_or("no recorded progress")?)
}

/// `(obligation, attempt, outcome, evidence)` of each effective
/// acknowledgement, in the read's order.
fn effective(progress: &ErasureRecordedProgressV1) -> Vec<EffectiveRowV1> {
    progress
        .effective
        .iter()
        .map(|value| {
            (
                value.obligation(),
                value.attempt(),
                value.outcome(),
                value.evidence(),
            )
        })
        .collect()
}

/// Preview, then finalize, `input`: the two receipts are the same bytes and
/// the preview committed nothing.
fn preview_then_finalize(
    coordinator: &mut Coordinator,
    adapter: &PublicPort,
    request: ErasureReferenceV1,
    input: &ErasureReceiptInputV1,
) -> Result<ErasureReceiptV1, Box<dyn std::error::Error>> {
    let manifest = adapter.current_manifest(request);
    let before = progress(adapter, request)?;
    let previewed = coordinator.preview_receipt(request, input.clone())?;
    assert_eq!(adapter.current_manifest(request), manifest);
    assert_eq!(progress(adapter, request)?, before);
    // A second preview reads the same, uncached record.
    assert_eq!(
        coordinator.preview_receipt(request, input.clone())?,
        previewed
    );
    let receipt = coordinator.finalize(request, input.clone())?;
    assert_eq!(previewed.to_canonical_cbor()?, receipt.to_canonical_cbor()?);
    assert_ne!(adapter.current_manifest(request), manifest);
    // After the commit, the preview is finalize's exact retry.
    assert_eq!(
        coordinator.preview_receipt(request, input.clone())?,
        receipt
    );
    Ok(receipt)
}

type EffectiveRowV1 = (
    ErasureReferenceV1,
    ErasureReferenceV1,
    ErasureAcknowledgementOutcomeV1,
    ErasureReferenceV1,
);

/// Run attempt 0 to a partial failure, one positive and one negative
/// acknowledgement, checking the recorded progress at every step. Returns
/// its receipt and its effective acknowledgements.
fn partially_failed(
    coordinator: &mut Coordinator,
    adapter: &PublicPort,
    request: ErasureReferenceV1,
    obligations: &[ErasureObligationV1],
) -> Result<(ErasureReceiptV1, Vec<EffectiveRowV1>), Box<dyn std::error::Error>> {
    let first = admission(request, 0, None, obligations)?;
    coordinator.dispatch_destruction(request, &first)?;
    assert_eq!(recorded(adapter, request)?.active, Some(first.clone()));
    let positive = ErasureAcknowledgementOutcomeV1::Acknowledged;
    let negative = ErasureAcknowledgementOutcomeV1::Negative;
    coordinator.acknowledge(
        request,
        acknowledgement(&obligations[0], reference(41), positive),
    )?;
    coordinator.acknowledge(
        request,
        acknowledgement(&obligations[1], reference(42), negative),
    )?;
    let attempted = vec![
        (
            obligations[0].reference(),
            first.reference(),
            positive,
            reference(41),
        ),
        (
            obligations[1].reference(),
            first.reference(),
            negative,
            reference(42),
        ),
    ];
    assert_eq!(effective(&recorded(adapter, request)?), attempted);
    // An incomplete attempt issues no receipt before its deadline.
    assert_eq!(
        coordinator
            .preview_receipt(request, receipt_input(ATTEMPT_DEADLINE - 1, reference(40)))
            .map(drop),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let partial = preview_then_finalize(
        coordinator,
        adapter,
        request,
        &receipt_input(ATTEMPT_DEADLINE, reference(40)),
    )?;
    assert_eq!(partial.lifecycle(), ErasureLifecycleV1::PartialFailure);
    // The exact retry refuses another signature.
    assert_eq!(
        coordinator
            .preview_receipt(request, receipt_input(ATTEMPT_DEADLINE, reference(43)))
            .map(drop),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let after_partial = recorded(adapter, request)?;
    let after_partial_effective = effective(&after_partial);
    assert_eq!(
        (
            after_partial.active,
            after_partial.completed_attempt_count,
            after_partial.latest_receipt,
            after_partial_effective,
        ),
        (None, 1, Some(partial.clone()), attempted.clone())
    );
    Ok((partial, attempted))
}

#[test]
fn recorded_progress_and_preview_follow_every_committed_step() -> TestResult {
    let request = request()?;
    let id = request.reference();
    let obligations = obligations(id)?;
    let (mut coordinator, adapter) = frozen(&request)?;
    assert_eq!(progress(&PublicPort::new(adapter_config()), id)?, None);
    let at_freeze = recorded(&adapter, id)?;
    let mut frozen_obligations = at_freeze.obligations;
    frozen_obligations.sort_by_key(ErasureObligationV1::reference);
    assert_eq!(frozen_obligations, obligations);
    assert_eq!(
        (
            at_freeze.effective.len(),
            at_freeze.active,
            at_freeze.completed_attempt_count,
            at_freeze.latest_receipt,
        ),
        (0, None, 0, None)
    );
    // Before any attempt there is nothing to preview, as for finalize.
    assert_eq!(
        coordinator
            .preview_receipt(id, receipt_input(ATTEMPT_DEADLINE, reference(40)))
            .map(drop),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let (partial, attempted) = partially_failed(&mut coordinator, &adapter, id, &obligations)?;

    // Attempt 1 retries the negative obligation; only the positive
    // acknowledgement of attempt 0 stays effective.
    let retry = admission(id, 1, Some(&partial), &obligations[1..])?;
    coordinator.dispatch_destruction(id, &retry)?;
    let retrying = recorded(&adapter, id)?;
    assert_eq!(retrying.active, Some(retry.clone()));
    assert_eq!(effective(&retrying), attempted[..1].to_vec());
    let positive = ErasureAcknowledgementOutcomeV1::Acknowledged;
    coordinator.acknowledge(
        id,
        acknowledgement(&obligations[1], reference(44), positive),
    )?;
    let retried = preview_then_finalize(
        &mut coordinator,
        &adapter,
        id,
        &receipt_input(ATTEMPT_DEADLINE + 2, reference(45)),
    )?;
    assert_eq!(retried.lifecycle(), ErasureLifecycleV1::Complete);
    let done = recorded(&adapter, id)?;
    let done_effective = effective(&done);
    assert_eq!(
        (
            done.active,
            done.completed_attempt_count,
            done.latest_receipt,
            done_effective,
        ),
        (
            None,
            2,
            Some(retried),
            vec![
                attempted[0],
                (
                    obligations[1].reference(),
                    retry.reference(),
                    positive,
                    reference(44)
                ),
            ]
        )
    );
    Ok(())
}

#[test]
fn recorded_progress_and_preview_refuse_an_unrecoverable_record() -> TestResult {
    let request = request()?;
    let id = request.reference();
    let (mut coordinator, adapter) = frozen(&request)?;
    // An unknown request has no record to preview.
    assert_eq!(
        coordinator
            .preview_receipt(
                reference(99),
                receipt_input(ATTEMPT_DEADLINE, reference(40))
            )
            .map(drop),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    // A manifest whose bytes no longer match its address fails closed.
    let stored = adapter.current_manifest(id).ok_or("no manifest")?;
    adapter.replace_manifest_raw(id, reference(98), stored.canonical_cbor().to_vec())?;
    assert_eq!(
        progress(&adapter, id),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    Ok(())
}

/// A minimal executor through the public port: every command's owner work
/// is negative, committed as an ELNEG1 and its ELO1 into the context.
struct NegativeExecutor;

impl ErasureAuthorityExecutionV1 for NegativeExecutor {
    type Context = Vec<PreparedLocalOwnerEffectV1>;

    fn execute(
        &mut self,
        command: &ErasureOwnerCommandV1,
        context: &mut Self::Context,
    ) -> Result<ErasureOwnerResultV1, ErasureErrorV1> {
        let destruction = command.destruction;
        let effect = LocalErasureNegativeResultV1 {
            command: destruction.command,
            owner_ref: destruction.owner,
            error: ErasureErrorV1::ArtifactDeletionFailed,
        };
        let owner_result = LocalErasureOwnerResultV1 {
            request: command.request,
            attempt: destruction.provenance,
            obligation: destruction.obligation,
            command: destruction.command,
            owner_ref: destruction.owner,
            error: Some(effect.error),
            effect_digest: effect.reference()?,
        };
        let prepared = PreparedLocalOwnerEffectV1::new(
            LocalOwnerEffectV1::Negative(effect.to_canonical_cbor()?),
            &owner_result.to_canonical_cbor()?,
        )?;
        let result = ErasureOwnerResultV1::bind(command, prepared.owner_result().canonical_cbor())?;
        context.push(prepared);
        Ok(result)
    }
}

#[test]
fn an_executor_turns_each_dispatched_command_into_an_owner_result() -> TestResult {
    let request = request()?;
    let id = request.reference();
    let obligations = obligations(id)?;
    let (mut coordinator, adapter) = frozen(&request)?;
    let attempt = admission(id, 0, None, &obligations)?;
    coordinator.dispatch_destruction(id, &attempt)?;
    let mut executor = NegativeExecutor;
    let mut owner_effects = Vec::new();
    let mut results = Vec::new();
    for obligation in &obligations {
        let command = ErasureOwnerCommandV1 {
            request: id,
            destruction: ErasureDestructionCommandV1::from_obligation(
                obligation,
                attempt.reference(),
            ),
        };
        let executed = executor.execute(&command, &mut owner_effects)?;
        // A re-execution of the same command is the same owner result.
        assert_eq!(executor.execute(&command, &mut owner_effects)?, executed);
        assert_eq!(executed.command(), &command);
        assert_eq!(
            executed.error(),
            Some(ErasureErrorV1::ArtifactDeletionFailed)
        );
        let result = executed.owner_result();
        coordinator.acknowledge(
            id,
            acknowledgement(
                obligation,
                result,
                ErasureAcknowledgementOutcomeV1::Negative,
            ),
        )?;
        results.push((
            obligation.reference(),
            attempt.reference(),
            ErasureAcknowledgementOutcomeV1::Negative,
            result,
        ));
    }
    // Each acknowledgement's evidence is the ELO1 its command produced,
    // and each ELO1 binds its command, attempt and ELNEG1 effect.
    assert_eq!(effective(&recorded(&adapter, id)?), results);
    assert_eq!(owner_effects.len(), 4);
    for (prepared, obligation) in owner_effects.iter().step_by(2).zip(&obligations) {
        let owner_result = LocalErasureOwnerResultV1::from_canonical_cbor(
            prepared.owner_result().canonical_cbor(),
        )?;
        let effect = prepared.effect_object().ok_or("no owner effect")?;
        assert_eq!(effect.tag(), "ELNEG1");
        assert_eq!(
            (
                owner_result.request,
                owner_result.attempt,
                owner_result.obligation,
                owner_result.command,
                owner_result.error,
                owner_result.effect_digest,
            ),
            (
                id,
                attempt.reference(),
                obligation.reference(),
                obligation.command_identity(),
                Some(ErasureErrorV1::ArtifactDeletionFailed),
                effect.reference(),
            )
        );
    }
    Ok(())
}

#[test]
fn an_owner_result_binds_only_the_command_it_answers() -> TestResult {
    let request = request()?;
    let id = request.reference();
    let obligation = obligations(id)?[0];
    let command = ErasureOwnerCommandV1 {
        request: id,
        destruction: ErasureDestructionCommandV1::from_obligation(&obligation, reference(50)),
    };
    let answer = LocalErasureOwnerResultV1 {
        request: id,
        attempt: reference(50),
        obligation: obligation.reference(),
        command: obligation.command_identity(),
        owner_ref: obligation.owner(),
        error: None,
        effect_digest: reference(51),
    };
    let bytes = answer.to_canonical_cbor()?;
    let bound = ErasureOwnerResultV1::bind(&command, &bytes)?;
    assert_eq!(bound.owner_result(), answer.reference()?);
    assert_eq!(bound.command(), &command);
    assert_eq!(bound.error(), None);
    // An ELO1 answering any other request, attempt, obligation, command or
    // owner is refused, as are bytes that are not one canonical ELO1.
    for other in [
        LocalErasureOwnerResultV1 {
            request: reference(52),
            ..answer
        },
        LocalErasureOwnerResultV1 {
            attempt: reference(52),
            ..answer
        },
        LocalErasureOwnerResultV1 {
            obligation: reference(52),
            ..answer
        },
        LocalErasureOwnerResultV1 {
            command: reference(52),
            ..answer
        },
        LocalErasureOwnerResultV1 {
            owner_ref: reference(52),
            ..answer
        },
    ] {
        assert_eq!(
            ErasureOwnerResultV1::bind(&command, &other.to_canonical_cbor()?),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
    }
    assert!(ErasureOwnerResultV1::bind(&command, &bytes[1..]).is_err());
    Ok(())
}

#[test]
fn a_receipt_preview_never_retains_a_recovery_error() -> TestResult {
    let request = request()?;
    let id = request.reference();
    let (_, adapter) = frozen(&request)?;
    // A fresh coordinator recovers the record itself: a recoverable record
    // without an attempt previews nothing.
    let fresh = ErasureCoordinatorStateMachineV1::new(adapter.clone(), reference(2));
    assert_eq!(
        fresh
            .preview_receipt(id, receipt_input(ATTEMPT_DEADLINE, reference(40)))
            .map(drop),
        Err(ErasureErrorV1::PolicyConflict)
    );
    let stored = adapter.current_manifest(id).ok_or("no manifest")?;
    adapter.replace_manifest_raw(id, reference(98), stored.canonical_cbor().to_vec())?;
    // The unrecoverable record is refused and nothing is retained ...
    let mut corrupt = ErasureCoordinatorStateMachineV1::new(adapter.clone(), reference(2));
    assert_eq!(
        corrupt
            .preview_receipt(id, receipt_input(ATTEMPT_DEADLINE, reference(40)))
            .map(drop),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(adapter.recovery_error_refs(id)?, Vec::new());
    // ... while finalize retains the same recovery failure.
    assert_eq!(
        corrupt
            .finalize(id, receipt_input(ATTEMPT_DEADLINE, reference(40)))
            .map(drop),
        Err(ErasureErrorV1::ProvenanceMissing)
    );
    assert_eq!(adapter.recovery_error_refs(id)?.len(), 1);
    Ok(())
}
