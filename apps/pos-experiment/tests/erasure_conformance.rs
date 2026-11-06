//! ADR-060 erasure conformance cases through the public erasure host
//! (ADR-062 Revision 8 slice N5, #1233; owner note `ADR-062_R8_Erasure_Cases`).
//!
//! Every case of `fixtures/conformance/erasure/cases.json` runs through
//! `ErasureExecutionHostV1` over `MemoryStore` and `SQLite`. The two adapters
//! must produce identical `ERS1`, `ERC1` and `ERRJ1` bytes, the run must
//! reproduce the projection that `scripts/generate_erasure_conformance_fixtures.py`
//! derives independently, and the records must equal the checked-in recorded
//! artifacts (`executions.json` and `records/`). Each run also writes its
//! artifacts to `$CARGO_TARGET_TMPDIR/erasure-conformance` so a changed case
//! can be re-recorded from CI.

use std::collections::BTreeMap;
use std::error::Error;
use std::path::{Path, PathBuf};

use pos_core::erasure::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementV1,
    ErasureAdministrativeResolutionActionV1, ErasureAdministrativeResolutionInputV1,
    ErasureAdministrativeResolutionV1, ErasureArtifactTransitionV1, ErasureAuthorizationDecisionV1,
    ErasureErrorV1, ErasureForkAdmissionInputV1, ErasureHostErrorV1, ErasureInventoryResultV1,
    ErasureLifecycleV1, ErasureObligationV1, ErasureReceiptInputV1, ErasureReceiptInventoriesV1,
    ErasureReceiptV1, ErasureRecoveryAuthorizationVerifierV1, ErasureReferenceV1,
    ErasureReplayClaimV1, ErasureRequestV1, ErasureRetryAdmissionInputV1, ErasureRetryAdmissionV1,
    ErasureScopeExtensionInputV1, ErasureScopeExtensionV1, ErasureVerifiedTopologyObservationV1,
};
use pos_core::{CanonicalBytes, EntityId, EventDraft, Kind, Seq, TimelineId, TimelineMeta};
use pos_experiment::erasure_conformance::{
    case_obligations, ErasureCaseCatalogueV1, ErasureCaseDigestV1, ErasureCaseErrorV1,
    ErasureCaseRecordV1, ErasureCaseRunV1, ErasureCaseV1,
};
use pos_runtime::{ErasureCoordinatorAuthorityV1, ErasureHostStatusV1};
use pos_store::StoreConfig;
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The erased subject payload. It is never written to a fixture; the
/// generator's `--check` also scans every erasure fixture for it.
const CANARY: &[u8] = b"pigloros-erasure-canary:subject-payload-v1";

fn fail<E: std::fmt::Debug>(error: E) -> Box<dyn Error> {
    format!("{error:?}").into()
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/conformance/erasure")
}

fn load() -> TestResult<(ErasureCaseCatalogueV1, Value)> {
    let bytes = std::fs::read(fixture_root().join("cases.json"))?;
    Ok((
        serde_json::from_slice(&bytes)?,
        serde_json::from_slice(&bytes)?,
    ))
}

fn find<'a>(catalogue: &'a ErasureCaseCatalogueV1, id: &str) -> TestResult<&'a ErasureCaseV1> {
    catalogue
        .cases
        .iter()
        .find(|case| case.case_id == id)
        .ok_or_else(|| format!("missing case {id}").into())
}

const fn digest(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

fn read_request(path: &str) -> TestResult<ErasureRequestV1> {
    ErasureRequestV1::from_canonical_cbor(&std::fs::read(fixture_root().join(path))?).map_err(fail)
}

/// The original request of a policy-conflict case, which the authority refuses.
fn conflicted_request(case: &ErasureCaseV1) -> TestResult<Option<ErasureReferenceV1>> {
    match case.policy_conflict {
        Some(_) => Ok(Some(read_request(&case.request)?.reference())),
        None => Ok(None),
    }
}

fn open(
    catalogue: &ErasureCaseCatalogueV1,
    case: &ErasureCaseV1,
    store: StoreConfig,
) -> TestResult<ErasureCaseRunV1> {
    ErasureCaseRunV1::open(catalogue, case, store, conflicted_request(case)?).map_err(fail)
}

fn run(
    catalogue: &ErasureCaseCatalogueV1,
    case: &ErasureCaseV1,
    store: StoreConfig,
) -> TestResult<ErasureCaseRecordV1> {
    open(catalogue, case, store)?
        .execute(&fixture_root())
        .map_err(fail)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(DIGITS[usize::from(byte >> 4)]),
                char::from(DIGITS[usize::from(byte & 0x0f)]),
            ]
        })
        .collect()
}

fn store_record(
    records: &mut BTreeMap<String, Vec<u8>>,
    extension: &str,
    bytes: Vec<u8>,
) -> String {
    let name = format!(
        "records/{}.{extension}",
        hex(blake3::hash(&bytes).as_bytes())
    );
    records.insert(name.clone(), bytes);
    name
}

/// The `executions.json` entry of one case; its records go to `records`.
/// Each history's request must re-encode to its checked-in `ERQ1` file.
fn case_files(
    case: &ErasureCaseV1,
    record: &ErasureCaseRecordV1,
    records: &mut BTreeMap<String, Vec<u8>>,
) -> TestResult<Value> {
    let mut histories = Vec::new();
    for (index, history) in record.histories.iter().enumerate() {
        let request_file = match (&case.policy_conflict, index) {
            (Some(conflict), 1) => conflict.request.clone(),
            _ => case.request.clone(),
        };
        assert_eq!(
            history.request.to_canonical_cbor().map_err(fail)?,
            std::fs::read(fixture_root().join(&request_file))?,
            "{}: the host's ERQ1 differs from the independently written request",
            case.case_id
        );
        let mut states = Vec::new();
        for state in &history.states {
            states.push(store_record(
                records,
                "ers1",
                state.to_canonical_cbor().map_err(fail)?,
            ));
        }
        let mut receipts = Vec::new();
        for receipt in &history.receipts {
            receipts.push(store_record(
                records,
                "erc1",
                receipt.to_canonical_cbor().map_err(fail)?,
            ));
        }
        histories.push(json!({
            "request": request_file,
            "authorization_refusal": history.authorization_refusal.map(|error| format!("{error:?}")),
            "states": states,
            "receipts": receipts,
        }));
    }
    let mut rejoins = Vec::new();
    for rejoin in &record.rejoins {
        rejoins.push(json!({
            "proof": store_record(records, "errj1", rejoin.proof.to_canonical_cbor().map_err(fail)?),
            "outcome": outcome_name(&rejoin.outcome),
        }));
    }
    Ok(json!({ "case_id": case.case_id, "histories": histories, "rejoins": rejoins }))
}

fn outcome_name<T>(outcome: &Result<T, ErasureErrorV1>) -> String {
    outcome
        .as_ref()
        .map_or_else(|error| format!("{error:?}"), |_| "Admitted".to_owned())
}

fn index_of(
    obligations: &[ErasureObligationV1],
    found: impl Fn(&ErasureObligationV1) -> bool,
) -> TestResult<usize> {
    obligations
        .iter()
        .position(found)
        .ok_or_else(|| "a record names an obligation the case does not have".into())
}

/// The projection the generator derives for a case, rebuilt from the run.
fn projection(case: &ErasureCaseV1, record: &ErasureCaseRecordV1) -> TestResult<Value> {
    let mut histories = Vec::new();
    for history in &record.histories {
        let obligations = case_obligations(case, history.request.reference()).map_err(fail)?;
        let mut receipts = Vec::new();
        for receipt in &history.receipts {
            receipts.push(receipt_projection(&obligations, history, receipt)?);
        }
        histories.push(json!({
            "authorization_refusal": history.authorization_refusal.map(|error| format!("{error:?}")),
            "lifecycles": history.states.iter().map(|state| format!("{:?}", state.lifecycle())).collect::<Vec<_>>(),
            "replay_claims": history.states.iter().map(|state| format!("{:?}", state.replay_claim())).collect::<Vec<_>>(),
            "receipts": receipts,
        }));
    }
    Ok(json!({
        "histories": histories,
        "rejoins": record.rejoins.iter().map(|rejoin| outcome_name(&rejoin.outcome)).collect::<Vec<_>>(),
    }))
}

fn receipt_projection(
    obligations: &[ErasureObligationV1],
    history: &pos_experiment::erasure_conformance::ErasureCaseHistoryV1,
    receipt: &ErasureReceiptV1,
) -> TestResult<Value> {
    let terminal = history
        .states
        .iter()
        .find(|state| state.state_digest() == receipt.terminal_state())
        .ok_or("the receipt's terminal ERS1 is not in the history")?;
    let mut acknowledgements = Vec::new();
    for ack in receipt.acknowledgements() {
        acknowledgements.push(json!({
            "obligation": index_of(obligations, |o| o.reference() == ack.obligation)?,
            "outcome": format!("{:?}", ack.outcome),
        }));
    }
    let inventories = receipt.inventories();
    let mut rows = Vec::new();
    for row in [
        &inventories.artifacts,
        &inventories.keys,
        &inventories.replicas,
        &inventories.backups,
    ]
    .into_iter()
    .flatten()
    {
        rows.push(json!({
            "obligation": index_of(obligations, |o| o.category() == row.category && o.target() == row.target)?,
            "from": format!("{:?}", row.transition.from),
            "to": format!("{:?}", row.transition.to),
        }));
    }
    let owners = |owners: &[ErasureReferenceV1]| -> Vec<String> {
        owners.iter().map(|owner| hex(&owner.digest())).collect()
    };
    Ok(json!({
        "lifecycle": format!("{:?}", receipt.lifecycle()),
        "replay_claim": format!("{:?}", receipt.replay_claim()),
        "acknowledgements": acknowledgements,
        "pending_owners": owners(terminal.pending_owners()),
        "failed_owners": owners(terminal.failed_owners()),
        "rows": rows,
    }))
}

#[test]
fn every_case_reproduces_its_independent_projection_and_checked_in_records() -> TestResult {
    let (catalogue, raw) = load()?;
    let raw_cases = raw["cases"].as_array().ok_or("cases.json has no cases")?;
    assert_eq!(raw_cases.len(), catalogue.cases.len());
    let mut records = BTreeMap::new();
    let mut executions = Vec::new();
    for (case, raw_case) in catalogue.cases.iter().zip(raw_cases) {
        let memory = run(&catalogue, case, StoreConfig::Memory)?;
        let sqlite = run(&catalogue, case, StoreConfig::SqliteInMemory)?;
        let mut memory_records = BTreeMap::new();
        let mut sqlite_records = BTreeMap::new();
        let memory_files = case_files(case, &memory, &mut memory_records)?;
        let sqlite_files = case_files(case, &sqlite, &mut sqlite_records)?;
        assert_eq!(
            memory_files, sqlite_files,
            "{}: the MemoryStore and SQLite records differ",
            case.case_id
        );
        assert_eq!(memory_records, sqlite_records, "{}", case.case_id);
        assert_eq!(
            projection(case, &memory)?,
            raw_case["expected"],
            "{}: the run differs from the independently derived projection",
            case.case_id
        );
        records.extend(memory_records);
        executions.push(memory_files);
    }
    let executions = serde_json::to_string_pretty(&json!({
        "schema": "pigloros.erasure-conformance.executions.v1",
        "cases": executions,
    }))? + "\n";
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("erasure-conformance");
    std::fs::create_dir_all(out.join("records"))?;
    std::fs::write(out.join("executions.json"), &executions)?;
    for (name, bytes) in &records {
        std::fs::write(out.join(name), bytes)?;
    }
    assert_eq!(
        std::fs::read_to_string(fixture_root().join("executions.json"))?,
        executions,
        "executions.json differs from this run"
    );
    for (name, bytes) in &records {
        assert_eq!(&std::fs::read(fixture_root().join(name))?, bytes, "{name}");
    }
    assert_eq!(
        std::fs::read_dir(fixture_root().join("records"))?.count(),
        records.len(),
        "records/ holds artifacts no case produced"
    );
    Ok(())
}

#[test]
fn reordered_and_duplicated_acknowledgements_give_identical_records() -> TestResult {
    let (catalogue, _) = load()?;
    let case = find(&catalogue, "complete-all-categories")?;
    let mut reordered = case.clone();
    for attempt in &mut reordered.attempts {
        attempt.acknowledgements.reverse();
        let first = *attempt
            .acknowledgements
            .first()
            .ok_or("no acknowledgement")?;
        attempt.acknowledgements.push(first);
    }
    let mut original_records = BTreeMap::new();
    let mut reordered_records = BTreeMap::new();
    let original = case_files(
        case,
        &run(&catalogue, case, StoreConfig::Memory)?,
        &mut original_records,
    )?;
    let changed = case_files(
        &reordered,
        &run(&catalogue, &reordered, StoreConfig::Memory)?,
        &mut reordered_records,
    )?;
    assert_eq!(original, changed);
    assert_eq!(original_records, reordered_records);
    Ok(())
}

const fn receipt_input(
    rows: ErasureReceiptInventoriesV1,
    issue_position: u64,
    signature: ErasureReferenceV1,
) -> ErasureReceiptInputV1 {
    let zero = digest(0);
    ErasureReceiptInputV1 {
        request: zero,
        terminal_state: zero,
        coordinator: zero,
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: 0,
        acknowledgements: Vec::new(),
        frozen_targets: Vec::new(),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        inventories: rows,
        replay_claim: ErasureReplayClaimV1::Exact,
        policy: zero,
        trust: zero,
        provenance: zero,
        issue_position,
        signature,
        receipt_digest: zero,
    }
}

fn artifact_and_key_rows(
    obligations: &[ErasureObligationV1],
    from: ErasureReplayClaimV1,
    to: ErasureReplayClaimV1,
) -> ErasureReceiptInventoriesV1 {
    let row = |obligation: &ErasureObligationV1| ErasureInventoryResultV1 {
        category: obligation.category(),
        target: obligation.target(),
        transition: ErasureArtifactTransitionV1 {
            from,
            to,
            reason: digest(70),
            owner: obligation.owner(),
            acknowledgements: digest(71),
            provenance: digest(72),
        },
        retained_disclosure: digest(73),
    };
    ErasureReceiptInventoriesV1 {
        artifacts: obligations.first().map(row).into_iter().collect(),
        keys: obligations.get(1).map(row).into_iter().collect(),
        replicas: Vec::new(),
        backups: Vec::new(),
    }
}

#[test]
fn a_receipt_row_that_upgrades_its_replay_claim_is_refused() -> TestResult {
    let (catalogue, _) = load()?;
    let mut case = find(&catalogue, "partial-failure-then-retry")?.clone();
    case.attempts.clear();
    case.rejoins.clear();
    let mut run = open(&catalogue, &case, StoreConfig::Memory)?;
    let record = run.execute(&fixture_root()).map_err(fail)?;
    let history = record.histories.first().ok_or("no history")?;
    assert_eq!(
        history
            .states
            .last()
            .map(pos_core::erasure::ErasureStateV1::lifecycle),
        Some(ErasureLifecycleV1::AccessFrozen)
    );
    let request = history.request.reference();
    let obligations = case_obligations(&case, request).map_err(fail)?;
    let admission = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request,
        attempt_ordinal: 0,
        source_receipt: None,
        unresolved_obligations: obligations
            .iter()
            .map(ErasureObligationV1::reference)
            .collect(),
        command_identities: obligations
            .iter()
            .map(ErasureObligationV1::command_identity)
            .collect(),
        policy: catalogue.policy.reference(),
        trust: catalogue.trust.reference(),
        admitted_position: 11,
        deadline_position: 20,
        authorization_provenance: digest(74),
    })
    .map_err(fail)?;
    let mut commands = run.host().command_sender().map_err(fail)?;
    commands
        .dispatch_erasure_destruction(request, &admission)
        .map_err(fail)?;
    for obligation in &obligations {
        commands
            .acknowledge_erasure(
                request,
                ErasureAcknowledgementV1 {
                    obligation: obligation.reference(),
                    target: obligation.target(),
                    owner: obligation.owner(),
                    evidence: digest(75),
                    outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
                },
            )
            .map_err(fail)?;
    }
    let upgrading = receipt_input(
        artifact_and_key_rows(
            &obligations,
            ErasureReplayClaimV1::StructuralOnly,
            ErasureReplayClaimV1::Exact,
        ),
        20,
        digest(76),
    );
    assert_eq!(
        commands.finalize_erasure_request(request, &upgrading).err(),
        Some(ErasureHostErrorV1::Conflict)
    );
    let weakening = receipt_input(
        artifact_and_key_rows(
            &obligations,
            ErasureReplayClaimV1::Exact,
            ErasureReplayClaimV1::StructuralOnly,
        ),
        20,
        digest(76),
    );
    let receipt = commands
        .finalize_erasure_request(request, &weakening)
        .map_err(fail)?;
    assert_eq!(receipt.lifecycle(), ErasureLifecycleV1::Complete);
    assert_eq!(receipt.replay_claim(), ErasureReplayClaimV1::StructuralOnly);
    assert_eq!(run.host().status(), ErasureHostStatusV1::Ready);
    Ok(())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn canary_draft() -> EventDraft {
    EventDraft::new(
        EntityId::new(),
        Kind::new("erasure-conformance.subject"),
        CanonicalBytes::from_static(CANARY),
    )
}

/// Run one case with the canary subject Event on a Timeline bound to its
/// frozen scope. The Timeline id is a random ULID inside the scope
/// commitment, so the run is compared with the projection, not the bytes.
fn run_with_canary(
    catalogue: &ErasureCaseCatalogueV1,
    case: &ErasureCaseV1,
    store: StoreConfig,
) -> TestResult<(ErasureCaseRunV1, ErasureCaseRecordV1, TimelineId)> {
    let mut run = open(catalogue, case, store)?;
    let timeline = {
        let mut commands = run.host().command_sender().map_err(fail)?;
        let timeline = commands.create_timeline("erasure-subject").map_err(fail)?;
        commands
            .append(timeline.id(), &[canary_draft()])
            .map_err(fail)?;
        timeline.id()
    };
    run.authority().bind_affected_timeline(timeline);
    let record = run.execute(&fixture_root()).map_err(fail)?;
    Ok((run, record, timeline))
}

fn assert_no_canary(context: &str, text: &str) {
    assert!(
        !contains(text.as_bytes(), CANARY),
        "{context} carries erased bytes"
    );
}

/// Every error value a case run returned, as `Display` and `Debug` text.
fn returned_error_texts(record: &ErasureCaseRecordV1) -> Vec<String> {
    let mut texts = Vec::new();
    for refusal in record
        .histories
        .iter()
        .filter_map(|history| history.authorization_refusal)
    {
        texts.push(format!("{refusal} {refusal:?}"));
        let wrapped = ErasureCaseErrorV1::Host(refusal);
        texts.push(format!("{wrapped} {wrapped:?}"));
    }
    for error in record
        .rejoins
        .iter()
        .filter_map(|rejoin| rejoin.outcome.as_ref().err())
    {
        texts.push(format!("{error} {error:?}"));
        let wrapped = ErasureCaseErrorV1::Fixture(*error);
        texts.push(format!("{wrapped} {wrapped:?}"));
    }
    texts
}

/// Owner decision 10, for every case on both adapters: the erased canary
/// payload is in the store before the erasure, yet it appears in no record,
/// in no `Debug` text of a record, and in no `Display` or `Debug` text of an
/// error the run returned. The erasure path writes no log: its crates have no
/// logging dependency and no logging or print call, which
/// `scripts/generate_erasure_conformance_fixtures.py --check` pins.
#[test]
fn no_case_carries_erased_bytes_on_either_adapter() -> TestResult {
    let (catalogue, raw) = load()?;
    let raw_cases = raw["cases"].as_array().ok_or("cases.json has no cases")?;
    for (case, raw_case) in catalogue.cases.iter().zip(raw_cases) {
        for store in [StoreConfig::Memory, StoreConfig::SqliteInMemory] {
            let context = format!("{} on {store:?}", case.case_id);
            let (_, record, _) = run_with_canary(&catalogue, case, store)?;
            assert_eq!(
                projection(case, &record)?,
                raw_case["expected"],
                "{context}: the canary run differs from the projection"
            );
            let mut records = BTreeMap::new();
            case_files(case, &record, &mut records)?;
            for (name, bytes) in &records {
                assert!(
                    !contains(bytes, CANARY),
                    "{context}: {name} carries erased bytes"
                );
            }
            assert_no_canary(&context, &format!("{record:?}"));
            for text in returned_error_texts(&record) {
                assert_no_canary(&context, &text);
            }
        }
    }
    Ok(())
}

#[test]
fn every_case_error_text_is_closed_and_payload_free() {
    for error in [
        ErasureCaseErrorV1::Read(std::io::ErrorKind::NotFound),
        ErasureCaseErrorV1::Fixture(ErasureErrorV1::PolicyConflict),
        ErasureCaseErrorV1::Host(ErasureHostErrorV1::AccessFrozen),
        ErasureCaseErrorV1::InvalidIndex,
        ErasureCaseErrorV1::MissingHistory,
    ] {
        let text = error.to_string();
        assert!(text.starts_with("erasure case "), "{text}");
        assert_no_canary("case error", &format!("{text} {error:?}"));
    }
}

#[test]
fn a_completed_erasure_stays_contained_and_admits_no_resurrection() -> TestResult {
    let (catalogue, _) = load()?;
    let case = find(&catalogue, "complete-all-categories")?;
    let (mut run, record, timeline) = run_with_canary(&catalogue, case, StoreConfig::Memory)?;
    assert_no_resurrection(&catalogue, &mut run, &record, timeline, &canary_draft())
}

/// After `Complete`: the erased Timeline stays contained, an exact finalize
/// retry returns the committed `ERC1`, and neither a further destruction
/// attempt nor a Fork of the erased Timeline is admitted.
fn assert_no_resurrection(
    catalogue: &ErasureCaseCatalogueV1,
    run: &mut ErasureCaseRunV1,
    record: &ErasureCaseRecordV1,
    timeline: TimelineId,
    draft: &EventDraft,
) -> TestResult {
    let history = record.histories.first().ok_or("no history")?;
    let request = history.request.reference();
    let receipt = history.receipts.first().ok_or("no receipt")?.clone();
    let mut commands = run.host().command_sender().map_err(fail)?;
    let refusals = [
        commands.append(timeline, std::slice::from_ref(draft)).err(),
        commands.timeline(timeline).err(),
    ];
    for refusal in refusals {
        assert_eq!(refusal, Some(ErasureHostErrorV1::AccessFrozen));
        let text = format!("{refusal:?} {}", ErasureHostErrorV1::AccessFrozen);
        assert!(!contains(text.as_bytes(), CANARY));
    }
    let retry = ErasureReceiptInputV1 {
        replay_claim: receipt.replay_claim(),
        ..receipt_input(
            receipt.inventories().clone(),
            receipt.issue_position(),
            receipt.signature(),
        )
    };
    assert_eq!(
        commands
            .finalize_erasure_request(request, &retry)
            .map_err(fail)?,
        receipt,
        "an exact finalize retry must return the committed ERC1"
    );
    let resurrection = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
        request,
        attempt_ordinal: 1,
        source_receipt: Some(receipt.receipt_digest()),
        unresolved_obligations: Vec::new(),
        command_identities: Vec::new(),
        policy: catalogue.policy.reference(),
        trust: catalogue.trust.reference(),
        admitted_position: 21,
        deadline_position: 30,
        authorization_provenance: digest(77),
    })
    .map_err(fail)?;
    assert_eq!(
        commands
            .dispatch_erasure_destruction(request, &resurrection)
            .err(),
        Some(ErasureHostErrorV1::Conflict),
        "a Complete request admits no further destruction attempt"
    );
    assert_eq!(
        commands
            .fork_timeline_identified(
                digest(78),
                timeline,
                Seq::from_u64(1),
                "erasure-subject-fork",
            )
            .err(),
        Some(ErasureHostErrorV1::Conflict),
        "no Fork of an erased Timeline is admitted after Complete"
    );
    assert_eq!(run.host().status(), ErasureHostStatusV1::Ready);
    Ok(())
}

#[test]
fn the_fixture_authority_refuses_only_the_conflicted_authorization() -> TestResult {
    let (catalogue, _) = load()?;
    let case = find(&catalogue, "policy-conflict-corrected")?;
    let conflicted = conflicted_request(case)?.ok_or("no conflicted request")?;
    let run = open(&catalogue, case, StoreConfig::Memory)?;
    let authority = run.authority();
    for (request, decision, expected) in [
        (
            conflicted,
            ErasureAuthorizationDecisionV1::Authorized,
            Err(ErasureErrorV1::PolicyConflict),
        ),
        (conflicted, ErasureAuthorizationDecisionV1::Rejected, Ok(())),
        (
            digest(80),
            ErasureAuthorizationDecisionV1::Authorized,
            Ok(()),
        ),
    ] {
        assert_eq!(
            authority.admit_authorization(request, digest(81), decision),
            expected
        );
    }
    let extension = ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
        request: conflicted,
        scope_commitment: digest(82),
        fork: digest(83),
        child_timeline: TimelineId::new(),
        lineage_rule: digest(84),
        predecessor_extension: None,
        admission_provenance: digest(85),
    })
    .map_err(fail)?;
    assert_eq!(authority.validate_scope_extension(&extension), Ok(()));
    assert_eq!(authority.admit_scope_extension(&extension), Ok(()));
    let resolution =
        ErasureAdministrativeResolutionV1::new(ErasureAdministrativeResolutionInputV1 {
            request: conflicted,
            affected_digests: vec![digest(86)],
            action: ErasureAdministrativeResolutionActionV1::RecoverExactEvidence,
            scope_commitment: digest(87),
            policy: catalogue.policy.reference(),
            trust: catalogue.trust.reference(),
            principal: digest(88),
            authorization_provenance: digest(89),
            reason: digest(90),
            issue_position: 12,
            predecessor_resolution: None,
        })
        .map_err(fail)?;
    assert_eq!(
        authority.validate_administrative_resolution(&resolution),
        Ok(())
    );
    let child = TimelineMeta::root("erasure-fork-candidate");
    assert_eq!(
        authority.verified_topology_observation_for_candidate(digest(91), digest(92), &child),
        Ok(Some(ErasureVerifiedTopologyObservationV1::new(
            digest(92),
            Vec::new(),
            vec![child.id],
        ))),
        "before the freeze a Fork candidate is known and unaffected"
    );
    assert_eq!(
        authority.resolve_fork_child_scope(child.id, &child),
        Ok(catalogue.scope_member.reference())
    );
    let admission = ErasureForkAdmissionInputV1 {
        operation: digest(93),
        expected_inventory_generation: digest(94),
        child_scope: catalogue.scope_member.reference(),
        child,
    };
    assert_eq!(
        authority.admit_fork_scope_extension(&extension, &admission),
        Ok(())
    );
    assert_eq!(
        authority.admit_administrative_resolution(&resolution),
        Ok(())
    );
    Ok(())
}

#[test]
fn malformed_digests_and_missing_request_files_are_closed_errors() -> TestResult {
    assert_eq!(
        serde_json::from_str::<ErasureCaseDigestV1>(&format!("\"{}\"", "ab".repeat(32)))?,
        ErasureCaseDigestV1([0xab; 32])
    );
    for text in [
        "ab".repeat(31),
        "ab".repeat(33),
        format!("{}a", "ab".repeat(31)),
        format!("zz{}", "ab".repeat(31)),
    ] {
        assert!(
            serde_json::from_str::<ErasureCaseDigestV1>(&format!("\"{text}\"")).is_err(),
            "{text}"
        );
    }
    let (catalogue, _) = load()?;
    let case = find(&catalogue, "legal-hold")?;
    let mut run = open(&catalogue, case, StoreConfig::Memory)?;
    assert_eq!(
        run.execute(&fixture_root().join("missing")).err(),
        Some(ErasureCaseErrorV1::Read(std::io::ErrorKind::NotFound))
    );
    Ok(())
}
