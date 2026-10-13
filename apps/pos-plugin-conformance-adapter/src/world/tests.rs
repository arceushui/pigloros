//! R8-A11, R8-A12 and R8-A13: the interpreter, on a pure fake of the world port.

use std::collections::VecDeque;

use pos_plugin_release::ContentValidationV1;
use pos_plugin_supervisor::CommunityPluginSubjectResultV1 as Result1;
use pos_runtime::community_plugin_host::{MeteringV1, TrustDenialBasisV1};
use serde_json::{json, Value};

use super::*;
use crate::hex;
use crate::map::record_bytes;
use crate::test_support::{anchor_bytes, material, parsed, pieces, release, subcase, TestResult};
use pos_reference::evaluator_domain::FixtureFamily;

type E = CommunityPluginHostErrorV1;

const TRUST: E = E::ArtifactTrustDenied {
    basis: TrustDenialBasisV1::TrustStateUnavailable,
};

const NOT_ACTIVE: E = E::ArtifactTrustDenied {
    basis: TrustDenialBasisV1::NotActive,
};

const INVOCATION_HEX: &str = "07070707070707070707070707070707";

const fn identity() -> ReleaseIdentityV1 {
    ReleaseIdentityV1 {
        pmf1_digest: [0xa1; 32],
        release_digest: [0xb2; 32],
    }
}

fn outcome(result: Result1, launched: bool) -> CommunityPluginSubjectOutcomeV1 {
    CommunityPluginSubjectOutcomeV1 {
        plugin_id: "p".to_owned(),
        pmf1_digest: None,
        release_digest: None,
        tps1_digest: None,
        execution_profile_digest: launched.then_some([9; 32]),
        tick: 5,
        mode: CommunityPluginModeV1::Local,
        content_validation: ContentValidationV1::NotPerformed,
        result,
    }
}

fn committed(digest: [u8; 32]) -> CommunityPluginSubjectOutcomeV1 {
    let metering = MeteringV1 {
        startup_fuel: 1,
        call_fuel: 2,
        memory_bytes: 3,
        host_calls: 4,
    };
    outcome(
        Result1::Committed {
            output_digest: Some(digest),
            metering: Some(metering),
        },
        true,
    )
}

fn refused(error: &'static str, basis: Option<&'static str>) -> CommunityPluginSubjectOutcomeV1 {
    let class = "PreExecutionRejection";
    outcome(
        Result1::Refused {
            error,
            basis,
            class,
        },
        false,
    )
}

/// A pure fake of the world: it scripts the answers of the steps and records the calls.
#[derive(Default)]
struct Fake {
    log: Vec<&'static str>,
    setup: Option<SetupArgsV1>,
    open_error: Option<E>,
    installs: VecDeque<Result<(), E>>,
    binds: VecDeque<Result<ReleaseIdentityV1, E>>,
    refreshes: VecDeque<Result<(), E>>,
    passes: VecDeque<Result<Vec<CommunityPluginSubjectOutcomeV1>, E>>,
    events: Vec<Vec<u8>>,
    events_error: Option<E>,
    state: Vec<u8>,
    outcome: Vec<u8>,
    seen_states: Vec<Vec<u8>>,
    install_args: Vec<InstallArgsV1>,
    bind_args: Vec<BindArgsV1>,
    refresh_args: Vec<RefreshArgsV1>,
    pass_args: Vec<PassArgsV1>,
}

impl WorldPortV1 for Fake {
    fn open(&mut self, setup: SetupArgsV1) -> Result<(), E> {
        self.log.push("open");
        self.setup = Some(setup);
        self.open_error.map_or(Ok(()), Err)
    }

    fn install(&mut self, args: &InstallArgsV1) -> Result<(), E> {
        self.log.push("install");
        self.install_args.push(args.clone());
        self.installs.pop_front().unwrap_or(Ok(()))
    }

    fn bind(&mut self, args: &BindArgsV1) -> Result<ReleaseIdentityV1, E> {
        self.log.push("bind");
        self.state.clone_from(&args.initial_state_bytes);
        self.bind_args.push(args.clone());
        self.binds.pop_front().unwrap_or(Ok(identity()))
    }

    fn refresh(&mut self, args: &RefreshArgsV1) -> Result<(), E> {
        self.log.push("refresh");
        self.refresh_args.push(args.clone());
        self.refreshes.pop_front().unwrap_or(Ok(()))
    }

    fn pass(&mut self, args: &PassArgsV1) -> Result<Vec<CommunityPluginSubjectOutcomeV1>, E> {
        self.log.push("pass");
        self.seen_states.push(self.state.clone());
        self.pass_args.push(args.clone());
        self.state = format!("state-{}", self.pass_args.len()).into_bytes();
        let default = Ok(vec![committed([7; 32])]);
        self.passes.pop_front().unwrap_or(default)
    }

    fn committed_event_payloads(&mut self) -> Result<Vec<Vec<u8>>, E> {
        self.log.push("events");
        self.events_error
            .map_or_else(|| Ok(self.events.clone()), Err)
    }

    fn committed_state(&mut self) -> Vec<u8> {
        self.log.push("state");
        self.state.clone()
    }

    fn outcome_bytes(&self) -> Vec<u8> {
        self.outcome.clone()
    }
}

fn install_step(name: &str) -> Value {
    json!({
        "step": "install", "release": release(name), "material": material(),
        "instant_micros": 40_000_000, "tick": 5,
    })
}

fn bind_step(name: &str, plugin: &str, with_material: Value) -> Value {
    json!({
        "step": "bind", "release": release(name), "material": with_material,
        "plugin_id": plugin, "instant_micros": 50_000_000, "tick": 5,
        "initial_state": {"schema": hex::encode(&[1; 32]), "bytes": "696e6974"},
        "event_type": "prototype.driven",
    })
}

fn refresh_step(with_material: Value) -> Value {
    json!({
        "step": "refresh", "material": with_material, "instant_micros": 55_000_000, "tick": 6,
    })
}

fn pass_step(members: Vec<Value>) -> Value {
    json!({
        "step": "pass", "members": members, "instant_micros": 50_000_000, "tick": 5,
        "invocation_id": INVOCATION_HEX, "random_domain": hex::encode(&[2; 32]),
        "timeline_seq": 3, "observation": "00ff", "simulation_time": 11,
    })
}

fn member(plugin: &str) -> Value {
    json!({"plugin_id": plugin})
}

fn scan_step(marker: &str, sources: &[&str], plugin: &str) -> Value {
    json!({
        "step": "scan", "marker": marker, "in": sources,
        "retained": {"plugin_id": plugin, "invocation_id_hex": INVOCATION_HEX},
    })
}

/// The standard prefix of a passing sub-case.
fn prefix() -> Vec<Value> {
    vec![
        install_step("a"),
        bind_step("a", "p", material()),
        pass_step(vec![member("p")]),
    ]
}

fn committed_expect(digest: [u8; 32]) -> Value {
    json!({"kind": "committed", "output_digest": hex::encode(&digest)})
}

fn run(fake: &mut Fake, document: &Value) -> Result<SubCaseRecordV1, Box<dyn std::error::Error>> {
    let subcase = parsed(document)?;
    Ok(interpret(
        &subcase,
        &pieces(),
        fake,
        CommunityPluginModeV1::Local,
    ))
}

#[test]
fn the_result_of_a_two_pass_subcase_is_the_last_pass_and_the_state_is_carried() -> TestResult {
    let mut fake = Fake::default();
    fake.passes.push_back(Ok(vec![committed([1; 32])]));
    fake.passes.push_back(Ok(vec![committed([2; 32])]));
    let mut steps = prefix();
    steps.push(pass_step(vec![member("p")]));
    let record = run(
        &mut fake,
        &subcase("pos.3", steps, committed_expect([2; 32])),
    )?;
    assert!(record.matched);
    assert_eq!(record.steps_run, 4);
    assert_eq!(record.outcomes.len(), 2);
    assert_eq!(record.committed, Some([2; 32]));
    assert_eq!(record.worker_launches, 2);
    assert_eq!(record.setup_refusal, None);
    let usage = ResourceUsage {
        memory_bytes: 3,
        cpu_fuel: 3,
        host_calls: 4,
        ..ResourceUsage::default()
    };
    assert_eq!(record.usage, usage);
    assert_eq!(
        fake.seen_states,
        vec![b"init".to_vec(), b"state-1".to_vec()]
    );
    assert_eq!(fake.log, ["open", "install", "bind", "pass", "pass"]);
    // The first pass is not the result: an expectation of its digest does not match.
    let mut again = Fake::default();
    again.passes.push_back(Ok(vec![committed([1; 32])]));
    again.passes.push_back(Ok(vec![committed([2; 32])]));
    let mut steps = prefix();
    steps.push(pass_step(vec![member("p")]));
    let first = run(
        &mut again,
        &subcase("pos.3", steps, committed_expect([1; 32])),
    )?;
    assert!(!first.matched);
    Ok(())
}

#[test]
fn the_setup_opens_the_world_with_the_releases_the_first_material_and_the_mode() -> TestResult {
    let mut fake = Fake::default();
    let steps = vec![
        bind_step("a", "p", Value::Null),
        refresh_step(material()),
        install_step("b"),
    ];
    let document = subcase("x", steps, committed_expect([0; 32]));
    let record = interpret(
        &parsed(&document)?,
        &pieces(),
        &mut fake,
        CommunityPluginModeV1::AirGapped,
    );
    let setup = fake.setup.ok_or("the world was not opened")?;
    assert_eq!(setup.mode, CommunityPluginModeV1::AirGapped);
    assert!(setup.source.is_some());
    assert!(
        setup.genesis.is_some(),
        "the refresh material is the first non-null one"
    );
    assert_eq!(record.steps_run, 3);
    assert_eq!(fake.log, ["open", "bind", "refresh", "install"]);
    assert!(fake.bind_args[0].material.is_none());
    assert_eq!(fake.refresh_args[0].tick, 6);
    assert_eq!(fake.install_args[0].instant_micros, 40_000_000);
    assert_eq!(fake.bind_args[0].initial_state_bytes, b"init");
    assert_eq!(fake.bind_args[0].initial_state_schema, [1; 32]);
    assert_eq!(fake.bind_args[0].event_type, "prototype.driven");
    Ok(())
}

#[test]
fn a_subcase_without_steps_opens_no_world() -> TestResult {
    let mut fake = Fake::default();
    let blake = json!({"kind": "digest", "value": hex::encode(&[0; 32]),
        "compute": {"what": "blake3_of", "input": "x"}});
    let record = run(&mut fake, &subcase("ind.1", Vec::new(), blake))?;
    assert!(fake.log.is_empty());
    assert_eq!(record.steps_run, 0);
    assert!(!record.matched, "the digest differs");
    Ok(())
}

#[test]
fn a_world_that_does_not_open_is_the_setup_refusal() -> TestResult {
    let mut fake = Fake {
        open_error: Some(TRUST),
        ..Fake::default()
    };
    let expect = json!({"kind": "refused", "error": "ArtifactTrustDenied",
        "class": "PreExecutionRejection", "basis": "TrustStateUnavailable"});
    let record = run(&mut fake, &subcase("den.x", prefix(), expect))?;
    assert_eq!(fake.log, ["open"]);
    assert_eq!(record.steps_run, 0);
    assert_eq!(record.setup_refusal, Some(TRUST));
    assert!(record.matched);
    Ok(())
}

#[test]
fn a_step_that_refuses_partway_is_the_result_and_later_steps_do_not_run() -> TestResult {
    // dgr.4: install R1, then the refused install of R2'.
    let mut fake = Fake::default();
    fake.installs.push_back(Ok(()));
    fake.installs.push_back(Err(TRUST));
    let steps = vec![
        install_step("a"),
        install_step("b"),
        bind_step("a", "p", material()),
    ];
    let expect = json!({"kind": "refused", "error": "ArtifactTrustDenied",
        "class": "PreExecutionRejection", "basis": "TrustStateUnavailable"});
    let record = run(&mut fake, &subcase("dgr.4", steps.clone(), expect.clone()))?;
    assert!(record.matched);
    assert_eq!(record.steps_run, 2, "the refusing step is counted");
    assert_eq!(fake.log, ["open", "install", "install"]);
    assert_eq!(record.setup_refusal, Some(TRUST));
    assert_eq!(record.committed, None);

    // An expectation that names another refusal is a mismatch.
    let mut again = Fake::default();
    again.installs.push_back(Ok(()));
    again.installs.push_back(Err(TRUST));
    let other = json!({
        "kind": "refused", "error": "IncompatibleAbi", "class": "PreExecutionRejection",
    });
    let mismatch = run(&mut again, &subcase("dgr.4", steps.clone(), other))?;
    assert!(!mismatch.matched);
    // So is one that names the error with another basis, class or index.
    for wrong in [
        json!({"kind": "refused", "error": "ArtifactTrustDenied",
            "class": "PreExecutionRejection", "basis": "NotActive"}),
        json!({"kind": "refused", "error": "ArtifactTrustDenied",
            "class": "Authoritative", "basis": "TrustStateUnavailable"}),
        json!({"kind": "refused", "error": "ArtifactTrustDenied",
            "class": "PreExecutionRejection"}),
        json!({"kind": "refused", "error": "ArtifactTrustDenied",
            "class": "PreExecutionRejection", "basis": "TrustStateUnavailable", "index": 0}),
        json!({"kind": "failed", "error": "ArtifactTrustDenied", "class": "Authoritative"}),
        committed_expect([0; 32]),
    ] {
        let mut fake = Fake::default();
        fake.installs.push_back(Ok(()));
        fake.installs.push_back(Err(TRUST));
        let record = run(&mut fake, &subcase("dgr.4", steps.clone(), wrong.clone()))?;
        assert!(!record.matched, "{wrong}");
    }
    Ok(())
}

#[test]
fn the_index_is_read_from_the_setup_refusal_only() -> TestResult {
    let denied = E::CapabilityDenied { index: 3 };
    let expect = |index: u64| {
        json!({"kind": "refused", "error": "CapabilityDenied",
            "class": "PreExecutionRejection", "index": index})
    };
    for (index, matches) in [(3, true), (2, false)] {
        let mut fake = Fake::default();
        fake.binds.push_back(Err(denied));
        let record = run(&mut fake, &subcase("den.01", prefix(), expect(index)))?;
        assert_eq!(record.matched, matches, "index {index}");
        assert_eq!(record.steps_run, 2);
    }
    let missing = E::MissingFeature { index: 0 };
    let mut fake = Fake::default();
    fake.binds.push_back(Err(missing));
    let feature = json!({"kind": "refused", "error": "MissingFeature",
        "class": "PreExecutionRejection", "index": 0});
    assert!(run(&mut fake, &subcase("den.02", prefix(), feature))?.matched);

    // An outcome-record refusal carries no index: an index expectation is a mismatch.
    let mut fake = Fake::default();
    fake.passes
        .push_back(Ok(vec![refused("CapabilityDenied", None)]));
    let record = run(&mut fake, &subcase("den.01", prefix(), expect(0)))?;
    assert!(!record.matched);
    Ok(())
}

#[test]
fn an_outcome_that_is_refused_or_failed_stops_the_subcase_and_is_compared() -> TestResult {
    let mut fake = Fake::default();
    fake.passes
        .push_back(Ok(vec![refused("ArtifactTrustDenied", Some("NotActive"))]));
    let mut steps = prefix();
    steps.push(pass_step(vec![member("p")]));
    let expect = json!({"kind": "refused", "error": "ArtifactTrustDenied",
        "class": "PreExecutionRejection", "basis": "NotActive"});
    let record = run(&mut fake, &subcase("den.20", steps.clone(), expect))?;
    assert!(record.matched);
    assert_eq!(record.steps_run, 3, "the second pass does not run");
    assert_eq!(record.worker_launches, 0, "no receipt, no launch");

    let mut fake = Fake::default();
    let failed = outcome(
        Result1::Failed {
            error: "FuelExhausted",
            class: "Authoritative",
        },
        true,
    );
    fake.passes.push_back(Ok(vec![failed]));
    let expect = json!({"kind": "failed", "error": "FuelExhausted", "class": "Authoritative"});
    let record = run(&mut fake, &subcase("res.1", steps, expect))?;
    assert!(record.matched);
    assert_eq!(record.worker_launches, 1);
    assert_eq!(record.usage, ResourceUsage::default());
    Ok(())
}

#[test]
fn an_operational_outcome_matches_no_expectation() -> TestResult {
    let crashed = outcome(
        Result1::Failed {
            error: "WorkerCrashed",
            class: "Operational",
        },
        true,
    );
    for expect in [
        json!({"kind": "failed", "error": "WorkerCrashed", "class": "Operational"}),
        committed_expect([7; 32]),
    ] {
        let mut fake = Fake::default();
        fake.passes.push_back(Ok(vec![crashed.clone()]));
        let record = run(&mut fake, &subcase("res.1", prefix(), expect))?;
        assert!(!record.matched);
        assert_eq!(record.outcomes, vec![crashed.clone()]);
    }
    Ok(())
}

#[test]
fn a_pass_that_does_not_commit_stops_and_the_first_such_outcome_decides() -> TestResult {
    let mut fake = Fake::default();
    fake.passes.push_back(Ok(vec![
        committed([1; 32]),
        refused("ArtifactTrustDenied", Some("Expired")),
        committed([3; 32]),
    ]));
    let record = run(
        &mut fake,
        &subcase("x", prefix(), committed_expect([1; 32])),
    )?;
    assert_eq!(record.outcomes.len(), 1);
    assert_eq!(record.committed, None);
    assert!(!record.matched);

    let mut fake = Fake::default();
    fake.passes
        .push_back(Ok(vec![committed([1; 32]), committed([3; 32])]));
    let record = run(
        &mut fake,
        &subcase("x", prefix(), committed_expect([3; 32])),
    )?;
    assert!(record.matched, "no refusal: the last outcome decides");

    let mut fake = Fake::default();
    fake.passes.push_back(Ok(Vec::new()));
    let record = run(
        &mut fake,
        &subcase("x", prefix(), committed_expect([3; 32])),
    )?;
    assert!(record.outcomes.is_empty());
    assert!(!record.matched, "a pass with no member has no result");
    assert_eq!(record.steps_run, 3);

    let mut fake = Fake::default();
    fake.passes.push_back(Err(TRUST));
    let record = run(
        &mut fake,
        &subcase("x", prefix(), committed_expect([3; 32])),
    )?;
    assert_eq!(record.setup_refusal, Some(TRUST));
    Ok(())
}

#[test]
fn a_committed_digest_that_differs_is_a_mismatch_with_the_observed_digest() -> TestResult {
    let mut fake = Fake::default();
    let record = run(
        &mut fake,
        &subcase("pos.1", prefix(), committed_expect([8; 32])),
    )?;
    assert!(!record.matched);
    assert_eq!(record.committed, Some([7; 32]));
    Ok(())
}

fn absent(marker: &str, plugin: &str) -> Value {
    json!({"kind": "absent", "marker": marker,
        "retained": {"plugin_id": plugin, "invocation_id_hex": INVOCATION_HEX}})
}

/// `prefix()`, the scan of `marker` in every source, and the `absent` expectation.
fn scanning(marker: &str, plugin: &str) -> Value {
    let mut steps = prefix();
    steps.push(scan_step(marker, &["events", "state", "outcome"], plugin));
    subcase("del.1", steps, absent(marker, plugin))
}

type Found = (Vec<ScanSource>, bool);

fn found_by(fake: &mut Fake, marker: &str) -> Result<Found, Box<dyn std::error::Error>> {
    let record = run(fake, &scanning(marker, "p"))?;
    let scan = record.scan.ok_or("the scan did not run")?;
    assert!(scan.retained_ok);
    assert_eq!(record.matched, scan.found.is_empty());
    Ok((scan.found, record.matched))
}

#[test]
fn a_scan_finds_the_marker_in_the_source_that_holds_it() -> TestResult {
    let mut events = Fake {
        events: vec![b"x".to_vec(), b"a secret b".to_vec()],
        state: b"clean".to_vec(),
        outcome: b"clean".to_vec(),
        ..Fake::default()
    };
    assert_eq!(found_by(&mut events, "secret")?.0, [ScanSource::Events]);
    let mut state = Fake {
        outcome: b"clean".to_vec(),
        ..Fake::default()
    };
    // The state of the fake after one pass is `state-1`.
    assert_eq!(found_by(&mut state, "state-")?.0, [ScanSource::State]);
    let mut outcome = Fake {
        outcome: b"has secret".to_vec(),
        ..Fake::default()
    };
    assert_eq!(found_by(&mut outcome, "secret")?.0, [ScanSource::Outcome]);
    let mut nothing = Fake {
        events: vec![b"clean".to_vec()],
        ..Fake::default()
    };
    assert_eq!(found_by(&mut nothing, "secret")?, (Vec::new(), true));
    let mut all = Fake {
        events: vec![b"state-".to_vec()],
        outcome: b"state-".to_vec(),
        ..Fake::default()
    };
    let found = found_by(&mut all, "state-")?;
    assert_eq!(
        found.0,
        [ScanSource::Events, ScanSource::State, ScanSource::Outcome]
    );
    assert!(!found.1);
    Ok(())
}

#[test]
fn a_scan_reads_only_the_sources_it_names_once_and_in_order() -> TestResult {
    let mut fake = Fake {
        events: vec![b"secret".to_vec()],
        outcome: b"secret".to_vec(),
        ..Fake::default()
    };
    let mut steps = prefix();
    steps.push(scan_step("secret", &["outcome", "events", "events"], "p"));
    let record = run(&mut fake, &subcase("del.2", steps, absent("secret", "p")))?;
    let scan = record.scan.ok_or("scan")?;
    assert_eq!(scan.found, [ScanSource::Events, ScanSource::Outcome]);
    assert_eq!(fake.log, ["open", "install", "bind", "pass", "events"]);
    Ok(())
}

#[test]
fn an_empty_marker_is_in_every_source() -> TestResult {
    let mut fake = Fake::default();
    let found = found_by(&mut fake, "")?;
    assert_eq!(
        found.0,
        [ScanSource::Events, ScanSource::State, ScanSource::Outcome]
    );
    Ok(())
}

#[test]
fn a_retained_mismatch_clears_retained_ok_and_marks_the_entry() -> TestResult {
    let mut fake = Fake::default();
    let record = run(&mut fake, &scanning("secret", "q"))?;
    let scan = record.scan.clone().ok_or("scan")?;
    assert!(!scan.retained_ok);
    assert!(scan.found.is_empty());
    assert_eq!(scan.observed_plugin_id, "p");
    assert_eq!(scan.observed_invocation_id_hex, INVOCATION_HEX);
    assert!(!record.matched);
    let family = FixtureFamily::DeletionRedaction;
    let observed = String::from_utf8(record_bytes("c", family, &[record]))?;
    assert!(observed.contains("{\"id\":\"del.1\",\"kind\":\"mismatch\"}"), "{observed}");
    Ok(())
}

#[test]
fn a_scan_without_a_bind_or_a_pass_observes_empty_metadata() -> TestResult {
    let mut fake = Fake::default();
    let steps = vec![install_step("a"), scan_step("m", &["state"], "p")];
    let record = run(&mut fake, &subcase("del.1", steps, absent("m", "p")))?;
    let scan = record.scan.ok_or("scan")?;
    assert!(!scan.retained_ok);
    assert_eq!(scan.observed_plugin_id, "");
    assert_eq!(scan.observed_invocation_id_hex, "");
    Ok(())
}

#[test]
fn a_scan_that_cannot_read_a_source_is_a_setup_refusal() -> TestResult {
    let mut fake = Fake {
        events_error: Some(TRUST),
        ..Fake::default()
    };
    let record = run(&mut fake, &scanning("m", "p"))?;
    assert_eq!(record.setup_refusal, Some(TRUST));
    assert_eq!(record.scan, None);
    assert!(!record.matched);
    assert_eq!(record.steps_run, 4);
    Ok(())
}

#[test]
fn an_absent_expectation_needs_a_scan_that_ran() -> TestResult {
    let mut fake = Fake::default();
    let steps = vec![install_step("a")];
    let record = run(&mut fake, &subcase("del.1", steps, absent("m", "p")))?;
    assert!(!record.matched);
    Ok(())
}

fn digest_expect(compute: &Value, value: &str) -> Value {
    json!({"kind": "digest", "compute": compute, "value": value})
}

const BLAKE3_IND_1: &str = "92adc8f0b327b091f85e847d3fa1f7cb46e16bdd74f389d79b2e61171c2715c3";
const R7_D1: &str = "9df81ceb0d029665c3317e72736385b21af951200babd30cbbfc7d0a8d11e100";

fn r7_d1() -> Value {
    json!({
        "what": "profile_digest",
        "ceilings": [67_108_864, 1_000_000_000, 1_000_000, 16_777_216, 16_384],
        "runtime": {
            "version": "fixture-1",
            "features": ["runtime", "component-model", "cranelift"],
            "engine": [524_288, true, true],
            "traps": [
                ["UnreachableCodeReached", "unreachable"],
                ["OutOfFuel", "FuelExhausted"],
                ["Interrupt", "OperationalWatchdogStop"],
            ],
        },
    })
}

type Computed = Option<[u8; 32]>;

fn computed(
    compute: &Value,
    steps: Vec<Value>,
    fake: &mut Fake,
) -> Result<Computed, Box<dyn std::error::Error>> {
    let record = run(
        fake,
        &subcase("ind.x", steps, digest_expect(compute, &"00".repeat(32))),
    )?;
    Ok(record.computed)
}

fn digest_of(text: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    Ok(hex::decode_array::<32>(text).ok_or("not hex32")?)
}

#[test]
fn each_compute_kind_has_a_golden() -> TestResult {
    let mut fake = Fake::default();
    let input = "PiglorOS independent fixture plugin-conformance";
    let blake = json!({"what": "blake3_of", "input": input});
    assert_eq!(
        computed(&blake, Vec::new(), &mut fake)?,
        Some(digest_of(BLAKE3_IND_1)?)
    );
    assert_eq!(
        computed(&r7_d1(), Vec::new(), &mut fake)?,
        Some(digest_of(R7_D1)?)
    );

    // The expectation compares the computed value with the payload's.
    let record = run(
        &mut fake,
        &subcase("ind.4", Vec::new(), digest_expect(&r7_d1(), R7_D1)),
    )?;
    assert!(record.matched);
    assert_eq!(record.steps_run, 0);
    let wrong = digest_expect(&r7_d1(), BLAKE3_IND_1);
    let record = run(&mut fake, &subcase("ind.4", Vec::new(), wrong))?;
    assert!(!record.matched);
    assert_eq!(record.computed, Some(digest_of(R7_D1)?));

    // The identity and the output digest are the fake port's values.
    let pmf1 = json!({"what": "release_identity", "field": "pmf1"});
    let release_field = json!({"what": "release_identity", "field": "release"});
    let output = json!({"what": "output_digest", "pass_index": 0});
    assert_eq!(
        computed(&pmf1, prefix(), &mut Fake::default())?,
        Some([0xa1; 32])
    );
    assert_eq!(
        computed(&release_field, prefix(), &mut Fake::default())?,
        Some([0xb2; 32])
    );
    assert_eq!(
        computed(&output, prefix(), &mut Fake::default())?,
        Some([7; 32])
    );
    Ok(())
}

#[test]
fn a_compute_that_cannot_exist_is_a_mismatch() -> TestResult {
    let pmf1 = json!({"what": "release_identity", "field": "pmf1"});
    assert_eq!(
        computed(&pmf1, Vec::new(), &mut Fake::default())?,
        None,
        "no bind"
    );
    assert_eq!(
        computed(&pmf1, vec![install_step("a")], &mut Fake::default())?,
        None,
        "a bind that did not run"
    );
    let mut refusing = Fake::default();
    refusing.binds.push_back(Err(TRUST));
    assert_eq!(
        computed(&pmf1, prefix(), &mut refusing)?,
        None,
        "a refused bind"
    );

    for index in [1, 2, 9_007_199_254_740_991_u64] {
        let output = json!({"what": "output_digest", "pass_index": index});
        assert_eq!(
            computed(&output, prefix(), &mut Fake::default())?,
            None,
            "{index}"
        );
    }
    let output = json!({"what": "output_digest", "pass_index": 0});
    let mut refused_pass = Fake::default();
    refused_pass
        .passes
        .push_back(Ok(vec![refused("ArtifactTrustDenied", Some("Expired"))]));
    assert_eq!(
        computed(&output, prefix(), &mut refused_pass)?,
        None,
        "a pass that refused"
    );

    let mut bad_rows = Vec::new();
    for (path, replacement) in [
        ("traps", json!([["OutOfFuel", "other"]])),
        ("traps", json!([["OutOfFuel", "bogus"]])),
        (
            "traps",
            json!([
                ["OutOfFuel", "FuelExhausted"],
                ["OutOfFuel", "FuelExhausted"]
            ]),
        ),
    ] {
        let mut profile = r7_d1();
        profile["runtime"][path] = replacement;
        bad_rows.push(profile);
    }
    let mut small = r7_d1();
    small["ceilings"] = json!([1, 2, 3, 4, 5]);
    bad_rows.push(small);
    for profile in bad_rows {
        assert_eq!(
            computed(&profile, Vec::new(), &mut Fake::default())?,
            None,
            "{profile}"
        );
    }
    Ok(())
}

#[test]
fn the_features_and_rows_are_sorted_by_the_encoder_not_by_the_payload() -> TestResult {
    let mut reordered = r7_d1();
    reordered["runtime"]["features"] = json!(["cranelift", "runtime", "component-model"]);
    reordered["runtime"]["traps"] = json!([
        ["Interrupt", "OperationalWatchdogStop"],
        ["UnreachableCodeReached", "unreachable"],
        ["OutOfFuel", "FuelExhausted"],
    ]);
    assert_eq!(
        computed(&reordered, Vec::new(), &mut Fake::default())?,
        Some(digest_of(R7_D1)?)
    );
    Ok(())
}

#[test]
fn a_nested_document_decides_the_malformed_expectation() -> TestResult {
    let garbage = pieces();
    let nested = hex::encode(blake3::hash(b"manifest-a").as_bytes());
    let mut fake = Fake::default();
    let mut document = subcase("mal.6", Vec::new(), json!({"kind": "malformed"}));
    document["nested"] = json!(nested);
    let record = interpret(
        &parsed(&document)?,
        &garbage,
        &mut fake,
        CommunityPluginModeV1::Local,
    );
    assert!(
        record.matched,
        "bytes that are not a sub-case document are malformed"
    );

    let valid = subcase("n.1", Vec::new(), json!({"kind": "malformed"})).to_string();
    let with_valid = PiecesV1::from_blobs([valid.clone().into_bytes()]);
    document["nested"] = json!(hex::encode(blake3::hash(valid.as_bytes()).as_bytes()));
    let nested = parsed(&document)?;
    let record = interpret(
        &nested,
        &with_valid,
        &mut fake,
        CommunityPluginModeV1::Local,
    );
    assert!(
        !record.matched,
        "a well-formed nested document is not malformed"
    );
    Ok(())
}

#[test]
fn a_subcase_that_cannot_be_resolved_runs_nothing() -> TestResult {
    let mut fake = Fake::default();
    let mut document = subcase("x", prefix(), committed_expect([7; 32]));
    document["steps"][0]["release"]["manifest"] = json!(hex::encode(&[0xee; 32]));
    let record = run(&mut fake, &document)?;
    assert_eq!(record, SubCaseRecordV1::empty("x"));
    assert!(fake.log.is_empty());
    Ok(())
}

fn build(document: &Value) -> Result<PreparedV1, Box<dyn std::error::Error>> {
    Ok(PreparedV1::build(&parsed(document)?, &pieces())?)
}

fn invalid(document: &Value) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(PreparedV1::build(&parsed(document)?, &pieces()).is_err())
}

fn address_of(name: &str) -> Result<BundleAddressV1, Box<dyn std::error::Error>> {
    let entry = InMemoryReleaseEntryV1::from_bytes(
        format!("manifest-{name}").into_bytes(),
        vec![format!("blob-{name}").into_bytes()],
    )?;
    Ok(entry.address().clone())
}

#[test]
fn the_members_of_a_pass_read_the_address_the_payload_names() -> TestResult {
    let members = vec![
        member("p"),
        json!({"plugin_id": "p", "at": "absent"}),
        json!({"plugin_id": "p", "at": release("b")}),
    ];
    let steps = vec![
        install_step("a"),
        bind_step("a", "p", material()),
        pass_step(members),
    ];
    let prepared = build(&subcase("x", steps, committed_expect([0; 32])))?;
    let ResolvedStepV1::Pass(pass) = &prepared.steps[2] else {
        return Err("not a pass".into());
    };
    assert_eq!(pass.members[0].address, address_of("a")?);
    let nothing = BundleAddressV1::new(format!("sha256:{}", "0".repeat(64)), 1)?;
    assert_eq!(pass.members[1].address, nothing);
    assert_eq!(pass.members[2].address, address_of("b")?);
    assert_eq!(pass.invocation_id, [7; 16]);
    assert_eq!(pass.random_domain, [2; 32]);
    assert_eq!(pass.timeline_seq, 3);
    assert_eq!(pass.observation, [0, 255]);
    assert_eq!(pass.simulation_time, 11);
    assert_eq!((pass.instant_micros, pass.tick), (50_000_000, 5));
    assert!(pass.material.is_some());
    Ok(())
}

#[test]
fn the_material_of_a_pass_is_that_of_the_most_recent_bind_or_refresh() -> TestResult {
    let pass = |steps: Vec<Value>| -> Result<bool, Box<dyn std::error::Error>> {
        let prepared = build(&subcase("x", steps, committed_expect([0; 32])))?;
        let last = prepared.steps.last().ok_or("no steps")?;
        let ResolvedStepV1::Pass(pass) = last else {
            return Err("not a pass".into());
        };
        Ok(pass.material.is_some())
    };
    let pass_p = pass_step(vec![member("p")]);
    assert!(pass(vec![bind_step("a", "p", material()), pass_p.clone()])?);
    assert!(!pass(vec![
        bind_step("a", "p", Value::Null),
        pass_p.clone()
    ])?);
    let steps = vec![
        bind_step("a", "p", material()),
        refresh_step(Value::Null),
        pass_p.clone(),
    ];
    assert!(!pass(steps)?, "a refresh with no material replaces it");
    let steps = vec![
        bind_step("a", "p", Value::Null),
        refresh_step(material()),
        pass_p,
    ];
    assert!(pass(steps)?);
    Ok(())
}

#[test]
fn a_release_named_twice_is_one_entry() -> TestResult {
    // `new` would refuse the duplicate address, so this proves the deduplication.
    let steps = vec![
        install_step("a"),
        bind_step("a", "p", material()),
        install_step("b"),
    ];
    let prepared = build(&subcase("x", steps, committed_expect([0; 32])))?;
    assert!(prepared.source.is_some());
    let none = build(&subcase(
        "x",
        vec![refresh_step(material())],
        committed_expect([0; 32]),
    ))?;
    assert!(none.source.is_none(), "no release, no source");
    let empty = build(&subcase("x", Vec::new(), committed_expect([0; 32])))?;
    assert!(empty.source.is_none() && empty.genesis.is_none() && empty.steps.is_empty());
    Ok(())
}

#[test]
fn a_digest_that_names_no_piece_is_payload_invalid_everywhere() -> TestResult {
    let nothing = json!(hex::encode(&[0xee; 32]));
    let expect = committed_expect([0; 32]);
    let good_pass = pass_step(vec![member("p")]);
    let bind = || bind_step("a", "p", material());
    let with_at = || {
        let member = json!({"plugin_id": "p", "at": release("b")});
        vec![bind(), pass_step(vec![member])]
    };
    let places: Vec<(Vec<Value>, &str)> = vec![
        (vec![install_step("a")], "/0/release/manifest"),
        (vec![install_step("a")], "/0/release/blobs/0"),
        (vec![install_step("a")], "/0/material/anchor"),
        (vec![install_step("a")], "/0/material/tps1"),
        (vec![install_step("a")], "/0/material/ptr1/0"),
        (vec![install_step("a")], "/0/material/prv1/0"),
        (vec![bind()], "/0/release/manifest"),
        (vec![bind()], "/0/release/blobs/0"),
        (vec![bind()], "/0/material/anchor"),
        (vec![refresh_step(material())], "/0/material/tps1"),
        (vec![refresh_step(material())], "/0/material/anchor"),
        (with_at(), "/1/members/0/at/manifest"),
        (with_at(), "/1/members/0/at/blobs/0"),
    ];
    for (steps, pointer) in places {
        let mut document = subcase("x", steps, expect.clone());
        let target = document["steps"]
            .pointer_mut(pointer)
            .ok_or("no such place")?;
        *target = nothing.clone();
        assert!(invalid(&document)?, "{pointer}");
    }
    // A second bind of one Plugin.
    let twice = subcase("x", vec![bind(), bind()], expect.clone());
    assert!(invalid(&twice)?);
    // A member with an explicit `at` whose Plugin no bind named.
    let explicit = json!({"plugin_id": "q", "at": "absent"});
    let document = subcase("x", vec![bind(), pass_step(vec![explicit])], expect.clone());
    assert!(invalid(&document)?);
    // A member without `at` whose Plugin no bind named.
    let document = subcase(
        "x",
        vec![bind(), pass_step(vec![member("q")])],
        expect.clone(),
    );
    assert!(invalid(&document)?);
    let document = subcase("x", vec![good_pass], expect.clone());
    assert!(invalid(&document)?, "a pass before any bind");
    // The nested digest.
    let mut document = subcase("mal.6", Vec::new(), json!({"kind": "malformed"}));
    document["nested"] = nothing;
    assert!(invalid(&document)?);
    Ok(())
}

#[test]
fn an_undecodable_anchor_or_a_refused_entry_or_material_is_payload_invalid() -> TestResult {
    let expect = committed_expect([0; 32]);
    let garbage = PiecesV1::from_blobs([
        b"manifest-a".to_vec(),
        b"blob-a".to_vec(),
        b"tps1".to_vec(),
        b"ptr1".to_vec(),
        b"prv1".to_vec(),
        b"not an anchor".to_vec(),
    ]);
    let mut document = subcase("x", vec![install_step("a")], expect.clone());
    let anchor = blake3::hash(b"not an anchor");
    document["steps"][0]["material"]["anchor"] = json!(hex::encode(anchor.as_bytes()));
    assert!(PreparedV1::build(&parsed(&document)?, &garbage).is_err());

    // An empty manifest is refused by the entry.
    let empty = PiecesV1::from_blobs([
        Vec::new(),
        b"blob-a".to_vec(),
        b"tps1".to_vec(),
        b"ptr1".to_vec(),
        b"prv1".to_vec(),
        anchor_bytes(),
    ]);
    let mut document = subcase("x", vec![install_step("a")], expect.clone());
    document["steps"][0]["release"]["manifest"] = json!(hex::encode(blake3::hash(b"").as_bytes()));
    assert!(PreparedV1::build(&parsed(&document)?, &empty).is_err());

    // A history with no record is refused by `from_bytes_v1`.
    let mut document = subcase("x", vec![install_step("a")], expect);
    document["steps"][0]["material"]["ptr1"] = json!([]);
    assert!(invalid(&document)?);
    Ok(())
}

#[test]
fn the_outcome_record_encoding_has_a_golden() {
    let not_run = CommunityPluginSubjectOutcomeV1 {
        mode: CommunityPluginModeV1::Local,
        tick: 0,
        ..outcome(Result1::NotRun, false)
    };
    assert_eq!(
        hex::encode(&outcome_bytes_of(&not_run)),
        "8b64504f4231016170f6f6f6f600000081664e6f7452756e"
    );
}

fn full_digests(
    result: Result1,
    tick: u64,
    mode: CommunityPluginModeV1,
) -> CommunityPluginSubjectOutcomeV1 {
    CommunityPluginSubjectOutcomeV1 {
        pmf1_digest: Some([1; 32]),
        release_digest: Some([2; 32]),
        tps1_digest: Some([3; 32]),
        execution_profile_digest: Some([4; 32]),
        tick,
        mode,
        ..outcome(result, true)
    }
}

#[test]
fn every_result_of_the_outcome_record_has_its_encoding() {
    let metering = MeteringV1 {
        startup_fuel: 1,
        call_fuel: 2,
        memory_bytes: 3,
        host_calls: 4,
    };
    let committed = Result1::Committed {
        output_digest: Some([9; 32]),
        metering: Some(metering),
    };
    let golden = concat!(
        "8b64504f42310161705820010101010101010101010101010101010101010101",
        "0101010101010101010101582002020202020202020202020202020202020202",
        "0202020202020202020202020258200303030303030303030303030303030303",
        "0303030303030303030303030303035820040404040404040404040404040404",
        "04040404040404040404040404040404040501008369436f6d6d697474656458",
        "2009090909090909090909090909090909090909090909090909090909090909",
        "098401020304",
    );
    let record = full_digests(committed, 5, CommunityPluginModeV1::AirGapped);
    assert_eq!(hex::encode(&outcome_bytes_of(&record)), golden);

    let staged = Result1::Staged {
        output_digest: None,
        metering: None,
    };
    let record = CommunityPluginSubjectOutcomeV1 {
        pmf1_digest: None,
        release_digest: Some([2; 32]),
        tps1_digest: None,
        execution_profile_digest: None,
        tick: 300,
        ..outcome(staged, false)
    };
    assert_eq!(
        hex::encode(&outcome_bytes_of(&record)),
        concat!(
            "8b64504f4231016170f658200202020202020202020202020202020202020202",
            "020202020202020202020202f6f619012c00008366537461676564f6f6",
        )
    );

    let cases = [
        (
            Result1::Refused {
                error: "ArtifactTrustDenied",
                basis: Some("NotActive"),
                class: "PreExecutionRejection",
            },
            concat!(
                "8b64504f4231016170f6f6f6f600000084675265667573656473417274696661",
                "6374547275737444656e696564694e6f74416374697665755072654578656375",
                "74696f6e52656a656374696f6e",
            ),
        ),
        (
            Result1::Refused {
                error: "IncompatibleAbi",
                basis: None,
                class: "PreExecutionRejection",
            },
            concat!(
                "8b64504f4231016170f6f6f6f60000008467526566757365646f496e636f6d70",
                "617469626c65416269f675507265457865637574696f6e52656a656374696f6e",
            ),
        ),
        (
            Result1::Failed {
                error: "FuelExhausted",
                class: "Authoritative",
            },
            concat!(
                "8b64504f4231016170f6f6f6f600000083664661696c65646d4675656c457868",
                "6175737465646d417574686f7269746174697665",
            ),
        ),
        (
            Result1::Discarded,
            "8b64504f4231016170f6f6f6f60000008169446973636172646564",
        ),
    ];
    for (result, expected) in cases {
        let record = CommunityPluginSubjectOutcomeV1 {
            tick: 0,
            ..outcome(result, false)
        };
        assert_eq!(hex::encode(&outcome_bytes_of(&record)), expected);
    }
}
