//! ADR-021 Revision 4 Decision 3 inherited-lineage erasure gating (#499).
//!
//! A Fork's stitched history includes its ancestors' Events. Every stitched
//! read, `Export`, projection read and Driver pass of a Fork therefore applies
//! each inherited ancestor's own erasure decision for the same operation,
//! under one fence, and fails closed with the same closed error when any
//! contributing scope denies.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use pos_core::{
    ConsentAuthority, CoreError, EntityId, ErasureContainmentErrorV1, ErasureContainmentGateV1,
    Event, EventReadBounds, Seq, SeqRange, TimelineId, TimelineMeta,
};
use pos_runtime::{
    LocalScheduledAdmissionHostV1, PluginRegistry, RuntimeError, ScheduledAdmissionStoreV1,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};

use super::{
    harness::Capture,
    support::{ancestry, draft, pass, persona_token, FixturePlugin, ScriptedDriver, TestOk},
};

const SIGNAL: &str = "inherited.signal";

/// A root with two Events, its Fork at Seq 2 and that Fork's own Fork, plus
/// an unrelated root with one Event and its Fork, behind one open gate.
struct Lineage {
    store: &'static str,
    backend: Box<dyn ScheduledAdmissionStoreV1>,
    gate: Arc<ErasureContainmentGateV1>,
    root: TimelineId,
    child: TimelineId,
    grandchild: TimelineId,
    unrelated: TimelineId,
    unrelated_fork: TimelineId,
}

fn lineages() -> Vec<Lineage> {
    let backends: [(&'static str, Box<dyn ScheduledAdmissionStoreV1>); 2] = [
        ("memory", Box::new(MemoryStore::new())),
        ("sqlite", Box::new(SqliteStore::open(":memory:").test_ok())),
    ];
    backends
        .into_iter()
        .map(|(store, mut backend)| {
            let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
            backend.bind_erasure_gate(Arc::clone(&gate)).test_ok();
            let entity = EntityId::new();
            let root = backend.create_timeline("root").test_ok().id();
            backend
                .append(
                    root,
                    &[draft(entity, SIGNAL, b"a"), draft(entity, SIGNAL, b"b")],
                )
                .test_ok();
            let child = backend.fork(root, Seq::from_u64(2), "child").test_ok().id();
            let grandchild = backend
                .fork(child, Seq::from_u64(2), "grandchild")
                .test_ok()
                .id();
            let unrelated = backend.create_timeline("unrelated").test_ok().id();
            backend
                .append(unrelated, &[draft(entity, SIGNAL, b"c")])
                .test_ok();
            let unrelated_fork = backend
                .fork(unrelated, Seq::from_u64(1), "unrelated-fork")
                .test_ok()
                .id();
            Lineage {
                store,
                backend,
                gate,
                root,
                child,
                grandchild,
                unrelated,
                unrelated_fork,
            }
        })
        .collect()
}

/// A registry on the lineage's gate whose one Driver would emit a signal,
/// with that Driver's step counter.
fn signalling_registry(
    lineage: &Lineage,
    authority: &ConsentAuthority,
) -> (PluginRegistry, Arc<AtomicUsize>) {
    let driver = ScriptedDriver::new(
        "inherited-signal",
        vec![draft(EntityId::new(), SIGNAL, b"pass")],
    );
    let steps = Arc::clone(&driver.steps);
    let mut registry = PluginRegistry::new()
        .with_erasure_gate(lineage.gate.clone())
        .with_consent_authority(authority.clone());
    registry
        .register_generated(
            &FixturePlugin::new("inherited-signal", &[SIGNAL], true),
            None,
            Some(Box::new(driver)),
        )
        .test_ok();
    registry.compose_non_participant_drivers().test_ok();
    (registry, steps)
}

/// The closed erasure decision of a runtime operation, or `ok`.
fn decision<T>(result: &Result<T, RuntimeError>) -> String {
    match result {
        Ok(_) => "ok".to_owned(),
        // Non-erasure errors render with their full Debug output.
        Err(RuntimeError::ErasureContainment(error)) => format!("{error:?}"),
        Err(error) => format!("{error:?}"),
    }
}

/// The closed error of a store read, or the number of Events it returned.
fn read_outcome(result: &Result<Vec<Event>, CoreError>) -> String {
    result.as_ref().map_or_else(
        |error| format!("{error:?}"),
        |events| events.len().to_string(),
    )
}

fn own_events(lineage: &Lineage, timeline: TimelineId) -> usize {
    lineage
        .backend
        .read_own(timeline, SeqRange::all())
        .test_ok()
        .len()
}

/// PCF-R4-006: a Fork of a frozen ancestor fails its Driver pass and its
/// stitched read closed, and nothing commits.
#[must_use]
pub fn frozen_ancestor_fails_pass_and_read() -> Capture {
    let mut capture = Capture::default();
    let host = LocalScheduledAdmissionHostV1::shared().test_ok();
    for mut lineage in lineages() {
        let store = lineage.store;
        let authority = ConsentAuthority::new();
        let (mut registry, steps) = signalling_registry(&lineage, &authority);
        let child_chain = ancestry(lineage.backend.as_ref(), lineage.child);
        let grandchild_chain = ancestry(lineage.backend.as_ref(), lineage.grandchild);
        let revisions = host
            .observe(&registry, lineage.backend.as_mut(), lineage.child)
            .test_ok();
        lineage.gate.freeze_timeline_for_test(lineage.root);

        let head = Seq::from_u64(2);
        let child_pass =
            registry.step_all_anchored_with_events(lineage.child, &child_chain, head, &[]);
        let grandchild_pass = registry.step_all_anchored_with_events(
            lineage.grandchild,
            &grandchild_chain,
            head,
            &[],
        );
        let admitted = host.admit(&mut registry, lineage.backend.as_mut(), revisions, head, 0);
        capture.record(store, "pass.child", decision(&child_pass));
        capture.record(store, "pass.grandchild", decision(&grandchild_pass));
        capture.record(store, "admitted", decision(&admitted));
        capture.record(store, "driver.steps", steps.load(Ordering::SeqCst));
        capture.record(
            store,
            "own-events.child",
            own_events(&lineage, lineage.child),
        );
        for (key, timeline) in [
            ("read.child", lineage.child),
            ("read.grandchild", lineage.grandchild),
        ] {
            let read = lineage.backend.read(timeline, SeqRange::all());
            capture.record(store, key, read_outcome(&read));
        }
        let unrelated = pass(
            &mut registry,
            lineage.backend.as_mut(),
            lineage.unrelated,
            None,
        );
        capture.record(store, "unrelated.committed", decision(&unrelated));
        capture.record(
            store,
            "unrelated.events",
            own_events(&lineage, lineage.unrelated),
        );
    }
    capture
}

/// PCF-R4-007: inherited reads follow a completed ancestor's persisted state.
///
/// They behave exactly as a direct read does, and an unrelated Fork reads
/// normally.
#[must_use]
pub fn completed_ancestor_follows_persisted_state() -> Capture {
    let mut capture = Capture::default();
    for lineage in lineages() {
        let store = lineage.store;
        let authority = ConsentAuthority::new();
        let (mut registry, _) = signalling_registry(&lineage, &authority);
        let child_chain = ancestry(lineage.backend.as_ref(), lineage.child);
        let unrelated_chain = ancestry(lineage.backend.as_ref(), lineage.unrelated_fork);
        let lifecycle = lineage
            .gate
            .complete_timeline_erasure_for_test(lineage.root)
            .test_ok();
        capture.record(store, "lifecycle", format!("{lifecycle:?}"));
        let backend = lineage.backend.as_ref();
        capture.record(
            store,
            "ancestor.read",
            read_outcome(&backend.read(lineage.root, SeqRange::all())),
        );
        capture.record(
            store,
            "fork.read",
            read_outcome(&backend.read(lineage.child, SeqRange::all())),
        );
        capture.record(
            store,
            "fork.read-bounded",
            read_outcome(&backend.read_bounded(
                lineage.child,
                SeqRange::all(),
                EventReadBounds::new(1_024, 64, 8, 64),
            )),
        );
        capture.record(
            store,
            "unrelated-fork.read",
            read_outcome(&backend.read(lineage.unrelated_fork, SeqRange::all())),
        );
        let head = Seq::from_u64(2);
        let fork_pass =
            registry.step_all_anchored_with_events(lineage.child, &child_chain, head, &[]);
        registry.abort_step();
        capture.record(store, "fork.pass", decision(&fork_pass));
        let unrelated_pass = registry.step_all_anchored_with_events(
            lineage.unrelated_fork,
            &unrelated_chain,
            Seq::from_u64(1),
            &[],
        );
        registry.abort_step();
        capture.record(store, "unrelated-fork.pass", decision(&unrelated_pass));
    }
    capture
}

/// PCF-R4-008: with an ancestor in a frozen or completed scope, a Fork's
/// `Export` and projection-read paths fail closed, and an unrelated Fork
/// succeeds.
#[must_use]
pub fn export_and_projection_fail_closed() -> Capture {
    let mut capture = Capture::default();
    for scope in ["frozen", "completed"] {
        for lineage in lineages() {
            record_export_and_projection(&mut capture, scope, &lineage);
        }
    }
    capture
}

fn record_export_and_projection(capture: &mut Capture, scope: &str, lineage: &Lineage) {
    let store = lineage.store;
    let authority = ConsentAuthority::new();
    let subject = EntityId::new();
    let token = persona_token(&authority, lineage.child, subject);
    let (mut registry, _) = signalling_registry(lineage, &authority);
    let child_chain = ancestry(lineage.backend.as_ref(), lineage.child);
    let unrelated_chain = ancestry(lineage.backend.as_ref(), lineage.unrelated_fork);
    if scope == "frozen" {
        lineage.gate.freeze_timeline_for_test(lineage.root);
    } else {
        lineage
            .gate
            .complete_timeline_erasure_for_test(lineage.root)
            .test_ok();
    }
    let backend = lineage.backend.as_ref();
    for (key, timeline) in [
        ("chain-hash", lineage.child),
        ("unrelated.chain-hash", lineage.unrelated_fork),
    ] {
        let hash = backend.chain_hash_at(timeline, Seq::from_u64(1));
        let outcome = hash.map_or_else(|error| format!("{error:?}"), |_| "ok".to_owned());
        capture.record(store, &format!("{scope}.{key}"), outcome);
    }
    let refold = registry.refold_projection_events(lineage.child, &child_chain, &[], None);
    capture.record(store, &format!("{scope}.refold.refused"), refold.is_err());
    let unrelated_refold =
        registry.refold_projection_events(lineage.unrelated_fork, &unrelated_chain, &[], None);
    capture.record(
        store,
        &format!("{scope}.unrelated.refold"),
        decision(&unrelated_refold),
    );
    let projection = registry.projection_state_for_reducer(
        lineage.child,
        &child_chain,
        Seq::from_u64(2),
        0,
        &token,
        "inherited-signal",
        subject,
    );
    capture.record(store, &format!("{scope}.projection"), decision(&projection));
}

/// PCF-R4-009: the unanchored `step_all` on a Fork whose ancestor is frozen
/// fails closed with `AccessFrozen`, and nothing commits.
#[must_use]
pub fn unanchored_step_all_fails_closed() -> Capture {
    let mut capture = Capture::default();
    let host = LocalScheduledAdmissionHostV1::shared().test_ok();
    for mut lineage in lineages() {
        let store = lineage.store;
        let authority = ConsentAuthority::new();
        let (mut registry, steps) = signalling_registry(&lineage, &authority);
        let child_chain: Vec<TimelineMeta> = ancestry(lineage.backend.as_ref(), lineage.child);
        let revisions = host
            .observe(&registry, lineage.backend.as_mut(), lineage.child)
            .test_ok();
        lineage.gate.freeze_timeline_for_test(lineage.root);
        let stepped = registry.step_all(lineage.child, &child_chain);
        let admitted = host.admit(
            &mut registry,
            lineage.backend.as_mut(),
            revisions,
            Seq::from_u64(2),
            0,
        );
        capture.record(store, "step_all", decision(&stepped));
        capture.record(
            store,
            "frozen",
            matches!(
                stepped,
                Err(RuntimeError::ErasureContainment(
                    ErasureContainmentErrorV1::AccessFrozen
                ))
            ),
        );
        capture.record(store, "driver.steps", steps.load(Ordering::SeqCst));
        capture.record(store, "admitted", decision(&admitted));
        capture.record(store, "own-events", own_events(&lineage, lineage.child));
    }
    capture
}
