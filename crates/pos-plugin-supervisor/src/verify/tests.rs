use pos_runtime::community_plugin_host::{EventDraftV1, TraceAnnotationV1};

use super::*;
use crate::fixtures::{descriptor, invocation, negotiated, output};

#[test]
fn a_descriptor_must_describe_the_negotiated_release() {
    let negotiated = negotiated();
    let valid = descriptor(&negotiated);
    assert!(verify_descriptor(&valid, &negotiated));
    let changes: [fn(&mut PluginDescriptorV1); 9] = [
        |d| d.plugin_id.push('x'),
        |d| d.world.push('x'),
        |d| d.abi_major = 1,
        |d| d.min_abi_minor = 1,
        |d| d.max_abi_minor = 1,
        |d| d.required_features.push("alpha".to_owned()),
        |d| d.manifest_digest = [1; 32],
        |d| d.release_digest = [1; 32],
        |d| d.release_digest[31] = 1,
    ];
    for (index, change) in changes.iter().enumerate() {
        let mut changed = valid.clone();
        change(&mut changed);
        assert!(!verify_descriptor(&changed, &negotiated), "change {index}");
    }
}

fn resealed(change: impl FnOnce(&mut PluginOutputV1)) -> PluginOutputV1 {
    let mut changed = output(&invocation());
    change(&mut changed);
    changed.output_digest = plugin_output_digest_v1(&changed);
    changed
}

#[test]
fn an_output_must_answer_its_invocation_within_limits() {
    let invocation = invocation();
    let limits = DeterministicBudgetV1 {
        event_count: 1,
        state_bytes: 4,
        ..DeterministicBudgetV1::MAXIMA
    };
    assert!(verify_output(&output(&invocation), &invocation, &limits));
    let mut tampered = output(&invocation);
    tampered.output_digest[0] ^= 1;
    assert!(!verify_output(&tampered, &invocation, &limits));
    let foreign = resealed(|output| output.invocation_id = [0; 16]);
    assert!(!verify_output(&foreign, &invocation, &limits));
    let draft = output(&invocation).event_drafts[0].clone();
    let many: Vec<EventDraftV1> = vec![draft; 2];
    let crowded = resealed(|output| output.event_drafts = many);
    assert!(!verify_output(&crowded, &invocation, &limits));
    let large = resealed(|output| output.next_state_bytes = vec![0; 5]);
    assert!(!verify_output(&large, &invocation, &limits));
    let annotation = |bytes| TraceAnnotationV1 {
        annotation_schema_id: 1,
        canonical_bytes: vec![0; bytes],
        dependency_digests: Vec::new(),
    };
    let half = MAX_TRACE_ANNOTATION_BYTES_V1 / 2;
    let full = resealed(|output| output.trace_annotations = vec![annotation(half); 2]);
    assert!(verify_output(&full, &invocation, &limits));
    let over = resealed(|output| {
        output.trace_annotations = vec![annotation(half), annotation(half + 1)];
    });
    assert!(!verify_output(&over, &invocation, &limits));
}
