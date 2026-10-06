//! Full validation of one `plugin-output` before anything is returned.
//!
//! Fields are validated in WIT order, so the lowest failing field ordinal
//! wins (ADR-061 validation order). Shape, length, encoding, order, echo and
//! digest failures are `InvalidGuestOutput`; the effective `event_count`,
//! `event_bytes` and `state_bytes` limits and the WIT count bounds are
//! `OutputLimitExceeded`. Any failure discards the whole output.
//!
//! `event_bytes` counts the `canonical-payload` bytes of every `EventDraft`.
//! `EventDrafts` and trace annotations keep the guest's order; each
//! dependency-digest list must be strictly increasing.

use pos_crypto::plugin_execution::DeterministicBudgetV1;
use pos_runtime::community_plugin_host::{
    plugin_output_digest_v1, EventDraftV1, PluginOutputV1, TraceAnnotationV1,
};
use wasmtime::component::Val;

use crate::lift::{
    bytes, digest, ensure, fields, fixed, id, list, ordered_digests, u32_value, within, Lifted,
    INVALID, LIMIT,
};

/// WIT bound on trace annotations in one output.
pub(crate) const MAX_TRACE_ANNOTATIONS: usize = 1_024;
/// WIT bound on dependency digests in one output.
pub(crate) const MAX_DEPENDENCY_DIGESTS: usize = 4_096;

/// What one output is validated against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OutputBounds {
    /// The invocation ID the output must echo.
    pub(crate) invocation_id: [u8; 16],
    /// Effective `event_count`, `event_bytes` and `state_bytes`.
    pub(crate) limits: DeterministicBudgetV1,
}

/// The dependency digests an output may still carry.
struct DependencyBudget {
    left: usize,
}

impl DependencyBudget {
    fn charge(&mut self, digests: Vec<[u8; 32]>) -> Lifted<Vec<[u8; 32]>> {
        self.left = self.left.checked_sub(digests.len()).ok_or(LIMIT)?;
        Ok(digests)
    }
}

/// Lift and validate one `plugin-output`.
pub(crate) fn plugin_output(value: &Val, bounds: &OutputBounds) -> Lifted<PluginOutputV1> {
    let [invocation_id, drafts, schema, state, annotations, consumed, output_digest] =
        fields(value)?;
    let mut dependencies = DependencyBudget {
        left: MAX_DEPENDENCY_DIGESTS,
    };
    let output = PluginOutputV1 {
        invocation_id: echoed_invocation(invocation_id, bounds.invocation_id)?,
        event_drafts: event_drafts(drafts, &bounds.limits, &mut dependencies)?,
        next_state_schema: digest(schema)?,
        next_state_bytes: state_bytes(state, bounds.limits.state_bytes)?,
        trace_annotations: trace_annotations(annotations, &mut dependencies)?,
        consumed_dependencies: dependencies.charge(ordered_digests(consumed)?)?,
        output_digest: digest(output_digest)?,
    };
    ensure(output.output_digest == plugin_output_digest_v1(&output), INVALID)?;
    Ok(output)
}

fn echoed_invocation(value: &Val, invocation_id: [u8; 16]) -> Lifted<[u8; 16]> {
    let echoed = fixed(value)?;
    ensure(echoed == invocation_id, INVALID)?;
    Ok(echoed)
}

fn event_drafts(
    value: &Val,
    limits: &DeterministicBudgetV1,
    dependencies: &mut DependencyBudget,
) -> Lifted<Vec<EventDraftV1>> {
    let items = list(value)?;
    within(items.len(), limits.event_count)?;
    let drafts = items
        .iter()
        .map(|item| event_draft(item, dependencies))
        .collect::<Lifted<Vec<_>>>()?;
    let payload_bytes = drafts
        .iter()
        .map(|draft| draft.canonical_payload.len())
        .fold(0, usize::saturating_add);
    within(payload_bytes, limits.event_bytes)?;
    Ok(drafts)
}

fn event_draft(value: &Val, dependencies: &mut DependencyBudget) -> Lifted<EventDraftV1> {
    let [schema, entity, event_type, payload, dependency_digests] = fields(value)?;
    Ok(EventDraftV1 {
        event_schema_id: u32_value(schema)?,
        entity_id: fixed(entity)?,
        event_type: id(event_type)?,
        canonical_payload: bytes(payload)?,
        dependency_digests: dependencies.charge(ordered_digests(dependency_digests)?)?,
    })
}

fn state_bytes(value: &Val, limit: u64) -> Lifted<Vec<u8>> {
    let state = bytes(value)?;
    within(state.len(), limit)?;
    Ok(state)
}

fn trace_annotations(
    value: &Val,
    dependencies: &mut DependencyBudget,
) -> Lifted<Vec<TraceAnnotationV1>> {
    let items = list(value)?;
    ensure(items.len() <= MAX_TRACE_ANNOTATIONS, LIMIT)?;
    items
        .iter()
        .map(|item| trace_annotation(item, dependencies))
        .collect()
}

fn trace_annotation(value: &Val, dependencies: &mut DependencyBudget) -> Lifted<TraceAnnotationV1> {
    let [schema, canonical_bytes, dependency_digests] = fields(value)?;
    Ok(TraceAnnotationV1 {
        annotation_schema_id: u32_value(schema)?,
        canonical_bytes: bytes(canonical_bytes)?,
        dependency_digests: dependencies.charge(ordered_digests(dependency_digests)?)?,
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::host_v1::byte_list;
    use crate::test_values::{digest_val, digests_val, numbered_digest, record, text_val};

    const INVOCATION: [u8; 16] = [1; 16];
    const LIMITS: DeterministicBudgetV1 = DeterministicBudgetV1 {
        memory_bytes: 65_536,
        fuel: 1,
        host_calls: 0,
        event_count: 2,
        event_bytes: 4,
        state_bytes: 3,
        log_calls: 0,
        log_bytes: 0,
    };
    const BOUNDS: OutputBounds = OutputBounds {
        invocation_id: INVOCATION,
        limits: LIMITS,
    };

    fn draft_val(draft: &EventDraftV1) -> Val {
        record(vec![
            ("event-schema-id", Val::U32(draft.event_schema_id)),
            ("entity-id", byte_list(&draft.entity_id)),
            ("event-type", text_val(&draft.event_type)),
            ("canonical-payload", byte_list(&draft.canonical_payload)),
            ("dependency-digests", digests_val(&draft.dependency_digests)),
        ])
    }

    fn annotation_val(annotation: &TraceAnnotationV1) -> Val {
        record(vec![
            (
                "annotation-schema-id",
                Val::U32(annotation.annotation_schema_id),
            ),
            ("canonical-bytes", byte_list(&annotation.canonical_bytes)),
            (
                "dependency-digests",
                digests_val(&annotation.dependency_digests),
            ),
        ])
    }

    /// The Canonical ABI value of `output`, with its digest as given.
    fn output_val(output: &PluginOutputV1) -> Val {
        record(vec![
            ("invocation-id", byte_list(&output.invocation_id)),
            (
                "event-drafts",
                Val::List(output.event_drafts.iter().map(draft_val).collect()),
            ),
            ("next-state-schema", digest_val(&output.next_state_schema)),
            ("next-state-bytes", byte_list(&output.next_state_bytes)),
            (
                "trace-annotations",
                Val::List(
                    output
                        .trace_annotations
                        .iter()
                        .map(annotation_val)
                        .collect(),
                ),
            ),
            (
                "consumed-dependencies",
                digests_val(&output.consumed_dependencies),
            ),
            ("output-digest", digest_val(&output.output_digest)),
        ])
    }

    fn draft(payload: &[u8]) -> EventDraftV1 {
        EventDraftV1 {
            event_schema_id: 1,
            entity_id: [2; 16],
            event_type: "plugin.event".to_owned(),
            canonical_payload: payload.to_vec(),
            dependency_digests: vec![[3; 32], [4; 32]],
        }
    }

    fn annotation(dependencies: Vec<[u8; 32]>) -> TraceAnnotationV1 {
        TraceAnnotationV1 {
            annotation_schema_id: 5,
            canonical_bytes: vec![6],
            dependency_digests: dependencies,
        }
    }

    /// A valid output with its digest.
    fn output() -> PluginOutputV1 {
        sealed(PluginOutputV1 {
            invocation_id: INVOCATION,
            event_drafts: vec![draft(&[1, 2]), draft(&[3, 4])],
            next_state_schema: [7; 32],
            next_state_bytes: vec![8, 9, 10],
            trace_annotations: vec![annotation(vec![[9; 32]])],
            consumed_dependencies: vec![[10; 32]],
            output_digest: [0; 32],
        })
    }

    fn sealed(mut output: PluginOutputV1) -> PluginOutputV1 {
        output.output_digest = plugin_output_digest_v1(&output);
        output
    }

    fn validate(output: &PluginOutputV1) -> Lifted<PluginOutputV1> {
        plugin_output(&output_val(output), &BOUNDS)
    }

    #[test]
    fn a_valid_output_lifts_unchanged() {
        assert_eq!(validate(&output()), Ok(output()));
    }

    #[test]
    fn the_digest_and_the_echoed_invocation_must_match() {
        let mut forged = output();
        forged.output_digest = [0; 32];
        assert_eq!(validate(&forged), Err(INVALID));
        let mut foreign = output();
        foreign.invocation_id = [9; 16];
        assert_eq!(validate(&sealed(foreign)), Err(INVALID));
        assert_eq!(plugin_output(&Val::U8(0), &BOUNDS), Err(INVALID));
    }

    #[test]
    fn event_drafts_stay_within_count_bytes_and_shape() {
        let mut many = output();
        many.event_drafts.push(draft(&[]));
        assert_eq!(validate(&sealed(many)), Err(LIMIT));
        let mut heavy = output();
        heavy.event_drafts[1].canonical_payload.push(5);
        assert_eq!(validate(&sealed(heavy)), Err(LIMIT));
        let mut unnamed = output();
        unnamed.event_drafts[0].event_type = "Event".to_owned();
        assert_eq!(validate(&sealed(unnamed)), Err(INVALID));
        let mut unordered = output();
        unordered.event_drafts[0].dependency_digests.reverse();
        assert_eq!(validate(&sealed(unordered)), Err(INVALID));
    }

    #[test]
    fn state_bytes_stay_within_the_effective_limit() {
        let mut large = output();
        large.next_state_bytes.push(11);
        assert_eq!(validate(&sealed(large)), Err(LIMIT));
    }

    #[test]
    fn annotations_and_dependencies_stay_within_the_wit_bounds() {
        let mut fullest = output();
        fullest.trace_annotations = vec![annotation(Vec::new()); MAX_TRACE_ANNOTATIONS];
        assert!(validate(&sealed(fullest.clone())).is_ok());
        fullest.trace_annotations.push(annotation(Vec::new()));
        assert_eq!(validate(&sealed(fullest)), Err(LIMIT));
        let digests: Vec<[u8; 32]> = (0..MAX_DEPENDENCY_DIGESTS).map(numbered_digest).collect();
        let mut exact = output();
        exact.event_drafts.clear();
        exact.trace_annotations = vec![annotation(digests[..1].to_vec())];
        exact.consumed_dependencies = digests[1..].to_vec();
        assert!(validate(&sealed(exact.clone())).is_ok());
        exact.event_drafts.push(draft(&[]));
        assert_eq!(validate(&sealed(exact)), Err(LIMIT));
    }

    #[test]
    fn the_first_failing_field_wins() {
        let mut both = output();
        both.event_drafts[1].event_type = "Event".to_owned();
        both.next_state_bytes.push(11);
        assert_eq!(validate(&sealed(both)), Err(INVALID));
        let mut both = output();
        both.event_drafts.push(draft(&[]));
        both.output_digest = [0; 32];
        assert_eq!(validate(&both), Err(LIMIT));
        let mut value = output_val(&output());
        if let Val::Record(fields) = &mut value {
            fields[2].1 = digest_val(&[0; 31]);
            fields[3].1 = byte_list(&[0; 4]);
        }
        assert_eq!(plugin_output(&value, &BOUNDS), Err(INVALID));
    }

    /// `value` with field `index` of the first item of list field `list`
    /// replaced by a `u8`, or the whole first item when `index` is `None`.
    fn replaced_item(value: &Val, list: usize, index: Option<usize>) -> Val {
        let mut value = value.clone();
        if let Val::Record(fields) = &mut value {
            if let Val::List(items) = &mut fields[list].1 {
                match (index, &mut items[0]) {
                    (Some(index), Val::Record(item)) => item[index].1 = Val::U8(0),
                    (_, item) => *item = Val::U8(0),
                }
            }
        }
        value
    }

    fn replaced(value: &Val, index: usize) -> Val {
        let mut value = value.clone();
        if let Val::Record(fields) = &mut value {
            fields[index].1 = Val::U8(0);
        }
        value
    }

    #[test]
    fn every_field_of_the_wrong_kind_is_invalid() {
        let value = output_val(&output());
        let invalid = |broken: &Val| plugin_output(broken, &BOUNDS) == Err(INVALID);
        for index in 0..7 {
            assert!(invalid(&replaced(&value, index)), "output {index}");
        }
        for (list, fields) in [(1, 5), (4, 3)] {
            for index in 0..fields {
                let broken = replaced_item(&value, list, Some(index));
                assert!(invalid(&broken), "{list}.{index}");
            }
            assert!(invalid(&replaced_item(&value, list, None)), "{list}");
        }
        let mut unordered = output();
        unordered.consumed_dependencies = vec![[2; 32], [1; 32]];
        assert_eq!(validate(&sealed(unordered)), Err(INVALID));
    }
}
