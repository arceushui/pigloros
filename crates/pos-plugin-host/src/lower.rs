//! Lowering of host-built values into Canonical ABI values.

use pos_runtime::community_plugin_host::{ArtifactRefV1, PluginInvocationV1};
use wasmtime::component::Val;


/// The Canonical ABI value of `invocation` with `kind`.
pub(crate) fn invocation_val(invocation: &PluginInvocationV1, kind: &str) -> Val {
    record(vec![
        ("invocation-id", byte_list(&invocation.invocation_id)),
        ("kind", Val::Enum(kind.to_owned())),
        (
            "timeline-position",
            record(vec![
                (
                    "timeline-id",
                    byte_list(&invocation.timeline_position.timeline_id),
                ),
                ("seq", Val::U64(invocation.timeline_position.seq)),
                ("tick", Val::U64(invocation.timeline_position.tick)),
                (
                    "scheduler-position",
                    Val::U32(invocation.timeline_position.scheduler_position),
                ),
            ]),
        ),
        (
            "output-base-ordinal",
            Val::U32(invocation.output_base_ordinal),
        ),
        ("principal-ref", lower_artifact(&invocation.principal_ref)),
        (
            "authorization-decision",
            lower_artifact(&invocation.authorization_decision),
        ),
        (
            "observation-snapshot",
            lower_artifact(&invocation.observation_snapshot),
        ),
        (
            "observation-bytes",
            byte_list(&invocation.observation_bytes),
        ),
        (
            "prior-state-schema",
            lower_digest(&invocation.prior_state_schema),
        ),
        (
            "prior-state-bytes",
            byte_list(&invocation.prior_state_bytes),
        ),
        (
            "execution-profile-digest",
            lower_digest(&invocation.execution_profile_digest),
        ),
        (
            "trust-policy-snapshot-digest",
            lower_digest(&invocation.trust_policy_snapshot_digest),
        ),
        (
            "deterministic-budget-id",
            record(vec![(
                "utf8",
                byte_list(invocation.deterministic_budget_id.as_bytes()),
            )]),
        ),
        (
            "deterministic-random-domain",
            lower_digest(&invocation.deterministic_random_domain),
        ),
        ("provenance-root", lower_digest(&invocation.provenance_root)),
    ])
}

/// A `list<u8>` value.
pub(crate) fn byte_list(bytes: &[u8]) -> Val {
    Val::List(bytes.iter().copied().map(Val::U8).collect())
}

/// A record value with `fields` in WIT order.
pub(crate) fn record(fields: Vec<(&str, Val)>) -> Val {
    Val::Record(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

fn lower_digest(value: &[u8; 32]) -> Val {
    record(vec![("value", byte_list(value))])
}

fn lower_artifact(value: &ArtifactRefV1) -> Val {
    record(vec![
        ("schema-id", Val::U32(value.schema_id)),
        ("byte-length", Val::U64(value.byte_length)),
        ("digest", lower_digest(&value.digest)),
    ])
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::test_values::{invocation, ok};

    #[test]
    fn invocations_lower_in_wit_field_order() {
        let Val::Record(fields) = invocation_val(&invocation(), "drive") else {
            return ok(Err("not a record"));
        };
        let names: Vec<&str> = fields.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            [
                "invocation-id",
                "kind",
                "timeline-position",
                "output-base-ordinal",
                "principal-ref",
                "authorization-decision",
                "observation-snapshot",
                "observation-bytes",
                "prior-state-schema",
                "prior-state-bytes",
                "execution-profile-digest",
                "trust-policy-snapshot-digest",
                "deterministic-budget-id",
                "deterministic-random-domain",
                "provenance-root",
            ]
        );
        assert_eq!(fields[1].1, Val::Enum("drive".to_owned()));
        assert_eq!(fields[3].1, Val::U32(6));
    }
}
