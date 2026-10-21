//! The ADR-119 trigger reader (section 4.2): the pass outcome to a closed cause.

use pos_core::PluginId;
use pos_runtime::community_plugin_host::{CommunityPassOutcomeV1, PassResultV1};
use pos_runtime::FallbackTriggerCauseV1;

/// The cause `plugin`'s member failed with in the pass `outcome`, if the pass can trigger.
///
/// Only a `Failed` or `Refused` pass can trigger. The cause is the member's
/// `gates[i].launch_failure`: the latest failure the pass recorded for the member, captured
/// before the pass closed, so never an earlier pass's. A `Committed` pass never triggers, even
/// with a `launch_failure` left by a successful retry, and an `InDoubt` pass waits for
/// recovery. The handle, its sticky `last_failure` and the registry's mirrored availability
/// are never read. Whether the cause is eligible, and for which entry, is the classifier's
/// decision (`declared_fallback_trigger_v1`).
#[must_use]
pub fn fallback_trigger_cause_v1(
    outcome: &CommunityPassOutcomeV1,
    plugin: PluginId,
) -> Option<FallbackTriggerCauseV1> {
    let failed = matches!(
        outcome.result,
        PassResultV1::Failed { .. } | PassResultV1::Refused
    );
    let entry = outcome.gates.iter().find(|entry| entry.plugin == plugin);
    let failure = entry.and_then(|entry| entry.launch_failure);
    failure
        .filter(|_| failed)
        .map(FallbackTriggerCauseV1::from_host_error)
}
