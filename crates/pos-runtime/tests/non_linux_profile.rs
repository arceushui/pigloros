#![cfg(not(target_os = "linux"))]

use pos_core::{Capability, Plugin, PluginId};
use pos_runtime::{InstalledOutputPolicySourceV1, OutputAdmissionErrorV1, OutputPolicyBindingV1};

struct FixturePlugin(PluginId);

impl Plugin for FixturePlugin {
    fn id(&self) -> PluginId {
        self.0
    }

    fn name(&self) -> &'static str {
        "non-linux-fixture"
    }

    fn capability(&self) -> Capability {
        Capability::default()
    }
}

#[test]
fn non_linux_host_cannot_promote_generated_profile() {
    let plugin = FixturePlugin(PluginId::new());
    assert!(matches!(
        OutputPolicyBindingV1::from_installed_source(
            &plugin,
            InstalledOutputPolicySourceV1::Generated,
            &[],
            "deterministic-local-v1",
        ),
        Err(OutputAdmissionErrorV1::ArtifactInvalid { kind: "EPF1" })
    ));
}
