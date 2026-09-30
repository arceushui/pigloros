#![cfg(not(target_os = "linux"))]

use pos_core::{Capability, Plugin, PluginId};
use pos_runtime::PluginRegistry;

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
fn non_linux_host_can_register_a_local_plugin() {
    let plugin = FixturePlugin(PluginId::new());
    let mut registry = PluginRegistry::new();
    registry
        .register_local(&plugin, vec!["non-linux.fixture".to_owned()], None, None)
        .expect("local registration should work without installed profile evidence");
    assert_eq!(registry.len(), 1);
}
