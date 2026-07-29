use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{
    clock::WallTime,
    crypto::Hash,
    ids::{PluginId, TimelineId},
};

/// Records a nondeterministic adapter call so it can be replayed identically.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterRecord {
    pub plugin_id: PluginId,
    pub call_index: u64,
    pub input_hash: Hash,
    pub output_hash: Hash,
    pub wall_time: WallTime,
}

/// A versioned, allow-listed experiment configuration that can be executed again.
///
/// This deliberately describes only compositions the host knows how to construct;
/// arbitrary plugin trait objects are not portable manifest data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExperimentRecipe {
    /// The deterministic reference composition shipped by `pos experiment run`.
    BuiltinReferenceV1 { ticks: u64 },
}

/// A signed manifest that allows a third party to re-run an experiment and
/// get a bit-identical result hash. Moat #5: cryptographically verifiable provenance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproManifest {
    pub timeline_id: TimelineId,
    pub head_hash: Hash,
    pub created_at: WallTime,
    pub plugin_versions: HashMap<String, String>,
    pub adapter_records: Vec<AdapterRecord>,
    /// Human-readable label for this experiment run.
    pub label: Option<String>,
    /// An executable configuration when the producing host can provide one.
    #[serde(default)]
    pub recipe: Option<ExperimentRecipe>,
}

impl ReproManifest {
    #[must_use]
    pub fn new(timeline_id: TimelineId, head_hash: Hash, created_at: WallTime) -> Self {
        Self {
            timeline_id,
            head_hash,
            created_at,
            plugin_versions: HashMap::new(),
            adapter_records: Vec::new(),
            label: None,
            recipe: None,
        }
    }

    #[must_use]
    pub fn with_plugin_version(
        mut self,
        plugin: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        self.plugin_versions.insert(plugin.into(), version.into());
        self
    }

    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Attach the versioned recipe required for an independent re-run.
    #[must_use]
    pub fn with_recipe(mut self, recipe: ExperimentRecipe) -> Self {
        self.recipe = Some(recipe);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::TimelineId;

    fn sample_manifest() -> ReproManifest {
        ReproManifest::new(
            TimelineId::new(),
            Hash::from_bytes([1u8; 32]),
            WallTime::from_micros(1_000_000),
        )
        .with_plugin_version("pos-core", "0.1.0")
        .with_label("experiment-001")
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn manifest_json_round_trip() {
        let m = sample_manifest();
        let back: ReproManifest =
            serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn manifest_cbor_round_trip() {
        let m = sample_manifest();
        let mut buf = Vec::new();
        ciborium::into_writer(&m, &mut buf).unwrap();
        let back: ReproManifest = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn adapter_record_json_round_trip() {
        let ar = AdapterRecord {
            plugin_id: PluginId::new(),
            call_index: 7,
            input_hash: Hash::from_bytes([2u8; 32]),
            output_hash: Hash::from_bytes([3u8; 32]),
            wall_time: WallTime::from_micros(500),
        };
        let back: AdapterRecord =
            serde_json::from_str(&serde_json::to_string(&ar).unwrap()).unwrap();
        assert_eq!(ar, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn manifest_with_adapter_records() {
        let mut m = sample_manifest();
        m.adapter_records.push(AdapterRecord {
            plugin_id: PluginId::new(),
            call_index: 0,
            input_hash: Hash::zero(),
            output_hash: Hash::zero(),
            wall_time: WallTime::from_micros(0),
        });
        let back: ReproManifest =
            serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(m.adapter_records.len(), back.adapter_records.len());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn manifest_label_optional() {
        let m = ReproManifest::new(TimelineId::new(), Hash::zero(), WallTime::from_micros(0));
        assert!(m.label.is_none());

        let labeled = m.with_label("my-run");
        assert_eq!(labeled.label.as_deref(), Some("my-run"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn manifest_recipe_round_trip() {
        let manifest =
            sample_manifest().with_recipe(ExperimentRecipe::BuiltinReferenceV1 { ticks: 12 });
        let decoded: ReproManifest =
            serde_json::from_str(&serde_json::to_string(&manifest).unwrap()).unwrap();
        assert_eq!(decoded.recipe, manifest.recipe);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn legacy_manifest_without_recipe_is_readable() {
        let json = serde_json::to_string(&sample_manifest()).unwrap();
        let decoded: ReproManifest = serde_json::from_str(&json).unwrap();
        assert!(decoded.recipe.is_none());
    }
}
