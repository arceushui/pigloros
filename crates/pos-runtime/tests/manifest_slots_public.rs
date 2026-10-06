//! ADR-088: host-authored, stable manifest slots declared once at
//! `register_local` and recorded by the registry (#555).

use std::error::Error;

use pos_core::{
    state::{Reducer, State},
    Capability, Event, OwnerIdV1, Plugin, PluginId,
};
use pos_runtime::{
    ManifestRegistrationErrorV1, ManifestSlotErrorV1, ManifestSlotV1, PluginAvailabilityV1,
    PluginRegistrationV1, PluginRegistry, RuntimeError, MAX_MANIFEST_SLOT_BYTES_V1,
};

type TestResult = Result<(), Box<dyn Error>>;

const GRAMMAR_HINT: &str = "use A-Z a-z 0-9 . _ - (1-64 bytes)";

struct SlotPlugin {
    id: PluginId,
    name: &'static str,
    reducer_only: bool,
}

impl SlotPlugin {
    fn new(name: &'static str) -> Self {
        Self {
            id: PluginId::new(),
            name,
            reducer_only: false,
        }
    }

    const fn reducer_only(mut self) -> Self {
        self.reducer_only = true;
        self
    }
}

impl Plugin for SlotPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn capability(&self) -> Capability {
        Capability {
            has_reducer: self.reducer_only,
            ..Capability::default()
        }
    }
}

struct TallyReducer;

impl Reducer for TallyReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, _state: &mut State, _event: &Event) {}
}

fn register(
    registry: &mut PluginRegistry,
    plugin: &SlotPlugin,
    slot: &str,
) -> Result<(), RuntimeError> {
    let reducer: Option<Box<dyn Reducer>> = if plugin.reducer_only {
        Some(Box::new(TallyReducer))
    } else {
        None
    };
    registry.register_local(
        plugin,
        ManifestSlotV1::try_new(slot)?,
        vec![format!("role-{slot}")],
        reducer,
        None,
    )
}

fn catalog_slots(registry: &mut PluginRegistry) -> Result<Vec<String>, Box<dyn Error>> {
    let owner = OwnerIdV1::from_static("app");
    let admitted = registry.admit_local_manifest_registration(owner, 1)?;
    let rows = &admitted.catalog().as_input().rows;
    Ok(rows.iter().map(|row| row.stable_slot.clone()).collect())
}

#[test]
fn a_complete_slot_set_admits_exactly_the_supplied_slots() -> TestResult {
    let north = SlotPlugin::new("weather");
    let south = SlotPlugin::new("weather");
    let tally = SlotPlugin::new("tally").reducer_only();
    let mut registry = PluginRegistry::new();
    register(&mut registry, &south, "weather-south")?;
    register(&mut registry, &tally, "tally")?;
    register(&mut registry, &north, "weather-north")?;

    let expected = ["tally", "weather-north", "weather-south"];
    assert_eq!(catalog_slots(&mut registry)?, expected);
    let owner = OwnerIdV1::from_static("app");
    let resealed = registry.admit_local_manifest_registration(owner, 1);
    assert!(matches!(
        resealed,
        Err(ManifestRegistrationErrorV1::BatchState)
    ));
    Ok(())
}

#[test]
fn same_name_plugins_and_a_reducer_only_plugin_keep_their_own_slots() -> TestResult {
    let north = SlotPlugin::new("weather");
    let south = SlotPlugin::new("weather");
    let tally = SlotPlugin::new("tally").reducer_only();
    let mut registry = PluginRegistry::new();
    register(&mut registry, &north, "weather-north")?;
    register(&mut registry, &south, "weather-south")?;
    register(&mut registry, &tally, "tally")?;

    let recorded = registry.recorded_manifest_slots();
    let text: Vec<(&str, PluginId)> = recorded
        .iter()
        .map(|(slot, plugin_id)| (slot.as_str(), *plugin_id))
        .collect();
    assert_eq!(
        text,
        [
            ("tally", tally.id()),
            ("weather-north", north.id()),
            ("weather-south", south.id()),
        ]
    );
    let owner = OwnerIdV1::from_static("app");
    let admitted = registry.admit_local_manifest_registration(owner, 2)?;
    let rows = &admitted.catalog().as_input().rows;
    assert_eq!(rows.len(), 3);
    for (row, (slot, plugin_id)) in rows.iter().zip(&text) {
        assert_eq!(row.stable_slot, *slot);
        assert_eq!(row.plugin_id, *plugin_id);
    }
    assert_eq!(rows[0].plugin_name, "tally");
    assert_eq!(rows[1].plugin_name, rows[2].plugin_name);
    assert!(rows
        .iter()
        .all(|row| !row.stable_slot.starts_with("plugin-")));
    let sources = registry.admitted_manifest_policy_sources(&admitted)?;
    assert_eq!(sources.len(), 3);
    Ok(())
}

#[test]
fn slot_grammar_pins_both_length_boundaries() -> TestResult {
    let longest = "a".repeat(MAX_MANIFEST_SLOT_BYTES_V1);
    assert_eq!(ManifestSlotV1::try_new(&longest)?.as_str(), longest);
    let too_long = ManifestSlotV1::try_new(&"a".repeat(65));
    assert_eq!(too_long, Err(ManifestSlotErrorV1::TooLong { length: 65 }));
    let empty = ManifestSlotV1::try_new("");
    assert_eq!(empty, Err(ManifestSlotErrorV1::Empty));
    assert_eq!(ManifestSlotV1::try_new("Az09._-")?.as_str(), "Az09._-");
    assert_eq!(
        ManifestSlotErrorV1::Empty.to_string(),
        format!("manifest slot is empty; {GRAMMAR_HINT}")
    );
    assert_eq!(
        ManifestSlotErrorV1::TooLong { length: 65 }.to_string(),
        format!("manifest slot is 65 bytes; {GRAMMAR_HINT}")
    );
    Ok(())
}

#[test]
fn slot_grammar_rejects_space_slash_and_non_ascii_with_actionable_text() {
    let cases = [
        ("Foo Bar", "' '", 3),
        ("a/b", "'/'", 1),
        ("caf\u{e9}", "'\u{e9}'", 3),
    ];
    for (slot, character, index) in cases {
        let error = ManifestSlotV1::try_new(slot).err();
        assert_eq!(
            error.map(|error| error.to_string()),
            Some(format!(
                "manifest slot {slot:?} contains {character} at byte {index}; {GRAMMAR_HINT}"
            ))
        );
    }
}

#[test]
fn a_bad_slot_is_rejected_before_any_registry_mutation() -> TestResult {
    let first = SlotPlugin::new("first");
    let mut registry = PluginRegistry::new();
    register(&mut registry, &first, "first")?;
    let before = registry.recorded_manifest_slots();

    let second = SlotPlugin::new("second");
    let long = "x".repeat(65);
    for bad in ["", "has space", "a/b", "caf\u{e9}", long.as_str()] {
        let result = register(&mut registry, &second, bad);
        assert!(matches!(result, Err(RuntimeError::ManifestSlot(_))));
    }
    assert_eq!(registry.len(), 1);
    assert!(!registry.contains(&second.id()));
    assert_eq!(registry.recorded_manifest_slots(), before);
    register(&mut registry, &second, "second")?;
    assert_eq!(catalog_slots(&mut registry)?, ["first", "second"]);
    Ok(())
}

#[test]
fn a_duplicate_slot_is_rejected_before_any_registry_mutation() -> TestResult {
    let north = SlotPlugin::new("weather");
    let south = SlotPlugin::new("weather");
    let mut registry = PluginRegistry::new();
    register(&mut registry, &north, "weather")?;
    let before = registry.recorded_manifest_slots();

    let error = register(&mut registry, &south, "weather").err();
    assert!(matches!(
        error,
        Some(RuntimeError::ManifestSlot(
            ManifestSlotErrorV1::Duplicate { .. }
        ))
    ));
    assert_eq!(
        error.map(|error| error.to_string()),
        Some(
            "manifest slot \"weather\" is already registered; give Plugin \"weather\" another slot"
                .to_owned()
        )
    );
    assert_eq!(registry.len(), 1);
    assert!(!registry.contains(&south.id()));
    assert_eq!(registry.recorded_manifest_slots(), before);
    register(&mut registry, &south, "weather-south")?;
    assert_eq!(catalog_slots(&mut registry)?, ["weather", "weather-south"]);
    Ok(())
}

#[test]
fn a_duplicate_plugin_id_is_rejected_and_records_no_extra_slot() -> TestResult {
    let plugin = SlotPlugin::new("weather");
    let mut registry = PluginRegistry::new();
    register(&mut registry, &plugin, "weather")?;
    let before = registry.recorded_manifest_slots();

    assert!(register(&mut registry, &plugin, "weather-again").is_err());
    assert_eq!(registry.len(), 1);
    assert_eq!(registry.recorded_manifest_slots(), before);
    assert_eq!(catalog_slots(&mut registry)?, ["weather"]);
    Ok(())
}

#[test]
fn a_plugin_registered_without_a_slot_names_itself_and_the_fix() -> TestResult {
    let slotted = SlotPlugin::new("slotted");
    let bare = SlotPlugin::new("unslotted");
    let mut registry = PluginRegistry::new();
    register(&mut registry, &slotted, "slotted")?;
    let pin = pos_runtime::PluginPinV1::try_new(
        pos_runtime::DomainImplementationKindV1::Plugin,
        pos_runtime::PluginIsolationV1::OperatorTrustedNative,
        pos_core::Hash::from_bytes([7; 32]),
        vec!["bare-role".to_owned()],
    )?;
    let registration = PluginRegistrationV1::new(pin, PluginAvailabilityV1::Available);
    registry.register_pinned_generated(&bare, registration, None, None)?;

    let owner = OwnerIdV1::from_static("app");
    let error = registry.admit_local_manifest_registration(owner, 1).err();
    assert_eq!(
        error.map(|error| error.to_string()),
        Some(format!(
            "Plugin \"unslotted\" ({}) has no manifest slot; register it with \
             PluginRegistry::register_local and a ManifestSlotV1",
            bare.id()
        ))
    );
    assert_eq!(registry.recorded_manifest_slots().len(), 1);
    Ok(())
}

#[test]
fn an_empty_registry_has_no_recorded_slots() {
    assert!(PluginRegistry::new().recorded_manifest_slots().is_empty());
}

#[test]
fn the_same_slots_name_the_catalog_in_two_runs_with_different_plugin_ids() -> TestResult {
    let mut first = PluginRegistry::new();
    let mut second = PluginRegistry::new();
    register(&mut first, &SlotPlugin::new("weather"), "weather")?;
    register(&mut second, &SlotPlugin::new("weather"), "weather")?;

    assert_eq!(catalog_slots(&mut first)?, catalog_slots(&mut second)?);
    assert_ne!(
        first.recorded_manifest_slots()[0].1,
        second.recorded_manifest_slots()[0].1
    );
    Ok(())
}

#[test]
fn re_registering_a_plugin_under_a_taken_slot_reports_the_slot() -> TestResult {
    let plugin = SlotPlugin::new("weather");
    let mut registry = PluginRegistry::new();
    register(&mut registry, &plugin, "weather")?;
    let before = registry.recorded_manifest_slots();

    let error = register(&mut registry, &plugin, "weather").err();
    assert_eq!(
        error.map(|error| error.to_string()),
        Some(
            "manifest slot \"weather\" is already registered; give Plugin \"weather\" another slot"
                .to_owned()
        )
    );
    assert_eq!(registry.recorded_manifest_slots(), before);
    Ok(())
}
