//! ADR-088: the manifest roster is built from the registry's admitted Plugins (#556).

use std::error::Error;

use pos_core::{
    compare_manifest_plugin_rosters_v1,
    state::{Reducer, State},
    Capability, ComparedFieldV1, Event, Hash, Kind, ManifestPluginEntryV1,
    ManifestPluginRosterErrorV1, ManifestPluginRosterV1, OwnerIdV1, Plugin, PluginId,
    ReproManifest, RosterComparisonErrorV1, TimelineId, WallTime,
};
use pos_runtime::{
    AdmittedCompositionV1, ManifestRegistrationErrorV1, ManifestRosterBuildErrorV1, ManifestSlotV1,
    PluginRegistry,
};

type TestResult = Result<(), Box<dyn Error>>;

struct RosterPlugin {
    id: PluginId,
    name: &'static str,
    reducer_only: bool,
    owns: Option<&'static str>,
}

impl RosterPlugin {
    fn new(name: &'static str) -> Self {
        Self {
            id: PluginId::new(),
            name,
            reducer_only: false,
            owns: None,
        }
    }

    // A Plugin with a fixed id that owns one Event type, so its generated policy declares it.
    const fn owning(id: PluginId, event_type: &'static str) -> Self {
        Self {
            id,
            name: "weather",
            reducer_only: false,
            owns: Some(event_type),
        }
    }

    const fn reducer_only(mut self) -> Self {
        self.reducer_only = true;
        self
    }
}

impl Plugin for RosterPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: self.owns.into_iter().map(Kind::new).collect(),
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
    plugin: &RosterPlugin,
    slot: &str,
) -> Result<(), Box<dyn Error>> {
    let reducer: Option<Box<dyn Reducer>> = if plugin.reducer_only {
        Some(Box::new(TallyReducer))
    } else {
        None
    };
    let roles = vec![format!("role-{slot}")];
    registry.register_local(plugin, ManifestSlotV1::try_new(slot)?, roles, reducer, None)?;
    Ok(())
}

struct Composition {
    registry: PluginRegistry,
    admitted: AdmittedCompositionV1,
    north: PluginId,
    south: PluginId,
    tally: PluginId,
}

// Two Plugins share the display name `weather`; `tally` is reducer-only. Registration order is
// not slot order.
fn admitted_composition() -> Result<Composition, Box<dyn Error>> {
    let north = RosterPlugin::new("weather");
    let south = RosterPlugin::new("weather");
    let tally = RosterPlugin::new("tally").reducer_only();
    let mut registry = PluginRegistry::new();
    register(&mut registry, &south, "weather-south")?;
    register(&mut registry, &tally, "tally")?;
    register(&mut registry, &north, "weather-north")?;
    let owner = OwnerIdV1::from_static("roster-app");
    let admitted = registry.admit_local_manifest_registration(owner, 1)?;
    Ok(Composition {
        registry,
        admitted,
        north: north.id(),
        south: south.id(),
        tally: tally.id(),
    })
}

const fn timeline() -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes([7; 16]))
}

#[test]
fn the_roster_is_sorted_by_slot_and_keeps_same_name_rows_apart() -> TestResult {
    let built = admitted_composition()?;
    let roster = built.registry.manifest_plugin_roster(&built.admitted)?;
    let rows = roster.entries();
    let slots: Vec<&str> = rows
        .iter()
        .map(ManifestPluginEntryV1::stable_slot)
        .collect();
    assert_eq!(slots, ["tally", "weather-north", "weather-south"]);
    let ids: Vec<PluginId> = rows.iter().map(ManifestPluginEntryV1::plugin_id).collect();
    assert_eq!(ids, [built.tally, built.north, built.south]);
    let names: Vec<&str> = rows
        .iter()
        .map(ManifestPluginEntryV1::plugin_name)
        .collect();
    assert_eq!(names, ["tally", "weather", "weather"]);
    assert!(rows.iter().all(|row| row.plugin_version() == "0.1.0"));
    assert_ne!(rows[1].eop1_digest(), rows[2].eop1_digest());
    assert_ne!(rows[1].closure_bytes(), rows[2].closure_bytes());
    Ok(())
}

#[test]
fn every_row_carries_the_exact_native_digest_and_closure_bytes() -> TestResult {
    let built = admitted_composition()?;
    let sources = built
        .registry
        .admitted_manifest_policy_sources(&built.admitted)?;
    let roster = built.registry.manifest_plugin_roster(&built.admitted)?;
    assert_eq!(sources.len(), roster.entries().len());
    for row in roster.entries() {
        let source = sources
            .iter()
            .find(|source| source.plugin_id() == row.plugin_id())
            .ok_or("every roster row has an admitted source")?;
        assert_eq!(row.stable_slot(), source.stable_slot());
        assert_eq!(row.eop1_digest(), source.eop1_native_digest());
        assert_eq!(row.closure_bytes(), source.opc1_bytes());
        assert!(row.closure_bytes().starts_with(b"OPC1"));
        assert_ne!(row.eop1_digest(), Hash::zero());
    }
    Ok(())
}

#[test]
fn the_retained_roster_matches_the_capability_roster() -> TestResult {
    let built = admitted_composition()?;
    let expected = built.registry.manifest_plugin_roster(&built.admitted)?;
    let retained = built.registry.retained_manifest_plugin_roster()?;
    assert_eq!(retained, Some(expected));
    Ok(())
}

#[test]
fn a_registry_that_was_never_admitted_has_no_retained_roster() -> TestResult {
    let mut registry = PluginRegistry::new();
    assert_eq!(registry.retained_manifest_plugin_roster(), Ok(None));
    register(&mut registry, &RosterPlugin::new("weather"), "weather")?;
    assert_eq!(registry.retained_manifest_plugin_roster(), Ok(None));
    Ok(())
}

#[test]
fn another_registrys_capability_cannot_build_a_roster() -> TestResult {
    let built = admitted_composition()?;
    let other = PluginRegistry::new();
    let failure = other.manifest_plugin_roster(&built.admitted);
    let stale = ManifestRosterBuildErrorV1::Admission(ManifestRegistrationErrorV1::IncompleteBatch);
    assert_eq!(failure, Err(stale));
    Ok(())
}

#[test]
fn build_errors_say_what_failed_without_echoing_closure_bytes() {
    let stale = ManifestRosterBuildErrorV1::from(ManifestRegistrationErrorV1::IncompleteBatch);
    let message = stale.to_string();
    assert!(message.starts_with("cannot read the admitted Plugins: "));
    let oversized = ManifestRosterBuildErrorV1::Roster(ManifestPluginRosterErrorV1::RosterTooLarge);
    let message = oversized.to_string();
    assert!(message.starts_with("an admitted Plugin does not fit the manifest roster: "));
}

#[test]
fn the_built_roster_survives_json_and_cbor_with_same_name_rows_intact() -> TestResult {
    let built = admitted_composition()?;
    let roster = built.registry.manifest_plugin_roster(&built.admitted)?;
    let created = WallTime::from_micros(1_000_000);
    let head = Hash::from_bytes([9; 32]);
    let manifest = ReproManifest::new(timeline(), head, created, roster, Vec::new(), None)?;
    let from_json = ReproManifest::from_json(manifest.to_json()?.as_bytes())?;
    let from_cbor = ReproManifest::from_cbor(&manifest.to_cbor()?)?;
    for decoded in [from_json, from_cbor] {
        assert_eq!(decoded, manifest);
        let rows = decoded.plugin_roster().entries();
        assert_eq!(rows[1].plugin_name(), rows[2].plugin_name());
        assert_ne!(rows[1].eop1_digest(), rows[2].eop1_digest());
        assert_ne!(rows[1].closure_bytes(), rows[2].closure_bytes());
    }
    Ok(())
}

// One admitted registry holding `plugins` at their slots, and its retained roster.
fn admitted_roster(
    plugins: &[(&RosterPlugin, &str)],
) -> Result<ManifestPluginRosterV1, Box<dyn Error>> {
    let mut registry = PluginRegistry::new();
    for (plugin, slot) in plugins {
        register(&mut registry, plugin, slot)?;
    }
    let owner = OwnerIdV1::from_static("roster-app");
    let _admitted = registry.admit_local_manifest_registration(owner, 1)?;
    let roster = registry.retained_manifest_plugin_roster()?;
    Ok(roster.ok_or("an admitted registry retains its roster")?)
}

fn recorded(roster: ManifestPluginRosterV1) -> ReproManifest {
    let head = Hash::from_bytes([9; 32]);
    let created = WallTime::from_micros(1_000_000);
    ReproManifest::recorded(timeline(), head, created, roster, None)
}

#[test]
fn a_changed_output_declaration_changes_the_roster_and_its_comparison() -> TestResult {
    let id = PluginId::new();
    let baseline = admitted_roster(&[(&RosterPlugin::owning(id, "weather.rain"), "weather")])?;
    let changed = admitted_roster(&[(&RosterPlugin::owning(id, "weather.snow"), "weather")])?;
    assert_ne!(baseline, changed);
    assert_ne!(recorded(baseline.clone()), recorded(changed.clone()));
    let mismatch = compare_manifest_plugin_rosters_v1(&baseline, &changed);
    let expected = RosterComparisonErrorV1::PolicyMismatch {
        slot: "weather".to_owned(),
        field: ComparedFieldV1::EventTypeSet,
    };
    assert_eq!(mismatch, Err(expected));
    Ok(())
}

#[test]
fn fresh_plugin_ids_at_the_same_slots_compare_equal() -> TestResult {
    let first = RosterPlugin::owning(PluginId::new(), "weather.rain");
    let second = RosterPlugin::owning(PluginId::new(), "weather.rain");
    let baseline = admitted_roster(&[(&first, "weather")])?;
    let candidate = admitted_roster(&[(&second, "weather")])?;
    assert_ne!(baseline, candidate);
    let marker = compare_manifest_plugin_rosters_v1(&baseline, &candidate)?;
    assert_eq!(marker.slot_count(), 1);
    Ok(())
}

#[test]
fn a_missing_or_extra_slot_is_rejected() -> TestResult {
    let alone = RosterPlugin::new("weather");
    let paired = RosterPlugin::new("weather");
    let tally = RosterPlugin::new("tally").reducer_only();
    let single = admitted_roster(&[(&alone, "weather")])?;
    let double = admitted_roster(&[(&paired, "weather"), (&tally, "tally")])?;
    let missing = RosterComparisonErrorV1::MissingPlugin {
        slot: "tally".to_owned(),
    };
    let dropped = compare_manifest_plugin_rosters_v1(&double, &single);
    assert_eq!(dropped, Err(missing));
    let unexpected = RosterComparisonErrorV1::UnexpectedPlugin {
        slot: "tally".to_owned(),
    };
    let added = compare_manifest_plugin_rosters_v1(&single, &double);
    assert_eq!(added, Err(unexpected));
    Ok(())
}
