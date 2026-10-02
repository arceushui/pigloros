//! Host catalogue of staged Reducers for protected candidates (ADR-113 §1).
//!
//! Only the eight audited first-party Plugin reducers have reviewed staged
//! catalogue entries. A reviewed entry is admitted only with its §10
//! conformance evidence. No evidence is recorded in this build, so reviewed
//! admission fails closed; fixtures are admitted only through
//! `test-support`. Every candidate the provider opens builds each admitted
//! reducer fresh through [`InstalledPluginFactoryV1::build`] from the
//! retained frozen configuration, re-checks that the built Plugin is the
//! recorded one, and keeps only its `reducer`.

use std::{any::type_name, collections::HashSet, sync::Arc, time::Duration};

use pos_core::{staged_install::ProjectionSourceV1, Event, Hash, Plugin, Reducer};
use pos_state::{
    CandidateBoundsV1, CandidateReducerV1, DetachedProjectionCandidateV1, InitialStateV1,
    ProjectionCandidateErrorV1, ProtectedProjectionProviderV1, RecordedConsumerV1,
};

use super::InstalledPluginFactoryV1;

/// Largest per-callback bound a staged Reducer may be admitted with.
pub const MAX_STAGED_CALLBACK_BOUND_V1: Duration = Duration::from_millis(250);

/// One reviewed staged Reducer factory.
struct ReviewedStagedFactoryV1 {
    /// Reviewed stable identifier. It is the only factory name hashed into
    /// the recorded reducer identity, so that identity does not depend on
    /// the compiler.
    id: &'static str,
    /// `std::any::type_name` of the factory type. Its output is not stable
    /// across compiler versions, so it is used only to recognise the factory
    /// within one build: the host and every Plugin crate it admits are
    /// compiled together. Each Plugin crate's `staged_factory_type_name`
    /// test checks its real factory type against this list in that build.
    type_name: &'static str,
}

/// The eight audited Plugin reducer factories. Each factory is implemented
/// on its Plugin type in the owning Plugin crate.
const REVIEWED_STAGED_FACTORIES_V1: [ReviewedStagedFactoryV1; 8] = [
    ReviewedStagedFactoryV1 {
        id: "pigloros/staged-factory/agent/v1",
        type_name: "pos_plugin_agent::AgentPlugin",
    },
    ReviewedStagedFactoryV1 {
        id: "pigloros/staged-factory/bridges/v1",
        type_name: "pos_plugin_bridges::BridgePlugin",
    },
    ReviewedStagedFactoryV1 {
        id: "pigloros/staged-factory/eval/v1",
        type_name: "pos_plugin_eval::EvalPlugin",
    },
    ReviewedStagedFactoryV1 {
        id: "pigloros/staged-factory/persona/v1",
        type_name: "pos_plugin_persona::PersonaPlugin",
    },
    ReviewedStagedFactoryV1 {
        id: "pigloros/staged-factory/rule-agent/v1",
        type_name: "pos_plugin_rule_agent::RuleAgentPlugin",
    },
    // The Society factory is compiled only with the `installed-factory`
    // feature of `pos-plugin-society`; without it there is nothing to admit.
    ReviewedStagedFactoryV1 {
        id: "pigloros/staged-factory/society/v1",
        type_name: "pos_plugin_society::SocietyPlugin",
    },
    ReviewedStagedFactoryV1 {
        id: "pigloros/staged-factory/synthetic-obs/v1",
        type_name: "pos_plugin_synthetic_obs::SyntheticObsPlugin",
    },
    ReviewedStagedFactoryV1 {
        id: "pigloros/staged-factory/world/v1",
        type_name: "pos_plugin_world::WorldPlugin",
    },
];

/// Whether `factory_type_name`, the `std::any::type_name` of a factory in
/// this build, is on the reviewed staged Reducer factory list.
///
/// Each Plugin crate's `staged_factory_type_name` test uses it to check its
/// real factory type against the actual reviewed list.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[must_use]
pub fn is_reviewed_staged_factory(factory_type_name: &str) -> bool {
    REVIEWED_STAGED_FACTORIES_V1
        .iter()
        .any(|entry| entry.type_name == factory_type_name)
}

/// Declared bound on the State growth of one `apply`:
/// `per_payload_byte * payload_bytes + constant_bytes` (ADR-113 §4 E5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StagedGrowthBoundV1 {
    per_payload_byte: u64,
    constant_bytes: u64,
}

impl StagedGrowthBoundV1 {
    /// Bytes of State growth allowed per Event payload byte.
    #[must_use]
    pub const fn per_payload_byte(&self) -> u64 {
        self.per_payload_byte
    }

    /// Bytes of State growth allowed per `apply` regardless of payload.
    #[must_use]
    pub const fn constant_bytes(&self) -> u64 {
        self.constant_bytes
    }
}

/// Reviewed staged-execution record of one admitted catalogue entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StagedReducerAdmissionV1 {
    callback_bound: Duration,
    growth_bound: StagedGrowthBoundV1,
    conformance_digest: Option<Hash>,
}

impl StagedReducerAdmissionV1 {
    /// The candidate bounds this record admits.
    #[must_use]
    pub const fn candidate_bounds(&self) -> CandidateBoundsV1 {
        CandidateBoundsV1 {
            callback_bound: self.callback_bound,
            growth_per_payload_byte: self.growth_bound.per_payload_byte,
            growth_constant_bytes: self.growth_bound.constant_bytes,
        }
    }

    /// Admitted bound on the duration of one Reducer callback.
    #[must_use]
    pub const fn callback_bound(&self) -> Duration {
        self.callback_bound
    }

    /// Declared bound on the State growth of one `apply`.
    #[must_use]
    pub const fn growth_bound(&self) -> StagedGrowthBoundV1 {
        self.growth_bound
    }
}

/// Declared record shared by the reviewed entries until §10 conformance
/// measures them on the reference runner. Without a conformance digest it
/// admits nothing.
const PENDING_CONFORMANCE_ADMISSION_V1: StagedReducerAdmissionV1 = StagedReducerAdmissionV1 {
    callback_bound: MAX_STAGED_CALLBACK_BOUND_V1,
    growth_bound: StagedGrowthBoundV1 {
        per_payload_byte: 6,
        constant_bytes: 4096,
    },
    conformance_digest: None,
};

/// Closed failures of staged Reducer admission. Nothing is admitted on error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StagedReducerAdmissionErrorV1 {
    /// The factory is not one of the reviewed staged Reducer factories.
    NotReviewed,
    /// The reviewed entry has no §10 conformance evidence in this build.
    ConformanceEvidenceMissing,
    /// The factory built no Reducer.
    MissingReducer,
    /// A Reducer for the built Plugin identity is already admitted.
    DuplicatePlugin,
}

/// Admission provenance, which selects the admission record.
#[derive(Clone, Copy)]
enum StagedEvidenceV1 {
    /// A reviewed entry with its recorded conformance evidence.
    Reviewed,
    /// A nonproduction fixture that never reaches a production provider.
    #[cfg(any(test, feature = "test-support"))]
    Fixture,
}

/// The admission record of one entry and the factory identifier hashed into
/// its reducer identity.
type StagedEvidenceRecordV1 = (StagedReducerAdmissionV1, &'static str);

impl StagedEvidenceV1 {
    fn admission<F: InstalledPluginFactoryV1>(
        self,
    ) -> Result<StagedEvidenceRecordV1, StagedReducerAdmissionErrorV1> {
        match self {
            Self::Reviewed => reviewed_admission::<F>(),
            // A fixture has no reviewed identifier; its identity is bound to
            // the type name and is meaningful only within one build.
            #[cfg(any(test, feature = "test-support"))]
            Self::Fixture => Ok((PENDING_CONFORMANCE_ADMISSION_V1, type_name::<F>())),
        }
    }
}

/// Resolve the reviewed record and stable identifier of `F`, which must be
/// implemented on its own reviewed Plugin type.
fn reviewed_admission<F>() -> Result<StagedEvidenceRecordV1, StagedReducerAdmissionErrorV1>
where
    F: InstalledPluginFactoryV1,
{
    let factory = type_name::<F>();
    let reviewed = REVIEWED_STAGED_FACTORIES_V1
        .iter()
        .find(|entry| entry.type_name == factory && type_name::<F::Plugin>() == factory)
        .ok_or(StagedReducerAdmissionErrorV1::NotReviewed)?;
    let admission = PENDING_CONFORMANCE_ADMISSION_V1;
    // Admission requires recorded conformance evidence, which #512 supplies.
    admission
        .conformance_digest
        .is_some()
        .then_some((admission, reviewed.id))
        .ok_or(StagedReducerAdmissionErrorV1::ConformanceEvidenceMissing)
}

/// Identity of one admitted entry: the factory identifier, Plugin name and
/// version, frozen configuration and admission record. It excludes the
/// per-build `PluginId`.
fn staged_reducer_identity<P: Plugin>(
    factory_id: &str,
    plugin: &P,
    configuration_details: &[u8],
    admission: &StagedReducerAdmissionV1,
) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros/staged-reducer-identity/v1");
    super::hash_framed(&mut hasher, factory_id.as_bytes());
    super::hash_framed(&mut hasher, plugin.name().as_bytes());
    super::hash_framed(&mut hasher, plugin.version().as_bytes());
    super::hash_framed(&mut hasher, configuration_details);
    hasher.update(&admission.callback_bound.as_micros().to_le_bytes());
    hasher.update(&admission.growth_bound.per_payload_byte.to_le_bytes());
    hasher.update(&admission.growth_bound.constant_bytes.to_le_bytes());
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// The parts of one fresh build a candidate keeps or re-checks.
struct BuiltReducerV1 {
    name: &'static str,
    version: &'static str,
    reducer: Option<Box<dyn Reducer>>,
}

/// Builds one fresh product from the retained frozen configuration.
type StagedReducerBuilderV1 = Box<dyn Fn() -> BuiltReducerV1 + Send + Sync>;

/// One admitted entry: its recorded identity and Plugin, record and fresh
/// builder.
struct AdmittedStagedReducerV1 {
    consumer: RecordedConsumerV1,
    name: &'static str,
    version: &'static str,
    admission: StagedReducerAdmissionV1,
    build: StagedReducerBuilderV1,
}

impl AdmittedStagedReducerV1 {
    /// Build a fresh reducer and re-check that the built Plugin is the
    /// recorded one. The built Plugin and approver are dropped unused.
    fn candidate_reducer(&self) -> Result<CandidateReducerV1, ProjectionCandidateErrorV1> {
        let built = (self.build)();
        let recorded = built.name == self.name && built.version == self.version;
        built
            .reducer
            .filter(|_| recorded)
            .map(|reducer| CandidateReducerV1 {
                consumer: self.consumer,
                name: self.name,
                reducer,
                bounds: self.admission.candidate_bounds(),
                observation_policy: None,
            })
            .ok_or(ProjectionCandidateErrorV1::PluginMismatch)
    }
}

/// Host catalogue implementation of [`ProtectedProjectionProviderV1`].
///
/// It holds only admitted entries, each with its frozen configuration behind
/// an `Arc`; [`Default`] creates it empty. Consumers registered any other
/// way, such as through `PluginRegistry::register_*` or
/// `ProjectionRegistry::register`, are never admitted, and a plan naming one
/// is rejected before any build. This provider is the only admission path
/// for detached projection candidates.
#[derive(Default)]
pub struct HostProjectionProviderV1 {
    entries: Vec<AdmittedStagedReducerV1>,
}

impl HostProjectionProviderV1 {
    /// Admit the reviewed staged Reducer entry of factory `F`.
    ///
    /// The factory is built once here to bind the recorded identity, and
    /// once more for every candidate later opened.
    ///
    /// # Errors
    /// Rejects an unreviewed factory, a reviewed entry without conformance
    /// evidence, a factory that builds no Reducer, or a duplicate Plugin
    /// identity, without admitting anything.
    pub fn admit<F>(
        &mut self,
        frozen_configuration: Arc<F::Configuration>,
    ) -> Result<RecordedConsumerV1, StagedReducerAdmissionErrorV1>
    where
        F: InstalledPluginFactoryV1 + 'static,
        F::Configuration: Send + Sync + 'static,
    {
        self.admit_with::<F>(frozen_configuration, StagedEvidenceV1::Reviewed)
    }

    /// Admit any factory as a nonproduction fixture entry.
    ///
    /// # Errors
    /// Returns the same closed errors as [`Self::admit`] after its review
    /// and evidence checks.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn admit_fixture<F>(
        &mut self,
        frozen_configuration: Arc<F::Configuration>,
    ) -> Result<RecordedConsumerV1, StagedReducerAdmissionErrorV1>
    where
        F: InstalledPluginFactoryV1 + 'static,
        F::Configuration: Send + Sync + 'static,
    {
        self.admit_with::<F>(frozen_configuration, StagedEvidenceV1::Fixture)
    }

    /// The admission record of one recorded consumer, when it is admitted
    /// with exactly that identity.
    #[must_use]
    pub fn admission(&self, consumer: &RecordedConsumerV1) -> Option<StagedReducerAdmissionV1> {
        self.admitted(consumer).ok().map(|entry| entry.admission)
    }

    fn admit_with<F>(
        &mut self,
        frozen_configuration: Arc<F::Configuration>,
        evidence: StagedEvidenceV1,
    ) -> Result<RecordedConsumerV1, StagedReducerAdmissionErrorV1>
    where
        F: InstalledPluginFactoryV1 + 'static,
        F::Configuration: Send + Sync + 'static,
    {
        let (admission, factory_id) = evidence.admission::<F>()?;
        let product = F::build(&frozen_configuration);
        let details = F::configuration_details(&frozen_configuration);
        let consumer = RecordedConsumerV1::new(
            product.plugin.id(),
            staged_reducer_identity(factory_id, &product.plugin, &details, &admission),
        );
        if product.reducer.is_none() {
            return Err(StagedReducerAdmissionErrorV1::MissingReducer);
        }
        if self
            .entries
            .iter()
            .any(|entry| entry.consumer.plugin_id() == consumer.plugin_id())
        {
            return Err(StagedReducerAdmissionErrorV1::DuplicatePlugin);
        }
        self.entries.push(AdmittedStagedReducerV1 {
            consumer,
            name: product.plugin.name(),
            version: product.plugin.version(),
            admission,
            build: Box::new(move || {
                let product = F::build(&frozen_configuration);
                BuiltReducerV1 {
                    name: product.plugin.name(),
                    version: product.plugin.version(),
                    reducer: product.reducer,
                }
            }),
        });
        Ok(consumer)
    }

    /// Resolve one recorded consumer to its admitted entry.
    fn admitted(
        &self,
        consumer: &RecordedConsumerV1,
    ) -> Result<&AdmittedStagedReducerV1, ProjectionCandidateErrorV1> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.consumer.plugin_id() == consumer.plugin_id())
            .ok_or(ProjectionCandidateErrorV1::NotAdmitted)?;
        (entry.consumer == *consumer)
            .then_some(entry)
            .ok_or(ProjectionCandidateErrorV1::ConsumerSetMismatch)
    }

    /// Resolve the complete recorded set before any factory is built.
    fn admitted_set(
        &self,
        recorded_consumers: &[RecordedConsumerV1],
    ) -> Result<Vec<&AdmittedStagedReducerV1>, ProjectionCandidateErrorV1> {
        if recorded_consumers.is_empty() || names_a_plugin_twice(recorded_consumers) {
            return Err(ProjectionCandidateErrorV1::ConsumerSetMismatch);
        }
        recorded_consumers
            .iter()
            .map(|consumer| self.admitted(consumer))
            .collect()
    }
}

fn names_a_plugin_twice(recorded_consumers: &[RecordedConsumerV1]) -> bool {
    let mut seen = HashSet::with_capacity(recorded_consumers.len());
    !recorded_consumers
        .iter()
        .all(|consumer| seen.insert(consumer.plugin_id()))
}

impl ProtectedProjectionProviderV1 for HostProjectionProviderV1 {
    fn open_candidate(
        &self,
        recorded_consumers: &[RecordedConsumerV1],
        initial_state: InitialStateV1,
        source: ProjectionSourceV1,
    ) -> Result<DetachedProjectionCandidateV1, ProjectionCandidateErrorV1> {
        let entries = self.admitted_set(recorded_consumers)?;
        entries
            .into_iter()
            .map(AdmittedStagedReducerV1::candidate_reducer)
            .collect::<Result<Vec<_>, _>>()
            .and_then(|reducers| {
                DetachedProjectionCandidateV1::from_reducers(reducers, initial_state, source)
            })
    }
}

/// Fold a host-captured Event range into one detached candidate.
///
/// This matches how `PluginRegistry::fold_events` folds the visible registry:
/// the host drops consent-closed markers, then the candidate applies the live
/// fold step.
pub fn fold_detached_candidate_v1(candidate: &mut DetachedProjectionCandidateV1, events: &[Event]) {
    candidate.fold_events(&super::host_projection_events(events));
}
