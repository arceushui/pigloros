//! The sub-case runner seam and the real world port (ADR-061 revision 8 decision 2).
//!
//! [`SubCaseRunnerV1`] is the public seam above the interpreter: the case driver asks it for
//! the record of each sub-case, and a test-side decorator can record its calls.
//! [`SupervisorRunnerV1`] builds the real port, [`EvaluationWorldPortV1`], and interprets the
//! sub-case on it. The port has no logic of its own: it builds the S1c2 world, calls `install`,
//! `gate_for_driver`, `refresh_policy` and `run_pass` with a fixture wall source at the instant
//! of the step, builds and registers the Driver of a `bind` step, and reads the world back.

use std::path::PathBuf;
use std::sync::{Arc, MutexGuard, PoisonError};
use std::time::Duration;

use pos_core::trusted_clock::{FixtureEvaluationInstantV1, FixtureWallSourceV1};
use pos_core::Hash;
use pos_plugin_release::InMemoryReleaseSourceV1;
use pos_plugin_supervisor::{
    register_community_driver, CommunityDriverConfigV1, CommunityDriverSettingsV1,
    CommunityDriverV1, CommunityMemberV1, CommunityPluginHandleV1, CommunityPluginSubjectOutcomeV1,
    CommunityPluginSupervisorV1, CommunityStateV1, WorkerProgramV1,
};
use pos_runtime::community_pin_v1;
use pos_runtime::community_plugin_host::{
    pinned_runtime_v1, CommunityEvaluationWorldV1, CommunityPluginCeilingsV1,
    CommunityPluginExecutionProfileV1, CommunityPluginExpectationV1, CommunityPluginHostAbiV1,
    CommunityPluginHostV1, CommunityPluginModeV1,
    CommunityPluginTrustMaterialV1, FixedTrustMaterialSourceV1, GatedCommunityReleaseV1,
    ReleaseIdentityV1, TrustDenialBasisV1,
};

use crate::composite::PiecesV1;
use crate::invocation::{
    ConformancePluginV1, FixtureInvocationSourceV1, PassInputsV1, SharedInputsV1,
};
use crate::payload::SubCaseV1;
use crate::world::{
    interpret, outcome_bytes_of, BindArgsV1, HostError, InstallArgsV1, PassArgsV1, PassMemberV1,
    RefreshArgsV1, SetupArgsV1, SubCaseRecordV1, WorldPortV1,
};

/// The outcome records of one pass.
type Outcomes = Vec<CommunityPluginSubjectOutcomeV1>;

/// The per-launch worker watchdog, in milliseconds.
///
/// It is the worker tests' budget for compiling a Component in an instrumented build. The case `watchdog_ms` is the number of launches of the
/// family times this value.
pub const LAUNCH_WATCHDOG_MS: u64 = 300_000;

/// `ArtifactTrustDenied{TrustStateUnavailable}`: the state the world needs is unusable.
const UNAVAILABLE: HostError = HostError::ArtifactTrustDenied {
    basis: TrustDenialBasisV1::TrustStateUnavailable,
};

/// The per-launch watchdog the Drivers' supervisors are built with.
#[must_use]
pub const fn launch_watchdog() -> Duration {
    Duration::from_millis(LAUNCH_WATCHDOG_MS)
}

/// A wiring fault of the port itself (no world, no source, a Driver that cannot be built or
/// registered): not a verdict on the release, so it is operational (`WorkerCrashed`) and the
/// case becomes `Unavailable`. `TrustStateUnavailable` is kept for material that is genuinely
/// absent.
const WIRING: HostError = HostError::WorkerCrashed;

/// The role of every conformance Driver's pin.
const PIN_ROLE: &str = "conformance";

/// Runs one sub-case and reports its record.
pub trait SubCaseRunnerV1 {
    /// Run `subcase` of a payload whose pieces are `pieces` in the Execution Mode `mode`.
    fn run(
        &self,
        subcase: &SubCaseV1,
        pieces: &PiecesV1,
        mode: CommunityPluginModeV1,
    ) -> SubCaseRecordV1;
}

/// The runner that launches the supervised worker program.
#[derive(Clone, Debug)]
pub struct SupervisorRunnerV1 {
    program: WorkerProgramV1,
}

impl SupervisorRunnerV1 {
    /// A runner whose Drivers launch `program`.
    #[must_use]
    pub const fn new(program: WorkerProgramV1) -> Self {
        Self { program }
    }

    /// A runner whose Drivers launch the program at `path`, or `None` for a relative path. A
    /// path that holds no program is not an error here: the launch fails and the member is
    /// `WorkerCrashed`.
    #[must_use]
    pub fn with_program(path: impl Into<PathBuf>) -> Option<Self> {
        WorkerProgramV1::new(path.into()).map(Self::new)
    }
}

impl SubCaseRunnerV1 for SupervisorRunnerV1 {
    fn run(
        &self,
        subcase: &SubCaseV1,
        pieces: &PiecesV1,
        mode: CommunityPluginModeV1,
    ) -> SubCaseRecordV1 {
        let mut port = EvaluationWorldPortV1::new(self.program.clone());
        interpret(subcase, pieces, &mut port, mode)
    }
}

/// A Driver the port registered for a `bind` step.
struct Bound {
    plugin_id: String,
    handle: CommunityPluginHandleV1,
    inputs: SharedInputsV1,
}

/// The world of one sub-case and what the port keeps beside it.
struct OpenWorld {
    world: CommunityEvaluationWorldV1,
    source: Option<InMemoryReleaseSourceV1>,
    mode: CommunityPluginModeV1,
    bound: Vec<Bound>,
    /// The identity of the release the most recent `bind` gated.
    identity: Option<ReleaseIdentityV1>,
    /// The canonical bytes of the outcome records of the last pass.
    outcome: Vec<u8>,
}

/// The real port over the S1c2 world: logic-free beyond the wiring.
pub struct EvaluationWorldPortV1 {
    program: WorkerProgramV1,
    open: Option<OpenWorld>,
}

impl EvaluationWorldPortV1 {
    /// A port whose Drivers launch `program`; it has no world until [`WorldPortV1::open()`].
    #[must_use]
    pub const fn new(program: WorkerProgramV1) -> Self {
        Self {
            program,
            open: None,
        }
    }

    fn world(&mut self) -> Result<&mut OpenWorld, HostError> {
        self.open.as_mut().ok_or(WIRING)
    }
}

/// The wall source that returns the instant of a step at every sample.
fn fixture_wall(instant_micros: u64) -> Result<FixtureWallSourceV1, HostError> {
    FixtureEvaluationInstantV1::from_micros(instant_micros)
        .map(FixtureWallSourceV1::new)
        .or(Err(WIRING))
}

/// The material source of a step: `None` is the explicit unreadable material.
fn fixed_source(material: Option<CommunityPluginTrustMaterialV1>) -> FixedTrustMaterialSourceV1 {
    material.map_or_else(
        FixedTrustMaterialSourceV1::unavailable,
        FixedTrustMaterialSourceV1::new,
    )
}

fn lock(inputs: &SharedInputsV1) -> MutexGuard<'_, PassInputsV1> {
    inputs.lock().unwrap_or_else(PoisonError::into_inner)
}

impl OpenWorld {
    fn install(&mut self, args: &InstallArgsV1) -> Result<(), HostError> {
        let wall = fixture_wall(args.instant_micros);
        let material = args.material.as_ref().ok_or(UNAVAILABLE);
        let source = self.source.as_ref().ok_or(WIRING);
        source.and_then(|source| {
            material.and_then(|material| {
                wall.and_then(|mut wall| {
                    self.world
                        .install(source, &args.address, material, &mut wall, args.tick)
                        .map(|_installed| ())
                })
            })
        })
    }

    fn gate(&mut self, args: &BindArgsV1) -> Result<GatedCommunityReleaseV1, HostError> {
        let material = fixed_source(args.material.clone());
        let expectation = CommunityPluginExpectationV1 {
            plugin_id: args.plugin_id.clone(),
            release: None,
        };
        let wall = fixture_wall(args.instant_micros);
        let source = self.source.as_ref().ok_or(WIRING);
        source.and_then(|source| {
            wall.and_then(|mut wall| {
                self.world.gate_for_driver(
                    &expectation,
                    source,
                    &args.address,
                    &material,
                    &mut wall,
                    args.tick,
                )
            })
        })
    }

    /// Build the Driver of `gated` and register it in the world's registry.
    fn driver(
        &mut self,
        args: &BindArgsV1,
        gated: GatedCommunityReleaseV1,
        program: &WorkerProgramV1,
    ) -> Result<Bound, HostError> {
        let inputs = SharedInputsV1::default();
        let plugin = ConformancePluginV1::new(&args.event_type);
        let profile = CommunityPluginExecutionProfileV1::new(
            self.mode,
            CommunityPluginCeilingsV1::V1,
            Some(pinned_runtime_v1()),
        );
        let supervisor = CommunityPluginSupervisorV1::new(program.clone(), launch_watchdog());
        let pin = community_pin_v1(Hash::from_bytes([1; 32]), vec![PIN_ROLE.to_owned()]);
        let settings = |supervisor| CommunityDriverSettingsV1 {
            plugin_id: pos_core::Plugin::id(&plugin),
            name: "conformance",
            tick_interval: Duration::from_millis(100),
            subscriptions: Vec::new(),
            supervisor,
            source: Box::new(FixtureInvocationSourceV1::new(Arc::clone(&inputs))),
            initial_state: CommunityStateV1 {
                schema: args.initial_state_schema,
                bytes: args.initial_state_bytes.clone(),
            },
        };
        supervisor
            .ok_or(WIRING)
            .and_then(|supervisor| {
                CommunityDriverConfigV1::from_gated(
                    gated,
                    &CommunityPluginHostAbiV1::v1(),
                    &profile,
                    &args.plugin_id,
                    settings(supervisor),
                )
            })
            .and_then(|config| {
                let (driver, handle) = CommunityDriverV1::new(config);
                let registered = pin.or(Err(WIRING)).and_then(|pin| {
                    register_community_driver(self.world.plugins_mut(), &plugin, pin, driver)
                        .or(Err(WIRING))
                });
                registered.map(|()| Bound {
                    plugin_id: args.plugin_id.clone(),
                    handle,
                    inputs,
                })
            })
    }

    /// The members of a pass, each with a copy of its Driver's handle for the outcome records.
    fn members(
        &self,
        args: &PassArgsV1,
    ) -> Result<Vec<(CommunityMemberV1, CommunityPluginHandleV1)>, HostError> {
        let pair = |member: &PassMemberV1, source: &InMemoryReleaseSourceV1| {
            let found = self
                .bound
                .iter()
                .find(|bound| bound.plugin_id == member.plugin_id);
            found.ok_or(WIRING).map(|bound| {
                *lock(&bound.inputs) = PassInputsV1 {
                    invocation_id: args.invocation_id,
                    random_domain: args.random_domain,
                    timeline_seq: args.timeline_seq,
                    observation: args.observation.clone(),
                    simulation_time: args.simulation_time,
                };
                let expectation = CommunityPluginExpectationV1 {
                    plugin_id: member.plugin_id.clone(),
                    release: self
                        .identity
                        .map(|identity| (identity.pmf1_digest, identity.release_digest)),
                };
                let handle = bound.handle.clone();
                let built = CommunityMemberV1::new(
                    handle.clone(),
                    Box::new(source.clone()),
                    member.address.clone(),
                    Box::new(fixed_source(args.material.clone())),
                    expectation,
                );
                (built, handle)
            })
        };
        self.source.as_ref().ok_or(WIRING).and_then(|source| {
            args.members
                .iter()
                .map(|member| pair(member, source))
                .collect()
        })
    }

    fn pass(&mut self, args: &PassArgsV1) -> Result<Outcomes, HostError> {
        let wall = fixture_wall(args.instant_micros);
        let members = self.members(args);
        wall.and_then(|mut wall| {
            members.and_then(|pairs| {
                let (members, handles): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
                let mut host = CommunityPluginHostV1::new(members);
                self.world
                    .run_pass(&mut host, &mut wall, args.tick)
                    .map(|outcome| {
                        outcome
                            .gates
                            .iter()
                            .zip(&handles)
                            .map(|(entry, handle)| {
                                let receipt =
                                    entry.invocation_id.and_then(|id| handle.receipt_for(id));
                                CommunityPluginSubjectOutcomeV1::assemble(
                                    entry,
                                    args.tick,
                                    self.mode,
                                    receipt.as_ref(),
                                )
                            })
                            .collect::<Vec<_>>()
                    })
            })
        })
        .inspect(|outcomes| {
            self.outcome = outcomes.iter().flat_map(outcome_bytes_of).collect();
        })
    }
}

impl WorldPortV1 for EvaluationWorldPortV1 {
    fn open(&mut self, setup: SetupArgsV1) -> Result<(), HostError> {
        let SetupArgsV1 {
            source,
            genesis,
            mode,
        } = setup;
        let world = genesis
            .ok_or(WIRING)
            .and_then(|genesis| CommunityEvaluationWorldV1::open(&genesis));
        world.map(|world| {
            self.open = Some(OpenWorld {
                world,
                source,
                mode,
                bound: Vec::new(),
                identity: None,
                outcome: Vec::new(),
            });
        })
    }

    fn install(&mut self, args: &InstallArgsV1) -> Result<(), HostError> {
        self.world().and_then(|open| open.install(args))
    }

    fn bind(&mut self, args: &BindArgsV1) -> Result<ReleaseIdentityV1, HostError> {
        let program = self.program.clone();
        self.world().and_then(|open| {
            open.gate(args).and_then(|gated| {
                let identity = gated.identity();
                open.driver(args, gated, &program).map(|bound| {
                    open.bound.push(bound);
                    open.identity = Some(identity);
                    identity
                })
            })
        })
    }

    fn refresh(&mut self, args: &RefreshArgsV1) -> Result<(), HostError> {
        let wall = fixture_wall(args.instant_micros);
        let material = args.material.as_ref().ok_or(UNAVAILABLE);
        self.world().and_then(|open| {
            material.and_then(|material| {
                wall.and_then(|mut wall| {
                    let mut host = CommunityPluginHostV1::<CommunityMemberV1>::new(Vec::new());
                    open.world
                        .refresh(&mut host, material, &mut wall, args.tick)
                })
            })
        })
    }

    fn pass(&mut self, args: &PassArgsV1) -> Result<Outcomes, HostError> {
        self.world().and_then(|open| open.pass(args))
    }

    fn committed_event_payloads(&mut self) -> Result<Vec<Vec<u8>>, HostError> {
        let events = self.world().and_then(|open| open.world.committed_events());
        events.map(|events| {
            events
                .iter()
                .map(|event| event.payload.as_slice().to_vec())
                .collect()
        })
    }

    fn committed_state(&mut self) -> Vec<u8> {
        self.open
            .as_ref()
            .and_then(|open| open.bound.last())
            .map(|bound| bound.handle.committed_state().bytes)
            .unwrap_or_default()
    }

    fn outcome_bytes(&self) -> Vec<u8> {
        self.open
            .as_ref()
            .map(|open| open.outcome.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
