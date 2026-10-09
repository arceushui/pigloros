//! The community Plugin Driver adapter (ADR-061 revision 4, #543).
//!
//! [`CommunityDriverV1`] implements pos-runtime's [`Driver`] trait. Each
//! `step` runs the Plugin's `drive` export in one fresh supervised worker,
//! maps the guest's output to the pipeline's `EventDraft`s, and stages them in
//! the registry's usual pending step. Nothing is committed by `step`: the
//! registry validates every draft (host-owned types, ownership, output
//! admission, schema) and commits the whole pass atomically through
//! `PluginRegistry::admit_scheduled_pass`, or discards every staged Driver
//! output. That host validation is the only approval. The guest never commits,
//! there is no `approve` export, the adapter has no approver of its own, and a
//! failed pass is never retried implicitly.
//!
//! Registration goes through [`register_community_driver()`]: the local-pinned
//! path (`register_pinned_generated` with a `GovernedCommunity` pin) and the
//! non-participant scheduled profile. Trust-derived admission is #544.
//!
//! # Non-durable state
//! The next Plugin state, the invocation receipts, the last failure and the
//! quarantine live in process memory only. They are lost on restart, fabricate
//! no Event, and are not recorded in a `ReproManifest` or commit receipt: that
//! needs a storage decision and belongs to the follow-up #560.
//! - The next state is held in the adapter and adopted through
//!   [`Driver::commit_step()`] only after the whole batch commits. An abort
//!   discards it, and a store outcome that is unknown keeps it staged for
//!   `recover_scheduled_pass`.
//! - A draft that declares `dependency_digests` is `UnsupportedSchema`: no
//!   `EventDraft` field can commit them, so the adapter refuses them rather
//!   than dropping them silently.
//! - Trace annotations are validated by the engine and the supervisor and
//!   then dropped; only their count survives, in the receipt.
//!
//! # Quarantine
//! A failure quarantines the failing Plugin and nobody else; see
//! [`quarantine_for()`](pos_runtime::community_plugin_host::quarantine_for).
//! The adapter refuses to run while quarantined, and the host mirrors the
//! quarantine into the registry with
//! [`CommunityPluginHandleV1::sync_registry()`]. The registry's pass-time
//! check is registry-wide: while any selected Driver is quarantined, the
//! registry refuses the whole pass before any Driver runs, so a quarantined
//! Plugin stops every Plugin's passes until the host calls
//! [`CommunityPluginHandleV1::clear_quarantine()`]. A refused pass stages
//! nothing and adds no new failure.
//!
//! # Classification of a failed pass
//! The host passes the error of a failed pass to
//! [`classify_pass_failure()`](pos_runtime::community_plugin_host::classify_pass_failure).
//! A commit failure has no failing Plugin, so no handle is marked by it; a
//! host error raised while staging was already recorded by the failing
//! adapter's own `step`, so there is no separate recording call.

mod output;
mod state;

use std::sync::Arc;
use std::time::Duration;

use pos_core::{Plugin, PluginId, TimelineId};
use pos_runtime::community_plugin_host::{
    CommunityPluginHostErrorV1, GuestPluginErrorV1, HostInputs, InvocationReportV1, MeteringV1,
    NegotiatedCommunityPluginV1, PluginInvocationV1, PluginOutputV1,
};
use pos_runtime::{
    DomainImplementationKindV1, Driver, ObservationView, PluginAvailabilityV1,
    PluginCompositionErrorV1, PluginIsolationV1, PluginPinFieldV1, PluginPinV1,
    PluginRegistrationV1, PluginRegistry, ProjectionKey, RuntimeError, ScheduledDriverBindingV1,
    StepOutput,
};

use self::output::mapped_drafts;
use self::state::Shared;
pub use self::state::{
    CommunityInvocationReceiptV1, CommunityPluginHandleV1, CommunityStateV1, ReceiptDispositionV1,
    MAX_RETAINED_RECEIPTS_V1,
};
use crate::supervisor::CommunityPluginSupervisorV1;

type Error = CommunityPluginHostErrorV1;

/// The host-built inputs of one invocation.
///
/// `Driver::step` carries no invocation ID, artifact reference, profile digest
/// or provenance root, so the host builds them and hands them over here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvocationContextV1 {
    /// The invocation. Its `prior_state_schema` and `prior_state_bytes` are
    /// ignored and overwritten: the adapter always substitutes the Plugin
    /// state it holds (the initial state, then each committed next state), so
    /// the host cannot feed a different state through the context.
    pub invocation: PluginInvocationV1,
    /// The deterministic `host-v1` values.
    pub host_inputs: HostInputs,
}

/// A host-supplied source of invocation contexts, one per `step`.
///
/// It runs inside the Driver step with the Timeline and the Driver's own
/// scoped observation view. A refusal is a closed host error, for example
/// `ArtifactRevoked` from the host's trust evidence: it discards the pass and
/// quarantines or marks the Plugin like any other failure of its class.
pub trait InvocationContextSourceV1: Send + Sync {
    /// Build the next invocation's context.
    ///
    /// # Errors
    /// Returns the closed host error that refuses the invocation.
    fn context(
        &mut self,
        timeline: TimelineId,
        observation: &ObservationView<'_>,
    ) -> Result<InvocationContextV1, CommunityPluginHostErrorV1>;
}

/// What the host supplies to build one community Driver adapter.
pub struct CommunityDriverConfigV1 {
    /// The Plugin this Driver belongs to.
    pub plugin_id: PluginId,
    /// The Driver's diagnostic name.
    pub name: &'static str,
    /// Minimum interval between ticks.
    pub tick_interval: Duration,
    /// The projection states the Driver observes.
    pub subscriptions: Vec<ProjectionKey>,
    /// The supervisor that launches each worker.
    pub supervisor: CommunityPluginSupervisorV1,
    /// The negotiated release.
    pub negotiated: NegotiatedCommunityPluginV1,
    /// The verified Component bytes.
    pub component: Vec<u8>,
    /// The source of every invocation's host-built inputs.
    pub source: Box<dyn InvocationContextSourceV1>,
    /// The Plugin state before the first committed step (non-durable).
    pub initial_state: CommunityStateV1,
}

/// A community Plugin's [`Driver`], running `drive` in supervised workers.
pub struct CommunityDriverV1 {
    name: &'static str,
    tick_interval: Duration,
    subscriptions: Vec<ProjectionKey>,
    supervisor: CommunityPluginSupervisorV1,
    negotiated: NegotiatedCommunityPluginV1,
    component: Vec<u8>,
    source: Box<dyn InvocationContextSourceV1>,
    shared: Arc<Shared>,
    /// The next state staged by the pending step, adopted only on commit.
    staged: Option<CommunityStateV1>,
}

impl CommunityDriverV1 {
    /// Build the adapter and the host's handle on its in-memory state.
    #[must_use]
    pub fn new(config: CommunityDriverConfigV1) -> (Self, CommunityPluginHandleV1) {
        let shared = Arc::new(Shared::new(config.plugin_id, config.initial_state));
        let handle = CommunityPluginHandleV1::new(Arc::clone(&shared));
        let driver = Self {
            name: config.name,
            tick_interval: config.tick_interval,
            subscriptions: config.subscriptions,
            supervisor: config.supervisor,
            negotiated: config.negotiated,
            component: config.component,
            source: config.source,
            shared,
            staged: None,
        };
        (driver, handle)
    }

    /// Refuse to run while quarantined (or otherwise not available).
    fn ensure_available(&self) -> Result<(), RuntimeError> {
        match self.shared.availability() {
            PluginAvailabilityV1::Available => Ok(()),
            // Keep in step with the registry's own pass-time refusal in
            // `pos-runtime` `registry/availability.rs`: same error, same fields.
            availability => Err(PluginCompositionErrorV1::ImplementationUnavailable {
                plugin_id: self.shared.plugin_id(),
                availability,
            }
            .into()),
        }
    }

    /// Run one `drive` and stage its result.
    fn invoke(
        &mut self,
        timeline: TimelineId,
        observation: &ObservationView<'_>,
    ) -> Result<StepOutput, Error> {
        let context = self.source.context(timeline, observation)?;
        let invocation = with_prior_state(context.invocation, self.shared.committed_state());
        let id = invocation.invocation_id;
        let report = self
            .supervisor
            .drive(
                &self.negotiated,
                &self.component,
                &invocation,
                context.host_inputs,
            )
            .inspect_err(|failure| self.record(id, ReceiptParts::failed(*failure)))?;
        self.accept(id, report)
    }

    /// Record the receipt of a returned report and stage a valid output.
    fn accept(
        &mut self,
        invocation_id: [u8; 16],
        report: InvocationReportV1<PluginOutputV1>,
    ) -> Result<StepOutput, Error> {
        let metering = Some(report.metering);
        match report.result {
            Err(guest) => {
                let parts = ReceiptParts {
                    metering,
                    guest_error: Some(guest),
                    ..ReceiptParts::failed(Error::GuestDeclaredFailure)
                };
                self.record(invocation_id, parts);
                Err(Error::GuestDeclaredFailure)
            }
            Ok(output) => {
                let staged = self.stage(&output);
                let parts = ReceiptParts {
                    output_digest: Some(output.output_digest),
                    metering,
                    dropped_trace_annotations: output.trace_annotations.len(),
                    failure: staged.as_ref().err().copied(),
                    disposition: if staged.is_ok() {
                        ReceiptDispositionV1::Staged
                    } else {
                        ReceiptDispositionV1::Discarded
                    },
                    guest_error: None,
                };
                self.record(invocation_id, parts);
                staged
            }
        }
    }

    /// Map every draft, then hold the next state until commit.
    fn stage(&mut self, output: &PluginOutputV1) -> Result<StepOutput, Error> {
        let event_bytes = self.negotiated.limits().values().event_bytes;
        mapped_drafts(output, event_bytes).map(|drafts| {
            self.staged = Some(CommunityStateV1 {
                schema: output.next_state_schema,
                bytes: output.next_state_bytes.clone(),
            });
            StepOutput::new(drafts)
        })
    }

    fn record(&self, invocation_id: [u8; 16], parts: ReceiptParts) {
        self.shared.push_receipt(CommunityInvocationReceiptV1 {
            invocation_id,
            negotiated: self.negotiated.clone(),
            output_digest: parts.output_digest,
            metering: parts.metering,
            dropped_trace_annotations: parts.dropped_trace_annotations,
            failure: parts.failure,
            guest_error: parts.guest_error,
            disposition: parts.disposition,
        });
    }
}

/// The variable part of one receipt.
struct ReceiptParts {
    output_digest: Option<[u8; 32]>,
    metering: Option<MeteringV1>,
    dropped_trace_annotations: usize,
    failure: Option<Error>,
    guest_error: Option<GuestPluginErrorV1>,
    disposition: ReceiptDispositionV1,
}

impl ReceiptParts {
    /// An invocation that ended in `failure` with nothing staged.
    const fn failed(failure: Error) -> Self {
        Self {
            output_digest: None,
            metering: None,
            dropped_trace_annotations: 0,
            failure: Some(failure),
            guest_error: None,
            disposition: ReceiptDispositionV1::Discarded,
        }
    }
}

/// `invocation` with the Plugin state the adapter holds.
fn with_prior_state(
    mut invocation: PluginInvocationV1,
    state: CommunityStateV1,
) -> PluginInvocationV1 {
    invocation.prior_state_schema = state.schema;
    invocation.prior_state_bytes = state.bytes;
    invocation
}

impl Driver for CommunityDriverV1 {
    fn step(
        &mut self,
        timeline: TimelineId,
        observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        // A step left unresolved cannot be committed any more: drop its state.
        self.staged = None;
        self.shared.discard();
        self.ensure_available()?;
        self.invoke(timeline, &observations).map_err(|error| {
            self.shared.record_failure(error);
            RuntimeError::from(error)
        })
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn tick_interval(&self) -> Duration {
        self.tick_interval
    }

    fn subscriptions(&self) -> &[ProjectionKey] {
        &self.subscriptions
    }

    /// Adopt the staged next state: the whole batch committed.
    fn commit_step(&mut self) {
        if let Some(state) = self.staged.take() {
            self.shared.commit(state);
        }
    }

    /// Discard the staged next state with the pass.
    fn abort_step(&mut self) {
        self.staged = None;
        self.shared.discard();
    }
}

/// Register a community Plugin's Driver on the local-pinned path.
///
/// The Plugin's metadata is the host-supplied output policy
/// (`register_pinned_generated`): the registry still applies its host-owned
/// type, ownership and output-admission validation to every draft. The
/// Driver is assigned the non-participant scheduled profile, so it is never
/// mixed with participant-bound Drivers in a pass.
///
/// The profile assignment requires every Driver already registered to be
/// assigned too, and registration is not undone if it fails.
///
/// # Errors
/// Returns a pin that is not a `GovernedCommunity` Plugin as an
/// `IncompatibleImplementation`, then the registry's registration and
/// profile-composition errors.
pub fn register_community_driver(
    registry: &mut PluginRegistry,
    plugin: &dyn Plugin,
    pin: PluginPinV1,
    driver: CommunityDriverV1,
) -> Result<(), RuntimeError> {
    require_community_pin(plugin.id(), &pin)?;
    registry
        .register_pinned_generated(
            plugin,
            PluginRegistrationV1::new(pin, PluginAvailabilityV1::Available),
            None,
            Some(Box::new(driver)),
        )
        .and_then(|()| {
            registry.compose_scheduled_profiles(&[(
                plugin.id(),
                ScheduledDriverBindingV1::NonParticipant,
            )])
        })
}

/// The pin must be a community Plugin's.
fn require_community_pin(plugin_id: PluginId, pin: &PluginPinV1) -> Result<(), RuntimeError> {
    let field = if pin.implementation_kind() != DomainImplementationKindV1::Plugin {
        Some(PluginPinFieldV1::ImplementationKind)
    } else if pin.isolation() != PluginIsolationV1::GovernedCommunity {
        Some(PluginPinFieldV1::Isolation)
    } else {
        None
    };
    field.map_or(Ok(()), |field| {
        Err(PluginCompositionErrorV1::IncompatibleImplementation { plugin_id, field }.into())
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
