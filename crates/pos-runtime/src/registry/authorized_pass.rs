//! ADR-021 scheduled passes over ADR-059 participant-authorized views (#481).
//!
//! In a participant-authorized scheduled pass, each due Driver observes only
//! the view the host derived for it. It never receives subscription-scoped
//! Projection state. The host materializes every view from the same base
//! Timeline cut, and each view is revalidated against current authority
//! before any Driver runs. Each Driver receives only its own view. So it
//! cannot read another participant's view, raw Projection state, or raw
//! Timeline Events.
//!
//! The staged pass retains one digest. It binds the base cut and each
//! Driver's authorized view, in host schedule order.
//! [`PluginRegistry::admit_authorized_scheduled_pass`] binds that digest into
//! the `ScheduledAiDriver` admission basis. There, it revalidates every view
//! again before the store compares the basis.

use pos_core::{
    AuthorityErrorV1, AuthorityRegistrySnapshotV1, ErasureProtectedOperationV1, EventDraft, Hash,
    KnowledgeSnapshotV1, ObservationSnapshotV1, PersistedAuthorityV1, ReplayClaimEvaluationV1, Seq,
    TimelineId,
};
use pos_state::AuthorizedObservationV1;

use super::{
    invoke_driver, reject_host_owned_drafts, reject_unowned_plugin_drafts, validate_plugin_output,
    AuthorizedDriverTargetV1, AuthorizedPendingStep, OperationContext, PendingStep, PluginEntry,
    PluginRegistry,
};
use crate::{driver::ObservationView, error::RuntimeError};

/// One due Driver and the participant-authorized view the host derived for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedDriverViewV1 {
    /// The Driver's Plugin and the Timeline of the pass.
    pub target: AuthorizedDriverTargetV1,
    /// The host-materialized OBS1 observation for this Driver alone.
    pub observation: AuthorizedObservationV1,
    /// The KNS1 knowledge snapshot derived from that observation.
    pub knowledge: KnowledgeSnapshotV1,
}

/// Current authority that the host resolved for one participant-authorized view.
///
/// The host resolves it again at the commit boundary, so that a revocation,
/// erasure, or consent loss after staging aborts the whole pass.
#[derive(Clone, Copy, Debug)]
pub struct AuthorizedViewAuthorityV1<'a> {
    /// ADR-060 evaluation of the view's registered OBS1 artifact.
    pub artifact_evaluation: &'a ReplayClaimEvaluationV1,
    /// The current persisted authority chain for the view's grant.
    pub authority: &'a PersistedAuthorityV1,
    /// The current authority registry snapshot.
    pub authority_registry: &'a AuthorityRegistrySnapshotV1,
    /// The authority position at which the evidence is evaluated.
    pub authority_position: Seq,
}

impl AuthorizedViewAuthorityV1<'_> {
    /// Release `observation`'s OBS1 snapshot only while its authority evidence
    /// is current and its registered artifact remains authoritative.
    fn release<'o>(
        &self,
        observation: &'o AuthorizedObservationV1,
    ) -> Result<&'o ObservationSnapshotV1, RuntimeError> {
        observation
            .revalidate(
                self.authority,
                self.authority_registry,
                self.authority_position,
            )
            .and_then(|()| observation.authoritative_snapshot(self.artifact_evaluation))
            .map_err(RuntimeError::Authority)
    }
}

impl PluginRegistry {
    /// Stage one scheduled pass in which each due Driver observes only its
    /// participant-authorized view.
    ///
    /// `views` lists the due Drivers in host schedule order, which is Plugin
    /// registration order. `authorities` holds the current authority for the
    /// view at the same index. Every view must be derived from the base cut
    /// `(timeline, observed_through)`, and a Driver must declare no legacy
    /// Projection or Event subscriptions. A failure in any Driver aborts every
    /// Driver staged by the pass. The staged pass commits only through
    /// [`Self::admit_authorized_scheduled_pass`].
    ///
    /// # Errors
    /// Returns [`RuntimeError::ModeMismatch`] in Replay mode, or
    /// [`RuntimeError::PendingDriverStep`] while a pass is unfinished. Returns
    /// [`RuntimeError::NoDriver`] for an unregistered or Driverless Plugin. A
    /// closed authority error covers views out of schedule order, unpaired or
    /// stale authority, views from another base cut, and ambient
    /// subscriptions. A Driver, output, schema, or budget error is also
    /// possible.
    pub fn stage_authorized_scheduled_pass(
        &mut self,
        timeline: TimelineId,
        observed_through: Seq,
        views: &[AuthorizedDriverViewV1],
        authorities: &[AuthorizedViewAuthorityV1<'_>],
    ) -> Result<Vec<EventDraft>, RuntimeError> {
        self.ensure_live_execution()
            .and_then(|()| self.ensure_no_pending_step())
            .and_then(|()| self.ensure_schedule_order(views))
            .and_then(|()| release_views(timeline, observed_through, views, authorities))
            .and_then(|snapshots| {
                self.with_erasure_mut_fence(
                    timeline,
                    ErasureProtectedOperationV1::PluginInput,
                    |registry| {
                        registry.stage_released_views(timeline, observed_through, views, &snapshots)
                    },
                )
            })
    }

    /// Require registered Plugins in strictly ascending registration order.
    fn ensure_schedule_order(&self, views: &[AuthorizedDriverViewV1]) -> Result<(), RuntimeError> {
        views
            .iter()
            .map(|view| {
                let plugin_id = view.target.plugin_id;
                self.plugins
                    .get_index_of(&plugin_id)
                    .ok_or_else(|| RuntimeError::NoDriver {
                        name: plugin_id.to_string(),
                    })
            })
            .collect::<Result<Vec<usize>, RuntimeError>>()
            .and_then(|indices| {
                if indices.windows(2).all(|pair| pair[0] < pair[1]) {
                    Ok(())
                } else {
                    Err(AuthorityErrorV1::UnauthorizedSource.into())
                }
            })
    }

    fn stage_released_views(
        &mut self,
        timeline: TimelineId,
        observed_through: Seq,
        views: &[AuthorizedDriverViewV1],
        snapshots: &[ObservationSnapshotV1],
    ) -> Result<Vec<EventDraft>, RuntimeError> {
        self.restored_binding = None;
        let mut drafts = Vec::new();
        let mut staged = Vec::new();
        for (view, snapshot) in views.iter().zip(snapshots) {
            let plugin_id = view.target.plugin_id;
            staged.push(plugin_id);
            let invoked = self
                .plugins
                .get_mut(&plugin_id)
                .map_or(
                    Err(RuntimeError::NoDriver {
                        name: plugin_id.to_string(),
                    }),
                    |entry| invoke_authorized_entry(entry, timeline, snapshot, &view.knowledge),
                )
                .and_then(|output| self.check_pass_output(drafts.len(), output));
            match invoked {
                Ok(output) => drafts.extend(output),
                Err(error) => {
                    let _ = self.abort_drivers(&staged);
                    return Err(error);
                }
            }
        }
        let event_cursors = staged.iter().map(|id| (*id, observed_through)).collect();
        self.pending_step = Some(PendingStep {
            timeline,
            driver_ids: staged,
            cadence_updates: Vec::new(),
            event_cursors,
            operation: OperationContext::Public,
            staged_drafts: drafts.clone(),
            authorized: Some(AuthorizedPendingStep {
                observations: views.iter().map(|view| view.observation.clone()).collect(),
                observed_through,
                view_digest: authorized_view_digest(timeline, observed_through, views, snapshots),
            }),
            scheduled: None,
        });
        Ok(drafts)
    }

    /// Schema-validate one Driver's output and charge it to the pass budget.
    fn check_pass_output(
        &self,
        staged: usize,
        output: Vec<EventDraft>,
    ) -> Result<Vec<EventDraft>, RuntimeError> {
        let requested = u64::try_from(staged.saturating_add(output.len())).unwrap_or(u64::MAX);
        self.schemas
            .validate_batch(&output)
            .and_then(|()| match self.resource_limit {
                Some(limit) if requested > limit => Err(RuntimeError::ResourceExhausted {
                    driver: "host-tick-budget".to_owned(),
                    requested,
                    limit,
                }),
                _ => Ok(output),
            })
    }
}

impl AuthorizedPendingStep {
    /// Revalidate every retained view against current authority at the
    /// commit boundary. Return the base cut and the authorized-view digest
    /// that the admission basis binds.
    pub(super) fn revalidate(
        &self,
        authorities: &[AuthorizedViewAuthorityV1<'_>],
    ) -> Result<(Seq, Hash), RuntimeError> {
        paired(self.observations.len(), authorities)
            .and_then(|()| {
                self.observations.iter().zip(authorities).try_for_each(
                    |(observation, authority)| authority.release(observation).map(|_| ()),
                )
            })
            .map(|()| (self.observed_through, self.view_digest))
    }
}

/// Invoke one Driver with only its authorized view, then admit its output.
fn invoke_authorized_entry(
    entry: &mut PluginEntry,
    timeline: TimelineId,
    snapshot: &ObservationSnapshotV1,
    knowledge: &KnowledgeSnapshotV1,
) -> Result<Vec<EventDraft>, RuntimeError> {
    let Some(driver) = entry.driver.as_mut() else {
        return Err(RuntimeError::NoDriver {
            name: entry.name.clone(),
        });
    };
    if !driver.subscriptions().is_empty() || !driver.event_subscriptions().is_empty() {
        return Err(AuthorityErrorV1::UnauthorizedSource.into());
    }
    let invoked = invoke_driver(
        driver.as_mut(),
        timeline,
        ObservationView::from_authorized_snapshot(snapshot, knowledge),
    );
    invoked.and_then(|output| {
        reject_host_owned_drafts(&output)
            .and_then(|()| reject_unowned_plugin_drafts(&output, &entry.owned_event_types))
            .and_then(|()| validate_plugin_output(entry, &output.drafts))
            .map(|()| output.drafts)
    })
}

/// Require exactly one current authority for each view.
fn paired(views: usize, authorities: &[AuthorizedViewAuthorityV1<'_>]) -> Result<(), RuntimeError> {
    if views == authorities.len() {
        Ok(())
    } else {
        Err(AuthorityErrorV1::UnauthorizedSource.into())
    }
}

/// Release every view's snapshot from its current authority and bind it to
/// the pass's base cut.
fn release_views(
    timeline: TimelineId,
    observed_through: Seq,
    views: &[AuthorizedDriverViewV1],
    authorities: &[AuthorizedViewAuthorityV1<'_>],
) -> Result<Vec<ObservationSnapshotV1>, RuntimeError> {
    paired(views.len(), authorities).and_then(|()| {
        views
            .iter()
            .zip(authorities)
            .map(|(view, authority)| {
                authority
                    .release(&view.observation)
                    .and_then(|snapshot| bind_view(timeline, observed_through, view, snapshot))
            })
            .collect()
    })
}

/// Accept a released snapshot only for its own Driver, its knowledge, and the
/// pass's base cut.
fn bind_view(
    timeline: TimelineId,
    observed_through: Seq,
    view: &AuthorizedDriverViewV1,
    snapshot: &ObservationSnapshotV1,
) -> Result<ObservationSnapshotV1, RuntimeError> {
    let bound = snapshot.plugin_id() == view.target.plugin_id
        && view.target.timeline == timeline
        && snapshot.timeline_id() == timeline
        && snapshot.observed_through() == observed_through;
    view.knowledge
        .validate_observation_snapshot(snapshot)
        .and_then(|()| {
            if bound {
                Ok(snapshot.clone())
            } else {
                Err(AuthorityErrorV1::UnauthorizedSource)
            }
        })
        .map_err(RuntimeError::Authority)
}

/// Bind the base cut and every Driver's authorized view, in host schedule
/// order, into one digest.
fn authorized_view_digest(
    timeline: TimelineId,
    observed_through: Seq,
    views: &[AuthorizedDriverViewV1],
    snapshots: &[ObservationSnapshotV1],
) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.AuthorizedScheduledPass.v1\0");
    hasher.update(&timeline.inner().to_bytes());
    hasher.update(&observed_through.as_u64().to_be_bytes());
    hasher.update(&u64::try_from(views.len()).unwrap_or(u64::MAX).to_be_bytes());
    for (view, snapshot) in views.iter().zip(snapshots) {
        hasher.update(&view.target.plugin_id.inner().to_bytes());
        hasher.update(snapshot.digest().as_bytes());
        hasher.update(view.knowledge.digest().as_bytes());
    }
    Hash::from_bytes(*hasher.finalize().as_bytes())
}
