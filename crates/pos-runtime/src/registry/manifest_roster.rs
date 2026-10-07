//! The ADR-088 MPR1 Plugin roster, built from the admitted Plugin sources.

use pos_core::{ManifestPluginEntryV1, ManifestPluginRosterErrorV1, ManifestPluginRosterV1};

use super::PluginRegistry;
use crate::composition::{
    AdmittedCompositionV1, AdmittedManifestPolicySourceV1, ManifestRegistrationErrorV1,
};

/// Closed failures while building the manifest roster from admitted Plugins.
///
/// Neither variant echoes closure bytes.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ManifestRosterBuildErrorV1 {
    /// The registry could not read its admitted Plugin sources.
    #[error("cannot read the admitted Plugins: {0}")]
    Admission(#[from] ManifestRegistrationErrorV1),
    /// The admitted rows do not fit one roster, for example above its 1 GiB size cap.
    #[error("an admitted Plugin does not fit the manifest roster: {0}")]
    Roster(ManifestPluginRosterErrorV1),
}

impl PluginRegistry {
    /// Build the manifest roster for one admitted composition, sorted by stable slot.
    ///
    /// Each row carries the recorded slot, `PluginId`, display name, version, EOP1 digest and the
    /// exact OPC1 closure bytes. The whole roster is built before it is returned, so a failure
    /// leaves nothing partial, and a later call never overwrites an earlier result. Two
    /// same-name Plugins stay two rows, and a reducer-only Plugin is included.
    ///
    /// The display name is copied from the admitted composition's own catalog row, which the
    /// registry checked against the registered Plugin when it admitted the batch; it is never
    /// read from a mutable registry entry. This builder takes the registry's own capability and
    /// not a `VerifiedManifestOwnerLinkV1`: that verified link exposes digests only, so it cannot
    /// supply names or exact closure bytes. Whether an owner authenticated this roster is
    /// checked later, by the installed verifier, and a decoded or built roster grants no Replay
    /// capability.
    ///
    /// # Errors
    /// `Admission` for a stale capability or an unavailable native byte copy; `Roster` when the
    /// rows exceed the roster bounds.
    pub fn manifest_plugin_roster(
        &self,
        admitted: &AdmittedCompositionV1,
    ) -> Result<ManifestPluginRosterV1, ManifestRosterBuildErrorV1> {
        let sources = self.admitted_manifest_policy_sources(admitted)?;
        roster_from_sources(&sources)
    }

    /// Build the manifest roster for the composition this registry has admitted, if any.
    ///
    /// `Ok(None)` means the registry holds no manifest batch: it was never admitted through
    /// [`Self::admit_local_manifest_registration`], for example because its Plugins were added
    /// with `register` or `register_generated`. A host that records a run in that case may keep
    /// an empty roster, which is not a Replay claim: it names no Plugin, and the installed
    /// verifier rejects it against any admitted composition.
    ///
    /// The retained batch is read without an `AdmittedCompositionV1`. A local admission cannot
    /// go stale, because every ordinary registration path rejects a registry that holds a
    /// batch; a batch that no longer matches the registered Plugins, such as a prepared
    /// installed batch that is still incomplete, is an error.
    ///
    /// # Errors
    /// `Admission` when the retained batch does not match the registered Plugins; `Roster` when
    /// the rows exceed the roster bounds, for example its 1 GiB size cap. An error is never
    /// replaced by an empty or partial roster.
    pub fn retained_manifest_plugin_roster(
        &self,
    ) -> Result<Option<ManifestPluginRosterV1>, ManifestRosterBuildErrorV1> {
        let batch = self.manifest_batch.as_ref();
        let roster = batch.map(|catalog| {
            self.policy_sources_for(catalog)
                .map_err(ManifestRosterBuildErrorV1::from)
                .and_then(|sources| roster_from_sources(&sources))
        });
        roster.transpose()
    }
}

fn roster_from_sources(
    sources: &[AdmittedManifestPolicySourceV1],
) -> Result<ManifestPluginRosterV1, ManifestRosterBuildErrorV1> {
    sources
        .iter()
        .map(entry_from_source)
        .collect::<Result<Vec<_>, _>>()
        .and_then(ManifestPluginRosterV1::new)
        .map_err(ManifestRosterBuildErrorV1::Roster)
}

fn entry_from_source(
    source: &AdmittedManifestPolicySourceV1,
) -> Result<ManifestPluginEntryV1, ManifestPluginRosterErrorV1> {
    ManifestPluginEntryV1::new(
        source.stable_slot(),
        source.plugin_id(),
        source.plugin_name(),
        source.plugin_version(),
        source.eop1_native_digest(),
        source.opc1_bytes(),
    )
}
