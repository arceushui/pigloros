//! `MemoryStore` publication of community ARD1 rows (owner decision on #560,
//! note 22722, G7).
//!
//! Community ARD1 rows join the store's artifact-registration catalogue, so
//! the erasure inventory sees them like every other registration. The only
//! input is the sealed batch the community extractor verified; no caller
//! row, owner or registration is accepted.
//!
//! Every check runs before the first insertion, so a refusal leaves the
//! catalogue unchanged.

use pos_core::community_lifecycle::{
    community_catalogue_owner_v1, CommunityLifecycleErrorV1 as Error,
};
use pos_core::ArtifactRegistrationCatalogRowV1;

use super::MemoryStore;
use crate::community::CommunityArtifactBatchV1;

impl MemoryStore {
    /// Publish every ARD1 of `batch` under its generation's artifact-catalogue
    /// owner `community-artifact:<T32>:<G32>`, bound to its Timeline.
    ///
    /// # Errors
    /// Returns `Conflict` when any registration address or artifact identity
    /// is already catalogued, and `InvalidBinding` for a row the catalogue
    /// codec refuses.
    pub(crate) fn commit_community_artifact_batch(
        &mut self,
        batch: &CommunityArtifactBatchV1,
    ) -> Result<(), Error> {
        let (timeline, generation) = batch.coordinates();
        community_catalogue_owner_v1(timeline, generation)
            .and_then(|owner| {
                batch
                    .records()
                    .iter()
                    .map(|record| {
                        let registration = record.registration();
                        ArtifactRegistrationCatalogRowV1::from_persisted(
                            owner,
                            registration.fields().artifact_class,
                            registration.fields().artifact_digest,
                            registration.address(),
                            record.object().to_vec(),
                            registration.canonical_cbor(),
                        )
                        .ok()
                        .ok_or(Error::InvalidBinding)
                    })
                    .collect::<Result<Vec<_>, Error>>()
            })
            .and_then(|rows| {
                let taken = rows.iter().any(|row| {
                    self.artifact_registrations
                        .contains_key(&row.registration_address())
                        || self.artifact_registration_identities.contains_key(&(
                            *row.owner_id(),
                            row.artifact_class(),
                            row.artifact_digest(),
                        ))
                });
                if taken {
                    return Err(Error::Conflict);
                }
                for row in rows {
                    let address = row.registration_address();
                    self.artifact_registration_identities.insert(
                        (*row.owner_id(), row.artifact_class(), row.artifact_digest()),
                        address,
                    );
                    self.artifact_registration_timelines
                        .insert((timeline, address));
                    self.artifact_registrations.insert(address, row);
                }
                Ok(())
            })
    }
}
