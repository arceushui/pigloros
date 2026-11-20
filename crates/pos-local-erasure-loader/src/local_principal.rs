//! The store-recorded identity of the Local Principal (#1361) that every
//! Local erasure root binds.
//!
//! It holds the well-known grant and authority Timeline derivations, and the
//! authority registry digest of the root grant a store records.
//!
//! The Gateway provisions the Principal; every root that composes the Local
//! erasure authority reads it through this module, so the derivation
//! contexts stay byte-identical across roots.

use pos_core::{
    AuthorityPersistenceErrorV1, AuthorityPersistencePortV1, CapabilityGrantV1, Hash, TimelineId,
};
use thiserror::Error;
use ulid::Ulid;

/// Closed failures reading the recorded Local Principal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum LocalPrincipalReadErrorV1 {
    /// The store's authority records cannot be read.
    #[error("Local Principal authority is unavailable")]
    Unavailable,
    /// The store records a Local Principal grant whose authority record is
    /// invalid or conflicts with its Timeline.
    #[error(
        "the store's Local Principal authority record is unreadable or conflicts with its \
         authority Timeline; restore the store from a backup"
    )]
    Corrupt,
}

/// The hash of the derivation `context`.
#[must_use]
pub fn derived_hash(context: &str) -> Hash {
    Hash::from_bytes(blake3::derive_key(context, &[]))
}

/// The Timeline identity of the derivation `context`: the 128-bit prefix of
/// its hash, read as a ULID.
#[must_use]
pub fn derived_timeline(context: &str) -> TimelineId {
    let digest = blake3::derive_key(context, &[]);
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest[..16]);
    TimelineId::from_ulid(Ulid::from_bytes(identity))
}

/// The one grant identity a store's Local Principal is recorded under.
#[must_use]
pub fn local_principal_grant_id() -> Hash {
    derived_hash("pigloros gateway local principal grant v1")
}

/// The authority Timeline the Local Principal's grant is issued on.
#[must_use]
pub fn local_principal_authority_timeline() -> TimelineId {
    derived_timeline("pigloros gateway local principal authority timeline v1")
}

/// The authority registry digest of the Local Principal root grant `store`
/// records, or `None` when it records no Local Principal (a store resolves
/// no chain for an absent leaf grant).
///
/// # Errors
/// Returns [`LocalPrincipalReadErrorV1::Unavailable`] when the authority
/// records cannot be read and [`LocalPrincipalReadErrorV1::Corrupt`] when
/// the recorded chain is invalid.
pub fn recorded_registry_digest<S>(store: &S) -> Result<Option<Hash>, LocalPrincipalReadErrorV1>
where
    S: AuthorityPersistencePortV1 + ?Sized,
{
    store
        .load_authority(local_principal_grant_id())
        .map(Some)
        .or_else(absent_authority)
        .map(|persisted| {
            persisted.and_then(|persisted| {
                persisted
                    .chain()
                    .grants()
                    .last()
                    .map(CapabilityGrantV1::authority_registry_digest)
            })
        })
}

/// An authority read error as a recorded digest: no chain for the absent
/// leaf grant (`Conflict`) means no Local Principal.
fn absent_authority<T>(
    error: AuthorityPersistenceErrorV1,
) -> Result<Option<T>, LocalPrincipalReadErrorV1> {
    match error {
        AuthorityPersistenceErrorV1::Conflict => Ok(None),
        AuthorityPersistenceErrorV1::Unavailable => Err(LocalPrincipalReadErrorV1::Unavailable),
        _ => Err(LocalPrincipalReadErrorV1::Corrupt),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use pos_core::{
        AuthorityCommitOutcomeV1, AuthorityMutationPermitV1, AuthorityPersistenceBindingV1,
        AuthorizationDenialEvidenceV1, AuthorizationDenialPermitV1, CapabilityRevocationV1,
        PersistedAuthorityV1,
    };

    use super::*;

    /// An authority port whose every read fails with one error.
    struct Failing(AuthorityPersistenceErrorV1);

    impl AuthorityPersistencePortV1 for Failing {
        fn bind_authority_persistence(
            &mut self,
            _binding: AuthorityPersistenceBindingV1,
        ) -> Result<(), AuthorityPersistenceErrorV1> {
            Err(self.0)
        }

        fn issue_capability_grant(
            &mut self,
            _permit: AuthorityMutationPermitV1,
            _grant: &CapabilityGrantV1,
        ) -> Result<AuthorityCommitOutcomeV1, AuthorityPersistenceErrorV1> {
            Err(self.0)
        }

        fn revoke_capability_grant(
            &mut self,
            _permit: AuthorityMutationPermitV1,
            _revocation: &CapabilityRevocationV1,
        ) -> Result<AuthorityCommitOutcomeV1, AuthorityPersistenceErrorV1> {
            Err(self.0)
        }

        fn load_authority(
            &self,
            _leaf_grant_id: Hash,
        ) -> Result<PersistedAuthorityV1, AuthorityPersistenceErrorV1> {
            Err(self.0)
        }

        fn record_authorization_denial(
            &mut self,
            _permit: AuthorizationDenialPermitV1,
        ) -> Result<(), AuthorityPersistenceErrorV1> {
            Err(self.0)
        }

        fn load_authorization_denials(
            &self,
            _after: u64,
            _limit: usize,
        ) -> Result<Vec<(u64, AuthorizationDenialEvidenceV1)>, AuthorityPersistenceErrorV1>
        {
            Err(self.0)
        }
    }

    /// The derivation contexts are the ones the Gateway provisioned under;
    /// the Timeline is the 128-bit prefix of its context's hash.
    #[test]
    fn the_local_principal_identities_are_their_fixed_derivations() {
        let grant = blake3::derive_key("pigloros gateway local principal grant v1", &[]);
        assert_eq!(local_principal_grant_id(), Hash::from_bytes(grant));
        let timeline = blake3::derive_key(
            "pigloros gateway local principal authority timeline v1",
            &[],
        );
        let mut prefix = [0; 16];
        prefix.copy_from_slice(&timeline[..16]);
        assert_eq!(
            local_principal_authority_timeline(),
            TimelineId::from_ulid(Ulid::from_bytes(prefix))
        );
        assert_ne!(derived_hash("a"), derived_hash("b"));
        assert_ne!(derived_timeline("a"), derived_timeline("b"));
    }

    /// An absent leaf is an unprovisioned store; an unreadable store and
    /// every other refusal fail closed with their typed errors.
    #[test]
    fn the_recorded_registry_digest_maps_each_read_outcome() {
        assert_eq!(
            recorded_registry_digest(&Failing(AuthorityPersistenceErrorV1::Conflict)),
            Ok(None)
        );
        assert_eq!(
            recorded_registry_digest(&Failing(AuthorityPersistenceErrorV1::Unavailable)),
            Err(LocalPrincipalReadErrorV1::Unavailable)
        );
        for corrupt in [
            AuthorityPersistenceErrorV1::InvalidRecord,
            AuthorityPersistenceErrorV1::StaleEpoch,
            AuthorityPersistenceErrorV1::TimelineOrder,
        ] {
            assert_eq!(
                recorded_registry_digest(&Failing(corrupt)),
                Err(LocalPrincipalReadErrorV1::Corrupt)
            );
        }
        assert_eq!(
            LocalPrincipalReadErrorV1::Unavailable.to_string(),
            "Local Principal authority is unavailable"
        );
    }
}
