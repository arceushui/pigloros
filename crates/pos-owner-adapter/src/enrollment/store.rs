#![cfg(any(test, feature = "test-support"))]
//! The bound store's side of ADR-137 P3: steps 2, 3 and 6.

use std::collections::{BTreeMap, BTreeSet};

use pos_core::EntityId;
use pos_crypto::subject_nonce_ledger::SubjectStoreFileIdV1;
use pos_owner_bridge::{OwnerError, OwnerErrorKind};

const REGISTRY: OwnerError = OwnerError::new(OwnerErrorKind::Registry);

/// The identity that ADR-137 P3 step 6 registers and activates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectKeyRegistration {
    /// The ADR-091 owner: `subject:` and the subject's 32 lowercase hex digits.
    pub owner_id: String,
    /// The subject the owner is derived from.
    pub subject_id: EntityId,
    /// The epoch that commit verified under P3 step 2.
    pub epoch: u64,
    /// The ADR-091 `key_material_digest` of the confirmed root.
    pub root_material_digest: [u8; 32],
}

/// The store steps of enrollment, injected into the enrollment adapter.
///
/// Each method is one shared-store transaction of ADR-137 P3. The adapter
/// calls them in P3 order under the E16 lifetime lock and the subject owner's
/// exclusive session lock; it never retries one. Only
/// [`VolatileEnrollmentStore`] implements this trait until the protected
/// store implementation lands (#1373).
pub trait EnrollmentStore {
    /// P3 step 2, the store half: the highest P1 epoch of the owner.
    ///
    /// In one read snapshot, refuse when B6 rows fence the subject's
    /// Timeline, then return the highest epoch or high-water entry that the
    /// bound store's registry holds for `owner_id` in any lifecycle state, or
    /// zero when it holds none.
    ///
    /// # Errors
    /// Returns the store's failure. A B6 fence or an unreadable or malformed
    /// P1 inventory must refuse; P1 is never treated as empty.
    fn registry_epoch_ceiling(
        &mut self,
        owner_id: &str,
        subject_id: EntityId,
    ) -> Result<u64, OwnerError>;

    /// P3 step 3: commit the P3a staging record.
    ///
    /// In one `BEGIN IMMEDIATE`, insert `(owner_id, epoch, store_file_id)` for
    /// the bound store and return that store's proven file identity, which the
    /// SNL1 row of step 5 carries.
    ///
    /// # Errors
    /// Returns the store's failure. Nothing is staged after a failure.
    fn commit_staging_record(
        &mut self,
        owner_id: &str,
        epoch: u64,
    ) -> Result<SubjectStoreFileIdV1, OwnerError>;

    /// P3 step 6, the linearization point: register and activate.
    ///
    /// In one `BEGIN IMMEDIATE`, re-check the B6 rows, require the epoch to be
    /// strictly above the owner's high-water mark, register and activate the
    /// identity under the ADR-065 rules, and delete the staging record.
    ///
    /// # Errors
    /// Returns the store's failure. The staged artifacts then stay for
    /// ADR-137 P5 recovery.
    fn register(&mut self, registration: &SubjectKeyRegistration) -> Result<(), OwnerError>;
}

impl<S: EnrollmentStore + ?Sized> EnrollmentStore for &mut S {
    fn registry_epoch_ceiling(
        &mut self,
        owner_id: &str,
        subject_id: EntityId,
    ) -> Result<u64, OwnerError> {
        (**self).registry_epoch_ceiling(owner_id, subject_id)
    }

    fn commit_staging_record(
        &mut self,
        owner_id: &str,
        epoch: u64,
    ) -> Result<SubjectStoreFileIdV1, OwnerError> {
        (**self).commit_staging_record(owner_id, epoch)
    }

    fn register(&mut self, registration: &SubjectKeyRegistration) -> Result<(), OwnerError> {
        (**self).register(registration)
    }
}

/// An in-memory [`EnrollmentStore`] with the P3 store semantics.
///
/// It models the owner's registry high-water marks, B6 fences, the P3a
/// staging table and the registered identities, and refuses with `Registry`
/// where the protected store would. It persists nothing.
#[derive(Debug)]
pub struct VolatileEnrollmentStore {
    store_file_id: SubjectStoreFileIdV1,
    high_water: BTreeMap<String, u64>,
    fenced: BTreeSet<EntityId>,
    staging: BTreeSet<(String, u64)>,
    registrations: Vec<SubjectKeyRegistration>,
}

impl VolatileEnrollmentStore {
    /// An empty store whose proven file identity is `store_file_id`.
    #[must_use]
    pub const fn new(store_file_id: SubjectStoreFileIdV1) -> Self {
        Self {
            store_file_id,
            high_water: BTreeMap::new(),
            fenced: BTreeSet::new(),
            staging: BTreeSet::new(),
            registrations: Vec::new(),
        }
    }

    /// Record `epoch` as a P1 epoch of `owner_id`, as an earlier registration
    /// or a `Destroyed` tombstone would. A lower epoch leaves the mark as is.
    pub fn record_epoch(&mut self, owner_id: &str, epoch: u64) {
        let mark = self.high_water.entry(owner_id.to_owned()).or_default();
        *mark = epoch.max(*mark);
    }

    /// Add a B6 erasure-fence row for the subject's Timeline.
    pub fn fence(&mut self, subject_id: EntityId) {
        self.fenced.insert(subject_id);
    }

    /// The P3a staging records, in `(owner_id, epoch)` order.
    pub fn staging_records(&self) -> impl Iterator<Item = (&str, u64)> {
        self.staging
            .iter()
            .map(|(owner_id, epoch)| (owner_id.as_str(), *epoch))
    }

    /// The registered identities, in registration order.
    #[must_use]
    pub fn registrations(&self) -> &[SubjectKeyRegistration] {
        &self.registrations
    }

    fn ceiling(&self, owner_id: &str) -> u64 {
        self.high_water.get(owner_id).copied().unwrap_or_default()
    }

    fn admit(&self, subject_id: EntityId) -> Result<(), OwnerError> {
        accept(!self.fenced.contains(&subject_id))
    }
}

impl EnrollmentStore for VolatileEnrollmentStore {
    fn registry_epoch_ceiling(
        &mut self,
        owner_id: &str,
        subject_id: EntityId,
    ) -> Result<u64, OwnerError> {
        self.admit(subject_id).map(|()| self.ceiling(owner_id))
    }

    fn commit_staging_record(
        &mut self,
        owner_id: &str,
        epoch: u64,
    ) -> Result<SubjectStoreFileIdV1, OwnerError> {
        accept(self.staging.insert((owner_id.to_owned(), epoch))).map(|()| self.store_file_id)
    }

    fn register(&mut self, registration: &SubjectKeyRegistration) -> Result<(), OwnerError> {
        let staged = (registration.owner_id.clone(), registration.epoch);
        self.admit(registration.subject_id)
            .and_then(|()| {
                accept(
                    registration.epoch > self.ceiling(&registration.owner_id)
                        && self.staging.contains(&staged),
                )
            })
            .map(|()| {
                self.staging.remove(&staged);
                self.record_epoch(&registration.owner_id, registration.epoch);
                self.registrations.push(registration.clone());
            })
    }
}

fn accept(accepted: bool) -> Result<(), OwnerError> {
    accepted.then_some(()).ok_or(REGISTRY)
}
