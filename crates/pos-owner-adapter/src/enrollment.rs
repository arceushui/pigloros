#![cfg(any(test, feature = "test-support"))]
//! The real ADR-091 [`EnrollmentPort`]: ADR-110 §8 E1 to E5 and ADR-137 P3.
//!
//! [`OwnerEnrollmentAdapter`] serves one enrollment of one subject. It is
//! opened under the held E16 encryptor lock, takes the subject owner's
//! exclusive session/inventory lock and keeps it until it is dropped, so the
//! whole ceremony and the commit run under that lock (ADR-110 §8, ADR-137 P3).
//!
//! Opening picks the epoch with the ADR-137 P3 step 2 rule before any
//! ceremony runs, and [`OwnerEnrollmentAdapter::context`] hands it to the
//! bridge. `commit` re-runs that rule and refuses with `Registry` unless it
//! yields the same epoch (owner decision 2026-11-21, an interpretation of P3).
//! The store steps 2, 3 and 6 go through the injected [`EnrollmentStore`].
//!
//! Errors use the bridge's three owner kinds: `Wrap` for randomness, sealing
//! and authenticated opening; `Registry` for a refused identity, inventory,
//! ledger or epoch; `DurableWrite` for a failed P3 step 4 or 5 write. A commit
//! that fails after its P3a staging record leaves that record and whatever it
//! staged for ADR-137 P5 recovery, which no artifact of this crate performs.

use pos_core::EntityId;
use pos_crypto::subject_key::{
    subject_owner_id, SubjectKeyWrapParamsV1, SubjectKeyWrapV1, SubjectPrfOutputV1,
    SubjectRootKeyV1,
};
use pos_crypto::subject_nonce_ledger::{SubjectNonceLedgerRowV1, SubjectNonceLedgerV1};
use pos_owner_bridge::encryptor_lock::linux::{
    SubjectEncryptorLock, SubjectKeyArtifactKind, SubjectKeyArtifactName,
    SubjectOwnerExclusiveGuard,
};
use pos_owner_bridge::{
    BridgeError, ConfirmedBinding, EnrollmentContext, EnrollmentPort, OwnerError, OwnerErrorKind,
    PrfOutput, RootFingerprint, SealInputs, SecureRandom,
};
use pos_owner_bridge_codec::{
    encode_subject_credential_binding, PrfInput, SubjectId, MAX_SUBJECT_CREDENTIAL_BINDING_BYTES,
};
use ulid::Ulid;
use zeroize::Zeroizing;

mod inventory;
mod store;

use inventory::Inventory;
pub use store::{EnrollmentStore, SubjectKeyRegistration, VolatileEnrollmentStore};

/// The relying party of every owner credential (ADR-097 §5).
const RP_ID: &str = "localhost";
/// The root, the wrap salt and the subkey salt (32 bytes each) and the
/// 12-byte wrap nonce, drawn in one fill.
const RANDOM_BYTES: usize = 108;
const WRAP: OwnerError = OwnerError::new(OwnerErrorKind::Wrap);
const REGISTRY: OwnerError = OwnerError::new(OwnerErrorKind::Registry);
const DURABLE_WRITE: OwnerError = OwnerError::new(OwnerErrorKind::DurableWrite);

/// The in-memory root and its `SubjectKeyWrapV1`, never persisted before
/// `commit`.
///
/// The root is wiped when the candidate drops, whether `commit` consumed it
/// or the bridge abandoned it.
pub struct EnrollmentCandidate {
    root: SubjectRootKeyV1,
    wrap: SubjectKeyWrapV1,
}

/// The ADR-091 owner adapter for one enrollment of one subject.
///
/// It holds the subject owner's exclusive session/inventory lock from
/// [`Self::open`] until it drops.
pub struct OwnerEnrollmentAdapter<'lock, S, R> {
    lock: &'lock SubjectEncryptorLock,
    _owner: SubjectOwnerExclusiveGuard<'lock>,
    context: EnrollmentContext,
    subject: EntityId,
    store: S,
    random: R,
}

impl<'lock, S: EnrollmentStore, R: SecureRandom> OwnerEnrollmentAdapter<'lock, S, R> {
    /// Open an enrollment of `subject_id` and pick its epoch.
    ///
    /// The owner is derived from the subject (ADR-091), and its exclusive
    /// session/inventory lock is taken before anything is read. The epoch is
    /// the smallest one strictly above the store's P1 ceiling, every epoch a
    /// `subject-keys.v1` artifact names for the owner, and every epoch of the
    /// owner's SNL1 rows (ADR-137 P3 step 2). `random` later draws the root,
    /// the salts and the wrap nonce.
    ///
    /// # Errors
    /// Returns `Owner(Registry)` for the nil subject, an unrecognized or
    /// unreadable artifact inventory, a missing or invalid SNL1 ledger, or no
    /// epoch above the ceiling; the store's own refusal as `Owner`; and the
    /// lock's `Unavailable(InterfaceUnavailable)` while any other holder of
    /// the owner's session lock remains.
    pub fn open(
        lock: &'lock SubjectEncryptorLock,
        subject_id: SubjectId,
        owner_window: Option<u64>,
        mut store: S,
        random: R,
    ) -> Result<Self, BridgeError> {
        let subject = EntityId::from_ulid(Ulid::from_bytes(*subject_id.as_bytes()));
        let owner_id = subject_owner_id(subject).or(Err(BridgeError::Owner(REGISTRY)))?;
        let owner = lock.try_lock_subject_owner_exclusive(&owner_id)?;
        let epoch = Inventory::read(lock)
            .and_then(|inventory| next_epoch(lock, &mut store, &owner_id, subject, &inventory))
            .map_err(BridgeError::Owner)?;
        Ok(Self {
            lock,
            _owner: owner,
            context: EnrollmentContext {
                owner_id,
                subject_id,
                epoch,
                owner_window,
            },
            subject,
            store,
            random,
        })
    }

    /// The context to pass to `OwnerBridge::enroll` with this adapter.
    #[must_use]
    pub const fn context(&self) -> &EnrollmentContext {
        &self.context
    }

    fn staged_binding(
        &self,
        wrap: &SubjectKeyWrapV1,
        confirmed: &ConfirmedBinding,
    ) -> Result<Vec<u8>, OwnerError> {
        let context = &self.context;
        let params = wrap.params();
        let mut buffer = [0_u8; MAX_SUBJECT_CREDENTIAL_BINDING_BYTES];
        confirmed
            .binding()
            .ok()
            .filter(|binding| {
                (
                    binding.owner_id(),
                    binding.subject_id(),
                    binding.epoch(),
                    binding.credential_id(),
                    params.subject_id,
                    params.epoch,
                ) == (
                    context.owner_id.as_str(),
                    context.subject_id,
                    context.epoch,
                    params.credential_id.as_slice(),
                    self.subject,
                    context.epoch,
                )
            })
            .and_then(|binding| encode_subject_credential_binding(&binding, &mut buffer).ok())
            .map(|length| buffer[..length].to_vec())
            .ok_or(REGISTRY)
    }

    fn stage(&self, kind: SubjectKeyArtifactKind, bytes: &[u8]) -> Result<(), OwnerError> {
        SubjectKeyArtifactName::new(kind, &self.context.owner_id, self.context.epoch)
            .ok_or(DURABLE_WRITE)
            .and_then(|name| {
                self.lock
                    .stage_subject_key_artifact(&name, bytes)
                    .or(Err(DURABLE_WRITE))
            })
    }

    /// P3 step 5: add the new row through one checked ledger replacement,
    /// then read the replaced ledger back.
    fn stage_ledger_row(&self, row: SubjectNonceLedgerRowV1) -> Result<(), OwnerError> {
        read_ledger(self.lock)
            .and_then(|ledger| {
                let mut rows: Vec<_> = ledger.rows().cloned().chain([row]).collect();
                rows.sort_by(|left, right| {
                    (&left.owner_id, left.epoch).cmp(&(&right.owner_id, right.epoch))
                });
                SubjectNonceLedgerV1::new(rows).ok()
            })
            .and_then(|ledger| {
                self.lock
                    .replace_nonce_ledger_bytes(ledger.as_bytes())
                    .ok()
                    .and_then(|()| self.lock.read_nonce_ledger_bytes().ok())
                    .filter(|read| read.as_slice() == ledger.as_bytes())
            })
            .map(drop)
            .ok_or(DURABLE_WRITE)
    }
}

impl<S: EnrollmentStore, R: SecureRandom> EnrollmentPort for OwnerEnrollmentAdapter<'_, S, R> {
    type Candidate = EnrollmentCandidate;

    /// Run one bounded inventory pass over `subject-keys.v1`.
    fn credential_unbound(&mut self, credential_id: &[u8]) -> Result<bool, OwnerError> {
        Inventory::read(self.lock).map(|inventory| inventory.credential_unbound(credential_id))
    }

    /// Draw a fresh root, salts and nonce, and seal the wrap in memory.
    ///
    /// The bridge must seal over this adapter's own context; any other is a
    /// `Registry` refusal. A randomness failure is a `Wrap` failure.
    fn seal_candidate(
        &mut self,
        prf: PrfOutput<'_>,
        inputs: SealInputs<'_>,
    ) -> Result<(EnrollmentCandidate, RootFingerprint), OwnerError> {
        if inputs.context() != &self.context {
            return Err(REGISTRY);
        }
        seal(
            &mut self.random,
            Sealing {
                subject: self.subject,
                epoch: self.context.epoch,
                credential_id: inputs.credential_id(),
                prf_input: inputs.prf_input(),
            },
            prf.as_bytes(),
        )
    }

    fn confirm_candidate(
        &mut self,
        candidate: &EnrollmentCandidate,
        prf: PrfOutput<'_>,
    ) -> Result<RootFingerprint, OwnerError> {
        confirm(candidate, prf.as_bytes())
    }

    /// Re-check, then stage and register in ADR-137 P3 order.
    ///
    /// The binding must name this adapter's owner, subject and epoch and the
    /// wrap's credential, and the wrap this subject and epoch. Then one
    /// inventory pass repeats the unbound check and P3 step 2 must yield the
    /// opened epoch again. Steps 3 to 6 follow: the staging record, the wrap,
    /// the binding, the SNL1 row with both counters at 1, and registration.
    fn commit(
        &mut self,
        candidate: EnrollmentCandidate,
        binding: ConfirmedBinding,
    ) -> Result<(), OwnerError> {
        let binding = self.staged_binding(&candidate.wrap, &binding)?;
        let inventory = Inventory::read(self.lock)?;
        let epoch = next_epoch(
            self.lock,
            &mut self.store,
            &self.context.owner_id,
            self.subject,
            &inventory,
        )?;
        if epoch != self.context.epoch
            || !inventory.credential_unbound(&candidate.wrap.params().credential_id)
        {
            return Err(REGISTRY);
        }
        let store_file_id = self
            .store
            .commit_staging_record(&self.context.owner_id, epoch)?;
        self.stage(SubjectKeyArtifactKind::Wrap, &candidate.wrap.to_bytes())?;
        self.stage(SubjectKeyArtifactKind::Binding, &binding)?;
        let root_material_digest = *candidate.root.material_digest().as_bytes();
        self.stage_ledger_row(SubjectNonceLedgerRowV1 {
            owner_id: self.context.owner_id.clone(),
            epoch,
            root_material_digest,
            store_file_id,
            data_next: 1,
            bootstrap_next: 1,
        })?;
        self.store.register(&SubjectKeyRegistration {
            owner_id: self.context.owner_id.clone(),
            subject_id: self.subject,
            epoch,
            root_material_digest,
        })
    }

    /// Dropping the candidate wipes its root; nothing durable exists yet.
    fn abandon(&mut self, _candidate: EnrollmentCandidate) {}
}

/// The public inputs of one seal besides the randomness.
#[derive(Clone, Copy)]
struct Sealing<'a> {
    subject: EntityId,
    epoch: u64,
    credential_id: &'a [u8],
    prf_input: PrfInput,
}

fn seal(
    random: &mut impl SecureRandom,
    sealing: Sealing<'_>,
    prf: &[u8; 32],
) -> Result<(EnrollmentCandidate, RootFingerprint), OwnerError> {
    let mut drawn = Zeroizing::new([0_u8; RANDOM_BYTES]);
    random.fill(drawn.as_mut_slice()).or(Err(WRAP))?;
    let root = SubjectRootKeyV1::from_bytes(std::array::from_fn(|index| drawn[index]));
    let params = SubjectKeyWrapParamsV1 {
        subject_id: sealing.subject,
        epoch: sealing.epoch,
        rp_id: RP_ID.to_owned(),
        credential_id: sealing.credential_id.to_vec(),
        prf_input: *sealing.prf_input.as_bytes(),
        wrap_salt: std::array::from_fn(|index| drawn[32 + index]),
        subkey_salt: std::array::from_fn(|index| drawn[64 + index]),
        wrap_nonce: std::array::from_fn(|index| drawn[96 + index]),
    };
    let prf = SubjectPrfOutputV1::from_bytes(*prf);
    SubjectKeyWrapV1::seal(params, &root, &prf)
        .map(|wrap| {
            let fingerprint = fingerprint(&root);
            (EnrollmentCandidate { root, wrap }, fingerprint)
        })
        .or(Err(WRAP))
}

/// ADR-110 §8 E4: authenticate and open the wrap under the confirmation PRF,
/// and fingerprint the root that the open produced.
fn confirm(candidate: &EnrollmentCandidate, prf: &[u8; 32]) -> Result<RootFingerprint, OwnerError> {
    candidate
        .wrap
        .open(&SubjectPrfOutputV1::from_bytes(*prf))
        .map(|root| fingerprint(&root))
        .or(Err(WRAP))
}

/// The ADR-091 `key_material_digest` of a root.
fn fingerprint(root: &SubjectRootKeyV1) -> RootFingerprint {
    RootFingerprint::from_bytes(*root.material_digest().as_bytes())
}

/// ADR-137 P3 step 2: the smallest epoch strictly above every epoch the
/// store, the artifact inventory and the SNL1 ledger name for the owner.
fn next_epoch(
    lock: &SubjectEncryptorLock,
    store: &mut impl EnrollmentStore,
    owner_id: &str,
    subject: EntityId,
    inventory: &Inventory,
) -> Result<u64, OwnerError> {
    let registry = store.registry_epoch_ceiling(owner_id, subject)?;
    let ledger = read_ledger(lock).ok_or(REGISTRY)?;
    let ledger = ledger
        .rows()
        .filter(|row| row.owner_id == owner_id)
        .map(|row| row.epoch)
        .max()
        .unwrap_or_default();
    registry
        .max(inventory.epoch_ceiling(owner_id))
        .max(ledger)
        .checked_add(1)
        .ok_or(REGISTRY)
}

/// Read and strictly decode the SNL1 ledger, or `None`.
fn read_ledger(lock: &SubjectEncryptorLock) -> Option<SubjectNonceLedgerV1> {
    lock.read_nonce_ledger_bytes()
        .ok()
        .and_then(|bytes| SubjectNonceLedgerV1::from_bytes(&bytes).ok())
}

#[cfg(test)]
mod tests;
