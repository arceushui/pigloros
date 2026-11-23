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
//! ledger or epoch; `DurableWrite` for a failed P3 step 4 or 5 write.
//!
//! A commit that fails after its P3a staging record and before step 6 has a
//! definite outcome: the identity is not registered. It then runs the
//! ADR-137 P5 deletion for this attempt at once, after wiping the root
//! (P3): the wrap and binding files, the SNL1 row and the record. A failed
//! registration (step 6) may have an unknown commit outcome, so it deletes
//! nothing and leaves the attempt to P5 recovery at the next owner start.
//!
//! Known limitation: the pos-crypto key types take the root and the PRF
//! output as by-value `[u8; 32]` arrays, so each passes through a stack
//! temporary that is not wiped; the values that this crate owns are held in
//! `Zeroizing` or in the wiping pos-crypto types.

use pos_core::EntityId;
use pos_crypto::subject_key::{
    subject_owner_id, SubjectKeyWrapParamsV1, SubjectKeyWrapV1, SubjectPrfOutputV1,
    SubjectRootKeyV1,
};
use pos_crypto::subject_nonce_ledger::{
    SubjectNonceLedgerRowV1, SubjectNonceLedgerV1, SubjectStoreFileIdV1,
};
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

mod discard;
mod store;

use crate::inventory::Inventory;
use crate::RP_ID;
use discard::{discard_attempt, Attempt};
pub use store::{EnrollmentStore, SubjectKeyRegistration, VolatileEnrollmentStore};

/// The root, the wrap salt and the subkey salt (32 bytes each) and the
/// 12-byte wrap nonce, drawn in one fill.
const RANDOM_BYTES: usize = 108;
const WRAP: OwnerError = OwnerError::new(OwnerErrorKind::Wrap);
const REGISTRY: OwnerError = OwnerError::new(OwnerErrorKind::Registry);
const DURABLE_WRITE: OwnerError = OwnerError::new(OwnerErrorKind::DurableWrite);
/// The store-file identity with the longest SNL1 encoding, so a step 2 dry
/// run that fits proves the real step 5 row fits.
const WIDEST_STORE_FILE_ID: SubjectStoreFileIdV1 = SubjectStoreFileIdV1::Linux {
    device: u64::MAX,
    inode: u64::MAX,
};

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
    owner: SubjectOwnerExclusiveGuard<'lock>,
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
    /// owner's SNL1 rows (ADR-137 P3 step 2). Step 2 also dry-runs step 5: the
    /// ledger must have room for this epoch's row. `random` later draws the
    /// root, the salts and the wrap nonce.
    ///
    /// # Errors
    /// Returns `Owner(Registry)` for the nil subject, an unrecognized or
    /// unreadable artifact inventory, a missing or invalid SNL1 ledger, a
    /// ledger without room for this epoch's row, or no epoch above the
    /// ceiling. The room probe is conservative: it uses the widest store-file
    /// identity, so it may refuse a ledger with up to 16 bytes of headroom
    /// that the real row would fit. Also returns the store's own refusal as
    /// `Owner`, and the lock's `Unavailable(InterfaceUnavailable)` while any
    /// other holder of the owner's session lock remains.
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
            owner,
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
            // Unreachable: the bridge validated this binding when it built it.
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
            // Unreachable error: a validated binding always fits 4,096 bytes.
            .and_then(|binding| encode_subject_credential_binding(&binding, &mut buffer).ok())
            .map(|length| buffer[..length].to_vec())
            .ok_or(REGISTRY)
    }

    /// The reserved wrap and binding names of this enrollment.
    fn artifact_names(&self) -> Result<[SubjectKeyArtifactName; 2], OwnerError> {
        let name =
            |kind| SubjectKeyArtifactName::new(kind, &self.context.owner_id, self.context.epoch);
        name(SubjectKeyArtifactKind::Wrap)
            .zip(name(SubjectKeyArtifactKind::Binding))
            .map(<[_; 2]>::from)
            // Unreachable: open() derived a non-nil owner and the epoch is at least 1.
            .ok_or(REGISTRY)
    }

    /// P3 steps 4 and 5: the wrap, the binding, then the SNL1 row.
    fn stage(
        &self,
        names: &[SubjectKeyArtifactName; 2],
        contents: [&[u8]; 2],
        row: SubjectNonceLedgerRowV1,
    ) -> Result<(), OwnerError> {
        names
            .iter()
            .zip(contents)
            .try_for_each(|(name, bytes)| self.lock.stage_subject_key_artifact(name, bytes))
            .or(Err(DURABLE_WRITE))
            .and_then(|()| self.stage_ledger_row(row))
    }

    /// P3 step 5: re-read the ledger under the held lock, add the new row
    /// through one checked ledger replacement, then read it back.
    ///
    /// The step 2 dry run already proved that the row fits, so the row-fit
    /// refusal is ruled out here unless the ledger changed outside this
    /// process's lifetime lock. A real write or read-back failure still
    /// returns `DurableWrite`.
    fn stage_ledger_row(&self, row: SubjectNonceLedgerRowV1) -> Result<(), OwnerError> {
        read_ledger(self.lock)
            .and_then(|ledger| with_row(&ledger, row))
            .ok_or(DURABLE_WRITE)
            .and_then(|ledger| write_ledger(self.lock, &ledger))
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

    /// Re-check, then stage and register in ADR-137 P3 order, or delete a
    /// definitely failed attempt by ADR-137 P5.
    ///
    /// The binding must name this adapter's owner, subject and epoch and the
    /// wrap's credential, and the wrap this subject and epoch. Then one
    /// inventory pass repeats the unbound check and P3 step 2 must yield the
    /// opened epoch again, including step 2's dry run of step 5: a ledger without room
    /// for the row refuses with `Registry` before anything is staged. The
    /// probe is conservative: it uses the widest store-file identity, so it
    /// may refuse a ledger with up to 16 bytes of headroom that the real row
    /// would fit. The root is wiped once its digest is taken. Steps 3 to 6
    /// follow: the staging record, the wrap, the binding, the SNL1 row with
    /// both counters at 1, and registration. When step 4 or 5 fails, the P5
    /// deletion of this attempt runs before the error returns. It keeps
    /// everything while P1 may hold the identity or the ledger is unreadable,
    /// and keeps the files and the row when the row names another store.
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
        let names = self.artifact_names()?;
        let EnrollmentCandidate { root, wrap } = candidate;
        let root_material_digest = *root.material_digest().as_bytes();
        // Only the digest is needed from here on, so the root is wiped now.
        drop(root);
        let store_file_id = self
            .store
            .commit_staging_record(&self.context.owner_id, epoch)?;
        let row = SubjectNonceLedgerRowV1 {
            owner_id: self.context.owner_id.clone(),
            epoch,
            root_material_digest,
            store_file_id,
            data_next: 1,
            bootstrap_next: 1,
        };
        if let Err(error) = self.stage(&names, [&wrap.to_bytes(), &binding], row) {
            let attempt = Attempt {
                subject: self.subject,
                epoch,
                store_file_id,
                names: &names,
            };
            // A failed deletion leaves the staging record, so P5 recovery at
            // the next owner start finishes it; the staging error is returned.
            let _retained = discard_attempt(self.lock, &self.owner, &mut self.store, &attempt);
            return Err(error);
        }
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

/// Draw the root, salts and nonce and seal the wrap in memory.
///
/// The root and the PRF output reach pos-crypto as by-value `[u8; 32]`
/// temporaries, which are not wiped (the module's known limitation).
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
        // Unreachable: the subject is non-nil, the epoch at least 1, the RP ID
        // fixed and canonical, and the bridge's verifier bounds the credential ID
        // to 1-1,024 bytes.
        .or(Err(WRAP))
}

/// ADR-110 §8 E4: authenticate and open the wrap under the confirmation PRF,
/// and fingerprint the root that the open produced.
///
/// The PRF output reaches pos-crypto as a by-value `[u8; 32]` temporary.
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
///
/// It also dry-runs P3 step 5: the ledger with this epoch's row added, using
/// the widest store-file identity, must still be a valid SNL1. So a full
/// ledger refuses with `Registry` before anything is staged.
fn next_epoch(
    lock: &SubjectEncryptorLock,
    store: &mut impl EnrollmentStore,
    owner_id: &str,
    subject: EntityId,
    inventory: &Inventory,
) -> Result<u64, OwnerError> {
    let registry = store.registry_epoch_ceiling(owner_id, subject)?;
    let ledger = read_ledger(lock).ok_or(REGISTRY)?;
    let ledger_ceiling = ledger
        .rows()
        .filter(|row| row.owner_id == owner_id)
        .map(|row| row.epoch)
        .max()
        .unwrap_or_default();
    registry
        .max(inventory.epoch_ceiling(owner_id))
        .max(ledger_ceiling)
        .checked_add(1)
        .filter(|epoch| {
            let probe = SubjectNonceLedgerRowV1 {
                owner_id: owner_id.to_owned(),
                epoch: *epoch,
                root_material_digest: [0; 32],
                store_file_id: WIDEST_STORE_FILE_ID,
                data_next: 1,
                bootstrap_next: 1,
            };
            with_row(&ledger, probe).is_some()
        })
        .ok_or(REGISTRY)
}

/// `ledger` with `row` inserted in SNL1 identity order, or `None` when the
/// result is not a valid SNL1 (over 1 MiB, or a repeated identity).
///
/// Owner IDs have a fixed length and CBOR unsigned integers sort by value,
/// so `(owner_id, epoch)` order is SNL1's identity-byte order.
fn with_row(
    ledger: &SubjectNonceLedgerV1,
    row: SubjectNonceLedgerRowV1,
) -> Option<SubjectNonceLedgerV1> {
    let mut rows: Vec<_> = ledger.rows().cloned().chain([row]).collect();
    rows.sort_by(|left, right| (&left.owner_id, left.epoch).cmp(&(&right.owner_id, right.epoch)));
    SubjectNonceLedgerV1::new(rows).ok()
}

/// Durably replace the ledger with `ledger` and read it back unchanged, as
/// ADR-137 N1 replaces it.
///
/// # Errors
/// Returns `DurableWrite` when the replacement fails or the read-back
/// differs. The outcome may then be unconfirmed.
fn write_ledger(
    lock: &SubjectEncryptorLock,
    ledger: &SubjectNonceLedgerV1,
) -> Result<(), OwnerError> {
    lock.replace_nonce_ledger_bytes(ledger.as_bytes())
        .ok()
        .and_then(|()| lock.read_nonce_ledger_bytes().ok())
        .filter(|read| read.as_slice() == ledger.as_bytes())
        .map(drop)
        .ok_or(DURABLE_WRITE)
}

/// Read and strictly decode the SNL1 ledger, or `None`.
fn read_ledger(lock: &SubjectEncryptorLock) -> Option<SubjectNonceLedgerV1> {
    lock.read_nonce_ledger_bytes()
        .ok()
        .and_then(|bytes| SubjectNonceLedgerV1::from_bytes(&bytes).ok())
}

#[cfg(test)]
mod tests;
