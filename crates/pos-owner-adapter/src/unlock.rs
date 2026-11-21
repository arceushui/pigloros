#![cfg(any(test, feature = "test-support"))]
//! The real ADR-091 [`UnlockPort`]: ADR-110 §8 unlock and the §9 binding update.
//!
//! [`OwnerUnlockAdapter`] serves unlocks of one subject epoch. It is opened
//! under the held E16 encryptor lock, takes the subject owner's **shared**
//! session/inventory lock and keeps it until it is dropped (ADR-091:
//! encryption, decryption and unlock hold a shared owner lock; ADR-097 §4
//! step 2). Enrollment, rotation and destruction take the exclusive lock, so
//! none of them can run while an unlock adapter lives.
//!
//! Opening is the ADR-097 §5 cross-check, and it runs before any ceremony.
//! One bounded D2 inventory pass must find exactly one wrap and exactly one
//! binding whose contents name the owner and epoch, each under its canonical
//! P4 name. A missing, duplicate (under any name, `.tmp` included), misnamed,
//! malformed or mismatched artifact makes the key unavailable. The wrap's RP
//! ID must be `localhost` (ADR-091 rejects any other RP before PRF
//! evaluation), the binding must name the subject and the wrap's credential,
//! and the injected [`UnlockStore`] must hold the exact live registry
//! identity. [`OwnerUnlockAdapter::request`] then hands the bridge the binding
//! and the wrap's PRF input.
//!
//! `persist_binding_update` replaces the binding atomically (ADR-110 §9).
//! Updates from concurrent unlocks are serialized by one process-wide binding
//! mutex; the E16 lifetime lock makes this the only owner process of the OS
//! user. Under that mutex the update re-reads the artifacts and writes only
//! when the wrap and binding are still the ones this adapter opened, so an
//! update never rests on a counter that another unlock has already advanced.
//!
//! Errors use the bridge's three owner kinds: `Wrap` for the authenticated
//! open; `Registry` for a refused identity, inventory, cross-check, registry
//! identity, root fingerprint or binding update; `DurableWrite` for a failed
//! binding replacement.
//!
//! Known limitation: the pos-crypto PRF type takes the PRF output as a
//! by-value `[u8; 32]` array, so it passes through a stack temporary that is
//! not wiped; the root is held only in the wiping pos-crypto type.

use std::sync::{Mutex, PoisonError};

use pos_core::EntityId;
use pos_crypto::subject_key::{
    subject_owner_id, SubjectKeyWrapV1, SubjectPrfOutputV1, SubjectRootKeyV1,
};
use pos_owner_bridge::encryptor_lock::linux::{
    SubjectEncryptorLock, SubjectKeyArtifactKind, SubjectKeyArtifactName, SubjectOwnerSharedGuard,
};
use pos_owner_bridge::{
    BindingUpdate, BridgeError, OwnerError, OwnerErrorKind, PrfOutput, UnlockPort,
};
use pos_owner_bridge_codec::{
    decode_subject_credential_binding, encode_subject_credential_binding,
    SubjectCredentialBindingInputV1, SubjectCredentialBindingV1, SubjectId,
    MAX_SUBJECT_CREDENTIAL_BINDING_BYTES,
};
use ulid::Ulid;

use crate::inventory::{Artifact, Inventory};
use crate::RP_ID;

mod store;

pub use store::UnlockStore;

const WRAP: OwnerError = OwnerError::new(OwnerErrorKind::Wrap);
const REGISTRY: OwnerError = OwnerError::new(OwnerErrorKind::Registry);
const DURABLE_WRITE: OwnerError = OwnerError::new(OwnerErrorKind::DurableWrite);

/// ADR-110 §9: the binding mutex that serializes binding updates from
/// concurrent unlocks in this, the only owner process of the OS user.
static BINDING_UPDATES: Mutex<()> = Mutex::new(());

/// The binding and PRF input that `OwnerBridge::unlock` takes.
///
/// They are ADR-110 §8 unlock step 1's inputs, copied out of the adapter so
/// that the adapter itself can be borrowed mutably as the port.
pub struct UnlockRequest {
    binding: Vec<u8>,
    prf_input: [u8; 32],
}

impl UnlockRequest {
    /// The cross-checked binding: its stored allow-list, key, flags and
    /// counter.
    ///
    /// # Errors
    /// Returns `Owner(Registry)` if the bytes do not decode. That is
    /// unreachable: opening decoded these same bytes.
    pub fn binding(&self) -> Result<SubjectCredentialBindingV1<'_>, BridgeError> {
        decode_subject_credential_binding(&self.binding).or(Err(BridgeError::Owner(REGISTRY)))
    }

    /// The wrap's PRF evaluation input.
    #[must_use]
    pub const fn prf_input(&self) -> &[u8; 32] {
        &self.prf_input
    }
}

/// A root that `open_pending` unwrapped and that is not yet released.
///
/// Dropping it wipes the root, which is what happens when the binding update
/// fails.
pub struct PendingRoot {
    root: SubjectRootKeyV1,
}

/// The unlocked session: a keyring entry with the opened root and its wrap.
///
/// The wrap's public inputs (the identity and the subkey salt) are what the
/// ADR-091 subkey derivation reads besides the root. Dropping the entry
/// wipes the root.
pub struct SubjectKeyringEntry {
    root: SubjectRootKeyV1,
    wrap: SubjectKeyWrapV1,
}

impl SubjectKeyringEntry {
    /// The wrap that the root was opened from.
    #[must_use]
    pub const fn wrap(&self) -> &SubjectKeyWrapV1 {
        &self.wrap
    }

    /// The ADR-091 `key_material_digest` of the opened root.
    #[must_use]
    pub fn root_material_digest(&self) -> [u8; 32] {
        *self.root.material_digest().as_bytes()
    }
}

/// The wrap and the binding bytes that one inventory pass cross-checked.
struct Loaded {
    wrap: SubjectKeyWrapV1,
    binding: Vec<u8>,
}

/// The ADR-091 owner adapter for unlocks of one subject epoch.
///
/// It holds the subject owner's shared session/inventory lock from
/// [`Self::open`] until it drops.
pub struct OwnerUnlockAdapter<'lock> {
    lock: &'lock SubjectEncryptorLock,
    _owner: SubjectOwnerSharedGuard<'lock>,
    owner_id: String,
    subject_id: SubjectId,
    epoch: u64,
    wrap: SubjectKeyWrapV1,
    binding: Vec<u8>,
    root_material_digest: [u8; 32],
    opened: bool,
}

impl<'lock> OwnerUnlockAdapter<'lock> {
    /// Open an unlock of `subject_id` at `epoch` and cross-check its
    /// artifacts before any ceremony.
    ///
    /// The owner is derived from the subject (ADR-091), and its shared
    /// session/inventory lock is taken before anything is read. Then one
    /// bounded inventory pass loads the wrap and the binding, which must
    /// agree as the module documentation describes, and `store` must return
    /// the live registry identity's root fingerprint.
    ///
    /// # Errors
    /// Returns `Owner(Registry)` for the nil subject, epoch zero, an
    /// unrecognized or unreadable artifact inventory, a missing, duplicate,
    /// misnamed or mismatched wrap or binding, or a wrap whose RP ID is not
    /// `localhost`. Also returns the store's own refusal as `Owner`, and the
    /// lock's `Unavailable(InterfaceUnavailable)` while the owner's exclusive
    /// lock is held.
    pub fn open(
        lock: &'lock SubjectEncryptorLock,
        subject_id: SubjectId,
        epoch: u64,
        store: &mut impl UnlockStore,
    ) -> Result<Self, BridgeError> {
        let subject = EntityId::from_ulid(Ulid::from_bytes(*subject_id.as_bytes()));
        let owner_id = subject_owner_id(subject).or(Err(BridgeError::Owner(REGISTRY)))?;
        let owner = lock.try_lock_subject_owner_shared(&owner_id)?;
        let (loaded, root_material_digest) = load(lock, &owner_id, subject_id, epoch)
            .and_then(|loaded| {
                store
                    .registered_root_material_digest(&owner_id, subject, epoch)
                    .map(|digest| (loaded, digest))
            })
            .map_err(BridgeError::Owner)?;
        Ok(Self {
            lock,
            _owner: owner,
            owner_id,
            subject_id,
            epoch,
            wrap: loaded.wrap,
            binding: loaded.binding,
            root_material_digest,
            opened: false,
        })
    }

    /// The binding and PRF input to pass to `OwnerBridge::unlock` with this
    /// adapter.
    #[must_use]
    pub fn request(&self) -> UnlockRequest {
        UnlockRequest {
            binding: self.binding.clone(),
            prf_input: self.wrap.params().prf_input,
        }
    }

    /// The binding with the accepted counter and backup state.
    ///
    /// The bridge verified the assertion against the binding it was handed;
    /// this re-applies the ADR-097 §5 rules against the binding this adapter
    /// opened: a nonzero counter must advance strictly, and the codec refuses
    /// a backup state without backup eligibility.
    fn updated_binding(&self, update: BindingUpdate) -> Result<Vec<u8>, OwnerError> {
        let mut buffer = [0_u8; MAX_SUBJECT_CREDENTIAL_BINDING_BYTES];
        decode_subject_credential_binding(&self.binding)
            // Unreachable error: open() decoded these same bytes.
            .ok()
            .filter(|stored| counter_advanced(stored.sign_count(), update.sign_count))
            .and_then(|stored| {
                SubjectCredentialBindingV1::new(SubjectCredentialBindingInputV1 {
                    owner_id: stored.owner_id(),
                    subject_id: stored.subject_id(),
                    epoch: stored.epoch(),
                    credential_id: stored.credential_id(),
                    user_handle: stored.user_handle(),
                    public_key: stored.public_key(),
                    backup_eligible: stored.backup_eligible(),
                    backup_state: update.backup_state,
                    sign_count: update.sign_count,
                    transports: stored.transports(),
                })
                .ok()
            })
            // Unreachable error: a validated binding always fits 4,096 bytes.
            .and_then(|binding| encode_subject_credential_binding(&binding, &mut buffer).ok())
            .map(|length| buffer[..length].to_vec())
            .ok_or(REGISTRY)
    }
}

impl UnlockPort for OwnerUnlockAdapter<'_> {
    type Pending = PendingRoot;
    type Session = SubjectKeyringEntry;

    /// Authenticate and open the wrap under `prf`.
    ///
    /// The opened root's fingerprint must equal the registry identity's. A
    /// failed open is `Wrap`; an opened root with another fingerprint is
    /// `Registry`. The PRF output reaches pos-crypto as a by-value
    /// `[u8; 32]` temporary.
    fn open_pending(&mut self, prf: PrfOutput<'_>) -> Result<PendingRoot, OwnerError> {
        self.wrap
            .open(&SubjectPrfOutputV1::from_bytes(*prf.as_bytes()))
            .or(Err(WRAP))
            .and_then(|root| {
                accept(*root.material_digest().as_bytes() == self.root_material_digest)
                    .map(|()| root)
            })
            .map(|root| {
                self.opened = true;
                PendingRoot { root }
            })
    }

    /// Atomically replace the binding with the accepted counter and backup
    /// state.
    ///
    /// It refuses with `Registry`, writing nothing, unless a root was opened
    /// first, the update passes the ADR-097 §5 counter and backup rules
    /// against the opened binding, and, under the binding mutex, a fresh
    /// inventory pass still finds exactly the wrap and binding this adapter
    /// opened. A failed replacement is `DurableWrite`; an error after the
    /// rename leaves an unconfirmed outcome.
    fn persist_binding_update(&mut self, update: &BindingUpdate) -> Result<(), OwnerError> {
        accept(self.opened)
            .and_then(|()| self.updated_binding(*update))
            .and_then(|updated| {
                SubjectKeyArtifactName::new(
                    SubjectKeyArtifactKind::Binding,
                    &self.owner_id,
                    self.epoch,
                )
                // Unreachable: open() found the binding under this very name.
                .ok_or(DURABLE_WRITE)
                .map(|name| (name, updated))
            })
            .and_then(|(name, updated)| {
                serialized(|| {
                    load(self.lock, &self.owner_id, self.subject_id, self.epoch)
                        .and_then(|current| {
                            accept(current.wrap == self.wrap && current.binding == self.binding)
                        })
                        .and_then(|()| {
                            self.lock
                                .replace_subject_key_artifact(&name, &updated)
                                .or(Err(DURABLE_WRITE))
                        })
                })
                .map(|()| updated)
            })
            .map(|updated| self.binding = updated)
    }

    /// Hand the opened root and its wrap to a keyring entry.
    fn release(&mut self, pending: PendingRoot) -> SubjectKeyringEntry {
        SubjectKeyringEntry {
            root: pending.root,
            wrap: self.wrap.clone(),
        }
    }
}

/// One inventory pass: the sole wrap and binding of `(owner_id, epoch)`,
/// cross-checked.
fn load(
    lock: &SubjectEncryptorLock,
    owner_id: &str,
    subject_id: SubjectId,
    epoch: u64,
) -> Result<Loaded, OwnerError> {
    Inventory::read(lock).and_then(|inventory| {
        let wrap = sole(&inventory, owner_id, epoch, SubjectKeyArtifactKind::Wrap)
            // Unreachable `None`: the inventory parsed these bytes as a wrap.
            .and_then(|artifact| SubjectKeyWrapV1::from_bytes(&artifact.bytes).ok());
        let binding = sole(&inventory, owner_id, epoch, SubjectKeyArtifactKind::Binding);
        wrap.zip(binding)
            .filter(|(wrap, binding)| cross_checked(wrap, &binding.bytes, subject_id))
            .map(|(wrap, binding)| Loaded {
                wrap,
                binding: binding.bytes.clone(),
            })
            .ok_or(REGISTRY)
    })
}

/// The one file whose contents parse as `kind` for `(owner_id, epoch)`,
/// provided it has the canonical P4 name of that kind, owner and epoch.
///
/// `None` when there is no such file, more than one under any names
/// (a `.tmp` copy included), the one file has another name, or the epoch is
/// zero.
fn sole<'a>(
    inventory: &'a Inventory,
    owner_id: &'a str,
    epoch: u64,
    kind: SubjectKeyArtifactKind,
) -> Option<&'a Artifact> {
    SubjectKeyArtifactName::new(kind, owner_id, epoch).and_then(|name| {
        let mut matches = inventory
            .artifacts(owner_id, epoch)
            .filter(|artifact| artifact.kind == kind);
        matches.next().filter(|artifact| {
            artifact.name == name.canonical().as_bytes() && matches.next().is_none()
        })
    })
}

/// ADR-097 §5 and ADR-091: the wrap's RP ID is `localhost`, and the binding
/// names the subject and the wrap's credential.
///
/// The inventory match already fixed the owner and epoch of both, and the
/// wrap's owner is derived from its subject, so the wrap names the subject
/// too. Both codecs fix the role; the binding codec fixes its RP ID and
/// origin.
fn cross_checked(wrap: &SubjectKeyWrapV1, binding: &[u8], subject_id: SubjectId) -> bool {
    decode_subject_credential_binding(binding).is_ok_and(|binding| {
        wrap.params().rp_id == RP_ID
            && binding.subject_id() == subject_id
            && binding.credential_id() == wrap.params().credential_id.as_slice()
    })
}

/// The ADR-097 §5 counter rule, as the bridge's verifier applies it: a zero
/// counter may stay zero, and any other counter must strictly advance.
const fn counter_advanced(stored: u32, current: u32) -> bool {
    (stored == 0 && current == 0) || current > stored
}

/// Run `update` under the binding mutex.
///
/// A poisoned mutex is still taken: `update` re-reads the durable artifacts
/// before it writes, so an earlier panic leaves nothing to trust in memory.
fn serialized<T>(update: impl FnOnce() -> T) -> T {
    let guard = BINDING_UPDATES
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let outcome = update();
    drop(guard);
    outcome
}

fn accept(accepted: bool) -> Result<(), OwnerError> {
    accepted.then_some(()).ok_or(REGISTRY)
}
