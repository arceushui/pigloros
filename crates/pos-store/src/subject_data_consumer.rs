#![cfg(any(test, feature = "test-support"))]
//! Test-support `SubjectDataEncryption` consumer over ordinary `EventStore` adapters.
//!
//! This module joins the accepted pieces of ADR-091, ADR-097 and ADR-121 into
//! one executable path: an unlocked subject root, a reserved nonce counter, the
//! combined two-identity prepared append, the owner field read with its five
//! callback outcomes, and confirmed key destruction.
//!
//! It is deliberately not the protected owner adapter, and it claims none of:
//!
//! - an implementation, constructor or bound context of
//!   [`SubjectFieldOwnerReadPortV1`](pos_crypto::subject_field_read::SubjectFieldOwnerReadPortV1);
//!   the read here is a free function with that port's callback and error
//!   shapes, without shared admission or quarantine;
//! - the ADR-123 native file binding, the Gateway lease, the durable
//!   intent/receipt protocol, or activation;
//! - one `BEGIN IMMEDIATE` covering the erasure check, Event lookup, decrypt
//!   and callback; the erasure boundary here is the store's existing
//!   containment gate on the Timeline read, and no ADR-097 B6 fence row exists;
//! - durable nonce reservation under the ADR-110 E16 lock; reservations go
//!   through [`SubjectNonceReservationPortV1`], and the only implementation
//!   here is volatile;
//! - the ADR-097 B4 plaintext grammar; only the inherited 8,192-byte raw cap
//!   is enforced, on both append and read.
//!
//! Private bytes stay in `pos-crypto` values held by [`SubjectKeyringV1`];
//! nothing here hands a root, subkey or plaintext to `pos-core` or to a store.

use std::collections::BTreeMap;

use pos_core::{
    deletion_receipt, CanonicalBytes, CoreError, EntityId, Event, EventDraft, EventStore,
    FieldStateV1, Hash, KeyDestructionOutcomeV1, KeyDestructionRequestV1, KeyIdentityV1,
    KeyRecordV1, KeyRegistryErrorV1, KeyRegistryHistoricalDecryptionPortV1, KeyRegistryStateV1,
    KeyRoleV1, Kind, OwnerIdV1, PreparedSubjectAppendAuthorizationV1, PublicKey, SeqRange,
    TimelineEventEnvelopeInputV1, TimelineEventEnvelopeV1, TimelineEventVerificationV1, TimelineId,
};
use pos_crypto::key_roles::{
    sign_timeline_event_for_registered_role, verify_committed_timeline_event_v1, SigningKeyMaterial,
};
use pos_crypto::subject_ciphertext::SubjectCiphertextV1;
use pos_crypto::subject_data::{
    subject_data_public_header, SubjectDataV1, SUBJECT_DATA_EVENT_TYPE,
};
use pos_crypto::subject_field_read::{
    SubjectFieldOwnerReadErrorV1, SubjectFieldReadCallbackErrorV1, SubjectFieldReadError,
    SubjectFieldReadResultV1, SubjectFieldSelectorV1,
};
use pos_crypto::subject_key::{
    subject_owner_id, SubjectKeyUseV1, SubjectKeyWrapV1, SubjectPrfOutputV1, SubjectRootKeyV1,
};
use pos_crypto::subject_nonce_ledger::SubjectNonceLedgerV1;
use thiserror::Error;
use zeroize::Zeroizing;

/// The accepted field tag of [`SubjectFieldSelectorV1::PersonaPreferenceWeights`].
pub const PERSONA_PREFERENCE_WEIGHTS_FIELD_TAG: &str = "persona.preference_weights";

/// The inherited raw logical plaintext cap of one subject field value.
pub const MAX_SUBJECT_FIELD_PLAINTEXT_BYTES: usize = 8_192;

/// A closed, payload-free refusal of this consumer's key and write operations.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SubjectDataConsumerErrorV1 {
    /// The nil subject has no ADR-091 subject key owner.
    #[error("subject has no subject key owner")]
    InvalidSubject,
    /// The wrap names a subject other than the keyring's.
    #[error("subject key wrap belongs to another subject")]
    WrapSubjectMismatch,
    /// The wrap's epoch already holds an unlocked root; it is never replaced.
    #[error("subject key epoch is already unlocked")]
    AlreadyUnlocked,
    /// The wrap did not authenticate under the supplied PRF output.
    #[error("subject key wrap did not open")]
    UnlockFailed,
    /// The requested epoch is not unlocked in the keyring.
    #[error("subject key epoch is locked")]
    KeyLocked,
    /// The store could not load its key registry; nothing was reserved.
    #[error("key registry is unavailable")]
    RegistryUnavailable,
    /// The store has no registry, or its registry does not hold this exact
    /// owner, `SubjectDataEncryption` role, epoch and root fingerprint as the
    /// active epoch.
    #[error("subject key is not the active encryption epoch")]
    KeyNotActive,
    /// The plaintext exceeds [`MAX_SUBJECT_FIELD_PLAINTEXT_BYTES`].
    #[error("subject field plaintext exceeds its raw cap")]
    PlaintextBoundExceeded,
    /// No exact nonce row exists, its data counter is exhausted, or the port
    /// returned a counter that is not above the last one this keyring used
    /// for the epoch.
    #[error("subject nonce reservation was refused")]
    NonceReservationRefused,
    /// The combined prepared append failed; no Event was committed and the
    /// reserved counter stays spent. Every cause collapses here without
    /// distinction: a registry that changed since it was loaded, a refused
    /// encryption or signing authorization, a missing Timeline, erasure
    /// containment, a refused encryption or signature, and any insertion or
    /// commit failure of the store.
    #[error("subject data append was refused")]
    AppendRefused,
    /// The request names another owner or the registry refused it.
    #[error("subject key destruction was refused")]
    DestructionRefused,
}

/// The unlocked subject roots of one subject, with the pinned owner-process
/// Timeline signing trust anchor that `subject.data.v1` Events must carry.
///
/// A root is held only between [`Self::unlock`] and [`Self::lock`] or
/// [`destroy_subject_key`]. Roots are wiped on drop and never printed.
#[derive(Debug)]
pub struct SubjectKeyringV1 {
    subject: EntityId,
    owner: OwnerIdV1,
    timeline_signing_anchor: (KeyIdentityV1, PublicKey),
    epochs: BTreeMap<u64, UnlockedEpoch>,
}

/// One unlocked root and the highest data counter this keyring has used with it.
#[derive(Debug)]
struct UnlockedEpoch {
    wrap: SubjectKeyWrapV1,
    root: SubjectRootKeyV1,
    last_data_counter: u64,
}

impl SubjectKeyringV1 {
    /// Create a keyring with every epoch locked.
    ///
    /// # Errors
    /// Returns [`SubjectDataConsumerErrorV1::InvalidSubject`] for the nil subject.
    pub fn new(
        subject: EntityId,
        timeline_signing_identity: KeyIdentityV1,
        timeline_signing_public_key: PublicKey,
    ) -> Result<Self, SubjectDataConsumerErrorV1> {
        subject_owner_id(subject)
            .ok()
            .and_then(|owner| OwnerIdV1::new(owner).ok())
            .map(|owner| Self {
                subject,
                owner,
                timeline_signing_anchor: (timeline_signing_identity, timeline_signing_public_key),
                epochs: BTreeMap::new(),
            })
            .ok_or(SubjectDataConsumerErrorV1::InvalidSubject)
    }

    /// The `SubjectDataEncryption` identity of this subject at `epoch`.
    #[must_use]
    pub const fn key_identity(&self, epoch: u64) -> KeyIdentityV1 {
        KeyIdentityV1::from_parts(self.owner, KeyRoleV1::SubjectDataEncryption, epoch)
    }

    /// Open `wrap` under `prf` and hold its root for the wrap's epoch.
    ///
    /// # Errors
    /// Returns [`SubjectDataConsumerErrorV1::WrapSubjectMismatch`] for another
    /// subject's wrap, [`SubjectDataConsumerErrorV1::AlreadyUnlocked`] when
    /// the epoch already holds a root, and
    /// [`SubjectDataConsumerErrorV1::UnlockFailed`] when the wrap does not
    /// authenticate; none of them changes the keyring.
    pub fn unlock(
        &mut self,
        wrap: SubjectKeyWrapV1,
        prf: &SubjectPrfOutputV1,
    ) -> Result<KeyIdentityV1, SubjectDataConsumerErrorV1> {
        if wrap.params().subject_id != self.subject {
            return Err(SubjectDataConsumerErrorV1::WrapSubjectMismatch);
        }
        let epoch = wrap.params().epoch;
        if self.epochs.contains_key(&epoch) {
            return Err(SubjectDataConsumerErrorV1::AlreadyUnlocked);
        }
        wrap.open(prf)
            .map(|root| {
                let unlocked = UnlockedEpoch {
                    wrap,
                    root,
                    last_data_counter: 0,
                };
                self.epochs.insert(epoch, unlocked);
                self.key_identity(epoch)
            })
            .map_err(|_| SubjectDataConsumerErrorV1::UnlockFailed)
    }

    /// Drop the root held for `epoch`, if any, with its counter high-water.
    pub fn lock(&mut self, epoch: u64) {
        self.epochs.remove(&epoch);
    }
}

/// Reserves the next data-use nonce counter before AES-GCM may use it.
///
/// An implementation must make the reservation durable before returning and
/// must never return the same counter twice for one identity and root. The
/// consumer additionally refuses a counter that is not above the last one the
/// same keyring used for the epoch since its unlock; that volatile guard does
/// not replace the port's durable obligation.
pub trait SubjectNonceReservationPortV1 {
    /// Reserve the next data counter of `identity` under `root_material_digest`.
    ///
    /// # Errors
    /// Returns [`SubjectDataConsumerErrorV1::NonceReservationRefused`] when no
    /// exact row exists or the counter is exhausted.
    fn reserve_data_counter(
        &mut self,
        identity: KeyIdentityV1,
        root_material_digest: Hash,
    ) -> Result<u64, SubjectDataConsumerErrorV1>;
}

/// An in-memory SNL1 artifact advanced in place: structurally exact, never durable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolatileSubjectNonceLedgerV1 {
    ledger: SubjectNonceLedgerV1,
}

impl VolatileSubjectNonceLedgerV1 {
    /// Hold an already enrolled SNL1 artifact.
    #[must_use]
    pub const fn new(ledger: SubjectNonceLedgerV1) -> Self {
        Self { ledger }
    }

    /// The current SNL1 artifact, including every spent reservation.
    #[must_use]
    pub const fn ledger(&self) -> &SubjectNonceLedgerV1 {
        &self.ledger
    }
}

impl SubjectNonceReservationPortV1 for VolatileSubjectNonceLedgerV1 {
    fn reserve_data_counter(
        &mut self,
        identity: KeyIdentityV1,
        root_material_digest: Hash,
    ) -> Result<u64, SubjectDataConsumerErrorV1> {
        let reserved = self
            .ledger
            .rows()
            .find(|row| {
                row.owner_id == identity.owner_id.as_str()
                    && row.epoch == identity.epoch
                    && row.root_material_digest == *root_material_digest.as_bytes()
            })
            .and_then(|row| {
                self.ledger
                    .advance_counter(row, SubjectKeyUseV1::Data)
                    .ok()
                    .map(|next| (row.data_next, next))
            });
        reserved
            .map(|(counter, next)| {
                self.ledger = next;
                counter
            })
            .ok_or(SubjectDataConsumerErrorV1::NonceReservationRefused)
    }
}

/// One complete `persona.preference_weights` value to append for the keyring's subject.
pub struct SubjectDataAppendV1<'a> {
    /// The subject Timeline that receives the `subject.data.v1` Event.
    pub timeline_id: TimelineId,
    /// The unlocked, active `SubjectDataEncryption` epoch.
    pub epoch: u64,
    /// The owner-process `TimelineIntegritySigning` material of the keyring's anchor.
    pub signing: &'a SigningKeyMaterial,
    /// The complete plaintext weight set, at most
    /// [`MAX_SUBJECT_FIELD_PLAINTEXT_BYTES`]; its grammar is not validated.
    pub weights: &'a [u8],
}

/// Encrypt and append one `subject.data.v1` Event through the combined
/// two-identity prepared append.
///
/// The order is: raw cap, unlocked epoch, loaded registry, active registry
/// identity and root fingerprint, nonce reservation, the keyring's counter
/// high-water, then the store's combined boundary, inside which AES-256-GCM
/// and the Timeline signature run.
///
/// # Errors
/// Returns the closed [`SubjectDataConsumerErrorV1`] of the first refusal. A
/// refusal before the reservation spends no counter; a later refusal commits
/// no Event and never returns its counter.
pub fn append_subject_preference_weights<S: EventStore + ?Sized>(
    store: &mut S,
    keys: &mut SubjectKeyringV1,
    nonces: &mut dyn SubjectNonceReservationPortV1,
    request: &SubjectDataAppendV1<'_>,
) -> Result<Event, SubjectDataConsumerErrorV1> {
    if request.weights.len() > MAX_SUBJECT_FIELD_PLAINTEXT_BYTES {
        return Err(SubjectDataConsumerErrorV1::PlaintextBoundExceeded);
    }
    let subject = keys.subject;
    let identity = keys.key_identity(request.epoch);
    let signing_identity = keys.timeline_signing_anchor.0;
    let Some(unlocked) = keys.epochs.get_mut(&request.epoch) else {
        return Err(SubjectDataConsumerErrorV1::KeyLocked);
    };
    let digest = unlocked.root.material_digest();
    let Ok(loaded) = store.load_key_registry() else {
        return Err(SubjectDataConsumerErrorV1::RegistryUnavailable);
    };
    let active = loaded.filter(|registry| is_active_encryption_key(registry, identity, digest));
    let Some(registry) = active else {
        return Err(SubjectDataConsumerErrorV1::KeyNotActive);
    };
    nonces
        .reserve_data_counter(identity, digest)
        .and_then(|counter| {
            if counter > unlocked.last_data_counter {
                unlocked.last_data_counter = counter;
                Ok(counter)
            } else {
                Err(SubjectDataConsumerErrorV1::NonceReservationRefused)
            }
        })
        .and_then(|counter| {
            // Every failure of this callback is one closed refusal: the store
            // reports it as a payload-free append failure, and no typed cause
            // of key derivation, header or AES-GCM refusal crosses the boundary.
            let mut prepare_payload = |input: &TimelineEventEnvelopeInputV1| {
                unlocked
                    .wrap
                    .derive_subkey(&unlocked.root, SubjectKeyUseV1::Data)
                    .ok()
                    .zip(
                        subject_data_public_header(subject, PERSONA_PREFERENCE_WEIGHTS_FIELD_TAG)
                            .ok(),
                    )
                    .and_then(|(subkey, header)| {
                        SubjectCiphertextV1::encrypt(
                            &subkey,
                            counter,
                            input,
                            &header,
                            PERSONA_PREFERENCE_WEIGHTS_FIELD_TAG,
                            request.weights,
                        )
                        .ok()
                    })
                    .and_then(|ciphertext| SubjectDataV1::new(ciphertext).ok())
                    .map(|data| CanonicalBytes::from_vec(data.as_bytes().to_vec()))
                    .ok_or_else(|| {
                        CoreError::Storage("subject field encryption refused".to_owned())
                    })
            };
            let mut sign = |authorized: &mut KeyRegistryStateV1,
                            envelope: &TimelineEventEnvelopeV1,
                            payload: &CanonicalBytes| {
                sign_timeline_event_for_registered_role(
                    authorized,
                    request.signing,
                    envelope,
                    payload,
                )
                .map_err(|error| CoreError::Storage(error.to_string()))
            };
            store
                .append_prepared_subject_encrypted_timeline_signed(
                    request.timeline_id,
                    &registry,
                    EventDraft::new(
                        subject,
                        Kind::new(SUBJECT_DATA_EVENT_TYPE),
                        CanonicalBytes::from_static(&[]),
                    ),
                    PreparedSubjectAppendAuthorizationV1 {
                        encryption_identity: identity,
                        encryption_material_digest: digest,
                        signing_identity,
                        signing_material_digest: request.signing.material_digest(),
                        signing_public_key: request.signing.public_verification_key(),
                    },
                    &mut prepare_payload,
                    &mut sign,
                )
                .map_err(|_| SubjectDataConsumerErrorV1::AppendRefused)
        })
}

fn is_active_encryption_key(
    registry: &KeyRegistryStateV1,
    identity: KeyIdentityV1,
    digest: Hash,
) -> bool {
    registry.active_key(&identity.owner_id, identity.role)
        == Some(KeyRecordV1 {
            identity,
            private_material_digest: Some(digest),
            public_verification_key: None,
        })
}

/// Read the latest committed value of `field` for `subject_id` and hand its
/// outcome to `deliver` exactly once.
///
/// A keyring reads only its own subject: any other `subject_id` delivers
/// `Integrity`, whatever that keyring's lock or destruction state and whether
/// or not a value exists. The latest `subject.data.v1` Event of the subject in
/// Timeline Order is selected without fallback. Its ciphertext must name the
/// keyring's subject and the Event must verify under the keyring's pinned
/// owner-process trust anchor; decryption runs inside the store's
/// historical-decryption authorization, and `Present` moves one fresh
/// allocation while the adapter-owned staging is wiped after the callback.
///
/// # Errors
/// Returns [`SubjectFieldOwnerReadErrorV1::ErasureFenced`] when the store's
/// erasure containment refuses the Timeline read, and
/// [`SubjectFieldOwnerReadErrorV1::ReadUnavailableBeforeDelivery`] for any
/// other store failure; both deliver zero times. Returns
/// [`SubjectFieldOwnerReadErrorV1::CallbackFailed`] when `deliver` fails.
pub fn read_subject_field<S>(
    store: &mut S,
    keys: &SubjectKeyringV1,
    timeline_id: TimelineId,
    subject_id: EntityId,
    field: SubjectFieldSelectorV1,
    deliver: &mut dyn FnMut(
        SubjectFieldReadResultV1,
    ) -> Result<(), SubjectFieldReadCallbackErrorV1>,
) -> Result<(), SubjectFieldOwnerReadErrorV1>
where
    S: EventStore + KeyRegistryHistoricalDecryptionPortV1,
{
    // The closed selector has exactly one accepted field; a second variant
    // must not compile here until its tag is bound.
    let SubjectFieldSelectorV1::PersonaPreferenceWeights = field;
    store
        .read(timeline_id, SeqRange::all())
        .and_then(|events| store.load_key_registry().map(|registry| (events, registry)))
        .map_err(|error| read_refusal(&error))
        .and_then(|(events, registry)| {
            let latest = events.iter().rev().find(|event| {
                event.entity == subject_id && event.event_type.as_str() == SUBJECT_DATA_EVENT_TYPE
            });
            deliver_latest(
                store,
                keys,
                registry.as_ref(),
                (subject_id, latest),
                PERSONA_PREFERENCE_WEIGHTS_FIELD_TAG,
                deliver,
            )
            .map_err(|SubjectFieldReadCallbackErrorV1::Failed| {
                SubjectFieldOwnerReadErrorV1::CallbackFailed
            })
        })
}

fn deliver_latest<S: KeyRegistryHistoricalDecryptionPortV1>(
    store: &mut S,
    keys: &SubjectKeyringV1,
    registry: Option<&KeyRegistryStateV1>,
    (subject_id, latest): (EntityId, Option<&Event>),
    field_tag: &str,
    deliver: &mut dyn FnMut(
        SubjectFieldReadResultV1,
    ) -> Result<(), SubjectFieldReadCallbackErrorV1>,
) -> Result<(), SubjectFieldReadCallbackErrorV1> {
    // The requester's context is checked before any Event or key state, so
    // another subject's keyring learns neither existence nor destruction.
    if subject_id != keys.subject {
        return deliver(Err(SubjectFieldReadError::Integrity));
    }
    let Some(event) = latest else {
        return deliver(Err(SubjectFieldReadError::NoValue));
    };
    let Some((data, envelope)) = verified_subject_data(keys, registry, event) else {
        return deliver(Err(SubjectFieldReadError::Integrity));
    };
    let identity = keys.key_identity(data.ciphertext().epoch());
    let Some(unlocked) = keys.epochs.get(&identity.epoch) else {
        return deliver(locked_outcome(registry, identity));
    };
    let digest = unlocked.root.material_digest();
    let authorized = store.with_decryption_authorization(identity, digest, || {
        let staged = open_subject_field(unlocked, &data, &envelope, field_tag);
        deliver(
            staged
                .as_ref()
                .map(|plaintext| {
                    FieldStateV1::Present(CanonicalBytes::from_vec(plaintext.to_vec()))
                })
                .map_err(|error| *error),
        )
    });
    authorized.unwrap_or_else(|denial| deliver(denied_outcome(denial)))
}

fn verified_subject_data(
    keys: &SubjectKeyringV1,
    registry: Option<&KeyRegistryStateV1>,
    event: &Event,
) -> Option<(SubjectDataV1, TimelineEventEnvelopeV1)> {
    SubjectDataV1::from_bytes(event.payload.as_slice())
        .ok()
        .zip(TimelineEventEnvelopeV1::from_committed_event(event).ok())
        .filter(|(data, _)| {
            data.ciphertext().subject_id() == keys.subject
                && verify_committed_timeline_event_v1(
                    event,
                    registry,
                    Some(keys.timeline_signing_anchor),
                ) == TimelineEventVerificationV1::Verified
        })
}

/// Every failure is the one payload-free `Integrity` outcome ADR-121 allows:
/// a typed derivation, context, authentication or bound cause never reaches
/// the callback.
fn open_subject_field(
    unlocked: &UnlockedEpoch,
    data: &SubjectDataV1,
    envelope: &TimelineEventEnvelopeV1,
    field_tag: &str,
) -> Result<Zeroizing<Vec<u8>>, SubjectFieldReadError> {
    unlocked
        .wrap
        .derive_subkey(&unlocked.root, SubjectKeyUseV1::Data)
        .ok()
        .and_then(|subkey| {
            data.ciphertext()
                .decrypt(&subkey, envelope.input(), &data.public_header(), field_tag)
                .ok()
        })
        .filter(|plaintext| plaintext.len() <= MAX_SUBJECT_FIELD_PLAINTEXT_BYTES)
        .ok_or(SubjectFieldReadError::Integrity)
}

fn locked_outcome(
    registry: Option<&KeyRegistryStateV1>,
    identity: KeyIdentityV1,
) -> SubjectFieldReadResultV1 {
    let destroyed = registry.and_then(|registry| registry.tombstone(identity));
    if destroyed.is_some() {
        Ok(FieldStateV1::RedactedDestroyed)
    } else {
        Err(SubjectFieldReadError::KeyUnavailable)
    }
}

const fn denied_outcome(denial: KeyRegistryErrorV1) -> SubjectFieldReadResultV1 {
    match denial {
        KeyRegistryErrorV1::Destroyed => Ok(FieldStateV1::RedactedDestroyed),
        KeyRegistryErrorV1::DestructionPending => Err(SubjectFieldReadError::KeyUnavailable),
        _ => Err(SubjectFieldReadError::Integrity),
    }
}

const fn read_refusal(error: &CoreError) -> SubjectFieldOwnerReadErrorV1 {
    match error {
        CoreError::ErasureAccessFrozen | CoreError::ErasureContainmentUnavailable => {
            SubjectFieldOwnerReadErrorV1::ErasureFenced
        }
        _ => SubjectFieldOwnerReadErrorV1::ReadUnavailableBeforeDelivery,
    }
}

/// Record pending destruction, drop the keyring's root, then commit the
/// `Destroyed` tombstone with the request-bound deletion receipt.
///
/// Repeating the exact request is idempotent and resumes a pending request.
///
/// # Errors
/// Returns [`SubjectDataConsumerErrorV1::DestructionRefused`] when the request
/// names another owner or role, or when the registry refuses either phase. A
/// request refused before the pending state leaves the root unlocked.
pub fn destroy_subject_key<S: EventStore + ?Sized>(
    store: &mut S,
    keys: &mut SubjectKeyringV1,
    request: KeyDestructionRequestV1,
) -> Result<KeyDestructionOutcomeV1, SubjectDataConsumerErrorV1> {
    if request.identity != keys.key_identity(request.identity.epoch) {
        return Err(SubjectDataConsumerErrorV1::DestructionRefused);
    }
    store
        .begin_key_registry_destruction(request)
        .and_then(|_| {
            keys.lock(request.identity.epoch);
            store.complete_key_registry_destruction(request, deletion_receipt(&request))
        })
        .map(|(outcome, _)| outcome)
        .map_err(|_| SubjectDataConsumerErrorV1::DestructionRefused)
}
