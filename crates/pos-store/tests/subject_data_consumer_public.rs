//! Public conformance of the test-support `SubjectDataEncryption` consumer over
//! the Memory and `SQLite` adapters.
//!
//! The consumer is not a protected owner-read adapter: these tests qualify no
//! `SubjectFieldOwnerReadPortV1` binding, native file binding, or activation.

use std::sync::Arc;

use pos_core::{
    deletion_receipt, CanonicalBytes, CoreError, EntityId, ErasureContainmentGateV1,
    ErasureReplayClaimV1, Event, EventDraft, EventStore, FieldStateV1, Hash,
    KeyDestructionOutcomeV1, KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1,
    KeyRegistryHistoricalDecryptionPortV1, KeyRegistryStateV1, KeyRoleV1, Kind, OwnerIdV1,
    PreparedSubjectAppendAuthorizationV1, SeqRange, TimelineEventEnvelopeInputV1,
    TimelineEventEnvelopeV1, TimelineId,
};
use pos_crypto::key_roles::{
    destroy_registered_signing_key, sign_timeline_event_for_registered_role, SigningKeyMaterial,
};
use pos_crypto::signing::generate_keypair;
use pos_crypto::subject_ciphertext::SubjectCiphertextV1;
use pos_crypto::subject_data::{
    subject_data_public_header, SubjectDataErrorV1, SubjectDataV1, SUBJECT_DATA_EVENT_TYPE,
};
use pos_crypto::subject_field_read::{
    SubjectFieldOwnerReadErrorV1, SubjectFieldReadCallbackErrorV1, SubjectFieldReadError,
    SubjectFieldReadResultV1, SubjectFieldSelectorV1,
};
use pos_crypto::subject_key::{
    subject_owner_id, SubjectKeyUseV1, SubjectKeyWrapErrorV1, SubjectKeyWrapParamsV1,
    SubjectKeyWrapV1, SubjectPrfOutputV1, SubjectRootKeyV1,
};
use pos_crypto::subject_nonce_ledger::{SubjectNonceLedgerRowV1, SubjectNonceLedgerV1};
use pos_store::subject_data_consumer::{
    append_subject_preference_weights, destroy_subject_key, read_subject_field,
    SubjectDataAppendV1, SubjectDataConsumerErrorV1 as Refusal, SubjectKeyringV1,
    SubjectNonceReservationPortV1, VolatileSubjectNonceLedgerV1, MAX_SUBJECT_FIELD_PLAINTEXT_BYTES,
    PERSONA_PREFERENCE_WEIGHTS_FIELD_TAG,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};
use ulid::Ulid;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type ReadOutcome = (
    Result<(), SubjectFieldOwnerReadErrorV1>,
    Vec<SubjectFieldReadResultV1>,
);

/// Sorts before `SUBJECT` in SNL1 identity order.
const DECOY: EntityId = EntityId::from_ulid(Ulid::from_bytes([0x11; 16]));
const SUBJECT: EntityId = EntityId::from_ulid(Ulid::from_bytes([0x22; 16]));
const OTHER: EntityId = EntityId::from_ulid(Ulid::from_bytes([0x33; 16]));

trait Adapter: EventStore + KeyRegistryHistoricalDecryptionPortV1 {}

impl<S: EventStore + KeyRegistryHistoricalDecryptionPortV1> Adapter for S {}

/// Distinct, non-repeating bytes for one seed.
fn pattern<const N: usize>(seed: u8) -> [u8; N] {
    let mut next = seed;
    std::array::from_fn(|_| {
        next = next.wrapping_mul(31).wrapping_add(17);
        next
    })
}

/// The public wrap and the test's own copy of the private inputs behind it.
struct SubjectKey {
    wrap: SubjectKeyWrapV1,
    root: [u8; 32],
    prf: [u8; 32],
}

impl SubjectKey {
    fn digest(&self) -> Hash {
        SubjectRootKeyV1::from_bytes(self.root).material_digest()
    }

    fn prf(&self) -> SubjectPrfOutputV1 {
        SubjectPrfOutputV1::from_bytes(self.prf)
    }
}

fn subject_key(
    subject: EntityId,
    epoch: u64,
    seed: u8,
) -> Result<SubjectKey, SubjectKeyWrapErrorV1> {
    let root = pattern(seed);
    let prf = pattern(seed.wrapping_add(1));
    SubjectKeyWrapV1::seal(
        SubjectKeyWrapParamsV1 {
            subject_id: subject,
            epoch,
            rp_id: "localhost".to_owned(),
            credential_id: pattern::<16>(seed.wrapping_add(2)).to_vec(),
            prf_input: pattern(seed.wrapping_add(3)),
            wrap_salt: pattern(seed.wrapping_add(4)),
            subkey_salt: pattern(seed.wrapping_add(5)),
            wrap_nonce: pattern(seed.wrapping_add(6)),
        },
        &SubjectRootKeyV1::from_bytes(root),
        &SubjectPrfOutputV1::from_bytes(prf),
    )
    .map(|wrap| SubjectKey { wrap, root, prf })
}

fn encryption_identity(
    subject: EntityId,
    epoch: u64,
) -> Result<KeyIdentityV1, Box<dyn std::error::Error>> {
    let owner = OwnerIdV1::new(subject_owner_id(subject)?)?;
    Ok(KeyIdentityV1::new(
        owner,
        KeyRoleV1::SubjectDataEncryption,
        epoch,
    ))
}

fn signing(owner: &'static str) -> (SigningKeyMaterial, KeyIdentityV1) {
    let (key, _) = generate_keypair();
    (
        SigningKeyMaterial::new(key),
        KeyIdentityV1::new(owner, KeyRoleV1::TimelineIntegritySigning, 1),
    )
}

fn nonce_row(
    subject: EntityId,
    epoch: u64,
    digest: Hash,
    data_next: u64,
) -> Result<SubjectNonceLedgerRowV1, SubjectKeyWrapErrorV1> {
    subject_owner_id(subject).map(|owner_id| SubjectNonceLedgerRowV1 {
        owner_id,
        epoch,
        root_material_digest: *digest.as_bytes(),
        store_file_id: [0, 0],
        data_next,
        bootstrap_next: 1,
    })
}

fn ledger(
    rows: impl IntoIterator<Item = SubjectNonceLedgerRowV1>,
) -> Result<VolatileSubjectNonceLedgerV1, Box<dyn std::error::Error>> {
    Ok(VolatileSubjectNonceLedgerV1::new(
        SubjectNonceLedgerV1::new(rows)?,
    ))
}

fn next_data_counters(nonces: &VolatileSubjectNonceLedgerV1) -> Vec<u64> {
    nonces.ledger().rows().map(|row| row.data_next).collect()
}

/// One bound store with the owner-process and Gateway signing identities, the
/// subject's active epoch 1, its unlocked keyring and its enrolled nonce row.
struct Fixture {
    gate: Arc<ErasureContainmentGateV1>,
    timeline: TimelineId,
    owner: SigningKeyMaterial,
    owner_identity: KeyIdentityV1,
    gateway: SigningKeyMaterial,
    gateway_identity: KeyIdentityV1,
    key: SubjectKey,
    keys: SubjectKeyringV1,
    nonces: VolatileSubjectNonceLedgerV1,
}

impl Fixture {
    fn keyring(&self, subject: EntityId) -> Result<SubjectKeyringV1, Refusal> {
        SubjectKeyringV1::new(
            subject,
            self.owner_identity,
            self.owner.public_verification_key(),
        )
    }
}

fn fixture<S: Adapter>(store: &mut S) -> Result<Fixture, Box<dyn std::error::Error>> {
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    store.bind_erasure_gate(Arc::clone(&gate))?;
    let (owner, owner_identity) = signing("piglor-owner");
    let (gateway, gateway_identity) = signing("timeline-owner");
    let key = subject_key(SUBJECT, 1, 0x10)?;
    let mut registry = KeyRegistryStateV1::new();
    for (identity, material) in [(owner_identity, &owner), (gateway_identity, &gateway)] {
        registry.register_key(KeyRegistrationV1::new(
            identity,
            material.material_digest(),
            Some(material.public_verification_key()),
        ))?;
    }
    let identity = encryption_identity(SUBJECT, 1)?;
    registry.register_key(KeyRegistrationV1::new(identity, key.digest(), None))?;
    store.save_key_registry(&registry)?;
    let timeline = store.create_timeline("subject-data")?.id();
    let mut keys = SubjectKeyringV1::new(SUBJECT, owner_identity, owner.public_verification_key())?;
    assert_eq!(keys.key_identity(1), identity);
    assert_eq!(keys.unlock(key.wrap.clone(), &key.prf()), Ok(identity));
    let nonces = ledger([
        nonce_row(DECOY, 1, key.digest(), 7)?,
        nonce_row(SUBJECT, 1, key.digest(), 1)?,
    ])?;
    Ok(Fixture {
        gate,
        timeline,
        owner,
        owner_identity,
        gateway,
        gateway_identity,
        key,
        keys,
        nonces,
    })
}

fn append<S: EventStore + ?Sized>(
    store: &mut S,
    fx: &mut Fixture,
    epoch: u64,
    weights: &[u8],
) -> Result<Event, Refusal> {
    append_subject_preference_weights(
        store,
        &fx.keys,
        &mut fx.nonces,
        &SubjectDataAppendV1 {
            timeline_id: fx.timeline,
            epoch,
            signing: &fx.owner,
            weights,
        },
    )
}

fn read<S: Adapter>(store: &mut S, keys: &SubjectKeyringV1, timeline: TimelineId) -> ReadOutcome {
    let mut delivered = Vec::new();
    let outcome = read_subject_field(
        store,
        keys,
        timeline,
        SUBJECT,
        SubjectFieldSelectorV1::PersonaPreferenceWeights,
        &mut |result| {
            delivered.push(result);
            Ok(())
        },
    );
    (outcome, delivered)
}

/// Exactly one delivery of `result` and a clean outer return.
fn field(result: SubjectFieldReadResultV1) -> ReadOutcome {
    (Ok(()), vec![result])
}

fn present(weights: &[u8]) -> ReadOutcome {
    field(Ok(FieldStateV1::Present(CanonicalBytes::from_vec(
        weights.to_vec(),
    ))))
}

const fn refused(error: SubjectFieldOwnerReadErrorV1) -> ReadOutcome {
    (Err(error), Vec::new())
}

fn subject_data(event: &Event) -> Result<SubjectDataV1, SubjectDataErrorV1> {
    SubjectDataV1::from_bytes(event.payload.as_slice())
}

fn try_seal(
    key: &SubjectKey,
    counter: u64,
    field_tag: &str,
    plaintext: &[u8],
    input: &TimelineEventEnvelopeInputV1,
) -> Result<CanonicalBytes, Box<dyn std::error::Error>> {
    let root = SubjectRootKeyV1::from_bytes(key.root);
    let subkey = key.wrap.derive_subkey(&root, SubjectKeyUseV1::Data)?;
    let header = subject_data_public_header(input.entity_id, field_tag)?;
    let ciphertext =
        SubjectCiphertextV1::encrypt(&subkey, counter, input, &header, field_tag, plaintext)?;
    Ok(CanonicalBytes::from_vec(
        SubjectDataV1::new(ciphertext)?.as_bytes().to_vec(),
    ))
}

/// Encrypt outside the consumer, as an independent producer of SDP1 bytes.
fn seal(
    key: &SubjectKey,
    counter: u64,
    field_tag: &str,
    plaintext: &[u8],
    input: &TimelineEventEnvelopeInputV1,
) -> Result<CanonicalBytes, CoreError> {
    try_seal(key, counter, field_tag, plaintext, input)
        .map_err(|error| CoreError::Storage(error.to_string()))
}

/// Commit one `subject.data.v1` Event with a caller-made payload and signer,
/// through the store's own combined prepared append.
fn append_crafted<S: EventStore + ?Sized>(
    store: &mut S,
    fx: &Fixture,
    entity: EntityId,
    signer: (&SigningKeyMaterial, KeyIdentityV1),
    payload: &mut dyn FnMut(&TimelineEventEnvelopeInputV1) -> Result<CanonicalBytes, CoreError>,
) -> Result<Event, CoreError> {
    let registry = store
        .load_key_registry()?
        .ok_or_else(|| CoreError::Storage("key registry is absent".to_owned()))?;
    let mut sign = |authorized: &mut KeyRegistryStateV1,
                    envelope: &TimelineEventEnvelopeV1,
                    bytes: &CanonicalBytes| {
        sign_timeline_event_for_registered_role(authorized, signer.0, envelope, bytes)
            .map_err(|error| CoreError::Storage(error.to_string()))
    };
    store.append_prepared_subject_encrypted_timeline_signed(
        fx.timeline,
        &registry,
        EventDraft::new(
            entity,
            Kind::new(SUBJECT_DATA_EVENT_TYPE),
            CanonicalBytes::from_static(b"placeholder"),
        ),
        PreparedSubjectAppendAuthorizationV1 {
            encryption_identity: fx.keys.key_identity(1),
            encryption_material_digest: fx.key.digest(),
            signing_identity: signer.1,
            signing_material_digest: signer.0.material_digest(),
            signing_public_key: signer.0.public_verification_key(),
        },
        payload,
        &mut sign,
    )
}

fn exercise_round_trip<S: Adapter>(store: &mut S) -> TestResult {
    let mut fx = fixture(store)?;
    assert_eq!(
        read(store, &fx.keys, fx.timeline),
        field(Err(SubjectFieldReadError::NoValue))
    );
    let first = append(store, &mut fx, 1, b"first weights")?;
    let data = subject_data(&first)?;
    assert_eq!(
        (
            first.entity,
            first.event_type.as_str(),
            first.signature_identity
        ),
        (SUBJECT, SUBJECT_DATA_EVENT_TYPE, Some(fx.owner_identity))
    );
    assert_eq!(
        (
            data.ciphertext().counter(),
            data.ciphertext().epoch(),
            data.ciphertext().key_use(),
            data.ciphertext().field_tag(),
        ),
        (
            1,
            1,
            SubjectKeyUseV1::Data,
            PERSONA_PREFERENCE_WEIGHTS_FIELD_TAG
        )
    );
    assert_eq!(
        PERSONA_PREFERENCE_WEIGHTS_FIELD_TAG,
        "persona.preference_weights"
    );
    assert_eq!(store.read_own(fx.timeline, SeqRange::all())?, vec![first]);
    assert_eq!(
        read(store, &fx.keys, fx.timeline),
        present(b"first weights")
    );

    // Neither a later Event of another subject nor a later Event of another
    // type for this subject is the subject's field value.
    append_crafted(
        store,
        &fx,
        OTHER,
        (&fx.owner, fx.owner_identity),
        &mut |_| Ok(CanonicalBytes::from_static(b"another subject")),
    )?;
    store.append(
        fx.timeline,
        &[EventDraft::new(
            SUBJECT,
            Kind::new("timeline.note.v1"),
            CanonicalBytes::from_static(b"clear note"),
        )],
    )?;
    assert_eq!(
        read(store, &fx.keys, fx.timeline),
        present(b"first weights")
    );

    // Each Event carries the complete value; the latest one wins.
    let second = append(store, &mut fx, 1, b"second weights")?;
    assert_eq!(subject_data(&second)?.ciphertext().counter(), 2);
    assert_eq!(
        read(store, &fx.keys, fx.timeline),
        present(b"second weights")
    );
    assert_eq!(next_data_counters(&fx.nonces), vec![7, 3]);
    Ok(())
}

#[test]
fn round_trip_delivers_the_latest_value_once_in_both_adapters() -> TestResult {
    exercise_round_trip(&mut MemoryStore::new())?;
    exercise_round_trip(&mut SqliteStore::open_in_memory()?)
}

fn exercise_handoff<S: Adapter>(store: &mut S) -> TestResult {
    let mut fx = fixture(store)?;
    let exact = vec![0x5a; MAX_SUBJECT_FIELD_PLAINTEXT_BYTES];
    let over = vec![0x5a; MAX_SUBJECT_FIELD_PLAINTEXT_BYTES + 1];
    assert_eq!(MAX_SUBJECT_FIELD_PLAINTEXT_BYTES, 8_192);

    // One over the raw cap is refused before a counter is reserved.
    assert_eq!(
        append(store, &mut fx, 1, &over).err(),
        Some(Refusal::PlaintextBoundExceeded)
    );
    assert_eq!(next_data_counters(&fx.nonces), vec![7, 1]);
    append(store, &mut fx, 1, &exact)?;
    assert_eq!(read(store, &fx.keys, fx.timeline), present(&exact));

    // The handed-off value is one fresh allocation that its caller can wipe.
    let (outcome, mut delivered) = read(store, &fx.keys, fx.timeline);
    let Some(Ok(FieldStateV1::Present(handed_off))) = delivered.pop() else {
        return Err("expected one Present delivery".into());
    };
    assert_eq!((outcome, delivered.len()), (Ok(()), 0));
    assert_eq!(handed_off.try_zeroize_owned(), Ok(()));

    // A failing callback still received its single outcome.
    let mut calls = 0;
    let failed = read_subject_field(
        store,
        &fx.keys,
        fx.timeline,
        SUBJECT,
        SubjectFieldSelectorV1::PersonaPreferenceWeights,
        &mut |_| {
            calls += 1;
            Err(SubjectFieldReadCallbackErrorV1::Failed)
        },
    );
    assert_eq!(
        (failed, calls),
        (Err(SubjectFieldOwnerReadErrorV1::CallbackFailed), 1)
    );

    // A committed value one over the raw cap is an integrity outcome, and an
    // independently produced value at the cap is still delivered.
    let owner = (&fx.owner, fx.owner_identity);
    append_crafted(store, &fx, SUBJECT, owner, &mut |input| {
        seal(
            &fx.key,
            900,
            PERSONA_PREFERENCE_WEIGHTS_FIELD_TAG,
            &over,
            input,
        )
    })?;
    assert_eq!(
        read(store, &fx.keys, fx.timeline),
        field(Err(SubjectFieldReadError::Integrity))
    );
    append_crafted(store, &fx, SUBJECT, owner, &mut |input| {
        seal(
            &fx.key,
            901,
            PERSONA_PREFERENCE_WEIGHTS_FIELD_TAG,
            &exact,
            input,
        )
    })?;
    assert_eq!(read(store, &fx.keys, fx.timeline), present(&exact));
    Ok(())
}

#[test]
fn raw_cap_and_callback_handoff_are_exact_in_both_adapters() -> TestResult {
    exercise_handoff(&mut MemoryStore::new())?;
    exercise_handoff(&mut SqliteStore::open_in_memory()?)
}

fn exercise_wrong_keys<S: Adapter>(store: &mut S) -> TestResult {
    let mut fx = fixture(store)?;
    append(store, &mut fx, 1, b"weights")?;
    let reservations = fx.nonces.clone();
    assert_eq!(
        fx.keyring(EntityId::from_ulid(Ulid::nil())).err(),
        Some(Refusal::InvalidSubject)
    );

    // Another registered subject cannot open this subject's wrap or field.
    let other_key = subject_key(OTHER, 1, 0x40)?;
    let mut registry = store.load_key_registry()?.ok_or("key registry is absent")?;
    registry.register_key(KeyRegistrationV1::new(
        encryption_identity(OTHER, 1)?,
        other_key.digest(),
        None,
    ))?;
    store.save_key_registry(&registry)?;
    let mut other = fx.keyring(OTHER)?;
    assert_eq!(
        other.unlock(fx.key.wrap.clone(), &fx.key.prf()),
        Err(Refusal::WrapSubjectMismatch)
    );
    assert_eq!(
        other.unlock(other_key.wrap.clone(), &fx.key.prf()),
        Err(Refusal::UnlockFailed)
    );
    assert_eq!(
        read(store, &other, fx.timeline),
        field(Err(SubjectFieldReadError::KeyUnavailable))
    );
    assert_eq!(
        other.unlock(other_key.wrap.clone(), &other_key.prf()),
        Ok(encryption_identity(OTHER, 1)?)
    );
    assert_eq!(
        read(store, &other, fx.timeline),
        field(Err(SubjectFieldReadError::Integrity))
    );

    // The right identity with a root the registry never registered.
    let forged = subject_key(SUBJECT, 1, 0x70)?;
    let mut mismatched = fx.keyring(SUBJECT)?;
    mismatched.unlock(forged.wrap.clone(), &forged.prf())?;
    assert_eq!(
        read(store, &mismatched, fx.timeline),
        field(Err(SubjectFieldReadError::Integrity))
    );
    let request = SubjectDataAppendV1 {
        timeline_id: fx.timeline,
        epoch: 1,
        signing: &fx.owner,
        weights: b"forged",
    };
    assert_eq!(
        append_subject_preference_weights(store, &mismatched, &mut fx.nonces, &request).err(),
        Some(Refusal::KeyNotActive)
    );

    // An unlocked epoch the registry never registered, and a locked epoch.
    let unregistered = subject_key(SUBJECT, 3, 0x90)?;
    fx.keys
        .unlock(unregistered.wrap.clone(), &unregistered.prf())?;
    assert_eq!(
        append(store, &mut fx, 3, b"unregistered").err(),
        Some(Refusal::KeyNotActive)
    );
    assert_eq!(
        append(store, &mut fx, 2, b"locked").err(),
        Some(Refusal::KeyLocked)
    );

    // A keyring pinned to another Timeline signing key trusts no Event here.
    let mut repinned = SubjectKeyringV1::new(
        SUBJECT,
        fx.owner_identity,
        fx.gateway.public_verification_key(),
    )?;
    repinned.unlock(fx.key.wrap.clone(), &fx.key.prf())?;
    assert_eq!(
        read(store, &repinned, fx.timeline),
        field(Err(SubjectFieldReadError::Integrity))
    );
    assert_eq!(fx.nonces, reservations);
    assert_eq!(read(store, &fx.keys, fx.timeline), present(b"weights"));
    Ok(())
}

#[test]
fn wrong_owner_epoch_and_material_are_rejected_in_both_adapters() -> TestResult {
    exercise_wrong_keys(&mut MemoryStore::new())?;
    exercise_wrong_keys(&mut SqliteStore::open_in_memory()?)
}

/// A reservation port that hands out the forbidden counter zero.
struct ZeroCounter;

impl SubjectNonceReservationPortV1 for ZeroCounter {
    fn reserve_data_counter(&mut self, _: KeyIdentityV1, _: Hash) -> Result<u64, Refusal> {
        Ok(0)
    }
}

fn exercise_failed_appends<S: Adapter>(store: &mut S) -> TestResult {
    let mut fx = fixture(store)?;

    // The Gateway's signing material is not the owner-process identity: the
    // combined append refuses, and the reserved counter stays spent.
    let gateway_signed = SubjectDataAppendV1 {
        timeline_id: fx.timeline,
        epoch: 1,
        signing: &fx.gateway,
        weights: b"weights",
    };
    assert_eq!(
        append_subject_preference_weights(store, &fx.keys, &mut fx.nonces, &gateway_signed).err(),
        Some(Refusal::AppendRefused)
    );
    // A refused encryption commits nothing either.
    let owner_signed = SubjectDataAppendV1 {
        signing: &fx.owner,
        ..gateway_signed
    };
    assert_eq!(
        append_subject_preference_weights(store, &fx.keys, &mut ZeroCounter, &owner_signed).err(),
        Some(Refusal::AppendRefused)
    );
    assert!(store.read_own(fx.timeline, SeqRange::all())?.is_empty());
    let committed =
        append_subject_preference_weights(store, &fx.keys, &mut fx.nonces, &owner_signed)?;
    assert_eq!(subject_data(&committed)?.ciphertext().counter(), 2);

    // A missing or exhausted nonce row reserves nothing.
    for rows in [
        Vec::new(),
        vec![nonce_row(SUBJECT, 1, fx.key.digest(), 1 << 32)?],
        vec![nonce_row(SUBJECT, 1, Hash::from_bytes([3; 32]), 1)?],
        vec![nonce_row(SUBJECT, 2, fx.key.digest(), 1)?],
    ] {
        let mut nonces = ledger(rows)?;
        let unchanged = nonces.clone();
        assert_eq!(
            append_subject_preference_weights(store, &fx.keys, &mut nonces, &owner_signed).err(),
            Some(Refusal::NonceReservationRefused)
        );
        assert_eq!(nonces, unchanged);
    }

    // Signing fails inside the combined boundary once the material is gone.
    let mut scratch = store.load_key_registry()?.ok_or("key registry is absent")?;
    let destruction = KeyDestructionRequestV1::new(
        fx.owner_identity,
        fx.owner.material_digest(),
        Hash::from_bytes([9; 32]),
    );
    destroy_registered_signing_key(&mut fx.owner, destruction, &mut scratch)?;
    assert_eq!(
        append(store, &mut fx, 1, b"unsigned").err(),
        Some(Refusal::AppendRefused)
    );
    assert_eq!(
        store.read_own(fx.timeline, SeqRange::all())?,
        vec![committed]
    );
    assert_eq!(next_data_counters(&fx.nonces), vec![7, 4]);
    assert_eq!(read(store, &fx.keys, fx.timeline), present(b"weights"));
    Ok(())
}

#[test]
fn failed_append_commits_nothing_and_spends_its_counter_in_both_adapters() -> TestResult {
    exercise_failed_appends(&mut MemoryStore::new())?;
    exercise_failed_appends(&mut SqliteStore::open_in_memory()?)
}

fn exercise_untrusted_events<S: Adapter>(store: &mut S) -> TestResult {
    let mut fx = fixture(store)?;
    append(store, &mut fx, 1, b"weights")?;
    let owner = (&fx.owner, fx.owner_identity);
    let integrity = || field(Err(SubjectFieldReadError::Integrity));

    // A verifying Gateway signature is still the wrong owner for this type.
    append_crafted(
        store,
        &fx,
        SUBJECT,
        (&fx.gateway, fx.gateway_identity),
        &mut |input| {
            seal(
                &fx.key,
                900,
                PERSONA_PREFERENCE_WEIGHTS_FIELD_TAG,
                b"gateway",
                input,
            )
        },
    )?;
    assert_eq!(read(store, &fx.keys, fx.timeline), integrity());

    // The latest Event is never skipped in favour of an earlier valid one.
    append_crafted(store, &fx, SUBJECT, owner, &mut |input| {
        seal(&fx.key, 901, "persona.unregistered", b"other field", input)
    })?;
    assert_eq!(read(store, &fx.keys, fx.timeline), integrity());
    append_crafted(store, &fx, SUBJECT, owner, &mut |_| {
        Ok(CanonicalBytes::from_static(b"not an SDP1 payload"))
    })?;
    assert_eq!(read(store, &fx.keys, fx.timeline), integrity());

    let restored = append(store, &mut fx, 1, b"restored")?;
    assert_eq!(subject_data(&restored)?.ciphertext().counter(), 2);
    assert_eq!(read(store, &fx.keys, fx.timeline), present(b"restored"));
    Ok(())
}

#[test]
fn unverified_or_malformed_latest_event_is_an_integrity_outcome_in_both_adapters() -> TestResult {
    exercise_untrusted_events(&mut MemoryStore::new())?;
    exercise_untrusted_events(&mut SqliteStore::open_in_memory()?)
}

fn exercise_rotation<S: Adapter>(store: &mut S) -> TestResult {
    let mut fx = fixture(store)?;
    append(store, &mut fx, 1, b"epoch one")?;
    let rotated = subject_key(SUBJECT, 2, 0x40)?;
    let mut registry = store.load_key_registry()?.ok_or("key registry is absent")?;
    registry.register_key(KeyRegistrationV1::new(
        encryption_identity(SUBJECT, 2)?,
        rotated.digest(),
        None,
    ))?;
    store.save_key_registry(&registry)?;
    fx.keys.unlock(rotated.wrap.clone(), &rotated.prf())?;
    fx.nonces = ledger(fx.nonces.ledger().rows().cloned().chain([nonce_row(
        SUBJECT,
        2,
        rotated.digest(),
        1,
    )?]))?;

    // The retained epoch still decrypts but no longer encrypts, and a refusal
    // before reservation spends no counter.
    assert_eq!(read(store, &fx.keys, fx.timeline), present(b"epoch one"));
    assert_eq!(
        append(store, &mut fx, 1, b"stale").err(),
        Some(Refusal::KeyNotActive)
    );
    assert_eq!(next_data_counters(&fx.nonces), vec![7, 2, 1]);

    let event = append(store, &mut fx, 2, b"epoch two")?;
    let data = subject_data(&event)?;
    assert_eq!(
        (data.ciphertext().epoch(), data.ciphertext().counter()),
        (2, 1)
    );
    assert_eq!(read(store, &fx.keys, fx.timeline), present(b"epoch two"));

    // Locking the latest value's epoch never falls back to the older value.
    fx.keys.lock(2);
    assert_eq!(
        read(store, &fx.keys, fx.timeline),
        field(Err(SubjectFieldReadError::KeyUnavailable))
    );
    assert_eq!(
        append(store, &mut fx, 2, b"locked").err(),
        Some(Refusal::KeyLocked)
    );
    fx.keys.unlock(rotated.wrap.clone(), &rotated.prf())?;
    assert_eq!(read(store, &fx.keys, fx.timeline), present(b"epoch two"));
    Ok(())
}

#[test]
fn rotation_keeps_the_old_epoch_decrypt_only_in_both_adapters() -> TestResult {
    exercise_rotation(&mut MemoryStore::new())?;
    exercise_rotation(&mut SqliteStore::open_in_memory()?)
}

fn destruction_request(fx: &Fixture, authorization: u8) -> KeyDestructionRequestV1 {
    KeyDestructionRequestV1::new(
        fx.keys.key_identity(1),
        fx.key.digest(),
        Hash::from_bytes([authorization; 32]),
    )
}

fn exercise_pending_destruction<S: Adapter>(store: &mut S) -> TestResult {
    let mut fx = fixture(store)?;
    append(store, &mut fx, 1, b"weights")?;
    let request = destruction_request(&fx, 7);

    // A request for another material fingerprint or another owner's key is
    // refused before the pending state, so the root stays unlocked.
    let wrong_material = KeyDestructionRequestV1::new(
        request.identity,
        Hash::from_bytes([8; 32]),
        request.authorization_digest,
    );
    let gateway_key = KeyDestructionRequestV1::new(
        fx.gateway_identity,
        fx.gateway.material_digest(),
        request.authorization_digest,
    );
    for refused_request in [wrong_material, gateway_key] {
        assert_eq!(
            destroy_subject_key(store, &mut fx.keys, refused_request),
            Err(Refusal::DestructionRefused)
        );
    }
    assert_eq!(read(store, &fx.keys, fx.timeline), present(b"weights"));

    // Pending destruction denies encryption and decryption without redacting.
    store.begin_key_registry_destruction(request)?;
    let unavailable = || field(Err(SubjectFieldReadError::KeyUnavailable));
    assert_eq!(read(store, &fx.keys, fx.timeline), unavailable());
    assert_eq!(
        read(store, &fx.keyring(SUBJECT)?, fx.timeline),
        unavailable()
    );
    assert_eq!(
        append(store, &mut fx, 1, b"late").err(),
        Some(Refusal::KeyNotActive)
    );
    assert_eq!(next_data_counters(&fx.nonces), vec![7, 2]);

    // The exact request resumes the pending destruction to its tombstone.
    let outcome = destroy_subject_key(store, &mut fx.keys, request)?;
    let KeyDestructionOutcomeV1::Destroyed(tombstone) = outcome else {
        return Err("expected the resumed request to commit the tombstone".into());
    };
    assert_eq!(
        (tombstone.identity, tombstone.deletion_receipt),
        (request.identity, deletion_receipt(&request))
    );
    assert_eq!(
        read(store, &fx.keys, fx.timeline),
        field(Ok(FieldStateV1::RedactedDestroyed))
    );
    Ok(())
}

#[test]
fn pending_destruction_is_unavailable_and_resumes_in_both_adapters() -> TestResult {
    exercise_pending_destruction(&mut MemoryStore::new())?;
    exercise_pending_destruction(&mut SqliteStore::open_in_memory()?)
}

fn exercise_confirmed_destruction<S: Adapter>(store: &mut S) -> TestResult {
    let mut fx = fixture(store)?;
    append(store, &mut fx, 1, b"weights")?;
    let request = destruction_request(&fx, 7);
    let mut retained = fx.keyring(SUBJECT)?;
    retained.unlock(fx.key.wrap.clone(), &fx.key.prf())?;

    let outcome = destroy_subject_key(store, &mut fx.keys, request)?;
    let KeyDestructionOutcomeV1::Destroyed(tombstone) = outcome else {
        return Err("expected the first request to commit the tombstone".into());
    };
    // The exact retry is idempotent; a different authorization is refused.
    assert_eq!(
        destroy_subject_key(store, &mut fx.keys, request),
        Ok(KeyDestructionOutcomeV1::AlreadyDestroyed(tombstone))
    );
    let reauthorized = destruction_request(&fx, 6);
    assert_eq!(
        destroy_subject_key(store, &mut fx.keys, reauthorized),
        Err(Refusal::DestructionRefused)
    );
    let registry = store.load_key_registry()?.ok_or("key registry is absent")?;
    assert_eq!(registry.tombstone(request.identity), Some(tombstone));

    // The destroying keyring dropped its root; a keyring that still holds the
    // root is denied by the registry. Both redact, and neither encrypts.
    let redacted = FieldStateV1::RedactedDestroyed;
    assert_eq!(
        redacted.weaken_replay_claim(ErasureReplayClaimV1::Exact),
        ErasureReplayClaimV1::StructuralOnly
    );
    assert_eq!(
        read(store, &fx.keys, fx.timeline),
        field(Ok(redacted.clone()))
    );
    assert_eq!(read(store, &retained, fx.timeline), field(Ok(redacted)));
    assert_eq!(
        append(store, &mut fx, 1, b"late").err(),
        Some(Refusal::KeyLocked)
    );
    let late = SubjectDataAppendV1 {
        timeline_id: fx.timeline,
        epoch: 1,
        signing: &fx.owner,
        weights: b"late",
    };
    assert_eq!(
        append_subject_preference_weights(store, &retained, &mut fx.nonces, &late).err(),
        Some(Refusal::KeyNotActive)
    );
    assert_eq!(next_data_counters(&fx.nonces), vec![7, 2]);
    assert_eq!(store.read_own(fx.timeline, SeqRange::all())?.len(), 1);
    Ok(())
}

#[test]
fn confirmed_destruction_redacts_and_retries_idempotently_in_both_adapters() -> TestResult {
    exercise_confirmed_destruction(&mut MemoryStore::new())?;
    exercise_confirmed_destruction(&mut SqliteStore::open_in_memory()?)
}

fn exercise_erasure_boundary<S: Adapter>(store: &mut S, unbound: &mut S) -> TestResult {
    let mut fx = fixture(store)?;
    append(store, &mut fx, 1, b"weights")?;

    // A fail-closed containment gate refuses the read, and a store with no
    // registry has no active key.
    unbound.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_fail_closed()))?;
    assert_eq!(
        read(unbound, &fx.keys, fx.timeline),
        refused(SubjectFieldOwnerReadErrorV1::ErasureFenced)
    );
    let unregistered = SubjectDataAppendV1 {
        timeline_id: fx.timeline,
        epoch: 1,
        signing: &fx.owner,
        weights: b"weights",
    };
    assert_eq!(
        append_subject_preference_weights(unbound, &fx.keys, &mut fx.nonces, &unregistered).err(),
        Some(Refusal::KeyNotActive)
    );
    assert_eq!(next_data_counters(&fx.nonces), vec![7, 2]);

    // A non-erasure store failure is not an erasure refusal.
    assert_eq!(
        read(store, &fx.keys, TimelineId::new()),
        refused(SubjectFieldOwnerReadErrorV1::ReadUnavailableBeforeDelivery)
    );
    // Once the Timeline is access-frozen, nothing is decrypted or delivered.
    assert_eq!(read(store, &fx.keys, fx.timeline), present(b"weights"));
    fx.gate.freeze_timeline_for_test(fx.timeline);
    assert_eq!(
        read(store, &fx.keys, fx.timeline),
        refused(SubjectFieldOwnerReadErrorV1::ErasureFenced)
    );
    Ok(())
}

#[test]
fn erasure_containment_refuses_before_any_delivery_in_both_adapters() -> TestResult {
    exercise_erasure_boundary(&mut MemoryStore::new(), &mut MemoryStore::new())?;
    exercise_erasure_boundary(
        &mut SqliteStore::open_in_memory()?,
        &mut SqliteStore::open_in_memory()?,
    )
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn reopened_sqlite_store_redacts_and_never_held_private_bytes() -> TestResult {
    let directory = tempfile::TempDir::new()?;
    let path = directory.path().join("owner.db");
    let path = path.to_str().ok_or("temporary path is not UTF-8")?;
    let mut store = SqliteStore::open(path)?;
    let mut fx = fixture(&mut store)?;
    let weights: [u8; 48] = pattern(0xc0);
    let event = append(&mut store, &mut fx, 1, &weights)?;
    assert_eq!(read(&mut store, &fx.keys, fx.timeline), present(&weights));

    // The durable bytes hold the ciphertext, and neither the root, the PRF
    // output nor the plaintext; the keyring prints no root.
    let mut durable = std::fs::read(path)?;
    durable.extend(std::fs::read(format!("{path}-wal")).unwrap_or_default());
    let data = subject_data(&event)?;
    assert!(contains(&durable, data.ciphertext().ciphertext_and_tag()));
    for private in [&fx.key.root[..], &fx.key.prf[..], &weights[..]] {
        assert!(!contains(&durable, private));
        assert!(!contains(event.payload.as_slice(), private));
    }
    assert!(format!("{:?}", fx.keys).contains("SubjectRootKeyV1(<redacted>)"));

    // Replay on a fresh handle with no unlocked key: only the committed
    // tombstone turns the field into `RedactedDestroyed`.
    let request = destruction_request(&fx, 7);
    drop(store);
    let mut pending = SqliteStore::open(path)?;
    pending.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let locked = fx.keyring(SUBJECT)?;
    assert_eq!(
        read(&mut pending, &locked, fx.timeline),
        field(Err(SubjectFieldReadError::KeyUnavailable))
    );
    destroy_subject_key(&mut pending, &mut fx.keys, request)?;
    drop(pending);
    let mut reopened = SqliteStore::open(path)?;
    reopened.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    assert_eq!(
        read(&mut reopened, &locked, fx.timeline),
        field(Ok(FieldStateV1::RedactedDestroyed))
    );
    Ok(())
}
