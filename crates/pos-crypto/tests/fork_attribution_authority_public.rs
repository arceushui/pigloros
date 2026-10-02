//! Public-seam tests for ADR-105 `FAE1` issuer signature verification.

use ed25519_dalek::{Signer, SigningKey};
use pos_core::{
    CanonicalBytes, EntityId, EventId, ForkAttributionAuthorityEnvelopeInputV1,
    ForkAttributionAuthorityEnvelopeV1, ForkAttributionAuthorityRecordsV1,
    ForkAttributionAuthorityUnsignedEnvelopeV1, ForkAttributionClassifierRecordsV1,
    ForkAttributionIssuerPolicyEntryV1, ForkAttributionIssuerPolicyInputV1,
    ForkAttributionIssuerPolicyV1, ForkAttributionIssuerStateV1, ForkAttributionIssuerV1,
    ForkEventEvidenceV1, ForkTimelineImportInputV1, ForkTimelineImportV1, Hash,
    ImportedKeyRecordV1, ImportedKeyTombstoneV1, KeyIdentityV1, KeyRoleV1, Kind, PublicKey, Seq,
    Signature, TimelineEventEnvelopeInputV1, TimelineEventEnvelopeV1, TimelineId, WallTime,
};
use pos_crypto::fork_attribution_authority::{
    verify_fork_attribution_authority_envelope_signature_v1, verify_fork_attribution_issuer_key_v1,
    verify_fork_attribution_issuer_policy_keys_v1,
    ForkAttributionAuthoritySignatureErrorV1 as SignatureError,
};
use ulid::Ulid;

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

/// A compressed point that fails Ed25519 decompression.
const INVALID_POINT: [u8; 32] = {
    let mut bytes = [0; 32];
    bytes[31] = 0xff;
    bytes
};
/// The identity point: a valid encoding of small order.
const WEAK_POINT: [u8; 32] = {
    let mut bytes = [0; 32];
    bytes[0] = 1;
    bytes
};

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

const fn timeline_id(value: u8) -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([value; 16]))
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn issuer(key: [u8; 32]) -> Fallible<ForkAttributionIssuerV1> {
    Ok(ForkAttributionIssuerV1::new(
        "issuer-a",
        1,
        PublicKey::from_bytes(key),
    )?)
}

fn attribution_identity() -> KeyIdentityV1 {
    KeyIdentityV1::new("creator-a", KeyRoleV1::SubjectAttributionSigning, 1)
}

fn evidence(seq: u64, payload: &[u8]) -> Fallible<ForkEventEvidenceV1> {
    let payload = CanonicalBytes::from_vec(payload.to_vec());
    let envelope = TimelineEventEnvelopeV1::new(
        TimelineEventEnvelopeInputV1 {
            identity: KeyIdentityV1::new("timeline-owner", KeyRoleV1::TimelineIntegritySigning, 1),
            origin_timeline_id: timeline_id(2),
            event_id: EventId::from_ulid(Ulid::from_parts(seq, 7)),
            origin_logical_seq: Seq::from_u64(seq),
            entity_id: EntityId::from_ulid(Ulid::from_parts(1, 2)),
            event_type: Kind::new("fork.test"),
            schema_version: 1,
            wall_time: WallTime::from_micros(1_000 + seq),
            causation_id: None,
            correlation_id: None,
        },
        &payload,
    )?;
    Ok(ForkEventEvidenceV1::new(
        envelope,
        payload,
        Signature::from_bytes([0x77; 64]),
    )?)
}

fn fork(local_head: u64) -> Fallible<ForkTimelineImportV1> {
    Ok(ForkTimelineImportV1::new(ForkTimelineImportInputV1 {
        child_timeline_id: timeline_id(2),
        name: None,
        owner: None,
        parent_timeline_id: timeline_id(1),
        parent_cut: 4,
        local_head,
        parent_chain_hash: hash(0x66),
    })?)
}

/// Two Events, one intervention, a classifier, and a destroyed source key.
fn input(issuer: ForkAttributionIssuerV1) -> Fallible<ForkAttributionAuthorityEnvelopeInputV1> {
    Ok(ForkAttributionAuthorityEnvelopeInputV1 {
        import_operation_id: hash(0x11),
        issuer,
        issuer_policy_digest: hash(0x33),
        records: ForkAttributionAuthorityRecordsV1 {
            principal_owner_binding: b"POB1".to_vec(),
            fork_admission: b"FAR1".to_vec(),
            event_origins: vec![b"EOR1-a".to_vec(), b"EOR1-b".to_vec()],
            intervention_admissions: vec![b"FIA1".to_vec()],
            publication_operation: b"FPO1".to_vec(),
            publication_binding: b"FPB1".to_vec(),
            publication_artifact: b"FPA1".to_vec(),
        },
        key_record: ImportedKeyRecordV1::new(
            attribution_identity(),
            None,
            PublicKey::from_bytes([0x55; 32]),
        )?,
        key_tombstone: Some(ImportedKeyTombstoneV1::new(
            attribution_identity(),
            hash(0x44),
            hash(0x45),
            hash(0x46),
        )?),
        event_evidence: vec![evidence(5, b"first")?, evidence(6, b"second")?],
        timeline_import: fork(2)?,
        classifier: Some(ForkAttributionClassifierRecordsV1 {
            source: b"FCS1".to_vec(),
            table: b"FCT1".to_vec(),
            registration: b"FCR1".to_vec(),
        }),
        append_operations: vec![b"FOP1-a".to_vec(), b"FOP1-b".to_vec()],
    })
}

fn sign(
    input: ForkAttributionAuthorityEnvelopeInputV1,
    key: &SigningKey,
) -> Fallible<ForkAttributionAuthorityEnvelopeV1> {
    let unsigned = ForkAttributionAuthorityUnsignedEnvelopeV1::new(input)?;
    let signature = key.sign(&unsigned.signature_message());
    Ok(ForkAttributionAuthorityEnvelopeV1::new(
        unsigned,
        Signature::from_bytes(signature.to_bytes()),
    ))
}

fn valid_input() -> Fallible<ForkAttributionAuthorityEnvelopeInputV1> {
    input(issuer(signing_key(7).verifying_key().to_bytes())?)
}

#[test]
fn issuer_signature_verifies_over_the_exact_unsigned_preimage() -> Fallible<()> {
    let key = signing_key(7);
    let envelope = sign(valid_input()?, &key)?;
    assert_eq!(
        verify_fork_attribution_authority_envelope_signature_v1(&envelope),
        Ok(())
    );
    let decoded =
        ForkAttributionAuthorityEnvelopeV1::from_canonical_cbor(&envelope.to_canonical_cbor())?;
    assert_eq!(
        verify_fork_attribution_authority_envelope_signature_v1(&decoded),
        Ok(())
    );

    let mut tampered = *envelope.signature().as_bytes();
    tampered[0] ^= 1;
    let forged = ForkAttributionAuthorityEnvelopeV1::new(
        envelope.unsigned().clone(),
        Signature::from_bytes(tampered),
    );
    let unsigned_only = key.sign(envelope.unsigned().canonical_bytes());
    let undomained = ForkAttributionAuthorityEnvelopeV1::new(
        envelope.unsigned().clone(),
        Signature::from_bytes(unsigned_only.to_bytes()),
    );
    let foreign = sign(valid_input()?, &signing_key(8))?;
    for candidate in [forged, undomained, foreign] {
        assert_eq!(
            verify_fork_attribution_authority_envelope_signature_v1(&candidate),
            Err(SignatureError::InvalidSignature)
        );
    }
    Ok(())
}

/// One input per signed field 2–21; fields 5 and 6 are derived from these.
fn field_mutations() -> Fallible<Vec<ForkAttributionAuthorityEnvelopeInputV1>> {
    let base = valid_input()?;
    let mut mutations = Vec::new();
    for field in 2..=21 {
        let mut changed = base.clone();
        let records = &mut changed.records;
        match field {
            2 => changed.import_operation_id = hash(0x12),
            3 => {
                changed.issuer =
                    ForkAttributionIssuerV1::new("issuer-b", 1, base.issuer.public_key())?
            }
            4 => changed.issuer_policy_digest = hash(0x34),
            5 | 6 => continue,
            7 => records.principal_owner_binding.push(0),
            8 => records.fork_admission.push(0),
            9 => records.event_origins[1].push(0),
            10 => records.intervention_admissions[0].push(0),
            11 => records.publication_operation.push(0),
            12 => records.publication_binding.push(0),
            13 => records.publication_artifact.push(0),
            14 | 15 => {
                changed.key_tombstone = Some(ImportedKeyTombstoneV1::new(
                    attribution_identity(),
                    hash(0x47),
                    hash(0x45),
                    hash(0x46),
                )?);
            }
            16 => changed.event_evidence[1] = evidence(6, b"other")?,
            17 => changed.timeline_import = fork(3)?,
            21 => changed.append_operations[0].push(0),
            _ => {
                let classifier = changed.classifier.as_mut().ok_or("classifier")?;
                match field {
                    18 => classifier.source.push(0),
                    19 => classifier.table.push(0),
                    _ => classifier.registration.push(0),
                }
            }
        }
        mutations.push(changed);
    }
    let mut live = base;
    live.key_record = ImportedKeyRecordV1::new(
        attribution_identity(),
        Some(hash(0x44)),
        PublicKey::from_bytes([0x55; 32]),
    )?;
    live.key_tombstone = None;
    mutations.push(live);
    Ok(mutations)
}

#[test]
fn issuer_signature_covers_every_preimage_field() -> Fallible<()> {
    let original = sign(valid_input()?, &signing_key(7))?;
    let mutations = field_mutations()?;
    assert_eq!(mutations.len(), 19);
    for (index, mutation) in mutations.into_iter().enumerate() {
        let unsigned = ForkAttributionAuthorityUnsignedEnvelopeV1::new(mutation)?;
        assert_ne!(
            unsigned.canonical_bytes(),
            original.unsigned().canonical_bytes()
        );
        let replayed = ForkAttributionAuthorityEnvelopeV1::new(unsigned, original.signature());
        assert_eq!(
            verify_fork_attribution_authority_envelope_signature_v1(&replayed),
            Err(SignatureError::InvalidSignature),
            "mutation {index}"
        );
    }
    Ok(())
}

#[test]
fn invalid_or_weak_issuer_keys_never_verify() -> Fallible<()> {
    let valid = issuer(signing_key(7).verifying_key().to_bytes())?;
    assert_eq!(verify_fork_attribution_issuer_key_v1(&valid), Ok(()));
    for key in [INVALID_POINT, WEAK_POINT] {
        let rejected = issuer(key)?;
        assert_eq!(
            verify_fork_attribution_issuer_key_v1(&rejected),
            Err(SignatureError::InvalidIssuerKey)
        );
        let envelope = sign(input(rejected)?, &signing_key(7))?;
        assert_eq!(
            verify_fork_attribution_authority_envelope_signature_v1(&envelope),
            Err(SignatureError::InvalidIssuerKey)
        );
    }
    let policy = |weak: [u8; 32]| -> Fallible<ForkAttributionIssuerPolicyV1> {
        Ok(ForkAttributionIssuerPolicyV1::new(
            ForkAttributionIssuerPolicyInputV1 {
                scope: "scope-a".to_owned(),
                generation: 1,
                previous_policy_digest: None,
                entries: vec![
                    ForkAttributionIssuerPolicyEntryV1 {
                        issuer: valid.clone(),
                        state: ForkAttributionIssuerStateV1::Active,
                    },
                    ForkAttributionIssuerPolicyEntryV1 {
                        issuer: ForkAttributionIssuerV1::new(
                            "issuer-b",
                            1,
                            PublicKey::from_bytes(weak),
                        )?,
                        state: ForkAttributionIssuerStateV1::Retired,
                    },
                ],
            },
        )?)
    };
    let healthy = policy(signing_key(9).verifying_key().to_bytes())?;
    assert_eq!(
        verify_fork_attribution_issuer_policy_keys_v1(&healthy),
        Ok(())
    );
    assert_eq!(
        verify_fork_attribution_issuer_policy_keys_v1(&policy(WEAK_POINT)?),
        Err(SignatureError::InvalidIssuerKey)
    );
    Ok(())
}
