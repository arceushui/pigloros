//! Golden TEP1 payload and TRX1 envelope vectors at the public codec seam.
//!
//! The pinned values were produced independently of this crate from the RFC
//! 9180 base-mode suite (`DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`,
//! `ChaCha20Poly1305`), the reference BLAKE3 implementation, and the
//! `ChaCha12` keystream behind the seeded `StdRng`. They lock the exact wire
//! bytes, not only round-trip behavior.

use pos_core::{
    CanonicalBytes, EntityId, Event, EventId, EventOriginV1, Hash, KeyIdentityV1, KeyRoleV1, Kind,
    OwnerIdV1, RecipientKeyDescriptorV1, SchemaVersion, Seq, Signature, Timeline, TimelineExport,
    TimelineId, TimelineMeta, TimelineMode, WallTime,
};
use pos_crypto::recipient_export::{
    decrypt_timeline_export_v1, encrypt_timeline_export_v1, timeline_export_payload_digest_v1,
    RecipientTimelineExportV1,
};
use pos_crypto::recipient_key::derive_recipient_keypair_v1;
use rand::{rngs::StdRng, SeedableRng};
use ulid::Ulid;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const EXPORT_ID: [u8; 16] = [5; 16];
const RNG_SEED: [u8; 32] = [42; 32];

/// TEP1 for one unsigned Event (`unsigned`) and one signed Event (`signed`).
const GOLDEN_TEP1: &str = concat!(
    "8b44544550310150000000000000000000000000000000030166676f6c64656e",
    "5000000000000000000000000000000004f6f602f6828c500000000000000000",
    "000000000000006550000000000000000000000000000000c86a746573742e65",
    "76656e7448756e7369676e65640101f6f601f6f65820f052878538b9eabbed53",
    "e5bfba0f0eb38aacd467757a84ce847fd03992c47faf8c500000000000000000",
    "000000000000006650000000000000000000000000000000c86a746573742e65",
    "76656e74467369676e65640202f6f60158400606060606060606060606060606",
    "0606060606060606060606060606060606060606060606060606060606060606",
    "0606060606060606060606060606060606068366736f75726365020158202a99",
    "10f60de087519ec389d888bcf012357e29cb3a5f28af608f578673342084",
);
const GOLDEN_TEP1_DIGEST: &str = "c191b4c06d9a08a849b80ad65d9e190555c8c8be5d37dd83247b062f53c47666";
const RECIPIENT_PUBLIC_KEY: &str =
    "de8923a675d02180cdd7d0097ba404b9e1e2930d5665cba58d1765006361793b";

/// The two-chunk TRX1 seals a 70,314-byte TEP1 whose unsigned Event carries
/// 70,000 bytes of `0xa5`.
const TWO_CHUNK_TEP1_DIGEST: &str =
    "5e2114d9f7b8de234f44b09a6655e60aa5a440a3143010bee244c378652f823c";
const TWO_CHUNK_TRX1_LENGTH: usize = 70_523;
const TWO_CHUNK_TRX1_BLAKE3: &str =
    "c2a93f21cb00ceb02743e7f6fcd19e131704acd5bbbb4d2429b585507e4eabb5";
/// TRX1 fields 0-6: magic, suite, header, and the seeded HPKE `enc`.
const TWO_CHUNK_TRX1_PREFIX: &str = concat!(
    "88445452583101182001038a5005050505050505050505050505050505500000",
    "000000000000000000000000000302f6782a726563697069656e743a30303030",
    "3030303030303030303030303030303030303030303030303030303104015820",
    "de8923a675d02180cdd7d0097ba404b9e1e2930d5665cba58d1765006361793b",
    "1a000112aa025820c7b6de1dd76cb5323ef9aa4063c3142709fa312e18bf71ec",
    "6092d10d5012a115",
);
const TWO_CHUNK_ENC: &str = "c7b6de1dd76cb5323ef9aa4063c3142709fa312e18bf71ec6092d10d5012a115";

fn from_hex(value: &str) -> TestResult<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| -> TestResult<u8> { Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?) })
        .collect()
}

fn id(value: u128) -> Ulid {
    Ulid::from(value)
}

fn event(sequence: u64, payload: Vec<u8>, signed: bool) -> TestResult<Event> {
    let payload_hash = Hash::from_bytes(*blake3::hash(&payload).as_bytes());
    let signature_identity = if signed {
        Some(KeyIdentityV1::from_parts(
            OwnerIdV1::new("source")?,
            KeyRoleV1::TimelineIntegritySigning,
            1,
        ))
    } else {
        None
    };
    Ok(Event {
        id: EventId::from_ulid(id(100 + u128::from(sequence))),
        entity: EntityId::from_ulid(id(200)),
        event_type: Kind::new("test.event"),
        payload: CanonicalBytes::from_vec(payload),
        wall_time: WallTime::from_micros(sequence),
        seq: Seq::from_u64(sequence),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: signature_identity.map(|_| Signature::from_bytes([6; 64])),
        signature_identity,
        origin: None,
        payload_hash,
    })
}

/// One unsigned Event followed by one signed Event on a root Live Timeline.
fn export(unsigned_payload: Vec<u8>) -> TestResult<TimelineExport> {
    Ok(TimelineExport {
        timeline: Timeline {
            meta: TimelineMeta {
                id: TimelineId::from_ulid(id(3)),
                mode: TimelineMode::Live,
                name: Some("golden".to_owned()),
                owner: Some(EntityId::from_ulid(id(4))),
                fork_point: None,
            },
            head: Seq::from_u64(2),
        },
        events: vec![
            event(1, unsigned_payload, false)?,
            event(2, b"signed".to_vec(), true)?,
        ],
        parent_fork_hash: None,
    })
}

fn recipient() -> TestResult<(RecipientKeyDescriptorV1, [u8; 32])> {
    let (private, public) = derive_recipient_keypair_v1(&[9; 32]);
    assert_eq!(public.to_vec(), from_hex(RECIPIENT_PUBLIC_KEY)?);
    let descriptor = RecipientKeyDescriptorV1::for_grantee(EntityId::from_ulid(id(1)), 1, public)?;
    Ok((descriptor, private))
}

/// Decrypted Events carry the origin rebuilt from their own coordinates.
fn with_origins(mut source: TimelineExport) -> Vec<Event> {
    let timeline_id = source.timeline.id();
    for event in &mut source.events {
        event.origin = Some(EventOriginV1 {
            origin_timeline_id: timeline_id,
            origin_logical_seq: event.seq,
        });
    }
    source.events
}

#[test]
fn golden_tep1_pins_one_unsigned_and_one_signed_event() -> TestResult {
    let (recipient, private) = recipient()?;
    let source = export(b"unsigned".to_vec())?;
    let golden = from_hex(GOLDEN_TEP1)?;
    let mut rng = StdRng::from_seed(RNG_SEED);

    let encrypted = encrypt_timeline_export_v1(&source, recipient, EXPORT_ID, &mut rng)?;
    // The payload digest is BLAKE3 over the exact TEP1 bytes that were sealed.
    assert_eq!(
        encrypted.payload_digest,
        timeline_export_payload_digest_v1(&golden)
    );
    assert_eq!(
        encrypted.payload_digest.as_bytes().to_vec(),
        from_hex(GOLDEN_TEP1_DIGEST)?
    );
    assert_eq!(
        encrypted.envelope.header.payload_length,
        u64::try_from(golden.len())?
    );
    assert_eq!(encrypted.envelope.ciphertext_chunks.len(), 1);

    let decrypted =
        decrypt_timeline_export_v1(&encrypted.encode(), EXPORT_ID, recipient, &private)?;
    assert_eq!(decrypted.payload_digest, encrypted.payload_digest);
    assert_eq!(decrypted.export.timeline.meta, source.timeline.meta);
    assert_eq!(decrypted.export.timeline.head, source.timeline.head);
    assert_eq!(decrypted.export.events, with_origins(source));
    let events = &decrypted.export.events;
    assert!(events
        .first()
        .ok_or("unsigned event is absent")?
        .signature
        .is_none());
    assert!(events
        .get(1)
        .ok_or("signed event is absent")?
        .signature
        .is_some());
    Ok(())
}

#[test]
fn golden_trx1_pins_a_seeded_two_chunk_hpke_envelope() -> TestResult {
    let (recipient, private) = recipient()?;
    let source = export(vec![0xa5; 70_000])?;
    let mut rng = StdRng::from_seed(RNG_SEED);

    let encrypted = encrypt_timeline_export_v1(&source, recipient, EXPORT_ID, &mut rng)?;
    let encoded = encrypted.encode();
    assert_eq!(
        encrypted.payload_digest.as_bytes().to_vec(),
        from_hex(TWO_CHUNK_TEP1_DIGEST)?
    );
    assert_eq!(encrypted.envelope.enc.to_vec(), from_hex(TWO_CHUNK_ENC)?);
    assert_eq!(
        encrypted
            .envelope
            .ciphertext_chunks
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>(),
        [65_552, 4_794]
    );
    let prefix = from_hex(TWO_CHUNK_TRX1_PREFIX)?;
    assert_eq!(encoded.get(..prefix.len()), Some(prefix.as_slice()));
    assert_eq!(encoded.len(), TWO_CHUNK_TRX1_LENGTH);
    assert_eq!(
        blake3::hash(&encoded).as_bytes().to_vec(),
        from_hex(TWO_CHUNK_TRX1_BLAKE3)?
    );

    assert_eq!(
        RecipientTimelineExportV1::decode(&encoded)?,
        encrypted.envelope
    );
    let decrypted = decrypt_timeline_export_v1(&encoded, EXPORT_ID, recipient, &private)?;
    assert_eq!(decrypted.payload_digest, encrypted.payload_digest);
    assert_eq!(decrypted.export.events, with_origins(source));
    Ok(())
}
