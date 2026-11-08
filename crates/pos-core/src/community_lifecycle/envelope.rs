//! Exact COH1/COE1 framing and local context bindings; never key-use authority.

use super::{
    bounded_bytes, canonical_end, digest, encode_coordinates, fixed_bytes, read_coordinates,
    read_hash, read_head, record_cursor, record_prefix, validate_coordinates, validate_horizon,
    CommunityLifecycleErrorV1 as Error, CommunityPassKeyV1, Result,
    MAX_COMMUNITY_PASS_KEY_BYTES_V1,
};
use crate::{
    encode_bytes, encode_hash, encode_head, CborCursor, Hash, KeyIdentityV1, KeyRegistryErrorV1,
    KeyRoleV1, OwnerIdV1, TimelineId,
};
use zeroize::Zeroizing;

/// Maximum plaintext in one admitted community envelope: 3 MiB.
pub const MAX_COMMUNITY_ENVELOPE_PLAINTEXT_BYTES_V1: usize = 3 * 1024 * 1024;
const MAX_HEADER: usize = 1024;
const MAX_ENVELOPE: usize = 3_147_840;
const MAX_CIPHERTEXT: usize = MAX_COMMUNITY_ENVELOPE_PLAINTEXT_BYTES_V1 + 16;

/// Closed purpose/key partition. A decoded value grants no use permission.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityArtifactPurposeV1 {
    /// Code0: State, inputs and required execution provenance.
    ExecutionState,
    /// Code1: optional validated presentation traces.
    PresentationTrace,
    /// Code2: retained tuple/output/metering recording.
    ReplayEvidence,
    /// Code3: closed host lifecycle metadata.
    LifecycleControl,
}

impl CommunityArtifactPurposeV1 {
    /// Return the fixed ADR-128 purpose code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::ExecutionState => 0,
            Self::PresentationTrace => 1,
            Self::ReplayEvidence => 2,
            Self::LifecycleControl => 3,
        }
    }

    const fn admits(self, kind: CommunityArtifactKindV1) -> bool {
        use CommunityArtifactKindV1 as K;
        matches!(
            (self, kind),
            (
                Self::ExecutionState,
                K::StateContent
                    | K::StateRevisionOrHead
                    | K::PreparedInvocation
                    | K::ExecutionProvenance
            ) | (Self::PresentationTrace, K::TraceAnnotation)
                | (Self::ReplayEvidence, K::ReplayReceiptOrRoot)
                | (Self::LifecycleControl, K::LifecycleControl)
                | (_, K::BoundedRecordBundle | K::ClassificationProof)
        )
    }
}

/// Closed plaintext kind; bundles still require their actual schema extractor.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityArtifactKindV1 {
    /// Code0.
    StateContent,
    /// Code1.
    StateRevisionOrHead,
    /// Code2.
    PreparedInvocation,
    /// Code3.
    ExecutionProvenance,
    /// Code4.
    TraceAnnotation,
    /// Code5.
    ReplayReceiptOrRoot,
    /// Code6.
    LifecycleControl,
    /// Code7; not permission for arbitrary nested schemas.
    BoundedRecordBundle,
    /// Code8.
    ClassificationProof,
}

impl CommunityArtifactKindV1 {
    /// Return the fixed ADR-128 record-kind code.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::StateContent => 0,
            Self::StateRevisionOrHead => 1,
            Self::PreparedInvocation => 2,
            Self::ExecutionProvenance => 3,
            Self::TraceAnnotation => 4,
            Self::ReplayReceiptOrRoot => 5,
            Self::LifecycleControl => 6,
            Self::BoundedRecordBundle => 7,
            Self::ClassificationProof => 8,
        }
    }
}

/// Exact key-operation identity; initialization/control IDs are raw16 bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityArtifactOperationV1 {
    /// Code0; carries the exact CPK1, not an Event/Tick coordinate.
    Pass(CommunityPassKeyV1),
    /// Code1; original nonzero host-issued initialization ID.
    Initialization([u8; 16]),
    /// Code2; original nonzero host-issued control/protection ID.
    Control([u8; 16]),
}

/// Structural header fields; none is independently verified admission evidence.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityArtifactHeaderInputV1 {
    /// Actual envelope/key Timeline, including a metadata anchor when admitted.
    pub timeline: TimelineId,
    /// Actual envelope/key generation.
    pub generation: [u8; 16],
    /// Separate operation/purpose key partition.
    pub purpose: CommunityArtifactPurposeV1,
    /// Original pass or control coordinate.
    pub operation: CommunityArtifactOperationV1,
    /// Plaintext format category, not a substitute for its schema validator.
    pub record_kind: CommunityArtifactKindV1,
    /// Exact admitted scope cover identity.
    pub scope_cover_digest: Hash,
    /// Original positive i64-bounded evidence horizon.
    pub evidence_not_after_micros: u64,
}

/// Canonical COH1 with a derived exact owner spelling and literal role7/epoch1.
/// No `Debug`, `Clone` or Serde alternative exposes the context identities.
pub struct CommunityArtifactHeaderV1 {
    input: CommunityArtifactHeaderInputV1,
    owner: OwnerIdV1,
}

impl CommunityArtifactHeaderV1 {
    /// Validate local context/purpose bindings and derive the fixed owner ID.
    ///
    /// # Errors
    /// Rejects zero/foreign coordinates, IDs and scope; incompatible purposes;
    /// or an out-of-range evidence horizon. No live key/admission is created.
    pub fn new(input: CommunityArtifactHeaderInputV1) -> Result<Self> {
        validate_coordinates(input.timeline, input.generation)
            .and_then(|()| validate_operation(input.operation, input.timeline, input.generation))
            .and_then(|()| {
                if input.scope_cover_digest == Hash::zero()
                    || !input.purpose.admits(input.record_kind)
                {
                    return Err(Error::InvalidBinding);
                }
                validate_horizon(input.evidence_not_after_micros)
            })
            .and_then(|()| derive_owner(input).map(|owner| Self { input, owner }))
    }

    /// Borrow the exact untrusted structural fields.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityArtifactHeaderInputV1 {
        &self.input
    }

    /// Return the derived identity data, never a qualified material handle.
    #[must_use]
    pub const fn key_identity(&self) -> KeyIdentityV1 {
        KeyIdentityV1::from_parts(self.owner, KeyRoleV1::CommunityArtifactEncryption, 1)
    }

    /// Encode the exact thirteen-field COH1 in a pre-sized zeroizing buffer.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(MAX_HEADER));
        record_prefix(&mut out, 13, *b"COH1");
        encode_coordinates(&mut out, input.timeline, input.generation);
        encode_head(&mut out, 0, u64::from(input.purpose.code()));
        encode_operation(&mut out, input.operation);
        encode_head(&mut out, 0, u64::from(input.record_kind.code()));
        encode_bytes(&mut out, self.owner.as_str().as_bytes(), 3);
        out.extend_from_slice(&[7, 1]);
        encode_hash(&mut out, input.scope_cover_digest);
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// Derive the exact 32-byte `EnvelopeContext` AAD from canonical COH1.
    #[must_use]
    pub fn associated_data_digest(&self) -> Hash {
        let bytes = self.to_canonical_cbor();
        digest(b"PiglorOS.Community.EnvelopeContext.v1\0", &bytes)
    }

    /// Decode preferred COH1 and require its owner/role/epoch to match exactly.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, oversized, unsupported or trailing
    /// records, bad context/purpose bindings and any alternate owner spelling.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, MAX_HEADER, 13, *b"COH1").and_then(|mut cursor| {
            read_header(&mut cursor).and_then(|(input, owner)| {
                Self::new(input).and_then(|header| {
                    if header.owner != owner {
                        return Err(Error::InvalidBinding);
                    }
                    canonical_end(&cursor).map(|()| header)
                })
            })
        })
    }
}

/// Borrowed COE1 ciphertext. Parsing does not authenticate it or expose a key.
pub struct CommunityEncryptedEnvelopeV1<'a> {
    header: CommunityArtifactHeaderV1,
    nonce: [u8; 12],
    ciphertext_and_tag: &'a [u8],
}

impl<'a> CommunityEncryptedEnvelopeV1<'a> {
    /// Bind structural header/nonce/ciphertext parts without claiming validity.
    ///
    /// # Errors
    /// Rejects a ciphertext without its16-byte tag or above the3MiB payload cap.
    pub fn new(
        header: CommunityArtifactHeaderV1,
        nonce: [u8; 12],
        ciphertext_and_tag: &'a [u8],
    ) -> Result<Self> {
        if (16..=MAX_CIPHERTEXT).contains(&ciphertext_and_tag.len()) {
            Ok(Self {
                header,
                nonce,
                ciphertext_and_tag,
            })
        } else {
            Err(Error::BoundsExceeded)
        }
    }

    /// Borrow the structural header; current authority is still unverified.
    #[must_use]
    pub const fn header(&self) -> &CommunityArtifactHeaderV1 {
        &self.header
    }

    /// Borrow the exact nonce; the decoder cannot prove its entropy source.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    /// Borrow exact encrypted bytes and their postfix tag from the input range.
    #[must_use]
    pub const fn ciphertext_and_tag(&self) -> &'a [u8] {
        self.ciphertext_and_tag
    }

    /// Encode exact five-field COE1 with room reserved before all prefix writes.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let header = self.header.to_canonical_cbor();
        let mut out = Zeroizing::new(Vec::with_capacity(
            self.ciphertext_and_tag.len() + MAX_HEADER + 64,
        ));
        record_prefix(&mut out, 5, *b"COE1");
        encode_bytes(&mut out, &header, 2);
        encode_bytes(&mut out, &self.nonce, 2);
        encode_bytes(&mut out, self.ciphertext_and_tag, 2);
        out
    }

    /// Derive exact COE1 physical identity without claiming authentication.
    #[must_use]
    pub fn address(&self) -> Hash {
        let bytes = self.to_canonical_cbor();
        digest(b"PiglorOS.Community.Envelope.v1\0", &bytes)
    }

    /// Decode one whole COE1 while borrowing its potentially large cipher range.
    ///
    /// # Errors
    /// Rejects invalid nested COH1, nonce/framing, sizes and trailing bytes.
    /// Successful parsing does not prove AEAD authentication or admission.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(bytes, MAX_ENVELOPE, 5, *b"COE1").and_then(|mut cursor| {
            bounded_bytes(&mut cursor, MAX_HEADER)
                .and_then(CommunityArtifactHeaderV1::from_canonical_cbor)
                .and_then(|header| fixed_bytes(&mut cursor).map(|nonce| (header, nonce)))
                .and_then(|(header, nonce)| {
                    bounded_bytes(&mut cursor, MAX_CIPHERTEXT)
                        .and_then(|ciphertext| Self::new(header, nonce, ciphertext))
                })
                .and_then(|envelope| canonical_end(&cursor).map(|()| envelope))
        })
    }
}

fn validate_operation(
    operation: CommunityArtifactOperationV1,
    timeline: TimelineId,
    generation: [u8; 16],
) -> Result<()> {
    let invalid = match operation {
        CommunityArtifactOperationV1::Pass(key) => {
            key.timeline() != timeline || key.generation() != generation
        }
        CommunityArtifactOperationV1::Initialization(id)
        | CommunityArtifactOperationV1::Control(id) => id == [0; 16],
    };
    if invalid {
        Err(Error::InvalidBinding)
    } else {
        Ok(())
    }
}

fn encode_operation(out: &mut Vec<u8>, operation: CommunityArtifactOperationV1) {
    match operation {
        CommunityArtifactOperationV1::Pass(key) => {
            out.push(0);
            let key_bytes = Zeroizing::new(key.to_canonical_cbor());
            encode_bytes(out, &key_bytes, 2);
        }
        CommunityArtifactOperationV1::Initialization(id) => {
            out.push(1);
            encode_bytes(out, &id, 2);
        }
        CommunityArtifactOperationV1::Control(id) => {
            out.push(2);
            encode_bytes(out, &id, 2);
        }
    }
}

fn derive_owner(input: CommunityArtifactHeaderInputV1) -> Result<OwnerIdV1> {
    let mut text = Zeroizing::new(String::with_capacity(128));
    text.push_str("community:");
    append_hex(&mut text, &input.timeline.inner().to_bytes());
    text.push(':');
    append_hex(&mut text, &input.generation);
    text.push(':');
    text.push(char::from(b'0' + input.purpose.code()));
    match input.operation {
        CommunityArtifactOperationV1::Pass(key) => {
            text.push_str(":p:");
            append_hex(&mut text, &key.ordinal().to_be_bytes());
        }
        CommunityArtifactOperationV1::Initialization(id) => {
            text.push_str(":i:");
            append_hex(&mut text, &id);
        }
        CommunityArtifactOperationV1::Control(id) => {
            text.push_str(":c:");
            append_hex(&mut text, &id);
        }
    }
    OwnerIdV1::from_borrowed(&text).map_err(owner_error)
}

pub(super) fn append_hex(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 15)]));
    }
}

const fn owner_error(_: KeyRegistryErrorV1) -> Error {
    Error::InvalidBinding
}

pub(super) fn read_purpose(cursor: &mut CborCursor<'_>) -> Result<CommunityArtifactPurposeV1> {
    read_head(cursor, 0).and_then(|code| match code {
        0 => Ok(CommunityArtifactPurposeV1::ExecutionState),
        1 => Ok(CommunityArtifactPurposeV1::PresentationTrace),
        2 => Ok(CommunityArtifactPurposeV1::ReplayEvidence),
        3 => Ok(CommunityArtifactPurposeV1::LifecycleControl),
        _ => Err(Error::InvalidEncoding),
    })
}

pub(super) fn read_kind(cursor: &mut CborCursor<'_>) -> Result<CommunityArtifactKindV1> {
    read_head(cursor, 0).and_then(|code| match code {
        0 => Ok(CommunityArtifactKindV1::StateContent),
        1 => Ok(CommunityArtifactKindV1::StateRevisionOrHead),
        2 => Ok(CommunityArtifactKindV1::PreparedInvocation),
        3 => Ok(CommunityArtifactKindV1::ExecutionProvenance),
        4 => Ok(CommunityArtifactKindV1::TraceAnnotation),
        5 => Ok(CommunityArtifactKindV1::ReplayReceiptOrRoot),
        6 => Ok(CommunityArtifactKindV1::LifecycleControl),
        7 => Ok(CommunityArtifactKindV1::BoundedRecordBundle),
        8 => Ok(CommunityArtifactKindV1::ClassificationProof),
        _ => Err(Error::InvalidEncoding),
    })
}

fn read_operation(cursor: &mut CborCursor<'_>) -> Result<CommunityArtifactOperationV1> {
    read_head(cursor, 0).and_then(|kind| {
        bounded_bytes(cursor, MAX_COMMUNITY_PASS_KEY_BYTES_V1).and_then(|bytes| match kind {
            0 => CommunityPassKeyV1::from_canonical_cbor(bytes)
                .map(CommunityArtifactOperationV1::Pass),
            1 | 2 => <[u8; 16]>::try_from(bytes)
                .map_err(|_| Error::InvalidEncoding)
                .map(|id| {
                    if kind == 1 {
                        CommunityArtifactOperationV1::Initialization(id)
                    } else {
                        CommunityArtifactOperationV1::Control(id)
                    }
                }),
            _ => Err(Error::InvalidEncoding),
        })
    })
}

pub(super) fn read_owner(cursor: &mut CborCursor<'_>) -> Result<OwnerIdV1> {
    read_head(cursor, 3).and_then(|length| {
        if length > 128 {
            return Err(Error::BoundsExceeded);
        }
        cursor
            .take(usize::try_from(length).unwrap_or(usize::MAX))
            .map_err(Error::from)
            .and_then(|bytes| std::str::from_utf8(bytes).map_err(|_| Error::InvalidEncoding))
            .and_then(|text| OwnerIdV1::from_borrowed(text).map_err(owner_error))
    })
}

pub(super) fn read_role_epoch(cursor: &mut CborCursor<'_>) -> Result<()> {
    read_head(cursor, 0).and_then(|role| {
        read_head(cursor, 0).and_then(|epoch| {
            if role == 7 && epoch == 1 {
                Ok(())
            } else {
                Err(Error::InvalidBinding)
            }
        })
    })
}

fn read_header(cursor: &mut CborCursor<'_>) -> Result<(CommunityArtifactHeaderInputV1, OwnerIdV1)> {
    read_coordinates(cursor).and_then(|(timeline, generation)| {
        read_purpose(cursor).and_then(|purpose| {
            read_operation(cursor).and_then(|operation| {
                read_kind(cursor).and_then(|record_kind| {
                    read_owner(cursor).and_then(|owner| {
                        read_role_epoch(cursor).and_then(|()| {
                            read_hash(cursor).and_then(|scope_cover_digest| {
                                read_head(cursor, 0).map(|evidence_not_after_micros| {
                                    (
                                        CommunityArtifactHeaderInputV1 {
                                            timeline,
                                            generation,
                                            purpose,
                                            operation,
                                            record_kind,
                                            scope_cover_digest,
                                            evidence_not_after_micros,
                                        },
                                        owner,
                                    )
                                })
                            })
                        })
                    })
                })
            })
        })
    })
}
