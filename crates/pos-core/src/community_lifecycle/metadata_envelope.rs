//! Closed CNE1 framing; parsing never authenticates ciphertext or current use.

use super::metadata_scope::MAX_SCOPE_ENCODING;
use super::{
    bounded_bytes, canonical_end, digest, fixed_bytes, record_cursor, record_prefix,
    CommunityArtifactKindV1, CommunityArtifactOperationV1, CommunityArtifactPurposeV1,
    CommunityEncryptedEnvelopeV1, CommunityLifecycleErrorV1 as Error, CommunityMetadataScopeV1,
    Result,
};
use crate::{encode_bytes, Hash};
use zeroize::Zeroizing;

const MAX_RECORD: usize = 4_194_304;
const MAX_ENVELOPE: usize = 3_147_840;
const _: () = assert!(MAX_SCOPE_ENCODING + MAX_ENVELOPE + 32 < MAX_RECORD);

/// Exact ADR-129 native metadata whitelist, not an extensible decoder registry.
/// The schema label alone does not verify a decrypted body's semantics.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityMetadataSchemaV1 {
    /// Original owner binding.
    Cob1,
    /// Actual input scope binding.
    Csb1,
    /// Original provenance.
    Cpv1,
    /// Current authority evidence.
    Cau1,
    /// Current view, transient by default.
    Cav1,
    /// Identity/allocation selection.
    Csi1,
    /// Copy inventory.
    Cci1,
    /// Materialization binding.
    Cmi1,
    /// Dependency commit.
    Cpd1,
    /// Pre-Reserve budget forecast.
    Cbq1,
    /// Durable profile.
    Cdp1,
    /// Member binding.
    Cmb1,
    /// Negotiated tuple.
    Cnt1,
    /// Member State/progress.
    Cms1,
    /// Selected head.
    Csh1,
    /// Host progress.
    Cst1,
    /// Generation request.
    Cgi1,
    /// Generation admission.
    Cga1,
    /// Generation control.
    Cgc1,
    /// Reservation request.
    Cri1,
    /// Reservation result.
    Cpr1,
    /// Sealed result.
    Cps1,
    /// Committed pass.
    Cpc1,
    /// Aborted pass.
    Cab1,
    /// Quarantine key.
    Cqk1,
    /// Quarantine control.
    Cqc1,
    /// Quarantine revision.
    Cqr1,
    /// Quarantine outcome.
    Cqo1,
    /// Native graph root.
    Cgr1,
    /// Factual Tick bridge.
    Ctb1,
    /// Original metadata policy.
    Nmp1,
}

impl CommunityMetadataSchemaV1 {
    /// Exact four-byte wire label, never a Rust discriminant or debug spelling.
    #[must_use]
    pub const fn magic(self) -> [u8; 4] {
        match self {
            Self::Cob1 => *b"COB1",
            Self::Csb1 => *b"CSB1",
            Self::Cpv1 => *b"CPV1",
            Self::Cau1 => *b"CAU1",
            Self::Cav1 => *b"CAV1",
            Self::Csi1 => *b"CSI1",
            Self::Cci1 => *b"CCI1",
            Self::Cmi1 => *b"CMI1",
            Self::Cpd1 => *b"CPD1",
            Self::Cbq1 => *b"CBQ1",
            Self::Cdp1 => *b"CDP1",
            Self::Cmb1 => *b"CMB1",
            Self::Cnt1 => *b"CNT1",
            Self::Cms1 => *b"CMS1",
            Self::Csh1 => *b"CSH1",
            Self::Cst1 => *b"CST1",
            Self::Cgi1 => *b"CGI1",
            Self::Cga1 => *b"CGA1",
            Self::Cgc1 => *b"CGC1",
            Self::Cri1 => *b"CRI1",
            Self::Cpr1 => *b"CPR1",
            Self::Cps1 => *b"CPS1",
            Self::Cpc1 => *b"CPC1",
            Self::Cab1 => *b"CAB1",
            Self::Cqk1 => *b"CQK1",
            Self::Cqc1 => *b"CQC1",
            Self::Cqr1 => *b"CQR1",
            Self::Cqo1 => *b"CQO1",
            Self::Cgr1 => *b"CGR1",
            Self::Ctb1 => *b"CTB1",
            Self::Nmp1 => *b"NMP1",
        }
    }

    /// Resolve only an exact admitted metadata label. Data/failure/claim and
    /// clear bootstrap schemas cannot be imported under this wrapper.
    #[must_use]
    pub const fn from_magic(magic: [u8; 4]) -> Option<Self> {
        match &magic {
            b"COB1" => Some(Self::Cob1),
            b"CSB1" => Some(Self::Csb1),
            b"CPV1" => Some(Self::Cpv1),
            b"CAU1" => Some(Self::Cau1),
            b"CAV1" => Some(Self::Cav1),
            b"CSI1" => Some(Self::Csi1),
            b"CCI1" => Some(Self::Cci1),
            b"CMI1" => Some(Self::Cmi1),
            b"CPD1" => Some(Self::Cpd1),
            b"CBQ1" => Some(Self::Cbq1),
            b"CDP1" => Some(Self::Cdp1),
            b"CMB1" => Some(Self::Cmb1),
            b"CNT1" => Some(Self::Cnt1),
            b"CMS1" => Some(Self::Cms1),
            b"CSH1" => Some(Self::Csh1),
            b"CST1" => Some(Self::Cst1),
            b"CGI1" => Some(Self::Cgi1),
            b"CGA1" => Some(Self::Cga1),
            b"CGC1" => Some(Self::Cgc1),
            b"CRI1" => Some(Self::Cri1),
            b"CPR1" => Some(Self::Cpr1),
            b"CPS1" => Some(Self::Cps1),
            b"CPC1" => Some(Self::Cpc1),
            b"CAB1" => Some(Self::Cab1),
            b"CQK1" => Some(Self::Cqk1),
            b"CQC1" => Some(Self::Cqc1),
            b"CQR1" => Some(Self::Cqr1),
            b"CQO1" => Some(Self::Cqo1),
            b"CGR1" => Some(Self::Cgr1),
            b"CTB1" => Some(Self::Ctb1),
            b"NMP1" => Some(Self::Nmp1),
            _ => None,
        }
    }
}

/// Borrowed CNE1 ciphertext and minimal scope cover, without authentication.
///
/// The concrete owner must first obtain current metadata service authority,
/// authenticate the ciphertext and validate the exact plaintext schema/body
/// locator. Service inspection still cannot release State/guest input bytes.
pub struct CommunityMetadataEnvelopeV1<'a> {
    schema: CommunityMetadataSchemaV1,
    scope_bytes: &'a [u8],
    envelope_bytes: &'a [u8],
    scope: CommunityMetadataScopeV1<'a>,
    envelope: CommunityEncryptedEnvelopeV1<'a>,
}

impl<'a> CommunityMetadataEnvelopeV1<'a> {
    /// Bind the actual canonical scope cover to the metadata-only control header.
    ///
    /// # Errors
    /// Rejects malformed scope/envelope bytes, wrong purpose/kind/operation,
    /// anchor Timeline/generation/scope mismatch or an overlong metadata horizon.
    /// Valid framing does not prove ciphertext integrity, actual scope or grant.
    pub fn new(
        schema: CommunityMetadataSchemaV1,
        scope_bytes: &'a [u8],
        envelope_bytes: &'a [u8],
    ) -> Result<Self> {
        CommunityMetadataScopeV1::from_canonical_cbor(scope_bytes).and_then(|scope| {
            CommunityEncryptedEnvelopeV1::from_canonical_cbor(envelope_bytes).and_then(|envelope| {
                let cover = scope.as_input();
                let header = envelope.header().as_input();
                if header.purpose != CommunityArtifactPurposeV1::LifecycleControl
                    || header.record_kind != CommunityArtifactKindV1::LifecycleControl
                    || header.operation
                        != CommunityArtifactOperationV1::Control(cover.protection_operation_id)
                    || header.timeline != cover.metadata_anchor_timeline
                    || header.generation != cover.metadata_anchor_generation
                    || header.scope_cover_digest != scope.digest()
                    || header.evidence_not_after_micros > cover.metadata_not_after_micros
                {
                    Err(Error::InvalidBinding)
                } else {
                    Ok(Self {
                        schema,
                        scope_bytes,
                        envelope_bytes,
                        scope,
                        envelope,
                    })
                }
            })
        })
    }

    /// Exact closed schema label, not proof of its encrypted body's shape.
    #[must_use]
    pub const fn schema(&self) -> CommunityMetadataSchemaV1 {
        self.schema
    }

    /// Borrow original admitted-shape scope data; current premises remain unverified.
    #[must_use]
    pub const fn scope_cover(&self) -> &CommunityMetadataScopeV1<'a> {
        &self.scope
    }

    /// Borrow the unauthenticated parsed envelope for actual guarded decryption.
    #[must_use]
    pub const fn envelope(&self) -> &CommunityEncryptedEnvelopeV1<'a> {
        &self.envelope
    }

    /// Borrow exact original scope bytes for native owner accounting.
    #[must_use]
    pub const fn scope_cover_bytes(&self) -> &'a [u8] {
        self.scope_bytes
    }

    /// Borrow exact original COE1 bytes, not an owned ciphertext clone.
    #[must_use]
    pub const fn envelope_bytes(&self) -> &'a [u8] {
        self.envelope_bytes
    }

    /// Copy exact5-field CNE1 into fully pre-sized zeroizing framing storage.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(
            self.scope_bytes.len() + self.envelope_bytes.len() + 32,
        ));
        record_prefix(&mut out, 5, *b"CNE1");
        encode_bytes(&mut out, &self.schema.magic(), 2);
        encode_bytes(&mut out, self.scope_bytes, 2);
        encode_bytes(&mut out, self.envelope_bytes, 2);
        out
    }

    /// Exact `NativeEvidenceEnvelope` physical identity, not a logical State hash.
    #[must_use]
    pub fn address(&self) -> Hash {
        digest(
            b"PiglorOS.Community.NativeEvidenceEnvelope.v1\0",
            &self.to_canonical_cbor(),
        )
    }

    /// Parse the complete bounded wrapper, borrowing scope/ciphertext ranges.
    ///
    /// # Errors
    /// Rejects nonpreferred/malformed/versioned/oversized/trailing bytes,
    /// non-whitelisted schemas and mismatched nested header/scope bindings.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(bytes, MAX_RECORD, 5, *b"CNE1").and_then(|mut cursor| {
            fixed_bytes(&mut cursor)
                .and_then(|magic| {
                    CommunityMetadataSchemaV1::from_magic(magic).ok_or(Error::InvalidBinding)
                })
                .and_then(|schema| {
                    bounded_bytes(&mut cursor, 1_048_576).and_then(|scope| {
                        bounded_bytes(&mut cursor, MAX_ENVELOPE).and_then(|envelope| {
                            canonical_end(&cursor).and_then(|()| Self::new(schema, scope, envelope))
                        })
                    })
                })
        })
    }
}
