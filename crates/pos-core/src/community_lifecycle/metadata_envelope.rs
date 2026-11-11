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

// Generate declarations only: enum and table cannot drift on insertion or
// reordering. Both lookup algorithms remain ordinary functions below.
macro_rules! metadata_schemas {
    ($($(#[$doc:meta])* $schema:ident => $label:literal),+ $(,)?) => {
        /// Exact ADR-129 native metadata whitelist, not an extensible registry.
        /// The schema label does not verify a decrypted body's semantics.
        #[derive(Clone, Copy, Eq, PartialEq)]
        pub enum CommunityMetadataSchemaV1 {
            $($(#[$doc])* $schema,)+
        }

        impl CommunityMetadataSchemaV1 {
            // Ordinals index only this private table, never a wire encoding.
            const LABELS: [(Self, [u8; 4]); 31] = [
                $((Self::$schema, *$label),)+
            ];
        }
    };
}

metadata_schemas! {
    /// Original owner binding.
    Cob1 => b"COB1",
    /// Actual input scope binding.
    Csb1 => b"CSB1",
    /// Original provenance.
    Cpv1 => b"CPV1",
    /// Current authority evidence.
    Cau1 => b"CAU1",
    /// Current view, transient by default.
    Cav1 => b"CAV1",
    /// Identity/allocation selection.
    Csi1 => b"CSI1",
    /// Copy inventory.
    Cci1 => b"CCI1",
    /// Materialization binding.
    Cmi1 => b"CMI1",
    /// Dependency commit.
    Cpd1 => b"CPD1",
    /// Pre-Reserve budget forecast.
    Cbq1 => b"CBQ1",
    /// Durable profile.
    Cdp1 => b"CDP1",
    /// Member binding.
    Cmb1 => b"CMB1",
    /// Negotiated tuple.
    Cnt1 => b"CNT1",
    /// Member State/progress.
    Cms1 => b"CMS1",
    /// Selected head.
    Csh1 => b"CSH1",
    /// Host progress.
    Cst1 => b"CST1",
    /// Generation request.
    Cgi1 => b"CGI1",
    /// Generation admission.
    Cga1 => b"CGA1",
    /// Generation control.
    Cgc1 => b"CGC1",
    /// Reservation request.
    Cri1 => b"CRI1",
    /// Reservation result.
    Cpr1 => b"CPR1",
    /// Sealed result.
    Cps1 => b"CPS1",
    /// Committed pass.
    Cpc1 => b"CPC1",
    /// Aborted pass.
    Cab1 => b"CAB1",
    /// Quarantine key.
    Cqk1 => b"CQK1",
    /// Quarantine control.
    Cqc1 => b"CQC1",
    /// Quarantine revision.
    Cqr1 => b"CQR1",
    /// Quarantine outcome.
    Cqo1 => b"CQO1",
    /// Native graph root.
    Cgr1 => b"CGR1",
    /// Factual Tick bridge.
    Ctb1 => b"CTB1",
    /// Original metadata policy.
    Nmp1 => b"NMP1",
}

impl CommunityMetadataSchemaV1 {
    /// Exact four-byte wire label, never a Rust discriminant or debug spelling.
    #[must_use]
    pub const fn magic(self) -> [u8; 4] {
        Self::LABELS[self as usize].1
    }

    /// Resolve only an exact admitted metadata label. Data/failure/claim and
    /// clear bootstrap schemas cannot be imported under this wrapper.
    #[must_use]
    pub const fn from_magic(magic: [u8; 4]) -> Option<Self> {
        let mut remaining: &[(Self, [u8; 4])] = &Self::LABELS;
        while let Some((entry, rest)) = remaining.split_first() {
            let (schema, label) = *entry;
            if u32::from_be_bytes(label) == u32::from_be_bytes(magic) {
                return Some(schema);
            }
            remaining = rest;
        }
        None
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
