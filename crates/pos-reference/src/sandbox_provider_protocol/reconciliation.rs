//! The V1 reconciliation evidence that SRY1 field 5 digests (ADR-069 R15
//! §3.1 and §3.2).
//!
//! `reconciliation-evidence-v1` is the fixed 10-item tuple
//! `[attempt-id, agr1-digest, terminal-spy1-digest, final-sau1-digest,
//! true × 6]`. Its six booleans are the CDDL literal `true`: a residual
//! resource is never a tuple but an SPE1 (R15 §3.3), so the encoder's input
//! has no boolean fields. The tuple has no magic and no self-digest; its
//! digest is the specialized
//! `BLAKE3-256("PiglorOS.ReconciliationEvidence.v1\0" || tuple)`.
//!
//! Only the encoder ships (R15 N10): no V1 party receives the tuple bytes.

use super::SandboxProviderProtocolError;

/// The domain of the V1 reconciliation-evidence digest.
pub const RECONCILIATION_EVIDENCE_V1_DOMAIN: &[u8] = b"PiglorOS.ReconciliationEvidence.v1\0";

/// The exact length of every canonical tuple: `0x8a`, 17, 3 × 34, 6 × 1.
pub const RECONCILIATION_EVIDENCE_V1_BYTES: usize = 126;

/// The preferred-deterministic CBOR heads of the tuple (RFC 8949 §4.2.1).
const ARRAY_OF_TEN: u8 = 0x8a;
const ID16_HEAD: u8 = 0x50;
const DIGEST32_HEAD: [u8; 2] = [0x58, 0x20];
const TRUE: u8 = 0xf5;

/// The digest fields the tuple binds (R15 §3.2), each copied from the
/// retained records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconciliationEvidenceFields {
    /// The SRQ1 attempt ID, which is the AGR1 attempt ID.
    pub attempt_id: [u8; 16],
    /// The AGR1 self-digest the SRQ1 names.
    pub agr1_digest: [u8; 32],
    /// The self-digest of the retained, delivered terminal SPY1.
    pub terminal_spy1_digest: [u8; 32],
    /// The self-digest of the last SAU1 of that response.
    pub final_sau1_digest: [u8; 32],
}

/// The exact canonical `reconciliation-evidence-v1` bytes of one attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconciliationEvidence {
    bytes: [u8; RECONCILIATION_EVIDENCE_V1_BYTES],
}

impl ReconciliationEvidence {
    /// Encode the tuple of `fields` with its six `true` booleans.
    ///
    /// # Errors
    /// `FieldOutOfBounds` for a zero attempt ID or digest (R9 §6 rule 2).
    pub fn new(
        fields: &ReconciliationEvidenceFields,
    ) -> Result<Self, SandboxProviderProtocolError> {
        let digests = [
            fields.agr1_digest,
            fields.terminal_spy1_digest,
            fields.final_sau1_digest,
        ];
        if fields.attempt_id == [0; 16] || digests.contains(&[0; 32]) {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        let mut bytes = [TRUE; RECONCILIATION_EVIDENCE_V1_BYTES];
        bytes[0] = ARRAY_OF_TEN;
        bytes[1] = ID16_HEAD;
        bytes[2..18].copy_from_slice(&fields.attempt_id);
        for (index, digest) in digests.iter().enumerate() {
            let start = 18 + 34 * index;
            bytes[start..start + 2].copy_from_slice(&DIGEST32_HEAD);
            bytes[start + 2..start + 34].copy_from_slice(digest);
        }
        Ok(Self { bytes })
    }

    /// The exact canonical tuple bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; RECONCILIATION_EVIDENCE_V1_BYTES] {
        &self.bytes
    }

    /// SRY1 field 5: `BLAKE3-256(domain || tuple)`.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(RECONCILIATION_EVIDENCE_V1_DOMAIN);
        hasher.update(&self.bytes);
        *hasher.finalize().as_bytes()
    }
}
