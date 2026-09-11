//! ADR-060 no-resurrection evidence for replica rejoin.
//!
//! `ERRJ1` is deliberately payload-free.  It binds a replica's complete
//! replica/backup inventory view to one terminal `ERC1` receipt, but the
//! opaque attestation digest is still verified by the host that admits the
//! replica.  The core contract therefore provides a deterministic structural
//! gate without pretending to be a signer or transport adapter.

use super::evidence::{
    array, bytes32, decode_limited, digest, domain_digest, encode_limited, exact_array, header,
    target_from_value, target_value, text, uint, unsigned,
};
use super::{
    reference_zero, ErasureErrorV1, ErasureInventoryCategoryV1, ErasureReceiptV1,
    ErasureReferenceV1, ErasureRequiredTargetV1, ERASURE_MAX_INVENTORY_RESULTS,
    ERASURE_PORTABLE_RECORD_MAX_BYTES, VERSION,
};
use ciborium::value::Value;

/// Domain tag for one no-resurrection rejoin proof.
pub const ERASURE_REJOIN_PROOF_TAG_V1: &str = "ERRJ1";

const ERASURE_REJOIN_ENTRY_TAG_V1: &str = "ERRJE1";

/// The only dispositions that can prove a replica cannot restore erased data.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ErasureRejoinDispositionV1 {
    /// The target was destroyed and its key or artifact identity is tombstoned.
    Tombstoned,
    /// The target cannot be recovered by this replica or its backup inventory.
    Unrecoverable,
}

impl ErasureRejoinDispositionV1 {
    /// Return the stable V1 wire code.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::Tombstoned => 0,
            Self::Unrecoverable => 1,
        }
    }

    /// Decode one stable V1 wire code.
    ///
    /// # Errors
    ///
    /// Returns [`ErasureErrorV1::InvalidEncoding`] for an unknown code.
    pub const fn from_code(code: u64) -> Result<Self, ErasureErrorV1> {
        match code {
            0 => Ok(Self::Tombstoned),
            1 => Ok(Self::Unrecoverable),
            _ => Err(ErasureErrorV1::InvalidEncoding),
        }
    }
}

/// One canonical, payload-free inventory assertion supplied by a rejoining
/// replica.  `evidence` is an opaque digest authenticated by the host.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ErasureRejoinInventoryV1 {
    /// The replica or backup owner category represented by this assertion.
    pub category: ErasureInventoryCategoryV1,
    /// The frozen target whose erased state cannot be restored.
    pub target: ErasureRequiredTargetV1,
    /// The registered owner of the target evidence.
    pub owner: ErasureReferenceV1,
    /// The closed no-resurrection disposition.
    pub disposition: ErasureRejoinDispositionV1,
    /// Host-authenticated evidence digest; payload bytes never cross the seam.
    pub evidence: ErasureReferenceV1,
}

/// Construction fields for one `ERRJ1` proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureRejoinProofInputV1 {
    /// The ERQ1 request being rejoined.
    pub request: ErasureReferenceV1,
    /// The terminal ERC1 receipt that closed the destructive attempt.
    pub terminal_receipt: ErasureReferenceV1,
    /// The registered replica-set identity.
    pub replica_set: ErasureReferenceV1,
    /// The registered replica identity.
    pub replica_id: ErasureReferenceV1,
    /// Monotonic generation of the complete inventory snapshot.
    pub inventory_generation: ErasureReferenceV1,
    /// Canonical replica and backup assertions.
    pub entries: Vec<ErasureRejoinInventoryV1>,
    /// Opaque host-authenticated attestation for the snapshot.
    pub attestation: ErasureReferenceV1,
}

/// A content-addressed, payload-free no-resurrection proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureRejoinProofV1 {
    input: ErasureRejoinProofInputV1,
    content_digest: ErasureReferenceV1,
}

/// Host capability that authenticates the opaque attestation in an `ERRJ1`
/// proof.  The core record remains payload-free; only the owner of the
/// attestation can authorize topology rejoin.
pub trait ErasureRejoinAttestationVerifierV1 {
    /// Authenticate one proof's host-owned attestation.
    ///
    /// # Errors
    ///
    /// Returns a closed authorization or provenance error when the attestation
    /// is not valid for this proof.
    fn verify(&self, proof: &ErasureRejoinProofV1) -> Result<(), ErasureErrorV1>;
}

/// A structural admission token returned after a proof is bound to a complete
/// terminal receipt.
///
/// A host must still authenticate the proof's attestation before allowing the
/// replica to rejoin a live topology.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureRejoinAdmissionV1 {
    request: ErasureReferenceV1,
    terminal_receipt: ErasureReferenceV1,
    replica_set: ErasureReferenceV1,
    replica_id: ErasureReferenceV1,
    proof: ErasureReferenceV1,
}

impl ErasureRejoinProofV1 {
    /// Construct and content-address one canonical `ERRJ1` proof.
    ///
    /// # Errors
    ///
    /// Returns a closed error when entries are not bounded, canonical, or
    /// payload-free, or when required identity evidence is absent.
    pub fn new(mut input: ErasureRejoinProofInputV1) -> Result<Self, ErasureErrorV1> {
        if input.entries.len() > ERASURE_MAX_INVENTORY_RESULTS
            || input.request == reference_zero()
            || input.terminal_receipt == reference_zero()
            || input.replica_set == reference_zero()
            || input.replica_id == reference_zero()
            || input.inventory_generation == reference_zero()
            || input.attestation == reference_zero()
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        input.entries.sort_unstable();
        if input.entries.windows(2).any(|pair| pair[0] == pair[1])
            || input.entries.iter().any(|entry| {
                !matches!(
                    entry.category,
                    ErasureInventoryCategoryV1::Replica | ErasureInventoryCategoryV1::Backup
                ) || entry.owner == reference_zero()
                    || entry.evidence == reference_zero()
                    || entry.target.replica_set != input.replica_set
                    || entry.target.replica_id != input.replica_id
            })
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the bound ERQ1 request.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }

    /// Return the terminal ERC1 receipt identity.
    #[must_use]
    pub const fn terminal_receipt(&self) -> ErasureReferenceV1 {
        self.input.terminal_receipt
    }

    /// Return the registered replica-set identity.
    #[must_use]
    pub const fn replica_set(&self) -> ErasureReferenceV1 {
        self.input.replica_set
    }

    /// Return the registered replica identity.
    #[must_use]
    pub const fn replica_id(&self) -> ErasureReferenceV1 {
        self.input.replica_id
    }

    /// Return the complete inventory generation identity.
    #[must_use]
    pub const fn inventory_generation(&self) -> ErasureReferenceV1 {
        self.input.inventory_generation
    }

    /// Return the canonical inventory assertions.
    #[must_use]
    pub fn entries(&self) -> &[ErasureRejoinInventoryV1] {
        &self.input.entries
    }

    /// Return the host-authenticated attestation identity.
    #[must_use]
    pub const fn attestation(&self) -> ErasureReferenceV1 {
        self.input.attestation
    }

    /// Return this proof's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }

    /// Encode the exact deterministic `ERRJ1` record.
    ///
    /// # Errors
    ///
    /// Returns a closed error if canonical serialization exceeds its bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        self.clone().with_digest().and_then(|expected| {
            encode_limited(&proof_value(&expected), ERASURE_PORTABLE_RECORD_MAX_BYTES)
        })
    }

    /// Decode and validate one exact deterministic `ERRJ1` record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or mismatched
    /// content-address evidence.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_INVENTORY_RESULTS,
        )
        .and_then(|value| exact_array(&value, 10).and_then(proof_from_fields))
    }

    /// Validate that this proof closes the receipt's replica and backup
    /// inventories, then return the structural rejoin-admission token.
    ///
    /// The host remains responsible for authenticating [`Self::attestation`]
    /// before it uses the returned token to mutate topology membership.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the receipt is partial, inventory coverage
    /// is incomplete, or the proof is bound to another request or receipt.
    pub fn admit(
        &self,
        receipt: &ErasureReceiptV1,
        verifier: &dyn ErasureRejoinAttestationVerifierV1,
    ) -> Result<ErasureRejoinAdmissionV1, ErasureErrorV1> {
        let request_matches = self.request() == receipt.request();
        let receipt_matches = self.terminal_receipt() == receipt.receipt_digest();
        if !(request_matches && receipt_matches) {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        if receipt.lifecycle() != super::ErasureLifecycleV1::Complete {
            return if receipt.inventories().backups.is_empty() {
                Err(ErasureErrorV1::BackupInventoryIncomplete)
            } else {
                Err(ErasureErrorV1::BackupDeletionPending)
            };
        }

        let mut expected = receipt
            .inventories()
            .replicas
            .iter()
            .chain(&receipt.inventories().backups)
            .filter(|entry| {
                entry.target.replica_set == self.replica_set()
                    && entry.target.replica_id == self.replica_id()
            })
            .map(|entry| (entry.category, entry.target, entry.transition.owner))
            .collect::<Vec<_>>();
        expected.sort_unstable();
        let mut found = self
            .entries()
            .iter()
            .map(|entry| (entry.category, entry.target, entry.owner))
            .collect::<Vec<_>>();
        found.sort_unstable();
        if expected.is_empty() || found != expected {
            return Err(ErasureErrorV1::BackupInventoryIncomplete);
        }
        verifier.verify(self)?;
        Ok(ErasureRejoinAdmissionV1 {
            request: self.request(),
            terminal_receipt: self.terminal_receipt(),
            replica_set: self.replica_set(),
            replica_id: self.replica_id(),
            proof: self.reference(),
        })
    }

    fn with_digest(mut self) -> Result<Self, ErasureErrorV1> {
        encode_limited(&proof_core_value(&self), ERASURE_PORTABLE_RECORD_MAX_BYTES).map(|bytes| {
            self.content_digest =
                ErasureReferenceV1::from_digest(domain_digest(ERASURE_REJOIN_PROOF_TAG_V1, &bytes));
            self
        })
    }
}

fn entry_value(entry: ErasureRejoinInventoryV1) -> Value {
    Value::Array(vec![
        text(ERASURE_REJOIN_ENTRY_TAG_V1),
        uint(VERSION),
        uint(entry.category.code()),
        target_value(entry.target),
        digest(entry.owner),
        uint(entry.disposition.code()),
        digest(entry.evidence),
    ])
}

fn entry_from_fields(fields: &[Value]) -> Result<ErasureRejoinInventoryV1, ErasureErrorV1> {
    header(fields, ERASURE_REJOIN_ENTRY_TAG_V1)?;
    let category = ErasureInventoryCategoryV1::from_code(unsigned(&fields[2])?)?;
    if !matches!(
        category,
        ErasureInventoryCategoryV1::Replica | ErasureInventoryCategoryV1::Backup
    ) {
        return Err(ErasureErrorV1::ScopeInvalid);
    }
    Ok(ErasureRejoinInventoryV1 {
        category,
        target: target_from_value(&fields[3])?,
        owner: bytes32(&fields[4])?,
        disposition: ErasureRejoinDispositionV1::from_code(unsigned(&fields[5])?)?,
        evidence: bytes32(&fields[6])?,
    })
}

fn entries_value(entries: &[ErasureRejoinInventoryV1]) -> Value {
    Value::Array(entries.iter().copied().map(entry_value).collect())
}

fn entries_from_value(value: &Value) -> Result<Vec<ErasureRejoinInventoryV1>, ErasureErrorV1> {
    array(value, ERASURE_MAX_INVENTORY_RESULTS).and_then(|values| {
        values
            .iter()
            .map(|value| exact_array(value, 7).and_then(entry_from_fields))
            .collect()
    })
}

fn proof_fields(proof: &ErasureRejoinProofV1) -> Vec<Value> {
    vec![
        text(ERASURE_REJOIN_PROOF_TAG_V1),
        uint(VERSION),
        digest(proof.request()),
        digest(proof.terminal_receipt()),
        digest(proof.replica_set()),
        digest(proof.replica_id()),
        digest(proof.inventory_generation()),
        entries_value(proof.entries()),
        digest(proof.attestation()),
    ]
}

fn proof_core_value(proof: &ErasureRejoinProofV1) -> Value {
    Value::Array(proof_fields(proof))
}

fn proof_value(proof: &ErasureRejoinProofV1) -> Value {
    let mut fields = proof_fields(proof);
    fields.push(digest(proof.reference()));
    Value::Array(fields)
}

fn proof_from_fields(fields: &[Value]) -> Result<ErasureRejoinProofV1, ErasureErrorV1> {
    header(fields, ERASURE_REJOIN_PROOF_TAG_V1)?;
    let entries = entries_from_value(&fields[7])?;
    if entries.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ErasureErrorV1::ScopeInvalid);
    }
    let proof = ErasureRejoinProofV1::new(ErasureRejoinProofInputV1 {
        request: bytes32(&fields[2])?,
        terminal_receipt: bytes32(&fields[3])?,
        replica_set: bytes32(&fields[4])?,
        replica_id: bytes32(&fields[5])?,
        inventory_generation: bytes32(&fields[6])?,
        entries,
        attestation: bytes32(&fields[8])?,
    })?;
    if proof.reference() == bytes32(&fields[9])? {
        Ok(proof)
    } else {
        Err(ErasureErrorV1::ProvenanceMissing)
    }
}

impl ErasureRejoinAdmissionV1 {
    /// Return the admitted ERQ1 request.
    #[must_use]
    pub const fn request(self) -> ErasureReferenceV1 {
        self.request
    }

    /// Return the admitted terminal ERC1 receipt.
    #[must_use]
    pub const fn terminal_receipt(self) -> ErasureReferenceV1 {
        self.terminal_receipt
    }

    /// Return the admitted replica-set identity.
    #[must_use]
    pub const fn replica_set(self) -> ErasureReferenceV1 {
        self.replica_set
    }

    /// Return the admitted replica identity.
    #[must_use]
    pub const fn replica_id(self) -> ErasureReferenceV1 {
        self.replica_id
    }

    /// Return the content address of the proof that produced this token.
    #[must_use]
    pub const fn proof(self) -> ErasureReferenceV1 {
        self.proof
    }
}
