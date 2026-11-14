//! The ADR-069 R9 attempt evidence records (RQE1, KOE1 and TME1) and their
//! verifier, through the public `pos_reference` seam.
//!
//! The oracle is independent: expected bytes come from the R9 §7 vectors,
//! which an independent Python implementation computed, and every changed
//! record is re-encoded with ciborium and re-digested with BLAKE3 in the
//! test, never with the codecs under test.

#[path = "sandbox_attempt_evidence_public/bundle.rs"]
mod bundle;
#[path = "sandbox_attempt_evidence_public/codes.rs"]
mod codes;
#[path = "sandbox_attempt_evidence_public/observed.rs"]
mod observed;
#[path = "sandbox_attempt_evidence_public/oracle.rs"]
mod oracle;
#[path = "sandbox_attempt_evidence_public/requested.rs"]
mod requested;
#[path = "sandbox_attempt_evidence_public/terminated.rs"]
mod terminated;
#[path = "sandbox_attempt_evidence_public/vectors.rs"]
mod vectors;
