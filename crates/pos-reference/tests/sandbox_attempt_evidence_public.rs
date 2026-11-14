//! The ADR-069 R9 attempt evidence records (RQE1, KOE1 and TME1) and their
//! verifier, through the public `pos_reference` seam.
//!
//! The oracle is independent: expected bytes come from the R9 §7 vectors,
//! which an independent Python implementation computed, and every changed
//! record is re-encoded with ciborium and re-digested with BLAKE3 in the
//! test, never with the codecs under test.

#[path = "sandbox_attempt_evidence_public/mod.rs"]
mod cases;
