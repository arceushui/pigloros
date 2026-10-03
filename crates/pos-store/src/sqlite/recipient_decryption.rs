//! Closed failures for retained role-4 recipient export decryption.

use pos_core::KeyRegistryErrorV1;
use pos_crypto::recipient_export::RecipientExportErrorV1;
use thiserror::Error;

/// Why a recipient owner did not yield a decrypted candidate export.
///
/// The variants follow ADR-098's precedence: the TRX1 envelope and its
/// recorded recipient identity are checked before any registry access;
/// registry state (locked, absent, pending, destroyed) is checked before
/// private material is opened; and HPKE authentication runs last.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RecipientExportDecryptionErrorV1 {
    /// The TRX1 envelope is invalid, names another export or recipient, or
    /// fails authentication.
    #[error(transparent)]
    Export(RecipientExportErrorV1),
    /// The held registry boundary is unavailable or denies the identity.
    #[error(transparent)]
    Registry(KeyRegistryErrorV1),
    /// The registered private material is missing, unsafe, or corrupt.
    #[error("recipient private key material is unavailable")]
    MaterialUnavailable,
}
