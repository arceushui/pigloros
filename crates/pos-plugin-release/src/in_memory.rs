//! A source-neutral, in-memory [`ReleaseSourceV1`] built from raw bytes (ADR-061 revision 8
//! decision 5).
//!
//! The source holds the manifest and the blobs of each release and runs the verifier on every
//! read, so a fault inside any held byte is found at the read and nothing is cached. It exists
//! for evaluation worlds that carry their releases as bytes and must not need a SHA-256
//! dependency of their own.
//!
//! Because `from_bytes` keys each blob by the SHA-256 of its own bytes, a blob whose bytes were
//! altered is found as an unexpected key (`BoundsExceeded`); `DigestMismatch` is unreachable
//! through this source.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::oci::{
    verify_oci_closure_v1, BundleAddressV1, ReleaseSourceErrorV1, ReleaseSourceV1,
    VerifiedReleaseBundleV1,
};
use crate::{sha256_digest, EMPTY_CONFIG_BYTES, EMPTY_CONFIG_DIGEST};

/// A closed failure of the in-memory release source's construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InMemoryReleaseErrorV1 {
    /// The manifest is empty or larger than the V1 manifest bound, so it has no address.
    #[error("in-memory release manifest has no valid address")]
    InvalidAddress,
    /// Two entries have the same manifest address.
    #[error("in-memory release address is duplicated")]
    DuplicateAddress,
    /// The source holds no release.
    #[error("in-memory release source is empty")]
    Empty,
}

/// One release held as bytes: its manifest, its address, and its blobs keyed by SHA-256 digest.
///
/// The entry does not check that the bytes form a valid closure; every read of the source does.
#[derive(Clone, Debug)]
pub struct InMemoryReleaseEntryV1 {
    address: BundleAddressV1,
    manifest: Vec<u8>,
    blobs: BTreeMap<String, Vec<u8>>,
}

impl InMemoryReleaseEntryV1 {
    /// An entry from the exact manifest bytes and the layer blobs.
    ///
    /// The address is the SHA-256 digest and the length of `manifest`, and each blob is keyed
    /// by the SHA-256 digest of its own bytes. The fixed empty-config blob `{}`, which the
    /// verifier expects in every closure, is always added, so `blobs` omit it.
    ///
    /// # Errors
    /// Returns `InvalidAddress` when `manifest` is empty or larger than the V1 manifest bound.
    pub fn from_bytes(
        manifest: Vec<u8>,
        blobs: Vec<Vec<u8>>,
    ) -> Result<Self, InMemoryReleaseErrorV1> {
        let address = BundleAddressV1::new(sha256_digest(&manifest), manifest.len() as u64)
            .map_err(|_| InMemoryReleaseErrorV1::InvalidAddress)?;
        let mut keyed = BTreeMap::new();
        keyed.insert(EMPTY_CONFIG_DIGEST.to_owned(), EMPTY_CONFIG_BYTES.to_vec());
        for bytes in blobs {
            keyed.insert(sha256_digest(&bytes), bytes);
        }
        Ok(Self {
            address,
            manifest,
            blobs: keyed,
        })
    }

    /// The address of the held manifest.
    #[must_use]
    pub const fn address(&self) -> &BundleAddressV1 {
        &self.address
    }

    /// The verified closure of the held bytes.
    fn verify(&self) -> Result<VerifiedReleaseBundleV1, ReleaseSourceErrorV1> {
        verify_oci_closure_v1(
            self.address.clone(),
            self.manifest.clone(),
            self.blobs.clone(),
        )
    }
}

/// A [`ReleaseSourceV1`] over releases held in memory.
///
/// The source is `Clone` over shared bytes: every clone serves the same releases.
#[derive(Clone, Debug)]
pub struct InMemoryReleaseSourceV1 {
    entries: Arc<BTreeMap<BundleAddressV1, InMemoryReleaseEntryV1>>,
}

impl InMemoryReleaseSourceV1 {
    /// A source over `entries`.
    ///
    /// # Errors
    /// Returns `Empty` for no entry and `DuplicateAddress` when two entries share an address.
    pub fn new(entries: Vec<InMemoryReleaseEntryV1>) -> Result<Self, InMemoryReleaseErrorV1> {
        if entries.is_empty() {
            return Err(InMemoryReleaseErrorV1::Empty);
        }
        let mut held = BTreeMap::new();
        for entry in entries {
            if held.insert(entry.address.clone(), entry).is_some() {
                return Err(InMemoryReleaseErrorV1::DuplicateAddress);
            }
        }
        Ok(Self {
            entries: Arc::new(held),
        })
    }
}

impl ReleaseSourceV1 for InMemoryReleaseSourceV1 {
    /// Verify the held closure at `address` on every call.
    ///
    /// # Errors
    /// Returns `NotFound` for an address no entry holds, and otherwise the verifier's closed
    /// error for the held bytes.
    fn read_verified(
        &self,
        address: &BundleAddressV1,
    ) -> Result<VerifiedReleaseBundleV1, ReleaseSourceErrorV1> {
        self.entries
            .get(address)
            .ok_or(ReleaseSourceErrorV1::NotFound)
            .and_then(InMemoryReleaseEntryV1::verify)
    }
}
