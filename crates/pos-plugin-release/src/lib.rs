#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

//! Bounded, source-neutral Plugin release transport and local OCI publication.
//!
//! This crate verifies OCI transport closure only. It deliberately does not
//! parse PMF1 or make signing, trust-admission, installation, or activation
//! decisions.

#[cfg(target_os = "linux")]
mod local;
mod oci;

use std::collections::BTreeSet;

const MAX_JCS_BYTES: usize = 64 * 1024;

/// Parse bounded canonical JSON shared by private transport adapters.
fn parse_jcs_object(bytes: &[u8]) -> Result<serde_json::Value, ReleaseSourceErrorV1> {
    if bytes.is_empty() || bytes.len() > MAX_JCS_BYTES || has_duplicate_object_keys(bytes) {
        return Err(ReleaseSourceErrorV1::InvalidDescriptor);
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| ReleaseSourceErrorV1::InvalidDescriptor)?;
    let canonical =
        serde_json::to_vec(&value).map_err(|_| ReleaseSourceErrorV1::InvalidDescriptor)?;
    if canonical != bytes {
        return Err(ReleaseSourceErrorV1::InvalidDescriptor);
    }
    Ok(value)
}

/// Reject duplicate object keys before `serde_json` can collapse them.
fn has_duplicate_object_keys(bytes: &[u8]) -> bool {
    let mut parser = DuplicateKeyScanner { bytes, cursor: 0 };
    parser.value().is_err() || parser.cursor != bytes.len()
}

struct DuplicateKeyScanner<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl DuplicateKeyScanner<'_> {
    fn value(&mut self) -> Result<(), ()> {
        self.whitespace();
        match self.byte()? {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => self.string().map(|_| ()),
            b't' => self.literal(b"true"),
            b'f' => self.literal(b"false"),
            b'n' => self.literal(b"null"),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(()),
        }
    }

    fn object(&mut self) -> Result<(), ()> {
        self.take(b'{')?;
        self.whitespace();
        let mut keys = BTreeSet::new();
        if self.consume(b'}') {
            return Ok(());
        }
        loop {
            self.whitespace();
            let key = self.string()?;
            if !keys.insert(key) {
                return Err(());
            }
            self.whitespace();
            self.take(b':')?;
            self.value()?;
            self.whitespace();
            if self.consume(b'}') {
                return Ok(());
            }
            self.take(b',')?;
        }
    }

    fn array(&mut self) -> Result<(), ()> {
        self.take(b'[')?;
        self.whitespace();
        if self.consume(b']') {
            return Ok(());
        }
        loop {
            self.value()?;
            self.whitespace();
            if self.consume(b']') {
                return Ok(());
            }
            self.take(b',')?;
        }
    }

    fn string(&mut self) -> Result<String, ()> {
        self.take(b'"')?;
        let start = self.cursor;
        let mut escaped = false;
        while let Some(byte) = self.bytes.get(self.cursor).copied() {
            self.cursor += 1;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                let raw =
                    std::str::from_utf8(&self.bytes[start - 1..self.cursor]).map_err(|_| ())?;
                return serde_json::from_str(raw).map_err(|_| ());
            } else if byte < 0x20 {
                return Err(());
            }
        }
        Err(())
    }

    fn number(&mut self) -> Result<(), ()> {
        let start = self.cursor;
        while self.bytes.get(self.cursor).is_some_and(|byte| {
            byte.is_ascii_digit() || matches!(*byte, b'-' | b'+' | b'.' | b'e' | b'E')
        }) {
            self.cursor += 1;
        }
        std::str::from_utf8(&self.bytes[start..self.cursor])
            .ok()
            .and_then(|number| serde_json::from_str::<serde_json::Number>(number).ok())
            .map_or(Err(()), |_| Ok(()))
    }

    fn literal(&mut self, literal: &[u8]) -> Result<(), ()> {
        if self.bytes.get(self.cursor..self.cursor + literal.len()) == Some(literal) {
            self.cursor += literal.len();
            Ok(())
        } else {
            Err(())
        }
    }

    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.cursor)
            .is_some_and(|byte| matches!(*byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.cursor += 1;
        }
    }

    fn byte(&self) -> Result<u8, ()> {
        self.bytes.get(self.cursor).copied().ok_or(())
    }

    fn take(&mut self, expected: u8) -> Result<(), ()> {
        if self.consume(expected) {
            Ok(())
        } else {
            Err(())
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.bytes.get(self.cursor) == Some(&expected) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }
}

#[cfg(target_os = "linux")]
pub use local::PublishOutcomeV1;
#[cfg(target_os = "linux")]
pub use local::RecoveryOutcomeV1;
#[cfg(target_os = "linux")]
pub use local::RecoveryReportV1;
#[cfg(target_os = "linux")]
pub use local::{LocalOciPublicationErrorV1, LocalOciPublisherV1};
pub use oci::{
    verify_oci_closure_v1, BlobV1, BundleAddressV1, BundleMemberV1, ReleaseSourceErrorV1,
    ReleaseSourceV1, VerifiedReleaseBundleV1,
};
