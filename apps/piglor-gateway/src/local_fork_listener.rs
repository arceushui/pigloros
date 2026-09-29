//! ADR-109's bounded local Fork-admission wire boundary.
//!
//! This module deliberately stops after authenticating the Unix peer and
//! decoding the complete FAL1 frame.  The durable delivery journal owns the
//! later claim, FAC1, FRP1, and response-delivery transitions.

use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{MetadataExt as _, PermissionsExt as _},
        net::{UnixListener, UnixStream},
    },
    path::Path,
    time::{Duration, Instant},
};

use ciborium::value::Value;
use pos_core::{Hash, TimelineId};
use ulid::Ulid;

use crate::local_fork_authentication::{
    AuthenticatedUnixPeerV1, LocalForkAuthenticationCredentialsV1, LocalForkAuthenticationErrorV1,
};

pub(super) const MAX_FAL1_PAYLOAD_BYTES_V1: usize = 512;
/// Whole-request read deadline and per-response write timeout.
const FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CHILD_NAME_BYTES_V1: usize = 128;
const FAL1_DOMAIN: &[u8] = b"pigloros/fal1/request/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LocalForkAdmissionCodeV1 {
    Ok,
    Unauthenticated,
    Conflict,
    StaleFoldBoundary,
    ParentChanged,
    AuthorityUnavailable,
    Indeterminate,
    InvalidRequest,
}

impl LocalForkAdmissionCodeV1 {
    const fn wire(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Unauthenticated => 1,
            Self::Conflict => 2,
            Self::StaleFoldBoundary => 3,
            Self::ParentChanged => 4,
            Self::AuthorityUnavailable => 5,
            Self::Indeterminate => 6,
            Self::InvalidRequest => 7,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum LocalForkAdmissionRequestV1 {
    Bind {
        operation_id: Hash,
    },
    Fork {
        operation_id: Hash,
        parent_id: TimelineId,
        cut: u64,
        descriptor_hash: Hash,
        composition_hash: Hash,
        attribution_required: bool,
        child_name: String,
    },
}

impl LocalForkAdmissionRequestV1 {
    #[must_use]
    pub(super) const fn operation_id(&self) -> Hash {
        match self {
            Self::Bind { operation_id } | Self::Fork { operation_id, .. } => *operation_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum LocalForkAdmissionResultV1 {
    Bind {
        principal_digest: Hash,
    },
    Fork {
        child_id: TimelineId,
        admission_digest: Hash,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LocalForkAdmissionResponseV1 {
    code: LocalForkAdmissionCodeV1,
    result: Option<LocalForkAdmissionResultV1>,
}

impl LocalForkAdmissionResponseV1 {
    #[must_use]
    pub(super) const fn rejected(code: LocalForkAdmissionCodeV1) -> Self {
        Self { code, result: None }
    }

    #[must_use]
    pub(super) const fn bind_ok(principal_digest: Hash) -> Self {
        Self {
            code: LocalForkAdmissionCodeV1::Ok,
            result: Some(LocalForkAdmissionResultV1::Bind { principal_digest }),
        }
    }

    #[must_use]
    pub(super) const fn fork_ok(child_id: TimelineId, admission_digest: Hash) -> Self {
        Self {
            code: LocalForkAdmissionCodeV1::Ok,
            result: Some(LocalForkAdmissionResultV1::Fork {
                child_id,
                admission_digest,
            }),
        }
    }

    /// Encode the fixed-shape canonical FARL1 array.
    ///
    /// Every field is a definite-length head with a fixed width, so the
    /// shortest-form bytes are written directly and encoding cannot fail.
    #[must_use]
    pub(super) fn to_canonical_cbor(&self) -> Vec<u8> {
        // array(4), text(5) "FARL1", uint 1, uint code (0..=7).
        let mut bytes = vec![
            0x84,
            0x65,
            b'F',
            b'A',
            b'R',
            b'L',
            b'1',
            1,
            self.code.wire(),
        ];
        match &self.result {
            None => bytes.push(0xf6),
            Some(LocalForkAdmissionResultV1::Bind { principal_digest }) => {
                // array(2), uint 1, bytes(32).
                bytes.extend_from_slice(&[0x82, 1, 0x58, 0x20]);
                bytes.extend_from_slice(principal_digest.as_bytes());
            }
            Some(LocalForkAdmissionResultV1::Fork {
                child_id,
                admission_digest,
            }) => {
                // array(3), uint 2, bytes(16), bytes(32).
                bytes.extend_from_slice(&[0x83, 2, 0x50]);
                bytes.extend_from_slice(&child_id.inner().to_bytes());
                bytes.extend_from_slice(&[0x58, 0x20]);
                bytes.extend_from_slice(admission_digest.as_bytes());
            }
        }
        bytes
    }
}

pub(super) struct CompletedLocalForkAdmissionV1 {
    pub(super) peer: AuthenticatedUnixPeerV1,
    pub(super) request: LocalForkAdmissionRequestV1,
    pub(super) host_request_id: Hash,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LocalForkFrameErrorV1 {
    /// A complete canonical FAL1 has invalid semantic fields; reply code 7.
    Invalid,
    /// Framing or canonical-CBOR validation failed before a FAL1 exists.
    Malformed,
    Transport,
    Peer,
}

/// Authenticate a connected Unix peer, then read exactly one complete FAL1.
///
/// EOF after the exact prefix and payload is part of request completeness. No
/// caller receives a decoded request until this check succeeds, so authority
/// work cannot start on a stream with delayed trailing input. One deadline
/// bounds the whole request, so a slow peer cannot extend it byte by byte.
pub(super) fn read_completed_request(
    stream: &mut UnixStream,
    credentials: &LocalForkAuthenticationCredentialsV1,
) -> Result<CompletedLocalForkAdmissionV1, LocalForkFrameErrorV1> {
    let peer = credentials
        .authenticate_peer(stream)
        .map_err(map_peer_error)?;
    let payload = read_framed_payload(stream, Instant::now() + FRAME_TIMEOUT)?;
    let request = decode_request(&payload)?;
    Ok(CompletedLocalForkAdmissionV1 {
        peer,
        request,
        host_request_id: request_digest(&payload),
    })
}

/// Bind one new service-owned admission-client pathname-stream listener.
/// Existing filesystem entries are never replaced by this boundary.
pub(super) fn bind_pathname_listener(path: &Path) -> io::Result<UnixListener> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Fork-admission socket path has no parent directory",
        )
    })?;
    validate_socket_parent(
        parent,
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    )?;
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

/// The pre-existing parent grants only the admission-client group pathname
/// traversal. It must be a real directory owned by this service and its
/// primary admission-client group, with exact mode 0750. Other UIDs cannot
/// reach the pathname before or after bind; admitted group peers authenticate
/// through `SO_PEERCRED` before any request bytes are accepted.
fn validate_socket_parent(parent: &Path, owner_uid: u32, admission_group: u32) -> io::Result<()> {
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_uid
        || metadata.gid() != admission_group
        || metadata.mode() & 0o777 != 0o750
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Fork-admission socket parent must be service-owned with mode 0750",
        ));
    }
    Ok(())
}

/// Write one complete FARL1 response within the frame timeout. The caller
/// owns the post-commit write outcome and must mark an interrupted delivery
/// indeterminate in its journal.
pub(super) fn write_response(
    stream: &mut UnixStream,
    response: &LocalForkAdmissionResponseV1,
) -> io::Result<()> {
    let payload = response.to_canonical_cbor();
    // A FARL1 is at most 62 bytes, so its length always fits the u32 prefix.
    let length = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    stream
        .set_write_timeout(Some(FRAME_TIMEOUT))
        .and_then(|()| stream.write_all(&length.to_be_bytes()))
        .and_then(|()| stream.write_all(&payload))
}

fn read_framed_payload(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Vec<u8>, LocalForkFrameErrorV1> {
    let mut prefix = [0_u8; 4];
    read_exact_until(stream, &mut prefix, deadline)?;
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .ok()
        .filter(|length| (1..=MAX_FAL1_PAYLOAD_BYTES_V1).contains(length))
        .ok_or(LocalForkFrameErrorV1::Malformed)?;
    let mut payload = vec![0_u8; length];
    read_exact_until(stream, &mut payload, deadline)?;
    let mut trailing = [0_u8; 1];
    match read_until(stream, &mut trailing, deadline) {
        Ok(0) => Ok(payload),
        Ok(_) | Err(_) => Err(LocalForkFrameErrorV1::Transport),
    }
}

/// Fill `buffer` before `deadline`; EOF, timeout, and I/O errors all close.
fn read_exact_until(
    stream: &mut UnixStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), LocalForkFrameErrorV1> {
    let mut filled = 0;
    while filled < buffer.len() {
        match read_until(stream, &mut buffer[filled..], deadline) {
            Ok(0) | Err(_) => return Err(LocalForkFrameErrorV1::Transport),
            Ok(read) => filled += read,
        }
    }
    Ok(())
}

/// One read re-armed with the time remaining before `deadline`. An expired
/// deadline yields a zero timeout, which the socket refuses as an error.
fn read_until(stream: &mut UnixStream, buffer: &mut [u8], deadline: Instant) -> io::Result<usize> {
    stream
        .set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))
        .and_then(|()| stream.read(buffer))
}

/// Decode every structural FAL1 field before any semantic check, so a
/// malformed frame always closes silently even when it also carries an
/// invalid semantic value.
fn decode_request(payload: &[u8]) -> Result<LocalForkAdmissionRequestV1, LocalForkFrameErrorV1> {
    decode_structure(payload).and_then(validate_semantics)
}

fn decode_structure(payload: &[u8]) -> Result<LocalForkAdmissionRequestV1, LocalForkFrameErrorV1> {
    let value: Value =
        ciborium::from_reader(payload).map_err(|_| LocalForkFrameErrorV1::Malformed)?;
    // Re-encoding the single decoded item and comparing it with the complete
    // payload rejects both non-canonical encodings and trailing items.
    let mut canonical = Vec::new();
    if ciborium::into_writer(&value, &mut canonical).is_err() || canonical != payload {
        return Err(LocalForkFrameErrorV1::Malformed);
    }
    let Value::Array(fields) = value else {
        return Err(LocalForkFrameErrorV1::Malformed);
    };
    if fields.len() != 3
        || !matches!(fields.first(), Some(Value::Text(marker)) if marker == "FAL1")
        || !matches!(fields.get(1), Some(Value::Integer(version)) if *version == 1.into())
    {
        return Err(LocalForkFrameErrorV1::Malformed);
    }
    let Value::Array(intent) = &fields[2] else {
        return Err(LocalForkFrameErrorV1::Malformed);
    };
    let Some(Value::Integer(kind)) = intent.first() else {
        return Err(LocalForkFrameErrorV1::Malformed);
    };
    match u8::try_from(*kind).map_err(|_| LocalForkFrameErrorV1::Malformed)? {
        1 if intent.len() == 2 => Ok(LocalForkAdmissionRequestV1::Bind {
            operation_id: hash(&intent[1])?,
        }),
        2 if intent.len() == 8 => Ok(LocalForkAdmissionRequestV1::Fork {
            operation_id: hash(&intent[1])?,
            parent_id: timeline(&intent[2])?,
            cut: integer(&intent[3])?,
            descriptor_hash: hash(&intent[4])?,
            composition_hash: hash(&intent[5])?,
            attribution_required: boolean(&intent[6])?,
            child_name: name(&intent[7])?,
        }),
        _ => Err(LocalForkFrameErrorV1::Malformed),
    }
}

/// Semantic FAL1 checks run only on a structurally complete request.
fn validate_semantics(
    request: LocalForkAdmissionRequestV1,
) -> Result<LocalForkAdmissionRequestV1, LocalForkFrameErrorV1> {
    let valid = match &request {
        LocalForkAdmissionRequestV1::Bind { operation_id } => *operation_id != Hash::zero(),
        LocalForkAdmissionRequestV1::Fork {
            operation_id,
            parent_id,
            descriptor_hash,
            composition_hash,
            child_name,
            ..
        } => {
            [operation_id, descriptor_hash, composition_hash]
                .into_iter()
                .all(|digest| *digest != Hash::zero())
                && !parent_id.inner().is_nil()
                && (1..=MAX_CHILD_NAME_BYTES_V1).contains(&child_name.len())
                && !child_name.contains('\0')
        }
    };
    if valid {
        Ok(request)
    } else {
        Err(LocalForkFrameErrorV1::Invalid)
    }
}

fn hash(value: &Value) -> Result<Hash, LocalForkFrameErrorV1> {
    let Value::Bytes(bytes) = value else {
        return Err(LocalForkFrameErrorV1::Malformed);
    };
    <[u8; 32]>::try_from(bytes.as_slice())
        .map(Hash::from_bytes)
        .map_err(|_| LocalForkFrameErrorV1::Malformed)
}

fn timeline(value: &Value) -> Result<TimelineId, LocalForkFrameErrorV1> {
    let Value::Bytes(bytes) = value else {
        return Err(LocalForkFrameErrorV1::Malformed);
    };
    <[u8; 16]>::try_from(bytes.as_slice())
        .map(|bytes| TimelineId::from_ulid(Ulid::from_bytes(bytes)))
        .map_err(|_| LocalForkFrameErrorV1::Malformed)
}

fn integer(value: &Value) -> Result<u64, LocalForkFrameErrorV1> {
    let Value::Integer(value) = value else {
        return Err(LocalForkFrameErrorV1::Malformed);
    };
    u64::try_from(*value).map_err(|_| LocalForkFrameErrorV1::Malformed)
}

const fn boolean(value: &Value) -> Result<bool, LocalForkFrameErrorV1> {
    match value {
        Value::Bool(value) => Ok(*value),
        _ => Err(LocalForkFrameErrorV1::Malformed),
    }
}

fn name(value: &Value) -> Result<String, LocalForkFrameErrorV1> {
    match value {
        Value::Text(name) => Ok(name.clone()),
        _ => Err(LocalForkFrameErrorV1::Malformed),
    }
}

fn request_digest(payload: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FAL1_DOMAIN);
    hasher.update(payload);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

const fn map_peer_error(error: LocalForkAuthenticationErrorV1) -> LocalForkFrameErrorV1 {
    match error {
        LocalForkAuthenticationErrorV1::PeerUnauthenticated => LocalForkFrameErrorV1::Peer,
        LocalForkAuthenticationErrorV1::CredentialUnavailable
        | LocalForkAuthenticationErrorV1::CredentialInvalid => LocalForkFrameErrorV1::Transport,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};
    use std::{net::Shutdown, os::unix::fs::symlink};

    #[test]
    fn exact_adr_bind_golden_vector_decodes() {
        let mut payload = vec![0x83, 0x64, b'F', b'A', b'L', b'1', 1, 0x82, 1, 0x58, 0x20];
        payload.extend_from_slice(&[1; 32]);
        assert_eq!(payload.len(), 43);
        assert_eq!(
            &Sha256::digest(&payload)[..],
            &[
                0x5e, 0xe5, 0x12, 0x99, 0x26, 0x05, 0xf2, 0x30, 0x08, 0x6f, 0x59, 0x00, 0x12, 0xb0,
                0x9f, 0xf5, 0x37, 0x8d, 0x02, 0x59, 0x2b, 0x81, 0x31, 0x5c, 0xe0, 0x71, 0x5e, 0xcf,
                0xfb, 0x1c, 0x0a, 0x5b,
            ]
        );
        assert_eq!(
            decode_request(&payload),
            Ok(LocalForkAdmissionRequestV1::Bind {
                operation_id: Hash::from_bytes([1; 32]),
            })
        );
        assert_eq!(
            request_digest(&payload).as_bytes(),
            &[
                0xe0, 0xe4, 0xec, 0x22, 0x7d, 0xdd, 0xad, 0x24, 0xde, 0x5b, 0x28, 0x3f, 0x1a, 0x88,
                0x8c, 0x94, 0x39, 0xed, 0x26, 0x46, 0x8e, 0x81, 0x69, 0x33, 0x7b, 0xef, 0xd2, 0xb7,
                0x82, 0xe2, 0x14, 0xda,
            ]
        );
    }

    #[test]
    fn exact_adr_response_golden_vectors_encode() {
        let bind = LocalForkAdmissionResponseV1::bind_ok(Hash::from_bytes([5; 32]));
        let bind_cbor = bind.to_canonical_cbor();
        assert_eq!(
            bind_cbor,
            [0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 0, 0x82, 1, 0x58, 0x20,]
                .into_iter()
                .chain([5; 32])
                .collect::<Vec<_>>()
        );
        let unauth =
            LocalForkAdmissionResponseV1::rejected(LocalForkAdmissionCodeV1::Unauthenticated)
                .to_canonical_cbor();
        assert_eq!(
            unauth,
            vec![0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 1, 0xf6]
        );
        assert_eq!(
            &Sha256::digest(bind_cbor.as_slice())[..],
            &[
                0xf6, 0x97, 0xc6, 0x76, 0x72, 0x28, 0xeb, 0xce, 0xf2, 0x86, 0xbe, 0x21, 0x81, 0xad,
                0x1a, 0xd0, 0xf4, 0xff, 0x59, 0x93, 0xfb, 0x04, 0xaa, 0x82, 0xe3, 0x4b, 0x2e, 0x7e,
                0x55, 0x63, 0x10, 0x74
            ]
        );
        assert_eq!(
            &Sha256::digest(&unauth)[..],
            &[
                0xcd, 0xc8, 0x6d, 0x22, 0x86, 0xbe, 0xa5, 0xad, 0x8d, 0x61, 0xf9, 0x75, 0x0e, 0xe4,
                0xab, 0xf1, 0x9c, 0x0d, 0xeb, 0x6b, 0x74, 0x61, 0x78, 0xa5, 0x24, 0x06, 0xbb, 0x8f,
                0xe1, 0xfc, 0x54, 0xc3
            ]
        );
    }

    #[test]
    fn exact_adr_maximum_fork_golden_vector_decodes() {
        let mut payload = vec![0x83, 0x64, b'F', b'A', b'L', b'1', 1, 0x88, 2, 0x58, 0x20];
        payload.extend_from_slice(&[1; 32]);
        payload.push(0x50);
        payload.extend_from_slice(&[2; 16]);
        payload.extend_from_slice(&[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        payload.extend_from_slice(&[0x58, 0x20]);
        payload.extend_from_slice(&[3; 32]);
        payload.extend_from_slice(&[0x58, 0x20]);
        payload.extend_from_slice(&[4; 32]);
        payload.extend_from_slice(&[0xf5, 0x78, 0x80]);
        payload.extend_from_slice(&[b'a'; 128]);
        assert_eq!(payload.len(), 268);
        assert_eq!(
            &Sha256::digest(&payload)[..],
            &[
                0xec, 0xb0, 0xbb, 0x75, 0xc7, 0x51, 0x5d, 0x6d, 0xe6, 0x9a, 0x83, 0x89, 0x17, 0x09,
                0xc6, 0x3d, 0xaf, 0xde, 0xb0, 0xb9, 0x3a, 0xd5, 0x5c, 0x18, 0xb2, 0x09, 0x47, 0x72,
                0x9e, 0x28, 0x5d, 0x80,
            ]
        );
        let mut zero_parent = payload.clone();
        // The parent TimelineId starts after the canonical FAL1/Fork prefix,
        // operation ID, and byte-string marker.
        zero_parent[44..60].fill(0);
        assert_eq!(
            decode_request(&zero_parent),
            Err(LocalForkFrameErrorV1::Invalid)
        );
        assert_eq!(
            decode_request(&payload),
            Ok(LocalForkAdmissionRequestV1::Fork {
                operation_id: Hash::from_bytes([1; 32]),
                parent_id: TimelineId::from_ulid(ulid::Ulid::from_bytes([2; 16])),
                cut: u64::MAX,
                descriptor_hash: Hash::from_bytes([3; 32]),
                composition_hash: Hash::from_bytes([4; 32]),
                attribution_required: true,
                child_name: "a".repeat(128),
            })
        );
    }

    #[test]
    fn every_rejection_code_has_an_exact_farl1_vector() {
        for (code, wire) in [
            (LocalForkAdmissionCodeV1::Unauthenticated, 1),
            (LocalForkAdmissionCodeV1::Conflict, 2),
            (LocalForkAdmissionCodeV1::StaleFoldBoundary, 3),
            (LocalForkAdmissionCodeV1::ParentChanged, 4),
            (LocalForkAdmissionCodeV1::AuthorityUnavailable, 5),
            (LocalForkAdmissionCodeV1::Indeterminate, 6),
            (LocalForkAdmissionCodeV1::InvalidRequest, 7),
        ] {
            assert_eq!(
                LocalForkAdmissionResponseV1::rejected(code).to_canonical_cbor(),
                vec![0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, wire, 0xf6]
            );
        }
    }

    #[test]
    fn exact_fork_response_golden_vector_has_stable_sha256() {
        let bytes = LocalForkAdmissionResponseV1::fork_ok(
            TimelineId::from_ulid(ulid::Ulid::from_bytes([6; 16])),
            Hash::from_bytes([7; 32]),
        )
        .to_canonical_cbor();
        assert_eq!(
            bytes,
            [0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 0, 0x83, 2, 0x50]
                .into_iter()
                .chain([6; 16])
                .chain([0x58, 0x20])
                .chain([7; 32])
                .collect::<Vec<_>>()
        );
        assert_eq!(
            &Sha256::digest(&bytes)[..],
            &[
                0x07, 0xc4, 0x8d, 0xa0, 0x5f, 0xaa, 0x6d, 0x48, 0x55, 0xd8, 0x43, 0xf5, 0x2c, 0x6f,
                0x98, 0x30, 0x2f, 0x8f, 0x99, 0xca, 0xb5, 0x42, 0xcf, 0x5f, 0xe2, 0xad, 0x21, 0x06,
                0x3e, 0xf8, 0xd5, 0x43
            ]
        );
    }

    #[test]
    fn decoder_rejects_noncanonical_and_semantically_invalid_values() {
        let mut valid = vec![0x83, 0x64, b'F', b'A', b'L', b'1', 1, 0x82, 1, 0x58, 0x20];
        valid.extend_from_slice(&[1; 32]);
        let mut noncanonical = valid.clone();
        noncanonical.splice(6..7, [0x18, 1]);
        assert_eq!(
            decode_request(&noncanonical),
            Err(LocalForkFrameErrorV1::Malformed)
        );
        assert_eq!(
            decode_request(&[0xa0]),
            Err(LocalForkFrameErrorV1::Malformed)
        );
        let mut zero = valid;
        zero[11..].fill(0);
        assert_eq!(decode_request(&zero), Err(LocalForkFrameErrorV1::Invalid));
    }

    #[test]
    fn decoder_rejects_each_fal1_shape_before_authority_work() -> io::Result<()> {
        let mut bind = vec![0x83, 0x64, b'F', b'A', b'L', b'1', 1, 0x82, 1, 0x58, 0x20];
        bind.extend_from_slice(&[1; 32]);
        let mut trailing_cbor = bind.clone();
        trailing_cbor.push(0);
        assert_eq!(
            decode_request(&trailing_cbor),
            Err(LocalForkFrameErrorV1::Malformed)
        );

        let encode = |value: Value| -> io::Result<Vec<u8>> {
            let mut bytes = Vec::new();
            ciborium::into_writer(&value, &mut bytes).map_err(io::Error::other)?;
            Ok(bytes)
        };
        let malformed = [
            Value::Array(vec![
                Value::Text("wrong".to_owned()),
                Value::Integer(1.into()),
                Value::Array(vec![]),
            ]),
            Value::Array(vec![
                Value::Text("FAL1".to_owned()),
                Value::Integer(2.into()),
                Value::Array(vec![]),
            ]),
            Value::Array(vec![
                Value::Text("FAL1".to_owned()),
                Value::Integer(1.into()),
                Value::Integer(1.into()),
            ]),
            Value::Array(vec![
                Value::Text("FAL1".to_owned()),
                Value::Integer(1.into()),
                Value::Array(vec![Value::Text("bind".to_owned())]),
            ]),
            Value::Array(vec![
                Value::Text("FAL1".to_owned()),
                Value::Integer(1.into()),
                Value::Array(vec![Value::Integer(3.into())]),
            ]),
        ];
        for value in malformed {
            assert_eq!(
                decode_request(&encode(value)?),
                Err(LocalForkFrameErrorV1::Malformed)
            );
        }

        Ok(())
    }

    #[test]
    fn decoder_rejects_each_fork_field_before_authority_work() -> io::Result<()> {
        let encode = |value: Value| -> io::Result<Vec<u8>> {
            let mut bytes = Vec::new();
            ciborium::into_writer(&value, &mut bytes).map_err(io::Error::other)?;
            Ok(bytes)
        };

        let fork_with = |index: usize, replacement: Value| {
            let mut intent = vec![
                Value::Integer(2.into()),
                Value::Bytes(vec![1; 32]),
                Value::Bytes(vec![2; 16]),
                Value::Integer(0.into()),
                Value::Bytes(vec![3; 32]),
                Value::Bytes(vec![4; 32]),
                Value::Bool(false),
                Value::Text("child".to_owned()),
            ];
            intent[index] = replacement;
            Value::Array(vec![
                Value::Text("FAL1".to_owned()),
                Value::Integer(1.into()),
                Value::Array(intent),
            ])
        };
        for (index, replacement) in [
            (1, Value::Text("not-a-hash".to_owned())),
            (2, Value::Text("not-a-timeline".to_owned())),
            (3, Value::Text("not-a-cut".to_owned())),
            (4, Value::Bytes(vec![3; 31])),
            (5, Value::Bytes(vec![4; 31])),
            (6, Value::Text("not-a-bool".to_owned())),
            (7, Value::Integer(1.into())),
        ] {
            assert_eq!(
                decode_request(&encode(fork_with(index, replacement))?),
                Err(LocalForkFrameErrorV1::Malformed)
            );
        }
        for (index, replacement) in [
            (1, Value::Bytes(vec![1; 31])),
            (2, Value::Bytes(vec![2; 15])),
        ] {
            assert_eq!(
                decode_request(&encode(fork_with(index, replacement))?),
                Err(LocalForkFrameErrorV1::Malformed)
            );
        }
        assert_eq!(
            decode_request(&encode(Value::Array(vec![
                Value::Text("FAL1".to_owned()),
                Value::Integer(1.into()),
                Value::Array(vec![Value::Integer((-1).into())]),
            ]))?),
            Err(LocalForkFrameErrorV1::Malformed)
        );
        assert_eq!(
            decode_request(&[0xff]),
            Err(LocalForkFrameErrorV1::Malformed)
        );
        for name in ["", "has\0nul", "a".repeat(129).as_str()] {
            assert_eq!(
                decode_request(&encode(fork_with(7, Value::Text(name.to_owned())))?),
                Err(LocalForkFrameErrorV1::Invalid)
            );
        }

        assert_eq!(
            map_peer_error(LocalForkAuthenticationErrorV1::PeerUnauthenticated),
            LocalForkFrameErrorV1::Peer
        );
        for error in [
            LocalForkAuthenticationErrorV1::CredentialUnavailable,
            LocalForkAuthenticationErrorV1::CredentialInvalid,
        ] {
            assert_eq!(map_peer_error(error), LocalForkFrameErrorV1::Transport);
        }
        Ok(())
    }

    #[test]
    fn decoder_checks_every_structural_field_before_semantics() -> io::Result<()> {
        let encode = |value: Value| -> io::Result<Vec<u8>> {
            let mut bytes = Vec::new();
            ciborium::into_writer(&value, &mut bytes).map_err(io::Error::other)?;
            Ok(bytes)
        };
        let fork_with = |index: usize, replacement: Value| {
            let mut intent = vec![
                Value::Integer(2.into()),
                Value::Bytes(vec![1; 32]),
                Value::Bytes(vec![2; 16]),
                Value::Integer(0.into()),
                Value::Bytes(vec![3; 32]),
                Value::Bytes(vec![4; 32]),
                Value::Bool(false),
                Value::Text("child".to_owned()),
            ];
            intent[index] = replacement;
            Value::Array(vec![
                Value::Text("FAL1".to_owned()),
                Value::Integer(1.into()),
                Value::Array(intent),
            ])
        };
        // Structure is checked in full before semantics: a zero operation ID
        // with a malformed later field still closes silently.
        let zero_operation_bad_tail = Value::Array(vec![
            Value::Text("FAL1".to_owned()),
            Value::Integer(1.into()),
            Value::Array(vec![
                Value::Integer(2.into()),
                Value::Bytes(vec![0; 32]),
                Value::Bytes(vec![2; 16]),
                Value::Integer(0.into()),
                Value::Bytes(vec![3; 32]),
                Value::Bytes(vec![4; 32]),
                Value::Bool(false),
                Value::Integer(1.into()),
            ]),
        ]);
        assert_eq!(
            decode_request(&encode(zero_operation_bad_tail)?),
            Err(LocalForkFrameErrorV1::Malformed)
        );
        for (index, zero) in [
            (1, Value::Bytes(vec![0; 32])),
            (4, Value::Bytes(vec![0; 32])),
            (5, Value::Bytes(vec![0; 32])),
        ] {
            assert_eq!(
                decode_request(&encode(fork_with(index, zero))?),
                Err(LocalForkFrameErrorV1::Invalid)
            );
        }
        Ok(())
    }

    #[test]
    fn complete_framed_request_is_bound_to_the_kernel_authenticated_peer() -> io::Result<()> {
        let credentials = crate::local_fork_authentication::test_credentials_for_current_peer()
            .map_err(io::Error::other)?;
        let payload = [0x83, 0x64, b'F', b'A', b'L', b'1', 1, 0x82, 1, 0x58, 0x20]
            .into_iter()
            .chain([6; 32])
            .collect::<Vec<_>>();
        let mut frame = u32::try_from(payload.len())
            .map_err(|_| io::Error::other("FAL1 payload length exceeds u32"))?
            .to_be_bytes()
            .to_vec();
        frame.extend_from_slice(&payload);
        let (mut client, mut server) = UnixStream::pair()?;
        client.write_all(&frame)?;
        client.shutdown(Shutdown::Write)?;

        let completed = read_completed_request(&mut server, &credentials)
            .map_err(|error| io::Error::other(format!("request rejected: {error:?}")))?;
        assert_eq!(
            completed.request,
            LocalForkAdmissionRequestV1::Bind {
                operation_id: Hash::from_bytes([6; 32]),
            }
        );
        assert_eq!(completed.host_request_id, request_digest(&payload));
        Ok(())
    }

    #[test]
    fn listener_rejects_an_unregistered_kernel_peer_before_reading_a_frame() -> io::Result<()> {
        let credentials =
            crate::local_fork_authentication::test_credentials_rejecting_current_peer()
                .map_err(io::Error::other)?;
        let (_client, mut server) = UnixStream::pair()?;
        assert_eq!(
            read_completed_request(&mut server, &credentials).err(),
            Some(LocalForkFrameErrorV1::Peer)
        );
        Ok(())
    }

    fn deadline() -> Instant {
        Instant::now() + FRAME_TIMEOUT
    }

    #[test]
    fn framing_closes_once_the_whole_request_deadline_expires() -> io::Result<()> {
        let (mut client, mut server) = UnixStream::pair()?;
        client.write_all(&[0, 0, 0, 1, 7])?;
        client.shutdown(Shutdown::Write)?;
        assert_eq!(
            read_framed_payload(&mut server, Instant::now()),
            Err(LocalForkFrameErrorV1::Transport)
        );

        // A peer that keeps trickling bytes cannot extend the deadline: the
        // remaining time shrinks across reads instead of re-arming in full.
        let (mut client, mut server) = UnixStream::pair()?;
        let writer = std::thread::spawn(move || -> io::Result<()> {
            for byte in [0, 0, 0, 2, 7] {
                client.write_all(&[byte])?;
                std::thread::sleep(Duration::from_millis(40));
            }
            std::thread::sleep(Duration::from_millis(200));
            client.shutdown(Shutdown::Write)
        });
        let started = Instant::now();
        assert_eq!(
            read_framed_payload(&mut server, started + Duration::from_millis(100)),
            Err(LocalForkFrameErrorV1::Transport)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        writer
            .join()
            .map_err(|_| io::Error::other("trickle writer panicked"))??;
        Ok(())
    }

    #[test]
    fn framing_requires_exact_length_and_eof() -> io::Result<()> {
        let payload = vec![1, 2, 3];
        let mut frame = 3_u32.to_be_bytes().to_vec();
        frame.extend_from_slice(&payload);
        let (mut client, mut server) = UnixStream::pair()?;
        client.write_all(&frame)?;
        client.shutdown(Shutdown::Write)?;
        assert_eq!(read_framed_payload(&mut server, deadline()), Ok(payload));

        let (mut client, mut server) = UnixStream::pair()?;
        let fragments = [vec![0, 0], vec![0, 3, 1], vec![2, 3]];
        let writer = std::thread::spawn(move || -> io::Result<()> {
            for fragment in fragments {
                client.write_all(&fragment)?;
            }
            client.shutdown(Shutdown::Write)
        });
        assert_eq!(
            read_framed_payload(&mut server, deadline()),
            Ok(vec![1, 2, 3])
        );
        writer
            .join()
            .map_err(|_| io::Error::other("fragment writer panicked"))??;

        let (mut client, mut server) = UnixStream::pair()?;
        client.write_all(&[0, 0, 0, 1, 7])?;
        server.set_nonblocking(true)?;
        assert_eq!(
            read_framed_payload(&mut server, deadline()),
            Err(LocalForkFrameErrorV1::Transport)
        );

        let (mut client, mut server) = UnixStream::pair()?;
        client.write_all(&[0, 0, 0, 1, 7, 8])?;
        client.shutdown(Shutdown::Write)?;
        assert_eq!(
            read_framed_payload(&mut server, deadline()),
            Err(LocalForkFrameErrorV1::Transport)
        );

        let (client, mut server) = UnixStream::pair()?;
        client.shutdown(Shutdown::Write)?;
        assert_eq!(
            read_framed_payload(&mut server, deadline()),
            Err(LocalForkFrameErrorV1::Transport)
        );

        let (mut client, mut server) = UnixStream::pair()?;
        client.write_all(&[0, 0, 0, 2, 7])?;
        client.shutdown(Shutdown::Write)?;
        assert_eq!(
            read_framed_payload(&mut server, deadline()),
            Err(LocalForkFrameErrorV1::Transport)
        );

        let (mut client, mut server) = UnixStream::pair()?;
        client.write_all(&[0, 0, 0, 0])?;
        client.shutdown(Shutdown::Write)?;
        assert_eq!(
            read_framed_payload(&mut server, deadline()),
            Err(LocalForkFrameErrorV1::Malformed)
        );

        let (mut client, mut server) = UnixStream::pair()?;
        let length = u32::try_from(MAX_FAL1_PAYLOAD_BYTES_V1 + 1)
            .map_err(|_| io::Error::other("FAL1 maximum payload exceeds u32"))?;
        client.write_all(&length.to_be_bytes())?;
        client.shutdown(Shutdown::Write)?;
        assert_eq!(
            read_framed_payload(&mut server, deadline()),
            Err(LocalForkFrameErrorV1::Malformed)
        );
        Ok(())
    }

    #[test]
    fn response_is_prefixed_and_pathname_listener_is_private() -> io::Result<()> {
        let (mut writer, mut reader) = UnixStream::pair()?;
        write_response(
            &mut writer,
            &LocalForkAdmissionResponseV1::rejected(LocalForkAdmissionCodeV1::InvalidRequest),
        )?;
        let mut prefix = [0; 4];
        reader.read_exact(&mut prefix)?;
        assert_eq!(u32::from_be_bytes(prefix), 10);
        let mut payload = vec![0; 10];
        reader.read_exact(&mut payload)?;
        assert_eq!(
            payload,
            vec![0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 7, 0xf6]
        );

        let directory = tempfile::tempdir().map_err(io::Error::other)?;
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750))?;
        validate_socket_parent(directory.path(), uid, gid)?;
        let socket = directory.path().join("fork-admission.sock");
        let listener = bind_pathname_listener(&socket)?;
        assert_eq!(fs::metadata(&socket)?.permissions().mode() & 0o777, 0o660);
        let client_path = socket.clone();
        let client = std::thread::spawn(move || UnixStream::connect(client_path));
        let (_peer, _) = listener.accept()?;
        client
            .join()
            .map_err(|_| io::Error::other("pathname client panicked"))??;
        drop(listener);
        assert!(bind_pathname_listener(&socket).is_err());

        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755))?;
        assert!(validate_socket_parent(directory.path(), uid, gid).is_err());
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750))?;
        assert!(validate_socket_parent(directory.path(), uid.wrapping_add(1), gid).is_err());
        assert!(validate_socket_parent(directory.path(), uid, gid.wrapping_add(1)).is_err());
        Ok(())
    }

    #[test]
    fn pathname_listener_refuses_missing_or_indirect_parents_before_bind() -> io::Result<()> {
        let missing_parent = bind_pathname_listener(Path::new("/"))
            .err()
            .ok_or_else(|| io::Error::other("root path unexpectedly accepted as socket"))?;
        assert_eq!(missing_parent.kind(), io::ErrorKind::InvalidInput);

        let directory = tempfile::tempdir().map_err(io::Error::other)?;
        let missing = bind_pathname_listener(&directory.path().join("missing/fork-admission.sock"))
            .err()
            .ok_or_else(|| io::Error::other("a missing socket parent was accepted"))?;
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);

        let target = directory.path().join("target");
        fs::create_dir(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o750))?;
        let indirect = directory.path().join("indirect");
        symlink(&target, &indirect)?;
        let error = bind_pathname_listener(&indirect.join("fork-admission.sock"))
            .err()
            .ok_or_else(|| io::Error::other("symlinked socket parent unexpectedly accepted"))?;
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!indirect.join("fork-admission.sock").exists());
        Ok(())
    }
}
