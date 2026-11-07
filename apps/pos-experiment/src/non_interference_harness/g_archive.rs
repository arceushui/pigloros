//! The `NI-ARCHIVE-009` capture adapter of the non-interference harness
//! (ADR-062 Revision 8 slice N1b, #1284; ADR-127 section 7).
//!
//! The row shares the G-PUB subject, seam store and denied sibling
//! ([`super::g_pub`]): the Events each mode produced are imported into the
//! seam beside the denied sibling Timeline and exported with
//! `export_timeline_own`. The export is projected onto the RVA1 members
//! (`pos_conformance::run_evidence_archive`), written by the RVA1 builder
//! and imported by the independent evaluator-side reader
//! (`pos_reference::run_evidence_archive`).
//!
//! # Value-dependent inputs
//!
//! The host stages every member to a file of a staging directory beside the
//! seam store, outside every captured path. The unauthorized value decides:
//! - each staging file's name, its read-only flag and its mtime, and a denied
//!   staging file holding the value at value-dependent compressibility. None
//!   of these reaches the archive: the builder has no parameter that carries
//!   them, RVA1 has no compressor, and the tar block layout is fixed;
//! - the insertion order (sorted when its first byte is even, reversed
//!   otherwise) and the read chunk size (1 + first byte mod 7). These reach
//!   the builder, which sorts and reads to the end.
//!
//! The staging directory is removed after the capture and never named in an
//! error or a log.
//!
//! # Surfaces
//!
//! The six surfaces are byte-exact (ADR-127 section 7). When the honest
//! import admits the archive:
//! - Member table: `[[name, mode, size, digest]...]`; operationally the
//!   header walk.
//! - archive bytes: `[[name, data]...]`; publicly and operationally the exact
//!   RVA1 bytes.
//! - decompressed bundle: `[[name, data]...]`.
//! - digest: the member table; publicly `[archive digest, [member
//!   digests]]`.
//! - evaluator import: the import outcomes; publicly `[outcomes, archive
//!   digest]`.
//! - logs: `[["write", "ok", member count, archive length], ["import",
//!   category]...]`.
//!
//! A refused import records `["refused", category]` in the authoritative
//! facets of the first four surfaces and in the decompressed bundle, and
//! `[archive digest, null]` publicly for the digest. The `Denial` variant also
//! imports the archive once with a wrong expected digest (its byte 0 is
//! flipped by XOR with `0xff`), as the G-PUB public probe does, and records the closed
//! `DigestMismatch` category.

use std::fs::{self, File, FileTimes};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use ciborium::Value;
use pos_conformance::run_evidence_archive::{
    run_evidence_members_v1, RunEvidenceArchiveBuilderV1, RunEvidenceMemberV1,
};
use pos_conformance::{NonInterferenceRawOperationalV1, NonInterferenceVariantV1};
use pos_core::Event;
use pos_reference::run_evidence_archive::{
    import_run_evidence_archive_v1, ImportedRunEvidenceArchiveV1, RunEvidenceArchiveErrorV1,
};

use super::capture::{digest, encode, text, uint, SurfacesV1};
use super::g_pub::{seam_export, GPubRunV1};
use super::{hex, NonInterferenceNonExecutedCauseV1};

/// The staging directory, beside the run's seam store.
pub const G_ARCHIVE_STAGING_DIRECTORY_V1: &str = "g-archive-staging";

const BLOCK: usize = 512;
const MEMBER_MODE: u64 = 0o644;
const ADMITTED: &str = "admitted";

/// One staged member: its archive name and its staging file.
pub(super) struct StagedMemberV1 {
    pub(super) name: String,
    pub(super) path: PathBuf,
}

/// The archive encoder: the staged members in insertion order and the read
/// chunk size, to the archive bytes.
type EncoderV1 = dyn Fn(&[StagedMemberV1], usize) -> Option<Vec<u8>>;

/// Capture the six `NI-ARCHIVE-009` surfaces of one run.
pub(super) fn archive_surfaces(
    run: &GPubRunV1<'_>,
    events: &[Event],
    store: &Path,
) -> Result<SurfacesV1, NonInterferenceNonExecutedCauseV1> {
    capture_with_encoder(run, events, store, &rva1_encoder)
}

/// The capture with an injected encoder. Only [`archive_surfaces`] calls it
/// outside the unit tests, always with the RVA1 builder.
fn capture_with_encoder(
    run: &GPubRunV1<'_>,
    events: &[Event],
    store: &Path,
    encoder: &EncoderV1,
) -> Result<SurfacesV1, NonInterferenceNonExecutedCauseV1> {
    let staging = store.with_file_name(G_ARCHIVE_STAGING_DIRECTORY_V1);
    let written = seam_export(run, events, store)
        .and_then(|export| run_evidence_members_v1(&export).ok())
        .and_then(|members| stage(&staging, run.unauthorized_value, &members))
        .and_then(|staged| {
            encoder(staged.as_slice(), chunk_size(run.unauthorized_value))
                .map(|bytes| (staged.len(), bytes))
        });
    let removed = fs::remove_dir_all(&staging).is_ok();
    written
        .filter(|_| removed)
        .map(|(count, bytes)| surfaces(run.variant, count, &bytes))
        .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
}

/// The RVA1 builder adapter: it reads each staged file in chunks and ignores
/// the file's name and metadata.
fn rva1_encoder(staged: &[StagedMemberV1], chunk: usize) -> Option<Vec<u8>> {
    let mut builder = RunEvidenceArchiveBuilderV1::new();
    staged
        .iter()
        .try_for_each(|member| {
            File::open(&member.path).ok().and_then(|file| {
                builder
                    .insert(&member.name, ChunkedV1 { inner: file, chunk })
                    .ok()
            })
        })
        .and_then(|()| builder.finish().ok())
        .map(|archive| archive.bytes)
}

/// A reader that returns at most `chunk` bytes per read.
struct ChunkedV1<R> {
    inner: R,
    chunk: usize,
}

impl<R: Read> Read for ChunkedV1<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let length = buffer.len().min(self.chunk);
        self.inner.read(&mut buffer[..length])
    }
}

fn first_byte_even(unauthorized_value: &[u8]) -> bool {
    unauthorized_value.first().is_some_and(|byte| byte % 2 == 0)
}

fn chunk_size(unauthorized_value: &[u8]) -> usize {
    1 + usize::from(unauthorized_value.first().copied().unwrap_or_default() % 7)
}

/// The denied staging file's bytes: the value repeated when its first byte is
/// even (compressible), its BLAKE3 output stream otherwise (incompressible).
fn denied_bytes(unauthorized_value: &[u8]) -> Vec<u8> {
    let length = 64 * unauthorized_value.len();
    if first_byte_even(unauthorized_value) {
        unauthorized_value.repeat(64)
    } else {
        let mut bytes = vec![0; length];
        blake3::Hasher::new()
            .update(unauthorized_value)
            .finalize_xof()
            .fill(&mut bytes);
        bytes
    }
}

/// Write one staging file with a value-dependent mtime and read-only flag.
fn stage_file(path: &Path, data: &[u8], unauthorized_value: &[u8]) -> Option<()> {
    let first = unauthorized_value.first().copied().unwrap_or_default();
    let modified = SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(first) * 86_400);
    fs::write(path, data)
        .and_then(|()| File::options().write(true).open(path))
        .and_then(|file| file.set_times(FileTimes::new().set_modified(modified)))
        .and_then(|()| fs::metadata(path))
        .and_then(|metadata| {
            let mut permissions = metadata.permissions();
            if !first_byte_even(unauthorized_value) {
                permissions.set_readonly(true);
            }
            fs::set_permissions(path, permissions)
        })
        .ok()
}

/// Stage the members and the denied file; return the members in insertion
/// order.
fn stage(
    directory: &Path,
    unauthorized_value: &[u8],
    members: &[RunEvidenceMemberV1],
) -> Option<Vec<StagedMemberV1>> {
    let tag = hex(unauthorized_value);
    fs::create_dir_all(directory)
        .ok()
        .and_then(|()| {
            stage_file(
                &directory.join(format!("denied-{tag}.stage")),
                &denied_bytes(unauthorized_value),
                unauthorized_value,
            )
        })
        .and_then(|()| {
            members
                .iter()
                .enumerate()
                .map(|(index, member)| {
                    let path = directory.join(format!("stage-{tag}-{index}"));
                    stage_file(&path, &member.data, unauthorized_value).map(|()| StagedMemberV1 {
                        name: member.name.clone(),
                        path,
                    })
                })
                .collect::<Option<Vec<_>>>()
        })
        .map(|mut staged| {
            if !first_byte_even(unauthorized_value) {
                staged.reverse();
            }
            staged
        })
}

/// The 512-byte header blocks of an archive.
///
/// They are found by stepping over each header's declared padded size, up
/// to an all-zero block, the end of the input or a size field that is not 11
/// octal digits.
fn header_walk(bytes: &[u8]) -> Vec<u8> {
    let mut walk = Vec::new();
    // The index of the block that holds the next header.
    let mut next = 0;
    for (index, block) in bytes.chunks_exact(BLOCK).enumerate() {
        if index < next {
            continue;
        }
        if block.iter().all(|byte| *byte == 0) {
            break;
        }
        walk.extend_from_slice(block);
        let digits = &block[124..135];
        if !digits.iter().all(|digit| (b'0'..=b'7').contains(digit)) {
            break;
        }
        let size = digits
            .iter()
            .fold(0_usize, |size, digit| size * 8 + usize::from(digit - b'0'));
        next = index + 1 + size.div_ceil(BLOCK);
    }
    walk
}

fn category(result: &Result<ImportedRunEvidenceArchiveV1, RunEvidenceArchiveErrorV1>) -> String {
    result
        .as_ref()
        .map_or_else(|error| format!("{error:?}"), |_| ADMITTED.to_owned())
}

fn outcome(result: &Result<ImportedRunEvidenceArchiveV1, RunEvidenceArchiveErrorV1>) -> Value {
    result.as_ref().map_or_else(
        |error| refusal(*error),
        |imported| {
            Value::Array(vec![
                text(ADMITTED),
                uint(1),
                uint(imported.members.len() as u64),
            ])
        },
    )
}

fn refusal(error: RunEvidenceArchiveErrorV1) -> Value {
    Value::Array(vec![text("refused"), text(&format!("{error:?}"))])
}

/// The `Denial` probe's expected digest: byte 0 flipped by XOR with `0xff`.
const fn wrong_digest(mut digest: [u8; 32]) -> [u8; 32] {
    digest[0] ^= 0xff;
    digest
}

fn exact(bytes: &[u8]) -> NonInterferenceRawOperationalV1 {
    NonInterferenceRawOperationalV1::ByteExact(bytes.to_vec())
}

/// The six surfaces of one written archive.
fn surfaces(variant: NonInterferenceVariantV1, count: usize, bytes: &[u8]) -> SurfacesV1 {
    let archive_digest = digest(bytes);
    let mut imports = vec![import_run_evidence_archive_v1(bytes, &archive_digest)];
    if variant == NonInterferenceVariantV1::Denial {
        imports.push(import_run_evidence_archive_v1(
            bytes,
            &wrong_digest(archive_digest),
        ));
    }
    let outcomes = Value::Array(imports.iter().map(outcome).collect());
    let import_public = encode(&Value::Array(vec![
        outcomes.clone(),
        Value::Bytes(archive_digest.to_vec()),
    ]));
    let logs = encode(&Value::Array(
        std::iter::once(Value::Array(vec![
            text("write"),
            text("ok"),
            uint(count as u64),
            uint(bytes.len() as u64),
        ]))
        .chain(
            imports
                .iter()
                .map(|result| Value::Array(vec![text("import"), text(&category(result))])),
        )
        .collect(),
    ));
    let (table, bundle, digests) = match &imports[0] {
        Ok(imported) => imported_records(&archive_digest, imported),
        Err(error) => {
            let refused = encode(&refusal(*error));
            let digests = encode(&Value::Array(vec![
                Value::Bytes(archive_digest.to_vec()),
                Value::Null,
            ]));
            (refused.clone(), refused, digests)
        }
    };
    SurfacesV1 {
        authoritative: vec![
            table.clone(),
            bundle.clone(),
            bundle.clone(),
            table.clone(),
            encode(&outcomes),
            logs.clone(),
        ],
        public: vec![
            table,
            bytes.to_vec(),
            bundle.clone(),
            digests.clone(),
            import_public.clone(),
            logs.clone(),
        ],
        operational: vec![
            exact(&header_walk(bytes)),
            exact(bytes),
            exact(&bundle),
            exact(&digests),
            exact(&import_public),
            exact(&logs),
        ],
    }
}

/// The records of an admitted archive.
///
/// They are the member table `[[name, mode, size, digest]...]`, the bundle
/// `[[name, data]...]` and the digests `[archive digest, [member digests]]`.
fn imported_records(
    archive_digest: &[u8; 32],
    imported: &ImportedRunEvidenceArchiveV1,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let members = &imported.members;
    let table = members
        .iter()
        .map(|member| {
            Value::Array(vec![
                text(&member.name),
                uint(MEMBER_MODE),
                uint(member.size),
                Value::Bytes(member.digest.to_vec()),
            ])
        })
        .collect();
    let bundle = members
        .iter()
        .map(|member| Value::Array(vec![text(&member.name), Value::Bytes(member.data.clone())]))
        .collect();
    let digests = Value::Array(vec![
        Value::Bytes(archive_digest.to_vec()),
        Value::Array(
            members
                .iter()
                .map(|member| Value::Bytes(member.digest.to_vec()))
                .collect(),
        ),
    ]);
    (
        encode(&Value::Array(table)),
        encode(&Value::Array(bundle)),
        encode(&digests),
    )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    //! The sensitivity controls of ADR-127 section 7: each replaces the RVA1
    //! builder with a deliberately leaky encoder and must give a divergence
    //! at the stated first surface and facet.

    use std::time::UNIX_EPOCH;

    use pos_conformance::{
        execute_non_interference_pair, normalize_non_interference_capture_v1, ExecutionModeV1,
        NonInterferenceDivergenceCoordinateV1, NonInterferenceExecutionErrorV1,
        NonInterferenceRawCaptureV1,
    };

    use super::super::g_pub::{
        g_pub_experiment_v1, g_pub_fixture_v1, G_PUB_ARCHIVE_FIXTURE_ID_V1,
        G_PUB_CANARY_UNAUTHORIZED_V1, G_PUB_CONTROL_UNAUTHORIZED_V1, G_PUB_STORE_FILE_V1,
    };
    use super::super::session::recorded;
    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    /// A ustar archive of `(name, mtime, data)` in the given order, with the
    /// RVA1 header fields otherwise.
    fn ustar(entries: &[(String, u64, Vec<u8>)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (name, mtime, data) in entries {
            let mut header = [0_u8; BLOCK];
            header[..name.len()].copy_from_slice(name.as_bytes());
            header[100..108].copy_from_slice(b"0000644\0");
            header[108..116].copy_from_slice(b"0000000\0");
            header[116..124].copy_from_slice(b"0000000\0");
            header[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
            header[136..148].copy_from_slice(format!("{mtime:011o}\0").as_bytes());
            header[148..156].copy_from_slice(b"        ");
            header[156] = b'0';
            header[257..265].copy_from_slice(b"ustar\x0000");
            let sum = header.iter().map(|byte| u32::from(*byte)).sum::<u32>();
            header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
            bytes.extend_from_slice(&header);
            bytes.extend_from_slice(data);
            bytes.resize(bytes.len().next_multiple_of(BLOCK), 0);
        }
        bytes.resize(bytes.len() + 2 * BLOCK, 0);
        bytes
    }

    fn entry(member: &StagedMemberV1, name: String, mtime: u64) -> Option<(String, u64, Vec<u8>)> {
        fs::read(&member.path).ok().map(|data| (name, mtime, data))
    }

    fn sorted(staged: &[StagedMemberV1]) -> Vec<&StagedMemberV1> {
        let mut members = staged.iter().collect::<Vec<_>>();
        members.sort_by_cached_key(|member| member.name.clone());
        members
    }

    /// Keeps the insertion order.
    fn order_keeping(staged: &[StagedMemberV1], _: usize) -> Option<Vec<u8>> {
        staged
            .iter()
            .map(|member| entry(member, member.name.clone(), 0))
            .collect::<Option<Vec<_>>>()
            .map(|entries| ustar(&entries))
    }

    /// Copies each staging file's mtime into its header.
    fn mtime_copier(staged: &[StagedMemberV1], _: usize) -> Option<Vec<u8>> {
        sorted(staged)
            .into_iter()
            .map(|member| {
                fs::metadata(&member.path)
                    .and_then(|metadata| metadata.modified())
                    .ok()
                    .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
                    .and_then(|since| entry(member, member.name.clone(), since.as_secs()))
            })
            .collect::<Option<Vec<_>>>()
            .map(|entries| ustar(&entries))
    }

    /// Names each member after its staging file.
    fn staging_names(staged: &[StagedMemberV1], _: usize) -> Option<Vec<u8>> {
        sorted(staged)
            .into_iter()
            .map(|member| {
                member
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .and_then(|name| entry(member, name.to_owned(), 0))
            })
            .collect::<Option<Vec<_>>>()
            .map(|entries| ustar(&entries))
    }

    /// The control and canary captures of one Replay coordinate with
    /// `encoder`, and the case's first divergence.
    fn controlled(
        encoder: &EncoderV1,
    ) -> TestResult<(
        Option<NonInterferenceDivergenceCoordinateV1>,
        Vec<NonInterferenceRawCaptureV1>,
    )> {
        let fixture = g_pub_fixture_v1(
            G_PUB_ARCHIVE_FIXTURE_ID_V1,
            NonInterferenceVariantV1::Success,
            ExecutionModeV1::Replay,
        )?;
        let mut session = g_pub_experiment_v1(&fixture.permitted_input)?.start()?;
        let (_, events) = recorded(&mut session)?;
        let work = tempfile::tempdir()?;
        let mut raws = Vec::new();
        let case = execute_non_interference_pair(&fixture, |run| {
            let directory = work.path().join(format!("run-{}", raws.len()));
            fs::create_dir_all(&directory)
                .map_err(|_| NonInterferenceExecutionErrorV1::CaptureUnavailable)?;
            let raw = capture_with_encoder(
                &GPubRunV1 {
                    fixture_id: G_PUB_ARCHIVE_FIXTURE_ID_V1,
                    variant: run.subject.variant,
                    permitted_input: run.subject.permitted_input,
                    unauthorized_value: run.unauthorized_value,
                },
                &events,
                &directory.join(G_PUB_STORE_FILE_V1),
                encoder,
            )
            .map(|surfaces| surfaces.into_capture(G_PUB_ARCHIVE_FIXTURE_ID_V1))
            .map_err(|_| NonInterferenceExecutionErrorV1::CaptureUnavailable)?;
            raws.push(raw.clone());
            normalize_non_interference_capture_v1(G_PUB_ARCHIVE_FIXTURE_ID_V1, raw)
        })?;
        Ok((case.first_divergence, raws))
    }

    fn operational_bytes(raw: &NonInterferenceRawCaptureV1, index: usize) -> Vec<u8> {
        match &raw.operational[index] {
            NonInterferenceRawOperationalV1::ByteExact(bytes) => bytes.clone(),
            _ => Vec::new(),
        }
    }

    #[test]
    fn the_rva1_builder_gives_no_divergence() -> TestResult {
        let (divergence, raws) = controlled(&rva1_encoder)?;
        assert_eq!(divergence, None);
        assert_eq!(raws[0].public[1], raws[1].public[1]);
        Ok(())
    }

    #[test]
    fn each_leaky_encoder_diverges_at_its_stated_surface_and_facet() -> TestResult {
        // The values decide sorted and reversed insertion orders.
        assert!(first_byte_even(G_PUB_CONTROL_UNAUTHORIZED_V1));
        assert!(!first_byte_even(G_PUB_CANARY_UNAUTHORIZED_V1));
        let order_keeping: &EncoderV1 = &order_keeping;
        let mtime_copier: &EncoderV1 = &mtime_copier;
        let staging_names: &EncoderV1 = &staging_names;
        for (encoder, operational, categories) in [
            (order_keeping, false, ["admitted", "ClosureIncomplete"]),
            (mtime_copier, true, ["InvalidEncoding", "InvalidEncoding"]),
            (
                staging_names,
                true,
                ["ClosureIncomplete", "ClosureIncomplete"],
            ),
        ] {
            let (divergence, raws) = controlled(encoder)?;
            // The leak changes the archive bytes between control and canary.
            assert_ne!(raws[0].public[1], raws[1].public[1]);
            for (raw, category) in raws.iter().zip(categories) {
                assert!(
                    String::from_utf8_lossy(&raw.public[5]).contains(category),
                    "{category}"
                );
            }
            let coordinate = divergence.ok_or("no divergence")?;
            assert_eq!(coordinate.surface_ordinal, 0);
            let facets = (raws[0].authoritative[0].len() + raws[0].public[0].len()) as u64;
            assert_eq!(coordinate.byte_offset >= facets, operational);
            if operational {
                assert_ne!(
                    operational_bytes(&raws[0], 0),
                    operational_bytes(&raws[1], 0)
                );
            }
        }
        Ok(())
    }

    #[test]
    fn the_capture_reads_in_chunks_and_removes_its_staging_directory() -> TestResult {
        // A one-byte reader yields the same archive as one read.
        let directory = tempfile::tempdir()?;
        let members = [RunEvidenceMemberV1 {
            name: "RVA1".to_owned(),
            data: vec![0x82, 0x64, b'R', b'V', b'A', b'1', 0x01],
        }];
        let staged = stage(directory.path(), b"\x01", &members).ok_or("not staged")?;
        let mut whole = Vec::new();
        File::open(&staged[0].path)?.read_to_end(&mut whole)?;
        let mut chunked = Vec::new();
        ChunkedV1 {
            inner: File::open(&staged[0].path)?,
            chunk: 1,
        }
        .read_to_end(&mut chunked)?;
        assert_eq!(chunked, whole);
        assert_eq!(chunk_size(b"\x01"), 2);
        assert_eq!(chunk_size(b""), 1);
        // The denied file holds the value only when its first byte is even.
        assert_eq!(denied_bytes(b"\x02\x03"), b"\x02\x03".repeat(64));
        assert_eq!(denied_bytes(b"\x01").len(), 64);
        assert_ne!(denied_bytes(b"\x01"), vec![1; 64]);
        Ok(())
    }

    #[test]
    fn the_staging_follows_the_value() -> TestResult {
        let members = ["a", "b"].map(|name| RunEvidenceMemberV1 {
            name: name.to_owned(),
            data: name.as_bytes().to_vec(),
        });
        for (value, order, readonly) in [
            (&b"\x02z"[..], ["a", "b"], false),
            (b"\x03", ["b", "a"], true),
        ] {
            let directory = tempfile::tempdir()?;
            let staged = stage(directory.path(), value, &members).ok_or("not staged")?;
            assert_eq!(
                staged
                    .iter()
                    .map(|member| member.name.as_str())
                    .collect::<Vec<_>>(),
                order
            );
            let tag = hex(value);
            let denied = directory.path().join(format!("denied-{tag}.stage"));
            assert_eq!(fs::read(&denied)?, denied_bytes(value));
            for member in &staged {
                let index = usize::from(member.name == "b");
                assert_eq!(
                    member.path,
                    directory.path().join(format!("stage-{tag}-{index}"))
                );
                assert_eq!(fs::read(&member.path)?, member.name.as_bytes());
                let metadata = fs::metadata(&member.path)?;
                assert_eq!(metadata.permissions().readonly(), readonly);
                assert_eq!(
                    metadata.modified()?,
                    UNIX_EPOCH + Duration::from_secs(u64::from(value[0]) * 86_400)
                );
            }
        }
        // A staging directory that cannot be created stages nothing.
        let file = tempfile::NamedTempFile::new()?;
        assert!(stage(&file.path().join("staging"), b"\x02", &members).is_none());
        Ok(())
    }

    #[test]
    fn the_wrong_digest_flips_byte_zero() {
        let mut expected = [0x0f; 32];
        expected[0] = 0xf0;
        assert_eq!(wrong_digest([0x0f; 32]), expected);
    }

    #[test]
    fn the_header_walk_stops_at_a_zero_block_or_an_invalid_size() {
        let archive = ustar(&[("RVA1".to_owned(), 0, vec![1]), ("x".to_owned(), 0, vec![])]);
        assert_eq!(header_walk(&archive).len(), 2 * BLOCK);
        // A multi-digit size steps over three data blocks.
        let long = ustar(&[
            ("a".to_owned(), 0, vec![1; 1100]),
            ("b".to_owned(), 0, vec![2]),
        ]);
        let walk = header_walk(&long);
        assert_eq!(walk.len(), 2 * BLOCK);
        assert_eq!(walk[BLOCK], b'b');
        let mut broken = archive;
        broken[124] = b'9';
        assert_eq!(header_walk(&broken).len(), BLOCK);
        assert!(header_walk(&[0; BLOCK]).is_empty());
        assert!(header_walk(&[]).is_empty());
    }
}
