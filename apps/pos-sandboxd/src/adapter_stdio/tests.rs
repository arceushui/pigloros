use std::io::Write as _;
use std::os::fd::AsFd as _;

use rustix::fs::{fstat, FileType, OFlags};

use super::*;
use crate::test_fixtures::{TestPayload, TestResult};

/// R10 §8.1 `S`: a 70-byte valid Unavailable observation, an EAO1 frame
/// then an EOE1 frame.
const S: &str = "00000007826445414f3101000000378964454f45310103f6f6f6f688000000000000000058209cd8b956c8795d49680acf9b4a3e44ead3889f3e1f2caf8edbcb156e0d6dc02d";

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .filter_map(|index| u8::from_str_radix(&text[index..index + 2], 16).ok())
        .collect()
}

fn stream() -> Vec<u8> {
    hex(S)
}

/// One length-prefixed frame of `body`.
fn frame(body: &[u8]) -> Vec<u8> {
    let mut framed = u32::try_from(body.len())
        .unwrap_or(u32::MAX)
        .to_be_bytes()
        .to_vec();
    framed.extend_from_slice(body);
    framed
}

#[test]
fn the_framing_predicate_follows_the_r10_section_8_1_streams() {
    let s = stream();
    assert_eq!(s.len(), 70);
    assert!(framed(&s));
    let mut trailing = s.clone();
    trailing.push(0);
    assert!(!framed(&trailing));
    assert!(!framed(&s[..69]));
    assert!(!framed(&[0, 0, 0, 0]));
    assert!(!framed(&s[..11]));
    assert!(!framed(&[]));
    assert!(!framed(&[0]));
}

#[test]
fn the_framing_predicate_checks_every_frame_byte_for_byte() {
    let header = frame(&EAO1_BODY);
    let end = frame(&[0x89, 0x64, 0x45, 0x4f, 0x45, 0x31, 0x01]);
    // Any number of frames may come between the header and the EOE1 frame.
    let mut middle = header.clone();
    middle.extend(frame(&[0x85, 0x64, 0x45, 0x4f, 0x42, 0x31]));
    middle.extend(&end);
    assert!(framed(&middle));
    // The first frame is exactly the EAO1 header.
    let mut other_header = frame(&[0x82, 0x64, 0x45, 0x41, 0x4f, 0x31, 0x02]);
    other_header.extend(&end);
    assert!(!framed(&other_header));
    // Bodies are 1 to 131072 bytes; a longer prefix is malformed.
    let mut oversized = header.clone();
    oversized.extend(&131_073_u32.to_be_bytes());
    oversized.extend(vec![0; 131_073]);
    assert!(!framed(&oversized));
    let mut largest = header.clone();
    largest.extend(frame(&vec![0; 131_072]));
    largest.extend(&end);
    assert!(framed(&largest));
    // A header alone, or a header and further frames without EOE1, is not
    // a stream.
    let mut unterminated = header;
    unterminated.extend(frame(&[1]));
    assert!(!framed(&unterminated));
}

#[test]
fn channels_are_pipes_with_blocking_unit_ends_and_a_checked_null_stderr() -> TestResult {
    let (unit, provider) = open_channels()?;
    let (input, output, error) = unit.into_parts();
    for descriptor in [input.as_fd(), output.as_fd()] {
        assert_eq!(
            FileType::from_raw_mode(fstat(descriptor)?.st_mode),
            FileType::Fifo
        );
        assert!(!fcntl_getfl(descriptor)?.contains(OFlags::NONBLOCK));
    }
    // Exact access modes: stdin read-only, stdout and stderr write-only.
    assert_eq!(fcntl_getfl(&input)? & OFlags::RWMODE, OFlags::RDONLY);
    assert_eq!(fcntl_getfl(&output)? & OFlags::RWMODE, OFlags::WRONLY);
    assert_eq!(fcntl_getfl(&error)? & OFlags::RWMODE, OFlags::WRONLY);
    let null = fstat(&error)?;
    assert_eq!(
        FileType::from_raw_mode(null.st_mode),
        FileType::CharacterDevice
    );
    assert_eq!(null.st_rdev, makedev(1, 3));
    for descriptor in [provider.input.as_fd(), provider.output.as_fd()] {
        assert!(fcntl_getfl(descriptor)?.contains(OFlags::NONBLOCK));
    }
    // Close-on-exec everywhere: no descriptor leaks into another program.
    for descriptor in [
        input.as_fd(),
        output.as_fd(),
        error.as_fd(),
        provider.input.as_fd(),
        provider.output.as_fd(),
    ] {
        assert!(rustix::io::fcntl_getfd(descriptor)?.contains(rustix::io::FdFlags::CLOEXEC));
    }
    // The provider writes stdin and reads stdout.
    let mut adapter_output = std::fs::File::from(std::os::fd::OwnedFd::from(output));
    adapter_output.write_all(b"out")?;
    let mut read = [0; 3];
    assert_eq!(rustix::io::read(&provider.output, &mut read)?, 3);
    assert_eq!(&read, b"out");
    assert_eq!(rustix::io::write(&provider.input, b"in")?, 2);
    Ok(())
}

#[test]
fn a_stderr_target_that_is_not_dev_null_refuses_the_channels() -> TestResult {
    assert!(matches!(
        open_channels_with("/dev/zero"),
        Err(StdioChannelError::NotNullDevice)
    ));
    let file = tempfile::NamedTempFile::new()?;
    let path = file.path().to_str().ok_or("a non-UTF-8 temporary path")?;
    assert!(matches!(
        open_channels_with(path),
        Err(StdioChannelError::NotNullDevice)
    ));
    assert!(matches!(
        open_channels_with("/nonexistent/null"),
        Err(StdioChannelError::Io(_))
    ));
    Ok(())
}

#[tokio::test]
async fn descriptors_the_reactor_refuses_feed_and_capture_nothing() -> TestResult {
    // A regular file cannot be registered with epoll.
    let file = tempfile::tempfile()?;
    let payload: Arc<dyn AttemptPayload> = Arc::new(TestPayload::default());
    let (accepted, _) = feed(
        file.try_clone()?.into(),
        &payload,
        None,
        std::future::pending(),
    )
    .await;
    assert_eq!(accepted, 0);
    let captured = capture(file.into(), 10, std::future::pending()).await;
    assert!(captured.bytes.is_empty());
    assert_eq!(captured.stop, CaptureStop::Aborted);
    Ok(())
}

#[tokio::test]
async fn an_unreadable_input_stops_the_feed() -> TestResult {
    let (_unit, provider) = open_channels()?;
    let payload: Arc<dyn AttemptPayload> = Arc::new(TestPayload {
        fail_read: true,
        ..TestPayload::default()
    });
    let (accepted, _) = feed(provider.input, &payload, None, std::future::pending()).await;
    assert_eq!(accepted, 0);
    Ok(())
}

#[tokio::test]
async fn a_feed_without_a_representable_deadline_runs_until_it_completes() -> TestResult {
    let (unit, provider) = open_channels()?;
    let payload: Arc<dyn AttemptPayload> = Arc::new(TestPayload::with_input(b"input"));
    let (accepted, finish) = feed(provider.input, &payload, None, std::future::pending()).await;
    assert_eq!(accepted, 5);
    assert!(finish > 0);
    let mut read = [0; 5];
    let (input, _, _) = unit.into_parts();
    assert_eq!(rustix::io::read(&input, &mut read)?, 5);
    assert_eq!(&read, b"input");
    Ok(())
}

#[test]
fn the_descriptor_digests_the_exact_captured_bytes() -> TestResult {
    let charge = crate::StagingLedger::new(crate::StagingLimits { aggregate_bytes: 0 })
        .reserve_storage(0)?;
    let output = Captured {
        bytes: stream(),
        stop: CaptureStop::EndOfStream,
    }
    .fenced(charge);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.SandboxOutputBytes.v1\0");
    hasher.update(&stream());
    let descriptor = output.descriptor();
    assert_eq!(descriptor.byte_length, 70);
    assert_eq!(&descriptor.digest, hasher.finalize().as_bytes());
    assert_eq!(
        output.capture(),
        OutputCaptureRecord {
            accepted_bytes: 70,
            ceiling_reached: false,
            complete_frame: true,
        }
    );
    Ok(())
}

/// The name of the function each line of `source` belongs to.
fn enclosing_functions(source: &str) -> Vec<(Option<String>, &str)> {
    let mut current = None;
    source
        .lines()
        .map(|line| {
            if let Some(rest) = line.trim_start().split("fn ").nth(1) {
                if line.trim_start().starts_with("fn ")
                    || line.trim_start().starts_with("async fn ")
                    || line.trim_start().starts_with("pub(crate) fn ")
                    || line.trim_start().starts_with("pub(crate) async fn ")
                    || line.trim_start().starts_with("pub fn ")
                {
                    current = rest
                        .split(|character: char| !character.is_alphanumeric() && character != '_')
                        .next()
                        .map(ToOwned::to_owned);
                }
            }
            (current.clone(), line)
        })
        .collect()
}

/// I2 (R10 §6): the provider only writes the stdin channel, in the feed, and
/// only reads the stdout channel, in the capture.
#[test]
fn the_provider_only_writes_stdin_and_only_reads_stdout() {
    let source = include_str!("../adapter_stdio.rs");
    let production = source
        .split("#[cfg(test)]\n#[cfg_attr(coverage_nightly, coverage(off))]\nmod tests;")
        .next()
        .unwrap_or_default();
    let mut writes = Vec::new();
    let mut reads = Vec::new();
    for (function, line) in enclosing_functions(production) {
        if line.contains("write(") || line.contains("poll_write") {
            writes.push(function.clone());
        }
        if line.contains("io::read(") || line.contains("poll_read") {
            reads.push(function);
        }
    }
    assert_eq!(writes, [Some("write_input".to_owned())]);
    assert_eq!(
        reads,
        [Some("read_output".to_owned()), Some("drain".to_owned())]
    );
    // The feed holds only the stdin end and the capture only the stdout end.
    assert!(production.contains("provider.input,\n            &payload,"));
    assert!(production.contains("capture(provider.output,"));
}

/// I9 (R10 §6): the launcher passes fds 0 to 2 through unchanged; it never
/// names stdin or stdout.
#[test]
fn the_launcher_never_touches_stdin_or_stdout() -> TestResult {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/launcher");
    let mut checked = 0;
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        if path.file_name().is_some_and(|name| name == "tests.rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path)?.to_lowercase();
        for name in ["stdin", "stdout", "fd 0", "fd 1"] {
            assert!(!source.contains(name), "{} names {name}", path.display());
        }
        checked += 1;
    }
    assert!(checked >= 8);
    Ok(())
}

#[test]
fn each_read_outcome_has_its_capture_stop() {
    let mut bytes = Vec::new();
    assert_eq!(take(&mut bytes, Ok(&[]), 3), Some(CaptureStop::EndOfStream));
    assert_eq!(take(&mut bytes, Ok(&[1, 2]), 3), None);
    assert_eq!(take(&mut bytes, Ok(&[3, 4]), 3), Some(CaptureStop::Ceiling));
    assert_eq!(bytes, [1, 2, 3]);
    let drained = Err(std::io::ErrorKind::WouldBlock.into());
    assert_eq!(take(&mut bytes, drained, 3), Some(CaptureStop::EndOfStream));
    let failed = Err(std::io::ErrorKind::BrokenPipe.into());
    assert_eq!(take(&mut bytes, failed, 3), Some(CaptureStop::Aborted));
}

#[test]
fn the_capture_never_holds_more_memory_than_its_limit() {
    let mut bytes = Vec::new();
    let limit = 100_000;
    let chunk = vec![7; 30_000];
    for _ in 0..3 {
        assert_eq!(accept(&mut bytes, &chunk, limit), None);
        assert!(bytes.capacity() <= 100_000);
    }
    assert_eq!(
        accept(&mut bytes, &chunk, limit),
        Some(CaptureStop::Ceiling)
    );
    assert_eq!(bytes.len(), 100_000);
    assert_eq!(bytes.capacity(), 100_000);
}
