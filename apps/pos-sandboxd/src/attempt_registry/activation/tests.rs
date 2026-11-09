//! The activation marker's format, its durable replacement, and the crash
//! frontiers of that replacement.

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod cases {
    use std::fs::{self, File};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;

    use super::super::super::tests::{in_lock_test_process, with_io_fault};
    use super::super::super::{
        PlannedAttemptIntent, PreparedAttemptDirectory, RegistryDirectory, SystemdAttemptRecovery,
        SystemdAttemptRegistry,
    };
    use super::super::*;
    use crate::restart::RootsReleased;
    use crate::SystemdAttemptUnitAbsenceObservation;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    const OTHER_BOOT: [u8; 16] = [0xee; 16];

    /// An independent byte oracle for one PAA1 marker.
    fn marker_bytes(boot: [u8; 16], seconds: u64, nanoseconds: u64) -> Vec<u8> {
        [
            b"PAA1".as_slice(),
            &boot,
            &seconds.to_le_bytes(),
            &nanoseconds.to_le_bytes(),
        ]
        .concat()
    }

    const fn at(seconds: u64, milliseconds: u64) -> Duration {
        Duration::from_millis(seconds * 1000 + milliseconds)
    }

    #[test]
    fn the_marker_is_exactly_its_tag_boot_seconds_and_nanoseconds() -> TestResult {
        let marker = ActivationMarker {
            boot: [7; 16],
            sent: Duration::new(41, 999_999_999),
        };
        let bytes = marker_bytes([7; 16], 41, 999_999_999);
        assert_eq!(marker.encode().as_slice(), bytes.as_slice());
        assert_eq!(parse_content(&bytes, false)?, Some(marker));
        assert_eq!(parse_content(&bytes, true)?, Some(marker));
        Ok(())
    }

    #[test]
    fn no_request_yet_is_the_all_zero_record_and_never_waited_for() -> TestResult {
        let bytes = marker_bytes([0; 16], 0, 0);
        assert_eq!(
            ActivationMarker::UNREQUESTED.encode().as_slice(),
            bytes.as_slice()
        );
        assert_eq!(
            parse_content(&bytes, false)?,
            Some(ActivationMarker::UNREQUESTED)
        );
        for now in [Duration::ZERO, at(100, 0)] {
            assert_eq!(
                ActivationMarker::UNREQUESTED.remaining(([7; 16], now)).ok(),
                Some(None)
            );
        }
        // Any other record with the zero boot ID is malformed.
        for invalid in [marker_bytes([0; 16], 1, 0), marker_bytes([0; 16], 0, 1)] {
            assert!(matches!(
                parse_content(&invalid, false),
                Err(SystemdAttemptRegistryError::InvalidIntent)
            ));
        }
        Ok(())
    }

    #[test]
    fn only_a_complete_tagged_marker_with_valid_nanoseconds_is_committed() {
        let valid = marker_bytes([7; 16], 41, 5);
        // Every prefix is a recognizable interrupted write, never a marker.
        for length in 0..valid.len() {
            assert!(
                matches!(parse_content(&valid[..length], true), Ok(None)),
                "{length}"
            );
            assert!(parse_content(&valid[..length], false).is_err(), "{length}");
        }
        let mut oversized = valid.clone();
        oversized.push(0);
        let mut retagged = valid;
        retagged[3] = b'2';
        for invalid in [
            oversized,
            retagged,
            marker_bytes([7; 16], 41, 1_000_000_000),
            marker_bytes([7; 16], 41, 1 << 32),
        ] {
            for temporary in [false, true] {
                assert!(matches!(
                    parse_content(&invalid, temporary),
                    Err(SystemdAttemptRegistryError::InvalidIntent)
                ));
            }
        }
    }

    #[test]
    fn only_a_request_of_this_boot_younger_than_the_deadline_is_waited_out() {
        let marker = ActivationMarker {
            boot: [7; 16],
            sent: at(100, 0),
        };
        // The 60 s activator deadline plus the 10 s server margin.
        assert_eq!(SERVER_MARGIN, at(10, 0));
        for (now, remaining) in [
            (at(100, 0), Some(at(70, 0))),
            (at(110, 0), Some(at(60, 0))),
            (at(160, 0), Some(at(10, 0))),
            (at(169, 999), Some(at(0, 1))),
            (at(170, 0), None),
            (at(171, 0), None),
        ] {
            assert_eq!(marker.remaining(([7; 16], now)).ok(), Some(remaining));
        }
        assert_eq!(marker.remaining((OTHER_BOOT, at(100, 0))).ok(), Some(None));
        assert!(matches!(
            marker.remaining(([7; 16], at(99, 999))),
            Err(SystemdAttemptRegistryError::ActivationMarker)
        ));
    }

    #[test]
    fn only_one_canonical_uuid_line_is_a_boot_id() {
        assert_eq!(
            parse_boot_id(b"0123abcd-ef01-2345-6789-ABCDEF012345\n"),
            Some([
                0x01, 0x23, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
                0x23, 0x45
            ])
        );
        for invalid in [
            b"0123abcd-ef01-2345-6789-abcdef012345".as_slice(),
            b"0123abcd-ef01-2345-6789-abcdef012345\n\n",
            b"0123abcdef01-2345-6789-abcdef012345\n",
            b"0123abcd-ef01-2345-6789-abcdef01234\n",
            b"0123abcg-ef01-2345-6789-abcdef012345\n",
            b"+123abcd-ef01-2345-6789-abcdef012345\n",
            b"00000000-0000-0000-0000-000000000000\n",
            b"\xff123abcd-ef01-2345-6789-abcdef012345\n",
            b"",
        ] {
            assert_eq!(parse_boot_id(invalid), None);
            assert_eq!(
                instant_on(invalid).map_err(|error| error.kind()),
                Err(io::ErrorKind::InvalidData)
            );
        }
    }

    fn monotonic() -> Duration {
        let now = clock_gettime(ClockId::Monotonic);
        Duration::from_secs(now.tv_sec.unsigned_abs())
            + Duration::from_nanos(now.tv_nsec.unsigned_abs())
    }

    fn host_boot_id() -> TestResult<Vec<u8>> {
        let text = fs::read_to_string(BOOT_ID)?;
        let hex = text.trim_end().replace('-', "");
        Ok((0..16)
            .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16))
            .collect::<Result<_, _>>()?)
    }

    #[test]
    fn the_host_instant_is_this_boot_at_its_monotonic_time() -> TestResult {
        let before = monotonic();
        let (boot, now) = boot_instant()?;
        let after = monotonic();
        assert_eq!(boot.to_vec(), host_boot_id()?);
        assert!(
            before <= now && now <= after,
            "{before:?} {now:?} {after:?}"
        );
        let (failed, steps) = with_io_fault(Some(0), boot_instant);
        assert!(failed.is_err());
        assert_eq!(steps, 1);
        Ok(())
    }

    fn runtime() -> TestResult<tempfile::TempDir> {
        let runtime = tempfile::tempdir()?;
        for path in [
            runtime.path().to_path_buf(),
            runtime.path().join("registry"),
            runtime.path().join("attempts"),
        ] {
            fs::create_dir_all(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        }
        Ok(runtime)
    }

    fn open_registry(runtime: &Path) -> TestResult<SystemdAttemptRegistry> {
        let parent = File::open(runtime)?;
        Ok(SystemdAttemptRegistry::from_runtime_directory(
            &parent,
            parent.metadata()?.uid(),
        )?)
    }

    fn intent(id: u8) -> TestResult<PlannedAttemptIntent> {
        Ok(PlannedAttemptIntent::new([id; 16], [2; 32])?)
    }

    fn prepared(registry: &SystemdAttemptRegistry) -> TestResult<PreparedAttemptDirectory> {
        Ok(registry.commit_planned(&intent(1)?)?.prepare_directory()?)
    }

    fn write_marker(runtime: &Path, bytes: &[u8]) -> TestResult {
        let path = runtime.join("registry").join(MARKER_NAME);
        fs::write(&path, bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    fn read_marker(runtime: &Path) -> TestResult<ActivationMarker> {
        let path = runtime.join("registry").join(MARKER_NAME);
        let metadata = fs::metadata(&path)?;
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        Ok(parse_content(&fs::read(path)?, false)?.ok_or("a complete marker")?)
    }

    #[test]
    fn each_request_durably_replaces_the_marker_with_this_boot_and_time() -> TestResult {
        let runtime = runtime()?;
        let registry = open_registry(runtime.path())?;
        let prepared = prepared(&registry)?;
        let before = boot_instant()?;
        prepared.record_activation_request()?;
        let first = read_marker(runtime.path())?;
        prepared.record_activation_request()?;
        let second = read_marker(runtime.path())?;
        let after = boot_instant()?;
        assert_eq!([first.boot, second.boot], [before.0; 2]);
        let times = [before.1, first.sent, second.sent, after.1];
        assert!(times.windows(2).all(|pair| pair[0] <= pair[1]), "{times:?}");
        // Only the intent and the marker remain, and the owner still commits.
        assert_eq!(fs::read_dir(runtime.path().join("registry"))?.count(), 2);
        registry.commit_planned(&intent(2)?)?;
        Ok(())
    }

    #[test]
    fn a_closed_owner_still_records_the_request_and_stays_closed() -> TestResult {
        let runtime = runtime()?;
        let registry = open_registry(runtime.path())?;
        let prepared = prepared(&registry)?;
        registry.state.lock().map_err(|_| "owner")?.failed = true;
        prepared.record_activation_request()?;
        assert_eq!(read_marker(runtime.path())?.boot, boot_instant()?.0);
        assert!(registry.commit_planned(&intent(2)?).is_err());
        // A failed write on a closed owner leaves it closed.
        let (failed, _) = with_io_fault(Some(0), || prepared.record_activation_request());
        assert!(failed.is_err());
        assert!(registry.commit_planned(&intent(2)?).is_err());
        Ok(())
    }

    #[test]
    fn an_exhausted_or_poisoned_owner_records_no_request() -> TestResult {
        for fault in 0..2 {
            let runtime = runtime()?;
            let registry = open_registry(runtime.path())?;
            let prepared = prepared(&registry)?;
            match fault {
                0 => registry.state.lock().map_err(|_| "owner")?.next_sequence = u64::MAX,
                _ => assert!(std::panic::catch_unwind(|| {
                    let _guard = registry.state.lock();
                    std::panic::resume_unwind(Box::new(()));
                })
                .is_err()),
            }
            assert!(prepared.record_activation_request().is_err(), "{fault}");
            assert_eq!(read_marker(runtime.path())?, ActivationMarker::UNREQUESTED);
            assert!(registry.commit_planned(&intent(2)?).is_err());
        }
        Ok(())
    }

    /// Record a request over a marker of another boot, failing the I/O step
    /// `fail_at`, abandon the owner as a crash would, and reconcile. Returns
    /// whether the restart must wait for the new request, and the steps taken.
    fn crash_at(fail_at: Option<usize>) -> TestResult<(bool, usize)> {
        let runtime = runtime()?;
        write_marker(runtime.path(), &marker_bytes(OTHER_BOOT, 5, 0))?;
        let registry = open_registry(runtime.path())?;
        let prepared = prepared(&registry)?;
        let (result, steps) = with_io_fault(fail_at, || prepared.record_activation_request());
        // A failed write refuses the request and closes the owner.
        assert_eq!(result.is_ok(), fail_at.is_none());
        assert_eq!(
            registry.commit_planned(&intent(2)?).is_ok(),
            fail_at.is_none()
        );
        drop((prepared, registry));
        let parent = File::open(runtime.path())?;
        let held = RegistryDirectory::from_runtime_directory(&parent, parent.metadata()?.uid())?;
        let recovery = SystemdAttemptRecovery::from_directory(held)?;
        let wait = recovery.activation_wait(boot_instant()?)?;
        // Reconciliation removes an interrupted write and keeps the marker.
        let absent = recovery
            .entries()
            .iter()
            .map(|entry| SystemdAttemptUnitAbsenceObservation::for_test(entry.unit_name().clone()))
            .collect::<Vec<_>>();
        recovery.remove_reconciled(&absent, &RootsReleased::for_test(Vec::new()))?;
        drop(recovery);
        assert_eq!(fs::read_dir(runtime.path().join("registry"))?.count(), 1);
        open_registry(runtime.path())?.commit_planned(&intent(3)?)?;
        Ok((wait.is_some(), steps))
    }

    #[test]
    fn a_crash_at_every_marker_step_leaves_a_registry_restart_reconciles() -> TestResult {
        if !in_lock_test_process(
            "attempt_registry::activation::tests::cases::a_crash_at_every_marker_step_leaves_a_registry_restart_reconciles",
        )? {
            return Ok(());
        }
        let (waits, steps) = crash_at(None)?;
        assert!(waits);
        let committed = (0..steps)
            .map(|fail_at| crash_at(Some(fail_at)).map(|(waits, _)| waits))
            .collect::<TestResult<Vec<_>>>()?;
        // The new request is waited for exactly from its rename on: before it,
        // the other boot's marker remains and no wait is needed.
        assert!(committed.windows(2).all(|pair| pair[0] <= pair[1]));
        assert_eq!(committed.first(), Some(&false));
        assert_eq!(committed.last(), Some(&true));
        Ok(())
    }

    #[test]
    fn a_new_owner_records_no_request_before_its_first_commit_and_keeps_a_marker() -> TestResult {
        if !in_lock_test_process(
            "attempt_registry::activation::tests::cases::a_new_owner_records_no_request_before_its_first_commit_and_keeps_a_marker",
        )? {
            return Ok(());
        }
        let runtime = runtime()?;
        let registry = open_registry(runtime.path())?;
        assert_eq!(read_marker(runtime.path())?, ActivationMarker::UNREQUESTED);
        // A crash between a directory stage and the first request: restart
        // sees that no request was sent and needs no wait.
        drop((prepared(&registry)?, registry));
        let parent = File::open(runtime.path())?;
        let held = RegistryDirectory::from_runtime_directory(&parent, parent.metadata()?.uid())?;
        let recovery = SystemdAttemptRecovery::from_directory(held)?;
        assert_eq!(recovery.activation_wait(boot_instant()?)?, None);
        drop(recovery);
        // An owner beside an existing marker keeps it.
        let marked = self::runtime()?;
        write_marker(marked.path(), &marker_bytes(OTHER_BOOT, 5, 0))?;
        drop(open_registry(marked.path())?);
        assert_eq!(
            fs::read(marked.path().join("registry").join(MARKER_NAME))?,
            marker_bytes(OTHER_BOOT, 5, 0)
        );
        Ok(())
    }

    /// Open a new owner of an empty registry, failing the I/O step `fail_at`,
    /// and reconcile what remains. Returns the steps taken.
    fn crash_opening(fail_at: Option<usize>) -> TestResult<usize> {
        let runtime = runtime()?;
        let (opened, steps) = with_io_fault(fail_at, || open_registry(runtime.path()));
        assert_eq!(opened.is_ok(), fail_at.is_none());
        drop(opened);
        let parent = File::open(runtime.path())?;
        let held = RegistryDirectory::from_runtime_directory(&parent, parent.metadata()?.uid())?;
        let recovery = SystemdAttemptRecovery::from_directory(held)?;
        // No intent was committed, so no wait and no missing-marker refusal.
        assert_eq!(recovery.activation_wait(boot_instant()?)?, None);
        recovery.remove_reconciled(&[], &RootsReleased::for_test(Vec::new()))?;
        drop(recovery);
        // The next owner finds the marker or creates it, and commits.
        open_registry(runtime.path())?.commit_planned(&intent(3)?)?;
        assert_eq!(read_marker(runtime.path())?, ActivationMarker::UNREQUESTED);
        Ok(steps)
    }

    #[test]
    fn a_crash_at_every_initial_marker_step_leaves_a_registry_restart_reconciles() -> TestResult {
        if !in_lock_test_process(
            "attempt_registry::activation::tests::cases::a_crash_at_every_initial_marker_step_leaves_a_registry_restart_reconciles",
        )? {
            return Ok(());
        }
        let steps = crash_opening(None)?;
        let reached = (0..steps)
            .map(|fail_at| crash_opening(Some(fail_at)))
            .collect::<TestResult<Vec<_>>>()?;
        assert_eq!(reached, (1..=steps).collect::<Vec<_>>());
        Ok(())
    }
}
