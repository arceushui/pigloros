//! Original-device absence through the owned-root release and host observer seams.

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod cases {
    use std::{
        task::{Context, Poll, Waker},
        time::Duration,
    };

    use tokio::time::{advance, Instant};

    use super::super::super::release::Release;
    use super::super::*;

    const UNVERIFIED: ImageActivationError = ImageActivationError::ResourceAbsenceUnverified;

    fn quarantined(tree: &PreparedTree) -> TestResult {
        tree.prepared.verify_directory()?;
        assert!(tree
            .registry
            .commit_planned(&PlannedAttemptIntent::new([10; 16], [9; 32])?)
            .is_err());
        assert!(tree
            .runtime
            .path()
            .join("registry")
            .join(component(&tree.prepared))
            .is_file());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn delayed_reference_release_requires_both_original_generations() -> TestResult {
        let tree = prepared_tree()?;
        let (kernel, root) = attached_root(&tree.prepared)?;
        let devices = root.identity.devices();
        kernel.absence.lock().map_err(|_| "probe script")?.extend([
            (Duration::ZERO, Ok(false)),
            (Duration::from_millis(20), Ok(false)),
            (Duration::from_millis(20), Ok(true)),
        ]);
        let deadline = Instant::now() + Duration::from_millis(100);
        Release::new(root, &tree.prepared, deadline)
            .finish(&kernel)
            .await?;
        assert!(Instant::now() < deadline);
        assert_eq!(kernel.detached(), 1);
        assert_eq!(
            *kernel.probes.lock().map_err(|_| "probes")?,
            vec![devices; 3]
        );
        tree.prepared.verify_directory()?;
        tree.registry
            .commit_planned(&PlannedAttemptIntent::new([10; 16], [9; 32])?)?;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn original_deadline_covers_time_before_the_first_poll() -> TestResult {
        let tree = prepared_tree()?;
        let (kernel, root) = attached_root(&tree.prepared)?;
        let deadline = Instant::now() + Duration::from_millis(50);
        let release = Release::new(root, &tree.prepared, deadline);
        advance(Duration::from_millis(50)).await;
        assert_eq!(release.finish(&kernel).await, Err(UNVERIFIED));
        assert_eq!(kernel.detached(), 0);
        assert!(kernel.probes.lock().map_err(|_| "probes")?.is_empty());
        quarantined(&tree)
    }

    #[tokio::test(start_paused = true)]
    async fn acknowledged_detach_cannot_repair_late_missing_or_bad_absence() -> TestResult {
        for (delay, result) in [
            (Duration::from_millis(40), Ok(true)),
            (Duration::from_millis(50), Ok(true)),
            (Duration::from_millis(51), Ok(true)),
            (Duration::from_secs(1), Ok(false)),
            (Duration::ZERO, Err(UNVERIFIED)),
        ] {
            let tree = prepared_tree()?;
            let (kernel, root) = attached_root(&tree.prepared)?;
            kernel
                .absence
                .lock()
                .map_err(|_| "probe script")?
                .push_back((delay, result));
            let deadline = Instant::now() + Duration::from_millis(50);
            let observed = Release::new(root, &tree.prepared, deadline)
                .finish(&kernel)
                .await;
            assert_eq!(
                observed,
                if delay == Duration::from_millis(40) {
                    Ok(())
                } else {
                    Err(UNVERIFIED)
                }
            );
            assert_eq!(kernel.detached(), 1);
            assert_eq!(kernel.probes.lock().map_err(|_| "probes")?.len(), 1);
            if observed.is_err() {
                quarantined(&tree)?;
            }
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn still_present_devices_exhaust_the_original_budget() -> TestResult {
        let tree = prepared_tree()?;
        let (kernel, root) = attached_root(&tree.prepared)?;
        kernel
            .absence
            .lock()
            .map_err(|_| "probe script")?
            .extend(std::iter::repeat_n((Duration::ZERO, Ok(false)), 20));
        let deadline = Instant::now() + Duration::from_millis(25);
        assert_eq!(
            Release::new(root, &tree.prepared, deadline)
                .finish(&kernel)
                .await,
            Err(UNVERIFIED)
        );
        assert_eq!(Instant::now(), deadline);
        assert!(kernel.probes.lock().map_err(|_| "probes")?.len() > 1);
        quarantined(&tree)
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_before_and_after_detach_preserves_quarantine() -> TestResult {
        for after_detach in [false, true] {
            let tree = prepared_tree()?;
            let (kernel, root) = attached_root(&tree.prepared)?;
            if after_detach {
                kernel
                    .absence
                    .lock()
                    .map_err(|_| "probe script")?
                    .push_back((Duration::from_secs(1), Ok(true)));
                let mut future = Box::pin(
                    Release::new(root, &tree.prepared, cleanup_deadline()).finish(&kernel),
                );
                assert_eq!(
                    future
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Pending
                );
                assert_eq!(kernel.detached(), 1);
                drop(future);
            } else {
                // Exercise the public constructor, not only a test adapter:
                // its guard must exist before the future is first polled.
                drop(root.detach(&tree.prepared, cleanup_deadline()));
                assert_eq!(kernel.detached(), 0);
            }
            quarantined(&tree)?;
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn changed_intent_while_waiting_cannot_complete_cleanup() -> TestResult {
        let tree = prepared_tree()?;
        let (kernel, root) = attached_root(&tree.prepared)?;
        kernel
            .absence
            .lock()
            .map_err(|_| "probe script")?
            .push_back((Duration::from_millis(20), Ok(true)));
        let mut future =
            Box::pin(Release::new(root, &tree.prepared, cleanup_deadline()).finish(&kernel));
        assert_eq!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        );
        let record = tree
            .runtime
            .path()
            .join("registry")
            .join(component(&tree.prepared));
        fs::write(&record, b"changed")?;
        assert_eq!(future.await, Err(ImageActivationError::EvidenceMismatch));
        assert_eq!(fs::read(record)?, b"changed");
        assert!(tree
            .registry
            .commit_planned(&PlannedAttemptIntent::new([10; 16], [9; 32])?)
            .is_err());
        Ok(())
    }

    #[tokio::test]
    async fn changing_generations_are_pending_and_backwards_evidence_rejects() -> TestResult {
        const CHILD: &str = "PIGLOROS_ABSENCE_SAMPLE_CHILD";
        const TEST: &str = concat!(
            module_path!(),
            "::changing_generations_are_pending_and_backwards_evidence_rejects"
        );
        if bounded_fixture_child(CHILD, TEST)? {
            return Ok(());
        }
        use rustix::fs::{mkfifoat, open, Mode, OFlags, CWD};
        use std::time::Instant;

        for (first, second, expected) in [(101, 103, Ok(false)), (103, 99, Err(UNVERIFIED))] {
            let host = tempfile::tempdir()?;
            let kernel = HostKernel::at(host.path(), host.path());
            let path = host.path().join("dev/block/7:7");
            write(&path.join("diskseq"), &first.to_string())?;
            let barrier = path.join("dev");
            mkfifoat(CWD, &barrier, Mode::RUSR | Mode::WUSR)?;
            let writer = thread::spawn(move || -> TestResult {
                let deadline = Instant::now() + Duration::from_secs(30);
                let descriptor = loop {
                    match open(
                        &barrier,
                        OFlags::WRONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
                        Mode::empty(),
                    ) {
                        Ok(descriptor) => break descriptor,
                        Err(error)
                            if error == rustix::io::Errno::NXIO && Instant::now() < deadline =>
                        {
                            thread::sleep(Duration::from_millis(1))
                        }
                        Err(error) => return Err(error.into()),
                    }
                };
                // The first diskseq was read before this FIFO opened. Publish
                // the next generation and replace the path for the next sample.
                fs::write(path.join("diskseq"), second.to_string())?;
                let replacement = path.join("next-dev");
                fs::write(&replacement, "7:7\n")?;
                fs::rename(replacement, &barrier)?;
                writeln!(File::from(descriptor), "7:7")?;
                Ok(())
            });
            let device = block_generation((7, 7), 101).ok_or("loop")?;
            let observed = kernel.devices_absent([device; 2]).await;
            writer.join().map_err(|_| "absence writer panicked")??;
            assert_eq!(observed, expected);
        }
        Ok(())
    }

    #[tokio::test]
    async fn host_requires_each_device_and_distinguishes_reuse_from_missing_attributes(
    ) -> TestResult {
        let host = tempfile::tempdir()?;
        let kernel = HostKernel::at(host.path(), host.path());
        let devices = [
            block_generation((253, 3), 102).ok_or("mapper")?,
            block_generation((7, 7), 101).ok_or("loop")?,
        ];
        fs::create_dir_all(host.path().join("dev/block"))?;
        assert_eq!(kernel.devices_absent(devices).await, Ok(true));
        for (index, device) in devices.into_iter().enumerate() {
            let path = host
                .path()
                .join(format!("dev/block/{}:{}", device.device.0, device.device.1));
            write(
                &path.join("dev"),
                &format!("{}:{}\n", device.device.0, device.device.1),
            )?;
            write(&path.join("diskseq"), &device.diskseq.to_string())?;
            // The other device is already absent; this one still blocks.
            assert_eq!(
                kernel.devices_absent(devices).await,
                Ok(false),
                "device {index}"
            );
            // No loop/backing_file or dm/uuid exists in this fixture. Missing
            // auxiliary attributes cannot turn a present generation absent.
            write(
                &path.join("diskseq"),
                &(device.diskseq.get() + 1).to_string(),
            )?;
            assert_eq!(kernel.devices_absent(devices).await, Ok(true));
            for invalid in ["0", "-1", "bad", "101\n102", "18446744073709551616"] {
                write(&path.join("diskseq"), invalid)?;
                assert_eq!(kernel.devices_absent(devices).await, Err(UNVERIFIED));
            }
            write(
                &path.join("diskseq"),
                &(device.diskseq.get() - 1).to_string(),
            )?;
            assert_eq!(kernel.devices_absent(devices).await, Err(UNVERIFIED));
            fs::remove_file(path.join("diskseq"))?;
            assert_eq!(kernel.devices_absent(devices).await, Err(UNVERIFIED));
            fs::create_dir(path.join("diskseq"))?;
            assert_eq!(kernel.devices_absent(devices).await, Err(UNVERIFIED));
            fs::remove_dir(path.join("diskseq"))?;
            write(
                &path.join("diskseq"),
                &(device.diskseq.get() + 1).to_string(),
            )?;
            for invalid in ["7:8", "bad", "4294967296:7"] {
                write(&path.join("dev"), invalid)?;
                assert_eq!(kernel.devices_absent(devices).await, Err(UNVERIFIED));
            }
            fs::remove_dir_all(&path)?;
        }
        fs::remove_dir(host.path().join("dev/block"))?;
        assert_eq!(kernel.devices_absent(devices).await, Err(UNVERIFIED));
        // A non-directory ancestor produces ENOTDIR, never device absence.
        write(&host.path().join("dev/block"), "not sysfs")?;
        assert_eq!(kernel.devices_absent(devices).await, Err(UNVERIFIED));
        Ok(())
    }
}
