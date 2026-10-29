//! Boot-local generation checks through the existing attachment/readback seam.

use super::*;

pub(super) fn mutations() -> Vec<Mutation> {
    vec![
        ("no mapper generation", |o| {
            edit_mapper(o, |m| m.identity = None)
        }),
        ("mapper is not the mounted device", |o| {
            edit_mapper(o, |m| m.identity = Some(block_generation((253, 4), 102)));
        }),
        ("no first loop generation", |o| {
            edit_loop(o, |d| d.identity = None)
        }),
        ("no second loop generation", |o| {
            edit_slaves(o, |s| {
                s[1].loop_device.as_mut().expect("loop fixture").identity = None
            });
        }),
        ("contradictory loop device numbers", |o| {
            edit_loop(o, |d| d.identity = Some(block_generation((7, 8), 101)));
        }),
        ("contradictory loop generations", |o| {
            edit_loop(o, |d| d.identity = Some(block_generation((7, 7), 103)));
        }),
    ]
}

#[test]
fn unverified_generations_refuse_attachment_and_detach() -> TestResult {
    for (name, mutate) in mutations() {
        let tree = prepared_tree()?;
        let expected = expected(&component(&tree.prepared));
        let mut invalid = matching(&expected);
        mutate(&mut invalid);
        assert_ne!(invalid, matching(&expected), "fault injected: {name}");
        let kernel = FakeKernel::accepting(invalid.clone());
        assert_eq!(
            attach_and_verify(&kernel, &tree.prepared, &expected, file_mount()?, || Ok(())).err(),
            Some(ImageActivationError::EvidenceMismatch),
            "attachment: {name}"
        );
        assert_eq!(kernel.detached(), 1);

        let mut kernel = FakeKernel::accepting(matching(&expected));
        let root = attach_and_verify(&kernel, &tree.prepared, &expected, file_mount()?, || Ok(()))?;
        kernel.observations = invalid;
        let record = tree
            .runtime
            .path()
            .join("registry")
            .join(component(&tree.prepared));
        let bytes = fs::read(&record)?;
        assert_eq!(
            root.detach_with(&kernel, &tree.prepared),
            Err(ImageActivationError::EvidenceMismatch),
            "detach: {name}"
        );
        assert_eq!(kernel.detached(), 0);
        assert_eq!(fs::read(&record)?, bytes);
        tree.prepared.verify_directory()?;
        assert!(tree
            .registry
            .commit_planned(&PlannedAttemptIntent::new([10; 16], [9; 32])?)
            .is_err());
    }
    Ok(())
}

#[test]
fn host_generation_reads_require_valid_device_numbers_and_nonzero_diskseq() -> TestResult {
    let tree = prepared_tree()?;
    let (attempt, root) = tree.prepared.held_directories();
    let host = tempfile::tempdir()?;
    let kernel = HostKernel::at(host.path(), host.path());
    let node = kernel
        .observe(root.as_fd(), attempt, root, "/absent")
        .mount
        .ok_or("root node")?;
    let block = host
        .path()
        .join(format!("dev/block/{}:{}", node.device.0, node.device.1));
    let loop_path = host.path().join("class/block/loop7");
    for path in [&block, &loop_path] {
        for (dev, diskseq) in [
            (None, Some("101")),
            (Some("7:7"), None),
            (Some("7:7"), Some("0")),
            (Some("7:7"), Some("")),
            (Some("7:7"), Some("-1")),
            (Some("7:7"), Some("18446744073709551616")),
            (Some("7:7"), Some("not-a-generation")),
            (Some("7:7"), Some("101\n102")),
            (Some("not-a-device"), Some("101")),
            (Some("7:x"), Some("101")),
            (Some("4294967296:7"), Some("101")),
        ] {
            fs::create_dir_all(path)?;
            for (name, value) in [("dev", dev), ("diskseq", diskseq)] {
                let file = path.join(name);
                if let Some(value) = value {
                    write(&file, value)?;
                } else if file.exists() {
                    fs::remove_file(file)?;
                }
            }
            let observed = kernel.observe(root.as_fd(), attempt, root, "/absent");
            assert_eq!(observed.mapper.ok_or("mapper sample")?.identity, None);
            assert_eq!(kernel.loop_device("loop7").identity, None);
        }
        write(&path.join("dev"), "7:7\n")?;
        write(&path.join("diskseq"), "18446744073709551615\n")?;
        let observed = if path == &block {
            kernel
                .observe(root.as_fd(), attempt, root, "/absent")
                .mapper
                .ok_or("mapper sample")?
                .identity
        } else {
            kernel.loop_device("loop7").identity
        };
        assert_eq!(observed, Some(block_generation((7, 7), u64::MAX)));
        // An unreadable attribute is not an absent device or an adopted identity.
        fs::remove_file(path.join("diskseq"))?;
        fs::create_dir(path.join("diskseq"))?;
        assert_eq!(
            if path == &block {
                kernel
                    .observe(root.as_fd(), attempt, root, "/absent")
                    .mapper
                    .ok_or("mapper sample")?
                    .identity
            } else {
                kernel.loop_device("loop7").identity
            },
            None
        );
        fs::remove_dir(path.join("diskseq"))?;
        fs::remove_file(path.join("dev"))?;
    }
    Ok(())
}

#[test]
fn changes_during_each_host_device_sample_invalidate_its_generation() -> TestResult {
    use rustix::fs::{mkfifoat, open, Mode, OFlags, CWD};
    use std::time::{Duration, Instant};

    let tree = prepared_tree()?;
    let (attempt, root) = tree.prepared.held_directories();
    for is_loop in [false, true] {
        for (attribute, replacement) in [("diskseq", "103"), ("dev", "7:8")] {
            let host = tempfile::tempdir()?;
            let kernel = HostKernel::at(host.path(), host.path());
            let node = kernel
                .observe(root.as_fd(), attempt, root, "/absent")
                .mount
                .ok_or("root node")?;
            let path = if is_loop {
                host.path().join("class/block/loop7")
            } else {
                host.path()
                    .join(format!("dev/block/{}:{}", node.device.0, node.device.1))
            };
            write(&path.join("dev"), "7:7\n")?;
            write(&path.join("diskseq"), "101\n")?;
            let barrier = path.join(if is_loop {
                "loop/backing_file"
            } else {
                "dm/uuid"
            });
            fs::create_dir_all(barrier.parent().ok_or("barrier parent")?)?;
            mkfifoat(CWD, &barrier, Mode::RUSR | Mode::WUSR)?;
            let changed = path.join(attribute);
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
                // Opening the FIFO for writing proves the observer already
                // passed its first identity read and is reading the facts.
                fs::write(changed, replacement)?;
                writeln!(File::from(descriptor), "/absent")?;
                Ok(())
            });
            let identity = if is_loop {
                kernel.loop_device("loop7").identity
            } else {
                kernel
                    .observe(root.as_fd(), attempt, root, "/absent")
                    .mapper
                    .ok_or("mapper sample")?
                    .identity
            };
            writer.join().map_err(|_| "generation writer panicked")??;
            assert_eq!(identity, None, "{is_loop}/{attribute}");
        }
    }
    Ok(())
}
