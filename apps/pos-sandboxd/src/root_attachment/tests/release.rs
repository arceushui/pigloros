//! The complete detach operation with the existing private kernel port.
//! Actual mounted-host conformance remains the separate #444 suite.

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod cases {
    use super::super::*;

    #[tokio::test]
    async fn eight_owned_roots_detach_without_deleting_intent_or_other_directories() -> TestResult {
        let tree = prepared_tree()?;
        let mut directories = vec![tree.prepared];
        for id in [1, 2, 3, 4, 5, 6, 8] {
            directories.push(
                tree.registry
                    .commit_planned(&PlannedAttemptIntent::new([id; 16], [9; 32])?)?
                    .prepare_directory()?,
            );
        }
        for (index, directory) in directories.into_iter().enumerate() {
            let key = component(&directory);
            let record = tree.runtime.path().join("registry").join(&key);
            let bytes = fs::read(&record)?;
            let (kernel, root) = attached_root(&directory)?;
            detach_owned(root, &kernel, &directory).await?;
            assert_eq!(kernel.detached(), 1);
            assert!(tree
                .runtime
                .path()
                .join("attempts")
                .join(&key)
                .join("root")
                .exists());
            assert_eq!(fs::read(&record)?, bytes);
            assert_eq!(
                fs::read_dir(tree.runtime.path().join("attempts"))?.count(),
                8 - index
            );
            directory.remove_unmounted()?;
            assert_eq!(fs::read(&record)?, bytes);
        }
        assert_eq!(
            fs::read_dir(tree.runtime.path().join("registry"))?.count(),
            8
        );
        tree.registry
            .commit_planned(&PlannedAttemptIntent::new([10; 16], [9; 32])?)?;
        Ok(())
    }

    #[tokio::test]
    async fn changed_ownership_rejects_before_detach_and_quarantines_the_owner() -> TestResult {
        for fault in 0..9 {
            let tree = prepared_tree()?;
            let key = component(&tree.prepared);
            let record = tree.runtime.path().join("registry").join(&key);
            let attempts = tree.runtime.path().join("attempts");
            let attempt = attempts.join(&key);
            let (kernel, root) = attached_root(&tree.prepared)?;
            match fault {
                0 => fs::write(&record, b"changed")?,
                1 => {
                    let mut bytes = fs::read(&record)?;
                    bytes[52] ^= 1;
                    fs::write(&record, bytes)?;
                }
                2 => fs::set_permissions(tree.runtime.path(), fs::Permissions::from_mode(0o755))?,
                3 => fs::set_permissions(&attempts, fs::Permissions::from_mode(0o755))?,
                4 => fs::set_permissions(&attempt, fs::Permissions::from_mode(0o755))?,
                5 => {
                    fs::rename(&attempts, tree.runtime.path().join("held-attempts"))?;
                    fs::create_dir(&attempts)?;
                    fs::set_permissions(&attempts, fs::Permissions::from_mode(0o700))?;
                }
                6 => {
                    fs::rename(&attempt, attempts.join("held-attempt"))?;
                    fs::create_dir(&attempt)?;
                    fs::set_permissions(&attempt, fs::Permissions::from_mode(0o700))?;
                }
                7 => {
                    fs::rename(&attempt, attempts.join("held-attempt"))?;
                    std::os::unix::fs::symlink(attempts.join("held-attempt"), &attempt)?;
                }
                _ => {
                    fs::remove_file(&record)?;
                    std::os::unix::fs::symlink(attempt.join("root"), &record)?;
                }
            }
            let held_root = tree.prepared.held_directories().1.try_clone()?;
            assert_eq!(
                detach_owned(root, &kernel, &tree.prepared).await,
                Err(ImageActivationError::EvidenceMismatch)
            );
            assert_eq!(kernel.detached(), 0, "fault {fault}");
            assert!(held_root.metadata()?.nlink() > 0);
            assert!(fs::symlink_metadata(&record).is_ok());
            assert!(tree
                .registry
                .commit_planned(&PlannedAttemptIntent::new([10; 16], [9; 32])?)
                .is_err());
        }
        Ok(())
    }

    #[tokio::test]
    async fn fresh_kernel_evidence_and_original_mount_id_are_required_before_detach() -> TestResult
    {
        for fault in 0..9 {
            let tree = prepared_tree()?;
            let key = component(&tree.prepared);
            let record = tree.runtime.path().join("registry").join(&key);
            let bytes = fs::read(&record)?;
            let (mut kernel, root) = attached_root(&tree.prepared)?;
            match fault {
                0 => kernel.observations.mount = None,
                1 => kernel.observations.path = None,
                2 => {
                    // Internally valid evidence for another mount still rejects.
                    let node = Node {
                        mount_id: 42,
                        device: (253, 3),
                        inode: 1,
                    };
                    kernel.observations.mount = Some(node);
                    kernel.observations.path = Some(node);
                    edit_entry(&mut kernel.observations, |entry| entry.mount_id = 42);
                    if let Some(executable) = kernel.observations.executable.as_mut() {
                        executable.node.mount_id = 42;
                    }
                }
                3 => edit_mapper(&mut kernel.observations, |mapper| mapper.uuid = None),
                4 => edit_loop(&mut kernel.observations, |device| {
                    device.backing = Some((7, 8));
                }),
                5 => kernel.observations.parent_mount_id = None,
                6 => kernel.observations.executable = None,
                7 => edit_entry(&mut kernel.observations, |entry| {
                    entry.optional.push("shared:5".to_owned());
                }),
                _ => kernel.detach = Err(ImageActivationError::TeardownFailure),
            }
            let error = if fault == 8 {
                ImageActivationError::TeardownFailure
            } else {
                ImageActivationError::EvidenceMismatch
            };
            assert_eq!(
                detach_owned(root, &kernel, &tree.prepared).await,
                Err(error),
                "fault {fault}"
            );
            assert_eq!(kernel.detached(), usize::from(fault == 8));
            assert_eq!(fs::read(record)?, bytes);
            tree.prepared.verify_directory()?;
            assert!(tree
                .registry
                .commit_planned(&PlannedAttemptIntent::new([10; 16], [9; 32])?)
                .is_err());
        }
        Ok(())
    }

    #[tokio::test]
    async fn same_image_device_substitutions_refuse_launch_and_detach() -> TestResult {
        for fault in 0..7 {
            let tree = prepared_tree()?;
            let record = tree
                .runtime
                .path()
                .join("registry")
                .join(component(&tree.prepared));
            let bytes = fs::read(&record)?;
            let (mut kernel, root) = attached_root(&tree.prepared)?;
            match fault {
                0 => {
                    let mut node = kernel.observations.mount.ok_or("attached node")?;
                    node.device.1 += 1;
                    kernel.observations.mount = Some(node);
                    kernel.observations.path = Some(node);
                    edit_entry(&mut kernel.observations, |entry| entry.device = node.device);
                    edit_mapper(&mut kernel.observations, |mapper| {
                        mapper.identity = block_generation(node.device, 102);
                    });
                    if let Some(executable) = kernel.observations.executable.as_mut() {
                        executable.node.device = node.device;
                    }
                }
                1 => edit_mapper(&mut kernel.observations, |mapper| {
                    mapper.uuid = Some("CRYPT-VERITY-another-root".to_owned());
                }),
                2 => edit_slaves(&mut kernel.observations, |slaves| {
                    for slave in slaves {
                        slave.loop_name = Some("loop8".to_owned());
                    }
                }),
                3 => {
                    let node = kernel.observations.mount.as_mut().ok_or("attached node")?;
                    node.inode += 1;
                    kernel.observations.path = Some(*node);
                }
                4 => edit_mapper(&mut kernel.observations, |mapper| {
                    mapper.identity = block_generation((253, 3), 103);
                }),
                _ => edit_slaves(&mut kernel.observations, |slaves| {
                    for slave in slaves {
                        if let Some(device) = slave.loop_device.as_mut() {
                            device.identity = if fault == 5 {
                                block_generation((7, 8), 101)
                            } else {
                                block_generation((7, 7), 103)
                            };
                        }
                    }
                }),
            }
            // Every replacement still satisfies the admitted image. Refusal
            // must come from retaining the original device identities.
            assert!(root.expected.verify(&kernel.observations).is_ok());
            assert_eq!(
                recheck(&kernel, &root, &tree.prepared, Some(&root.expected), || Ok(
                    ()
                )),
                Err(ImageActivationError::EvidenceMismatch),
                "launch with substitution {fault}"
            );
            assert_eq!(
                detach_owned(root, &kernel, &tree.prepared).await,
                Err(ImageActivationError::EvidenceMismatch),
                "detach with substitution {fault}"
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

    #[tokio::test]
    async fn reordered_identical_device_evidence_rechecks_and_detaches() -> TestResult {
        let tree = prepared_tree()?;
        let (mut kernel, root) = attached_root(&tree.prepared)?;
        edit_slaves(&mut kernel.observations, |slaves| slaves.reverse());
        edit_loop(&mut kernel.observations, |device| {
            if let Some(partitions) = device.partitions.as_mut() {
                partitions.reverse();
            }
        });
        assert_eq!(
            recheck(&kernel, &root, &tree.prepared, Some(&root.expected), || Ok(
                ()
            )),
            Ok(root.root_directory().clone())
        );
        detach_owned(root, &kernel, &tree.prepared).await?;
        assert_eq!(kernel.detached(), 1);
        tree.prepared.verify_directory()?;
        tree.registry
            .commit_planned(&PlannedAttemptIntent::new([10; 16], [9; 32])?)?;
        Ok(())
    }

    #[tokio::test]
    async fn a_quarantined_owner_can_detach_but_never_reopens_admission() -> TestResult {
        let tree = prepared_tree()?;
        let (kernel, root) = attached_root(&tree.prepared)?;
        assert!(tree
            .registry
            .commit_planned(tree.prepared.intent())
            .is_err());
        detach_owned(root, &kernel, &tree.prepared).await?;
        assert_eq!(kernel.detached(), 1);
        assert!(tree
            .registry
            .commit_planned(&PlannedAttemptIntent::new([10; 16], [9; 32])?)
            .is_err());
        Ok(())
    }

    #[tokio::test]
    async fn foreign_directory_and_real_host_dispatch_reject_without_mutating_resources(
    ) -> TestResult {
        let tree = prepared_tree()?;
        let foreign = tree
            .registry
            .commit_planned(&PlannedAttemptIntent::new([10; 16], [9; 32])?)?
            .prepare_directory()?;
        let (kernel, root) = attached_root(&tree.prepared)?;
        assert_eq!(
            detach_owned(root, &kernel, &foreign).await,
            Err(ImageActivationError::EvidenceMismatch)
        );
        assert_eq!(kernel.detached(), 0);
        foreign.verify_directory()?;
        let tree = prepared_tree()?;
        let (_kernel, root) = attached_root(&tree.prepared)?;
        // The public facade observes a regular file on the real kernel; it must
        // refuse before issuing an unmount. Positive mounted-host proof is #444.
        assert_eq!(
            root.detach(&tree.prepared, cleanup_deadline()).await,
            Err(ImageActivationError::EvidenceMismatch)
        );
        tree.prepared.verify_directory()?;
        Ok(())
    }
}
