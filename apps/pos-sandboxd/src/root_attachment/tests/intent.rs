//! Durable pre-launch root identity through the existing owned-root seam.

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod cases {
    use super::super::*;
    use crate::test_fixtures::{root_record_fixture, with_io_fault};
    use crate::SystemdAttemptRecovery;

    #[tokio::test]
    async fn root_intent_is_committed_once_and_retained_after_resource_cleanup() -> TestResult {
        if bounded_fixture_child(
            "PIGLOROS_ROOT_INTENT_CHILD",
            concat!(
                module_path!(),
                "::root_intent_is_committed_once_and_retained_after_resource_cleanup"
            ),
        )? {
            return Ok(());
        }
        let tree = prepared_tree()?;
        let (kernel, root) = attached_root(&tree.prepared)?;
        let key = component(&tree.prepared);
        let path = tree.runtime.path().join("registry").join(&key);
        let expected = root_record_fixture(fs::read(&path)?, &key);
        assert_eq!(expected.len(), 393);

        let checked = recheck(&kernel, &root, &tree.prepared, Some(&root.expected), || {
            Ok(())
        })?;
        assert_eq!(
            checked.as_str(),
            format!("/run/pigloros/sandbox/attempts/{key}/root")
        );
        assert_eq!(fs::read(&path)?, expected);
        let inode = fs::metadata(&path)?.ino();
        recheck(&kernel, &root, &tree.prepared, Some(&root.expected), || {
            Ok(())
        })?;
        assert_eq!(
            fs::metadata(&path)?.ino(),
            inode,
            "a repeat must not republish"
        );
        assert_eq!(fs::read(&path)?, expected);
        assert_eq!(
            fs::read_dir(tree.runtime.path().join("registry"))?.count(),
            1
        );

        detach_owned(root, &kernel, &tree.prepared).await?;
        tree.prepared.remove_unmounted()?;
        assert_eq!(fs::read(&path)?, expected);
        drop(tree.registry);
        let parent = fs::File::open(tree.runtime.path())?;
        let recovery =
            SystemdAttemptRecovery::from_runtime_directory(&parent, parent.metadata()?.uid())?;
        assert_eq!(recovery.entries().len(), 1);
        let entry = &recovery.entries()[0];
        assert!(!entry.is_temporary());
        assert_eq!(entry.component(), key);
        let intent = entry.intent().ok_or("recorded root intent")?;
        assert_eq!(intent.planned().attempt_id(), [7; 16]);
        assert!(intent.directory_identities().is_some());
        recovery.verify_unchanged()?;
        drop(recovery);
        assert!(
            SystemdAttemptRegistry::from_runtime_directory(&parent, parent.metadata()?.uid())
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn root_intent_io_failures_refuse_launch_and_preserve_recovery_state() -> TestResult {
        if bounded_fixture_child(
            "PIGLOROS_ROOT_INTENT_IO_CHILD",
            concat!(
                module_path!(),
                "::root_intent_io_failures_refuse_launch_and_preserve_recovery_state"
            ),
        )? {
            return Ok(());
        }
        let count = {
            let tree = prepared_tree()?;
            let (kernel, root) = attached_root(&tree.prepared)?;
            let (result, count) = with_io_fault(None, || {
                recheck(&kernel, &root, &tree.prepared, Some(&root.expected), || {
                    Ok(())
                })
            });
            result?;
            let bytes = fs::read(
                tree.runtime
                    .path()
                    .join("registry")
                    .join(component(&tree.prepared)),
            )?;
            assert_eq!(&bytes[..4], b"PAI3");
            assert_eq!(bytes.len(), 393);
            count
        };
        assert!(count > 0);
        for fail_at in 0..count {
            let tree = prepared_tree()?;
            let (kernel, root) = attached_root(&tree.prepared)?;
            let key = component(&tree.prepared);
            let path = tree.runtime.path().join("registry").join(&key);
            let (result, observed) = with_io_fault(Some(fail_at), || {
                recheck(&kernel, &root, &tree.prepared, Some(&root.expected), || {
                    Ok(())
                })
            });
            assert_eq!(
                result,
                Err(ImageActivationError::EvidenceMismatch),
                "fault {fail_at}"
            );
            assert_eq!(observed, fail_at + 1, "fault {fail_at} must be reached");
            let retained = fs::read(&path)?;
            assert!(
                recheck(&kernel, &root, &tree.prepared, Some(&root.expected), || Ok(
                    ()
                ))
                .is_err()
            );
            assert_eq!(fs::read(&path)?, retained);
            assert!(tree
                .registry
                .commit_planned(&PlannedAttemptIntent::new([8; 16], [9; 32])?)
                .is_err());
            assert_eq!(kernel.detached(), 0);
            drop(root);
            drop(tree.prepared);
            drop(tree.registry);
            let parent = fs::File::open(tree.runtime.path())?;
            let recovery =
                SystemdAttemptRecovery::from_runtime_directory(&parent, parent.metadata()?.uid())?;
            assert!(recovery
                .entries()
                .iter()
                .any(|entry| entry.component() == key));
            recovery.verify_unchanged()?;
            drop(recovery);
            assert!(SystemdAttemptRegistry::from_runtime_directory(
                &parent,
                parent.metadata()?.uid()
            )
            .is_err());
        }
        Ok(())
    }

    #[test]
    fn changed_committed_root_is_not_rewritten_or_released_for_launch() -> TestResult {
        let tree = prepared_tree()?;
        let (kernel, root) = attached_root(&tree.prepared)?;
        recheck(&kernel, &root, &tree.prepared, Some(&root.expected), || {
            Ok(())
        })?;
        let path = tree
            .runtime
            .path()
            .join("registry")
            .join(component(&tree.prepared));
        let mut changed = fs::read(&path)?;
        changed[248] ^= 1;
        fs::write(&path, &changed)?;
        let reads = kernel.readbacks.load(Ordering::SeqCst);
        assert_eq!(
            recheck(&kernel, &root, &tree.prepared, Some(&root.expected), || Ok(
                ()
            )),
            Err(ImageActivationError::EvidenceMismatch)
        );
        assert_eq!(kernel.readbacks.load(Ordering::SeqCst), reads);
        assert_eq!(fs::read(&path)?, changed);
        assert!(tree
            .registry
            .commit_planned(&PlannedAttemptIntent::new([8; 16], [9; 32])?)
            .is_err());
        Ok(())
    }

    #[test]
    fn authority_change_during_persistence_cannot_release_a_launch_token() -> TestResult {
        let tree = prepared_tree()?;
        let (kernel, root) = attached_root(&tree.prepared)?;
        let path = tree
            .runtime
            .path()
            .join("registry")
            .join(component(&tree.prepared));
        let mut checked = 0;
        let persisted = std::cell::Cell::new(false);
        let result = recheck(&kernel, &root, &tree.prepared, Some(&root.expected), || {
            checked += 1;
            if checked == 1 {
                Ok(())
            } else {
                persisted.set(fs::read(&path).is_ok_and(|bytes| bytes.starts_with(b"PAI3")));
                Err(StagingError::AuthorityChanged)
            }
        });
        assert_eq!(checked, 2);
        assert!(persisted.get(), "the second check must follow persistence");
        assert_eq!(result, Err(ImageActivationError::EvidenceMismatch));
        assert_eq!(&fs::read(&path)?[..4], b"PAI3");
        Ok(())
    }

    #[tokio::test]
    async fn a_later_verified_mount_cannot_replace_the_original_root_intent() -> TestResult {
        let tree = prepared_tree()?;
        let (kernel, root) = attached_root(&tree.prepared)?;
        let activated = root.expected.clone();
        recheck(&kernel, &root, &tree.prepared, Some(&activated), || Ok(()))?;
        let path = tree
            .runtime
            .path()
            .join("registry")
            .join(component(&tree.prepared));
        let retained = fs::read(&path)?;
        detach_owned(root, &kernel, &tree.prepared).await?;
        let mut observed = matching(&activated);
        for node in [&mut observed.mount, &mut observed.path]
            .into_iter()
            .flatten()
        {
            node.mount_id = 42;
        }
        edit_entry(&mut observed, |entry| entry.mount_id = 42);
        if let Some(executable) = observed.executable.as_mut() {
            executable.node.mount_id = 42;
        }
        edit_mapper(&mut observed, |mapper| {
            mapper.identity = block_generation((253, 3), 104);
        });
        edit_slaves(&mut observed, |slaves| {
            for slave in slaves {
                if let Some(device) = slave.loop_device.as_mut() {
                    device.identity = block_generation((7, 7), 103);
                }
            }
        });
        let later_kernel = FakeKernel::accepting(observed);
        let later = attach_and_verify(
            &later_kernel,
            &tree.prepared,
            &activated,
            file_mount()?,
            || Ok(()),
        )?;
        assert_eq!(later.mount_id(), 42);
        assert_eq!(
            recheck(
                &later_kernel,
                &later,
                &tree.prepared,
                Some(&activated),
                || Ok(())
            ),
            Err(ImageActivationError::EvidenceMismatch)
        );
        assert_eq!(
            later_kernel.readbacks.load(Ordering::SeqCst),
            2,
            "the later valid readback must be reached"
        );
        assert_eq!(fs::read(&path)?, retained);
        assert!(tree
            .registry
            .commit_planned(&PlannedAttemptIntent::new([8; 16], [9; 32])?)
            .is_err());
        Ok(())
    }
}
