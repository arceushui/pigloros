//! Restart detachment of a still-mounted root through the private kernel
//! port. Actual mounted-host conformance remains the separate #444 suite.

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod cases {
    use super::super::*;
    use crate::RecordedRootEntry;
    use crate::{SystemdAttemptRecovery, TransientServiceUnitName};

    /// The recorded root entry of attempt `[7; 16]` after its owner crashed;
    /// with `recorded`, its PAI3 root facts were committed first.
    fn recovered_entry(recorded: bool) -> Result<(tempfile::TempDir, RecordedRootEntry), BoxError> {
        let PreparedTree {
            runtime,
            prepared,
            registry,
        } = prepared_tree()?;
        if recorded {
            let identity = recorded_identity(&prepared)?;
            prepared.record_root(&identity, || Ok(()))?;
        }
        drop(prepared);
        drop(registry);
        let parent = fs::File::open(runtime.path())?;
        let recovery =
            SystemdAttemptRecovery::from_runtime_directory(&parent, parent.metadata()?.uid())?;
        let mut entries = recovery.recorded_root_entries()?;
        let entry = entries.pop().ok_or("no recorded root entry")?;
        assert!(entries.is_empty());
        Ok((runtime, entry))
    }

    fn attempt_component() -> Result<String, BoxError> {
        Ok(TransientServiceUnitName::from_attempt_id([7; 16])?
            .attempt_component()
            .to_owned())
    }

    /// A fake kernel that reads back exactly the fixture's provider root.
    fn mounted_kernel(observations: Observations) -> Result<FakeKernel, BoxError> {
        Ok(FakeKernel {
            mount_path: Some(tempfile::NamedTempFile::new()?.into_temp_path()),
            ..FakeKernel::accepting(observations)
        })
    }

    fn provider_root() -> Result<Observations, BoxError> {
        Ok(matching(&expected(&attempt_component()?)))
    }

    /// The fixture root's mapper and loop generations.
    fn fixture_devices() -> Result<[BlockIdentity; 2], BoxError> {
        Ok([
            block_generation((253, 3), 102).ok_or("mapper")?,
            block_generation((7, 7), 101).ok_or("loop")?,
        ])
    }

    /// Detach through the fake kernel over the fixture image directory.
    async fn detach(
        kernel: &FakeKernel,
        entry: RecordedRootEntry,
        deadline: tokio::time::Instant,
    ) -> Result<(), ImageActivationError> {
        detach_from(kernel, entry, Path::new(FIXTURE_IMAGES), deadline).await
    }

    async fn detach_from(
        kernel: &FakeKernel,
        entry: RecordedRootEntry,
        images: &Path,
        deadline: tokio::time::Instant,
    ) -> Result<(), ImageActivationError> {
        let detached =
            super::super::super::recovered::detach_with(kernel, entry, images, deadline).await;
        detached
    }

    fn edit_both_loops(observed: &mut Observations, edit: impl Fn(&mut Slave)) {
        edit_slaves(observed, |slaves| slaves.iter_mut().for_each(edit));
    }

    #[tokio::test]
    async fn a_provider_root_is_detached_and_its_devices_awaited() -> TestResult {
        if !crate::test_fixtures::in_lock_test_process(
            "root_attachment::tests::recovered::cases::a_provider_root_is_detached_and_its_devices_awaited",
        )
        .map_err(|error| error.to_string())?
        {
            return Ok(());
        }
        for recorded in [false, true] {
            let (_runtime, entry) = recovered_entry(recorded)?;
            let kernel = mounted_kernel(provider_root()?)?;
            // The devices remain once, then are gone.
            kernel
                .absence
                .lock()
                .map_err(|_| "poisoned fixture")?
                .push_back((std::time::Duration::ZERO, Ok(false)));
            detach(&kernel, entry, cleanup_deadline()).await?;
            assert_eq!(kernel.detached(), 1);
            let devices = fixture_devices()?;
            assert_eq!(
                *kernel.probes.lock().map_err(|_| "poisoned fixture")?,
                vec![devices, devices]
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn an_unmounted_or_unobservable_root_is_never_detached() -> TestResult {
        if !crate::test_fixtures::in_lock_test_process(
            "root_attachment::tests::recovered::cases::an_unmounted_or_unobservable_root_is_never_detached",
        )
        .map_err(|error| error.to_string())?
        {
            return Ok(());
        }
        let unmounted = |observed: &mut Observations| observed.parent_mount_id = Some(41);
        let no_mount = |observed: &mut Observations| observed.mount = None;
        let no_parent = |observed: &mut Observations| observed.parent_mount_id = None;
        let cases: [Case<'_>; 3] = [
            (&unmounted, Ok(())),
            (&no_mount, Err(ImageActivationError::EvidenceMismatch)),
            (&no_parent, Err(ImageActivationError::EvidenceMismatch)),
        ];
        for (edit, expected) in cases {
            let (_runtime, entry) = recovered_entry(true)?;
            let mut observed = provider_root()?;
            edit(&mut observed);
            let kernel = mounted_kernel(observed)?;
            let result = detach(&kernel, entry, cleanup_deadline()).await;
            assert_eq!(result, expected);
            assert_eq!(kernel.detached(), 0);
        }
        Ok(())
    }

    /// One readback edit and the detach result it must give.
    type Case<'a> = (
        &'a dyn Fn(&mut Observations),
        Result<(), ImageActivationError>,
    );

    /// One readback edit and whether a PAI2 attempt, which recorded no root
    /// facts, still accepts it.
    type Edit = (Box<dyn Fn(&mut Observations)>, bool);

    fn edit(change: impl Fn(&mut Observations) + 'static, pai2_accepts: bool) -> Edit {
        (Box::new(change), pai2_accepts)
    }

    fn node(mount_id: u64, inode: u64) -> Node {
        Node {
            mount_id,
            device: (253, 3),
            inode,
        }
    }

    /// Edits of the mount itself, none of which a provider root shows.
    fn mount_edits() -> Result<Vec<Edit>, BoxError> {
        let other_root = format!(
            "{}x",
            expected(&attempt_component()?).root_directory.as_str()
        );
        Ok(vec![
            edit(|observed| observed.path = None, false),
            edit(|observed| observed.path = Some(node(41, 2)), false),
            edit(|observed| observed.filesystem_magic = Some(1), false),
            edit(|observed| observed.read_only = Some(false), false),
            edit(|observed| observed.entry = None, false),
            edit(
                |observed| edit_entry(observed, |entry| entry.parent_id = 29),
                false,
            ),
            edit(
                |observed| edit_entry(observed, |entry| entry.device = (253, 4)),
                false,
            ),
            edit(
                |observed| edit_entry(observed, |entry| entry.root = "/sub".to_owned()),
                false,
            ),
            edit(
                move |observed| {
                    edit_entry(observed, |entry| entry.mount_point.clone_from(&other_root));
                },
                false,
            ),
            edit(
                |observed| edit_entry(observed, |entry| entry.options = "rw,nosuid".to_owned()),
                false,
            ),
            edit(
                |observed| {
                    edit_entry(observed, |entry| {
                        entry.super_options = "rw,user_xattr,acl".to_owned();
                    });
                },
                false,
            ),
            edit(
                |observed| edit_entry(observed, |entry| entry.filesystem = "ext4".to_owned()),
                false,
            ),
            edit(
                |observed| {
                    edit_entry(observed, |entry| {
                        entry.optional = vec!["shared:5".to_owned()];
                    });
                },
                false,
            ),
        ])
    }

    /// Edits of the mapper and loop devices, none of which a provider root
    /// shows.
    fn device_edits() -> Vec<Edit> {
        vec![
            edit(|observed| observed.mapper = None, false),
            edit(
                |observed| edit_mapper(observed, |mapper| mapper.identity = None),
                false,
            ),
            edit(
                |observed| {
                    edit_mapper(observed, |mapper| {
                        mapper.identity = block_generation((253, 4), 102);
                    });
                },
                false,
            ),
            edit(
                |observed| edit_mapper(observed, |mapper| mapper.uuid = None),
                false,
            ),
            edit(
                |observed| {
                    edit_mapper(observed, |mapper| {
                        mapper.uuid = Some("CRYPT-LUKS2-5f0e5a1c-root".to_owned());
                    });
                },
                false,
            ),
            edit(
                |observed| edit_mapper(observed, |mapper| mapper.read_only = Some(0)),
                false,
            ),
            edit(
                |observed| edit_mapper(observed, |mapper| mapper.slaves = None),
                false,
            ),
            edit(
                |observed| edit_slaves(observed, |slaves| drop(slaves.pop())),
                false,
            ),
            edit(
                |observed| {
                    edit_slaves(observed, |slaves| {
                        let third = slaves[0].clone();
                        slaves.push(third);
                    });
                },
                false,
            ),
            edit(
                |observed| edit_slaves(observed, |slaves| slaves[0].loop_name = None),
                false,
            ),
            edit(
                |observed| {
                    edit_slaves(observed, |slaves| {
                        slaves[1].loop_name = Some("loop8".to_owned());
                    });
                },
                false,
            ),
            edit(
                |observed| edit_slaves(observed, |slaves| slaves[0].loop_device = None),
                false,
            ),
            edit(
                |observed| {
                    edit_slaves(observed, |slaves| {
                        if let Some(device) = slaves[1].loop_device.as_mut() {
                            device.identity = block_generation((7, 7), 100);
                        }
                    });
                },
                false,
            ),
            edit(
                |observed| {
                    edit_both_loops(observed, |slave| {
                        if let Some(device) = slave.loop_device.as_mut() {
                            device.identity = None;
                        }
                    });
                },
                false,
            ),
            edit(
                |observed| edit_loop(observed, |device| device.offset = Some(1)),
                false,
            ),
            edit(
                |observed| edit_loop(observed, |device| device.size_limit = Some(1)),
                false,
            ),
            edit(
                |observed| edit_loop(observed, |device| device.autoclear = Some(0)),
                false,
            ),
            edit(
                |observed| edit_loop(observed, |device| device.read_only = Some(0)),
                false,
            ),
        ]
    }

    /// The loop is backed by another image than the one PAI2 recorded from
    /// the admission, or its backing file cannot be read.
    fn backing_edits() -> Vec<Edit> {
        [
            Some(crate::OTHER_IMAGES[0]),
            Some(crate::OTHER_IMAGES[1]),
            None,
        ]
        .into_iter()
        .map(|backing| {
            edit(
                move |observed| edit_loop(observed, |device| device.backing = backing),
                false,
            )
        })
        .collect()
    }

    /// Edits of only the PAI3 record's identities: another activation of the
    /// image PAI2 recorded still satisfies a PAI2 attempt.
    fn recorded_edits() -> Vec<Edit> {
        vec![
            edit(
                |observed| {
                    observed.mount = Some(node(42, 1));
                    observed.path = Some(node(42, 1));
                },
                true,
            ),
            edit(
                |observed| {
                    observed.mount = Some(node(41, 2));
                    observed.path = Some(node(41, 2));
                },
                true,
            ),
            edit(
                |observed| {
                    edit_mapper(observed, |mapper| {
                        mapper.identity = block_generation((253, 3), 103);
                    });
                },
                true,
            ),
            edit(
                |observed| {
                    edit_mapper(observed, |mapper| {
                        mapper.uuid = Some("CRYPT-VERITY-other-root".to_owned());
                    });
                },
                true,
            ),
            edit(
                |observed| {
                    edit_both_loops(observed, |slave| slave.loop_name = Some("loop9".to_owned()));
                },
                true,
            ),
            edit(
                |observed| {
                    edit_both_loops(observed, |slave| {
                        if let Some(device) = slave.loop_device.as_mut() {
                            device.identity = block_generation((7, 7), 100);
                        }
                    });
                },
                true,
            ),
        ]
    }

    #[tokio::test]
    async fn only_exactly_the_recorded_provider_root_is_detached() -> TestResult {
        if !crate::test_fixtures::in_lock_test_process(
            "root_attachment::tests::recovered::cases::only_exactly_the_recorded_provider_root_is_detached",
        )
        .map_err(|error| error.to_string())?
        {
            return Ok(());
        }
        let edits = mount_edits()?
            .into_iter()
            .chain(device_edits())
            .chain(backing_edits())
            .chain(recorded_edits());
        for (index, (change, pai2_accepts)) in edits.enumerate() {
            for recorded in [false, true] {
                let (_runtime, entry) = recovered_entry(recorded)?;
                let mut observed = provider_root()?;
                change(&mut observed);
                let kernel = mounted_kernel(observed)?;
                let result = detach(&kernel, entry, cleanup_deadline()).await;
                let accepted = pai2_accepts && !recorded;
                let expected = if accepted {
                    Ok(())
                } else {
                    Err(ImageActivationError::EvidenceMismatch)
                };
                assert_eq!(result, expected, "edit {index}, recorded {recorded}");
                assert_eq!(kernel.detached(), usize::from(accepted));
            }
        }
        // The image directory passed down is the provider's: any other
        // refuses.
        for recorded in [false, true] {
            let (_runtime, entry) = recovered_entry(recorded)?;
            let kernel = mounted_kernel(provider_root()?)?;
            let result =
                detach_from(&kernel, entry, Path::new("/elsewhere"), cleanup_deadline()).await;
            assert_eq!(result, Err(ImageActivationError::EvidenceMismatch));
            assert_eq!(kernel.detached(), 0);
        }
        // A loop that is not backed by a provider image, a root with a
        // submount, and an unreadable mount table.
        for (provider_image, submounts) in [(false, Some(false)), (true, Some(true)), (true, None)]
        {
            for recorded in [false, true] {
                let (_runtime, entry) = recovered_entry(recorded)?;
                let kernel = FakeKernel {
                    provider_image,
                    submounts,
                    ..mounted_kernel(provider_root()?)?
                };
                let result = detach(&kernel, entry, cleanup_deadline()).await;
                assert_eq!(result, Err(ImageActivationError::EvidenceMismatch));
                assert_eq!(kernel.detached(), 0);
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_detach_late_deadline_or_unproved_absence_is_refused() -> TestResult {
        if !crate::test_fixtures::in_lock_test_process(
            "root_attachment::tests::recovered::cases::a_failed_detach_late_deadline_or_unproved_absence_is_refused",
        )
        .map_err(|error| error.to_string())?
        {
            return Ok(());
        }
        // The detach command fails.
        let (_runtime, entry) = recovered_entry(true)?;
        let kernel = FakeKernel {
            detach: Err(ImageActivationError::TeardownFailure),
            ..mounted_kernel(provider_root()?)?
        };
        let result = detach(&kernel, entry, cleanup_deadline()).await;
        assert_eq!(result, Err(ImageActivationError::TeardownFailure));
        // The deadline has already passed: nothing is detached.
        let (_runtime, entry) = recovered_entry(true)?;
        let kernel = mounted_kernel(provider_root()?)?;
        let result = detach(&kernel, entry, tokio::time::Instant::now()).await;
        assert_eq!(result, Err(ImageActivationError::ResourceAbsenceUnverified));
        assert_eq!(kernel.detached(), 0);
        // The absence probe fails, or outlasts the deadline.
        for probe in [
            (
                std::time::Duration::ZERO,
                Err(ImageActivationError::ResourceAbsenceUnverified),
            ),
            (std::time::Duration::from_secs(5), Ok(true)),
        ] {
            let (_runtime, entry) = recovered_entry(true)?;
            let kernel = mounted_kernel(provider_root()?)?;
            kernel
                .absence
                .lock()
                .map_err(|_| "poisoned fixture")?
                .push_back(probe);
            let result = detach(&kernel, entry, cleanup_deadline()).await;
            assert_eq!(result, Err(ImageActivationError::ResourceAbsenceUnverified));
            assert_eq!(kernel.detached(), 1);
        }
        Ok(())
    }

    #[tokio::test]
    async fn the_host_detaches_only_a_provider_root_it_reads_back() -> TestResult {
        if !crate::test_fixtures::in_lock_test_process(
            "root_attachment::tests::recovered::cases::the_host_detaches_only_a_provider_root_it_reads_back",
        )
        .map_err(|error| error.to_string())?
        {
            return Ok(());
        }
        // An unmounted root is left to the directory inventory.
        let (runtime, entry) = recovered_entry(true)?;
        crate::RootResourceIdentity::detach_recovered(entry, cleanup_deadline()).await?;
        let root = runtime
            .path()
            .join("attempts")
            .join(attempt_component()?)
            .join("root");
        assert!(root.is_dir());
        // A root entry on another mount that is no provider root is refused
        // without any detach.
        let (_runtime, entry) = recovered_entry(true)?;
        let foreign = RecordedRootEntry {
            root: rustix::fs::open(
                "/proc",
                rustix::fs::OFlags::PATH
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )?,
            ..entry
        };
        assert_eq!(
            crate::RootResourceIdentity::detach_recovered(foreign, cleanup_deadline()).await,
            Err(ImageActivationError::EvidenceMismatch)
        );
        Ok(())
    }

    #[test]
    fn only_a_mount_table_entry_parented_by_the_root_is_a_submount() -> TestResult {
        let host = tempfile::tempdir()?;
        let kernel = HostKernel::at(&host.path().join("proc"), &host.path().join("sys"));
        // No mount table.
        assert_eq!(kernel.has_submounts(41), None);
        fs::create_dir_all(host.path().join("proc/self"))?;
        let root =
            "41 30 253:3 / /run/pigloros/sandbox/attempts/a/root ro,relatime - erofs /dev/dm-3 ro";
        let child = "42 41 0:5 / /run/pigloros/sandbox/attempts/a/root/x rw - tmpfs tmpfs rw";
        let sibling = "43 30 0:6 / /run/other rw - tmpfs tmpfs rw";
        for (table, expected) in [
            (format!("{root}\n{sibling}\n"), Some(false)),
            (format!("{root}\n{child}\n"), Some(true)),
            // A malformed line could hide a submount.
            (format!("{root}\nnot a mount entry\n"), None),
        ] {
            fs::write(host.path().join("proc/self/mountinfo"), &table)?;
            assert_eq!(kernel.has_submounts(41), expected, "{table}");
        }
        Ok(())
    }

    #[test]
    fn only_a_bound_loop_over_a_provider_image_is_a_provider_image() -> TestResult {
        let host = tempfile::tempdir()?;
        let root = host.path();
        let block = root.join("sys/block");
        let kernel = HostKernel::at(&root.join("proc"), &root.join("sys"));
        fs::create_dir_all(root.join("real/images"))?;
        std::os::unix::fs::symlink("real", root.join("link"))?;
        let images = root.join("link/images");
        let canonical = root.join("real/images").display().to_string();
        fake_block(&block, "loop2", true, Some(&format!("{canonical}/ab\n")))?;
        fake_block(&block, "loop3", true, Some("/srv/other.img\n"))?;
        fake_block(&block, "loop4", true, Some("\n"))?;
        fake_block(&block, "loop5", false, None)?;
        assert!(kernel.provider_image("loop2", &images));
        for name in ["loop3", "loop4", "loop5", "loop6"] {
            assert!(!kernel.provider_image(name, &images), "{name}");
        }
        // An image directory that cannot be resolved.
        assert!(!kernel.provider_image("loop2", &root.join("missing")));
        // The production rule sweeps the installed images.
        assert_eq!(
            images_directory(),
            Path::new(pos_reference::selector::installation::SANDBOX_ARTIFACT_ROOT).join("images")
        );
        Ok(())
    }
}
