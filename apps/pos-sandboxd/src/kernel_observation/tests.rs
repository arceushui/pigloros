use std::{
    os::fd::AsFd,
    os::unix::fs::MetadataExt,
    process::{Child, Command, Stdio},
};

use rustix::fs::{statat, CWD};

use super::*;
use crate::test_fixtures::{cgroup_listing, FakeUnitNetwork, TestResult};

const INVOCATION: [u8; 16] = [0x12; 16];
const ADAPTER: FdIdentity = FdIdentity {
    mount_id: 9,
    inode: 77,
};

fn own_pid() -> u32 {
    std::process::id()
}

/// Namespaces that are not this process's own.
fn foreign_provider() -> TestResult<ProviderNamespaces> {
    let own = ProviderNamespaces::observe()?;
    Ok(ProviderNamespaces::for_test(
        NamespaceSet::for_test_shifted(own.namespaces()),
    ))
}

fn context(cgroup: &File, work: bool) -> TestResult<ObservationContext<'_>> {
    let metadata = cgroup.metadata()?;
    Ok(ObservationContext::new(
        CgroupView::new(cgroup.as_fd(), (metadata.dev(), metadata.ino())),
        RootIdentity::FIXTURE,
        ADAPTER,
        [7; 32],
        work,
    ))
}

/// The manager's view of this process as the unit's main process.
fn this_unit() -> impl Fn() -> Result<(u32, [u8; 16]), KernelObservationError> {
    || Ok((own_pid(), INVOCATION))
}

/// A unit network check that finds only `lo`.
fn isolated() -> FakeUnitNetwork {
    FakeUnitNetwork::isolated()
}

/// A child that exits at once; reap it with `wait`.
fn short_lived() -> TestResult<Child> {
    Ok(Command::new(std::env::current_exe()?)
        .arg("--list")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?)
}

/// Wait, up to ten seconds, until `pidfd` reports its process exited.
fn exited(pidfd: &OwnedFd) -> TestResult {
    let mut polled = [PollFd::new(pidfd, PollFlags::IN)];
    let ten_seconds = Timespec {
        tv_sec: 10,
        tv_nsec: 0,
    };
    let ready = poll(&mut polled, Some(&ten_seconds))?;
    assert_eq!(ready, 1);
    Ok(())
}

#[test]
fn this_process_is_observed_through_its_anchored_procdir() -> TestResult {
    let (_directory, cgroup) = cgroup_listing(own_pid())?;
    let provider = foreign_provider()?;
    let observed = observe_unit(
        &this_unit(),
        &context(&cgroup, false)?,
        &provider,
        &isolated(),
    )?;
    let observation = observed.observation();
    let own = ProviderNamespaces::observe()?;
    assert_eq!(observation.main_pid(), own_pid());
    assert_eq!(observation.invocation_id(), INVOCATION);
    assert_eq!(observation.adapter(), ADAPTER);
    assert_eq!(observation.root(), RootIdentity::FIXTURE);
    assert_eq!(observation.namespaces(), own.namespaces());
    assert_eq!(observation.provider_namespaces(), provider.namespaces());
    assert_eq!(observation.observed_fdl1_digest(), [7; 32]);
    assert_eq!(observation.work(), None);
    assert!(observed.work().is_none());
    let executable = std::fs::metadata(std::env::current_exe()?)?;
    assert_eq!(observation.launcher().inode, executable.ino());
    let metadata = cgroup.metadata()?;
    assert_eq!(observation.cgroup().inode(), metadata.ino());
    assert_eq!(observation.cgroup().device().major(), major(metadata.dev()));
    assert_eq!(observation.cgroup().device().minor(), minor(metadata.dev()));
    // Two observations of an unchanged process are equal: the recheck's rule.
    let again = observe_unit(
        &this_unit(),
        &context(&cgroup, false)?,
        &provider,
        &isolated(),
    )?;
    assert_eq!(again.observation(), observation);
    Ok(())
}

#[test]
fn a_requested_work_mount_is_observed_and_held_for_after_exit() -> TestResult {
    // `/dev/shm` stands in for the unit's `/work`: a tmpfs mount root reached
    // through the procdir's `root` magic link.
    let (_directory, cgroup) = cgroup_listing(own_pid())?;
    let paths = ProcPaths {
        proc: "/proc",
        work: "root/dev/shm",
    };
    let observed = observe_unit_in(
        paths,
        &this_unit(),
        &context(&cgroup, true)?,
        &foreign_provider()?,
        &isolated(),
    )?;
    let work = observed.observation().work().ok_or("no /work")?;
    assert!(work.capacity_bytes() > 0);
    let held = observed.work().ok_or("no /work handle")?;
    let usage = WorkUsage::observe(held)?;
    assert_eq!(usage.mount(), work);
    let shm = statx(CWD, "/dev/shm", AtFlags::empty(), StatxFlags::MNT_ID)?;
    assert_eq!(work.mount_id(), shm.stx_mnt_id);
    assert_eq!(usage.mount().mount_id(), shm.stx_mnt_id);
    let block = u64::try_from(fstatfs(held)?.f_bsize)?;
    assert!(usage.available_bytes() <= work.capacity_bytes());
    // Free space is counted in whole blocks, and a test host has some.
    assert_eq!(usage.available_bytes() % block, 0);
    assert!(usage.available_bytes() >= block);
    // The release outcome keeps this handle for the terminal reading.
    let evidence = observed.observation().fixture_evidence()?;
    let mut outcome = crate::ReleaseOutcome::new(None, Some((observed, evidence)), None);
    assert!(outcome.work().is_some());
    // The terminal reading takes the handle, so nothing keeps it open after
    // `work-after` (ADR-069 R15 §3.6 item 3, N9).
    assert!(outcome.take_work().is_some());
    assert!(outcome.work().is_none());
    assert!(outcome.take_work().is_none());
    Ok(())
}

#[test]
fn a_process_list_is_read_up_to_its_bound_and_no_further() -> TestResult {
    let directory = tempfile::tempdir()?;
    let listing = |size: u64| -> TestResult<File> {
        let head = format!("{}\n", own_pid());
        let padding = usize::try_from(size)? - head.len();
        let mut body = head.into_bytes();
        body.extend(std::iter::repeat_n(b'\n', padding));
        std::fs::write(directory.path().join("cgroup.procs"), body)?;
        Ok(File::open(directory.path())?)
    };
    assert_eq!(member(listing(MAX_PROCS_BYTES)?.as_fd(), own_pid()), Ok(()));
    assert_eq!(
        member(listing(MAX_PROCS_BYTES + 1)?.as_fd(), own_pid()),
        Err(KernelObservationError::CgroupProcs)
    );
    Ok(())
}

#[test]
fn a_work_path_that_is_no_tmpfs_root_is_refused() -> TestResult {
    let root = File::open("/")?;
    assert!(matches!(
        observe_work(root.as_fd(), "nonexistent-work"),
        Err(KernelObservationError::WorkRead(_))
    ));
    assert!(matches!(
        observe_work(root.as_fd(), "proc"),
        Err(KernelObservationError::WorkCapacity)
    ));
    assert!(matches!(
        WorkUsage::observe(&File::open("/proc")?),
        Err(KernelObservationError::WorkCapacity)
    ));
    let (_directory, cgroup) = cgroup_listing(own_pid())?;
    let paths = ProcPaths {
        proc: "/proc",
        work: "root/nonexistent-work",
    };
    assert!(matches!(
        observe_unit_in(
            paths,
            &this_unit(),
            &context(&cgroup, true)?,
            &foreign_provider()?,
            &isolated()
        ),
        Err(KernelObservationError::WorkRead(_))
    ));
    Ok(())
}

/// R9 §4.4: `exe` and `ns/*` are magic links whose targets are the evidence.
/// Statting the links themselves (`AT_SYMLINK_NOFOLLOW`) yields other
/// identities, which would silently break the RDY1 launcher equality and the
/// namespace-isolation check; this fails if the observation ever stops
/// following them.
#[test]
fn magic_links_are_followed_and_a_nofollow_stat_would_differ() -> TestResult {
    let procdir = open(format!("/proc/{}", own_pid()), DIRECTORY, Mode::empty())?;
    let required = launcher(procdir.as_fd())?;
    let link = statx(
        &procdir,
        "exe",
        AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::INO.union(StatxFlags::MNT_ID),
    )?;
    let executable = std::fs::metadata(std::env::current_exe()?)?;
    assert_eq!(required.inode, executable.ino());
    assert_ne!(
        (link.stx_mnt_id, link.stx_ino),
        (required.mount_id, required.inode)
    );

    let net = namespace(procdir.as_fd(), "net")?;
    let own = ProviderNamespaces::observe()?;
    assert_eq!(net, own.namespaces().identities()[5]);
    let net_link = statat(&procdir, "ns/net", AtFlags::SYMLINK_NOFOLLOW)?;
    let nofollow = KernelIdentity::of(net_link.st_dev, net_link.st_ino)?;
    assert_ne!(nofollow, net);
    // The link's identity is no namespace the isolation check could compare.
    assert!(!own.namespaces().identities().contains(&nofollow));
    let path = statat(CWD, format!("/proc/{}/ns/net", own_pid()), AtFlags::empty())?;
    assert_eq!(KernelIdentity::of(path.st_dev, path.st_ino)?, net);
    Ok(())
}

#[test]
fn a_process_directory_off_procfs_is_never_trusted() -> TestResult {
    let fake = tempfile::tempdir()?;
    let proc = fake.path().to_str().ok_or("path")?;
    assert!(matches!(
        ProcessAnchor::open(proc, own_pid()),
        Err(KernelObservationError::ProcDirectory(_))
    ));
    std::fs::create_dir(fake.path().join(own_pid().to_string()))?;
    assert!(matches!(
        ProcessAnchor::open(proc, own_pid()),
        Err(KernelObservationError::NotProcfs)
    ));
    assert!(matches!(
        procfs(File::open(fake.path())?.as_fd()),
        Err(KernelObservationError::NotProcfs)
    ));
    let (_directory, cgroup) = cgroup_listing(own_pid())?;
    let paths = ProcPaths {
        proc,
        work: "root/work",
    };
    assert!(matches!(
        observe_unit_in(
            paths,
            &this_unit(),
            &context(&cgroup, false)?,
            &foreign_provider()?,
            &isolated()
        ),
        Err(KernelObservationError::NotProcfs)
    ));
    Ok(())
}

#[test]
fn an_exited_process_is_never_observed() -> TestResult {
    let mut child = short_lived()?;
    let pid = Pid::from_raw(i32::try_from(child.id())?).ok_or("pid")?;
    let pidfd = pidfd_open(pid, PidfdFlags::empty())?;
    let procdir = open(format!("/proc/{}", child.id()), DIRECTORY, Mode::empty())?;
    exited(&pidfd)?;
    // The pidfd of an exited, unreaped process signals its exit.
    assert_eq!(alive(pidfd.as_fd()), Err(KernelObservationError::Exited));
    child.wait()?;
    // Once reaped, its directory descriptor reaches nothing, and no pidfd
    // can be opened for its PID.
    assert!(matches!(
        NamespaceSet::read(procdir.as_fd()),
        Err(KernelObservationError::Namespace(_))
    ));
    assert_eq!(
        launcher(procdir.as_fd()),
        Err(KernelObservationError::Executable)
    );
    assert!(matches!(
        ProcessAnchor::open("/proc", child.id()),
        Err(KernelObservationError::Pidfd(_))
    ));
    Ok(())
}

/// The network namespace is read last, with its descriptor: a process whose
/// other five namespaces read but whose `ns/net` does not is refused.
#[test]
fn a_process_without_a_readable_network_namespace_is_refused() -> TestResult {
    let fake = tempfile::tempdir()?;
    std::fs::create_dir(fake.path().join("ns"))?;
    for name in OTHER_NAMESPACES {
        std::fs::write(fake.path().join("ns").join(name), b"")?;
    }
    let procdir = open(fake.path(), DIRECTORY, Mode::empty())?;
    assert!(matches!(
        NamespaceSet::read_retaining(procdir.as_fd()),
        Err(KernelObservationError::Namespace(_))
    ));
    std::fs::write(fake.path().join("ns").join(NET), b"")?;
    let (namespaces, net) = NamespaceSet::read_retaining(procdir.as_fd())?;
    let status = fstat(&net)?;
    assert_eq!(
        namespaces.identities()[5],
        KernelIdentity::of(status.st_dev, status.st_ino)?
    );
    Ok(())
}

#[test]
fn a_main_pid_outside_the_bound_cgroup_is_refused() -> TestResult {
    let (_directory, other) = cgroup_listing(own_pid() + 1)?;
    assert_eq!(
        member(other.as_fd(), own_pid()),
        Err(KernelObservationError::NotInCgroup)
    );
    let empty = tempfile::tempdir()?;
    assert_eq!(
        member(File::open(empty.path())?.as_fd(), own_pid()),
        Err(KernelObservationError::CgroupProcs)
    );
    assert_eq!(
        observe_unit(
            &this_unit(),
            &context(&other, false)?,
            &foreign_provider()?,
            &isolated()
        )
        .err(),
        Some(KernelObservationError::NotInCgroup)
    );
    Ok(())
}

#[test]
fn a_unit_in_the_providers_namespaces_is_refused() -> TestResult {
    let (_directory, cgroup) = cgroup_listing(own_pid())?;
    let provider = ProviderNamespaces::observe()?;
    assert_eq!(
        observe_unit(
            &this_unit(),
            &context(&cgroup, false)?,
            &provider,
            &isolated()
        )
        .err(),
        Some(KernelObservationError::SharedNamespace)
    );
    Ok(())
}

#[test]
fn the_manager_identity_must_be_readable_and_unchanged() -> TestResult {
    let (_directory, cgroup) = cgroup_listing(own_pid())?;
    let context = context(&cgroup, false)?;
    let provider = foreign_provider()?;
    let unreadable = || Err::<(u32, [u8; 16]), _>(KernelObservationError::Identity);
    assert_eq!(
        observe_unit(&unreadable, &context, &provider, &isolated()).err(),
        Some(KernelObservationError::Identity)
    );
    let reads = std::cell::Cell::new(0_u8);
    let drifting = || {
        reads.set(reads.get().wrapping_add(1));
        Ok::<_, KernelObservationError>((own_pid(), [reads.get(); 16]))
    };
    assert_eq!(
        observe_unit(&drifting, &context, &provider, &isolated()).err(),
        Some(KernelObservationError::IdentityChanged)
    );
    reads.set(0);
    let failing_again = || {
        reads.set(reads.get().wrapping_add(1));
        if reads.get() > 1 {
            Err(KernelObservationError::Identity)
        } else {
            Ok((own_pid(), INVOCATION))
        }
    };
    assert_eq!(
        observe_unit(&failing_again, &context, &provider, &isolated()).err(),
        Some(KernelObservationError::Identity)
    );
    let no_main = || Ok::<_, KernelObservationError>((0, INVOCATION));
    assert_eq!(
        observe_unit(&no_main, &context, &provider, &isolated()).err(),
        Some(KernelObservationError::NoMainProcess)
    );
    Ok(())
}

#[test]
fn device_numbers_are_kept_within_the_kernel_bounds() -> TestResult {
    let largest = DeviceNumber::new(MAX_MAJOR, MAX_MINOR).ok_or("in bounds")?;
    assert_eq!((largest.major(), largest.minor()), (4095, 1_048_575));
    assert_eq!(DeviceNumber::new(MAX_MAJOR + 1, 0), None);
    assert_eq!(DeviceNumber::new(0, MAX_MINOR + 1), None);
    let (_directory, cgroup) = cgroup_listing(own_pid())?;
    let context = ObservationContext::new(
        CgroupView::new(cgroup.as_fd(), (u64::MAX, 1)),
        RootIdentity::FIXTURE,
        ADAPTER,
        [7; 32],
        false,
    );
    assert_eq!(
        observe_unit(&this_unit(), &context, &foreign_provider()?, &isolated()).err(),
        Some(KernelObservationError::Device)
    );
    Ok(())
}

#[test]
fn the_root_identity_names_its_mapper_and_loop_device() {
    let root = RootIdentity::FIXTURE;
    assert_eq!(root.mount_id(), 301);
    assert_eq!(
        (
            root.mapper().device().major(),
            root.mapper().device().minor()
        ),
        (253, 3)
    );
    assert_eq!(root.mapper().diskseq(), NonZeroU64::MIN);
    assert_eq!(root.loop_device().device().major(), 7);
    assert_eq!(root.loop_device().diskseq(), NonZeroU64::MAX);
    assert_eq!(
        BlockDevice::of((253, 3), NonZeroU64::MIN),
        Some(root.mapper())
    );
    assert_eq!(BlockDevice::of((MAX_MAJOR + 1, 0), NonZeroU64::MIN), None);
}

#[test]
fn a_cgroup_view_reports_the_bound_identity() -> TestResult {
    let directory = File::open("/")?;
    assert_eq!(
        CgroupView::new(directory.as_fd(), (1, 2)).identity(),
        (1, 2)
    );
    Ok(())
}

/// R9 §4.4: every one of the six namespace types must differ from the
/// provider's; sharing any single one is refused.
#[test]
fn sharing_any_single_namespace_type_with_the_provider_is_refused() -> TestResult {
    let own = *ProviderNamespaces::observe()?.namespaces();
    let foreign = NamespaceSet::for_test_shifted(&own);
    assert!(own.isolated_from(&foreign));
    let network = isolated();
    for (shared, name) in [OTHER_NAMESPACES.as_slice(), &[NET]]
        .concat()
        .iter()
        .enumerate()
    {
        let mut provider = foreign;
        provider.0[shared] = own.0[shared];
        assert!(!own.isolated_from(&provider), "{name}");
        let (_directory, cgroup) = cgroup_listing(own_pid())?;
        assert_eq!(
            observe_unit(
                &this_unit(),
                &context(&cgroup, false)?,
                &ProviderNamespaces::for_test(provider),
                &network
            )
            .err(),
            Some(KernelObservationError::SharedNamespace),
            "{name}"
        );
    }
    // The check is never made on a namespace the provider shares.
    assert!(network.seen().is_empty());
    Ok(())
}

/// R14 N12: the check reads the very network namespace the observation
/// names, on the descriptor opened with the identities, and a failed check
/// leaves no observation, for every class of failure.
#[test]
fn the_unit_network_check_reads_the_observed_namespace_and_can_refuse() -> TestResult {
    let (_directory, cgroup) = cgroup_listing(own_pid())?;
    let provider = foreign_provider()?;
    let network = isolated();
    let observed = observe_unit(&this_unit(), &context(&cgroup, false)?, &provider, &network)?;
    let net = statat(CWD, "/proc/self/ns/net", AtFlags::empty())?;
    assert_eq!(network.seen(), [(net.st_dev, net.st_ino)]);
    assert_eq!(
        observed.observation().namespaces().identities()[5],
        KernelIdentity::of(net.st_dev, net.st_ino)?
    );
    for error in [UnitNetworkError::Transport, UnitNetworkError::Changed] {
        let refusing = FakeUnitNetwork::answering(Err(error));
        assert_eq!(
            observe_unit(
                &this_unit(),
                &context(&cgroup, false)?,
                &provider,
                &refusing
            )
            .err(),
            Some(KernelObservationError::UnitNetwork(error))
        );
        assert_eq!(refusing.seen().len(), 1);
    }
    Ok(())
}

#[test]
fn the_providers_own_process_directory_is_trusted_only_on_procfs() -> TestResult {
    let fake = tempfile::tempdir()?;
    let path = fake.path().to_str().ok_or("path")?;
    assert_eq!(
        ProviderNamespaces::observe_at(path),
        Err(KernelObservationError::NotProcfs)
    );
    assert!(matches!(
        ProviderNamespaces::observe_at("/nonexistent-proc-self"),
        Err(KernelObservationError::ProcDirectory(_))
    ));
    assert_eq!(
        ProviderNamespaces::observe_at("/proc/self"),
        ProviderNamespaces::observe()
    );
    Ok(())
}

/// The process list is matched line by line, exactly: neither a prefix nor
/// an extension of the PID is a member, and a last line without a newline
/// still counts.
#[test]
fn a_process_list_matches_whole_lines_only() -> TestResult {
    let directory = tempfile::tempdir()?;
    let listed = |body: &str, pid: u32| -> TestResult<Result<(), KernelObservationError>> {
        std::fs::write(directory.path().join("cgroup.procs"), body)?;
        Ok(member(File::open(directory.path())?.as_fd(), pid))
    };
    assert_eq!(
        listed("123\n", 12)?,
        Err(KernelObservationError::NotInCgroup)
    );
    assert_eq!(
        listed("12\n", 123)?,
        Err(KernelObservationError::NotInCgroup)
    );
    assert_eq!(
        listed("1\n312\n", 12)?,
        Err(KernelObservationError::NotInCgroup)
    );
    assert_eq!(listed("1\n12", 12)?, Ok(()));
    assert_eq!(listed("12\n1\n", 12)?, Ok(()));
    Ok(())
}

/// The adapter is identified beneath the anchored `/proc/<MainPID>/root`,
/// so in the main process's own mount namespace, and resolved as the
/// launcher resolves it: beneath that root, never through a symlink or a
/// magic link.
#[test]
fn the_adapter_is_observed_beneath_the_unit_root() -> TestResult {
    let executable = std::env::current_exe()?;
    let path = executable.to_str().ok_or("path")?;
    let expected = statx(
        CWD,
        path,
        AtFlags::empty(),
        StatxFlags::INO.union(StatxFlags::MNT_ID),
    )?;
    let process = MainProcess::open(own_pid())?;
    assert_eq!(
        process.adapter(path)?,
        FdIdentity {
            mount_id: expected.stx_mnt_id,
            inode: expected.stx_ino,
        }
    );
    // The leading slash is the unit root's own.
    assert_eq!(
        process.adapter(path.trim_start_matches('/'))?,
        process.adapter(path)?
    );
    // The executable is read through the same anchor.
    assert_eq!(process.executable()?.metadata()?.ino(), expected.stx_ino);
    let directory = tempfile::tempdir()?;
    let link = directory.path().join("adapter");
    std::os::unix::fs::symlink(&executable, &link)?;
    for refused in [
        link.to_str().ok_or("path")?.to_owned(),
        format!("{}/missing", directory.path().to_str().ok_or("path")?),
        "../../etc/passwd".to_owned(),
        // A magic link beneath the root.
        format!("/proc/{}/exe", own_pid()),
    ] {
        assert!(matches!(
            process.adapter(&refused),
            Err(KernelObservationError::Adapter)
        ));
    }
    Ok(())
}

/// Only an identity that carries its mount ID is an adapter identity.
#[test]
fn an_identity_without_a_mount_id_is_refused() {
    let mount = StatxFlags::INO.union(StatxFlags::MNT_ID).bits();
    assert_eq!(
        fd_identity(mount, 5, 6),
        Some(FdIdentity {
            mount_id: 5,
            inode: 6
        })
    );
    assert_eq!(fd_identity(StatxFlags::INO.bits(), 5, 6), None);
}

/// The adapter is read only while the process is alive, before and after.
#[test]
fn the_adapter_of_an_exited_process_is_not_observed() -> TestResult {
    let executable = std::env::current_exe()?;
    let path = executable.to_str().ok_or("path")?;
    let anchor = ProcessAnchor::open("/proc", own_pid())?;
    let calls = std::cell::Cell::new(0);
    let exits_after_the_read = |_: BorrowedFd<'_>| {
        calls.set(calls.get() + 1);
        if calls.get() > 1 {
            Err(KernelObservationError::Exited)
        } else {
            Ok(())
        }
    };
    assert!(matches!(
        adapter_of(&anchor, path, &exits_after_the_read),
        Err(KernelObservationError::Exited)
    ));
    assert_eq!(calls.get(), 2);
    let mut child = short_lived()?;
    let pid = child.id();
    let pidfd = pidfd_open(
        Pid::from_raw(i32::try_from(pid)?).ok_or("pid")?,
        PidfdFlags::empty(),
    )?;
    exited(&pidfd)?;
    // Not reaped yet: its procdir still exists, but it is not alive, and
    // it has no executable any more.
    let process = MainProcess::open(pid)?;
    assert!(matches!(
        process.adapter(path),
        Err(KernelObservationError::Exited)
    ));
    assert!(matches!(
        process.executable(),
        Err(KernelObservationError::Executable)
    ));
    child.wait()?;
    Ok(())
}
