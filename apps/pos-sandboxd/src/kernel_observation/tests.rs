use std::{
    os::fd::AsFd,
    os::unix::fs::MetadataExt,
    process::{Child, Command, Stdio},
};

use rustix::fs::{statat, CWD};

use super::*;
use crate::test_fixtures::{cgroup_listing, TestResult};

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
    let observed = observe_unit(&this_unit(), &context(&cgroup, false)?, &provider)?;
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
    let again = observe_unit(&this_unit(), &context(&cgroup, false)?, &provider)?;
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
    let outcome = crate::ReleaseOutcome::new(None, Some(observed), None);
    assert!(outcome.work().is_some());
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
            &foreign_provider()?
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
            &foreign_provider()?
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
        observe_unit(&this_unit(), &context(&other, false)?, &foreign_provider()?).err(),
        Some(KernelObservationError::NotInCgroup)
    );
    Ok(())
}

#[test]
fn a_unit_in_the_providers_namespaces_is_refused() -> TestResult {
    let (_directory, cgroup) = cgroup_listing(own_pid())?;
    let provider = ProviderNamespaces::observe()?;
    assert_eq!(
        observe_unit(&this_unit(), &context(&cgroup, false)?, &provider).err(),
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
        observe_unit(&unreadable, &context, &provider).err(),
        Some(KernelObservationError::Identity)
    );
    let reads = std::cell::Cell::new(0_u8);
    let drifting = || {
        reads.set(reads.get().wrapping_add(1));
        Ok::<_, KernelObservationError>((own_pid(), [reads.get(); 16]))
    };
    assert_eq!(
        observe_unit(&drifting, &context, &provider).err(),
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
        observe_unit(&failing_again, &context, &provider).err(),
        Some(KernelObservationError::Identity)
    );
    let no_main = || Ok::<_, KernelObservationError>((0, INVOCATION));
    assert_eq!(
        observe_unit(&no_main, &context, &provider).err(),
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
        observe_unit(&this_unit(), &context, &foreign_provider()?).err(),
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
