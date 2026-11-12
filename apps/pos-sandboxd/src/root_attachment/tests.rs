use std::{
    collections::VecDeque,
    error::Error,
    fs,
    io::{IoSlice, IoSliceMut, Write},
    mem::MaybeUninit,
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream as StdUnixStream},
        },
    },
    path::Path,
    process::Command,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
    thread,
};

use pos_reference::provider_admission::{test_support::StagedInstallation, ProviderImageSnapshot};
use rustix::net::{
    recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};
use serde_json::json;

use super::*;
use super::{
    cmdline::vetoes_userspace_verity,
    observe::{
        has_mount_id, loop_of, mount_entry, BlockIdentity, ExecutableObservation, LoopDevice,
        Mapper, MountEntry, Node, Slave, ATTACH_BY_DESCRIPTOR, BACKING_OPEN, STATX_REQUEST,
    },
    verify::Extent,
};
use crate::{
    PlannedAttemptIntent, StagingLedger, StagingLimits, SystemdAttemptRegistry, ATTEMPT_ROOT_OPEN,
    ATTEMPT_ROOT_RESOLVE,
};

type BoxError = Box<dyn Error + Send + Sync>;
type TestResult = Result<(), BoxError>;
type AbsenceProbe = (std::time::Duration, Result<bool, ImageActivationError>);

/// The image directory the fake kernel's provider loops are backed from.
const FIXTURE_IMAGES: &str = "/fixture/images";

mod absence;
mod generations;
mod intent;
mod recovered;
mod release;

/// Retained value facts for the registry owner's impossible-state fault tests.
/// This creates no production constructor or lifecycle authority.
///
/// # Errors
/// Returns the existing fake attachment fixture's construction error.
pub fn recorded_identity(
    directory: &PreparedAttemptDirectory,
) -> Result<RootResourceIdentity, String> {
    attached_root(directory)
        .map(|(_, root)| root.resource_identity())
        .map_err(|error| error.to_string())
}

/// Released-root evidence for the single activation of `directory`.
///
/// It comes from the existing fake attachment and release fixtures. The
/// activation is recorded first, as the mountfsd request would; this grants
/// no other authority.
///
/// # Errors
/// Returns the attachment or release fixture's error.
pub async fn released_root(
    directory: &PreparedAttemptDirectory,
) -> Result<ReleasedAttemptRoot, String> {
    directory.begin_activation();
    let (kernel, root) = attached_root(directory).map_err(|error| error.to_string())?;
    let released = release_owned(root, &kernel, directory).await;
    released.map_err(|error| error.to_string())
}

/// One attached fixture root of `directory` with its fake kernel.
///
/// It is released through the lifecycle controller's root port. The
/// activation is recorded first, as the mountfsd request would.
pub struct FakeRootRelease {
    kernel: FakeKernel,
    root: VerifiedRootMount,
}

/// Detach the fake root and observe its fake devices, for the lifecycle
/// controller's root port.
///
/// # Errors
/// Returns the release's error.
pub async fn release_fake_root(
    fake: FakeRootRelease,
    directory: &PreparedAttemptDirectory,
    deadline: tokio::time::Instant,
) -> Result<ReleasedAttemptRoot, ImageActivationError> {
    let FakeRootRelease { kernel, root } = fake;
    let released = super::release::Release::new(root, directory, deadline)
        .finish(&kernel)
        .await;
    released
}

/// A fake root release; unless `absent`, the device-absence probe fails.
///
/// # Errors
/// Returns the attachment fixture's error.
pub fn fake_root_release(
    directory: &PreparedAttemptDirectory,
    absent: bool,
) -> Result<FakeRootRelease, String> {
    directory.begin_activation();
    let (kernel, root) = attached_root(directory).map_err(|error| error.to_string())?;
    let probes = [(
        std::time::Duration::ZERO,
        Err(ImageActivationError::ResourceAbsenceUnverified),
    )];
    kernel
        .absence
        .lock()
        .map_err(|_| "poisoned fixture")?
        .extend(probes.into_iter().filter(|_| !absent));
    Ok(FakeRootRelease { kernel, root })
}

/// One attached fixture root of `directory`, for the host to contradict.
///
/// The activation is recorded first.
///
/// # Errors
/// Returns the attachment fixture's error.
pub fn attached_fixture_root(
    directory: &PreparedAttemptDirectory,
) -> Result<VerifiedRootMount, String> {
    directory.begin_activation();
    attached_root(directory)
        .map(|(_kernel, root)| root)
        .map_err(|error| error.to_string())
}

/// Restart detachment of recorded roots over fake kernels.
///
/// Each kernel reads back the fixture provider root of its entry's attempt.
/// That root is mounted only on the one `mounted` attempt; every other root
/// is unmounted.
pub struct FakeRecoveredRoots {
    mounted: [u8; 16],
    detached: Mutex<Vec<([u8; 16], usize)>>,
}

impl FakeRecoveredRoots {
    /// Fake kernels with the fixture provider root mounted on `attempt_id`.
    #[must_use]
    pub const fn mounted_on(attempt_id: [u8; 16]) -> Self {
        Self {
            mounted: attempt_id,
            detached: Mutex::new(Vec::new()),
        }
    }

    /// Detach `entry`'s root through restart detachment over a fake kernel,
    /// recording how many detaches that kernel saw.
    ///
    /// # Errors
    /// Returns the detachment's error, or a fixture failure as
    /// [`ImageActivationError::Transport`].
    pub(crate) async fn detach(
        &self,
        entry: crate::RecordedRootEntry,
        deadline: tokio::time::Instant,
    ) -> Result<(), ImageActivationError> {
        let attempt_id = entry.intent.planned().attempt_id();
        let mut observed = matching(&expected(
            entry.intent.planned().unit_name().attempt_component(),
        ));
        if attempt_id != self.mounted {
            // An unmounted root is on the attempt directory's own mount.
            observed.parent_mount_id = observed.mount.map(|mount| mount.mount_id);
        }
        let mount_path = tempfile::NamedTempFile::new()
            .map_err(|_| ImageActivationError::Transport)?
            .into_temp_path();
        let kernel = FakeKernel {
            mount_path: Some(mount_path),
            ..FakeKernel::accepting(observed)
        };
        let detached =
            super::recovered::detach_with(&kernel, entry, Path::new(FIXTURE_IMAGES), deadline)
                .await;
        self.detached
            .lock()
            .map_err(|_| ImageActivationError::Transport)?
            .push((attempt_id, kernel.detached()));
        detached
    }

    /// Each detached entry's attempt and its kernel's detach count, in
    /// attempt order.
    ///
    /// # Errors
    /// Returns a poisoned fixture lock.
    pub fn detached(&self) -> Result<Vec<([u8; 16], usize)>, String> {
        let mut detached = self
            .detached
            .lock()
            .map_err(|_| "poisoned fixture".to_owned())?
            .clone();
        detached.sort_unstable();
        Ok(detached)
    }
}

#[tokio::test]
async fn recorded_generations_are_absent_only_when_neither_device_remains() -> TestResult {
    let host = tempfile::tempdir()?;
    let block = host.path().join("sys/dev/block");
    fs::create_dir_all(&block)?;
    let kernel = HostKernel::at(&host.path().join("proc"), &host.path().join("sys"));
    let recorded = [((253, 3), 102), ((7, 7), 101)];
    assert_eq!(generations_absent(&kernel, recorded).await, Ok(true));
    // The loop is still present with its recorded generation, then with an
    // older, contradictory one.
    fs::create_dir(block.join("7:7"))?;
    fs::write(block.join("7:7/dev"), "7:7\n")?;
    for (diskseq, expected) in [
        ("101\n", Ok(false)),
        (
            "100\n",
            Err(ImageActivationError::ResourceAbsenceUnverified),
        ),
    ] {
        fs::write(block.join("7:7/diskseq"), diskseq)?;
        assert_eq!(generations_absent(&kernel, recorded).await, expected);
    }
    // A zero sequence is never a recorded generation.
    assert_eq!(
        generations_absent(&kernel, [((253, 3), 102), ((7, 7), 0)]).await,
        Err(ImageActivationError::ResourceAbsenceUnverified)
    );
    // The real host has no device under the largest major and minor numbers.
    assert_eq!(
        RootResourceIdentity::recorded_generations_absent([
            ((4095, 1_048_575), 1),
            ((4095, 1_048_574), 1)
        ])
        .await,
        Ok(true)
    );
    // The production entry refuses a zero sequence.
    assert_eq!(
        RootResourceIdentity::recorded_generations_absent([
            ((4095, 1_048_575), 1),
            ((4095, 1_048_574), 0)
        ])
        .await,
        Err(ImageActivationError::ResourceAbsenceUnverified)
    );
    Ok(())
}

/// One fake `/sys/block/<name>` entry, with a `loop` directory when `bound`
/// and a backing file when `backing` is given.
fn fake_block(block: &Path, name: &str, bound: bool, backing: Option<&str>) -> TestResult {
    let directory = block.join(name).join(if bound { "loop" } else { "" });
    fs::create_dir_all(&directory)?;
    if let Some(text) = backing {
        fs::write(directory.join("backing_file"), text)?;
    }
    Ok(())
}

#[tokio::test]
async fn only_a_loop_over_a_provider_image_or_an_unreadable_loop_refuses() -> TestResult {
    use std::os::unix::ffi::OsStrExt;

    let host = tempfile::tempdir()?;
    let root = host.path();
    let block = root.join("sys/block");
    let kernel = HostKernel::at(&root.join("proc"), &root.join("sys"));
    // The image directory is reached through a symlinked root, as it would
    // be through a symlinked or bind-mounted parent.
    for directory in ["real/images", "real/images-other"] {
        fs::create_dir_all(root.join(directory))?;
        fs::write(root.join(directory).join("ab"), b"image")?;
    }
    std::os::unix::fs::symlink("real", root.join("link"))?;
    std::os::unix::fs::symlink("real", root.join("bind"))?;
    let images = root.join("link/images");
    let (lexical, canonical, bound) = (
        images.display().to_string(),
        root.join("real/images").display().to_string(),
        root.join("bind/images").display().to_string(),
    );
    // No block class to list.
    assert_eq!(kernel.provider_loops_absent(&images), None);
    // Unbound loops, other disks, non-loop or non-UTF-8 names and an
    // unrelated backing file are ignored.
    fake_block(&block, "loop0", false, None)?;
    fake_block(&block, "sda", true, Some(&format!("{lexical}/ab\n")))?;
    fake_block(&block, "loopx", true, None)?;
    fs::create_dir(block.join(std::ffi::OsStr::from_bytes(b"loop\xff")))?;
    fake_block(&block, "loop1", true, Some("/srv/other.img\n"))?;
    fake_block(&block, "loop2", true, Some("/srv/other.img\n"))?;
    // An image directory that cannot be resolved refuses.
    assert_eq!(kernel.provider_loops_absent(&root.join("missing")), None);
    let real = root.join("real").display().to_string();
    for (printed, absent) in [
        // Each rule alone: beneath the fixed path, beneath the canonical path
        // (both one level down, so the parent is not the image directory), or
        // a parent with the image directory's identity. Deleted images still
        // match.
        (format!("{lexical}/sub/ab"), false),
        (format!("{canonical}/sub/ab"), false),
        (format!("{bound}/ab"), false),
        (format!("{lexical}/sub/gone (deleted)"), false),
        (format!("{bound}/gone (deleted)"), false),
        // A prefix in the middle, a sibling directory and unrelated files.
        (format!("/srv{canonical}/ab"), true),
        (format!("{real}/images-other/ab"), true),
        ("/srv/gone.img (deleted)".to_owned(), true),
        ("/srv/other.img".to_owned(), true),
    ] {
        fs::write(
            block.join("loop2/loop/backing_file"),
            format!("{printed}\n"),
        )?;
        assert_eq!(
            kernel.provider_loops_absent(&images),
            Some(absent),
            "{printed}"
        );
    }
    // An unobservable `loop` entry, then an empty and a missing backing file.
    fs::write(block.join("loop3"), b"not a device directory")?;
    assert_eq!(kernel.provider_loops_absent(&images), None);
    fs::remove_file(block.join("loop3"))?;
    fs::write(block.join("loop2/loop/backing_file"), "\n")?;
    assert_eq!(kernel.provider_loops_absent(&images), None);
    fs::remove_file(block.join("loop2/loop/backing_file"))?;
    assert_eq!(kernel.provider_loops_absent(&images), None);
    // The production entry sweeps the real host, whose installation and
    // loop devices vary. Without an installed image directory it refuses.
    let swept = RootResourceIdentity::provider_loops_absent().await;
    let installed = Path::new(pos_reference::selector::installation::SANDBOX_ARTIFACT_ROOT)
        .join("images")
        .exists();
    assert!(installed || swept == Err(ImageActivationError::ResourceAbsenceUnverified));
    Ok(())
}

fn cleanup_deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + std::time::Duration::from_secs(1)
}

fn attached_root(
    directory: &PreparedAttemptDirectory,
) -> Result<(FakeKernel, VerifiedRootMount), BoxError> {
    let expected = expected(&component(directory));
    let (mount, mount_path) = tempfile::NamedTempFile::new()?.into_parts();
    let kernel = FakeKernel {
        mount_path: Some(mount_path),
        ..FakeKernel::accepting(matching(&expected))
    };
    let mount = QuarantinedRootMount::from_descriptor(mount.into());
    let root = attach_and_verify(&kernel, directory, &expected, mount, || Ok(()))?;
    Ok((kernel, root))
}

async fn detach_owned(
    root: VerifiedRootMount,
    kernel: &impl AttachmentKernel,
    directory: &PreparedAttemptDirectory,
) -> Result<(), ImageActivationError> {
    release_owned(root, kernel, directory).await.map(drop)
}

async fn release_owned(
    root: VerifiedRootMount,
    kernel: &impl AttachmentKernel,
    directory: &PreparedAttemptDirectory,
) -> Result<ReleasedAttemptRoot, ImageActivationError> {
    super::release::Release::new(root, directory, cleanup_deadline())
        .finish(kernel)
        .await
}

fn block_generation(device: (u32, u32), diskseq: u64) -> Option<BlockIdentity> {
    std::num::NonZeroU64::new(diskseq).map(|diskseq| BlockIdentity { device, diskseq })
}

/// Bound every participant in blocking filesystem fixtures, including readers.
/// `true` means the parent completed its child; `false` runs the child body.
fn bounded_fixture_child(variable: &str, full_test: &str) -> Result<bool, BoxError> {
    use std::time::{Duration, Instant};

    if std::env::var_os(variable).is_some() {
        return Ok(false);
    }
    let (_, test) = full_test.split_once("::").ok_or("test module path")?;
    let mut child = Command::new(std::env::current_exe()?)
        .args(["--exact", test, "--nocapture"])
        .env(variable, "1")
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let error: BoxError = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return status
                    .success()
                    .then_some(true)
                    .ok_or_else(|| format!("filesystem fixture child failed: {status}").into());
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(1)),
            Ok(None) => break "filesystem fixture child exceeded its deadline".into(),
            Err(error) => break error.into(),
        }
    };
    child.kill()?;
    child.wait()?;
    Err(error)
}

/// Rendezvous with an already-blocked fixture reader without hanging a writer.
fn open_fifo_writer(barrier: &Path) -> Result<File, BoxError> {
    use rustix::fs::{open, Mode, OFlags};
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match open(
            barrier,
            OFlags::WRONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => return Ok(File::from(descriptor)),
            Err(error) if error == rustix::io::Errno::NXIO && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

const PRIVILEGED_COMPOSITION_TEST: &str = "PIGLOROS_PRIVILEGED_COMPOSITION_TEST";
const VETO: &str = "systemd.allow_userspace_verity=0";

// ---------------------------------------------------------------------------
// Fixtures

fn expected(component: &str) -> Expected {
    Expected {
        root_directory: ActivatedRootDirectory::for_attempt(component),
        root: Extent {
            start: 1_048_576,
            length: 8_388_608,
        },
        verity: Extent {
            start: 9_437_184,
            length: 1_048_576,
        },
        signature: Extent {
            start: 10_485_760,
            length: 16_384,
        },
        held: crate::FIXTURE_IMAGE,
        executable_path: "/usr/bin/adapter".to_owned(),
        executable_digest: [11; 32],
    }
}

fn slave(expected: &Expected, extent: Extent) -> Slave {
    Slave {
        loop_name: Some("loop7".to_owned()),
        start: Some(extent.start / 512),
        size: Some(extent.length / 512),
        loop_device: Some(LoopDevice {
            identity: block_generation((7, 7), 101),
            backing: Some(expected.held),
            offset: Some(0),
            size_limit: Some(0),
            autoclear: Some(1),
            read_only: Some(1),
            partitions: Some(
                [expected.root, expected.verity, expected.signature]
                    .iter()
                    .map(|extent| Some((extent.start / 512, extent.length / 512)))
                    .collect(),
            ),
        }),
    }
}

/// The readback of exactly the admitted root at the expected attempt path.
fn matching(expected: &Expected) -> Observations {
    let node = Node {
        mount_id: 41,
        device: (253, 3),
        inode: 1,
    };
    Observations {
        mount: Some(node),
        path: Some(node),
        parent_mount_id: Some(30),
        filesystem_magic: Some(0xE0F5_E1E2),
        read_only: Some(true),
        entry: Some(MountEntry {
            mount_id: 41,
            parent_id: 30,
            device: (253, 3),
            root: "/".to_owned(),
            mount_point: expected.root_directory.as_str().to_owned(),
            options: "ro,nosuid,nodev,relatime".to_owned(),
            optional: Vec::new(),
            filesystem: "erofs".to_owned(),
            super_options: "ro,user_xattr,acl".to_owned(),
        }),
        mapper: Some(Mapper {
            identity: block_generation((253, 3), 102),
            uuid: Some("CRYPT-VERITY-5f0e5a1c-root".to_owned()),
            read_only: Some(1),
            slaves: Some(vec![
                slave(expected, expected.root),
                slave(expected, expected.verity),
            ]),
        }),
        executable: Some(ExecutableObservation {
            node: Node {
                mount_id: 41,
                device: (253, 3),
                inode: 77,
            },
            blake3: expected.executable_digest,
        }),
    }
}

fn edit_entry(observed: &mut Observations, edit: impl FnOnce(&mut MountEntry)) {
    if let Some(entry) = observed.entry.as_mut() {
        edit(entry);
    }
}

fn edit_mapper(observed: &mut Observations, edit: impl FnOnce(&mut Mapper)) {
    if let Some(mapper) = observed.mapper.as_mut() {
        edit(mapper);
    }
}

fn edit_slaves(observed: &mut Observations, edit: impl FnOnce(&mut Vec<Slave>)) {
    edit_mapper(observed, |mapper| {
        if let Some(slaves) = mapper.slaves.as_mut() {
            edit(slaves);
        }
    });
}

fn edit_loop(observed: &mut Observations, edit: impl FnOnce(&mut LoopDevice)) {
    edit_slaves(observed, |slaves| {
        if let Some(device) = slaves
            .first_mut()
            .and_then(|slave| slave.loop_device.as_mut())
        {
            edit(device);
        }
    });
}

/// A prepared attempt directory below a private temporary runtime tree.
struct PreparedTree {
    runtime: tempfile::TempDir,
    prepared: PreparedAttemptDirectory,
    registry: SystemdAttemptRegistry,
}

fn prepared_tree() -> Result<PreparedTree, BoxError> {
    let runtime = tempfile::tempdir()?;
    fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))?;
    for directory in ["registry", "attempts"] {
        let path = runtime.path().join(directory);
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    }
    let parent = fs::File::open(runtime.path())?;
    let owner = parent.metadata()?.uid();
    let registry = SystemdAttemptRegistry::from_runtime_directory(&parent, owner)?;
    let prepared = registry
        .commit_planned(&PlannedAttemptIntent::new([7; 16], [9; 32])?)?
        .prepare_fixture_directory()?;
    Ok(PreparedTree {
        runtime,
        prepared,
        registry,
    })
}

fn component(prepared: &PreparedAttemptDirectory) -> String {
    prepared.intent().unit_name().attempt_component().to_owned()
}

/// The fake clock stays at the original deadline after its timely checks.
#[derive(Clone, Copy)]
struct ClockExpiry {
    timely_checks: usize,
    deadline: tokio::time::Instant,
}

/// A descriptor-aware fake kernel that records every detach and readback.
struct FakeKernel {
    vetoes: bool,
    attach: Result<(), ImageActivationError>,
    private: Result<(), ImageActivationError>,
    observations: Observations,
    provider_image: bool,
    submounts: Option<bool>,
    detach: Result<(), ImageActivationError>,
    detached: AtomicUsize,
    readbacks: AtomicUsize,
    clock_checks: AtomicUsize,
    clock_expiry: Option<ClockExpiry>,
    absence: Mutex<VecDeque<AbsenceProbe>>,
    probes: Mutex<Vec<[BlockIdentity; 2]>>,
    // Keep the file linked without retaining another descriptor. Its pathname
    // and inode cannot be recycled while the closure witness is in use.
    mount_path: Option<tempfile::TempPath>,
    detached_mount: Mutex<Option<(std::path::PathBuf, std::path::PathBuf)>>,
}

impl FakeKernel {
    fn accepting(observations: Observations) -> Self {
        Self {
            vetoes: true,
            attach: Ok(()),
            private: Ok(()),
            observations,
            provider_image: true,
            submounts: Some(false),
            detach: Ok(()),
            detached: AtomicUsize::new(0),
            readbacks: AtomicUsize::new(0),
            clock_checks: AtomicUsize::new(0),
            clock_expiry: None,
            absence: Mutex::new(VecDeque::new()),
            probes: Mutex::new(Vec::new()),
            mount_path: None,
            detached_mount: Mutex::new(None),
        }
    }

    fn detached(&self) -> usize {
        self.detached.load(Ordering::SeqCst)
    }
}

impl AttachmentKernel for FakeKernel {
    fn now(&self) -> tokio::time::Instant {
        match self.clock_expiry {
            Some(expiry)
                if self.clock_checks.fetch_add(1, Ordering::SeqCst) >= expiry.timely_checks =>
            {
                expiry.deadline
            }
            _ => tokio::time::Instant::now(),
        }
    }

    fn vetoes_userspace_verity(&self) -> bool {
        self.vetoes
    }

    fn attach(&self, _: BorrowedFd<'_>, _: &File) -> Result<(), ImageActivationError> {
        self.attach
    }

    fn make_private(&self, _: BorrowedFd<'_>) -> Result<(), ImageActivationError> {
        self.private
    }

    fn observe(&self, _: BorrowedFd<'_>, _: &File, _: &File, _: &str) -> Observations {
        self.readbacks.fetch_add(1, Ordering::SeqCst);
        self.observations.clone()
    }

    /// Only the read-back loop over the fixture image directory can be a
    /// provider loop.
    fn provider_image(&self, loop_name: &str, images: &Path) -> bool {
        let read_back = self
            .observations
            .mapper
            .as_ref()
            .and_then(|mapper| mapper.slaves.as_ref())
            .and_then(|slaves| slaves.first())
            .and_then(|slave| slave.loop_name.as_deref());
        self.provider_image && read_back == Some(loop_name) && images == Path::new(FIXTURE_IMAGES)
    }

    /// Any mount other than the read-back one counts as having submounts.
    fn has_submounts(&self, mount_id: u64) -> Option<bool> {
        if self.observations.mount.map(|mount| mount.mount_id) == Some(mount_id) {
            self.submounts
        } else {
            Some(true)
        }
    }

    fn detach(&self, mount: BorrowedFd<'_>) -> Result<(), ImageActivationError> {
        let path = std::path::PathBuf::from(format!("/proc/self/fd/{}", mount.as_raw_fd()));
        let target = fs::read_link(&path).map_err(|_| ImageActivationError::EvidenceMismatch)?;
        *self
            .detached_mount
            .lock()
            .map_err(|_| ImageActivationError::EvidenceMismatch)? = Some((path, target));
        self.detached.fetch_add(1, Ordering::SeqCst);
        self.detach
    }

    async fn devices_absent(
        &self,
        devices: [BlockIdentity; 2],
    ) -> Result<bool, ImageActivationError> {
        let rejected = ImageActivationError::ResourceAbsenceUnverified;
        assert!(
            self.mount_path.is_some(),
            "retain the owned fixture pathname"
        );
        {
            let detached = self.detached_mount.lock().map_err(|_| rejected)?;
            assert!(detached.is_some(), "detach must precede absence probes");
            if let Some((path, target)) = &*detached {
                let current = match fs::read_link(path) {
                    Ok(current) => Some(current),
                    Err(error) => {
                        assert_eq!(
                            error.kind(),
                            std::io::ErrorKind::NotFound,
                            "unverified mount descriptor lookup"
                        );
                        None
                    }
                };
                assert_ne!(
                    current.as_ref(),
                    Some(target),
                    "mount FD must close before probing"
                );
            }
        }
        self.probes.lock().map_err(|_| rejected)?.push(devices);
        let (delay, result) = self
            .absence
            .lock()
            .map_err(|_| rejected)?
            .pop_front()
            .unwrap_or((std::time::Duration::ZERO, Ok(true)));
        tokio::time::sleep(delay).await;
        result
    }
}

fn file_mount() -> Result<QuarantinedRootMount, BoxError> {
    Ok(QuarantinedRootMount::from_descriptor(OwnedFd::from(
        tempfile::tempfile()?,
    )))
}

// ---------------------------------------------------------------------------
// Kernel command line (owner decision Q7.8, B3)

#[test]
fn only_one_plain_veto_word_disables_userspace_verity() {
    for accepted in [
        VETO.to_owned(),
        format!("BOOT_IMAGE=/vmlinuz root=/dev/vda1 {VETO} quiet\n"),
        format!("quiet\t{VETO}\r\n"),
        format!("{VETO}  foo.allow_userspace_verity=1 systemd.allow_userspace_verityx=1"),
        // Same length as the key, different text: not the option.
        format!("{VETO} systemd.allow_userspace_verify=1 systemd.allow-userspace-verify"),
    ] {
        assert!(vetoes_userspace_verity(accepted.as_bytes()), "{accepted:?}");
    }
    for rejected in [
        String::new(),
        "BOOT_IMAGE=/vmlinuz quiet".to_owned(),
        "systemd.allow_userspace_verity=1".to_owned(),
        "systemd.allow_userspace_verity=no".to_owned(),
        "systemd.allow_userspace_verity=00".to_owned(),
        "systemd.allow_userspace_verity".to_owned(),
        "systemd.allow-userspace-verity=0".to_owned(),
        format!("{VETO} {VETO}"),
        format!("{VETO} systemd.allow_userspace_verity=1"),
        format!("{VETO} systemd.allow-userspace_verity=1"),
        format!("{VETO} rd.systemd.allow_userspace_verity=1"),
        format!("{VETO} rd.systemd.allow-userspace-verity"),
        format!("\"{VETO}\""),
        format!("x=\"a {VETO} b\""),
        format!("x='a' {VETO}"),
        format!("{VETO} x=\\"),
        format!("{VETO} caf\u{e9}"),
        format!("{VETO}\u{c}quiet"),
        format!("{VETO}\u{0}"),
    ] {
        assert!(
            !vetoes_userspace_verity(rejected.as_bytes()),
            "{rejected:?}"
        );
    }
}

#[test]
fn the_host_kernel_reads_its_own_command_line() -> TestResult {
    let proc = tempfile::tempdir()?;
    let kernel = HostKernel::at(proc.path(), proc.path());
    assert!(!kernel.vetoes_userspace_verity());
    fs::write(proc.path().join("cmdline"), format!("quiet {VETO}\n"))?;
    assert!(kernel.vetoes_userspace_verity());
    fs::write(proc.path().join("cmdline"), "quiet\n")?;
    assert!(!kernel.vetoes_userspace_verity());
    Ok(())
}

// ---------------------------------------------------------------------------
// Readback parsing

#[test]
fn mountinfo_yields_exactly_one_entry_for_the_mount() {
    let line = "41 30 253:3 / /run/pigloros/sandbox/attempts/a/root ro,nosuid shared:7 master:2 - erofs /dev/mapper/root ro,user_xattr";
    let other = "30 1 0:25 / /run rw,nosuid shared:1 - tmpfs tmpfs rw,mode=755";
    let text = format!("{other}\n{line}\n");
    assert_eq!(
        mount_entry(&text, 41),
        Some(MountEntry {
            mount_id: 41,
            parent_id: 30,
            device: (253, 3),
            root: "/".to_owned(),
            mount_point: "/run/pigloros/sandbox/attempts/a/root".to_owned(),
            options: "ro,nosuid".to_owned(),
            optional: vec!["shared:7".to_owned(), "master:2".to_owned()],
            filesystem: "erofs".to_owned(),
            super_options: "ro,user_xattr".to_owned(),
        })
    );
    assert_eq!(mount_entry(&text, 30).map(|entry| entry.parent_id), Some(1));
    assert_eq!(mount_entry(&text, 99), None);
    assert_eq!(mount_entry(&format!("{line}\n{line}\n"), 41), None);
    for malformed in [
        "41 30 253:3 / /mnt ro erofs /dev/x ro",
        "x 30 253:3 / /mnt ro - erofs /dev/x ro",
        "41 x 253:3 / /mnt ro - erofs /dev/x ro",
        "41 30 x:3 / /mnt ro - erofs /dev/x ro",
        "41 30 253:x / /mnt ro - erofs /dev/x ro",
        "41 30 2533 / /mnt ro - erofs /dev/x ro",
        "41 30 253:3 / /mnt - erofs /dev/x ro",
        "41 30 253:3 / /mnt ro - erofs /dev/x",
    ] {
        assert_eq!(mount_entry(malformed, 41), None, "{malformed}");
    }
}

#[test]
fn only_loop_partition_names_name_a_loop_device() {
    assert_eq!(loop_of("loop7p1").as_deref(), Some("loop7"));
    assert_eq!(loop_of("loop12p10").as_deref(), Some("loop12"));
    for name in [
        "loop7",
        "loopp1",
        "loop7p",
        "loopxp1",
        "loop7px",
        "sda1",
        "nvme0n1p1",
    ] {
        assert_eq!(loop_of(name), None, "{name}");
    }
}

// ---------------------------------------------------------------------------
// Readback verification (ADR-087 §2 step 6)

#[test]
fn exactly_the_admitted_private_read_only_erofs_root_is_accepted() {
    let expected = expected("0123456789abcdef0123456789abcdef");
    let mut observed = matching(&expected);
    let identity = expected.verify(&observed);
    assert_eq!(
        identity.as_ref().map(|identity| identity.mount.mount_id),
        Ok(41)
    );
    edit_slaves(&mut observed, |slaves| slaves.swap(0, 1));
    assert_eq!(expected.verify(&observed), identity);
}

/// A named edit of the matching readback.
type Mutation = (&'static str, fn(&mut Observations));

/// One named difference per accepted mount and filesystem fact.
fn mount_mutations() -> Vec<Mutation> {
    vec![
        ("no mount", |o| o.mount = None),
        ("no path", |o| o.path = None),
        ("substituted path", |o| {
            o.path = Some(Node {
                mount_id: 42,
                device: (253, 3),
                inode: 1,
            });
        }),
        ("no executable", |o| o.executable = None),
        ("substituted executable", |o| {
            if let Some(executable) = o.executable.as_mut() {
                executable.blake3 = [12; 32];
            }
        }),
        ("executable on another mount", |o| {
            if let Some(executable) = o.executable.as_mut() {
                executable.node.mount_id = 42;
            }
        }),
        ("no parent", |o| o.parent_mount_id = None),
        ("foreign parent", |o| o.parent_mount_id = Some(31)),
        ("ext4 magic", |o| o.filesystem_magic = Some(0xEF53)),
        ("writable", |o| o.read_only = Some(false)),
        ("unknown writability", |o| o.read_only = None),
        ("no mountinfo entry", |o| o.entry = None),
        ("wrong device", |o| edit_entry(o, |e| e.device = (253, 4))),
        ("wrong root", |o| {
            edit_entry(o, |e| e.root = "/usr".to_owned());
        }),
        ("replaced path", |o| {
            edit_entry(o, |e| {
                e.mount_point = "/run/pigloros/sandbox/attempts/other/root".to_owned();
            });
        }),
        ("rw mount", |o| {
            edit_entry(o, |e| e.options = "rw,relatime".to_owned());
        }),
        ("rw superblock", |o| {
            edit_entry(o, |e| e.super_options = "rw".to_owned());
        }),
        ("not erofs", |o| {
            edit_entry(o, |e| e.filesystem = "squashfs".to_owned());
        }),
        ("shared propagation", |o| {
            edit_entry(o, |e| e.optional = vec!["shared:7".to_owned()]);
        }),
        ("slave propagation", |o| {
            edit_entry(o, |e| e.optional = vec!["master:2".to_owned()]);
        }),
    ]
}

/// One named difference per accepted device-mapper and loop fact.
fn generation_mutations() -> Vec<Mutation> {
    vec![
        ("no mapper generation", |o| {
            edit_mapper(o, |m| m.identity = None);
        }),
        ("mapper is not the mounted device", |o| {
            edit_mapper(o, |m| m.identity = block_generation((253, 4), 102));
        }),
        ("no first loop generation", |o| {
            edit_loop(o, |d| d.identity = None);
        }),
        ("no second loop generation", |o| {
            edit_slaves(o, |s| {
                if let Some(device) = s[1].loop_device.as_mut() {
                    device.identity = None;
                }
            });
        }),
        ("contradictory loop device numbers", |o| {
            edit_loop(o, |d| d.identity = block_generation((7, 8), 101));
        }),
        ("contradictory loop generations", |o| {
            edit_loop(o, |d| d.identity = block_generation((7, 7), 103));
        }),
    ]
}

fn device_mutations() -> Vec<Mutation> {
    vec![
        ("no mapper", |o| o.mapper = None),
        ("no dm uuid", |o| edit_mapper(o, |m| m.uuid = None)),
        ("not dm-verity", |o| {
            edit_mapper(o, |m| m.uuid = Some("LVM-abc".to_owned()));
        }),
        ("writable mapper", |o| {
            edit_mapper(o, |m| m.read_only = Some(0));
        }),
        ("no slaves", |o| edit_mapper(o, |m| m.slaves = None)),
        ("one slave", |o| {
            edit_slaves(o, |s| {
                s.pop();
            });
        }),
        ("three slaves", |o| {
            edit_slaves(o, |s| {
                let extra = s[0].clone();
                s.push(extra);
            });
        }),
        ("two loop devices", |o| {
            edit_slaves(o, |s| s[1].loop_name = Some("loop8".to_owned()));
        }),
        ("unnamed loop", |o| {
            edit_slaves(o, |s| {
                for slave in s {
                    slave.loop_name = None;
                }
            });
        }),
        ("wrong root extent", |o| {
            edit_slaves(o, |s| s[0].start = Some(2049));
        }),
        ("same extent twice", |o| {
            edit_slaves(o, |s| s[1] = s[0].clone());
        }),
        ("unknown size", |o| edit_slaves(o, |s| s[0].size = None)),
        ("overflowing start", |o| {
            edit_slaves(o, |s| s[0].start = Some(u64::MAX));
        }),
        ("no loop device", |o| {
            edit_slaves(o, |s| s[0].loop_device = None);
        }),
        ("substituted image", |o| {
            edit_loop(o, |d| d.backing = Some(crate::OTHER_IMAGES[0]));
        }),
        ("unknown backing", |o| edit_loop(o, |d| d.backing = None)),
        ("offset", |o| edit_loop(o, |d| d.offset = Some(512))),
        ("size limit", |o| {
            edit_loop(o, |d| d.size_limit = Some(4096));
        }),
        ("no autoclear", |o| edit_loop(o, |d| d.autoclear = Some(0))),
        ("writable loop", |o| edit_loop(o, |d| d.read_only = Some(0))),
        ("no partition table", |o| {
            edit_loop(o, |d| d.partitions = None);
        }),
        ("extra partition", |o| {
            edit_loop(o, |d| {
                d.partitions.get_or_insert_default().push(Some((1, 1)));
            });
        }),
        ("missing partition", |o| {
            edit_loop(o, |d| {
                d.partitions.get_or_insert_default().pop();
            });
        }),
        ("unknown partition extent", |o| {
            edit_loop(o, |d| d.partitions.get_or_insert_default()[2] = None);
        }),
        ("overflowing partition", |o| {
            edit_loop(o, |d| {
                d.partitions.get_or_insert_default()[2] = Some((u64::MAX, 1));
            });
        }),
    ]
}

/// One named difference from the matching readback per accepted fact.
fn readback_mutations() -> Vec<Mutation> {
    let mut mutations = mount_mutations();
    mutations.extend(device_mutations());
    mutations.extend(generation_mutations());
    mutations
}

#[test]
fn every_readback_difference_is_an_evidence_mismatch() {
    let expected = expected("0123456789abcdef0123456789abcdef");
    let mutations = readback_mutations();
    for (name, mutate) in mutations {
        let mut observed = matching(&expected);
        mutate(&mut observed);
        assert_eq!(
            expected.verify(&observed),
            Err(ImageActivationError::EvidenceMismatch),
            "{name}"
        );
    }
}

// ---------------------------------------------------------------------------
// Host kernel readback through synthetic procfs and sysfs trees

fn write(path: &Path, text: &str) -> TestResult {
    fs::create_dir_all(path.parent().ok_or("no parent")?)?;
    fs::write(path, text)?;
    Ok(())
}

fn write_mapper_fixture(sys: &Path, device: (u32, u32)) -> TestResult {
    let block = sys.join(format!("dev/block/{}:{}", device.0, device.1));
    write(&block.join("dev"), &format!("{}:{}\n", device.0, device.1))?;
    write(&block.join("diskseq"), "102\n")?;
    write(&block.join("dm/uuid"), "CRYPT-VERITY-abc-root\n")?;
    write(&block.join("ro"), "1\n")?;
    for name in ["loop7p1", "loop7p2", "sdz1"] {
        fs::create_dir_all(block.join("slaves").join(name))?;
    }
    Ok(())
}

#[test]
fn the_host_kernel_reads_back_the_mount_loop_and_mapper_by_descriptor() -> TestResult {
    let tree = prepared_tree()?;
    let (attempt, root) = tree.prepared.held_directories();
    let host = tempfile::tempdir()?;
    let (proc, sys) = (host.path().join("proc"), host.path().join("sys"));
    let kernel = HostKernel::at(&proc, &sys);

    // Unreadable procfs and sysfs: every dependent fact is absent.
    let observed = kernel.observe(root.as_fd(), attempt, root, "/usr/bin/adapter");
    let mount = observed.mount.ok_or("statx through the root descriptor")?;
    assert_eq!(observed.path, Some(mount));
    assert_eq!(observed.parent_mount_id, Some(mount.mount_id));
    assert!(observed.filesystem_magic.is_some());
    assert_eq!(observed.read_only, Some(false));
    assert_eq!(observed.entry, None);
    assert_eq!(
        observed.mapper,
        Some(Mapper {
            identity: None,
            uuid: None,
            read_only: None,
            slaves: None,
        })
    );

    let (major, minor) = mount.device;
    write(
        &proc.join("self/mountinfo"),
        &format!(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n{} 1 {major}:{minor} / /attempt ro shared:3 - erofs /dev/dm-3 ro\n",
            mount.mount_id
        ),
    )?;
    write_mapper_fixture(&sys, mount.device)?;
    // As in sysfs, a loop partition is a directory of its disk.
    let partitions = sys.join("class/block");
    let device = partitions.join("loop7");
    write(&device.join("dev"), "7:7\n")?;
    write(&device.join("diskseq"), "101\n")?;
    write(&device.join("loop7p1/start"), "2048\n")?;
    write(&device.join("loop7p1/size"), "16384\n")?;
    std::os::unix::fs::symlink(device.join("loop7p1"), partitions.join("loop7p1"))?;
    let mut image = tempfile::NamedTempFile::new()?;
    image.write_all(b"held image")?;
    let held = image.as_file().metadata()?;
    write(
        &device.join("loop/backing_file"),
        &format!("{}\n", image.path().display()),
    )?;
    write(&device.join("loop/offset"), "0\n")?;
    write(&device.join("loop/sizelimit"), "0\n")?;
    write(&device.join("loop/autoclear"), "1\n")?;
    write(&device.join("ro"), "1\n")?;

    let observed = kernel.observe(root.as_fd(), attempt, root, "/usr/bin/adapter");
    let entry = observed.entry.ok_or("the synthetic mountinfo entry")?;
    assert_eq!(entry.mount_point, "/attempt");
    assert_eq!(entry.optional, vec!["shared:3".to_owned()]);
    let mapper = observed.mapper.ok_or("the synthetic mapper")?;
    assert_eq!(mapper.uuid.as_deref(), Some("CRYPT-VERITY-abc-root"));
    assert_eq!(mapper.read_only, Some(1));
    assert_eq!(mapper.identity, block_generation(mount.device, 102));
    let mut slaves = mapper.slaves.ok_or("the synthetic slaves")?;
    slaves.sort_by_key(|slave| slave.loop_name.clone());
    let loop_device = LoopDevice {
        identity: block_generation((7, 7), 101),
        backing: Some((held.dev(), held.ino())),
        offset: Some(0),
        size_limit: Some(0),
        autoclear: Some(1),
        read_only: Some(1),
        partitions: Some(vec![Some((2048, 16384))]),
    };
    assert_eq!(slaves.len(), 3);
    assert_eq!(
        slaves[0],
        Slave {
            loop_name: None,
            start: None,
            size: None,
            loop_device: None,
        }
    );
    let mut loops: Vec<_> = slaves[1..].iter().map(|slave| slave.start).collect();
    loops.sort_unstable();
    assert_eq!(loops, vec![None, Some(2048)]);
    assert!(slaves[1..]
        .iter()
        .all(|slave| slave.loop_device.as_ref() == Some(&loop_device)));

    // A backing path that no longer names a file is absent, not adopted.
    let missing_device = LoopDevice {
        backing: None,
        ..loop_device
    };
    write(&device.join("loop/backing_file"), "/nonexistent/held\n")?;
    let observed = kernel.observe(root.as_fd(), attempt, root, "/usr/bin/adapter");
    let slaves = observed
        .mapper
        .and_then(|mapper| mapper.slaves)
        .ok_or("the synthetic slaves")?;
    assert!(slaves
        .iter()
        .filter(|slave| slave.loop_name.is_some())
        .all(|slave| slave.loop_device.as_ref() == Some(&missing_device)));
    Ok(())
}

#[test]
fn only_a_statx_mask_with_the_mount_id_bit_has_a_mount_id() {
    let bit = rustix::fs::StatxFlags::MNT_ID.bits();
    assert!(has_mount_id(bit));
    assert!(has_mount_id(
        bit | rustix::fs::StatxFlags::BASIC_STATS.bits()
    ));
    assert!(!has_mount_id(rustix::fs::StatxFlags::BASIC_STATS.bits()));
    assert!(!has_mount_id(0));
}

#[test]
fn propagation_and_detach_act_on_the_descriptor_link() -> TestResult {
    let file = tempfile::tempfile()?;
    let kernel = HostKernel::at(Path::new("/proc"), Path::new("/sys"));
    assert_eq!(
        kernel.descriptor_path(file.as_fd()),
        Path::new("/proc/self/fd").join(std::os::fd::AsRawFd::as_raw_fd(&file).to_string())
    );
    Ok(())
}

#[test]
fn descriptor_bound_flag_sets_are_pinned() {
    use rustix::fs::{OFlags, ResolveFlags, StatxFlags};
    use rustix::mount::MoveMountFlags;
    assert_eq!(
        BACKING_OPEN,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC
    );
    assert_eq!(
        ATTEMPT_ROOT_OPEN,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
    );
    assert_eq!(
        ATTEMPT_ROOT_RESOLVE,
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS
    );
    assert_eq!(
        ATTACH_BY_DESCRIPTOR,
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH
    );
    assert_eq!(STATX_REQUEST, StatxFlags::BASIC_STATS | StatxFlags::MNT_ID);
}

#[test]
fn symlinks_never_lead_to_the_backing_image_or_the_attempt_root() -> TestResult {
    // A loop backing path that is a symlink names the link, not the image.
    let sys = tempfile::tempdir()?;
    let image = tempfile::NamedTempFile::new()?;
    let link = sys.path().join("held-link");
    std::os::unix::fs::symlink(image.path(), &link)?;
    write(
        &sys.path().join("class/block/loop9/loop/backing_file"),
        &format!("{}\n", link.display()),
    )?;
    let kernel = HostKernel::at(sys.path(), sys.path());
    let backing = kernel.loop_device("loop9").backing;
    let link = fs::symlink_metadata(&link)?;
    let target = image.as_file().metadata()?;
    assert_eq!(backing, Some((link.dev(), link.ino())));
    assert_ne!(backing, Some((target.dev(), target.ino())));

    // An attempt root replaced by a symlink is not resolved.
    let tree = prepared_tree()?;
    let (attempt, root) = tree.prepared.held_directories();
    let attempt_path = tree
        .runtime
        .path()
        .join("attempts")
        .join(component(&tree.prepared));
    fs::rename(attempt_path.join("root"), attempt_path.join("real"))?;
    std::os::unix::fs::symlink("real", attempt_path.join("root"))?;
    let observed = kernel.observe(root.as_fd(), attempt, root, "/usr/bin/adapter");
    assert!(observed.mount.is_some());
    assert_eq!(observed.path, None);
    Ok(())
}

#[test]
fn an_unlinked_backing_image_has_no_readable_identity() -> TestResult {
    // The kernel prints an unlinked backing file with " (deleted)" appended.
    // No path then names the image, so its identity is unreadable and a
    // restart refuses to detach the root (fail closed); reading it from the
    // loop device itself would need an ioctl, which needs `unsafe`.
    let sys = tempfile::tempdir()?;
    let image = sys.path().join("held");
    fs::write(&image, b"image")?;
    let identity = fs::metadata(&image)?;
    let backing_file = sys.path().join("class/block/loop9/loop/backing_file");
    write(&backing_file, &format!("{}\n", image.display()))?;
    let kernel = HostKernel::at(sys.path(), sys.path());
    assert_eq!(
        kernel.loop_device("loop9").backing,
        Some((identity.dev(), identity.ino()))
    );
    fs::remove_file(&image)?;
    write(&backing_file, &format!("{} (deleted)\n", image.display()))?;
    assert_eq!(kernel.loop_device("loop9").backing, None);
    Ok(())
}

#[test]
fn host_kernel_operations_on_a_non_mount_fail_closed() -> TestResult {
    let tree = prepared_tree()?;
    let (_, root) = tree.prepared.held_directories();
    let kernel = HostKernel::system();
    let file = tempfile::tempfile()?;
    assert_eq!(
        kernel.attach(file.as_fd(), root),
        Err(ImageActivationError::AttachFailure)
    );
    assert_eq!(
        kernel.make_private(file.as_fd()),
        Err(ImageActivationError::AttachFailure)
    );
    assert_eq!(
        kernel.detach(file.as_fd()),
        Err(ImageActivationError::TeardownFailure)
    );
    tree.prepared.verify_directory()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Orchestration through the attachment port

#[test]
fn a_verified_root_is_returned_only_after_readback_and_re_admission() -> TestResult {
    let tree = prepared_tree()?;
    let expected = expected(&component(&tree.prepared));
    let kernel = FakeKernel::accepting(matching(&expected));
    let mount = file_mount()?;
    let verified = attach_and_verify(&kernel, &tree.prepared, &expected, mount, || Ok(()))?;
    assert_eq!(verified.root_directory(), &expected.root_directory);
    assert_eq!(verified.mount_id(), 41);
    assert!(rustix::fs::fstat(verified.mount()).is_ok());
    assert_eq!(kernel.detached(), 0);
    Ok(())
}

#[test]
fn every_partial_attachment_failure_detaches_or_reports_teardown() -> TestResult {
    let tree = prepared_tree()?;
    let expected = expected(&component(&tree.prepared));
    let mut mismatched = matching(&expected);
    mismatched.filesystem_magic = Some(0xEF53);
    let failure = Err(ImageActivationError::AttachFailure);
    let cases: Vec<(&str, FakeKernel, bool, ImageActivationError, usize)> = vec![
        (
            "attach",
            FakeKernel {
                attach: failure,
                ..FakeKernel::accepting(matching(&expected))
            },
            true,
            ImageActivationError::AttachFailure,
            0,
        ),
        (
            "private",
            FakeKernel {
                private: failure,
                ..FakeKernel::accepting(matching(&expected))
            },
            true,
            ImageActivationError::AttachFailure,
            1,
        ),
        (
            "readback",
            FakeKernel::accepting(mismatched.clone()),
            true,
            ImageActivationError::EvidenceMismatch,
            1,
        ),
        (
            "re-admission",
            FakeKernel::accepting(matching(&expected)),
            false,
            ImageActivationError::EvidenceMismatch,
            1,
        ),
        (
            "teardown",
            FakeKernel {
                detach: Err(ImageActivationError::TeardownFailure),
                ..FakeKernel::accepting(mismatched)
            },
            true,
            ImageActivationError::TeardownFailure,
            1,
        ),
    ];
    for (name, kernel, admitted, error, detached) in cases {
        let outcome = attach_and_verify(&kernel, &tree.prepared, &expected, file_mount()?, || {
            admitted
                .then_some(())
                .ok_or(ImageActivationError::EvidenceMismatch)
        });
        assert_eq!(outcome.err(), Some(error), "{name}");
        assert_eq!(kernel.detached(), detached, "{name}");
    }
    Ok(())
}

#[test]
fn the_host_kernel_hashes_the_executable_through_the_mount_descriptor() -> TestResult {
    let tree = prepared_tree()?;
    let (attempt, root) = tree.prepared.held_directories();
    let base = tree
        .runtime
        .path()
        .join("attempts")
        .join(component(&tree.prepared))
        .join("root");
    let host = tempfile::tempdir()?;
    let kernel = HostKernel::at(&host.path().join("proc"), &host.path().join("sys"));
    let observe = |path: &str| kernel.observe(root.as_fd(), attempt, root, path).executable;

    fs::create_dir_all(base.join("usr/bin"))?;
    fs::write(base.join("usr/bin/adapter"), b"adapter bytes")?;
    let mount = kernel
        .observe(root.as_fd(), attempt, root, "/usr/bin/adapter")
        .mount
        .ok_or("statx through the root descriptor")?;
    let found = observe("/usr/bin/adapter").ok_or("regular executable")?;
    assert_eq!(found.blake3, *blake3::hash(b"adapter bytes").as_bytes());
    assert_eq!(found.node.mount_id, mount.mount_id);
    assert_ne!(found.node.inode, 0);

    // Only a regular file reached without symlinks, magic links or ".." counts.
    std::os::unix::fs::symlink("adapter", base.join("usr/bin/link"))?;
    fs::create_dir(base.join("usr/bin/directory"))?;
    rustix::fs::mknodat(
        root,
        "usr/bin/fifo",
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR,
        0,
    )?;
    fs::write(base.join("../escaped"), b"adapter bytes")?;
    for path in [
        "/usr/bin/missing",
        "/usr/bin/link",
        "/usr/bin/directory",
        "/usr/bin/fifo",
        "/usr/../../escaped",
    ] {
        assert_eq!(observe(path), None, "{path}");
    }
    Ok(())
}

#[test]
fn recheck_mints_a_checked_root_only_for_the_same_authority_and_mount() -> TestResult {
    let tree = prepared_tree()?;
    let activated = expected(&component(&tree.prepared));
    let kernel = FakeKernel::accepting(matching(&activated));
    let verified = attach_and_verify(
        &kernel,
        &tree.prepared,
        &activated,
        file_mount()?,
        || Ok(()),
    )?;
    let checked = recheck(&kernel, &verified, &tree.prepared, Some(&activated), || {
        Ok(())
    })?;
    assert_eq!(checked, activated.root_directory);

    // Authority drift or a floor above the admission refuses.
    for below_floor in [false, true] {
        assert_eq!(
            recheck(
                &kernel,
                &verified,
                &tree.prepared,
                Some(&activated),
                || Err(if below_floor {
                    StagingError::BelowControlFloor
                } else {
                    StagingError::AuthorityChanged
                })
            ),
            Err(ImageActivationError::EvidenceMismatch)
        );
    }

    // Any readback difference refuses.
    for (name, mutate) in readback_mutations() {
        // A failed readback permanently quarantines this registry owner.
        let tree = prepared_tree()?;
        let activated = expected(&component(&tree.prepared));
        let (_, verified) = attached_root(&tree.prepared)?;
        let mut observed = matching(&activated);
        mutate(&mut observed);
        let drifted = FakeKernel::accepting(observed);
        assert_eq!(
            recheck(
                &drifted,
                &verified,
                &tree.prepared,
                Some(&activated),
                || Ok(())
            ),
            Err(ImageActivationError::EvidenceMismatch),
            "{name}"
        );
        assert_eq!(drifted.readbacks.load(Ordering::SeqCst), 1, "{name}");
    }

    // A consistent readback of a different mount ID refuses.
    let tree = prepared_tree()?;
    let activated = expected(&component(&tree.prepared));
    let (_, verified) = attached_root(&tree.prepared)?;
    let mut replaced = matching(&activated);
    let other = Node {
        mount_id: 42,
        device: (253, 3),
        inode: 1,
    };
    replaced.mount = Some(other);
    replaced.path = Some(other);
    edit_entry(&mut replaced, |entry| entry.mount_id = 42);
    if let Some(executable) = replaced.executable.as_mut() {
        executable.node.mount_id = 42;
    }
    assert_eq!(
        activated
            .verify(&replaced)
            .map(|identity| identity.mount.mount_id),
        Ok(42)
    );
    assert_eq!(
        recheck(
            &FakeKernel::accepting(replaced),
            &verified,
            &tree.prepared,
            Some(&activated),
            || Ok(())
        ),
        Err(ImageActivationError::EvidenceMismatch)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The real admission chain in the isolated root container

fn run_isolated(test_name: &str) -> TestResult {
    let runner = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/run-isolated-test.sh");
    let output = Command::new(runner)
        .arg(std::env::current_exe()?)
        .arg(test_name)
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "isolated test {test_name} failed with {}:\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}

fn receive_call(socket: &StdUnixStream) -> TestResult {
    let mut message = Vec::new();
    while message.last() != Some(&0) {
        let mut buffer = [0_u8; 4096];
        let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(4))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let received = recvmsg(
            socket,
            &mut [IoSliceMut::new(&mut buffer)],
            &mut control,
            RecvFlags::CMSG_CLOEXEC,
        )?;
        for ancillary in control.drain() {
            if let RecvAncillaryMessage::ScmRights(incoming) = ancillary {
                drop(incoming.collect::<Vec<_>>());
            }
        }
        if received.bytes == 0 {
            return Err("the call ended before its terminator".into());
        }
        message.extend_from_slice(&buffer[..received.bytes]);
    }
    Ok(())
}

/// A fake root mountfsd answering `calls` calls for the admitted root extent.
fn serve(listener: &UnixListener, root: Extent, calls: usize) -> TestResult {
    for _ in 0..calls {
        let (socket, _) = listener.accept()?;
        receive_call(&socket)?;
        let mut reply = serde_json::to_vec(&json!({"parameters": {
            "partitions": [{
                "designator": "root",
                "writable": false,
                "growFileSystem": false,
                "partitionNumber": 1,
                "architecture": "x86-64",
                "partitionUuid": "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
                "fileSystemType": "erofs",
                "partitionLabel": "root-x86-64",
                "size": root.length,
                "offset": root.start,
                "mountFileDescriptor": 0,
                "mountPoint": ["/"],
            }],
            "singleFileSystem": false,
            "imagePolicy": "root=signed+erofs:=absent",
            "imageSize": 16_777_216,
            "sectorSize": 512,
            "imageName": "pigloros-subject",
            "imageUuid": "a7e6f6d2-61a4-4b52-9f3c-0c3c4b8f7a10",
        }}))?;
        reply.push(0);
        let mount = tempfile::tempfile()?;
        let descriptors = [mount.as_fd()];
        let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !control.push(SendAncillaryMessage::ScmRights(&descriptors)) {
            return Err("the root descriptor exceeds the control space".into());
        }
        sendmsg(
            &socket,
            &[IoSlice::new(&reply)],
            &mut control,
            SendFlags::empty(),
        )?;
    }
    Ok(())
}

fn fixed_registry() -> TestResult {
    for component in [
        "/run/pigloros",
        "/run/pigloros/sandbox",
        "/run/pigloros/sandbox/registry",
        "/run/pigloros/sandbox/attempts",
    ] {
        fs::create_dir(component)?;
        fs::set_permissions(component, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Overwrite the first byte of the admitted, installed image.
fn corrupt_held_image(snapshot: &ProviderImageSnapshot) -> TestResult {
    let image = Path::new("/var/lib/pigloros/sandbox/images").join(
        snapshot
            .image()
            .manifest()
            .root_image_blake3_digest
            .iter()
            .flat_map(|byte| [byte >> 4, byte & 0x0f])
            .map(|nibble| char::from_digit(u32::from(nibble), 16).unwrap_or('0'))
            .collect::<String>(),
    );
    fs::set_permissions(&image, fs::Permissions::from_mode(0o600))?;
    fs::OpenOptions::new()
        .write(true)
        .open(&image)?
        .write_all(&[0xff])?;
    Ok(())
}

/// An activator that rejects every request it is sent.
struct RejectingActivator;

impl ImageActivator for RejectingActivator {
    fn mount_image(
        self,
        _: ActivationImage,
    ) -> impl Future<Output = Result<QuarantinedRootMount, ImageActivationError>> + Send {
        std::future::ready(Err(ImageActivationError::MethodRejected))
    }
}

/// The registry's activation marker records a request sent on this boot.
fn assert_request_recorded() -> TestResult {
    let marker = fs::read("/run/pigloros/sandbox/registry/activation")?;
    let hex = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim_end()
        .replace('-', "");
    let boot = (0..16)
        .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        (marker.get(..4), marker.len(), marker.get(4..20)),
        (Some(b"PAA1".as_slice()), 36, Some(boot.as_slice()))
    );
    Ok(())
}

/// A marker that cannot be replaced refuses the request before it is sent.
async fn unreplaceable_marker_refuses(
    kernel: &FakeKernel,
    admission: &HeldImageAdmission<'_>,
    prepared: &PreparedAttemptDirectory,
) -> TestResult {
    let marker = Path::new("/run/pigloros/sandbox/registry/activation");
    fs::remove_file(marker)?;
    fs::create_dir(marker)?;
    assert_eq!(
        activate(kernel, admission, prepared, || std::future::ready(Ok(
            RejectingActivator
        )))
        .await
        .err(),
        Some(ImageActivationError::AttachFailure)
    );
    Ok(())
}

/// Activate `prepared` once more, release its root and finish its cleanup.
async fn retry_and_clean(
    kernel: &FakeKernel,
    admission: &HeldImageAdmission<'_>,
    prepared: PreparedAttemptDirectory,
) -> TestResult {
    let retried = activate(
        kernel,
        admission,
        &prepared,
        MountfsdImageActivator::connect,
    )
    .await?;
    let released = release_owned(retried, kernel, &prepared).await?;
    prepared.finish_terminal_cleanup(crate::AttemptUnitTermination::Unsubmitted, Some(released))?;
    Ok(())
}

/// Prepare `planned` for `admission` after an admission of another SIM1
/// prepared nothing, and check that PAI2 records the held image's device and
/// inode after the directories'.
fn prepare_for_admission(
    registry: &SystemdAttemptRegistry,
    admission: &HeldImageAdmission<'_>,
    planned: &PlannedAttemptIntent,
) -> Result<PreparedAttemptDirectory, BoxError> {
    let other_image = PlannedAttemptIntent::new([0x45; 16], [0x78; 32])?;
    assert!(matches!(
        registry
            .commit_planned(&other_image)?
            .prepare_directory(admission),
        Err(crate::SystemdAttemptRegistryError::InvalidIntent)
    ));
    assert!(!Path::new("/run/pigloros/sandbox/attempts")
        .join(other_image.unit_name().attempt_component())
        .exists());
    let prepared = registry
        .commit_planned(planned)?
        .prepare_directory(admission)?;
    let held = rustix::fs::fstat(admission)?;
    let record = fs::read(Path::new("/run/pigloros/sandbox/registry").join(component(&prepared)))?;
    assert_eq!(record.len(), 100);
    assert_eq!(&record[..4], b"PAI2");
    assert_eq!(
        record[84..].to_vec(),
        [held.st_dev.to_le_bytes(), held.st_ino.to_le_bytes()].concat()
    );
    Ok(prepared)
}

/// A directory whose PAI2 record names another image is never activated.
async fn another_recorded_image_is_never_activated(
    kernel: &FakeKernel,
    registry: &SystemdAttemptRegistry,
    admission: &HeldImageAdmission<'_>,
    snapshot: &ProviderImageSnapshot,
) -> TestResult {
    let fixture = registry
        .commit_planned(&PlannedAttemptIntent::new(
            [0x46; 16],
            snapshot.request().authority.sim1_digest,
        )?)?
        .prepare_fixture_directory()?;
    assert_eq!(
        activate(kernel, admission, &fixture, MountfsdImageActivator::connect)
            .await
            .err(),
        Some(ImageActivationError::AttachFailure)
    );
    Ok(())
}

#[tokio::test]
async fn the_admitted_chain_reaches_attachment_only_through_every_gate() -> TestResult {
    if std::env::var_os(PRIVILEGED_COMPOSITION_TEST).is_none() {
        return run_isolated(
            "root_attachment::tests::the_admitted_chain_reaches_attachment_only_through_every_gate",
        );
    }
    let staged = StagedInstallation::stage_execution().map_err(|error| error.to_string())?;
    let snapshot = ProviderImageSnapshot::open(staged.request())?;
    let admission = snapshot.admit_held_image()?;
    fixed_registry()?;
    let registry = SystemdAttemptRegistry::open()?;
    let planned = PlannedAttemptIntent::new(
        snapshot.request().attempt_id,
        snapshot.request().authority.sim1_digest,
    )?;
    let prepared = prepare_for_admission(&registry, &admission, &planned)?;
    let root_directory = ActivatedRootDirectory::for_attempt(&component(&prepared));
    let expected = Expected::for_admission(&admission, root_directory.clone())
        .ok_or("the held image identity")?;

    // The isolated runner shares the hosted kernel's command line, which
    // does not veto userspace Verity: the public entry fails closed.
    assert_eq!(
        activate_admitted_root(&admission, &prepared).await.err(),
        Some(ImageActivationError::HostFeatureUnavailable)
    );
    // With the veto, a missing mountfsd is still unavailable.
    let kernel = FakeKernel {
        mount_path: Some(tempfile::NamedTempFile::new()?.into_temp_path()),
        ..FakeKernel::accepting(matching(&expected))
    };
    assert_eq!(
        activate(
            &kernel,
            &admission,
            &prepared,
            MountfsdImageActivator::connect
        )
        .await
        .err(),
        Some(ImageActivationError::HostFeatureUnavailable)
    );
    // No request was sent, so the marker still records none.
    assert_eq!(
        fs::read("/run/pigloros/sandbox/registry/activation")?,
        [b"PAA1".as_slice(), &[0; 32]].concat()
    );

    fs::create_dir("/run/systemd")?;
    let listener = UnixListener::bind("/run/systemd/io.systemd.MountFileSystem")?;
    let root = expected.root;
    let peer = thread::spawn(move || serve(&listener, root, 3));

    // Neither early failure reached mountfsd, so after one successful retry
    // the released root alone lets terminal cleanup delete intent last.
    retry_and_clean(&kernel, &admission, prepared).await?;
    assert_request_recorded()?;
    another_recorded_image_is_never_activated(&kernel, &registry, &admission, &snapshot).await?;
    let prepared = registry
        .commit_planned(&planned)?
        .prepare_directory(&admission)?;

    // Every gate passes: the verified root names the attempt path.
    let verified = activate(
        &kernel,
        &admission,
        &prepared,
        MountfsdImageActivator::connect,
    )
    .await?;
    assert_eq!(verified.root_directory(), &root_directory);
    assert_eq!(verified.mount_id(), 41);
    assert_eq!(kernel.detached(), 1);

    // The entry reservation consumes a fresh admission. The public recheck
    // re-reads the real host kernel: the fake descriptor is no attached EROFS
    // mount, so it refuses.
    check_admitted_recheck(&verified, &kernel, &registry, &snapshot, &staged, &prepared)?;

    // The held image changes after admission: re-admission rejects and the
    // attached root is detached again.
    corrupt_held_image(&snapshot)?;
    assert_eq!(
        activate(
            &kernel,
            &admission,
            &prepared,
            MountfsdImageActivator::connect
        )
        .await
        .err(),
        Some(ImageActivationError::EvidenceMismatch)
    );
    assert_eq!(kernel.detached(), 2);
    peer.join().map_err(|_| "the fake mountfsd panicked")??;

    unreplaceable_marker_refuses(&kernel, &admission, &prepared).await?;

    // A replaced attempt root rejects before mountfsd is called.
    let attempt = Path::new("/run/pigloros/sandbox/attempts").join(component(&prepared));
    fs::rename(attempt.join("root"), attempt.join("held-root"))?;
    fs::create_dir(attempt.join("root"))?;
    fs::set_permissions(attempt.join("root"), fs::Permissions::from_mode(0o700))?;
    assert_eq!(
        activate(
            &kernel,
            &admission,
            &prepared,
            MountfsdImageActivator::connect
        )
        .await
        .err(),
        Some(ImageActivationError::AttachFailure)
    );
    // The activation that reached mountfsd retains intent until its one root
    // is released; the later early failure does not change that.
    assert!(matches!(
        prepared.finish_terminal_cleanup(crate::AttemptUnitTermination::Unsubmitted, None),
        Err(crate::SystemdAttemptRegistryError::CleanupEvidence)
    ));
    Ok(())
}

#[test]
fn only_the_image_pai2_recorded_is_activated() -> TestResult {
    let tree = prepared_tree()?;
    let mut expected = expected(&component(&tree.prepared));
    assert_eq!(recorded_image_is_held(&tree.prepared, &expected), Ok(()));
    for held in crate::OTHER_IMAGES {
        expected.held = held;
        assert_eq!(
            recorded_image_is_held(&tree.prepared, &expected),
            Err(ImageActivationError::AttachFailure)
        );
    }
    Ok(())
}

#[test]
fn an_entry_binds_only_the_root_its_admission_activated() -> TestResult {
    let tree = prepared_tree()?;
    let expected = expected(&component(&tree.prepared));
    assert!(binds(&expected, Some(&expected.clone())));
    assert!(!binds(&expected, None));
    let mut other_image = expected.clone();
    other_image.held.1 += 1;
    let mut other_executable = expected.clone();
    other_executable.executable_digest[0] ^= 1;
    let mut other_path = expected.clone();
    other_path.executable_path.push('x');
    let mut other_root = expected.clone();
    other_root.root_directory = ActivatedRootDirectory::for_attempt("another");
    for other in [other_image, other_executable, other_path, other_root] {
        assert!(!binds(&expected, Some(&other)));
    }
    Ok(())
}

#[test]
fn a_recheck_consults_nothing_for_an_admission_it_was_not_activated_from() -> TestResult {
    let tree = prepared_tree()?;
    let expected = expected(&component(&tree.prepared));
    let kernel = FakeKernel::accepting(matching(&expected));
    let verified = attach_and_verify(&kernel, &tree.prepared, &expected, file_mount()?, || Ok(()))?;
    let mut other = expected;
    other.executable_digest[0] ^= 1;
    let consulted = std::cell::Cell::new(false);
    for candidate in [Some(&other), None] {
        assert_eq!(
            recheck(&kernel, &verified, &tree.prepared, candidate, || {
                consulted.set(true);
                Ok(())
            })
            .err(),
            Some(ImageActivationError::EvidenceMismatch)
        );
    }
    assert!(!consulted.get());
    Ok(())
}

fn check_admitted_recheck(
    verified: &VerifiedRootMount,
    kernel: &FakeKernel,
    registry: &SystemdAttemptRegistry,
    snapshot: &ProviderImageSnapshot,
    staged: &StagedInstallation,
    prepared: &PreparedAttemptDirectory,
) -> TestResult {
    let ledger = StagingLedger::new(StagingLimits {
        aggregate_bytes: 512 * 1024 * 1024,
    });
    let (_staging, input) = crate::test_fixtures::staged_execution::verified_input(staged, &ledger)
        .map_err(|error| error.to_string())?;
    let entry = input.entry();
    let record = Path::new("/run/pigloros/sandbox/registry").join(component(prepared));
    assert_eq!(&fs::read(&record)?[..4], b"PAI2");
    let checked = verified.recheck_with(kernel, prepared, &entry)?;
    let committed = fs::read(&record)?;
    assert_eq!(&committed[..4], b"PAI3");
    assert_eq!(committed.len(), 393);
    assert_eq!(checked.root_directory(), verified.root_directory());
    assert!(checked.matches_attempt(&AdmittedAttempt::from_entry(&entry, prepared)?));
    let foreign = registry
        .commit_planned(&PlannedAttemptIntent::new(
            [0x44; 16],
            snapshot.request().authority.sim1_digest,
        )?)?
        .prepare_fixture_directory()?;
    assert_eq!(
        verified.recheck_with(kernel, &foreign, &entry).err(),
        Some(ImageActivationError::EvidenceMismatch)
    );
    // The real host contradicts this fixture and permanently quarantines it.
    assert_eq!(
        verified.recheck(prepared, &entry).err(),
        Some(ImageActivationError::EvidenceMismatch)
    );
    assert_eq!(fs::read(&record)?, committed);
    assert!(registry
        .commit_planned(&PlannedAttemptIntent::new([0x45; 16], [9; 32])?)
        .is_err());
    Ok(())
}
