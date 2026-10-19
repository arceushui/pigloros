use std::{
    error::Error,
    fs,
    io::{IoSlice, IoSliceMut, Write},
    mem::MaybeUninit,
    os::{
        fd::{AsFd, OwnedFd},
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream as StdUnixStream},
        },
    },
    path::Path,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
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
    observe::{loop_of, mount_entry, LoopDevice, Mapper, MountEntry, Node, Slave},
    verify::Extent,
};
use crate::{PlannedAttemptIntent, SystemdAttemptRegistry};

type BoxError = Box<dyn Error + Send + Sync>;
type TestResult = Result<(), BoxError>;

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
        held: (5, 6),
    }
}

fn slave(expected: &Expected, extent: Extent) -> Slave {
    Slave {
        loop_name: Some("loop7".to_owned()),
        start: Some(extent.start / 512),
        size: Some(extent.length / 512),
        loop_device: Some(LoopDevice {
            backing: Some(expected.held),
            offset: Some(0),
            size_limit: Some(0),
            autoclear: Some(1),
            read_only: Some(1),
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
            uuid: Some("CRYPT-VERITY-5f0e5a1c-root".to_owned()),
            read_only: Some(1),
            slaves: Some(vec![
                slave(expected, expected.root),
                slave(expected, expected.verity),
            ]),
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
    _runtime: tempfile::TempDir,
    prepared: PreparedAttemptDirectory,
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
        .prepare_directory()?;
    Ok(PreparedTree {
        _runtime: runtime,
        prepared,
    })
}

fn component(prepared: &PreparedAttemptDirectory) -> String {
    prepared.intent().unit_name().attempt_component().to_owned()
}

/// A descriptor-aware fake kernel that records every detach.
struct FakeKernel {
    vetoes: bool,
    attach: Result<(), ImageActivationError>,
    private: Result<(), ImageActivationError>,
    observations: Observations,
    detach: Result<(), ImageActivationError>,
    detached: AtomicUsize,
}

impl FakeKernel {
    fn accepting(observations: Observations) -> Self {
        Self {
            vetoes: true,
            attach: Ok(()),
            private: Ok(()),
            observations,
            detach: Ok(()),
            detached: AtomicUsize::new(0),
        }
    }

    fn detached(&self) -> usize {
        self.detached.load(Ordering::SeqCst)
    }
}

impl AttachmentKernel for FakeKernel {
    fn vetoes_userspace_verity(&self) -> bool {
        self.vetoes
    }

    fn attach(&self, _: BorrowedFd<'_>, _: &File) -> Result<(), ImageActivationError> {
        self.attach
    }

    fn make_private(&self, _: BorrowedFd<'_>) -> Result<(), ImageActivationError> {
        self.private
    }

    fn observe(&self, _: BorrowedFd<'_>, _: &File, _: &File) -> Observations {
        self.observations.clone()
    }

    fn detach(&self, _: BorrowedFd<'_>) -> Result<(), ImageActivationError> {
        self.detached.fetch_add(1, Ordering::SeqCst);
        self.detach
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
fn only_one_plain_veto_token_disables_userspace_verity() {
    assert!(vetoes_userspace_verity(
        format!("BOOT_IMAGE=/vmlinuz root=/dev/vda1 {VETO} quiet\n").as_bytes()
    ));
    assert!(vetoes_userspace_verity(VETO.as_bytes()));
    for rejected in [
        String::new(),
        "BOOT_IMAGE=/vmlinuz quiet".to_owned(),
        "systemd.allow_userspace_verity=1".to_owned(),
        "systemd.allow_userspace_verity=no".to_owned(),
        "systemd.allow_userspace_verity=00".to_owned(),
        "systemd.allow_userspace_verity".to_owned(),
        format!("x{VETO}"),
        format!("\"{VETO}\""),
        format!("{VETO} {VETO}"),
        format!("{VETO} systemd.allow_userspace_verity=1"),
        format!("{VETO} rd.systemd.allow_userspace_verity=1"),
    ] {
        assert!(!vetoes_userspace_verity(rejected.as_bytes()), "{rejected}");
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
    assert_eq!(expected.verify(&observed), Ok(41));
    edit_slaves(&mut observed, |slaves| slaves.swap(0, 1));
    assert_eq!(expected.verify(&observed), Ok(41));
}

/// One named difference from the matching readback per accepted fact.
fn readback_mutations() -> Vec<(&'static str, fn(&mut Observations))> {
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
        ("no parent", |o| o.parent_mount_id = None),
        ("foreign parent", |o| o.parent_mount_id = Some(31)),
        ("ext4 magic", |o| o.filesystem_magic = Some(0xEF53)),
        ("writable", |o| o.read_only = Some(false)),
        ("unknown writability", |o| o.read_only = None),
        ("no mountinfo entry", |o| o.entry = None),
        ("wrong device", |o| edit_entry(o, |e| e.device = (253, 4))),
        ("wrong root", |o| {
            edit_entry(o, |e| e.root = "/usr".to_owned())
        }),
        ("replaced path", |o| {
            edit_entry(o, |e| {
                e.mount_point = "/run/pigloros/sandbox/attempts/other/root".to_owned();
            });
        }),
        ("rw mount", |o| {
            edit_entry(o, |e| e.options = "rw,relatime".to_owned())
        }),
        ("rw superblock", |o| {
            edit_entry(o, |e| e.super_options = "rw".to_owned())
        }),
        ("not erofs", |o| {
            edit_entry(o, |e| e.filesystem = "squashfs".to_owned())
        }),
        ("shared propagation", |o| {
            edit_entry(o, |e| e.optional = vec!["shared:7".to_owned()]);
        }),
        ("slave propagation", |o| {
            edit_entry(o, |e| e.optional = vec!["master:2".to_owned()]);
        }),
        ("no mapper", |o| o.mapper = None),
        ("no dm uuid", |o| edit_mapper(o, |m| m.uuid = None)),
        ("not dm-verity", |o| {
            edit_mapper(o, |m| m.uuid = Some("LVM-abc".to_owned()))
        }),
        ("writable mapper", |o| {
            edit_mapper(o, |m| m.read_only = Some(0))
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
            edit_slaves(o, |s| s[0].start = Some(2049))
        }),
        ("same extent twice", |o| {
            edit_slaves(o, |s| s[1] = s[0].clone())
        }),
        ("unknown size", |o| edit_slaves(o, |s| s[0].size = None)),
        ("overflowing start", |o| {
            edit_slaves(o, |s| s[0].start = Some(u64::MAX))
        }),
        ("no loop device", |o| {
            edit_slaves(o, |s| s[0].loop_device = None)
        }),
        ("substituted image", |o| {
            edit_loop(o, |d| d.backing = Some((5, 7)))
        }),
        ("unknown backing", |o| edit_loop(o, |d| d.backing = None)),
        ("offset", |o| edit_loop(o, |d| d.offset = Some(512))),
        ("size limit", |o| {
            edit_loop(o, |d| d.size_limit = Some(4096))
        }),
        ("no autoclear", |o| edit_loop(o, |d| d.autoclear = Some(0))),
        ("writable loop", |o| edit_loop(o, |d| d.read_only = Some(0))),
    ]
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

#[test]
fn the_host_kernel_reads_back_the_mount_loop_and_mapper_by_descriptor() -> TestResult {
    let tree = prepared_tree()?;
    let (attempt, root) = tree.prepared.held_directories();
    let host = tempfile::tempdir()?;
    let (proc, sys) = (host.path().join("proc"), host.path().join("sys"));
    let kernel = HostKernel::at(&proc, &sys);

    // Unreadable procfs and sysfs: every dependent fact is absent.
    let observed = kernel.observe(root.as_fd(), attempt, root);
    let mount = observed.mount.ok_or("statx through the root descriptor")?;
    assert_eq!(observed.path, Some(mount));
    assert_eq!(observed.parent_mount_id, Some(mount.mount_id));
    assert!(observed.filesystem_magic.is_some());
    assert_eq!(observed.read_only, Some(false));
    assert_eq!(observed.entry, None);
    assert_eq!(
        observed.mapper,
        Some(Mapper {
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
    let block = sys.join(format!("dev/block/{major}:{minor}"));
    write(&block.join("dm/uuid"), "CRYPT-VERITY-abc-root\n")?;
    write(&block.join("ro"), "1\n")?;
    for name in ["loop7p1", "loop7p2", "sdz1"] {
        fs::create_dir_all(block.join("slaves").join(name))?;
    }
    let partitions = sys.join("class/block");
    write(&partitions.join("loop7p1/start"), "2048\n")?;
    write(&partitions.join("loop7p1/size"), "16384\n")?;
    let mut image = tempfile::NamedTempFile::new()?;
    image.write_all(b"held image")?;
    let held = image.as_file().metadata()?;
    let device = partitions.join("loop7");
    write(
        &device.join("loop/backing_file"),
        &format!("{}\n", image.path().display()),
    )?;
    write(&device.join("loop/offset"), "0\n")?;
    write(&device.join("loop/sizelimit"), "0\n")?;
    write(&device.join("loop/autoclear"), "1\n")?;
    write(&device.join("ro"), "1\n")?;

    let observed = kernel.observe(root.as_fd(), attempt, root);
    let entry = observed.entry.ok_or("the synthetic mountinfo entry")?;
    assert_eq!(entry.mount_point, "/attempt");
    assert_eq!(entry.optional, vec!["shared:3".to_owned()]);
    let mapper = observed.mapper.ok_or("the synthetic mapper")?;
    assert_eq!(mapper.uuid.as_deref(), Some("CRYPT-VERITY-abc-root"));
    assert_eq!(mapper.read_only, Some(1));
    let mut slaves = mapper.slaves.ok_or("the synthetic slaves")?;
    slaves.sort_by_key(|slave| slave.loop_name.clone());
    let loop_device = LoopDevice {
        backing: Some((held.dev(), held.ino())),
        offset: Some(0),
        size_limit: Some(0),
        autoclear: Some(1),
        read_only: Some(1),
    };
    let missing_device = LoopDevice {
        backing: None,
        ..loop_device.clone()
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
    write(&device.join("loop/backing_file"), "/nonexistent/held\n")?;
    let observed = kernel.observe(root.as_fd(), attempt, root);
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
fn serve(listener: UnixListener, root: Extent, calls: usize) -> TestResult {
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

#[tokio::test]
async fn the_admitted_chain_reaches_attachment_only_through_every_gate() -> TestResult {
    if std::env::var_os(PRIVILEGED_COMPOSITION_TEST).is_none() {
        return run_isolated(
            "root_attachment::tests::the_admitted_chain_reaches_attachment_only_through_every_gate",
        );
    }
    let staged = StagedInstallation::stage().map_err(|error| error.to_string())?;
    let snapshot = ProviderImageSnapshot::open(staged.request())?;
    let admission = snapshot.admit_held_image()?;
    fixed_registry()?;
    let prepared = SystemdAttemptRegistry::open()?
        .commit_planned(&PlannedAttemptIntent::new([0x44; 16], [0x45; 32])?)?
        .prepare_directory()?;
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
    let kernel = FakeKernel::accepting(matching(&expected));
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

    fs::create_dir("/run/systemd")?;
    let listener = UnixListener::bind("/run/systemd/io.systemd.MountFileSystem")?;
    let root = expected.root;
    let peer = thread::spawn(move || serve(listener, root, 2));

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
    assert_eq!(kernel.detached(), 0);

    // The held image changes after admission: re-admission rejects and the
    // attached root is detached again.
    let image = Path::new("/var/lib/pigloros/sandbox/images").join(
        snapshot
            .image()
            .manifest()
            .root_image_blake3_digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    fs::set_permissions(&image, fs::Permissions::from_mode(0o600))?;
    fs::OpenOptions::new()
        .write(true)
        .open(&image)?
        .write_all(&[0xff])?;
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
    assert_eq!(kernel.detached(), 1);
    peer.join().map_err(|_| "the fake mountfsd panicked")??;

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
    Ok(())
}
