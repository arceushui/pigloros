//! KOE1, the kernel-observation evidence of ADR-069 R9 §4.4, with the
//! R14 §3.1 `network-readback`.
//!
//! Its self-digest is `observed_state_digest`: SPR1 ordinal 20, the last
//! authority digest of SAU1 events 11 to 13, and RLS1 ordinal 12.

mod network_readback;

use ciborium::value::Value;

use super::{
    consistent, digest, digest_value, open, optional, optional_value, seal, u32_in, uint_in, Result,
};
use crate::sandbox_provider_protocol::codec::{
    array, bytes_value, id16, text_value, uint, uint_value,
};
pub use network_readback::{
    LocalNetworkReadback, ReadbackFirewallBase, ReadbackFirewallChain, ReadbackFirewallHook,
    ReadbackFirewallPolicy, ReadbackFirewallRule, ReadbackPrefix, ReadbackRoute, ReadbackVethEnd,
};

use crate::sandbox_provider_protocol::{
    CgroupIdentity, FdIdentity, KernelObservationFacts, LauncherReady,
    SandboxProviderProtocolError, WorkMountFacts,
};

const MAGIC: &str = "KOE1";
/// R14 N3: the readback of up to 256 planned exchanges fits.
const MAX_RECORD_BYTES: usize = 64 * 1024;
/// The kernel's device-number bounds: 12 major and 20 minor bits.
const MAX_MAJOR: u32 = 4095;
const MAX_MINOR: u32 = 1_048_575;
/// The kernel's `PID_MAX_LIMIT`.
const MAX_PID: u32 = 4_194_304;

/// A kernel device number as `[major, minor]`, never a raw `st_dev`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceNumber {
    /// The major number, `0..=4095`.
    pub major: u32,
    /// The minor number, `0..=1048575`.
    pub minor: u32,
}

impl DeviceNumber {
    fn value(self) -> Value {
        Value::Array(vec![
            uint_value(u64::from(self.major)),
            uint_value(u64::from(self.minor)),
        ])
    }

    fn decode(value: &Value) -> Result<Self> {
        let [major, minor] = array::<2>(value)?;
        Ok(Self {
            major: u32_in(major, 0..=MAX_MAJOR)?,
            minor: u32_in(minor, 0..=MAX_MINOR)?,
        })
    }
}

/// A device and a nonzero inode: the identity of a cgroup directory.
pub(super) fn cgroup_identity(value: &Value) -> Result<CgroupIdentity> {
    let (device, inode) = device_inode(value)?;
    Ok(CgroupIdentity {
        major: device.major,
        minor: device.minor,
        inode,
    })
}

pub(super) fn cgroup_identity_value(identity: CgroupIdentity) -> Value {
    device_inode_value(
        DeviceNumber {
            major: identity.major,
            minor: identity.minor,
        },
        identity.inode,
    )
}

fn device_inode(value: &Value) -> Result<(DeviceNumber, u64)> {
    let [device, inode] = array::<2>(value)?;
    Ok((DeviceNumber::decode(device)?, uint_in(inode, 1..=u64::MAX)?))
}

fn device_inode_value(device: DeviceNumber, inode: u64) -> Value {
    Value::Array(vec![device.value(), uint_value(inode)])
}

/// One namespace: its nsfs device and inode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceIdentity {
    /// The nsfs device's major number.
    pub major: u32,
    /// The nsfs device's minor number.
    pub minor: u32,
    /// The namespace inode; never zero.
    pub inode: u64,
}

impl NamespaceIdentity {
    fn value(self) -> Value {
        device_inode_value(
            DeviceNumber {
                major: self.major,
                minor: self.minor,
            },
            self.inode,
        )
    }

    fn decode(value: &Value) -> Result<Self> {
        device_inode(value).map(|(device, inode)| Self {
            major: device.major,
            minor: device.minor,
            inode,
        })
    }
}

/// One block device generation: its device number and disk sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockIdentity {
    /// The device number.
    pub device: DeviceNumber,
    /// The disk sequence; never zero.
    pub diskseq: u64,
}

impl BlockIdentity {
    fn value(self) -> Value {
        Value::Array(vec![self.device.value(), uint_value(self.diskseq)])
    }

    fn decode(value: &Value) -> Result<Self> {
        let [device, diskseq] = array::<2>(value)?;
        Ok(Self {
            device: DeviceNumber::decode(device)?,
            diskseq: uint_in(diskseq, 1..=u64::MAX)?,
        })
    }
}

/// The attached root mount: its mount ID and device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootMount {
    /// The mount ID.
    pub mount_id: u64,
    /// The mounted device, which is the root mapper's.
    pub device: DeviceNumber,
}

impl RootMount {
    fn value(self) -> Value {
        Value::Array(vec![uint_value(self.mount_id), self.device.value()])
    }

    fn decode(value: &Value) -> Result<Self> {
        let [mount_id, device] = array::<2>(value)?;
        Ok(Self {
            mount_id: uint(mount_id)?,
            device: DeviceNumber::decode(device)?,
        })
    }
}

/// The KOE1 `kernel-observation` of one released unit (R9 §4.4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedKernelState {
    /// The unit's `InvocationID` (RDY1 ordinal 4).
    pub invocation_id: [u8; 16],
    /// The unit's `MainPID`, `1..=4194304`.
    pub main_pid: u32,
    /// The target of `/proc/<MainPID>/exe` (RDY1 ordinal 6).
    pub launcher: FdIdentity,
    /// The adapter beneath the verified root (RDY1 ordinal 9).
    pub adapter: FdIdentity,
    /// The attached root mount; its device is the mapper's.
    pub root_mount: RootMount,
    /// The root's device-mapper device.
    pub root_mapper: BlockIdentity,
    /// The loop device under the mapper.
    pub root_loop: BlockIdentity,
    /// The bound cgroup.
    pub cgroup: CgroupIdentity,
    /// The unit's namespaces: mnt, pid, ipc, uts, user and net.
    pub namespaces: [NamespaceIdentity; 6],
    /// The provider's namespaces of the same types; each differs from the
    /// unit's.
    pub provider_namespaces: [NamespaceIdentity; 6],
    /// The observed FDL1 digest (RDY1 ordinals 11 and 12).
    pub observed_fdl1_digest: [u8; 32],
    /// The `/work` mount and capacity, without its free space; null exactly
    /// when ELM1 limit 9 is zero.
    pub work: Option<WorkMountFacts>,
    /// The Local network readback (R14 §3.1); present exactly when the
    /// AGR1 mode is Local.
    pub network_readback: Option<LocalNetworkReadback>,
}

impl ObservedKernelState {
    fn value(&self) -> Value {
        Value::Array(vec![
            bytes_value(&self.invocation_id),
            uint_value(u64::from(self.main_pid)),
            self.launcher.value(),
            self.adapter.value(),
            self.root_mount.value(),
            self.root_mapper.value(),
            self.root_loop.value(),
            cgroup_identity_value(self.cgroup),
            namespaces_value(&self.namespaces),
            namespaces_value(&self.provider_namespaces),
            digest_value(&self.observed_fdl1_digest),
            optional_value(self.work, work_mount_value),
            optional_value(self.network_readback.as_ref(), LocalNetworkReadback::value),
        ])
    }

    fn decode(value: &Value) -> Result<Self> {
        let fields = array::<13>(value)?;
        let state = Self {
            invocation_id: id16(&fields[0])?,
            main_pid: u32_in(&fields[1], 1..=MAX_PID)?,
            launcher: fd_identity(&fields[2])?,
            adapter: fd_identity(&fields[3])?,
            root_mount: RootMount::decode(&fields[4])?,
            root_mapper: BlockIdentity::decode(&fields[5])?,
            root_loop: BlockIdentity::decode(&fields[6])?,
            cgroup: cgroup_identity(&fields[7])?,
            namespaces: namespaces(&fields[8])?,
            provider_namespaces: namespaces(&fields[9])?,
            observed_fdl1_digest: digest(&fields[10])?,
            work: optional(&fields[11], work_mount)?,
            network_readback: None,
        };
        if !(state.root_mount.device == state.root_mapper.device && state.isolated()) {
            std::io::Write::write_fmt(
                &mut std::io::stderr(),
                format_args!(
                    "pos-sandboxd diag: KOE1 mount={:?} mapper={:?} isolated={} ns={:?} provider_ns={:?}\n",
                    state.root_mount.device,
                    state.root_mapper.device,
                    state.isolated(),
                    state.namespaces,
                    state.provider_namespaces
                ),
            )
            .ok();
        }
        consistent(state.root_mount.device == state.root_mapper.device && state.isolated())
            .and_then(|()| state.with_network_readback(&fields[12]))
    }

    /// The state with its decoded `network-readback`, whose attempt
    /// namespace is neither the unit's nor the provider's network namespace
    /// (R14 rule 4).
    fn with_network_readback(self, value: &Value) -> Result<Self> {
        optional(value, |readback| {
            LocalNetworkReadback::decode(readback, self.namespaces[5], self.provider_namespaces[5])
        })
        .map(|network_readback| Self {
            network_readback,
            ..self
        })
    }

    /// No unit namespace is the provider's namespace of the same type.
    fn isolated(&self) -> bool {
        self.namespaces
            .iter()
            .zip(&self.provider_namespaces)
            .all(|(unit, provider)| unit != provider)
    }

    /// The observation agrees with the accepted `ReadyV1` (ordinals 4, 6,
    /// 9, 11 and 12) and with the runtime's namespaces.
    pub(super) fn matches_ready(
        &self,
        ready: &LauncherReady,
        provider_namespaces: &[NamespaceIdentity; 6],
    ) -> bool {
        let ready = &ready.fields;
        self.invocation_id == ready.launch_instance_id
            && [self.launcher, self.adapter] == [ready.launcher_identity, ready.adapter_identity]
            && [ready.expected_fdl1_digest, ready.observed_fdl1_digest]
                == [self.observed_fdl1_digest; 2]
            && self.provider_namespaces == *provider_namespaces
    }
}

/// KOE1 `status` with the fields it decides.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KernelObservationStatus {
    /// 0: `ReadyV1` was accepted and the unit observed.
    Observed {
        /// The accepted `ReadyV1`'s digest.
        ready1_digest: [u8; 32],
        /// The frozen observation.
        observation: Box<ObservedKernelState>,
    },
    /// 1: no valid `ReadyV1` was accepted.
    NotReached,
    /// 2: `ReadyV1` was accepted, but no observation was made or the
    /// provider's checks rejected it.
    ObservationFailed {
        /// The accepted `ReadyV1`'s digest.
        ready1_digest: [u8; 32],
    },
}

impl KernelObservationStatus {
    /// The R9 status code.
    #[must_use]
    pub const fn code(&self) -> u8 {
        match self {
            Self::Observed { .. } => 0,
            Self::NotReached => 1,
            Self::ObservationFailed { .. } => 2,
        }
    }

    /// The accepted `ReadyV1`'s digest; `None` when none was accepted.
    #[must_use]
    pub const fn ready1_digest(&self) -> Option<[u8; 32]> {
        match self {
            Self::Observed { ready1_digest, .. } | Self::ObservationFailed { ready1_digest } => {
                Some(*ready1_digest)
            }
            Self::NotReached => None,
        }
    }

    /// What the terminal classifier reads of it.
    pub(super) fn facts(&self) -> KernelObservationFacts {
        match self {
            Self::Observed { observation, .. } => KernelObservationFacts::Observed {
                invocation_id: observation.invocation_id,
                cgroup: observation.cgroup,
                work: observation.work,
            },
            Self::NotReached => KernelObservationFacts::NotReached,
            Self::ObservationFailed { .. } => KernelObservationFacts::ObservationFailed,
        }
    }

    fn decode(status: &Value, ready: &Value, observation: &Value) -> Result<Self> {
        match (uint(status)?, optional(ready, digest)?, observation) {
            (1, None, Value::Null) => Ok(Self::NotReached),
            (2, Some(ready1_digest), Value::Null) => Ok(Self::ObservationFailed { ready1_digest }),
            (0, Some(ready1_digest), observation) if observation != &Value::Null => {
                ObservedKernelState::decode(observation).map(|observation| Self::Observed {
                    ready1_digest,
                    observation: Box::new(observation),
                })
            }
            (0..=2, ..) => Err(SandboxProviderProtocolError::InconsistentFields),
            _ => Err(SandboxProviderProtocolError::FieldOutOfBounds),
        }
    }
}

/// The unsigned fields of one KOE1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelObservationEvidenceFields {
    /// The attempt.
    pub attempt_id: [u8; 16],
    /// The AGR1 self-digest.
    pub agr1_digest: [u8; 32],
    /// The status, with the `ReadyV1` digest and observation it decides.
    pub status: KernelObservationStatus,
    /// The attempt's RQE1 self-digest, in every status.
    pub requested_configuration_evidence: [u8; 32],
}

impl KernelObservationEvidenceFields {
    fn unsigned(&self) -> Vec<Value> {
        let observation = match &self.status {
            KernelObservationStatus::Observed { observation, .. } => observation.value(),
            KernelObservationStatus::NotReached
            | KernelObservationStatus::ObservationFailed { .. } => Value::Null,
        };
        vec![
            text_value(MAGIC),
            uint_value(1),
            bytes_value(&self.attempt_id),
            digest_value(&self.agr1_digest),
            uint_value(u64::from(self.status.code())),
            optional_value(self.status.ready1_digest().as_ref(), digest_value),
            digest_value(&self.requested_configuration_evidence),
            observation,
        ]
    }

    fn decode(fields: &[Value; 8]) -> Result<Self> {
        Ok(Self {
            attempt_id: id16(&fields[2])?,
            agr1_digest: digest(&fields[3])?,
            status: KernelObservationStatus::decode(&fields[4], &fields[5], &fields[7])?,
            requested_configuration_evidence: digest(&fields[6])?,
        })
    }
}

/// One KOE1: its validated fields, self-digest and canonical bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelObservationEvidence {
    fields: KernelObservationEvidenceFields,
    digest: [u8; 32],
    bytes: Vec<u8>,
}

impl KernelObservationEvidence {
    /// Encode and seal `fields`.
    ///
    /// # Errors
    /// Any R9 rule the decoded record would fail.
    pub fn new(fields: &KernelObservationEvidenceFields) -> Result<Self> {
        seal(MAGIC, fields.unsigned()).and_then(|bytes| Self::from_canonical_cbor(&bytes))
    }

    /// Decode and validate exact canonical KOE1 bytes.
    ///
    /// # Errors
    /// A closed protocol error for every R9 §6 rule the record alone decides.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        open(
            bytes,
            MAGIC,
            MAX_RECORD_BYTES,
            KernelObservationEvidenceFields::decode,
        )
        .map(|(fields, digest)| Self {
            fields,
            digest,
            bytes: bytes.to_vec(),
        })
    }

    /// The fields.
    #[must_use]
    pub const fn fields(&self) -> &KernelObservationEvidenceFields {
        &self.fields
    }

    /// The self-digest under `PiglorOS.KOE1.v1\0`: `observed_state_digest`.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// The canonical record bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// An `fd-identity` with a nonzero inode.
fn fd_identity(value: &Value) -> Result<FdIdentity> {
    FdIdentity::decode(value).and_then(|identity| {
        if identity.valid() {
            Ok(identity)
        } else {
            Err(SandboxProviderProtocolError::FieldOutOfBounds)
        }
    })
}

fn namespaces(value: &Value) -> Result<[NamespaceIdentity; 6]> {
    let [mnt, pid, ipc, uts, user, net] = array::<6>(value)?;
    Ok([
        NamespaceIdentity::decode(mnt)?,
        NamespaceIdentity::decode(pid)?,
        NamespaceIdentity::decode(ipc)?,
        NamespaceIdentity::decode(uts)?,
        NamespaceIdentity::decode(user)?,
        NamespaceIdentity::decode(net)?,
    ])
}

fn namespaces_value(namespaces: &[NamespaceIdentity; 6]) -> Value {
    Value::Array(namespaces.iter().map(|identity| identity.value()).collect())
}

/// KOE1 `work`: a mount ID and a nonzero capacity.
fn work_mount(value: &Value) -> Result<WorkMountFacts> {
    let [mount_id, capacity] = array::<2>(value)?;
    work_mount_parts(mount_id, capacity)
}

/// A `/work` mount ID and its nonzero capacity, as KOE1 `work` and TME1
/// `work-after` both begin.
pub(super) fn work_mount_parts(mount_id: &Value, capacity: &Value) -> Result<WorkMountFacts> {
    Ok(WorkMountFacts {
        mount_id: uint(mount_id)?,
        capacity_bytes: uint_in(capacity, 1..=u64::MAX)?,
    })
}

fn work_mount_value(work: WorkMountFacts) -> Value {
    Value::Array(vec![
        uint_value(work.mount_id),
        uint_value(work.capacity_bytes),
    ])
}
