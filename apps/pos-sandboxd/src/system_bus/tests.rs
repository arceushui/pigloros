use std::{
    error::Error,
    fs::{self, File},
    os::fd::OwnedFd as StdOwnedFd,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use pos_conformance::SandboxSyscallSetV1;
use pos_reference::sandbox_provider_protocol::{SandboxArchitecture, SandboxLimit};
use zbus::{
    connection::{socket::channel::Channel, Builder},
    fdo,
    object_server::SignalEmitter,
    zvariant::{OwnedFd, OwnedObjectPath, OwnedValue, Structure},
    Guid,
};

use super::*;
use crate::{
    ActivatedRootDirectory, AttemptCgroupEmptyBasis, LaunchMode, LauncherSource, SystemCallFilter,
    SystemdServiceLimits, TransientUnitLaunchInputs,
};

const X86_64: &[u8] = include_bytes!(
    "../../../../crates/pos-conformance/vectors/systemd-provider-v260.2/systemd-v260.2-x86_64.scs1.cbor"
);
const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const JOB_PATH: &str = "/org/freedesktop/systemd1/job/381";
const STOP_JOB_PATH: &str = "/org/freedesktop/systemd1/job/382";
const UNRELATED_JOB_PATH: &str = "/org/freedesktop/systemd1/job/999";
const UNIT_PATH: &str = "/org/freedesktop/systemd1/unit/pigloros_2dattempt_2dtest_2eservice";
const UNRELATED_UNIT_PATH: &str = "/org/freedesktop/systemd1/unit/unrelated_2eservice";
const CONTROL_GROUP_PATH: &str = "/system.slice/pigloros-attempt-test.service";
const ROOT_DIRECTORY: &str = "/run/pigloros/attempt-381/root";
const ROOT_IMAGE_POLICY: &str = "root=verity+signed";
const EXPECTED_PROPERTY_SHAPE: [(&str, &str); 42] = [
    ("Type", "s"),
    ("RootDirectory", "s"),
    ("BindReadOnlyPaths", "a(ssbt)"),
    ("DynamicUser", "b"),
    ("NoNewPrivileges", "b"),
    ("PrivateDevices", "b"),
    ("PrivateIPC", "b"),
    ("PrivateMounts", "b"),
    ("PrivateNetwork", "b"),
    ("PrivatePIDs", "s"),
    ("PrivateUsersEx", "s"),
    ("CapabilityBoundingSet", "t"),
    ("AmbientCapabilities", "t"),
    ("ProtectSystem", "s"),
    ("ProtectHome", "s"),
    ("ProtectControlGroupsEx", "s"),
    ("ProtectKernelTunables", "b"),
    ("ProtectKernelModules", "b"),
    ("ProtectKernelLogs", "b"),
    ("ProtectClock", "b"),
    ("ProtectHostname", "b"),
    ("ProtectProc", "s"),
    ("ProcSubset", "s"),
    ("RestrictNamespaces", "t"),
    ("RestrictSUIDSGID", "b"),
    ("RestrictRealtime", "b"),
    ("LockPersonality", "b"),
    ("SystemCallArchitectures", "as"),
    ("SystemCallFilter", "(bas)"),
    ("RestrictAddressFamilies", "(bas)"),
    ("UMask", "u"),
    ("KillMode", "s"),
    ("SendSIGKILL", "b"),
    ("MemoryMax", "t"),
    ("MemorySwapMax", "t"),
    ("TasksMax", "t"),
    ("CPUQuotaPerSecUSec", "t"),
    ("RuntimeMaxUSec", "t"),
    ("LimitNOFILE", "t"),
    ("LimitFSIZE", "t"),
    ("FileDescriptorStoreMax", "u"),
    ("ExtraFileDescriptors", "a(hs)"),
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedStart {
    unit_name: String,
    mode: String,
    property_names: Vec<String>,
    property_signatures: Vec<String>,
    descriptor_names: Vec<String>,
    auxiliary_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ObservedControl {
    Stop {
        name: String,
        mode: String,
    },
    Kill {
        name: String,
        whom: String,
        signal: i32,
    },
}

struct RecordingManager {
    observed: Arc<Mutex<Option<ObservedStart>>>,
    subscribed: Arc<AtomicBool>,
    behavior: ManagerBehavior,
}

#[derive(Clone)]
struct ManagerBehavior {
    subscription: SubscriptionBehavior,
    reject: bool,
    unit_lookup: UnitLookupBehavior,
    unit_lookups: Arc<AtomicUsize>,
    cgroup_lookup: CgroupLookupBehavior,
    cgroup_lookups: Arc<Mutex<Vec<String>>>,
    result: String,
    emit_unrelated: bool,
    start_job_signal: StartJobSignalBehavior,
    completion_unit: Option<String>,
    emit_completion: bool,
    control_calls: Arc<Mutex<Vec<ObservedControl>>>,
}

#[derive(Clone, Copy, Default)]
enum SubscriptionBehavior {
    #[default]
    Accept,
    Reject,
}

#[derive(Clone, Copy, Default)]
enum UnitLookupBehavior {
    #[default]
    Resolve,
    Reject,
    RejectAfterFirst,
    RejectAfterSecond,
    SubstituteAfterSecond,
}

#[derive(Clone, Copy, Default)]
enum CgroupLookupBehavior {
    #[default]
    Resolve,
    Reject,
    Substitute,
    RejectOnSecond,
    SubstituteOnSecond,
}

#[derive(Clone, Copy, Default)]
enum StartJobSignalBehavior {
    #[default]
    None,
    Canceled,
}

impl Default for ManagerBehavior {
    fn default() -> Self {
        Self {
            subscription: SubscriptionBehavior::default(),
            reject: false,
            unit_lookup: UnitLookupBehavior::default(),
            unit_lookups: Arc::new(AtomicUsize::new(0)),
            cgroup_lookup: CgroupLookupBehavior::default(),
            cgroup_lookups: Arc::new(Mutex::new(Vec::new())),
            result: "done".to_owned(),
            emit_unrelated: false,
            start_job_signal: StartJobSignalBehavior::default(),
            completion_unit: None,
            emit_completion: true,
            control_calls: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
impl RecordingManager {
    #[zbus(name = "Subscribe")]
    fn subscribe(&self) -> fdo::Result<()> {
        if matches!(self.behavior.subscription, SubscriptionBehavior::Reject) {
            return Err(fdo::Error::AccessDenied(
                "test subscription rejection".to_owned(),
            ));
        }
        self.subscribed.store(true, Ordering::SeqCst);
        Ok(())
    }

    #[zbus(name = "StartTransientUnit")]
    async fn start_transient_unit(
        &self,
        name: String,
        mode: String,
        properties: Vec<(String, OwnedValue)>,
        auxiliary: Vec<(String, Vec<(String, OwnedValue)>)>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<OwnedObjectPath> {
        if !self.subscribed.load(Ordering::SeqCst) {
            return Err(fdo::Error::Failed(
                "StartTransientUnit arrived before Subscribe".to_owned(),
            ));
        }
        if self.behavior.reject {
            return Err(fdo::Error::AccessDenied("test rejection".to_owned()));
        }
        let property_names = properties
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        let property_signatures = properties
            .iter()
            .map(|(_, value)| value.value_signature().to_string())
            .collect::<Vec<_>>();
        let descriptor_names = properties
            .into_iter()
            .find_map(|(property, value)| {
                (property == "ExtraFileDescriptors").then(|| descriptor_names(value))
            })
            .transpose()?
            .ok_or_else(|| fdo::Error::Failed("missing descriptor property".to_owned()))?;
        let auxiliary_count = auxiliary.len();
        // The generated D-Bus interface owns every decoded wire argument.
        drop(auxiliary);
        let call = ObservedStart {
            unit_name: name.clone(),
            mode,
            property_names,
            property_signatures,
            descriptor_names,
            auxiliary_count,
        };
        self.observed
            .lock()
            .map_err(|error| fdo::Error::Failed(error.to_string()))?
            .replace(call);
        let job_path = OwnedObjectPath::try_from(JOB_PATH)
            .map_err(|error| fdo::Error::Failed(error.to_string()))?;
        if self.behavior.emit_unrelated {
            let unrelated = OwnedObjectPath::try_from(UNRELATED_JOB_PATH)
                .map_err(|error| fdo::Error::Failed(error.to_string()))?;
            Self::job_removed(
                &emitter,
                999,
                unrelated,
                "unrelated.service".to_owned(),
                "failed".to_owned(),
            )
            .await
            .map_err(|error| fdo::Error::Failed(error.to_string()))?;
        }
        if self.behavior.emit_completion {
            Self::job_removed(
                &emitter,
                381,
                job_path.clone(),
                self.behavior
                    .completion_unit
                    .clone()
                    .unwrap_or_else(|| name.clone()),
                self.behavior.result.clone(),
            )
            .await
            .map_err(|error| fdo::Error::Failed(error.to_string()))?;
        }
        Ok(job_path)
    }

    #[zbus(name = "StopUnit")]
    async fn stop_unit(
        &self,
        name: String,
        mode: String,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<OwnedObjectPath> {
        if !self.subscribed.load(Ordering::SeqCst) {
            return Err(fdo::Error::Failed(
                "StopUnit arrived before Subscribe".to_owned(),
            ));
        }
        if self.behavior.reject {
            return Err(fdo::Error::AccessDenied("test stop rejection".to_owned()));
        }
        self.behavior
            .control_calls
            .lock()
            .map_err(|error| fdo::Error::Failed(error.to_string()))?
            .push(ObservedControl::Stop {
                name: name.clone(),
                mode,
            });
        let job = OwnedObjectPath::try_from(STOP_JOB_PATH)
            .map_err(|error| fdo::Error::Failed(error.to_string()))?;
        if matches!(
            self.behavior.start_job_signal,
            StartJobSignalBehavior::Canceled
        ) {
            Self::job_removed(
                &emitter,
                381,
                OwnedObjectPath::try_from(JOB_PATH)
                    .map_err(|error| fdo::Error::Failed(error.to_string()))?,
                name.clone(),
                "canceled".to_owned(),
            )
            .await
            .map_err(|error| fdo::Error::Failed(error.to_string()))?;
        }
        if self.behavior.emit_unrelated {
            Self::job_removed(
                &emitter,
                999,
                OwnedObjectPath::try_from(UNRELATED_JOB_PATH)
                    .map_err(|error| fdo::Error::Failed(error.to_string()))?,
                name.clone(),
                "done".to_owned(),
            )
            .await
            .map_err(|error| fdo::Error::Failed(error.to_string()))?;
        }
        if self.behavior.emit_completion {
            Self::job_removed(
                &emitter,
                382,
                job.clone(),
                self.behavior.completion_unit.clone().unwrap_or(name),
                self.behavior.result.clone(),
            )
            .await
            .map_err(|error| fdo::Error::Failed(error.to_string()))?;
        }
        Ok(job)
    }

    #[zbus(name = "KillUnit")]
    fn kill_unit(&self, name: String, whom: String, signal: i32) -> fdo::Result<()> {
        if self.behavior.reject {
            return Err(fdo::Error::AccessDenied("test kill rejection".to_owned()));
        }
        self.behavior
            .control_calls
            .lock()
            .map_err(|error| fdo::Error::Failed(error.to_string()))?
            .push(ObservedControl::Kill { name, whom, signal });
        Ok(())
    }

    #[zbus(name = "GetUnit")]
    fn get_unit(&self, name: String) -> fdo::Result<OwnedObjectPath> {
        let _ = (&self.observed, name);
        let lookup_index = self.behavior.unit_lookups.fetch_add(1, Ordering::SeqCst);
        if matches!(self.behavior.unit_lookup, UnitLookupBehavior::Reject)
            || (matches!(
                self.behavior.unit_lookup,
                UnitLookupBehavior::RejectAfterFirst
            ) && lookup_index > 0)
            || (matches!(
                self.behavior.unit_lookup,
                UnitLookupBehavior::RejectAfterSecond
            ) && lookup_index > 1)
        {
            return Err(fdo::Error::Failed("test lookup rejection".to_owned()));
        }
        let unit = if matches!(
            self.behavior.unit_lookup,
            UnitLookupBehavior::SubstituteAfterSecond
        ) && lookup_index > 1
        {
            UNRELATED_UNIT_PATH
        } else {
            UNIT_PATH
        };
        OwnedObjectPath::try_from(unit).map_err(|error| fdo::Error::Failed(error.to_string()))
    }

    #[zbus(name = "GetUnitByControlGroup")]
    fn get_unit_by_control_group(&self, path: String) -> fdo::Result<OwnedObjectPath> {
        let lookup_number = {
            let mut lookups = self
                .behavior
                .cgroup_lookups
                .lock()
                .map_err(|error| fdo::Error::Failed(error.to_string()))?;
            lookups.push(path);
            lookups.len()
        };
        if matches!(self.behavior.cgroup_lookup, CgroupLookupBehavior::Reject)
            || (matches!(
                self.behavior.cgroup_lookup,
                CgroupLookupBehavior::RejectOnSecond
            ) && lookup_number > 1)
        {
            return Err(fdo::Error::Failed(
                "test cgroup lookup rejection".to_owned(),
            ));
        }
        let unit = if matches!(
            self.behavior.cgroup_lookup,
            CgroupLookupBehavior::Substitute
        ) || (matches!(
            self.behavior.cgroup_lookup,
            CgroupLookupBehavior::SubstituteOnSecond
        ) && lookup_number > 1)
        {
            UNRELATED_UNIT_PATH
        } else {
            UNIT_PATH
        };
        OwnedObjectPath::try_from(unit).map_err(|error| fdo::Error::Failed(error.to_string()))
    }

    #[zbus(signal, name = "JobRemoved")]
    async fn job_removed(
        emitter: &SignalEmitter<'_>,
        id: u32,
        job: OwnedObjectPath,
        unit: String,
        result: String,
    ) -> zbus::Result<()>;
}

struct RecordingService {
    system_call_filter: Vec<String>,
    root_directory: String,
    service_limits: [u64; 7],
    property_reads: Arc<AtomicUsize>,
    control_group_reads: Arc<AtomicUsize>,
    control_group: String,
    control_group_behavior: ControlGroupBehavior,
    fail_root_directory: bool,
    fail_root_image_policy: bool,
    fail_memory_max: bool,
}

#[derive(Clone, Default)]
enum ControlGroupBehavior {
    #[default]
    Stable,
    Reject,
    RejectAfter(Arc<AtomicUsize>),
    ChangeAfter(Arc<AtomicUsize>),
}

impl RecordingService {
    fn exact(system_call_filter: Vec<String>) -> Self {
        Self {
            system_call_filter,
            root_directory: ROOT_DIRECTORY.to_owned(),
            service_limits: [134_217_728, 0, 16, 500_000, 5_000_000, 64, 4_096],
            property_reads: Arc::new(AtomicUsize::new(0)),
            control_group_reads: Arc::new(AtomicUsize::new(0)),
            control_group: CONTROL_GROUP_PATH.to_owned(),
            control_group_behavior: ControlGroupBehavior::default(),
            fail_root_directory: false,
            fail_root_image_policy: false,
            fail_memory_max: false,
        }
    }

    fn fixed<T>(&self, value: T) -> T {
        self.record_read();
        value
    }

    fn record_read(&self) {
        self.property_reads.fetch_add(1, Ordering::SeqCst);
    }
}

#[zbus::interface(name = "org.freedesktop.systemd1.Service")]
impl RecordingService {
    #[zbus(property, name = "ControlGroup")]
    fn control_group(&self) -> fdo::Result<String> {
        let reads = self.control_group_reads.fetch_add(1, Ordering::SeqCst);
        match &self.control_group_behavior {
            ControlGroupBehavior::Reject => Err(fdo::Error::Failed(
                "test ControlGroup read failure".to_owned(),
            )),
            ControlGroupBehavior::RejectAfter(threshold) => {
                if reads >= threshold.load(Ordering::SeqCst) {
                    Err(fdo::Error::Failed(
                        "test ControlGroup read failure".to_owned(),
                    ))
                } else {
                    Ok(self.control_group.clone())
                }
            }
            ControlGroupBehavior::ChangeAfter(threshold) => {
                let path = if reads >= threshold.load(Ordering::SeqCst) {
                    "/system.slice/substituted.service"
                } else {
                    self.control_group.as_str()
                };
                Ok(path.to_owned())
            }
            ControlGroupBehavior::Stable => Ok(self.control_group.clone()),
        }
    }

    #[zbus(property, name = "Type")]
    fn type_property(&self) -> &'static str {
        self.fixed("exec")
    }

    #[zbus(property, name = "RootDirectory")]
    fn root_directory(&self) -> fdo::Result<&str> {
        self.record_read();
        if self.fail_root_directory {
            Err(fdo::Error::Failed("test readback failure".to_owned()))
        } else {
            Ok(&self.root_directory)
        }
    }

    #[zbus(property, name = "BindReadOnlyPaths")]
    fn bind_read_only_paths(&self) -> Vec<(String, String, bool, u64)> {
        self.fixed(vec![(
            "/usr/lib/pigloros/release-launcher".to_owned(),
            "/.pigloros/release-launcher".to_owned(),
            false,
            0,
        )])
    }

    #[zbus(property, name = "DynamicUser")]
    fn dynamic_user(&self) -> bool {
        self.fixed(true)
    }

    #[zbus(property, name = "NoNewPrivileges")]
    fn no_new_privileges(&self) -> bool {
        self.fixed(true)
    }

    #[zbus(property, name = "PrivateDevices")]
    fn private_devices(&self) -> bool {
        self.fixed(true)
    }

    #[zbus(property, name = "PrivateIPC")]
    fn private_ipc(&self) -> bool {
        self.fixed(true)
    }

    #[zbus(property, name = "PrivateMounts")]
    fn private_mounts(&self) -> bool {
        self.fixed(true)
    }

    #[zbus(property, name = "PrivateNetwork")]
    fn private_network(&self) -> bool {
        self.fixed(true)
    }

    #[zbus(property, name = "PrivatePIDs")]
    fn private_pi_ds(&self) -> &'static str {
        self.fixed("yes")
    }

    #[zbus(property, name = "PrivateUsersEx")]
    fn private_users_ex(&self) -> &'static str {
        self.fixed("self")
    }

    #[zbus(property, name = "CapabilityBoundingSet")]
    fn capability_bounding_set(&self) -> u64 {
        self.fixed(0)
    }

    #[zbus(property, name = "AmbientCapabilities")]
    fn ambient_capabilities(&self) -> u64 {
        self.fixed(0)
    }

    #[zbus(property, name = "ProtectSystem")]
    fn protect_system(&self) -> &'static str {
        self.fixed("strict")
    }

    #[zbus(property, name = "ProtectHome")]
    fn protect_home(&self) -> &'static str {
        self.fixed("yes")
    }

    #[zbus(property, name = "ProtectControlGroupsEx")]
    fn protect_control_groups_ex(&self) -> &'static str {
        self.fixed("strict")
    }

    #[zbus(property, name = "ProtectKernelTunables")]
    fn protect_kernel_tunables(&self) -> bool {
        self.fixed(true)
    }

    #[zbus(property, name = "ProtectKernelModules")]
    fn protect_kernel_modules(&self) -> bool {
        self.fixed(true)
    }

    #[zbus(property, name = "ProtectKernelLogs")]
    fn protect_kernel_logs(&self) -> bool {
        self.fixed(true)
    }

    #[zbus(property, name = "ProtectClock")]
    fn protect_clock(&self) -> bool {
        self.fixed(true)
    }

    #[zbus(property, name = "ProtectHostname")]
    fn protect_hostname(&self) -> bool {
        self.fixed(true)
    }

    #[zbus(property, name = "ProtectProc")]
    fn protect_proc(&self) -> &'static str {
        self.fixed("invisible")
    }

    #[zbus(property, name = "ProcSubset")]
    fn proc_subset(&self) -> &'static str {
        self.fixed("pid")
    }

    #[zbus(property, name = "RestrictNamespaces")]
    fn restrict_namespaces(&self) -> u64 {
        self.fixed(0x7e02_0080)
    }

    #[zbus(property, name = "RestrictSUIDSGID")]
    fn restrict_suidsgid(&self) -> bool {
        self.fixed(true)
    }

    #[zbus(property, name = "RestrictRealtime")]
    fn restrict_realtime(&self) -> bool {
        self.fixed(true)
    }

    #[zbus(property, name = "LockPersonality")]
    fn lock_personality(&self) -> bool {
        self.fixed(true)
    }

    #[zbus(property, name = "SystemCallArchitectures")]
    fn system_call_architectures(&self) -> Vec<String> {
        self.fixed(vec!["native".to_owned()])
    }

    #[zbus(property, name = "SystemCallFilter")]
    fn system_call_filter(&self) -> (bool, Vec<String>) {
        self.record_read();
        (true, self.system_call_filter.clone())
    }

    #[zbus(property, name = "RestrictAddressFamilies")]
    fn restrict_address_families(&self) -> (bool, Vec<String>) {
        self.fixed((true, vec!["AF_UNIX".to_owned()]))
    }

    #[zbus(property, name = "UMask")]
    fn u_mask(&self) -> u32 {
        self.fixed(0o077)
    }

    #[zbus(property, name = "KillMode")]
    fn kill_mode(&self) -> &'static str {
        self.fixed("control-group")
    }

    #[zbus(property, name = "SendSIGKILL")]
    fn send_sigkill(&self) -> bool {
        self.fixed(true)
    }

    #[zbus(property, name = "MemoryMax")]
    fn memory_max(&self) -> fdo::Result<u64> {
        self.record_read();
        if self.fail_memory_max {
            Err(fdo::Error::Failed("test limit readback failure".to_owned()))
        } else {
            Ok(self.service_limits[0])
        }
    }

    #[zbus(property, name = "MemorySwapMax")]
    fn memory_swap_max(&self) -> u64 {
        self.fixed(self.service_limits[1])
    }

    #[zbus(property, name = "TasksMax")]
    fn tasks_max(&self) -> u64 {
        self.fixed(self.service_limits[2])
    }

    #[zbus(property, name = "CPUQuotaPerSecUSec")]
    fn cpu_quota_per_sec_u_sec(&self) -> u64 {
        self.fixed(self.service_limits[3])
    }

    #[zbus(property, name = "RuntimeMaxUSec")]
    fn runtime_max_u_sec(&self) -> u64 {
        self.fixed(self.service_limits[4])
    }

    #[zbus(property, name = "LimitNOFILE")]
    fn limit_nofile(&self) -> u64 {
        self.fixed(self.service_limits[5])
    }

    #[zbus(property, name = "LimitFSIZE")]
    fn limit_fsize(&self) -> u64 {
        self.fixed(self.service_limits[6])
    }

    #[zbus(property, name = "FileDescriptorStoreMax")]
    fn file_descriptor_store_max(&self) -> u32 {
        self.fixed(0)
    }

    #[zbus(property, name = "ExtraFileDescriptorNames")]
    fn extra_file_descriptor_names(&self) -> Vec<String> {
        self.fixed(vec![
            "piglor-host-service-v1".to_owned(),
            "piglor-release-v1".to_owned(),
        ])
    }

    #[zbus(property, name = "RootImagePolicy")]
    fn root_image_policy(&self) -> fdo::Result<&'static str> {
        self.record_read();
        if self.fail_root_image_policy {
            Err(fdo::Error::Failed("test readback failure".to_owned()))
        } else {
            Ok(ROOT_IMAGE_POLICY)
        }
    }
}

fn descriptor_names(value: OwnedValue) -> fdo::Result<Vec<String>> {
    Vec::<Structure<'static>>::try_from(value)
        .map_err(|error| fdo::Error::Failed(error.to_string()))?
        .into_iter()
        .map(|descriptor| {
            let mut fields = descriptor.into_fields().into_iter();
            fields
                .next()
                .ok_or_else(|| fdo::Error::Failed("descriptor is missing its fd".to_owned()))?;
            let name = fields
                .next()
                .ok_or_else(|| fdo::Error::Failed("descriptor is missing its name".to_owned()))?;
            String::try_from(name).map_err(|error| fdo::Error::Failed(error.to_string()))
        })
        .collect()
}

#[tokio::test]
async fn generated_proxy_submits_the_exact_closed_request() -> Result<(), Box<dyn Error>> {
    let observed = Arc::new(Mutex::new(None));
    let behavior = ManagerBehavior {
        emit_unrelated: true,
        ..ManagerBehavior::default()
    };
    let service = RecordingService::exact(expected_system_call_filter()?);
    let (transport, _server) = transport(Arc::clone(&observed), behavior, service).await?;
    let name = TransientServiceUnitName::from_attempt_id([0xab; 16])?;
    assert_eq!(
        name.as_str(),
        "pigloros-attempt-abababababababababababababababab.service"
    );

    let verified = transport
        .start(
            name.clone(),
            request(LaunchMode::Local {
                host_service: descriptor()?,
            })?,
        )
        .await?;
    assert_eq!(verified.unit_name(), &name);
    assert_eq!(verified.job().as_str(), JOB_PATH);
    assert_eq!(verified.unit_path(), UNIT_PATH);
    assert_eq!(verified.requested_readback().len(), 42);
    assert_eq!(verified.requested_readback()[0].name(), "Type");
    assert_eq!(
        verified.requested_readback()[41].name(),
        "ExtraFileDescriptors"
    );
    assert_eq!(
        verified.manager_readback().property(),
        SystemdManagerReadbackOnlyProperty::RootImagePolicy
    );
    assert_eq!(verified.manager_readback().value(), ROOT_IMAGE_POLICY);

    let call = observed
        .lock()
        .map_err(|error| error.to_string())?
        .clone()
        .ok_or("manager did not observe StartTransientUnit")?;
    assert_eq!(
        call.unit_name,
        "pigloros-attempt-abababababababababababababababab.service"
    );
    assert_eq!(call.mode, "fail");
    let property_shape = call
        .property_names
        .iter()
        .zip(&call.property_signatures)
        .map(|(name, signature)| (name.as_str(), signature.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(property_shape, EXPECTED_PROPERTY_SHAPE);
    assert_eq!(
        call.descriptor_names,
        ["piglor-host-service-v1", "piglor-release-v1"]
    );
    assert_eq!(call.auxiliary_count, 0);
    Ok(())
}

#[tokio::test]
async fn generated_proxy_preserves_manager_rejection() -> Result<(), Box<dyn Error>> {
    let behavior = ManagerBehavior {
        reject: true,
        ..ManagerBehavior::default()
    };
    let service = RecordingService::exact(expected_system_call_filter()?);
    let (transport, _server) = transport(Arc::new(Mutex::new(None)), behavior, service).await?;
    let result = transport
        .start(
            TransientServiceUnitName::from_attempt_id([0x01; 16])?,
            request(LaunchMode::AirGapped)?,
        )
        .await;
    let error = result.err().ok_or("manager rejection was accepted")?;
    assert!(error.to_string().contains("systemd rejected"));
    let SystemdTransientUnitTransportError::ManagerCall(_) = error else {
        return Err("manager rejection had the wrong error class".into());
    };
    Ok(())
}

#[tokio::test]
async fn manager_subscription_rejection_is_classified() -> Result<(), Box<dyn Error>> {
    let behavior = ManagerBehavior {
        subscription: SubscriptionBehavior::Reject,
        ..ManagerBehavior::default()
    };
    let service = RecordingService::exact(expected_system_call_filter()?);
    let error = transport(Arc::new(Mutex::new(None)), behavior, service)
        .await
        .err()
        .ok_or("manager subscription rejection was accepted")?;
    assert_eq!(
        error.to_string(),
        "failed to subscribe the systemd manager connection"
    );
    Ok(())
}

#[tokio::test]
async fn completed_unit_lookup_failure_is_classified() -> Result<(), Box<dyn Error>> {
    let behavior = ManagerBehavior {
        unit_lookup: UnitLookupBehavior::Reject,
        ..ManagerBehavior::default()
    };
    let service = RecordingService::exact(expected_system_call_filter()?);
    let (transport, _server) = transport(Arc::new(Mutex::new(None)), behavior, service).await?;
    let error = transport
        .start(
            TransientServiceUnitName::from_attempt_id([0x06; 16])?,
            request(LaunchMode::AirGapped)?,
        )
        .await
        .err()
        .ok_or("failed completed-unit lookup was accepted")?;
    assert!(matches!(
        error,
        SystemdTransientUnitTransportError::UnitLookup(_)
    ));
    Ok(())
}

#[tokio::test]
async fn every_non_successful_job_result_fails_closed() -> Result<(), Box<dyn Error>> {
    let cases = [
        ("canceled", SystemdJobFailure::Canceled),
        ("timeout", SystemdJobFailure::Timeout),
        ("failed", SystemdJobFailure::Failed),
        ("dependency", SystemdJobFailure::Dependency),
        ("skipped", SystemdJobFailure::Skipped),
        (
            "future-result",
            SystemdJobFailure::Unknown("future-result".to_owned()),
        ),
    ];
    for (result, expected) in cases {
        let behavior = ManagerBehavior {
            result: result.to_owned(),
            ..ManagerBehavior::default()
        };
        let service = RecordingService::exact(expected_system_call_filter()?);
        let property_reads = Arc::clone(&service.property_reads);
        let (transport, _server) = transport(Arc::new(Mutex::new(None)), behavior, service).await?;
        let error = transport
            .start(
                TransientServiceUnitName::from_attempt_id([0x02; 16])?,
                request(LaunchMode::AirGapped)?,
            )
            .await
            .err()
            .ok_or("failed job result was accepted")?;
        let SystemdTransientUnitTransportError::JobFailed(actual) = error else {
            return Err("failed job result had the wrong error class".into());
        };
        assert_eq!(actual, expected);
        assert_eq!(property_reads.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[tokio::test]
async fn matching_job_path_cannot_substitute_the_unit_name() -> Result<(), Box<dyn Error>> {
    let behavior = ManagerBehavior {
        completion_unit: Some("substituted.service".to_owned()),
        ..ManagerBehavior::default()
    };
    let service = RecordingService::exact(expected_system_call_filter()?);
    let (transport, _server) = transport(Arc::new(Mutex::new(None)), behavior, service).await?;
    let expected = TransientServiceUnitName::from_attempt_id([0x03; 16])?;
    let error = transport
        .start(expected.clone(), request(LaunchMode::AirGapped)?)
        .await
        .err()
        .ok_or("substituted completion unit was accepted")?;
    let SystemdTransientUnitTransportError::JobIdentityMismatch {
        expected: observed_expected,
        actual,
    } = error
    else {
        return Err("substituted completion unit had the wrong error class".into());
    };
    assert_eq!(observed_expected, expected.as_str());
    assert_eq!(actual, "substituted.service");
    Ok(())
}

#[tokio::test]
async fn unequal_typed_property_readback_fails_closed() -> Result<(), Box<dyn Error>> {
    let mut service = RecordingService::exact(expected_system_call_filter()?);
    service.root_directory = "/run/pigloros/substituted/root".to_owned();
    let (transport, _server) = transport(
        Arc::new(Mutex::new(None)),
        ManagerBehavior::default(),
        service,
    )
    .await?;
    let error = transport
        .start(
            TransientServiceUnitName::from_attempt_id([0x04; 16])?,
            request(LaunchMode::Local {
                host_service: descriptor()?,
            })?,
        )
        .await
        .err()
        .ok_or("unequal property readback was accepted")?;
    assert!(matches!(
        error,
        SystemdTransientUnitTransportError::Readback(TransientUnitRequestError::ReadbackMismatch)
    ));
    Ok(())
}

#[tokio::test]
async fn typed_property_read_failure_is_classified() -> Result<(), Box<dyn Error>> {
    let mut service = RecordingService::exact(expected_system_call_filter()?);
    service.fail_root_directory = true;
    let (transport, _server) = transport(
        Arc::new(Mutex::new(None)),
        ManagerBehavior::default(),
        service,
    )
    .await?;
    let error = transport
        .start(
            TransientServiceUnitName::from_attempt_id([0x05; 16])?,
            request(LaunchMode::Local {
                host_service: descriptor()?,
            })?,
        )
        .await
        .err()
        .ok_or("failed property read was accepted")?;
    let SystemdTransientUnitTransportError::PropertyReadback { property, .. } = error else {
        return Err("failed property read had the wrong error class".into());
    };
    assert_eq!(property, "RootDirectory");
    Ok(())
}

#[tokio::test]
async fn substituted_typed_service_limit_fails_closed() -> Result<(), Box<dyn Error>> {
    let mut service = RecordingService::exact(expected_system_call_filter()?);
    service.service_limits[2] = 17;
    let (transport, _server) = transport(
        Arc::new(Mutex::new(None)),
        ManagerBehavior::default(),
        service,
    )
    .await?;
    let error = transport
        .start(
            TransientServiceUnitName::from_attempt_id([0x06; 16])?,
            request(LaunchMode::AirGapped)?,
        )
        .await
        .err()
        .ok_or("substituted service limit was accepted")?;
    assert!(matches!(
        error,
        SystemdTransientUnitTransportError::Readback(TransientUnitRequestError::ReadbackMismatch)
    ));
    Ok(())
}

#[tokio::test]
async fn typed_service_limit_read_failure_is_classified() -> Result<(), Box<dyn Error>> {
    let mut service = RecordingService::exact(expected_system_call_filter()?);
    service.fail_memory_max = true;
    let (transport, _server) = transport(
        Arc::new(Mutex::new(None)),
        ManagerBehavior::default(),
        service,
    )
    .await?;
    let error = transport
        .start(
            TransientServiceUnitName::from_attempt_id([0x08; 16])?,
            request(LaunchMode::AirGapped)?,
        )
        .await
        .err()
        .ok_or("failed service-limit property read was accepted")?;
    let SystemdTransientUnitTransportError::PropertyReadback { property, .. } = error else {
        return Err("failed service-limit read had the wrong error class".into());
    };
    assert_eq!(property, "MemoryMax");
    Ok(())
}

#[tokio::test]
async fn manager_only_property_read_failure_is_classified() -> Result<(), Box<dyn Error>> {
    let mut service = RecordingService::exact(expected_system_call_filter()?);
    service.fail_root_image_policy = true;
    let (transport, _server) = transport(
        Arc::new(Mutex::new(None)),
        ManagerBehavior::default(),
        service,
    )
    .await?;
    let error = transport
        .start(
            TransientServiceUnitName::from_attempt_id([0x07; 16])?,
            request(LaunchMode::Local {
                host_service: descriptor()?,
            })?,
        )
        .await
        .err()
        .ok_or("failed manager-only property read was accepted")?;
    let SystemdTransientUnitTransportError::PropertyReadback { property, .. } = error else {
        return Err("failed manager-only property read had the wrong error class".into());
    };
    assert_eq!(property, "RootImagePolicy");
    Ok(())
}

#[tokio::test]
async fn stop_job_ignores_canceled_start_and_matches_stop() -> Result<(), Box<dyn Error>> {
    let behavior = ManagerBehavior {
        emit_unrelated: true,
        start_job_signal: StartJobSignalBehavior::Canceled,
        ..ManagerBehavior::default()
    };
    let calls = Arc::clone(&behavior.control_calls);
    let service = RecordingService::exact(expected_system_call_filter()?);
    let (transport, _server) = transport(Arc::new(Mutex::new(None)), behavior, service).await?;
    let name = TransientServiceUnitName::from_attempt_id([0x08; 16])?;
    let completed = transport.stop_job(name.clone()).await?;
    assert_eq!(completed.unit_name(), &name);
    assert_eq!(completed.job_path(), STOP_JOB_PATH);
    assert_eq!(
        calls.lock().map_err(|error| error.to_string())?.as_slice(),
        &[ObservedControl::Stop {
            name: name.as_str().to_owned(),
            mode: "replace".to_owned(),
        }]
    );
    Ok(())
}

#[tokio::test]
async fn stop_job_rejects_every_non_done_result() -> Result<(), Box<dyn Error>> {
    let cases = [
        ("canceled", SystemdJobFailure::Canceled),
        ("timeout", SystemdJobFailure::Timeout),
        ("failed", SystemdJobFailure::Failed),
        ("dependency", SystemdJobFailure::Dependency),
        ("skipped", SystemdJobFailure::Skipped),
        (
            "future-result",
            SystemdJobFailure::Unknown("future-result".to_owned()),
        ),
    ];
    for (result, expected) in cases {
        let behavior = ManagerBehavior {
            result: result.to_owned(),
            ..ManagerBehavior::default()
        };
        let service = RecordingService::exact(expected_system_call_filter()?);
        let (transport, _server) = transport(Arc::new(Mutex::new(None)), behavior, service).await?;
        let error = transport
            .stop_job(TransientServiceUnitName::from_attempt_id([0x09; 16])?)
            .await
            .err()
            .ok_or("non-done stop result was accepted")?;
        let SystemdTransientUnitTransportError::JobFailed(actual) = error else {
            return Err("stop result had the wrong error class".into());
        };
        assert_eq!(actual, expected);
    }
    Ok(())
}

#[tokio::test]
async fn stop_job_rejects_unit_substitution_and_manager_failure() -> Result<(), Box<dyn Error>> {
    let behavior = ManagerBehavior {
        completion_unit: Some("substituted.service".to_owned()),
        ..ManagerBehavior::default()
    };
    let service = RecordingService::exact(expected_system_call_filter()?);
    let (first_transport, _server) =
        transport(Arc::new(Mutex::new(None)), behavior, service).await?;
    let name = TransientServiceUnitName::from_attempt_id([0x0a; 16])?;
    let error = first_transport
        .stop_job(name.clone())
        .await
        .err()
        .ok_or("substituted stop unit was accepted")?;
    assert!(matches!(
        error,
        SystemdTransientUnitTransportError::JobIdentityMismatch { .. }
    ));

    let behavior = ManagerBehavior {
        reject: true,
        ..ManagerBehavior::default()
    };
    let service = RecordingService::exact(expected_system_call_filter()?);
    let (rejected_transport, _server) =
        transport(Arc::new(Mutex::new(None)), behavior, service).await?;
    let error = rejected_transport
        .stop_job(name)
        .await
        .err()
        .ok_or("rejected StopUnit call was accepted")?;
    assert!(matches!(
        error,
        SystemdTransientUnitTransportError::StopCall(_)
    ));
    Ok(())
}

#[tokio::test]
async fn force_kill_sends_whole_unit_sigkill_only() -> Result<(), Box<dyn Error>> {
    let behavior = ManagerBehavior::default();
    let calls = Arc::clone(&behavior.control_calls);
    let service = RecordingService::exact(expected_system_call_filter()?);
    let (first_transport, _server) =
        transport(Arc::new(Mutex::new(None)), behavior, service).await?;
    let name = TransientServiceUnitName::from_attempt_id([0x0b; 16])?;
    first_transport.force_kill(name.clone()).await?;
    assert_eq!(
        calls.lock().map_err(|error| error.to_string())?.as_slice(),
        &[ObservedControl::Kill {
            name: name.as_str().to_owned(),
            whom: "all".to_owned(),
            signal: 9,
        }]
    );

    let behavior = ManagerBehavior {
        reject: true,
        ..ManagerBehavior::default()
    };
    let service = RecordingService::exact(expected_system_call_filter()?);
    let (rejected_transport, _server) =
        transport(Arc::new(Mutex::new(None)), behavior, service).await?;
    let error = rejected_transport
        .force_kill(name)
        .await
        .err()
        .ok_or("rejected KillUnit call was accepted")?;
    assert!(matches!(
        error,
        SystemdTransientUnitTransportError::KillCall(_)
    ));
    Ok(())
}

#[tokio::test]
async fn exact_service_cgroup_is_reverse_mapped_and_kernel_observed() -> Result<(), Box<dyn Error>>
{
    let behavior = ManagerBehavior::default();
    let lookups = Arc::clone(&behavior.cgroup_lookups);
    let service = RecordingService::exact(expected_system_call_filter()?);
    let reads = Arc::clone(&service.control_group_reads);
    let (transport, _server, verified, temporary) =
        started_cgroup_transport(behavior, service).await?;
    let reads_before_binding = reads.load(Ordering::SeqCst);
    let mut bound = transport
        .bind_cgroup_with_root(
            &verified,
            CgroupRoot::for_test(File::open(temporary.path())?),
        )
        .await?;
    assert_eq!(reads.load(Ordering::SeqCst), reads_before_binding + 2);
    assert_eq!(bound.control_group(), CONTROL_GROUP_PATH);
    assert_eq!(
        lookups
            .lock()
            .map_err(|error| error.to_string())?
            .as_slice(),
        &[CONTROL_GROUP_PATH.to_owned(), CONTROL_GROUP_PATH.to_owned()]
    );
    let observed = bound.observe_empty()?;
    assert_eq!(observed.unit_name(), verified.unit_name());
    assert_eq!(observed.unit_path(), UNIT_PATH);
    assert_eq!(observed.basis(), AttemptCgroupEmptyBasis::Events);
    assert_eq!(
        observed.raw_events(),
        Some(b"populated 0\nfrozen 0\n".as_slice())
    );
    Ok(())
}

#[tokio::test]
async fn fixed_mount_binding_rejects_absent_attempt_cgroup() -> Result<(), Box<dyn Error>> {
    let service = RecordingService::exact(expected_system_call_filter()?);
    let (transport, _server, verified, _temporary) =
        started_cgroup_transport(ManagerBehavior::default(), service).await?;
    let error = transport
        .bind_cgroup(&verified)
        .await
        .err()
        .ok_or("absent attempt cgroup was accepted")?;
    assert!(matches!(
        error,
        SystemdTransientUnitTransportError::CgroupKernel(AttemptCgroupError::PathOpen(_))
    ));
    Ok(())
}

#[tokio::test]
async fn fixed_mount_failure_stops_before_bus_binding() -> Result<(), Box<dyn Error>> {
    let service = RecordingService::exact(expected_system_call_filter()?);
    let (transport, _server, verified, _temporary) =
        started_cgroup_transport(ManagerBehavior::default(), service).await?;
    let error = transport
        .bind_cgroup_with_root_result(&verified, Err(AttemptCgroupError::WrongFilesystem))
        .await
        .err()
        .ok_or("wrong fixed mount was accepted")?;
    assert!(matches!(
        error,
        SystemdTransientUnitTransportError::CgroupKernel(AttemptCgroupError::WrongFilesystem)
    ));
    Ok(())
}

#[tokio::test]
async fn cgroup_binding_rejects_lost_unit_lookup() -> Result<(), Box<dyn Error>> {
    let behavior = ManagerBehavior {
        unit_lookup: UnitLookupBehavior::RejectAfterFirst,
        ..ManagerBehavior::default()
    };
    let service = RecordingService::exact(expected_system_call_filter()?);
    let (transport, _server, verified, temporary) =
        started_cgroup_transport(behavior, service).await?;
    let error = transport
        .bind_cgroup_with_root(
            &verified,
            CgroupRoot::for_test(File::open(temporary.path())?),
        )
        .await
        .err()
        .ok_or("lost unit lookup was accepted")?;
    assert!(matches!(
        error,
        SystemdTransientUnitTransportError::UnitLookup(_)
    ));
    Ok(())
}

#[tokio::test]
async fn cgroup_binding_rechecks_unit_name_after_open() -> Result<(), Box<dyn Error>> {
    for unit_lookup in [
        UnitLookupBehavior::RejectAfterSecond,
        UnitLookupBehavior::SubstituteAfterSecond,
    ] {
        let behavior = ManagerBehavior {
            unit_lookup,
            ..ManagerBehavior::default()
        };
        let lookups = Arc::clone(&behavior.unit_lookups);
        let service = RecordingService::exact(expected_system_call_filter()?);
        let (transport, _server, verified, temporary) =
            started_cgroup_transport(behavior, service).await?;
        let error = transport
            .bind_cgroup_with_root(
                &verified,
                CgroupRoot::for_test(File::open(temporary.path())?),
            )
            .await
            .err()
            .ok_or("changed unit identity was accepted")?;
        assert!(matches!(
            error,
            SystemdTransientUnitTransportError::UnitLookup(_)
                | SystemdTransientUnitTransportError::CgroupUnitMismatch
        ));
        assert_eq!(lookups.load(Ordering::SeqCst), 3);
    }
    Ok(())
}

#[tokio::test]
async fn cgroup_binding_rejects_unit_substitution_before_property_read(
) -> Result<(), Box<dyn Error>> {
    let service = RecordingService::exact(expected_system_call_filter()?);
    let reads = Arc::clone(&service.control_group_reads);
    let (transport, _server, mut verified, temporary) =
        started_cgroup_transport(ManagerBehavior::default(), service).await?;
    let reads_before_binding = reads.load(Ordering::SeqCst);
    verified.unit_path = OwnedObjectPath::try_from(UNRELATED_UNIT_PATH)?;
    let error = transport
        .bind_cgroup_with_root(
            &verified,
            CgroupRoot::for_test(File::open(temporary.path())?),
        )
        .await
        .err()
        .ok_or("unit substitution was accepted")?;
    assert!(matches!(
        error,
        SystemdTransientUnitTransportError::CgroupUnitMismatch
    ));
    assert_eq!(reads.load(Ordering::SeqCst), reads_before_binding);
    Ok(())
}

#[tokio::test]
async fn cgroup_binding_rejects_reverse_lookup_failure_and_substitution(
) -> Result<(), Box<dyn Error>> {
    for cgroup_lookup in [
        CgroupLookupBehavior::Reject,
        CgroupLookupBehavior::Substitute,
        CgroupLookupBehavior::RejectOnSecond,
        CgroupLookupBehavior::SubstituteOnSecond,
    ] {
        let behavior = ManagerBehavior {
            cgroup_lookup,
            ..ManagerBehavior::default()
        };
        let service = RecordingService::exact(expected_system_call_filter()?);
        let (transport, _server, verified, temporary) =
            started_cgroup_transport(behavior, service).await?;
        let error = transport
            .bind_cgroup_with_root(
                &verified,
                CgroupRoot::for_test(File::open(temporary.path())?),
            )
            .await
            .err()
            .ok_or("bad reverse lookup was accepted")?;
        assert!(matches!(
            error,
            SystemdTransientUnitTransportError::CgroupReverseLookup(_)
                | SystemdTransientUnitTransportError::CgroupUnitMismatch
        ));
    }
    Ok(())
}

#[tokio::test]
async fn cgroup_binding_rejects_service_read_failure_and_change() -> Result<(), Box<dyn Error>> {
    let mut service = RecordingService::exact(expected_system_call_filter()?);
    service.control_group_behavior = ControlGroupBehavior::Reject;
    let (transport, _server, verified, temporary) =
        started_cgroup_transport(ManagerBehavior::default(), service).await?;
    let error = transport
        .bind_cgroup_with_root(
            &verified,
            CgroupRoot::for_test(File::open(temporary.path())?),
        )
        .await
        .err()
        .ok_or("failed ControlGroup read was accepted")?;
    assert!(matches!(
        error,
        SystemdTransientUnitTransportError::CgroupReadback(_)
    ));

    let threshold = Arc::new(AtomicUsize::new(usize::MAX));
    let mut service = RecordingService::exact(expected_system_call_filter()?);
    let reads = Arc::clone(&service.control_group_reads);
    service.control_group_behavior = ControlGroupBehavior::ChangeAfter(Arc::clone(&threshold));
    let (transport, _server, verified, temporary) =
        started_cgroup_transport(ManagerBehavior::default(), service).await?;
    let reads_before_binding = reads.load(Ordering::SeqCst);
    threshold.store(reads_before_binding + 1, Ordering::SeqCst);
    let error = transport
        .bind_cgroup_with_root(
            &verified,
            CgroupRoot::for_test(File::open(temporary.path())?),
        )
        .await
        .err()
        .ok_or("changed ControlGroup was accepted")?;
    assert!(matches!(
        error,
        SystemdTransientUnitTransportError::CgroupUnitMismatch
    ));
    assert_eq!(reads.load(Ordering::SeqCst), reads_before_binding + 2);

    let threshold = Arc::new(AtomicUsize::new(usize::MAX));
    let mut service = RecordingService::exact(expected_system_call_filter()?);
    let reads = Arc::clone(&service.control_group_reads);
    service.control_group_behavior = ControlGroupBehavior::RejectAfter(Arc::clone(&threshold));
    let (transport, _server, verified, temporary) =
        started_cgroup_transport(ManagerBehavior::default(), service).await?;
    let reads_before_binding = reads.load(Ordering::SeqCst);
    threshold.store(reads_before_binding + 1, Ordering::SeqCst);
    let error = transport
        .bind_cgroup_with_root(
            &verified,
            CgroupRoot::for_test(File::open(temporary.path())?),
        )
        .await
        .err()
        .ok_or("second ControlGroup read failure was accepted")?;
    assert!(matches!(
        error,
        SystemdTransientUnitTransportError::CgroupReadback(_)
    ));
    assert_eq!(reads.load(Ordering::SeqCst), reads_before_binding + 2);
    Ok(())
}

#[tokio::test]
async fn cgroup_binding_rejects_invalid_and_missing_kernel_paths() -> Result<(), Box<dyn Error>> {
    for path in ["/", "/system.slice/missing.service"] {
        let mut service = RecordingService::exact(expected_system_call_filter()?);
        service.control_group = path.to_owned();
        let (transport, _server, verified, temporary) =
            started_cgroup_transport(ManagerBehavior::default(), service).await?;
        let error = transport
            .bind_cgroup_with_root(
                &verified,
                CgroupRoot::for_test(File::open(temporary.path())?),
            )
            .await
            .err()
            .ok_or("invalid or missing cgroup was accepted")?;
        assert!(matches!(
            error,
            SystemdTransientUnitTransportError::CgroupKernel(
                AttemptCgroupError::InvalidPath | AttemptCgroupError::PathOpen(_)
            )
        ));
    }
    Ok(())
}

type StartedCgroupTransport = (
    SystemdTransientUnitTransport,
    zbus::Connection,
    SystemdVerifiedStart,
    tempfile::TempDir,
);

async fn started_cgroup_transport(
    behavior: ManagerBehavior,
    service: RecordingService,
) -> Result<StartedCgroupTransport, Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join(&CONTROL_GROUP_PATH[1..]);
    fs::create_dir_all(&directory)?;
    fs::write(directory.join("cgroup.events"), b"populated 0\nfrozen 0\n")?;
    let (transport, server) = transport(Arc::new(Mutex::new(None)), behavior, service).await?;
    let unit_name = TransientServiceUnitName::from_attempt_id([0x10; 16])?;
    let launch_request = request(LaunchMode::Local {
        host_service: descriptor()?,
    })?;
    let verified = transport.start(unit_name, launch_request).await?;
    Ok((transport, server, verified, temporary))
}

async fn transport(
    observed: Arc<Mutex<Option<ObservedStart>>>,
    behavior: ManagerBehavior,
    service: RecordingService,
) -> Result<(SystemdTransientUnitTransport, zbus::Connection), Box<dyn Error>> {
    let guid = Guid::generate();
    let (server_socket, client_socket) = Channel::pair();
    let subscribed = Arc::new(AtomicBool::new(false));
    let server = Builder::authenticated_socket(server_socket, guid.clone())?
        .p2p()
        .serve_at(
            MANAGER_PATH,
            RecordingManager {
                observed,
                subscribed,
                behavior,
            },
        )?
        .serve_at(UNIT_PATH, service)?
        .build();
    let client = Builder::authenticated_socket(client_socket, guid)?
        .p2p()
        .build();
    let (server, client) = tokio::join!(server, client);
    let server = server?;
    let client = client?;
    let transport =
        SystemdTransientUnitTransport::connect_with(std::future::ready(Ok(client))).await?;
    Ok((transport, server))
}

fn expected_system_call_filter() -> Result<Vec<String>, Box<dyn Error>> {
    SandboxSyscallSetV1::from_canonical_cbor(X86_64)
        .map(|authority| authority.expected_effective_names)
        .map_err(Into::into)
}

fn request(mode: LaunchMode) -> Result<TransientUnitRequest, Box<dyn Error>> {
    let authority = SandboxSyscallSetV1::from_canonical_cbor(X86_64)?;
    let filter = SystemCallFilter::from_selected_record(
        X86_64,
        authority.syscall_set_digest,
        SandboxArchitecture::X86_64,
    )?;
    let inputs = TransientUnitLaunchInputs::new(
        ActivatedRootDirectory::new("/run/pigloros/attempt-381/root")?,
        LauncherSource::new("/usr/lib/pigloros/release-launcher")?,
        mode,
        descriptor()?,
    );
    let limits = SystemdServiceLimits::from_effective_limits(&complete_effective_limits())?;
    Ok(TransientUnitRequest::compile(inputs, filter, limits))
}

fn complete_effective_limits() -> Vec<SandboxLimit> {
    (0..=16)
        .map(|limit_id| SandboxLimit {
            limit_id,
            value: match limit_id {
                0 => 134_217_728,
                1 => 0,
                2 => 16,
                3 => 500_000,
                4 => 5_000,
                5 => 64,
                6 => 4_096,
                _ => 1_000,
            },
        })
        .collect()
}

fn descriptor() -> Result<OwnedFd, std::io::Error> {
    File::open("/dev/null").map(|file| OwnedFd::from(StdOwnedFd::from(file)))
}

fn value() -> SystemdTransientUnitValue {
    SystemdTransientUnitValue::FileDescriptorStoreMax(1)
}

#[test]
fn owned_value_failure_is_classified() {
    let error = encode_property_with("TestProperty", value(), |_| {
        Err(zvariant::Error::IncorrectType)
    });
    assert_eq!(
        error.as_ref().err().map(ToString::to_string),
        Some("failed to serialize the typed transient-unit request".to_owned())
    );
}

#[test]
fn call_serialization_failure_is_classified() {
    let error = classify_call_error(zbus::Error::Variant(zvariant::Error::IncorrectType));
    assert_eq!(
        error.to_string(),
        "failed to serialize the typed transient-unit request"
    );
}

#[tokio::test]
async fn manager_proxy_failure_is_classified() -> Result<(), Box<dyn Error>> {
    let service = RecordingService::exact(expected_system_call_filter()?);
    let (transport, _server) = transport(
        Arc::new(Mutex::new(None)),
        ManagerBehavior::default(),
        service,
    )
    .await?;
    let proxy_error = zbus::Error::Failure("test proxy failure".to_owned());
    let name = TransientServiceUnitName("test.service".to_owned());
    let request = request(LaunchMode::AirGapped)?;
    let error = submit_and_verify(
        Err(proxy_error),
        Vec::new(),
        name,
        &request,
        &transport.connection,
    )
    .await;
    assert_eq!(
        error.as_ref().err().map(ToString::to_string),
        Some("failed to construct the typed systemd manager proxy".to_owned())
    );
    Ok(())
}

#[tokio::test]
async fn connection_and_manager_proxy_failures_are_classified() -> Result<(), Box<dyn Error>> {
    let connection_error = SystemdTransientUnitTransport::connect_with(std::future::ready(Err(
        zbus::Error::Failure("test connection failure".to_owned()),
    )))
    .await;
    assert!(matches!(
        connection_error,
        Err(SystemdTransientUnitTransportError::Connect(_))
    ));

    let proxy_error = SystemdTransientUnitTransport::subscribe_manager(Err(zbus::Error::Failure(
        "test proxy failure".to_owned(),
    )))
    .await;
    assert!(matches!(
        proxy_error,
        Err(SystemdTransientUnitTransportError::Proxy(_))
    ));
    Ok(())
}

#[tokio::test]
async fn preparation_and_encoding_failures_are_classified() -> Result<(), Box<dyn Error>> {
    let service = RecordingService::exact(expected_system_call_filter()?);
    let (transport, _server) = transport(
        Arc::new(Mutex::new(None)),
        ManagerBehavior::default(),
        service,
    )
    .await?;
    let prepared_error = transport
        .start_with_prepared(
            TransientServiceUnitName("prepared.service".to_owned()),
            request(LaunchMode::AirGapped)?,
            Err(zvariant::Error::IncorrectType),
        )
        .await;
    assert!(matches!(
        prepared_error,
        Err(SystemdTransientUnitTransportError::Serialization(_))
    ));

    let encoded_error = transport
        .start_with_encoded(
            TransientServiceUnitName("encoded.service".to_owned()),
            request(LaunchMode::AirGapped)?,
            Err(SystemdTransientUnitTransportError::Serialization(
                zvariant::Error::IncorrectType,
            )),
        )
        .await;
    assert!(matches!(
        encoded_error,
        Err(SystemdTransientUnitTransportError::Serialization(_))
    ));
    Ok(())
}

#[tokio::test]
async fn signal_subscription_and_stream_failures_are_classified() -> Result<(), Box<dyn Error>> {
    let service = RecordingService::exact(expected_system_call_filter()?);
    let (transport, _server) = transport(
        Arc::new(Mutex::new(None)),
        ManagerBehavior::default(),
        service,
    )
    .await?;
    let proxy = ManagerProxy::new(&transport.connection).await?;
    let request = request(LaunchMode::AirGapped)?;
    let subscription_error = submit_with_completions(
        &proxy,
        Err(zbus::Error::Failure(
            "test signal subscription failure".to_owned(),
        )),
        Vec::new(),
        TransientServiceUnitName("subscription.service".to_owned()),
        &request,
        &transport.connection,
    )
    .await;
    assert!(matches!(
        subscription_error,
        Err(SystemdTransientUnitTransportError::JobSignalSubscribe(_))
    ));

    let stop_subscription_error = stop_job_with_completions(
        &proxy,
        Err(zbus::Error::Failure(
            "test stop signal subscription failure".to_owned(),
        )),
        TransientServiceUnitName("pigloros-attempt-test.service".to_owned()),
    )
    .await;
    assert!(matches!(
        stop_subscription_error,
        Err(SystemdTransientUnitTransportError::JobSignalSubscribe(_))
    ));

    let job = SystemdStartJob(OwnedObjectPath::try_from(JOB_PATH)?);
    let mut ended = futures_util::stream::empty::<
        Result<SystemdJobCompletion, SystemdTransientUnitTransportError>,
    >();
    let ended_error =
        await_job_completion(&mut ended, job.as_str(), "ended.service".to_owned()).await;
    assert!(matches!(
        ended_error,
        Err(SystemdTransientUnitTransportError::JobSignalEnded)
    ));

    let signal_error = SystemdTransientUnitTransportError::JobSignal(zbus::Error::Failure(
        "test malformed signal".to_owned(),
    ));
    let mut malformed = futures_util::stream::once(std::future::ready(Err(signal_error)));
    let malformed_error =
        await_job_completion(&mut malformed, job.as_str(), "malformed.service".to_owned()).await;
    assert!(matches!(
        malformed_error,
        Err(SystemdTransientUnitTransportError::JobSignal(_))
    ));
    Ok(())
}

#[tokio::test]
async fn stop_job_rejects_ended_and_error_streams() -> Result<(), Box<dyn Error>> {
    let behavior = ManagerBehavior::default();
    let calls = Arc::clone(&behavior.control_calls);
    let service = RecordingService::exact(expected_system_call_filter()?);
    let (transport, _server) = transport(Arc::new(Mutex::new(None)), behavior, service).await?;
    let proxy = ManagerProxy::new(&transport.connection).await?;
    let name = TransientServiceUnitName::from_attempt_id([0x0c; 16])?;

    let mut ended = futures_util::stream::empty::<
        Result<SystemdJobCompletion, SystemdTransientUnitTransportError>,
    >();
    let ended_error = stop_job_with_stream(&proxy, &mut ended, name.clone()).await;
    assert!(matches!(
        ended_error,
        Err(SystemdTransientUnitTransportError::JobSignalEnded)
    ));

    let signal_error = SystemdTransientUnitTransportError::JobSignal(zbus::Error::Failure(
        "test malformed stop signal".to_owned(),
    ));
    let mut malformed = futures_util::stream::once(std::future::ready(Err(signal_error)));
    let malformed_error = stop_job_with_stream(&proxy, &mut malformed, name.clone()).await;
    assert!(matches!(
        malformed_error,
        Err(SystemdTransientUnitTransportError::JobSignal(_))
    ));

    let expected = ObservedControl::Stop {
        name: name.as_str().to_owned(),
        mode: "replace".to_owned(),
    };
    assert_eq!(
        calls.lock().map_err(|error| error.to_string())?.as_slice(),
        &[expected.clone(), expected]
    );
    Ok(())
}

#[tokio::test]
async fn stop_and_kill_proxy_failures_are_classified() {
    let stop = stop_job_with_proxy(
        Err(zbus::Error::Failure("test stop proxy failure".to_owned())),
        TransientServiceUnitName("pigloros-attempt-test.service".to_owned()),
    )
    .await;
    assert!(matches!(
        stop,
        Err(SystemdTransientUnitTransportError::Proxy(_))
    ));

    let kill = force_kill_with_proxy(
        Err(zbus::Error::Failure("test kill proxy failure".to_owned())),
        TransientServiceUnitName("pigloros-attempt-test.service".to_owned()),
    )
    .await;
    assert!(matches!(
        kill,
        Err(SystemdTransientUnitTransportError::Proxy(_))
    ));
}

#[test]
fn malformed_signal_arguments_are_classified() {
    let result = decode_job_completion(Err(zbus::Error::Failure(
        "test malformed arguments".to_owned(),
    )));
    assert!(matches!(
        result,
        Err(SystemdTransientUnitTransportError::JobSignal(_))
    ));
}

#[tokio::test]
async fn service_proxy_build_failure_is_classified() -> Result<(), Box<dyn Error>> {
    let request = request(LaunchMode::AirGapped)?;
    let result = verify_service(
        Err(zbus::Error::Failure(
            "test service proxy failure".to_owned(),
        )),
        TransientServiceUnitName("service-proxy.service".to_owned()),
        SystemdStartJob(OwnedObjectPath::try_from(JOB_PATH)?),
        OwnedObjectPath::try_from(UNIT_PATH)?,
        &request,
    )
    .await;
    assert!(matches!(
        result,
        Err(SystemdTransientUnitTransportError::ServiceProxy(_))
    ));
    Ok(())
}
