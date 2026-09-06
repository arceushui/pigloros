//! THROWAWAY PROTOTYPE: hosted evidence only for ADR-069 control primitives.
//! It is deliberately not production provider code and must never be promoted
//! by copying it into the workspace.

use futures_util::TryStreamExt as _;
use netlink_packet_core::{
    Emitable as _, NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE,
    NLM_F_EXCL, NLM_F_MATCH, NLM_F_REQUEST, NLM_F_ROOT,
};
use netlink_packet_netfilter::nftables::{
    ChainAttribute, ChainMessage, Cmp, DataAttribute, ExpressionAttribute, Expressions, GenMessage,
    Hook, Immediate, InetHookNumber, ListAttribute, Meta, MetaKey, NfTablesMessage, Operator,
    Payload, Register, RuleAttribute, RuleMessage, TableAttribute, TableMessage, Verdict,
    VerdictAttribute,
};
use netlink_packet_netfilter::{
    none::ControlMessage, NetfilterHeader, NetfilterMessage, NetfilterMessageInner,
    NetfilterProtoFamily,
};
use netlink_sys::{protocols::NETLINK_NETFILTER, Socket, SocketAddr};
use nix::sched::{unshare, CloneFlags};
use rtnetlink::{new_connection, LinkDummy};
use std::{
    fs::File,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    os::unix::fs::MetadataExt as _,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use zbus::zvariant::{OwnedValue, Type, Value};

const CONTROL_PLANE_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_MEMORY_MAX: u64 = 128 * 1024 * 1024;
const PROBE_TASKS_MAX: u64 = 16;
const PROBE_CPU_QUOTA_PER_SECOND_US: u64 = 500_000;
const PROBE_IO_WEIGHT: u64 = 100;

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.iter().any(|argument| argument == "--leaf") {
        loop {
            thread::park();
        }
    }
    if arguments
        .iter()
        .any(|argument| argument == "--attempt-worker")
    {
        run_attempt_worker();
        return;
    }
    if arguments
        .iter()
        .any(|argument| argument == "--normal-worker")
    {
        run_normal_worker();
        return;
    }
    if arguments
        .iter()
        .any(|argument| argument == "--namespace-worker")
    {
        run_namespace_worker(&arguments);
        return;
    }
    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        eprintln!("runtime-unavailable");
        return;
    };
    runtime.block_on(run(arguments));
}

async fn run(arguments: Vec<String>) {
    let privileged = arguments.iter().any(|argument| argument == "--privileged");
    let network_isolation =
        if privileged && arguments.iter().any(|argument| argument == "--offline") {
            isolate_network()
        } else {
            "not-requested"
        };
    let attempt_id = attempt_id(&arguments);
    if arguments
        .iter()
        .any(|argument| argument == "--cleanup-sample")
    {
        probe_cleanup_sample(&attempt_id, cleanup_mode(&arguments), network_isolation).await;
        return;
    }
    if arguments
        .iter()
        .any(|argument| argument == "--cgroup-limits")
    {
        probe_cgroup_limits(&attempt_id, network_isolation).await;
        return;
    }
    if arguments
        .iter()
        .any(|argument| argument == "--broker-death")
    {
        probe_broker_death(&attempt_id, network_isolation).await;
        return;
    }
    if arguments
        .iter()
        .any(|argument| argument == "--check-broker-clean")
    {
        check_broker_units_absent(&attempt_id).await;
        return;
    }
    if arguments
        .iter()
        .any(|argument| argument == "--inject-orphan")
    {
        inject_reconciliation_orphan(&attempt_id, network_isolation).await;
        return;
    }
    if arguments
        .iter()
        .any(|argument| argument == "--reconcile-orphan")
    {
        reconcile_orphan(&attempt_id, network_isolation).await;
        return;
    }
    if arguments
        .iter()
        .any(|argument| argument == "--check-orphan-clean")
    {
        check_orphan_unit_absent(&attempt_id).await;
        return;
    }
    let dbus = probe_systemd().await;
    let route = probe_route_netlink().await;
    let nftables_packet_bytes = encode_nftables_probe();
    println!("systemd={dbus};route_netlink={route};nftables_packet_bytes={nftables_packet_bytes}");
    if privileged {
        let started = Instant::now();
        let systemd_started = Instant::now();
        let systemd_lifecycle = probe_transient_slice(&attempt_id).await;
        let systemd_elapsed_us = systemd_started.elapsed().as_micros();
        let route_started = Instant::now();
        let route_lifecycle = probe_dummy_link_lifecycle(&attempt_id).await;
        let route_elapsed_us = route_started.elapsed().as_micros();
        let nftables_read_started = Instant::now();
        let nftables_read = probe_nftables_read();
        let nftables_read_elapsed_us = nftables_read_started.elapsed().as_micros();
        let nftables_atomic_started = Instant::now();
        let nftables_atomic = probe_nftables_atomic_table(&attempt_id);
        let nftables_atomic_elapsed_us = nftables_atomic_started.elapsed().as_micros();
        let namespace_started = Instant::now();
        let namespace = probe_namespace_descriptor_lifecycle();
        let namespace_elapsed_us = namespace_started.elapsed().as_micros();
        let dm_verity = probe_dm_verity_capability();
        println!(
            "attempt={attempt_id};network_isolation={network_isolation};transient_slice={systemd_lifecycle};transient_slice_us={systemd_elapsed_us};dummy_link={route_lifecycle};dummy_link_us={route_elapsed_us};nftables_read={nftables_read};nftables_read_us={nftables_read_elapsed_us};nftables_atomic={nftables_atomic};nftables_atomic_us={nftables_atomic_elapsed_us};namespace_descriptor={namespace};namespace_us={namespace_elapsed_us};dm_verity={dm_verity};total_us={}",
            started.elapsed().as_micros()
        );
    }
}

fn run_attempt_worker() {
    let mut signal = [0_u8; 1];
    if std::io::stdin().read_exact(&mut signal).is_err() {
        return;
    }
    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    let Ok(leaf) = Command::new(executable)
        .arg("--leaf")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return;
    };
    println!(
        "worker-ready;worker_pid={};leaf_pid={}",
        std::process::id(),
        leaf.id()
    );
    let _ = std::io::stdout().flush();
    loop {
        thread::park();
    }
}

fn run_normal_worker() {
    let mut signal = [0_u8; 1];
    if std::io::stdin().read_exact(&mut signal).is_err() {
        return;
    }
    println!("worker-ready;worker_pid={}", std::process::id());
    let _ = std::io::stdout().flush();
}

fn run_namespace_worker(arguments: &[String]) {
    let kind = argument_value(arguments, "--namespace-kind").unwrap_or("all");
    let Some(namespaces) = namespace_flags(kind) else {
        println!("namespace-worker-rejected;kind={kind};reason=unknown-kind");
        return;
    };
    if let Err(error) = unshare(namespaces) {
        println!("namespace-worker-rejected;kind={kind};reason={error}");
        return;
    }
    let Ok(executable) = std::env::current_exe() else {
        println!("namespace-worker-rejected");
        return;
    };
    let Ok(mut leaf) = Command::new(executable)
        .arg("--leaf")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        println!("namespace-worker-rejected");
        return;
    };
    println!(
        "namespace-worker-ready;worker_pid={};leaf_pid={}",
        std::process::id(),
        leaf.id()
    );
    let _ = std::io::stdout().flush();
    let mut release = [0_u8; 1];
    let _ = std::io::stdin().read_exact(&mut release);
    let _ = leaf.kill();
    let _ = leaf.wait();
}

fn namespace_flags(kind: &str) -> Option<CloneFlags> {
    match kind {
        "all" => Some(
            CloneFlags::CLONE_NEWNS
                | CloneFlags::CLONE_NEWPID
                | CloneFlags::CLONE_NEWIPC
                | CloneFlags::CLONE_NEWUTS
                | CloneFlags::CLONE_NEWUSER
                | CloneFlags::CLONE_NEWNET,
        ),
        "mnt" => Some(CloneFlags::CLONE_NEWNS),
        "pid" => Some(CloneFlags::CLONE_NEWPID),
        "ipc" => Some(CloneFlags::CLONE_NEWIPC),
        "uts" => Some(CloneFlags::CLONE_NEWUTS),
        "user" => Some(CloneFlags::CLONE_NEWUSER),
        "net" => Some(CloneFlags::CLONE_NEWNET),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CleanupMode {
    Normal,
    Cancel,
    Forced,
}

impl CleanupMode {
    const fn name(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Cancel => "cancel",
            Self::Forced => "forced",
        }
    }

    const fn worker_argument(self) -> &'static str {
        match self {
            Self::Normal => "--normal-worker",
            Self::Cancel | Self::Forced => "--attempt-worker",
        }
    }
}

fn cleanup_mode(arguments: &[String]) -> CleanupMode {
    match argument_value(arguments, "--cleanup-mode") {
        Some("cancel") => CleanupMode::Cancel,
        Some("forced") => CleanupMode::Forced,
        _ => CleanupMode::Normal,
    }
}

async fn probe_broker_death(attempt_id: &str, network_isolation: &str) {
    let Ok(connection) = zbus::Connection::system().await else {
        println!("broker-setup-rejected;reason=dbus-unavailable");
        return;
    };
    let Ok(proxy) = zbus_systemd::systemd1::ManagerProxy::new(&connection).await else {
        println!("broker-setup-rejected;reason=manager-unavailable");
        return;
    };
    let broker_unit = format!("pigloros-broker-{attempt_id}.scope");
    let attempt_unit = format!("pigloros-attempt-{attempt_id}.scope");
    if start_transient_scope(&proxy, &broker_unit, &[std::process::id()], &[])
        .await
        .is_err()
    {
        println!("broker-setup-rejected;reason=broker-scope");
        return;
    }

    let Ok((_worker, worker_line)) = spawn_scoped_worker(
        &proxy,
        &attempt_unit,
        std::slice::from_ref(&broker_unit),
        "--attempt-worker",
    )
    .await
    else {
        println!("broker-setup-rejected;reason=attempt-worker");
        return;
    };
    println!(
        "broker-ready;network_isolation={network_isolation};broker_pid={};broker_unit={broker_unit};attempt_unit={attempt_unit};{}",
        std::process::id(),
        worker_line.trim_end()
    );
    let _ = std::io::stdout().flush();
    std::future::pending::<()>().await;
}

async fn spawn_scoped_worker(
    proxy: &zbus_systemd::systemd1::ManagerProxy<'_>,
    unit: &str,
    binds_to: &[String],
    worker_argument: &str,
) -> Result<(std::process::Child, String), ()> {
    let executable = std::env::current_exe().map_err(|_| ())?;
    let mut worker = Command::new(executable)
        .arg(worker_argument)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())?;
    if start_transient_scope(proxy, unit, &[worker.id()], binds_to)
        .await
        .is_err()
        || !wait_for_unit_cgroup(worker.id(), unit)
    {
        let _ = worker.kill();
        return Err(());
    }
    let Some(mut worker_stdin) = worker.stdin.take() else {
        let _ = worker.kill();
        return Err(());
    };
    if worker_stdin.write_all(&[1]).is_err() {
        let _ = worker.kill();
        return Err(());
    }
    drop(worker_stdin);
    let Some(worker_stdout) = worker.stdout.take() else {
        let _ = worker.kill();
        return Err(());
    };
    let mut worker_line = String::new();
    if BufReader::new(worker_stdout)
        .read_line(&mut worker_line)
        .is_err()
        || !worker_line.starts_with("worker-ready;")
    {
        let _ = worker.kill();
        return Err(());
    }
    Ok((worker, worker_line))
}

async fn inject_reconciliation_orphan(attempt_id: &str, network_isolation: &str) {
    let Ok(connection) = zbus::Connection::system().await else {
        println!("orphan-setup-rejected;reason=dbus-unavailable");
        return;
    };
    let Ok(proxy) = zbus_systemd::systemd1::ManagerProxy::new(&connection).await else {
        println!("orphan-setup-rejected;reason=manager-unavailable");
        return;
    };
    let orphan_unit = format!("pigloros-orphan-{attempt_id}.scope");
    let Ok((_worker, worker_line)) =
        spawn_scoped_worker(&proxy, &orphan_unit, &[], "--attempt-worker").await
    else {
        println!("orphan-setup-rejected;reason=attempt-worker");
        return;
    };
    println!(
        "orphan-ready;network_isolation={network_isolation};orphan_unit={orphan_unit};{}",
        worker_line.trim_end()
    );
}

async fn reconcile_orphan(attempt_id: &str, network_isolation: &str) {
    let Ok(connection) = zbus::Connection::system().await else {
        println!("orphan-reconcile-rejected;reason=dbus-unavailable");
        return;
    };
    let Ok(proxy) = zbus_systemd::systemd1::ManagerProxy::new(&connection).await else {
        println!("orphan-reconcile-rejected;reason=manager-unavailable");
        return;
    };
    let orphan_unit = format!("pigloros-orphan-{attempt_id}.scope");
    match proxy
        .stop_unit(orphan_unit.clone(), "replace".to_owned())
        .await
    {
        Ok(_) => println!(
            "orphan-reconcile-requested;network_isolation={network_isolation};orphan_unit={orphan_unit}"
        ),
        Err(_) if proxy.get_unit(orphan_unit).await.is_err() => {
            println!("orphan-reconcile-complete;unit=already-absent");
        }
        Err(_) => println!("orphan-reconcile-rejected;reason=stop-unit"),
    }
}

async fn probe_cleanup_sample(attempt_id: &str, mode: CleanupMode, network_isolation: &str) {
    let Ok(connection) = zbus::Connection::system().await else {
        println!("cleanup-sample-rejected;reason=dbus-unavailable");
        return;
    };
    let Ok(proxy) = zbus_systemd::systemd1::ManagerProxy::new(&connection).await else {
        println!("cleanup-sample-rejected;reason=manager-unavailable");
        return;
    };
    let unit = format!("pigloros-cleanup-{}-{attempt_id}.scope", mode.name());
    let launch_started = Instant::now();
    let Ok((mut worker, _worker_line)) =
        spawn_scoped_worker(&proxy, &unit, &[], mode.worker_argument()).await
    else {
        println!("cleanup-sample-rejected;reason=worker-launch");
        return;
    };
    let launch_us = launch_started.elapsed().as_micros();
    let cleanup_started = Instant::now();
    match mode {
        CleanupMode::Normal => {}
        CleanupMode::Cancel => {
            if proxy
                .stop_unit(unit.clone(), "replace".to_owned())
                .await
                .is_err()
            {
                let _ = worker.kill();
                println!("cleanup-sample-rejected;reason=stop-unit");
                return;
            }
        }
        CleanupMode::Forced => {
            if proxy
                .kill_unit(unit.clone(), "all".to_owned(), 19)
                .await
                .is_err()
            {
                let _ = worker.kill();
                println!("cleanup-sample-rejected;reason=stop-signal");
                return;
            }
            thread::sleep(Duration::from_millis(100));
            if proxy
                .kill_unit(unit.clone(), "all".to_owned(), 9)
                .await
                .is_err()
            {
                let _ = worker.kill();
                println!("cleanup-sample-rejected;reason=kill-signal");
                return;
            }
            let stop_result = proxy.stop_unit(unit.clone(), "replace".to_owned()).await;
            if stop_result.is_err() && proxy.get_unit(unit.clone()).await.is_ok() {
                let _ = worker.kill();
                println!("cleanup-sample-rejected;reason=forced-stop");
                return;
            }
        }
    }
    if worker.wait().is_err() {
        println!("cleanup-sample-rejected;reason=worker-wait");
        return;
    }
    let unit_absent = wait_for_unit_absent(&proxy, &unit).await;
    let cleanup_us = cleanup_started.elapsed().as_micros();
    println!(
        "cleanup_sample={};attempt={attempt_id};network_isolation={network_isolation};launch_us={launch_us};cleanup_us={cleanup_us};unit_absent={unit_absent}",
        mode.name()
    );
}

async fn probe_cgroup_limits(attempt_id: &str, network_isolation: &str) {
    let Ok(connection) = zbus::Connection::system().await else {
        println!("cgroup-limits-rejected;reason=dbus-unavailable");
        return;
    };
    let Ok(proxy) = zbus_systemd::systemd1::ManagerProxy::new(&connection).await else {
        println!("cgroup-limits-rejected;reason=manager-unavailable");
        return;
    };
    let unit = format!("pigloros-limits-{attempt_id}.scope");
    let Ok((mut worker, _)) = spawn_scoped_worker(&proxy, &unit, &[], "--attempt-worker").await
    else {
        println!("cgroup-limits-rejected;reason=worker-launch");
        return;
    };
    let applied = cgroup_limits_match(worker.id());
    let stop_requested = proxy
        .stop_unit(unit.clone(), "replace".to_owned())
        .await
        .is_ok();
    let worker_reaped = worker.wait().is_ok();
    let unit_absent = wait_for_unit_absent(&proxy, &unit).await;
    println!(
        "cgroup_limits={};network_isolation={network_isolation};stop_requested={stop_requested};worker_reaped={worker_reaped};unit_absent={unit_absent}",
        if applied {
            "memory-cpu-pids-io-read-back-ok"
        } else {
            "read-back-mismatch"
        }
    );
}

fn cgroup_limits_match(pid: u32) -> bool {
    let Some(relative_path) = process_cgroup_path(pid) else {
        return false;
    };
    let cgroup = std::path::Path::new("/sys/fs/cgroup").join(relative_path);
    let memory_matches = read_trimmed(cgroup.join("memory.max"))
        .is_some_and(|value| value == PROBE_MEMORY_MAX.to_string());
    let tasks_match = read_trimmed(cgroup.join("pids.max"))
        .is_some_and(|value| value == PROBE_TASKS_MAX.to_string());
    let io_matches = read_trimmed(cgroup.join("io.weight"))
        .is_some_and(|value| value == format!("default {PROBE_IO_WEIGHT}"));
    let cpu_matches = read_trimmed(cgroup.join("cpu.max")).is_some_and(|value| {
        let mut fields = value.split_whitespace();
        let quota = fields.next().and_then(|field| field.parse::<u64>().ok());
        let period = fields.next().and_then(|field| field.parse::<u64>().ok());
        matches!((quota, period), (Some(quota), Some(period)) if quota * 2 == period)
    });
    memory_matches && tasks_match && io_matches && cpu_matches
}

fn process_cgroup_path(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()?
        .lines()
        .find_map(|line| line.split_once("::").map(|(_, path)| path.to_owned()))
}

fn read_trimmed(path: impl AsRef<std::path::Path>) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
}

async fn wait_for_unit_absent(
    proxy: &zbus_systemd::systemd1::ManagerProxy<'_>,
    unit: &str,
) -> bool {
    for _ in 0..100 {
        if proxy.get_unit(unit.to_owned()).await.is_err() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

fn wait_for_unit_cgroup(pid: u32, unit: &str) -> bool {
    let expected_suffix = format!("/{unit}");
    for _ in 0..100 {
        let attached =
            std::fs::read_to_string(format!("/proc/{pid}/cgroup")).is_ok_and(|cgroups| {
                cgroups
                    .lines()
                    .filter_map(|line| line.split_once("::"))
                    .any(|(_, path)| path.ends_with(&expected_suffix))
            });
        if attached {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    false
}

async fn start_transient_scope(
    proxy: &zbus_systemd::systemd1::ManagerProxy<'_>,
    name: &str,
    pids: &[u32],
    binds_to: &[String],
) -> Result<(), ()> {
    let mut properties = vec![
        (
            "Description".to_owned(),
            owned_value("PiglorOS #211 probe")?,
        ),
        ("PIDs".to_owned(), owned_value(pids.to_vec())?),
        ("KillMode".to_owned(), owned_value("control-group")?),
        ("SendSIGKILL".to_owned(), OwnedValue::from(true)),
        (
            "TimeoutStopUSec".to_owned(),
            OwnedValue::from(1_000_000_u64),
        ),
        ("MemoryMax".to_owned(), OwnedValue::from(PROBE_MEMORY_MAX)),
        ("TasksMax".to_owned(), OwnedValue::from(PROBE_TASKS_MAX)),
        (
            "CPUQuotaPerSecUSec".to_owned(),
            OwnedValue::from(PROBE_CPU_QUOTA_PER_SECOND_US),
        ),
        ("IOWeight".to_owned(), OwnedValue::from(PROBE_IO_WEIGHT)),
    ];
    if !binds_to.is_empty() {
        properties.push(("BindsTo".to_owned(), owned_value(binds_to.to_vec())?));
        properties.push(("After".to_owned(), owned_value(binds_to.to_vec())?));
    }
    proxy
        .start_transient_unit(name.to_owned(), "fail".to_owned(), properties, vec![])
        .await
        .map(|_| ())
        .map_err(|_| ())
}

fn owned_value<T>(value: T) -> Result<OwnedValue, ()>
where
    T: Type + Into<Value<'static>>,
{
    Value::new(value).try_into_owned().map_err(|_| ())
}

async fn check_broker_units_absent(attempt_id: &str) {
    let Ok(connection) = zbus::Connection::system().await else {
        println!("broker-cleanliness-unproven;reason=dbus-unavailable");
        return;
    };
    let Ok(proxy) = zbus_systemd::systemd1::ManagerProxy::new(&connection).await else {
        println!("broker-cleanliness-unproven;reason=manager-unavailable");
        return;
    };
    let broker_unit = format!("pigloros-broker-{attempt_id}.scope");
    let attempt_unit = format!("pigloros-attempt-{attempt_id}.scope");
    let broker_absent = proxy.get_unit(broker_unit).await.is_err();
    let attempt_absent = proxy.get_unit(attempt_unit).await.is_err();
    if broker_absent && attempt_absent {
        println!("broker-clean;broker_unit=absent;attempt_unit=absent");
    } else {
        println!(
            "broker-residual;broker_unit={};attempt_unit={}",
            if broker_absent { "absent" } else { "loaded" },
            if attempt_absent { "absent" } else { "loaded" }
        );
    }
}

async fn check_orphan_unit_absent(attempt_id: &str) {
    let Ok(connection) = zbus::Connection::system().await else {
        println!("orphan-cleanliness-unproven;reason=dbus-unavailable");
        return;
    };
    let Ok(proxy) = zbus_systemd::systemd1::ManagerProxy::new(&connection).await else {
        println!("orphan-cleanliness-unproven;reason=manager-unavailable");
        return;
    };
    let orphan_unit = format!("pigloros-orphan-{attempt_id}.scope");
    if proxy.get_unit(orphan_unit).await.is_err() {
        println!("orphan-clean;orphan_unit=absent");
    } else {
        println!("orphan-residual;orphan_unit=loaded");
    }
}

fn attempt_id(arguments: &[String]) -> String {
    if let Some(value) = argument_value(arguments, "--attempt-id") {
        let filtered: String = value
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(11)
            .collect();
        if !filtered.is_empty() {
            return filtered;
        }
    }
    std::process::id().to_string()
}

fn argument_value<'a>(arguments: &'a [String], name: &str) -> Option<&'a str> {
    arguments
        .windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].as_str())
}

fn isolate_network() -> &'static str {
    let Ok(host_inode) = File::open("/proc/1/ns/net")
        .and_then(|namespace| namespace.metadata())
        .map(|metadata| metadata.ino())
    else {
        return "host-namespace-unreadable";
    };
    if unshare(CloneFlags::CLONE_NEWNET).is_err() {
        return "unshare-rejected";
    }
    match File::open("/proc/thread-self/ns/net")
        .and_then(|namespace| namespace.metadata())
        .map(|metadata| metadata.ino())
    {
        Ok(current_inode) if current_inode != host_inode => "isolated-no-host-net",
        _ => "isolation-unproven",
    }
}

async fn probe_systemd() -> &'static str {
    let Ok(Ok(connection)) =
        tokio::time::timeout(CONTROL_PLANE_PROBE_TIMEOUT, zbus::Connection::system()).await
    else {
        return "unavailable";
    };
    let Ok(Ok(proxy)) = tokio::time::timeout(
        CONTROL_PLANE_PROBE_TIMEOUT,
        zbus_systemd::systemd1::ManagerProxy::new(&connection),
    )
    .await
    else {
        return "unavailable";
    };
    match tokio::time::timeout(
        CONTROL_PLANE_PROBE_TIMEOUT,
        proxy.get_unit("-.mount".to_owned()),
    )
    .await
    {
        Err(_) => "typed-get-unit-timeout",
        Ok(Ok(_)) => "typed-get-unit-ok",
        Ok(Err(_)) => "typed-get-unit-rejected",
    }
}

async fn probe_route_netlink() -> &'static str {
    let Ok((connection, handle, _)) = new_connection() else {
        return "unavailable";
    };
    tokio::spawn(connection);
    let mut links = handle.link().get().execute();
    match tokio::time::timeout(CONTROL_PLANE_PROBE_TIMEOUT, links.try_next()).await {
        Err(_) => "typed-link-read-timeout",
        Ok(Ok(Some(_))) => "typed-link-read-ok",
        Ok(Ok(None)) => "typed-link-read-empty",
        Ok(Err(_)) => "typed-link-read-rejected",
    }
}

fn encode_nftables_probe() -> usize {
    let payload = NfTablesMessage::GetGen(GenMessage { attributes: vec![] });
    let message = NetfilterMessage::new(
        NetfilterHeader::new(NetfilterProtoFamily::Unspec, 0, 0),
        payload,
    );
    let mut message = NetlinkMessage::from(message);
    message.finalize();
    let mut bytes = vec![0; message.buffer_len()];
    message.emit(&mut bytes);
    bytes.len()
}

async fn probe_transient_slice(attempt_id: &str) -> &'static str {
    let Ok(connection) = zbus::Connection::system().await else {
        return "unavailable";
    };
    let Ok(proxy) = zbus_systemd::systemd1::ManagerProxy::new(&connection).await else {
        return "unavailable";
    };
    let name = format!("pigloros-probe-{attempt_id}.slice");
    if proxy
        .start_transient_unit(name.clone(), "fail".to_owned(), vec![], vec![])
        .await
        .is_err()
    {
        return "create-rejected";
    }
    match proxy.stop_unit(name.clone(), "replace".to_owned()).await {
        Ok(_) => "typed-create-stop-ok",
        Err(_) if proxy.get_unit(name).await.is_err() => "typed-create-auto-cleanup-ok",
        Err(_) => "stop-rejected-unit-still-loaded",
    }
}

async fn probe_dummy_link_lifecycle(attempt_id: &str) -> &'static str {
    let Ok((connection, handle, _)) = new_connection() else {
        return "unavailable";
    };
    tokio::spawn(connection);
    let name = format!("pgl{attempt_id}");
    if handle
        .link()
        .add(LinkDummy::new(&name).build())
        .execute()
        .await
        .is_err()
    {
        return "create-rejected";
    }
    let mut links = handle.link().get().match_name(name).execute();
    let Ok(Some(link)) = links.try_next().await else {
        return "read-back-failed";
    };
    match handle.link().del(link.header.index).execute().await {
        Ok(()) => "typed-create-read-delete-ok",
        Err(_) => "delete-rejected",
    }
}

fn probe_nftables_read() -> &'static str {
    let Ok(mut socket) = Socket::new(NETLINK_NETFILTER) else {
        return "unavailable";
    };
    if socket.bind_auto().is_err() || socket.connect(&SocketAddr::new(0, 0)).is_err() {
        return "connect-rejected";
    }
    let payload = NfTablesMessage::GetGen(GenMessage { attributes: vec![] });
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST;
    let mut message = NetlinkMessage::new(
        header,
        NetlinkPayload::from(NetfilterMessage::new(
            NetfilterHeader::new(NetfilterProtoFamily::Unspec, 0, 0),
            payload,
        )),
    );
    message.finalize();
    let mut bytes = vec![0; message.buffer_len()];
    message.serialize(&mut bytes);
    if socket.send(&bytes, 0).is_err() {
        return "send-rejected";
    }
    let mut response = vec![0; 4096];
    match socket.recv(&mut &mut response[..], 0) {
        Ok(size) if size > 0 => "typed-read-ok",
        _ => "read-rejected",
    }
}

fn probe_nftables_atomic_table(attempt_id: &str) -> &'static str {
    let Ok(mut socket) = Socket::new(NETLINK_NETFILTER) else {
        return "socket-unavailable";
    };
    if socket.bind_auto().is_err() || socket.connect(&SocketAddr::new(0, 0)).is_err() {
        return "connect-rejected";
    }

    let table_name = format!("pgl211_{attempt_id}");
    let chain_name = "broker_output".to_owned();
    let ownership = format!("pigloros:#211:{attempt_id}:throwaway");
    let table = NfTablesMessage::NewTable(TableMessage {
        attributes: vec![
            TableAttribute::Name(table_name.clone()),
            TableAttribute::UserData(ownership.as_bytes().to_vec()),
        ],
    });
    let chain = NfTablesMessage::NewChain(ChainMessage {
        attributes: vec![
            ChainAttribute::Table(table_name.clone()),
            ChainAttribute::Name(chain_name.clone()),
            ChainAttribute::Policy(0),
            ChainAttribute::Type("filter".to_owned()),
            ChainAttribute::Hook(vec![
                Hook::Number(InetHookNumber::LocalOut.into()),
                Hook::Priority(0),
            ]),
            ChainAttribute::UserData(ownership.as_bytes().to_vec()),
        ],
    });
    let rule = NfTablesMessage::NewRule(RuleMessage {
        attributes: vec![
            RuleAttribute::Table(table_name.clone()),
            RuleAttribute::Chain(chain_name.clone()),
            RuleAttribute::Expressions(broker_allow_expressions()),
            RuleAttribute::UserData(ownership.as_bytes().to_vec()),
        ],
    });
    let create_flags = NLM_F_CREATE | NLM_F_EXCL;
    if nftables_batch_request(
        &socket,
        vec![
            (table, create_flags),
            (chain, create_flags),
            (rule, create_flags),
        ],
        1,
    )
    .is_err()
    {
        return "install-rejected";
    }

    let table_read_back = NfTablesMessage::GetTable(TableMessage {
        attributes: vec![TableAttribute::Name(table_name.clone())],
    });
    let table_matches = nftables_request(&socket, table_read_back, 0, 10)
        .is_ok_and(|reply| table_reply_matches(&reply, &table_name, ownership.as_bytes()));
    let chain_read_back = NfTablesMessage::GetChain(ChainMessage {
        attributes: vec![
            ChainAttribute::Table(table_name.clone()),
            ChainAttribute::Name(chain_name.clone()),
        ],
    });
    let chain_matches = nftables_request(&socket, chain_read_back, 0, 11).is_ok_and(|reply| {
        chain_reply_matches(&reply, &table_name, &chain_name, ownership.as_bytes())
    });
    let rule_read_back = NfTablesMessage::GetRule(RuleMessage {
        attributes: vec![
            RuleAttribute::Table(table_name.clone()),
            RuleAttribute::Chain(chain_name.clone()),
        ],
    });
    let rule_matches = nftables_dump_request(&socket, rule_read_back, 12).is_ok_and(|replies| {
        replies
            .iter()
            .any(|reply| rule_reply_matches(reply, &table_name, &chain_name, ownership.as_bytes()))
    });

    let delete = NfTablesMessage::DeleteTable(TableMessage {
        attributes: vec![TableAttribute::Name(table_name)],
    });
    let deleted = nftables_batch_request(&socket, vec![(delete, 0)], 20).is_ok();

    match (table_matches && chain_matches && rule_matches, deleted) {
        (true, true) => "typed-default-drop-allow-read-back-delete-ok",
        (false, true) => "policy-read-back-mismatch-cleaned",
        (_, false) => "delete-rejected-needs-reconcile",
    }
}

fn broker_allow_expressions() -> Vec<ListAttribute<ExpressionAttribute>> {
    vec![
        Expressions::Meta(vec![
            Meta::Key(MetaKey::Nfproto),
            Meta::DestinationRegister(Register::Reg1),
        ])
        .into(),
        Expressions::Cmp(vec![
            Cmp::SourceRegister(Register::Reg1),
            Cmp::Op(Operator::Equal),
            Cmp::Data(DataAttribute::Value(vec![2])),
        ])
        .into(),
        Expressions::Payload(vec![
            Payload::DestinationRegister(Register::Reg1),
            Payload::Base(1),
            Payload::Offset(16),
            Payload::Len(4),
        ])
        .into(),
        Expressions::Cmp(vec![
            Cmp::SourceRegister(Register::Reg1),
            Cmp::Op(Operator::Equal),
            Cmp::Data(DataAttribute::Value(vec![127, 0, 0, 1])),
        ])
        .into(),
        Expressions::Meta(vec![
            Meta::Key(MetaKey::L4Proto),
            Meta::DestinationRegister(Register::Reg1),
        ])
        .into(),
        Expressions::Cmp(vec![
            Cmp::SourceRegister(Register::Reg1),
            Cmp::Op(Operator::Equal),
            Cmp::Data(DataAttribute::Value(vec![6])),
        ])
        .into(),
        Expressions::Payload(vec![
            Payload::DestinationRegister(Register::Reg1),
            Payload::Base(2),
            Payload::Offset(2),
            Payload::Len(2),
        ])
        .into(),
        Expressions::Cmp(vec![
            Cmp::SourceRegister(Register::Reg1),
            Cmp::Op(Operator::Equal),
            Cmp::Data(DataAttribute::Value(vec![0x01, 0xbb])),
        ])
        .into(),
        Expressions::Immediate(vec![
            Immediate::DestinationRegister(Register::Verdict),
            Immediate::Data(DataAttribute::Verdict(vec![VerdictAttribute::Code(
                Verdict::Other(1),
            )])),
        ])
        .into(),
    ]
}

fn nftables_batch_request(
    socket: &Socket,
    operations: Vec<(NfTablesMessage, u16)>,
    sequence_number: u32,
) -> Result<(), ()> {
    const NFTABLES_SUBSYSTEM: u16 = 10;

    let begin = serialize_netfilter_message(
        NetfilterMessage::new(
            NetfilterHeader::new(NetfilterProtoFamily::Unspec, 0, NFTABLES_SUBSYSTEM),
            ControlMessage::BatchBegin,
        ),
        NLM_F_REQUEST,
        sequence_number,
    );
    let operation_count = u32::try_from(operations.len()).map_err(|_| ())?;
    let end = serialize_netfilter_message(
        NetfilterMessage::new(
            NetfilterHeader::new(NetfilterProtoFamily::Unspec, 0, NFTABLES_SUBSYSTEM),
            ControlMessage::BatchEnd,
        ),
        NLM_F_REQUEST,
        sequence_number + operation_count + 1,
    );
    let mut batch = Vec::with_capacity(begin.len() + end.len() + operations.len() * 128);
    batch.extend(begin);
    for (index, (payload, operation_flags)) in operations.into_iter().enumerate() {
        let offset = u32::try_from(index).map_err(|_| ())? + 1;
        batch.extend(serialize_netfilter_message(
            NetfilterMessage::new(
                NetfilterHeader::new(NetfilterProtoFamily::Inet, 0, 0),
                payload,
            ),
            NLM_F_REQUEST | NLM_F_ACK | operation_flags,
            sequence_number + offset,
        ));
    }
    batch.extend(end);
    socket.send(&batch, 0).map_err(|_| ())?;

    let mut pending: Vec<u32> = (1..=operation_count)
        .map(|offset| sequence_number + offset)
        .collect();
    while !pending.is_empty() {
        for reply in receive_netfilter_messages(socket)? {
            let Some(index) = pending
                .iter()
                .position(|sequence| *sequence == reply.header.sequence_number)
            else {
                continue;
            };
            if !matches!(reply.payload, NetlinkPayload::Error(ref error) if error.code.is_none()) {
                return Err(());
            }
            pending.swap_remove(index);
        }
    }
    Ok(())
}

fn serialize_netfilter_message(
    payload: NetfilterMessage,
    flags: u16,
    sequence_number: u32,
) -> Vec<u8> {
    let mut header = NetlinkHeader::default();
    header.flags = flags;
    header.sequence_number = sequence_number;
    let mut message = NetlinkMessage::new(header, NetlinkPayload::from(payload));
    message.finalize();
    let mut bytes = vec![0; message.buffer_len()];
    message.serialize(&mut bytes);
    bytes
}

fn receive_netfilter_messages(
    socket: &Socket,
) -> Result<Vec<NetlinkMessage<NetfilterMessage>>, ()> {
    let mut response = vec![0; 65_536];
    let size = socket.recv(&mut &mut response[..], 0).map_err(|_| ())?;
    let mut messages = Vec::new();
    let mut offset = 0;
    while offset < size {
        let length_bytes: [u8; 4] = response
            .get(offset..offset + 4)
            .ok_or(())?
            .try_into()
            .map_err(|_| ())?;
        let length = usize::try_from(u32::from_ne_bytes(length_bytes)).map_err(|_| ())?;
        if length < 16 || offset + length > size {
            return Err(());
        }
        messages.push(
            NetlinkMessage::<NetfilterMessage>::deserialize(&response[offset..offset + length])
                .map_err(|_| ())?,
        );
        offset += (length + 3) & !3;
    }
    Ok(messages)
}

fn nftables_request(
    socket: &Socket,
    payload: NfTablesMessage,
    operation_flags: u16,
    sequence_number: u32,
) -> Result<NetlinkMessage<NetfilterMessage>, ()> {
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | operation_flags;
    header.sequence_number = sequence_number;
    let mut message = NetlinkMessage::new(
        header,
        NetlinkPayload::from(NetfilterMessage::new(
            NetfilterHeader::new(NetfilterProtoFamily::Inet, 0, 0),
            payload,
        )),
    );
    message.finalize();
    let mut bytes = vec![0; message.buffer_len()];
    message.serialize(&mut bytes);
    if socket.send(&bytes, 0).is_err() {
        return Err(());
    }
    let response = receive_netfilter_messages(socket)?
        .into_iter()
        .find(|response| response.header.sequence_number == sequence_number)
        .ok_or(())?;
    if response.header.sequence_number != sequence_number {
        return Err(());
    }
    match &response.payload {
        NetlinkPayload::Error(error) if error.code.is_some() => Err(()),
        _ => Ok(response),
    }
}

fn nftables_dump_request(
    socket: &Socket,
    payload: NfTablesMessage,
    sequence_number: u32,
) -> Result<Vec<NetlinkMessage<NetfilterMessage>>, ()> {
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH;
    header.sequence_number = sequence_number;
    let mut message = NetlinkMessage::new(
        header,
        NetlinkPayload::from(NetfilterMessage::new(
            NetfilterHeader::new(NetfilterProtoFamily::Inet, 0, 0),
            payload,
        )),
    );
    message.finalize();
    let mut bytes = vec![0; message.buffer_len()];
    message.serialize(&mut bytes);
    socket.send(&bytes, 0).map_err(|_| ())?;

    let mut replies = Vec::new();
    loop {
        for reply in receive_netfilter_messages(socket)? {
            if reply.header.sequence_number != sequence_number {
                continue;
            }
            match reply.payload {
                NetlinkPayload::Done(_) => return Ok(replies),
                NetlinkPayload::Error(error) if error.code.is_some() => return Err(()),
                NetlinkPayload::InnerMessage(_) => replies.push(reply),
                _ => {}
            }
        }
    }
}

fn table_reply_matches(
    reply: &NetlinkMessage<NetfilterMessage>,
    table_name: &str,
    ownership: &[u8],
) -> bool {
    let NetlinkPayload::InnerMessage(NetfilterMessage {
        inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewTable(table)),
        ..
    }) = &reply.payload
    else {
        return false;
    };
    table
        .attributes
        .iter()
        .any(|attribute| matches!(attribute, TableAttribute::Name(name) if name == table_name))
        && table.attributes.iter().any(
            |attribute| matches!(attribute, TableAttribute::UserData(value) if value == ownership),
        )
}

fn chain_reply_matches(
    reply: &NetlinkMessage<NetfilterMessage>,
    table_name: &str,
    chain_name: &str,
    ownership: &[u8],
) -> bool {
    let NetlinkPayload::InnerMessage(NetfilterMessage {
        inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewChain(chain)),
        ..
    }) = &reply.payload
    else {
        return false;
    };
    let required = [
        ChainAttribute::Table(table_name.to_owned()),
        ChainAttribute::Name(chain_name.to_owned()),
        ChainAttribute::Policy(0),
        ChainAttribute::Type("filter".to_owned()),
        ChainAttribute::Hook(vec![
            Hook::Number(InetHookNumber::LocalOut.into()),
            Hook::Priority(0),
        ]),
        ChainAttribute::UserData(ownership.to_vec()),
    ];
    required
        .iter()
        .all(|required_attribute| chain.attributes.contains(required_attribute))
}

fn rule_reply_matches(
    reply: &NetlinkMessage<NetfilterMessage>,
    table_name: &str,
    chain_name: &str,
    ownership: &[u8],
) -> bool {
    let NetlinkPayload::InnerMessage(NetfilterMessage {
        inner: NetfilterMessageInner::NfTables(NfTablesMessage::NewRule(rule)),
        ..
    }) = &reply.payload
    else {
        return false;
    };
    rule.attributes
        .contains(&RuleAttribute::Table(table_name.to_owned()))
        && rule
            .attributes
            .contains(&RuleAttribute::Chain(chain_name.to_owned()))
        && rule
            .attributes
            .contains(&RuleAttribute::Expressions(broker_allow_expressions()))
        && rule
            .attributes
            .contains(&RuleAttribute::UserData(ownership.to_vec()))
}

// The descriptor, not a named /run/netns entry, is the ownership token. A
// single-threaded helper creates the complete namespace set before spawning
// its PID-namespace child. The broker retains all descriptors across child
// exit and never re-resolves a mutable path after acquisition.
fn probe_namespace_descriptor_lifecycle() -> String {
    const NAMESPACE_NAMES: [&str; 6] = ["mnt", "pid", "ipc", "uts", "user", "net"];
    if retain_namespace_handles("all", &NAMESPACE_NAMES).is_ok() {
        return "retained-fd-full-set-child-exit-drop-ok".to_owned();
    }
    let individual = NAMESPACE_NAMES
        .iter()
        .map(|name| {
            let status = if retain_namespace_handles(name, std::slice::from_ref(name)).is_ok() {
                "ok"
            } else {
                "unsupported"
            };
            format!("{name}:{status}")
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("required-full-set-unsupported;individual={individual}")
}

fn retain_namespace_handles(kind: &str, namespace_names: &[&str]) -> Result<(), ()> {
    let host_inodes = namespace_names
        .iter()
        .map(|name| namespace_inode(format!("/proc/self/ns/{name}")))
        .collect::<Result<Vec<_>, _>>()?;
    let executable = std::env::current_exe().map_err(|_| ())?;
    let mut worker = Command::new(executable)
        .arg("--namespace-worker")
        .arg("--namespace-kind")
        .arg(kind)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())?;
    let worker_stdout = worker.stdout.take().ok_or(())?;
    let mut ready = String::new();
    BufReader::new(worker_stdout)
        .read_line(&mut ready)
        .map_err(|_| ())?;
    let field_pid = |field_name: &str| {
        ready
            .trim()
            .split(';')
            .find_map(|field| field.strip_prefix(field_name))
            .and_then(|pid| pid.parse::<u32>().ok())
    };
    let subject_pid = if matches!(kind, "all" | "pid") {
        field_pid("leaf_pid=")
    } else {
        field_pid("worker_pid=")
    }
    .ok_or(())?;

    let acquisition = (|| {
        let retained = namespace_names
            .iter()
            .map(|name| File::open(format!("/proc/{subject_pid}/ns/{name}")).map_err(|_| ()))
            .collect::<Result<Vec<_>, _>>()?;
        let retained_inodes = namespace_inodes(&retained)?;
        if retained_inodes
            .iter()
            .zip(host_inodes)
            .any(|(retained_inode, host_inode)| *retained_inode == host_inode)
        {
            return Err(());
        }
        Ok((retained, retained_inodes))
    })();
    drop(worker.stdin.take());
    let worker_succeeded = worker.wait().map_err(|_| ())?.success();
    let (retained, retained_inodes) = acquisition?;
    if !worker_succeeded {
        return Err(());
    }
    let post_exit_inodes = namespace_inodes(&retained)?;
    (post_exit_inodes == retained_inodes)
        .then_some(())
        .ok_or(())
}

fn namespace_inodes(namespaces: &[File]) -> Result<Vec<u64>, ()> {
    namespaces
        .iter()
        .map(|namespace| {
            namespace
                .metadata()
                .map(|metadata| metadata.ino())
                .map_err(|_| ())
        })
        .collect()
}

fn namespace_inode(path: String) -> Result<u64, ()> {
    File::open(path)
        .and_then(|namespace| namespace.metadata())
        .map(|metadata| metadata.ino())
        .map_err(|_| ())
}

// A hosted runner has neither an admitted SIM1 nor its signature/keyring
// material.  Reporting this as unsupported is intentional: no unsigned or
// path-based activation is substituted for the ADR's signed activation proof.
fn probe_dm_verity_capability() -> &'static str {
    let module_present = std::path::Path::new("/sys/module/dm_verity").exists();
    let mapper_present = std::path::Path::new("/dev/mapper/control").exists();
    match (module_present, mapper_present) {
        (true, true) => {
            "host-capability-present;signed-activation-unsupported-no-SIM1-keyring-or-image"
        }
        _ => "host-capability-absent;signed-activation-unsupported-no-SIM1-keyring-or-image",
    }
}
