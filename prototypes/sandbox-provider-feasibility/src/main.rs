//! THROWAWAY PROTOTYPE: hosted evidence only for ADR-069 control primitives.
//! It is deliberately not production provider code and must never be promoted
//! by copying it into the workspace.

use futures_util::TryStreamExt as _;
use netlink_packet_core::{
    Emitable as _, NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE,
    NLM_F_EXCL, NLM_F_REQUEST,
};
use netlink_packet_netfilter::nftables::{
    GenMessage, NfTablesMessage, TableAttribute, TableMessage,
};
use netlink_packet_netfilter::{
    none::ControlMessage, NetfilterHeader, NetfilterMessage, NetfilterMessageInner,
    NetfilterProtoFamily,
};
use netlink_sys::{protocols::NETLINK_NETFILTER, Socket, SocketAddr};
use nix::sched::{setns, unshare, CloneFlags};
use rtnetlink::{new_connection, LinkDummy};
use std::{fs::File, os::unix::fs::MetadataExt as _, thread, time::Instant};

#[tokio::main]
async fn main() {
    let dbus = probe_systemd().await;
    let route = probe_route_netlink().await;
    let nftables_packet_bytes = encode_nftables_probe();
    println!("systemd={dbus};route_netlink={route};nftables_packet_bytes={nftables_packet_bytes}");
    if std::env::args().any(|argument| argument == "--privileged") {
        let attempt_id = attempt_id();
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
            "attempt={attempt_id};transient_slice={systemd_lifecycle};transient_slice_us={systemd_elapsed_us};dummy_link={route_lifecycle};dummy_link_us={route_elapsed_us};nftables_read={nftables_read};nftables_read_us={nftables_read_elapsed_us};nftables_atomic={nftables_atomic};nftables_atomic_us={nftables_atomic_elapsed_us};namespace_descriptor={namespace};namespace_us={namespace_elapsed_us};dm_verity={dm_verity};total_us={}",
            started.elapsed().as_micros()
        );
    }
}

fn attempt_id() -> String {
    let mut arguments = std::env::args();
    while let Some(argument) = arguments.next() {
        if argument == "--attempt-id" {
            if let Some(value) = arguments.next() {
                let filtered: String = value
                    .chars()
                    .filter(char::is_ascii_alphanumeric)
                    .take(11)
                    .collect();
                if !filtered.is_empty() {
                    return filtered;
                }
            }
        }
    }
    std::process::id().to_string()
}

async fn probe_systemd() -> &'static str {
    let Ok(connection) = zbus::Connection::system().await else {
        return "unavailable";
    };
    let Ok(proxy) = zbus_systemd::systemd1::ManagerProxy::new(&connection).await else {
        return "unavailable";
    };
    match proxy.get_unit("-.mount".to_owned()).await {
        Ok(_) => "typed-get-unit-ok",
        Err(_) => "typed-get-unit-rejected",
    }
}

async fn probe_route_netlink() -> &'static str {
    let Ok((connection, handle, _)) = new_connection() else {
        return "unavailable";
    };
    tokio::spawn(connection);
    let mut links = handle.link().get().execute();
    match links.try_next().await {
        Ok(Some(_)) => "typed-link-read-ok",
        Ok(None) => "typed-link-read-empty",
        Err(_) => "typed-link-read-rejected",
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
    match proxy.stop_unit(name, "fail".to_owned()).await {
        Ok(_) => "typed-create-stop-ok",
        Err(_) => "stop-rejected",
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

// This is one nftables transaction containing one table object.  It proves
// direct typed install/read-back/delete and deliberately does not claim the
// ADR's larger default-drop-plus-allow-rules transaction; that needs a tested
// batch-envelope implementation before it can be evidence.
fn probe_nftables_atomic_table(attempt_id: &str) -> &'static str {
    let Ok(mut socket) = Socket::new(NETLINK_NETFILTER) else {
        return "socket-unavailable";
    };
    if socket.bind_auto().is_err() || socket.connect(&SocketAddr::new(0, 0)).is_err() {
        return "connect-rejected";
    }

    let table_name = format!("pgl211_{attempt_id}");
    let ownership = format!("pigloros:#211:{attempt_id}:throwaway");
    let create = NfTablesMessage::NewTable(TableMessage {
        attributes: vec![
            TableAttribute::Name(table_name.clone()),
            TableAttribute::UserData(ownership.as_bytes().to_vec()),
        ],
    });
    if nftables_batch_request(&socket, create, NLM_F_CREATE | NLM_F_EXCL, 1).is_err() {
        return "install-rejected";
    }

    let read_back = NfTablesMessage::GetTable(TableMessage {
        attributes: vec![TableAttribute::Name(table_name.clone())],
    });
    let read_back_matches = nftables_request(&socket, read_back, 0, 2)
        .is_ok_and(|reply| table_reply_matches(&reply, &table_name, ownership.as_bytes()));

    let delete = NfTablesMessage::DeleteTable(TableMessage {
        attributes: vec![TableAttribute::Name(table_name)],
    });
    let deleted = nftables_batch_request(&socket, delete, 0, 3).is_ok();

    match (read_back_matches, deleted) {
        (true, true) => "typed-install-read-back-delete-ok",
        (false, true) => "read-back-mismatch-cleaned",
        (_, false) => "delete-rejected-needs-reconcile",
    }
}

fn nftables_batch_request(
    socket: &Socket,
    payload: NfTablesMessage,
    operation_flags: u16,
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
    let operation = serialize_netfilter_message(
        NetfilterMessage::new(
            NetfilterHeader::new(NetfilterProtoFamily::Inet, 0, 0),
            payload,
        ),
        NLM_F_REQUEST | NLM_F_ACK | operation_flags,
        sequence_number + 1,
    );
    let end = serialize_netfilter_message(
        NetfilterMessage::new(
            NetfilterHeader::new(NetfilterProtoFamily::Unspec, 0, NFTABLES_SUBSYSTEM),
            ControlMessage::BatchEnd,
        ),
        NLM_F_REQUEST,
        sequence_number + 2,
    );
    let mut batch = Vec::with_capacity(begin.len() + operation.len() + end.len());
    batch.extend(begin);
    batch.extend(operation);
    batch.extend(end);
    socket.send(&batch, 0).map_err(|_| ())?;

    let reply = receive_netfilter_message(socket)?;
    if reply.header.sequence_number != sequence_number + 1 {
        return Err(());
    }
    match reply.payload {
        NetlinkPayload::Error(error) if error.code.is_none() => Ok(()),
        _ => Err(()),
    }
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

fn receive_netfilter_message(socket: &Socket) -> Result<NetlinkMessage<NetfilterMessage>, ()> {
    let mut response = vec![0; 8192];
    let size = socket.recv(&mut &mut response[..], 0).map_err(|_| ())?;
    NetlinkMessage::<NetfilterMessage>::deserialize(&response[..size]).map_err(|_| ())
}

fn nftables_request(
    socket: &Socket,
    payload: NfTablesMessage,
    operation_flags: u16,
    sequence_number: u32,
) -> Result<NetlinkMessage<NetfilterMessage>, ()> {
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_ACK | operation_flags;
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
    let response = receive_netfilter_message(socket)?;
    if response.header.sequence_number != sequence_number {
        return Err(());
    }
    match &response.payload {
        NetlinkPayload::Error(error) if error.code.is_some() => Err(()),
        _ => Ok(response),
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

// The descriptor, not a named /run/netns entry, is the ownership token.  The
// temporary network namespace is entered only by this thread and the original
// namespace descriptor is retained until after restoration.
fn probe_namespace_descriptor_lifecycle() -> &'static str {
    let result = thread::spawn(|| {
        let original = File::open("/proc/thread-self/ns/net").map_err(|_| ())?;
        let original_inode = original.metadata().map_err(|_| ())?.ino();
        unshare(CloneFlags::CLONE_NEWNET).map_err(|_| ())?;
        let retained = File::open("/proc/thread-self/ns/net").map_err(|_| ())?;
        let retained_inode = retained.metadata().map_err(|_| ())?.ino();
        if retained_inode == original_inode {
            return Err(());
        }
        setns(&original, CloneFlags::CLONE_NEWNET).map_err(|_| ())?;
        let restored_inode = File::open("/proc/thread-self/ns/net")
            .and_then(|namespace| namespace.metadata())
            .map_err(|_| ())?
            .ino();
        (restored_inode == original_inode).then_some(()).ok_or(())
    })
    .join();
    match result {
        Ok(Ok(())) => "retained-fd-create-restore-drop-ok",
        Ok(Err(())) => "create-or-restore-rejected",
        Err(_) => "probe-thread-panicked",
    }
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
