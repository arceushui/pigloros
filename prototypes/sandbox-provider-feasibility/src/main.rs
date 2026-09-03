//! THROWAWAY PROTOTYPE: proves typed control-plane crates compose without
//! shelling out. Production code must not depend on this package.

use futures_util::TryStreamExt as _;
use netlink_packet_core::{
    Emitable as _, NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_REQUEST,
};
use netlink_packet_netfilter::nftables::{GenMessage, NfTablesMessage};
use netlink_packet_netfilter::{
    NetfilterHeader, NetfilterMessage, NetfilterProtoFamily,
};
use netlink_sys::{protocols::NETLINK_NETFILTER, Socket, SocketAddr};
use rtnetlink::{new_connection, LinkDummy};

#[tokio::main]
async fn main() {
    let dbus = probe_systemd().await;
    let route = probe_route_netlink().await;
    let nftables_packet_bytes = encode_nftables_probe();
    println!(
        "systemd={dbus};route_netlink={route};nftables_packet_bytes={nftables_packet_bytes}"
    );
    if std::env::args().any(|argument| argument == "--privileged") {
        let systemd_lifecycle = probe_transient_slice().await;
        let route_lifecycle = probe_dummy_link_lifecycle().await;
        let nftables_read = probe_nftables_read();
        println!(
            "transient_slice={systemd_lifecycle};dummy_link={route_lifecycle};nftables_read={nftables_read}"
        );
    }
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

async fn probe_transient_slice() -> &'static str {
    let Ok(connection) = zbus::Connection::system().await else {
        return "unavailable";
    };
    let Ok(proxy) = zbus_systemd::systemd1::ManagerProxy::new(&connection).await else {
        return "unavailable";
    };
    let name = "pigloros-sandbox-provider-prototype.slice".to_owned();
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

async fn probe_dummy_link_lifecycle() -> &'static str {
    let Ok((connection, handle, _)) = new_connection() else {
        return "unavailable";
    };
    tokio::spawn(connection);
    let name = "pigloros-probe0";
    if handle
        .link()
        .add(LinkDummy::new(name).build())
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
