//! THROWAWAY PROTOTYPE: proves typed control-plane crates compose without
//! shelling out. Production code must not depend on this package.

use futures_util::TryStreamExt as _;
use netlink_packet_core::{Emitable as _, NetlinkMessage};
use netlink_packet_netfilter::nftables::{GenMessage, NfTablesMessage};
use netlink_packet_netfilter::{
    NetfilterHeader, NetfilterMessage, NetfilterProtoFamily,
};
use rtnetlink::new_connection;
use zbus::zvariant::OwnedObjectPath;

#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
trait SystemdManager {
    #[zbus(name = "GetUnit")]
    fn get_unit(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
}

#[tokio::main]
async fn main() {
    let dbus = probe_systemd().await;
    let route = probe_route_netlink().await;
    let nftables_packet_bytes = encode_nftables_probe();
    println!(
        "systemd={dbus};route_netlink={route};nftables_packet_bytes={nftables_packet_bytes}"
    );
}

async fn probe_systemd() -> &'static str {
    let Ok(connection) = zbus::Connection::system().await else {
        return "unavailable";
    };
    let Ok(proxy) = SystemdManagerProxy::new(&connection).await else {
        return "unavailable";
    };
    match proxy.get_unit("-.mount").await {
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

