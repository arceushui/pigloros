#![cfg(windows)]

mod process;
mod socket;

// The crate-facing boundary keeps implementation modules private. Relative
// visibility exposes only these safe operations to the adapter, not internals.
pub(super) fn inspect_process(pid: u32) -> Result<Option<pos_owner_bridge::ProcessIdentity>, ()> {
    process::inspect(pid)
}

pub(super) fn bind_v4(port: u16) -> std::io::Result<std::net::TcpListener> {
    socket::bind_v4(port)
}

pub(super) fn bind_v6(port: u16) -> std::io::Result<std::net::TcpListener> {
    socket::bind_v6(port)
}

#[cfg(test)]
pub(super) fn competing_reuse(port: u16) -> std::io::Result<std::net::TcpListener> {
    socket::competing_reuse(port)
}
