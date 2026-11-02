#![cfg(windows)]

mod process;
mod registry;
mod socket;

impl crate::Native {
    pub(super) fn inspect_process(
        pid: u32,
    ) -> Result<Option<pos_owner_bridge::ProcessIdentity>, ()> {
        process::inspect(pid)
    }

    pub(super) fn bind_v4(port: u16) -> std::io::Result<std::net::TcpListener> {
        socket::bind_v4(port)
    }

    pub(super) fn bind_v6(port: u16) -> std::io::Result<std::net::TcpListener> {
        socket::bind_v6(port)
    }

    pub(super) fn query_policy(
        machine: bool,
        view64: bool,
        subkey: &[u16],
        name: &[u16],
    ) -> windows::Win32::Foundation::WIN32_ERROR {
        registry::query_policy(machine, view64, subkey, name)
    }

    #[cfg(test)]
    pub(super) fn competing_reuse(port: u16) -> std::io::Result<std::net::TcpListener> {
        socket::competing_reuse(port)
    }
}
