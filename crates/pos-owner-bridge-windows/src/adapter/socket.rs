#![cfg(windows)]
#![forbid(unsafe_code)]

use std::{io, net::TcpListener};

use pos_owner_bridge::listener::bind::{classify_bind_error, BindError, LoopbackBinder};

/// Exclusive IPv4/IPv6 loopback sockets on the fixed owner port, backlog four.
#[derive(Debug)]
pub struct WindowsLoopbackBinder {
    port: u16,
}

impl Default for WindowsLoopbackBinder {
    fn default() -> Self {
        Self { port: 49_291 }
    }
}

impl WindowsLoopbackBinder {
    #[cfg(test)]
    pub(crate) const fn ephemeral() -> Self {
        Self { port: 0 }
    }
}

fn classified(result: io::Result<TcpListener>) -> Result<TcpListener, BindError> {
    result.map_err(|error| classify_bind_error(&error))
}

impl LoopbackBinder for WindowsLoopbackBinder {
    fn bind_v4(&mut self) -> Result<TcpListener, BindError> {
        classified(crate::Native::bind_v4(self.port))
    }

    fn bind_v6(&mut self) -> Result<TcpListener, BindError> {
        classified(crate::Native::bind_v6(self.port))
    }

    fn probe_v6(&mut self) -> Result<(), BindError> {
        classified(crate::Native::bind_v6(0)).map(drop)
    }
}
