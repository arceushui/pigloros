#![cfg(windows)]
#![forbid(unsafe_code)]

use pos_owner_bridge::listener::{ListenerConfig, LoopbackListener};
use pos_owner_bridge::{BridgeError, LoopbackPort, ServedSnapshot, UnavailableCode};
use std::sync::{Arc, Mutex};

pub struct SharedLoopback(Arc<Mutex<LoopbackListener>>);

impl SharedLoopback {
    pub(super) fn start() -> Result<Self, BridgeError> {
        LoopbackListener::start(
            Box::new(crate::WindowsLoopbackBinder::default()),
            ListenerConfig::adr(),
        )
        .map(|listener| Self(Arc::new(Mutex::new(listener))))
    }
}

impl Clone for SharedLoopback {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl LoopbackPort for SharedLoopback {
    fn begin_navigation(&mut self) {
        if let Ok(mut listener) = self.0.lock() {
            listener.begin_navigation();
        }
    }

    fn served(&self) -> ServedSnapshot {
        self.0.lock().map_or(
            ServedSnapshot {
                count: 0,
                integrity_ok: false,
            },
            |listener| listener.served(),
        )
    }

    fn probe_ipv6(&mut self) -> Result<(), BridgeError> {
        self.0
            .lock()
            .map_err(|_| BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable))?
            .probe_ipv6()
    }
}
