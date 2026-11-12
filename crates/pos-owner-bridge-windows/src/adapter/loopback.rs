#![cfg(windows)]
#![forbid(unsafe_code)]

use pos_owner_bridge::listener::{ListenerConfig, LoopbackListener};
use pos_owner_bridge::{BridgeError, LoopbackPort, ServedSnapshot, UnavailableCode};
use std::sync::{Arc, Mutex};

pub(super) struct SharedLoopback(Arc<Mutex<LoopbackListener>>);

impl SharedLoopback {
    pub(super) fn start() -> Result<Self, BridgeError> {
        Self::with_config(ListenerConfig::adr())
    }

    #[cfg(test)]
    pub(super) fn start_fixture(
        profile: pos_owner_bridge::listener::FixtureProfile,
    ) -> Result<Self, BridgeError> {
        Self::with_config(ListenerConfig::fixture(profile))
    }

    fn with_config(config: ListenerConfig) -> Result<Self, BridgeError> {
        LoopbackListener::start(Box::new(crate::WindowsLoopbackBinder::default()), config)
            .map(|listener| Self(Arc::new(Mutex::new(listener))))
    }

    #[cfg(test)]
    pub(super) fn observation(
        &self,
    ) -> Result<pos_owner_bridge::listener::ListenerObservation, BridgeError> {
        self.0
            .lock()
            .map(|listener| listener.observation())
            .map_err(|_| BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable))
    }

    #[cfg(test)]
    pub(super) fn diagnostic_snapshot(&self, started: std::time::Instant) -> String {
        self.0.try_lock().map_or_else(
            |_| "listener_snapshot_unavailable=true".to_owned(),
            |listener| listener.diagnostic_snapshot(started),
        )
    }

    #[cfg(test)]
    pub(super) fn received_request_count(&self) -> Result<u64, BridgeError> {
        self.0
            .lock()
            .map(|listener| listener.received_request_count())
            .map_err(|_| BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable))
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
        #[cfg(test)]
        let _duration = crate::Native::readiness_span("ipv6-probe");
        let mut listener = self
            .0
            .lock()
            .map_err(|_| BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable))?;
        listener.probe_ipv6()
    }
}

#[cfg(test)]
mod tests {
    use super::SharedLoopback;
    use pos_owner_bridge::{BridgeError, LoopbackPort, UnavailableCode};
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpStream};
    use std::time::Duration;

    fn request_owner() -> std::io::Result<Vec<u8>> {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, 49_291))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.write_all(
            b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\n\
Sec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n",
        )?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        Ok(response)
    }

    #[test]
    fn cloned_ports_share_navigation_evidence_and_retain_the_listener(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _port = crate::Native::fixed_port_fixture();
        let mut first = SharedLoopback::start()?;
        let second = first.clone();
        assert!(request_owner()?.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert_eq!(first.served().count, 1);
        assert_eq!(second.served().count, 1);
        assert!(second.served().integrity_ok);
        first.begin_navigation();
        assert_eq!(second.served().count, 0);
        first.probe_ipv6()?;
        drop(first);
        assert!(request_owner()?.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert_eq!(second.served().count, 1);
        assert!(second.served().integrity_ok);
        Ok(())
    }

    #[test]
    fn a_poisoned_listener_lock_refuses_evidence_and_ipv6_admission(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _port = crate::Native::fixed_port_fixture();
        let mut port = SharedLoopback::start()?;
        let peer = port.clone();
        // Narrow fault injection: production can encounter a poisoned shared
        // mutex, but no network input should be able to trigger the unwind.
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _locked = peer.0.lock();
            std::panic::resume_unwind(Box::new("controlled listener lock poison"));
        }));
        assert!(poisoned.is_err());
        port.begin_navigation();
        assert_eq!(port.served().count, 0);
        assert!(!port.served().integrity_ok);
        assert_eq!(
            port.probe_ipv6(),
            Err(BridgeError::Unavailable(
                UnavailableCode::InterfaceUnavailable
            ))
        );
        assert!(!peer.served().integrity_ok);
        Ok(())
    }
}
