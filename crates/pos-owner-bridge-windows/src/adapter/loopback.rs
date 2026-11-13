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
        TcpStream::connect((Ipv4Addr::LOCALHOST, 49_291)).and_then(|mut stream| {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .and_then(|()| {
                    stream.write_all(
                        b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\n\
Sec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n",
                    )
                })
                .and_then(|()| {
                    let mut response = Vec::new();
                    stream.read_to_end(&mut response).map(|_| response)
                })
        })
    }

    #[test]
    fn cloned_ports_share_navigation_evidence_and_retain_the_listener() {
        let _port = crate::Native::fixed_port_fixture();
        let result = SharedLoopback::start().map(|mut first| {
            let second = first.clone();
            let response = request_owner();
            let error = response.as_ref().err();
            assert!(
                response
                    .as_ref()
                    .is_ok_and(|bytes| bytes.starts_with(b"HTTP/1.1 200 OK\r\n")),
                "first request: {error:?}"
            );
            assert_eq!(first.served().count, 1);
            assert_eq!(second.served().count, 1);
            assert!(second.served().integrity_ok);
            assert_eq!(first.received_request_count(), Ok(1));
            assert_eq!(second.received_request_count(), Ok(1));
            first.begin_navigation();
            assert_eq!(second.served().count, 0);
            assert_eq!(first.probe_ipv6(), Ok(()));
            drop(first);
            let response = request_owner();
            let error = response.as_ref().err();
            assert!(
                response
                    .as_ref()
                    .is_ok_and(|bytes| bytes.starts_with(b"HTTP/1.1 200 OK\r\n")),
                "second request: {error:?}"
            );
            assert_eq!(second.served().count, 1);
            assert!(second.served().integrity_ok);
            assert_eq!(second.received_request_count(), Ok(2));
        });
        assert!(result.is_ok(), "listener start: {result:?}");
    }

    #[test]
    fn a_poisoned_listener_lock_refuses_evidence_and_ipv6_admission() {
        let _port = crate::Native::fixed_port_fixture();
        let result = SharedLoopback::start().map(|mut port| {
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
            let unavailable = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);
            assert_eq!(port.probe_ipv6(), Err(unavailable));
            assert_eq!(port.observation(), Err(unavailable));
            assert_eq!(peer.received_request_count(), Err(unavailable));
            assert!(!peer.served().integrity_ok);
        });
        assert!(result.is_ok(), "listener start: {result:?}");
    }
}
