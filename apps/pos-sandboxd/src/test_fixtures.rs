//! Shared fixtures of the Local execute-path tests.
#![cfg(target_os = "linux")]

use std::{
    error::Error,
    fs::File,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use pos_reference::{
    provider_admission::AdmittedAuthority,
    sandbox_provider_protocol::{
        AdmissionAuthority, LocalNetworkAdmission, NetworkCapability, NetworkCaptureStore,
        NetworkEndpointConnector, NetworkExchangePlan, NetworkProxyLimits, SandboxExecutionMode,
    },
};

use crate::{ActiveAttempt, AdmittedAttempt};

/// The attempt every fixture belongs to.
pub const ATTEMPT: [u8; 16] = [0x41; 16];
/// Another attempt, for substitution cases.
pub const OTHER: [u8; 16] = [0x42; 16];
/// The exact planned request.
pub const REQUEST: &[u8] = b"exact request";
/// The exact planned response.
pub const RESPONSE: &[u8] = b"exact response";

/// The result type of the tests.
pub type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[must_use]
pub const fn authority() -> AdmittedAuthority {
    AdmittedAuthority {
        apt1_digest: [1; 32],
        trs1_digest: [2; 32],
        rvs1_digest: [3; 32],
        trust_epoch: 4,
        revocation_epoch: 5,
        policy_epoch: 6,
    }
}

#[must_use]
pub const fn grant_authority() -> AdmissionAuthority {
    crate::attempt::test_admission_authority()
}

pub fn admitted() -> TestResult<AdmittedAttempt> {
    Ok(AdmittedAttempt::for_test(
        ATTEMPT,
        authority(),
        SandboxExecutionMode::Local,
    )?)
}

pub fn active() -> TestResult<ActiveAttempt> {
    Ok(ActiveAttempt::record(
        admitted()?,
        Instant::now() + Duration::from_secs(30),
    ))
}

#[must_use]
pub fn admission(
    attempt: [u8; 16],
    authority: AdmissionAuthority,
    epochs: [u64; 3],
    exchanges: Vec<(NetworkExchangePlan, NetworkCapability)>,
) -> LocalNetworkAdmission {
    LocalNetworkAdmission::fixture(
        attempt,
        authority,
        epochs,
        exchanges,
        NetworkProxyLimits {
            request_bytes: 1_048_576,
            response_bytes: 1_048_576,
            milliseconds: 30_000,
        },
    )
}

#[must_use]
pub fn capability(address: SocketAddr) -> NetworkCapability {
    NetworkCapability {
        capability_id: "execute".to_owned(),
        address: vec![127, 0, 0, 1],
        destination_port: address.port(),
        request_maximum: 1_048_576,
        response_maximum: 1_048_576,
    }
}

/// Connects to the planned endpoint, like a real connector would.
pub struct LoopbackConnector;

impl NetworkEndpointConnector for LoopbackConnector {
    fn connect(&mut self, endpoint: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        TcpStream::connect_timeout(&endpoint, timeout)
    }
}

/// A remote that answers one exchange and reports the request it received.
pub fn remote() -> TestResult<(SocketAddr, thread::JoinHandle<io::Result<Vec<u8>>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept()?;
        let mut request = Vec::new();
        stream.read_to_end(&mut request)?;
        stream.write_all(RESPONSE)?;
        Ok(request)
    });
    Ok((address, server))
}

pub fn capture_store() -> TestResult<(tempfile::TempDir, Arc<NetworkCaptureStore>)> {
    let root = tempfile::tempdir()?;
    let store = NetworkCaptureStore::open(&File::open(root.path())?)?;
    Ok((root, Arc::new(store)))
}

pub fn plan() -> TestResult<NetworkExchangePlan> {
    Ok(NetworkExchangePlan::fixture(
        [9; 16], 0, "execute", REQUEST, RESPONSE,
    )?)
}

/// A Local proxy bound to a fresh attempt over `connector`, with the adapter
/// end of its channel. The admission plans one exchange with `address`.
///
/// # Errors
/// Fails if the channel or the binding cannot be created.
pub fn bound_proxy<C>(
    plan: NetworkExchangePlan,
    address: SocketAddr,
    connector: C,
) -> TestResult<(zbus::OwnedFd, crate::BoundLocalProxy, C)> {
    let (adapter, channel) = crate::HostServiceChannel::pair(ATTEMPT)?;
    let admission = admission(
        ATTEMPT,
        grant_authority(),
        [4, 5, 6],
        vec![(plan, capability(address))],
    );
    let checked = admitted()?
        .allowing(vec![capability(address)])
        .check_local(
            admission,
            crate::EstablishedNetwork::new(ATTEMPT, connector),
            channel,
        )?;
    let (binding, connector) = checked.bind();
    Ok((adapter, binding, connector))
}

/// The launcher-mode command of the fixture attempt.
///
/// # Errors
/// Fails if the fixture launch parameters cannot be encoded.
pub fn invocation() -> TestResult<crate::LauncherInvocation> {
    // One random nonce per test process, so every caller of the fixture builds
    // the same command without a hard-coded cryptographic value.
    static NONCE: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    let nonce = *NONCE.get_or_init(|| crate::fresh_nonce().unwrap_or_default());
    let parameters = pos_reference::sandbox_provider_protocol::LaunchParameters::new(
        ATTEMPT,
        nonce,
        [0x51; 32],
        "/usr/bin/adapter".to_owned(),
        vec!["--check".to_owned()],
        [8; 32],
    )?;
    Ok(crate::LauncherInvocation::from_parameters(&parameters)?)
}
