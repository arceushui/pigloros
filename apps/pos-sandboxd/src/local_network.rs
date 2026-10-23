//! The Local attempt's FD 3 host-service channel and its binding token
//! (ADR-069 section 7, #441; owner decisions Q7.14 and Q9.5).
//!
//! `serve_proxy` in `pos-reference` is provider-neutral: it serves any
//! [`LocalProxyBinding`]. This module supplies the only binding the provider
//! ever serves, [`BoundLocalProxy`]. It has no public constructor and is
//! minted solely from an [`ActiveAttempt`], which proves the attempt, the
//! authority heads the attempt was admitted with, the namespace and
//! firewall ([`EstablishedNetwork`]) and ownership of FD 3
//! ([`HostServiceChannel`]). A bare admission and an arbitrary channel cannot
//! be bound.
//!
//! The namespace, veth and nftables state behind a real Local network belong
//! to a separate ticket (owner decision Q9.5). Until that adapter exists,
//! [`FailClosedLocalNetwork`] establishes no namespace and refuses every
//! outbound connection, so a Local attempt that plans an exchange ends as
//! unavailable rather than reaching the host network.

use std::error::Error;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pos_reference::sandbox_provider_protocol::{
    serve_proxy, LocalNetworkAdmission, LocalNetworkSession, LocalProxyBinding,
    NetworkCaptureStore, NetworkEndpointConnector,
};
use zvariant::OwnedFd;

use crate::{ActiveAttempt, AdmittedAttempt};

/// The provider end of one attempt's FD 3 socket pair.
///
/// It is created together with the adapter end that the transient unit
/// receives, so a channel names the attempt whose unit holds the other end.
/// It has no public constructor.
#[derive(Debug)]
pub struct HostServiceChannel {
    attempt_id: [u8; 16],
    provider: UnixStream,
}

impl HostServiceChannel {
    /// Create the stream socket pair for `attempt_id`: the adapter end for
    /// `piglor-host-service-v1` and the provider end.
    pub(crate) fn pair(attempt_id: [u8; 16]) -> io::Result<(OwnedFd, Self)> {
        UnixStream::pair().map(|(provider, adapter)| {
            (
                OwnedFd::from(std::os::fd::OwnedFd::from(adapter)),
                Self {
                    attempt_id,
                    provider,
                },
            )
        })
    }
}

/// A Local namespace and firewall owned by one attempt, with the connector
/// that opens connections inside it.
///
/// The adapter that builds this reads the namespace, veth and nftables state
/// back before returning it, so its existence is that readback.
#[derive(Debug)]
pub struct EstablishedNetwork<C> {
    attempt_id: [u8; 16],
    connector: C,
}

impl<C> EstablishedNetwork<C> {
    /// Claim the namespace of `attempt_id`, whose state the caller has read
    /// back, with the connector that operates inside it.
    #[must_use]
    pub const fn new(attempt_id: [u8; 16], connector: C) -> Self {
        Self {
            attempt_id,
            connector,
        }
    }
}

/// The Local network port: it establishes one attempt's namespace.
///
/// An implementation creates the namespace, veth pair and default-drop
/// nftables rules for the attempt and reads them back before it returns. The
/// connector it hands out must honour the timeout it is given.
///
/// Teardown is RAII: the returned [`EstablishedNetwork`], and the connector
/// inside it, own the namespace, and dropping them removes it. The execute
/// path establishes the network before the recheck and before the unit
/// starts, so it drops the handle on every path that does not serve it: a
/// refused admission, a failed `take_unit_end`, a failed recheck, a failed
/// start, a refused release and a finished attempt. An implementation must
/// therefore make its `Drop` (or its connector's) tear the namespace down, and
/// must not rely on the caller to do it.
pub trait LocalNetworkPort {
    /// The connector that operates inside the established namespace.
    type Connector: NetworkEndpointConnector + Send + 'static;
    /// Why a namespace could not be established or read back.
    type Error: Error + Send + Sync + 'static;

    /// Establish and read back the namespace of `attempt_id`.
    ///
    /// # Errors
    /// Fails, leaving nothing behind, if the namespace, veth pair or firewall
    /// cannot be created or read back.
    fn establish(
        &self,
        attempt_id: [u8; 16],
    ) -> Result<EstablishedNetwork<Self::Connector>, Self::Error>;
}

/// The Local network adapter until a real namespace exists.
///
/// It owns no namespace and its connector refuses every connection, so a
/// Local attempt can never reach the host network through it.
#[derive(Clone, Copy, Debug, Default)]
pub struct FailClosedLocalNetwork;

impl LocalNetworkPort for FailClosedLocalNetwork {
    type Connector = RefusingConnector;
    type Error = std::convert::Infallible;

    fn establish(
        &self,
        attempt_id: [u8; 16],
    ) -> Result<EstablishedNetwork<RefusingConnector>, std::convert::Infallible> {
        Ok(EstablishedNetwork::new(attempt_id, RefusingConnector))
    }
}

/// A connector that fails every connection.
#[derive(Clone, Copy, Debug)]
pub struct RefusingConnector;

impl NetworkEndpointConnector for RefusingConnector {
    fn connect(&mut self, _endpoint: SocketAddr, _timeout: Duration) -> io::Result<TcpStream> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

/// Why an admission could not be bound to its active attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LocalProxyBindError {
    /// The admission's grant names another attempt.
    #[error("admission belongs to another attempt")]
    Attempt,
    /// The grant names another SIM1, or other authority heads or epochs than
    /// the attempt was admitted with.
    #[error("admission authority differs from the active attempt")]
    Authority,
    /// The namespace belongs to another attempt.
    #[error("network namespace belongs to another attempt")]
    Namespace,
    /// The channel belongs to another attempt.
    #[error("host-service channel belongs to another attempt")]
    Channel,
}

/// A Local admission, namespace and channel that were checked against the
/// admitted attempt they belong to.
///
/// Only `AdmittedAttempt::check_local` makes one, so holding it proves the
/// check ran. The execute path makes it before the unit is submitted, so a bad
/// admission never starts a unit, and binds it once the unit is active. It has
/// no public constructor.
#[derive(Debug)]
pub struct CheckedLocal<C> {
    admission: LocalNetworkAdmission,
    network: EstablishedNetwork<C>,
    channel: HostServiceChannel,
}

impl AdmittedAttempt {
    /// Check that `admission`, `network` and `channel` belong to this attempt.
    ///
    /// # Errors
    /// Rejects an admission whose grant names another attempt, SIM1, authority
    /// head or epoch, and a namespace or channel created for another attempt.
    /// The rejected inputs are dropped, which tears the namespace down.
    pub(crate) fn check_local<C>(
        &self,
        admission: LocalNetworkAdmission,
        network: EstablishedNetwork<C>,
        channel: HostServiceChannel,
    ) -> Result<CheckedLocal<C>, LocalProxyBindError> {
        let grant = admission.grant();
        let authority = self.authority();
        if grant.attempt_id != self.attempt_id() {
            return Err(LocalProxyBindError::Attempt);
        }
        if grant.authority.sim1_digest != self.sim1_digest()
            || grant.authority.apt1_digest != authority.apt1_digest
            || grant.authority.trs1_digest != authority.trs1_digest
            || grant.authority.rvs1_digest != authority.rvs1_digest
            || grant.trust_epoch != authority.trust_epoch
            || grant.revocation_epoch != authority.revocation_epoch
            || grant.policy_epoch != authority.policy_epoch
        {
            return Err(LocalProxyBindError::Authority);
        }
        if network.attempt_id != self.attempt_id() {
            return Err(LocalProxyBindError::Namespace);
        }
        if channel.attempt_id != self.attempt_id() {
            return Err(LocalProxyBindError::Channel);
        }
        Ok(CheckedLocal {
            admission,
            network,
            channel,
        })
    }
}

impl<C> CheckedLocal<C> {
    /// Bind the checked inputs to the attempt that is now active.
    ///
    /// The binding is the only value the provider serves with `serve_proxy`.
    /// The connector of the bound namespace is returned beside it. `active`
    /// must be the record of the attempt the inputs were checked against; the
    /// execute path makes both from the same [`AdmittedAttempt`].
    pub(crate) fn bind(self, active: &ActiveAttempt) -> (BoundLocalProxy, C) {
        (
            BoundLocalProxy {
                attempt_id: active.attempt_id(),
                admission: self.admission,
                channel: HostServiceStream(Arc::new(self.channel.provider)),
            },
            self.network.connector,
        )
    }
}

/// One Local admission bound to its active attempt and its FD 3 channel.
///
/// It has no public constructor and no way to replace its admission or its
/// channel; [`ActiveAttempt`] mints it.
#[derive(Debug)]
pub struct BoundLocalProxy {
    attempt_id: [u8; 16],
    admission: LocalNetworkAdmission,
    channel: HostServiceStream,
}

/// The provider end of a bound FD 3 channel.
///
/// It is shared with the watchdog, which closes it from another thread to end
/// a session that is blocked on the adapter. It has no public constructor.
#[derive(Clone, Debug)]
pub struct HostServiceStream(Arc<UnixStream>);

impl HostServiceStream {
    /// Shut both directions down. A blocked read or write of the proxy then
    /// fails, so the session ends instead of outliving the attempt.
    fn close(&self) {
        // A peer that already closed is not a failure of the close.
        self.0.shutdown(Shutdown::Both).ok();
    }
}

impl Read for HostServiceStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        (&*self.0).read(buffer)
    }
}

impl Write for HostServiceStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        (&*self.0).write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        // A socket buffers nothing in user space.
        Ok(())
    }
}

impl AsFd for HostServiceStream {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl BoundLocalProxy {
    /// The active attempt this binding was minted for.
    #[must_use]
    pub const fn attempt_id(&self) -> [u8; 16] {
        self.attempt_id
    }

    /// Serve this binding on a blocking thread until its channel ends or
    /// `deadline`.
    ///
    /// `serve_proxy`'s network deadline bounds socket I/O only; a stalled
    /// adapter is bounded here. When `deadline` passes, the channel is closed,
    /// which ends the session, and the outcome says so.
    ///
    /// The runtime must have its time driver enabled.
    ///
    /// # Errors
    /// Fails if the blocking task does not finish.
    pub async fn serve_until<C>(
        self,
        connector: C,
        store: Arc<NetworkCaptureStore>,
        deadline: Instant,
    ) -> Result<ServedProxy, ServeError>
    where
        C: NetworkEndpointConnector + Send + 'static,
    {
        let closer = self.channel.clone();
        let mut task = tokio::task::spawn_blocking(move || {
            let mut binding = self;
            let mut connector = connector;
            serve_proxy(&mut binding, &mut connector, &store)
        });
        let timed =
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), &mut task).await;
        let watchdog_expired = timed.is_err();
        if watchdog_expired {
            closer.close();
        }
        let session = match timed {
            Ok(joined) => joined,
            Err(_elapsed) => task.await,
        };
        session
            .map(|session| ServedProxy {
                session,
                watchdog_expired,
            })
            .map_err(ServeError)
    }
}

impl LocalProxyBinding for BoundLocalProxy {
    type Channel = HostServiceStream;

    fn parts(&mut self) -> (&LocalNetworkAdmission, &mut HostServiceStream) {
        (&self.admission, &mut self.channel)
    }
}

/// How a served channel ended.
#[derive(Debug)]
pub struct ServedProxy {
    /// The session, with its retained transcripts and termination.
    pub session: LocalNetworkSession,
    /// Whether the attempt watchdog closed the channel before it ended.
    pub watchdog_expired: bool,
}

/// The blocking proxy task did not finish.
#[derive(Debug, thiserror::Error)]
#[error("the proxy task did not finish")]
pub struct ServeError(#[source] tokio::task::JoinError);

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
