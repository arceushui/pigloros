//! Process startup helpers shared by every Gateway serve path.
//!
//! The binary's plain serve path and the local Fork-admission serve path open
//! their one erasure host, announce the TCP listener, and stop a partially
//! started Gateway after a bind failure in exactly the same way.

use std::{
    future::Future,
    io::{self, Write as _},
    net::SocketAddr,
};

use axum::Router;
use pos_runtime::{ErasureCoordinatorCompositionV1, ErasureExecutionHostV1};
use pos_store::StoreConfig;

use crate::{
    mode_profile::{GatewayModeBindingErrorV1, GatewayModeBindingV1},
    Gateway,
};

/// Which Gateway store capability the recovered host must provide.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayHostStoreV1 {
    /// The standard erasure host store.
    Standard,
    /// A store that also admits authenticated local `OwnTracks` ingress.
    OwnTracks,
}

/// Open and recover the one erasure host of `config` with `composition`.
///
/// # Errors
/// Returns a payload-free recovery error that carries only the closed host
/// error code.
pub fn open_recovered_erasure_host(
    config: StoreConfig,
    store: GatewayHostStoreV1,
    composition: &ErasureCoordinatorCompositionV1,
) -> io::Result<ErasureExecutionHostV1> {
    let limits = pos_core::ErasureRecoveryLimitsV1::compiled_maximum();
    let host = match store {
        GatewayHostStoreV1::Standard => {
            ErasureExecutionHostV1::open_with_authority(config, composition, limits)
        }
        GatewayHostStoreV1::OwnTracks => {
            ErasureExecutionHostV1::open_gateway_with_authority(config, composition, limits)
        }
    };
    host.map_err(erasure_host_failure)
}

/// The payload-free startup error of a host that is not ready: it carries
/// only the closed host error code.
pub(crate) fn erasure_host_failure(error: pos_core::ErasureHostErrorV1) -> io::Error {
    io::Error::other(format!("erasure host recovery failed ({})", error.code()))
}

/// Announce the bound HTTP listener on standard error.
pub fn announce_listening(addr: SocketAddr) {
    let mut output = io::stderr().lock();
    drop(writeln!(
        output,
        "piglor-gateway listening on http://{addr}"
    ));
}

/// Announce the bound execution mode on standard error (ADR-134 §4).
pub fn announce_mode_binding(mode: &GatewayModeBindingV1) {
    let mut output = io::stderr().lock();
    drop(writeln!(
        output,
        "piglor-gateway serving execution mode {}",
        mode.disclosure()
    ));
}

/// The router of a bound Gateway: after it answers a stale-binding refusal
/// (`503`), the serve loop stops (ADR-134 §8).
#[must_use]
pub fn bound_router(router: Router, mode: &GatewayModeBindingV1) -> Router {
    let signal = mode.stale_signal();
    router.layer(axum::middleware::map_response(
        move |response: axum::response::Response| {
            let signal = std::sync::Arc::clone(&signal);
            async move {
                if response
                    .extensions()
                    .get::<crate::mode_profile::ModeBindingStaleResponseV1>()
                    .is_some()
                {
                    signal.fire();
                }
                response
            }
        },
    ))
}

/// The graceful-shutdown future of a bound Gateway: the operator's
/// `shutdown`, or a write that found the binding stale.
pub fn shutdown_or_stale<S: Future<Output = ()> + Send + 'static>(
    shutdown: S,
    mode: &GatewayModeBindingV1,
) -> impl Future<Output = ()> + Send + 'static + use<S> {
    let signal = mode.stale_signal();
    async move {
        tokio::select! {
            () = shutdown => {}
            () = signal.wait() => {}
        }
    }
}

/// After the serve loop: a stale binding makes the process exit nonzero.
///
/// # Errors
/// Returns [`GatewayModeBindingErrorV1::Stale`] when a write found the
/// binding stale.
pub fn stale_binding_exit(mode: &GatewayModeBindingV1) -> Result<(), GatewayModeBindingErrorV1> {
    if mode.stale_signal().fired() {
        Err(GatewayModeBindingErrorV1::Stale)
    } else {
        Ok(())
    }
}

/// Stop what a failed bind left started, then report the bind failure.
///
/// # Errors
/// Always returns `error`; a failed executor shutdown is not reported over it.
pub async fn stop_after_bind_failure(
    gateway: &Gateway,
    error: io::Error,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    drop(gateway.shutdown().await);
    Err(Box::new(error))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_stale_binding_ends_the_serve_loop_and_exits_nonzero() {
        let mode = crate::mode_profile::test_binding(
            crate::mode_profile::GatewayModeProfileIdV1::Local,
            [],
        );
        announce_mode_binding(&mode);
        assert_eq!(stale_binding_exit(&mode), Ok(()));
        shutdown_or_stale(async {}, &mode).await;
        let waiting = shutdown_or_stale(std::future::pending(), &mode);
        mode.stale_signal().fire();
        waiting.await;
        assert_eq!(
            stale_binding_exit(&mode),
            Err(GatewayModeBindingErrorV1::Stale)
        );
    }

    #[test]
    fn startup_recovery_error_is_payload_free() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let unopenable = directory
            .path()
            .to_str()
            .ok_or("temporary directory path is not UTF-8")?
            .to_owned();
        for store in [GatewayHostStoreV1::Standard, GatewayHostStoreV1::OwnTracks] {
            let error = open_recovered_erasure_host(
                StoreConfig::Sqlite {
                    path: unopenable.clone(),
                },
                store,
                &ErasureCoordinatorCompositionV1::closed(),
            )
            .err()
            .ok_or("an unopenable store recovered")?;
            assert!(error
                .to_string()
                .starts_with("erasure host recovery failed ("));
        }
        Ok(())
    }
}
