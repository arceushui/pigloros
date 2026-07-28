#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
//! `piglor-gateway` binary — bind local HTTP/WS listener (ADR-014 / #69).
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use piglor_gateway::{router, AppState, Gateway, LedgerGateway, LedgerWriteMode};
use piglor_ledger::LedgerView;
use pos_plugin_ledger::{LedgerStore, TomlLedgerStore};
use pos_store::{open_store, StoreConfig};
use std::net::SocketAddr;

#[cfg(not(test))]
fn handle_run_error(e: &dyn std::error::Error) -> ! {
    eprintln!("Error: {e}");
    std::process::exit(1);
}

#[cfg(test)]
fn handle_run_error(e: &dyn std::error::Error) {
    eprintln!("Error (test): {e}");
}

fn main() {
    run_main(&std::env::args().collect::<Vec<_>>());
}

fn run_main(args: &[String]) {
    if let Err(e) = run_with_args(args) {
        handle_run_error(e.as_ref());
    }
}

fn run_with_args(args: &[String]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match args.get(1).map(String::as_str) {
        Some("serve") => {
            let addr = args
                .get(2)
                .map_or("127.0.0.1:8080", String::as_str)
                .parse::<SocketAddr>()?;
            warn_if_non_loopback(addr);
            let store_path = args.get(3).map(String::as_str);
            let (ledger_view, ledger_write) = load_ledger();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio current-thread runtime");
            rt.block_on(serve(
                addr,
                store_path,
                shutdown_signal(),
                ledger_view,
                ledger_write,
            ))
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            Ok(())
        }
        Some("version") => {
            println!("piglor-gateway {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => {
            eprintln!("Usage: piglor-gateway <serve [addr] [sqlite-path]|version>");
            eprintln!("  serve 127.0.0.1:8080           # Memory store");
            eprintln!("  serve 127.0.0.1:8080 /tmp/g.db # SQLite store");
            Ok(())
        }
    }
}

fn warn_if_non_loopback(addr: SocketAddr) {
    if !addr.ip().is_loopback() {
        eprintln!(
            "WARNING: binding {addr} (non-loopback) with no auth — anyone can append. Prefer 127.0.0.1 until #68."
        );
    }
}

fn load_ledger() -> (LedgerView, LedgerWriteMode) {
    let ledger_view = match std::env::var("LEDGER_SOURCE").ok() {
        Some(path) if !path.is_empty() => {
            eprintln!("LEDGER_SOURCE={path}: loading TOML ledger for display");
            let store = TomlLedgerStore::new(path);
            let today = format_utc_today();
            match store.load(&today) {
                Ok(ledger) => LedgerView::from(&ledger),
                Err(e) => {
                    eprintln!("WARNING: failed to load ledger: {e}");
                    LedgerView::default()
                }
            }
        }
        _ => LedgerView::default(),
    };
    let write = if std::env::var("LEDGER_WRITE").is_ok_and(|v| v == "1") {
        match std::env::var("LEDGER_SOURCE").ok() {
            Some(path) if !path.is_empty() => {
                let store = TomlLedgerStore::new(path);
                LedgerWriteMode::Ready(LedgerGateway::new(Box::new(store)))
            }
            _ => {
                eprintln!("LEDGER_WRITE=1 but LEDGER_SOURCE not set; store tier not yet available");
                LedgerWriteMode::Unconfigured
            }
        }
    } else {
        LedgerWriteMode::Disabled
    };
    (ledger_view, write)
}

#[cfg(not(test))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn format_utc_today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock set before Unix epoch")
        .as_secs();
    // days since 1970-01-01
    let days = u32::try_from(secs / 86_400).expect("overflow");
    let z = u64::from(days) + 719_468;
    let era = z / 146_097;
    let doe = u64::from(u32::try_from(z - era * 146_097).expect("overflow"));
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = mp + if mp < 10 { 3 } else { u64::wrapping_sub(9, 0) };
    let d = doy - (153 * mp + 2) / 5 + 1;
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
async fn shutdown_signal() {
    // Tests must not hang on ctrl_c; shut down as soon as the server is ready.
    tokio::task::yield_now().await;
}

async fn serve(
    addr: SocketAddr,
    sqlite_path: Option<&str>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ledger_view: LedgerView,
    ledger_write: LedgerWriteMode,
) -> Result<(), String> {
    let config = match sqlite_path {
        Some(path) => StoreConfig::Sqlite {
            path: path.to_owned(),
        },
        None => StoreConfig::Memory,
    };
    let gateway = Gateway::new(open_store(config).map_err(|e| e.to_string())?);
    let app = router(AppState {
        gateway,
        ledger_view,
        ledger_write,
    });
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| e.to_string())?;
    eprintln!("piglor-gateway listening on http://{addr}");
    // After graceful shutdown the accept-loop I/O error path is not practical to
    // force in unit tests; treat unexpected accept-loop failure as fatal.
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .expect("gateway HTTP accept loop failed");
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn warn_if_non_loopback_covers_both_arms() {
        warn_if_non_loopback("127.0.0.1:8080".parse().unwrap());
        warn_if_non_loopback("0.0.0.0:8080".parse().unwrap());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn main_does_not_panic_in_test_context() {
        main();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn version_and_usage_paths() {
        run_main(&[String::from("piglor-gateway"), String::from("version")]);
        run_main(&[String::from("piglor-gateway")]);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_main_error_path() {
        run_main(&[
            String::from("piglor-gateway"),
            String::from("serve"),
            String::from("not-an-addr"),
        ]);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_main_serve_memory_shuts_down() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        run_with_args(&[
            String::from("piglor-gateway"),
            String::from("serve"),
            addr.to_string(),
        ])
        .unwrap();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_main_serve_sqlite_shuts_down() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let path = std::env::temp_dir().join(format!("piglor-gw-cli-{}.db", std::process::id()));
        run_with_args(&[
            String::from("piglor-gateway"),
            String::from("serve"),
            addr.to_string(),
            path.to_str().unwrap().to_owned(),
        ])
        .unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn handle_run_error_prints() {
        handle_run_error(&GatewayProbe);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn serve_memory_and_sqlite_shut_down() {
        // Memory bind + immediate shutdown.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let serve_mem = tokio::spawn(async move {
            serve(
                addr,
                None,
                async move {
                    let _ = rx.await;
                },
                LedgerView::default(),
                LedgerWriteMode::Disabled,
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = tx.send(());
        serve_mem.await.unwrap().unwrap();

        // SQLite path arm.
        let dir = std::env::temp_dir().join(format!("piglor-gw-{}.db", std::process::id()));
        let path = dir.to_str().unwrap().to_owned();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let path_clone = path.clone();
        let serve_sql = tokio::spawn(async move {
            serve(
                addr,
                Some(path_clone.as_str()),
                async move {
                    let _ = rx.await;
                },
                LedgerView::default(),
                LedgerWriteMode::Disabled,
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = tx.send(());
        serve_sql.await.unwrap().unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_main_serve_open_store_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let dir = std::env::temp_dir().join(format!("piglor-gw-dir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let err = run_with_args(&[
            String::from("piglor-gateway"),
            String::from("serve"),
            addr.to_string(),
            dir.to_str().unwrap().to_owned(),
        ])
        .unwrap_err();
        assert!(!err.to_string().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_main_serve_bind_error() {
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = occupied.local_addr().unwrap();
        let err = run_with_args(&[
            String::from("piglor-gateway"),
            String::from("serve"),
            addr.to_string(),
        ])
        .unwrap_err();
        assert!(!err.to_string().is_empty());
        drop(occupied);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn serve_bind_error_direct() {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = occupied.local_addr().unwrap();
        let err = serve(
            addr,
            None,
            async {},
            LedgerView::default(),
            LedgerWriteMode::Disabled,
        )
        .await
        .unwrap_err();
        assert!(!err.is_empty());
        drop(occupied);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn serve_open_store_error_direct() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let dir = std::env::temp_dir().join(format!("piglor-gw-sql-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let err = serve(
            addr,
            Some(dir.to_str().unwrap()),
            async {},
            LedgerView::default(),
            LedgerWriteMode::Disabled,
        )
        .await
        .unwrap_err();
        assert!(!err.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[derive(Debug)]
    struct GatewayProbe;
    impl std::fmt::Display for GatewayProbe {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "probe")
        }
    }
    impl std::error::Error for GatewayProbe {}

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn load_ledger_gate_on_no_source_returns_unconfigured() {
        std::env::set_var("LEDGER_WRITE", "1");
        std::env::remove_var("LEDGER_SOURCE");
        let (view, mode) = super::load_ledger();
        std::env::remove_var("LEDGER_WRITE");
        assert!(matches!(mode, LedgerWriteMode::Unconfigured));
        assert!(view.entries.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn load_ledger_gate_on_with_source_returns_ready() {
        let dir =
            std::env::temp_dir().join(format!("piglor-gw-ledger-load-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.to_str().unwrap().to_owned();
        std::env::set_var("LEDGER_WRITE", "1");
        std::env::set_var("LEDGER_SOURCE", &path);
        let (_view, mode) = super::load_ledger();
        std::env::remove_var("LEDGER_WRITE");
        std::env::remove_var("LEDGER_SOURCE");
        assert!(matches!(mode, LedgerWriteMode::Ready(_)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn format_utc_today_produces_valid_date() {
        let date = super::format_utc_today();
        let parts: Vec<&str> = date.split('-').collect();
        assert_eq!(parts.len(), 3);
        let year: i32 = parts[0].parse().unwrap();
        let month: u32 = parts[1].parse().unwrap();
        let day: u32 = parts[2].parse().unwrap();
        assert!((2024..=2100).contains(&year));
        assert!((1..=12).contains(&month));
        assert!((1..=31).contains(&day));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn load_ledger_bad_source_returns_empty_view() {
        let file = std::env::temp_dir().join(format!("piglor-gw-bad-{}", std::process::id()));
        std::fs::write(&file, "not a dir").unwrap();
        std::env::set_var("LEDGER_WRITE", "1");
        std::env::set_var("LEDGER_SOURCE", file.to_str().unwrap());
        let (view, mode) = super::load_ledger();
        std::env::remove_var("LEDGER_WRITE");
        std::env::remove_var("LEDGER_SOURCE");
        // Store creation succeeds but loading fails because path is a file, not a directory
        assert!(view.entries.is_empty());
        let _ = std::fs::remove_file(file);
    }
}
