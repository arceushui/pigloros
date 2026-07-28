#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
//! `piglor-gateway` binary — bind local HTTP/WS listener (ADR-014 / #69).
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use piglor_gateway::{router, spectator_router, AppState, Gateway, LedgerConfig, LedgerWriteMode};
use piglor_ledger::LedgerView;
use pos_store::{open_store, StoreConfig};
use std::{net::SocketAddr, path::PathBuf};

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
            let store_path = args.get(3).map(String::as_str);
            let (ledger_view, ledger_write) = match load_ledger() {
                Ok(ledger) => ledger,
                Err(error) => return Err(Box::new(error)),
            };
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

fn is_spectator_deployment(addr: SocketAddr) -> bool {
    !addr.ip().is_loopback()
}

fn router_for_addr(addr: SocketAddr, state: AppState) -> axum::Router {
    if is_spectator_deployment(addr) {
        eprintln!(
            "piglor-gateway serving public Prediction Ledger routes only at {addr}; Timeline and write routes require loopback until #68 authentication exists"
        );
        spectator_router(state)
    } else {
        router(state)
    }
}

fn load_ledger() -> Result<(LedgerView, LedgerWriteMode), pos_plugin_ledger::LedgerError> {
    let source = std::env::var_os("LEDGER_SOURCE").map(PathBuf::from);
    LedgerConfig::new(
        source,
        std::env::var("LEDGER_WRITE").unwrap_or_default() == "1",
    )
    .load(&piglor_ledger::today_utc())
}

#[cfg(not(test))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
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
    let state = AppState {
        gateway,
        ledger_view,
        ledger_write,
    };
    let app = router_for_addr(addr, state);
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
    use std::ffi::{OsStr, OsString};
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    async fn serve_http_requests(bind_ip: IpAddr, requests: &[&str]) -> Vec<String> {
        let listener = tokio::net::TcpListener::bind((bind_ip, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
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

        let mut connect_addr = addr;
        connect_addr.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let requests = requests.iter().map(ToString::to_string).collect::<Vec<_>>();
        let responses = tokio::task::spawn_blocking(move || {
            requests
                .iter()
                .map(|request| {
                    let mut stream = std::net::TcpStream::connect(connect_addr).unwrap();
                    stream.write_all(request.as_bytes()).unwrap();
                    let mut response = String::new();
                    stream.read_to_string(&mut response).unwrap();
                    response
                })
                .collect::<Vec<_>>()
        })
        .await
        .unwrap();

        let _ = tx.send(());
        server.await.unwrap().unwrap();
        responses
    }

    const HEALTH_REQUEST: &str =
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    const CREATE_TIMELINE_REQUEST: &str = "POST /v1/timelines HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{\"name\":\"local\"}";

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &OsStr) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = std::env::var_os(key);
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn clean_ledger_environment() -> [EnvVarGuard; 2] {
        [
            EnvVarGuard::remove("LEDGER_SOURCE"),
            EnvVarGuard::remove("LEDGER_WRITE"),
        ]
    }

    fn ledger_temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("piglor-gw-ledger-{label}-{}", std::process::id()))
    }

    fn malformed_ledger_dir(label: &str) -> PathBuf {
        let dir = ledger_temp_path(label);
        let predictions = dir.join("predictions");
        std::fs::create_dir_all(&predictions).unwrap();
        std::fs::write(predictions.join("invalid.toml"), "not valid = [").unwrap();
        dir
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn non_loopback_server_is_public_read_only() {
        let responses = serve_http_requests(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            &[HEALTH_REQUEST, CREATE_TIMELINE_REQUEST],
        )
        .await;
        assert!(responses[0].starts_with("HTTP/1.1 200 OK"));
        assert!(responses[1].starts_with("HTTP/1.1 404 Not Found"));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn loopback_server_retains_timeline_api() {
        let responses =
            serve_http_requests(IpAddr::V4(Ipv4Addr::LOCALHOST), &[CREATE_TIMELINE_REQUEST]).await;
        assert!(responses[0].starts_with("HTTP/1.1 201 Created"));
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
        let _guard = ENV_LOCK.lock().unwrap();
        let _environment = clean_ledger_environment();
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
        let _guard = ENV_LOCK.lock().unwrap();
        let _environment = clean_ledger_environment();
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
        let _guard = ENV_LOCK.lock().unwrap();
        let _environment = clean_ledger_environment();
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
        let _guard = ENV_LOCK.lock().unwrap();
        let _environment = clean_ledger_environment();
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

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_main_serve_invalid_ledger_returns_error() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _environment = clean_ledger_environment();
        let dir = malformed_ledger_dir("startup");
        let _source = EnvVarGuard::set("LEDGER_SOURCE", dir.as_os_str());
        let error = run_with_args(&[
            String::from("piglor-gateway"),
            String::from("serve"),
            String::from("127.0.0.1:0"),
        ])
        .unwrap_err();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(error.to_string().contains("TOML"));
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
    fn startup_without_source_marks_writes_unconfigured() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _environment = clean_ledger_environment();
        let _write = EnvVarGuard::set("LEDGER_WRITE", OsStr::new("1"));
        let (view, mode) = load_ledger().unwrap();
        assert!(matches!(mode, LedgerWriteMode::Unconfigured));
        assert!(view.entries.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn startup_reads_configured_source_and_write_flag() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _environment = clean_ledger_environment();
        let dir = ledger_temp_path("startup-ready");
        std::fs::create_dir_all(&dir).unwrap();
        let _source = EnvVarGuard::set("LEDGER_SOURCE", dir.as_os_str());
        let (_, disabled) = load_ledger().unwrap();
        assert!(matches!(disabled, LedgerWriteMode::Disabled));
        {
            let _write = EnvVarGuard::set("LEDGER_WRITE", OsStr::new("1"));
            let (_, ready) = load_ledger().unwrap();
            assert!(matches!(ready, LedgerWriteMode::Ready(_)));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn startup_rejects_explicitly_configured_empty_source() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _environment = clean_ledger_environment();
        let _source = EnvVarGuard::set("LEDGER_SOURCE", OsStr::new(""));
        let Err(error) = load_ledger() else {
            panic!("an explicitly configured empty Ledger source must fail");
        };
        assert!(!error.to_string().is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn startup_rejects_configured_non_directory_source() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _environment = clean_ledger_environment();
        let path = ledger_temp_path("startup-not-directory");
        std::fs::write(&path, "not a directory").unwrap();
        let _source = EnvVarGuard::set("LEDGER_SOURCE", path.as_os_str());
        let Err(error) = load_ledger() else {
            panic!("a configured non-directory Ledger source must fail");
        };
        let _ = std::fs::remove_file(path);
        assert!(!error.to_string().is_empty());
    }

    #[cfg(unix)]
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn startup_preserves_non_unicode_ledger_source() {
        use std::os::unix::ffi::OsStringExt as _;

        let _guard = ENV_LOCK.lock().unwrap();
        let _environment = clean_ledger_environment();
        let mut path =
            format!("/tmp/piglor-gw-ledger-non-unicode-{}-", std::process::id()).into_bytes();
        path.push(0xff);
        let source = OsString::from_vec(path);
        let _source = EnvVarGuard::set("LEDGER_SOURCE", &source);
        let error = run_with_args(&[
            String::from("piglor-gateway"),
            String::from("serve"),
            String::from("127.0.0.1:0"),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("No such file or directory"));
    }
}
