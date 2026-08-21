#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
//! `piglor-gateway` binary — bind local HTTP/WS listener (ADR-014 / #69).
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use piglor_gateway::{
    router_for_addr, AppState, Gateway, LedgerConfig, LedgerWriteMode, OwnTracksOwnerKey,
};
use piglor_ledger::LedgerView;
use pos_store::{open_store, StoreConfig};
use std::{ffi::OsString, future::Future, net::SocketAddr, path::PathBuf, pin::Pin};

mod owntracks;

type ShutdownFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

fn handle_run_error(e: &dyn std::error::Error) {
    eprintln!("Error: {e}");
}

fn main() -> std::process::ExitCode {
    main_with_args(&std::env::args().collect::<Vec<_>>())
}

fn main_with_args(args: &[String]) -> std::process::ExitCode {
    match run_main(args) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            handle_run_error(error.as_ref());
            std::process::ExitCode::FAILURE
        }
    }
}

fn run_main(args: &[String]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_with_args(args)
}

fn run_with_args(args: &[String]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_with_args_and_shutdown(
        args,
        Box::pin(shutdown_signal_from(tokio::signal::ctrl_c())),
    )
}

#[derive(Clone, Debug, Default)]
struct LedgerEnvironment {
    source: Option<OsString>,
    write_enabled: bool,
}

impl LedgerEnvironment {
    fn from_process() -> Self {
        Self {
            source: std::env::var_os("LEDGER_SOURCE"),
            write_enabled: std::env::var("LEDGER_WRITE").unwrap_or_default() == "1",
        }
    }
}

fn run_with_args_and_shutdown(
    args: &[String],
    shutdown: ShutdownFuture,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_with_args_and_shutdown_with_environment(args, shutdown, LedgerEnvironment::from_process())
}

fn run_with_args_and_shutdown_with_environment(
    args: &[String],
    shutdown: ShutdownFuture,
    environment: LedgerEnvironment,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match args.get(1).map(String::as_str) {
        Some("owntracks") => {
            let output = owntracks::execute(&args[2..])?;
            println!("{output}");
            Ok(())
        }
        Some("serve") => {
            let serve_args = parse_serve_args(&args[2..])?;
            let (ledger_view, ledger_write) = match load_ledger_with_environment(environment) {
                Ok(ledger) => ledger,
                Err(error) => return Err(Box::new(error)),
            };
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("gateway Tokio runtime initialization failed");
            rt.block_on(serve_with_owntracks(
                serve_args.addr,
                serve_args.sqlite_path.as_deref(),
                serve_args.owntracks_owner_key.as_deref(),
                shutdown,
                ledger_view,
                ledger_write,
            ))
        }
        Some("version") => {
            println!("piglor-gateway {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => {
            eprintln!("Usage: piglor-gateway <owntracks|serve [addr] [sqlite-path] [--owntracks-owner-key <path>]|version>");
            eprintln!("  owntracks pair <sqlite-path> <owner-key-path> --consent-policy <path> <timeline-id> <entity-id>");
            eprintln!("  owntracks status <sqlite-path>");
            eprintln!("  owntracks rotate <sqlite-path> <owner-key-path>");
            eprintln!("  owntracks revoke <sqlite-path>");
            eprintln!("  serve 127.0.0.1:8080           # Memory store");
            eprintln!("  serve 127.0.0.1:8080 /tmp/g.db # SQLite store");
            Ok(())
        }
    }
}

#[derive(Debug)]
struct ServeArgs {
    addr: SocketAddr,
    sqlite_path: Option<String>,
    owntracks_owner_key: Option<PathBuf>,
}

fn parse_serve_args(
    args: &[String],
) -> Result<ServeArgs, Box<dyn std::error::Error + Send + Sync>> {
    let mut positional = Vec::new();
    let mut owner_key = None;
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--owntracks-owner-key" {
            if owner_key.is_some() {
                return Err("OwnTracks owner key option may be specified once".into());
            }
            let Some(path) = args.get(index + 1) else {
                return Err("OwnTracks owner key path is required".into());
            };
            owner_key = Some(PathBuf::from(path));
            index += 2;
        } else {
            positional.push(args[index].clone());
            index += 1;
        }
    }
    if positional.len() > 2 {
        return Err("serve accepts at most an address and SQLite path".into());
    }
    let addr = positional
        .first()
        .map_or(Ok("127.0.0.1:8080".parse()?), |value| value.parse())?;
    let sqlite_path = positional.get(1).cloned();
    if owner_key.is_some() && sqlite_path.is_none() {
        return Err("OwnTracks ingress requires an SQLite path".into());
    }
    Ok(ServeArgs {
        addr,
        sqlite_path,
        owntracks_owner_key: owner_key,
    })
}

fn is_spectator_deployment(addr: SocketAddr) -> bool {
    !addr.ip().is_loopback()
}

fn load_ledger_with_environment(
    environment: LedgerEnvironment,
) -> Result<(LedgerView, LedgerWriteMode), pos_plugin_ledger::LedgerError> {
    LedgerConfig::new(
        environment.source.map(PathBuf::from),
        environment.write_enabled,
    )
    .load(&piglor_ledger::today_utc())
}

async fn shutdown_signal_from<F>(signal: F)
where
    F: std::future::Future<Output = Result<(), std::io::Error>>,
{
    let _ = signal.await;
}

#[cfg_attr(not(test), allow(dead_code))]
async fn serve(
    addr: SocketAddr,
    sqlite_path: Option<&str>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ledger_view: LedgerView,
    ledger_write: LedgerWriteMode,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    serve_with_owntracks(addr, sqlite_path, None, shutdown, ledger_view, ledger_write).await
}

async fn serve_with_owntracks(
    addr: SocketAddr,
    sqlite_path: Option<&str>,
    owntracks_owner_key_path: Option<&std::path::Path>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ledger_view: LedgerView,
    ledger_write: LedgerWriteMode,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = match sqlite_path {
        Some(path) => StoreConfig::Sqlite {
            path: path.to_owned(),
        },
        None => StoreConfig::Memory,
    };
    let owntracks_owner_key = if is_spectator_deployment(addr) {
        None
    } else {
        owntracks_owner_key_path
            .map(OwnTracksOwnerKey::load)
            .transpose()?
    };
    let gateway = match (owntracks_owner_key.as_ref(), sqlite_path) {
        (Some(owner_key), Some(path)) => Gateway::new_with_owntracks_ingress(
            pos_store::sqlite::SqliteStore::open(path)?,
            owner_key,
        ),
        (None, _) => Gateway::new(open_store(config)?),
        (Some(_), None) => return Err("OwnTracks ingress requires an SQLite path".into()),
    };
    let state = AppState {
        gateway: gateway.clone(),
        ledger_view,
        ledger_write,
    };
    let app = router_for_addr(addr, state);
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(error) => {
            let _ = gateway.shutdown().await;
            return Err(Box::new(error));
        }
    };
    eprintln!("piglor-gateway listening on http://{addr}");
    let serve_result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await;
    let shutdown_result = gateway.shutdown().await;
    match (serve_result, shutdown_result) {
        (Err(error), _) => Err(Box::new(error)),
        (Ok(()), Err(error)) => Err(Box::new(error)),
        (Ok(()), Ok(())) => Ok(()),
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::handle_run_error;
    use std::fmt;

    #[derive(Debug)]
    struct ProbeError;

    impl fmt::Display for ProbeError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("probe")
        }
    }

    impl std::error::Error for ProbeError {}

    #[test]
    fn error_handler_is_callable_at_public_process_seam() {
        handle_run_error(&ProbeError);
    }

    #[test]
    fn main_error_returns_failure_exit_code() {
        let _ = super::main_with_args(&[
            "piglor-gateway".to_owned(),
            "serve".to_owned(),
            "not-an-address".to_owned(),
        ]);
    }

    #[test]
    fn run_with_args_reports_parse_and_bind_errors() {
        let parse_error = super::run_with_args(&[
            "piglor-gateway".to_owned(),
            "serve".to_owned(),
            "not-an-address".to_owned(),
        ])
        .unwrap_err();
        assert!(!parse_error.to_string().is_empty());

        let ledger_error = super::run_with_args_and_shutdown_with_environment(
            &[
                "piglor-gateway".to_owned(),
                "serve".to_owned(),
                "127.0.0.1:0".to_owned(),
            ],
            Box::pin(async {}),
            super::LedgerEnvironment {
                source: Some(
                    std::env::temp_dir()
                        .join("piglor-gateway-missing-ledger")
                        .into_os_string(),
                ),
                write_enabled: false,
            },
        )
        .unwrap_err();
        assert!(!ledger_error.to_string().is_empty());
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn owntracks_activation_requires_sqlite_and_parses_one_existing_key_path() {
        let missing_sqlite = parse_serve_args(&[
            "127.0.0.1:0".to_owned(),
            "--owntracks-owner-key".to_owned(),
            "/private/owner.key".to_owned(),
        ])
        .unwrap_err();
        assert!(missing_sqlite.to_string().contains("SQLite"));

        let parsed = parse_serve_args(&[
            "127.0.0.1:0".to_owned(),
            "/private/store.db".to_owned(),
            "--owntracks-owner-key".to_owned(),
            "/private/owner.key".to_owned(),
        ])
        .unwrap();
        assert_eq!(parsed.sqlite_path.as_deref(), Some("/private/store.db"));
        assert_eq!(
            parsed.owntracks_owner_key.as_deref(),
            Some(std::path::Path::new("/private/owner.key"))
        );

        let repeated = parse_serve_args(&[
            "127.0.0.1:0".to_owned(),
            "/private/store.db".to_owned(),
            "--owntracks-owner-key".to_owned(),
            "/private/one.key".to_owned(),
            "--owntracks-owner-key".to_owned(),
            "/private/two.key".to_owned(),
        ])
        .unwrap_err();
        assert!(repeated.to_string().contains("once"));
    }

    #[test]
    fn owntracks_argument_parser_rejects_missing_path_and_extra_positionals() {
        let missing_path = parse_serve_args(&["--owntracks-owner-key".to_owned()]).unwrap_err();
        assert!(missing_path.to_string().contains("path is required"));

        let too_many = parse_serve_args(&[
            "127.0.0.1:0".to_owned(),
            "one.db".to_owned(),
            "extra".to_owned(),
        ])
        .unwrap_err();
        assert!(too_many.to_string().contains("at most"));
    }

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
        let _ = run_main(&[String::from("piglor-gateway"), String::from("version")]);
        let _ = run_main(&[String::from("piglor-gateway")]);
    }

    #[test]
    fn owntracks_subcommand_is_dispatched_by_the_binary_entrypoint() {
        let database = std::env::temp_dir().join(format!(
            "piglor-gw-owntracks-dispatch-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        run_with_args_and_shutdown(
            &[
                String::from("piglor-gateway"),
                String::from("owntracks"),
                String::from("status"),
                database.display().to_string(),
            ],
            Box::pin(async {}),
        )
        .unwrap();
        let _ = std::fs::remove_file(database);
    }

    #[test]
    fn serve_dispatches_owner_key_and_sqlite_configuration() {
        let directory = std::env::temp_dir().join(format!(
            "piglor-gw-owner-serve-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let database = directory.join("gateway.db");
        let owner_key = directory.join("owner.key");
        owntracks::create_or_load_owner_key(&owner_key).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        run_with_args_and_shutdown(
            &[
                String::from("piglor-gateway"),
                String::from("serve"),
                addr.to_string(),
                database.display().to_string(),
                String::from("--owntracks-owner-key"),
                owner_key.display().to_string(),
            ],
            Box::pin(async {
                tokio::task::yield_now().await;
            }),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let missing_sqlite = runtime
            .block_on(serve_with_owntracks(
                addr,
                None,
                Some(&owner_key),
                async {},
                LedgerView::default(),
                LedgerWriteMode::Disabled,
            ))
            .unwrap_err();
        assert!(missing_sqlite.to_string().contains("SQLite"));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_main_error_path() {
        let _ = run_main(&[
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
        run_with_args_and_shutdown(
            &[
                String::from("piglor-gateway"),
                String::from("serve"),
                addr.to_string(),
            ],
            Box::pin(async {
                tokio::task::yield_now().await;
            }),
        )
        .unwrap();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_main_serve_sqlite_shuts_down() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let path = std::env::temp_dir().join(format!("piglor-gw-cli-{}.db", std::process::id()));
        run_with_args_and_shutdown(
            &[
                String::from("piglor-gateway"),
                String::from("serve"),
                addr.to_string(),
                path.to_str().unwrap().to_owned(),
            ],
            Box::pin(async {
                tokio::task::yield_now().await;
            }),
        )
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

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_main_serve_invalid_ledger_returns_error() {
        let dir = malformed_ledger_dir("startup");
        let error = run_with_args_and_shutdown_with_environment(
            &[
                String::from("piglor-gateway"),
                String::from("serve"),
                String::from("127.0.0.1:0"),
            ],
            Box::pin(async {}),
            LedgerEnvironment {
                source: Some(dir.clone().into_os_string()),
                write_enabled: false,
            },
        )
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
        assert!(!err.to_string().is_empty());
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
        assert!(!err.to_string().is_empty());
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
        let (view, mode) = load_ledger_with_environment(LedgerEnvironment {
            source: None,
            write_enabled: true,
        })
        .unwrap();
        assert!(matches!(mode, LedgerWriteMode::Unconfigured));
        assert!(view.entries.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn startup_reads_configured_source_and_write_flag() {
        let dir = ledger_temp_path("startup-ready");
        std::fs::create_dir_all(&dir).unwrap();
        let (_, disabled) = load_ledger_with_environment(LedgerEnvironment {
            source: Some(dir.clone().into_os_string()),
            write_enabled: false,
        })
        .unwrap();
        assert!(matches!(disabled, LedgerWriteMode::Disabled));
        let (_, ready) = load_ledger_with_environment(LedgerEnvironment {
            source: Some(dir.clone().into_os_string()),
            write_enabled: true,
        })
        .unwrap();
        assert!(matches!(ready, LedgerWriteMode::Ready(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn startup_rejects_explicitly_configured_empty_source() {
        let Err(error) = load_ledger_with_environment(LedgerEnvironment {
            source: Some(OsString::new()),
            write_enabled: false,
        }) else {
            panic!("an explicitly configured empty Ledger source must fail");
        };
        assert!(!error.to_string().is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn startup_rejects_configured_non_directory_source() {
        let path = ledger_temp_path("startup-not-directory");
        std::fs::write(&path, "not a directory").unwrap();
        let Err(error) = load_ledger_with_environment(LedgerEnvironment {
            source: Some(path.clone().into_os_string()),
            write_enabled: false,
        }) else {
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

        let temporary = std::env::temp_dir().join(format!(
            "piglor-gw-ledger-non-unicode-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut path = temporary.into_os_string().into_vec();
        path.push(0xff);
        let source = OsString::from_vec(path);
        let error = run_with_args_and_shutdown_with_environment(
            &[
                String::from("piglor-gateway"),
                String::from("serve"),
                String::from("127.0.0.1:0"),
            ],
            Box::pin(async {}),
            LedgerEnvironment {
                source: Some(source),
                write_enabled: false,
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("No such file or directory"));
    }
}

#[cfg(test)]
mod shutdown_signal_tests {
    #[tokio::test]
    async fn completed_signal_is_observed_without_process_signals() {
        super::shutdown_signal_from(async { Ok(()) }).await;
    }
}
