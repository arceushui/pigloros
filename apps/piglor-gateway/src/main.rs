#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
//! `piglor-gateway` binary — bind local HTTP/WS listener (ADR-014 / #69).
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

macro_rules! output_stdout {
    ($($arg:tt)*) => {{
        let mut output = std::io::stdout().lock();
        drop(std::io::Write::write_fmt(&mut output, format_args!($($arg)*)));
        drop(std::io::Write::write_all(&mut output, b"\n"));
    }};
}

macro_rules! output_stderr {
    ($($arg:tt)*) => {{
        let mut output = std::io::stderr().lock();
        drop(std::io::Write::write_fmt(&mut output, format_args!($($arg)*)));
        drop(std::io::Write::write_all(&mut output, b"\n"));
    }};
}

#[cfg(target_os = "linux")]
use piglor_gateway::local_fork_service::{
    provision_local_fork_admission_authority, serve_managed_local_fork_admission,
    ManagedLocalForkAdmissionV1,
};
use piglor_gateway::local_principal::local_gateway;
#[cfg(target_os = "linux")]
use piglor_gateway::local_principal::provision_local_principal_from_credentials;
use piglor_gateway::mode_profile::{
    bind_gateway_mode_v1, migrate_gateway_mode_v1, verify_gateway_serve_composition_v1,
    GatewayModeBindingV1, GatewayModeProfileIdV1, GatewayModeStoreLockV1, GatewayNetworkGrantV1,
    GatewayServeCompositionV1,
};
use piglor_gateway::startup::{
    announce_listening, announce_mode_binding, bound_router, open_recovered_erasure_host,
    shutdown_or_stale, stale_binding_exit, stop_after_bind_failure, GatewayHostStoreV1,
};
use piglor_gateway::{
    owntracks, router_for_addr, AppState, Gateway, LedgerConfig, LedgerWriteMode, OwnTracksOwnerKey,
};
use piglor_ledger::LedgerView;
use pos_runtime::ErasureCoordinatorCompositionV1;
use pos_store::StoreConfig;
use std::{
    collections::BTreeSet,
    ffi::OsString,
    future::Future,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
};

type ShutdownFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
type RunError = Box<dyn std::error::Error + Send + Sync>;

const GATEWAY_CREDENTIAL_DIRECTORY: &str = "/run/credentials/piglor-gateway.service";
const PROVISION_CREDENTIAL_DIRECTORY: &str =
    "/run/credentials/piglor-gateway-fork-admission-provision.service";
const LOCAL_PRINCIPAL_CREDENTIAL_DIRECTORY: &str =
    "/run/credentials/piglor-gateway-local-principal-provision.service";
#[cfg(target_os = "linux")]
const FORK_ADMISSION_SOCKET: &str = "/run/pigloros/fork-admission.sock";
const MIGRATE_MODE_USAGE: &str =
    "Usage: piglor-gateway migrate-mode <sqlite-path> --from <profile> --to <profile>";

fn handle_run_error(e: &dyn std::error::Error) {
    output_stderr!("Error: {e}");
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

fn run_main(args: &[String]) -> Result<(), RunError> {
    run_with_args(args)
}

fn run_with_args(args: &[String]) -> Result<(), RunError> {
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

fn run_with_args_and_shutdown(args: &[String], shutdown: ShutdownFuture) -> Result<(), RunError> {
    run_with_args_and_shutdown_with_environment(args, shutdown, LedgerEnvironment::from_process())
}

fn run_with_args_and_shutdown_with_environment(
    args: &[String],
    shutdown: ShutdownFuture,
    environment: LedgerEnvironment,
) -> Result<(), RunError> {
    migrate_mode_command(args).unwrap_or_else(|| {
        run_with_args_and_shutdown_with_environment_and_credentials(
            args,
            shutdown,
            environment,
            std::env::var_os("CREDENTIALS_DIRECTORY"),
        )
    })
}

fn run_with_args_and_shutdown_with_environment_and_credentials(
    args: &[String],
    shutdown: ShutdownFuture,
    environment: LedgerEnvironment,
    credential_directory: Option<OsString>,
) -> Result<(), RunError> {
    match args.get(1).map(String::as_str) {
        Some("owntracks") => {
            let output = owntracks::execute(&args[2..])?;
            output_stdout!("{output}");
            Ok(())
        }
        Some("serve") => {
            let request = parse_serve_request(&args[2..])?;
            let fork_credentials = request
                .args
                .require_local_fork_authority
                .then(|| {
                    credential_directory_from(
                        credential_directory.clone(),
                        GATEWAY_CREDENTIAL_DIRECTORY,
                    )
                })
                .transpose()?;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(serve_request(
                &request,
                fork_credentials.as_deref(),
                shutdown,
                environment,
            ))
        }
        Some(command @ ("provision-local-fork-authority" | "provision-local-principal")) => {
            provision_command(command, args, credential_directory)
        }
        Some("fork-admission-provision") => Err(
            "fork-admission-provision was replaced by the systemd-only provision-local-fork-authority entry point"
                .into(),
        ),
        Some("version") => {
            output_stdout!("piglor-gateway {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => {
            output_stderr!("Usage: piglor-gateway <owntracks|serve --profile <profile> [addr] [sqlite-path] [--network-grant <owntracks|public-read-only>]... [--owntracks-owner-key <path>] [--require-local-fork-authority]|migrate-mode <sqlite-path> --from <profile> --to <profile>|provision-local-fork-authority <sqlite-path>|provision-local-principal <sqlite-path>|version>");
            output_stderr!("  profiles: gateway-mode-local-v1, gateway-mode-air-gapped-v1");
            output_stderr!("  owntracks pair <sqlite-path> <owner-key-path> --consent-policy <path> <timeline-id> <entity-id>");
            output_stderr!("  owntracks status <sqlite-path>");
            output_stderr!("  owntracks rotate <sqlite-path> <owner-key-path>");
            output_stderr!("  owntracks revoke <sqlite-path>");
            output_stderr!("  serve --profile gateway-mode-local-v1 127.0.0.1:8080           # Memory store");
            output_stderr!("  serve --profile gateway-mode-local-v1 127.0.0.1:8080 /tmp/g.db # SQLite store");
            output_stderr!(
                "  provision-local-fork-authority is available only to its installed systemd unit"
            );
            output_stderr!(
                "  provision-local-principal is available only to its installed systemd unit"
            );
            Ok(())
        }
    }
}

/// `migrate-mode <sqlite-path> --from <profile> --to <profile>` (ADR-134 §8),
/// or `None` for every other command.
fn migrate_mode_command(args: &[String]) -> Option<Result<(), RunError>> {
    (args.get(1).map(String::as_str) == Some("migrate-mode")).then(|| migrate_mode(&args[2..]))
}

fn migrate_mode(args: &[String]) -> Result<(), RunError> {
    match args {
        [sqlite_path, from_flag, from, to_flag, to]
            if from_flag == "--from" && to_flag == "--to" =>
        {
            let audit = migrate_gateway_mode_v1(sqlite_path, from.parse()?, to.parse()?)?;
            output_stdout!("{audit}");
            Ok(())
        }
        _ => Err(MIGRATE_MODE_USAGE.into()),
    }
}

/// `provision-local-fork-authority <sqlite-path>` and `provision-local-principal
/// <sqlite-path>`: one-shot provisioning, only under each command's systemd unit.
fn provision_command(
    command: &str,
    args: &[String],
    credential_directory: Option<OsString>,
) -> Result<(), RunError> {
    #[cfg(target_os = "linux")]
    {
        let Some(sqlite_path) = args.get(2) else {
            return Err(format!("{command} requires an SQLite path").into());
        };
        if args.len() != 3 {
            return Err(format!("{command} accepts exactly an SQLite path").into());
        }
        let provisioned = if command == "provision-local-principal" {
            provision_local_principal_from_credentials(
                sqlite_path,
                &credential_directory_from(
                    credential_directory,
                    LOCAL_PRINCIPAL_CREDENTIAL_DIRECTORY,
                )?,
            )
        } else {
            provision_local_fork_admission_authority(
                sqlite_path,
                &credential_directory_from(credential_directory, PROVISION_CREDENTIAL_DIRECTORY)?,
            )
        };
        provisioned.map_err(Into::into)
    }
    #[cfg(not(target_os = "linux"))]
    {
        drop((args, credential_directory));
        Err(format!("{command} requires Linux systemd credentials").into())
    }
}

#[derive(Debug)]
struct ServeArgs {
    addr: SocketAddr,
    sqlite_path: Option<String>,
    owntracks_owner_key: Option<PathBuf>,
    require_local_fork_authority: bool,
}

/// Raw `serve` flags before address and storage validation.
struct ServeFlags {
    positional: Vec<String>,
    owner_key: Option<PathBuf>,
    require_local_fork_authority: bool,
}

fn parse_serve_flags(args: &[String]) -> Result<ServeFlags, RunError> {
    let mut flags = ServeFlags {
        positional: Vec::new(),
        owner_key: None,
        require_local_fork_authority: false,
    };
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--owntracks-owner-key" {
            if flags.owner_key.is_some() {
                return Err("OwnTracks owner key option may be specified once".into());
            }
            let Some(path) = args.get(index + 1) else {
                return Err("OwnTracks owner key path is required".into());
            };
            flags.owner_key = Some(PathBuf::from(path));
            index += 2;
        } else if args[index] == "--require-local-fork-authority" {
            if flags.require_local_fork_authority {
                return Err("Local Fork authority option may be specified once".into());
            }
            flags.require_local_fork_authority = true;
            index += 1;
        } else {
            flags.positional.push(args[index].clone());
            index += 1;
        }
    }
    Ok(flags)
}

fn parse_serve_args(args: &[String]) -> Result<ServeArgs, RunError> {
    let flags = parse_serve_flags(args)?;
    if flags.positional.len() > 2 {
        return Err("serve accepts at most an address and SQLite path".into());
    }
    let addr = flags
        .positional
        .first()
        .map_or(Ok("127.0.0.1:8080".parse()?), |value| value.parse())?;
    let sqlite_path = flags.positional.get(1).cloned();
    if flags.owner_key.is_some() && sqlite_path.is_none() {
        return Err("OwnTracks ingress requires an SQLite path".into());
    }
    if flags.require_local_fork_authority && sqlite_path.is_none() {
        return Err("Fork admission requires an SQLite path".into());
    }
    Ok(ServeArgs {
        addr,
        sqlite_path,
        owntracks_owner_key: flags.owner_key,
        require_local_fork_authority: flags.require_local_fork_authority,
    })
}

/// One `serve` invocation: its flags plus the required `--profile` and the
/// repeatable `--network-grant` (ADR-134 §4).
#[derive(Debug)]
struct ServeRequest {
    args: ServeArgs,
    profile: GatewayModeProfileIdV1,
    network_grants: BTreeSet<GatewayNetworkGrantV1>,
}

impl ServeRequest {
    /// The host-owned facts the startup predicates check.
    fn composition(&self, environment: &LedgerEnvironment) -> GatewayServeCompositionV1 {
        GatewayServeCompositionV1 {
            tcp_addr: self.args.addr,
            owntracks_ingress: self.args.owntracks_owner_key.is_some(),
            fork_admission_socket: self.args.require_local_fork_authority,
            ledger_source: environment.source.clone(),
            network_grants: self.network_grants.clone(),
        }
    }
}

/// The execution-mode flags of `serve`, split from the other arguments.
#[derive(Default)]
struct ModeFlags {
    profile: Option<GatewayModeProfileIdV1>,
    network_grants: BTreeSet<GatewayNetworkGrantV1>,
    rest: Vec<String>,
}

fn parse_serve_request(args: &[String]) -> Result<ServeRequest, RunError> {
    split_mode_flags(args).and_then(|flags| {
        let profile = flags
            .profile
            .ok_or("serve requires --profile <gateway-mode-local-v1|gateway-mode-air-gapped-v1>")?;
        parse_serve_args(&flags.rest).map(|args| ServeRequest {
            args,
            profile,
            network_grants: flags.network_grants,
        })
    })
}

fn split_mode_flags(args: &[String]) -> Result<ModeFlags, RunError> {
    let mut flags = ModeFlags::default();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        if flag == "--profile" || flag == "--network-grant" {
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("{flag} requires a value"))?;
            mode_flag(&mut flags, flag, value)?;
            index += 2;
        } else {
            flags.rest.push(args[index].clone());
            index += 1;
        }
    }
    Ok(flags)
}

fn mode_flag(flags: &mut ModeFlags, flag: &str, value: &str) -> Result<(), RunError> {
    if flag == "--profile" {
        if flags.profile.replace(value.parse()?).is_some() {
            return Err("--profile may be specified once".into());
        }
    } else if !flags.network_grants.insert(value.parse()?) {
        return Err("each --network-grant may be specified once".into());
    }
    Ok(())
}

fn credential_directory_from(
    directory: Option<OsString>,
    expected: &str,
) -> Result<PathBuf, RunError> {
    let directory = directory.ok_or("systemd credentials require CREDENTIALS_DIRECTORY")?;
    let directory = PathBuf::from(directory);
    validate_credential_directory(directory, expected)
}

fn validate_credential_directory(directory: PathBuf, expected: &str) -> Result<PathBuf, RunError> {
    (directory == *expected)
        .then_some(directory)
        .ok_or_else(|| "credential directory does not match its systemd unit".into())
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
    drop(signal.await);
}

/// ADR-134 §4 composition order: predicates 1 to 4 (pure configuration),
/// then the store's shared mode lock, then the store and its binding
/// (predicate 5), then the ledger, then the listeners. Each step must succeed
/// before the next; the lock is held for the whole serve.
async fn serve_request(
    request: &ServeRequest,
    fork_credentials: Option<&Path>,
    shutdown: impl Future<Output = ()> + Send + 'static,
    environment: LedgerEnvironment,
) -> Result<(), RunError> {
    let composition = request.composition(&environment);
    verify_gateway_serve_composition_v1(request.profile, &composition)?;
    let lock = request
        .args
        .sqlite_path
        .as_deref()
        .map(GatewayModeStoreLockV1::shared)
        .transpose()?;
    let owner_key = request
        .args
        .owntracks_owner_key
        .as_deref()
        .map(OwnTracksOwnerKey::load)
        .transpose()?;
    let served = serve_locked(
        request,
        &composition,
        fork_credentials,
        owner_key.as_ref(),
        shutdown,
        environment,
    )
    .await;
    drop(lock);
    served
}

async fn serve_locked(
    request: &ServeRequest,
    composition: &GatewayServeCompositionV1,
    fork_credentials: Option<&Path>,
    owner_key: Option<&OwnTracksOwnerKey>,
    shutdown: impl Future<Output = ()> + Send + 'static,
    environment: LedgerEnvironment,
) -> Result<(), RunError> {
    match fork_credentials {
        #[cfg(target_os = "linux")]
        Some(directory) => {
            serve_fork_admission(
                request,
                composition,
                directory,
                owner_key,
                shutdown,
                environment,
            )
            .await
        }
        #[cfg(not(target_os = "linux"))]
        Some(_) => Err("fork admission requires Linux Unix peer credentials".into()),
        None => serve_http(request, composition, owner_key, shutdown, environment).await,
    }
}

fn store_config(sqlite_path: Option<&str>) -> StoreConfig {
    sqlite_path.map_or(StoreConfig::Memory, |path| StoreConfig::Sqlite {
        path: path.to_owned(),
    })
}

const fn host_store(owner_key: Option<&OwnTracksOwnerKey>) -> GatewayHostStoreV1 {
    if owner_key.is_some() {
        GatewayHostStoreV1::OwnTracks
    } else {
        GatewayHostStoreV1::Standard
    }
}

/// Open the one erasure host of the store with the closed composition and
/// bind it to the requested execution mode (predicate 5).
fn open_bound_host(
    request: &ServeRequest,
    composition: &GatewayServeCompositionV1,
    owner_key: Option<&OwnTracksOwnerKey>,
) -> Result<(pos_runtime::ErasureExecutionHostV1, GatewayModeBindingV1), RunError> {
    let mut host = open_recovered_erasure_host(
        store_config(request.args.sqlite_path.as_deref()),
        host_store(owner_key),
        &ErasureCoordinatorCompositionV1::closed(),
    )?;
    let mode = bind_gateway_mode_v1(request.profile, composition, &mut host)?;
    Ok((host, mode))
}

async fn serve_http(
    request: &ServeRequest,
    composition: &GatewayServeCompositionV1,
    owner_key: Option<&OwnTracksOwnerKey>,
    shutdown: impl Future<Output = ()> + Send + 'static,
    environment: LedgerEnvironment,
) -> Result<(), RunError> {
    let (host, mode) = open_bound_host(request, composition, owner_key)?;
    let (ledger_view, ledger_write) = load_ledger_with_environment(environment)?;
    // D1 on #302: every protected route requires the Local Principal the
    // store records; an unprovisioned store answers them `401`.
    let gateway = local_gateway(host, owner_key)?;
    serve_gateway(
        request.args.addr,
        gateway,
        &mode,
        shutdown,
        (ledger_view, ledger_write),
    )
    .await
}

/// ADR-109 r9: one erasure host serves HTTP and the Fork listener, and the
/// binary composes only the closed erasure authority. The managed
/// credentials are decoded before the database opens.
#[cfg(target_os = "linux")]
async fn serve_fork_admission(
    request: &ServeRequest,
    composition: &GatewayServeCompositionV1,
    credential_directory: &Path,
    owner_key: Option<&OwnTracksOwnerKey>,
    shutdown: impl Future<Output = ()> + Send + 'static,
    environment: LedgerEnvironment,
) -> Result<(), RunError> {
    serve_managed_local_fork_admission(
        ManagedLocalForkAdmissionV1 {
            addr: request.args.addr,
            sqlite_path: request.args.sqlite_path.as_deref().unwrap_or_default(),
            credential_directory,
            socket_path: Path::new(FORK_ADMISSION_SOCKET),
            profile: request.profile,
            composition,
            owntracks_owner_key: owner_key,
            ledger: LedgerConfig::new(
                environment.source.map(PathBuf::from),
                environment.write_enabled,
            ),
        },
        shutdown,
    )
    .await
}

async fn serve_gateway(
    addr: SocketAddr,
    gateway: Gateway,
    mode: &GatewayModeBindingV1,
    shutdown: impl Future<Output = ()> + Send + 'static,
    (ledger_view, ledger_write): (LedgerView, LedgerWriteMode),
) -> Result<(), RunError> {
    let app = bound_router(
        router_for_addr(
            addr,
            AppState {
                gateway: gateway.clone(),
                ledger_view,
                ledger_write,
            },
        ),
        mode,
    );
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(error) => return stop_after_bind_failure(&gateway, error).await,
    };
    announce_listening(addr);
    announce_mode_binding(mode);
    let serve_result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_or_stale(shutdown, mode))
        .await;
    let shutdown_result = gateway.shutdown().await;
    drop(gateway);
    finish_run(serve_result, shutdown_result)
        .and_then(|()| stale_binding_exit(mode).map_err(Into::into))
}

fn finish_run<E>(
    serve_result: Result<(), std::io::Error>,
    shutdown_result: Result<(), E>,
) -> Result<(), RunError>
where
    E: std::error::Error + Send + Sync + 'static,
{
    match (serve_result, shutdown_result) {
        (Err(error), _) => Err(Box::new(error)),
        (Ok(()), Err(error)) => Err(Box::new(error)),
        (Ok(()), Ok(())) => Ok(()),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod coverage_tests {
    use super::{finish_run, handle_run_error};
    use std::fmt;

    trait TestResultExt<T, E> {
        fn test_err(self) -> Result<E, Box<dyn std::error::Error>>;
    }

    impl<T, E: std::fmt::Debug> TestResultExt<T, E> for Result<T, E> {
        fn test_err(self) -> Result<E, Box<dyn std::error::Error>> {
            self.err().ok_or_else(|| "expected an error".into())
        }
    }

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
    fn finish_run_reports_serve_and_shutdown_failures() {
        assert!(finish_run(
            Err(std::io::Error::other("serve")),
            Ok::<(), std::io::Error>(()),
        )
        .is_err());
        assert!(finish_run(
            Ok::<(), std::io::Error>(()),
            Err(std::io::Error::other("shutdown")),
        )
        .is_err());
        assert!(finish_run(Ok::<(), std::io::Error>(()), Ok::<(), std::io::Error>(()),).is_ok());
    }

    #[test]
    fn main_error_returns_failure_exit_code() {
        let _exit_code = super::main_with_args(&[
            "piglor-gateway".to_owned(),
            "serve".to_owned(),
            "--profile".to_owned(),
            "gateway-mode-local-v1".to_owned(),
            "not-an-address".to_owned(),
        ]);
    }

    #[test]
    fn run_with_args_reports_parse_and_bind_errors() -> Result<(), Box<dyn std::error::Error>> {
        let owntracks_error = super::run_with_args(&[
            "piglor-gateway".to_owned(),
            "owntracks".to_owned(),
            "invalid".to_owned(),
        ])
        .test_err()?;
        assert!(!owntracks_error.to_string().is_empty());

        let parse_error = super::run_with_args(&[
            "piglor-gateway".to_owned(),
            "serve".to_owned(),
            "--profile".to_owned(),
            "gateway-mode-local-v1".to_owned(),
            "not-an-address".to_owned(),
        ])
        .test_err()?;
        assert!(!parse_error.to_string().is_empty());

        let legacy_provision = super::run_with_args(&[
            "piglor-gateway".to_owned(),
            "fork-admission-provision".to_owned(),
        ])
        .test_err()?;
        assert!(legacy_provision.to_string().contains("systemd-only"));

        let ledger_error = super::run_with_args_and_shutdown_with_environment(
            &[
                "piglor-gateway".to_owned(),
                "serve".to_owned(),
                "--profile".to_owned(),
                "gateway-mode-local-v1".to_owned(),
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
        .test_err()?;
        assert!(!ledger_error.to_string().is_empty());
        Ok(())
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

    trait TestResultExt<T, E> {
        fn test_ok(self) -> Result<T, Box<dyn std::error::Error + Send + Sync>>;
        fn test_err(self) -> Result<E, Box<dyn std::error::Error + Send + Sync>>;
    }

    impl<T, E: std::fmt::Debug> TestResultExt<T, E> for Result<T, E> {
        fn test_ok(self) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
            self.map_err(|error| format!("unexpected error: {error:?}").into())
        }

        fn test_err(self) -> Result<E, Box<dyn std::error::Error + Send + Sync>> {
            self.err().ok_or_else(|| "expected an error".into())
        }
    }

    trait TestOptionExt<T> {
        fn test_ok(self) -> Result<T, Box<dyn std::error::Error + Send + Sync>>;
    }

    impl<T> TestOptionExt<T> for Option<T> {
        fn test_ok(self) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
            self.ok_or_else(|| "expected a value".into())
        }
    }

    #[test]
    fn serve_requires_one_profile_and_unique_network_grants(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let parse = |args: &[&str]| {
            parse_serve_request(&args.iter().map(ToString::to_string).collect::<Vec<_>>())
        };
        let missing = parse(&["127.0.0.1:0"]).test_err()?;
        assert!(missing.to_string().contains("requires --profile"));
        let request = parse(&[
            "--profile",
            "gateway-mode-local-v1",
            "0.0.0.0:0",
            "--network-grant",
            "public-read-only",
            "/private/store.db",
            "--network-grant",
            "owntracks",
        ])
        .test_ok()?;
        assert_eq!(request.profile, GatewayModeProfileIdV1::Local);
        assert_eq!(
            request.network_grants.iter().copied().collect::<Vec<_>>(),
            [
                GatewayNetworkGrantV1::OwnTracks,
                GatewayNetworkGrantV1::PublicReadOnly
            ]
        );
        assert_eq!(
            request.args.sqlite_path.as_deref(),
            Some("/private/store.db")
        );
        let air_gapped = parse(&["--profile", "gateway-mode-air-gapped-v1"]).test_ok()?;
        assert_eq!(air_gapped.profile, GatewayModeProfileIdV1::AirGapped);
        assert!(air_gapped.network_grants.is_empty());
        for (args, expected) in [
            (&["--profile"][..], "requires a value"),
            (&["--network-grant"][..], "requires a value"),
            (&["--profile", "deterministic-local-v1"][..], "unknown"),
            (
                &[
                    "--profile",
                    "gateway-mode-local-v1",
                    "--network-grant",
                    "ledger",
                ][..],
                "unknown network grant",
            ),
            (
                &[
                    "--profile",
                    "gateway-mode-local-v1",
                    "--profile",
                    "gateway-mode-local-v1",
                ][..],
                "once",
            ),
            (
                &[
                    "--profile",
                    "gateway-mode-local-v1",
                    "--network-grant",
                    "owntracks",
                    "--network-grant",
                    "owntracks",
                ][..],
                "once",
            ),
            (
                &["--profile", "gateway-mode-local-v1", "a", "b", "c"][..],
                "at most",
            ),
        ] {
            let error = parse(args).test_err()?;
            assert!(error.to_string().contains(expected), "{args:?}: {error}");
        }
        let composition = request.composition(&LedgerEnvironment {
            source: Some(OsString::from("/srv/ledger")),
            write_enabled: false,
        });
        assert_eq!(composition.tcp_addr, request.args.addr);
        assert!(!composition.owntracks_ingress);
        assert!(!composition.fork_admission_socket);
        assert_eq!(
            composition.ledger_source,
            Some(OsString::from("/srv/ledger"))
        );
        assert_eq!(composition.network_grants, request.network_grants);
        Ok(())
    }

    #[test]
    fn owntracks_activation_requires_sqlite_and_parses_one_existing_key_path(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let missing_sqlite = parse_serve_args(&[
            "127.0.0.1:0".to_owned(),
            "--owntracks-owner-key".to_owned(),
            "/private/owner.key".to_owned(),
        ])
        .test_err()?;
        assert!(missing_sqlite.to_string().contains("SQLite"));

        let parsed = parse_serve_args(&[
            "127.0.0.1:0".to_owned(),
            "/private/store.db".to_owned(),
            "--owntracks-owner-key".to_owned(),
            "/private/owner.key".to_owned(),
        ])
        .test_ok()?;
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
        .test_err()?;
        assert!(repeated.to_string().contains("once"));

        Ok(())
    }

    #[test]
    fn fork_admission_arguments_require_the_complete_private_configuration(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let missing_sqlite =
            parse_serve_args(&["--require-local-fork-authority".to_owned()]).test_err()?;
        assert!(missing_sqlite.to_string().contains("SQLite"));

        let parsed = parse_serve_args(&[
            "127.0.0.1:0".to_owned(),
            "/private/store.db".to_owned(),
            "--require-local-fork-authority".to_owned(),
        ])
        .test_ok()?;
        assert!(parsed.require_local_fork_authority);

        let repeated = parse_serve_args(&[
            "127.0.0.1:0".to_owned(),
            "/private/store.db".to_owned(),
            "--require-local-fork-authority".to_owned(),
            "--require-local-fork-authority".to_owned(),
        ])
        .test_err()?;
        assert!(repeated.to_string().contains("once"));
        Ok(())
    }

    #[test]
    fn managed_authority_accepts_only_its_fixed_credential_directory() {
        assert!(validate_credential_directory(
            PathBuf::from(GATEWAY_CREDENTIAL_DIRECTORY),
            GATEWAY_CREDENTIAL_DIRECTORY,
        )
        .is_ok());
        assert!(validate_credential_directory(
            PathBuf::from(PROVISION_CREDENTIAL_DIRECTORY),
            GATEWAY_CREDENTIAL_DIRECTORY,
        )
        .is_err());
        assert!(validate_credential_directory(
            PathBuf::from("relative/credentials"),
            GATEWAY_CREDENTIAL_DIRECTORY,
        )
        .is_err());
    }

    #[test]
    fn provision_command_rejects_direct_or_wrong_unit_credentials_before_database_open(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let directory = tempfile::tempdir().test_ok()?;
        let database = directory.path().join("gateway.db");
        let missing_path = run_with_args_and_shutdown_with_environment_and_credentials(
            &[
                "piglor-gateway".to_owned(),
                "provision-local-fork-authority".to_owned(),
            ],
            Box::pin(async {}),
            LedgerEnvironment::default(),
            None,
        )
        .test_err()?;
        assert!(missing_path.to_string().contains("requires an SQLite path"));

        let args = vec![
            "piglor-gateway".to_owned(),
            "provision-local-fork-authority".to_owned(),
            database.display().to_string(),
        ];
        let direct = run_with_args_and_shutdown_with_environment_and_credentials(
            &args,
            Box::pin(async {}),
            LedgerEnvironment::default(),
            None,
        )
        .test_err()?;
        assert!(direct.to_string().contains("CREDENTIALS_DIRECTORY"));
        assert!(!database.exists());

        let wrong_unit = run_with_args_and_shutdown_with_environment_and_credentials(
            &args,
            Box::pin(async {}),
            LedgerEnvironment::default(),
            Some(OsString::from("/run/credentials/not-piglor-gateway")),
        )
        .test_err()?;
        assert!(wrong_unit.to_string().contains("does not match"));
        assert!(!database.exists());

        let managed_but_unavailable = run_with_args_and_shutdown_with_environment_and_credentials(
            &args,
            Box::pin(async {}),
            LedgerEnvironment::default(),
            Some(OsString::from(PROVISION_CREDENTIAL_DIRECTORY)),
        )
        .test_err()?;
        assert!(!managed_but_unavailable.to_string().is_empty());
        assert!(!database.exists());

        let with_path = vec![
            "piglor-gateway".to_owned(),
            "provision-local-fork-authority".to_owned(),
            database.display().to_string(),
            "/run/credentials/piglor-gateway-fork-admission-provision.service".to_owned(),
        ];
        assert!(run_with_args_and_shutdown_with_environment_and_credentials(
            &with_path,
            Box::pin(async {}),
            LedgerEnvironment::default(),
            None,
        )
        .is_err());
        assert!(!database.exists());
        Ok(())
    }

    #[test]
    fn local_principal_provisioning_runs_only_under_its_systemd_unit(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let directory = tempfile::tempdir().test_ok()?;
        let database = directory.path().join("gateway.db");
        let run = |args: &[String], credentials: Option<&str>| {
            run_with_args_and_shutdown_with_environment_and_credentials(
                args,
                Box::pin(async {}),
                LedgerEnvironment::default(),
                credentials.map(OsString::from),
            )
        };
        let command = || {
            vec![
                "piglor-gateway".to_owned(),
                "provision-local-principal".to_owned(),
            ]
        };
        let missing_path = run(&command(), None).test_err()?;
        assert!(missing_path.to_string().contains("requires an SQLite path"));

        let mut extra = command();
        extra.extend([database.display().to_string(), "extra".to_owned()]);
        let extra = run(&extra, None).test_err()?;
        assert!(extra.to_string().contains("exactly an SQLite path"));

        let mut args = command();
        args.push(database.display().to_string());
        let direct = run(&args, None).test_err()?;
        assert!(direct.to_string().contains("CREDENTIALS_DIRECTORY"));
        let wrong_unit = run(&args, Some(PROVISION_CREDENTIAL_DIRECTORY)).test_err()?;
        assert!(wrong_unit.to_string().contains("does not match"));
        let unavailable = run(&args, Some(LOCAL_PRINCIPAL_CREDENTIAL_DIRECTORY)).test_err()?;
        assert!(!unavailable.to_string().is_empty());
        assert!(!database.exists());
        Ok(())
    }

    #[test]
    fn managed_serve_requires_the_gateway_credential_directory(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let directory = tempfile::tempdir().test_ok()?;
        let database = directory.path().join("gateway.db");
        let error = run_with_args_and_shutdown_with_environment_and_credentials(
            &[
                "piglor-gateway".to_owned(),
                "serve".to_owned(),
                "--profile".to_owned(),
                "gateway-mode-local-v1".to_owned(),
                "127.0.0.1:0".to_owned(),
                database.display().to_string(),
                "--require-local-fork-authority".to_owned(),
            ],
            Box::pin(async {}),
            LedgerEnvironment::default(),
            None,
        )
        .test_err()?;
        assert!(error.to_string().contains("CREDENTIALS_DIRECTORY"));
        assert!(!database.exists());
        Ok(())
    }

    #[test]
    fn owntracks_argument_parser_rejects_missing_path_and_extra_positionals(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let missing_path = parse_serve_args(&["--owntracks-owner-key".to_owned()]).test_err()?;
        assert!(missing_path.to_string().contains("path is required"));

        let too_many = parse_serve_args(&[
            "127.0.0.1:0".to_owned(),
            "one.db".to_owned(),
            "extra".to_owned(),
        ])
        .test_err()?;
        assert!(too_many.to_string().contains("at most"));

        Ok(())
    }

    async fn serve_http_requests(
        bind_ip: IpAddr,
        requests: &[&str],
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        serve_http_requests_on(bind_ip, None, requests).await
    }

    async fn serve_http_requests_on(
        bind_ip: IpAddr,
        sqlite_path: Option<String>,
        requests: &[&str],
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let listener = tokio::net::TcpListener::bind((bind_ip, 0))
            .await
            .test_ok()?;
        let addr = listener.local_addr().test_ok()?;
        drop(listener);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            serve(addr, sqlite_path.as_deref(), async move {
                match rx.await {
                    Ok(()) | Err(_) => {}
                }
            })
            .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut connect_addr = addr;
        connect_addr.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let requests = requests.iter().map(ToString::to_string).collect::<Vec<_>>();
        let responses = tokio::task::spawn_blocking(move || {
            requests
                .iter()
                .map(
                    |request| -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
                        let mut stream = std::net::TcpStream::connect(connect_addr).test_ok()?;
                        stream.write_all(request.as_bytes()).test_ok()?;
                        let mut response = String::new();
                        stream.read_to_string(&mut response).test_ok()?;
                        Ok(response)
                    },
                )
                .collect::<Result<Vec<_>, _>>()
        })
        .await
        .test_ok()?
        .test_ok()?;

        match tx.send(()) {
            Ok(()) | Err(()) => {}
        }
        server.await.test_ok()?.test_ok()?;
        Ok(responses)
    }

    const HEALTH_REQUEST: &str =
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    const CREATE_TIMELINE_REQUEST: &str = "POST /v1/timelines HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{\"name\":\"local\"}";

    fn ledger_temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("piglor-gw-ledger-{label}-{}", std::process::id()))
    }

    fn malformed_ledger_dir(
        label: &str,
    ) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
        let dir = ledger_temp_path(label);
        let predictions = dir.join("predictions");
        std::fs::create_dir_all(&predictions).test_ok()?;
        std::fs::write(predictions.join("invalid.toml"), "not valid = [").test_ok()?;
        Ok(dir)
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn non_loopback_server_is_public_read_only() {
        let result = non_loopback_server_is_public_read_only_impl().await;
        assert!(
            result.is_ok(),
            "non_loopback_server_is_public_read_only failed: {result:?}"
        );
    }

    async fn non_loopback_server_is_public_read_only_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let responses = serve_http_requests(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            &[HEALTH_REQUEST, CREATE_TIMELINE_REQUEST],
        )
        .await?;
        assert!(responses[0].starts_with("HTTP/1.1 200 OK"));
        assert!(responses[1].starts_with("HTTP/1.1 404 Not Found"));
        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn loopback_server_retains_timeline_api() {
        let result = loopback_server_retains_timeline_api_impl().await;
        assert!(
            result.is_ok(),
            "loopback_server_retains_timeline_api failed: {result:?}"
        );
    }

    /// D1 on #302: an unprovisioned host serves the Timeline API fail closed.
    async fn loopback_server_retains_timeline_api_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let responses =
            serve_http_requests(IpAddr::V4(Ipv4Addr::LOCALHOST), &[CREATE_TIMELINE_REQUEST])
                .await?;
        assert!(responses[0].starts_with("HTTP/1.1 401 Unauthorized"));
        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn the_provisioned_binary_admits_its_local_principal() {
        let result = the_provisioned_binary_admits_its_local_principal_impl().await;
        assert!(
            result.is_ok(),
            "the_provisioned_binary_admits_its_local_principal failed: {result:?}"
        );
    }

    async fn the_provisioned_binary_admits_its_local_principal_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use piglor_gateway::local_principal::{
            provision_local_principal, LocalPrincipalProvisionV1,
        };
        let directory = tempfile::tempdir().test_ok()?;
        let database = directory.path().join("gateway.db");
        let path = database
            .to_str()
            .ok_or("temporary path is not UTF-8")?
            .to_owned();
        let actor = pos_core::EntityId::new();
        // ADR-134 §8: the first `serve` binds the empty store; offline
        // provisioning follows.
        serve_http_requests_on(IpAddr::V4(Ipv4Addr::LOCALHOST), Some(path.clone()), &[]).await?;
        provision_local_principal(
            &mut pos_store::sqlite::SqliteStore::open(&path)?,
            &LocalPrincipalProvisionV1::try_new(
                &pos_core::PrincipalRefV1::try_new([9; 16], "local")?,
                [actor],
                [piglor_gateway::GatewayOperationV1::CREATE_TIMELINE],
            )?,
        )?;
        let admitted = format!(
            "POST /v1/timelines HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nx-piglor-actor-entity: {actor}\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{{\"name\":\"local\"}}"
        );
        let responses = serve_http_requests_on(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some(path),
            &[admitted.as_str(), CREATE_TIMELINE_REQUEST],
        )
        .await?;
        assert!(responses[0].starts_with("HTTP/1.1 201 Created"));
        assert!(responses[1].starts_with("HTTP/1.1 401 Unauthorized"));
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn main_does_not_panic_in_test_context() {
        main();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn version_and_usage_paths() {
        drop(run_main(&[
            String::from("piglor-gateway"),
            String::from("version"),
        ]));
        drop(run_main(&[String::from("piglor-gateway")]));
    }

    #[test]
    fn owntracks_subcommand_is_dispatched_by_the_binary_entrypoint(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let database = std::env::temp_dir().join(format!(
            "piglor-gw-owntracks-dispatch-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .test_ok()?
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
        .test_ok()?;
        drop(std::fs::remove_file(database));

        Ok(())
    }

    #[test]
    fn serve_dispatches_owner_key_and_sqlite_configuration(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let directory = std::env::temp_dir().join(format!(
            "piglor-gw-owner-serve-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .test_ok()?
                .as_nanos()
        ));
        std::fs::create_dir(&directory).test_ok()?;
        let database = directory.join("gateway.db");
        let owner_key = directory.join("owner.key");
        owntracks::create_or_load_owner_key(&owner_key).test_ok()?;
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().test_ok()?;
        run_with_args_and_shutdown(
            &[
                String::from("piglor-gateway"),
                String::from("serve"),
                String::from("--profile"),
                String::from("gateway-mode-local-v1"),
                addr.to_string(),
                database.display().to_string(),
                String::from("--owntracks-owner-key"),
                owner_key.display().to_string(),
                String::from("--network-grant"),
                String::from("owntracks"),
            ],
            Box::pin(async {
                tokio::task::yield_now().await;
            }),
        )
        .test_ok()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .test_ok()?;
        let missing_owner = runtime
            .block_on(serve_with_owntracks(
                addr,
                Some(database.to_str().test_ok()?),
                Some(&directory.join("missing.key")),
                async {},
            ))
            .test_err()?;
        assert!(!missing_owner.to_string().is_empty());
        let invalid_sqlite = runtime
            .block_on(serve_with_owntracks(
                addr,
                Some(directory.as_path().to_str().test_ok()?),
                Some(&owner_key),
                async {},
            ))
            .test_err()?;
        assert!(!invalid_sqlite.to_string().is_empty());
        std::fs::remove_dir_all(directory).test_ok()?;

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_main_error_path() {
        drop(run_main(&[
            String::from("piglor-gateway"),
            String::from("serve"),
            String::from("--profile"),
            String::from("gateway-mode-local-v1"),
            String::from("not-an-addr"),
        ]));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_main_serve_memory_shuts_down() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").test_ok()?;
        let addr = listener.local_addr().test_ok()?;
        drop(listener);
        run_with_args_and_shutdown(
            &[
                String::from("piglor-gateway"),
                String::from("serve"),
                String::from("--profile"),
                String::from("gateway-mode-local-v1"),
                addr.to_string(),
            ],
            Box::pin(async {
                tokio::task::yield_now().await;
            }),
        )
        .test_ok()?;

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_main_serve_sqlite_shuts_down() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").test_ok()?;
        let addr = listener.local_addr().test_ok()?;
        drop(listener);
        let path = std::env::temp_dir().join(format!("piglor-gw-cli-{}.db", std::process::id()));
        run_with_args_and_shutdown(
            &[
                String::from("piglor-gateway"),
                String::from("serve"),
                String::from("--profile"),
                String::from("gateway-mode-local-v1"),
                addr.to_string(),
                path.to_str().test_ok()?.to_owned(),
            ],
            Box::pin(async {
                tokio::task::yield_now().await;
            }),
        )
        .test_ok()?;
        drop(std::fs::remove_file(path));

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn handle_run_error_prints() {
        handle_run_error(&GatewayProbe);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn serve_memory_and_sqlite_shut_down() {
        let result = serve_memory_and_sqlite_shut_down_impl().await;
        assert!(
            result.is_ok(),
            "serve_memory_and_sqlite_shut_down failed: {result:?}"
        );
    }

    async fn serve_memory_and_sqlite_shut_down_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Memory bind + immediate shutdown.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .test_ok()?;
        let addr = listener.local_addr().test_ok()?;
        drop(listener);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let serve_mem = tokio::spawn(async move {
            serve(addr, None, async move {
                match rx.await {
                    Ok(()) | Err(_) => {}
                }
            })
            .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        match tx.send(()) {
            Ok(()) | Err(()) => {}
        }
        serve_mem.await.test_ok()?.test_ok()?;

        // SQLite path arm.
        let dir = std::env::temp_dir().join(format!("piglor-gw-{}.db", std::process::id()));
        let path = dir.to_str().test_ok()?.to_owned();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .test_ok()?;
        let addr = listener.local_addr().test_ok()?;
        drop(listener);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let path_clone = path.clone();
        let serve_sql = tokio::spawn(async move {
            serve(addr, Some(path_clone.as_str()), async move {
                match rx.await {
                    Ok(()) | Err(_) => {}
                }
            })
            .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        match tx.send(()) {
            Ok(()) | Err(()) => {}
        }
        serve_sql.await.test_ok()?.test_ok()?;
        drop(std::fs::remove_file(path));
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_main_serve_open_store_error() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").test_ok()?;
        let addr = listener.local_addr().test_ok()?;
        drop(listener);
        let dir = std::env::temp_dir().join(format!("piglor-gw-dir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).test_ok()?;
        let err = run_with_args(&[
            String::from("piglor-gateway"),
            String::from("serve"),
            String::from("--profile"),
            String::from("gateway-mode-local-v1"),
            addr.to_string(),
            dir.to_str().test_ok()?.to_owned(),
        ])
        .test_err()?;
        assert!(!err.to_string().is_empty());
        drop(std::fs::remove_dir_all(&dir));

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_main_serve_bind_error() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").test_ok()?;
        let addr = occupied.local_addr().test_ok()?;
        let err = run_with_args(&[
            String::from("piglor-gateway"),
            String::from("serve"),
            String::from("--profile"),
            String::from("gateway-mode-local-v1"),
            addr.to_string(),
        ])
        .test_err()?;
        assert!(!err.to_string().is_empty());
        drop(occupied);

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_main_serve_invalid_ledger_returns_error(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dir = malformed_ledger_dir("startup")?;
        let error = run_with_args_and_shutdown_with_environment(
            &[
                String::from("piglor-gateway"),
                String::from("serve"),
                String::from("--profile"),
                String::from("gateway-mode-local-v1"),
                String::from("127.0.0.1:0"),
            ],
            Box::pin(async {}),
            LedgerEnvironment {
                source: Some(dir.clone().into_os_string()),
                write_enabled: false,
            },
        )
        .test_err()?;
        drop(std::fs::remove_dir_all(&dir));
        assert!(error.to_string().contains("TOML"));

        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn serve_bind_error_direct() {
        let result = serve_bind_error_direct_impl().await;
        assert!(result.is_ok(), "serve_bind_error_direct failed: {result:?}");
    }

    async fn serve_bind_error_direct_impl() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .test_ok()?;
        let addr = occupied.local_addr().test_ok()?;
        let err = serve(addr, None, async {}).await.test_err()?;
        assert!(!err.to_string().is_empty());
        drop(occupied);
        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn serve_open_store_error_direct() {
        let result = serve_open_store_error_direct_impl().await;
        assert!(
            result.is_ok(),
            "serve_open_store_error_direct failed: {result:?}"
        );
    }

    async fn serve_open_store_error_direct_impl(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .test_ok()?;
        let addr = listener.local_addr().test_ok()?;
        drop(listener);
        let dir = std::env::temp_dir().join(format!("piglor-gw-sql-{}", std::process::id()));
        std::fs::create_dir_all(&dir).test_ok()?;
        let err = serve(addr, Some(dir.to_str().test_ok()?), async {})
            .await
            .test_err()?;
        assert!(!err.to_string().is_empty());
        drop(std::fs::remove_dir_all(&dir));
        Ok(())
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
    fn startup_without_source_marks_writes_unconfigured(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (view, mode) = load_ledger_with_environment(LedgerEnvironment {
            source: None,
            write_enabled: true,
        })
        .test_ok()?;
        assert!(matches!(mode, LedgerWriteMode::Unconfigured));
        assert!(view.entries.is_empty());

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn startup_reads_configured_source_and_write_flag(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dir = ledger_temp_path("startup-ready");
        std::fs::create_dir_all(&dir).test_ok()?;
        let (_, disabled) = load_ledger_with_environment(LedgerEnvironment {
            source: Some(dir.clone().into_os_string()),
            write_enabled: false,
        })
        .test_ok()?;
        assert!(matches!(disabled, LedgerWriteMode::Disabled));
        let (_, ready) = load_ledger_with_environment(LedgerEnvironment {
            source: Some(dir.clone().into_os_string()),
            write_enabled: true,
        })
        .test_ok()?;
        assert!(matches!(ready, LedgerWriteMode::Ready(_)));
        drop(std::fs::remove_dir_all(&dir));

        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn startup_rejects_explicitly_configured_empty_source(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let result = load_ledger_with_environment(LedgerEnvironment {
            source: Some(OsString::new()),
            write_enabled: false,
        });
        let error = result.test_err()?;
        assert!(!error.to_string().is_empty());
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn startup_rejects_configured_non_directory_source(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = ledger_temp_path("startup-not-directory");
        std::fs::write(&path, "not a directory").test_ok()?;
        let error = load_ledger_with_environment(LedgerEnvironment {
            source: Some(path.clone().into_os_string()),
            write_enabled: false,
        })
        .test_err()?;
        drop(std::fs::remove_file(path));
        assert!(!error.to_string().is_empty());

        Ok(())
    }

    #[cfg(unix)]
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn startup_preserves_non_unicode_ledger_source(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::os::unix::ffi::OsStringExt as _;

        let temporary = std::env::temp_dir().join(format!(
            "piglor-gw-ledger-non-unicode-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .test_ok()?
                .as_nanos()
        ));
        let mut path = temporary.into_os_string().into_vec();
        path.push(0xff);
        let source = OsString::from_vec(path);
        let error = run_with_args_and_shutdown_with_environment(
            &[
                String::from("piglor-gateway"),
                String::from("serve"),
                String::from("--profile"),
                String::from("gateway-mode-local-v1"),
                String::from("127.0.0.1:0"),
            ],
            Box::pin(async {}),
            LedgerEnvironment {
                source: Some(source),
                write_enabled: false,
            },
        )
        .test_err()?;
        assert!(error.to_string().contains("No such file or directory"));

        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod shutdown_signal_tests {
    #[tokio::test]
    async fn completed_signal_is_observed_without_process_signals() {
        super::shutdown_signal_from(async { Ok(()) }).await;
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod coverage_entrypoints {
    use super::*;

    #[test]
    fn serve_startup_covers_memory_and_owntracks_gate_bindings(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("gateway.db");
        let owner_key = directory.path().join("owner.key");
        owntracks::create_or_load_owner_key(&owner_key)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        runtime.block_on(serve_with_owntracks(
            "127.0.0.1:0".parse()?,
            Some(database.to_str().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "database path is not UTF-8",
                )
            })?),
            Some(&owner_key),
            async {},
        ))?;
        runtime.block_on(serve_with_owntracks(
            "127.0.0.1:0".parse()?,
            None,
            None,
            async {},
        ))?;
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod erasure_gate_coverage_tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn fork_admission_startup_fails_before_the_database_without_credentials(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("gateway.db");
        let sqlite_path = database.to_string_lossy();
        let mut request = local_request("127.0.0.1:0".parse()?, Some(sqlite_path.as_ref()), None);
        request.args.require_local_fork_authority = true;
        let started = serve_request(
            &request,
            Some(&directory.path().join("missing-credentials")),
            async {},
            LedgerEnvironment::default(),
        )
        .await;
        assert!(started.is_err());
        assert!(!database.exists());
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn fork_admission_fails_closed_off_linux(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let request = local_request("127.0.0.1:0".parse()?, None, None);
        assert!(serve_locked(
            &request,
            &request.composition(&LedgerEnvironment::default()),
            Some(Path::new("/run/credentials")),
            None,
            async {},
            LedgerEnvironment::default(),
        )
        .await
        .is_err());
        Ok(())
    }

    /// ADR-134 §4: every refused predicate fails before the lock, store,
    /// ledger or listener.
    #[tokio::test]
    async fn d6_violations_fail_before_store_ledger_or_listener(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("gateway.db");
        let sqlite_path = database.to_string_lossy().into_owned();
        let owner_key = directory.path().join("owner.key");
        let spectator: SocketAddr = "0.0.0.0:0".parse()?;
        let loopback: SocketAddr = "127.0.0.1:0".parse()?;
        let mut air_gapped_spectator = local_request(spectator, Some(sqlite_path.as_str()), None);
        air_gapped_spectator.profile = GatewayModeProfileIdV1::AirGapped;
        let mut air_gapped_owntracks =
            local_request(loopback, Some(sqlite_path.as_str()), Some(&owner_key));
        air_gapped_owntracks.profile = GatewayModeProfileIdV1::AirGapped;
        let mut ungranted_spectator = local_request(spectator, Some(sqlite_path.as_str()), None);
        ungranted_spectator.network_grants.clear();
        let mut ungranted_owntracks =
            local_request(loopback, Some(sqlite_path.as_str()), Some(&owner_key));
        ungranted_owntracks.network_grants.clear();
        let spectator_owntracks =
            local_request(spectator, Some(sqlite_path.as_str()), Some(&owner_key));
        for request in [
            air_gapped_spectator,
            air_gapped_owntracks,
            ungranted_spectator,
            ungranted_owntracks,
            spectator_owntracks,
        ] {
            let refused = serve_request(
                &request,
                None,
                std::future::pending(),
                LedgerEnvironment {
                    source: Some(OsString::from("/missing/ledger")),
                    write_enabled: false,
                },
            )
            .await
            .err()
            .ok_or("a D6 violation was served")?;
            assert!(!refused.to_string().contains("ledger"), "{refused}");
            assert!(!database.exists(), "{request:?}");
            assert!(!directory
                .path()
                .join("gateway.db.gateway-mode.lock")
                .exists());
            assert!(!owner_key.exists());
        }
        let network_ledger = serve_request(
            &local_request(loopback, Some(sqlite_path.as_str()), None),
            None,
            std::future::pending(),
            LedgerEnvironment {
                source: Some(OsString::from("https://ledger.example/")),
                write_enabled: false,
            },
        )
        .await
        .err()
        .ok_or("a network ledger source was served")?;
        assert!(network_ledger.to_string().contains("LEDGER_SOURCE"));
        assert!(!database.exists());
        Ok(())
    }

    /// ADR-134 §8: the first `serve` binds an empty store; a restart in
    /// another mode and a served store locked by `migrate-mode` are refused,
    /// and `migrate-mode` switches the mode.
    #[test]
    fn the_store_binding_survives_restarts_and_changes_only_by_migration(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("gateway.db");
        let path = database.to_string_lossy().into_owned();
        let serve_as = |profile: &str| {
            run_with_args_and_shutdown_with_environment(
                &[
                    "piglor-gateway".to_owned(),
                    "serve".to_owned(),
                    "--profile".to_owned(),
                    profile.to_owned(),
                    "127.0.0.1:0".to_owned(),
                    path.clone(),
                ],
                Box::pin(async {}),
                LedgerEnvironment::default(),
            )
        };
        serve_as("gateway-mode-local-v1")?;
        serve_as("gateway-mode-local-v1")?;
        let switched = serve_as("gateway-mode-air-gapped-v1")
            .err()
            .ok_or("a mode switch was served")?;
        assert!(switched.to_string().contains("migrate-mode"), "{switched}");
        let migrate = |from: &str, to: &str| {
            run_with_args_and_shutdown_with_environment(
                &[
                    "piglor-gateway".to_owned(),
                    "migrate-mode".to_owned(),
                    path.clone(),
                    "--from".to_owned(),
                    from.to_owned(),
                    "--to".to_owned(),
                    to.to_owned(),
                ],
                Box::pin(async {}),
                LedgerEnvironment::default(),
            )
        };
        let serving = GatewayModeStoreLockV1::shared(&path)?;
        assert!(migrate("gateway-mode-local-v1", "gateway-mode-air-gapped-v1").is_err());
        drop(serving);
        migrate("gateway-mode-local-v1", "gateway-mode-air-gapped-v1")?;
        serve_as("gateway-mode-air-gapped-v1")?;
        assert!(serve_as("gateway-mode-local-v1").is_err());
        assert!(migrate("gateway-mode-unknown-v1", "gateway-mode-local-v1").is_err());
        assert!(migrate("gateway-mode-air-gapped-v1", "gateway-mode-unknown-v1").is_err());
        let usage = migrate_mode(&["only-a-path".to_owned()])
            .err()
            .ok_or("migrate-mode accepted a malformed command")?;
        assert_eq!(usage.to_string(), MIGRATE_MODE_USAGE);
        assert!(
            migrate_mode_command(&["piglor-gateway".to_owned(), "version".to_owned()]).is_none()
        );
        Ok(())
    }

    /// A populated store that no `serve` bound is refused (development
    /// stores are recreated).
    #[test]
    fn a_populated_unbound_store_is_refused() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        use piglor_gateway::local_principal::{
            provision_local_principal, LocalPrincipalProvisionV1,
        };
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("gateway.db");
        let path = database.to_string_lossy().into_owned();
        provision_local_principal(
            &mut pos_store::sqlite::SqliteStore::open(&path)?,
            &LocalPrincipalProvisionV1::try_new(
                &pos_core::PrincipalRefV1::try_new([9; 16], "local")?,
                [pos_core::EntityId::new()],
                [piglor_gateway::GatewayOperationV1::CREATE_TIMELINE],
            )?,
        )?;
        let refused = run_with_args_and_shutdown_with_environment(
            &[
                "piglor-gateway".to_owned(),
                "serve".to_owned(),
                "--profile".to_owned(),
                "gateway-mode-local-v1".to_owned(),
                "127.0.0.1:0".to_owned(),
                path,
            ],
            Box::pin(async {}),
            LedgerEnvironment::default(),
        )
        .err()
        .ok_or("a populated unbound store was served")?;
        assert!(refused.to_string().contains("populated"), "{refused}");
        Ok(())
    }

    #[test]
    fn startup_reports_store_lock_and_open_failures() {
        let unopenable = "/dev/null/cannot/create/this/path";
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(error.to_string())));
        for owner_key in [None, Some(Path::new("/dev/null/owner.key"))] {
            assert!(runtime
                .block_on(serve_request(
                    &local_request(
                        SocketAddr::from(([127, 0, 0, 1], 0)),
                        Some(unopenable),
                        owner_key
                    ),
                    None,
                    async {},
                    LedgerEnvironment::default(),
                ))
                .is_err());
        }
    }
}

/// A Local `serve` request; a non-loopback bind and an owner key carry
/// their operator network grants.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn local_request(
    addr: SocketAddr,
    sqlite_path: Option<&str>,
    owner_key: Option<&Path>,
) -> ServeRequest {
    let mut network_grants = BTreeSet::new();
    if !addr.ip().is_loopback() {
        network_grants.insert(GatewayNetworkGrantV1::PublicReadOnly);
    }
    if owner_key.is_some() {
        network_grants.insert(GatewayNetworkGrantV1::OwnTracks);
    }
    ServeRequest {
        args: ServeArgs {
            addr,
            sqlite_path: sqlite_path.map(str::to_owned),
            owntracks_owner_key: owner_key.map(Path::to_path_buf),
            require_local_fork_authority: false,
        },
        profile: GatewayModeProfileIdV1::Local,
        network_grants,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
async fn serve(
    addr: SocketAddr,
    sqlite_path: Option<&str>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), RunError> {
    serve_with_owntracks(addr, sqlite_path, None, shutdown).await
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
async fn serve_with_owntracks(
    addr: SocketAddr,
    sqlite_path: Option<&str>,
    owner_key: Option<&Path>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), RunError> {
    serve_request(
        &local_request(addr, sqlite_path, owner_key),
        None,
        shutdown,
        LedgerEnvironment::default(),
    )
    .await
}
