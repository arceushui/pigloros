//! Process-private lifecycle for the ADR-109 pathname listener.

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use pos_store::sqlite::SqliteStore;

use crate::{
    local_fork_authentication::LocalForkAuthenticationCredentialsV1,
    local_fork_coordinator::LocalForkAdmissionCoordinatorV1,
    local_fork_listener::bind_pathname_listener,
};

/// Running local Fork-admission listener owned by the Gateway process.
///
/// The type exposes lifecycle only; its credential, session, journal, and
/// protocol values remain private to this crate.
pub(super) struct LocalForkAdmissionListenerV1 {
    stopping: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    socket_path: Option<PathBuf>,
}

impl LocalForkAdmissionListenerV1 {
    /// Stop accepting new local admission requests, join the worker, and
    /// unlink the socket pathname this listener bound.
    pub(super) fn stop(mut self) -> io::Result<()> {
        self.shutdown()
    }

    /// Idempotent: the worker is joined and the pathname removed at most once.
    /// The worker owns the bound listener, so its fd is closed before unlink.
    fn shutdown(&mut self) -> io::Result<()> {
        self.stopping.store(true, Ordering::Release);
        let joined = self.worker.take().map_or(Ok(()), |worker| {
            worker
                .join()
                .map_err(|_| io::Error::other("Fork-admission listener worker panicked"))
        });
        let unlinked = self.socket_path.take().map_or(Ok(()), fs::remove_file);
        joined.and(unlinked)
    }
}

impl Drop for LocalForkAdmissionListenerV1 {
    fn drop(&mut self) {
        drop(self.shutdown());
    }
}

/// Provision the empty `SQLite` store with the host credentials in one protected
/// systemd credential directory.
pub(super) fn provision_local_fork_admission_authority(
    sqlite_path: &str,
    credential_directory: &Path,
) -> io::Result<()> {
    let credentials = credentials(credential_directory)?;
    provision_with_credentials(sqlite_path, &credentials)
}

fn provision_with_credentials(
    sqlite_path: &str,
    credentials: &LocalForkAuthenticationCredentialsV1,
) -> io::Result<()> {
    let mut store = SqliteStore::open(sqlite_path).map_err(io::Error::other)?;
    credentials
        .provision_authority(&mut store)
        .map(|_| ())
        .map_err(io::Error::other)
}

/// Open the already-provisioned authority and start its private pathname listener.
///
/// This function completes all credential, authority, and journal checks before
/// it binds the socket pathname. Every retained tuple is graph-validated with
/// a private FRP1; only its eventual same-Principal retry receives a result.
pub(super) fn start_local_fork_admission_listener(
    sqlite_path: &str,
    credential_directory: &Path,
    socket_path: &Path,
) -> io::Result<LocalForkAdmissionListenerV1> {
    let credentials = credentials(credential_directory)?;
    start_with_credentials(sqlite_path, credentials, socket_path)
}

fn start_with_credentials(
    sqlite_path: &str,
    credentials: LocalForkAuthenticationCredentialsV1,
    socket_path: &Path,
) -> io::Result<LocalForkAdmissionListenerV1> {
    let store = SqliteStore::open(sqlite_path).map_err(io::Error::other)?;
    let mut coordinator =
        LocalForkAdmissionCoordinatorV1::open(store, credentials).map_err(io::Error::other)?;
    coordinator.reconcile_startup().map_err(io::Error::other)?;
    let listener = bind_pathname_listener(socket_path)?;
    listener.set_nonblocking(true)?;
    let stopping = Arc::new(AtomicBool::new(false));
    let worker_stopping = Arc::clone(&stopping);
    let worker = thread::Builder::new()
        .name("piglor-fork-admission".to_owned())
        .spawn(move || {
            while !worker_stopping.load(Ordering::Acquire) {
                // An idle listener (WouldBlock) and a disconnected peer both
                // back off briefly; neither can stop future local admissions.
                if coordinator.serve_one(&listener).is_err() {
                    thread::sleep(Duration::from_millis(10));
                }
            }
        })
        .map_err(io::Error::other)?;
    Ok(LocalForkAdmissionListenerV1 {
        stopping,
        worker: Some(worker),
        socket_path: Some(socket_path.to_path_buf()),
    })
}

fn credentials(directory: &Path) -> io::Result<LocalForkAuthenticationCredentialsV1> {
    LocalForkAuthenticationCredentialsV1::load(directory, rustix::process::geteuid().as_raw())
        .map_err(io::Error::other)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::local_fork_authentication::{
        test_credential_bytes_for_service, test_credentials_for_current_peer_with_seeds,
    };
    use ciborium::value::Value;
    use pos_core::EventStore as _;
    use pos_store::sqlite::SqliteStore;
    use rusqlite::{params, OptionalExtension as _};
    use std::{
        fs,
        io::{Read as _, Write as _},
        net::Shutdown,
        os::unix::{fs::PermissionsExt as _, net::UnixStream},
        thread,
        time::{Duration, Instant},
    };

    fn protected_credential_file(directory: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
        let path = directory.join(name);
        if path.exists() {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        fs::write(&path, bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o400))
    }

    fn protected_credentials(
        directory: &Path,
        adapter_seed: [u8; 32],
        host_seed: [u8; 32],
    ) -> io::Result<()> {
        let service_uid = rustix::process::geteuid().as_raw();
        let (auth, host) = test_credential_bytes_for_service(service_uid, adapter_seed, host_seed)
            .map_err(io::Error::other)?;
        protected_credential_file(directory, "pigloros.fork-admission-auth", &auth)?;
        protected_credential_file(directory, "pigloros.fork-admission-host-signer", &host)
    }

    fn protected_credential_directory(parent: &Path) -> io::Result<std::path::PathBuf> {
        let directory = parent.join("credentials");
        fs::create_dir(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        Ok(directory)
    }

    fn current_peer_credentials(
        adapter_seed: [u8; 32],
        host_seed: [u8; 32],
    ) -> io::Result<LocalForkAuthenticationCredentialsV1> {
        test_credentials_for_current_peer_with_seeds(adapter_seed, host_seed)
            .map_err(io::Error::other)
    }

    fn bind_payload(operation: u8) -> Vec<u8> {
        [0x83, 0x64, b'F', b'A', b'L', b'1', 1, 0x82, 1, 0x58, 0x20]
            .into_iter()
            .chain([operation; 32])
            .collect()
    }

    fn fork_payload(parent: pos_core::TimelineId) -> io::Result<Vec<u8>> {
        let value = Value::Array(vec![
            Value::Text("FAL1".to_owned()),
            Value::Integer(1.into()),
            Value::Array(vec![
                Value::Integer(2.into()),
                Value::Bytes(vec![6; 32]),
                Value::Bytes(parent.inner().to_bytes().to_vec()),
                Value::Integer(0.into()),
                Value::Bytes(vec![7; 32]),
                Value::Bytes(vec![8; 32]),
                Value::Bool(false),
                Value::Text("listener-child".to_owned()),
            ]),
        ]);
        let mut payload = Vec::new();
        ciborium::into_writer(&value, &mut payload).map_err(io::Error::other)?;
        Ok(payload)
    }

    fn frame(payload: &[u8]) -> io::Result<Vec<u8>> {
        let length = u32::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "test FAL1 too large"))?;
        Ok([length.to_be_bytes().as_slice(), payload].concat())
    }

    fn request(socket: &Path, payload: &[u8], fragmented: bool) -> io::Result<Vec<u8>> {
        let mut stream = UnixStream::connect(socket)?;
        let frame = frame(payload)?;
        if fragmented {
            for fragment in frame.chunks(3) {
                stream.write_all(fragment)?;
            }
        } else {
            stream.write_all(&frame)?;
        }
        stream.shutdown(Shutdown::Write)?;
        let mut prefix = [0_u8; 4];
        stream.read_exact(&mut prefix)?;
        let mut response = vec![
            0;
            usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "response length does not fit usize",
                )
            })?
        ];
        stream.read_exact(&mut response)?;
        Ok(response)
    }

    fn disconnect_after_complete_request(socket: &Path, payload: &[u8]) -> io::Result<()> {
        let mut stream = UnixStream::connect(socket)?;
        stream.write_all(&frame(payload)?)?;
        stream.shutdown(Shutdown::Both)
    }

    fn request_without_half_close(socket: &Path, payload: &[u8]) -> io::Result<()> {
        let mut stream = UnixStream::connect(socket)?;
        stream.write_all(&frame(payload)?)?;
        stream.set_read_timeout(Some(Duration::from_millis(100)))?;
        let mut byte = [0_u8; 1];
        match stream.read(&mut byte) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                Ok(())
            }
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "listener closed an incomplete request before its EOF",
            )),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "listener answered before the request half-close",
            )),
            Err(error) => Err(error),
        }
    }

    fn trailing_byte_request(socket: &Path, payload: &[u8]) -> io::Result<()> {
        let mut stream = UnixStream::connect(socket)?;
        stream.write_all(&frame(payload)?)?;
        stream.write_all(&[0])?;
        stream.shutdown(Shutdown::Write)?;
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        let mut byte = [0_u8; 1];
        match stream.read(&mut byte)? {
            0 => Ok(()),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "listener answered a request with trailing bytes",
            )),
        }
    }

    fn wait_for_delivery_state(database: &Path, expected: i64) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let observed = rusqlite::Connection::open(database).and_then(|connection| {
                connection
                    .query_row("SELECT state FROM fork_delivery_journal", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .optional()
            });
            if matches!(observed, Ok(Some(state)) if state == expected) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("expected durable delivery state {expected}, observed {observed:?}"),
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn fork_operation_count(database: &Path) -> rusqlite::Result<i64> {
        let operation_id = [6_u8; 32];
        rusqlite::Connection::open(database)?.query_row(
            "SELECT COUNT(*) FROM fork_admission_operations WHERE kind = 2 AND operation_id = ?1",
            params![operation_id.as_slice()],
            |row| row.get(0),
        )
    }

    fn fork_result(response: &[u8]) -> io::Result<([u8; 16], [u8; 32])> {
        let Value::Array(fields) = ciborium::from_reader(response).map_err(io::Error::other)?
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "FARL1 must be an array",
            ));
        };
        let [Value::Text(marker), Value::Integer(version), Value::Integer(code), Value::Array(result)] =
            fields.as_slice()
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid FARL1 fields",
            ));
        };
        if marker != "FARL1" || *version != 1.into() || *code != 0.into() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "FARL1 is not successful",
            ));
        }
        let [Value::Integer(kind), Value::Bytes(child), Value::Bytes(admission)] =
            result.as_slice()
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "FARL1 is not a Fork result",
            ));
        };
        if *kind != 2.into() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "FARL1 kind is not Fork",
            ));
        }
        let child = child
            .as_slice()
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid Fork child ID"))?;
        let admission = admission
            .as_slice()
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid admission digest"))?;
        Ok((child, admission))
    }

    #[test]
    fn provision_rejects_missing_protected_credentials() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("gateway.db");
        let credentials = directory.path().join("missing-credentials");
        assert!(provision_local_fork_admission_authority(
            &database.display().to_string(),
            &credentials,
        )
        .is_err());
        assert!(!database.exists());
        Ok(())
    }

    #[test]
    fn listener_start_rejects_missing_protected_credentials_before_bind(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("gateway.db");
        let credentials = directory.path().join("missing-credentials");
        let socket = directory.path().join("fork-admission.sock");
        assert!(start_local_fork_admission_listener(
            &database.display().to_string(),
            &credentials,
            &socket,
        )
        .is_err());
        assert!(!socket.exists());
        Ok(())
    }

    #[test]
    fn provision_rejects_missing_or_swapped_credential_files_before_database_open(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let database = directory.path().join("gateway.db");

        let service_uid = rustix::process::geteuid().as_raw();
        let (auth_credential, host_credential) =
            test_credential_bytes_for_service(service_uid, [7; 32], [8; 32])?;
        protected_credential_file(
            directory.path(),
            "pigloros.fork-admission-auth",
            &host_credential,
        )?;
        assert!(provision_local_fork_admission_authority(
            &database.display().to_string(),
            directory.path(),
        )
        .is_err());
        assert!(!database.exists());

        protected_credential_file(
            directory.path(),
            "pigloros.fork-admission-host-signer",
            &auth_credential,
        )?;
        assert!(provision_local_fork_admission_authority(
            &database.display().to_string(),
            directory.path(),
        )
        .is_err());
        assert!(!database.exists());
        Ok(())
    }

    #[test]
    fn listener_start_rejects_uninitialized_or_mismatched_authority_before_bind(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let runtime = tempfile::tempdir()?;
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o750))?;
        let database = directory.path().join("gateway.db");
        let credentials = protected_credential_directory(directory.path())?;
        let socket = runtime.path().join("fork-admission.sock");
        protected_credentials(&credentials, [7; 32], [8; 32])?;

        assert!(start_local_fork_admission_listener(
            &database.display().to_string(),
            &credentials,
            &socket,
        )
        .is_err());
        assert!(!socket.exists());

        provision_local_fork_admission_authority(&database.display().to_string(), &credentials)?;
        protected_credentials(&credentials, [9; 32], [8; 32])?;
        assert!(start_local_fork_admission_listener(
            &database.display().to_string(),
            &credentials,
            &socket,
        )
        .is_err());
        assert!(!socket.exists());

        protected_credentials(&credentials, [7; 32], [9; 32])?;
        assert!(start_local_fork_admission_listener(
            &database.display().to_string(),
            &credentials,
            &socket,
        )
        .is_err());
        assert!(!socket.exists());
        Ok(())
    }

    #[test]
    fn listener_start_rejects_an_insecure_runtime_directory_after_authority_open(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let runtime = tempfile::tempdir()?;
        let database = directory.path().join("gateway.db");
        let socket = runtime.path().join("fork-admission.sock");
        provision_with_credentials(
            &database.display().to_string(),
            &current_peer_credentials([7; 32], [8; 32])?,
        )?;

        assert!(start_with_credentials(
            &database.display().to_string(),
            current_peer_credentials([7; 32], [8; 32])?,
            &socket,
        )
        .is_err());
        assert!(!socket.exists());
        Ok(())
    }

    #[test]
    fn sqlite_open_failures_leave_authority_and_socket_uncreated(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let runtime = tempfile::tempdir()?;
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o750))?;
        let socket = runtime.path().join("fork-admission.sock");
        let database_directory = directory.path().join("not-a-database");
        fs::create_dir(&database_directory)?;
        let database = database_directory.display().to_string();
        let credentials = current_peer_credentials([7; 32], [8; 32])?;

        assert!(provision_with_credentials(&database, &credentials).is_err());
        assert!(start_with_credentials(&database, credentials, &socket).is_err());
        assert!(!socket.exists());
        Ok(())
    }

    #[test]
    fn listener_retains_post_commit_disconnect_as_uncertain_for_same_principal_retry(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let runtime = tempfile::tempdir()?;
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o750))?;
        let database = directory.path().join("gateway.db");
        let socket = runtime.path().join("fork-admission.sock");
        provision_with_credentials(
            &database.display().to_string(),
            &current_peer_credentials([7; 32], [8; 32])?,
        )?;
        let listener = start_with_credentials(
            &database.display().to_string(),
            current_peer_credentials([7; 32], [8; 32])?,
            &socket,
        )?;
        let payload = bind_payload(1);

        disconnect_after_complete_request(&socket, &payload)?;
        wait_for_delivery_state(&database, 2)?;

        let response = request(&socket, &payload, false)?;
        assert_eq!(
            &response[..10],
            &[0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 0, 0x82]
        );
        wait_for_delivery_state(&database, 3)?;
        listener.stop()?;
        assert!(!socket.exists());
        Ok(())
    }

    #[test]
    fn listener_accepts_fragmented_frames_and_refuses_unclosed_or_trailing_input(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let runtime = tempfile::tempdir()?;
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o750))?;
        let database = directory.path().join("gateway.db");
        let socket = runtime.path().join("fork-admission.sock");
        provision_with_credentials(
            &database.display().to_string(),
            &current_peer_credentials([7; 32], [8; 32])?,
        )?;
        let listener = start_with_credentials(
            &database.display().to_string(),
            current_peer_credentials([7; 32], [8; 32])?,
            &socket,
        )?;

        let fragmented = request(&socket, &bind_payload(2), true)?;
        assert_eq!(
            &fragmented[..10],
            &[0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 0, 0x82]
        );
        request_without_half_close(&socket, &bind_payload(3))?;
        trailing_byte_request(&socket, &bind_payload(4))?;
        let after_trailing = request(&socket, &bind_payload(4), false)?;
        // The first Bind already owns this Principal; a later distinct Bind
        // resolves to that binding, and the listener still answers after a
        // bad frame.
        assert_eq!(
            &after_trailing[..10],
            &[0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 0, 0x82]
        );
        listener.stop()?;
        assert!(!socket.exists());
        Ok(())
    }

    #[test]
    fn listener_creates_one_fork_and_retries_its_result_for_the_same_principal(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let runtime = tempfile::tempdir()?;
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o750))?;
        let database = directory.path().join("gateway.db");
        let socket = runtime.path().join("fork-admission.sock");
        let parent = {
            let mut store = SqliteStore::open(&database.display().to_string())?;
            store.create_timeline("listener Fork parent")?
        };
        assert!(parent.meta.is_root());
        assert_eq!(parent.head.as_u64(), 0);
        provision_with_credentials(
            &database.display().to_string(),
            &current_peer_credentials([7; 32], [8; 32])?,
        )?;
        let listener = start_with_credentials(
            &database.display().to_string(),
            current_peer_credentials([7; 32], [8; 32])?,
            &socket,
        )?;

        let bind = request(&socket, &bind_payload(5), false)?;
        assert_eq!(
            &bind[..10],
            &[0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 0, 0x82]
        );
        let payload = fork_payload(parent.id())?;
        let first = fork_result(&request(&socket, &payload, false)?)?;
        let retry = fork_result(&request(&socket, &payload, false)?)?;
        assert_ne!(first.0, [0; 16]);
        assert_ne!(first.1, [0; 32]);
        assert_eq!(first, retry);
        assert_eq!(fork_operation_count(&database)?, 1);
        listener.stop()?;
        assert!(!socket.exists());
        Ok(())
    }

    #[test]
    fn listener_rejects_a_fork_before_principal_ownership_is_bound(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let runtime = tempfile::tempdir()?;
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o750))?;
        let database = directory.path().join("gateway.db");
        let socket = runtime.path().join("fork-admission.sock");
        let parent = {
            let mut store = SqliteStore::open(&database.display().to_string())?;
            store.create_timeline("unbound Fork parent")?
        };
        provision_with_credentials(
            &database.display().to_string(),
            &current_peer_credentials([7; 32], [8; 32])?,
        )?;
        let listener = start_with_credentials(
            &database.display().to_string(),
            current_peer_credentials([7; 32], [8; 32])?,
            &socket,
        )?;

        // An unbound Principal is a semantic rejection (#465 InvalidRequest).
        assert_eq!(
            request(&socket, &fork_payload(parent.id())?, false)?,
            vec![0x84, 0x65, b'F', b'A', b'R', b'L', b'1', 1, 7, 0xf6]
        );
        listener.stop()?;
        assert!(!socket.exists());
        Ok(())
    }

    #[test]
    fn stopped_listener_without_worker_is_a_noop() {
        let listener = LocalForkAdmissionListenerV1 {
            stopping: Arc::new(AtomicBool::new(false)),
            worker: None,
            socket_path: None,
        };
        assert!(listener.stop().is_ok());
    }

    #[test]
    fn stopped_listener_reports_a_panicked_worker() {
        let listener = LocalForkAdmissionListenerV1 {
            stopping: Arc::new(AtomicBool::new(false)),
            worker: Some(thread::spawn(|| {
                std::panic::resume_unwind(Box::new("test worker panic"))
            })),
            socket_path: None,
        };
        assert!(listener.stop().is_err());
    }
}
