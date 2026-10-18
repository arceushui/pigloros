//! Native `SQLite` transaction observation and refusal for nonproduction tests.

use super::SqliteStore;
use pos_core::CoreError;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use std::{sync::Arc, time::Duration};

pub use rusqlite::hooks::TransactionOperation;

/// Native connection participating in a protected interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntervalConnectionV1 {
    /// The separate read snapshot used by direct read-only access.
    Reader,
    /// The writer reservation, also used for reads on a read-write store.
    Writer,
}

impl SqliteStore {
    /// Observe native transaction statements; return false to make `SQLite`
    /// itself refuse that statement. No connection or SQL interface escapes.
    ///
    /// # Errors
    /// Returns an error if `SQLite` cannot install its native authorizer.
    pub fn observe_interval_transactions_for_test(
        &self,
        observer: Arc<dyn Fn(IntervalConnectionV1, TransactionOperation) -> bool + Send + Sync>,
    ) -> Result<(), CoreError> {
        let reader_kind = if self.writer_reservation_connection.is_some() {
            IntervalConnectionV1::Reader
        } else {
            IntervalConnectionV1::Writer
        };
        let writer = self
            .writer_reservation_connection
            .as_ref()
            .map(|writer| (writer, IntervalConnectionV1::Writer, Arc::clone(&observer)));
        // The primary callback takes the caller's Arc; only a second
        // connection needs a separately owned observer clone.
        std::iter::once((&self.conn, reader_kind, observer))
            .chain(writer)
            .try_for_each(|(connection, kind, observer)| {
                connection.authorizer(Some(move |context: AuthContext<'_>| {
                    authorize(context, kind, observer.as_ref())
                }))
            })
            .map_err(observer_error)
    }

    /// Make a competing test writer report an existing reservation immediately.
    ///
    /// # Errors
    /// Returns an error if `SQLite` cannot configure the test connection.
    pub fn use_nonblocking_writer_for_test(&self) -> Result<(), CoreError> {
        self.conn
            .busy_timeout(Duration::ZERO)
            .map_err(observer_error)
    }
}

fn authorize(
    context: AuthContext<'_>,
    connection: IntervalConnectionV1,
    observer: &(dyn Fn(IntervalConnectionV1, TransactionOperation) -> bool + Send + Sync),
) -> Authorization {
    if let AuthAction::Transaction { operation } = context.action {
        if !observer(connection, operation) {
            return Authorization::Deny;
        }
    }
    Authorization::Allow
}

fn observer_error(_: rusqlite::Error) -> CoreError {
    CoreError::Storage("native test transaction observer unavailable".to_owned())
}

#[cfg(test)]
mod tests {
    use super::{observer_error, IntervalConnectionV1, SqliteStore, TransactionOperation};
    use pos_core::{
        counterfactual_store::test_fixtures::{assert_ok, ok},
        CoreError,
    };
    use std::sync::{Arc, Mutex};

    #[test]
    fn native_observer_covers_both_connection_shapes_and_can_refuse_begin() {
        let directory = ok(tempfile::tempdir());
        let path = directory.path().join("native-interval-observer.sqlite");
        let path = ok(path.to_str().ok_or("fixture path"));
        let writer = ok(SqliteStore::open(path));
        let reader = ok(SqliteStore::open_read_only(path));
        assert!(writer.writer_reservation_connection.is_none());
        assert!(reader.writer_reservation_connection.is_some());
        for store in [&writer, &reader] {
            let mut connections = vec![(
                &store.conn,
                if store.writer_reservation_connection.is_some() {
                    IntervalConnectionV1::Reader
                } else {
                    IntervalConnectionV1::Writer
                },
            )];
            if let Some(connection) = &store.writer_reservation_connection {
                connections.push((connection, IntervalConnectionV1::Writer));
            }
            for allow_begin in [true, false] {
                let observed = Arc::new(Mutex::new(Vec::new()));
                let callback_observed = Arc::clone(&observed);
                assert_ok(store.observe_interval_transactions_for_test(Arc::new(
                    move |connection, operation| {
                        let Ok(mut observed) = callback_observed.lock() else {
                            return false;
                        };
                        observed.push((connection, operation));
                        allow_begin || operation != TransactionOperation::Begin
                    },
                )));
                let mut expected = Vec::new();
                for &(connection, kind) in &connections {
                    assert_eq!(
                        ok(connection.query_row("SELECT 7", [], |row| row.get::<_, i64>(0))),
                        7
                    );
                    let began = connection.execute_batch("BEGIN DEFERRED");
                    expected.push((kind, TransactionOperation::Begin));
                    if allow_begin {
                        assert_ok(began);
                        assert_ok(connection.execute_batch("ROLLBACK"));
                        expected.push((kind, TransactionOperation::Rollback));
                    } else {
                        assert!(began.is_err());
                    }
                    assert!(connection.is_autocommit());
                }
                assert_eq!(*ok(observed.lock()), expected);
                let poisoned = Arc::clone(&observed);
                let worker = std::thread::spawn(move || {
                    // Own the lock until unwinding poisons it; do not unlock early.
                    let _guard = ok(poisoned.lock());
                    std::panic::resume_unwind(Box::new("intentional native observer poison"));
                });
                assert!(worker.join().is_err());
                assert!(observed.is_poisoned());
                for &(connection, _) in &connections {
                    assert!(connection.execute_batch("BEGIN DEFERRED").is_err());
                    assert!(connection.is_autocommit());
                }
            }
        }
    }

    #[test]
    fn nonblocking_test_writer_clears_the_actual_native_busy_timeout() {
        let store = ok(SqliteStore::open(":memory:"));
        let initial: i64 = ok(store
            .conn
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0)));
        assert!(initial > 0);
        assert_ok(store.use_nonblocking_writer_for_test());
        let actual: i64 = ok(store
            .conn
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0)));
        assert_eq!(actual, 0);
    }

    #[test]
    fn observer_error_mapping_does_not_expose_native_diagnostics() {
        let native = rusqlite::Error::InvalidParameterName("private_observer_detail".to_owned());
        assert!(native.to_string().contains("private_observer_detail"));
        // The error translation is independent of connection setup. Its typed
        // input deliberately contains detail that the public message must omit.
        assert!(matches!(
            observer_error(native),
            CoreError::Storage(message)
                if message == "native test transaction observer unavailable"
        ));
    }
}
