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
        std::iter::once((&self.conn, reader_kind))
            .chain(
                self.writer_reservation_connection
                    .as_ref()
                    .map(|writer| (writer, IntervalConnectionV1::Writer)),
            )
            .try_for_each(|(connection, kind)| {
                let observer = Arc::clone(&observer);
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
    use super::observer_error;
    use pos_core::CoreError;

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
