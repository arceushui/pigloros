//! Unwrapping fixture steps inside runners that cannot return a `Result`.

/// Unwrap a fixture step, failing the runner with the unexpected error.
///
/// `resume_unwind` is deliberate: the workspace denies `unwrap`, `expect` and `panic!`, and the
/// suite harness catches the unwind and reports it as a `RunnerPanicked` failure of the case.
pub trait TestOk<T> {
    /// The value, or an unwind that names the error.
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestOk<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected fixture error: {error:?}")))
        })
    }
}
