//! Fixture extensions shared by the registry test modules.

pub(super) trait TestValueExt<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!(
                "unexpected registry fixture error: {error:?}"
            )))
        })
    }
}

impl<T> TestValueExt<T> for Option<T> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|| {
            std::panic::resume_unwind(Box::new("missing registry fixture value"))
        })
    }
}

pub(super) trait TestErrorExt<T, E> {
    fn test_err(self) -> E;
}

impl<T: std::fmt::Debug, E> TestErrorExt<T, E> for Result<T, E> {
    fn test_err(self) -> E {
        match self {
            Ok(value) => std::panic::resume_unwind(Box::new(format!(
                "unexpected successful registry fixture value: {value:?}"
            ))),
            Err(error) => error,
        }
    }
}
