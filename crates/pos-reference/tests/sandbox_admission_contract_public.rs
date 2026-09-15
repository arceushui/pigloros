macro_rules! public_admission_tests {
    ($($tokens:tt)*) => {
        $($tokens)*
    };
}

include!("support/sandbox_admission_fixture.rs");
