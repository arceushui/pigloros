//! `pos-sandboxd-conformance IMAGE CERTIFICATE_DER KEY_DESCRIPTION`: the #444
//! QEMU evidence guest's driver (feature `test-support`, never deployed).
//!
//! This file only wires the library calls of
//! [`pos_sandboxd::packaged_conformance`], which hosted tests cover. The
//! mounted-root branch below runs only against the packaged mountfsd and
//! kernel of the evidence guest. Standard output carries the report lines;
//! closing standard input releases a held root.

use std::process::ExitCode;

use pos_sandboxd::packaged_conformance::{
    activate, exercise, exit_status, removal_line, report_line, ConformanceCase, ConformanceError,
    RELEASE_DEADLINE,
};

fn main() -> ExitCode {
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(ConformanceError::Io)
        .and_then(|runtime| runtime.block_on(run()));
    exit_status(result, &mut std::io::stderr())
}

async fn run() -> Result<(), ConformanceError> {
    let case = ConformanceCase::from_arguments(std::env::args_os().skip(1))?;
    let staged = case.stage()?;
    let activated = activate(&staged).await?;
    let directory = &activated.directory;
    let mut report = std::io::stdout();
    exercise(
        activated.outcome,
        |mount| format!("{}\t{}", mount.mount_id(), mount.root_directory().as_str()),
        |mount| async move {
            mount
                .detach(directory, tokio::time::Instant::now() + RELEASE_DEADLINE)
                .await
                .map(drop)
        },
        std::io::stdin(),
        &mut report,
    )
    .await?;
    report_line(
        &mut report,
        &removal_line(&activated.directory.remove_unmounted()),
    )
}
