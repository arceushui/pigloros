// Complete public execution admission; no raw policy or entry constructor.

use pos_reference::provider_admission::{
    execution::PreparedProviderExecution, test_support::StagedInstallation,
};
use pos_sandboxd::{StagingDirectory, StagingLedger, VerifiedStagedInput};
use std::{
    fs::{self, File},
    io::Read as _,
    os::unix::{
        fs::{MetadataExt as _, PermissionsExt as _},
        net::UnixStream,
    },
};

pub fn verified_input(
    staged: &StagedInstallation,
    ledger: &StagingLedger,
) -> Result<(tempfile::TempDir, VerifiedStagedInput), Box<dyn std::error::Error + Send + Sync>> {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let held = File::open(directory.path())?;
    let staging = StagingDirectory::from_held_directory(held.try_clone()?, held.metadata()?.uid())?;
    let (mut provider, mut selector) = UnixStream::pair()?;
    let input = std::thread::scope(|scope| {
        let client = scope.spawn(move || -> Result<(), String> {
            selector
                .set_read_timeout(Some(std::time::Duration::from_secs(30)))
                .map_err(|error| error.to_string())?;
            staged
                .write_source(&mut selector)
                .map_err(|error| error.to_string())?;
            let mut prefix = [0; 4];
            selector
                .read_exact(&mut prefix)
                .map_err(|error| error.to_string())?;
            let mut grant = vec![
                0;
                usize::try_from(u32::from_be_bytes(prefix))
                    .map_err(|error| error.to_string())?
            ];
            selector
                .read_exact(&mut grant)
                .map_err(|error| error.to_string())?;
            pos_reference::sandbox_provider_protocol::AdmissionGrant::from_canonical_cbor(&grant)
                .map_err(|error| error.to_string())?;
            staged
                .write_input(&mut selector)
                .map_err(|error| error.to_string())?;
            selector
                .shutdown(std::net::Shutdown::Write)
                .map_err(|error| error.to_string())
        });
        let result = (|| {
            let mut prepared = PreparedProviderExecution::receive(&mut provider, ledger)?;
            let name = prepared.request().attempt_id;
            prepared.send_grant(&mut provider, |message| {
                Ok(StagedInstallation::sign_grant(message))
            })?;
            staging.create_input(name, prepared)?.receive(&mut provider)
        })();
        drop(provider);
        let peer = client
            .join()
            .map_err(|_| "selector fixture panicked".to_owned())?;
        let input = result.map_err(|error| error.to_string())?;
        peer?;
        Ok::<_, String>(input)
    })?;
    Ok((directory, input))
}
