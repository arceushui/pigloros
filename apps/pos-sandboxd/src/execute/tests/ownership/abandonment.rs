use std::{fs, os::unix::fs::MetadataExt as _, path::Path};

use super::*;
use crate::test_fixtures::attempt_directory::require_isolated_root;

fn identity(path: &Path) -> std::io::Result<(u64, u64)> {
    let metadata = fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

#[tokio::test]
async fn owner_abandonment_fences_unpolled_execution_and_preserves_intent() -> TestResult {
    if !require_isolated_root(
        "execute::tests::ownership::abandonment::owner_abandonment_fences_unpolled_execution_and_preserves_intent",
    )
    .map_err(|error| error.to_string())?
    {
        return Ok(());
    }
    let owner = authenticated_owner()?;
    let attempt = AdmittedAttempt::from_entry(&owner.input.entry(), &owner.directory)?;
    assert_eq!(attempt.mode(), SandboxExecutionMode::AirGapped);
    let component = attempt.unit_name().attempt_component();
    let record = Path::new("/run/pigloros/sandbox/registry").join(component);
    let attempt_path = Path::new("/run/pigloros/sandbox/attempts").join(component);
    let root_path = attempt_path.join("root");
    let intent = fs::read(&record)?;
    let directories = [identity(&attempt_path)?, identity(&root_path)?];
    let mut scenario = Scenario::new()?;
    let rechecked = AtomicBool::new(false);
    let run = scenario.run_on(&LoopbackNetwork, job(&scenario, &attempt), || {
        rechecked.store(true, Ordering::SeqCst);
        Err(ImageActivationError::EvidenceMismatch)
    });

    drop(owner.directory);
    assert_eq!(owner.ledger.usage().attempts, 1);
    let failed = failure(run.await)?;
    assert!(matches!(failed.error, ExecuteError::AttemptAlreadyClaimed));
    assert_eq!(failed.unit, UnitState::NotStarted);
    assert!(scenario.entries().is_empty());
    assert!(!rechecked.load(Ordering::SeqCst));
    assert_eq!(fs::read(&record)?, intent);
    assert_eq!(
        [identity(&attempt_path)?, identity(&root_path)?],
        directories
    );
    assert_eq!(owner.ledger.usage().attempts, 1);
    drop(attempt);
    assert_eq!(owner.ledger.usage().attempts, 1);
    drop(owner.input);
    assert_eq!(owner.ledger.usage(), StagingUsage::default());
    Ok(())
}

#[tokio::test]
async fn admitted_clone_drop_leaves_the_prepared_owner_usable() -> TestResult {
    if !require_isolated_root(
        "execute::tests::ownership::abandonment::admitted_clone_drop_leaves_the_prepared_owner_usable",
    )
    .map_err(|error| error.to_string())?
    {
        return Ok(());
    }
    let owner = authenticated_owner()?;
    let attempt = AdmittedAttempt::from_entry(&owner.input.entry(), &owner.directory)?;
    assert_eq!(attempt.mode(), SandboxExecutionMode::AirGapped);
    drop(attempt.clone());
    let reconstructed = AdmittedAttempt::from_entry(&owner.input.entry(), &owner.directory)?;
    owner.directory.verify_directory()?;
    let mut scenario = Scenario::new()?;
    let mut mismatched = job(&scenario, &reconstructed);
    mismatched.mode = ModePlan::Fork;
    let failed = failure(
        scenario
            .run_on(&LoopbackNetwork, mismatched, || {
                Err(ImageActivationError::EvidenceMismatch)
            })
            .await,
    )?;
    // Reaching the ordinary mode check proves the owner still allowed a claim.
    assert!(matches!(failed.error, ExecuteError::ModeMismatch));
    assert_eq!(failed.unit, UnitState::NotStarted);
    assert!(scenario.entries().is_empty());
    assert_eq!(owner.ledger.usage().attempts, 1);
    Ok(())
}

#[tokio::test]
async fn directory_removal_fences_execution_and_retains_intent() -> TestResult {
    if !require_isolated_root(
        "execute::tests::ownership::abandonment::directory_removal_fences_execution_and_retains_intent",
    )
    .map_err(|error| error.to_string())?
    {
        return Ok(());
    }
    let owner = authenticated_owner()?;
    let attempt = AdmittedAttempt::from_entry(&owner.input.entry(), &owner.directory)?;
    assert_eq!(attempt.mode(), SandboxExecutionMode::AirGapped);
    let component = attempt.unit_name().attempt_component();
    let record = Path::new("/run/pigloros/sandbox/registry").join(component);
    let attempt_path = Path::new("/run/pigloros/sandbox/attempts").join(component);
    let intent = fs::read(&record)?;

    // No execution has been polled and the fresh tree has never been mounted.
    owner.directory.remove_unmounted()?;
    assert!(!attempt_path.exists());
    assert_eq!(fs::read(&record)?, intent);
    assert_eq!(owner.ledger.usage().attempts, 1);
    let mut scenario = Scenario::new()?;
    refused_owner(&mut scenario, &attempt).await?;
    assert_eq!(owner.ledger.usage().attempts, 1);
    drop(attempt);
    drop(owner.input);
    assert_eq!(owner.ledger.usage(), StagingUsage::default());
    assert_eq!(fs::read(&record)?, intent);
    Ok(())
}
