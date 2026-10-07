//! Public acceptance vectors for the ADR-103 revision 4 Plugin trust policy registry port on
//! the `SQLite` adapter (slice #569): the shared vectors C1, D1-D3, E1-E3, and F1-F2, plus the
//! `SQLite`-only clauses of S1 and restart retention.
#![cfg(all(target_os = "linux", feature = "sqlite"))]

#[path = "support/plugin_trust_registry_fixtures.rs"]
pub mod fixtures;

mod core_vectors {
    type Store = pos_store::sqlite::SqliteStore;
    include!("support/plugin_trust_registry_vectors_core.rs");
}

use std::sync::Arc;

use fixtures::{activation, release_one, release_two, Env, Harness, RegistryError, TestResult};
use pos_core::{store::EventStore, store::SeqRange, ErasureContainmentGateV1};
use pos_store::{
    plugin_trust_registry::{
        PluginTrustCommitOutcomeV1, PluginTrustPolicyRegistryV1, ProvisionOutcomeV1,
    },
    sqlite::SqliteStore,
};

fn path_of(directory: &tempfile::TempDir) -> TestResult<String> {
    Ok(directory
        .path()
        .join("existing.db")
        .to_str()
        .ok_or("non-UTF-8 path")?
        .to_owned())
}

#[test]
fn a_preexisting_store_file_is_missing_state_until_provisioned() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = path_of(&directory)?;
    drop(SqliteStore::open(&path)?);
    let mut store = SqliteStore::open(&path)?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let timeline = store.create_timeline("plugin-activation")?.id();
    let env = Env::new("scope")?;
    let genesis = env.genesis()?;
    assert_eq!(
        store.retained_policy_state("scope"),
        Err(RegistryError::MissingState)
    );
    assert_eq!(store.ledger("scope"), Err(RegistryError::MissingState));
    assert_eq!(
        store.active_release("scope", "plugin-a"),
        Err(RegistryError::MissingState)
    );
    assert_eq!(
        store.retained_release_decision("scope", [1; 32]),
        Err(RegistryError::MissingState)
    );
    assert_eq!(
        store.advance_policy(
            &env.anchor,
            &genesis.tps1,
            &genesis.evidence,
            genesis.trusted()?,
            genesis.tick
        ),
        Err(RegistryError::MissingState)
    );
    assert_eq!(
        store.admit(
            &env.anchor,
            &genesis.tps1,
            &genesis.evidence,
            &release_one().projection()?,
            genesis.trusted()?,
            genesis.tick,
            activation(timeline, 1)
        ),
        Err(RegistryError::MissingState)
    );
    assert_eq!(
        store.provision(&env.anchor, &env.genesis_tps1),
        Ok(ProvisionOutcomeV1::Created)
    );
    drop(store);
    let reopened = SqliteStore::open(&path)?;
    assert_eq!(reopened.retained_policy_state("scope")?.tps1_epoch(), 1);
    let mut again = reopened;
    assert_eq!(
        again.provision(&env.anchor, &env.genesis_tps1),
        Ok(ProvisionOutcomeV1::Unchanged)
    );
    Ok(())
}

#[test]
fn committed_state_survives_a_restart_and_a_retry_replays() -> TestResult {
    let mut h = Harness::<SqliteStore>::open()?;
    let genesis = h.env.genesis()?;
    let one = release_one();
    let two = release_two();
    let first = h.admit(&genesis, &one, 1)??;
    h.admit(&genesis, &two, 2)??;
    let policy = h.policy()?;
    let ledger = h.ledger()?;
    let events = h.events()?;
    let Harness {
        store,
        env,
        timeline,
        guard,
    } = h;
    drop(store);
    let directory = guard.directory.as_ref().ok_or("no directory")?;
    let path = directory
        .path()
        .join("plugin-trust.db")
        .to_str()
        .ok_or("non-UTF-8 path")?
        .to_owned();
    let mut store = SqliteStore::open(&path)?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    assert_eq!(store.retained_policy_state("scope")?, policy);
    assert_eq!(store.ledger("scope")?, ledger);
    assert_eq!(store.read(timeline, SeqRange::all())?, events);
    let retry = store.admit(
        &env.anchor,
        &genesis.tps1,
        &genesis.evidence,
        &one.projection()?,
        genesis.trusted()?,
        genesis.tick,
        activation(timeline, 1),
    )?;
    assert_eq!(
        retry.outcome(),
        PluginTrustCommitOutcomeV1::IdempotentReplay
    );
    assert_eq!(retry.decision(), first.decision());
    assert_eq!(store.read(timeline, SeqRange::all())?.len(), 2);
    drop(guard);
    Ok(())
}
