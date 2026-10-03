//! `SQLite` adapter for the ADR-105 `FIP1` issuer-policy port.
//!
//! Every accepted policy is one `fork_attribution_issuer_policies` row, and
//! the singleton `fork_attribution_issuer_policy_floor` row names the newest
//! one. An install reads the floor, appends the history row, and moves the
//! floor inside one `IMMEDIATE` transaction, so both become visible at commit
//! or neither does. Reads revalidate the stored bytes against the floor row.

use pos_core::{ForkAttributionIssuerPolicyV1, Hash};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use super::SqliteStore;
use crate::fork_attribution_issuer_policy::{
    admit_fork_attribution_issuer, checked_retained_policy, pinned_issuer_policy,
    plan_issuer_policy_install, AuthenticatedOperatorPolicyPinV1,
    ForkAttributionIssuerAdmissionBasisV1, ForkAttributionIssuerAdmissionQueryV1,
    ForkAttributionIssuerAdmissionV1, ForkAttributionIssuerPolicyErrorV1,
    ForkAttributionIssuerPolicyInstallationPortV1, IssuerPolicyFloorV1,
    IssuerPolicyInstallOutcomeV1, IssuerPolicyInstallReceiptV1, LoadedIssuerPolicyV1,
    PolicyResultV1,
};

/// The expected scope, generation, and digest of one stored policy, with its
/// bytes when the history row exists.
type StoredPolicyRowV1 = (String, i64, [u8; 32], Option<Vec<u8>>);

impl From<rusqlite::Error> for ForkAttributionIssuerPolicyErrorV1 {
    /// Deliberately conservative: no `SQLite` failure is trusted to prove what
    /// was or was not committed.
    fn from(_: rusqlite::Error) -> Self {
        Self::StorageIndeterminate
    }
}

impl ForkAttributionIssuerPolicyInstallationPortV1 for SqliteStore {
    fn install(
        &mut self,
        pin: &AuthenticatedOperatorPolicyPinV1,
        policy_bytes: &[u8],
    ) -> Result<IssuerPolicyInstallReceiptV1, ForkAttributionIssuerPolicyErrorV1> {
        let candidate = pinned_issuer_policy(pin, policy_bytes)?;
        let transaction = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = install_in_transaction(&transaction, &candidate);
        finish_issuer_policy_transaction(transaction, result)
    }

    fn issuer_policy_floor(
        &self,
    ) -> Result<Option<IssuerPolicyFloorV1>, ForkAttributionIssuerPolicyErrorV1> {
        let current = read_floor_policy(&self.conn)?;
        Ok(current.as_ref().map(IssuerPolicyFloorV1::of))
    }

    fn admit_issuer(
        &self,
        query: &ForkAttributionIssuerAdmissionQueryV1,
    ) -> Result<ForkAttributionIssuerAdmissionV1, ForkAttributionIssuerPolicyErrorV1> {
        admit_fork_attribution_issuer(query, |basis| match basis {
            ForkAttributionIssuerAdmissionBasisV1::CommittedImport { policy_generation } => {
                read_retained_policy(&self.conn, policy_generation)
            }
            ForkAttributionIssuerAdmissionBasisV1::AbsentImport => read_floor_policy(&self.conn),
        })
    }
}

/// Commit a successful install, or roll back a failed one; an unknown commit
/// or rollback outcome is `StorageIndeterminate`.
fn finish_issuer_policy_transaction<T>(
    transaction: rusqlite::Transaction<'_>,
    result: PolicyResultV1<T>,
) -> PolicyResultV1<T> {
    match result {
        Ok(value) => transaction
            .commit()
            .map(|()| value)
            .map_err(ForkAttributionIssuerPolicyErrorV1::from),
        Err(error) => Err(transaction.rollback().map_or(
            ForkAttributionIssuerPolicyErrorV1::StorageIndeterminate,
            |()| error,
        )),
    }
}

/// Plan against the floor read under the write lock, then persist a new floor.
fn install_in_transaction(
    conn: &Connection,
    candidate: &ForkAttributionIssuerPolicyV1,
) -> PolicyResultV1<IssuerPolicyInstallReceiptV1> {
    let current = read_floor_policy(conn)?;
    let receipt = plan_issuer_policy_install(candidate, current.as_ref())?;
    if receipt.outcome == IssuerPolicyInstallOutcomeV1::Installed {
        persist_floor_policy(conn, candidate, &receipt.floor)?;
    }
    Ok(receipt)
}

fn persist_floor_policy(
    conn: &Connection,
    candidate: &ForkAttributionIssuerPolicyV1,
    floor: &IssuerPolicyFloorV1,
) -> PolicyResultV1<()> {
    let digest = floor.digest.as_bytes().as_slice();
    let generation = sqlite_generation(floor.generation);
    conn.execute(
        "INSERT INTO fork_attribution_issuer_policies (policy_digest, generation, fip1_cbor)
         VALUES (?1, ?2, ?3)",
        params![digest, generation, candidate.to_canonical_cbor()],
    )?;
    conn.execute(
        "INSERT INTO fork_attribution_issuer_policy_floor
             (singleton, scope, generation, policy_digest)
         VALUES (1, ?1, ?2, ?3)
         ON CONFLICT (singleton) DO UPDATE SET
             scope = excluded.scope,
             generation = excluded.generation,
             policy_digest = excluded.policy_digest",
        params![floor.scope, generation, digest],
    )?;
    Ok(())
}

/// Read the floor policy, requiring the history row it names to decode to
/// exactly the floor's scope, generation, and digest.
fn read_floor_policy(conn: &Connection) -> LoadedIssuerPolicyV1 {
    let row = conn
        .query_row(
            "SELECT floor.scope, floor.generation, floor.policy_digest, history.fip1_cbor
             FROM fork_attribution_issuer_policy_floor AS floor
             LEFT JOIN fork_attribution_issuer_policies AS history
                 ON history.policy_digest = floor.policy_digest",
            [],
            |row| StoredPolicyRowV1::try_from(row),
        )
        .optional()?;
    row.map(stored_policy_row).transpose()
}

/// Decode one stored policy and require it to be exactly the expected scope,
/// generation, and digest.
fn stored_policy_row(
    (scope, generation, digest, bytes): StoredPolicyRowV1,
) -> PolicyResultV1<ForkAttributionIssuerPolicyV1> {
    let bytes = bytes.ok_or(ForkAttributionIssuerPolicyErrorV1::CorruptPolicy)?;
    // The table `CHECK` keeps generations in 1..=96; generation 0 matches none.
    let generation = u64::try_from(generation).unwrap_or(0);
    let digest = Hash::from_bytes(digest);
    let policy = stored_policy(&bytes)?;
    checked_retained_policy(policy, &scope, generation, digest)
}

/// Read the retained policy at one committed generation, if any, requiring it
/// to be in the floor's scope, at its row generation, and at its row digest.
fn read_retained_policy(conn: &Connection, generation: u64) -> LoadedIssuerPolicyV1 {
    let generation = sqlite_generation(generation);
    let row = conn
        .query_row(
            "SELECT floor.scope, history.generation, history.policy_digest, history.fip1_cbor
             FROM fork_attribution_issuer_policies AS history
             JOIN fork_attribution_issuer_policy_floor AS floor
             WHERE history.generation = ?1",
            params![generation],
            |row| StoredPolicyRowV1::try_from(row),
        )
        .optional()?;
    row.map(stored_policy_row).transpose()
}

/// `SQLite` stores generations as signed integers. Stored generations are
/// 1..=96, so an unrepresentable one becomes `-1`, which matches no row and
/// fails the table's `CHECK` on insert.
fn sqlite_generation(generation: u64) -> i64 {
    i64::try_from(generation).unwrap_or(-1)
}

/// Decode stored policy bytes; any failure is corrupt durable state.
fn stored_policy(bytes: &[u8]) -> PolicyResultV1<ForkAttributionIssuerPolicyV1> {
    ForkAttributionIssuerPolicyV1::from_canonical_cbor(bytes)
        .map_err(|_| ForkAttributionIssuerPolicyErrorV1::CorruptPolicy)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use ed25519_dalek::SigningKey;
    use pos_core::{
        ForkAttributionIssuerPolicyEntryV1, ForkAttributionIssuerPolicyInputV1,
        ForkAttributionIssuerStateV1, ForkAttributionIssuerV1, PublicKey,
    };
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    use super::*;

    type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

    const INDETERMINATE: ForkAttributionIssuerPolicyErrorV1 =
        ForkAttributionIssuerPolicyErrorV1::StorageIndeterminate;
    const CORRUPT: ForkAttributionIssuerPolicyErrorV1 =
        ForkAttributionIssuerPolicyErrorV1::CorruptPolicy;

    fn issuer() -> Fallible<ForkAttributionIssuerV1> {
        let signing = SigningKey::from_bytes(&[1; 32]);
        let key = PublicKey::from_bytes(signing.verifying_key().to_bytes());
        Ok(ForkAttributionIssuerV1::new("issuer-a", 1, key)?)
    }

    /// One policy holding the single test issuer in `state`.
    fn policy(
        generation: u64,
        previous: Option<Hash>,
        state: ForkAttributionIssuerStateV1,
    ) -> Fallible<ForkAttributionIssuerPolicyV1> {
        Ok(ForkAttributionIssuerPolicyV1::new(
            ForkAttributionIssuerPolicyInputV1 {
                scope: "destination-a".to_owned(),
                generation,
                previous_policy_digest: previous,
                entries: vec![ForkAttributionIssuerPolicyEntryV1 {
                    issuer: issuer()?,
                    state,
                }],
            },
        )?)
    }

    /// Generations 1..=3 hold one issuer: Active, then revoked in an emergency
    /// successor (retiring the only Active issuer is refused), then a third
    /// generation that tests use only where install fails before planning.
    fn lifecycle() -> Fallible<Vec<ForkAttributionIssuerPolicyV1>> {
        let states = [
            ForkAttributionIssuerStateV1::Active,
            ForkAttributionIssuerStateV1::Revoked,
            ForkAttributionIssuerStateV1::Revoked,
        ];
        let mut policies: Vec<ForkAttributionIssuerPolicyV1> = Vec::new();
        for (generation, state) in (1..).zip(states) {
            let previous = policies.last().map(ForkAttributionIssuerPolicyV1::digest);
            policies.push(policy(generation, previous, state)?);
        }
        Ok(policies)
    }

    fn install(
        store: &mut SqliteStore,
        policy: &ForkAttributionIssuerPolicyV1,
    ) -> PolicyResultV1<IssuerPolicyInstallOutcomeV1> {
        let pin = AuthenticatedOperatorPolicyPinV1::new("destination-a", policy.digest());
        store
            .install(&pin, &policy.to_canonical_cbor())
            .map(|receipt| receipt.outcome)
    }

    fn admit(
        store: &SqliteStore,
        policy: &ForkAttributionIssuerPolicyV1,
        basis: ForkAttributionIssuerAdmissionBasisV1,
    ) -> Fallible<PolicyResultV1<ForkAttributionIssuerAdmissionV1>> {
        Ok(store.admit_issuer(&ForkAttributionIssuerAdmissionQueryV1 {
            issuer: issuer()?,
            policy_digest: policy.digest(),
            basis,
        }))
    }

    /// Deny one transaction statement; `Unknown` is how `SQLite` names `COMMIT`.
    fn deny(store: &SqliteStore, denied: TransactionOperation) -> rusqlite::Result<()> {
        store.conn.authorizer(Some(move |context: AuthContext<'_>| {
            if context.action == (AuthAction::Transaction { operation: denied }) {
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }))
    }

    fn allow_all(store: &SqliteStore) -> rusqlite::Result<()> {
        store
            .conn
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
    }

    fn history_rows(store: &SqliteStore) -> rusqlite::Result<i64> {
        store.conn.query_row(
            "SELECT COUNT(*) FROM fork_attribution_issuer_policies",
            [],
            |row| row.get(0),
        )
    }

    /// A store holding the first two lifecycle policies.
    fn installed_store(policies: &[ForkAttributionIssuerPolicyV1]) -> Fallible<SqliteStore> {
        let mut store = SqliteStore::open_in_memory()?;
        for policy in &policies[..2] {
            assert_eq!(
                install(&mut store, policy),
                Ok(IssuerPolicyInstallOutcomeV1::Installed)
            );
        }
        Ok(store)
    }

    #[test]
    fn begin_commit_and_rollback_failures_are_indeterminate() -> Fallible<()> {
        let policies = lifecycle()?;
        let mut store = SqliteStore::open_in_memory()?;
        deny(&store, TransactionOperation::Begin)?;
        assert_eq!(install(&mut store, &policies[0]), Err(INDETERMINATE));
        allow_all(&store)?;
        assert_eq!(store.issuer_policy_floor(), Ok(None));

        // The denied COMMIT rolled back, so the exact retry installs it, and
        // a further retry recovers the committed result.
        deny(&store, TransactionOperation::Unknown)?;
        assert_eq!(install(&mut store, &policies[0]), Err(INDETERMINATE));
        allow_all(&store)?;
        assert_eq!(store.issuer_policy_floor(), Ok(None));
        let installed = Ok(IssuerPolicyInstallOutcomeV1::Installed);
        assert_eq!(install(&mut store, &policies[0]), installed);
        let recovered = Ok(IssuerPolicyInstallOutcomeV1::AlreadyInstalled);
        assert_eq!(install(&mut store, &policies[0]), recovered);

        let mut store = SqliteStore::open_in_memory()?;
        deny(&store, TransactionOperation::Rollback)?;
        assert_eq!(install(&mut store, &policies[1]), Err(INDETERMINATE));
        Ok(())
    }

    #[test]
    fn a_failed_history_or_floor_write_installs_nothing() -> Fallible<()> {
        let policies = lifecycle()?;
        for table in [
            "fork_attribution_issuer_policies",
            "fork_attribution_issuer_policy_floor",
        ] {
            let mut store = SqliteStore::open_in_memory()?;
            store.conn.execute_batch(&format!(
                "CREATE TRIGGER fault BEFORE INSERT ON {table}
                 BEGIN SELECT RAISE(ABORT, 'injected fault'); END;"
            ))?;
            assert_eq!(install(&mut store, &policies[0]), Err(INDETERMINATE));
            assert_eq!(store.issuer_policy_floor(), Ok(None));
            assert_eq!(history_rows(&store)?, 0);
        }
        Ok(())
    }

    #[test]
    fn a_floor_without_its_exact_history_row_is_corrupt() -> Fallible<()> {
        let policies = lifecycle()?;
        let other_digest = "x'0101010101010101010101010101010101010101010101010101010101010101'";
        for tamper in [
            "DELETE FROM fork_attribution_issuer_policies WHERE generation = 2".to_owned(),
            "UPDATE fork_attribution_issuer_policies SET fip1_cbor = x'00' WHERE generation = 2"
                .to_owned(),
            "UPDATE fork_attribution_issuer_policy_floor SET scope = 'destination-b'".to_owned(),
            "UPDATE fork_attribution_issuer_policy_floor SET generation = 1".to_owned(),
            format!(
                "UPDATE fork_attribution_issuer_policies SET policy_digest = {other_digest}
                 WHERE generation = 2;
                 UPDATE fork_attribution_issuer_policy_floor SET policy_digest = {other_digest};"
            ),
        ] {
            let mut store = installed_store(&policies)?;
            store.conn.execute_batch(&tamper)?;
            assert_eq!(store.issuer_policy_floor(), Err(CORRUPT));
            assert_eq!(install(&mut store, &policies[2]), Err(CORRUPT));
            let absent = ForkAttributionIssuerAdmissionBasisV1::AbsentImport;
            assert_eq!(admit(&store, &policies[1], absent)?, Err(CORRUPT));
        }
        Ok(())
    }

    #[test]
    fn undecodable_committed_policy_is_corrupt() -> Fallible<()> {
        let policies = lifecycle()?;
        let store = installed_store(&policies)?;
        store.conn.execute_batch(
            "UPDATE fork_attribution_issuer_policies SET fip1_cbor = x'00' WHERE generation = 1",
        )?;
        let committed = ForkAttributionIssuerAdmissionBasisV1::CommittedImport {
            policy_generation: 1,
        };
        assert_eq!(admit(&store, &policies[0], committed)?, Err(CORRUPT));
        Ok(())
    }

    #[test]
    fn unreadable_policy_tables_are_indeterminate() -> Fallible<()> {
        let policies = lifecycle()?;
        let store = installed_store(&policies)?;
        store
            .conn
            .execute_batch("DROP TABLE fork_attribution_issuer_policy_floor")?;
        assert_eq!(store.issuer_policy_floor(), Err(INDETERMINATE));
        store
            .conn
            .execute_batch("DROP TABLE fork_attribution_issuer_policies")?;
        let committed = ForkAttributionIssuerAdmissionBasisV1::CommittedImport {
            policy_generation: 1,
        };
        assert_eq!(admit(&store, &policies[0], committed)?, Err(INDETERMINATE));
        Ok(())
    }

    #[test]
    fn committed_lookups_cross_check_the_retained_row() -> Fallible<()> {
        let policies = lifecycle()?;
        let other_digest = "x'0101010101010101010101010101010101010101010101010101010101010101'";
        for (tamper, generation) in [
            (
                "UPDATE fork_attribution_issuer_policies SET generation = 5 WHERE generation = 1"
                    .to_owned(),
                5,
            ),
            (
                "UPDATE fork_attribution_issuer_policy_floor SET scope = 'destination-b'"
                    .to_owned(),
                1,
            ),
            (
                format!(
                    "UPDATE fork_attribution_issuer_policies SET policy_digest = {other_digest}
                     WHERE generation = 1"
                ),
                1,
            ),
        ] {
            let store = installed_store(&policies)?;
            store.conn.execute_batch(&tamper)?;
            let committed = ForkAttributionIssuerAdmissionBasisV1::CommittedImport {
                policy_generation: generation,
            };
            assert_eq!(admit(&store, &policies[0], committed)?, Err(CORRUPT));
        }
        Ok(())
    }

    #[test]
    fn a_ninety_seventh_record_is_refused() -> Fallible<()> {
        // Single-step transitions reach at most 95 records, so seed a floor
        // at the 96-record ceiling directly.
        let active = ForkAttributionIssuerStateV1::Active;
        let ceiling = policy(96, Some(Hash::from_bytes([2; 32])), active)?;
        let next = policy(97, Some(ceiling.digest()), active)?;
        let mut store = SqliteStore::open_in_memory()?;
        let digest = ceiling.digest();
        store.conn.execute(
            "INSERT INTO fork_attribution_issuer_policies (policy_digest, generation, fip1_cbor)
             VALUES (?1, 96, ?2)",
            params![digest.as_bytes().as_slice(), ceiling.to_canonical_cbor()],
        )?;
        store.conn.execute(
            "INSERT INTO fork_attribution_issuer_policy_floor
                 (singleton, scope, generation, policy_digest)
             VALUES (1, 'destination-a', 96, ?1)",
            params![digest.as_bytes().as_slice()],
        )?;
        let exhausted = Err(ForkAttributionIssuerPolicyErrorV1::HistoryExhausted);
        assert_eq!(install(&mut store, &next), exhausted);
        assert_eq!(history_rows(&store)?, 1);
        Ok(())
    }
}
