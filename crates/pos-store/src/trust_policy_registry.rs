//! Operator-owned, durable TPS1 admission for the Gateway EPF1 boundary.
//!
//! The release anchor is supplied by the trusted host, never read from TPS1.
//! This registry authenticates policy state; it does not install an EPF1 or
//! grant a runtime Plugin pin by itself.

use pos_conformance::{ExecutionProfileV1, TrustPolicySnapshotV1};
use rusqlite::{params, Connection, OpenFlags, Transaction, TransactionBehavior};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Operator-approved identity pinned outside the incoming TPS1 record.
pub struct OperatorReleaseTrustV1 {
    policy_id: String,
    operator_public_key: [u8; 32],
    genesis_digest: [u8; 32],
}

impl OperatorReleaseTrustV1 {
    /// Construct release inputs; the trusted Gateway host must pin these to
    /// its independently approved release, not accept them from a caller.
    #[must_use]
    pub const fn new(
        policy_id: String,
        operator_public_key: [u8; 32],
        genesis_digest: [u8; 32],
    ) -> Self {
        Self {
            policy_id,
            operator_public_key,
            genesis_digest,
        }
    }
}

/// Host-owned request for one exact canonical EPF1 artifact.
#[derive(Clone, Copy)]
pub struct GatewayEpf1TrustRequestV1<'a> {
    pub exact_epf1: &'a [u8],
    pub signing_key_id: &'a str,
    pub signing_root_version: u64,
}

/// Authenticated snapshot evidence, not a production installation capability.
pub struct AdmittedTrustSnapshotV1 {
    digest: [u8; 32],
    epoch: u64,
    raw_epf1_digest: [u8; 32],
}

impl AdmittedTrustSnapshotV1 {
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn raw_epf1_digest(&self) -> [u8; 32] {
        self.raw_epf1_digest
    }
}

/// Safe, closed TPS1 deployment admission errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustPolicyRegistryErrorV1 {
    InvalidSnapshot,
    InvalidOperatorSignature,
    InvalidGenesis,
    MissingState,
    CorruptState,
    StaleSnapshot,
    UnsupportedPosition,
    Expired,
    Revoked,
    UnsupportedRoot,
    UnsupportedVersion,
    InvalidEpf1,
    StorageUnavailable,
}

impl std::fmt::Display for TrustPolicyRegistryErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSnapshot => "invalid deployment TPS1 snapshot",
            Self::InvalidOperatorSignature => "TPS1 operator signature is not trusted",
            Self::InvalidGenesis => "TPS1 genesis does not match the operator release",
            Self::MissingState => "deployment trust state is not provisioned",
            Self::CorruptState => "deployment trust state is corrupt",
            Self::StaleSnapshot => "TPS1 epoch or predecessor is stale",
            Self::UnsupportedPosition => "global Gateway requires TPS1 position zero",
            Self::Expired => "TPS1 offline validity has expired or is invalid",
            Self::Revoked => "EPF1 artifact or signing root is revoked",
            Self::UnsupportedRoot => "EPF1 signing root is not current",
            Self::UnsupportedVersion => "EPF1 version is below the TPS1 minimum",
            Self::InvalidEpf1 => "EPF1 exact canonical artifact is invalid",
            Self::StorageUnavailable => "deployment trust storage is unavailable",
        })
    }
}

impl std::error::Error for TrustPolicyRegistryErrorV1 {}

struct StoredSnapshot {
    snapshot: TrustPolicySnapshotV1,
    bytes: Vec<u8>,
    digest: [u8; 32],
    genesis_digest: [u8; 32],
}

/// One private `SQLite` WAL state store owned by the Gateway host.
///
/// A whole-store rollback while the host is stopped is outside the protection
/// of this first deployment. The trusted host must own this single registry
/// instance and hold its mutable borrow through registration mutation.
pub struct DeploymentTrustPolicyRegistryV1 {
    connection: Connection,
    release: OperatorReleaseTrustV1,
    path: PathBuf,
    state_identity: (u64, u64),
}

impl DeploymentTrustPolicyRegistryV1 {
    /// Explicit operator genesis provisioning. Gateway startup never calls it.
    ///
    /// # Errors
    /// Rejects a non-genesis or incorrectly signed record, wrong release
    /// anchor, nonzero global position, existing state, or failed transaction.
    pub fn provision_explicit(
        path: &Path,
        release: &OperatorReleaseTrustV1,
        exact_tps1: &[u8],
    ) -> Result<(), TrustPolicyRegistryErrorV1> {
        let snapshot = authenticate(exact_tps1, release)?;
        let digest = raw_digest(exact_tps1);
        if snapshot.epoch != 1
            || snapshot.previous_snapshot_digest.is_some()
            || digest != release.genesis_digest
        {
            return Err(TrustPolicyRegistryErrorV1::InvalidGenesis);
        }
        require_global_position(&snapshot)?;
        let mut connection = open_connection(path, true)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| TrustPolicyRegistryErrorV1::StorageUnavailable)?;
        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS deployment_trust_state (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    policy_id TEXT NOT NULL, epoch INTEGER NOT NULL,
                    full_digest BLOB NOT NULL, exact_bytes BLOB NOT NULL,
                    genesis_digest BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS deployment_trust_audit (
                    sequence INTEGER PRIMARY KEY, action TEXT NOT NULL,
                    epoch INTEGER NOT NULL, full_digest BLOB NOT NULL
                );",
            )
            .map_err(|_| TrustPolicyRegistryErrorV1::StorageUnavailable)?;
        transaction
            .execute(
                "INSERT INTO deployment_trust_state VALUES (1, ?1, 1, ?2, ?3, ?2)",
                params![&release.policy_id, digest.as_slice(), exact_tps1],
            )
            .map_err(|_| TrustPolicyRegistryErrorV1::StorageUnavailable)?;
        audit(&transaction, "operator-genesis", 1, &digest)?;
        transaction
            .commit()
            .map_err(|_| TrustPolicyRegistryErrorV1::StorageUnavailable)
    }

    /// Open only an existing, intact and authenticated operator state store.
    ///
    /// # Errors
    /// Missing or corrupt state fails closed; startup never provisions it.
    pub fn open_current(
        path: &Path,
        release: OperatorReleaseTrustV1,
    ) -> Result<Self, TrustPolicyRegistryErrorV1> {
        let connection = open_connection(path, false)?;
        let stored = read_state(&connection)?;
        authenticate(&stored.bytes, &release)
            .map_err(|_| TrustPolicyRegistryErrorV1::CorruptState)?;
        if stored.snapshot.policy_id != release.policy_id
            || stored.genesis_digest != release.genesis_digest
        {
            return Err(TrustPolicyRegistryErrorV1::CorruptState);
        }
        let state_identity = path_identity(path)?;
        Ok(Self {
            connection,
            release,
            path: path.to_owned(),
            state_identity,
        })
    }

    /// Authenticate current TPS1 and one raw EPF1 before calling the trusted
    /// registration operation while this registry remains mutably borrowed.
    ///
    /// A signed successor is durably committed before checking whether this
    /// EPF1 is allowed, so a revocation cannot be lost on a denied request.
    /// The callback receives evidence only after that check succeeds.
    /// The callback must perform registry mutation synchronously and must not
    /// hand this evidence to a caller as a production capability.
    ///
    /// # Errors
    /// Rejects missing, stale, forged, expired or revoked policy and EPF1.
    pub fn with_admitted_epf1<T>(
        &mut self,
        exact_tps1: &[u8],
        request: GatewayEpf1TrustRequestV1<'_>,
        register: impl FnOnce(&AdmittedTrustSnapshotV1) -> Result<T, TrustPolicyRegistryErrorV1>,
    ) -> Result<T, TrustPolicyRegistryErrorV1> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TrustPolicyRegistryErrorV1::Expired)?
            .as_secs();
        self.with_admitted_epf1_at(exact_tps1, request, now, register)
    }

    fn with_admitted_epf1_at<T>(
        &mut self,
        exact_tps1: &[u8],
        request: GatewayEpf1TrustRequestV1<'_>,
        now: u64,
        register: impl FnOnce(&AdmittedTrustSnapshotV1) -> Result<T, TrustPolicyRegistryErrorV1>,
    ) -> Result<T, TrustPolicyRegistryErrorV1> {
        self.ensure_path_identity()?;
        let incoming = authenticate(exact_tps1, &self.release)?;
        require_global_position(&incoming)?;
        let digest = raw_digest(exact_tps1);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| TrustPolicyRegistryErrorV1::StorageUnavailable)?;
        let stored = read_state(&transaction)?;
        authenticate(&stored.bytes, &self.release)
            .map_err(|_| TrustPolicyRegistryErrorV1::CorruptState)?;
        if stored.snapshot.policy_id != self.release.policy_id
            || stored.genesis_digest != self.release.genesis_digest
        {
            return Err(TrustPolicyRegistryErrorV1::CorruptState);
        }
        if exact_tps1 != stored.bytes.as_slice() {
            if incoming.epoch <= stored.snapshot.epoch
                || incoming.previous_snapshot_digest != Some(stored.digest)
            {
                return Err(TrustPolicyRegistryErrorV1::StaleSnapshot);
            }
            let epoch = i64::try_from(incoming.epoch)
                .map_err(|_| TrustPolicyRegistryErrorV1::InvalidSnapshot)?;
            transaction
                .execute(
                    "UPDATE deployment_trust_state SET epoch = ?1, full_digest = ?2, exact_bytes = ?3 WHERE singleton = 1",
                    params![epoch, digest.as_slice(), exact_tps1],
                )
                .map_err(|_| TrustPolicyRegistryErrorV1::StorageUnavailable)?;
            audit(&transaction, "operator-successor", epoch, &digest)?;
        }
        transaction
            .commit()
            .map_err(|_| TrustPolicyRegistryErrorV1::StorageUnavailable)?;
        self.ensure_path_identity()?;
        let raw_epf1_digest = verify_epf1(&incoming, &request, now)?;
        register(&AdmittedTrustSnapshotV1 {
            digest,
            epoch: incoming.epoch,
            raw_epf1_digest,
        })
    }

    fn ensure_path_identity(&self) -> Result<(), TrustPolicyRegistryErrorV1> {
        if path_identity(&self.path)? == self.state_identity {
            Ok(())
        } else {
            Err(TrustPolicyRegistryErrorV1::CorruptState)
        }
    }
}

fn path_identity(path: &Path) -> Result<(u64, u64), TrustPolicyRegistryErrorV1> {
    std::fs::metadata(path)
        .map(|metadata| (metadata.dev(), metadata.ino()))
        .map_err(|_| TrustPolicyRegistryErrorV1::MissingState)
}

fn authenticate(
    bytes: &[u8],
    release: &OperatorReleaseTrustV1,
) -> Result<TrustPolicySnapshotV1, TrustPolicyRegistryErrorV1> {
    let snapshot = TrustPolicySnapshotV1::from_canonical_cbor(bytes)
        .map_err(|_| TrustPolicyRegistryErrorV1::InvalidSnapshot)?;
    if snapshot.policy_id != release.policy_id {
        return Err(TrustPolicyRegistryErrorV1::InvalidSnapshot);
    }
    snapshot
        .verify_operator_signature_v1(&release.operator_public_key, "deployment-operator")
        .map_err(|_| TrustPolicyRegistryErrorV1::InvalidOperatorSignature)?;
    Ok(snapshot)
}

const fn require_global_position(
    snapshot: &TrustPolicySnapshotV1,
) -> Result<(), TrustPolicyRegistryErrorV1> {
    if snapshot.effective_timeline_position == 0 {
        Ok(())
    } else {
        Err(TrustPolicyRegistryErrorV1::UnsupportedPosition)
    }
}

fn verify_epf1(
    snapshot: &TrustPolicySnapshotV1,
    request: &GatewayEpf1TrustRequestV1<'_>,
    now: u64,
) -> Result<[u8; 32], TrustPolicyRegistryErrorV1> {
    let expiry = parse_utc_seconds(&snapshot.offline_valid_through)
        .ok_or(TrustPolicyRegistryErrorV1::Expired)?;
    if now > expiry {
        return Err(TrustPolicyRegistryErrorV1::Expired);
    }
    let profile = ExecutionProfileV1::from_canonical_cbor(request.exact_epf1)
        .map_err(|_| TrustPolicyRegistryErrorV1::InvalidEpf1)?;
    let raw_epf1_digest = raw_digest(request.exact_epf1);
    if snapshot
        .revoked_artifact_digests
        .binary_search(&raw_epf1_digest)
        .is_ok()
        || snapshot
            .revoked_key_ids
            .binary_search_by(|key| key.as_str().cmp(request.signing_key_id))
            .is_ok()
    {
        return Err(TrustPolicyRegistryErrorV1::Revoked);
    }
    if !snapshot.trust_roots.iter().any(|root| {
        root.key_id == request.signing_key_id && root.root_version == request.signing_root_version
    }) {
        return Err(TrustPolicyRegistryErrorV1::UnsupportedRoot);
    }
    let minimum = snapshot
        .minimum_versions
        .iter()
        .find(|minimum| minimum.artifact_kind == "execution-profile")
        .ok_or(TrustPolicyRegistryErrorV1::UnsupportedVersion)?;
    if !profile.meets_minimum_version_v1(&minimum.semantic_version) {
        return Err(TrustPolicyRegistryErrorV1::UnsupportedVersion);
    }
    Ok(raw_epf1_digest)
}

fn raw_digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn open_connection(path: &Path, create: bool) -> Result<Connection, TrustPolicyRegistryErrorV1> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE;
    if create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let connection = Connection::open_with_flags(path, flags).map_err(|_| {
        if create {
            TrustPolicyRegistryErrorV1::StorageUnavailable
        } else {
            TrustPolicyRegistryErrorV1::MissingState
        }
    })?;
    let mode: String = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .map_err(|_| TrustPolicyRegistryErrorV1::StorageUnavailable)?;
    if mode != "wal" {
        return Err(TrustPolicyRegistryErrorV1::StorageUnavailable);
    }
    connection
        .execute_batch("PRAGMA synchronous = FULL")
        .map_err(|_| TrustPolicyRegistryErrorV1::StorageUnavailable)?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(|_| TrustPolicyRegistryErrorV1::StorageUnavailable)?;
    if synchronous != 2 {
        return Err(TrustPolicyRegistryErrorV1::StorageUnavailable);
    }
    Ok(connection)
}

fn read_state(connection: &Connection) -> Result<StoredSnapshot, TrustPolicyRegistryErrorV1> {
    let row: (String, i64, Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT policy_id, epoch, full_digest, exact_bytes, genesis_digest FROM deployment_trust_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => TrustPolicyRegistryErrorV1::MissingState,
            _ => TrustPolicyRegistryErrorV1::CorruptState,
        })?;
    let snapshot = TrustPolicySnapshotV1::from_canonical_cbor(&row.3)
        .map_err(|_| TrustPolicyRegistryErrorV1::CorruptState)?;
    if row.0 != snapshot.policy_id
        || u64::try_from(row.1).ok() != Some(snapshot.epoch)
        || row.2.as_slice() != raw_digest(&row.3).as_slice()
        || row.4.len() != 32
    {
        return Err(TrustPolicyRegistryErrorV1::CorruptState);
    }
    let audit_row: (i64, Vec<u8>) = connection
        .query_row(
            "SELECT epoch, full_digest FROM deployment_trust_audit ORDER BY sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| TrustPolicyRegistryErrorV1::CorruptState)?;
    if audit_row.0 != row.1 || audit_row.1 != row.2 {
        return Err(TrustPolicyRegistryErrorV1::CorruptState);
    }
    let genesis_digest: [u8; 32] = row
        .4
        .as_slice()
        .try_into()
        .map_err(|_| TrustPolicyRegistryErrorV1::CorruptState)?;
    Ok(StoredSnapshot {
        snapshot,
        digest: raw_digest(&row.3),
        bytes: row.3,
        genesis_digest,
    })
}

fn audit(
    transaction: &Transaction<'_>,
    action: &str,
    epoch: i64,
    digest: &[u8; 32],
) -> Result<(), TrustPolicyRegistryErrorV1> {
    transaction
        .execute(
            "INSERT INTO deployment_trust_audit(action, epoch, full_digest) VALUES (?1, ?2, ?3)",
            params![action, epoch, digest.as_slice()],
        )
        .map(|_| ())
        .map_err(|_| TrustPolicyRegistryErrorV1::StorageUnavailable)
}

fn parse_utc_seconds(value: &str) -> Option<u64> {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || [0..4, 5..7, 8..10, 11..13, 14..16, 17..19]
            .iter()
            .any(|range| !bytes[range.clone()].iter().all(u8::is_ascii_digit))
    {
        return None;
    }
    let number = |start: usize, end: usize| {
        value
            .get(start..end)
            .and_then(|part| part.parse::<i64>().ok())
    };
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day < 1 || day > days_in_month[usize::try_from(month - 1).ok()?] {
        return None;
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year / 400;
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let year_days = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + year_days - 719_468;
    u64::try_from(days * 86_400 + hour * 3_600 + minute * 60 + second).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const TEST_NOW: u64 = 1_780_000_000;

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[29; 32])
    }

    fn signed(mut snapshot: TrustPolicySnapshotV1) -> Vec<u8> {
        let message = snapshot
            .operator_signature_message_v1()
            .expect("valid operator message");
        snapshot.operator_signature = signer().sign(&message).to_bytes();
        snapshot.to_canonical_cbor().expect("canonical signed TPS1")
    }

    fn fixture_snapshot() -> TrustPolicySnapshotV1 {
        let bytes = pos_conformance::draft_trust_policy_snapshot_bytes_v1()
            .expect("draft structural TPS1 fixture");
        TrustPolicySnapshotV1::from_canonical_cbor(&bytes).expect("canonical TPS1 fixture")
    }

    fn fixture_profile() -> Vec<u8> {
        pos_conformance::draft_execution_profile_bytes_v1("deterministic-local-v1")
            .expect("canonical EPF1 fixture")
    }

    fn release(snapshot: &TrustPolicySnapshotV1, genesis: &[u8]) -> OperatorReleaseTrustV1 {
        OperatorReleaseTrustV1::new(
            snapshot.policy_id.clone(),
            signer().verifying_key().to_bytes(),
            raw_digest(genesis),
        )
    }

    fn request<'a>(
        snapshot: &'a TrustPolicySnapshotV1,
        profile: &'a [u8],
    ) -> GatewayEpf1TrustRequestV1<'a> {
        GatewayEpf1TrustRequestV1 {
            exact_epf1: profile,
            signing_key_id: &snapshot.trust_roots[0].key_id,
            signing_root_version: snapshot.trust_roots[0].root_version,
        }
    }

    #[test]
    fn genesis_requires_explicit_provisioning_and_reopens_with_signature() {
        let directory = tempfile::tempdir().expect("temporary trust directory");
        let path = directory.path().join("trust.db");
        let snapshot = fixture_snapshot();
        let genesis = signed(snapshot.clone());
        let anchor = release(&snapshot, &genesis);
        assert!(matches!(
            DeploymentTrustPolicyRegistryV1::open_current(&path, release(&snapshot, &genesis)),
            Err(TrustPolicyRegistryErrorV1::MissingState)
        ));
        DeploymentTrustPolicyRegistryV1::provision_explicit(&path, &anchor, &genesis)
            .expect("explicit genesis");
        assert!(
            DeploymentTrustPolicyRegistryV1::provision_explicit(&path, &anchor, &genesis).is_err()
        );
        let mut registry = DeploymentTrustPolicyRegistryV1::open_current(&path, anchor)
            .expect("reopen authenticated state");
        let profile = fixture_profile();
        let evidence = registry
            .with_admitted_epf1_at(&genesis, request(&snapshot, &profile), TEST_NOW, |proof| {
                Ok((proof.epoch(), proof.digest(), proof.raw_epf1_digest()))
            })
            .expect("unchanged signed policy");
        assert_eq!(evidence.0, 1);
        assert_eq!(evidence.1, raw_digest(&genesis));
        assert_eq!(evidence.2, raw_digest(&profile));
    }

    #[test]
    fn successor_is_durable_and_stale_epoch_fails_closed() {
        let directory = tempfile::tempdir().expect("temporary trust directory");
        let path = directory.path().join("trust.db");
        let snapshot = fixture_snapshot();
        let genesis = signed(snapshot.clone());
        let anchor = release(&snapshot, &genesis);
        DeploymentTrustPolicyRegistryV1::provision_explicit(&path, &anchor, &genesis)
            .expect("explicit genesis");
        let mut successor = snapshot.clone();
        successor.epoch = 2;
        successor.previous_snapshot_digest = Some(raw_digest(&genesis));
        let successor_bytes = signed(successor.clone());
        let profile = fixture_profile();
        let mut registry = DeploymentTrustPolicyRegistryV1::open_current(&path, anchor)
            .expect("open current state");
        registry
            .with_admitted_epf1_at(
                &successor_bytes,
                request(&successor, &profile),
                TEST_NOW,
                |_| Ok(()),
            )
            .expect("signed successor");
        assert!(matches!(
            registry.with_admitted_epf1_at(
                &genesis,
                request(&snapshot, &profile),
                TEST_NOW,
                |_| Ok(())
            ),
            Err(TrustPolicyRegistryErrorV1::StaleSnapshot)
        ));
        drop(registry);
        let mut reopened =
            DeploymentTrustPolicyRegistryV1::open_current(&path, release(&snapshot, &genesis))
                .expect("restart on durable successor");
        reopened
            .with_admitted_epf1_at(
                &successor_bytes,
                request(&successor, &profile),
                TEST_NOW,
                |_| Ok(()),
            )
            .expect("same successor after restart");
        let audit_count: i64 = reopened
            .connection
            .query_row("SELECT COUNT(*) FROM deployment_trust_audit", [], |row| {
                row.get(0)
            })
            .expect("audit count");
        assert_eq!(audit_count, 2);
    }

    #[test]
    fn forged_position_and_raw_digest_revocation_reject() {
        let snapshot = fixture_snapshot();
        let genesis = signed(snapshot.clone());
        let directory = tempfile::tempdir().expect("temporary trust directory");
        let path = directory.path().join("trust.db");
        DeploymentTrustPolicyRegistryV1::provision_explicit(
            &path,
            &release(&snapshot, &genesis),
            &genesis,
        )
        .expect("genesis");
        let mut registry =
            DeploymentTrustPolicyRegistryV1::open_current(&path, release(&snapshot, &genesis))
                .expect("open state");
        let profile = fixture_profile();
        let mut nonzero = snapshot.clone();
        nonzero.epoch = 2;
        nonzero.previous_snapshot_digest = Some(raw_digest(&genesis));
        nonzero.effective_timeline_position = 1;
        assert!(matches!(
            registry.with_admitted_epf1_at(
                &signed(nonzero),
                request(&snapshot, &profile),
                TEST_NOW,
                |_| Ok(())
            ),
            Err(TrustPolicyRegistryErrorV1::UnsupportedPosition)
        ));
        let mut revoked = snapshot.clone();
        revoked.epoch = 2;
        revoked.previous_snapshot_digest = Some(raw_digest(&genesis));
        revoked.revoked_artifact_digests.push(raw_digest(&profile));
        let revoked_bytes = signed(revoked);
        let mut callback_called = false;
        assert!(matches!(
            registry.with_admitted_epf1_at(
                &revoked_bytes,
                request(&snapshot, &profile),
                TEST_NOW,
                |_| {
                    callback_called = true;
                    Ok(())
                }
            ),
            Err(TrustPolicyRegistryErrorV1::Revoked)
        ));
        assert!(!callback_called);
        drop(registry);
        let mut reopened =
            DeploymentTrustPolicyRegistryV1::open_current(&path, release(&snapshot, &genesis))
                .expect("revocation remains committed after restart");
        assert!(matches!(
            reopened.with_admitted_epf1_at(
                &genesis,
                request(&snapshot, &profile),
                TEST_NOW,
                |_| Ok(())
            ),
            Err(TrustPolicyRegistryErrorV1::StaleSnapshot)
        ));
        assert!(matches!(
            reopened.with_admitted_epf1_at(
                &revoked_bytes,
                request(&snapshot, &profile),
                TEST_NOW,
                |_| Ok(())
            ),
            Err(TrustPolicyRegistryErrorV1::Revoked)
        ));
    }

    #[test]
    fn revoked_key_and_embedded_digest_distinction() {
        let snapshot = fixture_snapshot();
        let genesis = signed(snapshot.clone());
        let profile = fixture_profile();
        for revoke_key in [true, false] {
            let directory = tempfile::tempdir().expect("temporary trust directory");
            let path = directory.path().join("trust.db");
            DeploymentTrustPolicyRegistryV1::provision_explicit(
                &path,
                &release(&snapshot, &genesis),
                &genesis,
            )
            .expect("genesis");
            let mut registry =
                DeploymentTrustPolicyRegistryV1::open_current(&path, release(&snapshot, &genesis))
                    .expect("open state");
            let mut revoked_key = snapshot.clone();
            revoked_key.epoch = 2;
            revoked_key.previous_snapshot_digest = Some(raw_digest(&genesis));
            if revoke_key {
                revoked_key
                    .revoked_key_ids
                    .push(snapshot.trust_roots[0].key_id.clone());
            } else {
                let embedded = ExecutionProfileV1::from_canonical_cbor(&profile)
                    .expect("canonical EPF1")
                    .profile_digest;
                assert_ne!(embedded, raw_digest(&profile));
                revoked_key.revoked_artifact_digests.push(embedded);
            }
            let result = registry.with_admitted_epf1_at(
                &signed(revoked_key),
                request(&snapshot, &profile),
                TEST_NOW,
                |_| Ok(()),
            );
            if revoke_key {
                assert!(matches!(result, Err(TrustPolicyRegistryErrorV1::Revoked)));
            } else {
                result.expect("embedded digest is not raw EPF1 revocation");
            }
        }
    }

    #[test]
    fn invalid_signature_expiry_root_and_state_reject() {
        let snapshot = fixture_snapshot();
        let genesis = signed(snapshot.clone());
        let directory = tempfile::tempdir().expect("temporary trust directory");
        let path = directory.path().join("trust.db");
        DeploymentTrustPolicyRegistryV1::provision_explicit(
            &path,
            &release(&snapshot, &genesis),
            &genesis,
        )
        .expect("genesis");
        let mut registry =
            DeploymentTrustPolicyRegistryV1::open_current(&path, release(&snapshot, &genesis))
                .expect("open state");
        let profile = fixture_profile();
        let mut forged = snapshot.clone();
        forged.epoch = 2;
        let forged_bytes = forged.to_canonical_cbor().expect("structural TPS1");
        assert!(matches!(
            registry.with_admitted_epf1_at(
                &forged_bytes,
                request(&snapshot, &profile),
                TEST_NOW,
                |_| Ok(())
            ),
            Err(TrustPolicyRegistryErrorV1::InvalidOperatorSignature)
        ));
        assert!(matches!(
            registry.with_admitted_epf1_at(
                &genesis,
                request(&snapshot, &profile),
                u64::MAX,
                |_| Ok(())
            ),
            Err(TrustPolicyRegistryErrorV1::Expired)
        ));
        let bad_root = GatewayEpf1TrustRequestV1 {
            exact_epf1: &profile,
            signing_key_id: "foreign",
            signing_root_version: 1,
        };
        assert!(matches!(
            registry.with_admitted_epf1_at(&genesis, bad_root, TEST_NOW, |_| Ok(())),
            Err(TrustPolicyRegistryErrorV1::UnsupportedRoot)
        ));
        let mut discontinuous = snapshot.clone();
        discontinuous.epoch = 2;
        discontinuous.previous_snapshot_digest = Some([9; 32]);
        assert!(matches!(
            registry.with_admitted_epf1_at(
                &signed(discontinuous),
                request(&snapshot, &profile),
                TEST_NOW,
                |_| Ok(())
            ),
            Err(TrustPolicyRegistryErrorV1::StaleSnapshot)
        ));
        let mut same_epoch_changed = snapshot.clone();
        same_epoch_changed.offline_valid_through = "2031-01-01T00:00:00Z".to_owned();
        assert!(matches!(
            registry.with_admitted_epf1_at(
                &signed(same_epoch_changed),
                request(&snapshot, &profile),
                TEST_NOW,
                |_| Ok(())
            ),
            Err(TrustPolicyRegistryErrorV1::StaleSnapshot)
        ));
        let invalid_epf1 = GatewayEpf1TrustRequestV1 {
            exact_epf1: b"not canonical EPF1",
            signing_key_id: &snapshot.trust_roots[0].key_id,
            signing_root_version: snapshot.trust_roots[0].root_version,
        };
        assert!(matches!(
            registry.with_admitted_epf1_at(&genesis, invalid_epf1, TEST_NOW, |_| Ok(())),
            Err(TrustPolicyRegistryErrorV1::InvalidEpf1)
        ));
        drop(registry);
        let foreign_release = OperatorReleaseTrustV1::new(
            snapshot.policy_id.clone(),
            SigningKey::from_bytes(&[30; 32]).verifying_key().to_bytes(),
            raw_digest(&genesis),
        );
        assert!(matches!(
            DeploymentTrustPolicyRegistryV1::open_current(&path, foreign_release),
            Err(TrustPolicyRegistryErrorV1::CorruptState)
        ));
        let connection = Connection::open(&path).expect("operator test connection");
        connection
            .execute(
                "UPDATE deployment_trust_state SET full_digest = ?1 WHERE singleton = 1",
                params![vec![0_u8; 32]],
            )
            .expect("corrupt state");
        assert!(matches!(
            DeploymentTrustPolicyRegistryV1::open_current(&path, release(&snapshot, &genesis)),
            Err(TrustPolicyRegistryErrorV1::CorruptState)
        ));
    }

    #[test]
    fn denied_signed_successors_still_advance_policy() {
        let snapshot = fixture_snapshot();
        let genesis = signed(snapshot.clone());
        let profile = fixture_profile();
        for case in 0..3 {
            let directory = tempfile::tempdir().expect("temporary trust directory");
            let path = directory.path().join("trust.db");
            DeploymentTrustPolicyRegistryV1::provision_explicit(
                &path,
                &release(&snapshot, &genesis),
                &genesis,
            )
            .expect("genesis");
            let mut registry =
                DeploymentTrustPolicyRegistryV1::open_current(&path, release(&snapshot, &genesis))
                    .expect("open state");
            let mut successor = snapshot.clone();
            successor.epoch = 2;
            successor.previous_snapshot_digest = Some(raw_digest(&genesis));
            let expected = match case {
                0 => {
                    let minimum = successor
                        .minimum_versions
                        .iter_mut()
                        .find(|minimum| minimum.artifact_kind == "execution-profile")
                        .expect("execution-profile minimum");
                    minimum.semantic_version = "999.0.0".to_owned();
                    TrustPolicyRegistryErrorV1::UnsupportedVersion
                }
                1 => {
                    successor
                        .minimum_versions
                        .retain(|minimum| minimum.artifact_kind != "execution-profile");
                    TrustPolicyRegistryErrorV1::UnsupportedVersion
                }
                _ => {
                    successor.offline_valid_through = "unparseable".to_owned();
                    TrustPolicyRegistryErrorV1::Expired
                }
            };
            assert_eq!(
                registry
                    .with_admitted_epf1_at(
                        &signed(successor),
                        request(&snapshot, &profile),
                        TEST_NOW,
                        |_| Ok(())
                    )
                    .expect_err("signed successor denies profile"),
                expected
            );
            assert!(matches!(
                registry.with_admitted_epf1_at(
                    &genesis,
                    request(&snapshot, &profile),
                    TEST_NOW,
                    |_| Ok(())
                ),
                Err(TrustPolicyRegistryErrorV1::StaleSnapshot)
            ));
        }
    }

    #[test]
    fn utc_expiry_parser_rejects_malformed_and_handles_leap_days() {
        assert_eq!(parse_utc_seconds("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_utc_seconds("1970-01-02T00:00:00Z"), Some(86_400));
        assert!(parse_utc_seconds("2024-02-29T23:59:59Z").is_some());
        assert_eq!(parse_utc_seconds("2023-02-29T00:00:00Z"), None);
        assert_eq!(parse_utc_seconds("2024-13-01T00:00:00Z"), None);
        assert_eq!(parse_utc_seconds("2024-01-01T00:00:60Z"), None);
        assert_eq!(parse_utc_seconds("2030-01-01"), None);
    }

    #[test]
    fn removal_of_live_state_path_denies_new_admission() {
        let snapshot = fixture_snapshot();
        let genesis = signed(snapshot.clone());
        let directory = tempfile::tempdir().expect("temporary trust directory");
        let path = directory.path().join("trust.db");
        DeploymentTrustPolicyRegistryV1::provision_explicit(
            &path,
            &release(&snapshot, &genesis),
            &genesis,
        )
        .expect("genesis");
        let mut registry =
            DeploymentTrustPolicyRegistryV1::open_current(&path, release(&snapshot, &genesis))
                .expect("open state");
        std::fs::remove_file(&path).expect("remove temporary database path");
        let profile = fixture_profile();
        assert!(matches!(
            registry.with_admitted_epf1_at(
                &genesis,
                request(&snapshot, &profile),
                TEST_NOW,
                |_| Ok(())
            ),
            Err(TrustPolicyRegistryErrorV1::MissingState)
        ));
    }
}
