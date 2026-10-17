//! Shared ADR-099 revision 12 classified counterfactual fixtures.
//!
//! An [`Authority`] is one store's live Fork admission session and its one
//! permit issuer. [`Authority::admit`] creates a factual parent with two
//! Events, admits a local ("classified") Fork at its head, registers the
//! fixture classifier, and publishes the Fork's counterfactual facts. [`Spec`]
//! builds the invalidation command of such a Fork. The public Memory and
//! `SQLite` tests and the adapter unit tests include this one file; the items
//! are public so that no test crate sees them as unused.

use std::error::Error;

use ciborium::value::Value;
use pos_core::counterfactual_store::test_fixtures::{
    frontier_frame, hash_field, id_field, invalidation_frame, invalidation_middle, uint,
};
use pos_core::fork_authentication::{
    principal_digest_v1, AuthenticatedPrincipalRecordV1, ForkAuthenticationAdapterPolicyV1,
    ForkAuthenticationPolicyV1,
};
use pos_core::{
    CanonicalBytes, CounterfactualFactsV1, CounterfactualInvalidationCommandV1,
    CounterfactualInvalidationInputV1, CounterfactualStorePortV1, DependencyNodeCoordinateV1,
    DependencyNodeRecordV1, EntityId, EventDraft, EventStore, ForkAdmissionHostCommandV1,
    ForkAdmissionOperationResultV1, ForkAppendSourceIdentityV1, ForkClassifierSourceInputV1,
    ForkClassifierSourceV1, ForkEventSourceDescriptorV1, ForkExternalInputRouteV1, Hash, Kind,
    PipelineDraftBatchV1, PrincipalRefV1, PublicKey, RecomputationFrontierBytesV1,
    RecordedDependencyClassV1, RecordedNodeOriginV1, Seq, SuffixInvalidationBytesV1,
    TickDependencyRecordV1, TimelineId,
};
use pos_crypto::fork_authentication::{
    verify_authenticated_principal_evidence_v1, ForkAuthenticationAdapterSigningKeyV1,
    ForkHostSigningKeyV1, VerifiedAuthenticatedPrincipalEvidenceV1,
};
use pos_store::{
    ClassifiedTickAuthorityV1, ForkAdmissionAuthorityBootstrapPortV1, ForkAdmissionAuthorityPortV1,
    ForkAdmissionAuthoritySessionV1, ForkAppendSourcePermitV1, ForkEventPermitIssuerPortV1,
    ForkEventPermitIssuerV1, ForkEventProvenanceAuthorityPortV1,
};
use ulid::Ulid;

pub type Fallible<T> = Result<T, Box<dyn Error>>;

/// The parent cut of every fixture Fork: its parent's two factual Events.
pub const PARENT_CUT: u64 = 2;
/// The Tick of the invalidation every fixture commits.
pub const FIRST_TICK: u64 = 17;
/// The Event type of every ordinary fixture Tick draft.
pub const TICK_KIND: &str = "counterfactual.tick";
/// The registrar of the fixture classifier.
pub const REGISTRAR: &str = "classified-counterfactual.test";
/// The Owner the fixture `POC1` binds, the creator of every fixture Fork.
pub const OWNER: &str = "classified-owner";
/// The room revision descriptor every fixture Fork is admitted under.
const DESCRIPTOR: Hash = Hash::from_bytes([8; 32]);
/// The authentication adapter of the fixture Principal.
const AUTHENTICATION_ADAPTER: &str = "classified-counterfactual.adapter";

/// `SQLite` counts of every row kind a classified write on the Fork `?1` adds.
///
/// The kinds are own Events, `EOR1`, `FOP1`, generations, quarantine, artifacts,
/// dependency records, nodes, and edges. `EOR1` rows carry no child column,
/// so they are counted store-wide; `?1 = ?1` only keeps the one parameter
/// every query binds.
pub const WRITTEN_ROWS_SQL: [&str; 9] = [
    "SELECT count(*) FROM events WHERE timeline_id = ?1",
    "SELECT count(*) FROM fork_event_origins WHERE ?1 = ?1",
    "SELECT count(*) FROM fork_append_operations WHERE child_id = ?1",
    "SELECT count(*) FROM counterfactual_generations WHERE fork_id = ?1",
    "SELECT count(*) FROM counterfactual_quarantine WHERE fork_id = ?1",
    "SELECT count(*) FROM counterfactual_artifacts WHERE fork_id = ?1",
    "SELECT count(*) FROM counterfactual_dependency_records WHERE timeline_id = ?1",
    "SELECT count(*) FROM counterfactual_dependency_nodes WHERE timeline_id = ?1",
    "SELECT count(*) FROM counterfactual_dependency_edges WHERE timeline_id = ?1",
];

/// The names of every table of one `SQLite` database, in a stable order.
const TABLES_SQL: &str = "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name";

/// Every row of every table of one `SQLite` connection, in a stable order.
///
/// A refusal that must change nothing compares two of these snapshots.
///
/// # Errors
/// Returns the `SQLite` error.
pub fn database_rows(connection: &rusqlite::Connection) -> Fallible<Vec<String>> {
    let mut tables = connection.prepare(TABLES_SQL)?;
    let names = tables
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut lines = Vec::new();
    for name in names {
        table_rows(connection, &name, &mut lines)?;
    }
    Ok(lines)
}

/// Every row of every table of the `SQLite` database file at `path`.
///
/// # Errors
/// Returns the `SQLite` error.
pub fn database_rows_at(path: &std::path::Path) -> Fallible<Vec<String>> {
    let connection = rusqlite::Connection::open(path)?;
    database_rows(&connection)
}

/// Append every row of `table`, each rendered with its table name.
fn table_rows(
    connection: &rusqlite::Connection,
    table: &str,
    lines: &mut Vec<String>,
) -> Fallible<()> {
    let mut statement = connection.prepare(&format!("SELECT * FROM \"{table}\""))?;
    let width = statement.column_count();
    let mut cursor = statement.query([])?;
    while let Some(row) = cursor.next()? {
        let values = (0..width)
            .map(|index| row.get::<_, rusqlite::types::Value>(index))
            .collect::<Result<Vec<_>, _>>()?;
        lines.push(format!("{table} {values:?}"));
    }
    Ok(())
}

/// A digest of 32 copies of `value`.
#[must_use]
pub const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

/// A store that admits classified Forks and runs their counterfactual writes.
pub trait Host:
    EventStore
    + CounterfactualStorePortV1
    + ForkAdmissionAuthorityBootstrapPortV1
    + ForkAdmissionAuthorityPortV1
    + ForkEventProvenanceAuthorityPortV1
    + ForkEventPermitIssuerPortV1
{
}

impl<T> Host for T where
    T: EventStore
        + CounterfactualStorePortV1
        + ForkAdmissionAuthorityBootstrapPortV1
        + ForkAdmissionAuthorityPortV1
        + ForkEventProvenanceAuthorityPortV1
        + ForkEventPermitIssuerPortV1
{
}

fn host_key() -> Fallible<ForkHostSigningKeyV1> {
    Ok(ForkHostSigningKeyV1::from_seed([121; 32])?)
}

fn adapter_key() -> Fallible<ForkAuthenticationAdapterSigningKeyV1> {
    Ok(ForkAuthenticationAdapterSigningKeyV1::from_seed([122; 32])?)
}

fn policy() -> Fallible<ForkAuthenticationPolicyV1> {
    Ok(ForkAuthenticationPolicyV1::new(vec![
        ForkAuthenticationAdapterPolicyV1 {
            adapter_id: AUTHENTICATION_ADAPTER.to_owned(),
            verifying_key: adapter_key()?.public_key(),
            minimum_assurance: 1,
            registry_bindings: vec![hash(3)],
        },
    ])?)
}

fn evidence() -> Fallible<VerifiedAuthenticatedPrincipalEvidenceV1> {
    let record = AuthenticatedPrincipalRecordV1 {
        principal: PrincipalRefV1::try_new([6; 16], "classified.local")?,
        adapter_id: AUTHENTICATION_ADAPTER.to_owned(),
        assurance: 1,
        issued_at: 0,
        expires_at: u64::MAX,
        registry_binding: hash(3),
        operation_nonce: [7; 32],
    };
    let signed = adapter_key()?.sign_authenticated_principal(record)?;
    Ok(verify_authenticated_principal_evidence_v1(
        &policy()?,
        signed,
    )?)
}

fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

/// One host-signed FAC1 around a POC1 or FCC1 whose fields after the
/// Principal digest are `tail`, under operation ID `[operation; 32]`.
fn command<S: ForkAdmissionAuthorityBootstrapPortV1>(
    store: &S,
    session: &ForkAdmissionAuthoritySessionV1,
    kind: &str,
    operation: u8,
    tail: Vec<Value>,
) -> Fallible<ForkAdmissionHostCommandV1> {
    let verified = evidence()?;
    let principal = principal_digest_v1(&verified.evidence().record().principal)?;
    let store_id = store.fork_admission_host_record()?.store_id();
    let mut fields = vec![
        Value::Text(kind.to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(store_id.as_bytes().to_vec()),
        Value::Bytes(session.identity().as_bytes().to_vec()),
        Value::Bytes(vec![operation; 32]),
        Value::Bytes(verified.evidence().digest()?.as_bytes().to_vec()),
        Value::Bytes(principal.as_bytes().to_vec()),
    ];
    fields.extend(tail);
    let inner = encode(&Value::Array(fields))?;
    let signature = host_key()?.sign_command(&inner, &verified)?;
    let envelope = encode(&Value::Array(vec![
        Value::Text("FAC1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(inner),
        Value::Bytes(verified.evidence().to_canonical_cbor()?),
        Value::Bytes(signature.as_bytes().to_vec()),
    ]))?;
    Ok(ForkAdmissionHostCommandV1::from_canonical_cbor(&envelope)?)
}

fn route() -> Fallible<ForkEventSourceDescriptorV1> {
    Ok(ForkEventSourceDescriptorV1::new(
        "classified.route.v1",
        hash(0x45),
    )?)
}

/// The fixture classifier's one external route.
///
/// # Errors
/// Returns the descriptor construction error.
pub fn external_source() -> Fallible<ForkAppendSourceIdentityV1> {
    Ok(ForkAppendSourceIdentityV1::ExternalInput {
        adapter_identifier: "classified.route.adapter".to_owned(),
        source: route()?,
    })
}

/// The `FCS1` of the fixture registrar: one external route, no intervention.
///
/// # Errors
/// Returns the record construction error.
pub fn classifier_source() -> Fallible<ForkClassifierSourceV1> {
    Ok(ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
        room_revision_descriptor_hash: DESCRIPTOR,
        registrar_identifier: REGISTRAR.to_owned(),
        routes: vec![ForkExternalInputRouteV1::new(route()?, false)],
    })?)
}

/// One store's live Fork admission session and its one permit issuer.
pub struct Authority {
    pub session: ForkAdmissionAuthoritySessionV1,
    pub issuer: ForkEventPermitIssuerV1,
}

impl Authority {
    /// Initialize the store's Fork admission authority, open its session, and
    /// bind the fixture Principal to an Owner.
    ///
    /// # Errors
    /// Returns the store or signing error.
    pub fn open<S: Host>(store: &mut S) -> Fallible<Self> {
        let host = host_key()?;
        let key = PublicKey::from_bytes(host.public_key());
        let initialize = store.begin_fork_admission_initialize(key, policy()?.digest()?)?;
        let signature = host.sign_initialize(&initialize.to_canonical_cbor()?)?;
        store.finalize_fork_admission_initialize(&initialize, &signature)?;
        let authority = Self::reopen(store)?;
        let owner = vec![Value::Text(OWNER.to_owned())];
        let poc1 = command(store, &authority.session, "POC1", 0xa1, owner)?;
        store.execute_fork_admission_command(&authority.session, &policy()?, &poc1)?;
        Ok(authority)
    }

    /// Open a new session of an initialized store and take its issuer. The new
    /// session ends every earlier one, and with it every permit it issued.
    ///
    /// # Errors
    /// Returns the store or signing error.
    pub fn reopen<S: ForkAdmissionAuthorityBootstrapPortV1>(store: &mut S) -> Fallible<Self> {
        let host = host_key()?;
        let key = PublicKey::from_bytes(host.public_key());
        let open = store.begin_fork_admission_open(key, policy()?.digest()?)?;
        let signature = host.sign_open(&open.to_canonical_cbor()?)?;
        let mut session = store.finalize_fork_admission_open(&open, &signature)?;
        let issuer = session
            .take_event_permit_issuer()
            .ok_or("a new session yields its issuer")?;
        Ok(Self { session, issuer })
    }

    /// Create a factual parent with two Events, admit a local classified Fork
    /// at its head under FCC1 operation `[seed; 32]`, register the fixture
    /// classifier, and publish the Fork's counterfactual facts.
    ///
    /// # Errors
    /// Returns the store, signing, or authority error.
    pub fn admit<S: Host>(&self, store: &mut S, seed: u8) -> Fallible<TimelineId> {
        let fork = self.admit_unregistered(store, seed)?;
        let registrar = store.issue_classifier_registrar_permit(
            &self.issuer,
            &self.session,
            fork,
            classifier_source()?,
        )?;
        store.register_classifier(&self.session, &registrar, hash(seed ^ 0x80), fork)?;
        store.publish_counterfactual_facts(fork, facts())?;
        Ok(fork)
    }

    /// Create a factual parent with two Events and admit a local Fork at its
    /// head under FCC1 operation `[seed; 32]`, with no classifier and no facts.
    ///
    /// # Errors
    /// Returns the store, signing, or authority error.
    pub fn admit_unregistered<S: Host>(&self, store: &mut S, seed: u8) -> Fallible<TimelineId> {
        let parent = store.create_timeline("classified-parent")?.id();
        store.append(parent, &[draft(1, "factual"), draft(2, "factual")])?;
        let fork_fields = vec![
            Value::Bytes(parent.inner().to_bytes().to_vec()),
            Value::Integer(PARENT_CUT.into()),
            Value::Integer(PARENT_CUT.into()),
            Value::Bytes(DESCRIPTOR.as_bytes().to_vec()),
            Value::Bytes(vec![9; 32]),
            Value::Integer(1.into()),
            Value::Text(format!("classified-{seed}")),
        ];
        let fcc1 = command(store, &self.session, "FCC1", seed, fork_fields)?;
        let ForkAdmissionOperationResultV1::Fork(receipt) =
            store.execute_fork_admission_command(&self.session, &policy()?, &fcc1)?
        else {
            return Err("FCC1 did not admit a Fork".into());
        };
        Ok(receipt.child_id)
    }

    /// Issue a host-internal append permit for `fork`.
    ///
    /// # Errors
    /// Returns the issuance error.
    pub fn host_permit<S: Host>(
        &self,
        store: &S,
        fork: TimelineId,
    ) -> Fallible<ForkAppendSourcePermitV1> {
        self.permit(store, fork, ForkAppendSourceIdentityV1::HostInternal)
    }

    /// Activate the fixture's external route and issue an append permit for it.
    ///
    /// # Errors
    /// Returns the issuance error.
    pub fn external_permit<S: Host>(
        &mut self,
        store: &S,
        fork: TimelineId,
    ) -> Fallible<ForkAppendSourcePermitV1> {
        let source = external_source()?;
        self.issuer.trust_external_source(source.clone());
        self.permit(store, fork, source)
    }

    fn permit<S: Host>(
        &self,
        store: &S,
        fork: TimelineId,
        source: ForkAppendSourceIdentityV1,
    ) -> Fallible<ForkAppendSourcePermitV1> {
        let selected = classifier_source()?;
        Ok(store.issue_append_source_permit(
            &self.issuer,
            &self.session,
            fork,
            &selected,
            source,
        )?)
    }

    /// Lend the live session and `permit` for one classified call.
    #[must_use]
    pub const fn lend<'a>(
        &'a self,
        permit: &'a ForkAppendSourcePermitV1,
    ) -> ClassifiedTickAuthorityV1<'a> {
        ClassifiedTickAuthorityV1::new(&self.session, permit)
    }
}

/// The counterfactual facts every fixture Fork publishes.
#[must_use]
pub const fn facts() -> CounterfactualFactsV1 {
    CounterfactualFactsV1 {
        plan_digest: hash(5),
        dependency_graph_digest: hash(3),
        trust_epoch: 6,
        revocation_epoch: 7,
        erasure_epoch: 8,
    }
}

/// One draft of Event type `kind` whose payload is the one byte `value`.
#[must_use]
pub fn draft(value: u8, kind: &str) -> EventDraft {
    EventDraft::new(
        EntityId::from_ulid(Ulid::from(9_u128)),
        Kind::new(kind),
        CanonicalBytes::from_vec(vec![value]),
    )
}

/// One validated draft batch.
///
/// # Errors
/// Returns the batch contract error.
pub fn batch(drafts: Vec<EventDraft>) -> Fallible<PipelineDraftBatchV1> {
    Ok(PipelineDraftBatchV1::try_new(drafts)?)
}

/// A provisional record at `tick` of one node of `owner` whose artifact
/// digest is `hash(digest)`.
///
/// # Errors
/// Returns the record contract error.
pub fn node_record(tick: u64, owner: &str, digest: u8) -> Fallible<TickDependencyRecordV1> {
    let coordinate =
        DependencyNodeCoordinateV1::try_new(tick, 0, owner.to_owned(), 0, 7, hash(digest))?;
    let node = DependencyNodeRecordV1::try_new(
        coordinate,
        RecordedDependencyClassV1::EndogenousRecomputed,
        RecordedNodeOriginV1::Provisional,
        Vec::new(),
        hash(99),
    )?;
    record(tick, RecordedNodeOriginV1::Provisional, vec![node])
}

/// An empty record at `tick` of `origin`.
///
/// # Errors
/// Returns the record contract error.
pub fn empty_record(tick: u64, origin: RecordedNodeOriginV1) -> Fallible<TickDependencyRecordV1> {
    record(tick, origin, Vec::new())
}

fn record(
    tick: u64,
    origin: RecordedNodeOriginV1,
    nodes: Vec<DependencyNodeRecordV1>,
) -> Fallible<TickDependencyRecordV1> {
    Ok(TickDependencyRecordV1::try_new(
        tick,
        origin,
        nodes,
        Vec::new(),
    )?)
}

/// One invalidation request; every field defaults to a fresh fixture Fork.
pub struct Spec {
    pub fork: TimelineId,
    pub head: u64,
    pub prior: u64,
    pub first_tick: u64,
    pub drafts: Vec<EventDraft>,
}

impl Spec {
    /// The default request: two ordinary drafts at the Fork's own basis.
    #[must_use]
    pub fn new(fork: TimelineId) -> Self {
        Self {
            fork,
            head: PARENT_CUT,
            prior: 0,
            first_tick: FIRST_TICK,
            drafts: vec![draft(7, TICK_KIND), draft(8, TICK_KIND)],
        }
    }

    /// The validated invalidation command.
    ///
    /// # Errors
    /// Returns the artifact, batch, or command contract error.
    pub fn command(&self) -> Fallible<CounterfactualInvalidationCommandV1> {
        let facts = facts();
        let frontier_fields = [
            id_field([1; 16]),
            hash_field(facts.plan_digest),
            hash_field(hash(2)),
            hash_field(facts.dependency_graph_digest),
            vec![0x01],
        ]
        .concat();
        let frontier_bytes = frontier_frame(&frontier_fields, 0);
        let frontier = RecomputationFrontierBytesV1::try_from_canonical(frontier_bytes)?;
        let invalidation_fields = [
            id_field([1; 16]),
            hash_field(frontier.plan_digest()),
            id_field(self.fork.inner().to_bytes()),
            uint(self.prior),
            uint(self.prior + 1),
            hash_field(frontier.digest()),
            invalidation_middle(),
            // Commit coordinate: the Fork, its expected head, the first Tick.
            vec![0x83],
            id_field(self.fork.inner().to_bytes()),
            uint(self.head),
            uint(self.first_tick),
        ]
        .concat();
        let invalidation_bytes = invalidation_frame(&invalidation_fields, 0);
        let invalidation = SuffixInvalidationBytesV1::try_from_canonical(invalidation_bytes)?;
        Ok(CounterfactualInvalidationCommandV1::try_new(
            CounterfactualInvalidationInputV1 {
                fork: self.fork,
                fork_logical_head: Seq::from_u64(self.head),
                trust_epoch: facts.trust_epoch,
                revocation_epoch: facts.revocation_epoch,
                erasure_epoch: facts.erasure_epoch,
                frontier,
                invalidation,
                invalid_artifacts: vec![hash(10), hash(11)],
                evictions: vec![hash(12)],
                first_tick: self.first_tick,
                first_tick_drafts: batch(self.drafts.clone())?,
            },
        )?)
    }
}
