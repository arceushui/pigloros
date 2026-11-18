use pos_core::{
    CanonicalBytes, EntityId, ErasureHostErrorV1, ErasureProtectedOperationV1, EventDraft,
    EventReadBounds, Kind, SeqRange,
};
use pos_runtime::ErasureExecutionHostV1;
use pos_store::StoreConfig;
use std::error::Error;

fn assert_hosted_store_parity(config: StoreConfig) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut host = ErasureExecutionHostV1::open_verified_empty(
        config,
        pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
    )?;
    let (timeline, event) = {
        let mut commands = host.command_sender()?;
        let timeline = commands.create_timeline("public-host-parity")?;
        let draft = EventDraft::new(
            EntityId::new(),
            Kind::new("public.host.parity"),
            CanonicalBytes::from_static(b"payload"),
        );
        let mut fenced_append = Err(ErasureHostErrorV1::RecoveryUnavailable);
        let mut effect = |commands: &mut pos_runtime::ErasureCommandSenderV1<'_>| {
            fenced_append = commands.timeline(timeline.id()).and_then(|metadata| {
                metadata
                    .ok_or(ErasureHostErrorV1::AdapterFailure)
                    .and_then(|_| commands.append(timeline.id(), std::slice::from_ref(&draft)))
            });
        };
        commands.with_protected_effect_fence(
            timeline.id(),
            ErasureProtectedOperationV1::ProposedAction,
            &mut effect,
        )?;
        let mut events = fenced_append?;
        let event = events
            .pop()
            .ok_or_else(|| std::io::Error::other("host append returned no committed event"))?;
        (timeline, event)
    };
    let mut reads = host.read_sender()?;
    assert_eq!(
        reads.read_bounded(
            timeline.id(),
            SeqRange::all(),
            EventReadBounds::new(8, 32, 4, 4),
        )?,
        vec![event.clone()]
    );
    assert_eq!(reads.event_by_id(timeline.id(), event.id)?, Some(event));
    Ok(())
}

#[test]
fn memory_store_is_contained_by_the_public_host_api() -> Result<(), Box<dyn Error + Send + Sync>> {
    assert_hosted_store_parity(StoreConfig::Memory)
}

#[test]
fn sqlite_store_is_contained_by_the_public_host_api() -> Result<(), Box<dyn Error + Send + Sync>> {
    assert_hosted_store_parity(StoreConfig::SqliteInMemory)
}

#[test]
fn command_effect_panic_poisons_the_public_host() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut host = ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Memory,
        pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
    )?;
    let timeline = host
        .command_sender()?
        .create_timeline("command-effect-panic")?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        host.command_sender().and_then(|mut commands| {
            commands.with_protected_effect_fence(
                timeline.id(),
                ErasureProtectedOperationV1::ProposedAction,
                &mut |_| std::panic::resume_unwind(Box::new("injected command effect panic")),
            )
        })
    }));
    assert!(result.is_err());
    assert_eq!(host.status(), pos_runtime::ErasureHostStatusV1::Poisoned);
    // A host that is not ready builds no authority view.
    assert_eq!(
        host.authority_view().err(),
        Some(pos_core::ErasureHostErrorV1::RecoveryUnavailable)
    );
    Ok(())
}

/// A host-owned root Timeline opens once under its well-known identity: the
/// first open creates it, a later open returns the recorded Timeline
/// unchanged, on both adapters.
#[test]
fn a_root_timeline_opens_once_under_its_identity() -> Result<(), Box<dyn Error + Send + Sync>> {
    for config in [StoreConfig::Memory, StoreConfig::SqliteInMemory] {
        let mut host = ErasureExecutionHostV1::open_verified_empty(
            config,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )?;
        let id = pos_core::TimelineId::new();
        let mut commands = host.command_sender()?;
        assert!(!commands.records_timeline(id)?);
        let opened = commands.open_root_timeline(id, "host-owned")?;
        assert!(commands.records_timeline(id)?);
        assert!(!commands.records_timeline(pos_core::TimelineId::new())?);
        assert_eq!(opened.id(), id);
        assert_eq!(opened.meta.name.as_deref(), Some("host-owned"));
        assert!(opened.meta.fork_point.is_none());
        let reopened = commands.open_root_timeline(id, "renamed")?;
        assert_eq!(reopened, opened);
        assert_eq!(commands.timeline(id)?, Some(opened));
    }
    Ok(())
}

/// ADR-136 §1: a root created for an owner records that owner at
/// creation, and an unowned root records none, on both adapters.
#[test]
fn an_owned_root_records_its_owner_at_creation() -> Result<(), Box<dyn Error + Send + Sync>> {
    for config in [StoreConfig::Memory, StoreConfig::SqliteInMemory] {
        let mut host = ErasureExecutionHostV1::open_verified_empty(
            config,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )?;
        let owner = EntityId::new();
        let mut commands = host.command_sender()?;
        let owned = commands.create_owned_timeline("owned-root", owner)?;
        let unowned = commands.create_timeline("unowned-root")?;
        assert_eq!(owned.meta.owner, Some(owner));
        assert_eq!(owned.meta.name.as_deref(), Some("owned-root"));
        assert!(owned.meta.fork_point.is_none());
        assert_eq!(unowned.meta.owner, None);
        assert!(commands.records_timeline(owned.id())?);
        drop(commands);
        let mut reads = host.read_sender()?;
        assert_eq!(reads.timeline(owned.id())?, Some(owned));
        assert_eq!(reads.timeline(unowned.id())?, Some(unowned));
    }
    Ok(())
}

/// ADR-136 §4a: host-owned roots are outside a client root count, which
/// still stops after `maximum + 1` client roots; an identity the store
/// does not record changes nothing.
#[test]
fn a_client_root_count_leaves_out_recorded_host_roots() -> Result<(), Box<dyn Error + Send + Sync>>
{
    for config in [StoreConfig::Memory, StoreConfig::SqliteInMemory] {
        let mut host = ErasureExecutionHostV1::open_verified_empty(
            config,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )?;
        let consent = pos_core::TimelineId::new();
        let erasure_host = pos_core::TimelineId::new();
        let absent = pos_core::TimelineId::new();
        let host_roots = [consent, erasure_host, absent];
        {
            let mut commands = host.command_sender()?;
            commands.open_root_timeline(consent, "consent")?;
            commands.open_root_timeline(erasure_host, "erasure-host")?;
        }
        // Every recorded host root is a visible root the plain count sees,
        // so leaving it out never lets the client count drop below the
        // client roots.
        {
            let mut reads = host.read_sender()?;
            assert_eq!(reads.root_timeline_count_bounded(64)?, 2);
            assert_eq!(
                reads.client_root_timeline_count_bounded(64, &host_roots)?,
                0
            );
        }
        {
            let mut commands = host.command_sender()?;
            commands.create_timeline("client-1")?;
            commands.create_timeline("client-2")?;
        }
        let mut reads = host.read_sender()?;
        assert_eq!(reads.root_timeline_count_bounded(64)?, 4);
        assert_eq!(
            reads.client_root_timeline_count_bounded(64, &host_roots)?,
            2
        );
        assert_eq!(reads.client_root_timeline_count_bounded(64, &[])?, 4);
        // The bound still stops after `maximum + 1` client roots.
        assert_eq!(reads.client_root_timeline_count_bounded(0, &host_roots)?, 1);
        assert_eq!(reads.client_root_timeline_count_bounded(1, &host_roots)?, 2);
    }
    Ok(())
}

/// The Erasure Host Timeline read is `None` before the store records an
/// erasure store identity and the ELHT1 derivation of it afterwards.
#[test]
fn the_erasure_host_timeline_follows_the_store_identity() -> Result<(), Box<dyn Error + Send + Sync>>
{
    for config in [StoreConfig::Memory, StoreConfig::SqliteInMemory] {
        let mut host = ErasureExecutionHostV1::open_verified_empty(
            config,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )?;
        assert_eq!(host.read_sender()?.local_erasure_host_timeline()?, None);
    }
    let directory = tempfile::tempdir()?;
    let path = directory
        .path()
        .join("identity.db")
        .to_str()
        .ok_or("temporary path is not UTF-8")?
        .to_owned();
    let identity = pos_core::Hash::from_bytes([0x5a; 32]);
    pos_core::ErasureInventoryPersistencePortV1::init_erasure_store_identity(
        &mut pos_store::sqlite::SqliteStore::open(&path)?,
        identity,
    )?;
    let mut host = ErasureExecutionHostV1::open_with_authority(
        StoreConfig::Sqlite { path },
        &pos_runtime::ErasureCoordinatorCompositionV1::closed(),
        pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
    )?;
    assert_eq!(
        host.read_sender()?.local_erasure_host_timeline()?,
        Some(pos_core::local_erasure_host_timeline_v1(
            pos_core::ErasureReferenceV1::from_digest([0x5a; 32])
        )?)
    );
    Ok(())
}
