/// Private CLI compatibility adapter over generation-bound host senders.
///
/// The concrete `MemoryStore` or `SQLite` adapter and gate publication
/// authority never escape `ErasureExecutionHostV1`.
struct HostedCliStore {
    host: std::sync::Mutex<pos_runtime::ErasureExecutionHostV1>,
}

impl HostedCliStore {
    /// Open `config` under the erasure authority the shared loader composes
    /// from this process's deployment trust source.
    fn open(
        config: pos_store::StoreConfig,
    ) -> Result<Self, pos_local_erasure_loader::LocalErasureOpenErrorV1> {
        Self::open_with_trust(
            config,
            &pos_local_erasure_loader::LocalErasureTrustSourceV1::from_environment(),
        )
    }

    /// Open `config` under the erasure authority composed from `source`:
    /// closed for a store without an erasure store identity, else the Local
    /// erasure authority with no executor, or a typed refusal.
    fn open_with_trust(
        config: pos_store::StoreConfig,
        source: &pos_local_erasure_loader::LocalErasureTrustSourceV1,
    ) -> Result<Self, pos_local_erasure_loader::LocalErasureOpenErrorV1> {
        pos_local_erasure_loader::LocalErasureRecoveryV1::open_host(config, source).map(|host| {
            Self {
                host: std::sync::Mutex::new(host),
            }
        })
    }

    fn with_host<T>(
        &self,
        operation: impl FnOnce(
            &mut pos_runtime::ErasureExecutionHostV1,
        ) -> Result<T, pos_core::ErasureHostErrorV1>,
    ) -> Result<T, pos_core::CoreError> {
        self.host
            .lock()
            .map_err(|_| pos_core::CoreError::ErasureContainmentUnavailable)
            .and_then(|mut host| operation(&mut host).map_err(hosted_cli_store_error))
    }
}

impl pos_core::store::EventStore for HostedCliStore {
    fn bind_erasure_gate(
        &mut self,
        _gate: std::sync::Arc<pos_core::ErasureContainmentGateV1>,
    ) -> Result<(), pos_core::CoreError> {
        // The host owns the concrete gate; this adapter exposes only its read-only view.
        Err(pos_core::CoreError::ErasureContainmentUnavailable)
    }

    fn create_timeline(&mut self, name: &str) -> Result<pos_core::Timeline, pos_core::CoreError> {
        self.with_host(|host| {
            host.command_sender()
                .and_then(|mut sender| sender.create_timeline(name))
        })
    }

    fn append(
        &mut self,
        timeline: pos_core::TimelineId,
        drafts: &[pos_core::EventDraft],
    ) -> Result<Vec<pos_core::Event>, pos_core::CoreError> {
        self.with_host(|host| {
            host.command_sender()
                .and_then(|mut sender| sender.append(timeline, drafts))
        })
    }

    fn read(
        &self,
        timeline: pos_core::TimelineId,
        range: pos_core::store::SeqRange,
    ) -> Result<Vec<pos_core::Event>, pos_core::CoreError> {
        self.read_bounded(
            timeline,
            range,
            pos_core::store::EventReadBounds::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX),
        )
    }

    fn read_bounded(
        &self,
        timeline: pos_core::TimelineId,
        range: pos_core::store::SeqRange,
        bounds: pos_core::store::EventReadBounds,
    ) -> Result<Vec<pos_core::Event>, pos_core::CoreError> {
        self.with_host(|host| {
            host.read_sender()
                .and_then(|mut sender| sender.read_bounded(timeline, range, bounds))
        })
    }

    fn fork(
        &mut self,
        parent: pos_core::TimelineId,
        at_seq: pos_core::Seq,
        name: &str,
    ) -> Result<pos_core::Timeline, pos_core::CoreError> {
        self.with_host(|host| {
            host.command_sender()
                .and_then(|mut sender| sender.fork_timeline(parent, at_seq, name))
        })
    }

    fn list_timelines(&self) -> Result<Vec<pos_core::Timeline>, pos_core::CoreError> {
        self.with_host(|host| host.read_sender().and_then(|mut sender| sender.timelines()))
    }

    fn root_timeline_count_bounded(&self, maximum: usize) -> Result<usize, pos_core::CoreError> {
        self.with_host(|host| {
            host.read_sender()
                .and_then(|mut sender| sender.root_timeline_count_bounded(maximum))
        })
    }

    fn get_timeline(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<Option<pos_core::Timeline>, pos_core::CoreError> {
        self.with_host(|host| {
            host.read_sender()
                .and_then(|mut sender| sender.timeline(timeline))
        })
    }

    fn logical_head(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<pos_core::Seq, pos_core::CoreError> {
        self.with_host(|host| {
            host.read_sender()
                .and_then(|mut sender| sender.logical_head(timeline))
        })
    }
}

/// The store error of a refused open: a refused composition is a storage
/// error naming its typed refusal.
fn hosted_cli_open_error(
    error: pos_local_erasure_loader::LocalErasureOpenErrorV1,
) -> pos_core::CoreError {
    match error {
        pos_local_erasure_loader::LocalErasureOpenErrorV1::Load(error) => {
            pos_core::CoreError::Storage(error.to_string())
        }
        pos_local_erasure_loader::LocalErasureOpenErrorV1::Host(error) => {
            hosted_cli_store_error(error)
        }
    }
}

fn hosted_cli_store_error(error: pos_core::ErasureHostErrorV1) -> pos_core::CoreError {
    match error {
        pos_core::ErasureHostErrorV1::AccessFrozen => pos_core::CoreError::ErasureAccessFrozen,
        pos_core::ErasureHostErrorV1::RecoveryUnavailable
        | pos_core::ErasureHostErrorV1::StaleGeneration => {
            pos_core::CoreError::ErasureContainmentUnavailable
        }
        pos_core::ErasureHostErrorV1::AuthorizationDenied
        | pos_core::ErasureHostErrorV1::Conflict
        | pos_core::ErasureHostErrorV1::AdapterFailure
        | pos_core::ErasureHostErrorV1::ModeBindingStale => {
            pos_core::CoreError::Storage("erasure host rejected CLI operation".to_owned())
        }
    }
}

#[cfg(test)]
mod hosted_cli_store_tests {
    use super::*;
    use pos_core::store::EventStore;

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn sqlite_bounded_read_uses_the_host_fence() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::TempDir::new()?;
        let path = directory.path().join("cli-replay.db");
        let config = StoreConfig::Sqlite {
            path: path.to_string_lossy().into_owned(),
        };
        let mut store = HostedCliStore::open(config.clone())?;
        let timeline = store.create_timeline("cli-replay")?;
        drop(store);
        let store = HostedCliStore::open(config)?;
        assert!(store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                pos_core::store::EventReadBounds::new(8, 32, 4, 4),
            )?
            .is_empty());
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn delegates_the_cli_store_surface() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = HostedCliStore::open(StoreConfig::Memory)?;
        assert!(store
            .bind_erasure_gate(std::sync::Arc::new(
                pos_core::ErasureContainmentGateV1::new_test_open()
            ))
            .is_err());

        let parent = store.create_timeline("cli-parent")?;
        let draft = pos_core::EventDraft::new(
            pos_core::EntityId::new(),
            pos_core::Kind::new("cli.host.test"),
            pos_core::CanonicalBytes::from_static(b"payload"),
        );
        assert_eq!(store.append(parent.id(), &[draft])?.len(), 1);
        assert_eq!(store.read(parent.id(), SeqRange::all())?.len(), 1);
        assert_eq!(
            store
                .read_bounded(
                    parent.id(),
                    SeqRange::all(),
                    pos_core::store::EventReadBounds::new(16, 32, 4, 4),
                )?
                .len(),
            1
        );
        assert_eq!(store.logical_head(parent.id())?, Seq::from_u64(1));
        assert_eq!(store.list_timelines()?.len(), 1);
        assert_eq!(store.root_timeline_count_bounded(1)?, 1);
        assert_eq!(
            store
                .get_timeline(parent.id())?
                .map(|timeline| timeline.id()),
            Some(parent.id())
        );
        let child = store.fork(parent.id(), Seq::from_u64(1), "cli-child")?;
        assert_eq!(child.meta.fork_point, Some((parent.id(), Seq::from_u64(1))));
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn poisoned_host_and_error_mapping_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let store = HostedCliStore::open(StoreConfig::Memory)?;
        drop(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || {
                let _guard = store
                    .host
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                std::panic::resume_unwind(Box::new("poison hosted CLI store"));
            },
        )));
        assert!(matches!(
            store.list_timelines(),
            Err(pos_core::CoreError::ErasureContainmentUnavailable)
        ));
        assert!(matches!(
            hosted_cli_store_error(pos_core::ErasureHostErrorV1::AccessFrozen),
            pos_core::CoreError::ErasureAccessFrozen
        ));
        for error in [
            pos_core::ErasureHostErrorV1::RecoveryUnavailable,
            pos_core::ErasureHostErrorV1::StaleGeneration,
        ] {
            assert!(matches!(
                hosted_cli_store_error(error),
                pos_core::CoreError::ErasureContainmentUnavailable
            ));
        }
        for error in [
            pos_core::ErasureHostErrorV1::AuthorizationDenied,
            pos_core::ErasureHostErrorV1::Conflict,
            pos_core::ErasureHostErrorV1::AdapterFailure,
            pos_core::ErasureHostErrorV1::ModeBindingStale,
        ] {
            assert!(matches!(
                hosted_cli_store_error(error),
                pos_core::CoreError::Storage(_)
            ));
        }
        Ok(())
    }
}

/// ADR-136 acceptance test 11 for the CLI root (#1450): its store open
/// composes the closed authority for a store without an erasure store
/// identity, recovers a store that holds a Local erasure request from valid
/// credentials, and refuses missing or invalid ones.
#[cfg(target_os = "linux")]
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod keyless_erasure_tests {
    use pos_core::store::EventStore;
    use pos_local_erasure_loader::{
        LocalErasureLoadErrorV1, LocalErasureOpenErrorV1, LocalErasureTrustSourceV1,
    };
    use pos_runtime::LocalErasureCompositionErrorV1;

    use super::{hosted_cli_open_error, HostedCliStore, StoreConfig};
    use crate::keyless_store::KeylessStore;
    use crate::signing::TestResult;

    #[test]
    fn a_store_without_an_identity_opens_and_works() -> TestResult {
        let directory = tempfile::tempdir()?;
        let config = StoreConfig::Sqlite {
            path: directory
                .path()
                .join("cli.db")
                .to_str()
                .ok_or("temporary path is not UTF-8")?
                .to_owned(),
        };
        let source = LocalErasureTrustSourceV1 {
            credential_directory: None,
            trust_state: directory.path().join("absent-trust.db"),
        };
        let mut store = HostedCliStore::open_with_trust(config.clone(), &source)?;
        let timeline = store.create_timeline("cli")?;
        drop(store);
        let reopened = HostedCliStore::open_with_trust(config, &source)?;
        assert_eq!(
            reopened
                .get_timeline(timeline.id())?
                .map(|found| found.id()),
            Some(timeline.id())
        );
        Ok(())
    }

    #[test]
    fn valid_credentials_recover_a_store_that_holds_a_request() -> TestResult {
        let store = KeylessStore::new()?;
        let source = store.valid_source("valid")?;
        let recovered = HostedCliStore::open_with_trust(store.config(), &source)?;
        assert!(!recovered.list_timelines()?.is_empty());
        Ok(())
    }

    #[test]
    fn missing_credentials_are_a_typed_refusal() -> TestResult {
        let store = KeylessStore::new()?;
        let refusal = HostedCliStore::open_with_trust(store.config(), &store.missing_source())
            .err()
            .ok_or("an identified store without credentials is refused")?;
        assert_eq!(
            refusal,
            LocalErasureOpenErrorV1::Load(LocalErasureLoadErrorV1::CredentialsMissing)
        );
        assert!(matches!(
            hosted_cli_open_error(refusal),
            pos_core::CoreError::Storage(message)
                if message == LocalErasureLoadErrorV1::CredentialsMissing.to_string()
        ));
        assert!(matches!(
            hosted_cli_open_error(LocalErasureOpenErrorV1::Host(
                pos_core::ErasureHostErrorV1::AccessFrozen
            )),
            pos_core::CoreError::ErasureAccessFrozen
        ));
        Ok(())
    }

    #[test]
    fn an_invalid_bundle_or_signature_is_a_typed_refusal() -> TestResult {
        let store = KeylessStore::new()?;
        for source in [
            store.invalid_bundle_source("invalid-bundle")?,
            store.forged_signature_source("forged-signature")?,
        ] {
            assert_eq!(
                HostedCliStore::open_with_trust(store.config(), &source).err(),
                Some(LocalErasureOpenErrorV1::Load(
                    LocalErasureLoadErrorV1::Composition(
                        LocalErasureCompositionErrorV1::BundleInvalid
                    )
                ))
            );
        }
        Ok(())
    }
}
