/// Private CLI compatibility adapter over generation-bound host senders.
///
/// The concrete `MemoryStore` or `SQLite` adapter and gate publication
/// authority never escape `ErasureExecutionHostV1`.
struct HostedCliStore {
    host: std::sync::Mutex<pos_runtime::ErasureExecutionHostV1>,
    gate: std::sync::Arc<dyn pos_core::ErasureGate>,
}

impl HostedCliStore {
    fn open(config: pos_store::StoreConfig) -> Result<Self, pos_core::ErasureHostErrorV1> {
        Self::open_with_recovery(config, None)
    }

    fn open_with_recovery(
        config: pos_store::StoreConfig,
        composition: Option<&pos_runtime::ErasureCoordinatorCompositionV1>,
    ) -> Result<Self, pos_core::ErasureHostErrorV1> {
        pos_runtime::ErasureExecutionHostV1::open_with_recovery(
            config,
            composition,
            pos_core::ERASURE_MAX_INVENTORY_REQUESTS,
        )
        .map(|host| {
            let gate = host.containment_gate();
            Self {
                host: std::sync::Mutex::new(host),
                gate,
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

    fn with_read_sender<T>(
        &self,
        operation: impl FnOnce(
            &mut pos_runtime::ErasureReadSenderV1<'_>,
        ) -> Result<T, pos_core::CoreError>,
    ) -> Result<T, pos_core::CoreError> {
        self.host
            .lock()
            .map_err(|_| pos_core::CoreError::ErasureContainmentUnavailable)
            .and_then(|mut host| {
                host.read_sender()
                    .map_err(hosted_cli_store_error)
                    .and_then(|mut sender| operation(&mut sender))
            })
    }

    fn containment_gate(&self) -> std::sync::Arc<dyn pos_core::ErasureGate> {
        std::sync::Arc::clone(&self.gate)
    }
}

impl pos_core::store::EventStore for HostedCliStore {
    fn bind_erasure_gate(
        &mut self,
        gate: std::sync::Arc<dyn pos_core::ErasureGate>,
    ) -> Result<(), pos_core::CoreError> {
        if std::sync::Arc::ptr_eq(&self.gate, &gate) {
            Ok(())
        } else {
            Err(pos_core::CoreError::ErasureContainmentUnavailable)
        }
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

fn hosted_cli_store_error(error: pos_core::ErasureHostErrorV1) -> pos_core::CoreError {
    match error {
        pos_core::ErasureHostErrorV1::AccessFrozen => pos_core::CoreError::ErasureAccessFrozen,
        pos_core::ErasureHostErrorV1::RecoveryUnavailable
        | pos_core::ErasureHostErrorV1::StaleGeneration => {
            pos_core::CoreError::ErasureContainmentUnavailable
        }
        pos_core::ErasureHostErrorV1::AuthorizationDenied
        | pos_core::ErasureHostErrorV1::Conflict
        | pos_core::ErasureHostErrorV1::AdapterFailure => {
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
    fn delegates_the_cli_store_surface() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = HostedCliStore::open(StoreConfig::Memory)?;
        let gate = std::sync::Arc::clone(&store.gate);
        store.bind_erasure_gate(gate)?;
        assert!(store
            .bind_erasure_gate(std::sync::Arc::new(
                pos_core::ErasureContainmentGateV1::new()
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
        ] {
            assert!(matches!(
                hosted_cli_store_error(error),
                pos_core::CoreError::Storage(_)
            ));
        }
        Ok(())
    }
}
