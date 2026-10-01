//! Typed loaded-unit observations, not proof of namespace or resource absence.

use std::collections::BTreeSet;

use super::{
    ManagerProxy, OwnedObjectPath, SystemdTransientUnitTransport,
    SystemdTransientUnitTransportError, TransientServiceUnitName, UNIT_PREFIX, UNIT_SUFFIX,
};

type InventoryResult<T> = Result<T, SystemdTransientUnitTransportError>;
// Exact generated ListUnitsByPatterns reply element, a(ssssssouso).
type UnitRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    OwnedObjectPath,
    u32,
    String,
    OwnedObjectPath,
);

/// One manager-reported attempt unit with a canonical name and matching lookup.
///
/// All states, including inactive and failed, are observed. This is readback,
/// not proof of provider ownership, cgroup identity or emptiness. Listing may
/// omit units hidden by host access policy, so an empty result is not cleanup
/// evidence and must never reopen admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemdAttemptUnitObservation {
    unit_name: TransientServiceUnitName,
    attempt_id: [u8; 16],
    row: UnitRow,
}

impl SystemdAttemptUnitObservation {
    /// Canonical service identity independently resolved through `GetUnit`.
    #[must_use]
    pub const fn unit_name(&self) -> &TransientServiceUnitName {
        &self.unit_name
    }

    /// Nonzero identity decoded from the exact canonical service name.
    #[must_use]
    pub const fn attempt_id(&self) -> [u8; 16] {
        self.attempt_id
    }

    /// Human-readable manager description, never ownership evidence.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.row.1
    }

    /// Reported load state; not interpreted as resource absence.
    #[must_use]
    pub fn load_state(&self) -> &str {
        &self.row.2
    }

    /// Reported active state, including inactive or failed units.
    #[must_use]
    pub fn active_state(&self) -> &str {
        &self.row.3
    }

    /// Reported service-specific substate.
    #[must_use]
    pub fn sub_state(&self) -> &str {
        &self.row.4
    }

    /// Manager-reported following unit, if any, as an uninterpreted claim.
    #[must_use]
    pub fn following(&self) -> &str {
        &self.row.5
    }

    /// Object path which matched the manager's independent name lookup.
    #[must_use]
    pub fn unit_path(&self) -> &str {
        self.row.6.as_str()
    }

    /// Manager-reported job ID; zero denotes no queued job in the observation.
    #[must_use]
    pub const fn job_id(&self) -> u32 {
        self.row.7
    }

    /// Manager-reported job type, not a command-completion result.
    #[must_use]
    pub fn job_type(&self) -> &str {
        &self.row.8
    }

    /// Manager-reported job object path (unit path when no job is queued).
    #[must_use]
    pub fn job_path(&self) -> &str {
        self.row.9.as_str()
    }
}

impl SystemdTransientUnitTransport {
    /// Observe loaded units in the complete `pigloros-attempt-` name prefix.
    ///
    /// Queries without a state filter, validates canonical nonzero `AttemptId`
    /// service names, rejects duplicate names/paths, and resolves every name
    /// back to its listed object. Results are sorted by name. A caller must
    /// separately bound the operation and establish complete host visibility,
    /// registry ownership, kernel resource identity and cleanup evidence.
    ///
    /// # Errors
    /// Rejects proxy, listing or lookup failures and malformed, duplicate or
    /// changed identities. A disappeared unit requires a fresh observation;
    /// it is never converted into absence evidence.
    pub async fn observe_attempt_units(
        &self,
    ) -> InventoryResult<Vec<SystemdAttemptUnitObservation>> {
        observe_with_proxy(ManagerProxy::new(&self.connection).await).await
    }
}

async fn observe_with_proxy(
    proxy: Result<ManagerProxy<'_>, zbus::Error>,
) -> InventoryResult<Vec<SystemdAttemptUnitObservation>> {
    let proxy = proxy.map_err(SystemdTransientUnitTransportError::Proxy)?;
    let rows = proxy
        .list_units_by_patterns(Vec::new(), vec![format!("{UNIT_PREFIX}*")])
        .await
        .map_err(SystemdTransientUnitTransportError::InventoryCall)?;
    let mut names = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut observations = Vec::with_capacity(rows.len());
    for row in rows {
        let (unit_name, attempt_id) = parse_name(&row.0)?;
        if !names.insert(row.0.clone()) || !paths.insert(row.6.as_str().to_owned()) {
            return Err(SystemdTransientUnitTransportError::InventoryIdentityMismatch);
        }
        let resolved = proxy
            .get_unit(row.0.clone())
            .await
            .map_err(SystemdTransientUnitTransportError::UnitLookup)?;
        if resolved != row.6 {
            return Err(SystemdTransientUnitTransportError::InventoryIdentityMismatch);
        }
        observations.push(SystemdAttemptUnitObservation {
            unit_name,
            attempt_id,
            row,
        });
    }
    observations.sort_unstable_by(|a, b| a.unit_name.as_str().cmp(b.unit_name.as_str()));
    Ok(observations)
}

fn parse_name(name: &str) -> InventoryResult<(TransientServiceUnitName, [u8; 16])> {
    let component = name
        .strip_prefix(UNIT_PREFIX)
        .and_then(|rest| rest.strip_suffix(UNIT_SUFFIX))
        .filter(|component| component.len() == 32 && component.is_ascii())
        .ok_or(SystemdTransientUnitTransportError::InventoryIdentityMismatch)?;
    let mut id = [0; 16];
    for (index, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&component[index * 2..index * 2 + 2], 16)
            .map_err(|_| SystemdTransientUnitTransportError::InventoryIdentityMismatch)?;
    }
    let canonical = TransientServiceUnitName::from_attempt_id(id)
        .map_err(|_| SystemdTransientUnitTransportError::InventoryIdentityMismatch)?;
    if canonical.as_str() != name {
        return Err(SystemdTransientUnitTransportError::InventoryIdentityMismatch);
    }
    Ok((canonical, id))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };
    use zbus::{
        connection::{socket::channel::Channel, Builder},
        fdo, Guid,
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
    type Calls = Arc<Mutex<Vec<(Vec<String>, Vec<String>)>>>;

    #[derive(Clone, Copy)]
    enum Fault {
        None,
        List,
        Lookup,
        Substitute,
    }

    struct RecordingManager {
        rows: Vec<UnitRow>,
        calls: Calls,
        subscribed: Arc<AtomicBool>,
        fault: Fault,
    }

    #[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
    impl RecordingManager {
        fn subscribe(&self) {
            self.subscribed.store(true, Ordering::SeqCst);
        }

        fn list_units_by_patterns(
            &self,
            states: Vec<String>,
            patterns: Vec<String>,
        ) -> fdo::Result<Vec<UnitRow>> {
            self.calls
                .lock()
                .map_err(|error| fdo::Error::Failed(error.to_string()))?
                .push((states, patterns));
            if matches!(self.fault, Fault::List) {
                return Err(fdo::Error::AccessDenied("injected list failure".to_owned()));
            }
            Ok(self.rows.clone())
        }

        fn get_unit(&self, name: String) -> fdo::Result<OwnedObjectPath> {
            if matches!(self.fault, Fault::Lookup) {
                return Err(fdo::Error::UnknownObject("unit disappeared".to_owned()));
            }
            if matches!(self.fault, Fault::Substitute) {
                return OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/substitute")
                    .map_err(|error| fdo::Error::Failed(error.to_string()));
            }
            self.rows
                .iter()
                .find(|row| row.0 == name)
                .map(|row| row.6.clone())
                .ok_or_else(|| fdo::Error::UnknownObject(name))
        }
    }

    async fn transport(
        rows: Vec<UnitRow>,
        fault: Fault,
    ) -> TestResult<(SystemdTransientUnitTransport, zbus::Connection, Calls)> {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let subscribed = Arc::new(AtomicBool::new(false));
        let guid = Guid::generate();
        let (server_socket, client_socket) = Channel::pair();
        let server = Builder::authenticated_socket(server_socket, guid.clone())?
            .p2p()
            .serve_at(
                "/org/freedesktop/systemd1",
                RecordingManager {
                    rows,
                    calls: Arc::clone(&calls),
                    subscribed: Arc::clone(&subscribed),
                    fault,
                },
            )?
            .build();
        let client = Builder::authenticated_socket(client_socket, guid)?
            .p2p()
            .build();
        let (server, client) = tokio::join!(server, client);
        let server = server?;
        let transport = SystemdTransientUnitTransport::from_connection(client?).await?;
        assert!(subscribed.load(Ordering::SeqCst));
        Ok((transport, server, calls))
    }

    fn row(id: u8, state: &str) -> TestResult<UnitRow> {
        let name = TransientServiceUnitName::from_attempt_id([id; 16])?;
        let path =
            OwnedObjectPath::try_from(format!("/org/freedesktop/systemd1/unit/attempt{id}"))?;
        Ok((
            name.as_str().to_owned(),
            format!("attempt {id}"),
            "loaded".to_owned(),
            state.to_owned(),
            "dead".to_owned(),
            String::new(),
            path.clone(),
            0,
            String::new(),
            path,
        ))
    }

    #[tokio::test]
    async fn public_inventory_queries_whole_prefix_and_sorts_all_eight_states() -> TestResult {
        let states = [
            "active",
            "inactive",
            "failed",
            "activating",
            "deactivating",
            "reloading",
            "maintenance",
            "refreshing",
        ];
        let mut rows = Vec::new();
        for (id, state) in (1..=8).zip(states) {
            rows.push(row(id, state)?);
        }
        rows[0].7 = 42;
        rows[0].8 = "stop".to_owned();
        rows[0].9 = OwnedObjectPath::try_from("/org/freedesktop/systemd1/job/42")?;
        let expected = rows.clone();
        rows.reverse();
        let (transport, _server, calls) = transport(rows, Fault::None).await?;
        let observed = transport.observe_attempt_units().await?;
        assert_eq!(observed.len(), 8);
        assert_eq!(
            *calls.lock().map_err(|_| "poisoned fixture")?,
            vec![(Vec::<String>::new(), vec!["pigloros-attempt-*".to_owned()])]
        );
        for ((id, item), expected) in (1..=8).zip(&observed).zip(&expected) {
            assert_eq!(item.unit_name().as_str(), expected.0);
            assert_eq!(item.attempt_id(), [id; 16]);
            assert_eq!(item.description(), expected.1);
            assert_eq!(item.load_state(), expected.2);
            assert_eq!(item.active_state(), expected.3);
            assert_eq!(item.sub_state(), expected.4);
            assert_eq!(item.following(), expected.5);
            assert_eq!(item.unit_path(), expected.6.as_str());
            assert_eq!(item.job_id(), expected.7);
            assert_eq!(item.job_type(), expected.8);
            assert_eq!(item.job_path(), expected.9.as_str());
        }
        Ok(())
    }

    #[tokio::test]
    async fn empty_observation_is_returned_without_resource_absence_authority() -> TestResult {
        let (transport, _server, _calls) = transport(Vec::new(), Fault::None).await?;
        assert!(transport.observe_attempt_units().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn public_inventory_rejects_noncanonical_names_and_duplicate_identities() -> TestResult {
        for name in [
            "unrelated.service".to_owned(),
            "pigloros-attempt-1.service".to_owned(),
            format!("pigloros-attempt-{}.scope", "01".repeat(16)),
            format!("pigloros-attempt-{}.service", "é".repeat(16)),
            format!("pigloros-attempt-{}.service", "gh".repeat(16)),
            format!("pigloros-attempt-{}.service", "AB".repeat(16)),
            format!("pigloros-attempt-{}.service", "00".repeat(16)),
        ] {
            let mut value = row(1, "active")?;
            value.0 = name;
            let (transport, _server, _calls) = transport(vec![value], Fault::None).await?;
            assert!(matches!(
                transport.observe_attempt_units().await,
                Err(SystemdTransientUnitTransportError::InventoryIdentityMismatch)
            ));
        }
        for duplicate_name in [false, true] {
            let first = row(1, "active")?;
            let mut second = row(2, "inactive")?;
            if duplicate_name {
                second.0.clone_from(&first.0);
            } else {
                second.6.clone_from(&first.6);
            }
            let (transport, _server, _calls) = transport(vec![first, second], Fault::None).await?;
            assert!(matches!(
                transport.observe_attempt_units().await,
                Err(SystemdTransientUnitTransportError::InventoryIdentityMismatch)
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn public_inventory_propagates_list_lookup_and_substitution_failures() -> TestResult {
        for fault in [Fault::List, Fault::Lookup, Fault::Substitute] {
            let (transport, _server, _calls) = transport(vec![row(1, "active")?], fault).await?;
            let result = transport.observe_attempt_units().await;
            match fault {
                Fault::List => assert!(matches!(
                    result,
                    Err(SystemdTransientUnitTransportError::InventoryCall(_))
                )),
                Fault::Lookup => assert!(matches!(
                    result,
                    Err(SystemdTransientUnitTransportError::UnitLookup(_))
                )),
                _ => assert!(matches!(
                    result,
                    Err(SystemdTransientUnitTransportError::InventoryIdentityMismatch)
                )),
            }
        }
        assert!(matches!(
            observe_with_proxy(Err(zbus::Error::Failure(
                "injected proxy failure".to_owned()
            )))
            .await,
            Err(SystemdTransientUnitTransportError::Proxy(_))
        ));
        Ok(())
    }
}
