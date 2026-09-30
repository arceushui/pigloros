//! Runtime-owned closed host catalogue.
//!
//! A trusted composition root selects one reviewed [`HostCatalogueEntryV1`]
//! for its compiled [`InstalledPluginFactoryV1`] and passes a frozen
//! configuration. The runtime invokes the factory once, checks the actual
//! Plugin and approver against the entry's reviewed specification, seals the
//! product with its CFG1, EPF1, EOP1 and candidate pin links, and commits it
//! to the [`PluginRegistry`] atomically.
//!
//! Closure over factory types is enforced at runtime: an entry can be
//! selected for any factory type, and registration rejects a product whose
//! Plugin or approver type is not the one the reviewed specification names,
//! before any registry mutation. The catalogue's `compile_fail` doctest
//! proves only that entry fields are private.

use pos_core::{event::Kind, ActionApprover, Plugin, Reducer};

use super::{PendingRegistrationCallbacksV1, PluginRegistry, ReducerSlotV1, RegistrationOptions};
use crate::{
    composition::{
        DomainImplementationKindV1, PluginAvailabilityV1, PluginIsolationV1, PluginRegistrationV1,
    },
    error::RuntimeError,
    output_admission::{OutputPolicySourceV1, OutputPolicyBindingV1},
};

/// Executable profile selected by every reviewed host catalogue entry.
const CATALOGUE_PROFILE_ID_V1: &str = "deterministic-local-v1";

/// Factory compiled into one application composition root for its reviewed
/// host catalogue entry.
///
/// The runtime derives canonical CFG1 from [`Self::configuration_details`]
/// and invokes [`Self::build`] exactly once per registration, both with the
/// same frozen configuration. The factory returns only the actual Plugin and
/// callbacks: it cannot supply CFG1, EOP1, a registration pin, or any
/// registry or catalogue capability.
pub trait InstalledPluginFactoryV1 {
    /// Immutable configuration with every default resolved by the host.
    type Configuration;
    /// Actual Plugin built by this factory.
    type Plugin: Plugin;
    /// Actual action approver built by this factory.
    type Approver: ActionApprover + 'static;

    /// Deterministic details of the complete frozen configuration.
    fn configuration_details(configuration: &Self::Configuration) -> Vec<u8>;

    /// Build the actual Plugin and callbacks from the frozen configuration.
    fn build(
        configuration: &Self::Configuration,
    ) -> InstalledPluginProductV1<Self::Plugin, Self::Approver>;
}

/// Actual Plugin and callbacks built by one catalogue factory invocation.
pub struct InstalledPluginProductV1<P, A> {
    /// Actual Plugin instance.
    pub plugin: P,
    /// Reducer, present exactly when the Plugin declares one.
    pub reducer: Option<Box<dyn Reducer>>,
    /// Action approver for the reviewed action route.
    pub approver: A,
}

/// One reviewed entry of the runtime-owned closed host catalogue.
///
/// The entry fixes the reviewed output specification: accepted native Plugin
/// and approver types, source closure, declarations, and executable budget.
/// A composition root can only select [`Self::gateway`] for its compiled
/// factory; there is no constructor that accepts callbacks or a specification.
///
/// Closure over the factory is enforced at runtime, not by the type system:
/// `F` may be any [`InstalledPluginFactoryV1`], and registration rejects a
/// product whose actual Plugin or approver type is not the one the reviewed
/// specification names (`PluginMismatch` / `CallbackMismatch`) before any
/// registry mutation. The runtime cannot seal `F` at compile time, because
/// the reviewed factories live in downstream composition roots that a
/// runtime-owned sealed trait could not be implemented for.
///
/// The `compile_fail` example below proves only that the entry's fields are
/// private, so a caller cannot author its own specification; it says
/// nothing about which factory types may select an entry.
///
/// ```compile_fail
/// struct Foreign;
/// let _entry = pos_runtime::HostCatalogueEntryV1::<Foreign> {
///     spec: unimplemented!(),
///     factory: std::marker::PhantomData,
/// };
/// ```
pub struct HostCatalogueEntryV1<F> {
    pub(super) spec: OutputPolicySourceV1,
    pub(super) factory: std::marker::PhantomData<fn() -> F>,
}

impl<F: InstalledPluginFactoryV1> HostCatalogueEntryV1<F> {
    /// Select the reviewed Gateway action entry for the Gateway factory.
    ///
    /// This compiles for any factory type `F`. Only the Gateway's own
    /// factory can register successfully: registration checks the built
    /// Plugin and approver against the reviewed Gateway specification by
    /// type name and rejects any other product before mutating the registry.
    #[must_use]
    pub const fn gateway() -> Self {
        Self {
            spec: OutputPolicySourceV1::Gateway,
            factory: std::marker::PhantomData,
        }
    }
}

/// EPF1 provenance used to seal one catalogue product.
#[derive(Clone, Copy)]
pub(super) enum CatalogueEvidenceV1 {
    /// Host-verified installed profile of the selected entry.
    Installed,
    /// Draft profile and generated source for nonproduction fixtures.
    #[cfg(any(test, feature = "test-support"))]
    Generated,
}

impl CatalogueEvidenceV1 {
    /// The binding source this evidence resolves for the selected entry.
    pub(super) const fn binding_source(
        self,
        spec: OutputPolicySourceV1,
    ) -> OutputPolicySourceV1 {
        match self {
            Self::Installed => spec,
            #[cfg(any(test, feature = "test-support"))]
            Self::Generated => OutputPolicySourceV1::Generated,
        }
    }

    /// The registration a sealed bundle commits with its checked candidate
    /// pin: only installed evidence attaches the pin, fixtures never do.
    pub(super) fn registration(
        self,
        pin: crate::composition::PluginPinV1,
    ) -> Option<PluginRegistrationV1> {
        match self {
            Self::Installed => Some(PluginRegistrationV1::new(
                pin,
                PluginAvailabilityV1::Available,
            )),
            #[cfg(any(test, feature = "test-support"))]
            Self::Generated => None,
        }
    }
}

/// Runtime-private, single-use product sealed from one selected entry.
///
/// It is neither `Clone` nor serializable and has no constructor, extraction,
/// or callback attachment outside the registry module. Registration consumes
/// it.
pub(super) struct InstalledPluginBundleV1<P> {
    plugin: Box<P>,
    reducer: Option<Box<dyn Reducer>>,
    approver: Box<dyn ActionApprover>,
    route: Kind,
    configuration: Vec<u8>,
    pub(super) binding: OutputPolicyBindingV1,
    pub(super) pin: crate::composition::PluginPinV1,
    pub(super) evidence: CatalogueEvidenceV1,
}

impl<P: Plugin> InstalledPluginBundleV1<P> {
    pub(super) fn links(&self) -> CatalogueLinksV1<'_> {
        CatalogueLinksV1 {
            plugin: &*self.plugin,
            route: &self.route,
            configuration: &self.configuration,
            policy: self.binding.policy(),
            budget: self.binding.budget(),
            implementation: self.binding.implementation_artifact(),
            bound_configuration: self.binding.configuration_artifact(),
            execution_profile: self.binding.execution_profile_artifact(),
            retention_policy: self.binding.retention_policy_artifact(),
            pin: &self.pin,
        }
    }
}

/// Retained inputs whose exact identity links are checked before registration.
#[derive(Clone, Copy)]
pub(super) struct CatalogueLinksV1<'a> {
    pub(super) plugin: &'a dyn Plugin,
    pub(super) route: &'a Kind,
    pub(super) configuration: &'a [u8],
    pub(super) policy: &'a pos_core::output_policy::OutputPolicyV1,
    pub(super) budget: &'a pos_core::ExecutableBudgetPolicyV1,
    pub(super) implementation: &'a [u8],
    pub(super) bound_configuration: &'a [u8],
    pub(super) execution_profile: &'a [u8],
    pub(super) retention_policy: &'a [u8],
    pub(super) pin: &'a crate::composition::PluginPinV1,
}

impl CatalogueLinksV1<'_> {
    /// Check the `PluginId`, version, declaration, EBP1, EPF1, RTP1, CFG1,
    /// source and candidate pin links.
    ///
    /// Every link is computed up front; the error reported is that of the
    /// first failing link in the order listed above.
    pub(super) fn validate(&self) -> Result<(), crate::OutputAdmissionErrorV1> {
        let policy = self.policy.fields();
        let budget = self.budget.fields();
        let plugin_id = self.plugin.id();
        let mut declared = policy
            .output_declarations
            .iter()
            .map(pos_core::output_policy::OutputDeclarationV1::event_type)
            .collect::<Vec<_>>();
        declared.sort_unstable();
        let capability = self.plugin.capability();
        let mut owned = capability
            .owned_event_types
            .iter()
            .map(Kind::as_str)
            .collect::<Vec<_>>();
        owned.sort_unstable();
        let role = crate::installed_plugin_role_v1(self.plugin);
        first_broken_link([
            (
                policy.plugin_id == plugin_id,
                crate::OutputAdmissionErrorV1::PluginMismatch,
            ),
            (
                policy.plugin_version == self.plugin.version(),
                crate::OutputAdmissionErrorV1::PluginVersionMismatch,
            ),
            (
                declared == owned && declared.contains(&self.route.as_str()),
                crate::OutputAdmissionErrorV1::ArtifactIdentityMismatch {
                    kind: "declaration",
                },
            ),
            (
                policy.executable_profile_hash == self.budget.digest()
                    && budget
                        .plugin_cpu_reservations
                        .iter()
                        .any(|row| row.plugin_id == plugin_id),
                crate::OutputAdmissionErrorV1::PolicyIdentityMismatch,
            ),
            (
                budget.execution_profile_hash
                    == crate::execution_profile_artifact_hash_v1(self.execution_profile),
                crate::OutputAdmissionErrorV1::ArtifactIdentityMismatch { kind: "EPF1" },
            ),
            (
                policy.retention_policy_hash
                    == crate::host_artifact_hash_v1(
                        b"pigloros.retention-policy.v1",
                        self.retention_policy,
                    ),
                crate::OutputAdmissionErrorV1::ArtifactIdentityMismatch { kind: "RTP1" },
            ),
            (
                self.bound_configuration == self.configuration
                    && policy.base_configuration_digest
                        == crate::host_artifact_hash_v1(
                            b"pigloros.base-configuration.v1",
                            self.configuration,
                        ),
                crate::OutputAdmissionErrorV1::ArtifactIdentityMismatch {
                    kind: "configuration",
                },
            ),
            (
                policy.implementation_hash
                    == crate::implementation_artifact_hash_v1(self.implementation),
                crate::OutputAdmissionErrorV1::ArtifactIdentityMismatch {
                    kind: "implementation",
                },
            ),
            (
                self.pin.configuration_digest() == self.policy.digest()
                    && self.pin.roles() == std::slice::from_ref(&role),
                crate::OutputAdmissionErrorV1::ArtifactIdentityMismatch { kind: "pin" },
            ),
        ])
    }
}

/// Return the error of the first link, in array order, that does not hold.
///
/// Callers evaluate every link eagerly when building the array; this only
/// selects which failure is reported.
fn first_broken_link<const N: usize>(
    links: [(bool, crate::OutputAdmissionErrorV1); N],
) -> Result<(), crate::OutputAdmissionErrorV1> {
    links
        .into_iter()
        .find(|(held, _)| !held)
        .map_or(Ok(()), |(_, error)| Err(error))
}

/// Invoke the selected factory once and seal its product with the evidence.
///
/// The selected entry's reviewed specification checks the actual Plugin and
/// approver types whatever the evidence; only the EPF1/source provenance of
/// the binding varies. Installed evidence resolves the host-verified EPF1,
/// which is absent in Wave 8, so production sealing fails closed there.
pub(super) fn seal_catalogue_bundle<F: InstalledPluginFactoryV1>(
    entry: &HostCatalogueEntryV1<F>,
    frozen_configuration: &F::Configuration,
    evidence: CatalogueEvidenceV1,
) -> Result<InstalledPluginBundleV1<F::Plugin>, RuntimeError> {
    let source = evidence.binding_source(entry.spec);
    let details = F::configuration_details(frozen_configuration);
    let product = F::build(frozen_configuration);
    let plugin = Box::new(product.plugin);
    let resolved = first_broken_link([
        (
            entry.spec.accepts_plugin(&*plugin),
            crate::OutputAdmissionErrorV1::PluginMismatch,
        ),
        (
            entry.spec.accepts_approver::<F::Approver>(),
            crate::OutputAdmissionErrorV1::CallbackMismatch { kind: "approver" },
        ),
    ])
    .and_then(|()| {
        crate::canonical_plugin_configuration_v1(&*plugin, &details).map_err(|_| {
            crate::OutputAdmissionErrorV1::ArtifactInvalid {
                kind: "configuration",
            }
        })
    })
    .and_then(|configuration| {
        OutputPolicyBindingV1::from_source(
            &*plugin,
            source,
            &details,
            CATALOGUE_PROFILE_ID_V1,
        )
        .map(|binding| (configuration, binding))
    })
    .map_err(RuntimeError::from)
    .and_then(|(configuration, binding)| {
        crate::composition::PluginPinV1::try_new(
            DomainImplementationKindV1::Plugin,
            PluginIsolationV1::OperatorTrustedNative,
            binding.policy().digest(),
            vec![crate::installed_plugin_role_v1(&*plugin)],
        )
        .map(|pin| (configuration, binding, pin))
        .map_err(RuntimeError::from)
    });
    resolved.and_then(|(configuration, binding, pin)| {
        let bundle = InstalledPluginBundleV1 {
            plugin,
            reducer: product.reducer,
            approver: Box::new(product.approver),
            route: Kind::new(crate::output_admission::WORLD_ACTION_EVENT_TYPE_V1),
            configuration,
            binding,
            pin,
            evidence,
        };
        let validated = bundle.links().validate();
        validated.map(|()| bundle).map_err(RuntimeError::from)
    })
}

impl PluginRegistry {
    /// Register the product of one selected host catalogue entry.
    ///
    /// This is the sole production Plugin registration operation. The
    /// trusted composition root selects `entry` and passes a frozen
    /// configuration; runtime invokes the entry's factory once, checks the
    /// actual Plugin and approver against the reviewed specification, freezes
    /// CFG1, resolves the host-verified EPF1, checks every retained link, and
    /// commits atomically. No installed Gateway EPF1 exists in Wave 8, so
    /// registration fails closed before any registry mutation; positive
    /// installed registration arrives with Wave 9 (#460/#462/#461).
    ///
    /// # Errors
    /// Rejects a foreign Plugin or approver, invalid configuration, an
    /// unavailable installed EPF1, a broken artifact link, or a registration
    /// conflict, without changing the registry.
    pub fn register_from_host_catalogue_entry<F: InstalledPluginFactoryV1>(
        &mut self,
        entry: &HostCatalogueEntryV1<F>,
        frozen_configuration: &F::Configuration,
    ) -> Result<(), RuntimeError> {
        self.register_catalogue_entry(entry, frozen_configuration, CatalogueEvidenceV1::Installed)
    }

    /// Register a selected catalogue entry with nonproduction evidence.
    ///
    /// The factory, reviewed specification checks, link checks and atomic
    /// commit are those of [`Self::register_from_host_catalogue_entry`]; only
    /// the evidence differs. Generated source and draft EPF1 bytes never
    /// yield a registration pin, admitted composition, or append permission.
    ///
    /// # Errors
    /// Returns the same closed errors as the production operation.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn register_host_catalogue_fixture<F: InstalledPluginFactoryV1>(
        &mut self,
        entry: &HostCatalogueEntryV1<F>,
        frozen_configuration: &F::Configuration,
    ) -> Result<(), RuntimeError> {
        self.register_catalogue_entry(entry, frozen_configuration, CatalogueEvidenceV1::Generated)
    }

    fn register_catalogue_entry<F: InstalledPluginFactoryV1>(
        &mut self,
        entry: &HostCatalogueEntryV1<F>,
        frozen_configuration: &F::Configuration,
        evidence: CatalogueEvidenceV1,
    ) -> Result<(), RuntimeError> {
        seal_catalogue_bundle(entry, frozen_configuration, evidence)
            .and_then(|bundle| self.commit_catalogue_bundle(bundle))
    }

    // Consume the sealed bundle in one atomic registration. Only installed
    // evidence attaches the checked candidate pin.
    fn commit_catalogue_bundle<P: Plugin>(
        &mut self,
        bundle: InstalledPluginBundleV1<P>,
    ) -> Result<(), RuntimeError> {
        let InstalledPluginBundleV1 {
            plugin,
            reducer,
            approver,
            route,
            configuration: _,
            binding,
            pin,
            evidence,
        } = bundle;
        let registration = evidence.registration(pin);
        self.register_with_verified_output_policy_inner(
            &*plugin,
            binding,
            reducer,
            PendingRegistrationCallbacksV1 {
                driver: None,
                approver: Some(approver),
                approver_event_types: [route],
            },
            RegistrationOptions {
                registration,
                output_admission: None,
                manifest_slot: None,
                reducer_slot: ReducerSlotV1::ByPluginId,
            },
        )
    }
}
