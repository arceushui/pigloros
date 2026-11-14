//! ADR-133 host-composition module: the closed community lifecycle facade.
//!
//! [`CommunityLifecycleHostV1`] owns the installed authority catalogue and
//! exclusive use of one concrete protected domain. Store keeps sealed
//! persistence and the key vault, and the domain itself evaluates its current
//! metadata-service authority from the installed inputs (ADR-129 §3: the
//! concrete owner obtains it); this module only hands the installed authority
//! to the domain, never a decision. It is distinct from the
//! bounded worker and worker-protocol modules, and it grants no
//! caller-asserted authority, raw backend access or qualification.
//!
//! Each operation lives in its own file and `impl` block.

mod catalogue;
mod open;

pub use catalogue::CommunityInstalledCatalogueV1;
pub use pos_store::community::{
    CommunityBootstrapRequestV1, CommunityDomainOpenedV1, MemoryCommunityDomainV1,
};

/// The releasing community lifecycle capability for one protected domain.
///
/// It exposes only closed operations. There is no key, material, store,
/// record or State getter, and its fields are private:
///
/// ```compile_fail,E0599
/// fn leak(host: &pos_plugin_supervisor::host_composition::CommunityLifecycleHostV1<'_>) {
///     let _ = host.key();
/// }
/// ```
///
/// ```compile_fail,E0599
/// fn leak(host: &pos_plugin_supervisor::host_composition::CommunityLifecycleHostV1<'_>) {
///     let _ = host.store();
/// }
/// ```
///
/// ```compile_fail,E0599
/// fn leak(host: &pos_plugin_supervisor::host_composition::CommunityLifecycleHostV1<'_>) {
///     let _ = host.state();
/// }
/// ```
///
/// ```compile_fail,E0599
/// fn leak(host: &pos_plugin_supervisor::host_composition::CommunityLifecycleHostV1<'_>) {
///     let _ = host.nonce();
/// }
/// ```
///
/// ```compile_fail,E0616
/// fn leak(host: &pos_plugin_supervisor::host_composition::CommunityLifecycleHostV1<'_>) {
///     let _ = &host.domain;
/// }
/// ```
pub struct CommunityLifecycleHostV1<'a> {
    catalogue: CommunityInstalledCatalogueV1,
    domain: &'a mut MemoryCommunityDomainV1,
}
