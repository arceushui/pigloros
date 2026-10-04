//! The narrow, local decision-provider seam for provider-backed Agents.

use crate::protocol::{AgentDecisionRequestV1, ProviderAttempt};
use std::{
    collections::VecDeque,
    sync::{atomic::Ordering, Arc},
};

/// Supplies one bounded decision attempt for a host-owned request.
pub trait AgentDecisionProvider: Send + Sync {
    /// Returns exactly one locally produced attempt for `request`.
    fn decide(&mut self, request: &AgentDecisionRequestV1) -> ProviderAttempt;
}

/// Read-only call-count handle for the local fixture provider.
#[derive(Clone, Debug)]
#[expect(
    clippy::disallowed_types,
    reason = "ADR-113 §7: the reducer-module type list applies only inside `reducer.rs`; \
              the fixture provider's call counter is an atomic"
)]
pub struct FixtureProviderCallCount(Arc<std::sync::atomic::AtomicUsize>);

impl FixtureProviderCallCount {
    /// Returns the number of decisions requested from the fixture.
    #[must_use]
    pub fn get(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// Deterministic in-memory provider adapter for tests and local fixtures.
///
/// It retains only configured bounded attempts and a call count. Requests and
/// provider response bytes are never retained, logged, or exposed.
pub struct FixtureAgentDecisionProvider {
    attempts: VecDeque<ProviderAttempt>,
    call_count: FixtureProviderCallCount,
}

impl FixtureAgentDecisionProvider {
    /// Creates a local fixture that returns attempts in declaration order.
    #[must_use]
    #[expect(
        clippy::disallowed_types,
        reason = "ADR-113 §7: the reducer-module type list applies only inside `reducer.rs`; \
                  the fixture provider's call counter is an atomic"
    )]
    pub fn new(attempts: Vec<ProviderAttempt>) -> Self {
        Self {
            attempts: attempts.into(),
            call_count: FixtureProviderCallCount(Arc::new(std::sync::atomic::AtomicUsize::new(0))),
        }
    }

    /// Returns a shareable counter without exposing requests or response bytes.
    #[must_use]
    pub fn call_count_handle(&self) -> FixtureProviderCallCount {
        self.call_count.clone()
    }

    /// Returns the number of decision calls observed by this fixture.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.call_count.get()
    }
}

impl AgentDecisionProvider for FixtureAgentDecisionProvider {
    fn decide(&mut self, _request: &AgentDecisionRequestV1) -> ProviderAttempt {
        self.call_count.0.fetch_add(1, Ordering::SeqCst);
        self.attempts
            .pop_front()
            .unwrap_or(ProviderAttempt::NoResponse)
    }
}
