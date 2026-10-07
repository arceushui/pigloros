//! The bounded release CAS loop and its legal-successor rule (ADR-110 §5.7, invariant I15).

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use pos_owner_bridge::ceremony::release::{
    reachable, read_state, release_loop, ReleaseMode, MAX_RELEASE_ATTEMPTS,
};
use pos_owner_bridge::{
    BridgeError, NavigationId, OwnerWebSurface, PostGuard, ProcessIdentity, ProtocolCode,
    ReplyImage, RequestImage, SurfaceError, SurfaceEvent, SurfaceSpec,
};
use pos_owner_bridge_codec::ControlState;

const UNEXPECTED: BridgeError = BridgeError::Protocol(ProtocolCode::UnexpectedState);

/// A surface whose state word replays scripted loads and compare-exchange outcomes.
struct StateWord {
    loads: RefCell<VecDeque<u32>>,
    outcomes: RefCell<VecDeque<bool>>,
    exchanges: Cell<u32>,
    fail_loads: bool,
    fail_exchanges: bool,
}

impl StateWord {
    fn new(loads: &[u32], outcomes: &[bool]) -> Self {
        Self {
            loads: RefCell::new(loads.iter().copied().collect()),
            outcomes: RefCell::new(outcomes.iter().copied().collect()),
            exchanges: Cell::new(0),
            fail_loads: false,
            fail_exchanges: false,
        }
    }
}

const fn refused() -> SurfaceError {
    SurfaceError::new(UNEXPECTED)
}

impl OwnerWebSurface for StateWord {
    fn open(&mut self, _spec: &SurfaceSpec) -> Result<ProcessIdentity, SurfaceError> {
        Err(refused())
    }

    fn navigate(&mut self) -> Result<NavigationId, SurfaceError> {
        Err(refused())
    }

    fn create_and_write(&mut self, _r: &RequestImage, _h: &[u8; 64]) -> Result<(), SurfaceError> {
        Err(refused())
    }

    fn post(&mut self, _guard: &PostGuard) -> Result<(), SurfaceError> {
        Err(refused())
    }

    fn reply_load_state(&self) -> Result<u32, SurfaceError> {
        if self.fail_loads {
            return Err(refused());
        }
        self.loads.borrow_mut().pop_front().ok_or_else(refused)
    }

    fn reply_compare_exchange(&self, _current: u32, _new: u32) -> Result<bool, SurfaceError> {
        self.exchanges.set(self.exchanges.get() + 1);
        if self.fail_exchanges {
            return Err(refused());
        }
        self.outcomes.borrow_mut().pop_front().ok_or_else(refused)
    }

    fn reply_store_state(&self, _new: u32) -> Result<(), SurfaceError> {
        Err(refused())
    }

    fn reply_copy(&self, _out: &mut ReplyImage) -> Result<(), SurfaceError> {
        Err(refused())
    }

    fn zero_close_buffers(&mut self) -> Result<(), SurfaceError> {
        Err(refused())
    }

    fn close_controller(&mut self) -> Result<(), SurfaceError> {
        Err(refused())
    }

    fn take_event(&mut self) -> Option<SurfaceEvent> {
        None
    }

    fn finish(&mut self) -> Result<(), SurfaceError> {
        Err(refused())
    }
}

const EMPTY: ControlState = ControlState::Empty;
const RECEIVED: ControlState = ControlState::Received;
const WRITING: ControlState = ControlState::Writing;
const READY: ControlState = ControlState::Ready;
const FAILED: ControlState = ControlState::Failed;
const CONSUMING: ControlState = ControlState::Consuming;

#[test]
fn the_reachability_table_is_exactly_the_page_transition_graph() {
    let all = [
        ControlState::Empty,
        ControlState::Writing,
        ControlState::Ready,
        ControlState::Consuming,
        ControlState::ReleaseRequested,
        ControlState::Releasing,
        ControlState::Failed,
        ControlState::Received,
    ];
    let legal = [
        (EMPTY, RECEIVED),
        (EMPTY, WRITING),
        (EMPTY, READY),
        (EMPTY, FAILED),
        (RECEIVED, WRITING),
        (RECEIVED, READY),
        (RECEIVED, FAILED),
        (WRITING, READY),
        (WRITING, FAILED),
    ];
    for from in all {
        for to in all {
            assert_eq!(
                reachable(from, to),
                legal.contains(&(from, to)),
                "{from:?} -> {to:?}"
            );
        }
    }
}

#[test]
fn a_normal_retire_and_a_normal_success_win_on_the_first_attempt() {
    let retire = StateWord::new(&[0], &[true]);
    assert_eq!(
        release_loop(&retire, EMPTY, ReleaseMode::Terminal),
        Ok(None)
    );
    assert_eq!(retire.exchanges.get(), 1);
    let success = StateWord::new(&[3], &[true]);
    assert_eq!(
        release_loop(&success, CONSUMING, ReleaseMode::Terminal),
        Ok(None)
    );
}

#[test]
fn a_first_read_may_equal_a_polled_known_state() {
    for (known, word) in [(RECEIVED, 7), (WRITING, 1), (READY, 2), (FAILED, 6)] {
        let surface = StateWord::new(&[word], &[true]);
        assert_eq!(
            release_loop(&surface, known, ReleaseMode::Terminal),
            Ok(None)
        );
    }
}

#[test]
fn an_honest_page_costs_at_most_four_attempts() {
    let surface = StateWord::new(&[0, 7, 1, 2], &[false, false, false, true]);
    assert_eq!(
        release_loop(&surface, EMPTY, ReleaseMode::Terminal),
        Ok(None)
    );
    assert_eq!(surface.exchanges.get(), 4);
    assert!(surface.exchanges.get() <= u32::from(MAX_RELEASE_ATTEMPTS / 2));
}

#[test]
fn an_honest_multi_step_skip_is_accepted() {
    let skip_to_ready = StateWord::new(&[0, 2], &[false, true]);
    assert_eq!(
        release_loop(&skip_to_ready, EMPTY, ReleaseMode::Terminal),
        Ok(None)
    );
    let skip_to_failed = StateWord::new(&[7, 6], &[false, true]);
    assert_eq!(
        release_loop(&skip_to_failed, RECEIVED, ReleaseMode::Terminal),
        Ok(None)
    );
}

#[test]
fn a_timing_failure_is_void_when_the_page_advanced() {
    for (word, state) in [(7, RECEIVED), (1, WRITING), (2, READY), (6, FAILED)] {
        let surface = StateWord::new(&[word], &[]);
        assert_eq!(
            release_loop(&surface, EMPTY, ReleaseMode::Timing),
            Ok(Some(state))
        );
        assert_eq!(surface.exchanges.get(), 0);
    }
    let raced = StateWord::new(&[0, 6], &[false]);
    assert_eq!(
        release_loop(&raced, EMPTY, ReleaseMode::Timing),
        Ok(Some(FAILED))
    );
    assert_eq!(raced.exchanges.get(), 1);
    let quiet = StateWord::new(&[0], &[true]);
    assert_eq!(release_loop(&quiet, EMPTY, ReleaseMode::Timing), Ok(None));
}

#[test]
fn an_illegal_first_read_is_unexpected_state_without_a_compare_exchange() {
    for (known, word) in [
        (EMPTY, 4),
        (EMPTY, 5),
        (EMPTY, 3),
        (EMPTY, 8),
        (EMPTY, u32::MAX),
    ] {
        let surface = StateWord::new(&[word], &[true]);
        assert_eq!(
            release_loop(&surface, known, ReleaseMode::Terminal),
            Err(UNEXPECTED)
        );
        assert_eq!(surface.exchanges.get(), 0);
    }
    for (known, word) in [
        (RECEIVED, 0),
        (WRITING, 7),
        (READY, 7),
        (FAILED, 0),
        (CONSUMING, 2),
    ] {
        let surface = StateWord::new(&[word], &[true]);
        assert_eq!(
            release_loop(&surface, known, ReleaseMode::Terminal),
            Err(UNEXPECTED)
        );
    }
}

#[test]
fn a_reread_equal_to_the_previous_value_means_it_changed_and_changed_back() {
    let surface = StateWord::new(&[0, 0], &[false]);
    assert_eq!(
        release_loop(&surface, EMPTY, ReleaseMode::Terminal),
        Err(UNEXPECTED)
    );
    assert_eq!(surface.exchanges.get(), 1);
}

#[test]
fn an_illegal_successor_after_a_failed_compare_exchange_exits_the_loop() {
    for word in [3, 4, 5, 8, 0, 7] {
        let after_received = StateWord::new(&[7, word], &[false]);
        let outcome = release_loop(&after_received, RECEIVED, ReleaseMode::Terminal);
        assert_eq!(outcome, Err(UNEXPECTED), "word {word}");
    }
    for word in [1, 2, 6] {
        let after_received = StateWord::new(&[7, word], &[false, true]);
        let outcome = release_loop(&after_received, RECEIVED, ReleaseMode::Terminal);
        assert_eq!(outcome, Ok(None), "word {word}");
    }
}

#[test]
fn endless_churn_ends_within_the_attempt_bound() {
    let churn = [7, 1, 2, 7, 1, 2, 7, 1, 2, 7];
    let surface = StateWord::new(&churn, &[false; 10]);
    assert_eq!(
        release_loop(&surface, EMPTY, ReleaseMode::Terminal),
        Err(UNEXPECTED)
    );
    assert!(surface.exchanges.get() <= u32::from(MAX_RELEASE_ATTEMPTS));
    assert_eq!(surface.exchanges.get(), 3);
}

#[test]
fn surface_failures_surface_unchanged() {
    let mut failing_loads = StateWord::new(&[0], &[true]);
    failing_loads.fail_loads = true;
    assert_eq!(read_state(&failing_loads), Err(UNEXPECTED));
    assert_eq!(
        release_loop(&failing_loads, EMPTY, ReleaseMode::Terminal),
        Err(UNEXPECTED)
    );
    let mut failing_exchange = StateWord::new(&[0], &[true]);
    failing_exchange.fail_exchanges = true;
    assert_eq!(
        release_loop(&failing_exchange, EMPTY, ReleaseMode::Terminal),
        Err(UNEXPECTED)
    );
}

#[test]
fn a_state_word_outside_zero_to_seven_is_unexpected_state() {
    let surface = StateWord::new(&[9], &[]);
    assert_eq!(read_state(&surface), Err(UNEXPECTED));
}
