//! Observe logical cleanup while the State value and allocation are still live.

use std::cell::Cell;

use super::*;

thread_local! {
    static DROPS: Cell<(usize, bool, bool)> = const { Cell::new((0, false, false)) };
}

pub(super) fn observe_state_erasure(state: &CommunityStateV1) {
    let (count, _, _) = DROPS.get();
    DROPS.set((count + 1, state.schema == [0; 32], state.bytes.is_empty()));
}

pub(in crate::adapter) fn reset_observation() {
    DROPS.set((0, false, false));
}

pub(in crate::adapter) fn observation() -> (usize, bool, bool) {
    DROPS.get()
}

#[test]
fn dropping_a_state_clears_it_before_its_allocation_is_released() {
    reset_observation();
    drop(CommunityStateV1 {
        schema: [1; 32],
        bytes: b"private State".to_vec(),
    });
    assert_eq!(observation(), (1, true, true));
}

#[test]
fn replacement_and_final_shared_release_clear_each_owned_state() {
    reset_observation();
    let shared = Shared::new(
        PluginId::new(),
        CommunityStateV1 {
            schema: [1; 32],
            bytes: b"original".to_vec(),
        },
    );
    shared.commit(CommunityStateV1 {
        schema: [2; 32],
        bytes: b"replacement".to_vec(),
    });
    assert_eq!(observation(), (1, true, true));
    let snapshot = shared.committed_state();
    drop(shared);
    assert_eq!(observation(), (2, true, true));
    assert_eq!(snapshot.schema, [2; 32]);
    assert_eq!(snapshot.bytes, b"replacement");
    drop(snapshot);
    assert_eq!(observation(), (3, true, true));
}
