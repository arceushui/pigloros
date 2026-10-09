//! The preallocated slots wipe exactly what each wipe promises, and a plan hides its secrets.

use std::time::Instant;

use pos_owner_bridge_codec::{
    CeremonyId, CeremonyKind, CoseEs256PublicKey, OwnerBridgeCodecError, OwnerUserHandle,
};
use zeroize::Zeroizing;

use super::{CeremonyPlan, Slots, StoredGet};
use crate::fake::signer::FIXTURE_COSE_KEY;

#[test]
fn each_wipe_clears_its_own_secrets_and_the_sizes_are_the_protocol_capacities() {
    let mut slots = Slots::allocate();
    slots.prf.fill(1);
    slots.create_prf.fill(2);
    slots.copy_a.as_mut_bytes().fill(3);
    slots.request.as_mut_bytes().fill(5);
    slots.copy_b.select(CeremonyKind::Get);
    slots.copy_b.as_mut_bytes().fill(4);
    assert_eq!(slots.copy_b.as_bytes().len(), 8_192);
    slots.wipe_buffers();
    assert_eq!(*slots.prf, [1; 32]);
    assert!(slots.request.as_bytes().iter().all(|byte| *byte == 0));
    assert!(slots.copy_a.as_bytes().iter().all(|byte| *byte == 0));
    assert!(slots.copy_b.as_bytes().iter().all(|byte| *byte == 0));
    slots.prf.fill(1);
    slots.copy_a.as_mut_bytes().fill(3);
    slots.request.as_mut_bytes().fill(5);
    assert!(!slots.secrets_clear());
    slots.wipe_ceremony();
    assert!(slots.request.as_bytes().iter().all(|byte| *byte == 0));
    assert_eq!(*slots.prf, [0; 32]);
    assert_eq!(*slots.create_prf, [2; 32]);
    assert!(slots.copy_a.as_bytes().iter().all(|byte| *byte == 0));
    slots.wipe_all();
    assert_eq!(*slots.create_prf, [0; 32]);
    assert_eq!(slots.request.as_bytes().len(), 4_096);
    assert_eq!(slots.copy_a.as_bytes().len(), 73_728);
}

#[test]
fn a_plan_never_prints_its_challenge_user_handle_or_prf_input() {
    let plan = CeremonyPlan {
        kind: CeremonyKind::Create,
        ceremony_id: CeremonyId::from_bytes([0x11; 16]),
        challenge: Zeroizing::new([0x22; 32]),
        user_handle: Zeroizing::new([0x33; 32]),
        prf_input: Zeroizing::new([0x44; 32]),
        stored: None,
        t0: Instant::now(),
        generation: 7,
        owner_window: None,
        budget: None,
    };
    let printed = format!("{plan:?}");
    assert!(
        printed.contains("Create") && printed.contains('7'),
        "{printed}"
    );
    for secret in ["34", "51", "68", "17"] {
        assert!(
            !printed.contains(&format!("{secret}, {secret}")),
            "{printed}"
        );
    }
    assert!(
        !printed.contains("challenge") && !printed.contains("prf"),
        "{printed}"
    );
}

#[test]
fn a_plan_hands_out_its_secrets_as_codec_values() {
    let plan = CeremonyPlan {
        kind: CeremonyKind::Get,
        ceremony_id: CeremonyId::from_bytes([0x11; 16]),
        challenge: Zeroizing::new([0x22; 32]),
        user_handle: Zeroizing::new([0x33; 32]),
        prf_input: Zeroizing::new([0x44; 32]),
        stored: None,
        t0: Instant::now(),
        generation: 1,
        owner_window: None,
        budget: None,
    };
    assert_eq!(plan.challenge().as_bytes(), &[0x22; 32]);
    assert_eq!(plan.owner_user_handle().as_bytes(), &[0x33; 32]);
    assert_eq!(plan.prf_input_value().as_bytes(), &[0x44; 32]);
}

#[test]
fn wiping_the_secrets_clears_the_challenge_user_handle_and_prf_input() {
    let mut plan = CeremonyPlan {
        kind: CeremonyKind::Create,
        ceremony_id: CeremonyId::from_bytes([0x11; 16]),
        challenge: Zeroizing::new([0x22; 32]),
        user_handle: Zeroizing::new([0x33; 32]),
        prf_input: Zeroizing::new([0x44; 32]),
        stored: None,
        t0: Instant::now(),
        generation: 1,
        owner_window: None,
        budget: None,
    };
    assert!(!plan.secrets_clear());
    plan.wipe_secrets();
    assert!(plan.secrets_clear());
    assert_eq!(plan.challenge().as_bytes(), &[0; 32]);
    assert_eq!(plan.owner_user_handle().as_bytes(), &[0; 32]);
    assert_eq!(plan.prf_input_value().as_bytes(), &[0; 32]);
}

#[test]
fn a_stored_credential_never_prints_its_user_handle() -> Result<(), OwnerBridgeCodecError> {
    let stored = StoredGet {
        credential_id: vec![0xaa; 16],
        user_handle: OwnerUserHandle::from_bytes([0x37; 32]),
        public_key: CoseEs256PublicKey::from_canonical_encoding(&FIXTURE_COSE_KEY)?,
        backup_eligible: true,
        backup_state: false,
        sign_count: 9,
    };
    let printed = format!("{stored:?}");
    assert!(
        printed.contains("StoredGet") && printed.contains('9'),
        "{printed}"
    );
    for secret in ["55", "65", "66", "170"] {
        assert!(!printed.contains(secret), "{printed}");
    }
    Ok(())
}
