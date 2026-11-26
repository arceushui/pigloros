//! The software authenticator's own refusals, which the honest client never provokes.

use pos_owner_ctap::SoftAuthenticator;

use super::PIN;

fn soft(uv: bool) -> SoftAuthenticator {
    SoftAuthenticator::new("refusals", PIN, uv)
}

#[test]
fn unknown_commands_and_subcommands_are_refused() {
    assert_eq!(soft(false).process(&[]), [0x01]);
    assert_eq!(soft(false).process(&[0x09]), [0x01]);
    assert_eq!(soft(false).process(&[0x06, 0xa1, 0x02, 0x05]), [0x02]);
}

#[test]
fn token_requests_are_refused_without_uv_retries_or_a_key() {
    assert_eq!(soft(false).process(&[0x06, 0xa1, 0x02, 0x06]), [0x3c]);
    assert_eq!(soft(true).process(&[0x06, 0xa1, 0x02, 0x06]), [0x02]);
    let mut blocked = soft(false);
    blocked.set_pin_retries(0);
    assert_eq!(blocked.process(&[0x06, 0xa1, 0x02, 0x09]), [0x32]);
    assert_eq!(blocked.pin_retries(), 0);
    let mut missing = soft(false);
    assert_eq!(missing.process(&[0x06, 0xa1, 0x02, 0x09]), [0x31]);
    assert_eq!(missing.pin_retries(), 7);
}

#[test]
fn commands_without_a_hash_or_a_token_are_refused() {
    assert_eq!(soft(false).process(&[0x01]), [0x02]);
    assert_eq!(soft(false).process(&[0x01, 0xa1, 0x01, 0x41, 0x00]), [0x33]);
    assert_eq!(soft(false).process(&[0x02]), [0x02]);
    assert_eq!(soft(false).process(&[0x02, 0xa1, 0x02, 0x41, 0x00]), [0x33]);
}
