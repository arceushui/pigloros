//! The provenance digests of the Scenario Room golden examples come from
//! the Gateway's own derivation (#1398).

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn the_golden_examples_carry_the_derived_provenance_digest() -> TestResult {
    for example in [
        include_str!("../../../../contracts/gateway/v1/examples/draft-scenario-room-create.json"),
        include_str!("../../../../contracts/gateway/v1/examples/draft-scenario-room-get.json"),
        include_str!("../../../../contracts/gateway/v1/examples/draft-scenario-room-derive.json"),
    ] {
        let body = &serde_json::from_str::<serde_json::Value>(example)?["response"]["body"];
        let hex = body["descriptor"]["descriptor_hash"]
            .as_str()
            .ok_or("descriptor_hash")?;
        let mut descriptor_hash = [0; 32];
        for (byte, pair) in descriptor_hash
            .iter_mut()
            .zip(hex.as_bytes().chunks_exact(2))
        {
            *byte = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
        }
        let event_id = EventId::from_ulid(ulid::Ulid::from_string(
            body["commit"]["event_id"].as_str().ok_or("event_id")?,
        )?);
        assert_eq!(
            body["provenance"]["digest"].as_str(),
            Some(
                revision_provenance_digest_v1(&Hash::from_bytes(descriptor_hash), event_id)
                    .as_str()
            )
        );
    }
    Ok(())
}
