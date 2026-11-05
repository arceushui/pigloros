macro_rules! public_admission_tests {
    ($($tokens:tt)*) => {
        $($tokens)*
    };
}

include!("support/sandbox_admission_fixture.rs");

#[test]
fn payload_stream_finish_requires_every_chunk_and_the_exact_aggregate_digest() -> TestResult {
    use pos_reference::sandbox_provider_protocol::{
        PayloadDescriptor, PayloadDirection, PayloadStreamValidator, SandboxPayloadChunk,
    };

    // ADR-069's fixed wire chunk size; keep this oracle independent of the validator.
    const CHUNK_BYTES: usize = 1_048_576;
    let parent = [1; 32];
    let request = [2; 16];
    let attempt = [3; 16];
    let payload = [vec![b'a'; CHUNK_BYTES], b"end".to_vec()].concat();
    let length = u64::try_from(payload.len())?;
    let digest = payload_digest(b"PiglorOS.SandboxOutputBytes.v1\0", &payload);
    let chunks = payload
        .chunks(CHUNK_BYTES)
        .enumerate()
        .map(|(index, part)| -> TestResult<SandboxPayloadChunk> {
            let unsigned = Value::Array(vec![
                Value::Text("SBC1".to_owned()),
                integer(1),
                bytes(parent),
                Value::Bytes(request.to_vec()),
                Value::Bytes(attempt.to_vec()),
                integer(1),
                integer(u64::try_from(index)?),
                integer(u64::try_from(index * CHUNK_BYTES)?),
                Value::Bytes(part.to_vec()),
            ]);
            Ok(SandboxPayloadChunk::from_canonical_cbor(
                &self_digested_record("SBC1", unsigned)?,
            )?)
        })
        .collect::<TestResult<Vec<_>>>()?;

    assert_eq!(chunks.len(), 2);
    assert_eq!(length, 1_048_579);
    for (index, chunk) in chunks.iter().enumerate() {
        assert_eq!(chunk.parent_digest, parent);
        assert_eq!(chunk.request_id, request);
        assert_eq!(chunk.attempt_id, attempt);
        assert_eq!(chunk.direction, PayloadDirection::Output);
        assert_eq!(chunk.index, u64::try_from(index)?);
        assert_eq!(chunk.offset, [0, 1_048_576][index]);
        assert_eq!(chunk.bytes.len(), [CHUNK_BYTES, 3][index]);
        assert_eq!(
            chunk.bytes.as_slice(),
            [&payload[..CHUNK_BYTES], b"end"][index]
        );
    }

    let stream = |count: usize, digest| -> TestResult<PayloadStreamValidator> {
        let mut validator = PayloadStreamValidator::new(
            parent,
            request,
            attempt,
            PayloadDirection::Output,
            PayloadDescriptor {
                byte_length: length,
                digest,
            },
        )?;
        for chunk in chunks.iter().take(count) {
            validator.accept(chunk)?;
        }
        Ok(validator)
    };
    assert_eq!(stream(2, digest)?.finish(), Ok(()));
    for count in 0..2 {
        assert_eq!(
            stream(count, digest)?.finish(),
            Err(ProtocolError::InconsistentFields),
            "only {count} of the two chunks were accepted"
        );
    }
    let mut wrong_digest = digest;
    wrong_digest[0] ^= 1;
    assert_eq!(
        stream(2, wrong_digest)?.finish(),
        Err(ProtocolError::DigestMismatch)
    );
    Ok(())
}
