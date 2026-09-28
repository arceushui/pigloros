mod envelope_cases {
    use super::*;
    use der::{Reader, Tag, Tagged};

    fn edit_field(
        proof: &[u8],
        index: usize,
        edit: impl FnOnce(&mut der::Any) -> TestResult,
    ) -> TestResult<Vec<u8>> {
        let mut outer = ContentInfo::from_der(proof)?;
        let mut reader = der::SliceReader::new(outer.content.value())?;
        let mut fields: Vec<der::Any> = Vec::new();
        while !reader.is_finished() {
            fields.push(reader.decode()?);
        }
        edit(fields.get_mut(index).ok_or("missing CMS field")?)?;
        let encoded: Result<Vec<_>, _> = fields.iter().map(Encode::to_der).collect();
        outer.content = der::Any::new(Tag::Sequence, encoded?.concat())?;
        Ok(outer.to_der()?)
    }

    #[test]
    fn public_proof_verification_bounds_near_limit_digest_set_before_decoding() -> TestResult {
        let proof = edit_field(PROOF, 1, |digests| {
            let algorithm = digests.value();
            let count = (1024 * 1024 - 4096) / algorithm.len();
            *digests = der::Any::new(Tag::Set, algorithm.repeat(count))?;
            Ok(())
        })?;
        assert!(proof.len() > 1024 * 1024 - 4096);
        assert!(proof.len() <= 1024 * 1024);
        // The eager SetOfVec path would allocate the entire collection and
        // report duplicate DER. The profile limit must reject before it runs.
        assert_eq!(
            verify(&fixture(&proof, CERTIFICATE)?, NOW)?,
            Err(SandboxImageProofError::UnsupportedProfile)
        );
        Ok(())
    }

    #[test]
    fn public_proof_verification_rejects_unordered_and_duplicate_certificate_der() -> TestResult {
        let reversed = edit_field(CHAIN, 3, |certificates| {
            let mut reader = der::SliceReader::new(certificates.value())?;
            let mut entries = Vec::new();
            while !reader.is_finished() {
                entries.push(reader.tlv_bytes()?.to_vec());
            }
            entries.reverse();
            *certificates = der::Any::new(certificates.tag(), entries.concat())?;
            Ok(())
        })?;
        let duplicated = edit_field(PROOF, 3, |certificates| {
            *certificates = der::Any::new(certificates.tag(), certificates.value().repeat(2))?;
            Ok(())
        })?;
        for (proof, certificate) in [(reversed, CHAIN_SIGNER), (duplicated, CERTIFICATE)] {
            assert_eq!(
                verify(&fixture(&proof, certificate)?, NOW)?,
                Err(SandboxImageProofError::Malformed)
            );
        }
        Ok(())
    }

    #[test]
    fn public_proof_verification_rejects_malformed_envelope_fields() -> TestResult {
        let wrong_set_tag = edit_field(PROOF, 1, |digests| {
            *digests = der::Any::new(Tag::Sequence, digests.value())?;
            Ok(())
        })?;
        let truncated_element = edit_field(PROOF, 1, |digests| {
            *digests = der::Any::new(Tag::Set, vec![0x30, 0x82, 0xff, 0xff])?;
            Ok(())
        })?;
        let mut outer = ContentInfo::from_der(PROOF)?;
        outer.content = der::Any::new(Tag::Set, outer.content.value())?;
        let wrong_content_tag = outer.to_der()?;
        let mut outer = ContentInfo::from_der(PROOF)?;
        outer.content = der::Any::new(Tag::Sequence, [outer.content.value(), &[5, 0]].concat())?;
        for proof in [
            wrong_set_tag,
            truncated_element,
            wrong_content_tag,
            outer.to_der()?,
        ] {
            assert_eq!(
                verify(&fixture(&proof, CERTIFICATE)?, NOW)?,
                Err(SandboxImageProofError::Malformed)
            );
        }
        Ok(())
    }
}
