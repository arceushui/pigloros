mod envelope_cases {
    use super::*;
    use der::{Reader, Tag, Tagged};

    fn edit_field(
        proof: &[u8],
        index: usize,
        edit: impl FnOnce(&mut der::Any) -> TestResult,
    ) -> TestResult<Vec<u8>> {
        let mut outer = ContentInfo::from_der(proof)?;
        edit_children(&mut outer.content, |fields| {
            edit(fields.get_mut(index).ok_or("missing CMS field")?)
        })?;
        Ok(outer.to_der()?)
    }

    fn edit_children(
        value: &mut der::Any,
        edit: impl FnOnce(&mut Vec<der::Any>) -> TestResult,
    ) -> TestResult {
        let mut reader = der::SliceReader::new(value.value())?;
        let mut fields: Vec<der::Any> = Vec::new();
        while !reader.is_finished() {
            fields.push(reader.decode()?);
        }
        edit(&mut fields)?;
        let encoded: Result<Vec<_>, _> = fields.iter().map(Encode::to_der).collect();
        *value = der::Any::new(value.tag(), encoded?.concat())?;
        Ok(())
    }

    #[test]
    fn public_proof_verification_rejects_truncated_envelope_prefixes() -> TestResult {
        for count in 0..5 {
            let mut outer = ContentInfo::from_der(PROOF)?;
            edit_children(&mut outer.content, |fields| {
                fields.truncate(count);
                Ok(())
            })?;
            assert_eq!(
                verify(&fixture(&outer.to_der()?, CERTIFICATE)?, NOW)?,
                Err(SandboxImageProofError::Malformed),
                "SignedData prefix {count}"
            );
            let proof = edit_field(PROOF, 4, |signers| {
                let mut signer = der::Any::from_der(signers.value())?;
                edit_children(&mut signer, |fields| {
                    fields.truncate(count);
                    Ok(())
                })?;
                *signers = der::Any::new(Tag::Set, signer.to_der()?)?;
                Ok(())
            })?;
            assert_eq!(
                verify(&fixture(&proof, CERTIFICATE)?, NOW)?,
                Err(SandboxImageProofError::Malformed),
                "SignerInfo prefix {count}"
            );
        }
        Ok(())
    }

    #[test]
    fn public_proof_verification_rejects_wrong_container_types() -> TestResult {
        let mut outer = ContentInfo::from_der(PROOF)?;
        outer.content_type = ObjectIdentifier::new("1.2.3.4")?;
        assert_eq!(
            verify(&fixture(&outer.to_der()?, CERTIFICATE)?, NOW)?,
            Err(SandboxImageProofError::UnsupportedProfile)
        );
        for index in [0, 4] {
            let proof = edit_field(PROOF, index, |field| {
                *field = der::Any::null();
                Ok(())
            })?;
            assert_eq!(
                verify(&fixture(&proof, CERTIFICATE)?, NOW)?,
                Err(SandboxImageProofError::Malformed)
            );
        }
        let proof = edit_field(PROOF, 4, |signers| {
            *signers = der::Any::new(Tag::Set, der::Any::null().to_der()?)?;
            Ok(())
        })?;
        assert_eq!(
            verify(&fixture(&proof, CERTIFICATE)?, NOW)?,
            Err(SandboxImageProofError::Malformed)
        );
        Ok(())
    }

    #[test]
    fn public_proof_verification_rejects_normalized_nested_der_set() -> TestResult {
        let canonical = edit_cms(PROOF, |cms_data| {
            let mut signer = cms_data
                .signer_infos
                .0
                .get(0)
                .ok_or("missing signer")?
                .clone();
            let SignerIdentifier::IssuerAndSerialNumber(sid) = &mut signer.sid else {
                return Err("expected issuer SID".into());
            };
            sid.issuer = "CN=proof+OU=unit".parse()?;
            cms_data.signer_infos = vec![signer].try_into()?;
            Ok(())
        })?;
        let proof = edit_field(&canonical, 4, |signers| {
            edit_children(signers, |entries| {
                edit_children(entries.get_mut(0).ok_or("missing signer")?, |fields| {
                    edit_children(fields.get_mut(1).ok_or("missing SID")?, |sid| {
                        edit_children(sid.get_mut(0).ok_or("missing issuer")?, |rdns| {
                            edit_children(rdns.get_mut(0).ok_or("missing RDN")?, |attributes| {
                                assert_eq!(attributes.len(), 2);
                                attributes.reverse();
                                Ok(())
                            })
                        })
                    })
                })
            })
        })?;
        assert_ne!(proof, canonical);
        // The library normalizes this nested SET; only the complete roundtrip
        // distinguishes it from a canonical but unauthorized issuer SID.
        assert_eq!(
            verify(&fixture(&canonical, CERTIFICATE)?, NOW)?,
            Err(SandboxImageProofError::UnauthorizedSigner)
        );
        assert_eq!(
            verify(&fixture(&proof, CERTIFICATE)?, NOW)?,
            Err(SandboxImageProofError::Malformed)
        );
        Ok(())
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
    fn public_proof_verification_bounds_near_limit_certificate_before_decoding() -> TestResult {
        let proof = edit_field(PROOF, 3, |certificates| {
            let oversized = der::Any::new(Tag::Sequence, vec![0; 1024 * 1024 - 4096])?;
            *certificates = der::Any::new(certificates.tag(), oversized.to_der()?)?;
            Ok(())
        })?;
        assert!(proof.len() > 1024 * 1024 - 4096);
        assert!(proof.len() <= 1024 * 1024);
        assert_eq!(
            verify(&fixture(&proof, CERTIFICATE)?, NOW)?,
            Err(SandboxImageProofError::ResourceLimit)
        );
        Ok(())
    }

    #[test]
    fn public_proof_verification_rejects_near_limit_attributes_before_decoding() -> TestResult {
        let proof = edit_field(PROOF, 4, |signers| {
            let signer: der::Any = der::Any::from_der(signers.value())?;
            // An unknown trailing unsigned-attributes body must be rejected
            // without eagerly allocating or sorting its contents.
            let attributes = der::Any::new(
                Tag::ContextSpecific {
                    constructed: true,
                    number: der::TagNumber::N1,
                },
                vec![0; 1024 * 1024 - 4096],
            )?;
            let encoded = der::Any::new(
                Tag::Sequence,
                [signer.value(), attributes.to_der()?.as_slice()].concat(),
            )?;
            *signers = der::Any::new(Tag::Set, encoded.to_der()?)?;
            Ok(())
        })?;
        assert!(proof.len() > 1024 * 1024 - 4096);
        assert!(proof.len() <= 1024 * 1024);
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
