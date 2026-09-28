mod identity_cases {
    use super::*;

    fn issuer_proof(attribute_bytes: usize, reverse: bool) -> TestResult<Vec<u8>> {
        fn attribute(index: usize) -> TestResult<Vec<u8>> {
            let label = format!("{index:08x}");
            Ok(x509_cert::attr::AttributeTypeAndValue {
                oid: ObjectIdentifier::new("2.5.4.3")?,
                value: der::Any::encode_from(&der::asn1::Utf8StringRef::new(&label)?)?,
            }
            .to_der()?)
        }
        let count = attribute_bytes / attribute(0)?.len();
        let mut attributes = (0..count).map(attribute).collect::<TestResult<Vec<_>>>()?;
        if reverse {
            attributes.reverse();
        }
        let rdn = der::Any::new(Tag::Set, attributes.concat())?;
        let issuer = der::Any::new(Tag::Sequence, rdn.to_der()?)?;
        edit_field(PROOF, 4, |signers| {
            edit_children(signers, |entries| {
                edit_children(entries.get_mut(0).ok_or("missing signer")?, |fields| {
                    edit_children(fields.get_mut(1).ok_or("missing SID")?, |sid| {
                        *sid.get_mut(0).ok_or("missing issuer")? = issuer;
                        Ok(())
                    })
                })
            })
        })
    }

    #[test]
    fn public_proof_verification_bounds_near_limit_issuer_before_decoding() -> TestResult {
        let proof = issuer_proof(1024 * 1024 - 4096, false)?;
        assert!(proof.len() > 1024 * 1024 - 4096);
        assert!(proof.len() <= 1024 * 1024);
        assert_eq!(
            verify(&fixture(&proof, CERTIFICATE)?, NOW)?,
            Err(SandboxImageProofError::ResourceLimit)
        );
        Ok(())
    }

    #[test]
    fn public_proof_verification_rejects_reverse_ordered_bounded_issuer() -> TestResult {
        let proof = issuer_proof(64 * 1024 - 4096, true)?;
        assert!(proof.len() > 64 * 1024 - 4096);
        assert!(proof.len() <= 64 * 1024);
        assert_eq!(
            verify(&fixture(&proof, CERTIFICATE)?, NOW)?,
            Err(SandboxImageProofError::Malformed)
        );
        Ok(())
    }

    #[test]
    fn public_proof_verification_decodes_canonical_bounded_issuer() -> TestResult {
        let proof = issuer_proof(64 * 1024 - 4096, false)?;
        assert!(proof.len() > 64 * 1024 - 4096);
        assert!(proof.len() <= 64 * 1024);
        assert_eq!(
            verify(&fixture(&proof, CERTIFICATE)?, NOW)?,
            Err(SandboxImageProofError::UnauthorizedSigner)
        );
        Ok(())
    }
}
