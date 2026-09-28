//! Borrowed CMS envelope bounds before eager collection decoding.
//!
//! DER's `SetOfVec` sorts its decoded elements. Reject excess collections,
//! forbidden attributes and noncanonical ordering before that work occurs.

use der::{asn1::AnyRef, Any, Decode, Reader, SliceReader, Tag, TagNumber, Tagged};

use super::SandboxImageProofError as Error;

const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;

const IMPLICIT_ZERO: Tag = Tag::ContextSpecific {
    constructed: true,
    number: TagNumber::N0,
};
const IMPLICIT_ONE: Tag = Tag::ContextSpecific {
    constructed: true,
    number: TagNumber::N1,
};

pub(super) fn validate(content: &Any) -> Result<(), Error> {
    let mut reader = sequence(AnyRef::from(content))?;
    let _version: AnyRef<'_> = reader.decode()?;
    let digests: AnyRef<'_> = reader.decode()?;
    digests.tag().assert_eq(Tag::Set)?;
    bounded_elements(digests.value(), 1, Error::UnsupportedProfile)?;
    let _encapsulation: AnyRef<'_> = reader.decode()?;
    let mut next: AnyRef<'_> = reader.decode()?;
    if next.tag() == IMPLICIT_ZERO {
        for certificate in bounded_elements(next.value(), 8, Error::ResourceLimit)? {
            if certificate.len() > MAX_CERTIFICATE_BYTES {
                return Err(Error::ResourceLimit);
            }
        }
        next = reader.decode()?;
    }
    if next.tag() == IMPLICIT_ONE {
        return Err(Error::UnsupportedProfile);
    }
    next.tag().assert_eq(Tag::Set)?;
    for signer in bounded_elements(next.value(), 1, Error::UnsupportedProfile)? {
        reject_attributes(signer)?;
    }
    reader.finish(())?;
    Ok(())
}

fn sequence(value: AnyRef<'_>) -> Result<SliceReader<'_>, Error> {
    value.tag().assert_eq(Tag::Sequence)?;
    SliceReader::new(value.value()).map_err(Error::from)
}

fn bounded_elements(body: &[u8], maximum: usize, limit_error: Error) -> Result<Vec<&[u8]>, Error> {
    SliceReader::new(body)
        .map_err(Error::from)
        .and_then(|mut reader| {
            let mut elements = Vec::new();
            while !reader.is_finished() {
                if elements.len() == maximum {
                    return Err(limit_error);
                }
                let encoded = reader.tlv_bytes()?;
                if elements.last().is_some_and(|previous| *previous >= encoded) {
                    return Err(Error::Malformed);
                }
                elements.push(encoded);
            }
            Ok(elements)
        })
}

fn reject_attributes(encoded: &[u8]) -> Result<(), Error> {
    let mut reader = AnyRef::from_der(encoded)
        .map_err(Error::from)
        .and_then(sequence)?;
    let _version: AnyRef<'_> = reader.decode()?;
    validate_sid(reader.tlv_bytes()?)?;
    let _digest: AnyRef<'_> = reader.decode()?;
    let signature_algorithm: AnyRef<'_> = reader.decode()?;
    if signature_algorithm.tag() == IMPLICIT_ZERO {
        return Err(Error::UnsupportedProfile);
    }
    let _signature: AnyRef<'_> = reader.decode()?;
    if !reader.is_finished() {
        return Err(Error::UnsupportedProfile);
    }
    Ok(())
}

fn validate_sid(encoded: &[u8]) -> Result<(), Error> {
    // Either SID's identity fields must fit inside the selected certificate.
    // A larger SID cannot match any certificate in this closed profile.
    if encoded.len() > MAX_CERTIFICATE_BYTES {
        return Err(Error::ResourceLimit);
    }
    AnyRef::from_der(encoded)
        .map_err(Error::from)
        .and_then(|sid| {
            if sid.tag() == Tag::Sequence {
                SliceReader::new(sid.value())
                    .map_err(Error::from)
                    .and_then(|mut identity| {
                        let issuer: AnyRef<'_> = identity.decode()?;
                        validate_name(issuer)
                    })
            } else {
                Ok(())
            }
        })
}

fn validate_name(issuer: AnyRef<'_>) -> Result<(), Error> {
    let mut name = sequence(issuer)?;
    while !name.is_finished() {
        let rdn: AnyRef<'_> = name.decode()?;
        rdn.tag().assert_eq(Tag::Set)?;
        // Each DER element needs at least two encoded bytes. This derived
        // ceiling adds no restriction beyond the SID bound. Checking order
        // here prevents quadratic insertion sorting of noncanonical RDNs.
        let _attributes =
            bounded_elements(rdn.value(), MAX_CERTIFICATE_BYTES / 2, Error::ResourceLimit)?;
    }
    Ok(())
}
