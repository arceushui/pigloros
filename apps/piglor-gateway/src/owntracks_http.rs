//! Strict local HTTP decoding for V1 `OwnTracks` ingress.

use crate::{Gateway, GatewayError, OwnTracksIngressResult};
use axum::{
    body::{to_bytes, Body},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use pos_core::{CanonicalBytes, CoreError};
use pos_plugin_geo::{
    CompactLocationMetadata, CompactLocationObservation, SourceTimeBucket, V1SpatialCloaker,
    Wgs84Point,
};
pub(crate) const OWNTRACKS_MAX_BODY_BYTES: usize = 65_536;

pub(crate) async fn post_owntracks(gateway: Gateway, headers: HeaderMap, body: Body) -> Response {
    let Ok(bytes) = to_bytes(body, OWNTRACKS_MAX_BODY_BYTES).await else {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large");
    };
    if bytes.is_empty() {
        return (StatusCode::OK, "[]").into_response();
    }
    if !is_json(&headers) {
        return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type");
    }
    let Some((handle, secret)) = basic_credentials(&headers) else {
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    let payload = match minimize_location(&bytes) {
        Ok(payload) => payload,
        Err(LocationDecodeError::MalformedJson) => {
            return error(StatusCode::BAD_REQUEST, "malformed_json");
        }
        Err(LocationDecodeError::InvalidLocation) => {
            return error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_location");
        }
    };
    match gateway
        .admit_owntracks_ingress(handle, secret, payload)
        .await
    {
        Ok(OwnTracksIngressResult::RateLimited) => {
            let mut response = error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
            response.headers_mut().insert(
                header::RETRY_AFTER,
                "1".parse().expect("static Retry-After value"),
            );
            response
        }
        Ok(OwnTracksIngressResult::Accepted | OwnTracksIngressResult::Duplicate) => {
            (StatusCode::OK, "[]").into_response()
        }
        Ok(OwnTracksIngressResult::Conflict)
        | Err(GatewayError::Store(CoreError::GeographicAdmissionValidationFailed)) => {
            error(StatusCode::FORBIDDEN, "forbidden")
        }
        Ok(OwnTracksIngressResult::Unavailable) => {
            error(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
        }
        Err(GatewayError::Store(CoreError::GeographicAdmissionAuthenticationFailed)) => {
            error(StatusCode::UNAUTHORIZED, "unauthorized")
        }
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    }
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

fn basic_credentials(headers: &HeaderMap) -> Option<([u8; 32], [u8; 32])> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = decode_base64(encoded)?;
    let separator = decoded.iter().position(|byte| *byte == b':')?;
    let (handle, secret_with_separator) = decoded.split_at(separator);
    let secret = secret_with_separator.get(1..)?;
    Some((decode_hex_32(handle)?, decode_hex_32(secret)?))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocationDecodeError {
    MalformedJson,
    InvalidLocation,
}

fn minimize_location(bytes: &[u8]) -> Result<CanonicalBytes, LocationDecodeError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| LocationDecodeError::MalformedJson)?;
    let object = value
        .as_object()
        .ok_or(LocationDecodeError::InvalidLocation)?;
    if object.get("_type").and_then(serde_json::Value::as_str) != Some("location") {
        return Err(LocationDecodeError::InvalidLocation);
    }
    let latitude = object
        .get("lat")
        .and_then(serde_json::Value::as_f64)
        .ok_or(LocationDecodeError::InvalidLocation)?;
    let longitude = object
        .get("lon")
        .and_then(serde_json::Value::as_f64)
        .ok_or(LocationDecodeError::InvalidLocation)?;
    let source_time = object
        .get("tst")
        .and_then(serde_json::Value::as_i64)
        .ok_or(LocationDecodeError::InvalidLocation)?;
    let point =
        Wgs84Point::new(latitude, longitude).map_err(|_| LocationDecodeError::InvalidLocation)?;
    let cell = V1SpatialCloaker::new().cloak(point);
    let metadata =
        CompactLocationMetadata::v1(SourceTimeBucket::new(source_time.div_euclid(15 * 60)));
    Ok(CompactLocationObservation::new(cell, metadata).canonical_bytes())
}

fn decode_hex_32(value: &[u8]) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut decoded = [0; 32];
    for (index, pair) in value.chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(decoded)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut decoded = Vec::with_capacity((bytes.len() / 4) * 3);
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let last = index + 1 == bytes.len() / 4;
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        let c = if chunk[2] == b'=' {
            None
        } else {
            Some(base64_value(chunk[2])?)
        };
        let d = if chunk[3] == b'=' {
            None
        } else {
            Some(base64_value(chunk[3])?)
        };
        if !last && (c.is_none() || d.is_none()) || c.is_none() && d.is_some() {
            return None;
        }
        decoded.push((a << 2) | (b >> 4));
        if let Some(c) = c {
            decoded.push((b << 4) | (c >> 2));
            if let Some(d) = d {
                decoded.push((c << 6) | d);
            }
        }
    }
    Some(decoded)
}

fn base64_value(value: u8) -> Option<u8> {
    match value {
        b'A'..=b'Z' => Some(value - b'A'),
        b'a'..=b'z' => Some(value - b'a' + 26),
        b'0'..=b'9' => Some(value - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn error(status: StatusCode, code: &'static str) -> Response {
    (status, format!("{{\"error\":\"{code}\"}}")).into_response()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{basic_credentials, minimize_location, post_owntracks};
    use crate::Gateway;
    use axum::{
        body::{to_bytes, Body},
        http::{header, HeaderMap, HeaderValue, StatusCode},
    };
    use pos_core::{
        EntityId, EventStore, GeoLocationAdmissionFenceV1, OwnTracksEnrollmentRequestV1,
        OwnTracksEnrollmentStore,
    };
    use pos_store::{memory::MemoryStore, open_store, StoreConfig};
    use tokio::sync::mpsc;

    #[test]
    fn basic_credentials_reject_malformed_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static(
                "Basic MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwOjExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMQ==",
            ),
        );
        assert_eq!(basic_credentials(&headers), None);
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic not-base64"),
        );
        assert_eq!(basic_credentials(&headers), None);
    }

    #[test]
    fn basic_credentials_accept_pairing_hex() {
        let credential = format!("{}:{}", "0".repeat(64), "1".repeat(64));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", base64_encode(&credential))).unwrap(),
        );
        assert_eq!(basic_credentials(&headers), Some(([0; 32], [17; 32])));
    }

    fn base64_encode(value: &str) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut encoded = String::new();
        for chunk in value.as_bytes().chunks(3) {
            let first = chunk[0];
            let second = *chunk.get(1).unwrap_or(&0);
            let third = *chunk.get(2).unwrap_or(&0);
            encoded.push(char::from(TABLE[usize::from(first >> 2)]));
            encoded.push(char::from(
                TABLE[usize::from((first & 0x03) << 4 | second >> 4)],
            ));
            encoded.push(if chunk.len() > 1 {
                char::from(TABLE[usize::from((second & 0x0f) << 2 | third >> 6)])
            } else {
                '='
            });
            encoded.push(if chunk.len() > 2 {
                char::from(TABLE[usize::from(third & 0x3f)])
            } else {
                '='
            });
        }
        encoded
    }

    fn authenticated_headers(content_type: &'static str) -> HeaderMap {
        let credential = format!("{}:{}", "0".repeat(64), "1".repeat(64));
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", base64_encode(&credential))).unwrap(),
        );
        headers
    }

    fn location_body() -> Body {
        Body::from(&br#"{"_type":"location","lat":37.7749,"lon":-122.4194,"tst":1}"#[..])
    }

    fn enrolled_store() -> MemoryStore {
        const OWNER_KEY: [u8; 32] = [7; 32];
        let handle = [0; 32];
        let secret = [17; 32];
        let mut material = Vec::with_capacity(96);
        material.extend_from_slice(b"pigloros/owntracks/verifier/v1\0");
        material.extend_from_slice(&handle);
        material.extend_from_slice(&secret);
        let mut store = MemoryStore::new();
        let timeline = store.create_timeline("owntracks-http-test").unwrap();
        store
            .pair_owntracks_enrollment(OwnTracksEnrollmentRequestV1::new(
                timeline.id(),
                EntityId::new(),
                GeoLocationAdmissionFenceV1::new(1, ([1; 32], 2, [2; 32]), (1, false, 3)),
                *blake3::keyed_hash(&OWNER_KEY, &material).as_bytes(),
            ))
            .unwrap();
        store
    }

    #[test]
    fn minimization_discards_extra_telemetry_and_rejects_invalid_locations() {
        let first = minimize_location(
            br#"{"_type":"location","lat":37.7749,"lon":-122.4194,"tst":1,"acc":2,"tid":"x"}"#,
        )
        .unwrap();
        let second = minimize_location(
            br#"{"_type":"location","lat":37.7749,"lon":-122.4194,"tst":901,"acc":2,"tid":"x"}"#,
        )
        .unwrap();
        assert_ne!(first, second);
        assert!(minimize_location(br#"{"_type":"location","lat":91,"lon":0,"tst":1}"#).is_err());
        assert!(minimize_location(br#"{"_type":"location","lat":0,"lon":0,"tst":1.5}"#).is_err());
    }

    #[tokio::test]
    async fn empty_body_is_the_only_unauthenticated_success() {
        let response = post_owntracks(
            Gateway::new(open_store(StoreConfig::Memory).unwrap()),
            HeaderMap::new(),
            Body::empty(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap().as_ref(),
            b"[]"
        );
    }

    #[tokio::test]
    async fn rejects_unsupported_media_type_unauthorized_and_invalid_location() {
        let gateway = Gateway::new(open_store(StoreConfig::Memory).unwrap());
        let response = post_owntracks(gateway.clone(), HeaderMap::new(), location_body()).await;
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let mut json_headers = HeaderMap::new();
        json_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        let response = post_owntracks(gateway.clone(), json_headers, location_body()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let malformed_headers = authenticated_headers("application/json");
        let response = post_owntracks(
            gateway.clone(),
            malformed_headers,
            Body::from(&br#"{"_type":"location""#[..]),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = post_owntracks(
            gateway,
            authenticated_headers("application/json"),
            Body::from(&br#"{"_type":"location","lat":91,"lon":0,"tst":1}"#[..]),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn rejects_unauthorized_location_and_closed_executor() {
        const OWNER_KEY: [u8; 32] = [7; 32];
        const HANDLE: [u8; 32] = [0; 32];
        const SECRET: [u8; 32] = [17; 32];
        let response = post_owntracks(
            Gateway::new_with_owntracks_ingress_for_test(
                pos_store::memory::MemoryStore::new(),
                [0; 32],
            ),
            authenticated_headers("application/json"),
            location_body(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut material = Vec::with_capacity(96);
        material.extend_from_slice(b"pigloros/owntracks/verifier/v1\0");
        material.extend_from_slice(&HANDLE);
        material.extend_from_slice(&SECRET);
        let mut store = pos_store::memory::MemoryStore::new();
        let timeline = store.create_timeline("owntracks-auth-status").unwrap();
        store
            .pair_owntracks_enrollment(OwnTracksEnrollmentRequestV1::new(
                timeline.id(),
                EntityId::new(),
                GeoLocationAdmissionFenceV1::new(1, ([1; 32], 2, [2; 32]), (1, false, 3)),
                *blake3::keyed_hash(&OWNER_KEY, &material).as_bytes(),
            ))
            .unwrap();
        let mut invalid_headers = authenticated_headers("application/json");
        let invalid_credential = format!("{}:{}", "0".repeat(64), "2".repeat(64));
        invalid_headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", base64_encode(&invalid_credential)))
                .unwrap(),
        );
        let response = post_owntracks(
            Gateway::new_with_owntracks_ingress_for_test(store, OWNER_KEY),
            invalid_headers,
            location_body(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let gateway = Gateway::with_executor_for_test(crate::executor::StoreExecutor { tx });
        let response = post_owntracks(
            gateway,
            authenticated_headers("application/json"),
            location_body(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn oversized_body_is_rejected_before_authentication() {
        let response = post_owntracks(
            Gateway::new(open_store(StoreConfig::Memory).unwrap()),
            HeaderMap::new(),
            Body::from(vec![0; super::OWNTRACKS_MAX_BODY_BYTES + 1]),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn authenticated_location_is_minimized_and_admitted() {
        const OWNER_KEY: [u8; 32] = [7; 32];
        let handle = [0; 32];
        let secret = [17; 32];
        let mut material = Vec::with_capacity(96);
        material.extend_from_slice(b"pigloros/owntracks/verifier/v1\0");
        material.extend_from_slice(&handle);
        material.extend_from_slice(&secret);
        let mut store = pos_store::memory::MemoryStore::new();
        let timeline = store.create_timeline("owntracks-http").unwrap();
        store
            .pair_owntracks_enrollment(OwnTracksEnrollmentRequestV1::new(
                timeline.id(),
                EntityId::new(),
                GeoLocationAdmissionFenceV1::new(1, ([1; 32], 2, [2; 32]), (1, false, 3)),
                *blake3::keyed_hash(&OWNER_KEY, &material).as_bytes(),
            ))
            .unwrap();
        let gateway = Gateway::new_with_owntracks_ingress_for_test(store, OWNER_KEY);
        let mut notices = gateway.subscribe();
        let response = post_owntracks(
            gateway.clone(),
            authenticated_headers("application/json"),
            Body::from(
                &br#"{"_type":"location","lat":37.7749,"lon":-122.4194,"tst":1,"batt":90}"#[..],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap().as_ref(),
            b"[]"
        );
        assert_eq!(notices.recv().await.unwrap().event_type, "geo.location");

        let response = post_owntracks(
            gateway,
            authenticated_headers("application/json"),
            Body::from(
                &br#"{"_type":"location","lat":37.7749,"lon":-122.4194,"tst":901,"batt":90}"#[..],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(notices.recv().await.unwrap().event_type, "geo.location");
    }

    #[tokio::test]
    async fn duplicate_is_successful_without_a_second_notice_and_revocation_denies() {
        const OWNER_KEY: [u8; 32] = [7; 32];
        let gateway = Gateway::new_with_owntracks_ingress_for_test(enrolled_store(), OWNER_KEY);
        let mut notices = gateway.subscribe();
        let response = post_owntracks(
            gateway.clone(),
            authenticated_headers("application/json"),
            location_body(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(notices.recv().await.unwrap().event_type, "geo.location");

        let response = post_owntracks(
            gateway,
            authenticated_headers("application/json"),
            location_body(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(notices.try_recv().is_err());

        let mut revoked_store = enrolled_store();
        revoked_store.revoke_owntracks_enrollment().unwrap();
        let response = post_owntracks(
            Gateway::new_with_owntracks_ingress_for_test(revoked_store, OWNER_KEY),
            authenticated_headers("application/json"),
            location_body(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rate_limit_response_is_retryable_after_authentication() {
        const OWNER_KEY: [u8; 32] = [7; 32];
        let handle = [0; 32];
        let secret = [17; 32];
        let mut material = Vec::with_capacity(96);
        material.extend_from_slice(b"pigloros/owntracks/verifier/v1\0");
        material.extend_from_slice(&handle);
        material.extend_from_slice(&secret);
        let mut store = pos_store::memory::MemoryStore::new();
        let timeline = store.create_timeline("owntracks-rate-http").unwrap();
        store
            .pair_owntracks_enrollment(OwnTracksEnrollmentRequestV1::new(
                timeline.id(),
                EntityId::new(),
                GeoLocationAdmissionFenceV1::new(1, ([1; 32], 2, [2; 32]), (1, false, 3)),
                *blake3::keyed_hash(&OWNER_KEY, &material).as_bytes(),
            ))
            .unwrap();
        let gateway = Gateway::new_with_owntracks_ingress_for_test(store, OWNER_KEY);

        for _ in 0..5 {
            let response = post_owntracks(
                gateway.clone(),
                authenticated_headers("application/json"),
                location_body(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
        }
        let response = post_owntracks(
            gateway,
            authenticated_headers("application/json"),
            location_body(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "1");
    }
}
