//! Strict local HTTP decoding for V1 `OwnTracks` ingress.

use crate::{executor::OwnTracksIngressOutcome, Gateway, GatewayError};
use axum::{
    body::{to_bytes, Body},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use pos_core::{CanonicalBytes, CoreError, OwnTracksIngressInputV1};
use pos_plugin_geo::{GeoLocationPayload, SpatialCloaker, Wgs84Point};
use serde::Deserialize;

pub(crate) const OWNTRACKS_MAX_BODY_BYTES: usize = 65_536;

#[derive(Deserialize)]
struct LocationV1 {
    #[serde(rename = "_type")]
    kind: String,
    lat: f64,
    lon: f64,
    tst: serde_json::Number,
}

pub(crate) async fn post_owntracks(
    gateway: Gateway,
    owner_key: [u8; 32],
    headers: HeaderMap,
    body: Body,
) -> Response {
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
    let Some(payload) = minimize_location(&bytes) else {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_location");
    };
    match gateway
        .admit_owntracks_ingress(OwnTracksIngressInputV1::new(
            owner_key, handle, secret, payload,
        ))
        .await
    {
        Ok(OwnTracksIngressOutcome::RateLimited) => {
            let mut response = error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
            response.headers_mut().insert(
                header::RETRY_AFTER,
                "1".parse().expect("static Retry-After value"),
            );
            response
        }
        Ok(OwnTracksIngressOutcome::Admitted { outcome, .. })
            if outcome.is_accepted() || outcome.is_duplicate() =>
        {
            (StatusCode::OK, "[]").into_response()
        }
        Ok(OwnTracksIngressOutcome::Admitted { .. })
        | Err(GatewayError::Store(CoreError::GeographicAdmissionValidationFailed)) => {
            error(StatusCode::FORBIDDEN, "forbidden")
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

fn minimize_location(bytes: &[u8]) -> Option<CanonicalBytes> {
    let location: LocationV1 = serde_json::from_slice(bytes).ok()?;
    if location.kind != "location"
        || (location.tst.as_i64().is_none() && location.tst.as_u64().is_none())
    {
        return None;
    }
    let point = Wgs84Point::new(location.lat, location.lon).ok()?;
    let cell = SpatialCloaker::new(0.1).ok()?.cloak(point);
    let payload = GeoLocationPayload {
        cell_lat: cell.latitude(),
        cell_lng: cell.longitude(),
        resolution: 0.1,
    };
    let mut canonical = Vec::new();
    ciborium::into_writer(&payload, &mut canonical).ok()?;
    Some(CanonicalBytes::from_vec(canonical))
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
    use pos_plugin_geo::GeoLocationPayload;
    use pos_store::{open_store, StoreConfig};

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

    #[test]
    fn minimization_discards_extra_telemetry_and_rejects_invalid_locations() {
        let payload = minimize_location(
            br#"{"_type":"location","lat":37.7749,"lon":-122.4194,"tst":1,"acc":2,"tid":"x"}"#,
        )
        .unwrap();
        let location: GeoLocationPayload = ciborium::from_reader(payload.as_slice()).unwrap();
        assert!((location.resolution - 0.1).abs() < f64::EPSILON);
        assert!((location.cell_lat - 37.7749).abs() > f64::EPSILON);
        assert!(minimize_location(br#"{"_type":"location","lat":91,"lon":0,"tst":1}"#).is_none());
        assert!(minimize_location(br#"{"_type":"location","lat":0,"lon":0,"tst":1.5}"#).is_none());
    }

    #[tokio::test]
    async fn empty_body_is_the_only_unauthenticated_success() {
        let response = post_owntracks(
            Gateway::new(open_store(StoreConfig::Memory).unwrap()),
            [0; 32],
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
    async fn oversized_body_is_rejected_before_authentication() {
        let response = post_owntracks(
            Gateway::new(open_store(StoreConfig::Memory).unwrap()),
            [0; 32],
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
        let credential = format!("{}:{}", "0".repeat(64), "1".repeat(64));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", base64_encode(&credential))).unwrap(),
        );
        let response = post_owntracks(
            Gateway::new_with_owntracks_ingress(store),
            OWNER_KEY,
            headers,
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
    }
}
