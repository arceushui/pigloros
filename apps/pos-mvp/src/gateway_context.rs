//! Optional shared-world context for Wave 7 decision preview (ADR-015).
//!
//! Polls `piglor-gateway` for `society.signal` events and nudges preferences.

use std::collections::HashMap;

const NUDGE_SCALE: f64 = 0.25;

/// Society dimension means extracted from gateway event poll (`dimension` → mean `value`).
pub fn society_means_from_events(events: &[serde_json::Value]) -> HashMap<String, f64> {
    let mut sums: HashMap<String, f64> = HashMap::new();
    let mut counts: HashMap<String, u32> = HashMap::new();

    for event in events {
        if event.get("event_type").and_then(serde_json::Value::as_str) != Some("society.signal") {
            continue;
        }
        let Some(payload) = event.get("payload") else {
            continue;
        };
        let Some(dim) = payload.get("dimension").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(value) = payload
            .get("value")
            .and_then(serde_json::Value::as_f64)
            .filter(|v| v.is_finite())
        else {
            continue;
        };
        let key = dim.to_ascii_lowercase();
        *sums.entry(key).or_insert(0.0) += value;
        *counts.entry(dim.to_ascii_lowercase()).or_insert(0) += 1;
    }

    sums.into_iter()
        .filter_map(|(dim, sum)| {
            let n = counts.get(&dim).copied().unwrap_or(0);
            (n > 0).then_some((dim, sum / f64::from(n)))
        })
        .collect()
}

/// Nudge preferences that share a key with a society dimension mean.
pub fn apply_society_context(prefs: &mut [(String, f64)], means: &HashMap<String, f64>) {
    for (dim, mean) in means {
        let nudge = (mean - 0.5) * NUDGE_SCALE;
        if let Some((_, v)) = prefs.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(dim)) {
            *v = (*v + nudge).clamp(-1.0, 1.0);
        }
    }
}

/// Poll gateway for society signal means. `gateway` is base URL (e.g. `http://127.0.0.1:8080`).
pub fn fetch_society_means(
    gateway: &str,
    timeline_id: &str,
) -> Result<HashMap<String, f64>, String> {
    let base = gateway.trim_end_matches('/');
    let url = format!("{base}/v1/timelines/{timeline_id}/events?from_seq=0");
    let response = ureq::get(&url)
        .call()
        .map_err(|e| format!("gateway GET failed: {e}"))?;
    let body: serde_json::Value = response
        .into_json()
        .map_err(|e| format!("gateway JSON parse failed: {e}"))?;
    let events = body
        .get("events")
        .and_then(serde_json::Value::as_array)
        .map_or(&[] as &[serde_json::Value], Vec::as_slice);
    Ok(society_means_from_events(events))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn society_means_from_fixture() {
        let events = vec![
            serde_json::json!({
                "event_type": "society.signal",
                "payload": { "dimension": "trust", "value": 0.8 }
            }),
            serde_json::json!({
                "event_type": "society.signal",
                "payload": { "dimension": "trust", "value": 0.6 }
            }),
            serde_json::json!({
                "event_type": "world.action",
                "payload": { "dx": 1 }
            }),
            serde_json::json!({
                "event_type": "society.signal",
                "payload": { "dimension": "trust", "value": "nope" }
            }),
        ];
        let means = society_means_from_events(&events);
        assert!((means["trust"] - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn apply_society_context_nudges_matching_pref() {
        let mut prefs = vec![("trust".to_owned(), 0.5), ("food".to_owned(), 0.9)];
        let mut means = HashMap::new();
        means.insert("trust".to_owned(), 0.9);
        apply_society_context(&mut prefs, &means);
        assert!(prefs[0].1 > 0.5);
        assert!((prefs[1].1 - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn apply_society_context_ignores_unmatched_dimensions() {
        let mut prefs = vec![("food".to_owned(), 0.5)];
        let mut means = HashMap::new();
        means.insert("trust".to_owned(), 0.9);
        apply_society_context(&mut prefs, &means);
        assert!((prefs[0].1 - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn fetch_society_means_trims_trailing_slash() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = r#"{"events":[{"event_type":"society.signal","payload":{"dimension":"trust","value":0.9}}]}"#;
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.read(&mut [0u8; 1024]);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });
        let means =
            fetch_society_means(&format!("http://{addr}/"), "01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
        assert!((means["trust"] - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn fetch_society_means_parses_mock_http() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = r#"{"events":[{"event_type":"society.signal","payload":{"dimension":"trust","value":0.9}}]}"#;
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.read(&mut [0u8; 1024]);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });
        let means =
            fetch_society_means(&format!("http://{addr}"), "01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
        assert!((means["trust"] - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn fetch_society_means_treats_missing_events_as_empty() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = r"{}";
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.read(&mut [0u8; 1024]);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });
        let means =
            fetch_society_means(&format!("http://{addr}"), "01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
        assert!(means.is_empty());
    }

    #[test]
    fn fetch_society_means_rejects_non_success_status() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.read(&mut [0u8; 1024]);
            let response =
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(response.as_bytes());
        });
        let err = fetch_society_means(&format!("http://{addr}"), "01ARZ3NDEKTSV4RRFFQ69G5FAV")
            .unwrap_err();
        assert!(err.contains("404"), "{err}");
    }

    #[test]
    fn fetch_society_means_rejects_invalid_json() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.read(&mut [0u8; 1024]);
            let body = "not-json";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });
        let err = fetch_society_means(&format!("http://{addr}"), "01ARZ3NDEKTSV4RRFFQ69G5FAV")
            .unwrap_err();
        assert!(err.contains("JSON"), "{err}");
    }

    #[test]
    fn society_means_skips_non_finite_and_missing_fields() {
        let events = vec![
            serde_json::json!({"event_type": "society.signal"}),
            serde_json::json!({
                "event_type": "society.signal",
                "payload": { "value": 0.5 }
            }),
            serde_json::json!({
                "event_type": "society.signal",
                "payload": { "dimension": "trust", "value": "nope" }
            }),
        ];
        assert!(society_means_from_events(&events).is_empty());
    }

    #[test]
    fn fetch_society_means_rejects_bad_status() {
        let err = fetch_society_means("http://127.0.0.1:1", "01ARZ3NDEKTSV4RRFFQ69G5FAV")
            .expect_err("unreachable port");
        assert!(err.contains("gateway") || err.contains("failed"));
    }
}
