//! Optional shared-world context for Wave 7 decision preview (ADR-015).
//!
//! Polls `piglor-gateway` for timeline events: society means + AI Influence Index (#79).

use crate::ai_influence::{ai_influence_from_events, AiInfluenceIndex};
use std::collections::HashMap;
use std::io::Read;
use std::time::Duration;

const NUDGE_SCALE: f64 = 0.25;
/// Overall HTTP deadline for gateway poll (connect + read).
const GATEWAY_HTTP_TIMEOUT: Duration = Duration::from_secs(10);
/// Cap response body size (matches gateway write limit).
const MAX_GATEWAY_BODY_BYTES: u64 = 1024 * 1024;
const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Map society dimensions onto default scenario preference keys so ADR demos
/// (`places` / `work`) actually change scores without `--prefer trust=…`.
fn society_pref_aliases(dim: &str) -> &'static [&'static str] {
    match dim {
        "trust" => &["quiet", "focus"],
        "opinion" => &["city", "collaboration"],
        "economy" => &["food", "energy"],
        "culture" => &["nature", "autonomy"],
        "polarization" => &["collaboration", "energy"],
        _ => &[],
    }
}

/// Society dimension means extracted from gateway event poll (`dimension` → mean `value`).
///
/// Sample values and resulting means are clamped to `[0, 1]` (society semantics).
pub(crate) fn society_means_from_events(events: &[serde_json::Value]) -> HashMap<String, f64> {
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
        let value = value.clamp(0.0, 1.0);
        let key = dim.to_ascii_lowercase();
        *sums.entry(key.clone()).or_insert(0.0) += value;
        *counts.entry(key).or_insert(0) += 1;
    }

    sums.into_iter()
        .map(|(dim, sum)| {
            let n = counts[&dim];
            (dim, (sum / f64::from(n)).clamp(0.0, 1.0))
        })
        .collect()
}

/// Nudge preferences for matching keys **and** society→scenario aliases.
///
/// Each preference key is adjusted **once** by the average of all contributing
/// society nudges (exact dim match + aliases), so overlapping aliases
/// (`opinion`/`polarization` → `collaboration`) do not stack additively.
pub(crate) fn apply_society_context(prefs: &mut [(String, f64)], means: &HashMap<String, f64>) {
    let mut by_pref: HashMap<String, Vec<f64>> = HashMap::new();
    for (dim, mean) in means {
        let nudge = (*mean - 0.5) * NUDGE_SCALE;
        let mut targets: Vec<&str> = vec![dim.as_str()];
        targets.extend(society_pref_aliases(dim));
        targets.sort_unstable();
        targets.dedup();
        for target in targets {
            by_pref
                .entry(target.to_ascii_lowercase())
                .or_default()
                .push(nudge);
        }
    }
    for (key, values) in by_pref {
        let avg = average_f64(&values);
        if let Some((_, v)) = prefs.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(&key)) {
            *v = (*v + avg).clamp(-1.0, 1.0);
        }
    }
}

fn average_f64(values: &[f64]) -> f64 {
    match values {
        [] => 0.0,
        [only] => *only,
        many => {
            let sum: f64 = many.iter().sum();
            let mut n = 0.0_f64;
            for _ in many {
                n += 1.0;
            }
            sum / n
        }
    }
}

/// Plain-language lines for society means (#76 / ADR-015 follow-on).
///
/// Covers society dimensions (`trust`, `opinion`, `economy`, `culture`,
/// `polarization`) plus any other keys as generic preference-context hints.
#[must_use]
pub(crate) fn plain_language_context(means: &HashMap<String, f64>) -> Vec<String> {
    let mut dims: Vec<(&String, f64)> = means.iter().map(|(k, v)| (k, *v)).collect();
    dims.sort_by(|a, b| a.0.cmp(b.0));
    dims.into_iter()
        .map(|(dim, mean)| describe_dimension(dim, mean))
        .collect()
}

fn describe_dimension(dim: &str, mean: f64) -> String {
    let level = intensity_word(mean);
    match dim.to_ascii_lowercase().as_str() {
        "trust" => format!(
            "Trust in the shared world looks {level} (mean {mean:.2}) — weigh how much you rely on others' signals."
        ),
        "opinion" => format!(
            "Public opinion around this choice is {level} (mean {mean:.2}) — expect the crowd to lean that way."
        ),
        "economy" => format!(
            "Economic conditions read {level} (mean {mean:.2}) — resource and cost pressure may matter."
        ),
        "culture" => format!(
            "Cultural mood is {level} (mean {mean:.2}) — norms and identity cues may shape fit."
        ),
        "polarization" => format!(
            "Polarization is {level} (mean {mean:.2}) — disagreement may be sharp; pick carefully."
        ),
        other => format!(
            "Shared signal '{other}' is {level} (mean {mean:.2}) — preferences with this key may be nudged."
        ),
    }
}

fn intensity_word(mean: f64) -> &'static str {
    if mean >= 0.75 {
        "strong"
    } else if mean >= 0.55 {
        "elevated"
    } else if mean >= 0.45 {
        "balanced"
    } else if mean >= 0.25 {
        "soft"
    } else {
        "weak"
    }
}

/// Reject non-ULID timeline ids before interpolating into the URL path.
pub(crate) fn validate_timeline_id(timeline_id: &str) -> Result<(), String> {
    ulid::Ulid::from_string(timeline_id)
        .map(|_| ())
        .map_err(|e| format!("invalid timeline id (expected ULID): {e}"))
}

/// True when the gateway base URL's host is loopback (`127.0.0.1`, `localhost`, `::1`).
///
/// Parses scheme/userinfo/port carefully so hosts like `127.0.0.1.evil` are not treated
/// as loopback (substring match would incorrectly skip the ADR-015 warning).
fn gateway_host_is_loopback(gateway: &str) -> bool {
    let s = gateway.trim();
    // Normalize scheme case so `HTTP://` matches; then strip once.
    let lower = s.to_ascii_lowercase();
    let without_scheme = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))
        .unwrap_or(lower.as_str());
    let authority = without_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(rest) = hostport.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        // IPv4 / hostname: strip `:port` from the right once.
        hostport.rsplit_once(':').map_or(hostport, |(h, _)| h)
    };
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

fn warn_if_non_loopback(gateway: &str) {
    if !gateway_host_is_loopback(gateway) {
        eprintln!(
            "Warning: gateway URL is not loopback — ADR-015 demos assume local-only (no auth)."
        );
    }
}

/// Society means + AI Influence from one gateway poll.
pub(crate) struct TimelineContext {
    pub society_means: HashMap<String, f64>,
    pub ai_influence: AiInfluenceIndex,
}

/// One HTTP poll → society means and AI Influence Index (#79).
///
/// Hardening: ULID path validation, 10s overall timeout, no redirects, 1 MiB body cap.
pub(crate) fn fetch_timeline_context(
    gateway: &str,
    timeline_id: &str,
) -> Result<TimelineContext, String> {
    let events = fetch_gateway_events(gateway, timeline_id)?;
    Ok(TimelineContext {
        society_means: society_means_from_events(&events),
        ai_influence: ai_influence_from_events(&events),
    })
}

/// Poll gateway event list. `gateway` is base URL (e.g. `http://127.0.0.1:8080`).
fn fetch_gateway_events(
    gateway: &str,
    timeline_id: &str,
) -> Result<Vec<serde_json::Value>, String> {
    validate_timeline_id(timeline_id)?;
    warn_if_non_loopback(gateway);

    let base = gateway.trim_end_matches('/');
    // ULID charset is path-safe; still percent-encode for defense in depth.
    let encoded = urlencoding_path_segment(timeline_id);
    let url = format!("{base}/v1/timelines/{encoded}/events?from_seq=0");

    let agent = ureq::AgentBuilder::new()
        .timeout(GATEWAY_HTTP_TIMEOUT)
        .redirects(0)
        .build();
    let response = agent
        .get(&url)
        .call()
        .map_err(|e| format!("gateway GET failed: {e}"))?;
    let status = response.status();
    if !(200..300).contains(&status) {
        return Err(format!("gateway returned HTTP {status}"));
    }

    let mut reader = response.into_reader();
    let bytes = read_capped_body(&mut reader, MAX_GATEWAY_BODY_BYTES)?;
    let body = String::from_utf8(bytes).map_err(|e| format!("gateway body not UTF-8: {e}"))?;

    let body: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("gateway JSON parse failed: {e}"))?;
    let events = body
        .get("events")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(events)
}

fn read_capped_body(reader: &mut dyn Read, max_bytes: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("gateway body read failed: {e}"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!(
            "gateway body too large: exceeded {max_bytes} bytes"
        ));
    }
    Ok(bytes)
}

/// Percent-encode a single path segment (ULIDs pass through unchanged).
fn urlencoding_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(b));
            }
            _ => {
                out.push('%');
                out.push(char::from(HEX[(b >> 4) as usize]));
                out.push(char::from(HEX[(b & 0xf) as usize]));
            }
        }
    }
    out
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn fetch_society_means(
        gateway: &str,
        timeline_id: &str,
    ) -> Result<HashMap<String, f64>, String> {
        Ok(fetch_timeline_context(gateway, timeline_id)?.society_means)
    }

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
    fn society_means_clamps_out_of_range_samples() {
        let events = vec![
            serde_json::json!({
                "event_type": "society.signal",
                "payload": { "dimension": "trust", "value": 2.5 }
            }),
            serde_json::json!({
                "event_type": "society.signal",
                "payload": { "dimension": "opinion", "value": -1.0 }
            }),
        ];
        let means = society_means_from_events(&events);
        assert!((means["trust"] - 1.0).abs() < f64::EPSILON);
        assert!((means["opinion"] - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn plain_language_covers_society_dimensions_and_generic() {
        let mut means = HashMap::new();
        means.insert("trust".to_owned(), 0.9);
        means.insert("opinion".to_owned(), 0.6);
        means.insert("economy".to_owned(), 0.5);
        means.insert("culture".to_owned(), 0.3);
        means.insert("polarization".to_owned(), 0.1);
        means.insert("nature".to_owned(), 0.8);
        let lines = plain_language_context(&means);
        assert_eq!(lines.len(), 6);
        assert!(lines
            .iter()
            .any(|l| l.contains("Trust") && l.contains("strong")));
        assert!(lines
            .iter()
            .any(|l| l.contains("Public opinion") && l.contains("elevated")));
        assert!(lines
            .iter()
            .any(|l| l.contains("Economic") && l.contains("balanced")));
        assert!(lines
            .iter()
            .any(|l| l.contains("Cultural") && l.contains("soft")));
        assert!(lines
            .iter()
            .any(|l| l.contains("Polarization") && l.contains("weak")));
        assert!(lines
            .iter()
            .any(|l| l.contains("'nature'") && l.contains("strong")));
    }

    #[test]
    fn average_f64_handles_empty_and_values() {
        assert!((average_f64(&[]) - 0.0).abs() < f64::EPSILON);
        assert!((average_f64(&[0.4]) - 0.4).abs() < f64::EPSILON);
        assert!((average_f64(&[0.2, 0.4]) - 0.3).abs() < f64::EPSILON);
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
    fn apply_society_context_hits_all_alias_families() {
        let mut prefs = vec![
            ("quiet".to_owned(), 0.5),
            ("focus".to_owned(), 0.5),
            ("city".to_owned(), 0.5),
            ("collaboration".to_owned(), 0.5),
            ("food".to_owned(), 0.5),
            ("energy".to_owned(), 0.5),
            ("nature".to_owned(), 0.5),
            ("autonomy".to_owned(), 0.5),
        ];
        let mut means = HashMap::new();
        means.insert("trust".to_owned(), 0.9);
        means.insert("opinion".to_owned(), 0.9);
        means.insert("economy".to_owned(), 0.9);
        means.insert("culture".to_owned(), 0.9);
        means.insert("polarization".to_owned(), 0.9);
        apply_society_context(&mut prefs, &means);
        assert!(prefs.iter().all(|(_, v)| *v > 0.5));
    }

    #[test]
    fn apply_society_context_averages_overlapping_aliases() {
        let mut prefs = vec![("collaboration".to_owned(), 0.5)];
        let mut means = HashMap::new();
        // Both map to collaboration with the same mean → one averaged nudge, not 2×.
        means.insert("opinion".to_owned(), 0.9);
        means.insert("polarization".to_owned(), 0.9);
        apply_society_context(&mut prefs, &means);
        let expected = 0.5 + (0.9 - 0.5) * NUDGE_SCALE;
        assert!(
            (prefs[0].1 - expected).abs() < 1e-9,
            "got {} want {expected} (no double stack)",
            prefs[0].1
        );
    }

    #[test]
    fn apply_society_context_maps_trust_onto_places_quiet() {
        let mut prefs = vec![
            ("nature".to_owned(), 0.8),
            ("city".to_owned(), 0.5),
            ("food".to_owned(), 0.9),
            ("quiet".to_owned(), 0.7),
        ];
        let mut means = HashMap::new();
        means.insert("trust".to_owned(), 0.9);
        let before = prefs[3].1;
        apply_society_context(&mut prefs, &means);
        assert!(prefs[3].1 > before, "quiet should rise via trust alias");
    }

    #[test]
    fn apply_society_context_maps_trust_onto_work_focus() {
        let mut prefs = vec![
            ("autonomy".to_owned(), 0.8),
            ("focus".to_owned(), 0.7),
            ("collaboration".to_owned(), 0.5),
            ("energy".to_owned(), 0.6),
        ];
        let mut means = HashMap::new();
        means.insert("trust".to_owned(), 0.9);
        let before = prefs[1].1;
        apply_society_context(&mut prefs, &means);
        assert!(prefs[1].1 > before, "focus should rise via trust alias");
    }

    #[test]
    fn gateway_signal_to_places_score_changes() {
        let events = vec![serde_json::json!({
            "event_type": "society.signal",
            "payload": { "dimension": "culture", "value": 0.95 }
        })];
        let means = society_means_from_events(&events);
        let mut prefs = vec![
            ("nature".to_owned(), 0.5),
            ("city".to_owned(), 0.5),
            ("food".to_owned(), 0.5),
            ("quiet".to_owned(), 0.5),
        ];
        let model_before = pos_plugin_persona::PersonaModel::new(prefs.clone());
        let score_before = model_before.score_option("kyoto nature quiet temples");
        apply_society_context(&mut prefs, &means);
        let model_after = pos_plugin_persona::PersonaModel::new(prefs);
        let score_after = model_after.score_option("kyoto nature quiet temples");
        assert!(
            score_after > score_before,
            "culture→nature alias should lift Kyoto score ({score_before} → {score_after})"
        );
    }

    #[test]
    fn apply_society_context_ignores_unmatched_dimensions() {
        let mut prefs = vec![("food".to_owned(), 0.5)];
        let mut means = HashMap::new();
        means.insert("unmapped_dim".to_owned(), 0.9);
        apply_society_context(&mut prefs, &means);
        assert!((prefs[0].1 - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn validate_timeline_id_accepts_ulid() {
        validate_timeline_id("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
    }

    #[test]
    fn validate_timeline_id_rejects_path_injection() {
        let err = validate_timeline_id("../evil").unwrap_err();
        assert!(err.contains("invalid timeline"), "{err}");
        let err = validate_timeline_id("not a ulid").unwrap_err();
        assert!(err.contains("invalid timeline"), "{err}");
    }

    #[test]
    fn urlencoding_leaves_ulid_unchanged() {
        let id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        assert_eq!(urlencoding_path_segment(id), id);
        assert!(urlencoding_path_segment("a/b").contains('%'));
    }

    #[test]
    fn fetch_timeline_context_includes_ai_influence() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = r#"{"events":[
            {"event_type":"society.signal","payload":{"dimension":"trust","value":0.9}},
            {"event_type":"agent.action","payload":{"action":"nudge"}},
            {"event_type":"world.action","payload":{}}
        ]}"#;
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.read(&mut [0u8; 1024]);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });
        let ctx = fetch_timeline_context(&format!("http://{addr}"), "01ARZ3NDEKTSV4RRFFQ69G5FAV")
            .unwrap();
        assert!((ctx.society_means["trust"] - 0.9).abs() < f64::EPSILON);
        assert_eq!(ctx.ai_influence.total_events, 3);
        assert_eq!(ctx.ai_influence.ai_events, 1);
        assert!((ctx.ai_influence.index - (1.0 / 3.0)).abs() < 1e-9);
    }

    #[test]
    fn fetch_society_means_rejects_bad_timeline_id() {
        let err = fetch_society_means("http://127.0.0.1:8080", "bad").unwrap_err();
        assert!(err.contains("invalid timeline"), "{err}");
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
    fn fetch_society_means_rejects_redirect_status() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = r#"{"events":[{"event_type":"society.signal","payload":{"dimension":"trust","value":0.9}}]}"#;
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.read(&mut [0u8; 1024]);
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });
        let err = fetch_society_means(&format!("http://{addr}"), "01ARZ3NDEKTSV4RRFFQ69G5FAV")
            .unwrap_err();
        assert!(err.contains("HTTP 302"), "{err}");
    }

    #[test]
    fn fetch_society_means_rejects_non_utf8_body() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.read(&mut [0u8; 1024]);
            let bytes =
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n\xff\xfe";
            let _ = stream.write_all(bytes);
        });
        let err = fetch_society_means(&format!("http://{addr}"), "01ARZ3NDEKTSV4RRFFQ69G5FAV")
            .unwrap_err();
        assert!(err.contains("UTF-8"), "{err}");
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
    fn read_capped_body_maps_io_errors() {
        struct FailRead;
        impl Read for FailRead {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("boom"))
            }
        }
        let mut fail = FailRead;
        let err = read_capped_body(&mut fail, 64).unwrap_err();
        assert!(err.contains("read failed"), "{err}");
    }

    #[test]
    fn read_capped_body_ok_and_too_large() {
        let mut ok = &b"hi"[..];
        assert_eq!(read_capped_body(&mut ok, 10).unwrap(), b"hi");
        let big = vec![b'x'; 20];
        let mut reader = big.as_slice();
        let err = read_capped_body(&mut reader, 8).unwrap_err();
        assert!(err.contains("too large"), "{err}");
    }

    #[test]
    fn fetch_society_means_rejects_oversized_body() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // Omit Content-Length so the client reads until close; send > 1 MiB.
        let oversized = "x".repeat(usize::try_from(MAX_GATEWAY_BODY_BYTES).unwrap() + 8);
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.read(&mut [0u8; 1024]);
            let response = format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{oversized}");
            let _ = stream.write_all(response.as_bytes());
        });
        let err = fetch_society_means(&format!("http://{addr}"), "01ARZ3NDEKTSV4RRFFQ69G5FAV")
            .unwrap_err();
        assert!(err.contains("too large"), "{err}");
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

    #[test]
    fn warn_if_non_loopback_runs() {
        warn_if_non_loopback("http://127.0.0.1:8080");
        warn_if_non_loopback("http://localhost:8080");
        warn_if_non_loopback("http://[::1]:8080");
        warn_if_non_loopback("http://example.com:8080");
    }

    #[test]
    fn gateway_host_is_loopback_exact_hosts_only() {
        assert!(gateway_host_is_loopback("http://127.0.0.1:8080"));
        assert!(gateway_host_is_loopback("https://localhost"));
        assert!(gateway_host_is_loopback("HTTP://LOCALHOST:9"));
        assert!(gateway_host_is_loopback("http://[::1]:8080/v1"));
        assert!(gateway_host_is_loopback("http://user@127.0.0.1:9"));
        assert!(gateway_host_is_loopback("127.0.0.1:8080"));
        assert!(gateway_host_is_loopback("http://127.0.0.1:8080?x=1"));
        assert!(!gateway_host_is_loopback("http://127.0.0.1.evil:8080"));
        assert!(!gateway_host_is_loopback("http://example.com:8080"));
        assert!(!gateway_host_is_loopback("http://notlocalhost:8080"));
        assert!(!gateway_host_is_loopback(""));
    }
}
