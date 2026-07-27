//! Zero-JS static HTML renderer (ADR-017 Decision 3, Decision 7).
//!
//! Hand-rolled escaping — no template engine — and byte-deterministic
//! output for a given [`LedgerView`]. The page is self-contained (no
//! external CSS or fonts) so it can be hosted anywhere with relative URLs.

use std::fmt::Write as _;

use pos_plugin_ledger::{LedgerEntryView, LedgerView};

/// HTML-escape a string. Covers the five XML special characters.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Format a confidence in `[0.0, 1.0]` as a percent with one decimal (`80.0%`).
fn fmt_confidence(p: f64) -> String {
    format!("{:.1}%", p * 100.0)
}

/// Format a Brier Score with three decimals (`0.040`).
fn fmt_brier(p: f64) -> String {
    format!("{p:.3}")
}

/// Render the HTML page for a [`LedgerView`].
///
/// `pubkey_hex` is printed in the footer when `Some`; `None` produces a
/// note that the demo tier carries no signatures (ADR-017 Decision 5b).
#[must_use]
pub fn render_html(view: &LedgerView, pubkey_hex: Option<&str>) -> String {
    let mut s = String::with_capacity(2048);
    s.push_str("<!DOCTYPE html>\n");
    s.push_str("<html lang=\"en\">\n");
    s.push_str("<head>\n");
    s.push_str("<meta charset=\"utf-8\">\n");
    s.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    s.push_str("<title>Prediction Ledger</title>\n");
    s.push_str("<style>\n");
    s.push_str("body{font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;max-width:48rem;margin:2rem auto;padding:0 1rem;color:#222;}\n");
    s.push_str("h1{font-size:1.6rem;margin:0 0 .25rem;}\n");
    s.push_str(".headline{color:#555;margin:0 0 1rem;}\n");
    s.push_str(".entries{display:flex;flex-direction:column;gap:1rem;}\n");
    s.push_str(".entry{border:1px solid #ddd;border-radius:.4rem;padding:1rem;}\n");
    s.push_str(".entry.overdue{border-color:#d11;background:#fee;}\n");
    s.push_str(".entry.resolved{border-color:#1a8;background:#efe;}\n");
    s.push_str(".badge{display:inline-block;font-size:.75rem;padding:.1rem .45rem;border-radius:.3rem;background:#444;color:#fff;margin-left:.5rem;}\n");
    s.push_str(".badge.overdue{background:#d11;}\n");
    s.push_str(".badge.resolved{background:#1a8;}\n");
    s.push_str(".meta{color:#666;font-size:.85rem;}\n");
    s.push_str("footer{margin-top:2rem;border-top:1px solid #ddd;padding-top:1rem;color:#666;font-size:.85rem;}\n");
    s.push_str("code{background:#f4f4f4;padding:.1rem .3rem;border-radius:.2rem;}\n");
    s.push_str("</style>\n");
    s.push_str("</head>\n");
    s.push_str("<body>\n");
    s.push_str("<main>\n");
    s.push_str("<h1>Prediction Ledger</h1>\n");

    // Headline (ADR-017 Decision 7): counts always; mean Brier only when
    // n_resolved >= 1, otherwise the explicit "no Brier Score yet" copy.
    s.push_str("<p class=\"headline\">");
    let _ = write!(
        s,
        "{} pending / {} resolved",
        view.n_pending + view.n_overdue,
        view.n_resolved
    );
    if view.n_overdue > 0 {
        let _ = write!(s, " ({} overdue)", view.n_overdue);
    }
    match view.mean_brier {
        Some(b) => {
            let _ = write!(
                s,
                " — mean Brier Score: {} (n={})",
                fmt_brier(b),
                view.n_resolved
            );
        }
        None => s.push_str(" — no Brier Score yet"),
    }
    s.push_str("</p>\n");

    // Entries.
    s.push_str("<section class=\"entries\">\n");
    for entry in &view.entries {
        render_entry(&mut s, entry);
    }
    s.push_str("</section>\n");

    // Footer with verification instructions + committed pubkey.
    s.push_str("<footer>\n");
    s.push_str("<p>Verify each entry matches its OSF registration</p>\n");
    match pubkey_hex {
        Some(pk) => {
            let _ = writeln!(s, "<p>Public key: <code>{}</code></p>", esc(pk));
        }
        None => s.push_str("<p>Demo tier (TOML): entries are unsigned; verify with <code>b3sum</code> on the TOML files.</p>\n"),
    }
    s.push_str("</footer>\n");
    s.push_str("</main>\n");
    s.push_str("</body>\n");
    s.push_str("</html>\n");
    s
}

fn render_entry(s: &mut String, entry: &LedgerEntryView) {
    s.push_str("<article class=\"entry ");
    s.push_str(entry.status.as_str());
    s.push_str("\">\n");

    s.push_str("<h2>");
    s.push_str(&esc(&entry.title));
    s.push_str("</h2>\n");

    s.push_str("<p>");
    s.push_str(&esc(&entry.statement));
    s.push_str("</p>\n");

    s.push_str("<p class=\"meta\">Predicting: <strong>");
    s.push_str(&esc(&entry.predicted_outcome));
    s.push_str("</strong> · confidence: ");
    s.push_str(&fmt_confidence(entry.confidence));
    if let Some(scenario) = &entry.scenario {
        s.push_str(" · scenario: ");
        s.push_str(&esc(scenario));
    }
    s.push_str("</p>\n");

    s.push_str("<p class=\"meta\">Registered ");
    s.push_str(&esc(&entry.made_at));
    s.push_str(" · resolves by ");
    s.push_str(&esc(&entry.resolve_by));
    s.push_str(" · <a href=\"");
    s.push_str(&esc(&entry.osf_link));
    s.push_str("\">OSF</a></p>\n");

    s.push_str("<p class=\"meta\">Status: ");
    s.push_str(entry.status.as_str());
    s.push_str("<span class=\"badge ");
    s.push_str(entry.status.as_str());
    s.push_str("\">");
    s.push_str(entry.status.as_str());
    s.push_str("</span></p>\n");

    if entry.status == "resolved" {
        if let (Some(outcome), Some(at), Some(brier)) = (
            entry.outcome,
            entry.resolved_at.as_deref(),
            entry.brier_score,
        ) {
            s.push_str("<p class=\"meta\">Resolved ");
            s.push_str(&esc(at));
            s.push_str(" · outcome: ");
            s.push_str(if outcome { "occurred" } else { "did not occur" });
            s.push_str(" · Brier Score: ");
            s.push_str(&fmt_brier(brier));
            s.push_str("</p>\n");
        }
    }

    s.push_str("</article>\n");
}

/// Root `index.html` redirect to `/ledger` (HTML-only, zero-JS).
#[must_use]
pub fn render_redirect() -> String {
    let mut s = String::new();
    s.push_str("<!DOCTYPE html>\n");
    s.push_str("<html lang=\"en\">\n");
    s.push_str("<head>\n");
    s.push_str("<meta charset=\"utf-8\">\n");
    s.push_str("<meta http-equiv=\"refresh\" content=\"0; url=ledger/\">\n");
    s.push_str("<title>Prediction Ledger</title>\n");
    s.push_str("</head>\n");
    s.push_str("<body>\n");
    s.push_str("<p>Redirecting to <a href=\"ledger/\">Prediction Ledger</a>.</p>\n");
    s.push_str("</body>\n");
    s.push_str("</html>\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_plugin_ledger::LedgerEntryView;

    fn view(
        entries: Vec<LedgerEntryView>,
        n_pending: usize,
        n_overdue: usize,
        n_resolved: usize,
        mean_brier: Option<f64>,
    ) -> LedgerView {
        LedgerView {
            entries,
            n_pending,
            n_overdue,
            n_resolved,
            mean_brier,
            warnings: Vec::new(),
        }
    }

    fn pending_entry(id: &str, title: &str) -> LedgerEntryView {
        LedgerEntryView {
            id: id.to_owned(),
            title: title.to_owned(),
            statement: "Kyoto will be chosen".to_owned(),
            predicted_outcome: "Kyoto".to_owned(),
            confidence: 0.8,
            scenario: Some("places".to_owned()),
            status: "pending".to_owned(),
            brier_score: None,
            made_at: "2026-07-25T12:00:00Z".to_owned(),
            resolve_by: "2026-08-01".to_owned(),
            resolved_at: None,
            outcome: None,
            osf_link: "https://osf.io/example".to_owned(),
        }
    }

    fn resolved_entry(id: &str, brier: f64, outcome: bool) -> LedgerEntryView {
        let mut e = pending_entry(id, "Resolved");
        e.status = "resolved".to_owned();
        e.brier_score = Some(brier);
        e.resolved_at = Some("2026-07-30T09:00:00Z".to_owned());
        e.outcome = Some(outcome);
        e
    }

    fn overdue_entry(id: &str) -> LedgerEntryView {
        let mut e = pending_entry(id, "Past due");
        e.status = "overdue".to_owned();
        e
    }

    #[test]
    fn escape_html_special_chars() {
        assert_eq!(esc("safe"), "safe");
        assert_eq!(esc("<a>&'\""), "&lt;a&gt;&amp;&#39;&quot;");
        assert_eq!(esc("plain text 123"), "plain text 123");
    }

    #[test]
    fn confidence_and_brier_format() {
        assert_eq!(fmt_confidence(0.8), "80.0%");
        assert_eq!(fmt_confidence(0.0), "0.0%");
        assert_eq!(fmt_confidence(1.0), "100.0%");
        assert_eq!(fmt_brier(0.04), "0.040");
        assert_eq!(fmt_brier(0.34), "0.340");
        assert_eq!(fmt_brier(1.0), "1.000");
    }

    #[test]
    fn empty_state_says_no_brier_score_yet() {
        let v = view(vec![], 0, 0, 0, None);
        let html = render_html(&v, None);
        assert!(
            html.contains("0 pending / 0 resolved — no Brier Score yet"),
            "missing empty-state headline: {html}"
        );
        assert!(html.contains("Demo tier (TOML)"));
    }

    #[test]
    fn headline_shows_brier_when_resolved() {
        let v = view(vec![resolved_entry("id1", 0.04, true)], 0, 0, 1, Some(0.04));
        let html = render_html(&v, Some("deadbeef"));
        assert!(
            html.contains("0 pending / 1 resolved — mean Brier Score: 0.040 (n=1)"),
            "missing Brier headline: {html}"
        );
        assert!(html.contains("Public key: <code>deadbeef</code>"));
    }

    #[test]
    fn overdue_badge_shown_in_headline_and_entry() {
        let v = view(vec![overdue_entry("id1")], 0, 1, 0, None);
        let html = render_html(&v, None);
        assert!(
            html.contains("(1 overdue)"),
            "missing overdue count in headline: {html}"
        );
        assert!(html.contains("<article class=\"entry overdue\">"));
        assert!(html.contains("<span class=\"badge overdue\">overdue</span>"));
    }

    #[test]
    fn resolved_entry_displays_outcome_brier_and_status() {
        let v = view(vec![resolved_entry("id1", 0.04, true)], 0, 0, 1, Some(0.04));
        let html = render_html(&v, None);
        assert!(html.contains("outcome: occurred"));
        assert!(html.contains("Brier Score: 0.040"));
        assert!(html.contains("Status: resolved"));
    }

    #[test]
    fn negative_outcome_displays_did_not_occur() {
        let v = view(
            vec![resolved_entry("id1", 0.64, false)],
            0,
            0,
            1,
            Some(0.64),
        );
        let html = render_html(&v, None);
        assert!(html.contains("outcome: did not occur"));
        assert!(html.contains("Brier Score: 0.640"));
    }

    #[test]
    fn entries_are_html_escaped() {
        let mut e = pending_entry("id1", "<script>alert(1)</script>");
        e.statement = "A & B == <c>".to_owned();
        e.predicted_outcome = "x\"y".to_owned();
        let v = view(vec![e], 1, 0, 0, None);
        let html = render_html(&v, None);
        assert!(html.contains("<h2>&lt;script&gt;alert(1)&lt;/script&gt;</h2>"));
        assert!(html.contains("A &amp; B == &lt;c&gt;"));
        assert!(html.contains("<strong>x&quot;y</strong>"));
        // Raw '<script>' must not survive into the page.
        assert!(!html.contains("<script>alert"));
    }

    #[test]
    fn osf_link_is_escaped_and_href_safe() {
        let mut e = pending_entry("id1", "T");
        e.osf_link = "https://osf.io/x?a=1&b=2".to_owned();
        let v = view(vec![e], 1, 0, 0, None);
        let html = render_html(&v, None);
        assert!(html.contains("<a href=\"https://osf.io/x?a=1&amp;b=2\">OSF</a>"));
    }

    #[test]
    fn scenario_shown_when_present() {
        let v = view(vec![pending_entry("id1", "T")], 1, 0, 0, None);
        let html = render_html(&v, None);
        assert!(html.contains("scenario: places"));
    }

    #[test]
    fn scenario_omitted_when_absent() {
        let mut e = pending_entry("id1", "T");
        e.scenario = None;
        let v = view(vec![e], 1, 0, 0, None);
        let html = render_html(&v, None);
        assert!(!html.contains("scenario:"));
    }

    #[test]
    fn redirect_page_targets_ledger_subdir() {
        let html = render_redirect();
        assert!(html.contains("content=\"0; url=ledger/\""));
        assert!(html.contains("<a href=\"ledger/\">"));
    }

    #[test]
    fn render_is_byte_identical_on_re_run() {
        let v = view(
            vec![pending_entry("id1", "T"), resolved_entry("id2", 0.04, true)],
            1,
            0,
            1,
            Some(0.04),
        );
        let a = render_html(&v, Some("deadbeef"));
        let b = render_html(&v, Some("deadbeef"));
        assert_eq!(a, b);
        let a = render_redirect();
        let b = render_redirect();
        assert_eq!(a, b);
    }

    #[test]
    fn header_contains_doctype_and_viewport() {
        let v = view(vec![], 0, 0, 0, None);
        let html = render_html(&v, None);
        assert!(html.starts_with("<!DOCTYPE html>\n"));
        assert!(html.contains("viewport"));
    }

    #[test]
    fn resolved_entry_without_outcome_data_skips_brier_block() {
        // status == "resolved" but outcome/resolved_at/brier_score are None.
        // This covers the `}` on line 170 — the path where the outer
        // `if entry.status == "resolved"` guard is true but the inner
        // `if let (Some(outcome), Some(at), Some(brier))` pattern fails.
        let mut e = pending_entry("id1", "T");
        e.status = "resolved".to_owned();
        // outcome, resolved_at, brier_score left as None
        let v = view(vec![e], 0, 0, 1, None);
        let html = render_html(&v, None);
        assert!(html.contains("Status: resolved"));
        // Should NOT contain the Brier Score block.
        assert!(!html.contains("Brier Score:"));
    }
}
