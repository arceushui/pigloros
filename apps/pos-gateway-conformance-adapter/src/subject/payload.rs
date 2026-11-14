//! The case payload grammar of the requirements text (sections 1 and 2).
//!
//! The payload decodes into these exact records (no unknown member), then [`parse`] checks the
//! schema string, the family, the counts and texts, every route, and that each `{timeline}`
//! follows a capture. A payload outside the grammar is `None`, which is `payload-invalid`.

use serde::Deserialize;
use serde_json::Value;

use super::SCHEMA_ID;

/// The literal a path names the captured Timeline by.
pub(super) const TIMELINE_SLOT: &str = "{timeline}";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadV2 {
    schema: String,
    family: String,
    subcases: Vec<SubCaseV2>,
}

/// One sub-case: its own Gateway composition and its ordered exchanges.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SubCaseV2 {
    pub(super) id: String,
    title: String,
    pub(super) composition: CompositionV2,
    pub(super) exchanges: Vec<ExchangeV2>,
    #[serde(default)]
    pub(super) canary: Option<String>,
}

/// The Gateway a sub-case runs on (requirements section 3).
#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(super) enum CompositionV2 {
    /// No host authorizer.
    Open,
    /// The production serve composition with a fixture Local Principal document.
    Authorized,
}

/// The router of the same Gateway an exchange is sent through.
#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(super) enum RouterV2 {
    /// The full local route table.
    Loopback,
    /// The public listener of a non-loopback bind.
    Spectator,
}

#[derive(Clone, Copy, Deserialize)]
pub(super) enum MethodV2 {
    #[serde(rename = "GET")]
    Get,
    #[serde(rename = "POST")]
    Post,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum CaptureV2 {
    Timeline,
}

/// One HTTP exchange and its expected observation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExchangeV2 {
    pub(super) router: RouterV2,
    pub(super) method: MethodV2,
    pub(super) path: String,
    pub(super) expect: Value,
    #[serde(default)]
    actor: Option<bool>,
    #[serde(default)]
    pub(super) body: Option<Value>,
    #[serde(default)]
    capture: Option<CaptureV2>,
}

impl ExchangeV2 {
    /// Whether the exchange sends the fixture actor header.
    pub(super) const fn actor(&self) -> bool {
        self.actor.is_some()
    }

    /// Whether the exchange captures the Timeline ID of its response.
    pub(super) const fn captures(&self) -> bool {
        self.capture.is_some()
    }

    /// The route of the path, which [`parse`] has checked.
    pub(super) fn route(&self) -> RouteV2 {
        route_of(&self.path).unwrap_or(RouteV2::Health)
    }
}

/// The routes of the documented Gateway route table (requirements section 2).
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum RouteV2 {
    Health,
    Ledger,
    Create,
    Events,
    Signals,
    Actions,
}

impl RouteV2 {
    /// The capability an attempt must hold for the route.
    pub(super) const fn capability(self) -> &'static str {
        match self {
            Self::Health => "gateway.health.read",
            Self::Ledger => "gateway.ledger.read",
            Self::Create => "timeline.create",
            Self::Events => "timeline.events.read",
            Self::Signals => "timeline.signals.append",
            Self::Actions => "world.action.v1.submit",
        }
    }

    /// Whether a `201` response of the route commits one Event.
    pub(super) const fn commits(self) -> bool {
        match self {
            Self::Signals | Self::Actions => true,
            Self::Health | Self::Ledger | Self::Create | Self::Events => false,
        }
    }
}

fn route_of(path: &str) -> Option<RouteV2> {
    let base = path.split('?').next().unwrap_or_default();
    match base {
        "/health" => Some(RouteV2::Health),
        "/v1/ledger" => Some(RouteV2::Ledger),
        "/v1/timelines" => Some(RouteV2::Create),
        _ => base
            .strip_prefix("/v1/timelines/")
            .and_then(|rest| rest.split_once('/'))
            .filter(|(timeline, _)| !timeline.is_empty())
            .and_then(|(_, tail)| match tail {
                "events" => Some(RouteV2::Events),
                "signals" => Some(RouteV2::Signals),
                "actions" => Some(RouteV2::Actions),
                _ => None,
            }),
    }
}

/// Printable ASCII of `minimum..=maximum` bytes; `space` admits the space character.
fn printable(text: &str, minimum: usize, maximum: usize, space: bool) -> bool {
    (minimum..=maximum).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || (space && byte == b' '))
}

fn subcase_id_is_valid(id: &str, prefix: &str) -> bool {
    id.strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('.'))
        .is_some_and(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
}

fn exchanges_are_valid(exchanges: &[ExchangeV2]) -> bool {
    let mut captured = false;
    (1..=128).contains(&exchanges.len())
        && exchanges.iter().all(|exchange| {
            let valid = exchange.path.starts_with('/')
                && printable(&exchange.path, 1, 256, false)
                && route_of(&exchange.path).is_some()
                && exchange.actor != Some(false)
                && (captured || !exchange.path.contains(TIMELINE_SLOT));
            captured |= exchange.captures();
            valid
        })
}

fn subcase_is_valid(subcase: &SubCaseV2, prefix: &str) -> bool {
    subcase_id_is_valid(&subcase.id, prefix)
        && printable(&subcase.title, 1, 160, true)
        && subcase
            .canary
            .as_deref()
            .is_none_or(|canary| printable(canary, 1, 64, false))
        && exchanges_are_valid(&subcase.exchanges)
}

/// The sub-cases of a payload of `family` whose sub-case IDs start with `prefix`, or `None`
/// for a payload outside the grammar.
pub(super) fn parse(bytes: &[u8], family: &str, prefix: &str) -> Option<Vec<SubCaseV2>> {
    serde_json::from_slice::<PayloadV2>(bytes)
        .ok()
        .filter(|payload| {
            payload.schema == SCHEMA_ID
                && payload.family == family
                && (1..=64).contains(&payload.subcases.len())
                && payload
                    .subcases
                    .iter()
                    .all(|subcase| subcase_is_valid(subcase, prefix))
        })
        .map(|payload| payload.subcases)
}
