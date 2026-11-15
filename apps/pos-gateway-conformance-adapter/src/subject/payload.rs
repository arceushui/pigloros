//! The case payload grammar of the requirements text (sections 1 and 2).
//!
//! The payload decodes into these exact records (no unknown member), then [`parse`] checks the
//! schema string, the family, the counts and texts, every route, and that each `{timeline}`
//! follows a capture. A payload outside the grammar is `None`, which is `payload-invalid`.

use piglor_gateway::mode_profile::GatewayModeProfileIdV1;
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
    /// The production serve composition with a fixture Local Principal document, over a
    /// store bound to the Local execution mode.
    Authorized,
    /// The same composition over a store bound to the Air-Gapped execution mode.
    #[serde(rename = "authorized-air-gapped")]
    AuthorizedAirGapped,
}

impl CompositionV2 {
    /// The execution mode the store of an authorized composition is bound to; `None` for the
    /// open Gateway, which binds none.
    pub(super) const fn mode(self) -> Option<GatewayModeProfileIdV1> {
        match self {
            Self::Open => None,
            Self::Authorized => Some(GatewayModeProfileIdV1::Local),
            Self::AuthorizedAirGapped => Some(GatewayModeProfileIdV1::AirGapped),
        }
    }
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
        route_of(&self.path).unwrap_or(ROUTES[0])
    }
}

/// One route of the documented Gateway route table (requirements section 2).
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct RouteV2 {
    /// The path without its query; [`TIMELINE_SLOT`] stands for one non-empty segment.
    path: &'static str,
    /// The capability an attempt must hold for the route.
    capability: &'static str,
    /// Whether a `201` response of the route commits one Event.
    commits: bool,
}

/// The route table of the requirements text, section 2, in its order.
const ROUTES: [RouteV2; 7] = [
    RouteV2 {
        path: "/health",
        capability: "gateway.health.read",
        commits: false,
    },
    RouteV2 {
        path: "/v1/ledger",
        capability: "gateway.ledger.read",
        commits: false,
    },
    RouteV2 {
        path: "/v1/timelines",
        capability: "timeline.create",
        commits: false,
    },
    RouteV2 {
        path: "/v1/timelines/{timeline}/events",
        capability: "timeline.events.read",
        commits: false,
    },
    RouteV2 {
        path: "/v1/timelines/{timeline}/signals",
        capability: "timeline.signals.append",
        commits: true,
    },
    RouteV2 {
        path: "/v1/timelines/{timeline}/actions",
        capability: "world.action.v1.submit",
        commits: true,
    },
    RouteV2 {
        path: "/v1/session",
        capability: "session.read",
        commits: false,
    },
];

impl RouteV2 {
    /// The capability an attempt must hold for the route.
    pub(super) const fn capability(self) -> &'static str {
        self.capability
    }

    /// Whether a `201` response of the route commits one Event.
    pub(super) const fn commits(self) -> bool {
        self.commits
    }

    /// Whether `base`, a path without its query, names this route: the exact path, or for a
    /// Timeline route its prefix, one non-empty segment and its suffix.
    fn matches(self, base: &str) -> bool {
        self.path
            .split_once(TIMELINE_SLOT)
            .map_or(base == self.path, |(prefix, suffix)| {
                base.strip_prefix(prefix)
                    .and_then(|rest| rest.strip_suffix(suffix))
                    .is_some_and(|timeline| !timeline.is_empty() && !timeline.contains('/'))
            })
    }
}

fn route_of(path: &str) -> Option<RouteV2> {
    let base = path.split('?').next().unwrap_or_default();
    ROUTES.into_iter().find(|route| route.matches(base))
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
