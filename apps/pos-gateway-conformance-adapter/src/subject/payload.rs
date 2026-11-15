//! The case payload grammar of the requirements text (sections 1 and 2).
//!
//! The payload decodes into these exact records (no unknown member), then [`parse`] checks the
//! schema string, the family, the counts and texts, every route, and that each `{timeline}` and
//! each `{consent}` follows its capture. A payload outside the grammar is `None`, which is
//! `payload-invalid`.

use piglor_gateway::mode_profile::GatewayModeProfileIdV1;
use serde::Deserialize;
use serde_json::Value;

use super::SCHEMA_ID;

/// The literal a path names the captured Timeline by.
pub(super) const TIMELINE_SLOT: &str = "{timeline}";
/// The literal a request body names the captured consent by.
pub(super) const CONSENT_SLOT: &str = "{consent}";

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
    /// The Local composition with a fixture Local Principal document whose one consent
    /// governs Timeline creation (#309).
    #[serde(rename = "authorized-consented")]
    AuthorizedConsented,
}

impl CompositionV2 {
    /// The execution mode the store of an authorized composition is bound to; `None` for the
    /// open Gateway, which binds none.
    pub(super) const fn mode(self) -> Option<GatewayModeProfileIdV1> {
        match self {
            Self::Open => None,
            Self::Authorized | Self::AuthorizedConsented => Some(GatewayModeProfileIdV1::Local),
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
    /// The `id` of the response fills [`TIMELINE_SLOT`].
    Timeline,
    /// The `consent_ref` of the response's first consent fills [`CONSENT_SLOT`].
    Consent,
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
    /// The route [`parse`] matched the path to; never part of the payload.
    #[serde(skip)]
    route: Option<RouteV2>,
}

impl ExchangeV2 {
    /// Whether the exchange sends the fixture actor header.
    pub(super) const fn actor(&self) -> bool {
        self.actor.is_some()
    }

    /// The slot the exchange's response fills, if any.
    pub(super) const fn capture(&self) -> Option<CaptureV2> {
        self.capture
    }

    /// Whether the request body names the captured consent.
    fn uses_consent(&self) -> bool {
        self.body
            .as_ref()
            .is_some_and(|body| body.to_string().contains(CONSENT_SLOT))
    }

    /// The route [`parse`] matched the path to; every parsed exchange has one.
    pub(super) const fn route(&self) -> Option<RouteV2> {
        self.route
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
const ROUTES: [RouteV2; 8] = [
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
    RouteV2 {
        path: "/v1/me/consent-revocations",
        capability: "consent.revoke",
        commits: true,
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

/// Whether every exchange is in the grammar; each one's route is recorded as it is matched.
fn exchanges_are_valid(exchanges: &mut [ExchangeV2]) -> bool {
    let mut timeline = false;
    let mut consent = false;
    (1..=128).contains(&exchanges.len())
        && exchanges.iter_mut().all(|exchange| {
            exchange.route = route_of(&exchange.path);
            let valid = exchange.path.starts_with('/')
                && printable(&exchange.path, 1, 256, false)
                && exchange.route.is_some()
                && exchange.actor != Some(false)
                && (timeline || !exchange.path.contains(TIMELINE_SLOT))
                && (consent || !exchange.uses_consent());
            timeline |= matches!(exchange.capture, Some(CaptureV2::Timeline));
            consent |= matches!(exchange.capture, Some(CaptureV2::Consent));
            valid
        })
}

fn subcase_is_valid(subcase: &mut SubCaseV2, prefix: &str) -> bool {
    subcase_id_is_valid(&subcase.id, prefix)
        && printable(&subcase.title, 1, 160, true)
        && subcase
            .canary
            .as_deref()
            .is_none_or(|canary| printable(canary, 1, 64, false))
        && exchanges_are_valid(&mut subcase.exchanges)
}

/// The sub-cases of a payload of `family` whose sub-case IDs start with `prefix`, or `None`
/// for a payload outside the grammar.
pub(super) fn parse(bytes: &[u8], family: &str, prefix: &str) -> Option<Vec<SubCaseV2>> {
    serde_json::from_slice::<PayloadV2>(bytes)
        .ok()
        .and_then(|mut payload| {
            let valid = payload.schema == SCHEMA_ID
                && payload.family == family
                && (1..=64).contains(&payload.subcases.len())
                && payload
                    .subcases
                    .iter_mut()
                    .all(|subcase| subcase_is_valid(subcase, prefix));
            valid.then_some(payload.subcases)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUIREMENTS: &str = include_str!(
        "../../../../fixtures/conformance/profiles/gateway-client-conformance/normative-requirements.md"
    );
    const GENERATOR: &str =
        include_str!("../../../../scripts/generate_gateway_conformance_fixtures.py");

    /// The `(path, capability)` rows of the requirements' route table (section 2), with `:id`
    /// written as the Timeline slot.
    fn documented_routes() -> Vec<(String, String)> {
        let section = REQUIREMENTS
            .split("## 2. Routes and capabilities")
            .nth(1)
            .and_then(|rest| rest.split("## 3.").next())
            .unwrap_or_default();
        section
            .lines()
            .filter_map(|line| {
                let cells = line.split('|').map(str::trim).collect::<Vec<_>>();
                let route = cells.get(2)?.strip_prefix('`')?.strip_suffix('`')?;
                let (_, path) = route.split_once(' ')?;
                let capability = cells.get(3)?.strip_prefix('`')?.strip_suffix('`')?;
                Some((path.replace(":id", TIMELINE_SLOT), capability.to_owned()))
            })
            .collect()
    }

    /// The capabilities of the generator's `ROUTE_CAPABILITY` map.
    fn generator_capabilities() -> Vec<String> {
        let map = GENERATOR
            .split("ROUTE_CAPABILITY = {")
            .nth(1)
            .and_then(|rest| rest.split("\n}").next())
            .unwrap_or_default();
        let mut capabilities = map
            .lines()
            .filter_map(|line| line.trim().split_once(": "))
            .map(|(_, value)| value.trim_end_matches(',').trim_matches('"').to_owned())
            .collect::<Vec<_>>();
        capabilities.sort_unstable();
        capabilities
    }

    #[test]
    fn the_route_table_is_the_documented_one() {
        let documented = documented_routes();
        assert_eq!(documented.len(), ROUTES.len(), "{documented:?}");
        for (route, (path, capability)) in ROUTES.iter().zip(&documented) {
            assert_eq!(
                (route.path, route.capability),
                (path.as_str(), capability.as_str())
            );
            assert_eq!(route_of(path), Some(*route), "{path}");
            assert_eq!(route_of(&format!("{path}?limit=1")), Some(*route), "{path}");
        }
        let mut capabilities = ROUTES.map(RouteV2::capability).map(str::to_owned).to_vec();
        capabilities.sort_unstable();
        assert_eq!(generator_capabilities(), capabilities);
        assert_eq!(
            ROUTES.map(RouteV2::commits),
            [false, false, false, false, true, true, false, true]
        );
    }

    #[test]
    fn other_prefixes_and_suffixes_name_no_route() {
        for route in ROUTES {
            let concrete = route.path.replace(TIMELINE_SLOT, "t");
            for path in [
                format!("{concrete}x"),
                format!("{concrete}/"),
                format!("/x{concrete}"),
                concrete.to_uppercase(),
            ] {
                assert_eq!(route_of(&path), None, "{path}");
            }
        }
        for path in [
            "/v1/timelines//events",
            "/v1/timelines/a/b/events",
            "/v1/timelines/t",
            "/v1/session/events",
            "/v2/session",
            "/v2/timelines/t/events",
            "",
        ] {
            assert_eq!(route_of(path), None, "{path}");
        }
    }
}
