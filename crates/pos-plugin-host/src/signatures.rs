//! Exact `host-v1` import and `guest-v1` export types, checked at load.
//!
//! `deterministic-random` and `record-operational-log` are defined with
//! Wasmtime's dynamic `func_new`, which accepts any import type at link time,
//! and the dynamic call API accepts any export type until it is called. (The
//! typed bindings emit `unsafe impl`, which `unsafe_code = "forbid"`
//! rejects.) These checks therefore compare every imported function, and the
//! `describe`, `reduce` and `drive` exports, with their exact WIT signatures
//! before anything runs, so a mistyped Component is refused at load, never at
//! its first call.
//!
//! WIT shape knowledge lives in these places, which must change together:
//! this module (the exact signatures), `lower.rs` (the invocation value),
//! `lift.rs`, `describe.rs` and `output.rs` (the field order of lifted
//! returns), and `pos_runtime::community_plugin_host`'s contract types.

use wasmtime::component::types::{ComponentFunc, ComponentItem, Type};
use wasmtime::component::Component;
use wasmtime::Engine;

use crate::engine::GuestExport;
use crate::host_v1::HOST_V1_INTERFACE;

/// A Canonical ABI value type the world's signatures use.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Shape {
    Bool,
    U8,
    U16,
    U32,
    U64,
    List(Box<Self>),
    Option(Box<Self>),
    Record(Vec<(String, Self)>),
    Variant(Vec<(String, Option<Self>)>),
    Enum(Vec<String>),
    Result(Option<Box<Self>>, Option<Box<Self>>),
}

/// The payload of a variant case or a `result` side.
#[derive(Clone, Debug, Eq, PartialEq)]
enum PayloadShape {
    /// No payload.
    Absent,
    /// A payload of this shape.
    Present(Shape),
}

impl PayloadShape {
    fn into_option(self) -> Option<Shape> {
        match self {
            Self::Absent => None,
            Self::Present(shape) => Some(shape),
        }
    }
}

/// A function signature: named parameters, results and async-ness.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Signature {
    params: Vec<(String, Shape)>,
    results: Vec<Shape>,
    is_async: bool,
}

/// Whether every function the Component imports is a `host-v1` function with
/// its exact WIT signature.
///
/// Only functions are checked here. Every other imported item is left to the
/// `host-v1`-only linker, which refuses anything it does not define.
pub(crate) fn imported_functions_are_exact(engine: &Engine, component: &Component) -> bool {
    let component_type = component.component_type();
    let exact = component_type
        .imports(engine)
        .all(|(interface, import)| item_is_exact(engine, interface, &import.ty));
    exact
}

fn item_is_exact(engine: &Engine, interface: &str, item: &ComponentItem) -> bool {
    match item {
        ComponentItem::ComponentInstance(instance) => instance
            .exports(engine)
            .all(|(name, export)| imported_item_is_exact(interface, name, &export.ty)),
        // A bare function import is never a `host-v1` function.
        ComponentItem::ComponentFunc(_) => false,
        _ => true,
    }
}

fn imported_item_is_exact(interface: &str, name: &str, item: &ComponentItem) -> bool {
    match item {
        ComponentItem::ComponentFunc(func) => {
            interface == HOST_V1_INTERFACE
                && import_signature(name).is_some_and(|expected| {
                    signature(func).is_some_and(|actual| actual == expected)
                })
        }
        _ => true,
    }
}

/// Whether `func` has the exact WIT signature of `export`.
pub(crate) fn export_is_exact(export: GuestExport, func: &ComponentFunc) -> bool {
    signature(func).is_some_and(|actual| actual == export_signature(export))
}

/// The signature of a function, or `None` when it uses another value type.
fn signature(func: &ComponentFunc) -> Option<Signature> {
    let params = func
        .params()
        .map(|(name, ty)| shape(&ty).map(|shape| (name.to_owned(), shape)))
        .collect::<Option<Vec<_>>>()?;
    let results = func
        .results()
        .map(|ty| shape(&ty))
        .collect::<Option<Vec<_>>>()?;
    Some(Signature {
        params,
        results,
        is_async: func.async_(),
    })
}

/// The shape of a value type, or `None` for a type the world never uses.
fn shape(ty: &Type) -> Option<Shape> {
    match ty {
        Type::Bool => Some(Shape::Bool),
        Type::U8 => Some(Shape::U8),
        Type::U16 => Some(Shape::U16),
        Type::U32 => Some(Shape::U32),
        Type::U64 => Some(Shape::U64),
        Type::List(list) => shape(&list.ty()).map(|item| Shape::List(Box::new(item))),
        Type::Option(option) => shape(&option.ty()).map(|item| Shape::Option(Box::new(item))),
        Type::Record(record) => record
            .fields()
            .map(|field| shape(&field.ty).map(|shape| (field.name.to_owned(), shape)))
            .collect::<Option<Vec<_>>>()
            .map(Shape::Record),
        Type::Variant(variant) => variant
            .cases()
            .map(|case| {
                let payload = payload_shape(case.ty.as_ref())?;
                Some((case.name.to_owned(), payload.into_option()))
            })
            .collect::<Option<Vec<_>>>()
            .map(Shape::Variant),
        Type::Enum(cases) => Some(Shape::Enum(cases.names().map(str::to_owned).collect())),
        Type::Result(result) => {
            let ok = payload_shape(result.ok().as_ref())?.into_option();
            let err = payload_shape(result.err().as_ref())?.into_option();
            Some(Shape::Result(ok.map(Box::new), err.map(Box::new)))
        }
        _ => None,
    }
}

/// The shape of an optional payload type, or `None` for a type the world
/// never uses.
fn payload_shape(ty: Option<&Type>) -> Option<PayloadShape> {
    ty.map_or(Some(PayloadShape::Absent), |ty| {
        shape(ty).map(PayloadShape::Present)
    })
}

/// The exact WIT signature of one `host-v1` function.
fn import_signature(name: &str) -> Option<Signature> {
    let (params, result) = match name {
        "simulation-time" => (Vec::new(), Shape::U64),
        "deterministic-random" => (
            vec![
                named("domain", digest32()),
                named("offset", Shape::U64),
                named("length", Shape::U32),
            ],
            Shape::Result(Some(Box::new(bytes())), Some(Box::new(error_shape()))),
        ),
        "record-operational-log" => (
            vec![
                named("category", Shape::U16),
                named("message", bounded_text()),
            ],
            Shape::Result(None, Some(Box::new(error_shape()))),
        ),
        _ => return None,
    };
    Some(Signature {
        params,
        results: vec![result],
        is_async: false,
    })
}

/// The exact WIT signature of one `guest-v1` export.
fn export_signature(export: GuestExport) -> Signature {
    let (params, ok) = match export {
        GuestExport::Describe => (Vec::new(), descriptor_shape()),
        GuestExport::Reduce | GuestExport::Drive => {
            (vec![named("input", invocation_shape())], output_shape())
        }
    };
    Signature {
        params,
        results: vec![Shape::Result(
            Some(Box::new(ok)),
            Some(Box::new(error_shape())),
        )],
        is_async: false,
    }
}

fn named(name: &str, shape: Shape) -> (String, Shape) {
    (name.to_owned(), shape)
}

fn bytes() -> Shape {
    Shape::List(Box::new(Shape::U8))
}

fn digest32() -> Shape {
    Shape::Record(vec![named("value", bytes())])
}

fn bounded_text() -> Shape {
    Shape::Record(vec![named("utf8", bytes())])
}

fn field_ref() -> Shape {
    Shape::Record(vec![
        named("schema-id", Shape::U32),
        named("field-ordinal", Shape::U16),
    ])
}

/// `contract-v1.plugin-error`.
fn error_shape() -> Shape {
    let code = Shape::Variant(vec![
        ("invalid-invocation".to_owned(), Some(field_ref())),
        ("unsupported-schema".to_owned(), Some(Shape::U32)),
        ("capability-required".to_owned(), Some(bounded_text())),
        ("dependency-missing".to_owned(), Some(digest32())),
        ("deterministic-budget-exhausted".to_owned(), None),
        ("invalid-state".to_owned(), Some(field_ref())),
        ("migration-rejected".to_owned(), Some(field_ref())),
        ("guest-declared-failure".to_owned(), Some(Shape::U16)),
    ]);
    Shape::Record(vec![
        named("code", code),
        named("canonical-coordinate", Shape::Option(Box::new(bytes()))),
        named("related-digest", Shape::Option(Box::new(digest32()))),
    ])
}

fn list(item: Shape) -> Shape {
    Shape::List(Box::new(item))
}

fn enumeration(cases: &[&str]) -> Shape {
    Shape::Enum(cases.iter().map(|case| (*case).to_owned()).collect())
}

fn artifact_ref() -> Shape {
    Shape::Record(vec![
        named("schema-id", Shape::U32),
        named("byte-length", Shape::U64),
        named("digest", digest32()),
    ])
}

/// `contract-v1.capability-declaration`.
fn capability_declaration() -> Shape {
    Shape::Record(vec![
        named("capability-id", bounded_text()),
        named("operation", bounded_text()),
        named("resource-pattern", bounded_text()),
        named("purpose", bounded_text()),
        named("audience", bounded_text()),
        named("required", Shape::Bool),
        named("max-calls", Shape::U32),
        named("max-request-bytes", Shape::U32),
        named("max-response-bytes", Shape::U32),
    ])
}

/// `contract-v1.dependency-descriptor`.
fn dependency_descriptor() -> Shape {
    Shape::Record(vec![
        named("dependency-id", bounded_text()),
        named("release-digest", digest32()),
        named("world", bounded_text()),
        named("abi-major", Shape::U16),
        named("min-abi-minor", Shape::U16),
        named("max-abi-minor", Shape::U16),
        named("required-features", list(bounded_text())),
        named("required-capabilities", list(bounded_text())),
        named(
            "dependency-class",
            enumeration(&[
                "exogenous-frozen",
                "intervention-assigned",
                "endogenous-recomputed",
                "fixed-policy",
                "presentation-only",
            ]),
        ),
    ])
}

/// `contract-v1.migration-descriptor`.
fn migration_descriptor() -> Shape {
    Shape::Record(vec![
        named("from-state-schema", digest32()),
        named("to-state-schema", digest32()),
        named("migration-id", bounded_text()),
        named("migration-component", artifact_ref()),
        named("deterministic-budget-id", bounded_text()),
        named(
            "reverse-migration-id",
            Shape::Option(Box::new(bounded_text())),
        ),
    ])
}

/// `contract-v1.plugin-descriptor`.
fn descriptor_shape() -> Shape {
    Shape::Record(vec![
        named("plugin-id", bounded_text()),
        named("release-semver", bounded_text()),
        named("world", bounded_text()),
        named("abi-major", Shape::U16),
        named("min-abi-minor", Shape::U16),
        named("max-abi-minor", Shape::U16),
        named("required-features", list(bounded_text())),
        named("event-schema-digests", list(digest32())),
        named("state-schema-digest", digest32()),
        named("capabilities", list(capability_declaration())),
        named("migrations", list(migration_descriptor())),
        named("dependencies", list(dependency_descriptor())),
        named("manifest-digest", digest32()),
        named("release-digest", digest32()),
    ])
}

/// `contract-v1.plugin-invocation`.
fn invocation_shape() -> Shape {
    let timeline_position = Shape::Record(vec![
        named("timeline-id", bytes()),
        named("seq", Shape::U64),
        named("tick", Shape::U64),
        named("scheduler-position", Shape::U32),
    ]);
    Shape::Record(vec![
        named("invocation-id", bytes()),
        named("kind", enumeration(&["reduce", "drive"])),
        named("timeline-position", timeline_position),
        named("output-base-ordinal", Shape::U32),
        named("principal-ref", artifact_ref()),
        named("authorization-decision", artifact_ref()),
        named("observation-snapshot", artifact_ref()),
        named("observation-bytes", bytes()),
        named("prior-state-schema", digest32()),
        named("prior-state-bytes", bytes()),
        named("execution-profile-digest", digest32()),
        named("trust-policy-snapshot-digest", digest32()),
        named("deterministic-budget-id", bounded_text()),
        named("deterministic-random-domain", digest32()),
        named("provenance-root", digest32()),
    ])
}

/// `contract-v1.plugin-output`.
fn output_shape() -> Shape {
    let event_draft = Shape::Record(vec![
        named("event-schema-id", Shape::U32),
        named("entity-id", bytes()),
        named("event-type", bounded_text()),
        named("canonical-payload", bytes()),
        named("dependency-digests", list(digest32())),
    ]);
    let trace_annotation = Shape::Record(vec![
        named("annotation-schema-id", Shape::U32),
        named("canonical-bytes", bytes()),
        named("dependency-digests", list(digest32())),
    ]);
    Shape::Record(vec![
        named("invocation-id", bytes()),
        named("event-drafts", list(event_draft)),
        named("next-state-schema", digest32()),
        named("next-state-bytes", bytes()),
        named("trace-annotations", list(trace_annotation)),
        named("consumed-dependencies", list(digest32())),
        named("output-digest", digest32()),
    ])
}
