//! Exact `host-v1` import types, checked when a Component loads.
//!
//! `deterministic-random` and `record-operational-log` are defined with
//! Wasmtime's dynamic `func_new`, which accepts any import type at link time.
//! (The typed bindings emit `unsafe impl`, which `unsafe_code = "forbid"`
//! rejects.) This check therefore compares every imported function with the
//! exact `host-v1` signature before the linker runs, so a mistyped import is
//! refused at load, never at its first call.

use wasmtime::component::types::{ComponentFunc, ComponentItem, Type};
use wasmtime::component::Component;
use wasmtime::Engine;

use crate::host_v1::HOST_V1_INTERFACE;

/// A Canonical ABI value type the `host-v1` signatures use.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Shape {
    U8,
    U16,
    U32,
    U64,
    List(Box<Self>),
    Option(Box<Self>),
    Record(Vec<(String, Self)>),
    Variant(Vec<(String, Option<Self>)>),
    Result(Option<Box<Self>>, Option<Box<Self>>),
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
    component
        .component_type()
        .imports(engine)
        .all(|(interface, import)| item_is_exact(engine, interface, &import.ty))
}

fn item_is_exact(engine: &Engine, interface: &str, item: &ComponentItem) -> bool {
    match item {
        ComponentItem::ComponentInstance(instance) => instance
            .exports(engine)
            .all(|(name, export)| export_is_exact(interface, name, &export.ty)),
        // A bare function import is never a `host-v1` function.
        ComponentItem::ComponentFunc(_) => false,
        _ => true,
    }
}

fn export_is_exact(interface: &str, name: &str, item: &ComponentItem) -> bool {
    match item {
        ComponentItem::ComponentFunc(func) => {
            interface == HOST_V1_INTERFACE
                && expected_signature(name).is_some_and(|expected| {
                    signature(func).is_some_and(|actual| actual == expected)
                })
        }
        _ => true,
    }
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

/// The shape of a value type, or `None` for a type `host-v1` never uses.
fn shape(ty: &Type) -> Option<Shape> {
    match ty {
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
            .map(|case| optional_shape(case.ty.as_ref()).map(|shape| (case.name.to_owned(), shape)))
            .collect::<Option<Vec<_>>>()
            .map(Shape::Variant),
        Type::Result(result) => {
            let ok = optional_shape(result.ok().as_ref())?;
            let err = optional_shape(result.err().as_ref())?;
            Some(Shape::Result(ok.map(Box::new), err.map(Box::new)))
        }
        _ => None,
    }
}

/// `Some(None)` for an absent payload, `None` for an unsupported one.
fn optional_shape(ty: Option<&Type>) -> Option<Option<Shape>> {
    ty.map_or(Some(None), |ty| shape(ty).map(Some))
}

/// The exact WIT signature of one `host-v1` function.
fn expected_signature(name: &str) -> Option<Signature> {
    let (params, result) = match name {
        "simulation-time" => (Vec::new(), Shape::U64),
        "deterministic-random" => (
            vec![
                named("domain", digest32()),
                named("offset", Shape::U64),
                named("length", Shape::U32),
            ],
            Shape::Result(Some(Box::new(bytes())), Some(Box::new(plugin_error()))),
        ),
        "record-operational-log" => (
            vec![named("category", Shape::U16), named("message", bounded_text())],
            Shape::Result(None, Some(Box::new(plugin_error()))),
        ),
        _ => return None,
    };
    Some(Signature {
        params,
        results: vec![result],
        is_async: false,
    })
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
fn plugin_error() -> Shape {
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
