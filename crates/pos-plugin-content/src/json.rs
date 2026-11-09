//! Bounded JSON decoding without duplicate-key normalization.

use std::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::bundle::Refusal;

const MAX_DEPTH: usize = 64;
const MAX_NODES: usize = 262_144;

#[derive(Default)]
struct Budget {
    nodes: usize,
    exceeded: bool,
}

struct Node<'a> {
    budget: &'a mut Budget,
    depth: usize,
}

pub fn read(bytes: &[u8]) -> Result<Value, Refusal> {
    let mut budget = Budget::default();
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let outcome = Node {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(&mut decoder)
    .and_then(|value| decoder.end().map(|()| value));
    outcome.map_err(|_| {
        if budget.exceeded {
            Refusal::BoundsExceeded
        } else {
            Refusal::Malformed
        }
    })
}

impl<'de> DeserializeSeed<'de> for Node<'_> {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        if self.budget.nodes == MAX_NODES {
            self.budget.exceeded = true;
            return Err(de::Error::custom("JSON bound"));
        }
        self.budget.nodes += 1;
        decoder.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Node<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| de::Error::custom("non-finite JSON number"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        if self.depth == MAX_DEPTH {
            self.budget.exceeded = true;
            return Err(de::Error::custom("JSON depth"));
        }
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(Node {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Value, A::Error> {
        if self.depth == MAX_DEPTH {
            self.budget.exceeded = true;
            return Err(de::Error::custom("JSON depth"));
        }
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON key"));
            }
            let value = object.next_value_seed(Node {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
