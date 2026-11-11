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

pub(super) fn read(bytes: &[u8]) -> Result<Value, Refusal> {
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
        decoder.deserialize_any(self)
    }
}

fn count_node<E: de::Error>(budget: &mut Budget) -> Result<(), E> {
    if budget.nodes == MAX_NODES {
        budget.exceeded = true;
        return Err(de::Error::custom("JSON bound"));
    }
    budget.nodes += 1;
    Ok(())
}

impl<'de> Visitor<'de> for Node<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        count_node(self.budget)?;
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        count_node(self.budget)?;
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        count_node(self.budget)?;
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        count_node(self.budget)?;
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| de::Error::custom("non-finite JSON number"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        count_node(self.budget)?;
        Ok(Value::String(value.to_owned()))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        count_node(self.budget)?;
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        count_node(self.budget)?;
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
        count_node(self.budget)?;
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

#[cfg(test)]
mod tests {
    use super::{Budget, Node};
    use serde::de::{
        value::{BorrowedBytesDeserializer, Error},
        DeserializeSeed, Visitor,
    };

    // Serde requires expecting and supports non-JSON deserializers too. JSON
    // bytes cannot represent byte strings or infinities; exercise that narrow
    // trait contract without adding a product parser override.
    #[test]
    fn the_serde_visitor_refuses_byte_strings_and_nonfinite_numbers() {
        let mut budget = Budget::default();
        let result = Node {
            budget: &mut budget,
            depth: 0,
        }
        .deserialize(BorrowedBytesDeserializer::<Error>::new(b"not JSON"));
        assert!(result.is_err_and(|error| error.to_string().contains("bounded JSON")));
        for value in [f64::INFINITY, f64::NEG_INFINITY, f64::NAN] {
            assert!(Node {
                budget: &mut budget,
                depth: 0
            }
            .visit_f64::<Error>(value)
            .is_err());
        }
    }
}
