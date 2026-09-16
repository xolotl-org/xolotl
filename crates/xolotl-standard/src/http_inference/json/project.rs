//! Finite provider schemas select data before it is retained.
//!
//! Unknown keys use a fixed candidate matcher, including escaped keys. The
//! complete JSON grammar is still validated for skipped strings and subtrees.

use super::{Event, Kind, invalid};
use crate::http_inference::error::HttpInferenceError;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub(in crate::http_inference) type Limits = xolotl_types::InferenceResponseLimits;

pub(in crate::http_inference) enum Rule {
    Skip,
    Text,
    Number,
    Tag(&'static [&'static str]),
    Object(&'static [(&'static str, &'static Rule)]),
    Array { item: &'static Rule, first: bool },
}

pub(in crate::http_inference) static SKIP: Rule = Rule::Skip;
pub(in crate::http_inference) static TEXT: Rule = Rule::Text;
pub(in crate::http_inference) static NUMBER: Rule = Rule::Number;

pub(in crate::http_inference) struct Projection {
    rule: &'static Rule,
    frames: Vec<Frame>,
    result: Option<Value>,
    key: bool,
    matcher: Matcher,
    limits: Limits,
    bytes: u64,
    nodes: u64,
}

struct Frame {
    rule: &'static Rule,
    kind: Kind,
    value: Value,
    data: Vec<u8>,
    field: Option<(&'static str, &'static Rule)>,
    elements: usize,
    matcher: Matcher,
    bytes: u64,
    nodes: u64,
    weights: BTreeMap<&'static str, (u64, u64)>,
}

#[derive(Default)]
struct Matcher {
    offset: usize,
    candidates: u64,
}

impl Matcher {
    fn new(count: usize) -> Self {
        Self {
            offset: 0,
            candidates: if count < 64 {
                (1_u64 << count) - 1
            } else {
                u64::MAX
            },
        }
    }
    fn push<'a>(&mut self, bytes: &[u8], words: impl Iterator<Item = &'a str>) {
        for (index, word) in words.enumerate() {
            if self.candidates & (1 << index) != 0
                && word
                    .as_bytes()
                    .get(self.offset..)
                    .is_none_or(|tail| !tail.starts_with(bytes))
            {
                self.candidates &= !(1 << index);
            }
        }
        // Once every finite candidate is excluded, even arbitrarily large keys
        // cannot overflow a counter or allocate a retained copy.
        if self.candidates != 0 {
            self.offset += bytes.len();
        }
    }
    fn finish<'a>(&self, words: impl Iterator<Item = &'a str>) -> Option<usize> {
        words.enumerate().find_map(|(index, word)| {
            (self.candidates & (1 << index) != 0 && word.len() == self.offset).then_some(index)
        })
    }
}

impl Projection {
    pub(in crate::http_inference) fn new(rule: &'static Rule, limits: Limits) -> Self {
        Self {
            rule,
            frames: Vec::new(),
            result: None,
            key: false,
            matcher: Matcher::default(),
            limits,
            bytes: 0,
            nodes: 0,
        }
    }

    pub(in crate::http_inference) fn event(
        &mut self,
        event: Event<'_>,
    ) -> Result<(), HttpInferenceError> {
        match event {
            Event::KeyStart => {
                self.key = true;
                self.matcher = Matcher::new(self.fields().len());
            }
            Event::KeyEnd => {
                let field = self
                    .matcher
                    .finish(self.fields().iter().map(|(name, _)| *name))
                    .map(|index| self.fields()[index]);
                if let Some(frame) = self.frames.last_mut() {
                    if let Some((key, _)) = field {
                        // Last duplicate wins. Once its key is complete the
                        // previous value can be released before reading the new
                        // one; malformed replacements cannot publish either.
                        if let Value::Object(map) = &mut frame.value {
                            map.remove(key);
                        }
                        if let Some((bytes, nodes)) = frame.weights.remove(key) {
                            self.bytes -= bytes;
                            self.nodes -= nodes;
                            frame.bytes -= bytes;
                            frame.nodes -= nodes;
                        }
                    }
                    frame.field = field;
                }
                self.key = false;
            }
            Event::Data(bytes) if self.key => {
                let fields = self
                    .frames
                    .last()
                    .map_or(&[][..], |frame| match frame.rule {
                        Rule::Object(fields) => fields,
                        _ => &[],
                    });
                self.matcher
                    .push(bytes, fields.iter().map(|(name, _)| *name));
            }
            Event::Data(bytes) => self.data(bytes)?,
            Event::Start(kind) => self.start(kind)?,
            Event::End(kind) => self.end(kind)?,
        }
        Ok(())
    }

    pub(in crate::http_inference) fn finish(self) -> Result<Value, HttpInferenceError> {
        if !self.frames.is_empty() {
            return Err(invalid("unfinished selected JSON document"));
        }
        self.result
            .ok_or_else(|| invalid("missing selected JSON document"))
    }

    #[cfg(test)]
    pub(in crate::http_inference) fn retained(&self) -> (u64, u64) {
        (self.bytes, self.nodes)
    }

    fn fields(&self) -> &'static [(&'static str, &'static Rule)] {
        self.frames.last().map_or(&[], |frame| match frame.rule {
            Rule::Object(fields) => fields,
            _ => &[],
        })
    }

    fn start(&mut self, kind: Kind) -> Result<(), HttpInferenceError> {
        let rule = match self.frames.last() {
            None => self.rule,
            Some(frame) => match frame.rule {
                Rule::Object(_) if frame.kind == Kind::Object => {
                    frame.field.map_or(&SKIP, |(_, rule)| rule)
                }
                Rule::Array { item, first }
                    if frame.kind == Kind::Array && (!first || frame.elements == 0) =>
                {
                    item
                }
                _ => &SKIP,
            },
        };
        let nodes = u64::from(!matches!(rule, Rule::Skip));
        self.nodes = self
            .nodes
            .checked_add(nodes)
            .ok_or_else(|| invalid("selected JSON node count overflow"))?;
        self.check_limits()?;
        let value = match (rule, kind) {
            (Rule::Object(_), Kind::Object) => Value::Object(Map::new()),
            (Rule::Array { .. }, Kind::Array) => Value::Array(Vec::new()),
            _ => Value::Null,
        };
        let matcher = match rule {
            Rule::Tag(tags) => Matcher::new(tags.len()),
            _ => Matcher::default(),
        };
        self.frames.push(Frame {
            rule,
            kind,
            value,
            data: Vec::new(),
            field: None,
            elements: 0,
            matcher,
            bytes: 0,
            nodes,
            weights: BTreeMap::new(),
        });
        Ok(())
    }

    fn data(&mut self, bytes: &[u8]) -> Result<(), HttpInferenceError> {
        let Some(frame) = self.frames.last_mut() else {
            return Err(invalid("JSON data outside a value"));
        };
        match (frame.rule, frame.kind) {
            (Rule::Text, Kind::String) | (Rule::Number, Kind::Number) => {
                let count = u64::try_from(bytes.len())
                    .map_err(|_overflow| invalid("selected JSON length overflow"))?;
                self.bytes = self
                    .bytes
                    .checked_add(count)
                    .ok_or_else(|| invalid("selected JSON length overflow"))?;
                if self
                    .limits
                    .max_materialized_bytes
                    .is_some_and(|limit| self.bytes > limit)
                {
                    return Err(invalid(
                        "selected JSON materialization byte policy exceeded",
                    ));
                }
                frame.bytes += count;
                frame.data.extend_from_slice(bytes);
            }
            (Rule::Tag(tags), Kind::String) => frame.matcher.push(bytes, tags.iter().copied()),
            _ => {}
        }
        Ok(())
    }

    fn end(&mut self, kind: Kind) -> Result<(), HttpInferenceError> {
        let Some(mut frame) = self.frames.pop() else {
            return Err(invalid("unmatched JSON value end"));
        };
        if frame.kind != kind {
            return Err(invalid("mismatched selected JSON value end"));
        }
        match (frame.rule, frame.kind) {
            (Rule::Text, Kind::String) => {
                frame.value = Value::String(
                    String::from_utf8(frame.data)
                        .map_err(|_invalid_utf8| invalid("invalid decoded JSON string"))?,
                )
            }
            (Rule::Number, Kind::Number) => {
                frame.value = serde_json::from_slice(&frame.data)
                    .map_err(HttpInferenceError::ResponseJson)?;
                self.bytes -= frame.bytes;
                frame.bytes = 0;
            }
            (Rule::Tag(tags), Kind::String) => {
                frame.value = Value::String(
                    frame
                        .matcher
                        .finish(tags.iter().copied())
                        .map_or("", |index| tags[index])
                        .to_owned(),
                );
            }
            _ => {}
        }
        if let Some(parent) = self.frames.last_mut() {
            parent.elements = parent.elements.saturating_add(1);
            let kept = match (&mut parent.value, parent.rule) {
                (Value::Object(map), Rule::Object(_)) => {
                    if let Some((key, _)) = parent.field.take() {
                        map.insert(key.to_owned(), frame.value);
                        if let Some((bytes, nodes)) =
                            parent.weights.insert(key, (frame.bytes, frame.nodes))
                        {
                            self.bytes -= bytes;
                            self.nodes -= nodes;
                            parent.bytes -= bytes;
                            parent.nodes -= nodes;
                        }
                        true
                    } else {
                        false
                    }
                }
                (Value::Array(values), Rule::Array { first, .. })
                    if !first || parent.elements == 1 =>
                {
                    values.push(frame.value);
                    true
                }
                _ => false,
            };
            if kept {
                parent.bytes += frame.bytes;
                parent.nodes += frame.nodes;
            } else {
                self.bytes -= frame.bytes;
                self.nodes -= frame.nodes;
            }
        } else {
            self.result = Some(frame.value);
        }
        Ok(())
    }

    fn check_limits(&self) -> Result<(), HttpInferenceError> {
        if self
            .limits
            .max_materialized_nodes
            .is_some_and(|limit| self.nodes > limit)
        {
            return Err(invalid(
                "selected JSON materialization node policy exceeded",
            ));
        }
        Ok(())
    }
}
