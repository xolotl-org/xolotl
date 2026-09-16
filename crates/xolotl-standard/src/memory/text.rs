//! The ordered text projection used by memory indexing and consolidation.

use xolotl_types::{Value, ValueMap, ValueView, value::ListIter};

const ENTRY_FIELDS: [&str; 7] = [
    "content",
    "text",
    "knowledge",
    "summary",
    "trigger_hint",
    "title",
    "tags",
];
const FACET_FIELDS: [&str; 4] = ["trigger_hint", "tags", "title", "summary"];

enum Children<'a> {
    List(ListIter<'a>),
    Map { map: &'a ValueMap, index: usize },
}

impl<'a> Children<'a> {
    fn next(&mut self) -> Option<&'a Value> {
        match self {
            Self::List(values) => values.next(),
            Self::Map { map, index } => {
                while *index < ENTRY_FIELDS.len() + FACET_FIELDS.len() {
                    let position = *index;
                    *index += 1;
                    let child = if position < ENTRY_FIELDS.len() {
                        map.get(ENTRY_FIELDS[position])
                    } else {
                        map.get("facets")
                            .and_then(Value::as_map)
                            .and_then(|facets| {
                                facets.get(FACET_FIELDS[position - ENTRY_FIELDS.len()])
                            })
                    };
                    if child.is_some() {
                        return child;
                    }
                }
                None
            }
        }
    }
}

pub(super) fn entry_text(entry: &Value) -> String {
    let mut rendered = String::new();
    let mut frames = Vec::new();
    let mut next = Some(entry);
    loop {
        if let Some(value) = next.take() {
            match value.view() {
                ValueView::Str(text) if !text.trim().is_empty() => {
                    if !rendered.is_empty() {
                        rendered.push('\n');
                    }
                    rendered.push_str(text);
                }
                ValueView::List(values) => frames.push(Children::List(values.iter())),
                ValueView::Map(map) => frames.push(Children::Map { map, index: 0 }),
                _ => {}
            }
        }
        while let Some(frame) = frames.last_mut() {
            next = frame.next();
            if next.is_some() {
                break;
            }
            frames.pop();
        }
        if next.is_none() {
            return rendered;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;
    use std::collections::BTreeMap;

    #[test]
    fn selected_fields_keep_order_and_repeated_content() -> anyhow::Result<()> {
        let shared = Value::string("A".into());
        let entry = Value::map(BTreeMap::from([
            ("content".into(), Value::string("C".into())),
            (
                "text".into(),
                Value::list(vec![shared.clone(), Value::string(" ".into()), shared]),
            ),
            (
                "facets".into(),
                Value::map(BTreeMap::from([
                    ("trigger_hint".into(), Value::string("H".into())),
                    ("tags".into(), Value::string("G".into())),
                    ("title".into(), Value::string("T".into())),
                    ("summary".into(), Value::string("S".into())),
                    ("content".into(), Value::string("ignored".into())),
                ])),
            ),
            ("other".into(), Value::string("ignored".into())),
        ]));
        ensure!(entry_text(&entry) == "C\nA\nA\nH\nG\nT\nS");
        Ok(())
    }

    #[test]
    fn deep_index_text_and_release_use_a_small_call_stack() -> anyhow::Result<()> {
        std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| -> anyhow::Result<()> {
                let mut value = Value::string("retained".into());
                for depth in 0..20_000 {
                    value = if depth % 2 == 0 {
                        Value::list(vec![value])
                    } else {
                        Value::map(BTreeMap::from([("content".into(), value)]))
                    };
                }
                ensure!(entry_text(&value) == "retained");
                drop(value);
                Ok(())
            })?
            .join()
            .map_err(|_panic| anyhow::anyhow!("deep indexing thread panicked"))??;
        Ok(())
    }
}
