//! Borrowed text projection shared by local inference and HTTP serialization.

use std::{borrow::Cow, fmt::Write};
use xolotl_types::{Value, ValueList, ValueView};

pub(crate) fn render_text(mut value: &Value) -> Cow<'_, str> {
    loop {
        match value.view() {
            ValueView::Str(text) => return Cow::Borrowed(text),
            ValueView::Map(map) => {
                if let Some(text) = map.get("text").or_else(|| map.get("prompt")) {
                    value = text;
                    continue;
                }
            }
            _ => {}
        }
        return Cow::Owned(RenderedText(value).to_string());
    }
}

/// Hash the same projection without retaining its complete rendered contents.
pub(super) fn hash_text(value: &Value) -> Result<blake3::Hash, std::fmt::Error> {
    struct HashText(blake3::Hasher);
    impl Write for HashText {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            self.0.update(text.as_bytes());
            Ok(())
        }
    }
    let mut output = HashText(blake3::Hasher::new());
    write!(output, "{}", RenderedText(value))?;
    Ok(output.0.finalize())
}

pub(crate) struct RenderedText<'a>(pub(crate) &'a Value);

/// An owned traversal can pause while its immutable input remains shared.
/// No projected prompt string is constructed.
pub(crate) struct TextCursor {
    next: Option<Value>,
    frames: Vec<(ValueList, usize)>,
}

pub(crate) enum TextPart {
    Value(Value),
    Space,
}

pub(crate) enum TextProgress {
    Part(TextPart),
    Pending,
    Done,
}

impl TextCursor {
    pub(crate) fn new(value: Value) -> Self {
        Self {
            next: Some(value),
            frames: Vec::new(),
        }
    }

    /// Charge traversal as well as emitted bytes so long runs of empty or
    /// deeply wrapped values remain interruptible in asynchronous consumers.
    pub(crate) fn advance(&mut self, work: &mut usize) -> TextProgress {
        while *work != 0 {
            *work -= 1;
            if let Some(value) = self.next.take() {
                match value.view() {
                    ValueView::List(parts) => self.frames.push((parts.clone(), 0)),
                    ValueView::Map(map) => {
                        if let Some(text) = map.get("text").or_else(|| map.get("prompt")) {
                            self.next = Some(text.clone());
                            continue;
                        }
                        return TextProgress::Part(TextPart::Value(value));
                    }
                    _ => return TextProgress::Part(TextPart::Value(value)),
                }
            } else if let Some((parts, index)) = self.frames.last_mut() {
                if let Some(value) = parts.get(*index) {
                    self.next = Some(value.clone());
                    let separated = *index != 0;
                    *index += 1;
                    if separated {
                        return TextProgress::Part(TextPart::Space);
                    }
                } else {
                    self.frames.pop();
                }
            } else {
                return TextProgress::Done;
            }
        }
        TextProgress::Pending
    }
}

impl Iterator for TextCursor {
    type Item = TextPart;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut work = usize::MAX;
            match self.advance(&mut work) {
                TextProgress::Part(part) => return Some(part),
                TextProgress::Done => return None,
                TextProgress::Pending => {}
            }
        }
    }
}

impl std::fmt::Display for RenderedText<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for part in TextCursor::new(self.0.clone()) {
            match part {
                TextPart::Space => formatter.write_str(" ")?,
                TextPart::Value(value) => match value.as_str() {
                    Some(text) => formatter.write_str(text)?,
                    None => write!(formatter, "{value:?}")?,
                },
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;
    use std::collections::BTreeMap;

    #[test]
    fn separators_empty_parts_and_shared_children_keep_their_meaning() -> anyhow::Result<()> {
        let shared = Value::list(vec![Value::string("a".into()), Value::string("b".into())]);
        let request = Value::list(vec![
            Value::list(vec![]),
            Value::string(String::new()),
            shared.clone(),
            Value::map(BTreeMap::from([
                ("text".into(), shared),
                ("prompt".into(), Value::string("ignored".into())),
            ])),
        ]);
        ensure!(render_text(&request) == "  a b a b");
        ensure!(hash_text(&request)? == blake3::hash(b"  a b a b"));
        Ok(())
    }

    #[test]
    fn direct_and_wrapped_text_borrow_the_existing_leaf() -> anyhow::Result<()> {
        let value = Value::string("shared text".repeat(4096));
        let text_pointer = value
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing text"))?
            .as_ptr();
        let direct = render_text(&value);
        ensure!(matches!(direct, Cow::Borrowed(_)) && direct.as_ptr() == text_pointer);
        let wrapped = Value::map(BTreeMap::from([("text".into(), value)]));
        let projection = render_text(&wrapped);
        ensure!(matches!(projection, Cow::Borrowed(_)) && projection.as_ptr() == text_pointer);
        Ok(())
    }

    #[test]
    fn deep_projection_and_release_use_a_small_call_stack() -> anyhow::Result<()> {
        std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| -> anyhow::Result<()> {
                let mut value = Value::string("retained".into());
                for depth in 0..20_000 {
                    value = if depth % 2 == 0 {
                        Value::list(vec![value])
                    } else {
                        Value::map(BTreeMap::from([("prompt".into(), value)]))
                    };
                }
                ensure!(render_text(&value) == "retained");
                drop(value);
                Ok(())
            })?
            .join()
            .map_err(|_panic| anyhow::anyhow!("deep projection thread panicked"))??;
        Ok(())
    }
}
