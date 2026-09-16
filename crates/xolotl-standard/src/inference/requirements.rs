//! Capability discovery from a resident request, independent of backend selection.

use super::RequestRequirements;
use xolotl_types::{FrameKind, ModalitySet, OutputMode, Value, ValueView};

pub(super) fn requirements_of(input: &Value, output: OutputMode) -> RequestRequirements {
    let mut requirements = RequestRequirements {
        modality: ModalitySet::TEXT,
        needs_streaming: matches!(output, OutputMode::Stream),
        ..Default::default()
    };
    for value in crate::input::inspection_values(input) {
        match value.view() {
            ValueView::Blob(_) => {
                requirements.needs_vision = true;
                requirements.modality |= ModalitySet::IMAGE;
            }
            ValueView::Frame(frame) => {
                if frame.kind == FrameKind::Audio {
                    requirements.needs_audio = true;
                    requirements.modality |= ModalitySet::AUDIO;
                } else {
                    requirements.modality |= ModalitySet::VIDEO;
                }
            }
            ValueView::Map(map) => {
                requirements.needs_json |= map.get("response_format").and_then(Value::as_str)
                    == Some("json")
                    || map.get("json").and_then(Value::as_bool) == Some(true);
                requirements.needs_tools |= map.get("tools").is_some();
            }
            _ => {}
        }
    }
    requirements
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;
    use std::collections::BTreeMap;
    use xolotl_types::BlobRef;

    #[test]
    fn capability_scan_handles_shared_subgraphs_without_expanding_them() -> anyhow::Result<()> {
        let blob = BlobRef {
            hash: "fixture".into(),
            size: 0,
            mime: None,
        };
        let mut request = Value::map(BTreeMap::from([
            ("json".into(), Value::boolean(true)),
            ("tools".into(), Value::list(vec![])),
            ("image".into(), Value::blob(blob.clone())),
            ("audio".into(), Value::frame(blob, 1, FrameKind::Audio)),
        ]));
        for _ in 0..80 {
            request = Value::list(vec![request.clone(), request]);
        }
        let requirements = requirements_of(&request, OutputMode::Stream);
        ensure!(
            requirements.needs_streaming && requirements.needs_json && requirements.needs_tools
        );
        ensure!(requirements.needs_vision && requirements.needs_audio);
        ensure!(
            requirements
                .modality
                .contains(ModalitySet::IMAGE | ModalitySet::AUDIO)
        );
        Ok(())
    }
}
