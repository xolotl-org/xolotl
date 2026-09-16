//! Immutable public State declarations shared by every identical request sample.

use anyhow::Context;
use std::{collections::BTreeMap, num::NonZeroUsize};
use xolotl_types::{
    InferenceApiDialect, InferenceAuthRef, InferenceBackendDef, InferenceGroupDef,
    InferenceGroupPolicy, InferenceModelCapabilities, InferenceModelDef, InferenceResponseLimits,
    InferenceRoutingDef, Path, Value,
};

pub(super) fn declarations(
    base_url: &str,
    window: NonZeroUsize,
) -> anyhow::Result<[(Path, Value); 4]> {
    Ok([
        entry(
            "state://kernel/inference/backends/bench",
            &InferenceBackendDef {
                id: "bench".into(),
                dialect: InferenceApiDialect::OpenAiResponses,
                base_url: base_url.into(),
                auth: InferenceAuthRef::None,
                default_headers: BTreeMap::new(),
                request_overrides: BTreeMap::new(),
                api_version: None,
                io_window_bytes: Some(window),
                response_limits: InferenceResponseLimits {
                    max_materialized_bytes: Some(4),
                    max_materialized_nodes: Some(8),
                    max_json_frames: Some(16),
                },
                version: 0,
            },
        )?,
        entry(
            "state://kernel/inference/models/bench",
            &InferenceModelDef {
                id: "bench".into(),
                backend_id: "bench".into(),
                provider_model: "bench".into(),
                embedding_model: None,
                capabilities: InferenceModelCapabilities {
                    streaming: true,
                    ..Default::default()
                },
                weight: 1,
                version: 0,
            },
        )?,
        entry(
            "state://kernel/inference/groups/default",
            &InferenceGroupDef {
                name: "default".into(),
                policy: InferenceGroupPolicy::Priority,
                models: vec!["bench".into()],
                fallback: None,
                version: 0,
            },
        )?,
        entry(
            "state://kernel/routing/inference",
            &InferenceRoutingDef {
                default_group: "default".into(),
                max_retries: Some(0),
                version: 0,
            },
        )?,
    ])
}

fn entry(path: &str, declaration: &impl serde::Serialize) -> anyhow::Result<(Path, Value)> {
    let value = serde_json::from_value(serde_json::to_value(declaration)?)
        .context("invalid provider fixture declaration")?;
    Ok((Path::parse(path)?, value))
}
