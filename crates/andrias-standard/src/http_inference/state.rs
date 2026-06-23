use super::config::{HttpInferenceAuth, HttpInferenceConfig};
use super::error::HttpInferenceError;
use super::routing::{HttpInferenceGroup, HttpInferenceRoute, HttpInferenceRouterConfig};
use crate::inference::{InferenceMethodSupport, ModelCapabilities};
use crate::router::{GroupPolicy, Router};
use andrias_state::Backend;
use andrias_types::{
    InferenceAuthRef, InferenceBackendDef, InferenceGroupDef, InferenceGroupPolicy,
    InferenceModelCapabilities, InferenceModelDef, InferenceRoutingDef, Path, Value,
};
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Build an inference router from `state://kernel/inference/*` declarations.
///
/// Returns `Ok(None)` when no HTTP inference provider declarations are present.
pub(crate) async fn router_from_state(
    state: &Backend,
) -> Result<Option<Arc<Router>>, HttpInferenceError> {
    let backend_values = read_prefix_values(state, "state://kernel/inference/backends").await?;
    let model_values = read_prefix_values(state, "state://kernel/inference/models").await?;
    if backend_values.is_empty() && model_values.is_empty() {
        return Ok(None);
    }
    if backend_values.is_empty() || model_values.is_empty() {
        return Err(HttpInferenceError::IncompleteStateConfig);
    }

    let mut backends = BTreeMap::new();
    for (path, value) in backend_values {
        let def: InferenceBackendDef = decode_state_value(value, "InferenceBackendDef")?;
        let path_id = path_tail(&path, "InferenceBackendDef")?;
        def.validate_admission(path_id)
            .map_err(|source| HttpInferenceError::StateAdmission {
                label: "InferenceBackendDef",
                source,
            })?;
        backends.insert(def.id.clone(), def);
    }

    let mut routing_config = HttpInferenceRouterConfig::new();
    let mut qualified_models = BTreeMap::new();
    for (path, value) in model_values {
        let model: InferenceModelDef = decode_state_value(value, "InferenceModelDef")?;
        let path_id = path_tail(&path, "InferenceModelDef")?;
        model
            .validate_admission(path_id)
            .map_err(|source| HttpInferenceError::StateAdmission {
                label: "InferenceModelDef",
                source,
            })?;
        let backend =
            backends
                .get(&model.backend_id)
                .ok_or_else(|| HttpInferenceError::UnknownBackend {
                    model: model.id.clone(),
                    backend: model.backend_id.clone(),
                })?;
        let auth = resolve_auth(state, &backend.auth).await?;
        let config = runtime_config_from_defs(backend, &model, auth)?;
        qualified_models.insert(model.id.clone(), config.id.clone());
        routing_config =
            routing_config.with_route(HttpInferenceRoute::new(config).with_weight(model.weight));
    }

    for (path, value) in read_prefix_values(state, "state://kernel/inference/groups").await? {
        let group: InferenceGroupDef = decode_state_value(value, "InferenceGroupDef")?;
        let path_name = path_tail(&path, "InferenceGroupDef")?;
        group.validate_admission(path_name).map_err(|source| {
            HttpInferenceError::StateAdmission {
                label: "InferenceGroupDef",
                source,
            }
        })?;
        let models: Vec<String> = group
            .models
            .into_iter()
            .map(|model| qualified_models.get(&model).cloned().unwrap_or(model))
            .collect();
        let mut route_group =
            HttpInferenceGroup::new(group.name, group_policy_from_def(group.policy), models);
        if let Some(fallback) = group.fallback {
            route_group = route_group.with_fallback(fallback);
        }
        routing_config = routing_config.with_group(route_group);
    }

    if let Some(value) = state_read(state, "state://kernel/routing/inference").await? {
        let routing: InferenceRoutingDef = decode_state_value(value, "InferenceRoutingDef")?;
        routing
            .validate_admission()
            .map_err(|source| HttpInferenceError::StateAdmission {
                label: "InferenceRoutingDef",
                source,
            })?;
        routing_config = routing_config.with_default_group(routing.default_group);
        if let Some(max_retries) = routing.max_retries {
            routing_config = routing_config.with_max_retries(max_retries);
        }
    }

    routing_config.build().map(Arc::new).map(Some)
}

async fn read_prefix_values(
    state: &Backend,
    prefix: &str,
) -> Result<Vec<(Path, Value)>, HttpInferenceError> {
    let path = Path::parse(prefix).map_err(|e| HttpInferenceError::State(e.to_string()))?;
    state
        .read_prefix(&path)
        .await
        .map_err(|e| HttpInferenceError::State(e.to_string()))
}

async fn state_read(state: &Backend, path: &str) -> Result<Option<Value>, HttpInferenceError> {
    let path = Path::parse(path).map_err(|e| HttpInferenceError::State(e.to_string()))?;
    state
        .read(&path)
        .await
        .map_err(|e| HttpInferenceError::State(e.to_string()))
}

fn decode_state_value<T: serde::de::DeserializeOwned>(
    value: Value,
    label: &'static str,
) -> Result<T, HttpInferenceError> {
    let json = serde_json::to_value(value)
        .map_err(|source| HttpInferenceError::StateDecode { label, source })?;
    serde_json::from_value(json).map_err(|source| HttpInferenceError::StateDecode { label, source })
}

fn path_tail<'a>(path: &'a Path, label: &'static str) -> Result<&'a str, HttpInferenceError> {
    path.segments()
        .last()
        .map(|segment| segment.as_str())
        .ok_or_else(|| HttpInferenceError::StatePath {
            label,
            path: path.to_string(),
        })
}

async fn resolve_auth(
    state: &Backend,
    auth: &InferenceAuthRef,
) -> Result<HttpInferenceAuth, HttpInferenceError> {
    match auth {
        InferenceAuthRef::None => Ok(HttpInferenceAuth::None),
        InferenceAuthRef::BearerToken { token_ref } => {
            let token = read_secret_string(state, token_ref).await?;
            Ok(HttpInferenceAuth::bearer_token(token))
        }
        InferenceAuthRef::ApiKeyHeader { header, value_ref } => {
            let value = read_secret_string(state, value_ref).await?;
            Ok(HttpInferenceAuth::api_key_header(header.clone(), value))
        }
    }
}

async fn read_secret_string(state: &Backend, path: &Path) -> Result<String, HttpInferenceError> {
    let Some(value) = state
        .read(path)
        .await
        .map_err(|e| HttpInferenceError::State(e.to_string()))?
    else {
        return Err(HttpInferenceError::MissingSecret(path.to_string()));
    };
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| HttpInferenceError::BadSecret(path.to_string()))
}

fn runtime_config_from_defs(
    backend: &InferenceBackendDef,
    model: &InferenceModelDef,
    auth: HttpInferenceAuth,
) -> Result<HttpInferenceConfig, HttpInferenceError> {
    let mut config = HttpInferenceConfig::new(
        qualified_model_id(&backend.id, &model.id),
        backend.dialect,
        backend.base_url.clone(),
        model.provider_model.clone(),
        auth,
    );
    config.embedding_model = model.embedding_model.clone();
    if let Some(embedding_model) = &config.embedding_model {
        config.embedding_space_id =
            Some(format!("http-inference/{}/{}", backend.id, embedding_model));
    }
    config.capabilities = capabilities_from_def(model.capabilities);
    config.options.default_headers = backend.default_headers.clone();
    config.options.request_overrides = value_overrides_to_json(&backend.request_overrides)?;
    config.options.api_version = backend.api_version.clone();
    Ok(config)
}

fn qualified_model_id(backend_id: &str, model_id: &str) -> String {
    format!("{backend_id}/{model_id}")
}

fn value_overrides_to_json(
    overrides: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, JsonValue>, HttpInferenceError> {
    let mut out = BTreeMap::new();
    for (key, value) in overrides {
        let json = serde_json::to_value(value).map_err(HttpInferenceError::RequestJson)?;
        out.insert(key.clone(), json);
    }
    Ok(out)
}

fn capabilities_from_def(caps: InferenceModelCapabilities) -> ModelCapabilities {
    ModelCapabilities {
        methods: InferenceMethodSupport {
            infer: caps.methods.infer,
            embed: caps.methods.embed,
            rerank: caps.methods.rerank,
            plan: caps.methods.plan,
        },
        modality: caps.modality,
        tools: caps.tools,
        vision: caps.vision,
        audio: caps.audio,
        json: caps.json,
        streaming: caps.streaming,
    }
}

fn group_policy_from_def(policy: InferenceGroupPolicy) -> GroupPolicy {
    match policy {
        InferenceGroupPolicy::Priority => GroupPolicy::Priority,
        InferenceGroupPolicy::RoundRobin => GroupPolicy::RoundRobin,
        InferenceGroupPolicy::Latency => GroupPolicy::Latency,
        InferenceGroupPolicy::Weighted => GroupPolicy::Weighted,
    }
}
