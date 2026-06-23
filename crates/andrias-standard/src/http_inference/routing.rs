use super::backend::HttpInferenceBackend;
use super::config::HttpInferenceConfig;
use super::error::HttpInferenceError;
use crate::router::{GroupPolicy, ModelEntry, ModelGroup, Router};
use std::collections::{BTreeMap, BTreeSet};

/// One HTTP inference provider registered into an inference router.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct HttpInferenceRoute {
    /// HTTP inference provider backend configuration.
    pub(crate) config: HttpInferenceConfig,
    /// Relative routing weight.
    pub(crate) weight: u32,
}

impl HttpInferenceRoute {
    /// Create a route entry with weight `1`.
    pub(crate) fn new(config: HttpInferenceConfig) -> Self {
        Self { config, weight: 1 }
    }

    /// Set the route weight used by weighted groups.
    pub(crate) fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight.max(1);
        self
    }
}

/// An HTTP inference provider routing group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HttpInferenceGroup {
    /// Group name.
    pub(crate) name: String,
    /// Selection policy inside the group.
    pub(crate) policy: GroupPolicy,
    /// Model ids in priority order.
    pub(crate) models: Vec<String>,
    /// Optional fallback group.
    pub(crate) fallback: Option<String>,
}

impl HttpInferenceGroup {
    /// Create a group from model ids.
    pub(crate) fn new(
        name: impl Into<String>,
        policy: GroupPolicy,
        models: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            name: name.into(),
            policy,
            models: models.into_iter().map(Into::into).collect(),
            fallback: None,
        }
    }

    /// Set this group's fallback group.
    pub(crate) fn with_fallback(mut self, fallback: impl Into<String>) -> Self {
        self.fallback = Some(fallback.into());
        self
    }
}

/// HTTP inference provider router configuration.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct HttpInferenceRouterConfig {
    /// HTTP inference provider routes.
    pub(crate) routes: Vec<HttpInferenceRoute>,
    /// Optional routing groups.
    pub(crate) groups: Vec<HttpInferenceGroup>,
    /// Optional default group name.
    pub(crate) default_group: Option<String>,
    /// Retry count for retryable model errors.
    pub(crate) max_retries: Option<u32>,
}

impl HttpInferenceRouterConfig {
    /// Create an empty router configuration.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Add an HTTP inference provider route.
    pub(crate) fn with_route(mut self, route: HttpInferenceRoute) -> Self {
        self.routes.push(route);
        self
    }

    /// Add a routing group.
    pub(crate) fn with_group(mut self, group: HttpInferenceGroup) -> Self {
        self.groups.push(group);
        self
    }

    /// Set the default routing group.
    pub(crate) fn with_default_group(mut self, group: impl Into<String>) -> Self {
        self.default_group = Some(group.into());
        self
    }

    /// Set the retry count used for retryable model errors.
    pub(crate) fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = Some(max_retries);
        self
    }

    /// Build a [`Router`] with HTTP inference provider backends.
    pub(crate) fn build(self) -> Result<Router, HttpInferenceError> {
        if self.routes.is_empty() {
            return Err(HttpInferenceError::EmptyModelSet);
        }

        let mut entries = Vec::with_capacity(self.routes.len());
        let mut model_index = BTreeMap::new();
        for route in self.routes {
            let id = route.config.id.clone();
            if model_index.contains_key(&id) {
                return Err(HttpInferenceError::DuplicateModelId(id));
            }
            let backend = HttpInferenceBackend::new(route.config)?;
            let idx = entries.len();
            entries.push(
                ModelEntry::new(id.clone(), std::sync::Arc::new(backend)).with_weight(route.weight),
            );
            model_index.insert(id, idx);
        }

        let groups = self.groups;
        let mut known_group_names = BTreeSet::from(["default".to_string()]);
        let mut configured_group_names = BTreeSet::new();
        for group in &groups {
            if group.name.trim().is_empty() {
                return Err(HttpInferenceError::EmptyField {
                    field: "group.name",
                });
            }
            if !configured_group_names.insert(group.name.clone()) {
                return Err(HttpInferenceError::DuplicateGroup(group.name.clone()));
            }
            known_group_names.insert(group.name.clone());
        }

        let mut router = Router::new(entries);
        for group in groups {
            if group.models.is_empty() {
                return Err(HttpInferenceError::EmptyGroup {
                    group: group.name.clone(),
                });
            }
            if let Some(fallback) = &group.fallback
                && !known_group_names.contains(fallback)
            {
                return Err(HttpInferenceError::UnknownFallbackGroup {
                    group: group.name.clone(),
                    fallback: fallback.clone(),
                });
            }
            let mut members = Vec::with_capacity(group.models.len());
            for model in &group.models {
                let Some(idx) = model_index.get(model) else {
                    return Err(HttpInferenceError::UnknownGroupModel {
                        group: group.name.clone(),
                        model: model.clone(),
                    });
                };
                members.push(*idx);
            }
            let mut router_group = ModelGroup::new(group.name.clone(), group.policy, members);
            if let Some(fallback) = group.fallback {
                router_group = router_group.with_fallback(fallback);
            }
            router.add_group(router_group);
        }

        if let Some(default_group) = self.default_group {
            if !known_group_names.contains(&default_group) {
                return Err(HttpInferenceError::UnknownDefaultGroup(default_group));
            }
            router.set_default_group(default_group);
        }
        if let Some(max_retries) = self.max_retries {
            router.set_max_retries(max_retries);
        }
        Ok(router)
    }
}
