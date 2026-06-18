//! Runtime declarations for in-process Provider and Source projections.

use crate::external::{EventSource, OverflowPolicy, Role};
use crate::{EffectCapability, Path, Value};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

/// In-process projection declaration stored under
/// `state://kernel/projections/in-process/<id>`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InProcessProjectionDef {
    /// Declaration id used in the state path.
    pub id: String,
    /// Whether this projection provides effects or emits source events.
    pub role: Role,
    /// Implementation id resolved by the host's in-process registry.
    pub implementation: String,
    /// Provider role: effect resources this projection exposes.
    #[serde(default)]
    pub provides: Vec<EffectCapability>,
    /// Source role: event stream this projection writes to.
    #[serde(default)]
    pub emits: Option<EventSource>,
    /// Implementation-specific configuration.
    #[serde(default)]
    pub config: Value,
    /// Optimistic concurrency version.
    #[serde(default)]
    pub version: u64,
}

/// Admission failures for in-process projection declarations.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum InProcessProjectionConfigError {
    /// Required field was empty.
    #[error("{field} must not be empty")]
    EmptyField {
        /// Field name.
        field: &'static str,
    },
    /// Id was not safe to use as a state path segment.
    #[error("{field} is not a safe id segment")]
    BadId {
        /// Field name.
        field: &'static str,
    },
    /// Path id and value id differed.
    #[error("{field} {value:?} does not match path id {path:?}")]
    PathIdMismatch {
        /// Field name.
        field: &'static str,
        /// Id from the value.
        value: String,
        /// Id from the state path.
        path: String,
    },
    /// Implementation id was malformed.
    #[error("implementation is not a safe dotted id")]
    BadImplementation,
    /// Provider projection declared no capabilities.
    #[error("provider projection must declare at least one provided effect")]
    ProviderWithoutCapabilities,
    /// Provider projection also declared source events.
    #[error("provider projection must not declare a source event stream")]
    ProviderWithEventSource,
    /// Source projection declared no event sink.
    #[error("source projection must declare an event stream")]
    SourceWithoutEventStream,
    /// Source projection also declared provider capabilities.
    #[error("source projection must not declare provider capabilities")]
    SourceWithCapabilities,
    /// Effect path could not be parsed.
    #[error("provided effect path is malformed: {0}")]
    MalformedEffectPath(String),
    /// Effect path was not an effect resource.
    #[error("provided effect path must be a concrete effect:// path: {0}")]
    BadEffectPath(String),
    /// Effect path targeted a kernel-reserved effect.
    #[error("provided effect path must not target effect://kernel/*")]
    KernelEffectPath,
    /// Effect path was duplicated.
    #[error("provided effect path {0:?} is duplicated")]
    DuplicateEffectPath(String),
    /// Source event sink was not a concrete local state path.
    #[error("source event sink must be a concrete local non-reserved state:// path: {0}")]
    BadSourceEventSink(String),
    /// Source commands were enabled without command schemas.
    #[error("source commands require command_schema and command_result_schema")]
    SourceCommandsWithoutSchemas,
    /// Source event payload size limit was invalid.
    #[error("source max_inline_payload_bytes must be greater than zero")]
    InvalidSourcePayloadLimit,
    /// Source stream capacity was invalid.
    #[error("source stream capacity max_events must be greater than zero")]
    InvalidSourceCapacity,
    /// Source backpressure thresholds were invalid.
    #[error(
        "source backpressure thresholds must satisfy resume_threshold < pause_threshold <= max_events"
    )]
    InvalidSourceBackpressureThresholds,
    /// Source ingress rate limit was invalid.
    #[error("source rate_limit window_ms and max_events must be greater than zero")]
    InvalidSourceRateLimit,
    /// Version was not a positive config revision.
    #[error("version must be a positive config revision")]
    InvalidVersion,
}

impl InProcessProjectionDef {
    /// Validate this declaration against its state path id.
    pub fn validate_admission(&self, path_id: &str) -> Result<(), InProcessProjectionConfigError> {
        validate_id("id", &self.id)?;
        ensure_path_id("id", &self.id, path_id)?;
        if self.implementation.trim().is_empty() {
            return Err(InProcessProjectionConfigError::EmptyField {
                field: "implementation",
            });
        }
        if !is_safe_dotted_id(&self.implementation) {
            return Err(InProcessProjectionConfigError::BadImplementation);
        }
        if self.version == 0 {
            return Err(InProcessProjectionConfigError::InvalidVersion);
        }
        match self.role {
            Role::Provider => self.validate_provider(),
            Role::Source => self.validate_source(),
        }
    }

    fn validate_provider(&self) -> Result<(), InProcessProjectionConfigError> {
        if self.provides.is_empty() {
            return Err(InProcessProjectionConfigError::ProviderWithoutCapabilities);
        }
        if self.emits.is_some() {
            return Err(InProcessProjectionConfigError::ProviderWithEventSource);
        }
        let mut seen = BTreeSet::new();
        for capability in &self.provides {
            let effect = Path::parse(&capability.effect_path).map_err(|_| {
                InProcessProjectionConfigError::MalformedEffectPath(capability.effect_path.clone())
            })?;
            if effect.scheme() != "effect" || effect.segments().is_empty() {
                return Err(InProcessProjectionConfigError::BadEffectPath(
                    capability.effect_path.clone(),
                ));
            }
            if effect.segments().first().map(|segment| segment.as_str()) == Some("kernel") {
                return Err(InProcessProjectionConfigError::KernelEffectPath);
            }
            if !seen.insert(effect) {
                return Err(InProcessProjectionConfigError::DuplicateEffectPath(
                    capability.effect_path.clone(),
                ));
            }
        }
        Ok(())
    }

    fn validate_source(&self) -> Result<(), InProcessProjectionConfigError> {
        if !self.provides.is_empty() {
            return Err(InProcessProjectionConfigError::SourceWithCapabilities);
        }
        let emits = self
            .emits
            .as_ref()
            .ok_or(InProcessProjectionConfigError::SourceWithoutEventStream)?;
        validate_source_event_sink(&emits.sink)?;
        if emits.commands
            && (emits.command_schema.is_none() || emits.command_result_schema.is_none())
        {
            return Err(InProcessProjectionConfigError::SourceCommandsWithoutSchemas);
        }
        if emits.max_inline_payload_bytes == 0 {
            return Err(InProcessProjectionConfigError::InvalidSourcePayloadLimit);
        }
        validate_source_capacity(emits)?;
        if let Some(rate_limit) = emits.rate_limit.as_ref()
            && (rate_limit.window_ms == 0 || rate_limit.max_events == 0)
        {
            return Err(InProcessProjectionConfigError::InvalidSourceRateLimit);
        }
        Ok(())
    }
}

fn ensure_path_id(
    field: &'static str,
    value: &str,
    path: &str,
) -> Result<(), InProcessProjectionConfigError> {
    if value == path {
        Ok(())
    } else {
        Err(InProcessProjectionConfigError::PathIdMismatch {
            field,
            value: value.to_string(),
            path: path.to_string(),
        })
    }
}

fn validate_id(field: &'static str, id: &str) -> Result<(), InProcessProjectionConfigError> {
    if id.trim().is_empty() {
        return Err(InProcessProjectionConfigError::EmptyField { field });
    }
    if !is_safe_id_segment(id) {
        return Err(InProcessProjectionConfigError::BadId { field });
    }
    Ok(())
}

fn is_safe_id_segment(id: &str) -> bool {
    let mut chars = id.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn is_safe_dotted_id(id: &str) -> bool {
    id.split('.').all(is_safe_id_segment)
}

fn validate_source_event_sink(path: &Path) -> Result<(), InProcessProjectionConfigError> {
    let concrete = path
        .segments()
        .iter()
        .all(|seg| !matches!(seg.as_str(), "*" | "**"));
    if path.cluster().is_none()
        && path.scheme() == "state"
        && !path.segments().is_empty()
        && concrete
        && !crate::is_kernel_reserved(path)
        && !crate::is_vault_reserved(path)
        && !crate::is_fact_reserved(path)
    {
        Ok(())
    } else {
        Err(InProcessProjectionConfigError::BadSourceEventSink(
            path.to_string(),
        ))
    }
}

fn validate_source_capacity(emits: &EventSource) -> Result<(), InProcessProjectionConfigError> {
    if emits.capacity.max_events == 0 {
        return Err(InProcessProjectionConfigError::InvalidSourceCapacity);
    }
    if let OverflowPolicy::Backpressure {
        pause_threshold,
        resume_threshold,
    } = &emits.capacity.on_overflow
        && (resume_threshold >= pause_threshold || pause_threshold > &emits.capacity.max_events)
    {
        return Err(InProcessProjectionConfigError::InvalidSourceBackpressureThresholds);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OverflowPolicy, Purity, StreamCapacity};
    use anyhow::{Context, Result, ensure};

    fn provider_def(id: &str) -> InProcessProjectionDef {
        InProcessProjectionDef {
            id: id.into(),
            role: Role::Provider,
            implementation: "standard.fetch".into(),
            provides: vec![EffectCapability::new(
                "effect://fetch/get",
                Purity::Effectful,
            )],
            emits: None,
            config: Value::Null,
            version: 1,
        }
    }

    #[test]
    fn admits_generic_in_process_provider_projection() -> Result<()> {
        provider_def("fetch")
            .validate_admission("fetch")
            .context("admit declaration")
    }

    #[test]
    fn rejects_path_mismatch() -> Result<()> {
        let result = provider_def("fetch").validate_admission("other");
        ensure!(
            matches!(
                result,
                Err(InProcessProjectionConfigError::PathIdMismatch { .. })
            ),
            "expected path mismatch, got {result:?}"
        );
        Ok(())
    }

    #[test]
    fn rejects_kernel_effect_path() -> Result<()> {
        let mut value = provider_def("bad");
        value.provides[0].effect_path = "effect://kernel/process/inspect".into();
        let result = value.validate_admission("bad");
        ensure!(
            matches!(
                result,
                Err(InProcessProjectionConfigError::KernelEffectPath)
            ),
            "expected kernel effect rejection, got {result:?}"
        );
        Ok(())
    }

    #[test]
    fn admits_source_projection_shape() -> Result<()> {
        let value = InProcessProjectionDef {
            id: "events".into(),
            role: Role::Source,
            implementation: "standard.events".into(),
            provides: Vec::new(),
            emits: Some(EventSource {
                sink: Path::parse("state://events/local/test")?,
                purity: Purity::Effectful,
                event_schema: None,
                max_inline_payload_bytes: 1024,
                capacity: stream_capacity(),
                rate_limit: None,
                commands: false,
                command_schema: None,
                command_result_schema: None,
            }),
            config: Value::Null,
            version: 1,
        };
        value
            .validate_admission("events")
            .context("admit source projection")
    }

    #[test]
    fn rejects_source_kernel_sink() -> Result<()> {
        let value = InProcessProjectionDef {
            id: "events".into(),
            role: Role::Source,
            implementation: "standard.events".into(),
            provides: Vec::new(),
            emits: Some(EventSource {
                sink: Path::parse("state://kernel/events/test")?,
                purity: Purity::Effectful,
                event_schema: None,
                max_inline_payload_bytes: 1024,
                capacity: stream_capacity(),
                rate_limit: None,
                commands: false,
                command_schema: None,
                command_result_schema: None,
            }),
            config: Value::Null,
            version: 1,
        };
        let result = value.validate_admission("events");
        ensure!(
            matches!(
                result,
                Err(InProcessProjectionConfigError::BadSourceEventSink(_))
            ),
            "expected source sink rejection, got {result:?}"
        );
        Ok(())
    }

    fn stream_capacity() -> StreamCapacity {
        StreamCapacity {
            max_events: 16,
            on_overflow: OverflowPolicy::DropOldest,
        }
    }
}
