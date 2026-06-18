use thiserror::Error;

/// HTTP inference provider construction and protocol errors.
#[derive(Debug, Error)]
pub(crate) enum HttpInferenceError {
    /// Required config field was blank.
    #[error("{field} must not be empty")]
    EmptyField {
        /// Field name.
        field: &'static str,
    },
    /// Config requested a disabled dialect feature.
    #[error("HTTP inference provider dialect is not enabled: {0}")]
    DialectDisabled(&'static str),
    /// Base URL was invalid.
    #[error("HTTP inference provider base_url is invalid")]
    BadBaseUrl,
    /// Header name or value was invalid.
    #[error("HTTP inference provider header is invalid: {0}")]
    BadHeader(String),
    /// Request override tried to set a reserved field.
    #[error("HTTP inference provider request field is reserved: {0}")]
    ReservedRequestField(String),
    /// Numeric option was invalid.
    #[error("HTTP inference provider numeric option is invalid: {0}")]
    InvalidNumber(&'static str),
    /// Router config did not contain models.
    #[error("HTTP inference provider router has no models")]
    EmptyModelSet,
    /// Router config declared the same model id more than once.
    #[error("HTTP inference provider id is duplicated: {0}")]
    DuplicateModelId(String),
    /// Router config declared the same group more than once.
    #[error("HTTP inference provider group is duplicated: {0}")]
    DuplicateGroup(String),
    /// Router group has no members.
    #[error("HTTP inference provider group has no models: {group}")]
    EmptyGroup {
        /// Group name.
        group: String,
    },
    /// Router group referenced an unknown model.
    #[error("HTTP inference provider group {group:?} references unknown model {model:?}")]
    UnknownGroupModel {
        /// Group name.
        group: String,
        /// Unknown model id.
        model: String,
    },
    /// Router config referenced an unknown default group.
    #[error("HTTP inference provider default group is unknown: {0}")]
    UnknownDefaultGroup(String),
    /// Router group referenced an unknown fallback group.
    #[error(
        "HTTP inference provider group {group:?} references unknown fallback group {fallback:?}"
    )]
    UnknownFallbackGroup {
        /// Group containing the fallback reference.
        group: String,
        /// Missing fallback group.
        fallback: String,
    },
    /// Request contains a payload this backend cannot send safely.
    #[error("HTTP inference provider request payload is unsupported: {0}")]
    UnsupportedPayload(&'static str),
    /// The dialect does not support embeddings here.
    #[error("HTTP inference provider backend does not support embed")]
    EmbedUnsupported,
    /// HTTP request failed.
    #[error("HTTP inference provider request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// Request JSON could not be serialized.
    #[error("HTTP inference provider request JSON failed: {0}")]
    RequestJson(#[source] serde_json::Error),
    /// Response JSON could not be parsed.
    #[error("HTTP inference provider response JSON failed: {0}")]
    ResponseJson(#[source] serde_json::Error),
    /// Provider returned a non-success status.
    #[error("HTTP inference provider returned HTTP {status}: {body}")]
    ProviderHttpStatus {
        /// HTTP status code.
        status: u16,
        /// Redacted response body.
        body: String,
    },
    /// Provider response did not contain expected content.
    #[error("HTTP inference provider response missing field: {0}")]
    MissingResponseField(&'static str),
    /// State read failed while loading HTTP inference provider declarations.
    #[error("HTTP inference provider state read failed: {0}")]
    State(String),
    /// State value could not be decoded as an inference declaration.
    #[error("{label} is malformed: {source}")]
    StateDecode {
        /// Declaration type.
        label: &'static str,
        /// Decode error.
        #[source]
        source: serde_json::Error,
    },
    /// State path did not match the expected declaration shape.
    #[error("{label} state path is invalid: {path}")]
    StatePath {
        /// Declaration type.
        label: &'static str,
        /// State path.
        path: String,
    },
    /// State value failed declaration admission.
    #[error("{label} admission failed: {source}")]
    StateAdmission {
        /// Declaration type.
        label: &'static str,
        /// Admission error.
        #[source]
        source: nexus_types::InferenceConfigError,
    },
    /// State contains only part of the HTTP inference provider configuration.
    #[error("HTTP inference provider state config must include both backends and models")]
    IncompleteStateConfig,
    /// State contains no HTTP inference provider declarations.
    #[error("HTTP inference provider state config is not declared")]
    MissingStateConfig,
    /// A model references a backend id that is not declared.
    #[error("HTTP inference provider {model:?} references unknown backend {backend:?}")]
    UnknownBackend {
        /// Model id.
        model: String,
        /// Missing backend id.
        backend: String,
    },
    /// Secret reference was not present.
    #[error("HTTP inference provider secret is missing: {0}")]
    MissingSecret(String),
    /// Secret reference did not contain a string.
    #[error("HTTP inference provider secret must be a string: {0}")]
    BadSecret(String),
}
