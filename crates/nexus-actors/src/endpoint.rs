//! Endpoint session supervisor (§16.3.3 / §16.3.4): the per-extension session
//! state machine that gates the 3-stage handshake and enforces the fail-closed
//! frame discipline, plus the secure-envelope (PSK) credential layer.
//!
//! An out-of-process Source/Provider connects and runs:
//! ```text
//!   stage 1: extension → RoleSessionClientHello   (identity + cached generations)
//!   stage 2: daemon    → SessionContext           (authoritative generations)
//!   stage 3: extension → RoleReady(accepted)      (confirms alignment)
//! ```
//! The daemon dispatches **no business frame** (`Invoke`, inbound event) before
//! `RoleReady` (§16.3.3). After it, every Source frame's `ObservedGenerations`
//! must match the session's, and frames bearing a revoked credential generation
//! are rejected (§16.3.4 fail-closed invariants). This module is the in-process
//! state machine + envelope crypto; the live gRPC transport binds to it.

use nexus_kernel::{CheckCtx, PolicyDecision, PolicySnapshot};
use nexus_state::{Backend, StateError};
use nexus_types::extension::{
    AckStatus, EventAck, ExtensionProjectionDef, InboundEvent, JsonSchema, ObservedGenerations,
    Role, RoleReady, RoleSessionClientHello, SessionContext,
};
use nexus_types::{IdentityRef, Path, ResourceId, TaintSet, TaintSource, Value};
use std::collections::BTreeSet;

/// Where a session is in the handshake (§16.3.3). Business frames are only
/// admitted in [`SessionPhase::Ready`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionPhase {
    /// Connected; awaiting the extension's `RoleSessionClientHello` (stage 1).
    AwaitingHello,
    /// Hello received, `SessionContext` sent; awaiting `RoleReady` (stage 3).
    AwaitingReady,
    /// Handshake complete; business frames flow.
    Ready,
    /// Terminally closed (mismatch / revoked / shutdown). Fail-closed.
    Closed,
}

/// Why a frame was rejected by the session gate (§16.3.3 / §16.3.4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionReject {
    /// A business frame arrived before the handshake completed.
    NotReady,
    /// A handshake frame arrived in the wrong phase.
    OutOfOrder,
    /// The extension's confirmed context did not match the daemon's.
    ContextMismatch,
    /// A Source frame's observed generations are stale vs the session.
    StaleGeneration,
    /// The frame's credential generation has been revoked.
    RevokedCredential,
    /// The session is closed.
    Closed,
}

/// Why a Source event ingest was rejected at the daemon boundary (§16.3.4).
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceIngestError {
    #[error("session rejected frame: {0:?}")]
    Session(SessionReject),
    #[error("source projection {0} is not the ready session projection")]
    ProjectionMismatch(String),
    #[error("source session registry hash mismatch")]
    RegistryHashMismatch,
    #[error("source session credential generation mismatch")]
    CredentialGenerationMismatch,
    #[error("source session binding generation mismatch")]
    BindingGenerationMismatch,
    #[error("source session installation config version mismatch")]
    InstallationConfigVersionMismatch,
    #[error("source session projection version mismatch")]
    ProjectionVersionMismatch,
    #[error("extension is not a Source")]
    NotSource,
    #[error("source extension has no emits declaration")]
    MissingEmits,
    #[error("source event id is empty after path normalization")]
    InvalidEventId,
    #[error("payload schema mismatch: {0}")]
    Schema(String),
    #[error("policy rejected source event: {0}")]
    Policy(String),
    #[error("state write failed: {0}")]
    State(String),
}

/// Runtime authority required to admit one inbound Source event (§16.3.4).
pub struct SourceIngest<'a> {
    pub state: Backend,
    pub session: &'a EndpointSession,
    pub installation_id: &'a str,
    pub projection: &'a ExtensionProjectionDef,
    pub current_registry_hash: &'a str,
    pub credential_generation: u64,
    pub current_binding_generation: u64,
    pub current_installation_config_version: u64,
    pub policy: &'a PolicySnapshot,
    pub acting: IdentityRef,
    /// Resource id for the declared event sink. Source policy uses this as the
    /// runtime target key; callers that have not registered a concrete Resource
    /// can pass `ResourceId::new(0)` and still get input-dependent checks.
    pub target: ResourceId,
    pub now_millis: i64,
}

/// Authoritative daemon ingest for one [`InboundEvent`] (§16.3.4). This is the
/// only place an extension Source frame becomes state: it gates the ready
/// session, validates declaration/schema/policy, dedupes event ids durably, and
/// forcibly stamps `TaintSource::Inbound` before appending to the declared sink.
pub async fn ingest_source_event(
    req: SourceIngest<'_>,
    event: InboundEvent,
) -> Result<EventAck, SourceIngestError> {
    let emits = admit_source_ingest(&req, &event).await?;
    let source_key = source_projection_key(req.installation_id, &req.projection.id);
    let dedup = source_event_dedup_path(req.installation_id, &req.projection.id, &event.id)?;

    match req
        .state
        .write_cas(&dedup, None, Value::Int(event.timestamp_ms))
        .await
    {
        Ok(()) => {}
        Err(StateError::CasFailed { .. }) => {
            return Ok(EventAck {
                id: event.id,
                status: AckStatus::Duplicate,
            });
        }
        Err(e) => return Err(SourceIngestError::State(e.to_string())),
    }

    let taint = TaintSet::of(TaintSource::Inbound {
        source_projection_key: source_key.into(),
        event_stream: emits.sink.to_string().into(),
    });
    if let Err(e) = req
        .state
        .write_append_tainted(&emits.sink, event.payload.clone(), taint)
        .await
    {
        let _ = req.state.write_delete(&dedup).await;
        return Err(SourceIngestError::State(e.to_string()));
    }

    Ok(EventAck {
        id: event.id,
        status: AckStatus::Accepted,
    })
}

async fn admit_source_ingest<'a>(
    req: &'a SourceIngest<'_>,
    event: &InboundEvent,
) -> Result<&'a nexus_types::EventSource, SourceIngestError> {
    req.session
        .admit_source_event(&event.observed)
        .map_err(SourceIngestError::Session)?;
    req.session
        .admit_credential(req.credential_generation)
        .map_err(SourceIngestError::Session)?;
    let ctx = req
        .session
        .context()
        .ok_or(SourceIngestError::Session(SessionReject::NotReady))?;
    if ctx.installation_id != req.installation_id || ctx.projection_id != req.projection.id {
        return Err(SourceIngestError::ProjectionMismatch(
            source_projection_key(req.installation_id, &req.projection.id),
        ));
    }
    if ctx.role != Role::Source || req.projection.role != Role::Source {
        return Err(SourceIngestError::NotSource);
    }
    if ctx.registry_hash != req.current_registry_hash {
        return Err(SourceIngestError::RegistryHashMismatch);
    }
    if ctx.credential_generation != req.credential_generation {
        return Err(SourceIngestError::CredentialGenerationMismatch);
    }
    if ctx.binding_generation != req.current_binding_generation {
        return Err(SourceIngestError::BindingGenerationMismatch);
    }
    if ctx.extension_config_version != req.current_installation_config_version {
        return Err(SourceIngestError::InstallationConfigVersionMismatch);
    }
    if ctx.projection_version != req.projection.version {
        return Err(SourceIngestError::ProjectionVersionMismatch);
    }
    let emits = req
        .projection
        .emits
        .as_ref()
        .ok_or(SourceIngestError::MissingEmits)?;
    validate_json_schema(emits.event_schema.as_ref(), &event.payload)
        .map_err(SourceIngestError::Schema)?;
    match req
        .policy
        .check(&CheckCtx {
            input: &event.payload,
            acting: req.acting,
            now_millis: req.now_millis,
            target: req.target,
        })
        .await
    {
        PolicyDecision::Allow => Ok(emits),
        PolicyDecision::Ask { reason, .. } | PolicyDecision::Deny { reason } => {
            Err(SourceIngestError::Policy(reason))
        }
    }
}

fn source_event_dedup_path(
    installation_id: &str,
    projection_id: &str,
    event_id: &str,
) -> Result<Path, SourceIngestError> {
    let installation_id = path_segment(installation_id);
    let projection_id = path_segment(projection_id);
    let event_id = path_segment(event_id);
    if installation_id.is_empty() || projection_id.is_empty() || event_id.is_empty() {
        return Err(SourceIngestError::InvalidEventId);
    }
    Path::parse(&format!(
        "state://kernel/source-events/{}/{}/{}",
        installation_id, projection_id, event_id
    ))
    .map_err(|e| SourceIngestError::State(format!("invalid dedup path: {e}")))
}

fn source_projection_key(installation_id: &str, projection_id: &str) -> String {
    format!("{installation_id}/{projection_id}")
}

fn path_segment(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn validate_json_schema(schema: Option<&JsonSchema>, value: &Value) -> Result<(), String> {
    match schema {
        None => Ok(()),
        Some(Value::Map(schema)) => validate_schema_map(schema, value),
        Some(_) => Err("schema must be an object".into()),
    }
}

fn validate_schema_map(
    schema: &std::collections::BTreeMap<String, Value>,
    value: &Value,
) -> Result<(), String> {
    let supported: BTreeSet<&str> = ["type", "required", "properties"].into_iter().collect();
    for key in schema.keys() {
        if !supported.contains(key.as_str()) {
            return Err(format!("unsupported schema keyword `{key}`"));
        }
    }

    if let Some(t) = schema.get("type") {
        let expected = t
            .as_str()
            .ok_or_else(|| "`type` must be a string".to_string())?;
        if !schema_type_matches(expected, value) {
            return Err(format!("expected `{expected}`"));
        }
    }

    if let Some(required) = schema.get("required") {
        let keys = match required {
            Value::List(xs) => xs,
            _ => return Err("`required` must be a list".into()),
        };
        let m = match value {
            Value::Map(m) => m,
            _ => return Err("`required` applies only to objects".into()),
        };
        for key in keys {
            let key = key
                .as_str()
                .ok_or_else(|| "`required` entries must be strings".to_string())?;
            if !m.contains_key(key) {
                return Err(format!("missing required property `{key}`"));
            }
        }
    }

    if let Some(properties) = schema.get("properties") {
        let props = match properties {
            Value::Map(m) => m,
            _ => return Err("`properties` must be an object".into()),
        };
        let value_map = match value {
            Value::Map(m) => m,
            _ => return Err("`properties` applies only to objects".into()),
        };
        for (key, prop_schema) in props {
            if let Some(prop_value) = value_map.get(key) {
                validate_json_schema(Some(prop_schema), prop_value)
                    .map_err(|e| format!("property `{key}`: {e}"))?;
            }
        }
    }

    Ok(())
}

fn schema_type_matches(expected: &str, value: &Value) -> bool {
    match expected {
        "null" => matches!(value, Value::Null),
        "boolean" => matches!(value, Value::Bool(_)),
        "integer" => matches!(value, Value::Int(_)),
        "number" => matches!(value, Value::Int(_) | Value::Float(_)),
        "string" => matches!(value, Value::Str(_)),
        "array" => matches!(value, Value::List(_)),
        "object" => matches!(value, Value::Map(_)),
        _ => false,
    }
}

/// One extension session's authoritative state (§16.3.3). Owned by the daemon
/// side; the extension only ever echoes what it observes.
pub struct EndpointSession {
    phase: SessionPhase,
    /// The daemon-adjudicated context sent in stage 2 (the source of truth).
    context: Option<SessionContext>,
    /// The credential generation currently valid; frames on an older generation
    /// are rejected after a revoke (§16.3.4 fail-closed).
    valid_credential_generation: u64,
}

impl EndpointSession {
    /// A fresh session awaiting the extension's hello (stage 1).
    pub fn new() -> Self {
        Self {
            phase: SessionPhase::AwaitingHello,
            context: None,
            valid_credential_generation: 0,
        }
    }

    pub fn phase(&self) -> SessionPhase {
        self.phase
    }

    pub fn is_ready(&self) -> bool {
        self.phase == SessionPhase::Ready
    }

    pub fn context(&self) -> Option<&SessionContext> {
        self.context.as_ref()
    }

    /// Stage 1 → 2 (§16.3.3): the extension's hello is received and the daemon
    /// adjudicates the authoritative `SessionContext` to send back. The daemon
    /// chooses every generation; the extension's cached `observed` is advisory
    /// only. Returns the context to transmit, or rejects out-of-order/closed.
    pub fn on_hello(
        &mut self,
        hello: &RoleSessionClientHello,
        adjudicate: impl FnOnce(&RoleSessionClientHello) -> SessionContext,
    ) -> Result<SessionContext, SessionReject> {
        if self.phase == SessionPhase::Closed {
            return Err(SessionReject::Closed);
        }
        if self.phase != SessionPhase::AwaitingHello {
            return Err(SessionReject::OutOfOrder);
        }
        let context = adjudicate(hello);
        self.valid_credential_generation = context.credential_generation;
        self.context = Some(context.clone());
        self.phase = SessionPhase::AwaitingReady;
        Ok(context)
    }

    /// Stage 3 (§16.3.3): the extension confirms alignment. The accepted context
    /// must match what the daemon sent verbatim — any divergence is fail-closed
    /// (the session moves to Closed, no business frames ever flow).
    pub fn on_ready(&mut self, ready: &RoleReady) -> Result<(), SessionReject> {
        if self.phase == SessionPhase::Closed {
            return Err(SessionReject::Closed);
        }
        if self.phase != SessionPhase::AwaitingReady {
            return Err(SessionReject::OutOfOrder);
        }
        match &self.context {
            Some(ctx) if &ready.accepted_context == ctx => {
                self.phase = SessionPhase::Ready;
                Ok(())
            }
            _ => {
                self.phase = SessionPhase::Closed;
                Err(SessionReject::ContextMismatch)
            }
        }
    }

    /// Gate a business frame (`Invoke` dispatch / inbound event, §16.3.3): only
    /// admitted once `Ready`. Returns `Ok` to dispatch, or the reject reason.
    pub fn admit_business(&self) -> Result<(), SessionReject> {
        match self.phase {
            SessionPhase::Ready => Ok(()),
            SessionPhase::Closed => Err(SessionReject::Closed),
            _ => Err(SessionReject::NotReady),
        }
    }

    /// Gate an inbound Source event's observed generations (§16.3.3): a Source
    /// frame must not claim generations newer than the session's authoritative
    /// ones (a stale or forged frame is rejected). Equal/older presentation
    /// generations are fine (the extension may lag a config push).
    pub fn admit_source_event(&self, observed: &ObservedGenerations) -> Result<(), SessionReject> {
        self.admit_business()?;
        let ctx = self.context.as_ref().ok_or(SessionReject::NotReady)?;
        if observed.presentation_config_generation > ctx.presentation_config_generation
            || observed.alias_catalog_generation > ctx.alias_catalog_generation
        {
            return Err(SessionReject::StaleGeneration);
        }
        Ok(())
    }

    /// Gate a credential generation (§16.3.4 fail-closed): after a revoke bumps
    /// `valid_credential_generation`, any frame on an older generation is
    /// rejected. Equal-or-newer is accepted.
    pub fn admit_credential(&self, generation: u64) -> Result<(), SessionReject> {
        if generation < self.valid_credential_generation {
            return Err(SessionReject::RevokedCredential);
        }
        Ok(())
    }

    /// Revoke all credentials older than `new_generation` (§16.3.4): bumps the
    /// floor so stale-generation frames are refused thereafter.
    pub fn revoke_below(&mut self, new_generation: u64) {
        self.valid_credential_generation = self.valid_credential_generation.max(new_generation);
    }

    /// Close the session (shutdown / error). Fail-closed: no further frames.
    pub fn close(&mut self) {
        self.phase = SessionPhase::Closed;
    }
}

impl Default for EndpointSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_kernel::{CompiledCheck, PolicyDecision};
    use nexus_state::InMemoryBackend;
    use nexus_types::extension::{EventSource, Role};
    use nexus_types::{FloatBits, Purity, TaintSource};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn hello() -> RoleSessionClientHello {
        RoleSessionClientHello {
            role: Role::Source,
            installation_id: "inst-1".into(),
            projection_id: "source".into(),
            registry_hash: "h".into(),
            observed: ObservedGenerations::default(),
            config_schema: None,
        }
    }

    fn ctx() -> SessionContext {
        SessionContext {
            installation_id: "inst-1".into(),
            projection_id: "source".into(),
            role: Role::Source,
            registry_hash: "h".into(),
            credential_generation: 3,
            binding_generation: 1,
            extension_config_version: 1,
            projection_version: 1,
            presentation_config_generation: 2,
            alias_catalog_generation: 1,
        }
    }

    fn complete_handshake() -> EndpointSession {
        let mut s = EndpointSession::new();
        let sent = s.on_hello(&hello(), |_| ctx()).unwrap();
        s.on_ready(&RoleReady {
            accepted_context: sent,
        })
        .unwrap();
        s
    }

    fn source_projection(schema: Option<Value>) -> ExtensionProjectionDef {
        ExtensionProjectionDef {
            id: "source".into(),
            role: Role::Source,
            namespace: None,
            provides: vec![],
            emits: Some(EventSource {
                sink: Path::parse("state://chat/source/events").unwrap(),
                purity: Purity::Effectful,
                event_schema: schema,
            }),
            version: 1,
        }
    }

    fn event(id: &str, payload: Value) -> InboundEvent {
        InboundEvent {
            id: id.into(),
            payload,
            observed: ObservedGenerations {
                presentation_config_generation: 2,
                alias_catalog_generation: 1,
            },
            timestamp_ms: 123,
        }
    }

    fn source_req<'a>(
        state: Backend,
        session: &'a EndpointSession,
        projection: &'a ExtensionProjectionDef,
        policy: &'a PolicySnapshot,
    ) -> SourceIngest<'a> {
        SourceIngest {
            state,
            session,
            installation_id: "inst-1",
            projection,
            current_registry_hash: "h",
            credential_generation: 3,
            current_binding_generation: 1,
            current_installation_config_version: 1,
            policy,
            acting: IdentityRef::ROOT,
            target: ResourceId::new(1),
            now_millis: 123,
        }
    }

    fn message_payload(text: &str) -> Value {
        let mut m = BTreeMap::new();
        m.insert("text".into(), Value::Str(text.into()));
        Value::Map(m)
    }

    fn message_schema() -> Value {
        let mut text_schema = BTreeMap::new();
        text_schema.insert("type".into(), Value::Str("string".into()));

        let mut props = BTreeMap::new();
        props.insert("text".into(), Value::Map(text_schema));

        let mut schema = BTreeMap::new();
        schema.insert("type".into(), Value::Str("object".into()));
        schema.insert(
            "required".into(),
            Value::List(vec![Value::Str("text".into())]),
        );
        schema.insert("properties".into(), Value::Map(props));
        Value::Map(schema)
    }

    struct DenyAll;

    #[async_trait::async_trait]
    impl CompiledCheck for DenyAll {
        async fn evaluate(&self, _ctx: &CheckCtx) -> PolicyDecision {
            PolicyDecision::Deny {
                reason: "blocked".into(),
            }
        }

        fn name(&self) -> &'static str {
            "deny_all"
        }
    }

    #[test]
    fn business_frame_before_ready_is_rejected() {
        let mut s = EndpointSession::new();
        assert_eq!(s.admit_business(), Err(SessionReject::NotReady));
        s.on_hello(&hello(), |_| ctx()).unwrap();
        // Still not Ready (awaiting RoleReady) → business frame refused.
        assert_eq!(s.admit_business(), Err(SessionReject::NotReady));
    }

    #[test]
    fn full_handshake_reaches_ready_and_admits_business() {
        let s = complete_handshake();
        assert!(s.is_ready());
        assert_eq!(s.admit_business(), Ok(()));
    }

    #[test]
    fn context_mismatch_is_fail_closed() {
        let mut s = EndpointSession::new();
        let _sent = s.on_hello(&hello(), |_| ctx()).unwrap();
        // The extension confirms a DIFFERENT context → fail-closed Close.
        let mut wrong = ctx();
        wrong.credential_generation = 999;
        let r = s.on_ready(&RoleReady {
            accepted_context: wrong,
        });
        assert_eq!(r, Err(SessionReject::ContextMismatch));
        assert_eq!(s.phase(), SessionPhase::Closed);
        assert_eq!(s.admit_business(), Err(SessionReject::Closed));
    }

    #[test]
    fn out_of_order_ready_is_rejected() {
        let mut s = EndpointSession::new();
        // RoleReady before hello → out of order.
        assert_eq!(
            s.on_ready(&RoleReady {
                accepted_context: ctx()
            }),
            Err(SessionReject::OutOfOrder)
        );
    }

    #[test]
    fn stale_source_generation_is_rejected() {
        let s = complete_handshake();
        // Claiming a newer presentation generation than the session's → stale.
        let stale = ObservedGenerations {
            presentation_config_generation: 99,
            alias_catalog_generation: 1,
        };
        assert_eq!(
            s.admit_source_event(&stale),
            Err(SessionReject::StaleGeneration)
        );
        // Matching/older is fine.
        let ok = ObservedGenerations {
            presentation_config_generation: 2,
            alias_catalog_generation: 0,
        };
        assert_eq!(s.admit_source_event(&ok), Ok(()));
    }

    #[test]
    fn revoked_credential_generation_is_rejected() {
        let mut s = complete_handshake();
        // Current valid gen = 3. A frame on gen 3 is fine.
        assert_eq!(s.admit_credential(3), Ok(()));
        // Revoke below 5 → gen 3/4 now refused, 5+ accepted.
        s.revoke_below(5);
        assert_eq!(s.admit_credential(4), Err(SessionReject::RevokedCredential));
        assert_eq!(s.admit_credential(5), Ok(()));
    }

    #[tokio::test]
    async fn source_ingest_rejects_before_ready_and_writes_nothing() {
        let mut s = EndpointSession::new();
        s.on_hello(&hello(), |_| ctx()).unwrap();
        let state: Backend = Arc::new(InMemoryBackend::new());
        let def = source_projection(None);
        let policy = PolicySnapshot::empty();
        let err = ingest_source_event(
            source_req(state.clone(), &s, &def, &policy),
            event("e1", message_payload("hello")),
        )
        .await
        .unwrap_err();

        assert_eq!(err, SourceIngestError::Session(SessionReject::NotReady));
        assert_eq!(
            state
                .read(&Path::parse("state://chat/source/events").unwrap())
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn source_ingest_accepts_taints_and_dedupes_event_id() {
        let s = complete_handshake();
        let state: Backend = Arc::new(InMemoryBackend::new());
        let def = source_projection(None);
        let policy = PolicySnapshot::empty();
        let first = ingest_source_event(
            source_req(state.clone(), &s, &def, &policy),
            event("evt-1", message_payload("hello")),
        )
        .await
        .unwrap();
        let second = ingest_source_event(
            source_req(state.clone(), &s, &def, &policy),
            event("evt-1", message_payload("ignored")),
        )
        .await
        .unwrap();

        assert_eq!(first.status, AckStatus::Accepted);
        assert_eq!(second.status, AckStatus::Duplicate);
        let sink = Path::parse("state://chat/source/events").unwrap();
        let tv = state.read_tainted(&sink).await.unwrap().unwrap();
        assert_eq!(tv.value, Value::List(vec![message_payload("hello")]));
        assert!(tv.taint.sources().iter().any(|source| {
            matches!(
                source,
                TaintSource::Inbound {
                    source_projection_key,
                    event_stream
                } if source_projection_key.as_str() == "inst-1/source"
                    && event_stream.as_str() == "state://chat/source/events"
            )
        }));
    }

    #[tokio::test]
    async fn source_ingest_rejects_schema_mismatch_and_policy_deny() {
        let s = complete_handshake();
        let state: Backend = Arc::new(InMemoryBackend::new());
        let def = source_projection(Some(message_schema()));
        let policy = PolicySnapshot::empty();
        let err = ingest_source_event(
            source_req(state.clone(), &s, &def, &policy),
            event("evt-schema", Value::Float(FloatBits(1.0))),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SourceIngestError::Schema(_)));

        let deny = PolicySnapshot::new(vec![Arc::new(DenyAll)]);
        let err = ingest_source_event(
            source_req(state.clone(), &s, &def, &deny),
            event("evt-deny", message_payload("hello")),
        )
        .await
        .unwrap_err();
        assert_eq!(err, SourceIngestError::Policy("blocked".into()));
        assert_eq!(
            state
                .read(&Path::parse("state://chat/source/events").unwrap())
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn source_ingest_rejects_generation_mismatches() {
        let s = complete_handshake();
        let state: Backend = Arc::new(InMemoryBackend::new());
        let def = source_projection(None);
        let policy = PolicySnapshot::empty();
        let mut req = source_req(state, &s, &def, &policy);
        req.current_registry_hash = "other";
        let err = ingest_source_event(req, event("evt-hash", message_payload("hello")))
            .await
            .unwrap_err();
        assert_eq!(err, SourceIngestError::RegistryHashMismatch);

        let state: Backend = Arc::new(InMemoryBackend::new());
        let mut req = source_req(state, &s, &def, &policy);
        req.credential_generation = 4;
        let err = ingest_source_event(req, event("evt-cred", message_payload("hello")))
            .await
            .unwrap_err();
        assert_eq!(err, SourceIngestError::CredentialGenerationMismatch);

        let state: Backend = Arc::new(InMemoryBackend::new());
        let mut req = source_req(state, &s, &def, &policy);
        req.current_binding_generation = 2;
        let err = ingest_source_event(req, event("evt-binding", message_payload("hello")))
            .await
            .unwrap_err();
        assert_eq!(err, SourceIngestError::BindingGenerationMismatch);

        let state: Backend = Arc::new(InMemoryBackend::new());
        let mut req = source_req(state, &s, &def, &policy);
        req.current_installation_config_version = 2;
        let err = ingest_source_event(req, event("evt-config", message_payload("hello")))
            .await
            .unwrap_err();
        assert_eq!(err, SourceIngestError::InstallationConfigVersionMismatch);

        let state: Backend = Arc::new(InMemoryBackend::new());
        let mut projection = source_projection(None);
        projection.version = 2;
        let req = source_req(state, &s, &projection, &policy);
        let err = ingest_source_event(req, event("evt-projection", message_payload("hello")))
            .await
            .unwrap_err();
        assert_eq!(err, SourceIngestError::ProjectionVersionMismatch);
    }
}
