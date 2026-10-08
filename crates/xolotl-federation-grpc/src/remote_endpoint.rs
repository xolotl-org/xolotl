//! Kernel remote endpoint backed by a source-owned federated CallRef ledger.
//! The host owns local identity mapping, session renewal, and the persistent
//! OperationId namespace; this adapter owns exact routing and replay order.

use std::{
    collections::HashMap,
    io,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use sha2::{Digest as _, Sha384};
use xolotl_federation::{
    CallInspection, CallStatus, CallTarget, Digest, FederationError, FederationNodeId,
    FederationOutboundCallStore, FederationSubject, MAX_CALL_INPUT_BYTES,
    MAX_OUTBOUND_RESULT_BYTES as MAX_CALL_OUTPUT_BYTES, OutboundCallIntent, OutboundCallRecord,
    OutboundOriginEvidence, OutboundOriginState, PrepareCallRequest, RequestId,
};
use xolotl_kernel::driver::{DriverError, RemoteEndpoint, RemoteInvokeDispatch};
use xolotl_kernel::host::{
    BlockingSpawnError, BlockingSpawner, BlockingTaskError, blocking::dispatch,
};
use xolotl_types::{
    EndpointId, ErrorInfo, IdentityRef, Invoke, InvokeResult, MethodId, OperationId, Path,
    ResourceId, Value,
};

use crate::FederationGrpcSubscriberClient;

const REQUEST_DOMAIN: &[u8] = b"xolotl/federation/v1/kernel-call-request\0";
const BINDING_DOMAIN: &[u8] = b"xolotl/federation/v1/kernel-call-binding\0";

/// A host proof that the complete OperationId belongs to a stable, unreused
/// namespace. Reinspection must address the same RequestId; a fresh run
/// must never reuse one, even after source call receipts expire.
///
/// Production hosts must pair this port with a persistent Kernel
/// `ExecutionIdSource` and retain its namespace for the same database lifetime.
pub trait FederationCallIdentity: Send + Sync {
    /// Derive the same request ID on replay and a distinct ID for every new
    /// operation in this origin's persistent execution namespace.
    fn request_id(
        &self,
        origin: FederationNodeId,
        operation: OperationId,
    ) -> Result<RequestId, DriverError>;
}

/// SHA-384 domain-separated operation identity. The namespace is a random
/// persistent value owned by the same database as the Kernel execution-ID
/// source. Hosts must not construct this with ephemeral execution IDs.
pub struct DurableOperationIdHash {
    namespace: [u8; 32],
}

impl DurableOperationIdHash {
    /// Bind a nonzero, persistent namespace to the Kernel execution-ID source.
    pub fn new(namespace: [u8; 32]) -> Result<Self, DriverError> {
        if namespace == [0; 32] {
            return Err(DriverError::Transport(
                "federation operation namespace is zero".into(),
            ));
        }
        Ok(Self { namespace })
    }
}

impl FederationCallIdentity for DurableOperationIdHash {
    fn request_id(
        &self,
        origin: FederationNodeId,
        operation: OperationId,
    ) -> Result<RequestId, DriverError> {
        let mut digest = Sha384::new();
        digest.update(REQUEST_DOMAIN);
        digest.update(self.namespace);
        digest.update(origin.as_bytes());
        digest.update(operation.to_bytes());
        let digest = digest.finalize();
        let mut id = [0; 16];
        id.copy_from_slice(&digest[..16]);
        Ok(RequestId::from_bytes(id))
    }
}

/// A host-resolved principal and a stable name for the local acting identity.
/// The name must survive registry/identity numeric ID reassignment. Changing
/// its meaning requires a new binding generation.
pub struct FederationCallPrincipalBinding {
    /// Principal presented to the target under the authenticated Session.
    pub subject: FederationSubject,
    /// Stable local acting name included in the persisted binding fingerprint.
    pub stable_acting: Arc<str>,
}

/// Host-authoritative mapping from a Kernel acting identity to a federated
/// principal. Hosted identities need their separate holder proof in the chosen
/// authenticated Session; peer assertions never select this mapping.
pub trait FederationCallPrincipal: Send + Sync {
    /// Resolve the Kernel's actual acting identity for this exact local route.
    fn resolve(
        &self,
        binding: &FederationRemoteKey,
        acting: IdentityRef,
    ) -> Result<FederationCallPrincipalBinding, DriverError>;
}

/// A live authenticated Session and the context registered for the principal.
#[derive(Clone)]
pub struct FederationCallSession {
    /// Authenticated client connected to the route's target node.
    pub client: FederationGrpcSubscriberClient,
    /// Registered hosted-subject context, or zero for the node principal.
    pub context_id: u32,
}

/// May reconnect to the fixed target and register a fresh Hosted subject
/// context. The bridge asks again after a failed or closed Session.
#[async_trait]
pub trait FederationCallSessionProvider: Send + Sync {
    /// Obtain a current Session for this target and principal. A hosted subject
    /// must be registered again when the Session changes.
    async fn session(
        &self,
        target: FederationNodeId,
        subject: &FederationSubject,
    ) -> Result<FederationCallSession, DriverError>;
}

/// A deterministic, bounded codec for a single scalar call. Its identifier
/// participates in the persisted local binding fingerprint; changing codec
/// semantics requires a new identifier.
pub trait FederationCallCodec: Send + Sync {
    /// Stable codec contract name used in the durable route fingerprint.
    fn id(&self) -> &str;
    /// Encode one input under the call's wire byte limit.
    fn encode_input(&self, input: &Value) -> Result<Vec<u8>, DriverError>;
    /// Decode a retained terminal output after its byte limit is checked.
    fn decode_output(&self, output: &[u8]) -> Result<Value, DriverError>;
}

/// Tagged Xolotl Value JSON, bounded before allocation exceeds the wire limit.
#[derive(Default)]
pub struct JsonCallCodec;

/// The stock v1 method codec: the Kernel input and output are byte Values.
#[derive(Default)]
pub struct RawBytesCallCodec;

impl FederationCallCodec for RawBytesCallCodec {
    fn id(&self) -> &str {
        "xolotl.bytes.v1"
    }

    fn encode_input(&self, input: &Value) -> Result<Vec<u8>, DriverError> {
        let bytes = input
            .as_bytes()
            .ok_or_else(|| DriverError::InvalidInput("federated method requires bytes".into()))?;
        if bytes.len() > MAX_CALL_INPUT_BYTES {
            return Err(DriverError::InvalidInput(
                "federated input exceeds wire limit".into(),
            ));
        }
        Ok(bytes.to_vec())
    }

    fn decode_output(&self, output: &[u8]) -> Result<Value, DriverError> {
        if output.len() > MAX_CALL_OUTPUT_BYTES {
            return Err(DriverError::Transport(
                "federated output exceeds retained result limit".into(),
            ));
        }
        Ok(Value::shared_bytes(Arc::from(output)))
    }
}

impl FederationCallCodec for JsonCallCodec {
    fn id(&self) -> &str {
        "xolotl.value-json.v1"
    }

    fn encode_input(&self, input: &Value) -> Result<Vec<u8>, DriverError> {
        let mut output = LimitedWriter::new(MAX_CALL_INPUT_BYTES);
        serde_json::to_writer(&mut output, input).map_err(|_error| {
            DriverError::InvalidInput("federated input is not encodable".into())
        })?;
        Ok(output.bytes)
    }

    fn decode_output(&self, output: &[u8]) -> Result<Value, DriverError> {
        if output.len() > MAX_CALL_OUTPUT_BYTES {
            return Err(DriverError::Transport(
                "federated output exceeds retained result limit".into(),
            ));
        }
        serde_json::from_slice(output)
            .map_err(|_error| DriverError::Transport("invalid federated result value".into()))
    }
}

struct LimitedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl LimitedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }
}

impl io::Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("federated value exceeds wire limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Exact local handle binding. A stale generation, another resource, another
/// method, or a different concrete path cannot silently reuse a remote route.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FederationRemoteKey {
    /// Kernel endpoint used for the local resource binding.
    pub endpoint_id: EndpointId,
    /// Local resource identity, independent of the remote export.
    pub resource_id: ResourceId,
    /// Local method identity within the bound resource.
    pub method_id: MethodId,
    /// Registry generation fencing stale local bindings.
    pub binding_generation: u64,
    /// Concrete effect path selected by the Kernel invocation.
    pub effect_path: Path,
}

impl FederationRemoteKey {
    fn from_invoke(dispatch: RemoteInvokeDispatch, invoke: &Invoke) -> Self {
        Self {
            endpoint_id: dispatch.endpoint_id,
            resource_id: dispatch.resource_id,
            method_id: dispatch.method_id,
            binding_generation: dispatch.binding_generation,
            effect_path: invoke.effect_path.clone(),
        }
    }
}

/// Bounded time policy for a method. A caller's earlier Kernel deadline wins.
#[derive(Clone, Copy, Debug)]
pub struct FederationRemoteTiming {
    /// Maximum time to prepare the remote CallRef, in milliseconds.
    pub prepare_ms: u64,
    /// Maximum remote execution time, in milliseconds.
    pub execution_ms: u64,
    /// Minimum requested retention of the remote terminal, in milliseconds.
    pub result_retention_ms: u64,
    /// Delay between inspections while a call has no terminal, in milliseconds.
    pub poll_ms: u64,
}

impl Default for FederationRemoteTiming {
    fn default() -> Self {
        Self {
            prepare_ms: 30_000,
            execution_ms: 60_000,
            result_retention_ms: 86_400_000,
            poll_ms: 100,
        }
    }
}

impl FederationRemoteTiming {
    fn validate(self) -> Result<(), DriverError> {
        if self.prepare_ms == 0
            || self.execution_ms == 0
            || self.result_retention_ms == 0
            || self.poll_ms == 0
        {
            return Err(DriverError::Transport(
                "federation remote timing must be positive".into(),
            ));
        }
        Ok(())
    }
}

/// A fixed, exact mapping from one Kernel binding to one peer export method.
#[derive(Clone)]
pub struct FederationRemoteBinding {
    /// Exact local route eligible for this remote method.
    pub local: FederationRemoteKey,
    /// Stable method name, independent of registry-allocated MethodId.
    pub local_method_name: String,
    /// Authenticated node expected to own the remote method.
    pub target_node: FederationNodeId,
    /// Exported path, method, and contract digest at the target.
    pub target: CallTarget,
    /// Input and output codec for this immutable binding.
    pub codec: Arc<dyn FederationCallCodec>,
    /// Bounded preparation, execution, result, and poll timing.
    pub timing: FederationRemoteTiming,
}

/// The Kernel endpoint for a set of fixed federated method bindings.
/// It can be registered at any EndpointId through the normal Kernel registry.
pub struct FederationRemoteEndpoint {
    source: Arc<dyn FederationOutboundCallStore>,
    identity: Arc<dyn FederationCallIdentity>,
    principal: Arc<dyn FederationCallPrincipal>,
    sessions: Arc<dyn FederationCallSessionProvider>,
    blocking: Arc<dyn BlockingSpawner>,
    bindings: HashMap<FederationRemoteKey, FederationRemoteBinding>,
}

#[derive(Debug)]
enum SourceWorkError {
    Admission(BlockingSpawnError),
    Outcome(BlockingTaskError),
    Ledger(FederationError),
}

impl FederationRemoteEndpoint {
    /// Build a Kernel endpoint from exact bindings, durable origin ports and
    /// the host-owned blocking admission and shutdown domain.
    /// Duplicate local routes and invalid time policies are rejected.
    pub fn new(
        source: Arc<dyn FederationOutboundCallStore>,
        identity: Arc<dyn FederationCallIdentity>,
        principal: Arc<dyn FederationCallPrincipal>,
        sessions: Arc<dyn FederationCallSessionProvider>,
        blocking: Arc<dyn BlockingSpawner>,
        bindings: impl IntoIterator<Item = FederationRemoteBinding>,
    ) -> Result<Self, DriverError> {
        let mut by_local = HashMap::new();
        for binding in bindings {
            binding.timing.validate()?;
            if binding.target_node == source.local_node()
                || binding.target.contract_digest == [0; 32]
                || binding.local_method_name.is_empty()
                || binding.local_method_name.len() > 128
                || binding.codec.id().is_empty()
                || binding.codec.id().len() > 128
            {
                return Err(DriverError::Transport(
                    "invalid federation remote binding".into(),
                ));
            }
            if by_local.insert(binding.local.clone(), binding).is_some() {
                return Err(DriverError::Transport(
                    "duplicate federation remote binding".into(),
                ));
            }
        }
        Ok(Self {
            source,
            identity,
            principal,
            sessions,
            blocking,
            bindings: by_local,
        })
    }

    async fn run_source<Output: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<Output, FederationError> + Send + 'static,
    ) -> Result<Output, SourceWorkError> {
        dispatch(self.blocking.as_ref(), work)
            .map_err(SourceWorkError::Admission)?
            .await
            .map_err(SourceWorkError::Outcome)?
            .map_err(SourceWorkError::Ledger)
    }

    async fn bind_origin(
        &self,
        id: RequestId,
        operation: OperationId,
        binding: Digest,
    ) -> Result<OutboundOriginState, SourceWorkError> {
        let source = Arc::clone(&self.source);
        self.run_source(move || source.bind_outbound_origin(id, operation, binding))
            .await
    }

    async fn existing(&self, id: RequestId) -> Result<Option<OutboundCallRecord>, SourceWorkError> {
        let source = Arc::clone(&self.source);
        match self.run_source(move || source.outbound_call(id)).await {
            Ok(record) => Ok(Some(record)),
            Err(SourceWorkError::Ledger(FederationError::NotFound)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn release_consumed_result(
        &self,
        request_id: RequestId,
        operation: OperationId,
        terminal: &CallInspection,
        result: InvokeResult,
    ) -> InvokeResult {
        if terminal.execution_stopped && terminal.unresolved_effect_ids.is_empty() {
            let source = Arc::clone(&self.source);
            if let Err(error) = self
                .run_source(move || source.release_outbound_responsibility(request_id, operation))
                .await
            {
                tracing::warn!(?request_id, %operation, ?error, "consumed federation result retained; source responsibility release uncertain");
            }
        }
        result
    }

    async fn session(
        &self,
        target: FederationNodeId,
        subject: &FederationSubject,
    ) -> Result<FederationCallSession, DriverError> {
        let session = self.sessions.session(target, subject).await?;
        if session.client.peer_node() != target
            || (matches!(subject, FederationSubject::Node(_)) && session.context_id != 0)
            || (matches!(subject, FederationSubject::Hosted(_)) && session.context_id == 0)
        {
            return Err(DriverError::Transport(
                "federation Session does not match the bound peer or subject".into(),
            ));
        }
        Ok(session)
    }
}

#[async_trait]
impl RemoteEndpoint for FederationRemoteEndpoint {
    async fn invoke(
        &self,
        dispatch: RemoteInvokeDispatch,
        invoke: Invoke,
    ) -> Result<InvokeResult, DriverError> {
        let operation: OperationId = invoke.invocation_id.parse().map_err(|_error| {
            DriverError::InvalidInput("federation call requires a Kernel OperationId".into())
        })?;
        let key = FederationRemoteKey::from_invoke(dispatch, &invoke);
        let binding = self
            .bindings
            .get(&key)
            .ok_or_else(|| unknown(&invoke.invocation_id, "unbound federation remote method"))?;
        let request_id = self
            .identity
            .request_id(self.source.local_node(), operation)?;
        let source = Arc::clone(&self.source);
        let evidence = self
            .run_source(move || source.outbound_origin_evidence(request_id, operation))
            .await
            .map_err(|error| source_error(&invoke.invocation_id, error))?;
        if evidence == OutboundOriginEvidence::Retired {
            return Err(unknown(
                &invoke.invocation_id,
                "federation origin is retired",
            ));
        }
        let replay = evidence == OutboundOriginEvidence::Recorded;
        // Resolve the durable origin before local validation. A replay may have
        // emitted Invoke before the host changed its mode, principal mapping,
        // or codec; none of those changes may turn that effect into a known
        // pre-dispatch failure.
        if dispatch.method_id != invoke.method_id {
            return Err(unknown(
                &invoke.invocation_id,
                "federation dispatch method differs from Invoke",
            ));
        }
        if dispatch.output_mode != xolotl_types::OutputMode::Unary
            || invoke.output_stream_to.is_some()
        {
            return Err(if replay {
                unknown(
                    &invoke.invocation_id,
                    "federation output mode changed during replay",
                )
            } else {
                DriverError::UnsupportedOutput(dispatch.output_mode)
            });
        }
        let input = binding.codec.encode_input(&invoke.input).map_err(|error| {
            if replay {
                unknown(
                    &invoke.invocation_id,
                    "federation input codec changed during replay",
                )
            } else {
                error
            }
        })?;
        if input.len() > MAX_CALL_INPUT_BYTES {
            return Err(if replay {
                unknown(
                    &invoke.invocation_id,
                    "federation input exceeds wire limit during replay",
                )
            } else {
                DriverError::InvalidInput("federated input exceeds wire limit".into())
            });
        }
        let principal = self
            .principal
            .resolve(&key, dispatch.acting)
            .map_err(|error| {
                if replay {
                    unknown(
                        &invoke.invocation_id,
                        "federation principal changed during replay",
                    )
                } else {
                    error
                }
            })?;
        if principal.stable_acting.is_empty()
            || principal.stable_acting.len() > 1024
            || principal.stable_acting.chars().any(char::is_control)
        {
            return Err(unknown(
                &invoke.invocation_id,
                "federation principal has no stable acting name",
            ));
        }
        let subject = principal.subject;
        if matches!(subject, FederationSubject::Node(node) if node != self.source.local_node()) {
            return Err(unknown(
                &invoke.invocation_id,
                "node subject does not match local federation identity",
            ));
        }
        let binding_digest = fingerprint(binding, &principal.stable_acting, &subject);
        let origin_state = self
            .bind_origin(request_id, operation, binding_digest)
            .await
            .map_err(|error| source_error(&invoke.invocation_id, error))?;
        if origin_state == OutboundOriginState::Retired {
            return Err(unknown(
                &invoke.invocation_id,
                "retired federation origin cannot be dispatched again",
            ));
        }
        let existing = self
            .existing(request_id)
            .await
            .map_err(|error| source_error(&invoke.invocation_id, error))?;
        if let Some(record) = &existing {
            if record.intent.target_node != binding.target_node
                || record.intent.request.target != binding.target
                || record.intent.request.subject != subject
                || record.intent.input.as_ref() != input
            {
                return Err(unknown(
                    &invoke.invocation_id,
                    "persisted federation call differs from replay",
                ));
            }
            if let Some(terminal) = &record.terminal {
                let result = result_from_terminal(&invoke, binding, terminal)?;
                return Ok(self
                    .release_consumed_result(request_id, operation, terminal, result)
                    .await);
            }
        }
        let now = now_ms()?;
        let record = if let Some(record) = existing {
            record
        } else {
            let execution_deadline_ms = invoke
                .deadline_ms
                .map(|deadline| u64::try_from(deadline).unwrap_or(0))
                .unwrap_or_else(|| now.saturating_add(binding.timing.execution_ms))
                .min(now.saturating_add(binding.timing.execution_ms));
            let prepare_deadline_ms = now
                .saturating_add(binding.timing.prepare_ms)
                .min(execution_deadline_ms);
            if prepare_deadline_ms <= now || execution_deadline_ms <= now {
                return Err(DriverError::Transport(
                    "federated call deadline elapsed".into(),
                ));
            }
            let intent = OutboundCallIntent {
                target_node: binding.target_node,
                request: PrepareCallRequest {
                    authenticated_origin: self.source.local_node(),
                    subject: subject.clone(),
                    origin_request_id: request_id,
                    target: binding.target.clone(),
                    input_digest: Digest::from_bytes(Sha384::digest(&input).into()),
                    input_bytes: input.len() as u64,
                    prepare_deadline_ms,
                    execution_deadline_ms,
                    result_retention_ms: binding.timing.result_retention_ms,
                },
                input: Arc::from(input),
            };
            let session = self.session(binding.target_node, &subject).await?;
            session
                .client
                .prepare_call_persisted(session.context_id, intent, Arc::clone(&self.source), now)
                .await
                .map_err(|_error| unknown(&invoke.invocation_id, "call preparation uncertain"))?;
            self.existing(request_id)
                .await
                .map_err(|error| source_error(&invoke.invocation_id, error))?
                .ok_or_else(|| {
                    unknown(&invoke.invocation_id, "prepared call missing from source")
                })?
        };
        let prepared = match &record.prepared {
            Some(prepared) => prepared.clone(),
            None => {
                if now >= record.intent.request.prepare_deadline_ms {
                    return Err(unknown(&invoke.invocation_id, "call preparation expired"));
                }
                let session = self.session(binding.target_node, &subject).await?;
                session
                    .client
                    .prepare_call_persisted(
                        session.context_id,
                        record.intent.clone(),
                        Arc::clone(&self.source),
                        now,
                    )
                    .await
                    .map_err(|_error| {
                        unknown(&invoke.invocation_id, "call preparation uncertain")
                    })?
            }
        };
        if prepared.call.target != binding.target_node {
            return Err(unknown(
                &invoke.invocation_id,
                "prepared call changed target",
            ));
        }
        let session = self
            .session(binding.target_node, &subject)
            .await
            .map_err(|_error| {
                if record.invoke_possible {
                    unknown(
                        &invoke.invocation_id,
                        "call Session unavailable after Invoke may have sent",
                    )
                } else {
                    DriverError::Transport("federation call Session unavailable".into())
                }
            })?;
        if record.invoke_possible {
            let inspected = session
                .client
                .inspect_call_persisted(session.context_id, request_id, Arc::clone(&self.source))
                .await
                .map_err(|_error| unknown(&invoke.invocation_id, "call inspection unavailable"))?;
            if let Some(result) = terminal_result(&invoke, binding, &inspected)? {
                return Ok(self
                    .release_consumed_result(request_id, operation, &inspected, result)
                    .await);
            }
        }
        if now >= prepared.execution_deadline_ms {
            return Err(unknown(
                &invoke.invocation_id,
                "call execution deadline elapsed",
            ));
        }
        session
            .client
            .invoke_call_persisted(
                session.context_id,
                request_id,
                Arc::clone(&self.source),
                now,
            )
            .await
            .map_err(|_error| unknown(&invoke.invocation_id, "call invocation uncertain"))?;
        loop {
            let inspected = session
                .client
                .inspect_call_persisted(session.context_id, request_id, Arc::clone(&self.source))
                .await
                .map_err(|_error| unknown(&invoke.invocation_id, "call inspection unavailable"))?;
            if let Some(result) = terminal_result(&invoke, binding, &inspected)? {
                return Ok(self
                    .release_consumed_result(request_id, operation, &inspected, result)
                    .await);
            }
            if now_ms()? >= prepared.execution_deadline_ms {
                return Err(unknown(
                    &invoke.invocation_id,
                    "call result remains unresolved",
                ));
            }
            tokio::time::sleep(Duration::from_millis(binding.timing.poll_ms)).await;
        }
    }
}

fn terminal_result(
    invoke: &Invoke,
    binding: &FederationRemoteBinding,
    inspected: &CallInspection,
) -> Result<Option<InvokeResult>, DriverError> {
    match inspected.status {
        CallStatus::Finished | CallStatus::Closed => {
            result_from_terminal(invoke, binding, inspected).map(Some)
        }
        CallStatus::Unproven => Err(unknown(&invoke.invocation_id, "call has no retained proof")),
        CallStatus::Reserved | CallStatus::Preparing | CallStatus::Accepted => Ok(None),
    }
}

fn result_from_terminal(
    invoke: &Invoke,
    binding: &FederationRemoteBinding,
    terminal: &CallInspection,
) -> Result<InvokeResult, DriverError> {
    if !terminal.execution_stopped || !terminal.unresolved_effect_ids.is_empty() {
        return Err(unknown(
            &invoke.invocation_id,
            "remote execution or effects remain unresolved",
        ));
    }
    let result = terminal.result.as_ref().ok_or_else(|| {
        unknown(
            &invoke.invocation_id,
            "call result receipt expired or absent",
        )
    })?;
    result
        .verify()
        .map_err(|_error| unknown(&invoke.invocation_id, "call result receipt is invalid"))?;
    let outcome = if result.succeeded {
        Ok(binding
            .codec
            .decode_output(&result.output)
            .map_err(|_error| {
                unknown(&invoke.invocation_id, "call result codec rejected output")
            })?)
    } else {
        let code = result
            .failure_code
            .as_ref()
            .ok_or_else(|| unknown(&invoke.invocation_id, "call failure code is absent"))?;
        Err(ErrorInfo {
            kind: code.as_str().to_owned(),
            message: "remote call failed".into(),
        })
    };
    Ok(InvokeResult {
        invocation_id: invoke.invocation_id.clone(),
        outcome,
    })
}

fn fingerprint(
    binding: &FederationRemoteBinding,
    stable_acting: &str,
    subject: &FederationSubject,
) -> Digest {
    let mut hash = Sha384::new();
    hash.update(BINDING_DOMAIN);
    hash.update(binding.local.binding_generation.to_be_bytes());
    hash_text(&mut hash, stable_acting);
    match subject {
        FederationSubject::Node(node) => {
            hash.update([0]);
            hash.update(node.as_bytes());
        }
        FederationSubject::Hosted(hosted) => {
            hash.update([1]);
            hash.update(hosted.issuer.as_bytes());
            hash_text(&mut hash, &hosted.namespace);
            hash_text(&mut hash, &hosted.subject);
        }
    }
    hash_text(&mut hash, &binding.local.effect_path.to_string());
    hash_text(&mut hash, &binding.local_method_name);
    hash.update(binding.target_node.as_bytes());
    hash_text(&mut hash, binding.target.export.as_str());
    hash_text(&mut hash, binding.target.path.as_str());
    hash_text(&mut hash, binding.target.method.as_str());
    hash.update(binding.target.contract_digest);
    hash_text(&mut hash, binding.codec.id());
    Digest::from_bytes(hash.finalize().into())
}

fn hash_text(hash: &mut Sha384, text: &str) {
    hash.update((text.len() as u64).to_be_bytes());
    hash.update(text.as_bytes());
}

fn now_ms() -> Result<u64, DriverError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_error| DriverError::Transport("system clock before epoch".into()))?;
    u64::try_from(elapsed.as_millis())
        .map_err(|_error| DriverError::Transport("system clock out of range".into()))
}

fn unknown(operation_id: &str, reason: &'static str) -> DriverError {
    DriverError::OutcomeUnknown {
        operation_id: operation_id.to_owned(),
        reason: reason.into(),
    }
}

fn source_error(operation_id: &str, error: SourceWorkError) -> DriverError {
    match error {
        SourceWorkError::Admission(BlockingSpawnError::AtCapacity) => unknown(
            operation_id,
            "source call ledger job not admitted: host capacity exceeded; reconcile original identity",
        ),
        SourceWorkError::Admission(BlockingSpawnError::Unavailable) => unknown(
            operation_id,
            "source call ledger job not admitted: host unavailable; reconcile original identity",
        ),
        SourceWorkError::Outcome(BlockingTaskError::Panicked) => unknown(
            operation_id,
            "source call ledger worker panicked: result unavailable; reconcile original identity",
        ),
        SourceWorkError::Outcome(BlockingTaskError::Cancelled) => unknown(
            operation_id,
            "source call ledger worker discarded: result unavailable; reconcile original identity",
        ),
        SourceWorkError::Ledger(FederationError::Conflict) => {
            unknown(operation_id, "outbound origin or call conflicts")
        }
        SourceWorkError::Ledger(FederationError::ClockRollback) => {
            unknown(operation_id, "source clock moved backward")
        }
        SourceWorkError::Ledger(FederationError::Indeterminate) => unknown(
            operation_id,
            "source call ledger commit outcome indeterminate; reconcile original identity",
        ),
        SourceWorkError::Ledger(FederationError::Capacity) => unknown(
            operation_id,
            "source call ledger capacity exceeded; reconcile original identity",
        ),
        SourceWorkError::Ledger(_) => unknown(operation_id, "source call ledger unavailable"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, ensure};
    use xolotl_federation::{
        CallMethod, CallPath, CallPrepared, CallRef, ExportName, MemoryFederationOutboundCallStore,
        PersistedCallResult,
    };
    use xolotl_types::OutputMode;

    struct LocalPrincipal(FederationNodeId);

    impl FederationCallPrincipal for LocalPrincipal {
        fn resolve(
            &self,
            _binding: &FederationRemoteKey,
            _acting: IdentityRef,
        ) -> Result<FederationCallPrincipalBinding, DriverError> {
            Ok(FederationCallPrincipalBinding {
                subject: FederationSubject::Node(self.0),
                stable_acting: Arc::from("identity://test/actor"),
            })
        }
    }

    struct DenyPrincipal;

    impl FederationCallPrincipal for DenyPrincipal {
        fn resolve(
            &self,
            _binding: &FederationRemoteKey,
            _acting: IdentityRef,
        ) -> Result<FederationCallPrincipalBinding, DriverError> {
            Err(DriverError::Transport("identity mapping removed".into()))
        }
    }

    struct BrokenJsonCodec;

    struct DecodeRejectCodec;

    impl FederationCallCodec for DecodeRejectCodec {
        fn id(&self) -> &str {
            JsonCallCodec.id()
        }

        fn encode_input(&self, input: &Value) -> Result<Vec<u8>, DriverError> {
            JsonCallCodec.encode_input(input)
        }

        fn decode_output(&self, _output: &[u8]) -> Result<Value, DriverError> {
            Err(DriverError::Transport(
                "retained output cannot be decoded".into(),
            ))
        }
    }

    impl FederationCallCodec for BrokenJsonCodec {
        fn id(&self) -> &str {
            "xolotl.value-json.v1"
        }

        fn encode_input(&self, _input: &Value) -> Result<Vec<u8>, DriverError> {
            Err(DriverError::InvalidInput("codec changed".into()))
        }

        fn decode_output(&self, _output: &[u8]) -> Result<Value, DriverError> {
            Err(DriverError::Transport("codec changed".into()))
        }
    }

    struct NoSession;

    #[async_trait]
    impl FederationCallSessionProvider for NoSession {
        async fn session(
            &self,
            _target: FederationNodeId,
            _subject: &FederationSubject,
        ) -> Result<FederationCallSession, DriverError> {
            Err(DriverError::Transport("offline".into()))
        }
    }

    struct RetiredSource {
        node: FederationNodeId,
        request: RequestId,
        operation: OperationId,
        binding: Digest,
        releases: std::sync::atomic::AtomicUsize,
    }

    impl FederationOutboundCallStore for RetiredSource {
        fn release_outbound_responsibility(
            &self,
            _request: RequestId,
            _operation: OperationId,
        ) -> Result<(), FederationError> {
            self.releases
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(FederationError::Corrupt)
        }

        fn local_node(&self) -> FederationNodeId {
            self.node
        }

        fn outbound_origin_evidence(
            &self,
            request: RequestId,
            operation: OperationId,
        ) -> Result<OutboundOriginEvidence, FederationError> {
            if (request, operation) != (self.request, self.operation) {
                return Err(FederationError::Conflict);
            }
            Ok(OutboundOriginEvidence::Retired)
        }

        fn bind_outbound_origin(
            &self,
            request: RequestId,
            operation: OperationId,
            binding: Digest,
        ) -> Result<OutboundOriginState, FederationError> {
            if (request, operation, binding) != (self.request, self.operation, self.binding) {
                return Err(FederationError::Conflict);
            }
            Ok(OutboundOriginState::Retired)
        }

        fn stage_outbound_cancellation(
            &self,
            _operation: OperationId,
        ) -> Result<Option<RequestId>, FederationError> {
            Err(FederationError::Corrupt)
        }

        fn pending_outbound_cancellations(
            &self,
            _after: Option<RequestId>,
            _max: usize,
        ) -> Result<Vec<OutboundCallRecord>, FederationError> {
            Err(FederationError::Corrupt)
        }

        fn record_outbound_cancellation(
            &self,
            _request: RequestId,
            _response: xolotl_federation::CallCancelled,
        ) -> Result<OutboundCallRecord, FederationError> {
            Err(FederationError::Corrupt)
        }

        fn stage_outbound(
            &self,
            _intent: OutboundCallIntent,
            _now_ms: u64,
        ) -> Result<OutboundCallRecord, FederationError> {
            Err(FederationError::Corrupt)
        }

        fn bind_outbound_prepared(
            &self,
            _request: RequestId,
            _prepared: CallPrepared,
        ) -> Result<OutboundCallRecord, FederationError> {
            Err(FederationError::Corrupt)
        }

        fn mark_outbound_invoke_possible(
            &self,
            _request: RequestId,
            _now_ms: u64,
        ) -> Result<OutboundCallRecord, FederationError> {
            Err(FederationError::Corrupt)
        }

        fn settle_outbound(
            &self,
            _request: RequestId,
            _terminal: CallInspection,
        ) -> Result<OutboundCallRecord, FederationError> {
            Err(FederationError::Corrupt)
        }

        fn outbound_call(
            &self,
            _request: RequestId,
        ) -> Result<OutboundCallRecord, FederationError> {
            Err(FederationError::NotFound)
        }

        fn unsettled_outbound(
            &self,
            _after: Option<RequestId>,
            _max: usize,
        ) -> Result<Vec<OutboundCallRecord>, FederationError> {
            Err(FederationError::Corrupt)
        }
    }

    fn binding(generation: u64) -> Result<FederationRemoteBinding> {
        Ok(FederationRemoteBinding {
            local: FederationRemoteKey {
                endpoint_id: EndpointId::new(7),
                resource_id: ResourceId::new(8),
                method_id: MethodId::new(9),
                binding_generation: generation,
                effect_path: Path::parse("effect://federation/test")?,
            },
            local_method_name: "invoke".into(),
            target_node: FederationNodeId::from_bytes([2; 48]),
            target: CallTarget {
                export: ExportName::new("tools")?,
                path: CallPath::new("/test")?,
                method: CallMethod::new("run")?,
                contract_digest: [3; 32],
            },
            codec: Arc::new(JsonCallCodec),
            timing: FederationRemoteTiming::default(),
        })
    }

    fn invoke(
        binding: &FederationRemoteBinding,
        id: OperationId,
    ) -> (RemoteInvokeDispatch, Invoke) {
        (
            RemoteInvokeDispatch {
                endpoint_id: binding.local.endpoint_id,
                resource_id: binding.local.resource_id,
                method_id: binding.local.method_id,
                binding_generation: binding.local.binding_generation,
                acting: IdentityRef::ROOT,
                output_mode: OutputMode::Unary,
            },
            Invoke {
                invocation_id: id.to_string(),
                effect_path: binding.local.effect_path.clone(),
                method_id: binding.local.method_id,
                input: Value::string("input".into()),
                deadline_ms: None,
                output_stream_to: None,
            },
        )
    }

    #[test]
    fn operation_request_identity_survives_replay_and_isolated_namespaces() -> Result<()> {
        let origin = FederationNodeId::from_bytes([1; 48]);
        let id: OperationId = "4/5/6/7/8".parse()?;
        let first = DurableOperationIdHash::new([11; 32])?;
        let restored = DurableOperationIdHash::new([11; 32])?;
        let another = DurableOperationIdHash::new([12; 32])?;
        ensure!(first.request_id(origin, id)? == restored.request_id(origin, id)?);
        ensure!(first.request_id(origin, id)? != another.request_id(origin, id)?);
        ensure!(
            first.request_id(origin, id)?
                != first.request_id(origin, id.retry().context("retry exhausted")?)?
        );
        Ok(())
    }

    #[tokio::test]
    async fn source_jobs_distinguish_admission_outcome_and_ledger_failures() -> Result<()> {
        use xolotl_kernel::host::{BlockingJob, TokioBlockingSpawner};

        struct DiscardingHost;
        impl BlockingSpawner for DiscardingHost {
            fn spawn(&self, job: BlockingJob) -> Result<(), BlockingSpawnError> {
                drop(job);
                Ok(())
            }
        }

        let origin = FederationNodeId::from_bytes([1; 48]);
        let operation: OperationId = "4/5/6/7/8".parse()?;
        let binding = binding(1)?;
        let (dispatch, request) = invoke(&binding, operation);
        let identity: Arc<dyn FederationCallIdentity> =
            Arc::new(DurableOperationIdHash::new([13; 32])?);
        let request_id = identity.request_id(origin, operation)?;
        let source = Arc::new(MemoryFederationOutboundCallStore::new(
            origin,
            std::num::NonZeroUsize::new(32 * 1024 * 1024).context("source payload budget")?,
        ));
        let blocking = Arc::new(TokioBlockingSpawner::new(1)?);
        let endpoint = FederationRemoteEndpoint::new(
            source.clone(),
            Arc::clone(&identity),
            Arc::new(LocalPrincipal(origin)),
            Arc::new(NoSession),
            blocking.clone(),
            [binding.clone()],
        )?;
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        let occupied =
            xolotl_kernel::host::blocking::dispatch(blocking.as_ref(), move || -> Result<()> {
                let _entered = entered.send(());
                gate.recv_timeout(Duration::from_secs(5))?;
                Ok(())
            })?;
        tokio::time::timeout(Duration::from_secs(5), ready).await??;
        ensure!(matches!(
            endpoint.existing(request_id).await,
            Err(SourceWorkError::Admission(BlockingSpawnError::AtCapacity))
        ));
        ensure!(matches!(
            endpoint
                .bind_origin(request_id, operation, Digest::from_bytes([2; 48]))
                .await,
            Err(SourceWorkError::Admission(BlockingSpawnError::AtCapacity))
        ));
        ensure!(matches!(endpoint.invoke(dispatch, request.clone()).await,
            Err(DriverError::OutcomeUnknown { operation_id, reason })
                if operation_id == operation.to_string()
                    && reason == "source call ledger job not admitted: host capacity exceeded; reconcile original identity"));
        release.send(())?;
        occupied.await??;
        blocking.wait_idle().await;
        ensure!(
            source.bind_outbound_origin(request_id, operation, Digest::from_bytes([3; 48]))?
                == OutboundOriginState::Active
        );
        ensure!(matches!(
            endpoint
                .bind_origin(request_id, operation, Digest::from_bytes([2; 48]))
                .await,
            Err(SourceWorkError::Ledger(FederationError::Conflict))
        ));
        blocking.wait_idle().await;
        let capacity = endpoint
            .run_source(|| Err::<(), _>(FederationError::Capacity))
            .await;
        ensure!(matches!(
            capacity,
            Err(SourceWorkError::Ledger(FederationError::Capacity))
        ));
        ensure!(
            matches!(source_error(&operation.to_string(), capacity.err().context("business capacity was swallowed")?),
            DriverError::OutcomeUnknown { operation_id, reason }
                if operation_id == operation.to_string()
                    && reason == "source call ledger capacity exceeded; reconcile original identity")
        );
        blocking.wait_idle().await;
        let indeterminate = endpoint
            .run_source(|| Err::<(), _>(FederationError::Indeterminate))
            .await;
        ensure!(
            matches!(source_error(&operation.to_string(), indeterminate.err().context("unknown commit was swallowed")?),
            DriverError::OutcomeUnknown { operation_id, reason }
                if operation_id == operation.to_string()
                    && reason == "source call ledger commit outcome indeterminate; reconcile original identity")
        );
        blocking.wait_idle().await;
        let panicked = endpoint
            .run_source(|| -> Result<(), FederationError> {
                std::panic::resume_unwind(Box::new("source job panic"))
            })
            .await;
        ensure!(matches!(
            panicked,
            Err(SourceWorkError::Outcome(BlockingTaskError::Panicked))
        ));
        ensure!(
            matches!(source_error(&operation.to_string(), panicked.err().context("panic was swallowed")?),
            DriverError::OutcomeUnknown { operation_id, reason }
                if operation_id == operation.to_string()
                    && reason == "source call ledger worker panicked: result unavailable; reconcile original identity")
        );
        blocking.close();
        blocking.wait_idle().await;
        ensure!(matches!(
            endpoint.existing(request_id).await,
            Err(SourceWorkError::Admission(BlockingSpawnError::Unavailable))
        ));
        ensure!(matches!(
            endpoint
                .bind_origin(request_id, operation, Digest::from_bytes([3; 48]))
                .await,
            Err(SourceWorkError::Admission(BlockingSpawnError::Unavailable))
        ));
        ensure!(matches!(endpoint.invoke(dispatch, request).await,
            Err(DriverError::OutcomeUnknown { operation_id, reason })
                if operation_id == operation.to_string()
                    && reason == "source call ledger job not admitted: host unavailable; reconcile original identity"));
        let discarded = FederationRemoteEndpoint::new(
            source,
            identity,
            Arc::new(LocalPrincipal(origin)),
            Arc::new(NoSession),
            Arc::new(DiscardingHost),
            [binding],
        )?;
        let lost = discarded
            .existing(request_id)
            .await
            .err()
            .context("discarded lookup returned absence")?;
        ensure!(matches!(
            lost,
            SourceWorkError::Outcome(BlockingTaskError::Cancelled)
        ));
        ensure!(matches!(source_error(&operation.to_string(), lost),
            DriverError::OutcomeUnknown { operation_id, reason }
                if operation_id == operation.to_string()
                    && reason == "source call ledger worker discarded: result unavailable; reconcile original identity"));
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_origin_binding_stays_in_host_drain_and_survives_reopen() -> Result<()> {
        use std::{
            future::Future as _,
            sync::atomic::{AtomicUsize, Ordering},
            task::Poll,
        };
        use xolotl_kernel::host::{BlockingJob, TokioBlockingSpawner};

        struct SourceGate {
            entered: tokio::sync::oneshot::Sender<()>,
            release: std::sync::mpsc::Receiver<()>,
        }
        struct OriginHost {
            inner: Arc<TokioBlockingSpawner>,
            jobs: AtomicUsize,
            gate: std::sync::Mutex<Option<SourceGate>>,
        }
        impl BlockingSpawner for OriginHost {
            fn spawn(&self, job: BlockingJob) -> Result<(), BlockingSpawnError> {
                let gate = if self.jobs.fetch_add(1, Ordering::SeqCst) == 1 {
                    self.gate
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take()
                } else {
                    None
                };
                self.inner.spawn(Box::new(move || {
                    if let Some(gate) = gate {
                        let _entered = gate.entered.send(());
                        if gate.release.recv_timeout(Duration::from_secs(5)).is_err() {
                            return;
                        }
                    }
                    job();
                }))
            }
        }
        struct ObservedSessions(AtomicUsize);
        #[async_trait]
        impl FederationCallSessionProvider for ObservedSessions {
            async fn session(
                &self,
                _target: FederationNodeId,
                _subject: &FederationSubject,
            ) -> Result<FederationCallSession, DriverError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(DriverError::Transport("offline".into()))
            }
        }

        let directory = tempfile::tempdir()?;
        let path = directory.path().join("origin.redb");
        let database = xolotl_storage_redb::RedbStore::open(&path)?;
        let origin = FederationNodeId::from_bytes([1; 48]);
        let source = Arc::new(database.federation_store(origin)?);
        let namespace = source.kernel_call_namespace()?;
        let operation: OperationId = "4/5/6/7/8".parse()?;
        let binding = binding(1)?;
        let (dispatch, request) = invoke(&binding, operation);
        let identity: Arc<dyn FederationCallIdentity> =
            Arc::new(DurableOperationIdHash::new(namespace)?);
        let request_id = identity.request_id(origin, operation)?;
        let digest = fingerprint(
            &binding,
            "identity://test/actor",
            &FederationSubject::Node(origin),
        );
        let blocking = Arc::new(TokioBlockingSpawner::new(2)?);
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        let host = Arc::new(OriginHost {
            inner: Arc::clone(&blocking),
            jobs: AtomicUsize::new(0),
            gate: std::sync::Mutex::new(Some(SourceGate {
                entered,
                release: gate,
            })),
        });
        let sessions = Arc::new(ObservedSessions(AtomicUsize::new(0)));
        let endpoint = FederationRemoteEndpoint::new(
            source.clone(),
            Arc::clone(&identity),
            Arc::new(LocalPrincipal(origin)),
            sessions.clone(),
            host.clone(),
            [binding.clone()],
        )?;
        let mut invocation = Box::pin(endpoint.invoke(dispatch, request.clone()));
        tokio::select! {
            result = &mut invocation => anyhow::bail!("invoke completed before origin binding gate: {result:?}"),
            entered = tokio::time::timeout(Duration::from_secs(5), ready) => entered??,
        }
        ensure!(host.jobs.load(Ordering::SeqCst) == 2);
        drop(invocation);
        drop(endpoint);
        drop(source);
        drop(database);
        ensure!(sessions.0.load(Ordering::SeqCst) == 0);
        blocking.close();
        let mut idle = std::pin::pin!(blocking.wait_idle());
        ensure!(
            std::future::poll_fn(|context| Poll::Ready(idle.as_mut().poll(context)))
                .await
                .is_pending()
        );
        ensure!(matches!(
            xolotl_storage_redb::RedbStore::open(&path),
            Err(redb::DatabaseError::DatabaseAlreadyOpen)
        ));
        release.send(())?;
        tokio::time::timeout(Duration::from_secs(5), idle).await?;
        ensure!(sessions.0.load(Ordering::SeqCst) == 0);
        let database = xolotl_storage_redb::RedbStore::open(&path)?;
        let source = Arc::new(database.federation_store(origin)?);
        ensure!(matches!(
            source.bind_outbound_origin(request_id, operation, Digest::from_bytes([7; 48])),
            Err(FederationError::Conflict)
        ));
        ensure!(
            source
                .bind_outbound_origin(request_id, operation, digest)
                .context("reopen original durable origin binding")?
                == OutboundOriginState::Active
        );
        let reopened = Arc::new(TokioBlockingSpawner::new(2)?);
        let endpoint = FederationRemoteEndpoint::new(
            source,
            identity,
            Arc::new(LocalPrincipal(origin)),
            sessions.clone(),
            reopened.clone(),
            [binding],
        )?;
        ensure!(matches!(endpoint.invoke(dispatch, request).await,
            Err(DriverError::Transport(reason)) if reason == "offline"));
        ensure!(sessions.0.load(Ordering::SeqCst) == 1);
        reopened.close();
        reopened.wait_idle().await;
        Ok(())
    }

    #[tokio::test]
    async fn retired_origin_never_restarts_preparation() -> Result<()> {
        let origin = FederationNodeId::from_bytes([1; 48]);
        let operation: OperationId = "4/5/6/7/8".parse()?;
        let binding = binding(1)?;
        let (dispatch, request) = invoke(&binding, operation);
        let identity: Arc<dyn FederationCallIdentity> =
            Arc::new(DurableOperationIdHash::new([13; 32])?);
        let source = Arc::new(RetiredSource {
            releases: std::sync::atomic::AtomicUsize::new(0),
            node: origin,
            request: identity.request_id(origin, operation)?,
            operation,
            binding: fingerprint(
                &binding,
                "identity://test/actor",
                &FederationSubject::Node(origin),
            ),
        });
        let endpoint = FederationRemoteEndpoint::new(
            source,
            identity,
            Arc::new(LocalPrincipal(origin)),
            Arc::new(NoSession),
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            [binding],
        )?;
        ensure!(matches!(
            endpoint.invoke(dispatch, request.clone()).await,
            Err(DriverError::OutcomeUnknown { .. })
        ));
        let stream = RemoteInvokeDispatch {
            output_mode: xolotl_types::OutputMode::Stream,
            ..dispatch
        };
        ensure!(matches!(endpoint.invoke(stream, request).await,
            Err(DriverError::OutcomeUnknown { operation_id, .. }) if operation_id == operation.to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn local_validation_classifies_fresh_recorded_and_retired_origins() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        #[derive(Clone, Copy)]
        enum Validation {
            Stream,
            Oversized,
            Codec,
            Principal,
        }
        struct RejectedPrincipal;
        impl FederationCallPrincipal for RejectedPrincipal {
            fn resolve(
                &self,
                _binding: &FederationRemoteKey,
                _acting: IdentityRef,
            ) -> Result<FederationCallPrincipalBinding, DriverError> {
                Err(DriverError::Transport("principal unavailable".into()))
            }
        }
        struct OversizedCodec(Arc<AtomicUsize>);
        impl FederationCallCodec for OversizedCodec {
            fn id(&self) -> &str {
                "test.oversized"
            }
            fn encode_input(&self, _input: &Value) -> Result<Vec<u8>, DriverError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(vec![0; MAX_CALL_INPUT_BYTES + 1])
            }
            fn decode_output(&self, _output: &[u8]) -> Result<Value, DriverError> {
                Err(DriverError::Transport("unexpected decode".into()))
            }
        }
        let origin = FederationNodeId::from_bytes([1; 48]);
        let operation: OperationId = "4/5/6/7/8".parse()?;
        for (evidence, call_only) in [
            (OutboundOriginEvidence::Fresh, false),
            (OutboundOriginEvidence::Recorded, false),
            (OutboundOriginEvidence::Recorded, true),
            (OutboundOriginEvidence::Retired, false),
        ] {
            let source = Arc::new(MemoryFederationOutboundCallStore::new(
                origin,
                std::num::NonZeroUsize::new(32 * 1024 * 1024).context("source payload budget")?,
            ));
            let identity: Arc<dyn FederationCallIdentity> =
                Arc::new(DurableOperationIdHash::new([13; 32])?);
            let request_id = identity.request_id(origin, operation)?;
            if call_only {
                let route = binding(1)?;
                let (_dispatch, request) = invoke(&route, operation);
                let input: Arc<[u8]> = Arc::from(route.codec.encode_input(&request.input)?);
                source.stage_outbound(
                    OutboundCallIntent {
                        target_node: route.target_node,
                        request: PrepareCallRequest {
                            authenticated_origin: origin,
                            subject: FederationSubject::Node(origin),
                            origin_request_id: request_id,
                            target: route.target,
                            input_digest: Digest::from_bytes(Sha384::digest(&input).into()),
                            input_bytes: input.len() as u64,
                            prepare_deadline_ms: 200,
                            execution_deadline_ms: 300,
                            result_retention_ms: 500,
                        },
                        input,
                    },
                    100,
                )?;
            } else if evidence == OutboundOriginEvidence::Recorded {
                source.bind_outbound_origin(request_id, operation, Digest::from_bytes([2; 48]))?;
            } else if evidence == OutboundOriginEvidence::Retired {
                source.stage_outbound_cancellation(operation)?;
            }
            ensure!(source.outbound_origin_evidence(request_id, operation)? == evidence);
            if !call_only {
                ensure!(matches!(
                    source.outbound_call(request_id),
                    Err(FederationError::NotFound)
                ));
            }
            for validation in [
                Validation::Stream,
                Validation::Oversized,
                Validation::Codec,
                Validation::Principal,
            ] {
                let mut route = binding(1)?;
                let encodings = Arc::new(AtomicUsize::new(0));
                if matches!(validation, Validation::Oversized) {
                    route.codec = Arc::new(OversizedCodec(Arc::clone(&encodings)));
                } else if matches!(validation, Validation::Codec) {
                    route.codec = Arc::new(RawBytesCallCodec);
                }
                let (mut dispatch, request) = invoke(&route, operation);
                if matches!(validation, Validation::Stream) {
                    dispatch.output_mode = xolotl_types::OutputMode::Stream;
                }
                let principal: Arc<dyn FederationCallPrincipal> =
                    if matches!(validation, Validation::Principal) {
                        Arc::new(RejectedPrincipal)
                    } else {
                        Arc::new(LocalPrincipal(origin))
                    };
                let endpoint = FederationRemoteEndpoint::new(
                    source.clone(),
                    identity.clone(),
                    principal,
                    Arc::new(NoSession),
                    Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
                    [route],
                )?;
                let result = endpoint.invoke(dispatch, request).await;
                if evidence != OutboundOriginEvidence::Fresh {
                    ensure!(
                        matches!(result, Err(DriverError::OutcomeUnknown { operation_id, .. }) if operation_id == operation.to_string())
                    );
                } else if matches!(validation, Validation::Oversized | Validation::Codec) {
                    ensure!(matches!(result, Err(DriverError::InvalidInput(_))));
                } else if matches!(validation, Validation::Principal) {
                    ensure!(
                        matches!(result, Err(DriverError::Transport(reason)) if reason == "principal unavailable")
                    );
                } else {
                    ensure!(matches!(result, Err(DriverError::UnsupportedOutput(_))));
                }
                ensure!(source.outbound_origin_evidence(request_id, operation)? == evidence);
                if matches!(validation, Validation::Oversized) {
                    ensure!(
                        encodings.load(Ordering::SeqCst)
                            == usize::from(evidence != OutboundOriginEvidence::Retired)
                    );
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn settled_call_replays_offline_and_changed_binding_is_rejected() -> Result<()> {
        let origin = FederationNodeId::from_bytes([1; 48]);
        let source = Arc::new(MemoryFederationOutboundCallStore::new(
            origin,
            std::num::NonZeroUsize::new(32 * 1024 * 1024).context("source payload budget")?,
        ));
        let identity: Arc<dyn FederationCallIdentity> =
            Arc::new(DurableOperationIdHash::new([13; 32])?);
        let principal: Arc<dyn FederationCallPrincipal> = Arc::new(LocalPrincipal(origin));
        let sessions: Arc<dyn FederationCallSessionProvider> = Arc::new(NoSession);
        let first = binding(1)?;
        let operation: OperationId = "4/5/6/7/8".parse()?;
        let (dispatch, request) = invoke(&first, operation);
        let request_id = identity.request_id(origin, operation)?;
        source.bind_outbound_origin(
            request_id,
            operation,
            fingerprint(
                &first,
                "identity://test/actor",
                &FederationSubject::Node(origin),
            ),
        )?;
        let input: Arc<[u8]> = Arc::from(first.codec.encode_input(&request.input)?);
        source.stage_outbound(
            OutboundCallIntent {
                target_node: first.target_node,
                request: PrepareCallRequest {
                    authenticated_origin: origin,
                    subject: FederationSubject::Node(origin),
                    origin_request_id: request_id,
                    target: first.target.clone(),
                    input_digest: Digest::from_bytes(Sha384::digest(&input).into()),
                    input_bytes: input.len() as u64,
                    prepare_deadline_ms: 200,
                    execution_deadline_ms: 300,
                    result_retention_ms: 500,
                },
                input,
            },
            100,
        )?;
        let call = CallRef::new(first.target_node, [22; 32])?;
        source.bind_outbound_prepared(
            request_id,
            CallPrepared {
                origin_request_id: request_id,
                call,
                status: CallStatus::Reserved,
                reserved_until_ms: 190,
                execution_deadline_ms: 300,
                result_retention_ms: 500,
                authority_revision: 1,
                control_revision: 1,
            },
        )?;
        source.mark_outbound_invoke_possible(request_id, 110)?;
        let pending = FederationRemoteEndpoint::new(
            source.clone(),
            Arc::clone(&identity),
            Arc::clone(&principal),
            Arc::clone(&sessions),
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            [first.clone()],
        )?;
        ensure!(matches!(
            pending.invoke(dispatch, request.clone()).await,
            Err(DriverError::OutcomeUnknown { .. })
        ));
        let expected = Value::string("done".into());
        source.settle_outbound(
            request_id,
            CallInspection {
                call,
                status: CallStatus::Finished,
                control_revision: 2,
                authority_revision: 1,
                reserved_until_ms: 190,
                execution_deadline_ms: 300,
                result_retained_until_ms: 500,
                result: Some(PersistedCallResult::new(
                    true,
                    Arc::from(first.codec.encode_input(&expected)?),
                    None,
                )?),
                unresolved_effect_ids: Vec::new(),
                cancellation_requested: false,
                kernel_cancel_accepted: false,
                execution_stopped: true,
            },
        )?;
        let endpoint = FederationRemoteEndpoint::new(
            source.clone(),
            Arc::clone(&identity),
            Arc::clone(&principal),
            Arc::clone(&sessions),
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            [first.clone()],
        )?;
        let mut streamed = dispatch;
        streamed.output_mode = OutputMode::Stream;
        ensure!(matches!(
            endpoint.invoke(streamed, request.clone()).await,
            Err(DriverError::OutcomeUnknown { .. })
        ));
        let endpoint = FederationRemoteEndpoint::new(
            source.clone(),
            Arc::clone(&identity),
            Arc::new(DenyPrincipal),
            Arc::clone(&sessions),
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            [first.clone()],
        )?;
        ensure!(matches!(
            endpoint.invoke(dispatch, request.clone()).await,
            Err(DriverError::OutcomeUnknown { .. })
        ));
        let mut broken_codec = first.clone();
        broken_codec.codec = Arc::new(BrokenJsonCodec);
        let endpoint = FederationRemoteEndpoint::new(
            source.clone(),
            Arc::clone(&identity),
            Arc::clone(&principal),
            Arc::clone(&sessions),
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            [broken_codec],
        )?;
        ensure!(matches!(
            endpoint.invoke(dispatch, request.clone()).await,
            Err(DriverError::OutcomeUnknown { .. })
        ));

        let mut rejected_output = first.clone();
        rejected_output.codec = Arc::new(DecodeRejectCodec);
        let endpoint = FederationRemoteEndpoint::new(
            source.clone(),
            identity.clone(),
            principal.clone(),
            sessions.clone(),
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            [rejected_output],
        )?;
        ensure!(matches!(
            endpoint.invoke(dispatch, request.clone()).await,
            Err(DriverError::OutcomeUnknown { .. })
        ));
        ensure!(source.outbound_call(request_id)?.terminal.is_some());

        let changed = binding(2)?;
        let mut stale = dispatch;
        stale.binding_generation = 2;
        let endpoint = FederationRemoteEndpoint::new(
            source.clone(),
            identity.clone(),
            principal.clone(),
            sessions.clone(),
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            [changed],
        )?;
        ensure!(matches!(
            endpoint.invoke(stale, request.clone()).await,
            Err(DriverError::OutcomeUnknown { .. })
        ));
        ensure!(source.outbound_call(request_id)?.terminal.is_some());
        let endpoint = FederationRemoteEndpoint::new(
            source.clone(),
            identity,
            principal,
            sessions,
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            [first],
        )?;
        let mut reassigned = dispatch;
        reassigned.acting = IdentityRef(991);
        ensure!(endpoint.invoke(reassigned, request.clone()).await?.outcome == Ok(expected));
        ensure!(
            source.outbound_origin_evidence(request_id, operation)?
                == OutboundOriginEvidence::Retired
        );
        ensure!(matches!(
            source.outbound_call(request_id),
            Err(FederationError::NotFound)
        ));
        ensure!(matches!(
            endpoint.invoke(dispatch, request).await,
            Err(DriverError::OutcomeUnknown { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn result_release_skips_uncertain_work_and_preserves_output_on_failure() -> Result<()> {
        let origin = FederationNodeId::from_bytes([1; 48]);
        let operation: OperationId = "4/5/6/7/8".parse()?;
        let first = binding(1)?;
        let (_, request) = invoke(&first, operation);
        let identity: Arc<dyn FederationCallIdentity> =
            Arc::new(DurableOperationIdHash::new([13; 32])?);
        let request_id = identity.request_id(origin, operation)?;
        let source = Arc::new(RetiredSource {
            releases: std::sync::atomic::AtomicUsize::new(0),
            node: origin,
            request: request_id,
            operation,
            binding: fingerprint(
                &first,
                "identity://test/actor",
                &FederationSubject::Node(origin),
            ),
        });
        let endpoint = FederationRemoteEndpoint::new(
            source.clone(),
            identity,
            Arc::new(LocalPrincipal(origin)),
            Arc::new(NoSession),
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            [first.clone()],
        )?;
        for (stopped, unresolved, expected_releases) in
            [(false, false, 0), (true, true, 0), (true, false, 1)]
        {
            let terminal = CallInspection {
                call: CallRef::new(FederationNodeId::from_bytes([2; 48]), [22; 32])?,
                status: CallStatus::Finished,
                control_revision: 2,
                authority_revision: 1,
                reserved_until_ms: 190,
                execution_deadline_ms: 300,
                result_retained_until_ms: 500,
                result: Some(PersistedCallResult::new(
                    true,
                    Arc::from(first.codec.encode_input(&Value::string("owned".into()))?),
                    None,
                )?),
                unresolved_effect_ids: if unresolved {
                    vec![[3; 32]]
                } else {
                    Vec::new()
                },
                cancellation_requested: false,
                kernel_cancel_accepted: false,
                execution_stopped: stopped,
            };
            let decoded = result_from_terminal(&request, &first, &terminal);
            if expected_releases == 0 {
                ensure!(
                    matches!(decoded, Err(DriverError::OutcomeUnknown { operation_id, .. }) if operation_id == operation.to_string())
                );
                ensure!(source.releases.load(std::sync::atomic::Ordering::SeqCst) == 0);
                continue;
            }
            let result = decoded?;
            let returned = endpoint
                .release_consumed_result(request_id, operation, &terminal, result)
                .await;
            ensure!(returned.outcome == Ok(Value::string("owned".into())));
            ensure!(source.releases.load(std::sync::atomic::Ordering::SeqCst) == expected_releases);
        }
        Ok(())
    }
}
