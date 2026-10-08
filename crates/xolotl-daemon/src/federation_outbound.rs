//! Stock Kernel Resource bindings for authenticated outbound federated calls.
//! Registration precedes live execution, so each call resolves
//! the same local path and method before it can emit a wire request.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use tokio::sync::Mutex as AsyncMutex;
use xolotl_federation::{
    CallMethod, CallPath, CallTarget, ExportName, FederationNodeId, FederationOutboundCallStore,
    FederationSubject, HostedSubject, SubjectAssertion, SubjectHolderKey, SubjectIssuer,
    SubjectIssuerId, SubjectPurpose,
};
use xolotl_federation_grpc::{
    DurableOperationIdHash, FederationCallCodec, FederationCallIdentity, FederationCallPrincipal,
    FederationCallPrincipalBinding, FederationCallSession, FederationCallSessionProvider,
    FederationGrpcRuntime, FederationGrpcSubscriberClient, FederationHostedSubjectCredentials,
    FederationLocalCredentials, FederationPeerPolicy, FederationRemoteBinding,
    FederationRemoteEndpoint, FederationRemoteKey, FederationRemoteTiming, JsonCallCodec,
    RawBytesCallCodec, config::PeerDialConfig,
};
use xolotl_kernel::{Bootstrap, EchoDriver, driver::DriverDescriptor};
use xolotl_storage_redb::RedbFederationStore;
use xolotl_types::{
    Binding, CostModel, DriverRef, IdentityRef, Interface, InterfaceFamily, InterfaceSet, Metadata,
    Method, MethodAuthority, MethodId, ModalitySet, OutputModeSet, Path, Purity, Resource,
    ResourceDescriptor, ResourceKind, ResourceName, ResourceSelector, SchemaId, Transport,
};

use crate::config::{
    FederationOutboundCallConfig, FederationOutboundCodecConfig,
    FederationOutboundHostedSubjectConfig, FederationOutboundTimingConfig,
};

const MAX_OUTBOUND_METHODS: usize = 512;
const MAX_OUTBOUND_HOSTED_SUBJECTS: usize = 128;
const MAX_SESSION_HOSTED_SUBJECTS: u32 = 32;

#[derive(Clone)]
pub(crate) struct PreparedHostedSubject {
    name: String,
    acting: String,
    target: FederationNodeId,
    subject: HostedSubject,
    credentials: Arc<FederationHostedSubjectCredentials>,
}

pub(crate) struct StockConnectionConfig {
    pub(crate) routes: Vec<PeerDialConfig>,
    pub(crate) local: Arc<FederationLocalCredentials>,
    pub(crate) policy: Arc<dyn FederationPeerPolicy>,
    pub(crate) grpc: FederationGrpcRuntime,
}

struct PreparedActor {
    identity: IdentityRef,
    stable_acting: Arc<str>,
    subject: FederationSubject,
}

struct PreparedCall {
    local_path: Path,
    local_method: String,
    generation: u64,
    target_node: FederationNodeId,
    target: CallTarget,
    codec: Arc<dyn FederationCallCodec>,
    timing: FederationRemoteTiming,
    allowed_acting: Vec<PreparedActor>,
}

struct StockPrincipal {
    allowed: HashMap<(FederationRemoteKey, IdentityRef), FederationCallPrincipalBinding>,
}

impl FederationCallPrincipal for StockPrincipal {
    fn resolve(
        &self,
        binding: &FederationRemoteKey,
        acting: IdentityRef,
    ) -> Result<FederationCallPrincipalBinding, xolotl_kernel::driver::DriverError> {
        let binding = self
            .allowed
            .get(&(binding.clone(), acting))
            .ok_or_else(|| {
                xolotl_kernel::driver::DriverError::Transport(
                    "acting identity is not admitted for this federated method".into(),
                )
            })?;
        Ok(FederationCallPrincipalBinding {
            subject: binding.subject.clone(),
            stable_acting: Arc::clone(&binding.stable_acting),
        })
    }
}

struct HostedSessionCredentials {
    context_id: u32,
    credentials: Arc<FederationHostedSubjectCredentials>,
}

#[derive(Default)]
struct PeerClient {
    client: Option<FederationGrpcSubscriberClient>,
    registered: HashSet<u32>,
}

/// If an awaiter disappears after RegisterSubject was sent, the peer may have
/// accepted the context even though its acknowledgement was not observed.
/// Discard that Session so a later attempt cannot reuse the same context ID.
struct RegistrationAttempt<'a> {
    peer: &'a mut PeerClient,
    confirmed: bool,
}

impl<'a> RegistrationAttempt<'a> {
    fn new(peer: &'a mut PeerClient) -> Self {
        Self {
            peer,
            confirmed: false,
        }
    }

    fn confirm(&mut self, context_id: u32) {
        self.peer.registered.insert(context_id);
        self.confirmed = true;
    }
}

impl Drop for RegistrationAttempt<'_> {
    fn drop(&mut self) {
        if !self.confirmed {
            self.peer.client = None;
            self.peer.registered.clear();
        }
    }
}

struct StockSessions {
    local: Arc<FederationLocalCredentials>,
    policy: Arc<dyn FederationPeerPolicy>,
    grpc: FederationGrpcRuntime,
    routes: HashMap<FederationNodeId, PeerDialConfig>,
    hosted: HashMap<(FederationNodeId, HostedSubject), HostedSessionCredentials>,
    clients: Mutex<HashMap<FederationNodeId, Arc<AsyncMutex<PeerClient>>>>,
}

#[async_trait]
impl FederationCallSessionProvider for StockSessions {
    async fn session(
        &self,
        target: FederationNodeId,
        subject: &FederationSubject,
    ) -> Result<FederationCallSession, xolotl_kernel::driver::DriverError> {
        let hosted = match subject {
            FederationSubject::Node(node) if *node == self.local.node_id() => None,
            FederationSubject::Hosted(hosted) => {
                Some(self.hosted.get(&(target, hosted.clone())).ok_or_else(|| {
                    xolotl_kernel::driver::DriverError::Transport(
                        "hosted subject has no stock holder credentials for this peer".into(),
                    )
                })?)
            }
            _ => {
                return Err(xolotl_kernel::driver::DriverError::Transport(
                    "outbound node subject differs from local signer".into(),
                ));
            }
        };
        let route = self.routes.get(&target).ok_or_else(|| {
            xolotl_kernel::driver::DriverError::Transport("federation peer has no route".into())
        })?;
        let slot = {
            let mut clients = self.clients.lock().map_err(|_error| {
                xolotl_kernel::driver::DriverError::Transport(
                    "federation Session registry unavailable".into(),
                )
            })?;
            Arc::clone(
                clients
                    .entry(target)
                    .or_insert_with(|| Arc::new(AsyncMutex::new(PeerClient::default()))),
            )
        };
        let mut peer = slot.lock().await;
        if peer
            .client
            .as_ref()
            .is_none_or(FederationGrpcSubscriberClient::is_closed)
        {
            peer.client = Some(
                FederationGrpcSubscriberClient::connect(
                    route.clone(),
                    Arc::clone(&self.local),
                    Arc::clone(&self.policy),
                    self.grpc.clone(),
                )
                .await
                .map_err(|_error| {
                    xolotl_kernel::driver::DriverError::Transport(
                        "federation peer Session unavailable".into(),
                    )
                })?,
            );
            peer.registered.clear();
        }
        let client = peer
            .client
            .as_ref()
            .ok_or_else(|| {
                xolotl_kernel::driver::DriverError::Transport(
                    "federation peer Session unavailable".into(),
                )
            })?
            .clone();
        let context_id = if let Some(hosted) = hosted {
            if !peer.registered.contains(&hosted.context_id) {
                let mut attempt = RegistrationAttempt::new(&mut peer);
                let accepted = client
                    .register_subject(hosted.context_id, Arc::clone(&hosted.credentials))
                    .await
                    .map_err(|_error| {
                        xolotl_kernel::driver::DriverError::Transport(
                            "hosted subject registration rejected".into(),
                        )
                    })?;
                if accepted != hosted.context_id {
                    return Err(xolotl_kernel::driver::DriverError::Transport(
                        "hosted subject registration returned another context".into(),
                    ));
                }
                attempt.confirm(hosted.context_id);
            }
            hosted.context_id
        } else {
            0
        };
        Ok(FederationCallSession { client, context_id })
    }
}

/// Load only operator-provisioned, issuer-signed assertions. The local acting
/// identity is resolved later, against the local Kernel identity directory,
/// before live execution can dispatch an outbound effect.
pub(crate) fn parse_hosted(
    declarations: &[FederationOutboundHostedSubjectConfig],
    local: FederationNodeId,
    routes: impl IntoIterator<Item = FederationNodeId>,
) -> Result<Vec<PreparedHostedSubject>> {
    ensure!(
        declarations.len() <= MAX_OUTBOUND_HOSTED_SUBJECTS,
        "too many stock outbound Hosted subjects"
    );
    let targets: HashSet<_> = routes.into_iter().collect();
    let mut names = HashSet::new();
    let mut bindings = HashSet::new();
    let mut prepared = Vec::with_capacity(declarations.len());
    for declaration in declarations {
        ensure!(
            !declaration.name.is_empty()
                && declaration.name.len() <= 128
                && !declaration.name.chars().any(char::is_control)
                && names.insert(declaration.name.as_str()),
            "invalid or duplicate stock Hosted credential name"
        );
        let target = FederationNodeId::from_bytes(decode_hex::<48>(
            &declaration.peer_node,
            "outbound Hosted peer_node",
        )?);
        ensure!(
            target != local && targets.contains(&target),
            "outbound Hosted subject requires an enabled pinned peer route"
        );
        ensure!(
            declaration.acting == "root"
                || Path::parse(&declaration.acting)
                    .ok()
                    .is_some_and(|path| xolotl_kernel::identity::validate_path(&path).is_ok()),
            "outbound Hosted acting identity must be root or a concrete identity:// path"
        );
        let issuer_bytes = crate::config::read_private_bounded_file(
            &declaration.issuer_descriptor_path,
            "Hosted issuer descriptor",
            SubjectIssuer::ENCODED_LEN as u64,
        )?;
        let issuer = SubjectIssuer::decode(&issuer_bytes)
            .context("decode outbound Hosted issuer descriptor")?;
        let expected_subject = HostedSubject {
            issuer: SubjectIssuerId::from_bytes(decode_hex::<48>(
                &declaration.issuer,
                "outbound Hosted issuer",
            )?),
            namespace: declaration.namespace.clone(),
            subject: declaration.subject.clone(),
        };
        let assertion_bytes = crate::config::read_private_bounded_file(
            &declaration.assertion_path,
            "Hosted assertion",
            4096,
        )?;
        let assertion = SubjectAssertion::decode(&assertion_bytes)
            .context("decode outbound Hosted assertion")?;
        ensure!(
            assertion.audience() == target
                && assertion.presenter() == local
                && assertion.purpose() == SubjectPurpose::Invoke
                && assertion.subject() == &expected_subject
                && issuer.id() == expected_subject.issuer,
            "outbound Hosted assertion differs from the pinned subject, target, presenter or Invoke purpose"
        );
        let signature = crate::config::read_private_bounded_file(
            &declaration.issuer_signature_path,
            "Hosted issuer signature",
            xolotl_federation::FederationRoot::SIGNATURE_LEN as u64,
        )?;
        issuer
            .verify_assertion(&assertion, &signature)
            .context("verify outbound Hosted issuer signature")?;
        let holder_key = crate::config::read_private_bounded_file(
            &declaration.holder_key_path,
            "Hosted holder key",
            64 * 1024,
        )?;
        let holder = Arc::new(
            SubjectHolderKey::from_pkcs8(&holder_key)
                .context("decode outbound Hosted holder key")?,
        );
        let subject = expected_subject;
        ensure!(
            bindings.insert((target, subject.clone())),
            "duplicate stock Hosted subject for one target"
        );
        let credentials = Arc::new(
            FederationHostedSubjectCredentials::new(&issuer, assertion, signature.to_vec(), holder)
                .context("assemble outbound Hosted credentials")?,
        );
        prepared.push(PreparedHostedSubject {
            name: declaration.name.clone(),
            acting: declaration.acting.clone(),
            target,
            subject,
            credentials,
        });
    }
    Ok(prepared)
}

pub(crate) fn stock_sessions(
    local: Arc<FederationLocalCredentials>,
    policy: Arc<dyn FederationPeerPolicy>,
    grpc: FederationGrpcRuntime,
    routes: impl IntoIterator<Item = PeerDialConfig>,
    hosted: &[PreparedHostedSubject],
) -> Result<Arc<dyn FederationCallSessionProvider>> {
    let mut route_map = HashMap::new();
    for route in routes {
        ensure!(
            route_map.insert(route.expected_peer, route).is_none(),
            "duplicate outbound federation peer route"
        );
    }
    let mut context_ids = HashMap::<FederationNodeId, u32>::new();
    let mut subjects = HashMap::new();
    for item in hosted {
        ensure!(
            route_map.contains_key(&item.target),
            "Hosted subject has no enabled outbound peer route"
        );
        let next = context_ids.entry(item.target).or_default();
        *next += 1;
        ensure!(
            *next <= MAX_SESSION_HOSTED_SUBJECTS,
            "too many stock Hosted subjects for one peer Session"
        );
        ensure!(
            subjects
                .insert(
                    (item.target, item.subject.clone()),
                    HostedSessionCredentials {
                        context_id: *next,
                        credentials: Arc::clone(&item.credentials),
                    },
                )
                .is_none(),
            "duplicate Hosted subject for one peer Session"
        );
    }
    Ok(Arc::new(StockSessions {
        local,
        policy,
        grpc,
        routes: route_map,
        hosted: subjects,
        clients: Mutex::new(HashMap::new()),
    }))
}

/// Install exact outbound bindings before live requests. The stock host
/// uses the same redb file for the source ledger, operation namespace,
/// execution-ID allocator and host runtime.
pub(crate) fn install(
    boot: &Bootstrap,
    store: RedbFederationStore,
    declarations: &[FederationOutboundCallConfig],
    hosted: &[PreparedHostedSubject],
    connection: StockConnectionConfig,
) -> Result<()> {
    if declarations.is_empty() {
        return Ok(());
    }
    ensure!(
        declarations.len() <= MAX_OUTBOUND_METHODS,
        "too many outbound federation methods"
    );
    ensure!(
        store.local_node() == connection.local.node_id(),
        "outbound federation store differs from local signer"
    );
    let mut route_map = HashMap::new();
    for route in connection.routes {
        ensure!(
            route_map.insert(route.expected_peer, route).is_none(),
            "duplicate outbound federation peer route"
        );
    }
    let mut groups: BTreeMap<Path, Vec<PreparedCall>> = BTreeMap::new();
    let mut seen = HashSet::new();
    for declaration in declarations {
        let prepared = prepare(
            boot,
            declaration,
            hosted,
            &route_map,
            connection.local.node_id(),
        )?;
        ensure!(
            seen.insert((prepared.local_path.clone(), prepared.local_method.clone())),
            "duplicate outbound federation local path and method"
        );
        groups
            .entry(prepared.local_path.clone())
            .or_default()
            .push(prepared);
    }
    let registry = boot.kernel().registry();
    let endpoint_id = registry.next_endpoint_id();
    let mut bundles = Vec::with_capacity(groups.len());
    let mut remote_bindings = Vec::with_capacity(declarations.len());
    let mut allowed = HashMap::new();
    for (path, mut calls) in groups {
        calls.sort_by(|left, right| left.local_method.cmp(&right.local_method));
        ensure!(
            calls.len() <= 64,
            "a federated Resource supports at most 64 methods"
        );
        let generation = calls[0].generation;
        ensure!(
            calls.iter().all(|call| call.generation == generation),
            "methods on one federated Resource require one binding_generation"
        );
        let resource_id = registry.next_resource_id();
        let interface_id = registry.next_interface_id();
        let driver_id = registry.next_driver_id();
        let binding_id = registry.next_binding_id();
        let interfaces = InterfaceSet::new(vec![interface_id]);
        let mut methods = Vec::with_capacity(calls.len());
        for (index, call) in calls.into_iter().enumerate() {
            let method_id = MethodId::new(index as u64);
            let key = FederationRemoteKey {
                endpoint_id,
                resource_id,
                method_id,
                binding_generation: generation,
                effect_path: path.clone(),
            };
            for actor in call.allowed_acting {
                ensure!(
                    allowed
                        .insert(
                            (key.clone(), actor.identity),
                            FederationCallPrincipalBinding {
                                subject: actor.subject,
                                stable_acting: actor.stable_acting,
                            },
                        )
                        .is_none(),
                    "duplicate outbound acting identity"
                );
            }
            remote_bindings.push(FederationRemoteBinding {
                local: key,
                local_method_name: call.local_method.clone(),
                target_node: call.target_node,
                target: call.target,
                codec: call.codec,
                timing: call.timing,
            });
            methods.push(Method {
                id: method_id,
                name: call.local_method,
                authority: MethodAuthority::Perform,
                input: SchemaId::new(0),
                output: SchemaId::new(0),
                modality: ModalitySet::all(),
                purity: Purity::Idempotent,
                replay: Purity::Idempotent.replay_class(false),
                supports: OutputModeSet::UNARY,
                cost: CostModel::default(),
                batchable: false,
                finalize_allowed: false,
                requires_unprotected_input: true,
            });
        }
        let selector = ResourceSelector::exact("perform", &path)
            .context("invalid outbound federation selector")?;
        let path_text = path.to_string();
        bundles.push((
            vec![Interface {
                id: interface_id,
                family: InterfaceFamily::Callable,
                methods,
                laws: Vec::new(),
            }],
            DriverDescriptor {
                id: driver_id,
                name: path_text.clone(),
                implements: interfaces.clone(),
                transport: Transport::HostSession,
                driver: Arc::new(EchoDriver),
            },
            Binding {
                id: binding_id,
                selector,
                interfaces: interfaces.clone(),
                driver: DriverRef {
                    id: driver_id,
                    name: path_text,
                },
                endpoint: Some(endpoint_id),
                generation,
            },
            Resource {
                id: resource_id,
                descriptor: ResourceDescriptor {
                    name: ResourceName::new(path),
                    kind: ResourceKind::Effect,
                    addressing: Default::default(),
                    metadata: Metadata::default(),
                },
                interfaces,
                binding: binding_id,
            },
        ));
    }
    let source: Arc<dyn FederationOutboundCallStore> = Arc::new(store.clone());
    let identity: Arc<dyn FederationCallIdentity> =
        Arc::new(DurableOperationIdHash::new(store.kernel_call_namespace()?)?);
    let principal: Arc<dyn FederationCallPrincipal> = Arc::new(StockPrincipal { allowed });
    let blocking = connection.grpc.blocking_spawner();
    let sessions = stock_sessions(
        connection.local,
        connection.policy,
        connection.grpc,
        route_map.into_values(),
        hosted,
    )?;
    let endpoint = FederationRemoteEndpoint::new(
        source,
        identity,
        principal,
        sessions,
        blocking,
        remote_bindings,
    )?;
    registry.register_endpoint(endpoint_id, Arc::new(endpoint));
    for (interfaces, driver, binding, resource) in bundles {
        registry
            .admit_resource_bundle(interfaces, driver, binding, resource, false)
            .context("register outbound federation Resource")?;
    }
    Ok(())
}

fn prepare(
    boot: &Bootstrap,
    declaration: &FederationOutboundCallConfig,
    hosted: &[PreparedHostedSubject],
    routes: &HashMap<FederationNodeId, PeerDialConfig>,
    local: FederationNodeId,
) -> Result<PreparedCall> {
    let local_path =
        Path::parse(&declaration.local_path).context("invalid outbound federation local_path")?;
    ensure!(
        local_path.scheme() == "effect"
            && local_path.cluster().is_none()
            && local_path.is_concrete(),
        "outbound federation local_path must be a concrete local effect:// path"
    );
    ensure!(
        !declaration.local_method.is_empty()
            && declaration.local_method.len() <= 128
            && !declaration.local_method.chars().any(char::is_control),
        "invalid outbound federation local_method"
    );
    ensure!(
        declaration.binding_generation > 0,
        "outbound federation binding_generation must be positive"
    );
    let target_node = FederationNodeId::from_bytes(decode_hex::<48>(
        &declaration.peer_node,
        "outbound federation peer_node",
    )?);
    ensure!(
        target_node != local && routes.contains_key(&target_node),
        "outbound federation peer requires an enabled pinned dial route"
    );
    let target = CallTarget {
        export: ExportName::new(declaration.export.clone())?,
        path: CallPath::new(declaration.path.clone())?,
        method: CallMethod::new(declaration.method.clone())?,
        contract_digest: decode_hex::<32>(
            &declaration.contract_digest,
            "outbound federation contract_digest",
        )?,
    };
    ensure!(
        target.contract_digest != [0; 32],
        "outbound federation contract_digest must be nonzero"
    );
    ensure!(
        !declaration.allowed_acting.is_empty() || !declaration.allowed_hosted.is_empty(),
        "outbound federation method needs an admitted acting identity"
    );
    ensure!(
        declaration.allowed_acting.len() + declaration.allowed_hosted.len() <= 64,
        "outbound federation method needs 1..64 allowed acting identities"
    );
    let mut allowed_acting =
        Vec::with_capacity(declaration.allowed_acting.len() + declaration.allowed_hosted.len());
    let mut distinct = HashSet::new();
    for name in &declaration.allowed_acting {
        let (identity, stable_acting) = resolve_acting(boot, name)?;
        ensure!(
            distinct.insert(identity),
            "duplicate outbound acting identity"
        );
        allowed_acting.push(PreparedActor {
            identity,
            stable_acting,
            subject: FederationSubject::Node(local),
        });
    }
    let mut selected = HashSet::new();
    for credential_name in &declaration.allowed_hosted {
        ensure!(
            selected.insert(credential_name.as_str()),
            "duplicate outbound Hosted credential name"
        );
        let hosted = hosted
            .iter()
            .find(|hosted| hosted.name == *credential_name)
            .context("outbound Hosted credential name is not declared")?;
        ensure!(
            hosted.target == target_node,
            "outbound Hosted credential targets another peer"
        );
        let (identity, stable_acting) = resolve_acting(boot, &hosted.acting)?;
        ensure!(
            distinct.insert(identity),
            "one local acting identity cannot select multiple subjects for one method"
        );
        allowed_acting.push(PreparedActor {
            identity,
            stable_acting,
            subject: FederationSubject::Hosted(hosted.subject.clone()),
        });
    }
    let timing = timing(declaration.timing);
    let codec: Arc<dyn FederationCallCodec> = match declaration.codec {
        FederationOutboundCodecConfig::BytesV1 => Arc::new(RawBytesCallCodec),
        FederationOutboundCodecConfig::ValueJsonV1 => Arc::new(JsonCallCodec),
    };
    Ok(PreparedCall {
        local_path,
        local_method: declaration.local_method.clone(),
        generation: declaration.binding_generation,
        target_node,
        target,
        codec,
        timing,
        allowed_acting,
    })
}

fn resolve_acting(boot: &Bootstrap, name: &str) -> Result<(IdentityRef, Arc<str>)> {
    if name == "root" {
        return Ok((IdentityRef::ROOT, Arc::from("root")));
    }
    let path = Path::parse(name).context("invalid outbound acting identity path")?;
    xolotl_kernel::identity::validate_path(&path)
        .context("outbound acting identity must be a concrete identity:// path")?;
    Ok((
        boot.kernel().identities().resolve_or_register(&path)?,
        Arc::from(path.to_string()),
    ))
}

fn timing(config: FederationOutboundTimingConfig) -> FederationRemoteTiming {
    let defaults = FederationRemoteTiming::default();
    FederationRemoteTiming {
        prepare_ms: config.prepare_ms.unwrap_or(defaults.prepare_ms),
        execution_ms: config.execution_ms.unwrap_or(defaults.execution_ms),
        result_retention_ms: config
            .result_retention_ms
            .unwrap_or(defaults.result_retention_ms),
        poll_ms: config.poll_ms.unwrap_or(defaults.poll_ms),
    }
}

fn decode_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    ensure!(
        value.len() == 2 * N && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{label} must be exactly {} hexadecimal bytes",
        N
    );
    let mut decoded = [0; N];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let text = std::str::from_utf8(pair)?;
        decoded[index] = u8::from_str_radix(text, 16)?;
    }
    Ok(decoded)
}

#[cfg(all(test, unix))]
mod tests;
