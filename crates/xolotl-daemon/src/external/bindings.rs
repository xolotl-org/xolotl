//! Provider projection binding admission and registry publication.

use super::source::SourceCommandHub;
use super::source_endpoint::SourceRoleEndpoint;
use super::*;
use xolotl_kernel::driver::DriverDescriptor;
use xolotl_kernel::{EchoDriver, ResourceUpsert};
use xolotl_types::{
    Binding, CostModel, DriverRef, Interface, InterfaceFamily, InterfaceSet, Metadata, Method,
    ModalitySet, OutputModeSet, Resource, ResourceDescriptor, ResourceKind, SchemaId,
};

#[derive(Clone)]
pub(super) struct SourceBindingPublisher {
    registry: Registry,
    hub: SourceCommandHub,
    published: Arc<std::sync::Mutex<BTreeMap<(String, String), PublishedSourceBinding>>>,
}

#[derive(Clone, Copy)]
struct PublishedSourceBinding {
    resource_id: ResourceId,
    binding_id: xolotl_types::BindingId,
    endpoint_id: xolotl_types::EndpointId,
    generation: u64,
}

impl SourceBindingPublisher {
    pub(super) fn new(registry: Registry, hub: SourceCommandHub) -> Self {
        Self {
            registry,
            hub,
            published: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        }
    }

    /// Publish one stable command effect per projection. A second Ready session
    /// shares the binding; the Hub decides whether dispatch is unambiguous.
    pub(super) fn publish(
        &self,
        context: &SessionContext,
        projection: &ExternalProjectionDef,
    ) -> Result<(), tonic::Status> {
        if context.role != Role::Source
            || projection.role != Role::Source
            || projection.id != context.projection_id
        {
            return Err(tonic::Status::permission_denied(
                "source command binding rejected",
            ));
        }
        if !projection
            .emits
            .as_ref()
            .is_some_and(|emits| emits.commands)
        {
            return self.withdraw(&context.installation_id, &context.projection_id);
        }
        let path = xolotl_types::external::external_source_command_path(
            &context.installation_id,
            &context.projection_id,
        )
        .map_err(|error| {
            tonic::Status::invalid_argument(format!("source command path rejected: {error}"))
        })?;
        let key = (
            context.installation_id.clone(),
            context.projection_id.clone(),
        );
        let mut published = self.published.lock().map_err(|_error| {
            tonic::Status::internal("source command binding publisher unavailable")
        })?;
        let previous = published.get(&key).copied();
        if let Some(record) = previous {
            let current = self.registry.resource(record.resource_id).ok_or_else(|| {
                tonic::Status::failed_precondition("source command resource was removed")
            })?;
            let binding = self.registry.binding(record.binding_id).ok_or_else(|| {
                tonic::Status::failed_precondition("source command binding was removed")
            })?;
            if current.binding != record.binding_id
                || current.descriptor.name.path() != &path
                || binding.endpoint != Some(record.endpoint_id)
                || self.registry.remote_endpoint(record.endpoint_id).is_none()
            {
                return Err(tonic::Status::failed_precondition(
                    "source command resource ownership changed",
                ));
            }
            if record.generation == context.binding_generation {
                return Ok(());
            }
        }
        let selector = ResourceSelector::exact("perform", &path).map_err(|error| {
            tonic::Status::invalid_argument(format!("source command selector rejected: {error}"))
        })?;
        let endpoint_id = self.registry.next_endpoint_id();
        self.registry.register_endpoint(
            endpoint_id,
            Arc::new(SourceRoleEndpoint {
                hub: self.hub.clone(),
                installation_id: context.installation_id.clone(),
                projection_id: context.projection_id.clone(),
                effect_path: path.clone(),
                endpoint_id,
                binding_generation: context.binding_generation,
            }),
        );
        let staged = stage_remote_effect_binding(
            &self.registry,
            RemoteEffectBinding {
                path: &path,
                selector,
                method_name: "dispatch",
                purity: xolotl_types::Purity::Effectful,
                finalize_allowed: false,
                endpoint_id,
                binding_generation: context.binding_generation,
            },
        );
        let upsert = match staged {
            Ok(upsert) => upsert,
            Err(error) => {
                self.registry.unregister_endpoint(endpoint_id);
                return Err(error);
            }
        };
        let binding_id = upsert.binding;
        let result = if let Some(record) = previous {
            self.registry.relink_reclaimable_resource_if(
                &upsert.descriptor.name,
                record.resource_id,
                record.binding_id,
                upsert.interfaces,
                upsert.binding,
                upsert.descriptor.metadata,
            )
        } else {
            self.registry.admit_resource(
                Resource {
                    id: upsert.new_id,
                    descriptor: upsert.descriptor,
                    interfaces: upsert.interfaces,
                    binding: upsert.binding,
                },
                true,
            )
        };
        let resource_id = match result {
            Ok(resource_id) => resource_id,
            Err(error) => {
                self.registry.retire_unreferenced_binding(binding_id);
                self.registry.unregister_endpoint(endpoint_id);
                return Err(tonic::Status::failed_precondition(format!(
                    "source command binding rejected: {error}"
                )));
            }
        };
        published.insert(
            key,
            PublishedSourceBinding {
                resource_id,
                binding_id,
                endpoint_id,
                generation: context.binding_generation,
            },
        );
        if let Some(old) = previous {
            self.registry.unregister_endpoint(old.endpoint_id);
        }
        Ok(())
    }

    fn withdraw(&self, installation_id: &str, projection_id: &str) -> Result<(), tonic::Status> {
        let key = (installation_id.to_owned(), projection_id.to_owned());
        let mut published = self.published.lock().map_err(|_error| {
            tonic::Status::internal("source command binding publisher unavailable")
        })?;
        let Some(record) = published.get(&key).copied() else {
            return Ok(());
        };
        let path =
            xolotl_types::external::external_source_command_path(installation_id, projection_id)
                .map_err(|error| {
                    tonic::Status::invalid_argument(format!(
                        "source command path rejected: {error}"
                    ))
                })?;
        self.registry
            .remove_reclaimable_resource_if(
                &ResourceName::new(path),
                record.resource_id,
                record.binding_id,
            )
            .map_err(|error| {
                tonic::Status::failed_precondition(format!(
                    "source command binding withdrawal rejected: {error}"
                ))
            })?;
        published.remove(&key);
        self.registry.unregister_endpoint(record.endpoint_id);
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct ProviderBindingDeclaration {
    pub(super) path: Path,
    pub(super) purity: xolotl_types::Purity,
    pub(super) finalize_allowed: bool,
    pub(super) selector: ResourceSelector,
}

pub(super) fn validate_provider_projection_bindings(
    projection: &ExternalProjectionDef,
) -> Result<Vec<ProviderBindingDeclaration>, tonic::Status> {
    if projection.role != Role::Provider {
        return Err(tonic::Status::permission_denied(
            "provider projection rejected",
        ));
    }
    if projection.provides.is_empty() {
        return Err(tonic::Status::failed_precondition(
            "provider projection rejected",
        ));
    }

    let mut seen = std::collections::BTreeSet::new();
    let mut bindings = Vec::with_capacity(projection.provides.len());
    for capability in &projection.provides {
        let path = Path::parse(&capability.effect_path).map_err(|error| {
            tonic::Status::invalid_argument(format!("provider binding rejected: {error}"))
        })?;
        if !seen.insert(path.clone()) {
            return Err(tonic::Status::failed_precondition(
                "provider binding rejected",
            ));
        }
        let selector = ResourceSelector::exact("perform", &path).map_err(|error| {
            tonic::Status::failed_precondition(format!("provider binding rejected: {error}"))
        })?;
        bindings.push(ProviderBindingDeclaration {
            path,
            purity: capability.purity,
            finalize_allowed: capability.finalize_allowed,
            selector,
        });
    }
    Ok(bindings)
}

pub(super) fn register_provider_bindings(
    registry: &Registry,
    declarations: &[ProviderBindingDeclaration],
    endpoint_id: xolotl_types::EndpointId,
    context: &SessionContext,
) -> Result<HashMap<ProviderEndpointKey, Path>, tonic::Status> {
    register_provider_bindings_at_generation(
        registry,
        declarations,
        endpoint_id,
        context.binding_generation,
    )
}

pub(super) fn register_provider_bindings_at_generation(
    registry: &Registry,
    declarations: &[ProviderBindingDeclaration],
    endpoint_id: xolotl_types::EndpointId,
    binding_generation: u64,
) -> Result<HashMap<ProviderEndpointKey, Path>, tonic::Status> {
    let mut names = std::collections::HashSet::with_capacity(declarations.len());
    let mut staged: Vec<ResourceUpsert> = Vec::with_capacity(declarations.len());
    for declaration in declarations {
        if !names.insert(&declaration.path) {
            for upsert in staged {
                registry.retire_unreferenced_binding(upsert.binding);
            }
            return Err(tonic::Status::failed_precondition(
                "provider binding rejected",
            ));
        }
        match stage_provider_binding(registry, declaration, endpoint_id, binding_generation) {
            Ok(upsert) => staged.push(upsert),
            Err(error) => {
                for upsert in staged {
                    registry.retire_unreferenced_binding(upsert.binding);
                }
                return Err(error);
            }
        }
    }
    let staged_bindings: Vec<_> = staged.iter().map(|upsert| upsert.binding).collect();
    let resource_ids = registry
        .upsert_reclaimable_resources(staged, true)
        .map_err(|error| {
            for binding_id in staged_bindings {
                registry.retire_unreferenced_binding(binding_id);
            }
            tonic::Status::failed_precondition(format!("provider binding rejected: {error}"))
        })?;
    let mut ready_endpoints = HashMap::with_capacity(resource_ids.len());
    for (declaration, resource_id) in declarations.iter().zip(resource_ids) {
        ready_endpoints.insert(
            ProviderEndpointKey {
                resource_id,
                method_id: MethodId::new(0),
                binding_generation,
            },
            declaration.path.clone(),
        );
    }
    Ok(ready_endpoints)
}

#[cfg(all(test, feature = "external-grpc"))]
pub(super) fn register_provider_binding(
    registry: &Registry,
    declaration: &ProviderBindingDeclaration,
    endpoint_id: xolotl_types::EndpointId,
    binding_generation: u64,
) -> Result<(ProviderEndpointKey, Path), tonic::Status> {
    let registrations = register_provider_bindings_at_generation(
        registry,
        std::slice::from_ref(declaration),
        endpoint_id,
        binding_generation,
    )?;
    registrations
        .into_iter()
        .next()
        .ok_or_else(|| tonic::Status::internal("provider binding was not published"))
}

fn stage_provider_binding(
    registry: &Registry,
    declaration: &ProviderBindingDeclaration,
    endpoint_id: xolotl_types::EndpointId,
    binding_generation: u64,
) -> Result<ResourceUpsert, tonic::Status> {
    stage_remote_effect_binding(
        registry,
        RemoteEffectBinding {
            path: &declaration.path,
            selector: declaration.selector.clone(),
            method_name: "invoke",
            purity: declaration.purity,
            finalize_allowed: declaration.finalize_allowed,
            endpoint_id,
            binding_generation,
        },
    )
}

struct RemoteEffectBinding<'a> {
    path: &'a Path,
    selector: ResourceSelector,
    method_name: &'static str,
    purity: xolotl_types::Purity,
    finalize_allowed: bool,
    endpoint_id: xolotl_types::EndpointId,
    binding_generation: u64,
}

fn stage_remote_effect_binding(
    registry: &Registry,
    binding: RemoteEffectBinding<'_>,
) -> Result<ResourceUpsert, tonic::Status> {
    let RemoteEffectBinding {
        path,
        selector,
        method_name,
        purity,
        finalize_allowed,
        endpoint_id,
        binding_generation,
    } = binding;
    let effect_path = path.to_string();
    let iface_id = registry.next_interface_id();
    let interfaces = InterfaceSet::new(vec![iface_id]);
    let interface = Interface {
        id: iface_id,
        family: InterfaceFamily::Callable,
        methods: vec![Method {
            id: MethodId::new(0),
            name: method_name.into(),
            authority: xolotl_types::MethodAuthority::Perform,
            input: SchemaId::new(0),
            output: SchemaId::new(0),
            modality: ModalitySet::TEXT,
            purity,
            replay: purity.replay_class(false),
            supports: OutputModeSet::UNARY | OutputModeSet::ASYNC_PROCESS,
            cost: CostModel::default(),
            batchable: false,
            finalize_allowed,
            requires_unprotected_input: true,
        }],
        laws: Vec::new(),
    };

    let driver_id = registry.next_driver_id();
    let driver = DriverDescriptor {
        id: driver_id,
        name: effect_path.clone(),
        implements: interfaces.clone(),
        transport: Transport::HostSession,
        driver: Arc::new(EchoDriver),
    };

    let binding_id = registry.next_binding_id();
    registry
        .admit_reclaimable_bundle(
            vec![interface],
            driver,
            Binding {
                id: binding_id,
                selector,
                interfaces: interfaces.clone(),
                driver: DriverRef {
                    id: driver_id,
                    name: effect_path,
                },
                endpoint: Some(endpoint_id),
                generation: binding_generation,
            },
        )
        .map_err(|error| {
            tonic::Status::failed_precondition(format!("remote effect binding rejected: {error}"))
        })?;
    Ok(ResourceUpsert {
        new_id: registry.next_resource_id(),
        descriptor: ResourceDescriptor {
            name: ResourceName::new(path.clone()),
            kind: ResourceKind::Effect,
            addressing: Default::default(),
            metadata: Metadata::default(),
        },
        interfaces,
        binding: binding_id,
    })
}
