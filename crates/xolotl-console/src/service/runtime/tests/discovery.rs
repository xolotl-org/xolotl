use super::*;
use std::collections::BTreeSet;
use xolotl_kernel::{DriverDescriptor, FnDriver};
use xolotl_types::{
    Binding, DriverRef, Interface, InterfaceLaw, InterfaceSet, ResourceSelector, Transport,
};

#[tokio::test]
async fn resource_discovery_hides_opaque_laws_for_partial_interfaces() -> anyhow::Result<()> {
    let (state, mut principal, _) = fixture()?;
    let registry = state.boot.kernel().registry();
    let target = Path::parse("state://calculator/item")?;
    let resource_id = registry.resolve_resource(&ResourceName::new(target.clone()))?;
    let registered_resource = registry.resource(resource_id).context("resource")?;
    let original_interface = *registered_resource
        .interfaces
        .interfaces
        .first()
        .context("interface id")?;
    let mut interface = registry
        .interface(original_interface)
        .context("interface")?;
    interface.id = registry.next_interface_id();
    interface.laws = vec![
        InterfaceLaw::Idempotent {
            method: "read".into(),
        },
        InterfaceLaw::ReadYourWrites {
            write: "write".into(),
            read: "read".into(),
        },
        InterfaceLaw::Custom {
            name: "private_write_rule".into(),
        },
    ];
    registry.register_interface(interface.clone())?;
    let interfaces = InterfaceSet::new(vec![interface.id]);
    let driver_id = registry.next_driver_id();
    registry.register_driver(DriverDescriptor {
        id: driver_id,
        name: "law discovery test".into(),
        implements: interfaces.clone(),
        transport: Transport::InProcess,
        driver: Arc::new(FnDriver(|_: xolotl_types::MethodId, input: Value| {
            Ok(input)
        })),
    })?;
    let binding_id = registry.next_binding_id();
    registry.admit_binding(Binding {
        id: binding_id,
        selector: ResourceSelector::parse("*://state/calculator/**")?,
        interfaces: interfaces.clone(),
        driver: DriverRef {
            id: driver_id,
            name: "law discovery test".into(),
        },
        endpoint: None,
        generation: 2,
    })?;
    registry.relink_resource(&registered_resource.descriptor.name, interfaces, binding_id)?;

    let discover = |principal: &ConsolePrincipal| {
        resource(
            &state,
            principal,
            map_value([("target", Value::string(target.to_string()))]),
        )
    };
    let projected = |value: Value| -> anyhow::Result<Interface> {
        let interfaces = value
            .as_map()
            .and_then(|map| map.get("interfaces"))
            .context("visible interfaces")?;
        let interfaces: Vec<Interface> = serde_json::from_value(serde_json::to_value(interfaces)?)?;
        interfaces.into_iter().next().context("visible interface")
    };
    principal.grants = CapSet::from_strs(["read://state/calculator/**"])?;
    let limited = projected(discover(&principal)?)?;
    ensure!(limited.methods.len() == 1 && limited.methods[0].name == "read");
    ensure!(
        limited.laws
            == vec![InterfaceLaw::Idempotent {
                method: "read".into()
            }]
    );

    principal.grants =
        CapSet::from_strs(["read://state/calculator/**", "write://state/calculator/**"])?;
    let full = projected(discover(&principal)?)?;
    ensure!(full.methods.len() == 2 && full.laws == interface.laws);
    Ok(())
}

pub(in crate::service::runtime) fn mode<'a>(
    description: &'a Value,
    mode: &str,
    lifetime: &str,
) -> anyhow::Result<&'a xolotl_types::ValueMap> {
    description
        .as_map()
        .and_then(|map| map.get("execution_modes"))
        .and_then(Value::as_list)
        .context("execution modes")?
        .iter()
        .filter_map(Value::as_map)
        .find(|row| {
            row.get("mode").and_then(Value::as_str) == Some(mode)
                && row.get("lifetime").and_then(Value::as_str) == Some(lifetime)
        })
        .context("mode and lifetime contract")
}

#[tokio::test]
async fn discovery_describes_each_lifecycle_and_matches_its_public_schema() -> anyhow::Result<()> {
    let (base, principal, calls) = fixture()?;
    let descriptor = protocol::action_descriptors()
        .iter()
        .find(|action| action.id == protocol::ACTION_RUNTIME_DESCRIBE)
        .context("runtime descriptor")?;
    let row_schema = descriptor
        .output
        .definitions
        .iter()
        .find(|schema| schema.schema_id == "execution_mode")
        .context("execution mode definition")?;
    let fields = |schema: &protocol::SchemaDescriptor| -> BTreeSet<String> {
        schema
            .fields
            .iter()
            .map(|field| field.name.clone())
            .collect()
    };
    ensure!(
        descriptor
            .output
            .fields
            .iter()
            .any(|field| field.name == "execution_modes" && field.kind == "list<execution_mode>")
    );
    for enabled in [false, true] {
        for submissions in [false, true] {
            let state = ConsoleState::with_config(
                base.boot.clone(),
                ConsoleConfig {
                    session_store: Some(base.auth.session_store.clone()),
                    runtime: ConsoleRuntimeConfig {
                        enabled,
                        executions: crate::ConsoleExecutionConfig {
                            enabled: submissions,
                            ..Default::default()
                        },
                        ..base.runtime.config.clone()
                    },
                    ..Default::default()
                },
            )?;
            let description = execute(
                &state,
                &principal,
                ActionCall {
                    action: protocol::ACTION_RUNTIME_DESCRIBE.into(),
                    ..Default::default()
                },
            )
            .await?
            .output
            .context("description")?;
            let map = description.as_map().context("description map")?;
            ensure!(
                map.keys()
                    .map(|key| key.to_string())
                    .collect::<BTreeSet<_>>()
                    == fields(&descriptor.output)
            );
            let rows = map
                .get("execution_modes")
                .and_then(Value::as_list)
                .context("execution modes")?;
            ensure!(rows.len() == 3);
            for (name, lifetime, active, owner, entries, outputs) in [
                (
                    "call",
                    "host",
                    enabled,
                    "request",
                    [
                        protocol::ACTION_RUNTIME_OPERATION_INVOKE,
                        protocol::ACTION_RUNTIME_PROGRAM_RUN,
                    ],
                    vec!["unary", "collect", "sink_only"],
                ),
                (
                    "subscription",
                    "host",
                    enabled,
                    "subscription",
                    [
                        protocol::STREAM_RUNTIME_OPERATION,
                        protocol::STREAM_RUNTIME_PROGRAM,
                    ],
                    vec!["unary", "collect", "sink_only", "stream"],
                ),
                (
                    "submission",
                    "host",
                    enabled && submissions,
                    "service",
                    [
                        protocol::ACTION_RUNTIME_OPERATION_SUBMIT,
                        protocol::ACTION_RUNTIME_PROGRAM_SUBMIT,
                    ],
                    vec!["unary", "collect", "sink_only", "stream", "async_process"],
                ),
            ] {
                let row = mode(&description, name, lifetime)?;
                ensure!(
                    row.keys()
                        .map(|key| key.to_string())
                        .collect::<BTreeSet<_>>()
                        == fields(row_schema)
                );
                ensure!(row.get("owner").and_then(Value::as_str) == Some(owner));
                for field in ["enabled", "accepting"] {
                    ensure!(row.get(field).and_then(Value::as_bool) == Some(active));
                }
                for (field, expected) in [("entries", entries.to_vec()), ("output_modes", outputs)]
                {
                    let actual: Vec<_> = row
                        .get(field)
                        .and_then(Value::as_list)
                        .context("contract list")?
                        .iter()
                        .filter_map(Value::as_str)
                        .collect();
                    ensure!(
                        actual == expected,
                        "{name}/{lifetime}/{field}: actual={actual:?}, expected={expected:?}"
                    );
                }
            }
        }
    }
    ensure!(calls.load(Ordering::SeqCst) == 0);
    Ok(())
}
