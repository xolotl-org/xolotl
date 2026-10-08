use super::*;
use crate::protocol::ACTION_AUTHORITY_RESOURCE_ACCESS;
use xolotl_types::{
    GrantMethods, GrantRights, IdentityRef, MethodAuthority, OutputModeSet, ResourceAddressing,
    ResourceDescriptor, ResourceKind, ResourceSelector, RightFlags,
};

async fn access(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    target: &str,
    verb: &str,
) -> anyhow::Result<Value> {
    let result = execute(
        state,
        principal,
        ActionCall {
            action: ACTION_AUTHORITY_RESOURCE_ACCESS.into(),
            input: map_value([
                ("target", Value::string(target.into())),
                ("verb", Value::string(verb.into())),
            ]),
            ..Default::default()
        },
    )
    .await?;
    result.output.context("authority resource access output")
}

#[tokio::test]
async fn resource_access_explains_every_method_authority_and_spawn_with() -> anyhow::Result<()> {
    let (state, mut principal, _) = fixture()?;
    for authority in MethodAuthority::ALL {
        let verb = authority.verb();
        let target = match authority {
            MethodAuthority::Perform | MethodAuthority::Publish => "effect://calculator/run",
            MethodAuthority::Read
            | MethodAuthority::Write
            | MethodAuthority::Append
            | MethodAuthority::Subscribe => "state://calculator/item",
            MethodAuthority::Spawn => "process://calculator/task",
        };
        let result = access(&state, &principal, target, verb).await?;
        ensure!(
            result.as_map().and_then(|row| row.get("allowed")) == Some(&Value::boolean(true)),
            "{verb} should be explained as allowed"
        );
    }

    let result = access(&state, &principal, "effect://calculator/run", "spawn-with").await?;
    ensure!(result.as_map().and_then(|row| row.get("allowed")) == Some(&Value::boolean(true)));

    principal.grants = CapSet::from_strs(["append://state/kernel/console/users/alice"])?;
    let result = access(
        &state,
        &principal,
        "state://kernel/console/users/alice",
        "append",
    )
    .await?;
    ensure!(
        result.as_map().and_then(|row| row.get("allowed")) == Some(&Value::boolean(false)),
        "append on Console management state still needs management authority"
    );
    Ok(())
}

fn operation(target: &str, method: &str) -> anyhow::Result<Expression> {
    Ok(Expression::Invoke {
        operation: OperationTemplate {
            target: ResourceName::new(Path::parse(target)?),
            method: method.into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: None,
        },
    })
}

fn resource_call(target: &str, method: &str, input: i64) -> anyhow::Result<ActionCall> {
    call(
        Program::new(operation(target, method)?),
        Value::integer(input),
    )
}

async fn resource_value(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    target: &str,
    method: &str,
    input: i64,
) -> anyhow::Result<Value> {
    result_value(execute(state, principal, resource_call(target, method, input)?).await?)
}

fn restricted_anchor(
    boot: &Arc<Bootstrap>,
) -> anyhow::Result<Arc<xolotl_kernel::RequestProcess<'static>>> {
    Ok(Arc::new(boot.request_under_owned(
        boot.root(),
        IdentityRef::ROOT,
        &[xolotl_kernel::CompiledRequestGrantTemplate {
            selector: ResourceSelector::parse("perform://effect/calculator/run@account=alice")?,
            rights: GrantRights::new(GrantMethods::name("identity"), RightFlags::empty()),
        }],
    )?))
}

#[tokio::test]
async fn host_owned_request_anchor_attenuates_and_revokes_console_calls() -> anyhow::Result<()> {
    let (base, principal, calls) = fixture()?;
    let anchor = restricted_anchor(&base.boot)?;
    let state = ConsoleState::with_config(
        base.boot.clone(),
        ConsoleConfig {
            session_store: Some(base.auth.session_store.clone()),
            request_anchor: Some(anchor.clone()),
            runtime: ConsoleRuntimeConfig {
                enabled: true,
                capabilities: vec!["perform://effect/calculator/**".into()],
                ..Default::default()
            },
            ..Default::default()
        },
    )?;
    let anchor_id = anchor.id();
    drop(anchor);
    let identity = Program::new(operation("effect://calculator/run", "identity")?);
    let input = |account: &str| map_value([("account", Value::string(account.into()))]);
    let allowed = input("alice");
    ensure!(
        result_value(execute(&state, &principal, call(identity.clone(), allowed.clone())?).await?)?
            == allowed
    );
    ensure!(
        execute(&state, &principal, call(identity, input("bob"))?)
            .await
            .is_err(),
        "the parent's input predicate must survive Console grant derivation"
    );
    ensure!(matches!(
        execute(
            &state,
            &principal,
            resource_call("effect://calculator/run", "double", 2)?
        )
        .await,
        Err(error) if error.code == ConsoleErrorCode::Forbidden
    ));
    ensure!(calls.load(Ordering::SeqCst) == 1);

    ensure!(base.boot.cancel_process(anchor_id)?);
    ensure!(
        execute(
            &state,
            &principal,
            call(
                Program::new(operation("effect://calculator/run", "identity")?),
                input("alice")
            )?
        )
        .await
        .is_err(),
        "a revoked parent must reject new Console requests"
    );
    ensure!(calls.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[test]
fn request_anchor_must_belong_to_this_kernel_and_be_live() -> anyhow::Result<()> {
    let (base, _, _) = fixture()?;
    let other = Arc::new(Bootstrap::in_memory());
    let local = restricted_anchor(&base.boot)?;
    let foreign = restricted_anchor(&other)?;
    ensure!(
        local.id() == foreign.id(),
        "independent kernels can reuse process ids"
    );
    ensure!(matches!(
        ConsoleState::with_config(
            base.boot.clone(),
            ConsoleConfig {
                session_store: Some(base.auth.session_store.clone()),
                request_anchor: Some(foreign),
                ..Default::default()
            }
        ),
        Err(crate::ConsoleConfigError::RequestAnchor(_))
    ));

    let unavailable = restricted_anchor(&base.boot)?;
    ensure!(base.boot.cancel_process(unavailable.id())?);
    ensure!(matches!(
        ConsoleState::with_config(
            base.boot.clone(),
            ConsoleConfig {
                session_store: Some(base.auth.session_store.clone()),
                request_anchor: Some(unavailable),
                ..Default::default()
            }
        ),
        Err(crate::ConsoleConfigError::RequestAnchor(_))
    ));
    Ok(())
}

#[tokio::test]
async fn custom_resource_scheme_preserves_method_and_requested_path_authority() -> anyhow::Result<()>
{
    let (base, mut principal, calls) = fixture()?;
    let thermostat = "device://lab/thermostat";
    let sensors = "device://lab/sensors";
    for (path, addressing, selector, specs) in [
        (
            thermostat,
            ResourceAddressing::Exact,
            "*://device/lab/thermostat",
            vec![
                MethodSpec::new(
                    "sample",
                    MethodAuthority::Read,
                    Purity::Pure,
                    OutputModeSet::UNARY,
                )
                .observes_external(),
                MethodSpec::new(
                    "set",
                    MethodAuthority::Perform,
                    Purity::Effectful,
                    OutputModeSet::UNARY,
                ),
            ],
        ),
        (
            sensors,
            ResourceAddressing::Prefix,
            "read://device/lab/sensors/**",
            vec![
                MethodSpec::new(
                    "sample",
                    MethodAuthority::Read,
                    Purity::Pure,
                    OutputModeSet::UNARY,
                )
                .observes_external(),
            ],
        ),
    ] {
        let recorded = calls.clone();
        base.boot.register_resource(
            ResourceDescriptor {
                name: ResourceName::new(Path::parse(path)?),
                kind: ResourceKind::Device,
                addressing,
                metadata: Default::default(),
            },
            selector,
            InterfaceFamily::Callable,
            &specs,
            Arc::new(FnDriver(move |_, input| {
                recorded.fetch_add(1, Ordering::SeqCst);
                Ok(input)
            })),
        )?;
    }
    let state = ConsoleState::with_config(
        base.boot.clone(),
        ConsoleConfig {
            session_store: Some(base.auth.session_store.clone()),
            runtime: ConsoleRuntimeConfig {
                enabled: true,
                capabilities: vec![
                    "read://device/lab/thermostat#sample".into(),
                    "perform://device/lab/thermostat#set".into(),
                    "read://device/lab/sensors/**#sample".into(),
                ],
                ..Default::default()
            },
            ..Default::default()
        },
    )?;

    principal.grants = CapSet::from_strs(["read://device/lab/thermostat#sample"])?;
    let description = resource(
        &state,
        &principal,
        map_value([("target", Value::string(thermostat.into()))]),
    )?;
    ensure!(
        description.as_map().and_then(|row| row.get("kind"))
            == Some(&Value::string("device".into()))
    );
    ensure!(
        description.as_map().and_then(|row| row.get("addressing"))
            == Some(&Value::string("exact".into()))
    );
    let interfaces: Vec<Interface> = serde_json::from_value(serde_json::to_value(
        description
            .as_map()
            .and_then(|row| row.get("interfaces"))
            .context("device interfaces")?,
    )?)?;
    let visible_methods: Vec<_> = interfaces
        .iter()
        .flat_map(|interface| &interface.methods)
        .map(|method| method.name.as_str())
        .collect();
    ensure!(visible_methods == ["sample"]);
    ensure!(
        resource_value(&state, &principal, thermostat, "sample", 1).await? == Value::integer(1)
    );
    ensure!(matches!(
        execute(&state, &principal, resource_call(thermostat, "set", 2)?).await,
        Err(error) if error.code == ConsoleErrorCode::Forbidden
    ));
    principal.grants = CapSet::from_strs(["perform://device/lab/thermostat#set"])?;
    ensure!(resource_value(&state, &principal, thermostat, "set", 2).await? == Value::integer(2));

    principal.grants = CapSet::from_strs(["read://device/lab/sensors/room1#sample"])?;
    let prefix_description = resource(
        &state,
        &principal,
        map_value([("target", Value::string("device://lab/sensors/room1".into()))]),
    )?;
    ensure!(
        prefix_description
            .as_map()
            .and_then(|row| row.get("addressing"))
            == Some(&Value::string("prefix".into()))
    );
    ensure!(
        resource_value(
            &state,
            &principal,
            "device://lab/sensors/room1",
            "sample",
            3
        )
        .await?
            == Value::integer(3)
    );
    ensure!(matches!(
        execute(
            &state,
            &principal,
            resource_call("device://lab/sensors/room2", "sample", 4)?
        ).await,
        Err(error) if error.code == ConsoleErrorCode::Forbidden
    ));
    ensure!(calls.load(Ordering::SeqCst) == 3);
    Ok(())
}

#[tokio::test]
async fn named_method_grant_filters_discovery_and_invocation_on_the_same_path() -> anyhow::Result<()>
{
    let (state, mut principal, calls) = fixture()?;
    let target = "state://calculator/dual";
    let recorded = calls.clone();
    state.boot.register_subtree_resource_at(
        target,
        "read://state/calculator/dual",
        InterfaceFamily::Value,
        &[
            MethodSpec::new(
                "read",
                MethodAuthority::Read,
                Purity::Pure,
                OutputModeSet::UNARY,
            ),
            MethodSpec::new(
                "read_secret",
                MethodAuthority::Read,
                Purity::Pure,
                OutputModeSet::UNARY,
            ),
        ],
        Arc::new(FnDriver(move |_, input| {
            recorded.fetch_add(1, Ordering::SeqCst);
            Ok(input)
        })),
    )?;
    principal.grants = CapSet::from_strs(["read://state/calculator/dual#read"])?;
    let description = resource(
        &state,
        &principal,
        map_value([("target", Value::string(target.into()))]),
    )?;
    let interfaces: Vec<Interface> = serde_json::from_value(serde_json::to_value(
        description
            .as_map()
            .and_then(|row| row.get("interfaces"))
            .context("interfaces")?,
    )?)?;
    ensure!(
        interfaces
            .iter()
            .flat_map(|interface| &interface.methods)
            .map(|method| method.name.as_str())
            .collect::<Vec<_>>()
            == ["read"]
    );
    let read = call(Program::new(operation(target, "read")?), Value::integer(4))?;
    ensure!(result_value(execute(&state, &principal, read).await?)? == Value::integer(4));
    let secret = call(
        Program::new(operation(target, "read_secret")?),
        Value::integer(5),
    )?;
    ensure!(execute(&state, &principal, secret.clone()).await.is_err());
    ensure!(calls.load(Ordering::SeqCst) == 1);
    principal.grants = CapSet::from_strs(["read://state/calculator/dual"])?;
    ensure!(result_value(execute(&state, &principal, secret).await?)? == Value::integer(5));
    ensure!(calls.load(Ordering::SeqCst) == 2);
    Ok(())
}

#[test]
fn resource_preflight_intersects_method_names_before_resolving() -> anyhow::Result<()> {
    let (base, mut principal, _) = fixture()?;
    let installed = "effect://calculator/run";
    let missing = "effect://calculator/missing";
    let cases: [(&str, &str, &[&str]); 7] = [
        (
            "perform://effect/calculator/**#double",
            "perform://effect/calculator/**#identity",
            &[],
        ),
        (
            "perform://effect/calculator/**#double",
            "perform://effect/calculator/**#double",
            &["double"],
        ),
        (
            "perform://effect/calculator/**#double",
            "perform://effect/calculator/**",
            &["double"],
        ),
        (
            "perform://effect/calculator/**",
            "perform://effect/calculator/**#identity",
            &["identity"],
        ),
        (
            "perform://effect/calculator/**",
            "perform://effect/calculator/**",
            &["double", "identity"],
        ),
        (
            "perform://effect/calculator/**#double",
            "perform://effect/calculator/**#double@until=0",
            &[],
        ),
        (
            "perform://effect/calculator/**#double",
            "perform://effect/calculator/**#double@tenant=alice",
            &["double"],
        ),
    ];
    for (host, account, expected) in cases {
        let state = ConsoleState::with_config(
            base.boot.clone(),
            ConsoleConfig {
                session_store: Some(base.auth.session_store.clone()),
                runtime: ConsoleRuntimeConfig {
                    enabled: true,
                    capabilities: vec![host.into()],
                    ..Default::default()
                },
                ..Default::default()
            },
        )?;
        principal.grants = CapSet::from_strs([account])?;
        let describe = |target: &str| {
            resource(
                &state,
                &principal,
                map_value([("target", Value::string(target.into()))]),
            )
        };
        if expected.is_empty() {
            for target in [installed, missing] {
                ensure!(
                    matches!(
                        describe(target),
                        Err(ConsoleError::Auth(AuthError::PermissionDenied))
                    ),
                    "unauthorized resource existence leaked for {host} and {account}"
                );
            }
            continue;
        }
        let description = describe(installed)?;
        let interfaces: Vec<Interface> = serde_json::from_value(serde_json::to_value(
            description
                .as_map()
                .and_then(|row| row.get("interfaces"))
                .context("interfaces")?,
        )?)?;
        let visible: Vec<_> = interfaces
            .iter()
            .flat_map(|interface| &interface.methods)
            .map(|method| method.name.as_str())
            .collect();
        ensure!(
            visible == expected,
            "incorrect methods for {host} and {account}"
        );
    }
    Ok(())
}

#[test]
fn resource_preflight_handles_many_disjoint_method_selectors() -> anyhow::Result<()> {
    let (base, _, _) = fixture()?;
    let host: Vec<_> = (0..512)
        .map(|index| format!("perform://effect/calculator/**#host_{index}"))
        .collect();
    let mut account: Vec<_> = (0..512)
        .map(|index| format!("perform://effect/calculator/**#account_{index}"))
        .collect();
    let state = ConsoleState::with_config(
        base.boot.clone(),
        ConsoleConfig {
            session_store: Some(base.auth.session_store.clone()),
            runtime: ConsoleRuntimeConfig {
                enabled: true,
                capabilities: host,
                ..Default::default()
            },
            ..Default::default()
        },
    )?;
    let target = Path::parse("effect://calculator/run")?;
    let grants = CapSet::from_strs(account.iter().map(String::as_str))?;
    ensure!(!target_allowed(&state, &grants, &target));
    account.push("perform://effect/calculator/**#host_511".into());
    let grants = CapSet::from_strs(account.iter().map(String::as_str))?;
    ensure!(target_allowed(&state, &grants, &target));
    Ok(())
}

#[tokio::test]
async fn source_command_effect_uses_host_exposure_and_account_method_grant() -> anyhow::Result<()> {
    let (unexposed, mut principal, calls) = fixture()?;
    let target = "effect://external-source/acme/events/command";
    let recorded = calls.clone();
    unexposed.boot.register_subtree_resource_at(
        target,
        "perform://effect/external-source/acme/events/command",
        InterfaceFamily::Callable,
        &[MethodSpec::new(
            "dispatch",
            MethodAuthority::Perform,
            Purity::Effectful,
            OutputModeSet::UNARY,
        )],
        Arc::new(FnDriver(move |_, input| {
            recorded.fetch_add(1, Ordering::SeqCst);
            Ok(input)
        })),
    )?;
    let program = Program::new(operation(target, "dispatch")?);
    let input = Value::string("command".into());
    let invoke = || call(program.clone(), input.clone());
    let denied = execute(&unexposed, &principal, invoke()?).await;
    ensure!(matches!(denied, Err(error) if error.code == ConsoleErrorCode::Forbidden));

    let exposed = ConsoleState::with_config(
        unexposed.boot.clone(),
        ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            runtime: ConsoleRuntimeConfig {
                enabled: true,
                capabilities: vec![
                    "perform://effect/external-source/acme/events/command#dispatch".into(),
                ],
                ..Default::default()
            },
            ..Default::default()
        },
    )?;
    principal.grants =
        CapSet::from_strs(["perform://effect/external-source/acme/events/command#invoke"])?;
    let denied = execute(&exposed, &principal, invoke()?).await;
    ensure!(matches!(denied, Err(error) if error.code == ConsoleErrorCode::Forbidden));
    principal.grants =
        CapSet::from_strs(["perform://effect/external-source/acme/events/command#dispatch"])?;
    ensure!(result_value(execute(&exposed, &principal, invoke()?).await?)? == input);
    ensure!(calls.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[tokio::test]
async fn discovery_and_execution_use_host_authority_instead_of_method_names() -> anyhow::Result<()>
{
    let (state, mut principal, calls) = fixture()?;
    let effect = "effect://calculator/custom";
    let data = "state://calculator/custom";
    for (target, selector, specs) in [
        (
            effect,
            "perform://effect/calculator/custom",
            vec![MethodSpec::new(
                "read",
                MethodAuthority::Perform,
                Purity::Pure,
                OutputModeSet::UNARY,
            )],
        ),
        (
            data,
            "*://state/calculator/custom",
            vec![
                MethodSpec::new(
                    "load",
                    MethodAuthority::Read,
                    Purity::Pure,
                    OutputModeSet::UNARY,
                ),
                // Even a misleading name cannot change the host's authorization contract.
                MethodSpec::new(
                    "read",
                    MethodAuthority::Write,
                    Purity::Effectful,
                    OutputModeSet::UNARY,
                ),
                MethodSpec::new(
                    "push",
                    MethodAuthority::Append,
                    Purity::Effectful,
                    OutputModeSet::UNARY,
                ),
            ],
        ),
    ] {
        let recorded = calls.clone();
        state.boot.register_subtree_resource_at(
            target,
            selector,
            InterfaceFamily::Callable,
            &specs,
            Arc::new(FnDriver(move |_, input| {
                recorded.fetch_add(1, Ordering::SeqCst);
                Ok(input)
            })),
        )?;
    }
    principal.grants = CapSet::from_strs([
        "perform://effect/calculator/custom",
        "read://state/calculator/custom",
    ])?;
    let description = resource(
        &state,
        &principal,
        map_value([("target", Value::string(data.into()))]),
    )?;
    let interfaces = description
        .as_map()
        .and_then(|map| map.get("interfaces"))
        .context("interfaces")?;
    let interfaces: Vec<Interface> = serde_json::from_value(serde_json::to_value(interfaces)?)?;
    let methods = &interfaces.first().context("interface")?.methods;
    ensure!(
        methods.len() == 1
            && methods[0].name == "load"
            && methods[0].authority == MethodAuthority::Read
    );

    let denied = Program::new(operation(effect, "read")?.then(operation(data, "read")?));
    let error = execute(&state, &principal, call(denied.clone(), Value::integer(7))?)
        .await
        .err()
        .context("write denied")?;
    ensure!(error.code == ConsoleErrorCode::Forbidden && calls.load(Ordering::SeqCst) == 0);
    let allowed = Program::new(operation(effect, "read")?.then(operation(data, "load")?));
    ensure!(
        result_value(execute(&state, &principal, call(allowed, Value::integer(7))?).await?)?
            == Value::integer(7)
    );
    ensure!(calls.load(Ordering::SeqCst) == 2);
    principal.grants = CapSet::from_strs([
        "perform://effect/calculator/custom",
        "write://state/calculator/custom",
    ])?;
    ensure!(
        result_value(execute(&state, &principal, call(denied, Value::integer(9))?).await?)?
            == Value::integer(9)
    );
    ensure!(calls.load(Ordering::SeqCst) == 4);
    principal.grants = CapSet::from_strs(["append://state/calculator/custom"])?;
    let described = resource(
        &state,
        &principal,
        map_value([("target", Value::string(data.into()))]),
    )?;
    ensure!(serde_json::to_string(&described)?.contains("push"));
    ensure!(
        result_value(
            execute(
                &state,
                &principal,
                call(Program::new(operation(data, "push")?), Value::integer(11),)?
            )
            .await?
        )? == Value::integer(11)
    );
    ensure!(calls.load(Ordering::SeqCst) == 5);
    Ok(())
}

#[tokio::test]
async fn standard_compare_set_is_discoverable_and_requires_write_authority() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    xolotl_standard::install_standard(&boot, &xolotl_standard::StandardConfig::default())?;
    let state = ConsoleState::with_config(
        boot,
        ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            runtime: ConsoleRuntimeConfig {
                enabled: true,
                capabilities: vec!["*://state/application/**".into()],
                ..Default::default()
            },
            ..Default::default()
        },
    )?;
    let mut principal = ConsolePrincipal {
        authority_id: "local".into(),
        username: "writer".into(),
        account_id: "writer-account".into(),
        identity_path: "identity://console/accounts/writer-account".into(),
        grants: CapSet::from_strs(["write://state/application/**"])?,
        authority_ceiling: None,
        authentication: crate::AuthenticationEvidence {
            primary: crate::PrimaryAuthentication::Password { verified_at: 0 },
            secondary: Some(crate::SecondaryAuthentication::RecoveryCode { verified_at: 0 }),
        },
    };
    let path = Path::parse("state://application/record")?;
    let program = Program::new(operation(&path.to_string(), "compare_set")?);
    let input = map_value([("value", Value::integer(1))]);
    let described = resource(
        &state,
        &principal,
        map_value([("target", Value::string(path.to_string()))]),
    )?;
    ensure!(serde_json::to_string(&described)?.contains("compare_set"));
    ensure!(
        result_value(execute(&state, &principal, call(program.clone(), input.clone())?).await?)?
            == Value::boolean(true)
    );
    ensure!(state.state.read(&path).await? == Some(Value::integer(1)));
    principal.grants = CapSet::from_strs(["read://state/application/**"])?;
    let error = execute(&state, &principal, call(program, input)?)
        .await
        .err()
        .context("write denied")?;
    ensure!(error.code == ConsoleErrorCode::Forbidden);
    ensure!(state.state.read(&path).await? == Some(Value::integer(1)));
    Ok(())
}
