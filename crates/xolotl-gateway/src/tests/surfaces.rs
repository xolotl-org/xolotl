use super::{
    TEST_TOKEN, expect_accepted_stream, identity_profile, input_stream_submission, schema_type,
};
use crate::*;
use anyhow::{Context as _, bail, ensure};
use std::num::NonZeroUsize;
use std::sync::Arc;
use xolotl_kernel::{
    Driver, DriverContext, DriverDescriptor, DriverError, DriverOutput, MethodSpec,
};
use xolotl_types::{
    Binding, CostModel, DriverRef, Interface, InterfaceFamily, InterfaceSet, Metadata, Method,
    MethodAuthority, MethodId, ModalitySet, Purity, Resource, ResourceDescriptor, ResourceKind,
    ResourceName, ResourceSelector, SchemaId, Transport,
};

struct StreamingEcho;

#[async_trait::async_trait]
impl Driver for StreamingEcho {
    async fn call(
        &self,
        _method: MethodId,
        input: Value,
        output: OutputMode,
        context: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        if output == OutputMode::Stream {
            context.emit(input.clone()).await?;
        }
        Ok(DriverOutput::new(Outcome::Done(input)))
    }
}

struct Fixture {
    gateway: GatewayRuntime,
    session: GatewaySession,
}

impl Fixture {
    async fn new(inputs: [Option<Value>; 2], limits: GatewayLimitProfile) -> anyhow::Result<Self> {
        let boot = Arc::new(Bootstrap::in_memory());
        let target = boot.register_effect(
            "effect://test/aliases",
            &[MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Pure,
                MethodSpec::STREAM_ASYNC | MethodSpec::SINK_ASYNC,
            )],
            Arc::new(StreamingEcho),
        )?;
        let [number_input, text_input] = inputs;
        let profile = identity_profile()?
            .with_limits(limits)
            .with_surface(
                GatewaySurface::effect_invoke("number", target.clone())
                    .with_schema(number_input, Some(schema_type("integer")))
                    .with_output_stream_schema(schema_type("integer")),
            )
            .with_surface(
                GatewaySurface::effect_invoke("text", target)
                    .with_schema(text_input, Some(schema_type("string")))
                    .with_output_stream_schema(schema_type("string")),
            )
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["number", "text"],
                ["perform://effect/test/aliases"],
            ));
        let gateway = GatewayRuntime::new(
            boot,
            profile,
            Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
        )?;
        let session = gateway
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await?;
        Ok(Self { gateway, session })
    }

    async fn submit(&self, surface: &str, input: Value) -> anyhow::Result<GatewaySubmitResult> {
        Ok(self
            .gateway
            .submit(
                &self.session,
                GatewaySubmission::direct_input(surface, input),
            )
            .await?)
    }

    async fn open_input(&self, surface: &str) -> anyhow::Result<Box<GatewayAcceptedInputStream>> {
        expect_accepted_stream(
            self.gateway
                .accept_input_stream_submission(&self.session, input_stream_submission(surface))
                .await?,
        )
    }

    async fn open_output(
        &self,
        surface: &str,
        input: Value,
    ) -> anyhow::Result<GatewayOutputStream> {
        Ok(self
            .gateway
            .submit_output_stream(
                &self.session,
                GatewaySubmission::direct_input(surface, input)
                    .with_requested_output(OutputMode::Stream),
                StreamWindow {
                    max_chunks: NonZeroUsize::MIN,
                    max_inline_bytes: NonZeroUsize::MIN.saturating_add(4095),
                },
            )
            .await?)
    }
}

fn register_multimethod_effect(
    boot: &Bootstrap,
    invoke_authority: MethodAuthority,
) -> anyhow::Result<ResourceName> {
    let registry = boot.kernel().registry();
    let name = ResourceName::new(Path::parse("effect://test/multimethod")?);
    let interface_id = registry.next_interface_id();
    let interfaces = InterfaceSet::new(vec![interface_id]);
    let methods = [
        ("invoke", invoke_authority),
        ("admin", MethodAuthority::Perform),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (name, authority))| Method {
        id: MethodId::new(index as u64),
        name: name.into(),
        authority,
        input: SchemaId::new(0),
        output: SchemaId::new(0),
        modality: ModalitySet::TEXT,
        purity: Purity::Pure,
        replay: Purity::Pure.replay_class(false),
        supports: MethodSpec::UNARY_ASYNC,
        cost: CostModel::default(),
        batchable: false,
        finalize_allowed: false,
        requires_unprotected_input: false,
    })
    .collect();
    let interface = Interface {
        id: interface_id,
        family: InterfaceFamily::Callable,
        methods,
        laws: Vec::new(),
    };
    let driver_id = registry.next_driver_id();
    let driver = DriverDescriptor {
        id: driver_id,
        name: "multimethod".into(),
        implements: interfaces.clone(),
        transport: Transport::InProcess,
        driver: Arc::new(StreamingEcho),
    };
    let binding_id = registry.next_binding_id();
    let binding = Binding {
        id: binding_id,
        selector: ResourceSelector::parse("perform://effect/test/multimethod")?,
        interfaces: interfaces.clone(),
        driver: DriverRef {
            id: driver_id,
            name: "multimethod".into(),
        },
        endpoint: None,
        generation: 1,
    };
    let resource = Resource {
        id: registry.next_resource_id(),
        descriptor: ResourceDescriptor {
            name: name.clone(),
            kind: ResourceKind::Effect,
            addressing: Default::default(),
            metadata: Metadata::default(),
        },
        interfaces,
        binding: binding_id,
    };
    registry.admit_resource_bundle(vec![interface], driver, binding, resource, false)?;
    Ok(name)
}

#[tokio::test]
async fn gateway_opens_only_the_granted_invoke_method() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let target = register_multimethod_effect(&boot, MethodAuthority::Perform)?;
    let profile = identity_profile()?
        .with_surface(GatewaySurface::effect_invoke("multi", target))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["multi"],
            ["perform://effect/test/multimethod"],
        ));
    let gateway = GatewayRuntime::new(
        boot,
        profile,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?;
    let session = gateway
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let result = gateway
        .submit(
            &session,
            GatewaySubmission::direct_input("multi", Value::integer(7)),
        )
        .await?;
    ensure!(result.output.outcome == Outcome::Done(Value::integer(7)));
    Ok(())
}

#[test]
fn gateway_rejects_invoke_with_the_wrong_authority() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let target = register_multimethod_effect(&boot, MethodAuthority::Publish)?;
    let profile = identity_profile()?.with_surface(GatewaySurface::effect_invoke("multi", target));
    ensure!(matches!(
        GatewayRuntime::new(boot, profile, Arc::new(crate::MemoryGatewayIdempotencyStore::default())),
        Err(GatewayError::InvalidProfile(message)) if message.contains("expected perform")
    ));
    Ok(())
}

#[tokio::test]
async fn direct_submissions_use_selected_alias_input_and_output_schemas() -> anyhow::Result<()> {
    let fixture = Fixture::new(
        [Some(schema_type("integer")), Some(schema_type("string"))],
        GatewayLimitProfile::default(),
    )
    .await?;
    let result = fixture.submit("text", Value::from("hello")).await?;
    ensure!(result.accepted.surface_id == "text");
    ensure!(result.output.outcome == Outcome::Done(Value::from("hello")));
    ensure!(matches!(
        fixture
            .gateway
            .submit(
                &fixture.session,
                GatewaySubmission::direct_input("text", Value::integer(1)),
            )
            .await,
        Err(GatewayError::Rejected(_))
    ));

    let fixture = Fixture::new([None, None], GatewayLimitProfile::default()).await?;
    let result = fixture.submit("text", Value::integer(1)).await?;
    ensure!(matches!(
        result.output.outcome,
        Outcome::Fail(Failure::Custom { kind, message })
            if kind == "gateway_output_schema" && message.contains("surface text")
    ));
    let result = fixture
        .gateway
        .submit(
            &fixture.session,
            GatewaySubmission::direct_input("text", Value::integer(1))
                .with_requested_output(OutputMode::SinkOnly),
        )
        .await?;
    ensure!(result.output.outcome == Outcome::Done(Value::null()));
    Ok(())
}

#[tokio::test]
async fn input_stream_completion_uses_the_accepted_alias() -> anyhow::Result<()> {
    let fixture = Fixture::new(
        [Some(schema_type("integer")), Some(schema_type("string"))],
        GatewayLimitProfile::default(),
    )
    .await?;
    let stream = fixture.open_input("text").await?;
    let accepted = stream.accepted().clone();
    ensure!(accepted.surface_id == "text");
    ensure!(
        fixture.gateway.requests.inner.lock().entries[&accepted.submission_id]
            .accepted
            .surface_id
            == "text"
    );
    let result = fixture
        .gateway
        .complete_input_stream_submission(*stream, Value::from("folded text"), None)
        .await?;
    ensure!(result.accepted == accepted);
    ensure!(result.output.outcome == Outcome::Done(Value::from("folded text")));
    Ok(())
}

#[tokio::test]
async fn output_stream_uses_selected_alias_for_chunks_and_final_value() -> anyhow::Result<()> {
    let fixture = Fixture::new([None, None], GatewayLimitProfile::default()).await?;
    for (surface, value) in [
        ("number", Value::integer(1)),
        ("text", Value::from("delta")),
    ] {
        let mut stream = fixture.open_output(surface, value.clone()).await?;
        ensure!(stream.accepted().surface_id == surface);
        let mut chunks = 0;
        let completion = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                match stream.next().await.context("missing stream completion")?? {
                    GatewayOutputEvent::Chunk(chunk) => {
                        ensure!(chunk.value == value);
                        chunks += 1;
                    }
                    GatewayOutputEvent::Complete(completion) => {
                        break Ok::<_, anyhow::Error>(completion);
                    }
                }
            }
        })
        .await??;
        ensure!(chunks == 1);
        ensure!(completion.output.outcome == Outcome::Done(value));
        ensure!(stream.next().await.is_none());
    }
    let mut invalid = fixture.open_output("text", Value::integer(1)).await?;
    let Some(Ok(GatewayOutputEvent::Complete(completion))) = invalid.next().await else {
        bail!("selected alias accepted an invalid output chunk");
    };
    ensure!(matches!(
        completion.output.outcome,
        Outcome::Fail(Failure::Custom { kind, .. }) if kind == "gateway_output_stream_schema"
    ));
    Ok(())
}

#[tokio::test]
async fn alias_limits_are_independent_across_submission_modes() -> anyhow::Result<()> {
    let fixture = Fixture::new(
        [None, None],
        GatewayLimitProfile {
            max_in_flight_requests: 4,
            max_surface_in_flight_requests: 1,
            ..GatewayLimitProfile::default()
        },
    )
    .await?;
    for (input_alias, output_alias, output_value) in [
        ("text", "number", Value::integer(1)),
        ("number", "text", Value::from("independent")),
    ] {
        let input = fixture.open_input(input_alias).await?;
        let direct = fixture.submit(output_alias, output_value.clone()).await?;
        ensure!(direct.output.outcome == Outcome::Done(output_value.clone()));
        let output = fixture
            .open_output(output_alias, output_value.clone())
            .await?;
        {
            let requests = fixture.gateway.requests.inner.lock();
            ensure!(requests.global_running == 2);
            ensure!(requests.surface_running.len() == 2);
            ensure!(requests.surface_running[input_alias] == 1);
            ensure!(requests.surface_running[output_alias] == 1);
            ensure!(
                requests.entries[&input.accepted().submission_id]
                    .accepted
                    .surface_id
                    == input_alias
            );
            ensure!(
                requests.entries[&output.accepted().submission_id]
                    .accepted
                    .surface_id
                    == output_alias
            );
        }
        for (surface, value) in [("number", Value::integer(1)), ("text", Value::from("busy"))] {
            ensure!(matches!(
                fixture
                    .gateway
                    .submit(&fixture.session, GatewaySubmission::direct_input(surface, value))
                    .await,
                Err(GatewayError::LimitExceeded(message))
                    if message == "surface in-flight request limit"
            ));
        }
        drop(output);
        ensure!(
            fixture
                .submit(output_alias, output_value.clone())
                .await?
                .output
                .outcome
                == Outcome::Done(output_value)
        );
        fixture
            .gateway
            .fail_input_stream_submission(*input, "test complete")
            .await?;
        let requests = fixture.gateway.requests.inner.lock();
        ensure!(requests.global_running == 0);
        ensure!(requests.surface_running.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn preparation_owns_capacity_without_acceptance_and_drop_releases_it() -> anyhow::Result<()> {
    let fixture = Fixture::new(
        [None, None],
        GatewayLimitProfile {
            max_in_flight_requests: 1,
            ..GatewayLimitProfile::default()
        },
    )
    .await?;
    let preparation = fixture.gateway.prepare_submission(
        &fixture.session,
        GatewaySubmissionHead::direct_input("number"),
        None,
    )?;
    {
        let requests = fixture.gateway.requests.inner.lock();
        ensure!(requests.global_running == 1);
        ensure!(requests.entries.is_empty());
        ensure!(requests.budget_running == GatewayBudgetCharge::default());
    }
    ensure!(matches!(
        fixture
            .gateway
            .submit(
                &fixture.session,
                GatewaySubmission::direct_input("text", Value::from("blocked"))
            )
            .await,
        Err(GatewayError::LimitExceeded(_))
    ));
    drop(preparation);
    ensure!(fixture.gateway.requests.inner.lock().global_running == 0);
    let preparation = fixture.gateway.prepare_submission(
        &fixture.session,
        GatewaySubmissionHead::direct_input("number"),
        None,
    )?;
    let result = fixture
        .gateway
        .submit_prepared(preparation, Value::integer(7), None)
        .await?;
    ensure!(result.output.outcome == Outcome::Done(Value::integer(7)));
    ensure!(fixture.gateway.requests.inner.lock().global_running == 0);
    Ok(())
}

#[tokio::test]
async fn preparation_transfers_into_output_without_reacquiring_capacity() -> anyhow::Result<()> {
    let fixture = Fixture::new(
        [None, None],
        GatewayLimitProfile {
            max_in_flight_requests: 1,
            ..GatewayLimitProfile::default()
        },
    )
    .await?;
    let mut head = GatewaySubmissionHead::direct_input("number");
    head.requested_output = OutputMode::Stream;
    let preparation = fixture.gateway.prepare_submission(
        &fixture.session,
        head,
        Some(StreamWindow {
            max_chunks: NonZeroUsize::MIN,
            max_inline_bytes: NonZeroUsize::MIN.saturating_add(4095),
        }),
    )?;
    let output = fixture
        .gateway
        .submit_output_stream_prepared(preparation, Value::integer(7), None)
        .await?;
    {
        let requests = fixture.gateway.requests.inner.lock();
        ensure!(requests.global_running == 1);
        ensure!(requests.entries.len() == 1);
        ensure!(requests.budget_running.inflight_ops == 1);
    }
    drop(output);
    ensure!(fixture.gateway.requests.inner.lock().global_running == 0);
    Ok(())
}

#[tokio::test]
async fn foreign_preparation_releases_only_its_origin_capacity() -> anyhow::Result<()> {
    let origin = Fixture::new([None, None], GatewayLimitProfile::default()).await?;
    let other = Fixture::new([None, None], GatewayLimitProfile::default()).await?;
    let origin_owner = origin.gateway.prepare_submission(
        &origin.session,
        GatewaySubmissionHead::direct_input("number"),
        None,
    )?;
    let other_owner = other.gateway.prepare_submission(
        &other.session,
        GatewaySubmissionHead::direct_input("number"),
        None,
    )?;
    ensure!(
        matches!(other.gateway.submit_prepared(origin_owner, Value::integer(7), None).await,
        Err(GatewayError::Rejected(message)) if message.contains("another gateway runtime"))
    );
    ensure!(origin.gateway.requests.inner.lock().global_running == 0);
    ensure!(other.gateway.requests.inner.lock().global_running == 1);
    ensure!(other.gateway.requests.inner.lock().entries.is_empty());
    drop(other_owner);
    ensure!(other.gateway.requests.inner.lock().global_running == 0);
    Ok(())
}

#[tokio::test]
async fn wrong_preparation_output_port_releases_capacity() -> anyhow::Result<()> {
    let fixture = Fixture::new([None, None], GatewayLimitProfile::default()).await?;
    let preparation = fixture.gateway.prepare_submission(
        &fixture.session,
        GatewaySubmissionHead::direct_input("number"),
        None,
    )?;
    ensure!(
        fixture
            .gateway
            .submit_output_stream_prepared(preparation, Value::integer(7), None)
            .await
            .is_err()
    );
    ensure!(fixture.gateway.requests.inner.lock().global_running == 0);
    let mut head = GatewaySubmissionHead::direct_input("number");
    head.requested_output = OutputMode::Stream;
    let preparation = fixture.gateway.prepare_submission(
        &fixture.session,
        head,
        Some(StreamWindow {
            max_chunks: NonZeroUsize::MIN,
            max_inline_bytes: NonZeroUsize::MIN.saturating_add(4095),
        }),
    )?;
    ensure!(
        fixture
            .gateway
            .submit_prepared(preparation, Value::integer(7), None)
            .await
            .is_err()
    );
    ensure!(fixture.gateway.requests.inner.lock().global_running == 0);
    Ok(())
}

#[tokio::test]
async fn request_guard_cannot_release_cleanup_pin_before_confirmed_report() -> anyhow::Result<()> {
    let fixture = Fixture::new([None, None], GatewayLimitProfile::default()).await?;
    let mut stream = fixture.open_input("text").await?;
    let process = stream.request_process;
    ensure!(stream.request_guard.finish().is_err());
    ensure!(stream.request_guard.process.is_some());
    ensure!(
        fixture.gateway.boot.kernel().processes().status(process) == Some(ProcessStatus::Running)
    );
    let output = ExecutionOutput::new(Outcome::Done(Value::from("body")), TaintSet::author());
    fixture
        .gateway
        .boot
        .finish_request_process(process, &output)
        .await?;
    stream.request_guard.finish()?;
    ensure!(stream.request_guard.process.is_none());
    ensure!(fixture.gateway.requests.inner.lock().global_running == 1);
    drop(stream);
    ensure!(fixture.gateway.requests.inner.lock().global_running == 0);
    Ok(())
}

#[tokio::test]
async fn inspection_rejects_operations_outside_the_selected_surface() -> anyhow::Result<()> {
    let fixture = Fixture::new([None, None], GatewayLimitProfile::default()).await?;
    let profile = fixture.gateway.profile_snapshot();
    let surface = profile
        .surface_by_id("text")
        .context("missing text surface")?;
    for (target, method) in [
        (surface.target.clone(), "other"),
        (
            ResourceName::new(Path::parse("effect://test/another")?),
            "invoke",
        ),
    ] {
        let program = DoNode::op(OperationTemplate {
            target,
            method: method.into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::null()),
        });
        ensure!(matches!(
            inspect_lowered_submission(
                &program,
                &profile,
                "alice",
                surface,
                &fixture.gateway.boot,
                true,
            ),
            Err(GatewayError::Rejected(message)) if message.contains("selected surface text")
        ));
    }
    Ok(())
}
