use andrias_gateway::{
    GatewayError, GatewayPrincipalSurfaceBinding, GatewayProfile, GatewayPublication,
    GatewayRuntime, GatewaySurface,
};
use andrias_gateway_mcp::{
    McpGateway, McpJsonRpcResponse, mcp_prompt_publication, mcp_resource_publication,
    mcp_resource_template_publication, mcp_tool_publication,
};
use andrias_kernel::{Bootstrap, EchoDriver, FnDriver};
use andrias_types::{Outcome, OutcomeRef, Value};
use anyhow::{Context, bail, ensure};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;

const JSONRPC_INVALID_REQUEST: i64 = -32600;
const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
const JSONRPC_INVALID_PARAMS: i64 = -32602;
const JSONRPC_RESOURCE_NOT_FOUND: i64 = -32002;
const JSONRPC_GATEWAY_ERROR: i64 = -32000;
const TEST_TOKEN: &str = "mcp-token-for-alice-0001";
const MCP_PUBLISHED_PROTOCOL_VERSIONS: &[(&str, bool)] = &[
    ("2025-11-25", true),
    ("2025-06-18", true),
    ("2025-03-26", true),
    ("2024-11-05", false),
];

macro_rules! assert {
    ($condition:expr $(,)?) => {
        ensure!($condition, "assertion failed: {}", stringify!($condition));
    };
}

macro_rules! assert_eq {
    ($left:expr, $right:expr $(,)?) => {{
        let left = &$left;
        let right = &$right;
        ensure!(
            left == right,
            "assertion failed: left `{:?}` != right `{:?}`",
            left,
            right
        );
    }};
}

fn must<T, E>(result: Result<T, E>) -> anyhow::Result<T>
where
    E: std::error::Error + Send + Sync + 'static,
{
    Ok(result?)
}

fn response_result<'a>(
    response: &'a McpJsonRpcResponse,
    label: &'static str,
) -> anyhow::Result<&'a serde_json::Value> {
    response
        .result
        .as_ref()
        .with_context(|| format!("{label} returned no result"))
}

fn json_array<'a>(
    value: &'a serde_json::Value,
    key: &'static str,
) -> anyhow::Result<&'a Vec<serde_json::Value>> {
    value[key]
        .as_array()
        .with_context(|| format!("{key} was not an array"))
}

fn schema_type(kind: &str) -> Value {
    Value::Map(BTreeMap::from([("type".into(), Value::from(kind))]))
}

fn audit_outcomes(boot: &Bootstrap, event: &str) -> anyhow::Result<Vec<String>> {
    Ok(must(boot.kernel.facts.all_facts())?
        .into_iter()
        .filter_map(|fact| match fact.outcome_ref {
            OutcomeRef::Inline(Value::Map(m))
                if m.get("event").and_then(Value::as_str) == Some(event) =>
            {
                m.get("outcome").and_then(Value::as_str).map(str::to_string)
            }
            _ => None,
        })
        .collect())
}

fn register_echo(boot: &Bootstrap, effect: &str) -> anyhow::Result<andrias_types::ResourceName> {
    must(boot.register_effect(
        effect,
        &[andrias_kernel::MethodSpec::new(
            "invoke",
            andrias_types::Purity::Pure,
            andrias_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(EchoDriver),
    ))
}

fn register_fixed(
    boot: &Bootstrap,
    effect: &str,
    value: Value,
) -> anyhow::Result<andrias_types::ResourceName> {
    must(boot.register_effect(
        effect,
        &[andrias_kernel::MethodSpec::new(
            "invoke",
            andrias_types::Purity::Pure,
            andrias_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(FnDriver(move |_, _| Ok(value.clone()))),
    ))
}

fn echo_profile(
    target: andrias_types::ResourceName,
    publication: GatewayPublication,
) -> anyhow::Result<GatewayProfile> {
    Ok(must(GatewayProfile::new("mcp-test").with_bearer_identity(
        "cred-alice",
        "alice",
        TEST_TOKEN,
        "process://alice",
    ))?
    .with_surface(
        GatewaySurface::effect_invoke("echo", target)
            .with_publish_capability("publish://effect/echo/say")
            .with_schema(Some(schema_type("object")), Some(schema_type("object"))),
    )
    .with_publication(publication)
    .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
        "alice",
        ["echo"],
        ["perform://effect/echo/say"],
    )))
}

#[tokio::test]
async fn tool_call_runs_through_gateway() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let target = register_echo(&boot, "effect://echo/say")?;
    let profile = echo_profile(target, mcp_tool_publication("echo", "echo"))?;
    let inner = must(GatewayRuntime::new(boot, profile))?;
    let mcp = McpGateway::new(Arc::new(inner));

    let input = Value::Map(BTreeMap::from([("text".into(), Value::from("from-mcp"))]));
    let out = mcp.call_tool(TEST_TOKEN, "echo", input.clone()).await;
    let out = must(out)?;
    assert_eq!(out, Outcome::Done(input));
    Ok(())
}

#[tokio::test]
async fn descriptors_are_authenticated_and_kind_filtered() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let echo = register_echo(&boot, "effect://echo/say")?;
    let hidden = register_echo(&boot, "effect://hidden/run")?;
    let profile = must(GatewayProfile::new("mcp-test").with_bearer_identity(
        "cred-alice",
        "alice",
        TEST_TOKEN,
        "process://alice",
    ))?
    .with_surface(
        GatewaySurface::effect_invoke("echo", echo)
            .with_publish_capability("publish://effect/echo/say")
            .with_schema(Some(schema_type("object")), Some(schema_type("object"))),
    )
    .with_surface(
        GatewaySurface::effect_invoke("hidden", hidden)
            .with_publish_capability("publish://effect/hidden/run"),
    )
    .with_publication(
        mcp_tool_publication("echo", "echo")
            .with_description("Echo an object")
            .with_title("Echo")
            .with_annotations(Value::Map(BTreeMap::from([(
                "readOnlyHint".into(),
                Value::Bool(true),
            )])))
            .with_metadata(Value::Map(BTreeMap::from([(
                "owner".into(),
                Value::from("andrias-test"),
            )]))),
    )
    .with_publication(
        mcp_resource_publication("echo-resource", "andrias://echo/value", "echo")
            .with_description("Echo resource"),
    )
    .with_publication(
        mcp_tool_publication("hidden", "hidden").with_description("Hidden from alice"),
    )
    .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
        "alice",
        ["echo"],
        ["perform://effect/echo/say"],
    ));
    let inner = must(GatewayRuntime::new(boot.clone(), profile))?;
    let mcp = McpGateway::new(Arc::new(inner));

    let tools = must(mcp.list_tools(TEST_TOKEN).await)?;
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "echo");
    assert_eq!(tools[0].title.as_deref(), Some("Echo"));
    assert_eq!(tools[0].description.as_deref(), Some("Echo an object"));
    assert_eq!(tools[0].input_schema, Some(schema_type("object")));
    assert_eq!(tools[0].output_schema, Some(schema_type("object")));

    let resources = must(mcp.list_resources(TEST_TOKEN).await)?;
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].uri, "andrias://echo/value");

    assert!(audit_outcomes(&boot, "gateway_mcp")?.contains(&"describe_ok".into()));
    assert!(mcp.list_tools("wrong-token-for-alice-0001").await.is_err());
    Ok(())
}

#[tokio::test]
async fn jsonrpc_lists_and_calls_tools() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let echo = register_echo(&boot, "effect://echo/say")?;
    let profile = echo_profile(
        echo,
        mcp_tool_publication("echo", "echo")
            .with_description("Echo an object")
            .with_property(
                "icons",
                Value::List(vec![Value::Map(BTreeMap::from([(
                    "src".into(),
                    Value::from("andrias://icons/echo.png"),
                )]))]),
            )
            .with_metadata(Value::Map(BTreeMap::from([(
                "owner".into(),
                Value::from("andrias-test"),
            )]))),
    );
    let inner = must(GatewayRuntime::new(boot, profile?))?;
    let mcp = McpGateway::new(Arc::new(inner));

    let response = mcp
        .handle_jsonrpc_value(
            TEST_TOKEN,
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
        )
        .await;
    assert!(response.error.is_none());
    let result = response_result(&response, "tools/list")?;
    let tools = json_array(result, "tools")?;
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "echo");
    assert_eq!(tools[0]["description"], "Echo an object");
    assert_eq!(
        tools[0]["inputSchema"],
        must(serde_json::to_value(schema_type("object")))?
    );
    assert_eq!(tools[0]["icons"][0]["src"], "andrias://icons/echo.png");
    assert_eq!(tools[0]["_meta"]["owner"], "andrias-test");

    let call = mcp
        .handle_jsonrpc_value(
            TEST_TOKEN,
            json!({
                "jsonrpc": "2.0",
                "id": "call-1",
                "method": "tools/call",
                "params": {
                    "name": "echo",
                    "arguments": { "text": "from-jsonrpc" },
                    "_meta": { "progressToken": "progress-1" }
                }
            }),
        )
        .await;
    assert!(call.error.is_none());
    let result = response_result(&call, "tools/call")?;
    assert_eq!(result["structuredContent"]["text"], "from-jsonrpc");
    assert_eq!(result["content"][0]["text"], "{\"text\":\"from-jsonrpc\"}");
    assert_eq!(result["isError"], false);
    Ok(())
}

#[tokio::test]
async fn jsonrpc_passes_native_tool_content_types() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let native_result = Value::Map(BTreeMap::from([
        (
            "content".into(),
            Value::List(vec![
                Value::Map(BTreeMap::from([
                    ("type".into(), Value::from("image")),
                    ("data".into(), Value::from("iVBORw0KGgo=")),
                    ("mimeType".into(), Value::from("image/png")),
                ])),
                Value::Map(BTreeMap::from([
                    ("type".into(), Value::from("audio")),
                    ("data".into(), Value::from("UklGRg==")),
                    ("mimeType".into(), Value::from("audio/wav")),
                ])),
                Value::Map(BTreeMap::from([
                    ("type".into(), Value::from("resource_link")),
                    ("uri".into(), Value::from("andrias://docs/readme")),
                    ("name".into(), Value::from("readme")),
                    ("mimeType".into(), Value::from("text/markdown")),
                ])),
                Value::Map(BTreeMap::from([
                    ("type".into(), Value::from("resource")),
                    (
                        "resource".into(),
                        Value::Map(BTreeMap::from([
                            ("uri".into(), Value::from("andrias://docs/embed")),
                            ("text".into(), Value::from("embedded")),
                            ("mimeType".into(), Value::from("text/plain")),
                        ])),
                    ),
                ])),
            ]),
        ),
        (
            "structuredContent".into(),
            Value::Map(BTreeMap::from([("count".into(), Value::Int(4))])),
        ),
        ("isError".into(), Value::Bool(false)),
    ]));
    let target = register_fixed(&boot, "effect://tool/native", native_result)?;
    let profile = must(GatewayProfile::new("mcp-test").with_bearer_identity(
        "cred-alice",
        "alice",
        TEST_TOKEN,
        "process://alice",
    ))?
    .with_surface(
        GatewaySurface::effect_invoke("echo", target)
            .with_publish_capability("publish://effect/tool/native"),
    )
    .with_publication(mcp_tool_publication("echo", "echo"))
    .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
        "alice",
        ["echo"],
        ["perform://effect/tool/native"],
    ));
    let mcp = McpGateway::new(Arc::new(must(GatewayRuntime::new(boot, profile))?));

    let call = mcp
        .handle_jsonrpc_value(
            TEST_TOKEN,
            json!({
                "jsonrpc": "2.0",
                "id": "native",
                "method": "tools/call",
                "params": {
                    "name": "echo",
                    "arguments": {}
                }
            }),
        )
        .await;
    assert!(call.error.is_none());
    let result = response_result(&call, "tools/call")?;
    assert_eq!(result["content"][0]["type"], "image");
    assert_eq!(result["content"][1]["type"], "audio");
    assert_eq!(result["content"][2]["type"], "resource_link");
    assert_eq!(result["content"][3]["resource"]["text"], "embedded");
    assert_eq!(result["structuredContent"]["count"], 4);
    Ok(())
}

#[tokio::test]
async fn jsonrpc_rejects_invalid_native_tool_result() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let native_result = Value::Map(BTreeMap::from([(
        "content".into(),
        Value::List(vec![Value::Map(BTreeMap::from([
            ("type".into(), Value::from("image")),
            ("data".into(), Value::from("iVBORw0KGgo=")),
        ]))]),
    )]));
    let target = register_fixed(&boot, "effect://tool/native-bad", native_result)?;
    let profile = must(GatewayProfile::new("mcp-test").with_bearer_identity(
        "cred-alice",
        "alice",
        TEST_TOKEN,
        "process://alice",
    ))?
    .with_surface(
        GatewaySurface::effect_invoke("echo", target)
            .with_publish_capability("publish://effect/tool/native-bad"),
    )
    .with_publication(mcp_tool_publication("echo", "echo"))
    .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
        "alice",
        ["echo"],
        ["perform://effect/tool/native-bad"],
    ));
    let mcp = McpGateway::new(Arc::new(must(GatewayRuntime::new(boot, profile))?));

    let call = mcp
        .handle_jsonrpc_value(
            TEST_TOKEN,
            json!({
                "jsonrpc": "2.0",
                "id": "native-bad",
                "method": "tools/call",
                "params": {
                    "name": "echo",
                    "arguments": {}
                }
            }),
        )
        .await;
    assert_eq!(
        call.error.as_ref().map(|error| error.code),
        Some(JSONRPC_GATEWAY_ERROR)
    );
    Ok(())
}

#[tokio::test]
async fn jsonrpc_rejects_task_augmented_tool_call_when_not_advertised() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let target = register_echo(&boot, "effect://echo/say")?;
    let profile = echo_profile(target, mcp_tool_publication("echo", "echo"))?;
    let mcp = McpGateway::new(Arc::new(must(GatewayRuntime::new(boot, profile))?));

    let call = mcp
        .handle_jsonrpc_value(
            TEST_TOKEN,
            json!({
                "jsonrpc": "2.0",
                "id": "task",
                "method": "tools/call",
                "params": {
                    "name": "echo",
                    "arguments": {},
                    "task": {}
                }
            }),
        )
        .await;
    assert_eq!(
        call.error.as_ref().map(|error| error.code),
        Some(JSONRPC_INVALID_PARAMS)
    );
    Ok(())
}

#[tokio::test]
async fn jsonrpc_lists_and_reads_resources() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let target = register_fixed(
        &boot,
        "effect://resource/read",
        Value::Str("resource text".into()),
    )?;
    let profile = must(GatewayProfile::new("mcp-test").with_bearer_identity(
        "cred-alice",
        "alice",
        TEST_TOKEN,
        "process://alice",
    ))?
    .with_surface(
        GatewaySurface::effect_invoke("resource", target)
            .with_publish_capability("publish://effect/resource/read"),
    )
    .with_publication(
        mcp_resource_publication("readme", "andrias://docs/readme", "resource")
            .with_title("Readme")
            .with_description("Read the project readme")
            .with_property("mimeType", Value::from("text/plain"))
            .with_property("size", Value::Int(13)),
    )
    .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
        "alice",
        ["resource"],
        ["perform://effect/resource/read"],
    ));
    let mcp = McpGateway::new(Arc::new(must(GatewayRuntime::new(boot, profile))?));

    let list = mcp
        .handle_jsonrpc_value(
            TEST_TOKEN,
            json!({"jsonrpc":"2.0","id":1,"method":"resources/list"}),
        )
        .await;
    assert!(list.error.is_none());
    let resources = json_array(response_result(&list, "resources/list")?, "resources")?;
    assert_eq!(resources[0]["uri"], "andrias://docs/readme");
    assert_eq!(resources[0]["mimeType"], "text/plain");
    assert_eq!(resources[0]["size"], 13);

    let read = mcp
        .handle_jsonrpc_value(
            TEST_TOKEN,
            json!({
                "jsonrpc":"2.0",
                "id":2,
                "method":"resources/read",
                "params":{"uri":"andrias://docs/readme"}
            }),
        )
        .await;
    assert!(read.error.is_none());
    let contents = json_array(response_result(&read, "resources/read")?, "contents")?;
    assert_eq!(contents[0]["uri"], "andrias://docs/readme");
    assert_eq!(contents[0]["mimeType"], "text/plain");
    assert_eq!(contents[0]["text"], "resource text");
    Ok(())
}

#[tokio::test]
async fn jsonrpc_reads_binary_resource_content() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let target = register_fixed(
        &boot,
        "effect://resource/bin",
        Value::Bytes(vec![0, 1, 2, 253, 254, 255]),
    )?;
    let profile = must(GatewayProfile::new("mcp-test").with_bearer_identity(
        "cred-alice",
        "alice",
        TEST_TOKEN,
        "process://alice",
    ))?
    .with_surface(
        GatewaySurface::effect_invoke("resource", target)
            .with_publish_capability("publish://effect/resource/bin"),
    )
    .with_publication(
        mcp_resource_publication("binary", "andrias://blob/binary", "resource")
            .with_property("mimeType", Value::from("application/octet-stream")),
    )
    .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
        "alice",
        ["resource"],
        ["perform://effect/resource/bin"],
    ));
    let mcp = McpGateway::new(Arc::new(must(GatewayRuntime::new(boot, profile))?));

    let read = mcp
        .handle_jsonrpc_value(
            TEST_TOKEN,
            json!({
                "jsonrpc":"2.0",
                "id":2,
                "method":"resources/read",
                "params":{"uri":"andrias://blob/binary"}
            }),
        )
        .await;
    assert!(read.error.is_none());
    let contents = json_array(response_result(&read, "resources/read")?, "contents")?;
    assert_eq!(contents[0]["blob"], "AAEC/f7/");
    Ok(())
}

#[tokio::test]
async fn jsonrpc_lists_templates_and_routes_template_reads() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let target = register_echo(&boot, "effect://resource/template")?;
    let profile = must(GatewayProfile::new("mcp-test").with_bearer_identity(
        "cred-alice",
        "alice",
        TEST_TOKEN,
        "process://alice",
    ))?
    .with_surface(
        GatewaySurface::effect_invoke("template", target)
            .with_publish_capability("publish://effect/resource/template"),
    )
    .with_publication(
        mcp_resource_template_publication("file", "andrias://files/{path}", "template")
            .with_property("mimeType", Value::from("text/plain")),
    )
    .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
        "alice",
        ["template"],
        ["perform://effect/resource/template"],
    ));
    let mcp = McpGateway::new(Arc::new(must(GatewayRuntime::new(boot, profile))?));

    let list = mcp
        .handle_jsonrpc_value(
            TEST_TOKEN,
            json!({"jsonrpc":"2.0","id":1,"method":"resources/templates/list"}),
        )
        .await;
    assert!(list.error.is_none());
    let templates = json_array(
        response_result(&list, "resources/templates/list")?,
        "resourceTemplates",
    )?;
    assert_eq!(templates[0]["uriTemplate"], "andrias://files/{path}");

    let read = mcp
        .handle_jsonrpc_value(
            TEST_TOKEN,
            json!({
                "jsonrpc":"2.0",
                "id":2,
                "method":"resources/read",
                "params":{"uri":"andrias://files/readme.md"}
            }),
        )
        .await;
    assert!(read.error.is_none());
    let text = &response_result(&read, "resources/read")?["contents"][0]["text"];
    assert_eq!(
        text,
        "{\"uri\":\"andrias://files/readme.md\",\"uriTemplate\":\"andrias://files/{path}\"}"
    );
    Ok(())
}

#[tokio::test]
async fn jsonrpc_lists_and_gets_prompts() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let target = register_fixed(&boot, "effect://prompt/review", Value::from("Review this."))?;
    let profile = must(GatewayProfile::new("mcp-test").with_bearer_identity(
        "cred-alice",
        "alice",
        TEST_TOKEN,
        "process://alice",
    ))?
    .with_surface(
        GatewaySurface::effect_invoke("prompt", target)
            .with_publish_capability("publish://effect/prompt/review"),
    )
    .with_publication(
        mcp_prompt_publication("review", "prompt")
            .with_description("Review prompt")
            .with_property(
                "arguments",
                Value::List(vec![Value::Map(BTreeMap::from([
                    ("name".into(), Value::from("target")),
                    ("description".into(), Value::from("Review target")),
                    ("required".into(), Value::Bool(true)),
                ]))]),
            ),
    )
    .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
        "alice",
        ["prompt"],
        ["perform://effect/prompt/review"],
    ));
    let mcp = McpGateway::new(Arc::new(must(GatewayRuntime::new(boot, profile))?));

    let list = mcp
        .handle_jsonrpc_value(
            TEST_TOKEN,
            json!({"jsonrpc":"2.0","id":1,"method":"prompts/list"}),
        )
        .await;
    assert!(list.error.is_none());
    let prompts = json_array(response_result(&list, "prompts/list")?, "prompts")?;
    assert_eq!(prompts[0]["name"], "review");
    assert_eq!(prompts[0]["arguments"][0]["name"], "target");
    assert_eq!(prompts[0]["arguments"][0]["required"], true);

    let get = mcp
        .handle_jsonrpc_value(
            TEST_TOKEN,
            json!({
                "jsonrpc":"2.0",
                "id":2,
                "method":"prompts/get",
                "params":{"name":"review","arguments":{"target":"code"}}
            }),
        )
        .await;
    assert!(get.error.is_none());
    let result = response_result(&get, "prompts/get")?;
    assert_eq!(result["description"], "Review prompt");
    assert_eq!(result["messages"][0]["role"], "user");
    assert_eq!(result["messages"][0]["content"]["text"], "Review this.");
    Ok(())
}

#[tokio::test]
async fn jsonrpc_completes_prompt_and_resource_template_arguments() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let prompt = register_fixed(&boot, "effect://prompt/review", Value::from("Review this."))?;
    let template = register_echo(&boot, "effect://resource/template")?;
    let profile = must(GatewayProfile::new("mcp-test").with_bearer_identity(
        "cred-alice",
        "alice",
        TEST_TOKEN,
        "process://alice",
    ))?
    .with_surface(
        GatewaySurface::effect_invoke("prompt", prompt)
            .with_publish_capability("publish://effect/prompt/review"),
    )
    .with_surface(
        GatewaySurface::effect_invoke("template", template)
            .with_publish_capability("publish://effect/resource/template"),
    )
    .with_publication(
        mcp_prompt_publication("review", "prompt")
            .with_property(
                "arguments",
                Value::List(vec![Value::Map(BTreeMap::from([(
                    "name".into(),
                    Value::from("target"),
                )]))]),
            )
            .with_property(
                "completions",
                Value::Map(BTreeMap::from([(
                    "target".into(),
                    Value::List(vec![
                        Value::from("code"),
                        Value::from("config"),
                        Value::from("docs"),
                    ]),
                )])),
            ),
    )
    .with_publication(
        mcp_resource_template_publication("file", "andrias://files/{+path}", "template")
            .with_property(
                "completions",
                Value::Map(BTreeMap::from([(
                    "path".into(),
                    Value::List(vec![
                        Value::from("docs/readme.md"),
                        Value::from("src/lib.rs"),
                    ]),
                )])),
            ),
    )
    .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
        "alice",
        ["prompt", "template"],
        [
            "perform://effect/prompt/review",
            "perform://effect/resource/template",
        ],
    ));
    let mcp = McpGateway::new(Arc::new(must(GatewayRuntime::new(boot, profile))?));

    let prompt_complete = mcp
        .handle_jsonrpc_value(
            TEST_TOKEN,
            json!({
                "jsonrpc": "2.0",
                "id": "complete-prompt",
                "method": "completion/complete",
                "params": {
                    "ref": {
                        "type": "ref/prompt",
                        "name": "review"
                    },
                    "argument": {
                        "name": "target",
                        "value": "co"
                    },
                    "_meta": {
                        "progressToken": "complete-1"
                    }
                }
            }),
        )
        .await;
    assert!(prompt_complete.error.is_none());
    let result = response_result(&prompt_complete, "completion/complete prompt")?;
    assert_eq!(result["completion"]["values"][0], "code");
    assert_eq!(result["completion"]["values"][1], "config");
    assert_eq!(result["completion"]["total"], 2);
    assert_eq!(result["completion"]["hasMore"], false);

    let template_complete = mcp
        .handle_jsonrpc_value(
            TEST_TOKEN,
            json!({
                "jsonrpc": "2.0",
                "id": "complete-template",
                "method": "completion/complete",
                "params": {
                    "ref": {
                        "type": "ref/resource",
                        "uri": "andrias://files/{+path}"
                    },
                    "argument": {
                        "name": "path",
                        "value": "docs"
                    },
                    "context": {
                        "arguments": {}
                    }
                }
            }),
        )
        .await;
    assert!(template_complete.error.is_none());
    let result = response_result(&template_complete, "completion/complete template")?;
    assert_eq!(result["completion"]["values"][0], "docs/readme.md");
    assert_eq!(result["completion"]["total"], 1);
    Ok(())
}

#[tokio::test]
async fn jsonrpc_rejects_unknown_and_bad_requests_without_catalog_leak() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let profile = must(GatewayProfile::new("mcp-test").with_bearer_identity(
        "cred-alice",
        "alice",
        TEST_TOKEN,
        "process://alice",
    ))?;
    let mcp = McpGateway::new(Arc::new(must(GatewayRuntime::new(boot, profile))?));

    let unknown = mcp
        .handle_jsonrpc_value(
            TEST_TOKEN,
            json!({"jsonrpc":"2.0","id":1,"method":"unknown/method"}),
        )
        .await;
    assert_eq!(
        unknown.error.as_ref().map(|error| error.code),
        Some(JSONRPC_METHOD_NOT_FOUND)
    );

    let missing_id = mcp
        .handle_jsonrpc_value(TEST_TOKEN, json!({"jsonrpc":"2.0","method":"tools/list"}))
        .await;
    assert_eq!(
        missing_id.error.as_ref().map(|error| error.code),
        Some(JSONRPC_INVALID_REQUEST)
    );

    let credential_in_body = mcp
        .handle_jsonrpc_value(
            TEST_TOKEN,
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "credential": "must-not-be-here"
            }),
        )
        .await;
    assert_eq!(
        credential_in_body.error.as_ref().map(|error| error.code),
        Some(JSONRPC_INVALID_REQUEST)
    );

    let unknown_resource = mcp
        .handle_jsonrpc_value(
            TEST_TOKEN,
            json!({
                "jsonrpc":"2.0",
                "id":3,
                "method":"resources/read",
                "params":{"uri":"andrias://missing"}
            }),
        )
        .await;
    assert_eq!(
        unknown_resource.error.as_ref().map(|error| error.code),
        Some(JSONRPC_RESOURCE_NOT_FOUND)
    );
    Ok(())
}

#[tokio::test]
async fn jsonrpc_initialize_ping_and_initialized_notification_do_not_expose_surfaces()
-> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let profile = must(GatewayProfile::new("mcp-test").with_bearer_identity(
        "cred-alice",
        "alice",
        TEST_TOKEN,
        "process://alice",
    ))?;
    let mcp = McpGateway::new(Arc::new(must(GatewayRuntime::new(boot, profile))?));

    for (id, &(protocol_version, supports_completions)) in
        MCP_PUBLISHED_PROTOCOL_VERSIONS.iter().enumerate()
    {
        let initialized = mcp
            .handle_jsonrpc_value(
                "",
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": protocol_version,
                        "capabilities": {},
                        "clientInfo": {
                            "name": "test-client",
                            "version": "0.1.0"
                        }
                    }
                }),
            )
            .await;
        assert!(initialized.error.is_none());
        let result = response_result(&initialized, "initialize")?;
        assert_eq!(result["protocolVersion"], protocol_version);
        assert_eq!(result["capabilities"]["tools"]["listChanged"], false);
        assert_eq!(result["capabilities"]["resources"]["subscribe"], false);
        assert_eq!(result["capabilities"]["prompts"]["listChanged"], false);
        if supports_completions {
            assert!(result["capabilities"]["completions"].is_object());
        } else {
            assert!(result["capabilities"].get("completions").is_none());
        }
        assert!(result["capabilities"].get("logging").is_none());
        assert!(result["capabilities"].get("tasks").is_none());
        assert!(result.get("tools").is_none());
    }

    let notification = mcp
        .handle_jsonrpc_message_value(
            "",
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
        )
        .await;
    assert!(notification.is_none());

    let cancelled = mcp
        .handle_jsonrpc_message_value(
            "",
            json!({
                "jsonrpc":"2.0",
                "method":"notifications/cancelled",
                "params":{
                    "requestId":"call-1",
                    "reason":"client cancelled"
                }
            }),
        )
        .await;
    assert!(cancelled.is_none());

    let ping = mcp
        .handle_jsonrpc_value("", json!({"jsonrpc":"2.0","id":2,"method":"ping"}))
        .await;
    assert!(ping.error.is_none());
    Ok(())
}

#[test]
fn publication_requires_surface_publish_capability() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let target = register_echo(&boot, "effect://echo/say")?;
    let profile = must(GatewayProfile::new("mcp-test").with_bearer_identity(
        "cred-alice",
        "alice",
        TEST_TOKEN,
        "process://alice",
    ))?
    .with_surface(GatewaySurface::effect_invoke("echo", target))
    .with_publication(mcp_tool_publication("echo", "echo"))
    .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
        "alice",
        ["echo"],
        ["perform://effect/echo/say"],
    ));
    ensure!(
        matches!(
        GatewayRuntime::new(boot, profile),
        Err(GatewayError::InvalidProfile(message))
            if message.contains("without publish_capability")
        ),
        "profile without publish capability was accepted"
    );
    Ok(())
}

#[tokio::test]
async fn auth_failure_is_redacted_and_audited() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let target = register_echo(&boot, "effect://echo/say")?;
    let profile = echo_profile(target, mcp_tool_publication("echo", "echo"))?;
    let inner = must(GatewayRuntime::new(boot.clone(), profile))?;
    let mcp = McpGateway::new(Arc::new(inner));

    let err = match mcp
        .call_tool("wrong-token-for-alice-0001", "echo", Value::Null)
        .await
    {
        Ok(_) => bail!("call with wrong token unexpectedly succeeded"),
        Err(err) => err,
    };
    assert_eq!(err.to_string(), "gateway rejected MCP request");
    assert!(audit_outcomes(&boot, "gateway_mcp")?.contains(&"auth_failed".into()));
    Ok(())
}

#[tokio::test]
async fn tool_failure_is_mcp_result_not_jsonrpc_error() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let target = register_echo(&boot, "effect://echo/say")?;
    let profile = must(GatewayProfile::new("mcp-test").with_bearer_identity(
        "cred-alice",
        "alice",
        TEST_TOKEN,
        "process://alice",
    ))?
    .with_surface(
        GatewaySurface::effect_invoke("echo", target)
            .with_publish_capability("publish://effect/echo/say")
            .with_schema(Some(schema_type("object")), Some(schema_type("string"))),
    )
    .with_publication(mcp_tool_publication("echo", "echo"))
    .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
        "alice",
        ["echo"],
        ["perform://effect/echo/say"],
    ));
    let inner = must(GatewayRuntime::new(boot, profile))?;
    let mcp = McpGateway::new(Arc::new(inner));

    let response = mcp
        .handle_jsonrpc_value(
            TEST_TOKEN,
            json!({
                "jsonrpc": "2.0",
                "id": "call-1",
                "method": "tools/call",
                "params": {
                    "name": "echo",
                    "arguments": { "text": "from-jsonrpc" }
                }
            }),
        )
        .await;
    assert!(response.error.is_none());
    let result = response_result(&response, "tools/call")?;
    assert_eq!(result["isError"], true);
    Ok(())
}
