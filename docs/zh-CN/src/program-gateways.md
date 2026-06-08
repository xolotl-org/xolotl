# 程序网关

程序网关接收外部提交的工作，并通过共享 `nexus-gateway` 契约运行。提交的工作会变成 `DoNode` 程序，并以已衰减授权的请求进程执行。

## 共享语义

`nexus-gateway` 定义 `Gateway` 与 `InProcessGateway`。

当前 `InProcessGateway` 校验一个非空、可解析为身份路径的令牌，例如
`process://alice`。宿主可以限制允许的身份，声明请求进程的能力上限，并为每个请求暴露资源句柄。

所有协议适配器都遵循这个顺序：

1. 认证客户端令牌；
2. 把令牌映射为 `RequestIdentity`；
3. 为该身份创建请求进程；
4. 把入站帧转换为 `DoNode`；
5. 带入站污点求值程序；
6. 返回 `Outcome`。

网关审计记录使用适配器专用事件名，例如 `gateway_grpc` 和 `gateway_ws`。

## gRPC

gRPC API 定义在
`crates/nexus-proto/proto/nexus/v1/gateway.proto`：

```proto
service GatewayService {
  rpc Submit(SubmitRequest) returns (SubmitResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
}
```

当 `grpc` feature 启用时，`nexus-daemon` 会在 `[server].grpc_addr` 或
`NEXUS_GRPC_ADDR` 上提供该 API。该 feature 在默认构建中启用。

`SubmitRequest`：

| 字段 | 含义 |
| --- | --- |
| `auth_token` | 网关认证令牌。当前进程内网关把它解析为请求身份路径。 |
| `program` | 结构化 Protobuf `Program`；根字段是 `DoNode`。 |

`Program.root` 支持 `gateway.proto` 中定义的 `DoNode` 变体，包括
`pure`、顺序组合、fallback、并行组合、`let`、`acting`、`wait`、`fail` 和操作模板。

接入顺序：

1. 连接已配置的 gRPC 监听地址。
2. 用 `gateway.proto` 和 `common.proto` 生成客户端，或使用 `nexus-proto`
   的 Rust 绑定。
3. 调用 `Health`，读取 `HealthResponse { ready, version }`。
4. 构造 `Program { root: DoNode }`。
5. 调用 `Submit`，传入 `auth_token` 和 `program`。
6. 读取 `SubmitResponse.outcome`。

错误映射：

| 情况 | gRPC 状态 |
| --- | --- |
| 认证失败 | `Unauthenticated` |
| 已认证身份没有网关权限 | `PermissionDenied` |
| 缺少 `program` 或 `program` 无法转换 | `InvalidArgument` |
| 请求被准入或内核准备阶段拒绝 | `FailedPrecondition` |

## WebSocket

`nexus-gateway-websocket` 在 `[server].ws_addr` 或 `NEXUS_WS_ADDR` 对应的监听地址上暴露 `/ws`。该通道使用 WebSocket 文本帧，帧内容是 JSON。

客户端先发送认证帧：

```json
{"type":"auth","token":"process://alice"}
```

服务端返回映射后的身份：

```json
{"type":"authenticated","identity":"process://alice"}
```

之后客户端可以提交程序：

```json
{"type":"submit","id":1,"program":{ "...":"DoNode serde JSON" }}
```

结果携带同一个 `id`：

```json
{"type":"result","id":1,"outcome":{ "...":"Outcome JSON" }}
```

协议错误、认证错误和执行错误使用：

```json
{"type":"error","message":"..."}
```

程序 WebSocket 只接收文本帧。二进制帧、畸形 JSON、认证前提交都会返回错误帧。`program` 字段是 `nexus-graph::DoNode` 的 serde 表示；需要稳定跨语言模式时使用 gRPC。

## MCP

`nexus-gateway-mcp` 把选定 Nexus 效果暴露为 MCP 工具。每个发布的工具都绑定显式必需能力。调用会转换为普通网关提交，因此请求身份、授权、污点、执行和网关审计处理都与其它程序网关走同一路径。
