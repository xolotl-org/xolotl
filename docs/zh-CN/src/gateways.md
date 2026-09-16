# 网关

本页说明 `xolotld` 的监听地址和客户端协议。

应用客户端通过 profile 声明的 surface 提交任务；提供 effect 或事件的外部程序以
Provider 或 Source projection 接入，gRPC 和 WebSocket 实现这套独立的外部会话边界。

## 接入口

当 `[server]` 中的配置字段存在，或对应环境变量存在时，`xolotld` 会启动该通道。`xolotl-daemon` 默认启用 `external-grpc` 和 `external-websocket`；可以用 `--no-default-features --features external-grpc` 或 `--no-default-features --features external-websocket` 只构建其中一种 transport

| 接口 | 配置字段 | 环境变量 | 路径或服务 | 编码 |
| --- | --- | --- | --- | --- |
| 控制台 HTTP | `console_addr` | `XOLOTL_CONSOLE_ADDR` | `/health`、`/api/auth/*` | HTTP JSON |
| 控制台 WebSocket | `console_addr` | `XOLOTL_CONSOLE_ADDR` | `/ws` | 二进制 protobuf `ConsoleFrame`，`protobuf+xolotl-console-v1` |
| 应用 gRPC | `application_grpc_addr` | `XOLOTL_APPLICATION_GRPC_ADDR` | `xolotl.v1.application.ApplicationGateway` | Protobuf |
| External gRPC | `external_grpc_addr` | `XOLOTL_EXTERNAL_GRPC_ADDR` | `xolotl.v1.external.ExternalService.Session` | Protobuf |
| External WebSocket | `external_websocket_addr` | `XOLOTL_EXTERNAL_WEBSOCKET_ADDR` | `/ws` | 二进制 protobuf frame |

控制台 WebSocket 和 external WebSocket 都挂在 `/ws`，通过监听地址和帧编码区分：

- 控制台 WebSocket 使用 `[server].console_addr`，并在 `xolotl-console-v1` 子协议下发送二进制 protobuf 控制台帧
- External WebSocket 使用 `[server].external_websocket_addr` 和二进制 Provider/Source session frame

## 如何选择接口

| 需求 | 接口 |
| --- | --- |
| 执行管理动作、检查运行时状态、管理用户、管理会话、订阅状态或审计流 | 控制台协议 |
| 发现允许的 surface、上传类型化对象、以应用 principal 提交 AI 任务 | [应用网关](application-gateway.md)，可选 `application-grpc` feature |
| 连接提供 effect handler 的外部程序 | External gateway Provider |
| 连接发送入站事件或接收 outbound command 的外部程序 | External gateway Source |
| 把选定 Gateway publication 发布为 MCP tool、resource、resource template 和 prompt | MCP |

## External Gateway

External gateway session 见 [External Gateway](external-gateway.md)。Provider 和 Source 是唯一的外部 projection role。

外部程序运行在 Xolotl 进程之外，但需要作为声明过的 effect 或事件流投影进运行时，就使用这个入口。daemon 持有 session 准入、generation 检查、binding 选择和运行时限制；外部程序不能自声明授权范围。

## 嵌入式对象访问

按 profile 装配的 `GatewayRuntime` 通过 `with_object_store` 显式安装对象能力。
Gateway 和 `StandardConfig::with_object_store` 应接收同一个 `ObjectStore` 的克隆，
让准入后的引用能被标准 Provider 读取。Gateway 默认不安装对象适配器，内联提交无需对象能力。
State 只保留上传票据和证明，不存对象字节。

上传先提交不可变内容，再通过 CAS 发布票据回执。回执绑定 profile 名称、principal、surface、
可选的 submission token、摘要和大小，不固定 profile revision；使用时重新校验当前会话和权限。
未提交的票据不能授权引用已有内容。准入验证回执与规范元数据，并将对象来源信息传入执行。
单次证明在 Gateway 准入完成后、接受新的执行尝试前消费，
已准入的驱动失败不会恢复证明。回执 CAS 失败不会删除共享的已提交内容。

内核请求作用域持有已准入的进程，覆盖票据消费等待、执行以及跨调用的输入流。
丢弃未完成的提交或已接受的输入流会取消进程树并撤销句柄，异步清理共用宿主生命周期机制。
取消期间回执 CAS 的结果可能不确定，因此不会自动恢复单次票据。
已接受的输入流归属准入它的 runtime，克隆共享此归属；其他 runtime 不能完成或终止该流。

对象输入统一使用增量 API。`begin_object_upload` 只接收票据、媒体类型和 submission token
元数据，返回拥有生命周期的上传对象。`write` 借用每个数据块，将存储写入拆成最多 16 KiB
的窗口并处理部分确认，不保留历史载荷；调用方可以提供更小的块。总大小可以未知，窗口大小和
块数均不限制累计对象长度。票据声明的大小和摘要约束仍生效，当前票据编码可表示的大小最大为
`i64::MAX`。

```rust,ignore
use xolotl_gateway::{BeginObjectUploadRequest, Gateway, GatewayObjectKind};

let mut upload = gateway.begin_object_upload(&session, BeginObjectUploadRequest {
    ticket_id: ticket.ticket_id().into(),
    media_type: Some("application/octet-stream".into()),
    submission_token: None,
}).await?;
upload.write(&first_chunk).await?;
upload.write(&next_chunk).await?;
let result = upload.commit(GatewayObjectKind::Blob).await?;
```

输入结束时可用 `GatewayObjectKind::Tensor { dtype, shape }` 或
`GatewayObjectKind::Frame { ts_nanos, kind }` 提供解释信息，无需调用方预先构造摘要或字节数。
上传对象增量计算摘要，并用提交后的规范元数据校验最终引用。

上传对象自己持有原存储和实时 profile 状态，提交时不再接收另一 runtime。
写入一旦被轮询，失败或取消就会释放暂存 lease 并关闭上传，因为存储可能已经接受不确定的前缀；
尚未轮询的写入被丢弃时不改变上传状态。`abort` 可选，直接丢弃上传对象也会通过适配器既有的
所有权约定清理暂存。票据有效期不随活动延长；闲置过期的上传仍需丢弃或中止才能释放暂存。

可选的[应用网关](application-gateway.md)将增量 gRPC 输入交给此 API，
并在断开、超时或关闭时释放上传所有者。
调用方缓冲、传输解析、已提交对象和 State 留存仍各自承担内存或存储成本。

## MCP

MCP server 支持由 Gateway publication 定义。publication 为 `mcp` 协议命名一个 Gateway surface，并声明一种 kind：`tool`、`resource`、`resource_template` 或 `prompt`。它不重复声明 effect target、schema 或调用方绑定。发现接口只返回当前认证 principal 可见 surface 对应的 MCP publication。tool 调用、resource 读取和 prompt 请求都通过发布的 surface id 提交，因此 schema、limit、policy、Handle 归属、Fact、taint 和 audit 都仍走共享 Gateway 路径。

发布要求被引用的 surface 带有覆盖目标 effect 的 `publish://...` capability。MCP client 不能提交 raw effect path、raw capability、acting identity 或 raw Operation。

MCP adapter 优先协商 `2025-11-25`，并在 handshake 中保留所有已支持的已发布 MCP 协议修订。它实现 initialize、ping、tool、resource、resource template、prompt 和 completion 请求，但只在对应协议修订定义 completion 时声明 completion。不声明 logging、resource subscription、list-change notification 或 task execution。

MCP 专用字段留在 publication properties 中。`icons`、`mimeType`、`size`、prompt `arguments` 和静态 `completions` 由 MCP adapter 读取。Gateway 仍持有 surface target、schema、binding、limit 和 audit 路径。Tool result 可以返回原生 MCP `content`、`structuredContent`、`isError` 和 `_meta`；content block 会先校验再发送。

通过 `McpGateway::with_output_limits(McpOutputLimits)` 选择响应准入。默认允许
65,536 个逻辑 Value 节点、深度 32、8 MiB 内联载荷、65,536 个投影 JSON 节点和
16 MiB 编码消息。JSON 节点包含字节展开的数值数组与生成的媒体字段；编码字节包含
转义和最终 JSON-RPC 封套，共享子图按每次逻辑出现计数。普通 JSON 适配器最多支持
64 层 Value，更深结构可使用显式编码对象引用。这些传输预算不限制内核值深度或
累计任务数据量。结果在投影时被拒绝，不会撤销已完成的效果。

## 控制台协议

控制台 HTTP 只负责健康检查和认证。登录后的管理功能通过 Console WebSocket 执行，带授权、CAS、可见性门槛和审计记录。

控制台传输安全属于部署配置，见[配置](configuration.md)。本页只说明控制台协议入口。
