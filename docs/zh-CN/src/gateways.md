# 网关

本页说明 `nexusd` 的监听地址和客户端协议。

外部程序只有一套角色模型：以 Provider 或 Source projection 接入。gRPC 和 WebSocket 是同一个 external gateway 的两种传输实现。

## 接入口

当 `[server]` 中的配置字段存在，或对应环境变量存在时，`nexusd` 会启动该通道。`nexus-daemon` 默认启用 `external-grpc` 和 `external-websocket`；可以用 `--no-default-features --features external-grpc` 或 `--no-default-features --features external-websocket` 只构建其中一种 transport。

| 接口 | 配置字段 | 环境变量 | 路径或服务 | 编码 |
| --- | --- | --- | --- | --- |
| 控制台 HTTP | `console_addr` | `NEXUS_CONSOLE_ADDR` | `/health`、`/api/auth/*` | HTTP JSON |
| 控制台 WebSocket | `console_addr` | `NEXUS_CONSOLE_ADDR` | `/ws` | MessagePack，`msgpack+nexus-console-v1` |
| External gRPC | `external_grpc_addr` | `NEXUS_EXTERNAL_GRPC_ADDR` | `nexus.v1.external.ExternalService.Session` | Protobuf |
| External WebSocket | `external_websocket_addr` | `NEXUS_EXTERNAL_WEBSOCKET_ADDR` | `/ws` | 二进制 protobuf frame |

控制台 WebSocket 和 external WebSocket 都挂在 `/ws`，通过监听地址和帧编码区分：

- 控制台 WebSocket 使用 `[server].console_addr` 和 MessagePack 控制台帧。
- External WebSocket 使用 `[server].external_websocket_addr` 和二进制 Provider/Source session frame。

## 如何选择接口

| 需求 | 接口 |
| --- | --- |
| 执行管理动作、检查运行时状态、管理用户、管理会话、订阅状态或审计流 | 控制台协议 |
| 连接提供 effect handler 的外部程序 | External gateway Provider |
| 连接发送入站事件或接收 outbound command 的外部程序 | External gateway Source |
| 把选定 Gateway publication 发布为 MCP tool、resource、resource template 和 prompt | MCP |

## External Gateway

External gateway session 见 [External Gateway](external-gateway.md)。Provider 和 Source 是唯一的外部 projection role。

daemon 负责 session 准入和裁定：

1. 外部程序发送 `RoleSessionClientHello`；
2. daemon 读取 installation、其中选中的 projection、pairing 和已批准 session state；
3. daemon 发送带权威 generation 和限制的 `SessionContext`；
4. 外部程序回复 `RoleReady`；
5. session ready 后才允许业务 frame 流动。

Provider binding 来自 installation projection；`RoleReady` 只确认选定的 session context。Source event 只有通过 generation、schema、dedupe、capacity、rate 和 policy 检查后才会准入。

## MCP

MCP server 支持由 Gateway publication 定义。publication 为 `mcp` 协议命名一个 Gateway surface，并声明一种 kind：`tool`、`resource`、`resource_template` 或 `prompt`。它不重复声明 effect target、schema 或调用方绑定。发现接口只返回当前认证 principal 可见 surface 对应的 MCP publication。tool 调用、resource 读取和 prompt 请求都通过发布的 surface id 提交，因此 schema、limit、policy、Handle 归属、Fact、taint 和 audit 都仍走共享 Gateway 路径。

发布要求被引用的 surface 带有覆盖目标 effect 的 `publish://...` capability。MCP client 不能提交 raw effect path、raw capability、acting identity 或 raw Operation。

MCP adapter 优先协商 `2025-11-25`，并在 handshake 中保留近期兼容版本。它实现 initialize、ping、tool、resource、resource template、prompt 和 completion 请求。不声明 logging、resource subscription、list-change notification 或 task execution。

MCP 专用字段留在 publication properties 中。`icons`、`mimeType`、`size`、prompt `arguments` 和静态 `completions` 由 MCP adapter 读取。Gateway 仍持有 surface target、schema、binding、limit 和 audit 路径。Tool result 可以返回原生 MCP `content`、`structuredContent`、`isError` 和 `_meta`；content block 会先校验再发送。

## 控制台协议

控制台 HTTP 只负责健康检查和认证。登录后的管理功能通过 Console WebSocket 执行，带授权、CAS、可见性门槛和审计记录。

控制台传输安全由 daemon 持有，并通过 `[console.transport_security]` 配置。当前控制台
listener 是 plain listener：`local_trusted` 只允许 loopback，TLS 在可信前置代理终止时使用
`trusted_reverse_proxy`，除非控制台 listener 配置了 daemon 持有的 TLS material，否则
`production_tls` 会 fail closed。
