# 控制台协议

`nexus-console` 承载控制台客户端使用的管理协议。它提供健康检查和认证用的 HTTP 路由；登录后的管理动作和流订阅通过控制台 WebSocket 运行。

管理动作使用有描述符名称的调用。它们使用运行时的状态、授权、CAS、可见性和审计接口；当管理动作调用运行时效果时，该效果作为受能力约束的 `Operation` 执行。

## 监听地址

控制台 HTTP 和控制台 WebSocket 共用 `[server].console_addr`，环境变量回退为
`NEXUS_CONSOLE_ADDR`。

| 通道 | 路径 | 编码 |
| --- | --- | --- |
| HTTP | `/health`、`/api/auth/*` | HTTP JSON |
| WebSocket | `/ws` | 二进制 MessagePack，`msgpack+nexus-console-v1` |

## HTTP 路由

控制台 HTTP 路由由 `nexus-console::router` 提供：

| 路径 | 方法 | 用途 |
| --- | --- | --- |
| `/health` | `GET` | 健康检查。 |
| `/api/auth/login` | `POST` | 用户名、密码和可选 TOTP 登录。 |
| `/api/auth/key/challenge` | `POST` | 创建公钥登录挑战。 |
| `/api/auth/key/login` | `POST` | 提交公钥签名并完成登录。 |
| `/api/auth/step-up` | `POST` | 使用现有 bearer session 提升 MFA 等级。 |

认证路由要求 `Origin` 和 `Host` 请求头。origin 的 host、port 以及可信 forwarded
scheme 必须匹配控制台 listener 对外可见的 host。公钥登录还要求 JSON 里的 `origin`
字段与请求 `Origin` 头完全一致；该值会绑定进签名 transcript。

密码登录请求：

```json
{"username":"root","password":"...","totp_code":null}
```

公钥挑战请求：

```json
{"username":"root","origin":"https://console.example"}
```

公钥登录请求：

```json
{"username":"root","challenge_id":"...","signature":"...","origin":"https://console.example","key":null}
```

Step-up 请求体：

```json
{"password":"...","totp_code":null}
```

`/api/auth/step-up` 通过以下请求头传入现有会话：

```text
Authorization: Bearer <token>
```

登录、公钥登录和 step-up 都返回 `LoginResponse`：

| 字段 | 含义 |
| --- | --- |
| `sid` | 会话 ID。 |
| `token` | `sid.secret` 形式的 bearer token。 |
| `expires_at` | 绝对过期时间，Unix 毫秒。 |
| `idle_expires_at` | 空闲过期时间，Unix 毫秒。 |
| `mfa_level` | 会话 MFA 等级。 |

HTTP 认证错误映射：

| 情况 | 状态 |
| --- | --- |
| 缺少 bearer、无效会话、无效挑战或无效凭据 | `401 Unauthorized` |
| 账号不可用或权限不足 | `403 Forbidden` |
| 超过速率限制 | `429 Too Many Requests` |
| 用户名无效 | `400 Bad Request` |
| 内部认证状态或加密失败 | `500 Internal Server Error`，返回脱敏消息 |

## WebSocket 升级

控制台 WebSocket 挂在控制台监听地址的 `/ws`。升级时会检查：

- `Origin` 请求头存在且可解析；
- `Host` 请求头存在；
- origin host 和 port 与对外可见 host 匹配；
- 存在 `:path` 时，其值为 `/ws`；
- 来源级连接限制仍有容量。

端点接收二进制 MessagePack 帧。文本帧会返回 `ConsoleErrorCode::BadFrame`。
配置帧大小受后端 4 MiB 硬上限约束。

## 编码

线缆编码名是 `msgpack+nexus-console-v1`，协议版本是 `1`。

帧是与 serde 兼容的 MessagePack 值。服务端用具名字段编码帧。
`ActionCall.input`、`ActionResult.output`、流输入和事件里的 Nexus `Value`
载荷会封装在 `JsonBytes` 中；`JsonBytes` 是外层 MessagePack 帧里的 JSON 字符串。

## 会话顺序

客户端必须按以下顺序：

1. 通过 HTTP 登录，保存 `LoginResponse.token`。
2. 打开控制台 `/ws`。
3. 发送 `ClientFrame::Hello { hello }`，其中 `protocol_version = 1`，
   `accepted_encodings` 包含 `msgpack+nexus-console-v1`。
4. 接收 `ServerFrame::HelloAccepted { metadata }`。
5. 发送 `ClientFrame::Auth { token }`。
6. 接收 `ServerFrame::Authenticated { principal, metadata }`。
7. 使用 `ClientFrame::Call { id, call }` 调用动作，或使用
   `ClientFrame::Subscribe { id, stream }` 订阅流。

`Auth`、动作调用、订阅和取消订阅都要求先完成 `Hello`。动作调用、订阅和取消订阅还需要先完成
`Auth`。之后的每个请求在分发前都会重新校验 session id。

## 客户端帧

| 帧 | 载荷 | 用途 |
| --- | --- | --- |
| `Hello` | `ClientHello` | 协商协议版本和可接受编码。 |
| `Auth` | `token` | 提交 bearer session token。 |
| `Call` | `id`、`ActionCall` | 调用一个有描述符名称的动作。 |
| `Subscribe` | `id`、`StreamCall` | 订阅一个有描述符名称的流。 |
| `Unsubscribe` | `id` | 取消一个订阅。 |
| `Ping` | `nonce` | 保活；服务端返回 `Pong`。 |

`ClientHello`：

| 字段 | 含义 |
| --- | --- |
| `protocol_version` | 客户端支持的主要线缆版本。 |
| `client_name` | 可选客户端应用名称，用于审计和诊断。 |
| `accepted_encodings` | 客户端接受的编码，按偏好排序。 |

`ActionCall`：

| 字段 | 含义 |
| --- | --- |
| `action` | 动作 ID，例如 `config.read` 或 `state.snapshot`。 |
| `input` | Nexus `Value` 的 JSON 字符串，封装在 `JsonBytes` 中。 |
| `scope` | 可选可见性或高风险访问范围。 |
| `justification` | 可选操作理由。 |
| `ttl_ms` | 可选临时授权持续时间。 |

`StreamCall`：

| 字段 | 含义 |
| --- | --- |
| `stream` | 流 ID，例如 `state.watch` 或 `audit.facts.stream`。 |
| `input` | 流过滤条件的 JSON 字符串。 |
| `scope`、`justification`、`ttl_ms` | 受保护流需要的可见性元数据。 |
| `since_rev` | 预留游标；当前控制台流是 live-only，传入该字段会被拒绝。 |

## 服务端帧

| 帧 | 载荷 | 用途 |
| --- | --- | --- |
| `HelloAccepted` | `ProtocolMetadata` | 协议元数据、注册表版本、动作、流、可见性等级和敏感值类别。 |
| `Authenticated` | `PrincipalSummary`、`ProtocolMetadata` | 认证结果和刷新后的协议元数据。 |
| `Reply` | `id`、`ActionResult` | 动作响应或订阅确认。 |
| `Event` | `stream`、`ConsoleEvent` | 流事件投递。 |
| `Pong` | `nonce` | 保活响应。 |
| `Error` | 可选 `id`、`ConsoleErrorCode`、消息 | 协议、认证、校验、授权、速率限制或内部错误。 |

`ConsoleErrorCode` 的取值为 `BadFrame`、`NotAuthenticated`、`Unauthorized`、
`Forbidden`、`Conflict`、`BadRequest`、`RateLimited` 和 `Internal`。

## 动作和流

可用动作与流会通过 `ProtocolMetadata` 发布，也可以用 `protocol.describe`
或 `protocol.registry.snapshot` 获取。这些 metadata 响应会包含 listener 的实际传输安全模式和
unsafe relaxation。

已实现动作族包括：

| 动作族 | 示例 |
| --- | --- |
| 协议和注册表 | `protocol.describe`、`protocol.registry.snapshot`、`protocol.action_descriptor.get`、`protocol.schema.get` 兼容 alias、`registry.coverage.report` |
| 资源与编辑描述符 | `resource.type.list`、`resource.type.describe`、`resource.view.describe`、`graph.type.describe` |
| 授权和可见性 | `authority.principal.effective`、`authority.action.matrix`、`visibility.authority.describe`、`visibility.state.read`、`visibility.state.list` |
| 敏感值托管 | `secret.catalog`、`secret.reveal` |
| 状态和配置 | `state.snapshot`、`config.read`、`config.list`、`config.write_cas` |
| 控制台访问 | `access.user.*`、`access.role.*`、`access.session.*`、`access.session.current.logout` |
| 运行时、审计和来源链 | `runtime.process.inspect`、`audit.facts.recent`、`lineage.trace.read`、`lineage.fact.read`、`lineage.fact.by_operation`、`health.summary` |
| 外部程序和配对 | `external.installation.*`、`pairing.create`、`pairing.approve`、`pairing.deny`、`pairing.replace` |

资源和图描述符提供与编辑器形态无关的语义元数据：资源类型、字段、视图、
revision、关系、图节点类型、port、edge 和校验 hook。它们不指定 UI 组件，
也不能绕过用于校验、授权、CAS 和审计的固定 action descriptor。

注册表可能发布规划中的 action。当前规划中的编辑 envelope 包括
`change_set.create`、`change_set.update`、`change_set.validate`、
`change_set.diff`、`change_set.dry_run`、`change_set.apply` 和
`change_set.discard`；规划 action 可发现但不可执行。

流：

| 流 | 事件来源 |
| --- | --- |
| `state.watch` | 状态后端 watch 事件。 |
| `audit.facts.stream` | 审计事实记录事件。 |

帧大小、连接数、空闲时间、速率、订阅数、结果大小和事件发送限制来自
`[console.ws]`；后端会把配置值限制在硬上限内。
