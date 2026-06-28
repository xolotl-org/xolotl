# 控制台协议

`xolotl-console` 承载控制台客户端使用的管理协议。它提供健康检查和认证用的 HTTP 路由；登录后的管理动作和流订阅通过控制台 WebSocket 运行。

管理动作使用有描述符名称的调用。它们使用运行时的状态、授权、CAS、可见性和审计接口；当管理动作调用运行时效果时，该效果作为受能力约束的 `Operation` 执行。

## 监听地址

控制台 HTTP 和控制台 WebSocket 共用 `[server].console_addr`，环境变量回退为
`XOLOTL_CONSOLE_ADDR`

| 通道 | 路径 | 编码 |
| --- | --- | --- |
| HTTP | `/health`、`/api/auth/*` | HTTP JSON |
| WebSocket | `/ws` | 二进制 protobuf `ConsoleFrame`，`protobuf+xolotl-console-v1` |

## HTTP 路由

控制台 HTTP 路由由 `xolotl-console::router` 提供：

| 路径 | 方法 | 用途 |
| --- | --- | --- |
| `/health` | `GET` | 健康检查 |
| `/api/auth/login` | `POST` | 用户名、密码和可选 TOTP 登录 |
| `/api/auth/key/challenge` | `POST` | 创建公钥登录挑战 |
| `/api/auth/key/login` | `POST` | 提交公钥签名并完成登录 |
| `/api/auth/passkey/register/begin` | `POST` | 为已提权 bearer session 开始注册 passkey |
| `/api/auth/passkey/register/finish` | `POST` | 完成 passkey 注册并保存凭据 |
| `/api/auth/passkey/login/begin` | `POST` | 为指定用户名开始 passkey 登录 |
| `/api/auth/passkey/login/finish` | `POST` | 校验 passkey assertion 并签发 session |
| `/api/auth/step-up` | `POST` | 使用现有 bearer session 提升 MFA 等级 |
| `/api/auth/refresh` | `POST` | 轮换现有 session 的 bearer token |

认证路由要求 `Origin` 和 `Host` 请求头。origin 的 host、port 以及可信 forwarded
scheme 必须匹配控制台监听器对外可见的 host。公钥登录还要求 JSON 里的 `origin`
字段与请求 `Origin` 头完全一致；该值会绑定进签名 transcript。Passkey 路由使用
配置中的 WebAuthn relying-party id 和 origin，不规定任何前端布局或 UI 框架。

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

Passkey 注册 begin 请求：

```json
{"display_name":"Root Operator"}
```

Passkey 注册 begin 和 finish 要求：

```text
Authorization: Bearer <token>
```

Passkey 登录 begin 请求：

```json
{"username":"root"}
```

Passkey finish 请求携带浏览器从 `navigator.credentials.create` 或
`navigator.credentials.get` 返回的 credential response。

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
| `sid` | 会话 ID |
| `token` | `sid.secret` 形式的 bearer token |
| `expires_at` | 绝对过期时间，Unix 毫秒 |
| `idle_expires_at` | 空闲过期时间，Unix 毫秒 |
| `mfa_level` | 会话 MFA 等级 |

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

端点在 `xolotl-console-v1` WebSocket 子协议下接收二进制 protobuf
`ConsoleFrame` 帧。文本帧会返回 `ConsoleErrorCode::BadFrame`。
配置帧大小受后端 4 MiB 硬上限约束。

## 编码

线缆编码名是 `protobuf+xolotl-console-v1`，WebSocket 子协议是
`xolotl-console-v1`，协议版本是 `1`。

帧是 protobuf `xolotl.v1.console.ConsoleFrame` 消息。`ActionCall.input`、
`ActionResult.output`、流输入和事件里的 Xolotl `Value` 都使用原生
`xolotl.v1.Value` 消息，因此控制台客户端与 external gateway 共享同一套
`Value` 和 `Path` protobuf 形状。

## 会话顺序

客户端必须按以下顺序：

1. 通过 HTTP 登录，保存 `LoginResponse.token`
2. 打开控制台 `/ws`
3. 发送 `ClientFrame::Hello { hello }`，其中 `protocol_version = 1`，
   `accepted_encodings` 包含 `protobuf+xolotl-console-v1`。
4. 接收 `ServerFrame::HelloAccepted { metadata }`
5. 发送 `ClientFrame::Auth { token }`
6. 接收 `ServerFrame::Authenticated { principal, metadata }`
7. 使用 `ClientFrame::Call { id, call }` 调用动作，或使用
   `ClientFrame::Subscribe { id, stream }` 订阅流。

`Auth`、动作调用、订阅和取消订阅都要求先完成 `Hello`。动作调用、订阅和取消订阅还需要先完成
`Auth`。之后的每个请求在分发前都会重新校验 session id。

## 客户端帧

| 帧 | 载荷 | 用途 |
| --- | --- | --- |
| `Hello` | `ClientHello` | 协商协议版本和可接受编码 |
| `Auth` | `token` | 提交 bearer session token |
| `Call` | `id`、`ActionCall` | 调用一个有描述符名称的动作 |
| `Subscribe` | `id`、`StreamCall` | 订阅一个有描述符名称的流 |
| `Unsubscribe` | `id` | 取消一个订阅 |
| `Ping` | `nonce` | 保活；服务端返回 `Pong` |

`ClientHello`：

| 字段 | 含义 |
| --- | --- |
| `protocol_version` | 客户端支持的主要线缆版本 |
| `client_name` | 可选客户端应用名称，用于审计和诊断 |
| `accepted_encodings` | 客户端接受的编码；当前必须包含 `protobuf+xolotl-console-v1` |

`ActionCall`：

| 字段 | 含义 |
| --- | --- |
| `action` | 动作 ID，例如 `config.read` 或 `state.snapshot` |
| `input` | 原生 `xolotl.v1.Value` protobuf 消息 |
| `scope` | 可选可见性或高风险访问范围 |
| `justification` | 可选操作理由 |
| `ttl_ms` | 可选临时授权持续时间 |

`StreamCall`：

| 字段 | 含义 |
| --- | --- |
| `stream` | 流 ID，例如 `state.watch` 或 `audit.facts.stream` |
| `input` | 原生 `xolotl.v1.Value` 流过滤条件 |
| `scope`、`justification`、`ttl_ms` | 受保护流需要的可见性元数据 |
| `since_rev` | 预留字段；客户端必须省略。当前流是 live-only，传入会被拒绝 |

## 服务端帧

| 帧 | 载荷 | 用途 |
| --- | --- | --- |
| `HelloAccepted` | `ProtocolMetadata` | 协议元数据、注册表版本、动作、流、可见性等级和敏感值类别 |
| `Authenticated` | `PrincipalSummary`、`ProtocolMetadata` | 认证结果和刷新后的协议元数据 |
| `Reply` | `id`、`ActionResult` | 动作响应或订阅确认 |
| `Event` | `stream`、`ConsoleEvent` | 流事件投递 |
| `Pong` | `nonce` | 保活响应 |
| `Error` | 可选 `id`、`ConsoleErrorCode`、消息 | 协议、认证、校验、授权、速率限制或内部错误 |

`ConsoleErrorCode` 通过 protobuf `ConsoleError` 帧传输。服务端会把协议、
认证、授权、校验、冲突、速率限制和内部错误映射到规范的控制台错误枚举。

## 动作和流

可用动作与流会通过 `ProtocolMetadata` 发布，也可以用 `protocol.describe`
或 `protocol.registry.snapshot` 获取。这些元数据响应会包含监听器的实际传输安全模式和
不安全传输放宽项。

已实现动作族包括：

| 动作族 | 示例 |
| --- | --- |
| 协议和注册表 | `protocol.describe`、`protocol.registry.snapshot`、`protocol.action_descriptor.get`、`registry.coverage.report` |
| 资源与编辑描述符 | `resource.type.list`、`resource.type.describe`、`resource.view.describe` |
| 授权和可见性 | `authority.principal.effective`、`authority.action.matrix`、`visibility.authority.describe`、`visibility.state.read`、`visibility.state.list` |
| 敏感值托管 | `secret.catalog`、`secret.reveal` |
| 状态和配置 | `state.snapshot`、`config.read`、`config.list`、`config.write_cas`，仅用于没有专用 action 的配置 |
| 控制台访问 | `access.user.*`、`access.role.*`、`access.session.*`、`access.session.current.logout` |
| 运行时、审计和来源链 | `runtime.process.inspect`、`audit.facts.recent`、`lineage.trace.read`、`lineage.fact.read`、`health.summary` |
| 外部程序和配对 | `external.manifest.*`、`external.installation.*`、`pairing.create`、`pairing.approve`、`pairing.deny`、`pairing.replace` |
| 进程内 projection 状态 | `projection.in_process.status.list`、`projection.in_process.status.read` |
| Inference 路由 | `inference.backend.*`、`inference.model.*`、`inference.group.*`、`inference.routing.*` |

上表只列出可执行的动作族。每个 action 描述符还包含
`implementation_status`；状态为 `planned` 或 `blocked_by_custody` 的描述符
只用于覆盖范围统计和授权解释，直接发起 `Call` 会返回错误。

泛用 `config.*` action 会拒绝已经有专用动作族的运行时配置路径。对这些
路径使用 `access.*`、`external.*`、`inference.*` 和 `pairing.*`，让校验、
授权、CAS 和审计绑定到声明的资源类型。进程内 Provider/Source projection
声明通过 `config.*` 写入 `state://kernel/projections/in-process/<id>`，并走
共享 kernel config 准入。Projection status 只通过
`projection.in_process.status.*` 读取。
External projection 是 external installation 声明的一部分，仍通过
`external.installation.*` 管理。

资源和图描述符提供与编辑器形态无关的语义元数据：资源类型、字段、视图、
revision、关系、图节点类型、port、edge 和校验 hook。它们不指定 UI 组件，
也不能绕过用于校验、授权、CAS 和审计的固定 action 描述符。

流：

| 流 | 事件来源 |
| --- | --- |
| `state.watch` | 状态后端 watch 事件 |
| `audit.facts.stream` | 审计事实记录事件 |

帧大小、连接数、空闲时间、速率、订阅数、结果大小和事件发送限制来自
`[console.ws]`；后端会把配置值限制在硬上限内。
