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

帧大小、连接数、空闲时间、速率、订阅数、结果大小、队列和发送限制来自
`[console.ws]`；后端会把配置值限制在硬上限内。

## 出站限制

`max_frame_bytes` 同时约束入站和出站 protobuf 帧，默认 1 MiB，范围为 16 KiB 至 4 MiB。
转换前检查累计内联字节、最多 16,384 个 Value 节点、30 层 Value 嵌套和 256 个路径段，
通过后才克隆线缆载荷。完整 protobuf 消息还必须通过精确帧字节检查，随后才能分配编码
输出缓冲区。超限 Value 不会被截断。

`send_timeout_ms` 约束所有出站帧，包括回复和错误，默认 5 秒，范围为 100 毫秒至 60 秒。
它替代 `event_send_timeout_ms`。回复无法在预算内编码时，服务端返回携带原请求 ID 的
小型 `Internal` 错误。此时动作可能已经完成，错误不表示回滚，也不表示可以安全重试。
传输错误或发送超时会关闭连接。

每个连接的实时订阅共用一个最多 256 条的队列。`max_pending_event_bytes` 约束排队及
正在发送的订阅数据编码字节，默认 1 MiB，范围为 16 KiB 至 16 MiB。每个 worker 在尝试
入队前最多准备一帧有界数据，不会持有未计费帧等待队列空间。条数或字节预算耗尽都会
关闭产生该事件的订阅。独立控制路径最多保留 `max_subscriptions` 条各不超过 1 KiB
的关闭原因和一条正在发送的关闭帧，不计入数据预算。此预算也不包含来源广播存储、原生动作输出、转换临时结构、
socket 缓冲区或整个进程的内存。

State 和 Fact worker 统一由会话管理。lag、来源关闭、投影或编码失败、worker 异常
都会释放订阅名额并产生 `SubscriptionClosed`。关闭使该代订阅尚未发送的尾部失效；
旧事件和旧关闭通知不能影响使用相同 ID 的新订阅。会话关闭或被取消时会中止所属任务。
全部 worker 共用 250 毫秒的关闭期限，无法完成关闭则终止会话。
该期限约束异步等待；Tokio 无法强行抢占同步适配器工作或阻塞的析构函数，宿主适配器
仍需配合取消。

订阅可见性按请求的 `ttl_ms` 到期，最长十分钟。过期丢弃待发送数据并产生
`SubscriptionClosed`。成功 `Auth` 会在接纳新会话前清理旧订阅。每次事件发送都会
重新认证 SID；身份、有效权限集合或 MFA 级别发生变化时关闭连接，重新建立授权和订阅。
数据发送取可见性期限和发送超时的较早者，并在 socket 可写后再次检查是否过期。
已经交给 socket 的数据无法撤回。旧代次排队数据在出队丢弃前仍占队列额度，因此立即
替换的订阅仍可能遇到队列压力。

## Fact 查询

`audit.facts.recent` 返回一页反向追加顺序的记录，默认 64 条。
`lineage.trace.read` 要求指定 `process`，返回一页正向追加顺序的记录，默认 128 条。
两者均接受 `from`、`before`、`limit`、`max_bytes`、`max_examined`；recent 还接受
可选 `process`。游标与进程编号输入接受非负整数或十进制 `u64` 字符串；游标及数值标识符
投影输出为十进制字符串，避免客户端丢失精度。`op_id` 保留组合 OperationId 字符串格式。
`from` 表示全局物理追加位置，即使按进程过滤也不表示
匹配记录的行偏移。读取方向由动作固定。

页面输出字段如下：

| 字段 | 含义 |
| --- | --- |
| `items` | 按追加顺序排列的 Fact 投影；`completed` 反映当前完成状态 |
| `from`、`end` | 本页追加区间的包含下界和排他上界 |
| `next` | 十进制续页游标；区间结束时为 `null` |
| `order` | `forward` 或 `reverse` |
| `complete` | 本页是否已读完追加区间 |
| `examined` | 已访问候选数，包括被过滤或因字节预算不足而拒绝的候选 |
| `encoded_bytes` | 返回 Fact 在投影前的 JSON 编码长度之和 |
| `process` | 传入时返回所选进程 |

recent 用 `before=next` 和相同 `from` 续页；trace 用 `from=next`、`before=end` 续页，
保留筛选条件和预算。空页仍可能有续页，反向分页逐步缩小上界。固定追加区间排除后续
追加，但旧槽位的完成结果仍可能更新。trace 另返回 `partial=true` 和 `partial_reason`，
说明没有包含物化的来源链索引；这与分页是否完成无关，不再返回全历史 trace 总数。

条数受监听器的 Fact 或 trace 上限约束。JSON 字节上限为
`min(max_frame_bytes / 8, 256 KiB)`，为投影和帧预留空间。出站转换和精确帧大小仍需
通过各自独立的预算检查。
候选检查数默认 `max(limit, 4096)`，最高 65,536。零预算无效，超出上限的请求按上限执行。
第一个匹配记录超过字节预算时读取失败。`lineage.fact.read` 使用有字节限制的索引点查，
同样接受 `max_bytes` 和可选 `process`，后者默认 `op_id.process`。动作要求所选进程的
读取权限，并只返回当前调用进程与之匹配的记录；归属不同则返回未知记录，不暴露内容。
这些限额不计量解码堆或总内存。

`runtime.process.inspect` 和 `state.snapshot` 的 `runtime` section 默认只读元数据。
`include_recent_facts=true` 要求显式 `process`、对应 `state://fact/<process>` 的读取权限，
以及动作要求的可见性元数据。`recent_facts` 是一页有界反向结果，不再返回全历史
`fact_count`。一次快照最多接受一个 runtime section。进程行及 children 是独立集合，
目前仍未分页。

`health.summary.fact_sample` 包含 `sampled_facts`、`decisions` 和相同的页面元数据，
计数仅代表近期样本；原来的全局 `fact_count`、`fact_decisions` 字段已移除。
顶层 `fact_cursor` 是单独观察的十进制追加上界，不跟踪完成更新，也不保证与样本同一视图。
进程统计仍然枚举进程表。

## 实时审计

`audit.facts.stream` 只接收订阅后的通知，不回放历史。可选 `process` 在检查字节预算之前
筛选当前记录，无关进程的超大记录会被忽略。新增和完成更新都会触发有界索引重读；
事件以 `op_id` 为键表示 upsert。
通知可能不按提交顺序到达，也可能重复返回当前值。客户端应替换对应身份的记录，
不能把每个通知计为一个新 Fact。

积压导致 lag、记录消失或有界读取失败时，发送 `SubscriptionClosed` 并释放订阅名额。
上述共享生命周期和队列限制同样适用。关闭后应重新订阅，再通过显式有界分页核对保留记录，包括
可能更新过完成结果的旧槽位。先建立实时订阅再分页可缩小间隙；再次 lag 时重做核对。
这不提供原子快照或持久更新日志。

`StreamCall.since_rev` 是预留字段，当前拒绝传入。线缆 `ConsoleEvent.state_rev` 和
`fact_cursor` 保持零，`SubscriptionClosed.last_rev` 省略。追加游标无法恢复旧槽位的
完成更新。protobuf 信封结构保持不变，分页动作输出及精确标识符投影替换了原来的
Value 载荷形状。
