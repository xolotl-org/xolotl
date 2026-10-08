# Console 动作与流

WebSocket 承载与 Rust service、HTTP `/calls` 相同的已认证动作；实时订阅共用 Console 服务的准入与生命周期。服务入口见[控制台协议](console-protocol.md)，HTTP 端点见[HTTP 与凭据](console-http-and-credentials.md)。

## WebSocket 升级

Daemon 默认将控制台 WebSocket 挂在 `/api/console/v1/ws`。嵌入式宿主可将所选的相对 `/ws` 端点挂在其他前缀，也可不安装它。端点路径相对于宿主挂载点；宿主发布 `HttpApi::manifest` 时可从中读取该路径。升级时会检查：

- `Origin` 请求头存在且可解析；
- `Host` 请求头存在；
- origin host 和 port 与对外可见 host 匹配；
- 来源级连接限制仍有容量。

端点在 `xolotl-console-v1` WebSocket 子协议下接收二进制 protobuf `ConsoleFrame` 帧。文本帧会返回 `ConsoleErrorCode::BadFrame`。配置帧大小受后端 4 MiB 硬上限约束。

## 编码

自定义适配器可在不启用 `http` feature 时使用 `wire::decode_client_frame(bytes, max_frame_bytes)` 和 `wire::encode_server_frame(frame, max_frame_bytes)`。验证连接和来源证明后，在收取或解码携带调用的帧前通过 `ConsoleService::admit_call()` 保留共享调用容量；解码成功后以 `ConsoleCallAdmission::call` 消费许可，失败时丢弃许可。HTTP `/calls` 遵循此顺序。适配器自行限制字节量和收取期限。在 Prost 分配客户端消息前，解码器先检查帧字节上限，再扫描所有编码的调用及订阅输入，包括后来被重复 oneof 覆盖的字段。整帧最多允许 16,384 个 `Value` 节点和 30 层嵌套；未显式提供 value 的 map entry 也计为一个节点。帧字节上限约束线缆内联载荷。这些是 protobuf 转换工作量限制，独立于 runtime 输入与 Kernel 进程预算，并非进程运存上限。完成响应无法编码时，`wire::delivery_failure` 保留已知执行引用，不表示效果回滚或可以安全重试。

线缆编码名是 `protobuf+xolotl-console-v1`，WebSocket 子协议是 `xolotl-console-v1`，协议版本是 `1`。`ProtocolGreeting` 报告该编码，Hello 不协商其他编码。

帧是 protobuf `xolotl.v1.console.ConsoleFrame` 消息。`ActionCall.input`、`ActionResult.output`、流输入和事件里的 Xolotl `Value` 都使用原生 `xolotl.v1.Value` 消息，因此控制台客户端与 external gateway 共享同一套 `Value` 和 `Path` protobuf 形状。共享的 `value_from_pb` 解码器会拒绝损坏的嵌套值及未知的 null 枚举值，不会将其静默替换为 `Null`。v1 中外层 `Value` 的空 oneof 仍表示 `Null`。

## 会话顺序

客户端必须按以下顺序：

1. 通过共享同一 `ConsoleState` 的认证适配器取得已认证会话的 `token`，并完成必要的 continuation；daemon 默认使用 HTTP 认证。
2. 打开宿主挂载点下所选的控制台 `/ws` 端点（daemon 默认是 `/api/console/v1/ws`）。
3. 发送 `ClientFrame::Hello { hello }`，其中 `protocol_version = 1`，可选填 `client_name`。
4. 接收 `ServerFrame::HelloAccepted { metadata, transport }`
5. 发送 `ClientFrame::Auth { token }`
6. 接收 `ServerFrame::Authenticated { principal, metadata }`
7. 使用 `ClientFrame::Call { id, call }` 调用动作，或使用 `ClientFrame::Subscribe { id, stream }` 订阅流。

`Auth`、动作调用、订阅和取消订阅都要求先完成 `Hello`。动作调用、订阅和取消订阅还需要先完成 `Auth`。之后的每个请求在分发前都会重新校验 session id。

## 客户端帧

| 帧 | 载荷 | 用途 |
| --- | --- | --- |
| `Hello` | `ClientHello` | 确认固定的 v1 协议版本 |
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

`ActionCall`：

| 字段 | 含义 |
| --- | --- |
| `action` | 动作 ID，例如 `config.read` 或 `state.snapshot` |
| `registry_rev` | 可选描述符版本前置条件；不匹配时拒绝执行，客户端应先刷新元数据 |
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
| `registry_rev` | 可选的已发现注册表 revision；过期时在执行前返回 `registry_changed` |

## 服务端帧

| 帧 | 载荷 | 用途 |
| --- | --- | --- |
| `HelloAccepted` | `ProtocolGreeting`、`TransportSecuritySummary` | 轻量服务元数据及当前适配器的传输策略 |
| `Authenticated` | `PrincipalSummary`、`ProtocolGreeting` | 认证结果和刷新后的轻量元数据 |
| `Reply` | `id`、`ActionResult` | 动作响应或订阅确认 |
| `Event` | `stream`、`ConsoleEvent` | 流事件投递 |
| `Pong` | `nonce` | 保活响应 |
| `Error` | 可选 `id`、`ConsoleFailure` | 脱敏错误类别、消息及已知恢复信息 |

`ConsoleErrorCode` 通过 protobuf `ConsoleError` 帧传输。服务端会把协议、认证、授权、校验、冲突、速率限制和内部错误映射到规范的控制台错误枚举。每个 `ActionResult` 都返回本次使用的 `registry_rev`，包括无输出的修改结果和订阅确认。安装观察存储时，`server_rev` 是观察到的 Fact 追加游标，否则为零。禁用的观察动作和流不出现在 discovery 中；零不证明历史为空。State 并发编辑仍使用记录自身的版本。

没有观察存储时，`state.snapshot.fact_cursor`、`health.summary.fact_cursor` 与 `health.summary.fact_sample` 返回 `null`；State 与运行时观察仍可用。显式请求 recent Fact 须安装 sink。

## 动作和流

`runtime.operation.submit` 与 `runtime.program.submit` 可选传入 `submission_identity` map，其中 `registry_instance`、规范的无符号十进制字符串 `retry_epoch` 和 `nonce` 均为必填字段。不传时，不同 submit 调用仍不幂等。`runtime.describe` 以 `submission_retry_scope` 返回当前实例与 epoch；受保护重试保留原执行引用与期限，不重新编译。`runtime.submission.lookup` 要求该身份，仅返回 `evidence` 和可空的 `execution`，不返回输出，也不产生副作用。`preparing` 不表示已接受，`unproven` 不证明没有发生效果。共享逻辑配额及受信宿主关闭 epoch 的规则见[独立提交与结果保留](console-runtime.md#独立提交与结果保留)；重启后拒绝旧实例身份。

动作和订阅按描述符校验输入：未知字段、缺失必填项和错误类型均被拒绝。`definitions` 定义命名字段类型，`list<T>` 逐项校验，`T|null` 显式允许 null，`max_items` 限制列表长度。`snapshot_section` 通过 `discriminator`（`kind`）与 `variants` 选择分支 schema；服务端使用同一份定义校验嵌套输入。无必填字段的 map 可省略顶层输入；无输入动作声明为 `null`。

输入类型 `string` 要求非空；`u8`、`u32`、`u64`、`usize` 和 `positive_usize` 使用各自范围的 Xolotl 整数，`decimal_u64` 还接受纯数字十进制字符串。`path`、`path-pattern` 和 `operation_id` 检查语法，具体目标及资源约束由领域处理器校验。动作描述符的 step-up 门槛由共享服务执行，目标授权仍由领域处理器检查。

`protocol.describe` 返回 `ProtocolGreeting`：协议版本、服务名称、编码、Fact 游标、注册表 revision 和观察时间。握手与认证帧携带同样的轻量服务信息，帧大小不受能力目录规模影响。Hello 单独携带 `transport`，与 HTTP manifest 复用 `TransportSecuritySummary`：`mode`、`unsafe_transport`、`relaxations`。这些字段描述配置的准入策略，不证明端到端 TLS。认证响应不重复该连接已通过 Hello 返回的传输摘要。

认证后，通过 `protocol.registry.snapshot` 获取 `RegistrySnapshot`，其中包含上述轻量字段，以及动作和流的 schema、root 可见性约定、可见性等级和两种秘密托管类别 `non_recoverable_secret`、`one_time_secret`。描述符使用服务端实际校验所用的原生 schema 序列化为 Console `Value`，不再维护另一套 Protobuf 描述符模型。客户端按 `registry_rev` 缓存目录；revision 取决于契约和宿主运行时配置，不受时钟或 Fact 游标影响。

资源视图提供实际输入、输出 schema 和游标分页，不承诺服务端文本筛选或自定义排序。资源摘要由完整类型描述符生成；`registry_rev` 覆盖动作、流、资源类型、摘要和视图，编辑元数据变化也会使缓存失效。修订检查先于动作名称解析，因此旧名称也返回 `REGISTRY_CHANGED`，客户端应刷新目录。

Rust 服务和各适配器共用 `ConsoleFailure`，其 `code` 和脱敏 `message` 之外只含失败时已知的事实。`UNAUTHENTICATED` 表示缺失或无效凭据，`FORBIDDEN` 表示权限不足，`STEP_UP_REQUIRED` 携带要求的 MFA 等级，`REGISTRY_CHANGED` 表示目录过期，`VERSION_CONFLICT` 表示 CAS 冲突，`ADMISSION_REJECTED` 表示领域输入拒绝，`OUTCOME_UNKNOWN` 表示无法确定效果是否完成。HTTP `/calls` 对前六类分别映射到 401、403、403、409、409、422；容量满返回 429。

| 恢复字段 | 含义 |
| --- | --- |
| `retry_after_ms` | 已知的限流等待时间；释放时间未知时省略 |
| `required_mfa_level` | 本次准入所要求的 MFA 等级 |
| `mfa` | 可选的账户因素摘要；仅在主凭据或 bearer 验证后披露，普通动作 step-up 不携带 |
| `current_registry_rev` | 拒绝过期契约时观察到的目录版本 |
| `current_version` | CAS 比较失败时观察到的记录版本；省略不表示记录不存在 |
| `execution` | 已分配的 `process_id`、`program_id` 与可选 `execution_id`，预检、执行及收尾失败均保留 |
| `outcome_unknown` | 宿主签发的 `operation_ids` 列表与受控 `reason`，表示效果可能已执行，但无法确认结果；列表只包含已知需要核对的身份，并发调用可能有多个；它不是完整效果账本，空列表也不证明未发生效果。未识别的宿主原因归为 `unclassified`，其他失败不携带 |

`ActionResult` 携带可选 execution 与必要未决效果身份；响应编码失败继续保留已知引用。引用不授予进程或 Fact 读取权限；`execution_id` 需重新授权，不能作为去重凭据。Source 命令的 `operation_ids` 只含一个出站命令 ID，该 ID 派生自调用方的 Kernel OperationId；Source 回传同名错误文本也不能设置这个可信字段。HTTP `/calls` 对该代码返回 500。失败可能已有部分副作用；该状态不证明回滚，重试前须核对效果。已启动的 Kernel 评估若未在 Console 的有界等待内完成，返回 `OUTCOME_UNKNOWN`，其中 `operation_ids: []`、`reason: "settlement_timeout"`；空列表表示未取得身份，应在可用时核对进程与 Fact 证据。Kernel 自身在期限处报告未知结果时会列出尚未完成的 Operation ID。准入超时、取消和订阅缺少终结事件也不证明未执行效果。Kernel 已结算的取消可报告观察到的未决 ID；响应丢失或有界结算超时仍可能无法取得它们。已知等待时间才产生向上取整到秒的 HTTP `Retry-After`，响应体保留毫秒值；这些字段不保证安全重试。

动作族包括：

| 动作族 | 示例 |
| --- | --- |
| 协议和注册表 | `protocol.describe`、`protocol.registry.snapshot`、`protocol.action_descriptor.get` |
| 资源与编辑描述符 | `resource.type.list`、`resource.type.describe`、`resource.view.describe` |
| 授权和可见性 | `authority.principal.effective`、`authority.action.matrix`、`visibility.authority.describe`、`visibility.state.read`、`visibility.state.list` |
| 敏感值目录 | `secret.catalog` |
| 状态和配置 | `state.snapshot`、`config.read`、`config.list`、`config.write_cas`，仅用于没有专用 action 的配置 |
| 控制台访问 | `access.user.*`、`access.role.*`、`access.session.*`、`access.session.current.logout` |
| 运行时、审计和来源链 | `runtime.process.inspect`、`audit.facts.recent`、`lineage.trace.read`、`lineage.fact.read`、`health.summary` |
| 外部程序和配对 | `external.manifest.*`、`external.installation.*`、`external.source.claim.inspect`、`external.source.event.decision.inspect`、`pairing.create`、`pairing.approve`、`pairing.deny` |
| 联邦目录 | `federation.peer.read/list/write_cas`、`federation.peer_admission.read/write_cas`、`federation.export.read/list/write_cas`；仅安装本地管理端口时可用 |
| 进程内 projection 状态 | `projection.in_process.status.list`、`projection.in_process.status.read` |
| Inference 路由 | `inference.backend.*`、`inference.model.*`、`inference.group.*`、`inference.routing.*` |

`pairing.create` 的 action 输入对象直接包含必填的 `pairing_id`、`installation_id`，可选 `allowed_roles`、`expires_at`、`reveal_display_secret`；没有嵌套的 `input` 字段。例如：

```json
{"pairing_id":"pair-sensor-1","installation_id":"sensor-hub","reveal_display_secret":true}
```

调用方须在请求前选定并保存配对 ID。设置 `reveal_display_secret: true` 后，结果可携带一次性的 `display_secret`：64 个十六进制字符，编码 32 字节外部会话密钥。完成配对流程前，外部程序须把它保存到自己的凭据托管处；Console 边界交付时即消耗该值，之后无法列出或找回。Operation 与 Fact 只保存 hash／checksum 元数据。它属于外部 Provider/Source 凭据，与 Console 账号凭据及 Source 事件提交凭据不同。会话 wire 规则见 [External Gateway](external-gateway.md)。

要放弃仍处于 `created` 的旧配对意图并重新开始，先对旧 ID 调用 `pairing.deny`，再用新 ID 调用 `pairing.create`。这是两个独立操作，没有单次原子替换语义；响应结论未知时，先查询各自配对记录，再处理尚未完成的步骤。`pairing.deny` 不接受已批准的意图。如果新意图已创建但一次性 `display_secret` 未被安全收到，仅当当前 daemon 进程可能仍持有未交付的一次性展示值时，才可用相同 ID 与相同规范意图重试创建。重启后或 Console 边界已消费展示值后，不能从 vault 密钥重建展示结果；此时须拒绝该新意图并换新 ID 创建。

上表只列出可执行的动作族。`secret.catalog` 只列秘密元数据；通用可见性读取和订阅拒绝 vault 路径。秘密只通过拥有该凭据的具体授权流程交付，例如配对的一次性展示边界。凭据生命周期使用类型化 Rust 服务及清单中的 JSON 入口。

泛用 `config.*` action 会拒绝已经有专用动作族的管理路径。对这些路径使用 `access.*`、`external.*`、`inference.*` 和 `pairing.*`，让校验、授权、CAS 和审计绑定到声明的资源类型。进程内 Provider/Source projection 声明通过 `config.*` 写入 `state://kernel/projections/in-process/<id>`，由宿主安装的命名空间校验器检查路径和内容。Projection status 只通过 `projection.in_process.status.*` 读取。External projection 是 external installation 声明的一部分，仍通过 `external.installation.*` 管理。

`external.installation.read` 和 `.list` 返回包含 `definition`、`installation_epoch` 和 Source `scope_epochs` 的记录。更新或卸载时，把记录的 `definition.version` 作为 `expected_version`，`installation_epoch` 作为 `expected_installation_epoch`；两者必须一起提供。同 ID 退休重装后的版本可能又是 1，但新代次会拒绝旧更新或卸载请求。

动作描述符给出身份、风险、可见性、step-up、权限模板和输入／输出 schema；流描述符给出相应订阅元数据与输入／事件 schema。资源类型列表从完整资源描述符派生，仅列可用类型；每条 `resource.type.list` 摘要有 `resource_type`、`title`、`default_view`、`read_action`、`update_action` 五项。完整资源描述符还提供语义字段、视图和固定动作关联。`revision_field` 是更新动作的 CAS 输入字段；动作不提供 CAS 时为 null。描述符不指定 UI 组件，也不能绕过动作校验、授权和审计。

动作和流描述符用 `authority_templates` 声明模板，包括可选目标。`authority.action.matrix` 与 `authority.action.explain` 提供权限模板和已知门槛提示。每行包含 `templates_covered`，各模板的 `coverage` 为 `unconditional`、`predicate_bound`、`uncovered` 或 `invalid_template`。模板未覆盖不等于调用被拒绝：较窄的授权可能覆盖具体资源，模板也可能对应可选 section。没有更早的 MFA 或可见性门槛时，这些行返回 `input_required`；`preconditions_met` 同样只是当前已知准入门槛的提示，不是实现状态。具体目标与操作可通过 `authority.resource.access` 检查，实际动作仍会按输入和当前策略授权。该检查接受内核方法的具体权限动词（包括 `append`、`publish`）以及 `spawn-with`、`act-as`、`delegate`；不接受通配符作为被检查的动词。

流：

| 流 | 事件来源 |
| --- | --- |
| `state.watch` | 状态后端 watch 事件 |
| `audit.facts.stream` | 审计事实记录事件 |
| `runtime.operation.stream` | 执行一个已安装方法，交付其输出和最终结果 |
| `runtime.program.stream` | 执行可移植 Program，分别标识各 Operation 的输出端口 |

`state.watch` 的 Set、Append、DropPrefixAppend、Delete 事件均携带 `source` 来源摘要，固定包含 `tainted`、`author_constant`、`model_output`、`inbound`、`fetched` 和 `protected` 六个布尔字段。Set 表示替换值的来源；Append 合并追加项与原序列的来源；DropPrefixAppend 从已有列表头部移除 `removed` 项，再追加 `item`，并保留序列的保守来源；Delete 保留被删除记录的来源。Source 的 `DropOldest` 发出实际移除数；已有 sink 超过当前容量时，该数可大于一。增量事件需要已知的先前值；流发生 lag 后须重新读取当前 State，因为该流不能重放错过的事件。原始数据的六项来源摘要字段均为 false。这是来源摘要，不是无损 `TaintSet`：即使可观察业务路径，也不会交付入站 source/channel、抓取 host 或受保护来源路径。来源类别本身不授予底层来源的读取权限。runtime 输出中的 `taint` 属于独立的无损执行事件信封，遵守自身的授权与交付限制。

帧大小、连接数、空闲时间、速率、订阅数、队列和发送限制来自 `[console.ws]`；查询条数和字节预算来自 `[console.queries]`。后端会把配置限制在硬上限内。

## Source 提交证据检查

`external.source.claim.inspect` 和 `external.source.event.decision.inspect` 复用现有 `Call` 入口，包括 HTTP `/calls`。宿主须安装 `ConsoleConfig.source_management: Some(Arc<dyn SourceManagement>)`，默认不安装。该单一端口组合声明准入、安装目录和私有检查，不授予 Console 事件提交或维护权；daemon 从 Source ingress 使用的同一存储实例注入；没有 external 监听器的构建也可检查存量凭据。未安装端口返回 `BAD_REQUEST`，不会返回 `unproven` 或回退读取 State。

| 输入字段 | 约束 |
| --- | --- |
| `installation_id` | 1–256 字节的字面身份段 |
| `projection_id` | 1–256 字节的字面身份段 |
| `scope_epoch` | Source 投影的正十进制存储代次 |
| `stream_epoch` | 有序事件必须提供其正十进制流代次；无序事件省略 |
| `event_id` | 1–256 字节的字面事件身份段 |
| `claim_id` | 仅精确 claim 查询需要；来自可信宿主事故日志的 32 位小写十六进制字符串 |

`ActionCall.justification` 最多 1024 字节，去除两端空白后不能为空。共享服务要求有效会话及至少为 2 的 MFA 等级，并核验该账户当前能力是否覆盖具体目标 `effect://external/source/{installation_id}/{projection_id}/claims/inspect` 的 `perform`。例如可只授予 `perform://effect/external/source/chat/inbox/claims/inspect`，允许检查单个投影。State 可见性及 Source 会话凭据均不授予此权限。该动作不增加认证新鲜度要求。身份与理由在 Console 披露边界核验，不编码为私有 Source 审计记录。

按事件查询使用 `external.source.event.decision.inspect`，使用安装、投影、scope 代次、可选流代次及 event ID，不需要 `claim_id`。有序事件的 event ID 在流代次内去重；同名流退休后重开可复用该 ID，检查时必须提供相应代次，不能靠 ID 猜测。该动作单独要求具体目标 `effect://external/source/{installation_id}/{projection_id}/events/inspect` 的 `perform`。该动作读取当前保留的已接受事件决策及其精确 receipt；它不能枚举事件、推断已清理的决策，也不能证明一次未知尝试未提交。若同一 event ID 在原窗口后再次被接受，查询只返回当前决策，不能证明它就是待调查的旧尝试。保留窗口内，用同一 ID 改换 payload 或有序流位置会得到确定的身份冲突；原接受决策与凭据保持不变，检查不会报告被拒尝试。两种动作都逐次重新核验当前授权。

结果为 `{"status":"unproven"}`，或 `{"status":"committed","receipt":{...}}`。receipt 包含 `installation_id`、`projection_id`、`scope_epoch`、可选 `stream_epoch`、`event_id`、十六进制 `claim_id`、`sink` 和 `received_at_ms`，不包含事件 payload。存储端口在同一个一致、只读视图中读取精确身份，不写私有检查审计。观察审计归宿主披露边界，不要求 Console 与 Source 双重提交。当前账户权限、MFA、具体目标授权、理由及最终交付复核仍不可省略。返回其他身份的凭据时拒绝披露；存储提交不确定时，恢复拥有者重开之前拒绝核对读取。见[Source 检查合同](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-source/src/lib.rs)。安装删除后仍可检查尚未回收的旧凭据；动作不修改 sink、不执行去重维护、不删除 claim，也不重放事件。

Gateway 只在 Source 提交结果不确定时，将精确 claim 身份（含有序事件的 `stream_epoch`）写入宿主日志。Source ACK 不公开 `claim_id`。日志丢失时，按事件查询仍可找回**该身份当前保留的已接受决策**；有序事件还须从 Source 的 Open 回执或控制日志取得 `stream_epoch`，仅靠 event ID 无法定位已退休流的旧决策。清理后的决策无法重建，包括仅 ACK 交付失败且已过保留期的情况。`unproven` 可能表示凭据已过期或不可用；这个结果及错误都不证明回滚，也不授权补偿。提交和保留边界见[外部网关](external-gateway.md)。

## 联邦目录管理

目录 CAS 回复描述本地存储判定，不证明远端交付。目录提交不确定时，结构化 `OUTCOME_UNKNOWN` 要求先读取确切行再决定是否重试；没有回复不等于拒绝。联邦 Session 错误使用自己的 `SyncFailure.commit_verdict`，不是 Console 错误码或消息。嵌入联邦客户端时保留这一结构化远端判定，不从传输不可用或净化文本推断未提交；见[联邦客户端失败合同](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-federation-grpc/src/delivery.rs)。

宿主可把与联邦 Session 共用的 `FederationManagement` 存储端口注入 `ConsoleConfig.federation_management`。动作只修改本机目录，不经联邦会话向对端授予 Console 权限。未安装端口时，注册表不发布这些动作。stock daemon 启用联邦时安装同一个 redb 目录；启动配置拥有的 peer、在线准入和 export 行只能通过配置清单更改，Console 的 CAS 只能创建或更新应用拥有的行，归属检查在存储事务内完成。

所有动作使用 96 位小写十六进制 `peer_node`。`federation.peer.write_cas` 写入 `enabled`；`federation.peer_admission.write_cas` 写入正数 `minimum_online_generation` 及 `allowed_authorization_digests`，后者最多包含 8 个 96 位小写十六进制 SHA-384 摘要，允许空列表撤去在线准入。`federation.export.read/write_cas` 另指定字面 `export`；写入同时指定 `serve`、`receive`。三种写入都接受可选的 `expected_revision`：省略或传 `null` 表示只创建，更新必须传读到的正修订号。修订号和最低在线代次以十进制字符串返回，输入也接受正整数。记录返回 `owner`，取值为 `application` 或 `manifest`。结果不确定时先点读原行核对，不能盲目重复创建或修改。

peer 点读与写入要求 `state://kernel/federation/peers/{peer_node}` 的相应 `read`／`write` 权限；在线准入使用其 `/online-admission` 子路径，export 使用 `/exports` 子路径。所有写入都要求 MFA 等级至少为 2，并核验具体目标权限。`federation.peer.list` 要求整个 `state://kernel/federation/peers` 子树的无条件读权限；`federation.export.list` 要求该 peer 的 `/exports` 子树的无条件读权限。两种列表分别使用排他性的字面 node ID 或 export 名游标，单页 `limit` 为 1～255，默认 64，结果包含 `entries` 和可空的 `next_cursor`。页与页之间观察实时目录，不构成事务快照；这些字面游标和限额不属于下文通用 State 分页。普通 `config.*` 不能写联邦目录；单独启用 peer 也不会绕过在线密钥准入。主体、邀请、公开策略、路由和复制成员仍须通过各自宿主端口或 stock 清单管理。

## 管理分页、快照和并发修改

`config.list`、`access.user.list`、`access.role.list`、`external.installation.list`、`external.manifest.list`、`projection.in_process.status.list`、`inference.backend.list`、`inference.model.list`、`inference.group.list`、`visibility.state.list`、`access.session.list` 使用统一分页信封。输入支持可选的 `limit`、`max_bytes` 和 `cursor`；状态列表要求 `prefix`。会话页的 entries 是会话摘要，状态页的 entries 是 path/value。

输出为：

```json
{"entries":[{"path":"state://kernel/...","value":{}}],"next_cursor":"..."}
```

将 `next_cursor` 原样作为相同查询的下一次 `cursor`。`next_cursor` 为 `null` 表示结束；空页仍可能有续页。游标是不透明的 base64url 字符串，仅适用于原后端及原前缀。每次请求只读取一个有界后端页；后续页观察实时状态，不提供跨页事务快照。

基于 State 的列表，包括 `config.list`、`visibility.state.list` 和快照中的 `kernel_config` section，要求单条无条件 `read` grant 覆盖请求前缀及其全部后代（例如 `read://state/kernel/inference/**`）。精确路径 grant 只允许点读该路径，不允许扫描后代。服务在查询前检查子树权限，避免后端游标暴露已扫描的隐藏路径；返回前还会复核每条记录的路径。只需列出较窄范围时，应请求由相应子树 grant 覆盖的较窄前缀。

`limit` 默认为 256，受 `console.queries.max_state_list_limit` 限制；`max_bytes` 默认及上限由 `console.queries.max_page_bytes` 指定。二者都必须大于零。字节预算计量的是后端编码记录，最终响应仍接受独立的出站帧检查。管理查询的单条记录超出预算时返回 `BadRequest`，不会静默跳过记录；可提高预算或使用对应的单记录读取动作。业务状态通过 Operation 读取，驱动失败沿用通用的安全 `Internal` 投影。

`state.snapshot` 默认返回 `sessions` 和 `runtime`。显式 `kernel_config` section 要求具体的可管理前缀，接受同样的分页参数，并在该前缀对应的输出中返回分页对象。所有 section 都返回分页对象，包括 sessions 和 runtime；顶层 `truncated` 列出仍有续页的 section 键。一次快照最多接受 16 个 section，拒绝重复项，所有页共享快照字节预算。快照只提供当前完整观察，不提供增量游标。`server_rev` 是 Fact 游标，不能据此判断 State 是否变化；`registry_rev` 覆盖动作、流、资源类型和视图契约。

所有管理 CAS 写入都区分「不存在」与「存在但没有 version」：`expected_version = null` 只允许创建不存在的记录；无版本的引导记录按版本 `0` 更新。成功写入将版本加一。MFA 绑定、重放计数和恢复码消费使用独立 vault 聚合记录的 CAS。签发会话前复查账号和策略 epoch，因子验证不再改写用户权限记录。会话活动更新通过 CAS 合并时间戳，撤销后的记录不会被旧请求重新创建；token 轮换也比较旧 hash。

本地账户的 `access.user.write_cas` 创建请求只提供 `status`、`roles`、`grants` 和 `authority_ceiling`。Console 生成 `account_id`、`identity_path`（`identity://console/accounts/<account_id>`）、`bootstrap_owner`、`created_by` 和 `created_at`。更新时可省略这些服务端字段；若提供，必须与已有记录一致。用户名 `root` 只供 bootstrap 使用；删除后复用其他用户名会创建不同的账户身份。安装宿主 `AccountAuthority` 后，本地 user／role 管理动作不再发现，分发也拒绝；账户事实由宿主权威负责。

## 出站限制

有界 WebSocket 事件队列须在事件发送或丢弃前，对留存载荷字节和条目许可持续计量。取消订阅须丢弃其排队数据并释放费用，不重排仍存活的事件，也不把它们转入另一无界队列。这不同于只取消一次待完成的服务收取：已取得的事件仍为下一次收取保留；两种取消都不改变已接纳效果的提交状态。

订阅收取是本地观察，不授权排队后的帧披露。适配器为每条流取得一次 `delivery_authority()`，让排队帧保留共享 guard 的 clone。WebSocket 在 socket 可写后、数据交接前复核原始权限；grant／会话变化或原始期限到期，因而可以阻止已排队事件交付。停止交付不回滚来源提交或执行效果。队列费用仍由帧持有，直到发送或丢弃。自定义传输须实现相同的最终交接检查；见[服务边界](console-protocol.md#服务边界)。

`console.max_concurrent_calls` 默认 64（范围 1–4096），限制 Rust、HTTP 和 WebSocket 共用的活动动作；动作在读取 bearer State 前取得额度，HTTP `/calls` 收取有界请求体时也占用。`console.max_concurrent_authentications` 独立限制凭据及会话检查，同样默认 64（范围 1–4096）。容量满直接返回 `RateLimited`，不建立无界等待队列。密码 hash 和外部 verifier 使用更窄的独立额度。

`[console.queries]` 独立设置 `max_state_list_limit`（默认 512）、`max_fact_limit`（256）、`max_trace_limit`（512）、`max_process_limit`（256）及管理查询页的 `max_page_bytes`（131072）。执行输出读取使用独立的 `console.executions.max_output_page_bytes`。这些服务预算与 WebSocket 帧和队列预算不同；宿主应选择足以容纳目标响应的传输上限。

`max_frame_bytes` 同时约束入站和出站 protobuf 帧，默认 1 MiB，范围为 16 KiB 至 4 MiB。出站转换在克隆载荷前检查累计内联字节、最多 16,384 个 Value 节点、30 层 Value 嵌套和 256 个路径段。完整 protobuf 消息还必须通过精确帧字节检查，随后才能分配编码输出缓冲区。超限 Value 不会被截断。

`send_timeout_ms` 约束所有出站帧，包括回复和错误，默认 5 秒，范围为 100 毫秒至 60 秒。它替代 `event_send_timeout_ms`。回复无法在预算内编码时，服务端返回携带原请求 ID 的小型 `Internal` 错误。此时动作可能已经完成，错误不表示回滚，也不表示可以安全重试。传输错误或发送超时会关闭连接。

每个连接的实时订阅共用一个最多 256 条的队列。`max_pending_event_bytes` 约束排队及正在发送的订阅数据编码字节，默认 1 MiB，范围为 16 KiB 至 16 MiB。每个 worker 在尝试入队前最多准备一帧有界数据，不会持有未计费帧等待队列空间。条数或字节预算耗尽都会关闭产生该事件的订阅。独立控制路径最多保留 `max_subscriptions` 条各不超过 1 KiB 的关闭原因和一条正在发送的关闭帧，不计入数据预算。此预算也不包含来源广播存储、原生动作输出、转换临时结构、socket 缓冲区或整个进程的内存。

WebSocket 交付 worker 持有公共服务订阅。lag、来源关闭、投影或编码失败、worker 异常都会释放订阅名额并产生 `SubscriptionClosed`，这些失败使该代订阅尚未发送的尾部失效。共享服务返回结构化失败时，在可见性期限仍允许交付的前提下，先排空此前已接纳的排队事件，再发送带 `failure` 的关闭通知。正常完成也先排空已入队事件。活动订阅 ID 不允许复用，必须先取消。旧事件和旧关闭通知不能影响之后使用相同 ID 的新订阅。会话关闭或被取消时会中止所属任务。全部 worker 共用 250 毫秒的关闭期限，无法完成关闭则终止会话。该期限约束异步等待；Tokio 无法强行抢占同步适配器工作或阻塞的析构函数，宿主适配器仍需配合取消。

订阅可见性按请求的 `ttl_ms` 到期，最长十分钟。过期丢弃待发送数据并产生 `SubscriptionClosed`。成功 `Auth` 会在接纳新会话前清理旧订阅。每次事件发送都会重新认证 SID；身份、有效权限集合或 MFA 级别发生变化时关闭连接，重新建立授权和订阅。数据发送取可见性期限和发送超时的较早者，并在任何适配器缓冲／可写等待之后、实际向 socket 交接时再次检查是否过期。已经交给 socket 的数据无法撤回。取消代次时丢弃其排队帧并释放字节／条目许可；其余代次维持原事件顺序与费用。

## Fact 查询

`audit.facts.recent` 返回一页反向追加顺序的记录，默认 64 条。`lineage.trace.read` 要求指定 `process`，返回一页正向追加顺序的记录，默认 128 条。两者均接受 `from`、`before`、`limit`、`max_bytes`、`max_examined`；recent 还接受可选 `process`。游标与进程编号输入接受非负整数或十进制 `u64` 字符串；游标及数值标识符投影输出为十进制字符串，避免客户端丢失精度。`op_id` 保留组合 OperationId 字符串格式。`from` 表示全局物理追加位置，即使按进程过滤也不表示匹配记录的行偏移。读取方向由动作固定。

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

recent 用 `before=next` 和相同 `from` 续页；trace 用 `from=next`、`before=end` 续页，保留筛选条件和预算。空页仍可能有续页，反向分页逐步缩小上界。固定追加区间排除后续追加，但旧槽位的完成结果仍可能更新。trace 另返回 `partial=true` 和 `partial_reason`，说明没有包含物化的来源链索引；这与分页是否完成无关，trace 不提供全历史总数。

条数受 `console.queries.max_fact_limit` 或 `max_trace_limit` 约束。JSON 字节上限由 `console.queries.max_page_bytes` 指定，最高 256 KiB，与传输方式无关。出站转换和精确帧大小仍需通过各自独立的预算检查。候选检查数默认 `max(limit, 4096)`，最高 65,536。零预算无效，超出上限的请求按上限执行。第一个匹配记录超过字节预算时读取失败。`lineage.fact.read` 使用有字节限制的索引点查，同样接受 `max_bytes` 和可选 `process`，后者默认 `op_id.process`。动作要求所选进程的读取权限，并只返回当前调用进程与之匹配的记录；归属不同则返回未知记录，不暴露内容。这些限额不计量解码堆或总内存。

`runtime.process.inspect` 和 `state.snapshot` 的 `runtime` section 默认只读元数据。`include_recent_facts=true` 要求显式 `process`、对应 `state://fact/<process>` 的读取权限，以及动作要求的可见性元数据。`recent_facts` 是一页有界反向结果；一次快照最多接受一个 runtime section。进程查询返回 `entries/next_cursor`，`limit` 限制进程条数，按 ID 升序用 `cursor` 续读，`max_bytes` 限制投影字节。`fact_limit` 单独限制内嵌 Fact 页；`process` 与 `cursor` 互斥。只读元数据与 runtime 快照使用相同的进程检查权限，内嵌 Fact 才增加 MFA 和可见性门槛。进程行返回 `parent` 和 `child_count`，客户端可逐页构建树。显式指定但已不在保留表中的进程返回 `Unknown`，仍可按权限读取其保留 Fact。会话列表同样返回分页对象，按存储键排序，在单页内过滤过期项且不触发删除；空页也可能有续页。

`health.summary.fact_sample` 包含 `sampled_facts`、`decisions` 和相同的页面元数据，计数仅代表近期样本。顶层 `fact_cursor` 是单独观察的十进制追加上界，不跟踪完成更新，也不保证与样本同一视图。`process_count` 使用进程表的常数时间保留数量。

## 修改结果

修改动作通过 schema、step-up 及具体目标授权后，直接返回处理器结果。服务不写每次修改的 started／completion 审计，也不返回 ActionReceipt；诊断历史不作为提交屏障。失败或响应丢失仍不证明回滚，重复修改前核对实际数据或外部效果。

认证摘要由 Console 生成，描述本次请求验证的会话或成功签发的会话，不表示每个审计动作都完成了一次新认证。认证失败或尚未完成时不生成摘要；`console_ws` 连接事件、只凭 SID 的 `console_credential` 注销记录和独立执行事件只保留已知归属，缓存 principal 或账户 owner 不证明当前认证。网关审计 Fact 不再包含顶层 `mfa_level`；等级由完整会话证据派生，不能作为另一份可独立写入的认证事实。

## 实时审计

宿主事件标签依据完整行政网关 Fact 包络，由 `xolotl_types::audit::gateway_audit_event` 识别，不限制为 `console_` 事件名。普通 Operation 输出中的 `event` 字段不能使它获得该宿主事件的 `Custom` 审计标签。内核不把应用 details 解释为认证或权限，见[事实记录](state-and-facts.md#事实记录)。

`audit.facts.stream` 只接收订阅后的通知，不回放历史。可选 `process` 在检查字节预算之前筛选当前记录，无关进程的超大记录会被忽略。新增和完成更新都会触发有界索引重读；事件以 `op_id` 为键表示 upsert。通知可能不按提交顺序到达，也可能重复返回当前值。客户端应替换对应身份的记录，不能把每个通知计为一个新 Fact。

积压导致 lag、记录消失或有界读取失败时，发送 `SubscriptionClosed` 并释放订阅名额。上述共享生命周期和队列限制同样适用。关闭后应重新订阅，再通过显式有界分页核对保留记录，包括可能更新过完成结果的旧槽位。先建立实时订阅再分页可缩小间隙；再次 lag 时重做核对。这不提供原子快照或持久更新日志。

实时事件信封没有版本或续传游标。`SubscriptionClosed.failure` 保留已知的结构化服务错误和执行引用；正常结束没有 failure。追加游标无法恢复旧槽位的完成更新。客户端使用明确的分页读取核对历史。
