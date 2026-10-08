# External Gateway

External gateway 把进程外程序以 Provider 或 Source projection 接入 Xolotl。gRPC 和 WebSocket 是同一个 session 协议的两种传输实现。

## 角色

Provider session 暴露由所选 installation projection 声明的远端 effect handler。`RoleReady` 确认 daemon 选定的 session context 后，daemon 为该 ready session 注册这些 projection binding，并且只向已注册 effect 下发 invocation。

Source session 发送入站事件，也可接收宿主发出的 outbound command。声明命令的 Source projection 就绪时，daemon 发布一个可调用的 Effect resource，并通过共享的 Source command hub 将命令路由到当前会话。Source event 经 gRPC 或 WebSocket 到达后，进入相同的 schema、policy、capacity、dedupe 和 taint 路径。

Provider 和 Source 是唯一的外部 projection role。

## 传输

External gRPC 监听 `[server].external_grpc_addr` 或 `XOLOTL_EXTERNAL_GRPC_ADDR`，并提供 `xolotl.v1.external.ExternalService.Session`。

External WebSocket 监听 `[server].external_websocket_addr` 或 `XOLOTL_EXTERNAL_WEBSOCKET_ADDR`，在 `/ws` 上提供同一套逻辑 session frame。

两种传输共用 daemon 侧 handler 实现及 Provider/Source 准入规则。stock daemon 为每个监听器构造 handler，并跨监听器共享 Source 命令路由和资源发布。

嵌入使用时，`xolotl-gateway-websocket` 接受任意 `ExternalSessionHandler`，且不依赖 tonic。处理器保留自己的关联错误类型；服务构造函数接收 `fn(OutboundQueueError) -> H::OutboundError`，将 `Full`、`Closed`、`InvalidFrame` 和 `SequenceExhausted` 映射为宿主错误。

出站准入不等待队列容量：队列满时只拒绝本次提交，保留已排队帧；成功入队不代表远端已经收到。处理器错误只要求 `Debug`，供本地诊断并关闭会话，不转换成 wire status。daemon 选择了使用 tonic 错误的共享处理器；独立 WebSocket 宿主不受这一选择约束。

`session_route(service)` 返回已装配服务状态的 Axum `MethodRouter`。宿主可以通过 `.route("/external/session", session_route(service))` 自行挂载路径、组合路由和中间件。启动路由时须提供 `ConnectInfo<SocketAddr>`，例如使用 `into_make_service_with_connect_info::<SocketAddr>()`。自定义路径和默认 `/ws` 的 `serve` 辅助函数共用 upgrade 处理、传输安全检查及共享服务限制。

## 配置

daemon 的 gRPC 与 WebSocket 共享一个 `ExternalSessionScope`，包含握手在内最多接纳 256 个活动会话；嵌入服务默认拥有自己的作用域，宿主可注入共享实例。close 拒绝准入并中断其 reader、writer 与通知 worker；异步 shutdown 等待实际终止，丢弃等待者后仍可继续。丢弃 gRPC 响应中断尚未完成的输入读取；`on_closed` 在部分握手和取消等路径同步释放本地注册。

输入消息默认最大 1 MiB，首帧期限 10 秒、空闲期限 300 秒；WebSocket 在碎片组装前应用限制。Provider 取消同步尝试入队尽力通知，每会话一个 worker、最多 32 条等待通知，从入队起含等待共 1 秒期限。队列满可丢弃信号，不延迟本地释放；入队或发送成功不证明远端回滚。

监听地址、传输安全、WebSocket 传输上限和 Provider/Source 数值限制都归属[配置](configuration.md)。本页不重复 key 列表或默认 TOML 块。

session 准入后，这些设置限制 Provider dispatch 与结果解析、Source event ingress、Source command dispatch 和事件去重保留。Source event 的 payload 大小限制、stream 容量、溢出行为和 event-ingress 速率限制在每个 Source projection 上声明。

## 传输安全

传输安全模式及其需要的证书或代理字段见[配置](configuration.md)。某个监听器拒绝传输安全模式时，会在接受 external session 前停止启动。

使用受信反向代理时，应清除客户端传入的转发头，并将采用的 `X-Forwarded-Proto`、`X-Forwarded-For`、`X-Real-IP` 或 `Forwarded` 字段覆盖为单值。gRPC 监听器拒绝重复头及追加的转发链；WebSocket 监听器要求单个 `X-Forwarded-Proto` 头。本地受信 WebSocket 模式中，若提供浏览器 `Origin`，它必须是单个有效本地 origin；重复 `Origin` 头会被拒绝。

## Session 状态

外部安装声明保存在存储拥有者的 typed 目录。Console 的 `external.installation.read` 和 `.list` 返回包含 `definition` 与 `installation_epoch` 的存储记录；`.install` 要求记录不存在，`.update` 和 `.uninstall` 同时比较从该记录读取的 `expected_installation_epoch` 与 `expected_version`。`state://kernel/external-installations/*` 下的 State 值不授予准入权威。

存储签发的 `installation_epoch` 在声明更新时保持不变，退休后同 ID 重装才重新签发。每次安装或更新都会为各 Source 投影签发新的 `scope_epoch`。daemon 将两者写入 `SessionContext`，并在 Ready 及后续工作中核对当前目录；配置版本变化也会使旧活动会话上下文失效。Provider 的 `scope_epoch = 0`。

已批准 session state 读取自：

```text
state://kernel/external-sessions/<installation_id>/<role>
```

session record 必须匹配连接方的 installation id、role 和 `installation_epoch`。daemon 会在业务 frame 流动前拒绝缺失、不匹配、已撤销或非 ready 的 session record，并核对所引用配对已针对该角色和安装存续期批准且凭据代次相同；只写入部分会话投影不能单独认证。声明更新可以保留已批准的配对，但需要按新配置版本建立活动会话上下文。

`SessionContext.key_epoch` 是从该角色会话记录选定的当前 AEAD 代次。客户端用它密封 Ready；旧连接仅可在 `control.config_ack` drain 帧中使用紧邻的上一代次，更旧代次一律拒绝。新的业务帧须使用当前代次或重新建立会话。

`pairing.create` 要求调用方在请求前选定并保存 `pairing_id`，以便响应结论未知时查询该记录。配对生成 32 字节会话密钥，其 64 个十六进制字符只通过 Console `pairing.create` 请求的一次性 `display_secret` 边界交付。配对 State 记录保存 hash、checksum、状态和凭据代次；会话投影保存状态与凭据代次，两者都不保存密钥。

stock daemon 在独立的凭据 vault 中保存待批准和已签发密钥。使用 redb 时，该文件由 `storage.path` 替换扩展名为 `.external-credentials` 得到，例如 `xolotl.db` 对应 `xolotl.external-credentials`。vault 使用 `[external_credentials] key_file` 提供的独立宿主密钥加密；旧明文、错误密钥和损坏文件均被拒绝。memory 存储使用内存 vault。daemon 拒绝与安装存续期或凭据代次不匹配的密钥。

使用 redb 时，备份及访问控制须把 vault、其独立密钥与对应的 State 安装、会话记录配套管理；vault 更新与配对 State 写入不构成同一事务。

批准配对先持久化 vault 密钥，再发布角色会话 State 和 approved 状态。若批准中断而配对仍为 `created`，使用同一 pairing ID 重试；vault 核对原密钥与安装后复用已签发的凭据代次。响应丢失但状态已为 `approved` 时，应先检查状态，再决定下一步配对。

vault 替换后若持久性结论未知，该 daemon 进程会停止签发及提供会话密钥；重启加载磁盘内容后再由正常准入检查裁决。

要放弃未批准的 `created` 意图，先对旧 pairing ID 执行 `pairing.deny`，再用新 ID 执行 `pairing.create`。拒绝与创建分别提交，不存在单次原子替换。响应结论未知时，先查询各记录，再处理未完成的步骤；已批准意图不能通过此流程拒绝。

若新意图已创建但一次性的 `display_secret` 未被安全收到，当前 daemon 进程中严格相同 ID 与意图的创建重试可能交付尚未被 Console 边界消费的展示值；重启后或展示值已消费时不能从持久 vault 重建，此时须拒绝新意图并再次换新 ID 创建。

## Provider 流程

Provider 调用只会发送给 installation projection 声明并已为 ready session 注册的投影 effect，且调用输入必须匹配 Provider projection 的 `input_schema`。Provider 结果只接受 daemon 已登记的在途 invocation。结果必须来自同一个 ready Provider session generation，在 invocation deadline 前到达，并且不超过该 invocation 登记的结果大小限制。

原 invocation 期限一次换算为单调期限，覆盖出站队列等待及结果等待；发送前核对原绝对期限和单调期限，已接纳的真实结果不被之后的超时替代。发送 Invoke 前的拒绝是确定结果。开始发送后的发送失败、invocation deadline 或会话断开则结论未知：宿主报告 `Failure::OutcomeUnknown`，携带原 invocation ID（即 Kernel OperationId）及 `delivery_or_session_lost` 或 `deadline_exceeded` 原因。这些原因由宿主判定，不取自 Provider。不得自动重试结果未知的 effectful 调用。发送后超时或取消时，daemon 先移除自己拥有的本地登记与等待者，再异步尝试发送 `ProviderCancel` 控制帧，发送最多等待一秒。控制帧可能无法交付，本地释放不等待它。这是协作取消信号，不承诺撤销已经发生的外部副作用。

## Source 流程

Source event 只会在 session 处于 ready 状态且 generation 字段匹配 daemon 裁定的上下文后准入。后端在 event-id 去重或 sink 追加之前，于同一提交域核对活动 `scope_epoch` 和当前声明；已排队的旧事件不能重建退休的 scope。每个接受事件的去重期限由 daemon 接收时间与本次配置窗口固定，之后重配只影响新决定。

声明的 State sink、event-id 决策、可选流序列、速率记录和私有提交凭据由同一后端一次提交。成功 ACK 表示这些内容一起接受；同流并发事件由提交串行化，`seq=1` 失败不会让 `seq=2` 越过它。

### 有序流

ready Source session 上的有序流有显式生命周期：

1. 发送带 `stream_id` 的 `SourceStreamRequest { Inspect }`，读取 scope 控制修订号和该名称当前活动流的状态。
2. 用读到的修订号发送 `Open { expected_revision }`。存储占用一个活动流额度，签发不可复用的 `stream_epoch`，并设置 `last_seq = 0`。请求 ID 是稳定的 Open 身份；响应丢失后，可用相同请求 ID 和修订号重试，取回仍活动的同一代次。若其他控制操作改变了 scope 修订号，须先重新 Inspect，再用新请求发起 Open。
3. 有序 `InboundEvent` 同时携带 `stream_id`、下一个正整数 `seq` 和正整数 `stream_epoch`；缺少任一字段的数据帧不能开流。重连后，Inspect 返回活动代次及最后接受的序号，供 Source 续接。
4. 逻辑流结束时发送 `Retire { stream_epoch }`。存储在同一提交域阻断旧代次后续事件并返还额度。同名流随后可用新代次打开；断开 session 不会退休流。

`SourceStreamResult` 回显请求 ID 和流 ID，并返回快照、退休修订号或结构化拒绝。Open 和 Retire 都受当前 scope 约束，旧 session 不能修改已退休 scope。

内建存储对所有 scope 的活动有序流设置 `[storage].source_stream_limit`，默认 4096，可配置为 1–65536；满额拒绝 Open，不改变 sink 或事件决策，已有流仍可推进。scope 退休也会阻断旧提交，其遗留位置由有界维护返额。Retire 响应丢失后可用 Inspect 查看当前状态；快照不能证明过去的事件或外部效果从未发生。

有序事件的 event-ID 决策及凭据按 `stream_epoch` 分域；无序事件没有 stream epoch。同名流重新打开后可复用旧 event ID，不会被前一代次的决定误判为 Duplicate。

在决定仍保留的窗口内，同一 ID 只有在无损 tagged Value payload，以及有序事件的 `stream_id` 和 `seq` 都与原接受事件一致时才是 Duplicate。用同一 ID 提交不同内容或流位置会得到 `Rejected`、`event_id_conflict` 的确定 ACK，不改变原决定、sink、序列或速率。event ACK 回显 event ID 和可选 stream epoch，便于区分两代流。已退休流的旧事件在去重前即被拒绝，即使旧决定仍保留。

### 事件容量与存储

Source 声明安装时由实际存储拥有者检查其预算；内建内存/redb 后端限制单项 tagged Value 编码最多 1 MiB、Source 提交后的 sink 最多 65,536 项、两者声明乘积最多 64 MiB、速率窗口最多 65,536 次命中，安装及投影身份各最多 256 字节，canonical sink 路径最多 4096 字节。普通 State 写入有独立限制；DropOldest 按裁剪并追加后的 sink 判定，允许恢复此前超过 Source 容量的 List。

Console 未装配 `source_management` 端口时拒绝任何 external installation；只含 Provider 的声明跳过 Source 预算检查。自定义存储可声明自己的界限。

Gateway 不再为测量大小而预先编码 payload；内建后端在提交时用同一次流式 tagged Value 编码计算 `max_inline_payload_bytes` 的实际字节数和 event-ID 指纹，包括 `Null` 与转义后的字符串。超限为确定拒绝。daemon 每次加载 Source 会话声明时复核所装存储的限制。

当前项数和 sink 编码表示分别受限。数据来源及表示开销也占字节，因此未到 `capacity.max_events` 也可能确定地拒绝下一项；该拒绝不写入事件决策或推进流序列。Source 准入与计量以[Source 存储合同](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-source/src/lib.rs)为准。

声明 sink 仍是逻辑值为 List 的普通 State 路径。redb 的普通 State 写入与 Source 提交共用 State 的顶层 List 表示，不存在 Source 专属转换；表示及变更规则归[State 后端](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-storage-redb/src/state.rs)维护。若其他写入者把它改成非 List，下一次 Source 提交返回 `sink_type_mismatch` 的确定拒绝且不留私有预留。宿主应为 Source sink 安排单一写入责任；安装时的类型检查无法防止之后的并发替换。

Source 指外部事件服务；provenance 指值的数据来源链，由 `TaintSet` 表示。Source 身份和数据来源链都不授予访问权；来源表示归[类型合同](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-types/src/taint.rs)维护。

嵌入宿主为事件准入与维护提供同一可信 `SourceClock`。存储取得序列化锁或事务后只采样一次，以决定时刻处理去重、速率窗口、到期和清理；`received_at_ms` 仅为纪实时间。时钟低于受影响 scope 的已提交水位时拒绝，不通过截断回退获得新额度。见[Source 时钟合同](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-source/src/lib.rs)；这不是全局 runtime 时钟或 outbox。

### 不确定提交与核对

后端无法确定提交结论时，两种传输返回 status=`outcome_unknown` 且没有 `reject_reason` 的 event ACK；该状态不表示事件在提交前已被拒绝。Source 应尽快用相同 event ID 和 payload 重试；有序事件还须保持同一 stream ID、序号和 stream epoch。只有旧决策在后端判定点仍保留且流仍活动时，重试才会被判为 Duplicate。

即使事件在期限前到达，也可能在异步策略检查和排队期间跨过期限、被维护先清理。退休流的旧事件在去重前即被拒绝；调查早先的尝试须检查仍保留的凭据。

Source 数据帧无法检查凭据，也不能修改声明 sink 或污点。当前 sink 只保存 payload；特别是在 DropOldest 之后，payload 缺失不能证明事件未提交。

获授权的操作人员可调用 Console action `external.source.claim.inspect`，输入 `installation_id`、`projection_id`、`scope_epoch`、`event_id` 和 `claim_id`；有序事件还须输入 `stream_epoch`。epoch 是正十进制 u64，可以指向已退休的 scope 或流；无序事件不填 stream epoch。三项文本身份是非空、至多 256 UTF-8 字节的字面身份段，claim 为 32 位小写十六进制。

该动作要求 MFA 等级至少为 2、具体目标 `effect://external/source/{installation_id}/{projection_id}/claims/inspect` 的 `perform` 权限，以及原始长度至多 1024 UTF-8 字节、去除首尾空白后非空的 `ActionCall.justification`。认证后的披露边界归 Console，见[检查准入](console-actions-and-streams.md)。Source 端口在同一个一致存储视图中只读查询精确身份，不写私有检查审计。

`external.source.event.decision.inspect` 接收安装、投影、scope epoch 和 event ID；有序事件还须提供对应 stream epoch。它另要求具体目标 `effect://external/source/{installation_id}/{projection_id}/events/inspect` 的 `perform` 权限与相同的 MFA、理由及当前披露检查。该动作只在指定流代次内找回**当前保留的已接受决策**及其 claim 凭据，不枚举事件或历史尝试。同一代次的同一 event ID 在原窗口后再次被接受时，查询只返回较新的当前决策，不能确认旧尝试的结论。

结果为 `status: committed` 加 `receipt`，或不含凭据的 `status: unproven`。凭据包含 scope epoch、可选 stream epoch、四项 claim 身份、原 `sink` 和 `received_at_ms`，不返回事件 payload。`Unproven` 表示没有找到当前保留的凭据，不证明该尝试从未提交；它与检查错误都不允许自动补偿或重放。检查不变更 sink，不提供 claim 枚举、删除或维护能力。

确切 claim 定位来自 Gateway 在 Source 提交返回 `Indeterminate` 时记录的宿主结构化事故日志；有序事件的日志也记录 stream epoch，Source ACK 不公开 claim。需要确切尝试诊断的宿主应保护并保留这些日志。日志丢失、进程在记录前退出，或只有网络 ACK 丢失时，操作人员仍可凭 Open 响应或控制日志中的 stream epoch 查询**尚未清理**的接受记录；过期或清理后的缺失不证明该尝试回滚。检查不要求当前安装声明仍存在，可查询卸载后尚保留的凭据。

嵌入宿主通过一个 `ConsoleConfig.source_management` 对象安装声明检查、typed 目录和凭据检查；它不向 Console 提供事件提交、逐流控制或维护权限。stock daemon 从同一个 Source 存储实例装配 Console、Standard 和 external ingress；嵌入宿主也须保持这些独立服务同源。未启用 external listener 时仍可检查存量凭据。消息仍保持 v1。

### 维护与出站命令

共享命令 hub 在两种传输间共用全局单位额度，由 [`[external_gateway].source_command_limit`](configuration.md#external-gateway) 配置。待决命令、留存终态 ID 和 installation/projection 限速行都计费。待决命令已预留终态 ID 槽，新增限速行另占一个单位。满额在发送及消耗速率额度前拒绝，不驱逐有效且未过期的 ID。嵌入 registry 的零去重窗口在终态转换时释放 ID，但限速行保留至自身窗口到期；daemon 零去重配置取默认值。登记及周期 Source 维护每次最多检查 64 条留存 ID 与限速行，空闲 hub 也会清理。最早到期提示跳过不必要的遍历，内存游标跨批次续扫。该额度限制单位数，不限制字节或 RSS；命令状态不持久化。

嵌入宿主可用 `SourceCommandRegistry::with_capacity(NonZeroUsize)` 选择正额度，`Default` 使用 `DEFAULT_SOURCE_COMMAND_LIMIT`。`occupied()` 报告计费单位；每次 `expire_retained(now)` 返回 `SourceCommandMaintenanceReport { examined, removed, reached_end }`。完成表示本轮扫描结束或当前无需扫描，不表示未来插入的记录已处理；零释放不能替代完成判断。宿主也须在空闲维护时调用。复用主表，不保留逐 ID 到期索引；命令元数据只属于当前宿主生命周期。

周期维护的命令 registry 与 Source 私有事件决策、速率行和流位置共享 `max_batches_per_tick` 预算。有工作时轮流推进，轮转位置跨 tick 保留，预算为一也能推进两类拥有者。每个计费批次最多检查 64 行；未检查任何行的完成报告不收费，已完成者让出剩余预算。批次之间释放 hub 锁并让出调度。Source 存储清理过期决策与凭据、空闲限速行和已退休 scope 的流位置，返还流额度；其 redb 游标跨重启保留，命令游标仅在内存中续扫。游标之前的新行在回绕后访问。活动流由 Retire 显式结束；State 历史有独立留存策略。

声明 outbound command 的 Source projection 必须提供 command action schema 和成功 result schema。projection 就绪时，daemon 发布 `effect://external-source/{installation_id}/{projection_id}/command`，方法为 `dispatch`（`perform`、effectful；支持 unary 和 AsyncProcess）。Kernel Operation 将命令 action 作为输入。Console 可在宿主暴露精确资源、账户拥有相应 `perform` grant 后使用 `runtime.operation.invoke` 或 `.submit`；此命名空间不会自动开放。调用仍经过 Kernel grant、policy、Fact 与 taint 路径。该宿主会话绑定可经 gRPC 或 WebSocket 路由。派发要求恰好一个符合当前权威的 Ready session，并核验声明的 schema、命令限额及 `CommandResult` 的命令 ID。

调用者未给出更短期限时，daemon 最多等待 60 秒。登记时将期限一次换算为单调期限，发送与结果等待共用它；发送前同时检查原绝对期限和单调期限。发送前到期释放登记但不保留 ID，已接纳限速命中仍计费。发送前拒绝是确定结果；开始发送后的超时、断线或传输错误产生宿主签发的 `Failure::OutcomeUnknown { operation_ids, reason }`；该命令在 `operation_ids` 中贡献一个出站命令 ID；此 ID 即调用方的 Kernel OperationId，因此 Kernel 截止时间中断该命令时仍报告相同身份。端点原因限于 `deadline_exceeded`、`delivery_or_session_lost` 或 `result_identity_mismatch`；Kernel 截止时间结果未知也使用 `deadline_exceeded`。这些原因均不取自 Source 提供的文本。该失败到达 Console 时，Rust 服务、HTTP `/calls` 和 WebSocket 的错误均使用 `OUTCOME_UNKNOWN` 代码及包含 `operation_ids` 和 `reason` 的 `outcome_unknown` 对象；Source 回传的错误不能冒充宿主判定。取消可能使调用者拿不到响应，但待决 ID 在去重窗口内仍被阻挡。入队不证明执行；结果未知的 effectful 命令不得自动重试。v1 没有 Source 命令取消帧、持久 outbox 或持久命令收据，daemon 重启后无法确认在途命令的结果。

## SecureEnvelope

External gRPC 与 WebSocket 共用 v1 握手。端点先发送明文 `RoleSessionClientHello`，daemon 返回明文且有权威性的 `SessionContext`。双方从经验证的类型化 v1 消息计算协商 transcript hash：依次输入域字节 `xolotl/external/session-transcript/v1\0`，再按 Hello、Context 顺序输入各自 canonical typed-protobuf 编码的 8 字节大端长度及编码，最终求 SHA-256。类型化转换会排除未知 protobuf wire 字段。

随后端点在 `SecureEnvelope` 中发送完整回显选定 context 的 `RoleReady`，AAD frame type 为 `role_ready`、方向为 `client_to_daemon`。明文 Ready 会被拒绝；daemon 只有验证密文和回显 context 后才注册 Provider binding 或接纳 Source event。

Ready 后客户端的 `InboundEvent`、`SourceStreamRequest`、`CommandResult`、`InvokeResult` 和 `ControlFrame` 均须密封。daemon 发出的 `Invoke`、`OutboundCommand`、`EventAck`、`SourceStreamResult` 和 `ControlFrame` 也须密封。传输流错误和连接关闭仍属于传输事件，不是业务帧。

外部客户端须先解封 envelope，再解码其中的 `ExternalFrame`，并核对实际类型与经过认证的 AAD `frame_type` 一致。客户端还须核对 `daemon_to_client` 方向、选定的安装／投影／角色／会话与代次、transcript hash、当前策略允许的 key epoch，并维护接收侧 replay window。帧类型用小写 snake_case 变体名（如 `inbound_event`、`event_ack`）；控制帧用 `control.<kind>`，如 `control.config_ack`。AAD role 为 `provider` 或 `source`。

32 字节配对密钥是 v1 HKDF/ChaCha20-Poly1305 envelope 的 PSK。AAD 绑定安装凭据代次、projection、role、session、规范化 Hello/Context transcript hash、key epoch、frame type、sequence number、binding generation，以及必填方向域 `client_to_daemon` 或 `daemon_to_client`。daemon 拒绝把服务端响应反射为入站请求。

AAD context 与密钥代次须匹配选定会话和当前权威；仅持有旧配对密钥不能重开已退休安装或已撤销会话。Ready envelope 必须使用明文 Context 中的 key epoch；transcript hash 保护该字段，中途修改 Context 不能造出有效 Ready。

两个发送方向各从零开始递增自己的序号，同一连接重键后也不能复用。stock daemon 按 session 维持一个有界入站 replay window，不按 key epoch 分表；关闭会话时释放。首个经过 AEAD 验证的序号可从任意值建立空窗口，随后重复、过旧和跳跃过远的序号会在解码 frame body 前拒绝。

独立 v1 客户端须将内部类型化 `ExternalFrame` 编码为 protobuf。认证字节串按此顺序拼接：域 `xolotl-secure-external-envelope-v1`、安装 ID、凭据代次、AAD 版本、投影 ID、角色、会话 ID、序号、帧类型、绑定代次、凭据代次、transcript hash、key epoch、方向。每项先写其字节长度，使用无符号 64 位小端整数；AAD 版本用 4 字节小端，其他数值用 8 字节小端。

以 32 字节配对 PSK、salt `xolotl/external/session-envelope/chacha20poly1305/v1` 和上述认证字节串作为 HKDF info，用 HKDF-SHA256 导出 32 字节密钥。每个 envelope 生成新的随机 12 字节 `nonce_prefix`，将末尾八字节与大端序号逐字节 XOR，得到 ChaCha20-Poly1305 nonce；同一认证字节串用作 AEAD AAD。

wire 上的 protobuf `EnvelopeAad` 携带这些字段，其字段顺序不是密码学字节编码顺序。

嵌入宿主须在 `ExternalSessionHandler` 实现 `open_secure_envelope` 和 `seal_secure_envelope`。共享 adapter 负责 framing、规范会话 transcript、方向、出站序号与队列；handler 负责密钥查找、当前 key-epoch 策略、AEAD 解封／密封及撤销核对。

stock daemon 从私有 vault 取得密钥，在入站和出站帧上重验安装与会话权威。入站业务及解封回调借用选定的 `&SessionContext`；Ready 和 Closed 回调取得有所有权的 context，以便在会话生命周期中保存。
