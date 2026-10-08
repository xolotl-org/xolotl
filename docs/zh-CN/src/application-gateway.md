# 应用网关

应用 gRPC 监听器暴露一个按 profile 装配的 `GatewayRuntime`。它的 principal 和 surface 与外部 Provider/Source 会话分别准入。daemon 将同一个 ObjectStore 的克隆交给 Standard 和应用 runtime；State 保存授权记录和回执，对象存储保存内容。

每个 submission 的资源 dispatch 与受保护交付共享同一个当前 profile 授权上下文。Kernel 的 request-authorizer 接口在每次资源调用前复核，子调用继承该边界。替换 profile 会使旧修订签发的会话失效：尚未 dispatch 的工作被拒绝，已经接纳的效果保留真实结果和核对证据。交付在最后一次 await 后独立复核权限；不交付响应不等于撤销效果。

提交响应 Body 保留原会话与 surface，在编码前及每个就绪帧移交传输前复核当前权限。
缓存结果、结构化输出和不确定性回退遵守同一规则。撤权阻止尚未移交的数据和成功完成，
不改变已存储的效果或证据；已经交给网络的字节无法追回。编码缓冲只保留容量许可，
不保留授权上下文，最后一个切片释放后归还容量。

## 配置

可单独构建此可选入口：

```sh
cargo build -p xolotl-daemon --no-default-features --features application-grpc --locked
```

首次配置时启用持久 State 和 Console，暂不设置应用监听地址。通过已认证 Console 的 `config.write_cas` 创建 `state://kernel/gateway/profiles/tasks`。输入包含 `path`、profile `value` 和创建时的 `expected_version: null`。此动作要求写权限和既有 MFA step-up；Console 自动填写 `version: 1`，后续更新携带读到的 `expected_version` 并递增。

profile 文档集中声明凭据、身份映射、surface、绑定、注册的 authority 和 Gateway 准入限制。例如：

```json
{
  "profile_name": "tasks",
  "credentials": [{
    "credential_id": "worker-key",
    "principal_id": "worker",
    "verifier": {
      "kind": "bearer",
      "token_hash": "0000000000000000000000000000000000000000000000000000000000000000"
    }
  }],
  "identity_mappings": [{
    "principal_id": "worker",
    "identity_path": "identity://application/worker"
  }],
  "surfaces": [{ "surface_id": "clock", "target": "effect://time/now" }],
  "principal_surface_bindings": [{
    "principal_id": "worker",
    "visible_surfaces": ["clock"],
    "submit_surfaces": ["clock"],
    "capability_ceiling": ["perform://effect/time/now"]
  }],
  "registered_hosts": ["127.0.0.1:9445"]
}
```

`token_hash` 的全零值是占位符，应替换为由系统 CSPRNG 生成至少 32 字节随机量的 bearer secret 的小写 BLAKE3 摘要；profile 不存原始密钥。长度检查无法证明熵。客户端证书使用 `kind: "client_certificate"` 和 `der_sha384`（96 个小写十六进制字符）。空权限列表不授予访问；省略的 limit 字段使用 Gateway 既有默认值，可通过认证后的发现接口查询。未知字段会被拒绝。profile 只引用已注册 effect，不安装 Provider；引用远程 Provider 时，该 Provider 必须先进入 Ready 状态。

`identity_path` 必须是具体的本地 `identity://...` 路径。Gateway 在发布 profile 前通过 Kernel 共享身份目录登记活动映射，请求复用已分配的身份编号。`process://...` 寻址进程资源，不能表示调用者身份。

`limits.max_recent_cancellations` 限制单个 Gateway 注册表保留的取消记录数量（默认 4096，设为零则不保留），不约束活动请求、借出的输出、其他 runtime 实例或总 RSS。响应或借出的输出块仍占用容量时，请求条目继续驻留。profile 替换会立即按新的较小上限裁剪历史。

`limits.max_deadline_ms_from_now` 限制已提供的任务期限，包括 `Submit` 和 `SubmitOutput` 从 `grpc-timeout` 得出的服务端上限。客户端任务期限与 `grpc-timeout` 都没有提供时，不会创建任务计时器；准入、预算和连接限额仍然生效。

`GatewayRuntime::new` 通过 Kernel 已安装的 `HostRuntime` 启动请求与对象维护；宿主无法调度所需任务时，构造会明确失败。自行调度维护的宿主可使用 `GatewayRuntime::new_manual`，持续调用 `maintain_once(&mut GatewayMaintenanceCursor)`，包括没有新请求的时段。每次调用先处理期限索引中所有已到期请求；具备所需 State 端口时，再独立尝试最多一页票据扫描和一页读取授权扫描。请求清扫没有单次数量上限，大量请求同时到期会增加一次维护的耗时。游标须跟随同一个 runtime；成功返回的报告说明对象扫描是否可用、本轮遇到的超额行数，以及未能确认的进程取消次数。任一类可用扫描失败时，另一类仍会尝试，本次调用最终返回错误；此前成功的条件删除保留，失败类别的游标在下次调用时从前缀起点重扫。手动 Gateway 维护不处理 Kernel 中被丢弃的进程清理；宿主在恢复遗留进程与受控关闭时还须调用 `Bootstrap::drain_cleanup()`。该操作可能等待其他清理 owner，不宜放进每次短周期维护。daemon 使用自动维护。

`GatewayRuntime::status().maintenance` 分别报告 `request_deadlines` 与 `object_records`。每项都有 `state`、`observed_for`、`since_last_attempt`、`since_last_success`、`active_attempts` 和 `consecutive_failures`，均按 Kernel 宿主单调时钟计量。请求维护只有在全部到期进程取消获确认时才算成功；对象维护只有在票据与读取授权两类扫描都成功时才算成功。`Active` 表示宿主仍持有自动任务，且最近成功维护未超告警窗口。请求超过一秒、对象超过 20 秒没有完整成功时转为 `Overdue`；首次成功前从进度记录建立时计时。future 退出或被 abort 后为 `Stopped`。`Manual` 仅记录 `maintain_once` 的调用；宿主自定周期，不套用自动超期阈值。对象记录的 `Unavailable` 表示 State 缺少查询或有界条件写端口，保留记录由宿主清理。`active_attempts` 统计重叠的维护轮次；取消的轮次会释放计数并记一次失败，`since_last_attempt` 则显示最近一轮的开始时间。profile 认证的 `readiness` 与维护状态分开，运维应同时观察。

随后选择已存在的 profile 并启用监听器：

```toml
[server]
application_grpc_addr = "127.0.0.1:9445"

[application_gateway]
profile = "tasks"

[application_gateway.request_storage]
max_records = 4096
max_bytes = 67108864
max_record_bytes = 1048576
retry_epoch_ms = 900000

[application_gateway.grpc]
max_frame_bytes = 65536
max_concurrent_uploads = 8
max_concurrent_output_responses = 8
output_window_chunks = 16
output_window_bytes = 262144
first_frame_timeout_ms = 15000
idle_timeout_ms = 30000
storage_timeout_ms = 120000

[application_gateway.grpc.transport_security]
mode = "local_trusted"
```

配置未指定地址时，读取 `XOLOTL_APPLICATION_GRPC_ADDR`。二者都没有时，不读取 profile、不创建应用 runtime、不绑定端口，也不启动其 watcher。启用后的 profile 若缺失、格式错误或无法编译，启动失败；不会创建默认 principal，也没有自动重新导入已删除权限的种子文件。未编译 `application-grpc` 时配置该入口会报错，不会静默忽略环境变量中的地址。

运行时订阅精确的 State 记录。有效的新版本替换已编译 profile；无效替换保留上个有效版本。记录删除或缺失、State 重读失败、订阅丢失、关闭或报错，都会关闭监听器并取消活动 RPC。监听器不会自动重订阅或恢复；修复 State 后需要重启 daemon 来重新创建。需要保留监听但撤销全部访问时，可写入更高版本、凭据和绑定均为空的 closed profile。文档准入和实际资源解析仍是两项检查。

## 协议

Gateway 本地观察记录（包括 MCP 发现与认证事件）在宿主未安装观察存储时可省略；已安装存储的写入失败仍然可见，必需记录使用独立的严格 API。授权、重试回执和交付检查不依赖观察历史。

嵌入调用可先构造无 payload 的 `GatewaySubmissionHead`，通过 `Gateway::prepare_submission(session, head, output_window)` 非等待地取得不可克隆的 `GatewayPreparation`，再用 `submit_prepared` 或 `submit_output_stream_prepared` 移交 payload 和 provenance。准备拥有者固定 runtime、会话、profile、提交头、输出窗口和原期限；跨 runtime 使用或选择错误输出入口会拒绝并释放本次容量。准备尚不生成受理身份，也不建立幂等保留。现有 `submit`／`submit_output_stream` 是取得一次准备准入的便捷入口，不能限制调用者事先构造 Value 的成本。

gRPC 在认证和提交头校验后、protobuf payload 转为 Value 前取得共享准入；MCP 在认证并解析 surface 后、原始参数转为 Value 前取得准入。语义摘要、幂等 CAS、输入检查和对象元数据读取都在同一准入内；执行接管既有 guard，不嵌套取得另一名额。输入流沿用 stream-open 准入，折叠完成不重新取得。原始传输解码、帧缓冲和调用者已构造的 Value 仍有独立内存成本，并发名额不是 RSS 限制。丢弃准备释放本地名额，但取消或未知 CAS 不删除持久 pending 证据，不证明票据消费或外部效果回滚。详见[提交与对象输入设计](application-gateway.md)。

schema 位于 `xolotl-proto` 的 `proto/xolotl/v1/application.proto`，服务名称为 `xolotl.v1.application.ApplicationGateway`。

| RPC | 约定 |
| --- | --- |
| `Describe` | 认证后返回脱敏的 profile 版本、可见 surface、publication 和业务限制；`max_frame_bytes` 单独报告此适配器的实际传输帧上限 |
| `LookupRequest` | 只读、有界的原请求证据摘要，不含结果载荷，不创建导出 |
| `DeliverRequestResult` | 显式交付保留的原结果，不再次执行业务；可外化对象并创建读取授权 |
| `IssueUploadTicket` | 返回绑定 principal/surface 的有界对象集合票据，可声明内容、媒体类型和有效期限制 |
| `UploadObject` | 客户端流 `Begin -> Chunk* -> Finish -> HTTP 输入正常结束`，返回类型化引用和回执 |
| `DownloadObject` | 接收显式读取授权和绝对字节范围；返回 `Header -> Chunk* -> Completed`，随后正常结束 gRPC |
| `Submit` | 接收 surface id、结构化 Value、可选回执来源和提交选项，返回接受信息与 `SubmissionCompletion` |
| `SubmitOutput` | 相同的类型化输入，显式请求 Stream；返回 `Accepted -> Chunk* -> Completed`，随后正常结束 gRPC |

`Describe.max_frame_bytes` 限制此传输的一份编码 protobuf 封套，不计 HTTP/2 头、
gRPC framing、累计流量、对象长度或 RSS。它是传输事实，不覆盖 Gateway 业务限额。

每个 RPC 分别认证一个 `authorization: Bearer <secret>`，或在 mTLS 模式下使用监听器验证过的叶证书。authority 匹配使用 HTTP/2 `:authority`，独立的 `host` 元数据不能替换它。Gateway 在同一 profile 快照中检查会话有效性和 authority，避免混用旧 Host 列表与新版本会话。只有配置过的代理地址能提供 forwarded authority。TLS 模式要求实际 tonic TLS 连接证据，本地模式要求已验证的 loopback peer；TLS 文件配置与 external gRPC 相同。

受信反向代理必须清除客户端传入的转发头，并将采用的 `X-Forwarded-Proto`、`X-Forwarded-Host` 或 `Forwarded` 字段覆盖为单值。追加链、重复头或重复采用的 `Forwarded` 参数会被拒绝；Gateway 无法推断代理实际观察到的是哪一项。若宿主提供 `GrpcConnectionInfo`，其中的 peer 地址就是权威事实，即使该地址缺失也不会从另一份连接信息补值。

上传 `Begin` 包含 ticket id、可选媒体类型、submission token，以及本次上传的预期大小与摘要。内建对象存储与 Gateway 对对象内容使用小写 SHA-384 摘要（96 个十六进制字符）。票据级预期大小或摘要只适用于 `max_objects = 1`；多对象票据可对每次上传分别声明。每个 `Chunk` 只包含字节。`Finish` 选择 Blob、Tensor（`dtype`、`shape`）或 Frame（`ts_nanos`、`kind`），由服务端计算摘要和长度。

将返回的 `item` 与 `provenance` 一起提交给票据绑定的 surface，不要凭猜测重建引用，也不能换用其他 principal 的证明。一份 provenance 命名一张票据；票据可以保存多个已提交 Blob、Tensor 和 Frame 绑定。结构化输入可组合或重复使用其中完整的类型化 item。保留相同字节却改写 Tensor 的 dtype、shape 或 Frame 的 kind、时间戳，会在读取共享对象元数据前被拒绝。

票据默认至多保存 16 个不同类型化成员、1 GiB 不同规范 backing bytes、256 KiB 编码 State 行。profile 可在实现上限内分别配置这三个限制，签发请求只能进一步收紧 profile 限额。记录大小的预检为 State 键与来源 envelope 预留 4 KiB，后端有界读写仍以 256 KiB 为最终物理约束。票据最多接受 32 个媒体类型模式、 64 个 Tensor 维度和 16 KiB 的内联回执元数据。票据点查与条件更新都要求精确路径的有界 State 读写能力，编码记录预算为 256 KiB。宿主须将这两项能力装配到同一当前值提交域，才能签发票据。

一次提交的全部类型化成员必须属于同一张票据，不能跨票据拼接。单次使用票据的提交须携带 `idempotency_key` 或 `submission_token`；Gateway 将其与完整内容绑定，运行 Driver 前消费整张票据。消费结果未知时停止执行并保留待定幂等保留。折叠输入流只有拿到完整 payload 后才建立保留或重放。追加结果未知且无法读回本次操作身份时，上传返回不确定结果；别人的相同内容不能证明本次追加成功。详见[提交与对象输入设计](application-gateway.md)。

State 提供有界查询及有界条件写入时，自动维护按宿主时钟每五秒最多扫描 16 条票据、256 KiB 编码记录，条件删除过期或已消费的当前行；手动维护在票据扫描成功时推进一页，重启后从前缀起点扫描。State 先交付超大行前面的部分页；Gateway 处理该页，下轮明确跳过拒绝行并报告 `skipped_oversized`，不逐行重放或增加第二份扫描预算。检查数包含部分页已检查但未消费的超大边界行。超大或损坏记录可能保留；显式选择 redb `Full` 时历史还保留旧事件，因此这不是存储总量上限。并发替换成超过票据预算的行后，条件更新会在 redb 解码前拒绝；此时来源未知，该行仍需单独修复。

`DownloadObject` 接收 `read_grant_id`、绝对字节 `offset` 和可选 `length`。省略长度表示读取授权范围的剩余部分，零表示空范围。Header 返回冻结的规范 BlobRef、选定范围、初始 taint 和固定有效期；每个 Chunk 携带绝对偏移、字节和当前来源。Completed 返回 `next_offset` 和累计 `bytes_read`，范围结束可以早于完整对象 EOF。空范围也需要确认 gRPC 正常结束。错误使用 gRPC status，与 AI 执行结果及缓存 origin 分别表达。

受信宿主先决定是否允许披露对象，再调用 `GatewayRuntime::issue_object_read_grant(session, IssueObjectReadGrantRequest)`。请求用 `object: TaintedValue` 携带直接的 Blob、Tensor 或 Frame，并选定 profile 中已知的 `surface_id`、绝对 `offset`、可选 `length` 和 `expires_in_ms`。授权有效期受 profile 的 deadline 窗口约束。签发要求 State 提供精确路径的有界点读和有界条件写入，并在有界提交前把完整记录及 taint 对照 256 KiB 维护分页预算预检。协议不暴露远程签发接口；已知哈希、上传回执和带 taint 的执行结果都不自动授予读取权限。应用可以组合自己的结果导出策略来调用宿主签发 API，服务不会递归扫描普通结果并自动导出引用。

对象读取委托与目录发现、任务提交分别授权。有效的已认证受众可以只有目录可见权限，也可以没有任何发现或提交绑定；宿主仍可向其显式签发读授权。任务提交继续遵守原有 capability 和 surface 准入规则。已知 surface 与目标用于绑定委托作用域，不授予任务执行权限。

不可变的版本化 State 记录绑定 profile 名称及版本、principal 和凭据的身份及 generation、认证方式、身份路径、surface 目标、精确对象与字节范围。State 的 tainted envelope 是唯一持久化来源权威。共享存储与这些绑定一致时，受信副本或重启后的 runtime 可以消费授权；打开授权及每次存储读取前后的核验使用 256 KiB 有界 State 点读，当前记录超额时拒绝使用。profile 版本变化会使旧授权失效，读取活动不会续期。宿主通过 `revoke_object_read_grant(session, grant_id)` 有界条件删除授权记录，内容不受影响。具备 State 分页查询与有界条件写入时，Gateway 维护还会按至多 16 行、256 KiB 的分页比较删除过期授权；损坏或超额记录需另行修复。具备有界点读及条件写入、但没有分页查询的宿主仍可签发，保留记录的清理由宿主负责。存储保留仍由宿主选择。

`SubmitOutput` 与 `Submit` 共用准入、回执消费、执行和清理流程，接受信息先于执行。每个输出块包含类型化 `item` 和服务端分配的 `taint`；taint 记录数据来源，不授予对象访问权限。surface 可用独立的 `output_stream_schema` 在交付前验证每个完整输出块，原有 `output_schema` 则验证最终值。块校验一旦失败，请求就会失败，即使 driver 忽略发送错误也不能报告成功。最终值校验失败时保留该结果的 taint；块校验失败时将被拒绝块的 taint 合入最终失败。其他输出块分别保留自己的来源信息。

提交选定的 surface 身份贯穿准入、配额和最终 schema 校验；多个 surface 可以用不同 schema 暴露同一个 effect，不再通过目标反查而混淆。已受理请求使用冻结的 profile，后续替换配置作用于新准入，不会单凭配置替换就取消已受理请求。显式取消请求和关闭监听器仍由各自的统一生命周期负责。

`SubmitResponse` 必须包含 `accepted`，其 `terminal` 只能是 `completion` 或 `indeterminate`。流式 `SubmitOutput` 先交付 `Accepted`，随后是零个或多个 `Chunk`，最后交付 `Completed` 或 `Indeterminate`。正常 `completion`／`Completed` 共用 `SubmissionCompletion { outcome, origin, taint, unresolved_operations }`。成功、失败及缓存完成都携带宿主已观察到的对账状态：`operation_ids` 列出已知的不透明身份，`identities_incomplete` 表示有身份未能保留。pristine 用显式存在的空 `TaintSet` 表示，缺失 taint 属于无效结果。Rust 普通 `submit` 与 `GatewayOutputEvent::Complete` 同样返回 `GatewaySubmitResult { accepted, output: ExecutionOutput, origin }`；整次请求的幂等重放也保留对账状态。完成结果在幂等持久化和进程清理之后交付；driver 的 `StreamEnd` 不决定请求最终结果。

origin 按报告结果的边界定义。单次调用命中缓存时，其 `DriverOutput` 和 `StreamEnd` 报告 `CompletionOrigin::CachedOutcome`。程序在新的 Gateway 请求中执行时，即使内部调用命中内核缓存，请求仍报告 `COMPLETION_ORIGIN_CURRENT_ATTEMPT`。只有 Gateway 复用整个请求结果时才报告 `COMPLETION_ORIGIN_CACHED_OUTCOME`。两层缓存都保存最终结果及其 taint，不回放历史块。Gateway 幂等记录使用 `gateway-idempotency-v1` 和请求存储必需的 tainted envelope，未知格式或损坏记录会被拒绝。执行后若结果持久化、进程清理或输出交付失败，且当前会话仍有原 surface 的提交权限、连接仍能交付终态帧，`indeterminate` 保留原 `accepted`、稳定的 `reason_code` 和有界 `unresolved_operations`；帧容不下全部 ID 时截断并置 `identities_incomplete`。它不包含程序 outcome，也不证明重试安全。受理前的未知仍用 gRPC `FAILED_PRECONDITION` 和 `x-xolotl-error-code: outcome_unknown` 报告。

客户端还需要确认 gRPC 正常结束；断线、响应丢失及无法容纳受理身份的极小帧都可能使证据无法交付。`LookupRequest` 无须重发载荷即可读取保留的请求证据，不执行工作，也不是通用 Driver 对账。未结算请求仍须由宿主或外部效果系统按原身份核对。没有保留原幂等材料或没有可查询的外部身份时，不能保证客户端自行消除不确定性，也不能改用新身份重试。taint 和缓存 origin 都不授予引用对象的访问权限。

`GatewayRuntime::new` 与 `new_manual` 必须显式接收第三参数 `Arc<dyn GatewayIdempotencyStore>`。同一请求证据作用域的多个 runtime 必须共享同一 store。嵌入式内存宿主可选择 `MemoryGatewayIdempotencyStore::default()` 或 `new(limits)`；持久宿主在 redb 的 `gateway` feature 下使用 `RedbStore::gateway_idempotency_store(limits)`。请求证据独立于普通 State 与执行状态，不进入 State 历史。daemon 按所选存储装配：`storage.kind = "memory"` 创建共享内存请求 store，`"redb"` 则使用同一 redb 数据库与受跟踪的 blocking 准入 owner。持久装配失败不会静默降级到内存；不支持的请求证据布局拒绝打开，不把留存证据替换为空账本。

`application_gateway.request_storage` 是 daemon 请求存储限额的主配置 owner，默认值直接来自 `GatewayIdempotencyLimits`：保留身份 4096 条，编码键／行及 pending 结果预留总共 64 MiB，单行编码上限 1 MiB。三个字段均须非零，总字节容量至少容纳一个键及其完整结果预留。这些计量不是进程 RSS，也不约束调用方已构造的 Value。执行前 reserve 预留完整结果容量，settle 仅一次释放未用字节；满额仍能观察与重放已有身份。准入失败只能释放原 pending 预留；取消、效果不确定或未知结果不能据此删除证据。超大或冲突的结果提交不改变证据与计量。

请求证据不自动退休。宿主只能显式 `retire` 已知 committed 且没有未决操作或缺失身份的结果；它释放结果字节，但保留完整 fingerprint、来源和条数，使旧材料不能再执行。对象票据维护不清理请求证据。持久重开保留原 usage 并要求同一 limits，修改限额不会静默重置容量。删除 pending 或 committed 后接受同材料可能重复效果，改变 profile 修订也不延续旧请求的去重保证，见[留存合同](application-gateway.md)。

## 重试范围

保留的 `pending` 行只证明身份已预留且没有已结算结果，不证明执行仍在运行。重开不会恢复执行；沿原身份重试不能重新分派。结果缺失不证明效果未发生。

每个已认证 surface 发布 `request_scope`。携带 `idempotency_key` 或 `submission_token` 的提交必须在 `SubmitOptions.expected_request_scope` 中保留该值。准备阶段用准入所采用的同一 Profile 快照检查它，早于载荷转换、证据预留及效果。账本、Profile、主体绑定、目标或 schema 变化会拒绝原范围。发现接口本身不是提交前条件：客户端必须保存并发送该值，而不是在重试时刷新它。范围不授予权限。

请求存储拥有证据命名空间。共享内存适配器使用同一身份，替换内存存储产生新身份。redb 将其存入 v1 元数据，重开保持不变；元数据缺失、无效或格式不支持时拒绝打开，不生成替代身份，也不自动迁移。新账本无法对账旧效果。命名空间不检测同一数据库回滚到旧备份。同一证据域内，Profile 版本仍须对应不可变声明。

`Describe.retry_epoch` 返回请求存储当前的重试范围。`SubmitOptions.retry_epoch` 选择该范围，默认值为 0；`idempotency_key` 与 `submission_token` 保持字面值语义及 256 字节上限。变更 epoch 是新请求，不是重试；客户端对未知请求进行对账时必须保留原 epoch，不能自动升级到新范围。

只有可信宿主调用 `GatewayIdempotencyStore::close_retry_epoch(expected)`，原子推进存储域屏障并回收符合条件的已关闭范围证据。这不是 TTL、profile revision 或 reset，也不提供客户端关闭 RPC。pending 与未知工作继续占额并可观察；沿原身份提交可查询或重放尚保留的证据，但绝不重新分派效果。redb 重开保留屏障；内存存储不承诺重启后的安全重试。精确回收条件和不确定提交处理归[请求存储 rustdoc](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-gateway/src/idempotency_store.rs)维护。

stock 应用 daemon 按宿主单调时钟关闭重试 epoch。`application_gateway.request_storage.retry_epoch_ms` 默认 900000 ms，接受 1–86400000；超限拒绝而非截断。该存储域的维护间隔独立于 profile 修订、结果留存和 Console 注册表。延迟唤醒只关闭一次，从确认完成时刻安排下一轮。容量与间隔须共同适配请求速率：关闭前仍可能满额，未决工作继续占额。

维护与 profile 观察在已有监督任务中并发推进，慢存储不推迟撤权。每次存储读取或关闭受 `application_gateway.grpc.storage_timeout_ms` 限制。失败、超时或提交不确定使服务和监听器停止；已接纳存储工作仍遵守后端恢复合同，不自动重试，也不暗示回滚。嵌入宿主自行选择关闭政策。

## 原请求查询

Rust `Gateway::lookup_request` 与 gRPC `LookupRequest` 要求原 surface、`request_scope`、
重试 epoch，以及唯一的幂等 key 或提交 token；原提交同时有两者时，使用 key。
查询仍检查当前会话与 surface 权限；范围变化时拒绝，而不是搜索另一 Profile 或账本。
已关闭 epoch 内保留的证据仍可查询，查询不打开或推进 epoch。

仅携带提交 token 不会让所有纯调用自动保留结果；此类调用可能返回无法证明。
显式幂等 key 选择请求留存；必须使用 token 防重放的情形仍遵守原提交合同。

结果分别为 `unproven`（没有保留证据，不证明未执行）、`reserved`（预留，不证明受理或
仍在运行）、`settled`（原受理身份、Done／Short／Fail 结果类别及有界未决操作，不含结果内容或错误详情），
以及 `retired`（结果不可用，不允许重跑）。不回放历史流块；记录损坏是错误，不报告
`unproven`。已结算证据超出帧预算时返回容量错误，不伪造执行结果或未结算状态。

查询使用精确读取，不占执行准入、不创建 Process、不预留或结算请求、不写审计或对象／授权、不扫描。
存储期限与响应窗口仍有界，交付前复核当前权限。响应丢失后保留原身份；更换 key、scope
或 epoch 是新请求，不是恢复原请求。
后端仍在 `request_storage.max_record_bytes` 内读取和解码一条记录；小 wire 摘要不代表
存储工作或分配与载荷大小无关。查询检查元数据及必需载荷字段形态，完整载荷编解码由结果交付检查。

`DeliverRequestResult` 使用相同原请求身份和当前会话／surface 授权，但显式请求保留的载荷。
它通过已有结果交付路径返回 cached completion，不执行业务，也不回放历史流块。
安装结构化输出 externalizer 后，交付可能写入对象和读取授权，因此不是纯观察。
编码与最终移交前复核当前交付权限；Unproven、Reserved、Retired 返回 `FAILED_PRECONDITION`，均不授权重跑。
超大结果要求安装 externalizer；交付失败不改变已结算证据。
结果编码由已安装的适配器／externalizer 选择，不由提交选项 `requested_encoding` 选择；该字段已移除。

## 资源归属

对象授权清理移除授权 Value，不保证删除当前 State 记录。有来源删除在 `CurrentOnly` 下仍保留缺席来源，历史裁剪不释放它。内存与 redb 后端均原子执行配置的缺席记录数和编码字节额度；超额增长被拒绝，不会部分删除原值。宿主须将当前域留存与历史、对象内容分别计量，到期不证明存储空间已回收。这些额度不限制分配器字节或 RSS。见[状态与事实记录](state-and-facts.md)。

Gateway 持有请求清理 pin，直到 finalization custody 已完成且能取得提交后的 `ProcessFinalizationReport`；先将 finalizer 的 taint 和未决效果合并进正文输出，再缓存或交付，不用已知类型化 finalizer 失败替换正文 outcome。报告缺失、custody 未完成或终结错误仍是不确定结果，保留 pending 幂等证据，不能据此重新执行；报告存在本身不证明清理完成。折叠流重放把本次请求的清理证据合并进交付结果，但不改写原缓存。协议投影正文及累计 taint／未决效果，而不是完整的运行时清理报告。

每个上传 RPC 持有一个既有 `GatewayObjectUpload` 和一个共享 semaphore permit，超过并发窗口立即失败。适配器读取一帧，将字节借给存储写入，完成后才读取下一帧，不保留累计载荷缓冲。存储写入窗口最多 16 KiB。protobuf 帧包含封装开销，字节块必须小于 `max_frame_bytes`。

帧大小和并发窗口不限制累计对象长度，可以上传未知总大小的数据；票据显式约束和当前回执大小的 `i64::MAX` 表示范围仍生效。首帧、后续完整帧和存储操作分别有可配置等待窗口，无效配置会报错，不静默钳制。这些等待窗口不延长票据绝对有效期，也不替代任务准入期限。

下载持有一个基于既有可选对象读端口的 `GatewayObjectDownload`，不创建内核进程、后台生产任务或 reader 注册表。传输只保留一个最多为 `min(max_frame_bytes, 16 KiB)` 的字节窗口，按包含 taint 的实际 protobuf 编码大小拆帧。允许部分读取；无进度、偏移错误或与物理 EOF 不一致都会关闭读取所有者。对象长度与范围使用 `u64`，不受上传回执有符号长度表示的约束；空范围不读取对象字节。

每次存储读取前后及完成时，重新检查 State 中授权的完整值和来源；每帧交付前还检查活动会话与到期状态。已被轮询的读取失败或取消后，所有者关闭，调用方不能交付失败读取留下的缓冲内容。撤销会阻止后续授权读取，已经确认读取或进入传输缓冲的字节无法收回。每块 taint 合并打开时的来源、授权来源与本次读取来源，不累计已交付块的历史。多次读取不会固定对象以阻止删除，删除可能中断下载；同哈希重新发布仍代表相同字节，本次读取的来源信息仍会合入输出。

输出响应持有执行 future 和一个内核通道，传输轮询同时推进二者，不创建后台生产任务或第二条输出队列。`output_window_chunks` 和 `output_window_bytes` 限定已接受及消费者借出的内核块；字节计费采用值和来源的 tagged JSON 编码，不等同于 protobuf 字节数或 RSS。内核信用在有界 protobuf 转换完成后释放，之后由 tonic 持有副本。累计输出可以超过窗口而不积累历史块；编码器、HTTP/2 缓冲、单块转换和最终结果仍有独立的驻留成本。

`max_concurrent_output_responses` 由 Unary、流式输出和对象下载共享，限定尚在驻留的响应体，包括慢客户端和传输缓冲，其 permit 同时跟随响应体和移交 HTTP/2 的编码 DATA 字节，不复制载荷，最后一个所有者销毁后才释放。Gateway 的准入和预算许可同样跟随响应及借出的结果块，不延长已取消执行的进程寿命。取消或截止时间到达会撤销执行权限，但不会释放仍由活动响应占用的容量。慢 HTTP/2 客户端可能使响应不再被轮询，因此逻辑取消不能保证立刻销毁正在等待的 driver future。监听器关闭还会中断连接 I/O，以释放这类停滞响应。

最后一个请求 lease 释放后，只有已取消请求可能进入紧凑历史。同一 principal、Gateway 和 trace root 在取消决定后的 60 秒内可重复取消，有效期由 Kernel 的宿主单调时钟计量；达到 profile 上限时先逐出最早到期的记录，被逐出的重复取消返回 false。正常完成、失败及过期请求随最后一个 lease 一起离开请求表。截止时间扫描只索引确有任务 deadline 的活动请求，不遍历无 deadline 请求或取消历史。60 秒的逻辑有效期与物理回收分开：自动维护或后续请求表操作会裁剪过期历史；手动模式可在下一次维护或请求表操作前保留过期墓碑，但数量仍受配置上限约束。

入口在解码前捕获 `grpc-timeout`，将传输期限保留到响应结束。`Submit` 和 `SubmitOutput` 交给 Gateway 时都按剩余时间在所属宿主时钟域建立期限；Gateway 与客户端提供的绝对任务期限在同一单调域取更早者，执行器和过期扫描共用结果。执行及输出校验结束后，先决定取消或过期是否生效，并冻结正文结果，再清理进程、合并终结来源与未决效果，最后持久化完整幂等结果；这些决定保留累计 taint。任务截止时间尚未到达时，driver 返回的 `Timeout` 仍是普通驱动失败。完成决定之后，任务截止时间不再改写结果或丢弃排队输出，RPC 截止时间仍约束后续交付。RPC 过期后恢复响应轮询时，以 `DeadlineExceeded` 结束响应体。

缺帧、乱序、尾随帧、连接 reset、等待超时和关闭都会释放请求所有者。提交内容需要协议结束标记和真实 HTTP 请求体正常结束两项证据，因为 tonic 可能把 HTTP/2 CANCEL 转换为表面上的流 EOF。commit 或回执 CAS 期间取消，可能留下已发布内容或结果不确定的回执；不能为撤销不确定结果而删除共享内容。

关闭还会取消尚在解码、未进入 handler 的请求。daemon 将关闭信号传到连接读写，让未完成 HTTP/2 preface 或停止读取响应的客户端也不能使 tonic 内部连接任务一直存活。

stock daemon 将 application 服务与其他监听器、后台任务放在同一宿主生命周期作用域中。Kernel 建成后，启动错误和信号等待错误与正常退出使用相同异步收尾，完成后才返回原错误。收尾关闭 application 准入，复用服务的执行关闭与传输排空，等待后台任务终结，排空进程清理，最后等待共享阻塞端口的已接纳作业。取消 application 关闭 Future 不会丢弃待决任务句柄；直接丢弃整个宿主作用域只发出任务取消，不能代替完整异步收尾，也不回滚已经提交的外部效果。

daemon 同时观察必需监听器和维护任务的终结。意外正常返回、服务错误、panic 或外部 abort 都触发共同收尾并非零退出，不继续以缺失必需服务的状态运行。明确删除或确认缺失 application profile 只关闭本服务，丢失 profile 订阅或读取失败则升级到宿主。无效 profile 更新仍保留原已接受版本。daemon 不自动重启任务，也不隐式重放已接受工作；任务终结观察不检测悬挂或证明远端服务健康。

## 当前输出范围

`Submit` 支持 Unary 和 Collect，明确拒绝 Stream、AsyncProcess 和 SinkOnly，因为该 RPC 返回已完成的单次响应。内联输入、收集的结果、protobuf 解码和传输缓冲各有内存成本。帧限制也适用于响应，结果过大可能在执行后返回失败，重试仍应遵守幂等约定。

出站 `Value` 字段还遵守共享 protobuf 编码器的 30 层嵌套限制，每个值的根节点计为第一层，为 prost 默认解码递归上限内的封装消息留出空间。此限制适用于结果及发现接口的 schema 和 metadata；即使响应小于帧上限，超深仍返回 `ResourceExhausted`。增大 `max_frame_bytes` 不会提高此深度上限。

启用可选的 `xolotl-gateway-grpc/structured-output` feature 后，宿主可以通过 `ApplicationGrpcService::with_output_externalizer` 安装对象交付。适配器先尝试有界内联编码，超出单帧或嵌套预算时，轮询一个独占 Gateway 外置 Future。宿主显式选择 I/O 窗口、异步 key 工作区工厂和披露策略。内容发布及规范元数据读取先于策略判断和读取授权提交；策略看到原始输出、已认证受众、当前完整元数据和本次确切过期时间，不默认允许披露。

`OutputValue` 和 `OutputFailure` 分别选择唯一的内联或对象表示，`OutputOutcome` 独立保留 Done、Short 和 Fail。对象交付包含显式 encoding、完整 BlobRef、读取授权 ID 与到期时间；失败对象保存共享的完整外部标签 Failure 布局。完成来源与 taint 仍然必需，缓存结果也相同。外置错误只影响交付，不改写执行结果或幂等缓存；嵌套引用不获得授权。

`SubmitOutput` 在编码、策略等待和有界协议转换期间保留原始块的信用。同一个执行 owner 继续处理请求取消和截止时间；中断时先放弃当前编码，再交付原请求真正的最终失败。不增加生产任务或输出队列。Unary、流式输出和下载共享传输并发窗口，直到 HTTP/2 DATA 的最后所有者释放。编码文档可超过单帧和内联深度上限，消费者通过增量下载校验到真实正常 EOF。

准入元数据、对象描述符和对外声明的来源仍须装入响应帧。外置载荷不会移除这些元数据边界，也不会降低显式完整物化所需的内存。CBOR 编码逻辑树中的每次出现，极高共享率的常驻 DAG 可能显著膨胀；传输窗口不隐含累计对象或流字节上限。

`DownloadObject` 交付经宿主显式签发授权的字节，daemon 尚未安装通用的 Provider 结果导出策略，宿主在组合服务时明确选择策略。`value/read` 或 `ValueObjectReader` 显式消费结构化对象；推理后端不隐式加载引用，应用上传回执也不授予 Provider/Source 或 MCP 权限。
