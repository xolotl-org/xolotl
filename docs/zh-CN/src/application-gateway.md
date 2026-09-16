# 应用网关

应用 gRPC 监听器暴露一个按 profile 装配的 `GatewayRuntime`。它的 principal 和
surface 与外部 Provider/Source 会话分别准入。daemon 将同一个 ObjectStore 的克隆
交给 Standard 和应用 runtime；State 保存授权记录和回执，对象存储保存内容。

## 配置

可单独构建此可选入口：

```sh
cargo build -p xolotl-daemon --no-default-features --features application-grpc --locked
```

首次配置时启用持久 State 和 Console，暂不设置应用监听地址。通过已认证 Console 的
`config.write_cas` 创建 `state://kernel/gateway/profiles/tasks`。输入包含 `path`、
profile `value` 和创建时的 `expected_version: null`。此动作要求写权限和既有 MFA
step-up；Console 自动填写 `version: 1`，后续更新携带读到的 `expected_version` 并递增。

profile 文档集中声明凭据、身份映射、surface、绑定、注册的 authority 和 Gateway
准入限制。例如：

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
    "identity_path": "process://application/worker"
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

`token_hash` 的全零值是占位符，应替换为高熵 bearer secret 的小写 BLAKE3 摘要，
profile 不存原始密钥。客户端证书使用 `kind: "client_certificate"` 和 `der_sha256`。
空权限列表不授予访问；省略的 limit 字段使用 Gateway 既有默认值，可通过认证后的发现
接口查询。未知字段会被拒绝。profile 只引用已注册 effect，不安装 Provider；引用远程
Provider 时，该 Provider 必须先进入 Ready 状态。

随后选择已存在的 profile 并启用监听器：

```toml
[server]
application_grpc_addr = "127.0.0.1:9445"

[application_gateway]
profile = "tasks"

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

配置未指定地址时，读取 `XOLOTL_APPLICATION_GRPC_ADDR`。二者都没有时，不读取
profile、不创建应用 runtime、不绑定端口，也不启动其 watcher。启用后的 profile
若缺失、格式错误或无法编译，启动失败；不会创建默认 principal，也没有自动重新导入
已删除权限的种子文件。
未编译 `application-grpc` 时配置该入口会报错，不会静默忽略环境变量中的地址。

运行时订阅精确的 State 记录。有效的新版本替换已编译 profile；无效替换保留上个有效
版本。记录删除或缺失、State 重读失败、订阅丢失、关闭或报错，都会关闭监听器并取消
活动 RPC。监听器不会自动重订阅或恢复；修复 State 后需要重启 daemon 来重新创建。
需要保留监听但撤销全部访问时，可写入更高版本、凭据和绑定均为空的 closed profile。
文档准入和实际资源解析仍是两项检查。

## 协议

schema 位于 `xolotl-proto` 的 `proto/xolotl/v1/application.proto`，服务名称为
`xolotl.v1.application.ApplicationGateway`。

| RPC | 约定 |
| --- | --- |
| `Describe` | 认证后返回脱敏的 profile 版本、可见 surface、publication 和限制 |
| `IssueUploadTicket` | 返回绑定 principal/surface 的票据，可声明大小、摘要、媒体类型和有效期 |
| `UploadObject` | 客户端流 `Begin -> Chunk* -> Finish -> HTTP 输入正常结束`，返回类型化引用和回执 |
| `DownloadObject` | 接收显式读取授权和绝对字节范围；返回 `Header -> Chunk* -> Completed`，随后正常结束 gRPC |
| `Submit` | 接收 surface id、结构化 Value、可选回执来源和提交选项，返回接受信息与 `SubmissionCompletion` |
| `SubmitOutput` | 相同的类型化输入，显式请求 Stream；返回 `Accepted -> Chunk* -> Completed`，随后正常结束 gRPC |

每个 RPC 分别认证一个 `authorization: Bearer <secret>`，或在 mTLS 模式下使用监听器
验证过的叶证书。authority 匹配使用 HTTP/2 `:authority`，独立的 `host` 元数据不能替换
它。Gateway 在同一 profile 快照中检查会话有效性和 authority，避免混用旧 Host 列表与
新版本会话。只有配置过的代理地址能提供 forwarded authority。TLS 模式要求实际 tonic TLS
连接证据，本地模式要求已验证的 loopback peer；TLS 文件配置与 external gRPC 相同。

上传 `Begin` 包含 ticket id、可选媒体类型和 submission token。每个 `Chunk` 只包含
字节。`Finish` 选择 Blob、Tensor（`dtype`、`shape`）或 Frame（`ts_nanos`、`kind`），
由服务端计算摘要和长度。将返回的 `item` 与 `provenance` 一起提交给票据绑定的 surface，
不要凭猜测重建引用，也不能换用其他 principal 的证明。

`DownloadObject` 接收 `read_grant_id`、绝对字节 `offset` 和可选 `length`。
省略长度表示读取授权范围的剩余部分，零表示空范围。Header 返回冻结的规范 BlobRef、
选定范围、初始 taint 和固定有效期；每个 Chunk 携带绝对偏移、字节和当前来源。
Completed 返回 `next_offset` 和累计 `bytes_read`，范围结束可以早于完整对象 EOF。
空范围也需要确认 gRPC 正常结束。错误使用 gRPC status，与 AI 执行结果及缓存 origin
分别表达。

受信宿主先决定是否允许披露对象，再调用
`GatewayRuntime::issue_object_read_grant(session, IssueObjectReadGrantRequest)`。
请求用 `object: TaintedValue` 携带直接的 Blob、Tensor 或 Frame，并选定 profile 中已知的
`surface_id`、绝对 `offset`、可选 `length` 和 `expires_in_ms`。授权有效期受 profile
的 deadline 窗口约束。协议不暴露远程签发接口；已知哈希、上传回执和带 taint 的执行结果
都不自动授予读取权限。应用可以组合自己的结果导出策略来调用宿主签发 API，服务不会递归
扫描普通结果并自动导出引用。

对象读取委托与目录发现、任务提交分别授权。有效的已认证受众可以只有目录可见权限，
也可以没有任何发现或提交绑定；宿主仍可向其显式签发读授权。任务提交继续遵守原有
capability 和 surface 准入规则。已知 surface 与目标用于绑定委托作用域，不授予任务
执行权限。

不可变的版本化 State 记录绑定 profile 名称及版本、principal 和凭据的身份及 generation、
认证方式、身份路径、surface 目标、精确对象与字节范围。State 的 tainted envelope 是唯一
持久化来源权威。共享存储与这些绑定一致时，受信副本或重启后的 runtime 可以消费授权；
profile 版本变化会使旧授权失效，读取活动不会续期。宿主通过
`revoke_object_read_grant(session, grant_id)` 比较后删除授权记录，内容不受影响。
到期本身不回收 State 记录，保留策略由宿主选择。

`SubmitOutput` 与 `Submit` 共用准入、回执消费、执行和清理流程，接受信息先于执行。
每个输出块包含类型化 `item` 和服务端分配的 `taint`；taint 记录数据来源，不授予对象
访问权限。surface 可用独立的 `output_stream_schema` 在交付前验证每个完整输出块，
原有 `output_schema` 则验证最终值。块校验一旦失败，请求就会失败，即使 driver 忽略
发送错误也不能报告成功。最终值校验失败时保留该结果的 taint；块校验失败时将被拒绝块的
taint 合入最终失败。其他输出块分别保留自己的来源信息。

提交选定的 surface 身份贯穿准入、配额和最终 schema 校验；多个 surface 可以用不同
schema 暴露同一个 effect，不再通过目标反查而混淆。已受理请求使用冻结的 profile，
后续替换配置作用于新准入，不会单凭配置替换就取消已受理请求。显式取消请求和关闭
监听器仍由各自的统一生命周期负责。

`SubmitResponse.completion` 与 `SubmitOutput` 的 `Completed` 事件共用
`SubmissionCompletion { outcome, origin, taint }`。应用协议要求每个完成结果都包含
`outcome` 和 `taint`，失败与缓存结果也不例外。pristine 用显式存在的空 `TaintSet`
表示，缺失 taint 属于无效结果。Rust 普通 `submit` 与 `GatewayOutputEvent::Complete`
同样返回 `GatewaySubmitResult { accepted, output: ExecutionOutput, origin }`。
完成结果在幂等持久化和进程清理之后交付；driver 的 `StreamEnd` 不决定请求最终结果。

origin 按报告结果的边界定义。单次调用命中缓存时，其 `DriverOutput` 和 `StreamEnd`
报告 `CompletionOrigin::CachedOutcome`。程序在新的 Gateway 请求中执行时，即使内部
调用命中内核缓存，请求仍报告 `COMPLETION_ORIGIN_CURRENT_ATTEMPT`。只有 Gateway
复用整个请求结果时才报告 `COMPLETION_ORIGIN_CACHED_OUTCOME`。两层缓存都保存最终
结果及其 taint，不回放历史块。Gateway 幂等记录使用 `gateway-idempotency-v1` 和 State
必需的 tainted envelope，未知格式或损坏记录会被拒绝。

客户端还需要确认 gRPC 正常结束，断线和传输编码失败不能证明请求已完成。taint 和
缓存 origin 都不授予引用对象的访问权限。

## 资源归属

每个上传 RPC 持有一个既有 `GatewayObjectUpload` 和一个共享 semaphore permit，
超过并发窗口立即失败。适配器读取一帧，将字节借给存储写入，完成后才读取下一帧，不保留
累计载荷缓冲。存储写入窗口最多 16 KiB。protobuf 帧包含封装开销，字节块必须小于
`max_frame_bytes`。

帧大小和并发窗口不限制累计对象长度，可以上传未知总大小的数据；票据显式约束和当前
回执大小的 `i64::MAX` 表示范围仍生效。首帧、后续完整帧和存储操作分别有可配置等待
窗口，无效配置会报错，不静默钳制。这些等待窗口不延长票据绝对有效期，也不替代任务准入
期限。

下载持有一个基于既有可选对象读端口的 `GatewayObjectDownload`，不创建内核进程、
后台生产任务或 reader 注册表。传输只保留一个最多为 `min(max_frame_bytes, 16 KiB)`
的字节窗口，按包含 taint 的实际 protobuf 编码大小拆帧。允许部分读取；无进度、偏移
错误或与物理 EOF 不一致都会关闭读取所有者。对象长度与范围使用 `u64`，不受上传回执
有符号长度表示的约束；空范围不读取对象字节。

每次存储读取前后及完成时，重新检查 State 中授权的完整值和来源；每帧交付前还检查
活动会话与到期状态。已被轮询的读取失败或取消后，所有者关闭，调用方不能交付失败
读取留下的缓冲内容。撤销会阻止后续授权读取，已经确认读取或进入传输缓冲的字节无法
收回。每块 taint 合并打开时的来源、授权来源与本次读取来源，不累计已交付块的历史。
多次读取不会固定对象以阻止删除，删除可能中断下载；同哈希重新发布仍代表相同字节，
本次读取的来源信息仍会合入输出。

输出响应持有执行 future 和一个内核通道，传输轮询同时推进二者，不创建后台生产任务或
第二条输出队列。`output_window_chunks` 和 `output_window_bytes` 限定已接受及
消费者借出的内核块；字节计费采用值和来源的 tagged JSON 编码，不等同于 protobuf
字节数或 RSS。内核信用在有界 protobuf 转换完成后释放，之后由 tonic 持有副本。
累计输出可以超过窗口而不积累历史块；编码器、HTTP/2 缓冲、单块转换和最终结果仍有
独立的驻留成本。

`max_concurrent_output_responses` 由 Unary、流式输出和对象下载共享，限定尚在驻留的响应体，
包括慢客户端和传输缓冲，
其 permit 同时跟随响应体和移交 HTTP/2 的编码 DATA 字节，不复制载荷，最后一个
所有者销毁后才释放。Gateway 的准入和预算许可同样跟随响应及借出的结果块，
不延长已取消执行的进程寿命。
取消或截止时间到达会撤销执行权限，但不会释放仍由活动响应占用的容量。慢 HTTP/2
客户端可能使响应不再被轮询，因此逻辑取消不能保证立刻销毁正在等待的 driver future。
监听器关闭还会中断连接 I/O，以释放这类停滞响应。

入口在解码前捕获 `grpc-timeout`，将绝对截止时间保留到响应结束，并收紧提交的任务
截止时间。Gateway 将任务截止时间转换一次为单调时间点，供执行器和过期扫描共用。
执行及输出校验结束后，先决定取消或过期是否生效，并冻结请求结果，再持久化缓存和清理
进程；这些决定保留最终 taint。任务截止时间尚未到达时，driver 返回的 `Timeout` 仍是
普通驱动失败。完成决定之后，任务截止时间不再改写结果或丢弃排队输出，RPC 截止时间
仍约束后续交付。RPC 过期后恢复响应轮询时，以 `DeadlineExceeded` 结束响应体。

缺帧、乱序、尾随帧、连接 reset、等待超时和关闭都会释放请求所有者。提交内容需要协议
结束标记和真实 HTTP 请求体正常结束两项证据，因为 tonic 可能把 HTTP/2 CANCEL 转换为
表面上的流 EOF。commit 或回执 CAS 期间取消，可能留下已发布内容或结果不确定的回执；
不能为撤销不确定结果而删除共享内容。

关闭还会取消尚在解码、未进入 handler 的请求。daemon 将关闭信号传到连接读写，
让未完成 HTTP/2 preface 或停止读取响应的客户端也不能使 tonic 内部连接任务一直存活。

## 当前输出范围

`Submit` 支持 Unary 和 Collect，明确拒绝 Stream、AsyncProcess 和 SinkOnly，因为该
RPC 返回已完成的单次响应。内联输入、收集的结果、protobuf 解码和传输缓冲各有内存成本。
帧限制也适用于响应，结果过大可能在执行后返回失败，重试仍应遵守幂等约定。

出站 `Value` 字段还遵守共享 protobuf 编码器的 30 层嵌套限制，每个值的根节点计为
第一层，为 prost 默认解码递归上限内的封装消息留出空间。此限制适用于结果及发现接口的
schema 和 metadata；即使响应小于帧上限，超深仍返回 `ResourceExhausted`。
增大 `max_frame_bytes` 不会提高此深度上限。

启用可选的 `xolotl-gateway-grpc/structured-output` feature 后，宿主可以通过
`ApplicationGrpcService::with_output_externalizer` 安装对象交付。适配器先尝试
有界内联编码，超出单帧或嵌套预算时，轮询一个独占 Gateway 外置 Future。宿主显式选择
I/O 窗口、异步 key 工作区工厂和披露策略。内容发布及规范元数据读取先于策略判断和读取
授权提交；策略看到原始输出、已认证受众、当前完整元数据和本次确切过期时间，不默认允许披露。

`OutputValue` 和 `OutputFailure` 分别选择唯一的内联或对象表示，`OutputOutcome`
独立保留 Done、Short 和 Fail。对象交付包含显式 encoding、完整 BlobRef、读取授权 ID
与到期时间；失败对象保存共享的完整外部标签 Failure 布局。完成来源与 taint 仍然必需，
缓存结果也相同。外置错误只影响交付，不改写执行结果或幂等缓存；嵌套引用不获得授权。

`SubmitOutput` 在编码、策略等待和有界协议转换期间保留原始块的信用。同一个执行
owner 继续处理请求取消和截止时间；中断时先放弃当前编码，再交付原请求真正的最终失败。
不增加生产任务或输出队列。Unary、流式输出和下载共享传输并发窗口，直到 HTTP/2 DATA
的最后所有者释放。编码文档可超过单帧和内联深度上限，消费者通过增量下载校验到真实正常 EOF。

准入元数据、对象描述符和对外声明的来源仍须装入响应帧。外置载荷不会移除这些元数据边界，
也不会降低显式完整物化所需的内存。CBOR 编码逻辑树中的每次出现，极高共享率的常驻 DAG
可能显著膨胀；传输窗口不隐含累计对象或流字节上限。

`DownloadObject` 交付经宿主显式签发授权的字节，daemon 尚未安装通用的 Provider
结果导出策略，宿主在组合服务时明确选择策略。`value/read` 或 `ValueObjectReader`
显式消费结构化对象；推理后端不隐式加载引用，应用上传回执也不授予 Provider/Source 或 MCP 权限。
