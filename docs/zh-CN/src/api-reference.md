# API 参考

Rustdoc 是工作区的公开 API 参考。

用缺失文档检查生成：

```sh
RUSTDOCFLAGS='-D warnings -W missing-docs' cargo doc --workspace --all-features --no-deps --locked
```

打开工作区首页：

```text
target/doc/index.html
```

单个 Rust 包页面位于：

```text
target/doc/<crate_name>/index.html
```

Cargo 会把 Rust 包名里的连字符转换为下划线。例如：

```text
xolotl-sdk      -> target/doc/xolotl_sdk/index.html
xolotl-kernel   -> target/doc/xolotl_kernel/index.html
xolotl-standard   -> target/doc/xolotl_standard/index.html
```

## 阅读顺序

嵌入运行时：

- `xolotl-core`
- `xolotl-sdk`
- `xolotl-graph`
- `xolotl-types`
- `xolotl-kernel`

SDK 默认只导出 `xolotl_sdk::core`。无 allocator 宿主从 `ProgramImage`、`Values` 和
`Execution` 开始；启用 `host` 后提供 `Program`、`Expression`、`PreparedProgram`、
`ExecutionConfig`、`ExecutionLayout`、`ExecutionBuffers` 和 `Xolotl::run_prepared`。
`ProgramImage::resource_requirements` 提供无分配的资源分析；`PreparedProgram::layout`
按宿主配置报告执行容器大小；`run_prepared_with_buffers` 复用调用方的空闲容器。

prepared 执行接收 `TaintedValue { value, taint }`。portable `LinkedExecution` 和托管
Executor 返回 `ExecutionOutput { outcome, taint }`；SDK 执行入口返回
`Result<ExecutionOutput, XolotlError>`。`ExecutionOutput::into_result` 将来源保留在
`Result<TaintedValue, TaintedFailure>` 中，`TaintedFailure::into_value` 将诊断转为
下个程序的输入时也保留来源。调用用量与缓存 origin 属于单次调用边界，不放入 `ExecutionOutput`。
`Executor::with_deadline(tokio::time::Instant)` 按单调截止时间停止执行，保留已知活动来源并
释放待完成调用；进程终结仍由请求所有者负责。

`Execution::suspend` / `resume` 校验并交接活动存储，不克隆值；可选宿主利用此接口
在字节预算内为原生扩展增长容量。
用 `XolotlBuilder` 接入宿主状态与事实后端；
`durable` 提供检查点接口，`standard` 提供 Provider 安装 API。
`ExecutionIds` 与 `ExecutionIdSource` 将身份命名空间独立为可替换适配器，Kernel、Executor
及 SDK builder 均提供 `with_execution_ids`。构造函数
`OperationId::new(process, execution, invocation, position, attempt)` 与
`FromStr` / `Display` 共用五段格式；`to_bytes` 返回规范的 32 字节键，`retry` 在重试次数耗尽时返回 `None`。
feature 组合与恢复约定见[核心与可移植程序](core-and-portable.md)。
`Bootstrap::request_under` 用预编译授权创建拥有生命周期的请求。
`Arc<Bootstrap>` 上的 `request_under_owned` 返回持有共享宿主的同一种请求作用域，
可交给独立任务或已接受的输入流。两种持有方式共用取消与终结逻辑，借用方式不增加共享引用。
通过
`RequestProcess::executor` 创建执行器、`finish(&ExecutionOutput)` 提交终结清理并保留
body 状态的来源信息，或通过 `detach`
显式转交生命周期责任。SDK 普通执行入口自动使用该作用域。请求丢弃或终结中断后，
`Bootstrap::drain_cleanup` / `Xolotl::drain_cleanup` 返回 `ProcessCleanupReport`，
包含完成的进程树数量和保留的失败。丢弃单独的 Executor Future 不会结束进程；
SDK 持久化执行转交给恢复路径，丢弃时不排队取消请求。
`XolotlBuilder::with_process_capacity(NonZeroUsize)` 限制保留的进程条目数量。
`ProcessTable::set_capacity` 调整共享上限，`len` 包含终态与待清理条目。
`reap_finalized(limit)` 在完成后显式回收满足条件的叶子，保留仍有子进程的祖先与持久历史。
容量不足返回 `BootstrapError::ProcessAdmission(ProcessAdmissionError::Capacity)`。
首次实际回收后，任意历史快照需在新 Kernel 中导入。当前存储行通过独占租约恢复，
可在同一 Kernel 中继续推进积压任务。

首版宿主检查点保留值与失败的来源，所有字段、活动模块代码和绑定共用一张 Value 节点表。
程序加载器必须声明 `LoaderRevision`。通过 `Executor::with_steps` 或
`checkpoint_recovery()?.with_steps(module)` 重新连接 `StepModule`；恢复校验修订后使用
已保存的展开镜像继续执行。缺失 taint、未知格式、非法模块范围和加载器修订变化均被拒绝。
核心格式独立于宿主持久化格式。
`durable` 还导出 `CheckpointQuery`、`CheckpointInfo`、`DurableRecoveryConfig` 和
`DurableRecovery`。用 builder 的 `with_checkpoint_recovery_config` 设置分页数量、共享恢复
并发及显式回收批次；`ExecutionConfig::max_checkpoint_bytes` 限制读写编码大小。
应用准入前调用 `reserve_checkpoint_process_ids`，安装权限后创建 `checkpoint_recovery()`，
通过 `advance()` 处理下一页。`deferred` 表示容量不足，`complete` 表示扫描区间结束；
已调度程序可能仍在等待 I/O。存储适配器需实现有界 `scan`、`high_water`、`try_acquire`，
以及租约的有界 `load`、`commit` 和持久 `retire`。
`FactQuery`、`FactOrder` 与 `FactPage` 定义双向 Fact 读取，分别限制结果条数、候选数
和编码字节。使用 `query.next_page(&page)` 续页，筛选后的空页也可能尚未结束。
自定义 `FactStore` 必须实现 `scan` 及按身份索引的 `lookup(FactLookup)`。点查先筛选当前
调用进程再消耗字节预算，返回 `FactLookupResult::{Found, Missing, FilteredOut}`。
`get_bounded` 和无界 `get` 是不筛选进程的便利包装。
自动恢复使用分页读取，通过
`Bootstrap::recover_all_with_limits(RecoveryLimits)` 选择条数与编码字节预算，
默认每页 256 条、1 MiB。追加上界固定扫描哪些槽位，但不冻结并发完成更新。
`InMemoryBackend::with_options(InMemoryOptions)` 返回 `StateResult<InMemoryBackend>`，
在构造时组合三个独立选项：`read_shards: NonZeroUsize` 默认 1，使用内联 map；更大数量会
预留带填充的分片，供点读使用。写入仍然串行，前缀读取取得一致快照。
`history: MemoryHistory` 默认 `Full`，保留全部变更；`Disabled` 不存储历史或计算历史时间戳，
`read_range` 与时间戳非 0 的 `read_at` 返回 `Unsupported`，`read_at(path, 0)` 仍读取当前值。
`notification_capacity: NonZeroUsize` 默认 256，上限为
`InMemoryOptions::MAX_NOTIFICATION_CAPACITY`（1,048,576 个事件）。待发送队列满时，
在提交前拒绝匹配订阅的写入，慢广播接收者仍可能报告 lag。
`InMemoryBackend::new()` 使用默认配置；`with_notification_capacity(NonZeroUsize)`
也返回 `StateResult<InMemoryBackend>`，其他选项保持默认。不支持的容量与分片预留失败返回错误。
禁用历史不限制当前值数量、载荷大小或宿主总内存。自定义状态适配器必须实现保留来源信息的原子
`write_merge`，否则使用默认的 `Unsupported` 返回值。
使用 `ActorSpec` 和 `Xolotl::spawn_actor` 声明并启动命名长寿 Process。
Actor body 或终结器引用进程本地 `StepRef` 时，使用 `Xolotl::spawn_actor_with_steps`。
它接收共享的 `StepModule`，通过 `single`、`new` 或 `compose` 装配。普通请求使用
`run_with_steps` / `run_plan_with_steps`，独立执行器使用 `with_steps`。
`StepRef::new(name)` 在执行器的不可变模块中解析，可复用图和嵌套 Step 函数无需捕获进程编号。
Plan 编译入口为 `xolotl_plan::compile(&plan)`，SDK 的 `plan` feature 将其导出为
`xolotl_sdk::compile_plan`。
使用 `StandardConfig::with_modules` 选择实际安装的 standard 模块，使用
`StandardConfig::with_inference_backend` 接入标准模型类 effect 使用的宿主模型 backend。

协议适配器：

- `xolotl-gateway`
- `xolotl-proto`
- `xolotl-gateway-grpc`
- `xolotl-gateway-websocket`
- `xolotl-gateway-mcp`

External Provider/Source session 准入和 secure envelope helper 位于
`xolotl_gateway::external`。`xolotl-gateway` 根 API 用于 gateway profile、
session、submission、limit 和运行时状态。

标准提供方：

- `xolotl-standard`
- `xolotl-state`
- `xolotl-storage-redb`
- `xolotl-storage-fs`

Provider 可通过 `Driver::input_admission` 返回同步输入检查钩子，open 时将这个可选
函数指针冻结到方法的分发表条目。接受路径无需分配；拒绝时返回包含失败原因和可记录输入的
`Box<InputRejection>`。方法适配器在重命名方法时转发钩子，领域字段检查保留在 Provider 内。

## 流与对象

`xolotl_kernel::stream::{StreamSink, StreamRouter}` 是可移植的输出端口，接口不要求
Tokio 或 `Send`/`Sync`，宿主适配器显式添加这些约束。
`host::stream::channel(StreamWindow)` 按条数和内联编码字节限制已接收及借出的 chunk，
默认 64 条和 256 KiB，不限制流的累计长度。丢弃 `StreamChunk` 释放额度；
`into_value` 转移值的所有权并释放传输额度，后续保留由调用方负责。
`StreamEnd` 在之前的 chunk 释放后交付，只携带输入和最终结果的来源信息；
每个 chunk 保留自己的来源信息。单次调用命中缓存时，完成结果报告
`CompletionOrigin::CachedOutcome`，不会改变使用该调用执行的程序的 origin。

流式调用必须显式提供 sink 或 router。调用拥有 producer Future；接收端关闭或调用取消时，
该 Future 随之丢弃。State 不隐式收集 chunk。HTTP inference 增量解析 SSE，
只在首个输出 chunk 被接受之前允许重试或 fallback。
字节准入在 SSE 解析器保留输入之前验证 UTF-8，并处理一次流开头的 BOM。
未完成的 UTF-8 字符最多保留三个字节；非法输入立即失败，不累计缓存非法后缀。
请求 Future 直接拥有响应及缓冲区，不另建解析线程或队列。

HTTP 生成及 embedding 请求从共享输入、配置和 overrides 按需拉取 JSON 窗口，遵守 HTTP
背压。Unary 与 SSE 响应共用增量 JSON 校验和按 dialect 选择的投影，只物化选中的输出。
忽略字段和重复完成快照不会形成完整响应 DOM。非法 UTF-8、尾部语法错误及晚到的 Provider
错误会使响应失败；SSE 输出在整条记录校验通过后才交付。
`InferenceBackendDef::io_window_bytes` 控制 I/O 窗口，`response_limits` 分别选择输出字节、
节点和嵌套准入。默认策略不限制累计响应字节。保留的输入、选中输出、嵌套状态及 HTTP 库
缓冲区仍然占用内存。非成功响应最多保留 8 KiB 诊断前缀，展示最多 512 个脱敏字符；
达到前缀上限后无需等待 EOF。字节上限不等于 I/O 超时。

`xolotl_state::object::{ObjectRead, ObjectWrite, ObjectDelete}` 分别提供独立的可移植能力。
宿主 `ObjectStore` 通过 `with_read`、`with_write`、`with_delete` 安装适配器，再通过
`StandardConfig::with_object_store` 注入 Provider；文件适配器提供
`FileObjectStore::into_object_store`。读取填充调用方缓冲区，上传按部分写入确认推进，
commit 成功后才发布引用。有暂存资源的上传必须通过 `UploadId::with_lease` 交付清理所有者，
在最后一个所有者丢弃时释放未提交内容，或将清理责任移交给适配器的可靠机制。
`UploadId::stateless` 仅用于没有待清理资源的上传；`begin_upload` 在返回标识前被取消时，
也必须清理尚未交付的暂存资源。显式 abort 用于提前清理，调用方无需从 `Drop` 中启动异步
中止任务。缺少能力时明确返回错误。

`ObjectStore::write_all` 使用借用窗口处理部分写入，校验每次确认并返回下一偏移。
非零窗口不限制累计上传大小；该方法不提交或中止上传，失败、取消和暂存清理由上传所有者处理。

`ObjectWrite::commit_upload(upload, final_taint)` 在发布 I/O 前封存内容及初始/最终来源的并集。
同一封存上传重试必须使用相同来源；去重会把来源并集持久化到规范对象元数据。
`xolotl-value-object` 提供显式编码引用和增量读、写、复制消费者；Standard 的独立
`value-objects` feature 只安装宿主提供的端口。详见[增量值](incremental-values.md)。

嵌入式 `GatewayRuntime` 通过 `with_object_store` 接收同一个对象存储。
上传票据和证明仍保存在 State，内容与来源信息由 ObjectStore 保存；票据提交成功后才能授权对象引用。
回执同时绑定 profile 名称、principal 和 surface。单次回执在 Gateway 准入完成后、
接受新的执行尝试前消费，不以驱动最终成功为条件。
`Gateway::begin_object_upload` 接收不含字节载荷的 `BeginObjectUploadRequest`，
返回拥有生命周期的 `GatewayObjectUpload`，支持通过 `dyn Gateway` 使用。
`write(&[u8])` 借用每个输入块并返回累计确认字节数；`commit(GatewayObjectKind)`
生成规范的 Blob、Tensor 或 Frame 引用，形状和时间戳可在输入结束后提供，无需调用方预先计算摘要。
上传对象不保留完整输入。写入一旦被轮询，错误或取消都会关闭上传并释放暂存 lease；
尚未轮询的写入不改变上传状态，`abort` 可用于提前清理。
每次 I/O 周围重新检查当前 profile 和绝对过期时间，不延长票据有效期。
嵌入层负责投递传输数据块，并在闲置或断开时释放上传所有者。

`effect://blob/write` 接收字节或文本并返回 `BlobRef`；`effect://blob/read` 对不超过
1 MiB 的对象返回字节，大对象的 unary 读取返回规范的 `BlobRef`，stream 模式返回有界字节
chunk。`effect://blob/delete` 通过 `ObjectDelete` 删除已提交内容。
两者直接接受 Blob、Tensor 和 Frame 类型的 Value，也接受哈希字符串
或 `{hash}` map，操作的是引用对应的字节。`Value::backing_blob()` 从这三种类型的值
中借用底层 `BlobRef`。
Fetch 和文件读取在 unary 模式下增量上传大内容，stream 模式直接发出字节。

## Gateway 输出

`Gateway::submit_output_stream(session, submission, StreamWindow)` 要求
`OutputMode::Stream`。返回的 `GatewayOutputStream` 提供 `accepted()`、
`next().await` 和 `poll_next(cx)`，与普通 `submit`、输入流完成共用准入和执行。
`GatewayOutputEvent::Chunk` 携带 `GatewayOutputChunk`，可借用其中的
`TaintedValue`；即使响应已销毁，块仍保留内核窗口信用和 Gateway 容量。
`into_value()` 确认消费，并显式把后续留存责任转交调用方。销毁响应会取消剩余执行。

`GatewayOutputEvent::Complete` 与普通 `submit` 携带同一种 `GatewaySubmitResult`，
包含接受信息、`ExecutionOutput` 和请求 origin，在最终校验、幂等结果持久化和进程清理后返回。
正常完成等待借出的块释放；取消或任务过期会丢弃排队数据，可在已借出的块仍持有容量时报告终止。

`SubmitResponse.completion` 与流式 `Completed` 共用 protobuf
`SubmissionCompletion { outcome, origin, taint }`。最终 outcome 和 taint 都是必需字段，
失败与重放也不例外，pristine 用显式空集合表示。最终 schema 拒绝保留结果 taint；块校验
拒绝会把该块的 taint 合入最终失败，即使 driver 忽略发送错误。新的 Gateway 程序执行
报告 `CompletionOrigin::CurrentAttempt`，内部内核缓存命中也不改变它。只有整个请求的
Gateway 重放报告 `CachedOutcome`；幂等记录通过 State 必需的 envelope 保存完整结果
及其 taint，不保留历史块。taint 和 origin 不授予对象下载权限。

线协议 `OutputOutcome` 独立保留 Done、Short 或类型化 Fail 及其内联/对象表示。
启用 `gateway-grpc/structured-output` 后，在 `ApplicationGrpcService` 上显式安装
`GatewayOutputExternalizer`，让超出内联预算的值通过对象交付。`EncodedOutputObject`
携带编码、Blob、读取授权和过期时间；嵌套引用不隐式获得授权。原事件在编码及策略等待期间
持续持有容量，同时继续轮询执行取消和截止时间。接受元数据及来源集合仍需满足帧容量。
详见[应用网关](application-gateway.md)。

## 向量搜索

Embedding 生产者与检索消费者共用 `Embedding` 和 `EmbeddingRepresentation`。
Envelope 包含 `space_id`、`representation` 及可选 `embedding_model`。
这些都是基于普通 Value 的能力协议，内核无需增加模型专用控制流。

| 表示 `kind` | 必需字段 |
| --- | --- |
| `dense` | `values`：非空数值列表 |
| `tensor` | `tensor`：类型化的一维 `TensorRef` |
| `sparse` | `dimensions`、递增且不重复的 `indices`、等长 `values` |
| `multi` | `vectors`：非空、每行维数相同的数值列表 |
| `multi_tensor` | `tensor`：类型化的二维 `TensorRef` |

`StandardConfig::with_retrieval(RetrievalConfig)` 分别配置对象读取能力、I/O 窗口和标量工作
配额。张量引用要求显式安装读取端口；即使窗口只有一个字节，也能解码全部 dtype。
内置索引接收有限 `f32` 数值，以 `f64` 计算分数。稀疏维数和下标也接受十进制字符串，
以表示平台完整整数范围。索引会物化准入后的向量；I/O 窗口不限制索引存储占用。

`effect://index/upsert` 接收上述 envelope、`id`、可选 `generation` 和 `metric`。
空间固定表示族、维数及度量。稠密和稀疏空间支持 `cosine`（默认）、`dot` 和
`negative_squared_euclidean`；多向量空间必须声明 `mean_max_cosine`。
`mean_max_cosine` 对每个 query 向量求其与全部 document 向量的最大余弦值，
再对这些最大值取均值。
`delete` 接收 `space_id`、`id` 和可选的预期 `generation`。

`effect://index/search` 接收 `space_id`、`representation`，以及可选的 `metric`、`k`、`mode`。
省略 `metric` 时使用空间已声明的度量。`k` 默认 `10`，必须非负；`k: 0` 跳过评分，
仍校验表示并保留空间来源。

| `mode` | 搜索行为 |
| --- | --- |
| 省略或 `"auto"` | 大型稠密余弦空间的 ANN 可用时使用近似候选，否则精确回退，包括另一查询正在构建 ANN 的情况。 |
| `"exact"` | 无论空间大小，扫描所有条目并选出前 `k` 个结果。 |

其他 mode 值会被拒绝。以下输入请求精确搜索：

```json
{
  "space_id": "example/embedding-model",
  "representation": { "kind": "dense", "values": [0.25, -0.5, 1.0] },
  "k": 10,
  "mode": "exact"
}
```

结果最多包含 `k` 个 `{id, sim}` 条目，有已存 `generation` 时一并返回。
按分数降序排列，同分候选按 `id` 升序排列；`auto` 可能与 `exact` 不同。
搜索持有不可变分页根，离开注册表锁后按配置的标量工作量与遍历间隔协作让出，
单条超高维向量内部也有让出点。这不保证单次 poll 的硬实时上限。
空结果和依赖空间内容的校验错误仍保留所选空间的来源。

结果选择保留 `O(k)` 个条目，不包含查询/存储载荷及 ANN 候选发现。
ANN 在空间超过 4096 条后的 `auto` 搜索中惰性构建；缩至 2048 条及以下时释放。
构建可以取消，只有捕获的空间版本仍有效时才发布。

Memory 将表示和代次持久化到 State，索引是可重建投影。`store` 和 `commit` 默认只创建
不存在的记录，替换或提升已有记录需要提供 `expected_generation`。
返回值包含 `{ id, path, indexed, generation }`；`indexed: false` 表示 State 已接受记录，
但并发投影更新阻止了索引发布。同一 OperationId 和相同语义请求的重试复用首次提交的表示，
包括并发 embedding 调用产生不同数值结果的情况。Recall 在把分数关联到记录前逐条校验代次。
记录被新代次替换后，旧操作重试会产生冲突，不会重新创建已退役的代次。
默认 `consistency: "indexed"` 修复观察到的过期命中；`"reconcile"` 在 `k > 0` 时先从
State 重建。`k=0` 的回忆不触发重建。
`effect://memory/rebuild` 显式修复命名空间，无需再次调用 embedding 模型。
这是独立系统间的代次校验，不提供跨系统事务快照。
Memory 扫描使用 State 分页，遇到超大单行时显式点读，再用后端游标继续。
分页窗口不构成单条记忆的大小上限；选定的常驻表示仍有自身内存成本。

Memory 回忆先取最多 `8 * k` 个语义候选，再按 kind 筛选并进行最终重排。
它的 `mode: "exact"` 描述语义候选搜索，不保证筛选和重排后的全库前 `k` 名，
即使存在足够的合格记录，也可能返回不足 `k` 条。内置合并策略会收集整个命名空间，
在内存中进行两两文本比较；存储扫描分页不代表完整聚类过程具有固定内存或增量让出能力。
这些策略与内核执行窗口、流窗口独立。

## 张量视图

`TensorRef { blob, dtype, shape }` 描述已提交对象字节的一个视图。blob 哈希只标识
字节内容；不同 dtype 或 shape 的视图可以共享同一个 blob。完整引用随值和 Gateway
响应传递，无需再查询张量目录。

`effect://tensor/write` 接收内联 `data` 列表及可选的 `dtype`、`shape`，
分块序列化并在对象提交后返回 `TensorRef`。它需要 `ObjectWrite`，不写入 State。
默认 dtype 为 `f32`，默认 shape 为 `[data.len()]`。显式 `shape: []` 表示标量，
需要一个数据元素；shape 中存在长度为 0 的维度时表示空张量，需要空数据列表：

```json
{"data": [2.5], "shape": [], "dtype": "f64"}
```

```json
{"data": [], "shape": [0, 3], "dtype": "f32"}
```

维度必须是非负整数，shape 的元素总数必须与数据长度相等。支持的 dtype 为 `f16`、
`bf16`、`f32`、`f64`、`i8`、`i16`、`i32`、`i64`、`u8` 和 `bool`。
浮点类型接收整数或浮点值，按所选精度舍入，并支持 IEEE NaN 和无穷值。整数类型只接收
所选类型范围内的整数。`bool` 只接收布尔值，每个值编码为一个 `0` 或 `1` 字节。
多字节元素采用小端编码。

序列化器复用一个至多 16 KiB 的缓冲区，小张量只按实际编码长度预留空间。这限制了
序列化存储，不约束完整内联输入列表；需要增量输入字节时，使用 Gateway 对象上传。

将完整的 `TensorRef` 或 `FrameRef` 值直接传给独立安装的 `effect://blob/read` 或
`effect://blob/delete` 能力即可，也支持显式传入 `TensorRef.blob`。这些操作针对共享
字节，删除内容会影响使用该 blob 的所有视图。需要持久命名时，显式将完整 `TensorRef`
保存到应用选择的 State 路径；删除该 State 条目不会删除对象。

## 文档质量检查

公开 API 文档在缺失文档警告提升为错误时构建：

```sh
RUSTDOCFLAGS='-W missing-docs' cargo doc --workspace --no-deps
```

文档测试也应保持可运行：

```sh
cargo test --doc --workspace
```
