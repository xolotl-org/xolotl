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

## Rust 入口与宿主端口

联邦宿主通过 `ServedCapability` 选择所需服务组：
`server.connected_peer(peer, capability)` 按已认证服务组筛选有界连接 registry，
`client.serves(capability)` 检查已连接对端的声明；选择不替代操作的当前授权。
daemon 对象接收 clone `PreparedPublisher` 的传输 runtime，使接收连接共享其准入、
取消和排空域。wire 版本与服务组值归[联邦配置](configuration.md#联邦发布端)维护。

### 选用 crate

嵌入运行时通常从以下 crate 开始：

- `xolotl-core`
- `xolotl-sdk`
- `xolotl-graph`
- `xolotl-types`
- `xolotl-kernel`

可选节点互联使用 `xolotl-federation` 的 `FederationService`／`FederationStore` 管理发布、订阅、inbox 与投影位置，使用 `xolotl_federation_kernel::FederationKernelCallBridge` 将远端 CallRef 交给本轮 Kernel 请求。`xolotl-federation-grpc` 的客户端和服务端适配已认证 Session；`FederationGrpcObjectSource` 把固定节点、主体和授权的客户端接到 `FederationObjectReceiver::fetch`。内容验证后，嵌入宿主实现 `FederationObjectReferenceStore`，持久发布并保留精确应用引用，再调用 `bind_verified_object`；该函数在接收记录的 `Verified`→`Bound` CAS 完成前一直持有宿主 guard。两笔提交之间崩溃时沿原 transfer 身份重试。宿主仍须让其他应用引用与对象 GC 协调。stock 装配见[联邦配置](configuration.md#联邦发布端)，保留与恢复规则见[FederationStore 合同](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-federation/src/lib.rs)。本地 SDK 调用无须开启联邦。

SDK 默认只导出 `xolotl_sdk::core`。无 allocator 宿主从 `ProgramImage`、`Values` 和 `Execution` 开始；启用 `host` 后提供 `Program`、`Expression`、`PreparedProgram`、`ExecutionConfig`、`ExecutionLayout`、`ExecutionBuffers` 和 `Xolotl::run_prepared`。`ProgramImage::resource_requirements` 提供无分配的资源分析；`PreparedProgram::layout` 按宿主配置报告执行容器大小；`run_prepared_with_buffers` 复用调用方的空闲容器。

prepared 执行接收 `TaintedValue { value, taint }`。portable `LinkedExecution` 和托管 Executor 返回 `ExecutionOutput { outcome, taint, unresolved_operations }`；SDK 普通执行入口返回 `Result<ExecutionCompletion, XolotlError>`。显式通过 `output: ExecutionOutput` 读取正文；`finalization: Option<Arc<ProcessFinalizationReport>>` 独立保留清理证据，仅在准备阶段接纳进程前拒绝时为 `None`。`output.into_parts()` 将带来源的 `Result<TaintedValue, TaintedFailure>` 与有界未决效果身份一起返回，调用方组合结果时须携带两者；`TaintedFailure::into_value` 将诊断转为下个程序的输入时也保留来源。调用用量与缓存 origin 属于单次调用边界，不放入 `ExecutionOutput`。`invocation::invoke` 与托管 `DataPlane::execute` 返回 `InvocationResult`，将真实 `DriverOutput` 与可选 `CompletionError` 分开；确认请求前必须检查完成错误。`AccountPermit::Commit` 允许分派和结算异步提交，`AccountCompletion` 绑定结果与费用。可移植 `RequestDriver` 返回 `RequestCompletion`，普通事件放在 `Ok`，不能确认的调用通过 `Err(TaintedFailure)` 中断执行，避免进入 `Catch` 或继续发出效果。`Executor::with_deadline(HostDeadline)` 使用所属 Kernel 的 `HostRuntime` 生成的单调截止时间停止执行，保留已知活动来源并释放待完成调用；进程终结仍由请求所有者负责。

正文完成后若进程终结失败，SDK 返回 `XolotlError::Finalization { process, output, source }`，保留原输出、taint 和进程定位；`source: RequestFinishError` 保留类型化原因与原 `cleanup` ticket。宿主持有 ticket，通过 `Bootstrap::resume_cleanup(&source.cleanup)` 重试选定清理，不重跑正文；`source.cleanup.finalization_report()` 可观察后来提交的报告。`CleanupWaitExpired` 只表示调用方观察期限已到，不证明清理完成或回滚。准入失败时尚无正文输出，仍返回 `XolotlError::Bootstrap`。成功的 `RequestProcess::finish` 在释放 pin 前返回报告 `Arc`；保留报告不阻止进程自动退役。

`Execution::suspend` / `resume` 校验并交接活动存储，不克隆值；可选宿主利用此接口在字节预算内为原生扩展增长容量。

### Kernel 与请求作用域

内核定义唯一的 `KernelBuilder`，SDK 直接重新导出；`KernelBuilder::new(state)` 要求显式传入 State，普通请求清理不要求写入能力，业务发布按需使用对应写入端口，Fact 默认关闭，通过 `with_fact_sink` 显式安装。builder 独立创建新的内存执行 ID 来源；持久或共享执行命名空间必须显式使用 `with_execution_ids`，安装的 sink 与所选 ID 来源绑定。`build()` 返回 Kernel，`Bootstrap::from_kernel` 初始化根进程，`Xolotl::from_kernel` 增加 SDK 门面。`memory` feature 才安装内存 State 适配器与 `in_memory` 构造器。`standard` 提供显式 Provider 安装 API。Kernel 的 `registry()`、`handles()`、`processes()`、`facts()`、`state()` 访问选定的共享端口，`execution_config()` 按值返回默认配置。Bootstrap 通过 `kernel()` 与 `root()` 访问关联对象。`Xolotl::bootstrap()` 返回 `&Arc<Bootstrap>`，可组合原宿主的请求、取消与清理服务。

`ExecutionIds` 与 `ExecutionIdSource` 将执行 ID 来源独立为可替换适配器，通过 `KernelBuilder::with_execution_ids` 或低层可信 `Executor::with_execution_ids` 选择。构造函数 `OperationId::new(process, execution, invocation, position, attempt)` 与 `FromStr` / `Display` 共用五段格式；`to_bytes` 返回规范的 32 字节键，`retry` 在重试次数耗尽时返回 `None`。feature 组合与执行约定见[核心与可移植程序](core-and-portable.md)。

`Bootstrap::request_under` 用预编译授权创建拥有生命周期的请求。`Arc<Bootstrap>` 上的 `request_under_owned` 返回持有共享宿主的同一种请求作用域，可交给独立任务或已接受的输入流。两种持有方式共用取消与终结逻辑，借用方式不增加共享引用。通过 `RequestProcess::executor` 创建执行器、`finish(&ExecutionOutput)` 提交终结清理并保留 body 状态的来源信息，或通过 `detach` 显式转交生命周期责任。SDK 普通执行入口自动使用该作用域。请求丢弃或终结中断后，`Bootstrap::drain_cleanup` / `Xolotl::drain_cleanup` 返回 `ProcessCleanupReport`，包含完成的进程树数量和保留的失败。丢弃单独的 Executor Future 不会结束进程。

### 授权与调用身份

可信宿主可调用 `Bootstrap::open_for_as(process, acting, name, verb)`，按指定 `Acting` 身份编译开时策略；`open_for` 使用进程原本的身份。按具体的本地 `identity://...` 路径调用 `kernel.identities().resolve_or_register(&path)` 得到 `acting`；持久宿主须装配同一持久身份目录，恢复只读核验已登记的路径与编号。`IdentityRef` 只在签发它的目录内有意义；`process://...` 寻址进程资源。`Executor::bind_handle` 和 `bind_method_handle` 从活动句柄本身读取 acting 身份，若进程、所有者、具体目标或方法契约不符则返回 `HandleBindingError`。`Executor::prepare_operation_for(acting, template)` 可按该身份预检资源方法与开时策略，`prepare_operation` 则使用进程原本的身份。预先打开或预检不授予进入 `Acting` 作用域的权限；执行时仍根据进入作用域的值检查 `act-as` grant，每次调用也继续检查活动授权及策略。

### 执行与结果

`Executor::new(process, identity, data_plane, registry)` 创建独立执行器，要求宿主管理该进程的生命周期；此入口可组合独立创建的 Registry 和 HandleTable。需要进程表身份与生命周期时，先通过 `Bootstrap` 准入进程，再将同一 Kernel 的 ProcessTable、HandleTable、Registry 和时钟域交给 `Executor::from_process_table(process, processes, data_plane, registry)`；进程不存在时执行会拒绝。两个构造器都返回 `Result`，部分绑定或跨 Kernel 混用会拒绝。脱离 Kernel 装配直接组合 Executor 或 FactSink 的可信宿主，应分别通过 `Executor::with_identity_registry` 和 `FactSink::with_identity_registry` 安装签发该身份的同一目录；裸 `IdentityRef` 不能证明它在另一目录中的原路径。

`HostDeadline` 属于创建它的 `HostRuntime` 时钟域。设置期限、比较、计算剩余时间和等待遇到外域期限时返回 `ClockDomainError`；运行时的 Clone 保留同一时钟域。

`run`、`run_with_steps`、`run_plan`、`run_plan_with_steps` 及可移植程序入口都要求显式传入调用者 `IdentityRef`；只有主动发起系统请求时才传 `IdentityRef::ROOT`。身份本身不授予资源，可信宿主须授权资源允许列表。允许列表支持 `path://phone/effect/device/echo` 这样的具体 cluster 路径；SDK 按已安装方法的实际权限动词分组衰减，继续受父进程权限上限约束。`run_program`、`run_prepared` 和 `run_prepared_with_buffers` 返回 `Result<ExecutionCompletion, XolotlError>`。通过 `completion.output: ExecutionOutput` 读取结果 taint 与有界未决效果身份；`completion.output.into_parts()` 一并取出这些信息。`completion.finalization` 独立保留清理证据，只有准备阶段在接纳 Process 前拒绝时为 `None`。`PreparedProgram` 共享不可变指令，每次执行独占可变缓冲。

请求由 `RequestProcess` 拥有。`finish` 终结本次请求；`detach` 将清理责任交给宿主。丢弃拥有型请求会取消本轮树，`drain_cleanup` 重试待处理收尾。求值后终结失败通过 `XolotlError::Finalization { process, output, source }` 保留原结果和进程定位。Console 的[独立提交与结果保留](console-runtime.md#独立提交与结果保留)由当前服务托管。

### 清理与容量

按宿主范围维护时，在已准入进程仍被保留期间获取 `Bootstrap::cleanup_ticket(process)`。`CleanupTicket` 阻止该条目被 reap，但不延长内核生命期。`Bootstrap::resume_cleanup(&ticket)` 只重试已经选定的本地或子树清理，并返回 `CleanupProgress`；`NotRequested` 不发起取消。`ticket.is_complete()` 根据清理和原生拥有权释放确认完成，不由 terminal 状态推断。票据不能用于另一个内核；最后一份 clone 释放后解除回收保护。`ticket.terminal_status()` 单独读取首次选定的终态，即使业务发布或资源释放仍待重试也可查询；该决策不代表清理已经完成。`KernelBuilder::with_process_capacity(NonZeroUsize)` 限制保留的进程条目数量。`ProcessTable::set_capacity` 调整共享上限，`len` 包含终态与待清理条目。`reap_finalized(limit)` 在完成后显式回收满足条件的叶子，保留仍有子进程的祖先；业务数据和显式记录的 Fact 独立留存。容量不足返回 `BootstrapError::ProcessAdmission(ProcessAdmissionError::Capacity)`。

### 句柄

宿主侧 `HandleTable` 自行管理同步；克隆后共享槽，`get` 返回独立快照，`downgrade` 返回不会延长表生命周期的 `WeakHandleTable`。`open_resource` 和 `PreparedOpen::install` 接收 `&HandleTable`；衰减直接调用 `handles.derive(parent, rights, kind, owner)`。调用方无需获取表锁。`HandleTable::with_slot_limit(limit)` 设置固定的共享槽位索引额度，`KernelBuilder::with_handle_slot_limit(limit)` 在装配时选择该额度。默认不设限，零值拒绝任何安装。`slot_limit()` 报告配置值；`allocated_slots()` 统计历次分配的所有索引，包括空闲、保留祖先锚点和永久退役的槽。空闲索引复用不新增额度；满额时返回 `AuthorityError::Capacity`，不会撤销已有句柄。`len()` 则只统计保留的句柄载荷。该额度只限制槽位数量，不限制驱动和策略对象、在途快照或向量实际分配的字节容量。查询不能改写已安装的授权；生命周期以槽位为唯一依据，释放保留后代，撤销使后代失效，`Handle` 不另存可独立修改的生命周期。退出表的驱动和策略对象在解锁后销毁，批量回滚与所有者清理也遵守此边界。准入拒绝的审计回调同样在句柄表锁外执行。

打开后的 `DriverPlan` 条目保留原始接口声明，可通过 `methods()` 或 `entry(id).declaration()` 查询。原生宿主用 `insert_declared` 保留完整声明，用 `insert` 仅安装本地分派规则。句柄的打开类别、方法权限、世代及祖先活动状态在当前宿主中检查；释放保留已有后代，撤销使派生子树失效。

### 数据与诊断端口

State、Source、对象、身份及应用调用记录按各自合同选择持久后端。`FactQuery`、`FactOrder` 与 `FactPage` 独立限制结果条数、候选数和编码字节，使用 `query.next_page(&page)` 续页；空过滤页也可能尚未结束。自定义 `FactStore` 实现 `scan` 及按身份索引的 `lookup(FactLookup)`。Fact 记录由宿主显式选择，用于诊断；业务数据重开与结果核对不恢复程序位置。

#### Fact 观察配置

已安装实现的 `FactStore::is_enabled()` 默认返回 `true`；禁用 sink 的写入和经检查读取报告未安装，不返回假的空历史。未安装时 `record: true` 仍 fail-closed。`Bootstrap::record_optional_gateway_audit` 仅跳过未安装的观察存储，安装后错误继续传播；`record_gateway_audit` 仍严格要求记录成功。可选观察不作为必需的业务提交屏障。

`InMemoryFactStore::new()` 与 `with_capacity` 均使用 `FactRetentionLimits::default()`；`with_capacity` 选择广播容量，不是留存容量。通过 `with_limits` 选择显式留存限额：

| 字段 | 默认值 | 计量对象 |
| --- | --- | --- |
| `max_records` | 4,096 | 留存 Fact 记录 |
| `max_encoded_bytes` | 64 MiB | 全部记录编码字节 |
| `max_record_bytes` | 1 MiB | 单条记录编码字节 |

这些不是 RSS 限额。容量不足原子拒绝，不改变记录、游标或通知；重复 begin 不新增计量，completion 按编码大小净变化计量。不提供 Fact 自动退休。存储与计量规则归[Fact rustdoc](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-kernel/src/fact.rs)维护。

`RedbStore::fact_store_with_limits` 在事务内执行同样的预算检查，重开保留真实计量。同一运行中的数据库 adapter 必须选择一致的限额。两个派生留存计数器都不存在时，安装从实际留存行一次重建费用；部分计数器缺失或记录数不一致时拒绝安装。`fact_store()` 使用上表默认值。daemon 通过 `[storage.observations]` 显式启用这些预算；没有该节时仍独立保留执行身份。

### State、模块与标准服务

#### 内存 State

`InMemoryBackend::with_options(InMemoryOptions)` 返回 `StateResult<InMemoryBackend>`。各选项分别控制读取、留存与容量：

| 字段 | 默认值 | 计量与行为 |
| --- | --- | --- |
| `read_shards` | 1 | 非零；1 使用内联 map，更多分片为不同键的并发点读增加锁与驻留；写入串行，前缀读取取得一致快照 |
| `history` | `MemoryHistory::Disabled` | 默认不安装历史能力；`Full` 保留非 vault 变更直至裁剪 |
| `notification_capacity` | 256 | 非零；上限 1,048,576 个事件；待发送队列满时提交前拒绝匹配写入，慢广播接收者仍可能 lag |
| `source_stream_limit` | 4096 | 非零；上限 65,536 个 Source 流身份；满额拒绝新身份首次提交，已有流仍可推进 |
| `absence_limits` | `Some(65_536)` 条／`Some(64 MiB)` 编码字节 | 键与完整带来源缺席编码；`None` 显式取消该维度限制。零禁止新增计量；降低额度保留证据并允许非增长变更 |

`InMemoryBackend::new()` 使用默认配置；`with_notification_capacity(NonZeroUsize)` 也返回 `StateResult<InMemoryBackend>`，其他选项保持默认。不支持的容量与分片预留失败返回错误。禁用历史不限制 live 值数量或载荷；上述逻辑容量不等于分配量或宿主 RSS 上限。直接使用内存历史端口时，禁用历史只允许 `read_at(path, 0)` 读取当前观察；其他历史查询返回 `MissingCapability`。

#### 当前观察与 redb

自定义状态适配器在 `StateWrite::mutate` 中实现带来源的原子变更；`write_merge` 等是基于该入口的扩展方法。共享转换和提交合同见[State 变更合同](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-state/src/write.rs)。

redb 当前域保留删除后的缺席来源，`CurrentOnly` 关闭历史或 `Full` 裁剪历史不影响该记录。比较、分页与 Source 追加使用当前来源；缺席页可以没有 entry 而仍有来源、已消费字节和续读游标。`StateRead::read_tainted`、`StateBoundedRead::read_tainted_bounded` 和 `Backend::observe_signal` 的快照返回 `StateObservation { value: Option<Value>, taint: TaintSet }`，包含缺席来源。`Backend::observe_signal_current` 从同一配对 Signal 域重读；`read` 和 `read_bounded` 显式丢弃来源。redb 有界观察限制单条当前记录；`RedbOptions::absence_limits` 独立限制留存的带来源缺席记录及编码，默认与内存相同。

#### Actor 与 StepModule

使用 `ActorSpec` 和 `Xolotl::spawn_actor` 声明并启动命名长寿 Process。Actor body 或终结器引用进程本地 `StepRef` 时，使用 `Xolotl::spawn_actor_with_steps`。它接收共享的 `StepModule`，通过 `single`、`new` 或 `compose` 装配。普通请求使用 `run_with_steps` / `run_plan_with_steps`，独立执行器使用 `with_steps`。`StepRef::new(name)` 在执行器的不可变模块中解析，可复用图和嵌套 Step 函数无需捕获进程编号。

#### Plan 与标准模块

Plan 编译入口为 `xolotl_plan::compile(&plan)`，SDK 的 `plan` feature 将其导出为 `xolotl_sdk::compile_plan`。

使用 `StandardConfig::with_modules` 选择实际安装的 standard 模块，使用 `StandardConfig::with_inference_backend` 接入标准模型类 effect 使用的宿主模型 backend。

标准 `effect://approval/{ask,check,respond}` broker 按 `dedup_key` 保存单行记录，每个 key 标识一次业务审批。不同审批须使用不同 key；删除后以同一 key 重建既不隔离在途响应，也不开始独立的审批轮次。ask 只创建一次；重复请求保留原 fanout、quorum 与期限。响应做完整记录 CAS：RequireAll 合并并发投票，AnyOne 保留首个成功提交的裁决；迟到响应不能改写终态。CAS 冲突最多尝试八次提交，其他存储失败及提交未知不自动重试。期限使用 Kernel 的 `HostRuntime` 时钟，0 表示无期限，pending 且时间严格超过期限时为 expired；正文 `now_millis` 被拒绝。check 不写到期状态。获授权 broker 仍须认证人类响应，approver 标签不是身份凭证。这些记录不会自动接入 Kernel 的策略审批 registry，也不证明外部业务动作已经执行。

标准 `effect://time/{now,sleep,cron}` 同样使用安装宿主的 Kernel `HostRuntime`。now 返回 Unix 毫秒；sleep 接受非负时长，在宿主单调时钟上等待，不受墙上时间跳变影响，零延迟不注册等待。丢弃 Future 按宿主时钟契约只取消本次等待。cron 只计算下次时间，不注册周期任务：输入为正 interval_ms，或正 every 加 unit（s／m／h／d，默认 s），两种形式不能混用。单位乘法、下次时间加法及单调期限构造不可表示时明确拒绝，不 panic、回绕或饱和成别的有效计划。替换计时器不表示整个宿主构建没有 Tokio 依赖，也不提供持久调度。

### 协议适配器

协议适配器：

- `xolotl-gateway`
- `xolotl-proto`
- `xolotl-gateway-grpc`
- `xolotl-gateway-websocket`
- `xolotl-gateway-mcp`

External Provider/Source session 准入和 secure envelope helper 位于 `xolotl_gateway::external`。`xolotl-gateway` 根 API 用于 gateway profile、session、submission、limit 和运行时状态。

标准提供方：

- `xolotl-standard`
- `xolotl-state`
- `xolotl-storage-redb`
- `xolotl-storage-fs`

Provider 可通过 `Driver::input_admission` 返回同步输入检查钩子，open 时将这个可选函数指针冻结到方法的分发表条目。接受路径无需分配；拒绝时返回包含失败原因和可记录输入的 `Box<InputRejection>`。方法适配器在重命名方法时转发钩子，领域字段检查保留在 Provider 内。

## 终端安装

嵌入式宿主通过 `StandardConfig::with_terminal_runtime` 显式传入共享的 `TerminalRuntime`；缺少该拥有者时安装失败。`TerminalRuntime::default()` 最多接纳 16 个并发命令；`new(NonZeroUsize)` 选择其他有限上限。满额在创建子进程前拒绝，不排队。每个名额计入一个监督任务、其直接子进程及两个有界输出缓冲，不是进程 RSS 限额；每个缓冲默认 1 MiB，最多 16 MiB。一个监督任务同时轮询子进程退出与两条管道，直到直接子进程回收才返额。完整超时覆盖管道 EOF 和子进程退出，包括被后代继承而保持打开的管道。

调用在准入前要求原始 `DriverContext.operation_id`。进程启动后的超时、I/O 失败或关闭
返回携带该原身份的 `OutcomeUnknown`，程序处理失败也保留未决证据。回收子进程释放
清理责任，不证明外部效果回滚，也不授予重跑权限；政策、容量及进程创建拒绝仍是已知的效果前失败。

`close()` 永久关闭准入并取消已接纳调用；`shutdown().await` 还等待清理排空。宿主须保持执行器运行直到排空完成。并发或被取消的关闭等待者不丢失清理责任。取消、超时与关闭会丢弃管道并终止／回收直接子进程，不跟踪或终止后代，也不回滚效果。命令权限与自定义 Driver 边界见[安全与边界](security-and-boundaries.md#驱动边界)。

## 流与对象

`xolotl_kernel::stream::{StreamSink, StreamRouter}` 是可移植的输出端口，接口不要求 Tokio 或 `Send`/`Sync`，宿主适配器显式添加这些约束。`host::stream::channel(StreamWindow)` 按条数和内联编码字节限制已接收及借出的 chunk，默认 64 条和 256 KiB，不限制流的累计长度。丢弃 `StreamChunk` 释放额度；`into_value` 转移值的所有权并释放传输额度，后续保留由调用方负责。`StreamEnd` 在之前的 chunk 释放后交付，只携带输入和最终结果的来源信息；每个 chunk 保留自己的来源信息。单次调用命中缓存时，完成结果报告 `CompletionOrigin::CachedOutcome`，不会改变使用该调用执行的程序的 origin。

流式调用必须显式提供 sink 或 router。调用拥有 producer Future；接收端关闭或调用取消时，该 Future 随之丢弃。State 不隐式收集 chunk。HTTP inference 增量解析 SSE，只在首个输出 chunk 被接受之前允许重试或 fallback。字节准入在 SSE 解析器保留输入之前验证 UTF-8，并处理一次流开头的 BOM。未完成的 UTF-8 字符最多保留三个字节；非法输入立即失败，不累计缓存非法后缀。请求 Future 直接拥有响应及缓冲区，不另建解析线程或队列。

HTTP 生成及 embedding 请求从共享输入、配置和 overrides 按需拉取 JSON 窗口，遵守 HTTP 背压。Unary 与 SSE 响应共用增量 JSON 校验和按 dialect 选择的投影，只物化选中的输出。忽略字段和重复完成快照不会形成完整响应 DOM。非法 UTF-8、尾部语法错误及晚到的 Provider 错误会使响应失败；SSE 输出在整条记录校验通过后才交付。`InferenceBackendDef::io_window_bytes` 控制 I/O 窗口，`response_limits` 分别选择输出字节、节点和嵌套准入。默认策略不限制累计响应字节。保留的输入、选中输出、嵌套状态及 HTTP 库缓冲区仍然占用内存。非成功响应最多保留 8 KiB 诊断前缀，展示最多 512 个脱敏字符；达到前缀上限后无需等待 EOF。字节上限不等于 I/O 超时。

`xolotl_state::object::{ObjectRead, ObjectWrite, ObjectDelete}` 分别提供独立的可移植能力。宿主 `ObjectStore` 通过 `with_read`、`with_write`、`with_delete` 安装适配器，再通过 `StandardConfig::with_object_store` 注入 Provider；文件适配器提供 `FileObjectStore::into_object_store`。读取填充调用方缓冲区，上传按部分写入确认推进，commit 成功后才发布引用。有暂存资源的上传必须通过 `UploadId::with_lease` 交付清理所有者，在最后一个所有者丢弃时释放未提交内容，或将清理责任移交给适配器的可靠机制。`UploadId::stateless` 仅用于没有待清理资源的上传；`begin_upload` 在返回标识前被取消时，也必须清理尚未交付的暂存资源。显式 abort 用于提前清理，调用方无需从 `Drop` 中启动异步中止任务。缺少能力时明确返回错误。

对 `FileObjectStore`，最后一个上传 lease 丢弃后立即撤销身份，并将 staging 交给每个拥有者唯一、惰性启动且有界的清理线程。线程在首次上传时启动，只读使用不创建线程，其生命周期独立于调用方 Future 和 Tokio runtime。排队及运行中的清理在完成前继续占用上传槽位；显式 abort 等待物理清理。`pending_uploads()` 只统计注册的上传身份，不表示清理完成或可用槽位数。已完成但丢失回执的上传继续占槽，直到原拥有者按相同 sealed 请求重取回执或放弃责任。额度与默认值见[配置](configuration.md#运行时配置)。

Unix 上，文件后端 commit 成功表示内容文件、metadata 文件、对象目录及 `objects` 父目录已完成同步。rename 后同步失败可能留下可见但未经持久确认的内容；重试（包括完全重复发布）仍须完成同步。删除重试即使看到对象已缺席，也须同步父目录。重开检查实际存储，不证明物理断电后仍能保留数据；实际保证取决于文件系统与部署。非 Unix 尚未实现目录同步，不承诺目录项的断电持久性。详见拥有该规则的[对象存储合同](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-state/src/object.rs)。

`ObjectStore::write_all` 使用借用窗口处理部分写入，校验每次确认并返回下一偏移。非零窗口不限制累计上传大小；该方法不提交或中止上传，失败、取消和暂存清理由上传所有者处理。

`ObjectWrite::commit_upload(upload, final_taint)` 在发布 I/O 前封存内容及初始/最终来源的并集。同一封存上传重试必须使用相同来源；去重会把来源并集持久化到规范对象元数据。`xolotl-value-object` 提供显式编码引用和增量读、写、复制消费者；Standard 的独立 `value-objects` feature 只安装宿主提供的端口。详见[增量值](incremental-values.md)。

嵌入式 `GatewayRuntime` 通过 `with_object_store` 接收同一个对象存储。上传票据和证明仍保存在 State，内容与来源信息由 ObjectStore 保存。一张票据可保存有界的完整 Blob、Tensor、Frame 绑定；一次提交引用的所有成员必须属于该票据。回执同时绑定 profile 名称、principal 和 surface。默认上限为 16 个不同类型化绑定、1 GiB 不同规范 backing bytes 和 256 KiB 编码 State 行；profile 可在实现硬上限内配置，签发请求只能收紧 profile 限额。票据级预期大小或摘要要求 `max_objects = 1`，`BeginObjectUploadRequest` 则可单独绑定每次上传。单次使用票据要求 `idempotency_key` 或 `submission_token`，在 Gateway 准入完成后、接受新的执行尝试前消费，不以驱动最终成功为条件。消费结果未知时停止执行并保留待定幂等保留；折叠输入流仅在完整 payload 已知后建立保留或重放。`Gateway::begin_object_upload` 接收不含字节载荷的 `BeginObjectUploadRequest`，返回拥有生命周期的 `GatewayObjectUpload`，支持通过 `dyn Gateway` 使用。`write(&[u8])` 借用每个输入块并返回累计确认字节数；`commit(GatewayObjectKind)` 生成规范的 Blob、Tensor 或 Frame 引用，形状和时间戳可在输入结束后提供，无需调用方预先计算摘要。上传对象不保留完整输入。写入一旦被轮询，错误或取消都会关闭上传并释放暂存 lease；尚未轮询的写入不改变上传状态，`abort` 可用于提前清理。每次 I/O 周围重新检查当前 profile 和绝对过期时间，不延长票据有效期。嵌入层负责投递传输数据块，并在闲置或断开时释放上传所有者。若追加回执的结果无法通过持久操作身份读回确认，commit 返回不确定结果；其他上传产生相同内容不能证明本次追加成功。

`effect://blob/write` 接收字节或文本并返回 `BlobRef`；`effect://blob/read` 对不超过 1 MiB 的对象返回字节，大对象的 unary 读取返回规范的 `BlobRef`，stream 模式返回有界字节 chunk。`effect://blob/delete` 通过 `ObjectDelete` 删除已提交内容。两者直接接受 Blob、Tensor 和 Frame 类型的 Value，也接受哈希字符串或 `{hash}` map，操作的是引用对应的字节。`Value::backing_blob()` 从这三种类型的值中借用底层 `BlobRef`。Fetch 和文件读取在 unary 模式下增量上传大内容，stream 模式直接发出字节。

## MCP 发布

MCP publication 引用一个 Gateway surface，并声明 `tool`、`resource`、`resource_template` 或 `prompt` kind。它不重复声明 effect target、schema 或调用方绑定。仅当当前 principal 能发现该 surface，且 surface 持有覆盖目标 effect 的 `publish://...` capability，publication 才可见。MCP 调用通过 surface id 提交；客户端不能提交原始 effect path、capability、acting identity 或 `Operation`。

MCP 专用的 `icons`、`mimeType`、`size`、prompt `arguments` 和静态 `completions` 属于 publication properties。Adapter 校验原生 MCP `content`、`structuredContent`、`isError` 与 `_meta` 后交付。它优先协商 `2025-11-25`，同时保留其他已支持的已发布修订；实现 initialize、ping、tool、resource、resource template、prompt 和协议修订支持时的 completion，不声明 logging、resource subscription、list-change notification 或 task execution。

`McpGateway::call_tool`、`read_resource` 和 `get_prompt` 返回完整 `GatewaySubmitResult`，保留受理、outcome、taint、请求 origin 和 unresolved_operations。正常 JSON-RPC result 在 `_meta["xolotl/gateway"]` 中交付同一证据；原生 MCP 结果也不能替代这个宿主键。执行之后复核原 surface 的当前交付权限，撤权时不交付证据，但仍报告结果未知，不能据此认定未执行。

`McpGateway::with_output_limits(McpOutputLimits)` 设置响应准入。默认上限为 65,536 个逻辑 Value 节点、深度 32、8 MiB 内联载荷、65,536 个投影 JSON 节点和 16 MiB 编码消息。JSON 节点包括字节展开的数值数组与生成的媒体字段；编码大小包括转义及 JSON-RPC 封套，共享子图按每次出现计数。普通 JSON 适配器最多支持 64 层 Value。已受理结果无法渲染或装入响应时返回 JSON-RPC `-32001` 和脱敏的 `outcome unknown; reconcile before retrying`，在能装下时用 `error.data` 保留原受理和未决身份。截断身份须置 `identities_incomplete`，最小响应可能不含证据或将过大的请求 id 降为 null；这不授予重试权，也不撤销效果。Rust 类型化结果不受这组 JSON 预算约束。

工具业务失败仍是带宿主元数据的完整 `isError: true` result；资源和 prompt 的业务失败用 JSON-RPC `-32003` 及 `error.data` 中的完整 failure／元数据交付。失败响应不能装下时，同样转为未知交付结果。未知响应不包含 Gateway 私有诊断。MCP 尚无公开对账查询或通知式执行取消保证，详见[交付设计](application-gateway.md)。

## Gateway 输出

`Gateway::lookup_request` 通过 `GatewayRequestLookup` 读取原请求证据；
gRPC 对应入口为仅摘要的 `LookupRequest`。
`Gateway::read_retained_request_result` 读取缓存载荷，交付归适配器；gRPC 显式交付入口
`DeliverRequestResult` 接收 `LookupRequestRequest` 并返回 `SubmitResponse`。
配置的外化可能写入对象和授权，但两种入口均不重跑程序。身份绑定、证据状态与有界交付见
[原请求查询](application-gateway.md#原请求查询)。

原生摘要是 `GatewayRequestSummary { accepted, result_class, unresolved_operations }`，
类别为 `GatewayRequestResultClass::{Done, Short, Fail}`。保留结果读取返回
`GatewayRetainedRequestResult::{Available(Box<GatewaySubmitResult>), Unproven, Reserved, Retired}`；
只有 `Available` 携带原缓存输出及来源，原生读取本身不创建传输导出。

`Gateway::submit_output_stream(session, submission, StreamWindow)` 要求 `OutputMode::Stream`。返回的 `GatewayOutputStream` 提供 `accepted()`、`next().await` 和 `poll_next(cx)`，与普通 `submit`、输入流完成共用准入和执行。`GatewayOutputEvent::Chunk` 携带 `GatewayOutputChunk`，可借用其中的 `TaintedValue`；即使响应已销毁，块仍保留内核窗口信用和 Gateway 容量。`into_value()` 确认消费，并显式把后续留存责任转交调用方。销毁响应会取消剩余执行。

`GatewayOutputEvent::Complete` 与普通 `submit` 携带同一种 `GatewaySubmitResult`，包含接受信息、`ExecutionOutput` 和请求 origin，在最终校验、幂等结果持久化和进程清理后返回。正常完成等待借出的块释放；取消或任务过期会丢弃排队数据，可在已借出的块仍持有容量时报告终止。

`SubmitResponse.terminal.completion` 与流式 `Completed` 共用 `SubmissionCompletion { outcome, origin, taint, unresolved_operations }`。最终 outcome、taint 和对账状态都是必需字段，失败与重放也不例外，pristine 用显式空 taint 集合表示。当前会话仍有原 surface 的提交权限且传输仍可交付终态帧时，已接受请求的结果结算或编码失败使用 `SubmitResponse.terminal.indeterminate` 或流式 `Indeterminate`，保留有界效果身份但不宣称程序 outcome；连接丢失时无法交付这些证据。`Gateway::validate_submission_access` 供传输在披露受理和对账身份前复查当前会话与提交绑定。最终 schema 拒绝保留结果 taint；块校验拒绝会把该块的 taint 合入最终失败，即使 driver 忽略发送错误。新的 Gateway 程序执行报告 `CompletionOrigin::CurrentAttempt`，内部内核缓存命中也不改变它。只有整个请求的 Gateway 重放报告 `CachedOutcome`；独立请求存储以有界 envelope 保存完整结果及其 taint，不进入 State 历史，也不保留历史块；见[请求存储](application-gateway.md)。taint 和 origin 不授予对象下载权限。

线协议 `OutputOutcome` 独立保留 Done、Short 或类型化 Fail 及其内联/对象表示。启用 `gateway-grpc/structured-output` 后，在 `ApplicationGrpcService` 上显式安装 `GatewayOutputExternalizer`，让超出内联预算的值通过对象交付。`EncodedOutputObject` 携带编码、Blob、读取授权和过期时间；嵌套引用不隐式获得授权。原事件在编码及策略等待期间持续持有容量，同时继续轮询执行取消和截止时间。接受元数据及来源集合仍需满足帧容量。详见[应用网关](application-gateway.md)。

## 向量搜索

Embedding 生产者与检索消费者共用 `Embedding` 和 `EmbeddingRepresentation`。Envelope 包含 `space_id`、`representation` 及可选 `embedding_model`。这些都是基于普通 Value 的能力协议，内核无需增加模型专用控制流。

| 表示 `kind` | 必需字段 |
| --- | --- |
| `dense` | `values`：非空数值列表 |
| `tensor` | `tensor`：类型化的一维 `TensorRef` |
| `sparse` | `dimensions`、递增且不重复的 `indices`、等长 `values` |
| `multi` | `vectors`：非空、每行维数相同的数值列表 |
| `multi_tensor` | `tensor`：类型化的二维 `TensorRef` |

`StandardConfig::with_retrieval(RetrievalConfig)` 分别配置对象读取能力、I/O 窗口和标量工作配额。张量引用要求显式安装读取端口；即使窗口只有一个字节，也能解码全部 dtype。内置索引接收有限 `f32` 数值，以 `f64` 计算分数。稀疏维数和下标也接受十进制字符串，以表示平台完整整数范围。索引会物化准入后的向量；I/O 窗口不限制索引存储占用。

`effect://index/upsert` 接收上述 envelope、`id`、可选 `generation` 和 `metric`。空间固定表示族、维数及度量。稠密和稀疏空间支持 `cosine`（默认）、`dot` 和 `negative_squared_euclidean`；多向量空间必须声明 `mean_max_cosine`。`mean_max_cosine` 对每个 query 向量求其与全部 document 向量的最大余弦值，再对这些最大值取均值。`delete` 接收 `space_id`、`id` 和可选的预期 `generation`。

`effect://index/search` 接收 `space_id`、`representation`，以及可选的 `metric`、`k`、`mode`。省略 `metric` 时使用空间已声明的度量。`k` 默认 `10`，必须非负；`k: 0` 跳过评分，仍校验表示并保留空间来源。

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

结果最多包含 `k` 个 `{id, sim}` 条目，有已存 `generation` 时一并返回。按分数降序排列，同分候选按 `id` 升序排列；`auto` 可能与 `exact` 不同。搜索持有不可变分页根，离开注册表锁后按配置的标量工作量与遍历间隔协作让出，单条超高维向量内部也有让出点。这不保证单次 poll 的硬实时上限。空结果和依赖空间内容的校验错误仍保留所选空间的来源。

结果选择保留 `O(k)` 个条目，不包含查询/存储载荷及 ANN 候选发现。ANN 在空间超过 4096 条后的 `auto` 搜索中惰性构建；缩至 2048 条及以下时释放。构建可以取消，只有捕获的空间版本仍有效时才发布。

Memory 将表示和代次持久化到 State，索引是可重建投影。`store` 和 `commit` 默认只创建不存在的记录，替换或提升已有记录需要提供 `expected_generation`。返回值包含 `{ id, path, indexed, generation }`；`indexed: false` 表示 State 已接受记录，但并发投影更新阻止了索引发布。同一 OperationId 和相同语义请求的重试复用首次提交的表示，包括并发 embedding 调用产生不同数值结果的情况。Recall 在把分数关联到记录前逐条校验代次。记录被新代次替换后，旧操作重试会产生冲突，不会重新创建已退役的代次。默认 `consistency: "indexed"` 修复观察到的过期命中；`"reconcile"` 在 `k > 0` 时先从 State 重建。`k=0` 的回忆不触发重建。`effect://memory/rebuild` 显式修复命名空间，无需再次调用 embedding 模型。这是独立系统间的代次校验，不提供跨系统事务快照。Memory 扫描使用 State 分页，遇到超大单行时显式点读，再用后端游标继续。分页窗口不构成单条记忆的大小上限；选定的常驻表示仍有自身内存成本。

Memory 回忆先取最多 `8 * k` 个语义候选，再按 kind 筛选并进行最终重排。它的 `mode: "exact"` 描述语义候选搜索，不保证筛选和重排后的全库前 `k` 名，即使存在足够的合格记录，也可能返回不足 `k` 条。合并默认在写摘要前接纳最多 1024 条记录、累计 16 MiB 记录编码与 4 MiB 文本，`StandardConfig::with_memory_consolidation_limits` 可选显式非零限额。预计算借用词集合，每检查 1024 个 token 让出一次，保留非对称种子聚类。准入内两两比较仍为二次复杂度，限额不保证 RSS 或期限。这些策略与内核执行窗口、流窗口独立。

`RetrievalConfig::with_repair_attempts(NonZeroUsize)` 限制 Memory Recall 的搜索轮数及重建中每条记录的投影尝试数，初次尝试也计入，默认八次。耗尽返回 `Failure::HandlerError`，kind 为 `memory_repair_exhausted`，保留所有已观察来源，不返回部分排名或成功重建计数。取消停止后续修复，不撤销已提交记录或投影。此上限约束竞争放大，不限制命名空间大小、向量内存或完整调用时间；宿主仍负责调用期限。Memory 保留下游结构化失败，包括 Ranker 的原始类别和来源。

## 张量视图

`TensorRef { blob, dtype, shape }` 描述已提交对象字节的一个视图。blob 哈希只标识字节内容；不同 dtype 或 shape 的视图可以共享同一个 blob。完整引用随值和 Gateway 响应传递，无需再查询张量目录。

`effect://tensor/write` 接收内联 `data` 列表及可选的 `dtype`、`shape`，分块序列化并在对象提交后返回 `TensorRef`。它需要 `ObjectWrite`，不写入 State。默认 dtype 为 `f32`，默认 shape 为 `[data.len()]`。显式 `shape: []` 表示标量，需要一个数据元素；shape 中存在长度为 0 的维度时表示空张量，需要空数据列表：

```json
{"data": [2.5], "shape": [], "dtype": "f64"}
```

```json
{"data": [], "shape": [0, 3], "dtype": "f32"}
```

维度必须是非负整数，shape 的元素总数必须与数据长度相等。支持的 dtype 为 `f16`、`bf16`、`f32`、`f64`、`i8`、`i16`、`i32`、`i64`、`u8` 和 `bool`。浮点类型接收整数或浮点值，按所选精度舍入，并支持 IEEE NaN 和无穷值。整数类型只接收所选类型范围内的整数。`bool` 只接收布尔值，每个值编码为一个 `0` 或 `1` 字节。多字节元素采用小端编码。

序列化器复用一个至多 16 KiB 的缓冲区，小张量只按实际编码长度预留空间。这限制了序列化存储，不约束完整内联输入列表；需要增量输入字节时，使用 Gateway 对象上传。

将完整的 `TensorRef` 或 `FrameRef` 值直接传给独立安装的 `effect://blob/read` 或 `effect://blob/delete` 能力即可，也支持显式传入 `TensorRef.blob`。这些操作针对共享字节，删除内容会影响使用该 blob 的所有视图。需要持久命名时，显式将完整 `TensorRef` 保存到应用选择的 State 路径；删除该 State 条目不会删除对象。
