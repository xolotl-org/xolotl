# 核心与可移植程序

Xolotl 把控制流与模型执行、宿主服务分开。Agent、检索、工具调用和工作流由普通程序与能力受控的导入组合而成。核心本身不包含模型推理引擎。

## 分层

```text
Rust 表达式 / portable JSON              DoNode / Plan / protobuf
             |                                     |
       portable 编译器                         ExecutionGraph 转换
             +------------------+------------------+
                                |
                    xolotl-core 指令状态机
                   调用方提供任务、栈、绑定存储
                                |
                         请求与完成事件
                                |
              portable LinkedExecution 或可选托管执行
                    共用调用、值、作用域和流契约
                                |
                      按需装配 I/O、调度和存储
                                |
                     模型、工具、状态和连接器
```

`xolotl-core` 始终为 `no_std`，禁止 unsafe，默认没有依赖。宿主通过 `Values` 定义值语义；使用标量或定长值时，执行不需要堆分配。自定义值的 `Clone` 或宿主实现产生的分配不属于核心的零分配保证。

顺序延续和已完成的并行分支直接转移结果所有权。错误带来源的宿主需覆盖 `Values::influence_result`，为成功和失败都附加控制来源；`retain_result` 从任一分支取得控制快照。`retain_control` 默认克隆输入；共用的 `RuntimeValues` 只保留 taint，不为生成快照而格式化失败诊断。快照只参与结果的来源传播，不替换程序载荷或重放输入。等待中的请求和身份授权仍保留完整输入。分支分发、词法绑定、条件或清理需要的原始输入，以及 `Advance::Done` 返回的结果，在 `RuntimeValues` 下都保留共享所有权。自定义 `Values` 的复制成本由其实现决定。

`ProgramImage` 借用指令，`Execution` 借用任务、延续栈和绑定数组。`advance` 接受工作配额，返回 `Request`、`Waiting`、`Yielded`、`Cancel` 或 `Done`。宿主驱动 I/O，再通过匹配的任务与 ticket 调用 `complete(task, ticket, event, &image, &mut values)`。有效响应先附加来源，再进入隐式延续或由容量错误选择其他结果；stale 响应不改变任务来源。`Execution::retain_control` 为无法继续执行的宿主错误保留当前活动依赖，不累计操作或输出块历史。核心不创建线程、定时器或后台任务。延续栈共用一个调用方提供的定长帧池，压栈、弹栈和回收均为常数时间。帧数组长度决定总容量，`ExecutionLimits::frames_per_task` 单独限制每个任务的栈深。

最小宿主可用 `LinkedProgram` 与核心 `HandleTable` 在分派前检查导入的所有者、代次、方法权限和委派祖先；撤销祖先会使后代失效。定长 `Channel` 在满载或关闭时通过 `Full` 或 `Closed` 退回值的所有权，不静默丢弃数据。同步与唤醒由宿主实现。

## Feature 组合

| SDK feature | 包含内容 |
| --- | --- |
| 无，默认配置 | `xolotl_sdk::core`，无需 allocator 或异步运行时 |
| `serde` | 核心泛型序列化，仍支持 `no_std` |
| `program` | 通用值和 portable 编译器，支持 `no_std + alloc`，不依赖 Tokio 或存储 |
| `runtime` | 协作式执行、共用调用与作用域记账、State 和流端口，支持 `no_std + alloc` |
| `host` | 托管值、编译器、可配置时钟与任务调度器、默认 Tokio 适配器、宿主选定的 State 与可选 Fact 观察 |
| `memory` | 可选内存 State 适配器和 `in_memory` 构造器 |
| `multi-thread` | `host` 加 Tokio 多线程运行时支持 |
| `plan` | `host` 加现有 Plan 入口 |
| `standard` | `host` 加标准 Provider |

feature 可以叠加。编译组件、安装资源与授予权限是不同的宿主动作。`Xolotl` 和 `KernelBuilder` 需要启用 `host`，默认 SDK 只导出核心。`KernelBuilder::new(state)` 与 `Xolotl::new(state)` 要求显式传入 State；普通请求清理不要求其写入能力，Actor 目录与异步结果发布依赖对应业务写入端口。`memory` feature 提供 `in_memory` 构造器。`KernelBuilder::with_host_runtime` 可安装由宿主定义的 `HostClock`、`TaskSpawner` 与 `BlockingSpawner`；默认适配器使用 Tokio。

托管方法安装通过 `MethodSpec` 显式传入 `MethodAuthority`，权限、purity 和输出模式分别声明。Registry 接口描述符注册后不可改写；修改契约需使用新接口 ID 并重新绑定资源。准入检查方法权限类别、资源内唯一的方法名及 ID，所有接口合计最多 64 个方法。可调用方法的权限类别与资源 scheme 正交。`ResourceDescriptor.addressing` 显式选择精确或前缀解析；嵌入宿主可通过 `Bootstrap::register_resource` 安装任一模式并指定描述性类别。读取外部状态的纯方法须设置 `MethodSpec::observes_external()`。打开请求与 Handle 的方法位按接口声明顺序统一编号；方法 ID 是分派键，可在不同资源间复用。源 Grant 按稳定的方法名选择权限，不保存这些位置。打开句柄时，每个请求位都要解析到当前方法名及其声明的能力类别；即使源 Grant 显式选择 `all`，也要检查能力类别。Executor 保留解析方法时的绑定与接口契约；已有句柄继续使用冻结的执行计划，重新打开时若契约已改变则拒绝，需要创建新执行。句柄计划在发布前检查注册表版本，并发配置修改后不能重新写回旧缓存。图层 `lint`、`lint_actor` 接收宿主契约解析器；无法解析的方法报错，不再按名字推断权限。

## 可移植运行时

`runtime` feature 提供基于同一核心状态机的 `LinkedExecution`。`program.compile()?.with_provenance()` 消费编译产物，将常量载荷转移到 `TaintedValue`，将静态失败转为 `TaintedFailure`；portable 和 Tokio 执行共用 `RuntimeValues`，托管 `PreparedProgram::from_compiled` 也使用同一转换。

程序输入为 `TaintedValue { value, taint }`，机器错误为 `TaintedFailure { failure, taint }`，`LinkedExecution` 和托管 Executor 执行入口返回 `ExecutionOutput { outcome, taint, unresolved_operations }`。taint 描述完整结果，包括选择成功或失败的控制依赖。Catch 将错误转为诊断值时保留来源；分支选择、并行汇合和清理也保留参与结果选择的控制依赖。最终 taint 不会自动合并所有输出块的来源。`unresolved_operations` 独立于程序结果：托管执行即使在 Race 选出成功分支或 Catch 处理 `OutcomeUnknown` 后，也记录已观察到的未决效果；可移植 `RequestDriver::collect_evidence` 是必需的同步可信钩子。`LinkedExecution` 借用调用者拥有的 `UnresolvedOperations`，在消费完成或丢弃调用前收集，正常输出移动证据，丢弃执行则将证据留给调用者。纯适配器显式不记录，只接纳真实的宿主分类标识与分派阶段，不从远端错误文本推断。

`ExecutionOutput::into_parts()` 同时返回 `Result<TaintedValue, TaintedFailure>` 和 `UnresolvedOperations`；把结果组合进下一执行边界的调用方须携带两者。`TaintedFailure::into_value` 在诊断传入后续程序时保留来源，单次调用的 `DriverOutput::into_result` 也保留来源。driver 返回由数据决定的值或失败时，必须同时报告相应来源。调用用量和缓存 origin 保留在调用边界：缓存调用可以报告 `CachedOutcome`，其所在的新 Gateway 程序仍为 `CurrentAttempt`；只有整个 Gateway 请求的重放才具有请求级 `CachedOutcome`。

嵌入层提供任务、栈帧、绑定和 `PendingCall` 数组，以及 `LinkedProgram` 与句柄表。`RequestDriver` 和 `Cooperate` 使用关联 Future 类型，即时调用可以直接用 `Ready`，不要求装箱、`Send`、线程或 Tokio。需要 `!Unpin` Future 的驱动可以显式选择 `Pin<Box<F>>`。分派前及每次轮询待完成调用前都会重验权限，包括在写前记录屏障处挂起的调用。

受信任的请求适配器负责导入映射和上下文切换；外部效果驱动实现 `InvocationDriver`，只接收已经准入的操作。`invocation::invoke` 共用方法契约、`Billing`、`Reservation` 和 Fact 构造器。`Account` 只在预留或结算期间短暂访问 Scope，不跨 I/O 等待持有独占借用。树形账户适配器必须原子预留调用方与祖先账户，并只回滚本次失败的准入。`AccountRequest` 提供完整的已准入 `OperationId` 和受信任的 `CallContext`，记账凭据可以区分不同执行、重复调用和显式重试。`NoFacts` 在分派前拒绝必须记录的调用。

`Account::reserve` 是短暂的同步准入步骤。许可的 `Commit` Future 可以等待外部存储，且不跨 I/O 持有 Scope 借用。不要求 `Send` 或装箱，内存适配器返回 `Ready`。提交 Future 拥有自身事务状态，不能借用许可或临时完成视图；异步适配器在返回 Future 前编码或保留提交所需数据。托管进程账户在本轮运行中直接完成预留和结算。

`AccountPermit` 明确区分三个阶段。`dispatch` 在构造驱动 Future 前确认账户预留，成功后才能启动驱动；失败时阻止效果。`settle` 接收 `AccountCompletion`，把完整 `OperationId`、预留与实测费用、最终 `DriverOutput` 绑定到本次完成。视图借用输出，不强制克隆、分配或存储专用结果类型；外部账户适配器可在自身事务中保存结果与账户变化。结算等待期间持续拥有预留。Fact 观察由宿主单独选择，不代替账户准入。

结果保留实际交付的 outcome、来源顺序、用量（包括自定义维度和显式零值）及完成来源。计费使用投影前的结果，交给结算器的结果已应用 `SinkOnly`，丢弃的响应载荷不会被记账端口重新保留；成功、失败及短路语义仍保留。`settle` 可在效果执行后失败，`InvocationResult` 同时保留真实结果、taint、用量、缓存 origin 和 `CompletionError::Settlement`。显式选用的 Fact 写入失败以 `CompletionError::Fact` 单独报告。两者都不证明效果回滚或允许自动重试。

调用被丢弃或提交失败时，`abandon` 执行有界同步收尾。分派前取消退还预留，分派后取消保留预估支出；结算失败或等待中取消时，各预算维度保留预估与实测中的较大值。收尾释放并发槽。外部账户适配器自行承担未决提交与余额核对，不能因本地 Future 消失声称退款成功。驱动与提交 Future 在放弃许可前释放，成功结算后不再调用 `abandon`。可移植内存许可声明 `Error = Infallible`；可失败适配器提供能转换为 `Failure` 的错误。账户、业务数据与外部效果各有提交域。

托管 `DataPlane::execute` 和 `execute_with_stream` 返回相同的 `InvocationResult`。无法确认外部效果时，保留原操作身份供应用核对；不能把取消或本地丢失结果解释为效果未发生。可选 Fact 记录用于观察，不授予权限，不承担账户结算或程序恢复。

流调用在 sink 接纳前拥有终态。取得结论前取消可以发布取消；终态交付等待期间取消或交付被拒绝时，通过同步关闭保留已取得的终态状态、来源与 completion origin。接收端已关闭或终态已接纳时，不保证再次交付。交付错误与真实调用结果分别表达，必要结算未确认仍遵循自己的未知合同。交接只保留一个终态，不保留数据块历史或重启状态。

可选 Fact 失败不能遮蔽必要的流交付失败：`completion_error` 返回必要边界错误，可选观察失败交给诊断通道。先前必要结算或未知派发错误仍优先保留，实际 Driver 输出不变。

可移植 `RequestDriver` 返回 `RequestCompletion`。`Ok(HostEvent)` 推进机器，包括可以由 `Catch` 处理的普通失败；`Err(TaintedFailure)` 中断整轮执行，释放待定 Future 并保留控制来源，不确认请求，也不继续执行 `Catch` 或 `Finally` 中的效果。后续核对和生命周期清理由嵌入层负责。调用适配器用 `InvocationCall::operation()` 取得必要结算或输出交接未知的完整身份，将这类错误映射到中断分支。可选 Fact 失败保留已知 Driver 结果；确定的派发前拒绝保留实际失败。portable 示例也遵循这些规则，尽管它的内存账户提交不会失败。

取消时，嵌入层先关闭 `Scope` 准入，再调用 `LinkedExecution::cancel` 并继续轮询清理。驱动 Future 在取消确认和 `Finally` 之前释放。Drop 只释放资源，不能完成异步清理。身份切换、等待和设备 I/O 需要显式宿主适配器；示例使用固定身份并拒绝不支持的上下文切换。动态模块加载由托管适配器提供。

同一示例库可以在桌面宿主上执行 `no_std + alloc` 代码，也可以编译到 Cortex-M：

```sh
cargo run --manifest-path examples/portable-runtime/Cargo.toml --locked
cargo test --manifest-path examples/portable-runtime/Cargo.toml --locked
cargo check --manifest-path examples/portable-runtime/Cargo.toml --no-default-features --target thumbv7em-none-eabi --lib --locked
```

示例执行等价的 Rust 和 JSON 程序，汇合标量与字符串结果，结算 Scope 并释放句柄。实际开发板仍需提供入口、分配器、中断与 I/O；目标编译不能代表硬件延迟或完整运行时内存实测。

## 共用程序语言

原生 `DoNode` 编译在分配图存储或克隆载荷前，预检节点数量与源码位置命名空间，再使用显式帧降低。Actor 的 body／finalizer 绑定也先预检再克隆，克隆与路径绑定使用显式工作栈。嵌套不再受仅为递归调用栈设置的 256 层上限约束；有限图容量仍然适用，执行帧限额独立于编译。确定性源码位置和词法绑定恢复仍属于图合同。

portable 结构准入在降低前计量紧凑编码的保守下界。每处嵌入值中，不同常驻节点只检查一次；List／Map 的每条引用边均在下降遍历集合前计量。字符串、字节、map 键、Blob 哈希／媒体类型、Tensor 维度、Frame 的 blob 元数据及 StreamEnd 错误文本均计入；不读取或把引用对象内容计为内联源码。接纳 Rust 构造程序的宿主仍须单独测量精确紧凑编码大小。所有产出指令，包括控制包装和空序列的合成 Input，均在常量转换、载荷复制或导入注册前预留容量。拒绝不返回部分指令映像或未计量导入。

Plan 编译继续借用输入。`PlanCompileLimits` 默认限制紧凑源编码 1 MiB、65,536 个展开节点与深度 128；显式限额在物化前生效，校验、展开和 JSON 字面量转换采用迭代方式。输出准入计入合成序列、绑定和 bracket 节点，不只计源步骤。无绑定的序列片段在不重排步骤的前提下构造为平衡树：修饰仍包围此前的整个片段，词法绑定维持原作用域，成功输出传给后续步骤，失败阻止后续步骤。原始解析也先检查输入字节。这些限制不覆盖调用者构造、克隆、序列化和销毁 AST，也不保证这些操作可在任意小栈完成。

Rust `Program` / `Expression` 与 `Program::from_json` 使用相同源模型和编译器。JSON 有版本号，并拒绝未知字段。组合元素包含输入、常量、词法 `Let` / `Use`、顺序、条件、有界循环、递归调用、并行汇合、竞争、catch/finally、等待和身份作用域。更高层行为应组合这些元素，或增加宿主操作。

源 AST（`DoNode`、`Expression` 及其中的 JSON 字面量）在正常释放、准入拒绝和 panic 展开时均迭代释放。检查结构时使用借用，例如 `match &source.body` 或 `match &node`，不要通过按值匹配移出这些实现了 `Drop` 的枚举字段。组合拥有的节点使用构造器；编译产物不借用源 AST。

portable lowering 借用源节点并使用显式帧，提高 `CompileLimits.expression_depth` 不要求更深的原生调用栈。序列使用记录的入口／尾部地址链接，不反复扫描指令链。JSON 解码、源对象序列化和字面量转换仍有独立深度边界，提高编译限额不会移除这些边界。AST 释放复用序列和 JSON 容器的拥有迭代器，不复制宽分支节点工作区；下降前释放终端兄弟，耗尽的容器及时释放。待处理分支和仍保留的容器容量均影响堆峰值；源文档字节限额不是进程内存限额。

```rust,ignore
use xolotl_sdk::{Expression as E, Program, Transform};

let source = Program::new(E::literal(3).then(E::Transform {
    operation: Transform::Add { value: 4 },
}));
let compiled = source.compile()?;
```

等价 JSON：

```json
{"version":1,"body":{"kind":"sequence","steps":[{"kind":"literal","value":3},{"kind":"transform","operation":{"op":"add","value":4}}]}}
```

`Literal` 使用普通 JSON。`Constant` 和操作的 `literal_input` 使用类型标记编码，保留字节、blob、张量、帧、流结束标记和浮点原始位；包含 `type` 字段的普通 map 仍是 map。程序标识包含指令格式版本、实际降低后的指令、入口、绑定数量和有效 imports；不同源码降低为同一镜像时可以具有相同标识。它只标识产物，不授予执行权限。

宿主可在准备产物前使用 `CompiledProgram::map_imports` 绑定导入。它保留指令位置与词法槽位，拒绝跨越 request/scope 类型的替换，并重新计算可执行指纹。Signal wait 无需 Console 再改写导入：Kernel 在准备阶段将其降为目标资源上的 unary `subscribe` Operation，使用普通的 Handle 准入、剩余策略及 Fact 记录；已安装方法负责实际等待。条件谓词检查进入 Wait 的值，而非之后到达的信号值。

`PreparedProgram::new(&compiled)` 通过克隆容器和拥有的元数据保留调用方的编译产物；移交所有权时使用 `PreparedProgram::from_compiled(compiled)` 避免这次克隆。克隆已经准备好的 `PreparedProgram` 则共享指令、常量和缓存分析结果。

先用 `PreparedProgram::new` 准备一次程序，再用 `Xolotl::run_prepared` 传入身份、资源允许列表和 `TaintedValue` 输入。SDK 按方法声明的权限类别分别衰减允许列表内资源的已安装方法，不额外授予其他能力类别或传播标志。执行入口返回 `Result<ExecutionCompletion, XolotlError>`，显式通过 `completion.output` 读取正文结果、taint 和未决身份，通过 `completion.finalization` 读取不可变清理证据；组合下个请求时应保留正文来源及核对证据。每次调用创建授权衰减后的请求进程；指令被借用，可变执行存储互相独立。克隆 `PreparedProgram` 只增加共享引用，指令、常量和资源分析结果不重复分配。重复执行可传入 `ExecutionBuffers`，通过 `run_prepared_with_buffers` 或 `Executor::eval_prepared_with_buffers` 复用空闲容器；图入口也提供 `eval_graph_with_buffers`。`reserve_for` 可提前分配，`retained_bytes` 查询保留容量，`release` 将容量归还分配器。每个并发执行独占一组缓冲区，普通返回、失败和丢弃 Future 都会释放其中的值。缓冲复用不包含载荷、I/O Future 和进程记录的分配。丢弃 Future 只释放存储，无法运行异步 `Finally`。`run_program` 是每次准备指令的便捷入口。完整的 Rust/JSON 组合示例：

```sh
cargo run -p xolotl-sdk --features memory --example portable
```

protobuf `PortableProgram` envelope 携带有大小限制的 JSON 和程序标识，转换时进行校验。它不新增远程执行授权或不受限的网关入口。原生 `StepRef` 闭包仍属于已有托管图入口，不能序列化成 portable 函数。

portable 源码通过 `Expression::Module { module: StepRef::new("increment") }` 显式加载延续，JSON 表示为 `{"kind":"module","module":{"name":"increment"}}`。宿主通过 `StepModule::program(name, revision, loader)` 或 `StepBinding::program` 绑定加载器，再用 `StepModule::compose` 与原生函数组合。`ProgramLoader` 借用输入和可选参数，返回 `PreparedProgram`。加载器是同步无副作用函数；外部源码应先通过 Operation 读入。内核只保留加载器，不缓存所有返回过的镜像。`LoaderRevision::from_bytes([u8; 32])` 标识加载器实现及其捕获的配置，与每次返回程序的身份分开。实现或配置变化时，宿主必须更换 revision。源码位置保留模块内含义，执行 ticket 区分重复调用。原生和 portable 混合示例：

```sh
cargo run -p xolotl-sdk --features memory --example native_modules
```

## 资源与取消边界

标准 Context 装配驱动先验证已知层，并按常驻身份记忆化渲染字节长度，再选择提示材料。只把选中的层渲染到最终缓冲，不创建逐层文本中间副本。persona 与 environment 始终作为锚点保留，即使超过 token 估算额度；格式错误的已知层即使会被排除也仍然失败。提示大小与缓冲预留另行检查，保留锚点不免除物化失败，也不把 token 估算变为 RSS 限额。

核心不扩容调用方提供的存储，容量耗尽时返回错误。循环次数、可选累计转换配额和清理转换次数分别设置。`CompileLimits` 默认允许单个模块表达式嵌套 128 层、65,536 条指令、1 MiB 源文档。宿主可通过 `compile_with_limits` 与 `from_json_with_limits` 显式调整准入；调整限额不改变同一源文档的程序身份。JSON 解码仍有独立递归限制，指令地址仍使用 `u32`。

托管 `ExecutionConfig` 默认限制为 65 个任务槽、每任务 256 层栈、总计 1,024 个共享栈帧、每任务 1,024 个绑定、 65,536 条指令、16 MiB 执行容器浅层存储、4,096 次清理转换，以及 256 次转换的调度配额。`max_steps` 默认是 `None`；宿主可独立设置 `Some(quota)` 限制累计转换。耗尽一次调度配额只会让步，不会终止长任务。静态程序使用推导出的较小布局；递归程序无法静态估计时使用配置的容量上限。共享帧池由 `max_frames` 约束，不按任务数乘以每任务栈上限分配。一次 fork 保留挂起的父任务并使用两个子任务槽。

注册的 Process finalizer 共用一个 `ExecutionConfig::cleanup_timeout`，默认整段序列 30 秒。该墙钟期限与 `cleanup_steps` 互补，不抢占同步原生代码，也不停止已接纳的存储写入。派生资源执行（包括 finalizer）继承请求授权器；拒绝或超时保留本轮清理失败，本地 Handle 释放与终态发布仍继续。

包含原生 Step 或 portable 模块的程序也从当前镜像的推导布局开始。导入产生子程序后，宿主分析其需求，与初始镜像及仍在执行的原生调用的需求合并。已完成调用不再叠加，因此 64 个顺序标量 Step 只需要一个任务和一个栈帧。该估计是保守上界，任务、帧、绑定、指令和字节上限仍独立生效。

宿主只在必要时增长容器：先预留替换容器，再移动已有值，保持待完成 I/O 和 ticket 不变。增长期间的字节预算同时计算旧容器和替换容器。扩展被拒绝或预留失败时，撤销对应镜像改动，进入普通错误恢复；空闲容量可通过 `ExecutionBuffers` 留给后续执行复用。

加载的子程序独立转换并分析后，链接到可复用的指令、导入和绑定区间。执行器在宿主边界检查活动延续帧，回收已结束片段的常量和导入，并清空所有任务行中属于该片段的绑定值。嵌套调用和并发等待期间，活动地址保持稳定。相邻空闲区间会合并；较早片段结束后，即使较晚片段仍在等待，也能复用前者的空间。64 次各含一个局部变量的顺序调用只需一个绑定槽，指令空间只需容纳初始图和一个两指令片段。

空闲容器容量保留到执行结束。不同大小的活动片段可能留下无法容纳新片段的小空洞，因此配置上限约束包含空洞的地址范围，不能简单理解为活动指令数之和；当前没有移动式压缩。源码位置保留模块内含义，调用 ticket 区分重复调用，与存储地址复用无关；ticket 耗尽时返回错误，不复用已有记录身份。模块加载不存在累计源码位置上限。编译临时空间、代码容器和值载荷仍不计入 `max_storage_bytes`。

核心自身始终不扩容。`Execution::suspend` 释放存储借用并返回元数据；宿主可增长数组、重排绑定行，再通过 `Execution::resume` 校验并恢复，过程中不克隆值。这只是内存内交接，不是持久化提交或重新分派请求；`continuation_entries` 无分配地报告活动子程序。`clear_bindings` 不克隆值，释放宿主指定的已退役绑定区间；宿主必须先确认活动代码和作用域已不再引用该区间。

`ProgramImage::resource_requirements` 在核心层分析可达控制流，接收每条指令一个 `AnalysisSlot` 的临时数组。分析时间和临时空间均为线性，不递归使用原生调用栈，也不分配堆内存。顺序和互斥分支复用容量；并行分支叠加任务数，子任务的栈不叠加父任务已有的栈。非递归函数调用可静态推导；无法确定有限上界的维度返回 `None`，由宿主选择容量。分析仅覆盖当前镜像，不预测宿主返回的原生扩展。

编译器在词法作用域结束后复用绑定槽，并在调用、异常退出和并行分支中维持变量恢复语义。托管准备阶段缓存资源分析，`PreparedProgram::layout(&config)` 可在执行前查询任务数、总帧数、每任务栈深、绑定数量以及容器字节数。2,048 个顺序的单变量作用域只需一个绑定槽； 64 段顺序执行的二分支并行程序只需三个任务槽；纯顺序输入或转换链无需延续栈。两个分支中只有一个需要 64 帧时，父任务和两个子任务共用 64 帧，无需为三个任务分别预留。保留的缓冲容量也受当前字节预算约束。空闲缓冲需要替换时先释放旧分配；增长仍有活动值的缓冲时，还需计入上面说明的容器重叠部分。

字节上限只统计任务、栈和绑定容器，不包含值的堆载荷、已编译指令、驱动缓冲、Fact 留存或进程历史。要求总内存上限的宿主必须分别约束这些部分。转换次数不能抢占同步驱动或原生 Step；阻塞工作需要宿主隔离，并在操作层设置超时。

`cancel_process` 唤醒等待中的 Executor。即使待决效果可能已启动，取消结果仍为 `Failure::Cancelled`；它不证明回滚。已完成的托管 `ExecutionOutput` 单独保留观察到的未决身份；丢弃执行 Future 可能使这些身份无法交付。宿主先释放取消请求的 Future，再确认完成，归还预算并发额度并保留不确定的费用。`Finally` 在独立转换预算内执行，接收 body 的原始输入，保留 body 失败；body 成功而清理失败时返回清理失败，否则返回 body 的值。选定结果保留 body 与清理的控制依赖。Race 选中首个结果后，取消并清理另一分支再返回；胜出值不会抹掉败者的未决效果。

原生 `DoNode::finally` 与可移植 `Expression::Finally` 降到同一核心指令。`DoNode::bracket` 和 Plan 的 `bracket` 绑定取得的值，并将该值传给释放步骤；成功、普通失败或协作取消后均运行释放，同时保留 body 的结果作为程序结果。丢弃执行 Future 或强制超时不能运行词法清理，请求所有者仍须完成进程清理。

`Executor::with_deadline(HostDeadline)` 接受所属 Kernel 的 `HostRuntime` 生成的绝对单调截止时间。宿主在推进机器和等待 I/O 时检查它。若期限中断可能已产生外部效果的未完成调用，返回原因 `deadline_exceeded` 的 `Failure::OutcomeUnknown`；否则返回 `Failure::Timeout`。`Deterministic` 和 `Observation` 重放类别本身不构成未决效果。两种结果均保留机器当前活动来源，并释放待完成调用。这是立即停止，不能继续执行词法 `Finally`，请求所有者仍需结束进程并运行进程终结器。期限引发的 `OutcomeUnknown` 携带排序、去重后的 `operation_ids`，涵盖已轮询且仍待完成的效果调用。结果中的有界 `unresolved_operations` 独立于最终 outcome，保留这些身份与之前由宿主观察到的不确定性。`identities_incomplete` 表示有身份不可得，即使 ID 列表为空也不能推断没有效果。这些 ID 用于核对，不是此前全部效果的审计清单。同步 driver 和原生 Step 仍不能被抢占。

`with_deadline` 在期限来自另一 `HostRuntime` 时钟域时返回错误。运行时的 Clone 保留时钟域。宿主将应用持有的绝对到期时间转换为运行时期限时，使用该运行时的时钟；单调时钟值不能跨时钟域转移。

单独的 Executor Future 只拥有执行存储，不负责 Process 生命周期。`Bootstrap::request_under` 返回拥有请求生命周期的 `RequestProcess`：通过 `executor` 执行，再把完整 `ExecutionOutput` 交给 `finish(&output)`。进程终结保留 body 终态以及各终结器结果的来源。独立任务可使用 `Arc<Bootstrap>` 上的 `request_under_owned`，由同一个 `RequestProcess` 持有共享宿主，无需克隆宿主的内部字段。Gateway 从创建请求起，经过票据准入、执行和终结一直保留该所有者；已接受的输入流跨调用传递它。SDK 的图执行和普通 prepared 执行自动使用这一作用域。丢弃未完成作用域会立即关闭请求树、取消执行、中止已附着任务并撤销现有句柄；宿主的 `TaskSpawner` 接收任务时，再调度一次异步进程清理。正常完成的请求不创建清理任务。`Bootstrap::drain_cleanup` / `Xolotl::drain_cleanup` 尝试待清理工作，包括调度器关闭或后端失败留下的工作，并等待分离的清理任务释放所持 Kernel 对象。将它作为停机屏障前，须停止创建新请求。失败的进程树留待后续重试，不在内部无限重试；宿主阻塞作业另有自己的生命周期。

正常完成只结束指定进程，已独立启动的 Actor 和异步结果任务可以继续。显式关闭树会穿过已经完成的祖先处理所有后代，将没有既定终结结果的活进程取消，并等待受管正文 Future 释放。正文或终结器等待自身退出会返回 `ProcessBusy`。Actor 目录和异步结果使用保留在进程表中的终态发布对象，后端失败后结果仍可重试，不会提前完成清理。

正文完成后仍需排空输出时，在等待交付前调用 `RequestProcess::complete_body(&output)`。该同步交接沿用首次终态与 Local 清理合同，只保留正文来源及有界未决身份，不保存载荷；它不运行终结器，不确认清理完成，不覆盖此前的取消或 Tree 清理选择。服务持有原输出，交付失败后仍调用 `finish(&output)`。交接后释放拥有者保留已选择的正文结论；已经终结的进程拒绝新的正文证据。

进程终结器与程序内的词法 `Finally` 分别管理。清理中断后，尚未开始的进程终结器仍被保留；已尝试的终结器不会自动重放，中断会记为失败，因为外部效果可能未完成。生命周期记录重试保留原始时间戳、终结结果和已撤销句柄数量。完成后，在进程表锁外释放模块、附着 grant 和终结器存储。

丢弃执行 Future、强制中止 Tokio 任务、进程退出和 `finalize_process` 无法继续运行程序内的异步 `Finally`。优雅退出应先取消、等待执行器结果，再结束请求进程；进程清理 I/O 仍需要宿主超时。终态条目仅在清理与全部 custody 结束后才可由准入自动回收；显式记录的 Fact 另有留存策略。完成清理不代表总内存有界。

托管进程存储可以单独限制容量：

```rust,ignore
use std::num::NonZeroUsize;
use xolotl_sdk::{Bootstrap, DoNode, IdentityRef, KernelBuilder, Value};

let kernel = KernelBuilder::in_memory()
    .with_process_capacity(NonZeroUsize::new(64).ok_or("invalid capacity")?)
    .build();
let host = Bootstrap::from_kernel(kernel);
let request = host.request_under(host.root(), IdentityRef::ROOT, &[])?;
let output = request.executor().eval(&DoNode::pure(Value::null())).await;
let report = request.finish(&output).await?;
let examined_limit = 16;
let reaped = host.kernel().processes().reap_finalized(examined_limit);
```

根进程占一个条目。共同子进程准入在满表拒绝前自动检查排队的退役候选。只有清理完成，且没有任务、终结器、原生捕获、预留操作或清理 pin 的终态叶子才可回收；祖先有子成员时继续保留，不驱逐待清理或仍有 custody 的记录。每个锁内批次最多检查 32 个候选；满表准入可检查开始时捕获的队列长度，总成本为 O(该快照长度)，不是常数时间。新候选不会无限延长本次检查预算。`reap_finalized(limit)` 仍供显式维护：limit 限制检查候选数，包括失效或 pinned 项；返回值才是实际移除数。pin 丢弃只登记候选，不立即回收。示例保留的 `report` 在进程移除后仍可读取，不会 pin 进程。Tree 清理跨等待持有所选成员的 pin。`set_capacity` 在共享表间调整上限，但拒绝低于当前条目数的设置。容器容量保留供复用，条目数量上限不等于字节或 RSS 上限；回收不会删除显式记录的 Fact 或已发布的异步输出，存储留存与值载荷仍需独立预算。

进程 ID 单调增长，耗尽时拒绝准入。进程身份只定位本轮 Kernel 中的工作；重开应用数据不会重建进程或执行位置。

## 有界 Fact 读取

自定义存储实现 `FactStore::scan(FactQuery)` 和按身份索引的 `lookup(FactLookup)`。点查在同一存储视图内筛选当前调用进程，再检查字节预算。分页独立限制返回条数、候选检查数和编码字节，使用 `query.next_page(&page)` 续页；过滤后的空页仍可能尚未结束。每页 `end` 捕获该页读取上界，不冻结旧槽位的完成更新。

字节预算统计编码量，不是解码堆、后端缓存或 RSS 上限。Fact 是否记录、后端与留存由宿主选择。需要稳定诊断视图时停止写入；订阅 lag 后重新扫描可能变化的旧槽位。Fact 不能恢复控制流，也不证明权限或外部效果提交。

## 本轮挂起与数据持久化

`Execution::view()` 借用当前机器的状态和存储，供本轮检查。`suspend()` 消耗机器并返回 `SuspendedExecution`，释放调用方数组的借用；宿主可增长缓冲，再用 `resume(image, token, tasks, frames, bindings)` 继续同一次执行。任务、栈和绑定仍由宿主持有，挂起令牌不是持久程序快照。Kernel 用此路径扩展动态 step 的机器存储。

运行时拥有当前宿主生命周期内的请求、权限、预算和清理。Console 的[独立提交与结果保留](console-runtime.md#独立提交与结果保留)把执行责任交给当前服务，并使用有界结果留存。宿主退出后，应用重新打开 State、对象、凭据及业务调用记录，依据数据提交和外部系统状态决定后续工作。业务幂等键由应用选择；未知效果先核对再决定是否重试。

## 验证与测量

```sh
cargo check -p xolotl-sdk --no-default-features --target thumbv7em-none-eabi --lib
cargo check -p xolotl-sdk --features serde --target thumbv7em-none-eabi --lib
cargo bench -p xolotl-kernel --features memory --bench kernel_hot_paths -- process_reaping
cargo tree -p xolotl-sdk --no-default-features --edges normal
cargo run -p xolotl-core --release --example core_footprint
cargo bench -p xolotl-kernel --features memory --bench kernel_hot_paths -- kernel/prepared
cargo bench -p xolotl-kernel --features memory --bench kernel_hot_paths -- kernel/payload
cargo bench -p xolotl-kernel --features memory --bench kernel_hot_paths -- kernel/native
```

目标检查前需通过 rustup 安装 Cortex-M target。`core_footprint` 示例统计标量存储和每 1,000 次操作的批次均值，包含准入与存储重置；其中 p99 是批次均值的分位数，不是单请求尾延迟。prepared 基准包含宿主执行存储分配与调度器入口，不包含编译、请求进程创建、I/O 和推理。比较性能时应保持工作负载、feature、构建配置和硬件一致。

`benchmarks/runtime` 测量控制流、驻留值、portable 与托管执行、流取消、文件对象、State/Fact 数据重开及 Provider 解析。运行器将计时与堆统计分开，校验输出和资源释放，并在固定活动窗口下增加累计工作量。在仓库根目录运行：

```sh
python3 benchmarks/runtime/measure.py build --output target/runtime-measurements
python3 benchmarks/runtime/measure.py smoke time heap scaling --output target/runtime-measurements
```

工作负载参数、环境记录和测量范围见 `benchmarks/runtime/README.md`。堆报告统计夹具初始化和预热之后的分配，不代表进程 RSS 或设备内存；计时包含完整工作负载、结果校验及其持有资源的释放。
