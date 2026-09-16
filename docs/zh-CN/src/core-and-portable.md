# 核心与可移植程序

Xolotl 把控制流与模型执行、宿主服务分开。Agent、检索、工具调用和工作流由普通程序与
能力受控的导入组合而成。核心本身不包含模型推理引擎。

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
              portable LinkedExecution 或 Tokio 宿主
                    共用调用、值、作用域和流契约
                                |
                      按需装配 I/O、调度和存储
                                |
                     模型、工具、状态和连接器
```

`xolotl-core` 始终为 `no_std`，禁止 unsafe，默认没有依赖。宿主通过 `Values`
定义值语义；使用标量或定长值时，执行不需要堆分配。自定义值的 `Clone` 或宿主实现
产生的分配不属于核心的零分配保证。

顺序延续和已完成的并行分支直接转移结果所有权。错误带来源的宿主需覆盖
`Values::influence_result`，为成功和失败都附加控制来源；`retain_result` 从任一分支
取得控制快照。`retain_control` 默认克隆输入；
共用的 `RuntimeValues` 只保留 taint，不为生成快照而格式化失败诊断。快照只参与结果的
来源传播，不替换程序载荷或重放输入。等待中的请求和身份授权仍保留完整输入。分支分发、词法绑定、
条件或清理需要的原始输入，以及 `Advance::Done` 返回并保留用于检查点的结果，
在 `RuntimeValues` 下都保留共享所有权。自定义 `Values` 的复制成本由其实现决定。

`ProgramImage` 借用指令，`Execution` 借用任务、延续栈和绑定数组。`advance` 接受工作配额，
返回 `Request`、`Waiting`、`Yielded`、`Cancel` 或 `Done`。宿主驱动 I/O，再通过匹配的
任务与 ticket 调用 `complete(task, ticket, event, &image, &mut values)`。有效响应先附加
来源，再进入隐式延续或由容量错误选择其他结果；stale 响应不改变任务来源。
`Execution::retain_control` 为无法继续执行的宿主错误保留当前活动依赖，不累计操作或输出块
历史。核心不创建线程、定时器或后台任务。
延续栈共用一个调用方提供的定长帧池，压栈、弹栈和回收均为常数时间。
帧数组长度决定总容量，`ExecutionLimits::frames_per_task` 单独限制每个任务的栈深。

最小宿主可用 `LinkedProgram` 与核心 `HandleTable` 在分派前检查导入的所有者、代次、
方法权限和委派祖先；撤销祖先会使后代失效。定长 `Channel` 在满载或关闭时通过 `Full`
或 `Closed` 退回值的所有权，不静默丢弃数据。同步与唤醒由宿主实现。

## Feature 组合

| SDK feature | 包含内容 |
| --- | --- |
| 无，默认配置 | `xolotl_sdk::core`，无需 allocator 或异步运行时 |
| `serde` | 核心泛型序列化，仍支持 `no_std` |
| `program` | 通用值和 portable 编译器，支持 `no_std + alloc`，不依赖 Tokio 或存储 |
| `runtime` | 协作式执行、共用调用与作用域记账、State 和流端口，支持 `no_std + alloc` |
| `host` | 托管值、编译器、Tokio 单线程支持、内存状态与事实记录 |
| `multi-thread` | `host` 加 Tokio 多线程运行时支持 |
| `plan` | `host` 加现有 Plan 入口 |
| `standard` | `host` 加标准 Provider |
| `durable` | `host` 加检查点接口与序列化，仍需提供存储 |

feature 可以叠加。`durable` 不要求 `standard` 或网关；
`xolotl-storage-redb/durable` 提供独立检查点适配器。编译组件、安装资源与授予权限是不同的宿主动作。
`Xolotl` 和 `XolotlBuilder` 需要启用 `host`，默认 SDK 只导出核心。

## 可移植运行时

`runtime` feature 提供基于同一核心状态机的 `LinkedExecution`。
`program.compile()?.with_provenance()` 消费编译产物，将常量载荷转移到 `TaintedValue`，
将静态失败转为 `TaintedFailure`；portable 和 Tokio 执行共用 `RuntimeValues`，托管
`PreparedProgram::from_compiled` 也使用同一转换。

程序输入为 `TaintedValue { value, taint }`，机器错误为
`TaintedFailure { failure, taint }`，`LinkedExecution` 和托管 Executor 执行入口返回
`ExecutionOutput { outcome, taint }`。taint 描述完整结果，包括选择成功或失败的控制依赖。
Catch 将错误转为诊断值时保留来源；分支选择、并行汇合和清理也保留参与结果选择的控制依赖。
最终 taint 不会自动合并所有输出块的来源。

`ExecutionOutput::into_result` 返回 `Result<TaintedValue, TaintedFailure>`，
`TaintedFailure::into_value` 在诊断传入后续程序时保留来源，单次调用的
`DriverOutput::into_result` 遵循同一规则。driver 返回由数据决定的值或失败时，必须同时报告相应来源。
调用用量和缓存 origin 保留在调用边界：缓存调用可以报告 `CachedOutcome`，其所在的新
Gateway 程序仍为 `CurrentAttempt`；只有整个 Gateway 请求的重放才具有请求级 `CachedOutcome`。

嵌入层提供任务、栈帧、绑定和 `PendingCall` 数组，以及 `LinkedProgram` 与句柄表。
`RequestDriver` 和 `Cooperate` 使用关联 Future 类型，即时调用可以直接用 `Ready`，
不要求装箱、`Send`、线程或 Tokio。需要 `!Unpin` Future 的驱动可以显式选择 `Pin<Box<F>>`。
分派前及每次轮询待完成调用前都会重验权限，包括在写前记录屏障处挂起的调用。

受信任的请求适配器负责导入映射和上下文切换；外部效果驱动实现 `InvocationDriver`，只接收
已经准入的操作。`invocation::invoke` 共用方法契约、`Billing`、`Reservation` 和 Fact 构造器。
`Account` 只在预留或结算期间短暂访问 Scope，不跨 I/O 等待持有独占借用。树形账户适配器
必须原子预留调用方与祖先账户，并只回滚本次失败的准入。`NoFacts` 在分派前拒绝必须记录的调用。

取消时，嵌入层先关闭 `Scope` 准入，再调用 `LinkedExecution::cancel` 并继续轮询清理。
驱动 Future 在取消确认和 `Finally` 之前释放。Drop 只释放资源，不能完成异步清理。
身份切换、等待和设备 I/O 需要显式宿主适配器；示例使用固定身份并拒绝不支持的上下文切换。
持久恢复和动态模块加载由可选托管适配器提供。

同一示例库可以在桌面宿主上执行 `no_std + alloc` 代码，也可以编译到 Cortex-M：

```sh
cargo run --manifest-path examples/portable-runtime/Cargo.toml --locked
cargo test --manifest-path examples/portable-runtime/Cargo.toml --locked
cargo check --manifest-path examples/portable-runtime/Cargo.toml --no-default-features --target thumbv7em-none-eabi --lib --locked
```

示例执行等价的 Rust 和 JSON 程序，汇合标量与字符串结果，结算 Scope 并释放句柄。
实际开发板仍需提供入口、分配器、中断与 I/O；目标编译不能代表硬件延迟或完整运行时内存实测。

## 共用程序语言

Rust `Program` / `Expression` 与 `Program::from_json` 使用相同源模型和编译器。
JSON 有版本号，并拒绝未知字段。组合元素包含输入、常量、词法 `Let` / `Use`、顺序、
条件、有界循环、递归调用、并行汇合、竞争、catch/finally、等待和身份作用域。
更高层行为应组合这些元素，或增加宿主操作。

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

`Literal` 使用普通 JSON。`Constant` 和操作的 `literal_input` 使用类型标记编码，
保留字节、blob、张量、帧、流结束标记和浮点原始位；包含 `type` 字段的普通 map 仍是 map。
程序标识包含规范化源表示、编译器版本和指令版本，只标识产物，不授予执行权限。

先用 `PreparedProgram::new` 准备一次，再用 `Xolotl::run_prepared` 传入身份、资源允许列表
和 `TaintedValue` 输入。SDK 执行入口返回 `Result<ExecutionOutput, XolotlError>`，
组合下个请求时应保留结果 taint。每次调用创建授权衰减后的请求进程；指令被借用，可变执行存储互相独立。
克隆 `PreparedProgram` 只增加共享引用，指令、常量和资源分析结果不重复分配。
重复执行可传入 `ExecutionBuffers`，通过 `run_prepared_with_buffers` 或
`Executor::eval_prepared_with_buffers` 复用空闲容器；图入口也提供 `eval_graph_with_buffers`。
`reserve_for` 可提前分配，`retained_bytes` 查询保留容量，`release` 将容量归还分配器。
每个并发执行独占一组缓冲区，普通返回、失败和丢弃 Future 都会释放其中的值。
缓冲复用不包含载荷、I/O Future 和进程记录的分配。丢弃 Future 只释放存储，无法运行异步 `Finally`。
`run_program` 是每次准备指令的便捷入口。完整的 Rust/JSON 组合示例：

```sh
cargo run -p xolotl-sdk --features host --example portable
```

protobuf `PortableProgram` envelope 携带有大小限制的 JSON 和程序标识，转换时进行校验。
它不新增远程执行授权或不受限的网关入口。原生 `StepRef` 闭包仍属于已有托管图入口，
不能序列化成 portable 函数。

portable 源码通过 `Expression::Module { module: StepRef::new("increment") }` 显式加载延续，
JSON 表示为 `{"kind":"module","module":{"name":"increment"}}`。
宿主通过 `StepModule::program(name, revision, loader)` 或 `StepBinding::program` 绑定加载器，再用
`StepModule::compose` 与原生函数组合。`ProgramLoader` 借用输入和可选参数，返回 `PreparedProgram`。
加载器是同步无副作用函数；外部源码应先通过 Operation 读入。内核只保留加载器，不缓存所有返回过的镜像。
`LoaderRevision::from_bytes([u8; 32])` 标识加载器实现及其捕获的配置，与每次返回程序的身份分开。
实现或配置变化时，宿主必须更换 revision。恢复只能检查这份声明，无法识别未更新 revision 的实现变化。
源码位置保留模块内含义，执行 ticket 区分重复调用。原生和 portable 混合示例：

```sh
cargo run -p xolotl-sdk --features host --example native_modules
```

## 资源与取消边界

核心不扩容调用方提供的存储，容量耗尽时返回错误。循环次数、可选累计转换配额和清理转换次数
分别设置。`CompileLimits` 默认允许单个模块表达式嵌套 128 层、65,536 条指令、1 MiB 源文档。
宿主可通过 `compile_with_limits` 与 `from_json_with_limits` 显式调整准入；调整限额不改变
同一源文档的程序身份。JSON 解码仍有独立递归限制，指令地址仍使用 `u32`。

托管 `ExecutionConfig` 默认限制为 65 个任务槽、每任务 256 层栈、总计 1,024 个共享栈帧、每任务 1,024 个绑定、
65,536 条指令、16 MiB 执行容器浅层存储、4,096 次清理转换，以及
256 次转换的调度配额。`max_steps` 默认是 `None`；宿主可独立设置 `Some(quota)` 限制累计转换。
耗尽一次调度配额只会让步，不会终止长任务。静态程序使用推导出的较小布局；递归程序无法静态估计时使用
配置的容量上限。共享帧池由 `max_frames` 约束，不按任务数乘以每任务栈上限分配。
一次 fork 保留挂起的父任务并使用两个子任务槽。

包含原生 Step 或 portable 模块的程序也从当前镜像的推导布局开始。导入产生子程序后，宿主分析其需求，
与初始镜像及仍在执行的原生调用的需求合并。已完成调用不再叠加，因此 64 个顺序标量 Step
只需要一个任务和一个栈帧。该估计是保守上界，任务、帧、绑定、指令和字节上限仍独立生效。

宿主只在必要时增长容器：先预留替换容器，再移动已有值，保持待完成 I/O 和 ticket 不变。
增长期间的字节预算同时计算旧容器和替换容器。扩展被拒绝或预留失败时，撤销对应镜像改动，
进入普通错误恢复；空闲容量可通过 `ExecutionBuffers` 留给后续执行复用。

加载的子程序独立转换并分析后，链接到可复用的指令、导入和绑定区间。执行器在宿主边界检查
活动延续帧，回收已结束片段的常量和导入，并清空所有任务行中属于该片段的绑定值。
嵌套调用和并发等待期间，活动地址保持稳定。相邻空闲区间会合并；较早片段结束后，
即使较晚片段仍在等待，也能复用前者的空间。64 次各含一个局部变量的顺序调用只需
一个绑定槽，指令空间只需容纳初始图和一个两指令片段。

空闲容器容量保留到执行结束。不同大小的活动片段可能留下无法容纳新片段的小空洞，因此
配置上限约束包含空洞的地址范围，不能简单理解为活动指令数之和；当前没有移动式压缩。
源码位置保留模块内含义，调用 ticket 区分重复调用，与存储地址复用无关；ticket 耗尽时返回错误，
不复用已有记录身份。模块加载不存在累计源码位置上限。
编译临时空间、代码容器和值载荷仍不计入 `max_storage_bytes`。

核心自身始终不扩容。`Execution::suspend` 释放存储借用并返回元数据；宿主可增长数组、
重排绑定行，再通过 `Execution::resume` 校验并恢复，过程中不克隆值。
这只是内存内交接，不是持久化提交或重新分派请求；`continuation_entries` 无分配地报告活动子程序。
`clear_bindings` 不克隆值，释放宿主指定的已退役绑定区间；宿主必须先确认活动代码和作用域
已不再引用该区间。

`ProgramImage::resource_requirements` 在核心层分析可达控制流，接收每条指令一个
`AnalysisSlot` 的临时数组。分析时间和临时空间均为线性，不递归使用原生调用栈，也不分配堆内存。
顺序和互斥分支复用容量；并行分支叠加任务数，子任务的栈不叠加父任务已有的栈。
非递归函数调用可静态推导；无法确定有限上界的维度返回 `None`，由宿主选择容量。
分析仅覆盖当前镜像，不预测宿主返回的原生扩展。

编译器在词法作用域结束后复用绑定槽，并在调用、异常退出和并行分支中维持变量恢复语义。
托管准备阶段缓存资源分析，`PreparedProgram::layout(&config)` 可在执行前查询任务数、
总帧数、每任务栈深、绑定数量以及容器字节数。2,048 个顺序的单变量作用域只需一个绑定槽；
64 段顺序执行的二分支并行程序只需三个任务槽；纯顺序输入或转换链无需延续栈。
两个分支中只有一个需要 64 帧时，父任务和两个子任务共用 64 帧，无需为三个任务分别预留。
保留的缓冲容量也受当前字节预算约束。空闲缓冲需要替换时先释放旧分配；增长仍有活动值的缓冲时，
还需计入上面说明的容器重叠部分。

检查点恢复使用已保存的布局，并重新核验当前宿主的全部容量和字节上限。
提高配置上限不强制重排正在恢复的状态；降低到已用布局以下时拒绝恢复。
核心检查点使用独立的 `CHECKPOINT_VERSION = 1`，恢复时校验栈归属、原生子程序入口、自由链、计数及未使用槽位。
未知检查点格式会被拒绝；指令格式版本与检查点版本分别演进。

字节上限只统计任务、栈和绑定容器，不包含值的堆载荷、已编译指令、驱动缓冲、Fact 留存或
进程历史。要求总内存上限的宿主必须分别约束这些部分。转换次数不能抢占同步驱动或原生 Step；
阻塞工作需要宿主隔离，并在操作层设置超时。

`cancel_process` 唤醒等待中的 Executor。宿主先释放取消请求的 Future，再确认完成，
归还预算并发额度并保留不确定的费用。`Finally` 在独立转换预算内执行，接收 body 的
原始输入，保留 body 失败；body 成功而清理失败时返回清理失败，否则返回 body 的值。
选定结果保留 body 与清理的控制依赖。Race 选中首个结果后，取消并清理另一分支再返回。

`Executor::with_deadline(tokio::time::Instant)` 设置绝对单调截止时间。宿主在推进机器和
等待 I/O 时检查它；到期返回携带机器当前活动来源的 `Failure::Timeout`，并释放待完成调用。
这是立即停止，不能继续执行词法 `Finally`，请求所有者仍需结束进程并运行进程终结器。
同步 driver 和原生 Step 仍不能被抢占。

单独的 Executor Future 只拥有执行存储，不负责 Process 生命周期。
`Bootstrap::request_under` 返回拥有请求生命周期的 `RequestProcess`：通过 `executor`
执行，再把完整 `ExecutionOutput` 交给 `finish(&output)`。进程终结保留 body 终态以及
各终结器结果的来源。独立任务可使用 `Arc<Bootstrap>` 上的 `request_under_owned`，
由同一个 `RequestProcess` 持有共享宿主，无需克隆宿主的内部字段。
Gateway 从创建请求起，经过票据准入、执行和终结一直保留该所有者；已接受的输入流跨调用传递它。
SDK 的图执行和普通 prepared 执行自动使用这一作用域。
丢弃未完成作用域会立即关闭请求树、取消执行、中止已附着任务并撤销现有句柄；
当前线程处于 Tokio runtime 内时，再调度一次异步进程清理。正常完成的请求不创建清理任务。
`Bootstrap::drain_cleanup` / `Xolotl::drain_cleanup` 等待待清理工作，包括 runtime 关闭
或后端失败留下的工作；返回失败的进程树供后续重试，不在内部无限重试。

正常完成只结束指定进程，已独立启动的 Actor 和异步结果任务可以继续。
显式关闭树会穿过已经完成的祖先处理所有后代，将没有既定终结结果的活进程取消，
并等待受管正文 Future 释放。正文或终结器等待自身退出会返回 `ProcessBusy`。
Actor 目录和异步结果使用保留在进程表中的终态发布对象，后端失败后结果仍可重试，
不会提前完成清理。

进程终结器与程序内的词法 `Finally` 分别管理。清理中断后，尚未开始的进程终结器仍被保留；
已尝试的终结器不会自动重放，中断会记为失败，因为外部效果可能未完成。
生命周期记录重试保留原始时间戳、终结结果和已撤销句柄数量。完成后，在进程表锁外释放
模块、附着 grant 和终结器存储。

丢弃执行 Future、强制中止 Tokio 任务、进程退出和 `finalize_process` 无法继续运行程序内的
异步 `Finally`。优雅退出应先取消、等待执行器结果，再结束请求进程；进程清理 I/O 仍需要宿主超时。
终态进程条目、状态标记和 Fact 仍然留存，完成清理不代表总内存有界，也不等于自动回收进程历史。

托管进程存储可以单独限制容量：

```rust,ignore
use std::num::NonZeroUsize;
use xolotl_sdk::{DoNode, IdentityRef, Value, XolotlBuilder};

let host = XolotlBuilder::new()
    .with_process_capacity(NonZeroUsize::new(64).ok_or("invalid capacity")?)
    .build_bootstrap();
let request = host.request_under(host.root, IdentityRef::ROOT, &[])?;
let output = request.executor().eval(&DoNode::pure(Value::null())).await;
request.finish(&output).await?;
let reaped = host.kernel.processes.reap_finalized(16);
```

根进程占一个条目。容量不足时拒绝准入，终态记录与失败清理也占容量，不进行隐式驱逐。
只有终结提交完成、任务和终结器所有者均已退出的叶子才可回收；祖先只要仍有子进程就会保留。
同一批次可继续回收新满足条件的父进程，总数不超过请求上限。`set_capacity` 在共享表间
调整上限，但拒绝低于当前条目数的设置。容器容量保留供复用，条目数量上限不等于字节或 RSS
上限；回收不会删除 Fact、状态标记、异步输出或检查点，存储留存与值载荷仍需独立预算。

进程编号持续递增，耗尽时返回错误。首次实际回收会关闭该表的旧检查点导入，避免通过
保留的 Executor 或请求作用域重新取得旧进程权限。这个限制仍适用于任意快照导入；
`checkpoint_recovery()` 从当前存储行取得并持续持有独占租约，可以在同一 Kernel 中继续
恢复尚未退休的检查点。空队列回收和零批次不会关闭任意快照导入。

## 有界 Fact 读取

自动核对不再一次性物化全部 Fact 历史。宿主可以独立于执行容量与进程容量，选择更小的读取预算：

```rust,ignore
use std::num::NonZeroUsize;
use xolotl_sdk::RecoveryLimits;

let report = host.recover_all_with_limits(RecoveryLimits {
    page_limit: NonZeroUsize::new(32).ok_or("invalid record budget")?,
    max_encoded_bytes: NonZeroUsize::new(64 * 1024).ok_or("invalid byte budget")?,
}).await?;
```

默认每页 256 条、1 MiB JSON 编码输入。隔离条目逐条持久化，下一次读取前释放上一页，
页间让出执行权。发生错误时保留此前已写入的隔离记录并向调用方报错；单条记录超过字节
预算时，需要显式调大预算，不截断、不跳过。

自定义存储适配器实现 `FactStore::scan(FactQuery)` 和按身份索引的 `lookup(FactLookup)`。
点查在同一存储视图内筛选当前调用进程再检查字节，区分操作不存在和调用进程不匹配。
`get_bounded` 是不筛选进程的有界便利读取。分页查询选择正向或反向追加顺序，独立限制返回条数、
候选检查数和编码字节数。`FactQuery::new` 默认正向，候选预算等于条数上限。
内存把不匹配进程的槽位计入候选预算，有索引的后端可以避免访问这些槽位。因此空的过滤
页面仍可能有续页；候选预算约束访问次数，不约束单个值的处理耗时。

诊断调用方可使用 `FactSink::scan`、进程过滤，再对每页调用 `classify_recovery`。
用 `query.next_page(&page)` 续页直到返回 `None`，两个方向都保留全部过滤条件和预算。
每页 `end` 是该页捕获的上界，反向续页会逐步缩小。分页排除后续追加，但旧槽位的完成
结果仍可能更新。需要稳定的恢复结果时先暂停写入；订阅发生 lag 后，必须重新检查旧槽位及新增记录。

字节限额对 redb 统计已存 JSON，对内存统计当前 JSON 序列化长度。它不计量解码后的堆
大小、隔离输出、后端缓存或总 RSS。`get`、`all_facts`、`facts_of` 和 `recover_process`
保留为显式无界便利读取。Fact 留存与检查点目录扫描是独立机制；未完成检查点可能仍依赖
已完成 Fact 核对外部效果或进程终结，因此不能自动驱逐这些记录。

## 可选持久化

设置 `Program::durable = true`，通过 Kernel 或 SDK builder 接入 `CheckpointStore`。
不支持的宿主拒绝执行。日志提供进程独占租约，在分派和完成边界原子保存指令、任务、栈、
绑定、执行作用域、待处理调用 ticket、生命周期作用域、权限和预算；redb 使用立即持久化提交。
Fact 分类提供诊断，恢复执行需要完整机器检查点。

`OperationId` 包含五个坐标。首版 Fact 和宿主 journal 格式保留完整 Value 与来源，
包括清理或恢复帧持有的失败来源。每个 checkpoint 的常量、任务、帧、导入和绑定
共用一张节点表。未知格式直接拒绝，缺失 taint 不能补为 pristine，
也不能从历史推断缺失作用域。自定义 Fact 和检查点适配器还需实现
`ExecutionIdSource`；通过 `with_execution_ids` 可以独立于二者保留共同来源。
只要仍有检查点或对外可见的身份，该来源就必须保留。装配约束见[执行身份](architecture.md#执行身份)。

中断后不重复已完成效果。待处理请求只有在重放约定允许时才能继续；待处理非幂等效果或变化的
重放类别会进入隔离状态，等待核对。检查点不能对任意外部服务提供“恰好一次”保证。

持久程序可以加载 portable 模块。检查点保存实际代码、模块身份、重定位后的指令/导入/绑定范围，
以及活跃延续。恢复时校验模块边界，再重建空洞分配表和资源分析；分析临时存储只与最大模块有关。
即使调用者重新传入原始根程序，执行也使用检查点内实际链接的镜像。退出的模块释放其导入和绑定，
累计加载次数不会变成常驻容量限制。

持久化准入将加载器名称和 revision 固定到当前导入表；加载参数和挂起输入进入同一份 Value 表。
宿主负责重新提供闭包：直接恢复使用 `Executor::with_steps`，自动恢复使用
`checkpoint_recovery()?.with_steps(module)`。`ExecutionSnapshot::loader_dependencies()`
可以读取所需声明。加载器缺失或 revision 改变时，在调用加载器前拒绝恢复并保留原日志。
加载结果及其延续提交前中断，可以用原输入和参数重新加载；提交后直接恢复已保存代码，不再调用其加载器。
要求持久化的模块只能进入持久调用方。原生 Step 仍可用于非持久执行，持久化准入会拒绝它。
幂等缓存用于复用已完成结果，并发重试仍依赖方法声明的幂等性；缓存失败不能改写已知驱动结果。
如果驱动仍在执行时达到显式 `Collect` 上限，收集被取消，Fact 保持 pending，保留不确定费用，
不发布已完成的缓存条目。

恢复预算包含待处理调用的费用估计。无法核对之前预留记录时，不确定调用可能被重复计入预算；
不会仅因执行 Future 消失就自动退还费用。

当前启动适配器支持 root 直接持有、仅使用附着 grant、无原生终结器和 Actor 目录的请求进程。
准入拒绝其他上下文及分离的 `AsyncProcess` / 原始 `Stream` 输出；可使用拥有结果的 unary、
有界 collect 或 sink-only 模式。恢复重新检查授权约束、权限位和有效期。缺少 Provider
导入时保留检查点，安装完成后可再次调用恢复入口。

启动应用工作前调用 `reserve_checkpoint_process_ids`，通过持久化的进程编号高水位预留身份，
不解码程序。安装权限与 Provider 后创建 `Arc<Bootstrap>::checkpoint_recovery()` 会话，
从宿主后台循环调用 `advance()`。`resume_checkpointed_processes` 是单次有界推进的便利入口，
返回 `complete` 只表示本次固定编号区间已扫描完，不表示已调度的任务都执行结束。
daemon 使用后台会话推进，等待外部信号的程序不会阻塞网关启动。

`DurableRecoveryConfig` 默认每页 64 条目录记录、同一 Kernel 最多 16 个恢复任务、
`reap_batch = 0`。多个会话共享并发限额，取得容量和日志租约之后才加载检查点，租约直接
转移给执行器并持续到生命周期收尾。容量不足报告 `deferred`，会话保留当前游标，
不将容量问题视为隔离。小容量宿主可显式设置 `reap_batch`，或自行调用进程回收策略。
被隔离的低编号记录留在存储中，修复后新建会话可再次扫描，不在内存中累积待重试编号集合。

`ExecutionConfig::max_checkpoint_bytes` 默认 64 MiB，同时限制序列化写入与解码前的记录大小。
目录 `scan(CheckpointQuery)` 只读取键和编码长度；实际加载必须重新检查长度以及键与载荷
所有者是否一致。恢复还在进程准入前借用检查点验证核心布局、终态和待完成 ticket。
编码字节上限不等于解码后堆上限，载荷对象、解释器存储和驱动仍有各自的内存成本。
`CheckpointStore::snapshots()` 仅保留为显式全量检查接口，恢复链路不调用它。

生命周期按 Fact、终态标记和结果发布、检查点 `retire`、进程清理完成的顺序提交。
任一步失败都保留收尾状态并禁止回收。退休删除 active 行，但永久保留进程编号高水位，
同一租约不能再次提交。已提交的合法终结 Fact 可以直接驱动清理，包括显式取消留下的
未完成机器状态；这一路径不再要求原 Provider 可用，也不重放待完成效果。
检查点还保存已选择的 `terminal_intent`；待恢复的 `Finalizing` 记录需要从该意图、终结 Fact
或当前进程已经选定的结果中确定终态。没有任何明确来源时会隔离，
不会猜测它最终应当成功、失败还是取消。
直接导入的快照不能在缺少日志时创建新执行，旧 Executor 不能重建已退休的程序。

一个进程编号命名空间目前要求单个活动宿主拥有，应用准入前必须预留高水位。
每进程租约不能解决多个独立 Kernel 同时分配新 `ProcessId` 的碰撞；多宿主需要额外的
进程身份分配协议。固定目录上界只固定键区间，覆盖写可读到新版本，游标之前的晚插入
记录在下一轮出现，不能将一次会话视为全库快照。

SDK 的持久化执行通过 `RequestProcess::detach` 把请求所有权交给恢复路径。丢弃执行 Future
会释放日志租约并保留未完成检查点，不排队取消请求。使用 `detach` 的宿主必须负责最终结束进程，
检查点恢复需要显式调用。未结束和隔离的检查点、Fact 与状态历史仍需宿主留存策略；
Actor 树及外部流 session 的恢复尚未实现。

## 验证与测量

```sh
cargo check -p xolotl-sdk --no-default-features --target thumbv7em-none-eabi --lib
cargo check -p xolotl-sdk --features serde --target thumbv7em-none-eabi --lib
cargo bench -p xolotl-kernel --features host --bench kernel_hot_paths -- process_reaping
cargo tree -p xolotl-sdk --no-default-features --edges normal
cargo run -p xolotl-core --release --example core_footprint
cargo bench -p xolotl-kernel --features host --bench kernel_hot_paths -- kernel/prepared
cargo bench -p xolotl-kernel --features host --bench kernel_hot_paths -- kernel/payload
cargo bench -p xolotl-kernel --features host --bench kernel_hot_paths -- kernel/native
```

目标检查前需通过 rustup 安装 Cortex-M target。`core_footprint` 示例统计标量存储和每 1,000 次操作
的批次均值，包含准入与存储重置；其中 p99 是批次均值的分位数，不是单请求尾延迟。
prepared 基准包含宿主执行存储分配与调度器入口，不包含编译、请求进程创建、I/O 和推理。
比较性能时应保持工作负载、feature、构建配置和硬件一致。

`benchmarks/runtime` 测量控制流、驻留值、portable 与托管执行、流取消、文件对象、
State/Fact 恢复及 Provider 解析。运行器将计时与堆统计分开，校验输出和资源释放，
并在固定活动窗口下增加累计工作量。在仓库根目录运行：

```sh
python3 benchmarks/runtime/measure.py build --output target/runtime-measurements
python3 benchmarks/runtime/measure.py smoke time heap scaling --output target/runtime-measurements
```

工作负载参数、环境记录和测量范围见 `benchmarks/runtime/README.md`。堆报告统计
夹具初始化和预热之后的分配，不代表进程 RSS 或设备内存；计时包含完整工作负载、
结果校验及其持有资源的释放。
