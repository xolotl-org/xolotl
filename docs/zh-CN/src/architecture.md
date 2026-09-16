# 架构

Xolotl 让执行热路径保持很小：

```text
进程持有句柄，
对资源方法发起操作，
通过驱动计划执行，
遵守策略快照，
产出结果和事实记录。
```

托管运行时分成四类代码路径。下层的 `xolotl-core` 只负责结构化控制流、定长存储和宿主请求，
不依赖托管值模型、Tokio、注册表、存储或 Provider。

后续页面按这条主线展开：概念页面解释进程、资源、能力、操作、事实记录和重放；网关页面解释外部客户端如何进入运行时；配置页面解释宿主如何开放监听器、feature 和运行时声明。

## 控制路径

控制路径负责解析、校验、名称解析和编译。它拥有注册表、资源命名、准入检查、策略编译、绑定解析，以及 `open()` 句柄编译。

关键规则是：路径解析和注册表遍历发生在执行之前。进程拥有句柄之后，执行路径就可以只依赖已编译的 ID、权限位图、驱动计划和策略快照。

## 数据路径

数据路径通过已编译的句柄执行一个操作。它检查所有者、句柄存活状态、权限、必要时的剩余策略，随后分派驱动计划，并在操作需要持久记录时写入事实记录。

打开句柄时生成的 `MethodContract` 固化方法权限、输出支持、重放类别、成本、批量调用和清理准入。
`Invocation` 同时绑定操作的所有者与 acting identity，直接调用和执行器调用共用这一边界。
`DriverOutput` 一并返回结果、来源信息和可选的实测用量。宿主原子地记账到所有者和保留的祖先账户；
异步进程适配只对实际子进程效果计费一次。调度窗口不限制任务累计处理的字节数或转换次数。

方法显式声明是否要求未受保护的输入，执行器不通过效果名称推断网络访问。
推理、检索和存储驱动为实际产生或读取的数据附加来源信息。数据路径使用已编译的 ID、权限位图、驱动计划和策略快照。

可选的 Provider 输入校验函数在 open 阶段固化，在表锁外、策略和记录之前执行；
拒绝时显式提供安全的审计输入投影，未经授权的输入不进入记录。清理权限也在打开句柄时编译；
绑定资源所有者的清理权限不会因句柄派生而转移给其他进程。

`kernel::runtime` 为 `no_std + alloc` 嵌入提供 `LinkedExecution`，其请求适配器、GAT 驱动和
账户端口与 Tokio 共用方法准入、值语义、预留所有权和 Fact 构造。编译产物通过
`CompiledProgram::with_provenance` 转移常量，不克隆载荷缓冲。时间、I/O 和唤醒由宿主提供。

## 外部适配

外部适配把外部系统投影到同一个运行时模型中。Provider 通过驱动或远端绑定暴露 `effect://...` 资源。Source 把入站事件写入声明的状态流。gRPC 和 WebSocket 是同一个 Provider/Source gateway 的两种传输实现。

## 程序执行

portable `Program` 文档与 Rust 表达式共用编译器，产出核心指令。`PreparedProgram`
共享不可变的宿主指令、常量和资源分析，可被多个执行借用。核心按控制流推导资源峰值，
编译器复用已退出作用域的绑定槽；程序大小不再直接决定每次执行的容器大小。现有 `DoNode` / `ExecutionGraph`
也转换为同一状态机；进程本地 Step 是可选原生扩展，运行时展开受容量限制。

核心推进控制流并返回请求；宿主解析导入、检查权限、驱动并发 I/O，并用 ticket 匹配完成事件。
取消、错误恢复和词法清理在核心中统一实现。Executor 内部按职责划分：`image` 负责转换，
`config` 限制准入，`buffers` 管理调用方可复用的分配，`machine` 驱动请求，可选 `durable` 提供检查点屏障。
核心的 `frame` 模块管理共享定长帧池，单任务栈深和总帧容量独立约束。执行结束后缓冲区释放值，
保留空闲容量由调用方决定，内核不维护隐式全局池。

原生扩展同样从推导出的准入布局开始。宿主分析新子程序，按活动调用的需求和字节预算预留增长空间，
再通过 `suspend` / `resume` 校验并交接存储，保留待完成请求的 ticket。
准入或预留失败时先撤销新增镜像片段，再进入错误恢复。核心继续使用调用方提供的存储，
搭配不分配的值实现时保持无堆分配。

`image::arena` 负责可加载程序片段的链接与生命周期。原生图 Step 和 portable 程序加载器
共用片段分析、重定位、准入和回收。片段使用稳定地址区间；延续返回后回收代码、导入和绑定值。
交错结束的片段也能复用空间，活动代码无需移动。源码位置保留模块内含义，调用 ticket 区分重复调用，
与存储地址复用无关。内核不会隐式缓存所有曾加载的模块。这个分配器只属于单次托管执行，无依赖核心仅提供活动延续查询
和显式绑定释放。碎片与保留容器容量的边界见核心与可移植程序指南。

值的所有权随执行转移：顺序节点和已完成分支直接交出结果；宿主可通过
`Values::retain_control` 精简错误恢复所需的来源信息，待完成请求仍保留完整输入以支持恢复。
核心不要求使用共享指针、分配器或托管 taint 表示。

检查点包含词法值、任务、延续栈、执行身份和动态调用 ticket。Fact 用于分类已完成及不确定的
效果，无法重建原生延续或并发调度。执行恢复使用完整 portable 检查点。
检查点还保存活动模块片段及其延续范围。程序加载器显式声明独立的 `LoaderRevision`；
恢复时重新连接宿主提供的 `StepModule`，校验加载器修订后使用已保存的程序镜像继续执行。
加载器缺失、修订变化或代码引用跨越模块边界时，拒绝恢复并保留日志。
易失原生闭包仍不参与持久化执行。
具体约定见[核心与可移植程序](core-and-portable.md)。

## 执行身份

每次独立求值分配一个 `ExecutionId`，核心请求的完整 64 位 ticket 作为 `InvocationId`，
`NodeId` 始终表示静态源码位置。`OperationId` 共 32 字节，包含进程、执行、调用、位置和
显式重试次数。同一位置的循环调用、并发调用、Actor body 和分别执行的终结器都有独立身份。
检查点恢复沿用原执行作用域和待完成 ticket；显式重试只递增 `attempt`，溢出时返回失败。

`ExecutionIds` 是可替换的宿主适配器，通过 `ExecutionIdSource` 预留编号区间。
共享缓存每批最多预留 256 个作用域，每次求值取一次缓存锁，单次操作无需再分配身份。
持久化适配器先提交编号高位，再发放区间；删除 Fact 或检查点不能撤销编号预留。
无依赖核心无需增加字段或依赖。

宿主装配时选择一个来源：显式 `with_execution_ids` 优先，其次是已配置的检查点适配器，
最后是 Fact 适配器。来源必须在运行前配置。同一身份命名空间中的所有宿主都要保留并共享
这个来源，即使它们使用不同的状态、Fact 或检查点后端。共享 Fact 却选择互不相关的编号
来源会发生冲突，这种组合需要显式指定共同分配器。同一 redb 数据库的适配器共享编号高位表；
独立留存的存储可共享 `RedbStore::execution_id_source()` 或其他宿主来源。
检查点必须在原身份命名空间中恢复，不能重新绑定到无关分配器。

普通请求的生命周期身份按需初始化，写入 Process 检查点，调用序号使用零。
Actor 在目录准入前预留独立作用域，目录以进程和执行作用域共同标识所有者。
终结标记路径包含作用域，避免本地 ProcessId 重用时误读旧标记。重启准入会读取已提交的
生命周期 Fact，保留原时间戳和撤销句柄数，继续完成失败的标记写入。恢复准入按该操作身份
直接索引查询，不受进程历史数量影响；普通执行无需扫描历史。

## 工作区映射

| Rust 包 | 职责 |
| --- | --- |
| `xolotl-core` | 无宿主依赖的 `no_std` 控制流、定长存储、能力链接和有界通道 |
| `xolotl-types` | 核心 ID、路径、值、能力、操作、审计、跟踪、外接和进程数据 |
| `xolotl-value-codec` | 可移植事件校验、可选键工作区与增量 CBOR 编码 |
| `xolotl-value-object` | 显式编码引用，以及通过可移植对象端口增量读、写和复制值 |
| `xolotl-graph` | portable Rust/JSON 编译器、`DoNode`、`ExecutionGraph` 和行为体检查 |
| `xolotl-state` | 独立的可移植 State 与对象能力、可选宿主装配和内存适配器 |
| `xolotl-kernel` | 可移植调用、作用域与流规则，以及可选托管分派、调度、注册表和恢复 |
| `xolotl-storage-redb` | 基于 redb 的状态和事实记录存储 |
| `xolotl-storage-fs` | 增量不可变对象、暂存上传、原子发布与可选文件键工作区 |
| `xolotl-standard` | 标准进程内 Provider 和 Source 实现 |
| `xolotl-gateway` | Profile、提交所有权、会话、来源、对象访问及输出披露 |
| `xolotl-gateway-grpc` | 应用及 External Provider/Source gRPC 适配器，可选结构化对象输出 |
| `xolotl-gateway-websocket` | External Provider/Source WebSocket 适配器 |
| `xolotl-gateway-mcp` | 把选定 Gateway publication kind 暴露为 MCP 对象的服务端适配器 |
| `xolotl-proto` | Protobuf 模式定义和随仓库提供的 Rust 绑定 |
| `xolotl-console` | Web 控制台管理动作的 gateway |
| `xolotl-daemon` | 长期运行的宿主进程 `xolotld` |
| `xolotl-sdk` | 最小进程内嵌入式内核门面 |
| `xolotl-plan` | 计划文档解析和转换 |
| `xolotl-sim` | 确定性仿真和重放辅助工具 |

## 嵌入式宿主

`xolotl-sdk` 默认只包含无需 allocator 的核心。启用 `host` 后提供内存宿主和 portable 程序 API。
`XolotlBuilder` 允许嵌入式宿主在构建 `Bootstrap`
前提供自己的状态后端和事实记录接收端。SDK 的 `standard` feature 提供标准包安装 API，
供包含标准进程内 Provider 的宿主使用。嵌入方仍可替换策略来源、driver 和宿主装配。

`ExecutionConfig` 保存在 Kernel 上，每个派生 Executor 都继承相同的存储和执行预算。
值载荷与驱动自身的内存使用需要另设上限。

执行存储与请求生命周期分别拥有。SDK 的普通执行入口使用 `RequestProcess`；单独的
Executor 可在宿主维护的权限上下文中复用。`bootstrap::request` 负责作用域丢弃和显式
清理入口，`bootstrap::finalize` 负责推进进程终结器并提交生命周期记录。进度保存在进程表中
按需分配的记录里，不依赖某个 Future 存活，因此任务取消或 runtime 关闭后仍能重试。
正常完成的请求不创建后台清理任务。请求、Actor 和异步操作共用进程表的原子子进程准入，
检查点恢复也在插入时复核父进程。关闭树时先标记全部后代，再中止并等待正文任务退出。
`process::task` 管理任务的启动门、正文所有权和退出通知；任务在登记前不能开始正文。
正文完成后先保存结果和终结意图，再交出所有权，外部终结器因此不会与仍存活的正文并行。
持久化恢复任务保留未完成检查点的恢复责任，运行时中断不会自动生成终结标记。
`process::retention` 负责进程容量与显式叶子回收。容量包含根进程、活进程、待清理进程和
保留终态；只有终结提交完成且任务与终结器所有权均已释放的叶子才能进入就绪队列。
回收以常数时间解除父子链接，并将新满足条件的父进程加入同一批次；不扫描无关进程，
不在表锁内运行用户析构。仍有独立活子进程的祖先保持可达，回收后的容器容量可继续复用。

`XolotlBuilder::with_process_capacity` 配置初始上限，`ProcessTable::set_capacity`
在共享宿主间调整上限且不隐式驱逐条目。宿主显式调用 `reap_finalized(limit)`，并处理
准入容量耗尽。首次实际回收后，同一进程表关闭旧检查点导入，避免旧执行器与作用域因
恢复同一 ProcessId 而重新取得权限；这个限制保留在任意快照导入入口。当前存储行的租约恢复
另有私有准入路径，允许退休和回收之后继续处理积压记录。进程编号耗尽返回错误，
不会回绕。对同一 Kernel 的克隆反复 Bootstrap 装配会共享唯一根进程及其授权；
请求创建前的网关审计 Fact 归属该根进程，各自具有独立执行身份。
检查点在生命周期提交完成后退休删除，持久化进程编号高水位不随删除降低。
状态标记、Fact 和未结束检查点仍需独立留存策略，进程条目上限不能约束这些载荷或宿主总内存。
Fact 核对直接读取保留记录，不依赖进程表枚举；已回收或尚未恢复的进程仍可发现未决外部效果。

`bootstrap::actor` 负责声明检查与目录准入，`dataplane::async_process` 负责异步结果适配。
两者通过同一个 `ProcessPublication` 接口发布终态；结果与发布对象保留在进程表，
与生命周期 Fact、标记一起提交成功后才释放。单进程完成与整树关闭分别保留重试范围，
重试不会扩大取消范围。提交路径只需要进程表、句柄、Fact 和状态后端，
数据路径无需持有整个 Kernel。目录更新校验进程和执行作用域后使用 CAS；被取消的准入
可以保留终态占位记录，阻止后端迟到的初始 CAS 将目录重新写为 running。
异步结果路径包含进程和执行作用域，启动状态使用 CAS，避免重启复用编号或迟到写入覆盖终态。

正常完成只结束指定进程，已独立启动的 Actor 和异步结果任务可以继续运行。
显式关闭树则包含所有后代，即使祖先已经完成；无既定结果的活进程按取消处理。
正文或终结器请求等待自身退出时返回 `ProcessBusy`，宿主可先请求取消并让正文返回。

`ActorSpec` 是命名长寿 Process 的声明形态，包含可序列化的 `DoNode` body、声明能力、
预算和终结器。`Bootstrap::spawn_actor_under` 会检查 body 和终结器是否超出声明能力上限，
从父 Process 衰减出进程附着 grant，写入 `state://agents/<identity>/<name>`，并用普通
Executor 运行 body。body 如果使用进程本地 `StepRef`，宿主通过
`Bootstrap::spawn_actor_under_with_steps` 在执行开始前安装对应函数；终结器中的
`StepRef` 也必须在启动时提供。

原生步骤引用只携带名称与参数。宿主可以独立于进程创建组装已校验的 `StepModule`，
组合时检查重名，复用时共享不可变名称表与函数。每个进程持有供 body 和终结器使用的
模块，派生执行器直接从模块快照借用函数，无需读取全局 Step 注册表。空模块不分配内存，
独立执行器与普通请求也接受同一种模块。进程清理在进程表锁外释放模块，保留的旧执行器
会在进程终结后停止执行。

动态返回的子图会原地将结构化的 `state://process/self/...` 路径绑定到调用进程。
请求授权模板在权限衰减前绑定对应占位符，共享代码不会共享请求权限。

## 持久化进程的职责边界

检查点恢复涉及存储、执行和进程生命周期，每类规则由一个明确的模块负责：

| 模块 | 职责 |
| --- | --- |
| `process/checkpoint.rs` | 进程快照、日志生命周期状态、恢复准入与终态合并 |
| `process/retention.rs` | 进程容量、父子链接与显式回收 |
| `executor/durable.rs` | 机器快照、检查点存储契约与执行提交屏障 |
| `bootstrap/durable.rs` | 解码已提交的生命周期 Fact，检查当前请求权限 |
| `bootstrap/durable/recovery.rs` | 推进有界元数据分页，管理共享恢复容量 |
| `bootstrap/durable/recovery/admission.rs` | 校验机器执行条件，将程序、日志租约和容量转交给任务 |
| `bootstrap/finalize.rs` | 提交生命周期副作用，退役检查点后再完成进程清理 |
| `xolotl-storage-redb/src/checkpoint.rs` | 实现独占租约、有界存储读写和持久退役 |

进程准入明确返回 `Ready` 或 `Cleanup(status)`。快照终态、已保存的 intent、
已提交的 Fact 和当前进程已经选定的结果，存在时必须一致。旧的 Running 快照可以
接续已确定的清理；无法从任何来源确定结果的 Finalizing 快照保留等待核对。

进程表先计算不修改状态的准入计划，再在同一次写锁内应用。所有拒绝路径都发生在
修改进程状态、清理进度、预算、身份或父子链接之前。宿主可以在检查机器导入前预检，
但正式准入总会重新计算，以处理期间发生的取消或任务所有权变化。
持久化进程测试与实现相邻，位于 `process/checkpoint/tests.rs`。

## 存储契约

`FactStore` 必须实现有界的 `scan(FactQuery)` 和按操作身份索引的 `lookup(FactLookup)`。
分页请求独立限制返回条数、候选检查数和
JSON 字节数，支持正向或反向追加顺序、调用进程过滤，并从同一存储视图取得排他上界。
`query.next_page(&page)` 保留过滤条件和预算，推进对应的区间边界。空的过滤结果仍可能
存在续页，只有 `next = None` 表示结束。候选上限约束检查次数，不限制单个值的检查或
序列化耗时。

`FactLookup` 包含操作身份、可选当前调用进程和编码字节预算。适配器在同一存储视图内
定位并筛选，之后才复制或解码，返回 `Found`、`Missing` 或 `FilteredOut`。
无关进程的超大记录不会消耗所选进程的读取预算，记录丢失仍可单独识别。
`get_bounded` 和 `get` 是不限制进程的便利入口。

完成结果会更新旧槽位，固定追加区间并不冻结结果版本。订阅事件作为失效提示，收到后
重读当前操作；发生 lag 后重新扫描整个保留区间。Console 会关闭已 lag 的审计订阅，
由客户端重新核对并订阅。`all_facts`、`facts_of` 和单记录 `get` 是显式便利读取，不提供字节上限。

自动核对逐页处理，隔离条目逐条持久化。`RecoveryLimits` 默认每页 256 条、1 MiB 编码输入。
单条超限或后端失败会停止恢复，此前写入的隔离记录保留，不静默跳过证据。需要稳定分类时，
宿主应先暂停 Fact 写入。这些读取限额不约束历史留存、隔离存储或解码后的实际堆大小。
内存实现使用有界计数 writer 测量 JSON，redb 在解码前检查已存编码的字节长度。

Fact 读取按所属层组织职责：

| 模块 | 职责 |
| --- | --- |
| `xolotl-kernel/src/fact/scan.rs` | 查询与页面契约、适配器校验、有界内存遍历 |
| `xolotl-kernel/src/fact/lookup.rs` | 按当前进程筛选的点查契约、结果状态和适配器结果校验 |
| `xolotl-storage-redb/src/fact/read.rs` | 事务内双向读取、进程索引和有界索引点查 |
| `xolotl-standard/src/fact/read.rs` | 标准 Provider 共用的输入解析和审计页面投影 |
| `xolotl-console/src/ws/facts.rs` | Console 读取策略、投影、健康采样统计和按进程筛选的实时重读 |

Console 分发层保留授权和审计记录职责，查询契约不依赖管理协议。进程检查只在显式指定
进程并请求 Fact 时读取历史，避免枚举进程放大 Fact 预算。Console 的 recent/trace 返回
续页信息，health 聚合明确标为有界样本，不代表全部历史统计。

`InMemoryBackend::with_options(InMemoryOptions)` 在构造时独立选择 `read_shards`、
`history` 和 `notification_capacity`。默认使用一个内联 map，不分配分片数组；增加分片数会
分配带填充的 map 锁，点读只锁定对应分片。两种布局共用同一提交实现。分片写入先取得
journal 锁，再取得值分片锁；前缀读取在遍历所有分片期间持有 journal 读锁，取得一致快照。
所有写入仍然串行，大型前缀或历史读取可能延迟写入。被替换的值在所有 guard 释放后销毁，
构造过程不启动后台任务。

默认的 `MemoryHistory::Full` 保留全部变更，值、来源信息、时间戳与历史原子提交。
`MemoryHistory::Disabled` 跳过历史存储和时间戳计算，保留当前值、来源信息与通知。
历史时点的 `read_at` 和 `read_range` 返回 `Unsupported`；`read_at(path, 0)` 仍读取当前值。
这些选项在构造时固定，不提供滚动历史留存。两种模式都不限制当前值数量或载荷大小。

通知按提交顺序在所有锁外发送。待发送队列满时，在提交前拒绝匹配订阅的写入；慢广播接收者
仍可能报告 lag。没有订阅者就不分配通知存储，队列容量按事件数计算，不按字节计算。
`with_options` 和 `with_notification_capacity` 返回 `StateResult<InMemoryBackend>`，
不支持的通知容量与分片预留失败会返回错误。这些检查不保证后续值或订阅分配失败都能恢复。

redb 在同一写事务内完成 merge，并在该事务中
更新持久化的历史时钟，重启或墙钟回退不会使新提交的历史倒序。已有存储必须包含
这份元数据；schema 不完整时拒绝打开，不从历史重建时钟。事务失败会同时回滚值、历史与时钟。
两种实现的 merge 均保留已有来源信息，未实现原子 merge 的适配器由 trait 默认返回 `Unsupported`。
通知不是持久事件日志，redb 不保证并发写者之间的全局发送顺序；已提交顺序应读取状态历史。

## Console 宿主边界

Console 传输策略独立于内核的存储和执行契约。共享的 `xolotl-proto/src/encode.rs`
在无分配的 Value 准入检查后调用唯一的规范转换器，约束节点、嵌套和内联元数据，
不维护第二份 protobuf 映射。`xolotl-console/src/wire/encode.rs` 负责帧字段转换、
类型化路径和最终 protobuf 精确字节检查；`ws/outbound.rs` 负责发送期限，以及动作
结果超过线缆预算时保留请求 ID 的错误回复。

`ws/subscriptions.rs` 统一持有 State 和 Fact 任务，负责取消、可见性期限、代次、
完成处理，以及同时受条数和编码字节约束的队列。worker 先准备有界帧，再尝试入队，
队列满时退出。任务完成不依赖队列空间，完成会使该代订阅尚未发送的尾部失效。
管理器被销毁时中止所属任务，不主动分离 worker。分发层保留授权和审计职责；
重新认证或权限变化使之前的订阅失效。

这些限制约束转换工作量和保留的事件编码字节，不约束动作或广播后端已经物化的原生
Value、转换临时结构、传输缓冲区、存储历史和总 RSS。可移植核心和最小 SDK 不因此
引入 Console、protobuf 或 Tokio 依赖。

## 尚需完善的架构边界

- 状态标记、Fact 和未结束检查点仍需显式有界留存。检查点恢复已有分页、读写字节上限
  和共享并发准入，生命周期完成后删除活动记录。进程容量与回收约束条目数量，值载荷、
  状态历史、句柄和驱动分配仍需分别设置宿主限制。
- 进程及子进程枚举、状态前缀列表等管理集合仍会物化所选记录。Fact 分页不约束这些
  独立 API 的结果数量或遍历工作量。
- 内存历史目前支持完整留存或禁用历史读取。有界历史若要提供正确的历史查询，仍需定义
  覆盖范围与重建基线；分片读取不提供留存上限。
- 原生片段分配可以复用稳定地址区间并合并相邻空闲区间，但不能搬移活动片段。
  碎片化仍可能导致空闲总量足够、单次大分配却失败。

## 标准包 feature 选择

`xolotl-standard` 包含标准进程内 Provider 和 Source 实现。某个二进制不需要全部实现时，可以
用 Cargo feature 减少编译进来的模块。代码编译进二进制和资源被安装到运行时是两件事。

`fetch`、`fs` 和 `terminal` 这类高风险进程内实现必须留在独立的 `xolotl-standard`
feature 后面。daemon 或嵌入式宿主只能通过 kernel state 声明和固定 Console action
暴露它们。运行时进程内 projection 声明存储在 Xolotl state 中。

可选进程内 projection 声明属于运行时状态，路径为
`state://kernel/projections/in-process/<id>`。它们通过泛用 `config.*`
Console action、共享 kernel state 准入和宿主侧 reconcile 转换为普通
Resource、Interface、Driver 和 Binding 注册项。reconcile 结果写在
`state://kernel/projection-status/in-process/<id>`，通过
`projection.in_process.status.*` 读取。

部署时的 feature 选择和运行时声明路径见[配置](configuration.md)。HTTP 模型
Provider 的 dialect 见 [HTTP 推理 Provider](http-inference-providers.md)。嵌入式 API
入口见 [API 参考](api-reference.md)。
