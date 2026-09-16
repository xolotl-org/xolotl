# 状态与事实记录

Xolotl 把可变状态和事实流分开。

## 状态路径

`state://` 路径由 `xolotl-state` 中可独立组合的 `StateRead`、`StateWrite`、
`StateQuery`、`StateHistory`、`StateWatch` 和 `StateFlush` 能力服务。契约使用关联
Future，不要求 `Send`、共享所有权或特定调度器；静态实现可以返回 `Ready`，不分配
Future。可选宿主 `Backend` 通过 `with_read`、`with_write` 等方法仅装配所需能力，
调用未安装的能力返回 `MissingCapability`。

标准状态驱动暴露 `read`、`write`、`append`、`delete`、`list` 和 `compare_set` 操作。
`write` 始终原样保存输入，包括含 `cas` 或 `value` 字段的 map。
`compare_set` 接受必填 `value` 和可选 `expected`：缺少 `expected` 表示要求路径不存在；
显式 `expected: null` 表示匹配已存储的 null。未知选项会报错。

底层 `StateWrite` 能力还通过 `StateMutation::CompareDelete` 和
`write_compare_delete` 提供原子条件删除。比较当前值和删除在同一次后端提交中完成，
不要求安装 `StateRead`。`None` 匹配路径不存在并原样成功；`Some(Value::null())`
匹配已存储的 null。比较失败返回 `CasFailed`，不改变值、来源信息、历史或通知。
Gateway 用它释放带唯一标识的幂等预留，延迟到达的旧释放不能删除替代预留，
成功释放后不保留当前记录。变更历史仍遵循后端选择的留存策略。

因为状态访问走操作路径，能力检查、剩余策略、污点传播和审计会像其它效果一样应用到状态读写。

订阅通过事件总线门面 `effect://events/subscribe` 暴露，执行器的 `Wait(Signal)`
也使用状态订阅。契约提供轮询接口，明确报告事件丢失和关闭；Tokio receiver 仅存在于
可选的 `host/broadcast.rs` 适配器。信号等待先建立订阅，再读取当前值。
内存和 redb 共用 `host/watch.rs`：首次订阅时分配登记存储，订阅对象的 RAII guard
在销毁时立即移除登记。后端销毁会关闭其余订阅，订阅不通过强引用延长后端寿命，
也不创建后台任务。

流模式的 `effect://events/subscribe` 默认持续到取消、源关闭或匹配主题被删除。
可选的非负 `max_events` 是显式停止条件，零表示建立订阅前结束。
成功终值是完整的十进制已交付计数字符串；删除不产生数据块。
计数和后续失败保留已观察的全部主题来源，数据块携带自身事件的来源。
发布会追加到主题的已存储序列，持久化及留存成本与流信用窗口独立。

## 带污点的值

状态存储 `TaintedValue`：值加来源链。写入会把输入污点带入后端存储封套。读取会返回已存储的污点，因此受保护或低信任来源链会跨状态边界保留。

`TaintedValue` 统一定义在 `xolotl-types`，由 State 重新导出。历史读取同时回放值和
污点，追加列表会合并各项来源。记忆驱动在回忆、整合、恢复索引时保留存量来源信息，
并在调用远程 embedding 后端之前检查受保护数据。

`StateResult<T>` 的失败类型是 `StateFailure { error: StateError, taint: TaintSet }`。
后端在执行比较、部分扫描、记录解码的同一次锁或事务内捕获已观察来源。
调用方拒绝操作或返回降级结果时都必须保留这些来源，不能通过失败后重读路径恢复首次观察。
比较错误的诊断文本不打印已存储值；显式读取错误的结构化字段仍属于数据访问，
其来源由失败封套承载。

成功变更从同一原子边界返回 `StateCommit { taint }`。Compare-set 将当前与传入来源的
并集写入新记录，即使另一写入者只更改了相同值的来源，也不会丢失新增标签。
Append 和 Merge 保留参与数据的来源；条件删除通过回执返回已观察来源。
无条件 Set 明确替换存储来源，其回执仍描述后端实际进行的观察。
状态通知也保留该次提交的观察来源，包括 Append 和 Delete。
只包含删除事件的历史窗口仍带有其来源，不依赖更早的 Set 事件来补全。

## 状态分页

`StateScan` 和 `StateHistoryQuery` 分别约束每页返回条数、检查的候选数和编码字节数，
预算必须非零，默认值为 256 条、4,096 个候选和 1 MiB。
`StatePager` 和 `StateHistoryPager` 持有续页位置，调用方处理一页后再请求下一页。
每页视图一致，后续页面观察当时的实时状态；排序与不透明字节游标由后端定义，
游标只能用于原后端的相同查询。

空页仍可能包含 `next`；必须继续到 `next` 缺失，包括恰好在最后一条记录达到预算时。
单行超出字节预算返回包含 `StateError::RowTooLarge` 的 `StateFailure`，携带路径、所需编码大小、重试游标
和显式跳过后的续页游标，后端不会静默遗漏记录。redb 在解码前检查原始键与记录长度，
内存实现先统计借用值的无损编码大小，再克隆匹配值。

标准 `list` 接受 null 或包含 `cursor`（字节）、`limit`、`max_examined`、
`max_encoded_bytes` 的选项 map，返回 `entries`、`next`、`examined`、`encoded_bytes`。
每条记录包含 `path` 和 `value`，输出污点覆盖本页观察到的记录，也包括检查后留待下一页的行。
`StatePage::taint` 和 `StateHistoryPage::taint` 保留影响游标和字节计数的来源。

历史时间范围使用半开区间 `[from_millis, to_millis)`，反向区间会报错。
`read_at(path, 0)` 读取当前值，其他时间戳回放该时刻的历史值；这项便利方法可能遍历
路径的完整历史，需要显式工作预算时使用历史分页。分页预算不限制历史留存、单个解码值
或应用总工作量，收集全部页面的应用自行承担结果内存。

## 事实记录

事实记录是操作尝试的只追加记录。恢复、审计投影、跟踪投影、计费投影和不满足原因解释都从这些记录构建。

热路径通过存储引用和轻量标签保持事实记录紧凑。大内容用 blob、tensor 或帧引用表示。

## 有界读取

`FactQuery` 定义追加区间 `[from, before)`、可选调用进程筛选、
`FactOrder::{Forward, Reverse}`，以及独立的 `limit`、`max_examined` 和
`max_encoded_bytes` 预算。`FactQuery::new` 默认正向，候选检查预算等于返回条数上限。
`FactSink::scan` 会先校验适配器返回的边界和计数，再把页面交给调用方。

通过 `query.next_page(&page)` 保留方向、筛选条件和预算继续读取。
`page.next = None` 才表示区间结束。空 `facts` 数组仍可能有续页：内存扫描会把不匹配的
槽位计入 `max_examined`，有索引的适配器可以跳过无关进程。因剩余字节不足而拒绝的
候选也计入检查数，但保留为未读；若它是第一个匹配记录，读取返回错误。
`lookup(FactLookup)` 按索引定位后，在同一存储视图内先筛选当前调用进程，再检查字节预算
并复制或解码。结果区分 `Found`、`Missing` 和 `FilteredOut`，匹配记录超限会报错。
`get_bounded(id, bytes)` 是不筛选进程的便利包装。

正向续页把 `before` 固定为第一页的 `end`；反向续页将 `before` 缩小为 `next`，
保留原来的 `from`。每页的 `end` 描述该页捕获的区间上界。范围外的新追加不会进入续页，
但范围内仍可更新完成结果或调用进程归属。游标表示追加位置，不是时间戳、筛选后的行号
或可用于持久订阅重放的版本号。

标准 `state://fact` 或 `state://fact/<process>` 的 `read` 接受 `from`、`before`、
`order`、`limit`、`max_bytes` 和 `max_examined`，返回包含 `items`、`from`、`end`、
`next`、`order`、`complete`、`examined`、`encoded_bytes` 的对象。
游标和投影中的数值标识符输出为精确的十进制字符串，游标输入也接受非负整数。
默认返回 64 条、编码预算 256 KiB、检查 4,096 个候选；超过 256 条、256 KiB 或
65,536 个候选的预算，以及零预算和未知字段都会被拒绝。

```json
{"from":"0","before":"1200","order":"reverse","limit":32,"max_bytes":65536,"max_examined":256}
```

进程检查只在显式设置 `include_recent_facts=true` 且指定 `process` 时读取 Fact，
复用相同的查询解析和页面投影，默认反向读取 32 条。指定单进程可以避免枚举放大 Fact
预算。`recent_facts` 返回分页对象。
进程和子进程枚举仍有独立的留存成本。

这些预算约束返回的编码量和检查的候选数，不约束历史留存、解码堆、总 RSS 或耗时，
检查单个大值仍可能昂贵。精确的全历史分析需要显式分批处理或独立维护的投影，
单页计数不表示全局总量。`get`、`all_facts`、`facts_of` 和 `recover_process` 仍是
显式的无界诊断便利接口。

## 存储后端

State、历史、Fact 和程序常量共用显式节点表，保留字节、map、完整对象描述符、
流标记以及浮点原始位，格式统一按首个版本定义。缺少来源、节点表损坏或格式未知时
明确报错。存储只初始化空 schema，不回填缺失元数据，也不重新解释已有记录。

外部应用 schema 使用的普通 JSON 是另一种表示，持久值不能先经过无类型标记的 JSON 中转。
Fact 的 input 是完整 Value，成功 outcome 是可选 Value；decision 区分 pending 和
已失败、已拒绝调用，`Some(Value::null())` 表示成功返回 null。
Console 详情直接投影类型化值，保留完整张量和帧元数据。

`xolotl-state` 的可移植契约分别放在 `read.rs`、`write.rs`、`query.rs`、`history.rs`
和 `watch.rs`，宿主类型擦除位于 `host.rs`。关闭默认特性后使用 `no_std + alloc`；
`std` 只启用宿主组合，不引入 Tokio；`tokio` 启用广播适配；`memory` 启用内存实现。
`memory/storage.rs` 负责单锁或分片 map 的锁定与有界快照，当前值使用有序 map，
不额外维护全局索引。`MemoryHistory::Disabled` 只保留当前值和来源信息，
`Full` 保留全部变更历史，没有留存上限。

`InMemoryOptions` 独立选择读取分片、历史和通知容量。启用 SDK 的 `host` feature 后，
可通过后端注入接口组合这些选项：

```rust
use std::{num::NonZeroUsize, sync::Arc};
use xolotl_sdk::{InMemoryBackend, InMemoryOptions, MemoryHistory, XolotlBuilder};

let state = Arc::new(InMemoryBackend::with_options(InMemoryOptions {
    read_shards: NonZeroUsize::new(32).ok_or("zero read shards")?,
    history: MemoryHistory::Disabled,
    ..InMemoryOptions::default()
})?);
let host = XolotlBuilder::new().with_state_backend(state).build();
```

更多分片可以减少不同键之间的竞争，同时增加存储和锁定成本。禁用历史不限制当前值、
订阅者或宿主总内存。完整选项见 [API 参考](api-reference.md)。

`xolotl-storage-redb` 实现同一组能力，`state/read.rs` 负责事务分页，
`state/codec.rs` 负责无损存储编码。内存和 redb 实现通过 `into_backend()` 装配其
支持的宿主能力，自定义宿主可以只安装部分能力，也可以独立组合不同实现。
`FactStore` 适配器与可变 State 能力分开。

`xolotl.toml` 在引导时选择存储。控制台管理的运行时状态存在 Xolotl 状态中，不存在守护进程命令行中。
