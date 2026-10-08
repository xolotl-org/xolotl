# 状态与事实记录

Xolotl 把可变状态和事实流分开。

托管幂等调用保留缓存观察的来源，包括缺席。缓存 miss 的控制来源进入派发、派发前拒绝、结果和已选择的 Fact；需要非受保护输入的方法在派发前检查这些控制来源。缓存 hit 即使交付被撤销也保留缓存输出来源。流取消保留已取得的观察，未完成读取不证明来源；这些保证不依赖 Fact 记录。

## 状态路径

`state://` 路径由 `xolotl-state` 中可独立组合的 `StateRead`、`StateBoundedRead`、`StateWrite`、`StateBoundedWrite`、`StateQuery`、`StateHistory`、`StateWatch` 和 `StateFlush` 能力服务。契约使用关联 Future，不要求 `Send`、共享所有权或特定调度器；静态实现可以返回 `Ready`，不分配 Future。可选宿主 `Backend` 通过 `with_read`、`with_write` 等方法仅装配所需能力，调用未安装的能力返回 `MissingCapability`。

`StateRead::read_tainted(path)` 和 `StateBoundedRead::read_tainted_bounded(path, max_encoded_bytes)` 从一次一致当前视图返回 `StateObservation { value: Option<Value>, taint: TaintSet }`。`None` 表示带来源的缺席，`Some(Value::null())` 表示存在的 Null。Standard read 将缺席投影为 Null，但保留来源；`read` 是显式 value-only 投影。有界方法精确读取一条当前路径。宿主的 `Backend::read_bounded` 仅对可信元数据丢弃来源信息；缺少有界点读端口时不会退回无界 `StateRead` 或前缀查询。非零预算计量后端编码的键与记录，包含来源封套。redb Source sink 的物理记录为分项表示：`encoded_bytes` 计入路径和 marker，以及每项键值。物化逻辑 List 前即可判定字节大小；该预算不约束驻留 Value 的内存分配。

超额时返回类型化 `PointTooLarge`：redb 在解码载荷和来源前按原始行大小拒绝；内存后端对已驻留的借用值先计量，再克隆。redb 只观察大小时 `provenance_observed = false`，此时失败封套中的空污点表示来源未知，不能据此执行「无污点」降级。这项读取预算不限制已驻留内存、历史或后续条件变更。

`StateBoundedWrite` 独立提供 `compare_set_bounded` 和 `compare_delete_bounded`：两者在同一次原子提交中比较当前值，并在复制或解码超额现值之前按非零编码字节预算检查它。宿主须通过 `with_bounded_write` 显式安装；缺少该端口时不会退回普通 `StateWrite`。先前的有界点读不能约束随后被并发替换的现值。

redb 对超额现值返回 `PointTooLarge(provenance_observed = false)`，其来源未知；限内比较失败仍从同一次观察返回实际值与来源。这项写入预算只约束观察到的当前记录，不约束新值、历史或常驻堆。

删除也携带调用来源：`StateMutation::Delete(taint)`、`CompareDelete { expected, taint }` 和 `compare_delete_bounded(path, expected, taint, max_current_encoded_bytes)` 显式接收删除输入或控制来源。提交结果、失败以及实际 Delete 通知／历史保留它们与同域观察到的当前来源。`write_delete_tainted`、`write_compare_delete_tainted` 和 `write_compare_delete_tainted_bounded` 是带来源入口；不带 taint 的宿主 helper 明确提供 pristine 输入，标准 delete 方法不会使用它们丢弃 Operation 来源。当前缺席独立于历史保留删除来源，点读通过 `StateObservation::taint` 返回该来源。

若工作流依赖读写的关系，宿主还须把这些端口装配到一致的提交域。Console 认证的凭据 vault 与共享挑战账本依赖这一组合：各自的有界点读及条件 CAS 使用相同的编码行预算。只安装普通 State 读写端口的宿主不能执行这些认证操作。

标准状态驱动暴露 `read`、`write`、`append`、`delete`、`list` 和 `compare_set` 操作。`write` 始终原样保存输入，包括含 `cas` 或 `value` 字段的 map。`compare_set` 接受必填 `value` 和可选 `expected`：缺少 `expected` 表示要求路径不存在；显式 `expected: null` 表示匹配已存储的 null。未知选项会报错。

底层无界 `StateWrite` 能力还通过 `StateMutation::CompareDelete` 和 `write_compare_delete` 提供原子条件删除。比较当前值和删除在同一次后端提交中完成，不要求安装 `StateRead`。`None` 匹配路径不存在并原样成功；`Some(Value::null())` 匹配已存储的 null。比较失败返回 `CasFailed`，不改变值、来源信息、历史或通知。

Gateway 请求预留与保留结果由显式安装的 `GatewayIdempotencyStore` 拥有，不属于普通 State 或 State 历史。Gateway 对对象授权记录使用 State 条件删除，其来源与留存遵循 State 合同。见[应用 Gateway](application-gateway.md)。

标准状态驱动的 `compare_set` 使用这个普通写入能力；除非可信宿主明确改用独立有界端口，其当前行不受 `StateBoundedWrite` 的大小限制。

因为状态访问走操作路径，能力检查、剩余策略和污点传播会像其它效果一样应用到状态读写；Fact 观察由宿主选择。

订阅通过事件总线门面 `effect://events/subscribe` 暴露。标准 State 驱动的信号方法要求显式安装 `Backend::with_signal` 配对端口。该端口先在同一个提交域注册订阅，再读取当前值；分别安装的读与观察端口不会启用这一标准方法。Signal 等待当前存在值而非消费事件载荷：初始存在返回完整值，初始缺席建立来源 accumulator。每个精确路径通知先合入来源，再通过 `Backend::observe_signal_current` 从配对当前域重读；缺席继续等待，存在返回完整当前 Value，包括 Append 后的完整 List。lag 或关闭明确失败并保留累计来源；不回查历史、不新增持久等待。其他 `Wait(Signal)` 目标可提供自己的单次 `subscribe` 方法。

登记之后的写入要么出现在当前读取中，要么以该次提交的值和来源送达订阅；无法继续观察时必须明确报告 lag、失效或错误。观察端口提供轮询接口；Tokio receiver 仅存在于可选的 `host/broadcast.rs` 适配器。`StateFlush` 不自动建立跨端口一致性或持久性。

内存和 redb 共用 `host/watch.rs`：首次订阅时分配登记存储，订阅对象的 RAII guard 在销毁时立即移除登记。后端销毁会关闭其余订阅，订阅不通过强引用延长后端寿命，也不创建后台任务。同一 redb 存储创建的 State 适配器与 Source sink 共用发布协调器：订阅登记与提交串行，匹配通知按提交顺序排队。存储正在提交时，订阅者异步等待协调器。待交付和正在交付的通知共用 1024 项、8 MiB 的记账预算；费用是无须保留编码副本的 `StateEvent` 无损序列化字节数，加通知结构和发送端数组已分配槽位。序列化建立值图索引前，借用式预检还会在 262144 个独立节点、8192 层或 8 MiB 原始叶子与 map 键字节处停止，因此即使最终编码更短，也可能使订阅失效。单个事件若永远放不进预算，写入仍成功提交，并使匹配订阅失效；暂时的总量饱和在提交前拒绝写入。Source 的 `DropOldest` 发布携带实际移除数与新项的 `DropPrefixAppend` 事件，通知中的 List 载荷不随保留的 sink 增长；保守来源集合仍可能增长，超额事件仍会使订阅失效。观察者不需要 Source 容量声明即可重放。这些预算不限制订阅者广播缓冲区、精确常驻堆或总 RSS。若其他 worker 正在排空队列，写入结果可能先于通知返回，而持续写入可能延长排空者的返回时间。

流模式的 `effect://events/subscribe` 默认持续到取消、源关闭或匹配主题被删除。可选的非负 `max_events` 是显式停止条件，零表示建立订阅前结束。成功终值是完整的十进制已交付计数字符串；删除不产生数据块。计数和后续失败保留已观察的全部主题来源，数据块携带自身事件的来源。发布会追加到主题的已存储序列，持久化及留存成本与流信用窗口独立。

## 带污点的值

状态存储 `TaintedValue`：值加来源链。写入会把输入污点带入后端存储封套。读取会返回已存储的污点，因此受保护或低信任来源链会跨状态边界保留。

`TaintedValue` 统一定义在 `xolotl-types`，由 State 重新导出。历史读取同时回放值和污点，追加列表会合并各项来源。记忆驱动在回忆、整合、恢复索引时保留存量来源信息，并在调用远程 embedding 后端之前检查受保护数据。

`StateResult<T>` 的失败类型是 `StateFailure { error: StateError, taint: TaintSet }`。后端在执行比较、部分扫描、记录解码的同一次锁或事务内捕获已观察来源。调用方拒绝操作或返回降级结果时都必须保留这些来源，不能通过失败后重读路径恢复首次观察。比较错误的诊断文本不打印已存储值；显式读取错误的结构化字段仍属于数据访问，其来源由失败封套承载。

redb 写入返回 `StateError::CommitUncertain` 时，错误发生在提交阶段，变更可能已经持久化。宿主须停止使用共享该数据库实例的全部适配器，释放数据库使用者并重开数据库，再进行权威核对或决定是否重复 Append 或 Merge。恢复要求覆盖 State、Source、Facts、身份目录、执行 ID 存储以及已安装的 Gateway、Console 或 Federation 存储，而不只限于受影响的 State 路径。提交期间发生 panic 也需要恢复；只有 `redb::CommitError::TransactionPoisoned` 本身能确定事务已回滚。普通后端错误本身不证明变更是否提交，错误封套仍保留本次变更观察到的来源。参见 [RedbStore 恢复合同](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-storage-redb/src/lib.rs)。

同一 `RedbStore` 创建的适配器共享恢复拥有者。提交结论未知或提交期间 panic 后，实例进入必须重开的状态：跨存储域拒绝新的数据库事务、订阅和经检查提示值。`RedbStore::requires_reopen()` 暴露这一共享终止状态。此前接纳的快照与已确认的不可变执行 ID 预留仍有效，但旧值、缺席或来源不能证明未知变更已回滚。释放并重开实例后，再核对实际数据及适用的保留证据；隔离不回滚提交，也不恢复普通执行。

redb 提交结论未知会使共享实例的所有实时 State 订阅失效，并关闭 Fact 通知源，包括无关路径与适配器。单个已提交事件无法放进发布预算时，只使匹配的 State 订阅失效；此时普通重新读取／订阅可恢复尽力而为的观察，无须重开数据库。恢复唤醒在通知顺序锁释放后执行。存储提交结论未知时，先恢复数据库，再进行权威核对或重新订阅；通知不能充当提交回执。标准 State 驱动即使未观察到额外来源，也将未知写入结论作为 `kind = "state_commit_uncertain"` 的结构化失败返回。

成功变更从同一原子边界返回 `StateCommit { taint }`。Compare-set 将当前与传入来源的并集写入新记录，即使另一写入者只更改了相同值的来源，也不会丢失新增标签。Append 和 Merge 保留参与数据的来源；条件删除通过回执返回已观察来源。无条件 Set 明确替换存储来源，其回执仍描述后端实际进行的观察。状态通知也保留该次提交的观察来源，包括 Append 和 Delete。只包含删除事件的历史窗口仍带有其来源，不依赖更早的 Set 事件来补全。

## 状态分页

`StateScan` 和 `StateHistoryQuery` 分别约束每页返回条数、检查的候选数和编码字节数，预算必须非零，默认值为 256 条、4,096 个候选和 1 MiB。`StatePager` 和 `StateHistoryPager` 持有续页位置，调用方处理一页后再请求下一页。每页视图一致，后续页面观察当时的实时状态；排序与不透明字节游标由后端定义，游标只能用于原后端的相同查询。

空页仍可能包含 `next`；必须继续到 `next` 缺失，包括恰好在最后一条记录达到预算时。任一预算用尽，先结束本页，不再检查下一行。已消费候选后遇到超大行，先交付部分页，`next` 停在该行之前；历史扫描仅消费范围外候选时也先交付空页。没有消费进度时，返回包含 `StateError::RowTooLarge` 的 `StateFailure`，携带路径、所需编码大小、本次请求起点的重试游标和显式跳过后的续页游标。调用者明确点读或跳过超大行时不会遗漏前面的记录；编码损坏等其他错误仍返回失败。redb 在解码前检查原始键与记录长度，内存实现先统计借用值的无损编码大小，再克隆匹配值。

前缀包含精确路径及其后代，不包含文字前缀相近的邻居。后端从键确认范围后才观察内容和来源。`examined` 对物理候选收费，包括共享 Journal 扫描中范围外的历史键；这些键不贡献内容来源或编码字节。当前页对完整消费记录收费，包括有来源缺席；历史页对匹配记录收费完整字节，对时间过滤记录只收费键与来源元数据，不物化过滤载荷。

每条范围内记录的键与来源元数据须先适合完整页字节预算，再累积来源。头部拒绝返回 `provenance_observed = false` 并保留此前已观察来源。仍有预算时，至多一条已准入边界行贡献来源但不被消费，也不计入 `encoded_bytes`；消费记录与该边界的来源输入编码量不超过两倍页字节上限，这不是进程内存限额。头部准入或时间过滤历史的 `RowTooLarge` 所需大小是键与来源元数据大小；匹配载荷拒绝报告完整记录大小。

Standard 将来源未读取保留为 `Failure::HandlerError`，kind 为 `state_provenance_unavailable`，同时保留此前已观察来源。失败的空 taint 不证明拒绝记录是 pristine；这与描述数据提交结果未知的 `state_commit_uncertain` 分开。

标准 `list` 接受 null 或包含 `cursor`（字节）、`limit`、`max_examined`、`max_encoded_bytes` 的选项 map，返回 `entries`、`next`、`examined`、`encoded_bytes`。每条记录包含 `path` 和 `value`，输出污点覆盖本页观察到的记录，也包括检查后留待下一页的行。`StatePage::taint` 和 `StateHistoryPage::taint` 保留影响游标和字节计数的来源。

`list` 将查询前缀作为一个集合资源授权：`read://state/work` 允许列出其后代值，即使它不授权对每个后代路径单独调用 `read`。读取对象不同的数据应放在不同的集合前缀，或为 `list` 方法设置策略。

集合授权不能绕过保留命名空间。通用 State Handle 不能打开本地 kernel、vault 或原始 Fact 路径；即使持有通配授权，Standard `list` 也在查询前拒绝包含保留空间的本地 `state://` 根集合。Fact 的公开投影使用专用资源。可信宿主仍可直接查询 State 根集合，后端不承担应用授权或静默过滤记录。

历史时间范围使用半开区间 `[from_millis, to_millis)`，反向区间会报错。历史端口返回 `StateObservation`，区分有来源缺席和存在 Null。`read_at(path, 0)` 从当前域读取观察，其他时间戳从完整历史或裁剪后的路径基线回放该时刻的观察；早于全局保留水位的读取返回 `HistoryTrimmed { retained_from_millis }`，即使该路径从未出现。历史分页只返回原始变更，不把基线伪装为 Set；游标绑定路径、时间区间与保留水位。

受保护的 `state://vault/**` 即使启用 `Full` 也只保留当前值；非零历史点读及 vault 前缀历史查询返回 `HistoryExcluded`，更宽的扫描不含 vault 变更。这避免旧凭据 verifier 留在逻辑历史中，但不保证 redb 写时复制页或备份已安全擦除。

`read_at` 只回放指定时刻及之前保留的路径变更，但很长的历史前缀仍可能耗费大量工作，单次读取没有工作预算。需要显式遍历预算时使用历史分页；分页预算不限制历史留存、单个解码值或应用总工作量，收集全部页面的应用自行承担结果内存。

## 事实记录

普通 Executor 调用默认不记录 Fact。需要观察时选择 `Executor::with_fact_recording(true)`，直接调用则选择 `InvocationOptions::record`；KernelBuilder 默认禁用 Fact sink，须先显式安装再选择记录；安装 Fact 后端本身不启用记录。禁用的写入和经检查读取报告观察存储未安装，不是假空历史；显式要求记录时 fail-closed。内建 memory 与 redb 留存均有界，不提供自动退休；默认值与装配见[Fact 观察配置](api-reference.md#fact-观察配置)。载荷留存和后端写入属于这项显式观察策略的成本。

Fact 是宿主显式选择的操作观察记录。审计、跟踪和 `why_not` 投影可从这些记录构建；记录不授予权限，不是账户余额或外部效果提交的权威，也不恢复程序控制流。Fact 自身的存储提交按所选后端合同处理。

热路径通过存储引用和轻量标签保持事实记录紧凑。大内容用 blob、tensor 或帧引用表示。

身份字段分别表达不同事实：

| 字段 | 含义 |
| --- | --- |
| `caller` | 调用进程的 `ProcessId`，其数值不是身份。 |
| `caller_identity: Option<IdentityRef>` | 可信宿主在准入前固定观察一次的调用进程默认身份；`None` 明确表示未知。 |
| `acting` | 本次操作尝试选定的执行身份。 |

有 `ProcessTable` 的托管执行以进程表为身份基线，调用方提供的值不能覆盖表中观察。portable 或无进程表宿主显式提供基线，未知时保留 `None`。同一次调用的 pending、完成和拒绝记录复用准入快照。新的调用命中幂等缓存时也记录自身调用进程的身份，不继承生产者的基线。

只有 `caller_identity` 为 `Some` 且与 `acting` 不同，才派生 `AuditTag::CrossIdentity`，包括切换到 root 或从 root 切换。该标签表示一次身份切换尝试，不证明委托已经获准或效果已经发生。未知基线不生成标签，但没有标签也不能证明两者相同；不能从 `ProcessId` 或已选定的 acting 补造缺失基线。网关审计 Fact 的两个身份都使用 root。

宿主可以向同一条 Fact 流显式写入应用审计事件。`Bootstrap::record_gateway_audit` 接受 `GatewayAudit`：`event`、`outcome`、可选 `username`、`source_addr` 及应用拥有的 `details`。调用方在提交前脱敏，内核不验证这些标签的身份，也不解释 details 中的认证声明。

`xolotl_types::audit::gateway_audit_event` 校验完整行政包络，包括 `GATEWAY_AUDIT_NODE`、零 invocation 票据、无活动句柄的坐标、root 基线与 acting 身份及观察元数据；只有特殊位置并不足以识别事件。合法事件按任意非空宿主事件名得到 `AuditTag::Custom`，不要求 Console 前缀。普通 Operation 返回的 `event` 不能冒充这一包络。该识别校验可信 Fact 写入方的结构，不证明任意导入 Fact 的真实性。Console 将会话摘要放在 `details.authentication`，通用包络没有 MFA 字段；这些契约继续使用尚未正式发布的 v1。

redb Fact 适配器把存储提交错误视为结果未知：记录可能已经持久化。共享数据库恢复拥有者会关闭实时 Fact 通知源、使 State 订阅失效，并在重开前拒绝新的数据库操作，不论失败源自哪个适配器。已回滚的中毒事务不触发这一恢复状态。新的执行 ID 预留也会被拒绝，已经确认的缓存范围仍可使用。订阅关闭后须重开再重新有界扫描，包括可能已更新完成结果的旧槽位。返回错误不能证明本次 Fact 不存在。

redb 提交失败后，即使重开能恢复持久行，当前实例仍可能读取旧根。因此 `cursor()` 只是本地提示；结果未知期间 `FactSink::observed_cursor()` 会报错，响应修订不能把旧提示作为当前值。重开后，`scan` 捕获自身读取视图的上界供核对。`FactError::kind()` 区分提交时的 `CommitOutcomeUnknown` 与后续访问的 `ReopenRequired`；调用方应按类型分支，不解析诊断文本。`Other` 本身不证明外部效果是否运行。

重开后，调用方须按完整 `OperationId` 核对，再决定是否重试效果或完成记录。追加游标仍不是完成版本，实时通知也不是持久事件流。

## 有界读取

`FactQuery` 定义追加区间 `[from, before)`、可选调用进程筛选、`FactOrder::{Forward, Reverse}`，以及独立的 `limit`、`max_examined` 和 `max_encoded_bytes` 预算。`FactQuery::new` 默认正向，候选检查预算等于返回条数上限。`FactSink::scan` 会先校验适配器返回的边界和计数，再把页面交给调用方。

通过 `query.next_page(&page)` 保留方向、筛选条件和预算继续读取。`page.next = None` 才表示区间结束。空 `facts` 数组仍可能有续页：内存扫描会把不匹配的槽位计入 `max_examined`，有索引的适配器可以跳过无关进程。因剩余字节不足而拒绝的候选也计入检查数，但保留为未读；若它是第一个匹配记录，读取返回错误。

`lookup(FactLookup)` 按索引定位后，在同一存储视图内先筛选当前调用进程，再检查字节预算并复制或解码。结果区分 `Found`、`Missing` 和 `FilteredOut`，匹配记录超限会报错。`get_bounded(id, bytes)` 是不筛选进程的便利包装。

正向续页把 `before` 固定为第一页的 `end`；反向续页将 `before` 缩小为 `next`，保留原来的 `from`。每页的 `end` 描述该页捕获的区间上界。范围外的新追加不会进入续页，但范围内仍可更新完成结果或调用进程归属。游标表示追加位置，不是时间戳、筛选后的行号或可用于持久订阅重放的版本号。

标准 `state://fact` 或 `state://fact/<process>` 的 `read` 接受 `from`、`before`、`order`、`limit`、`max_bytes` 和 `max_examined`，返回包含 `items`、`from`、`end`、`next`、`order`、`complete`、`examined`、`encoded_bytes` 的对象。游标和投影中的数值标识符输出为精确的十进制字符串，游标输入也接受非负整数。默认返回 64 条、编码预算 256 KiB、检查 4,096 个候选；超过 256 条、256 KiB 或 65,536 个候选的预算，以及零预算和未知字段都会被拒绝。

```json
{"from":"0","before":"1200","order":"reverse","limit":32,"max_bytes":65536,"max_examined":256}
```

进程检查只在显式设置 `include_recent_facts=true` 且指定 `process` 时读取 Fact，复用相同的查询解析和页面投影，默认反向读取 32 条。指定单进程可以避免枚举放大 Fact 预算。`recent_facts` 返回分页对象。进程和子进程枚举仍有独立的留存成本。

这些预算约束返回的编码量和检查的候选数，不约束历史留存、解码堆、总 RSS 或耗时，检查单个大值仍可能昂贵。精确的全历史分析需要显式分批处理或独立维护的投影，单页计数不表示全局总量。`get`、`all_facts`和 `facts_of` 仍是显式的无界诊断便利接口。

## 存储后端

文件系统的 `max_uploads` 只限制上传，覆盖上传创建、存活上传记录、丢失回执及延迟上传清理。退役对象删除不占用这一容量，因此占满上传槽不能新增对前台对象删除的阻塞。前台文件系统任务仍受独立的 I/O 准入限额约束。

本轮拥有者存活期间，文件系统对象适配器保留被放弃上传的准入槽与暂存根目录租约，直到暂存目录删除成功或确认已不存在。删除失败后继续计量，本轮清理 worker 在存活期间重试，不要求被取消的调用者或其 Tokio runtime 恢复。最后一个 sender 关闭时再尝试一次，仍失败的目录留给之后的冷打开回收。并发打开的存储不能回收另一存活拥有者的暂存。已注册 pending upload 不包含延迟清理，因此 pending upload 数量为零不能证明上传容量已释放。这属于对象存储清理，不是 State 回滚或持久执行检查点。

`AbsenceLimits` 计量留存的带来源缺席记录，以及后端完整缺席编码加键。内存与 redb 默认 65,536 条、64 MiB；`None` 显式取消该维度限制，零禁止新增计量。超额增长原子拒绝，不丢失来源、历史或通知。redb 重开保留计量，降低额度允许非增长变更而不清除证据。相同观察在不同后端的编码字节计量可以不同。

Source 指纹在下降遍历前与精确编码时均检查预算，计量按驻留身份去重的节点、每个集合引用、键和字符串／字节内容。接纳后的指纹保持原标签表示，不缓冲完整编码。历史裁剪中，路径的第一个 Set 可直接替换基线，不读取旧基线；Append、Delete 与前缀追加仍依赖先前观察。

redb 的所有顶层 List 都由 State 当前 marker 和独立编码项拥有，包括普通 Set、compare-set 和 merge 写入的 List。项表就是当前值，不是副索引或另一份副本。普通 Append 只插入新项并更新 marker，保留项的原始键值不变；后续 Source 追加复用同一表示，不重建 List。替换或删除 List 在同一事务中移除旧项。比较和通用 Merge 仍可能物化当前 Value；Full 历史及 Set 通知继续保留完整事件载荷。

有界读取和比较计量路径键、marker、来源及所有项键值。Source 项数和字节限额在 Source 准入边界执行，不进入通用 State List 解码。State 拥有的格式使用 `XSL1`、`state_list_items_v1` 和 `state_list_meta_v1`。

内存使用持久 List 更新及前缀裁剪，但 Source 字节准入仍在提交锁内测量完整 tagged List 封套；有界当前观察也测量完整封套。计数省去完整输出缓冲，并不省去值图遍历和编码索引分配；跨项共享使其不能改为独立项编码大小之和。两种表示的编码字节费用都不是 RSS 上限。

State、历史、Fact 和程序常量共用显式节点表，保留字节、map、完整对象描述符、流标记以及浮点原始位，格式统一按首个版本定义。缺少来源、节点表损坏或格式未知时明确报错。存储只初始化空 schema，不合成缺失的权限、身份或提交证据，也不重新解释已有记录。仅在所属合同明确允许时，才可从实际留存数据重建派生计量。

规范 v1 Fact 必须包含可为 null 的 `caller_identity` 字段；null 表示未知，省略字段属于无效记录。不接受旧缺失字段形态，也不在解码时从 `caller` 或 `acting` 推断基线。

外部应用 schema 使用的普通 JSON 是另一种表示，持久值不能先经过无类型标记的 JSON 中转。Fact 的 input 是完整 Value，成功 outcome 是可选 Value；decision 区分 pending 和已失败、已拒绝调用，`Some(Value::null())` 表示成功返回 null。Console 详情直接投影类型化值，保留完整张量和帧元数据。

`xolotl-state` 的可移植契约分别放在 `read.rs`、`write.rs`、`query.rs`、`history.rs` 和 `watch.rs`，宿主类型擦除位于 `host.rs`。关闭默认特性后使用 `no_std + alloc`；`std` 只启用宿主组合，不引入 Tokio；`tokio` 启用广播适配；`memory` 启用内存实现。`memory/storage.rs` 负责单锁或分片 map 的锁定与有界快照，当前值使用有序 map，不额外维护全局索引。

内存默认的 `MemoryHistory::Disabled` 保留当前 live 值及有来源缺席，不安装历史能力。需要历史查询时必须显式选择 `Full`；在宿主主动推进保留水位前，它保留所有非 vault 变更。

`InMemoryOptions` 独立选择读取分片、历史、通知容量、Source 流身份及缺席记录额度；字段与默认值见 [API 参考](api-reference.md#内存-state)。启用 SDK 的 `memory` feature 后，可显式选择完整历史：

```rust
use std::num::NonZeroUsize;
use xolotl_sdk::{InMemoryBackend, InMemoryOptions, KernelBuilder, MemoryHistory, Xolotl};

let state = InMemoryBackend::with_options(InMemoryOptions {
    read_shards: NonZeroUsize::new(32).ok_or("zero read shards")?,
    history: MemoryHistory::Full,
    ..InMemoryOptions::default()
})?
.into_backend();
let kernel = KernelBuilder::new(state).build();
let host = Xolotl::from_kernel(kernel);
```

更多分片可以减少不同键之间的竞争，同时增加存储和锁定成本。默认不保留历史仍不限制当前值、订阅者或宿主总内存；未裁剪的 `Full` 历史随写入持续增长。

独立的 `StateHistoryRetention` 端口提供 `retained_from()` 和 `trim_before(floor, limits)`；动态 `Backend` 使用 `trim_history_before`：有预算的裁剪将旧变更原子折叠成各路径的值与来源基线；超预算不改变状态。水位前的读取明确失败，旧历史游标不能在水位推进后续扫。daemon 仅在显式配置 `[storage.history_maintenance]` 时间窗口时自动安排有界裁剪；未配置的 `Full` 继续保留历史，直到宿主手动裁剪。完整选项见 [API 参考](api-reference.md)。

`xolotl-storage-redb` 实现同一组能力，`state/read.rs` 负责事务分页，`state/codec.rs` 负责无损存储编码。`RedbStore::open` 默认采用 `RedbHistory::CurrentOnly`；需要完整历史时，应在构造 State 后端前调用 `RedbStore::open_with_history(path, RedbHistory::Full)`。两种模式都保留当前值，只有 `Full` 写入非 vault 变更记录并安装历史读取与裁剪端口。redb 将模式和保留水位保存在数据库中，重开不能改选模式；缺少必要表或元数据的数据库直接拒绝。

停止 State／Source 生产者后，`RedbStore::wait_idle()` 等待已接纳的 State／Source 阻塞作业释放数据库引用，包括结果等待者已消失的作业。返回的 Future 只持有完成追踪器，同进程重开时可先取得 Future、丢弃适配器和 Store，再等待它。同步 Fact 操作、Console 存储及其他数据库使用者须分别停止并释放；这不是整个数据库的关停操作。

裁剪在同一事务中删除旧历史逻辑行、发布路径基线和水位。按路径排序的历史表服务查询；额外的按时间排序索引让裁剪只访问水位前的候选行。普通 State 写入和 Source sink 提交都在同一事务中更新两种顺序。事件数和编码字节预算约束候选工作及暂存基线；超预算时回滚，不推进水位。额外索引增加 `Full` 写入和空间成本，删除逻辑行也不保证文件立即缩小。

启用 Federation 时，redb 在历史删除前于同一写事务中检查最多 64 个显式注册的 State publisher pin。注册也在写事务内检查当前 floor，避免裁剪／注册竞争。未完成页面保护尚未消费的时间戳，包括同时间戳的未扫描事件；已完成 cursor 保护下一个时间戳。pin 元数据无效或超预算时拒绝裁剪。移除 stock 发布配置保留 pin；可信宿主须先结清未完成页面，再显式释放精确的已完成 cursor。这不是全局 reader 管理器：没有持久 pin 的消费者仍依赖宿主明确的保留窗口政策。

publisher pin 元数据是必需的物理表，未启用 Federation 的构建也一样。这类构建可重开并使用 State，但任何 pin 仍存在时拒绝推进留存水位，须由启用 Federation 的拥有者结清或释放。pin 元数据缺失时拒绝重开，不创建空的留存证据。

daemon 的可选时间窗口策略不跟踪活动读者或审计、重放所需的最早时间；启用前宿主须明确决定何时允许旧历史读取失效，详见[配置](configuration.md#state-历史自动维护)。

内存和 redb 实现通过 `into_backend()` 装配其支持的宿主能力，自定义宿主可以只安装部分能力，也可以独立组合不同实现。`FactStore` 适配器与可变 State 能力分开。

`xolotl.toml` 在引导时选择存储。控制台管理的运行时状态存在 Xolotl 状态中，不存在守护进程命令行中。
