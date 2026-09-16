# 增量结构化值

结构化值可以增量编码到不可变对象，再按事件消费，无需收集完整编码载荷。
可移植与宿主执行、State、Fact 和 checkpoint 共用同一种不可变共享 `Value`。
事件处理和整值物化都是显式选择，I/O 窗口不会变成累计任务数据量上限。

## 常驻值所有权

`Value` 隐藏存储布局，通过 `view()` 观察语义变体，也可以使用
`as_list`、`as_map`、`as_str` 和 `as_bytes`。克隆为 O(1)；移入 String 或 Vec
会保留原有数据分配，`into_text` 和 `into_bytes` 返回具有独立生命周期的共享叶所有者。
克隆选中的子值后，可以释放原父值及其无关兄弟节点。

`ValueList` 和 `ValueMap` 使用类型明确的持久索引。更新共享未变化分支，复制一个叶和
对应索引路径。增长操作通过 `CollectionError` 报告表示范围溢出，但不承诺分配器内存
耗尽可恢复。最后一个集合所有者释放时进行迭代回收，无需临时分配工作栈，也不随值嵌套递归。

精确相等、语义摘要和 token 估算记忆化处理共享子图。摘要包含完整媒体元数据及浮点位，
不会读取外部内容；相等判断不把摘要相等当作精确证明。token 按每条逻辑边计数，溢出时
饱和至 `u64::MAX`。Debug 仅展示浅层概要。消费者可复用 `ValuePostorder` 借用遍历，
分配键只用于本次记忆化，不能作为持久标识。

带类型持久化使用后序节点表和根引用，解码直接构造 Value。
`ValueTableEncoder`、`ValueTableDecoder` 支持多个根共用一张表，包括 checkpoint
不同字段的重叠子图。编码保留物理共享，不保证语义相同但共享布局不同的值具有相同编码字节；
语义标识使用 `semantic_digest()`。普通 JSON 和 protobuf 仍是树形适配器，
需要独立的输出大小和解析深度准入策略。

顺序构造可使用 `ValueListBuilder` 和 `ValueMapBuilder`：它们只暂存最多 32 个成员的
未完成叶块与 O(log n) 个已完成索引根，按顺序构造耗时 O(n)。`finish()` 将已有叶块
直接交给同一种持久集合。Map 的 `append` 要求键按 UTF-8 字节严格递增且不重复；
输入无序时使用普通 `ValueMap::insert`。

## 可选组件

| 组件 | 职责 | 运行时依赖 |
| --- | --- | --- |
| `xolotl_types::value::event` | 逻辑事件、借用式 `ValueCursor`、纯语义 `Validator`、显式 `ValueBuilder` | `no_std + alloc`，无 I/O |
| `xolotl_value_codec::validation` | `EventValidator`、GAT `KeyStore`、分页 `MemoryKeyStore` | `no_std + alloc`，调用方驱动 Future |
| `xolotl-value-codec/cbor` | 经过语义校验的版本 1 编解码器 | 可选 `ciborium-ll`，无 State 或执行器 |
| `xolotl-value-object/cbor` | `ValueObjectWriter`、`ValueObjectReader` 与显式 `encode_value` / `read_value` | Codec 和可移植 State 对象端口 |
| `xolotl-storage-fs/value-workspace` | 支持超过常驻预算的 `FileKeyStore` | Tokio 文件 I/O，不依赖 CBOR |

这些组件不进入 SDK 的最小依赖树。value-object 关闭特性时仅提供显式编码描述符。
对象端口可以是静态实现，也可以是可选宿主 `ObjectStore`；后者实现相同的 GAT trait，
只转发已安装的能力。

## 共用语义

一个文档先记录 taint，再包含且仅包含一个值。`Begin`、`End` 界定集合和字段，
`Atom` 携带定长值与元数据，`Data` 借用字符串、字节及 map 键的片段。
事件覆盖现有全部 Value 变体，包括张量维度、帧时间戳、流错误及浮点原始位；
记录中的 taint 来源顺序和重复项都得到保留。

UTF-8 校验跨片段进行，普通 Path 和结构化路径字段复用同一个增量标识符规则。
map 键必须按 UTF-8 字节顺序严格递增且不重复。纯校验器只保留活动帧和键标识，
创建、公共前缀比较、追加和释放都通过显式工作区效果完成，同时只有一个事件事务。

`MemoryKeyOptions` 显式选择页大小、可选活动键数量和预留数据字节预算。
追加不会复制整个已增长的键，比较直接索引页。预留字节包含页尾空闲空间，map 与页目录
元数据另计；释放键会立即回收其页面。更大的键可以使用 `FileKeyStore`，从独立临时目录
按固定窗口重读。活动键预算独立于键长度，每个会话只有一个异步 worker 和容量为一的
请求队列。释放键等待文件删除；Drop 关闭队列，进行中的 I/O 和清理由 worker 继续持有，
`close().await` 可观察清理完成。运行时关闭或进程崩溃可能留下未发布的工作目录，
宿主应在隔离根目录中管理留存。

可选帧预算约束同时嵌套深度，不约束累计字节或元素数。单条 CBOR Data 记录最多为
`u32::MAX` 字节，更长字段拆成多条记录。编码偏移和逻辑长度使用 `u64`；
记录大小和 I/O 窗口都不构成累计任务上限。

## 显式物化

`ValueBuilder` 通过共用 Validator 和顺序集合构造器消费事件。`End(Document)` 封闭
候选结果；调用方确认实际输入 EOF 后，消费式 `finish()` 才交出值。错误立即释放
未完成字段、集合和键并关闭构造器，已完整解析的来源声明通过 `observed_taint()`
保留为失败证据。默认没有总字节、节点数或深度上限；
选择保留完整值的调用方可以独立配置物化准入：

```rust
use xolotl_types::value::event::{MaterializationLimits, ValueBuilder};

let mut builder = ValueBuilder::new(MaterializationLimits {
    max_payload_bytes: Some(64 * 1024 * 1024),
    max_nodes: Some(1_000_000),
    max_frames: None,
});
// 通过 builder.push(event)? 输入事件。
// 确认实际输入 EOF 后，再消费 builder.finish()?。
```

这些预算计算保留的逻辑载荷、语义节点和活动帧，不估算分配器开销或进程 RSS。
无需常驻完整值的消费者可以逐片段处理并释放事件。

## 独占发布与消费

对于已完成的 `TaintedValue`，`encode_value` 借用载荷和来源。
一般事件源通过 `ValueObjectWriter::begin` 提供起始来源，再调用
`write(event, &event_sources)`。校验和 I/O 之前即记录本次真实来源，因此被拒绝的事件
和被取消的写入也保留已经观察到的来源。
连续事件复用调用方的 scratch 缓冲区，满窗通过写入确认施加背压；`flush()` 可以发送
未满窗口而不结束文档。`finish(&final_taint)` 校验源 EOF、生成完整封套、确认尾窗
写入，再一起提交起始和后来观察到的来源。发布元数据必须覆盖这些来源；缺失时直接报错。

`ObjectWrite::commit_upload` 在可修复的前置检查通过后、发布 I/O 之前，一起冻结
内容和有效来源。冻结后不能继续写入；仍有效的上传只能用同一来源集合重试，来源顺序
和重复项不改变这个集合。去重先合并已有来源再返回规范元数据。成功交付后上传标识
可以退休，调用方持有的是已提交引用。

首次 poll 后的错误或取消会关闭整个 owner，释放工作区和私有上传 lease；
丢弃尚未 poll 的 write 或 flush Future 不影响后续使用。提交被取消时，实际发布结果
可能不确定，writer 不会以补偿操作删除共享内容。`WriteFailure` 和 `ReadFailure`
将结构化错误与已观察来源一起返回；polled Future 被取消后，也可从 owner 读取已观察来源。

结果包含 `EncodedValueRef { blob, encoding }` 和发布来源。编码必须显式选择，
MIME 只用于描述，内容去重时可能保留先前对象的 MIME。描述符、哈希和记录中的 taint
都不授予读取权限；宿主先决定是否允许披露，再为 backing blob 签发现有 Gateway 读取授权。

`Decoder::decode` 借用输入窗口直到语义校验完成。调用方按返回的消费长度推进，
处理事件，再提供未消费后缀。`DecodeStatus::End` 只表示封套结束，必须在底层数据源
真实、成功 EOF 后调用 `finish()` 才确认文档完整。在此之前不发布派生结果；
实际发布时还需合并开读元数据及每个读取块的真实来源，不能只信任编码内声明的 lineage。

`ValueObjectReader::open` 通过显式提供的读取端口核对完整规范元数据。
`next_event()` 借用一个 scratch 窗口，返回暂定事件和已观察来源。只有对象真实 EOF
和文档校验都完成后才返回 `None`，此时可通过 `finish()` 取得字段私有的 `ReadReceipt`。
凭据只证明文档验证，不授予披露权限，也不保证对象继续留存。`read_value` 将 reader
与私有 `ValueBuilder` 组合，取得凭据后才交出完整值；成功与失败都保留实际读取来源
和完整解析的声明，嵌套内容引用仍保持描述符形式。

`copy_value(reader, writer)` 接管两个配置完成的 owner，逐事件转发真实来源；
取得读取端的 EOF 凭据后才提交写入端。失败保留两端已观察来源，取消释放两个工作区
和未发布暂存。`encode_failure` 借用类型化 `Failure`，通过同一 cursor/writer
编码完整的外部标签布局，不格式化诊断字符串，也不构造临时完整 Map。

`EncodedValueRef::into_value` 和 `try_from_value` 定义精确协议 Map：
`{ encoding: "xolotl.value.cbor.v1", blob: <类型化 Blob> }`。额外字段、未知编码或
非类型化引用都会被拒绝。直接编码这种形状的 Map，得到的仍是普通 Map，内核不会自动解引用。

独立的 `xolotl-standard/value-objects` feature 提供
`install_value_objects(boot, objects, config, make_keys)`，只按已提供端口安装
`effect://value/read` 与 `effect://value/write`。每次调用独占配置的 I/O 窗口和
异步工厂创建的 key 工作区，安装本身不启动 worker 或缓冲区。`ValueObjectConfig`
分别描述 I/O 窗口、写入记录策略和读取物化策略；`memory_key_factory` 提供内存分页，
宿主也可注入文件工作区，无需强制依赖文件对象存储或完整 Standard providers。
Read 显式物化一份已验证文档；需要限制载荷驻留量的消费者直接使用
`ValueObjectReader` 事件。所有失败路径都保留已观察来源。

合法片段边界可能产生不同的编码字节哈希，因此它不能替代值的语义哈希。
任意字节范围的续传需要解析器检查点或索引。整份文档的来源为该文档累计；
独立流消息无需保留此前已释放消息的来源历史。
