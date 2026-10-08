# Console 运行时调用与提交

本页说明通过 Console 调用宿主资源、运行可移植程序、保留提交结果、安装模块和订阅。服务入口见[控制台协议](console-protocol.md)，动作和流描述符见 [动作与流](console-actions-and-streams.md)。

## 会话存储拥有者

宿主显式注入 `ConsoleConfig::session_store`，缺失存储即拒绝构造。可选 `MemoryConsoleSessionStore` 或 redb 的 `console` feature。共享存储的所有实例遵循同一不可变 `ConsoleSessionPolicy`：默认每账户留存 5 个会话、每存储域 10,000 个。账户满额时原子替换最早 `(issued_at, SID)` 行，释放的槽计入全局额度；否则全局满额拒绝准入，不驱逐其他账户。过期记录实际删除前仍计量。

会话聚合使用私有类型化存储，不写通用 State 或历史。行含 SID 最大 256 KiB；索引到期维护每次最多检查 16 行、256 KiB。签发不先扫描全部过期记录，因此较老的有效会话可能被替换，而较新的过期记录仍等待维护。列表和批量撤销分有界批次完成；touch／轮换只更新到期索引，不改变签发顺序或计数。未知创建只按原固定 SID、verifier、权限和有效期对账，读到缺席仍不确定，不创建新 SID 或再次驱逐。账户修改属于独立提交域。

嵌入宿主显式驱动 `ConsoleSessionStore::maintain`。daemon 在 Console 启用期间每秒执行一个有界到期批次并跳过错过的 tick；持续到期快于维护会占用容量，因此宿主须共同选择政策与维护吞吐。同一 redb 拥有者的活动句柄遵循同一政策，冲突装配被拒绝。拥有者关闭并重开数据库后，只有已留存的全局与每账户计数满足新额度才能变更政策，不重置计数或驱逐记录。

## Rust 运行时请求

嵌入宿主传入拥有型 `RuntimeCode::Operation { operation }` 或 `RuntimeCode::Program(Program)`，无需将程序转成 JSON 再解码。`RuntimeRequest` 同时携带输入、预算、期限、可见范围、理由、TTL 和可选注册表修订。

| 入口 | 拥有关系 |
| --- | --- |
| `ConsoleService::run_runtime` | 当前请求拥有。 |
| `ConsoleService::submit_runtime` | 接受后由当前 Console 宿主拥有。 |
| `ConsoleService::subscribe_runtime` | 当前订阅拥有，并遵守交付边界。 |

适配器在读取或解码不可信正文前调用 `service.admit_call()` 预留容量，再通过 `ConsoleCallAdmission::run_runtime` 或 `submit_runtime` 消费许可；丢弃许可释放容量。直接 service 入口复用同一准入路径。

Rust 与协议请求复用认证、MFA、开放范围、导入方法权限、输入限额及 Kernel 策略。`source` 是宿主验证的来源，不授予权限。独立提交可以脱离观察者，但只属于当前宿主生命周期，没有持久程序选项。

`ConsoleConfig.request_anchor` 可持有由 `Bootstrap::request_under_owned` 创建的 `Arc<RequestProcess<'static>>`；省略时从 Bootstrap root 派生。anchor 必须属于同一 Kernel、装配时可用且具有必需的委派上限。请求不能另选父进程或突破上限。退出取消已接受任务，失败清理保留责任以供后续重试。

## 宿主时钟与任务调度

Console 与 Kernel 共享 `HostRuntime` 的时钟、期限及任务调度。宿主可提供自定义 runtime，也可使用 Tokio 适配。

`ConsoleConfig.blocking_spawner` 默认共享 Kernel 的阻塞作业端口，用于密码计算、身份预留及同步存储。覆盖端口时须限制自己的 worker 与队列。已接受作业保持拥有直至结算；取消等待者不表示数据写入已回滚。

## 通用资源调用与可移植组合

Console 将领域管理动作和通用运行时入口分开：前者维护账号、凭据、CAS 等领域不变量，后者调用宿主已安装的资源。新增业务资源无需新增 Console action。可发现的入口为：

| 动作 | 输入与结果 |
| --- | --- |
| `runtime.describe` | 返回运行限额、`supported_imports`、含 `enabled` 和 `accepting` 的 `execution_modes`、`atomic`、当前调用方可见的模块目录及当前 `submission_retry_scope` |
| `runtime.resource.describe` | 输入具体 `target`，返回当前内核 Resource ID、描述性 `kind`、声明的 `addressing`（`exact` 或 `prefix`）及调用者可见的 Interface/Method；不披露前缀注册根，结果是建议性发现，不承诺残余策略放行 |
| `runtime.operation.invoke` | `target`、`method`、可选 `input`、`output`、`collect_limit`、`timeout_ms` |
| `runtime.program.run` | `source` 是 Portable Program v1 的 JSON 字符串；`input` 使用 Console 无损 Value；可选 `timeout_ms` |

两个执行动作都要求 MFA level 2，并在 ActionCall 外层提供 `scope`、`justification`、`ttl_ms`。服务在写入审计前将 `scope` 和 `justification` 各限制为 1024 字节。`output` 默认 `unary`，另支持 `sink_only` 和带正整数 `collect_limit` 的 `collect`。成功结果包含 `value`、`taint`、`outcome`（done/short）、十进制 `process_id` 以及十六进制 `program_id`。program_id 标识编译内容，同一程序多次运行有不同进程。

`ActionResult.unresolved_operations` 与成功值相互独立：Race 的失败分支可能已发起效果，Catch 恢复的失败也可能已提交外部效果。`operation_ids` 列出宿主已知、仍需核对的身份；`identities_incomplete` 表示未能保留全部身份。字段缺席表示宿主没有观察到待核对效果，不能证明外部没有发生效果。

例如，宿主注册 `effect://external/example/echo` 后，Program 的 `source` 可为：

```json
{
  "version": 1,
  "body": {
    "op": "sequence",
    "steps": [
      {"op": "invoke", "operation": {"target": "effect://external/example/echo", "method": "invoke"}},
      {"op": "transform", "operation": {"op": "length"}}
    ]
  }
}
```

外层 `input` 为字符串时，结果为该字符串的字符数。变量、命名函数、分支、有界循环、并行、竞争、异常处理及 Finally 使用同一个内核编译器。不要将 source 中的 tagged Value 常量转换成普通 JSON；字节等类型会丢失。资源方法按名称解析，source 不接收 `method_id`。

资源发现、单次调用、Portable Operation 和模块的操作声明均接受具体的本地路径 （如 `effect://app/echo`）或带 cluster 的路径（如 `path://edge/effect/app/echo`）。宿主须安装目标资源并开放对应方法权限，调用者也须持有匹配能力。例如 `perform://path://edge/effect/app/echo` 只覆盖该 cluster 中的资源；`perform://effect/app/echo` 只覆盖本地资源。内核仍在打开句柄和调用时检查请求 Grant、根进程权限及策略。cluster 限定是资源命名空间，不会自动安装远端传输，也不会隐含其他 cluster 的访问权。

宿主通过 `[console.runtime]` 或 `ConsoleRuntimeConfig` 启用执行，默认关闭且没有开放资源：

```toml
[console.runtime]
enabled = true
capabilities = ["perform://effect/external/example/**", "read://state/app/**"]
max_duration_ms = 30000
max_steps = 100000
max_collect_items = 256
max_request_grants = 4096
```

开放范围只收紧调用者权限，不能替调用者授权；账号的 grants/authority_ceiling 也必须覆盖实际目标。宿主开放范围与账号 grant 都可使用 `#` 按稳定方法名选择，例如 `perform://effect/external/example/echo#invoke`；没有 `#` 的选择器覆盖该动词与路径范围内的全部方法。AsyncProcess 还可分别要求 `spawn-with://effect/external/example/echo#invoke`。发现和准入按已安装方法的名称及其声明的权限类别核验，限定方法的能力不能授权其他方法或无方法上下文的检查。daemon 的本地 Console root 默认覆盖管理、external/proc 效果及业务数据读取，不自动获得所有新效果命名空间的权限。宿主可用 `RootProvisioning.additional_grants` 或 `[console.root].additional_grants` 在首次可信初始化时扩展 root 及其授权上限；它不会在重启时改写已有账号。开放选择器不接收谓词；调用者的条件能力不会被提升为无条件授权，内核残余策略仍保留。普通方法和 Acting 导入预检确认结构覆盖并排除已过期的 `@until`，将匹配的用户谓词保留到请求 Process；内核在每次使用时按真实 Operation 或 scope 输入及时钟检查。同一路径多条 grant 是备选关系，单条 grant 内的谓词仍全部成立；发现仅供参考。单目标至多保留 1024 个不同候选，整次程序的 `max_request_grants` 默认为 4096、配置上限为 16384。Kernel 将每个请求与锚点中所有结构及权利可覆盖的父 grant 分别衰减，保留顺序无关的 OR 候选；等价派生 grant 去重后，实际附加总数超过 16384 时在执行前拒绝。AsyncProcess 的方法候选与 `spawn-with` 候选分别相或，再按同一真实 Operation 输入与时钟相与。Console 向 Kernel 分别提交仅含方法名选择与仅含传播位的请求 grant，因此传播谓词不能增加可调用方法；后台任务定期复核账户权限时，保留候选原有的权限域与谓词；宿主完成子准入后，Kernel 在派生前复核两域 grant，不重复执行有状态宿主策略。可调用方法按已安装的 `MethodAuthority` 授权，不受资源 scheme 限定；`act-as` 只指向已登记的 `identity://...` 身份，`spawn` 指向进程资源。

每个已安装 Method 显式声明 `authority` 类别。发现、准入和订阅交付复查都读取宿主描述符，调用者不能覆盖；方法名及 purity 不决定权限。例如效果上的 `read` 方法可要求 `perform`，State 上的 `load` 可要求 `read`。标准 State 的 `compare_set`、`append`、`write`、`delete` 要求 `write`；`read`、`list` 要求 `read`；单次 `subscribe` 要求 `subscribe`。`perform` 不代表资源上的全部方法。多接口资源的源 Grant 按稳定方法名选择权限，打开请求与 Handle 使用统一的资源内方法位图；资源内的方法名及 ID 必须唯一。

初次准入先编译、检查全部导入、衰减方法权限及显式身份委托，并在任何效果前以请求身份预先打开 Operation 句柄。输入及 acting 身份相关策略在每次 Operation 时重新检查。标准 kernel/vault/Fact 保留路径必须使用对应管理动作。所有 HTTP、Rust、WebSocket 调用共用这些检查和执行准入；独立任务与活动调用分别管理容量。执行仅属于当前宿主生命周期，不提供检查点租约或重启恢复。

`resource.type.*` 仍描述管理视图类型，`runtime.resource.describe` 才是具体已安装资源的方法发现。目前没有全内核资源枚举接口，客户端从宿主开放约定或资源目录方法获取具体资源名称。

预算涵盖 source、外层输入 Value 的节点数、深度与内联字节、指令、导入数、步数、任务数、执行容器内存、Collect 条数和截止时间。协议调用与 Rust 拥有型请求在编译及执行前使用同一输入预算。超出时服务返回 `ConsoleFailure.code = bad_request`，protobuf 编码为 `VALIDATION_FAILED`，HTTP 状态码为 400。默认上限为 16384 次逻辑节点出现、深度 128 和 4 MiB 逻辑内联字节；共享子节点在每次逻辑出现处计入，键、标量及引用元数据计入，Blob/Tensor/Frame 指向的外置内容不计入。这项计量不是进程 RSS 或帧编码字节数。Console 不能提高内核上限；Driver 产生的 Value 仍需资源自身限制。附着调用和订阅的 Kernel 执行截止时间取 `timeout_ms` 与外层 `ttl_ms` 中较早者。附着调用随后最多等待一个 `executions.cleanup_timeout_ms` 取得 Kernel 终结结果，再以独立的有界时间完成进程收尾；这些等待不延长程序执行权限。若 Kernel 报告 `OutcomeUnknown`，之后的进程收尾失败不会抹去已知的 `operation_ids`。若已启动的评估在有界等待内仍未完成，Console 改为报告 `OutcomeUnknown`，其中 `operation_ids` 为空、原因是 `settlement_timeout`。订阅的可见性 `ttl_ms` 仍是严格的交付边界。已接受的独立提交使用自身固定的执行期限，可以超过本次请求 TTL。失败、取消和超时都可能发生在外部效果提交之后，没有隐式事务或重试去重。丢弃调用会取消请求并撤销句柄，宿主保留清理工作；不承诺在 Future 被丢弃后继续执行 Program 的 Finally。

所有运行时调用、订阅和提交均接受可选的 `budget` map。`[console.runtime.budget]` 使用相同字段，设置宿主允许的单次执行上限：

| 字段 | 含义 | 输入 |
| --- | --- | --- |
| `max_micro_usd` | 累计预留及结算费用，单位为百万分之一美元 | 非负整数或十进制字符串，最大 u64 |
| `max_inflight_ops` | 同时持有预算预留的操作数，包括免费调用 | 非负整数，最大 u32 |
| `max_inference_tokens` | 累计 Token 预留及内核结算用量 | 非负整数或十进制字符串，最大 u64 |

各维度均可省略或为 null，表示不增加该维度限制；零值有效。调用方与宿主上限逐项取交集，每次 Operation 同时计入全部祖先账户；新提交不会清空祖先已用额度。子进程共享父级账户，父进程正文结束后仍然受限。这是进程树生命周期预算，没有每日、每月重置；跨执行账户账单需由宿主独立记账。

例如 `budget: {"max_micro_usd": "1000000", "max_inflight_ops": 4}` 为整棵执行树设置 1 美元预算，允许最多 4 个同时执行的 Operation，不改变解释器任务槽数。Driver 执行前检查估算预留，完成后按实测用量结算；实测值可能超过预估。Token 结算沿用内核输出 Token 计数（优先实测数据，否则使用计费估算），并不设置提供方的生成长度。提供方专用限制应放在对应资源输入中。

成功调用输出、订阅的 `started`/`finished` 事件及执行元数据均返回 `budget`，表示接受时的进程树上限，三个字段始终存在。费用及 Token 以精确十进制字符串返回，无限制维度为 null。它不是剩余额度：子进程返回共享的来源上限，祖先账户和恢复配置还可能施加更严格限制。描述符定义名为 `execution_budget`。

Acting scope 接收具体、本地的 `identity://...` 身份。宿主开放范围和用户能力都必须覆盖对应 `act-as://identity/...`，包括未选择分支及传递模块中的身份导入。每个身份仅申请 `DELEGATE` 和空方法 bitmap；内核检查父级权利上限，保留到期时间及谓词，并在每次进入 scope 时以管道输入检查条件。Acting 改变 Operation/Fact 的 acting 身份，不继承目标身份的资源权限；退出 scope 恢复原身份。订阅投递同时复查身份委托和资源能力。`max_identities` 限制不同身份导入数，默认 128，最大 1024。

Signal wait 会成为目标资源路径上的单次 `subscribe` Operation。Console 在效果前检查宿主开放范围、用户能力及已安装方法的输出模式。所需能力由方法的 `MethodAuthority` 决定：标准 State 使用 `subscribe://state/...`，自定义方法也可要求 `perform://effect/...`；集群路径使用对应的 `<verb>://path://<cluster>/...` selector。用户能力可带条件谓词。每次进入 Wait 时，内核按普通 Operation 检查授权和残余策略，条件谓词读取进入 Wait 的输入值。已安装方法返回结果后，等待即完成。

标准 State 实现先订阅再读取，存在的值（包括 null）立即完成，否则等待该精确路径的下一次 Set/Append。Delete 继续等待，其来源合并到之后的结果或错误；lag 和关闭显式失败。标准 State 信号方法需要后端的配对观察端口，集群路径也一样。长时间等待期间，内核不会在方法完成时重新检查已撤销的授权；Console 订阅在向客户端交付事件前另行复查授权。调用和订阅仍受各自截止时间与取消控制。本地保留路径仍使用专门的 Console 管理动作。

## 独立提交与结果保留

提交在求值返回时登记有界正文结果投影，再排空输出日志。随后排空超时或工作者放弃保留该结果及清理证据；`stop_cause` 独立保存首次非空停止原因。收尾复用已有投影，不再次编码正文；只有尚未取得正文结论时才生成结算超时结果。

附着流的正文已知后，排空到期报告 `Failure::Timeout`，并保留正文及独立清理状态。`settlement_timeout` 只用于有界等待结束时尚未取得正文结论的情况。

`runtime.operation.submit`、`runtime.program.submit` 复用 invoke/run 参数、MFA 与可见性检查。服务在执行任何 Operation 前预留容量，返回元数据及 `ActionResult.execution.execution_id`。`runtime.describe.execution_modes` 的三个模式均为 `lifetime: "host"`，submission 的 `accepting` 同时报告退出时的准入关闭。

已接受任务不因响应丢弃、观察者断线、退出登录或会话到期取消，也不持有 bearer 或 SID 作为执行凭证。原 `timeout_ms`（省略时为宿主 `max_duration_ms`）固定执行期限；`ttl_ms` 限制准入与即时披露，不续期或缩短已接受任务。普通调用与订阅取执行期限和可见性期限中较早者。不传 `submission_identity` 时，不同 submit 调用仍是非幂等的即发即走提交；响应丢失不意味着可以安全重复提交。

两个 submit 动作均可选传入 `submission_identity: {registry_instance, retry_epoch, nonce}`，显式启用响应丢失后的重试保护。从 `runtime.describe.submission_retry_scope` 取得实例与 epoch，并在提交前保存 nonce。`retry_epoch` 必须是规范的无符号 u64 十进制**字符串**（`"0"` 或无前导零的数字），不能传整数。身份归属于不可变账户实例，不绑定 SID，也不授予权限。首次受保护接受返回完整任务元数据及 `submission_evidence: "accepted"`。同一身份和请求的已有提交重试返回原 `ActionResult.execution`，响应体仅含 `{execution, submission_evidence}`，证据为 `accepted` 或 `retired`；不重新编译、不再次分发，也不设置新期限。同一身份下修改请求会被拒绝。仅返回引用的重试避免读取记录时的过期竞态；须另按 `runtime.execution.get` 或 `runtime.execution.result` 各自的合同获取记录。submit 输出中的元数据字段因此为可选。输出或记录退役后，`retired` 保留原引用，不创建替代任务。

`runtime.submission.lookup` 要求同一身份，仅返回 `{evidence, execution}`：证据为 `unproven`、`preparing`、`accepted` 或 `retired`，前两者引用为 null，后两者为原引用。它采用与 `runtime.execution.get` 相同的归属、MFA 和可见性准入，不返回载荷或输出，也没有分发或修改副作用。`preparing` 不表示已接受；`unproven` 不证明没有发生效果，也不允许盲目重放。

`max_records` 与 `max_records_per_account` 限制共享的逻辑条目，包括 Preparing 预约与退役墓碑；记录及其别名只计费一次，不增加独立重试历史配置。受信宿主可通过 `ConsoleService::close_submission_retry_epoch` 推进预期 epoch，没有客户端关闭动作。已关闭 epoch 中仍保留的别名可继续查询，但其中不存在的身份不能执行。宿主重启会改变注册表实例并拒绝旧实例身份；这不证明旧效果未发生。

stock daemon 启用 runtime 提交时，按单调时钟使用 `console.submission_retry_epoch_ms` 关闭重试 epoch，详见[配置](configuration.md)。它复用每秒一轮的 Console 会话维护任务，在会话存储 I/O 前处理到期关闭。延迟的一轮只关闭一个 epoch，从实际关闭时间安排下一轮，不补造错过的代次。间隔不是每个请求的 TTL：实际关闭拒绝未知旧身份，仍留存的原记录继续提供受理证据。结果过期与 epoch 关闭独立，关闭不释放未完成的执行清理责任。嵌入宿主通过 `ConsoleService::submission_retry_scope` 及显式关闭方法选择自己的政策；从不关闭的宿主仍持续计量墓碑，可能耗尽新提交容量。

独立执行账户权限不依赖提交 SID；同一账户实例的新会话可以观察旧任务。披露在最后一次相关等待（含账户与凭据查询）后复核本次请求的当前 SID，正常空闲续期仍有效。嵌入宿主可同步调用 `ConsoleService::close_execution_admission(&self)`，仅关闭独立提交，不取消已接受任务或关闭普通调用与观察。`shutdown_executions` 复用该步骤，仍取消任务并等待有界收尾。

| 动作 | 行为 |
| --- | --- |
| `runtime.execution.get` | 读取元数据，不返回载荷。 |
| `runtime.execution.list` | 使用有界、不透明 cursor 页面列出本账户实例的元数据。 |
| `runtime.execution.result` | 读取 `record`、无损 `output`、`retention_failure`、`unresolved_operations` 与独立的 `finalization`。 |
| `runtime.execution.output.read` | 使用 `cursor`、`limit`、`max_bytes`、`wait_ms` 分页读取 Stream 事件。 |
| `runtime.execution.cancel` | 请求协作式取消并返回当前元数据，要求 MFA。 |
| `runtime.execution.forget` | 清理与活动来源凭据依赖结束后，删除已收尾记录。 |

六项动作均检查不可变账户实例的归属；重建同名账户不能继承旧任务。元数据和取消不要求继续拥有资源 grants；结果及输出读取重新检查 MFA、可见性、宿主开放范围和原操作／acting 权限。不存在、过期和他人记录统一返回不可用。列表使用 `console.queries` 预算，cursor 绑定账户与宿主实例。

Stream 日志归执行所有，与提交连接无关。页面返回 `entries`、`next_cursor`、`last_sequence`、`has_more`、`complete`；观察者各自分页，最多等待 30 秒，交付前重验权限。事件及终结标记的保留容量独立于最终结果。`max_output_page_bytes` 须容纳最大单事件与交付元数据；请求页太小时需提高 `max_bytes`。

效果前及运行期间定期检查账户身份、撤销／凭据代际和原条件 grant 候选。确证撤销、缺少覆盖原候选的当前 grant，或无法建立当前授权时停止任务。`authority_poll_ms` 控制检查频率，`authority_timeout_ms` 限制单次查询。每项 Operation 仍经过 Kernel 策略；仅退出会话不撤销已接受任务授权。

取消在原期限内给词法 Finally 有界执行机会，并遵守方法 `finalize_allowed` 合同。生命周期清理另有有界尝试，失败后重试清理而不重跑主体。任务退出且 Kernel 确认清理前，容量继续收费；结果过期只隐藏载荷，不释放待清理责任。取消或删除都不回滚已完成效果。

元数据分别表达 `status`（running、cancelling、finalizing、finished）、`outcome`、`result_status` 和 `cleanup_status`。提交与子任务生命周期使用本轮执行记录及 Kernel 清理报告，不另写生命周期审计；认证与可见性安全事件按各自合同处理。结果超限可省略载荷，不改变主体成功结论；`runtime.execution.result` 独立保留已知未决效果身份。未知中断仍表示未知，诊断失败不表示回滚。子任务另带来源执行及完整 operation ID；时间戳为 Unix 毫秒。

`finalization` 包含 `status: "pending"`、`"available"` 或 `"omitted"`，以及可空 `report` 与 `retention_failure`。可用报告包括清理终态、有序 taint、经安全投影且带索引的终结器失败，以及释放／撤销句柄计数。正文 `outcome` 与清理终态独立。正文和终结器的未决身份合并到另行有界的 `unresolved_operations` sidecar；省略报告不证明效果全部已知。Console 在释放清理 custody 前保存投影，因此 Kernel 自动退役进程后结果仍可查询。后来确认清理不重跑正文，也不延长结果留存。

元数据和保留的 Stream 终结条目还提供可空 `stop_cause`。宿主分类的 `output_limit`、`authority_revoked`、`shutdown`、`timed_out` 等停止原因独立可见，不替换已知成功正文或其类型化失败。正文 `outcome` 统一把 Done、Short、Cancelled 失败、Timeout 失败、其他失败及缺失正文分类为 `done`、`short`、`cancelled`、`timed_out`、`failed`、`interrupted`。输出限额触发取消后仍排空在途端口，并保留未决效果身份。读取针对目标核对已提交的清理证据，列表只核对有界候选页，然后才报告 complete；读取不运行清理 I/O 或过期驱逐。Forget 同样先交接证据，再释放 custody。

附着调用及订阅失败可通过有界 `ConsoleFailure.runtime_completion` 携带 `body`、`body_retention_failure` 与独立 `finalization`；生命周期失败另带安全 `cleanup_failure`。执行引用和已知未决身份独立保留。可信 Rust 宿主可检查仅原生可见的 `finalization_error.error`，其中类型化 `RequestFinishError` 及原清理 ticket 供重试；这些清理权限不序列化给客户端。编码、交付或 revision 报告失败不授权重放，也不撤销效果；交付仍须当前授权允许，且传输帧足以容纳错误。

```toml
[console.runtime.executions]
enabled = true                  # 同时要求 console.runtime.enabled
max_concurrent = 32
max_concurrent_per_account = 8
max_records = 256
max_records_per_account = 64
max_authority_bytes = 32768
max_result_bytes = 262144
max_finalization_bytes = 65536
max_output_event_bytes = 16384
max_output_page_bytes = 131072
max_output_events = 1024
max_output_bytes_per_execution = 1048576
max_output_bytes_total = 33554432
retention_ms = 900000
cleanup_timeout_ms = 5000
authority_poll_ms = 1000
authority_timeout_ms = 1000
```

执行前，每项活动或保留记录预留结果、清理投影与授权容量，Stream 另预留日志容量。`max_finalization_bytes` 独立限制保留报告的 JSON 字节，默认 64 KiB，配置超过 4 MiB 时拒绝。投影借用类型化失败进行安全诊断映射，直接保留编码字节，观察时解码。这些字节计量不限制原始报告、临时转换分配、allocator 容量或 RSS。`ConsoleService::shutdown_executions` 关闭准入、取消任务、停止后台清理并执行有界最终尝试；未完成清理仍保留责任，供后续退出调用重试。退出超时不撤销已接纳的阻塞释放作业，其拥有者到作业实际结束才释放，此前不能确认清理完成。记录与日志随宿主销毁。

`max_authority_bytes` 限制每项记录的 owner、operations authority、origin、长期保留候选 Capability 和实际 budget 的完整 JSON 逻辑表示，包含标点与转义；共享候选仍按每记录完整收费，不是 RSS 限制。root 与 child 预约等于上限可接受，超限在占用记录或执行槽位前拒绝；child 继承来源的实际 budget 和候选。保留候选继续用于当前权限及撤销检查。

## 提交中的子进程

独立提交支持 `output: "async_process"`。已安装方法须支持该模式，调用方同时具有方法权限和 `spawn-with`；附着调用／订阅不能分离子进程。

Driver 派发前，子任务预留自己的账户／全局容量，继承账户上限和原提交期限。父结果返回子任务 `ExecutionReference`；子任务分别拥有结果、取消及清理，父任务结束不取消独立拥有的子任务。

`source.operation_id` 保留 process、execution、invocation、position 和显式 retry attempt。同一活动来源调用再次受理时返回原已接受引用，不重复派发。尚待 Kernel 确认的预留不是接受凭据；不同请求及显式重试分别受理。

来源仍活动时，已结束子任务的接受凭据继续收费。结果过期隐藏载荷，原调用仍能核对原引用；来源与清理依赖结束前拒绝 forget。这些凭据仅在内存中保留。未知效果与失败清理保留原身份和责任，重试清理不重跑 Driver。


## 宿主模块组合

Rust 宿主使用 `ConsoleModule::new(ModuleManifest, loader)` 定义模块，再以 `ConsoleModules::new` 组装，或用 `ConsoleModules::compose` 合并独立模块目录，最后配置 `ConsoleConfig.modules`。daemon 默认目录为空；原生加载器由 Rust 宿主安装。远程 Portable `Module` 仅包含模块名和可选参数，管道输入由内核传给加载器。

每份清单声明 32 字节语义 `revision`、`operations` 中的具体本地或 cluster 资源/方法/输出模式、`identities` 中的具体本地 Acting 身份、`signals` 中的具体本地或 cluster Signal 资源路径，以及 `modules` 中的直接依赖。装配时拒绝重名、非法契约和缺失依赖。`operations[].output` 中的 `collect.limit` 是该模块允许请求的最大收集数量，声明时必须大于零；如果上限超过宿主的 `max_collect_items`，发现会隐藏该模块，准入会在分配进程前拒绝。已安装方法不支持所声明输出模式时同样处理。其他输出模式仍按精确值声明。清单会合并同一资源/方法的冗余较小 `Collect` 上限；变更有效上限会改变 `registry_rev`。`runtime.describe.modules` 每次按当前调用方能力与宿主 exposure 投影，只返回完整的规范化清单：声明的每项操作方法、输出模式、Acting 身份、Signal 订阅及所有传递模块依赖均须可见；AsyncProcess 操作还须有目标上的 `spawn-with`。不能裁剪单份清单，也不暴露被拒绝的依赖。响应的 `config` 不包含宿主的具体 capability selector。安装目录的原始完整清单仍参与 `registry_rev`；该修订号不随调用方能力变化，不能单独用于跨用户或权限变更后的模块目录缓存。模块目录表示安装结构，当前可用的执行生命周期由 `execution_modes` 单独报告。发现只是结构性、建议性的结果；本次请求选择的生命周期、程序预算、依赖输入的残余策略和实际执行准入均在使用时另行检查。宿主装配在规范化排序、去重后，对完整清单 JSON 数组设置 512 KiB 总上限；这限制目录投影开销，但不保证任意传输 frame 配置均可交付响应。加载器语义或捕获配置改变时，宿主必须修改 revision。动作和订阅均可携带 registry revision 前置条件，服务在解析动作/流名称和开始执行之前检查它。

准入遍历整个依赖图，支持环，并在任何顶层效果之前授权全部传递依赖。遍历受 `max_modules`（默认 64）、`max_operations`、`max_identities` 及 `max_request_grants` 限制。加载器返回的每个 Program 使用与直接程序相同的精确源码字节额度及指令／深度预算。Rust 程序（包括模块结果）先检查结构，再用有界 writer 核对紧凑 JSON 编码，通过后才编译；转义字符按实际编码长度计入。协议源码在解码前核对实际 JSON 字节长度。模块拒绝时不启动其返回的操作，也不回滚外层此前的效果。执行首个效果前，Operation 必须匹配本模块声明的具体目标、方法和输出模式；`Collect` 的实际 `limit` 必须在 1 到声明上限之间。Module 必须是声明的直接依赖，Acting 身份和 Signal 路径必须在本模块清单内。Signal 对应的 Operation 计入 `max_operations`。拒绝数字方法 ID；加载器返回 portable 模块。递归模块仍受内核累计代码、frame 和步数预算限制。单次调用和运行时订阅复用同一加载器。

加载器是可信、同步的宿主代码，必须纯粹、可终止且有界；I/O、时间和随机性应放入返回的 Operation。Console 能校验返回的 Program，不能抢占阻塞原生函数，也不能证明 Rust 闭包的纯度。客户端 source 不能安装原生代码。公开宿主组合回归见 `crates/xolotl-console/tests/http.rs`。

## 公共订阅与实时执行

`ConsoleService::subscribe(bearer, source, StreamCall)` 为 Rust 宿主和自定义传输提供公共订阅入口，WebSocket 复用相同准入与来源所有权。返回的 `ConsoleSubscription` 是独占接收端；`recv()` 每次返回一个 `ConsoleEvent`，终止错误只返回一次，结束后返回 `None`。丢弃接收端会关闭来源并请求取消；`close().await` 还会等待执行 worker 退出。取消正在等待的 `recv()` 不会丢失已经读取、尚待授权的事件。

State 提交结果不确定导致 watch 失效时，订阅返回终止错误。客户端须重新读取权威 State 并订阅；旧事件流不能证明该次写入是否提交。

建立后即可通过 `ConsoleSubscription::execution()` 取得执行引用，WebSocket 订阅确认携带同一引用。终止错误在 `SubscriptionClosed.failure` 中保留它，即使首个事件尚未交付。

每次交付检查当前会话、MFA epoch、身份、有效授权及目标权限。身份、授权集合或 MFA 变化时终止订阅。该校验只读，不延长会话空闲期，也不写入可能再次触发 watch 的会话 State；客户端请求和显式 refresh 仍属于会话活动。交付前后都检查可见性截止时间，已经排队的数据也不能在授权到期后继续返回。

`[console.streams]` 在 Rust 和所有 WebSocket 连接之间共享：

| 配置 | 默认值 | 范围 | 含义 |
| --- | --- | --- | --- |
| `max_subscriptions_global` | 1024 | 1–65536 | 当前宿主持有的订阅接收端总数 |
| `max_subscriptions_per_account` | 64 | 1–4096 | 每个已认证账户实例的订阅接收端数 |
| `max_event_bytes` | 1048576 | 1024–4194304 | 规范 v1 事件封套字节数，计入最大长度的订阅 ID |

宿主装配时约束这些值，由 `runtime.describe.subscription_limits` 发现，并计入 `registry_rev`。事件准入同时限制 Value 递归转换工作。接收端在关闭、丢弃或读取到终止之前保留订阅配额；保留接收端不等于创建了脱离请求的任务。Rust 调用方自行承担收到值之后的保留内存，来源存储与传输缓冲另有预算。

`runtime.operation.stream` 使用 `runtime.operation.invoke` 的输入字段，但 `output` 默认为 `stream`。`runtime.program.stream` 使用 `runtime.program.run` 的 Portable v1 source 和 input，各 Operation 自行选择输出模式。两者使用 `StreamCall.scope`、`justification`、`ttl_ms`，要求 MFA level 2，并执行与动作相同的全部导入预检。订阅成功会开始执行，因此丢失订阅确认后重试可能重复产生效果。这两种流不提供历史回放、恢复已有执行的连接或续传游标；结果不确定时通过保留的 Fact 和进程观察核对。

`runtime.describe.execution_modes` 以 `(mode, lifetime)` 唯一标识每种调用契约：

| 执行方式 | 生命周期 | 所有者 | 输出模式 |
| --- | --- | --- | --- |
| `call` | `host` | `request` | `unary`、`collect`、`sink_only` |
| `subscription` | `host` | `subscription` | `unary`、`collect`、`sink_only`、`stream` |
| `submission` | `host` | `service` | `unary`、`collect`、`sink_only`、`stream`、`async_process` |

每行同时提供 `entries`、`enabled` 和 `accepting`。未启用的契约仍然可发现；`enabled` 反映编译功能和宿主配置，`accepting` 还考虑提交服务的关闭状态。客户端按两个标识选择对应行，不依赖数组位置，也不自行组合独立的模式列表与生命周期列表。各行输出仍须满足已安装方法、权限及收集数量限制；发现不预留容量，也不承诺后续请求必然获准。动作描述符通过 `execution_mode` 定义公开完整字段。

流式 Program 可以组合 Unary、SinkOnly、有界 Collect 和 Stream，包括并行分支。单次调用与订阅执行共享 `max_concurrent_calls`，不能通过订阅绕过动作容量。

每个 Operation 的输出路由拥有独立的内核 `StreamWindow`。`[console.runtime]` 配置 `max_output_streams`（默认 16，最大 256）、`stream_window_chunks`（16，最大 4096）和 `stream_window_bytes`（262144，最大 4194304），零值拒绝启动。等待交付的端口仍占容量，超过端口上限会使该 Operation 失败。内核窗口按包含 taint 的无损 tagged JSON 计费，与 protobuf 事件上限独立。端口与调用方之间只保留一条排队事件、一条正在发送的事件，以及有界的终结槽。慢消费者对执行施加背压；WebSocket 自身队列饱和时还会关闭订阅。

执行 deadline 覆盖输出交付和进程收尾，并受 `ttl_ms` 约束。即使调用方不再读取，worker 到期也会释放执行容量。丢弃、取消订阅、过期、交付失败或授权失败会取消尚未完成的附着工作，清理沿用 `RequestProcess` 生命周期。正文返回后，在等待交付前将终态、来源及未决身份交接给 Kernel。随后排空失败或交付超时仍保留正文用于清理与有界错误投影，不将其替换为取消。工作者放弃时保留已经交接的清理证据，不保证向关闭的接收端交付。已提交效果不会回滚，取消 future 也不能执行异步 Finally。

protobuf `ConsoleEvent.runtime` 携带无损 Value，以 `kind` 区分事件；流描述符提供四个分支的 schema：

| `kind` | 字段 | 顺序 |
| --- | --- | --- |
| `started` | `process_id`、`program_id`、`budget` | 在执行输出之前 |
| `output` | `operation_id`、`value`、`taint` | 单个 Operation 内保持顺序，并行 Operation 可以交错 |
| `operation_finished` | `operation_id`、可空的安全 `failure`、`taint`、`origin` | 在该 Operation 全部数据之后；origin 为 `current_attempt` 或 `cached_outcome`，缓存终结不回放历史数据 |
| `finished` | `process_id`、`program_id`、`budget`、`outcome`、`value`、可空的安全 `failure`、`taint`、`unresolved_operations`、`finalization` | 在所有端口排空且请求收尾成功之后；outcome 为 `done`、`short` 或 `failed` |

标识符使用十进制字符串或内核 Operation ID 字符串，不需要客户端冒险转换为 JSON 浮点数。终结 sidecar 的完整 ID 计入 `max_event_bytes`；若事件超限，终止错误仍保留 sidecar，传输帧上限也须足以容纳该错误。保留的 Stream 日志终结条目仅提供数量和完整性摘要；完整 ID 通过 `runtime.execution.result` 查询。正常完成先交付已入队事件，再由 WebSocket 发出 `SubscriptionClosed`。超时、取消或传输丢失可能没有 `finished`；尤其订阅可见性 `ttl_ms` 到期后不再交付事件，即使带已知 `operation_ids` 的 Kernel 结果稍后到达。执行期限早于可见性 TTL 时，有界结算仍可能在可见性结束前交付终结结果。缺少终结事件不能证明没有产生效果。
