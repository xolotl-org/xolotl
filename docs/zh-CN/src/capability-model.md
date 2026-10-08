# 能力模型

授权范围从 `Grant` 开始，并在执行前编译成句柄。

## 路径

资源路径形态：

```text
<scheme>://[<segment>[/<segment>...]]
path://<cluster>/<scheme>[/<segment>...]
```

示例：

```text
effect://inference/infer
state://memory/alice/thread
process://alice
path://phone/effect/inference/infer
```

`path://` 形式显式指定 cluster；无此前缀的路径属于本地。cluster 参与路径相等、前缀与模式匹配。两种形式都允许应用自定义 scheme，但 `path` 保留为集群限定前缀。cluster 名可以与 scheme 同名，因为两者在 `path://<cluster>/<scheme>/...` 中的位置明确。

资源安装显式声明 `ResourceAddressing::Exact` 或 `Prefix`。Exact 仅解析已注册路径；Prefix 还解析同一 scheme 和 cluster 中的子路径，除非更近的注册项优先。资源类别和 scheme 不决定这种行为。授权始终按请求的完整路径检查。

操作选项应放在结构化输入值、显式资源段或策略/配置状态中。

本地与集群根路径都可以省略路径段。解析必须使用显式的 `://` 分隔符，不能使用仅靠 `/` 分隔的简写。

## 能力字面量

能力字面量使用动词型前缀：

```text
perform://effect/inference/infer
read://state/memory/alice/thread
write://state/kernel/config
perform://effect/events/subscribe
act-as://identity/alice
perform://path://phone/effect/inference/infer
read://path://*/state/memory/alice/**
read://device/lab/thermostat#sample
```

动词前缀和资源路径前缀是分开的。资源路径描述被操作的对象；能力字面量描述被授权的操作类别。可调用方法的 `perform`、`read`、`write`、`append`、`subscribe`、`publish` 可用于应用自定义 scheme；已安装的方法声明所需动词。`act-as` 指向 `identity://...` 身份，`spawn` 指向 `process://...` 资源。Acting 身份须是具体本地路径，进程路径不表示执行身份。

无 cluster 限定的能力**仅覆盖本地路径**，即使 scheme 或路径段带通配符。在能力字面量中，`path://phone/` 前缀只覆盖指定 cluster；`path://*/` 前缀覆盖任一集群路径，但不覆盖本地。只有规范根能力 `*://**` 同时覆盖本地与各集群路径。宿主仍可独立限制集群目标的访问。

在 `@` 谓词之前附加 `#<method>`，可按稳定方法名精确选择一个资源方法，例如 `perform://effect/app/echo#invoke` 或 `read://state/app/profile#load@account=alice`。没有 `#` 时，能力覆盖该动词与路径范围内的所有方法，但仍须符合方法声明的权限类别。方法名使用规范 UTF-8 百分号编码：ASCII 字母、数字、`-`、`_`、`.` 和 `~` 直接书写，其他字节使用大写 `%HH`（例如 `#read%2Fdetail`）。方法选择器没有通配语义；只指定了方法的能力不能用于缺少方法上下文的 `act-as` 等检查。

## 授权记录与权限

授权记录包含持有者进程、选择器、权限、约束和过期时间。选择器谓词与继承约束都按同一次操作的输入和时钟核验。源 Grant 使用稳定的方法名（或显式的 `all`）表示 `GrantMethods`，并携带委托等传播标志。打开请求与 Handle 使用资源内的方法位图。重新绑定资源即使改变方法顺序，也不会让按名称授权的旧 Grant 意外覆盖别的方法；`all` 则明确包含后来安装的方法。

选择器可以匹配精确路径或带通配符的路径段。派生或衰减授权范围时，请求的权限必须是父级权限的子集。

能力集合衰减同时比较 cluster 范围、路径语言和输入谓词。本地父能力不能派生集群子能力；指定集群的父能力不能派生其他集群或任意集群的子能力；任意集群的父能力只能派生指定集群的子能力，不能派生本地子能力。`*` 只匹配一个路径段，`**` 可匹配零个或多个；因此父级 `read://state/memory/*` 不能派生子级 `read://state/memory/**`。

父能力若限定方法，子能力必须保留同一方法；未限定方法的父能力可派生仅限某个方法的子能力。父级能力若有 `@account=alice` 之类输入谓词，子级必须保留相同谓词；无谓词的父级可以派生带谓词的更窄子级。`CapSet::intersect` 使用完整的 `Capability::covers_cap`，不会通过删去父级谓词获得权限。

结构覆盖判定偏保守，可能拒绝实际被包含的通配模式；需要此类组合时应声明更直接的父级选择器。`Capability::covers_cap_pattern` 只比较结构：Bootstrap 在继承路径另行保留父级谓词约束，Console 发现把这类权限标为 `predicate_bound`，实际调用仍按输入核验。单独的结构覆盖结果不授予调用权限。

`@until=<i64 Unix 毫秒>` 按当前墙上时钟限制能力有效期，截止毫秒仍有效。它只接受 `=` 及精确的有符号 64 位整数；格式错误或动态构造的非法 `until` 谓词均拒绝授权。

输入字段为整数时，阈值也必须是整数，并按整数精确比较，包括超过 `2^53` 的值；小数或越界阈值不能授权整数输入。浮点字段使用有限 `f64` 比较，`NaN` 和无穷大不能成为数值授权边界。缺失字段或类型不符同样拒绝授权。

## `open()`

`open()` 是控制路径编译器。它解析资源，选择覆盖请求的授权记录，检查打开时约束，解析绑定，构建驱动计划，编译剩余策略，并安装由进程持有的句柄。

之后数据路径针对句柄执行，不需要再次解析注册表。

打开后的 `DriverPlan` 同时保留全部原始方法声明及分派规则，包括请求权限以外的方法。`methods()` 和 `entry(id).declaration()` 可直接查看冻结接口，无需重新查询当前注册表。低层宿主可用 `insert` 添加没有声明的原生分派条目，或用 `insert_declared` 保留完整声明并从中生成分派规则。缺少声明的原生条目不能捕获为可移植授权。

嵌入宿主可通过 `prepare_open(&registry, request, attached_grants) -> PreparedOpen` 分开这两个阶段。准备过程不借用句柄表；返回的不可变结果可查看所有者、acting 身份、具体路径、权限、驱动契约和剩余策略。宿主能先核验或保存策略恢复描述，再分配句柄槽；丢弃计划不会创建句柄。

请求路径必须具体且解析到所选资源；通配目标在授权选择、策略回调和缓存写入之前返回 `OpenError::NonConcretePath`。授权选择器仍可使用路径模式。

`prepared.install(&handles)` 借用计划，在短暂的注册表版本保护下检查版本并安装。授权、策略或资源变化会使尚未安装的计划失效。安装不重新编译或求值剩余检查；静态策略使用准备时传入的时间，因此应在临近安装时准备。每次成功安装分配一个新槽。

低层宿主管理进程生命周期和附加授权。Bootstrap 与 Executor 在共享句柄表锁之外编译，再在安装时复核进程准入；受信任的 finalizer 和机器 cleanup 作用域仍按其专用规则准入。

宿主侧 `HandleTable` 是共享对象：克隆后仍操作相同的槽，公开操作自行管理同步。`get(id)` 返回独立快照，修改快照不会改写运行中的权限、驱动契约或策略；每次调用在准入时自行解析授权，保留快照不能使撤销后的新调用获准。

生命周期只属于槽位：`release` 停止自身使用并保留已有后代，`revoke` 使整个派生子树失效；没有另一个保留不可用驱动载荷的 `close` 状态。`HandleTable::derive` 原子检查父授权并安装衰减后的子句柄。

释放、撤销、所有者清理以及失败安装和批量回滚，都在解锁后销毁退出表的原生对象。驱动和策略可通过 `downgrade()` 保留 `WeakHandleTable`，避免与表构成循环所有权。

`Registry::new()` 最多保留 1024 个简单打开计划；`Registry::with_open_cache_capacity(entries)` 指定容量，零禁用缓存。带约束的 grant 和已安装策略源绕过缓存。淘汰不会使已准备或已安装的计划失效。缓存有效性、计量与释放规则归[Registry rustdoc](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-kernel/src/registry.rs)维护。

## 策略快照

策略源编译为 `PolicySnapshot`。打开时即可决定的条件被消去，依赖 Operation 输入、预算、限流、命令匹配、批准或其他运行时状态的检查保留为剩余检查。没有剩余检查时，Handle 标为 `Unconditional`，数据路径跳过该 Handle 的策略求值。

剩余检查按冻结的顺序运行，保留重复出现的有状态检查。权限、剩余策略与预算在当前调用的准入路径核对；Fact 不代替这些检查。句柄与原生检查属于当前宿主生命周期，新的宿主按安装的资源、策略与授权重新打开句柄。

## 持久限流

`RateLimitCheck::new(scope, maximum, window_millis, state)` 使用宿主指定的稳定账户作用域及 acting 身份记账。策略源可用 `OpenContext::resource_path` 建立按目标区分的账户，也可使用租户或 API 名称让多个目标共享额度；本地 Resource ID 不再作为持久账户键。作用域须非空白且不超过 512 个 UTF-8 字节，窗口必须为正数，零配额有效，错误配置直接拒绝。

状态位置为 `state://kernel/ratelimit/<scope-hash>/identity:<acting>`，哈希以固定域分隔完整作用域。v1 记录保存窗口长度和已准入时间戳。已有账户的窗口长度不能隐式修改，避免新窗口遗漏旧窗口已清除的历史；宿主需显式迁移状态或指定新的账户作用域。

损坏记录拒绝执行且不覆盖，多个实例通过 CAS 共享准入额度，时钟回退时保守保留未来时间戳。计数单位是策略求值，即使后续检查拒绝，也保留本次消耗；它不代表成功完成的 Operation 数。

## 协作锁

可选的 Standard 锁提供者将 `effect://lock/acquire` 与 `effect://lock/release` 暴露为 `invoke` 方法。取得操作接收锁名；成功时返回 `{ "acquired": true, "name": name, "token": token }`，已有持有者时返回 `acquired: false`、`token: null`。成功结果可直接作为释放输入。

释放必须携带 `name` 和 `token`，仅当原子比较并删除了该持有者的记录时返回 `true`。过期或已释放的 token 返回 `false`，不能删除后来的持有者，包括同一 Process 再次取得的锁。

每次成功取得锁都会生成新的随机 token。token 也包含取得操作的 Operation ID；State 提交结果不确定时，调用方可用**同一个 Operation ID**重试，以找回已提交的 token。取得操作可能已经持有锁却未拿到回执，新 Operation ID 不能认领这个持有者。

释放结果不确定时，可以带原 token 重试。随后返回 `false` 表示该 token 已不再持有锁；首次释放可能已经提交，也可能已有新持有者。调用方需要保留取得结果用于释放；这个提供者没有租约或自动过期机制。

具有 `state://kernel/locks/<name>` 读取权限的调用方可以观察锁记录。token 只用于并发所有权比较，不是保密的授权边界；释放仍需拥有 effect 方法权限。它不是外部资源的单调 fencing 编号，外部资源应自行拒绝过期持有者。
