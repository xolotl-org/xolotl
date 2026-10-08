# 程序与重放

Xolotl 通过同一个核心机器执行可移植程序和现有图。本页说明原生组合、效果类别及业务幂等；可移植执行见[核心与可移植程序](core-and-portable.md)。

## 程序入口形态

图入口形态为 `DoNode`，支持纯值、操作、命名步骤、分支、汇合、身份切换、等待、失败和结构化组合。

计划文档由 `xolotl-plan` 解析，并转换为同样的 `DoNode` 形态。`xolotl-proto` 中的结构化 protobuf `Program` 类型是同一可执行形态的线缆表示，并可无损转换为 `DoNode`。

Plan 步骤列表按文档顺序执行，只有显式 `Parallel` 与 `Race` 引入并发。`Let` 与 `Read.as` 将前序值计算绑定到当前列表的剩余步骤，后续绑定可以遮蔽同名绑定。分支、`Acting` body 与 `Bracket` body 继承外层绑定，但不导出局部名称；兄弟分支不能访问彼此的绑定。`Bracket` 在 body 中以 `_resource` 暴露取得的值，即使 body 遮蔽该名称，release 仍接收原来取得的值。

`Then` 与 `OnFail` 修改前序计算，不作用于后续步骤。紧跟 `Let` 或 `Read` 的修饰步骤属于绑定的生产者，因此后续 `Use` 取得其成功或恢复后的结果。修饰步骤不能位于列表开头。lowering 拒绝未绑定的 `Use` 名称。JSON 输入、值与参数都是字面数据；`${name}` 等字符串不进行插值，也不表示依赖关系。

原生图编译使用显式帧，在分配图存储或克隆载荷前预检节点总数与源码位置边界，不再设置仅为递归调用栈限制的独立 256 层嵌套上限。Plan 和 portable 的源深度限额、解码器限额仍属于独立准入合同。protobuf 树最多接受 48 层，因为每层还有包装消息，需留在 Prost 的 100 层解码上限内。`program_to_pb` 与 `program_from_pb` 也会把嵌套值计入剩余消息预算，拒绝无法解码的树。本地 Plan 与 SDK 直接编译 `DoNode`，不经过 protobuf，因此线缆上限不限制本地组合。

## 执行图

执行器把 `DoNode` 程序编译为 `ExecutionGraph`。节点 ID 在已编译图内保持稳定，表示源码位置，不能单独标识动态调用。`OperationId` 使用 `process/execution/invocation/position/attempt`，其中调用序号来自核心的 64 位请求 ticket。独立求值和终结器取得新的执行作用域。

## 步骤

步骤是组装到 `StepModule` 中的命名纯延续。`StepRef::new(name)` 只携带名称和可选参数，不包含进程编号。执行器仅从自己的不可变模块解析名称，将管道值与参数传入函数，并把返回的子图追加到核心指令镜像。名称缺失会在当前进程失败，不会回退到父进程或其他进程查找。

`StepModule::single` 定义一个函数，`StepModule::new` 接收一组 `StepBinding`，`StepModule::compose` 在同一命名空间组合多个模块并拒绝重名。空名称在装配时拒绝。模块克隆共享名称表与函数，空模块不分配内存。调用时直接借用函数，不获取注册表锁，也不更新函数的引用计数。

同一模块可以复用于独立执行器、普通请求和 Actor：

| 宿主场景 | 入口 |
| --- | --- |
| 显式身份的独立执行器 | `Executor::new(process, identity, data_plane, registry)?.with_steps(module)` |
| 使用 Kernel 进程表身份和生命周期的执行器 | `Executor::from_process_table(process, processes, data_plane, registry)?.with_steps(module)` |
| SDK 图请求 | `Xolotl::run_with_steps(identity, resources, program, module)` |
| SDK Plan 请求 | `Xolotl::run_plan_with_steps(identity, resources, plan, module)` |
| 已有进程下的请求 | `Bootstrap::spawn_request_process_under_with_steps(...)` |
| Actor body 与终结器 | `Xolotl::spawn_actor_with_steps(..., module)` |

执行器持有固定模块快照，`with_steps` 只覆盖该执行器。进程在终结器执行完后释放自己的模块引用，其他持有者仍可使用模块；附着到该进程的旧执行器会在进程终结后停止执行。独立执行器要求宿主显式提供身份并管理进程生命周期；需要进程表检查时使用 `from_process_table`。模块不携带 grant，每个操作使用调用请求自己的权限。SDK 的一次性请求入口由执行 Future 持有模块，丢弃 Future 会释放其中的原生函数引用。普通请求立即取消请求树，runtime 存在时安排一次清理尝试；`drain_cleanup` 可以继续保留的进程终结器与生命周期记录。丢弃执行无法继续程序自身异步 `Finally` 的内容。

返回子图中的嵌套延续和终结器沿用同一名称解析规则。结构化操作目标和信号路径中的 `state://process/self/...` 会在子图编译前绑定到调用进程。绑定会消费子图并原地修改路径，保留载荷和 AST 的已有分配，不把普通字符串或 Step 参数解释成路径。请求授权模板中的 `self` 也会在检查父进程权限上限前绑定，并保留谓词与方法限制。

`xolotl_plan::compile(&plan)` 也无需指定进程；SDK 的 `plan` feature 将其导出为 `compile_plan`。Actor 准入会检查静态 body 和终结器引用的名称。仅在动态子图中出现的函数也需要宿主预先安装，其名称在子图执行时解析。

I/O 和其它效果通过操作节点发生。可运行模块组合示例：

```sh
cargo run -p xolotl-sdk --features memory --example native_modules
```

## 重放类别

方法 purity 描述效果类别，供宿主判断结果未知与重试风险：

| Purity | 调用含义 |
| --- | --- |
| `Pure` / `Deterministic` | 纯计算或确定性操作，是否重算仍由调用方决定。 |
| `Observation` | 读取外部状态；重读可能观察到不同值。 |
| `IdempotentEffect` | 可在方法约定的幂等键范围内去重。 |
| `NonIdempotentEffect` | 重发可能产生第二次效果；结果未知时先核对原调用。 |

这些类别不自动重试，也不要求先提交审计记录。Fact 是可选诊断数据；权限、额度和业务数据提交由各自合同保护。

默认幂等键包含完整操作身份。业务 `_idem_key` 可跨执行和显式重试，在 acting 身份和源位置的命名空间内复用。应用应为不同业务操作选择不同键，避免同一位置的不相关调用相互去重。

## 仿真

`xolotl-sim` 提供虚拟时间、故障注入驱动和 `why_not` 投影。用它验证程序、权限与驱动在可控调度和故障条件下的可观察行为。`Sim::new` 是默认关闭观察的内存宿主；需要记录时显式配置带 Fact sink 的 `Sim::boot`，并在 Executor 上选择记录。仅安装存储不会启用记录。
