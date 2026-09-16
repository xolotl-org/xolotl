# 程序与重放

Xolotl 通过同一核心状态机执行 portable 程序与现有执行图。本页描述原生组合和 Fact 恢复诊断；
portable 完整检查点恢复见[核心与可移植程序](core-and-portable.md)。

## 程序入口形态

已有图入口形态是 `DoNode`。它支持纯值、操作、命名步骤、分支、汇合、身份切换、等待、失败和结构化组合。

计划文档由 `xolotl-plan` 解析，并转换为同样的 `DoNode` 形态。`xolotl-proto` 中的结构化 protobuf `Program` 类型是同一可执行形态的线缆表示，并可无损转换为 `DoNode`。

## 执行图

执行器把 `DoNode` 程序编译为 `ExecutionGraph`。节点 ID 在已编译图内保持稳定，表示源码位置，
不能单独标识动态调用。`OperationId` 使用 `process/execution/invocation/position/attempt`，
其中调用序号来自核心的 64 位请求 ticket。独立求值和终结器取得新的执行作用域；
检查点恢复保留原作用域和 ticket。

## 步骤

步骤是组装到 `StepModule` 中的命名纯延续。`StepRef::new(name)` 只携带名称和可选参数，
不包含进程编号。执行器仅从自己的不可变模块解析名称，将管道值与参数传入函数，并把返回的子图追加到
核心指令镜像。名称缺失会在当前进程失败，不会回退到父进程或其他进程查找。

`StepModule::single` 定义一个函数，`StepModule::new` 接收一组 `StepBinding`，
`StepModule::compose` 在同一命名空间组合多个模块并拒绝重名。空名称在装配时拒绝。
模块克隆共享名称表与函数，空模块不分配内存。调用时直接借用函数，不获取注册表锁，
也不更新函数的引用计数。

同一模块可以复用于独立执行器、普通请求和 Actor：

| 宿主场景 | 入口 |
| --- | --- |
| 显式调用方与宿主适配器 | `Executor::new(...).with_steps(module)` |
| SDK 图请求 | `Xolotl::run_with_steps(resources, program, module)` |
| SDK Plan 请求 | `Xolotl::run_plan_with_steps(resources, plan, module)` |
| 已有进程下的请求 | `Bootstrap::spawn_request_process_under_with_steps(...)` |
| Actor body 与终结器 | `Xolotl::spawn_actor_with_steps(..., module)` |

执行器持有固定模块快照，`with_steps` 只覆盖该执行器。进程在终结器执行完后释放自己的
模块引用，其他持有者仍可使用模块；附着到该进程的旧执行器会在进程终结后停止执行。
独立执行器需要通过 `with_processes` 接入宿主要求的进程生命周期检查。模块不携带 grant，
每个操作仍使用调用请求自己的权限。
SDK 的一次性请求入口由执行 Future 持有模块，丢弃 Future 会释放其中的原生函数引用。
普通请求立即取消请求树，runtime 存在时安排一次清理尝试；`drain_cleanup` 可以继续
保留的进程终结器与生命周期记录。丢弃执行无法继续程序自身异步 `Finally` 的内容。

返回子图中的嵌套延续、恢复和终结器沿用同一名称解析规则。结构化操作目标和信号路径中的
`state://process/self/...` 会在子图编译前绑定到调用进程。绑定会消费子图并原地修改路径，
保留载荷和 AST 的已有分配，不把普通字符串或 Step 参数解释成路径。
请求授权模板中的 `self` 也会在检查父进程权限上限前绑定，并保留谓词与方法限制。

`xolotl_plan::compile(&plan)` 也无需指定进程；SDK 的 `plan` feature 将其导出为
`compile_plan`。Actor 准入会检查静态 body 和终结器引用的名称。仅在动态子图中出现的
函数也需要宿主预先安装，其名称在子图执行时解析。

I/O 和其它效果通过操作节点发生。可运行模块组合示例：

```sh
cargo run -p xolotl-sdk --features host --example native_modules
```

## 重放类别

方法纯度派生内核强制执行的重放类别：

| 纯度 | 重放行为 |
| --- | --- |
| `Pure` / `Deterministic` | 安全时可重新计算或重新读取 |
| `Observation` | 在被消费时记录观察到的外部值或持久值 |
| `IdempotentEffect` | 可通过有效幂等键去重 |
| `NonIdempotentEffect` | 发出效果前必须先写入预备记录 |

事实流记录效果历史。`recover_process` 分类已完成和待完成记录，返回诊断及隔离项，
不会执行程序。Fact 无法还原原生延续、竞争分支结果、外部载荷或精确的输出来源信息。
`ReplayMap` 和 `with_replay` 已移除，恢复执行使用完整 portable 检查点。

默认幂等键包含完整操作身份。业务 `_idem_key` 按约定跨执行和显式重试去重，仍使用
acting 身份与源码位置作为命名空间。宿主需要使用业务专属键，区分位于同一位置的无关程序或操作。

## 仿真

`xolotl-sim` 提供确定性测试辅助工具：`ScriptedDriver`、`FixedClock`、`SimClock`、`CrashAfter`、`why_not` 和 `replay_report`。用它断言程序和驱动在崩溃/重放边界上的行为可预测。
