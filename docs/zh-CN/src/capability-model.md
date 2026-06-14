# 能力模型

授权范围从 `Grant` 开始，并在执行前编译成句柄。

## 路径

资源路径形态：

```text
path://[cluster/]<scheme>/<segment>[/<segment>...]
```

示例：

```text
effect://inference/infer
state://memory/alice/thread
process://alice
```

路径语法包含 scheme、可选 cluster 和路径段。操作选项应放在结构化输入值、显式资源段或策略/配置状态中。

## 能力字面量

能力字面量使用动词型前缀：

```text
perform://effect/inference/infer
read://state/memory/alice/thread
write://state/kernel/config
perform://effect/events/subscribe
act-as://process/alice
```

动词前缀和资源路径前缀是分开的。资源路径描述被操作的对象；能力字面量描述被授权的操作类别。

## 授权记录与权限

授权记录包含持有者进程、选择器、权限、约束和过期时间。权限由方法位图和委托等传播标志组成。

选择器可以匹配精确路径或带通配符的路径段。派生或衰减授权范围时，请求的权限必须是父级权限的子集。

## `open()`

`open()` 是控制路径编译器。它解析资源，选择覆盖请求的授权记录，检查打开时约束，解析绑定，构建驱动计划，编译剩余策略，并安装由进程持有的句柄。

之后数据路径针对句柄执行，不需要再次解析注册表。

## 策略快照

策略源会编译为 `PolicySnapshot`。能在打开时决定的内容会被消除；依赖操作输入、预算、速率限制、命令匹配、审批或其它运行时状态的检查会保留为剩余检查。

如果没有剩余检查，句柄会标记为 `Unconditional`，数据路径会跳过该句柄的策略求值。
