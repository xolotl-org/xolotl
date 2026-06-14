# 架构

Nexus 让执行热路径保持很小：

```text
进程持有句柄，
对资源方法发起操作，
通过驱动计划执行，
遵守策略快照，
产出结果和事实记录。
```

这些中文术语分别对应代码中的 `Process`、`Handle`、`Resource.method`、`Operation`、`DriverPlan`、`PolicySnapshot`、`Outcome` 和 `Fact`。

运行时分成四类代码路径。

## 控制路径

控制路径负责解析、校验、名称解析和编译。它拥有注册表、资源命名、准入检查、策略编译、绑定解析，以及 `open()` 句柄编译。

关键规则是：路径解析和注册表遍历发生在执行之前。进程拥有句柄之后，执行路径就可以只依赖已编译的 ID、权限位图、驱动计划和策略快照。

## 数据路径

数据路径通过已编译的句柄执行一个操作。它检查所有者、句柄存活状态、权限、必要时的剩余策略，随后分派驱动计划，并在操作需要持久记录时写入事实记录。

数据路径不解析路径，不遍历注册表，也不解析绑定。

## 外部适配

外部适配把外部系统投影到同一个运行时模型中。Provider 通过驱动或远端绑定暴露 `effect://...` 资源。Source 把入站事件写入声明的状态流。gRPC 和 WebSocket 是同一个 Provider/Source gateway 的两种传输实现。

## 程序执行

程序执行表示可持久执行的工作。`DoNode` 是可执行程序形态；计划文档和结构化 protobuf `Program` 值都会转换为 `DoNode`。执行器把 `DoNode` 编译为 `ExecutionGraph`，推进图节点，发出操作，运行命名的纯步骤，并在恢复时使用已记录的事实记录继续执行。

## 工作区映射

| Rust 包 | 职责 |
| --- | --- |
| `nexus-types` | 核心 ID、路径、值、能力、操作、审计、跟踪、外接和进程数据。 |
| `nexus-graph` | `DoNode`、`ExecutionGraph`、图编译器、游标和行为体检查。 |
| `nexus-state` | 状态后端 trait（特征）和内存实现。 |
| `nexus-kernel` | 注册表、策略、句柄表、执行路径、执行器、进程表、恢复和引导。 |
| `nexus-storage-redb` | 基于 redb 的状态和事实记录存储。 |
| `nexus-actors` | 标准进程内驱动和提供方。 |
| `nexus-gateway` | external 协议适配器共享的 session 准入、流控、taint 和 audit 代码。 |
| `nexus-gateway-grpc` | External Provider/Source gRPC 适配器。 |
| `nexus-gateway-websocket` | External Provider/Source WebSocket 适配器。 |
| `nexus-gateway-mcp` | 把选定 Nexus effect 暴露为 MCP tool 的服务端适配器。 |
| `nexus-proto` | Protobuf 模式定义和随仓库提供的 Rust 绑定。 |
| `nexus-console` | Web 控制台管理动作的 gateway。 |
| `nexus-daemon` | 长期运行的宿主进程 `nexusd`。 |
| `nexus-sdk` | 嵌入式门面和公开重导出。 |
| `nexus-plan` | 计划文档解析和转换。 |
| `nexus-sim` | 确定性仿真和重放辅助工具。 |
