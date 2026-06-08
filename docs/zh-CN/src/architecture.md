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

运行时分成四个平面。

## 控制平面

控制平面负责解析、校验、名称解析和编译。它拥有注册表、资源命名、准入检查、策略编译、绑定解析，以及 `open()` 句柄编译。

关键规则是：路径解析和注册表遍历发生在数据平面之前。进程拥有句柄之后，数据平面就可以只依赖已编译的 ID、权限位图、驱动计划和策略快照执行。

## 数据平面

数据平面通过已编译的句柄执行一个操作。它检查所有者、句柄存活状态、权限、必要时的剩余策略，随后分派驱动计划，并在操作需要持久记录时写入事实记录。

数据平面不解析路径，不遍历注册表，也不解析绑定。

## 扩展平面

扩展平面把外部系统投影到同一个运行时模型中。提供方通过驱动或远端绑定暴露 `effect://...` 资源。来源把入站事件写入声明的状态流。协议相关适配器应保持很薄，只把传输层内容翻译到共享运行时模型。

## 程序平面

程序平面表示可持久执行的工作。`DoNode` 是可执行程序形态；计划文档和结构化 protobuf `Program` 提交都会转换为 `DoNode`。执行器把 `DoNode` 编译为 `ExecutionGraph`，推进图节点，发出操作，运行命名的纯步骤，并在恢复时使用已记录的事实记录继续执行。

## 工作区映射

| Rust 包 | 职责 |
| --- | --- |
| `nexus-types` | 核心 ID、路径、值、能力、操作、审计、跟踪、扩展和进程数据。 |
| `nexus-graph` | `DoNode`、`ExecutionGraph`、图编译器、游标和行为体检查。 |
| `nexus-state` | 状态后端 trait（特征）和内存实现。 |
| `nexus-kernel` | 注册表、策略、句柄表、数据平面、执行器、进程表、恢复和引导。 |
| `nexus-storage-redb` | 基于 redb 的状态和事实记录存储。 |
| `nexus-actors` | 标准进程内驱动和提供方。 |
| `nexus-gateway` | 共享网关 trait（特征）和进程内请求网关。 |
| `nexus-gateway-grpc` | 基于共享网关的 gRPC 适配器。 |
| `nexus-gateway-websocket` | 程序提交 WebSocket 适配器。 |
| `nexus-gateway-mcp` | MCP 服务端网关适配器。 |
| `nexus-proto` | Protobuf 模式定义和随仓库提供的 Rust 绑定。 |
| `nexus-console` | Web 控制台后端的管理域网关。 |
| `nexus-daemon` | 长期运行的宿主进程 `nexusd`。 |
| `nexus-sdk` | 嵌入式门面和公开重导出。 |
| `nexus-plan` | 计划文档解析和转换。 |
| `nexus-sim` | 确定性仿真和重放辅助工具。 |
