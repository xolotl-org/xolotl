# 网关

本页是 `nexusd` 的接入口总览，用来判断客户端应该连接哪个监听地址和协议。
具体协议契约拆在独立页面：

- [程序网关](program-gateways.md)：外部客户端通过 gRPC、WebSocket 或 MCP
  适配器提交 `Program` 或 `DoNode` 工作。
- [控制台协议](console-protocol.md)：控制台客户端通过 HTTP 认证，再通过控制台
  WebSocket 执行管理动作和订阅。

## 接入口

当 `[server]` 中的配置字段存在，或对应环境变量存在时，`nexusd` 会启动该通道。
`nexus.toml.example` 默认配置了下列三个监听地址。gRPC 监听地址需要
`nexus-daemon` 的 `grpc` feature；默认构建已启用该 feature。

| 接口 | 配置字段 | 环境变量 | 路径或服务 | 编码 |
| --- | --- | --- | --- | --- |
| 控制台 HTTP | `console_addr` | `NEXUS_CONSOLE_ADDR` | `/health`、`/api/auth/*` | HTTP JSON |
| 控制台 WebSocket | `console_addr` | `NEXUS_CONSOLE_ADDR` | `/ws` | MessagePack，`msgpack+nexus-console-v1` |
| 程序 gRPC | `grpc_addr` | `NEXUS_GRPC_ADDR` | `nexus.v1.GatewayService` | Protobuf |
| 程序 WebSocket | `ws_addr` | `NEXUS_WS_ADDR` | `/ws` | 文本 JSON |

控制台 WebSocket 和程序 WebSocket 都挂在 `/ws`，需要通过监听地址和帧编码区分：

- 控制台 WebSocket 使用 `[server].console_addr` 和二进制 MessagePack 帧。
- 程序 WebSocket 使用 `[server].ws_addr` 和文本 JSON 帧。

## 如何选择接口

| 需求 | 接口 |
| --- | --- |
| 执行管理动作、检查运行时状态、管理用户、管理会话、订阅状态或审计流 | 控制台协议 |
| 从跨语言客户端提交结构化程序 | 程序 gRPC |
| 从 Rust 侧工具或仓库内测试提交 JSON `DoNode` | 程序 WebSocket |
| 把选定 Nexus 效果发布为带显式必需能力的 MCP 工具 | MCP 网关 |

## 请求边界

程序网关使用共享 `Gateway` trait（特征）：

1. 校验客户端提交的令牌；
2. 把令牌映射为请求身份，例如 `process://alice`；
3. 创建已衰减授权的请求进程；
4. 把协议载荷转换为 `DoNode` 程序；
5. 通过执行器运行程序并返回 `Outcome`。

宿主在构建 `InProcessGateway` 时声明请求可达的能力，并为请求进程打开需要暴露的资源句柄。网络适配器负责传输、认证帧解析、结构转换和网关审计标签。

控制台协议使用 `nexus-console`。HTTP 只承担健康检查和认证。登录后的管理路径使用控制台 WebSocket，通过有描述符名称的动作和流进行调用；授权、CAS、可见性门槛和审计记录仍由运行时路径处理。

## 扩展接入

扩展由一个安装声明加一个或多个投影声明。Provider 投影通过远端绑定暴露效果处理器。Source 投影把入站事件写入声明的状态流。配对、凭据生成、撤销下限、会话上下文和业务帧都表示为 `nexus-types` 与 `nexus-proto` 中的类型化数据。

敏感值限制在一次性展示边界；操作输入、状态、事实记录和跟踪只接收脱敏元数据或引用。
