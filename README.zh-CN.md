# Nexus

Nexus 是一个 AI 身份运行时：面向能力约束 effect、可恢复程序执行和可审计外部集成的微内核。

内核里唯一的主动实体是 `Process`。Process 持有编译后的能力句柄，对资源发起操作，在策略约束下通过 driver 执行，并把结果记录为 fact。文件、终端动作、模型、记忆、远端设备、长期状态和外部工具，都投影到同一套 `Resource / Interface / Driver` 模型里。

Default English documentation: [README.md](README.md)

## 当前状态

这个仓库是 Nexus runtime 与 gateway 的早期 Rust workspace。实现只跟随当前设计，不保留旧版兼容入口：

- resource path 不支持 `@param` 后缀，例如
  `effect://memory/recall@scope=user`；
- gRPC `GatewayService.Submit` 接收结构化 protobuf `Program`，不是 JSON 字符串；
- capability 字面量使用动词形式，例如
  `perform://effect/inference/infer`，不是 resource path。

## 架构

热路径保持很小：

```text
Process
  owns Handle
  issues Operation on Resource.method
  through DriverPlan
  under PolicySnapshot
  producing Outcome and Fact
```

运行时分成四个平面：

- Control plane：registry、命名、准入、policy 编译、binding 解析和 `open()` 句柄编译。
- Data plane：只围绕 `Process`、`Handle`、`Operation`、`Fact` 做固定成本执行。
- Extension plane：外部 provider、source、driver 和协议适配。
- Program plane：可恢复的 `Do<A>` 程序和执行图。

控制面负责解析和编译。数据面只执行已经编译好的对象。

## Workspace

| Crate | 职责 |
| --- | --- |
| `nexus-types` | 核心 ID、path、value、capability、operation、audit 类型。 |
| `nexus-graph` | 可恢复 `Do<A>` 程序 IR 和执行图编译器。 |
| `nexus-state` | State backend trait 与内存实现。 |
| `nexus-kernel` | Process、handle、registry、policy、executor、recovery、fact。 |
| `nexus-storage-redb` | 基于 redb 的持久 state 和 FactStore。 |
| `nexus-actors` | 标准 in-process driver 和 provider。 |
| `nexus-gateway` | 提交程序的共享 gateway 抽象。 |
| `nexus-gateway-grpc` | 使用 `nexus-proto` 的 gRPC `GatewayService` 适配器。 |
| `nexus-gateway-websocket` | WebSocket gateway 适配器。 |
| `nexus-gateway-mcp` | MCP server-side gateway 适配器。 |
| `nexus-proto` | Protobuf schema 和手工 vendored prost/tonic 绑定。 |
| `nexus-console` | Web console backend 的 HTTP 管理 gateway。 |
| `nexus-daemon` | 长期运行的宿主进程 `nexusd`。 |
| `nexus-sdk` | 嵌入和测试用便捷导出。 |
| `nexus-plan`, `nexus-sim` | 规划与仿真脚手架。 |

## 环境要求

- Rust 1.95 或更新版本。
- 匹配 stable toolchain 的 Cargo。
- 不需要本地安装 `protoc`。`nexus-proto` 已经带有 vendored prost/tonic Rust 绑定。

检查本地工具链：

```sh
cargo --version
```

## 构建与测试

```sh
cargo fmt --all
cargo check --workspace
cargo test --workspace
```

构建 daemon：

```sh
cargo build -p nexus-daemon
```

## 运行 `nexusd`

创建本地配置：

```sh
cp nexus.toml.example nexus.toml
```

启动 daemon：

```sh
cargo run -p nexus-daemon -- up
```

`nexusd` 只负责启动宿主进程。运行时管理由 console gateway 处理，不通过 daemon 子命令完成。

`nexus.toml.example` 默认地址：

- Console HTTP：`127.0.0.1:9000`
- gRPC gateway：`127.0.0.1:9100`
- WebSocket gateway：`127.0.0.1:9200`

首次启动时，如果 state 中没有 console root 账号，也没有配置预置凭据，`nexusd` 会把一次性 root 密码打印到 stderr。

## 配置

`nexus.toml` 只用于 bootstrap 配置，控制存储和 gateway 监听地址：

- `[storage]`：`redb` 持久存储或内存存储。
- `[server]`：console、gRPC、WebSocket 绑定地址。
- `[console.root]`：可选的预置 root 凭据。

运行时配置、provider 设置、模型路由、组、binding 和 policy 管理的状态，都属于 Nexus state，通过 console gateway 管理。

## 外部接口

### Console

`nexus-console` 暴露管理域 HTTP gateway：

- `GET /health`
- `POST /api/auth/login`
- `POST /api/auth/key/challenge`
- `POST /api/auth/key/login`
- `POST /api/auth/logout`
- `GET /api/inspect?path=...`
- `GET /api/inspect?path=...&prefix=true`
- `POST /api/config`

Console 操作仍然走 capability-bound 管理路径。Console 不是特权后门。

### gRPC 和 Proto

主要的外部程序提交 API 是
`crates/nexus-proto/proto/nexus/v1/gateway.proto` 里的 `GatewayService`。

```proto
service GatewayService {
  rpc Submit(SubmitRequest) returns (SubmitResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
}
```

`SubmitRequest.program` 是结构化 protobuf `Program`。它不是 JSON blob，也没有 `program_json` 兼容字段。

`nexus-proto` 是 Rust gateway 和移动端 Kotlin/Swift 等生成客户端的 wire schema 源头。

### WebSocket

`nexus-gateway-websocket` 提供 `/ws`，把 WebSocket frame 适配到共享 gateway 抽象。它和其它 gateway 一样走 request process、taint、policy、fact、handle 路径。

### MCP

`nexus-gateway-mcp` 只在每个 tool 绑定显式 required capability 后，才把选定 Nexus effect 暴露为 MCP tool。MCP call 会翻译成普通 gateway submission。

## Path 和 Capability 规则

Resource path 形态：

```text
path://[cluster/]<scheme>/<segment>[/<segment>...]
```

示例：

```text
effect://inference/infer
state://memory/alice/thread
process://alice
```

Capability 字面量使用动词 scheme：

```text
perform://effect/inference/infer
read://state/memory/alice/thread
write://state/kernel/config
```

Path 参数会被拒绝。需要参数时使用结构化 value、显式 resource segment 或 policy/config state，不使用 `@param` 后缀。

## 开发约束

- 解析、发现、policy source、schema 处理留在 control plane。
- Data plane 只处理编译后的 ID、handle、driver plan、policy snapshot、operation、outcome 和 fact。
- 外部协议 crate 应保持为 `nexus-gateway` 或 kernel extension 原语之上的薄适配层。
- 破坏性设计变更需要同步更新 proto、vendored binding、conversion、测试和文档。

## License

MIT。见 [LICENSE](LICENSE)。
