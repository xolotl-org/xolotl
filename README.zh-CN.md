# Nexus

Nexus 是面向模型应用的能力运行时。它把模型推理、工具调用、记忆、状态和外部系统映射为
`effect://` 与 `state://` 资源。程序通过 `open()` 编译出的句柄访问这些资源。模型后端、工具进程、状态存储和外部程序分别位于资源绑定、driver 或
Provider/Source projection 后面。

Nexus 负责模型调用、工具执行、长期状态和外部协议之间的执行边界。模型训练、应用界面和业务逻辑在运行时外部。所有访问都经过同一套 `Resource / Interface / Driver`、`open()` 句柄和能力检查路径。

英文默认文档：[README.md](README.md)

## 已实现功能

- 模型执行：`effect://inference/*` 支持推理、嵌入、重排和计划；模型路由按能力、模态、组策略、重试和回退选择后端。
- 工具接入：MCP 工具、文件、终端、网络抓取、时间、事件、锁、blob、tensor、审批和压缩都注册为 effect 资源。
- 记忆与上下文：记忆驱动结合状态后端、向量索引和重排器；上下文组装和压缩是独立 effect。
- 外部程序：外部程序通过 external gateway 以 Provider 或 Source projection 接入。
- 能力边界：`open()` 把资源路径、授权、策略和绑定编译为进程持有的句柄；派生进程只能获得衰减权限。
- 程序执行：Rust `DoNode`、Plan 文档和 protobuf `Program` AST 都会落到同一个执行图，由同一个执行器推进。

## 当前状态

核心运行时和 external Provider/Source gateway 已经实现。Nexus 还没有发布第一版，当前 gateway/config/protobuf 契约由 external Provider/Source 模型定义。

外部接入只有一套角色模型：

- Provider projection 暴露远端 effect handler。
- Source projection 发送入站事件，也可以接收 outbound command。
- gRPC 和 WebSocket 是同一个 external Provider/Source gateway 的两种传输实现。

MCP 把选定 Nexus effect 暴露为 MCP tool。它不创建新的外部角色。

## 文档

构建公开手册：

```sh
cargo install mdbook
mdbook build docs
mdbook build docs/zh-CN
```

- 中文手册：[docs/zh-CN/src/README.md](docs/zh-CN/src/README.md)
- 英文手册：[docs/src/README.md](docs/src/README.md)

本地预览可运行 `mdbook serve docs/zh-CN` 或 `mdbook serve docs`。
中文手册的统一译名见 [docs/zh-CN/src/glossary.md](docs/zh-CN/src/glossary.md)。

生成 Rust API 文档：

```sh
RUSTDOCFLAGS='-W missing-docs' cargo doc --workspace --no-deps
```

Rustdoc 输出在 `target/doc/index.html`。

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

这些行对应代码中的 `Process`、`Handle`、`Resource.method`、`Operation`、`DriverPlan`、`PolicySnapshot`、`Outcome` 和 `Fact`。

运行时分成四类代码路径：

- 控制路径：注册表、命名、准入、策略编译、绑定解析和 `open()` 句柄编译。
- 数据路径：围绕 `Process`、`Handle`、`Operation` 和 `Fact` 做固定成本执行。
- 外部适配：Provider、Source、driver 和协议适配器。
- 程序执行：可恢复的 `Do<A>` 程序和执行图。

## 工作区

| Rust 包 | 职责 |
| --- | --- |
| `nexus-types` | 核心 ID、路径、值、能力、操作、审计类型和 external Provider/Source 数据。 |
| `nexus-graph` | 可恢复 `Do<A>` 程序中间表示和执行图编译器。 |
| `nexus-state` | 状态后端 trait 与内存实现。 |
| `nexus-kernel` | 进程、句柄、注册表、策略、执行器、恢复、事实记录。 |
| `nexus-storage-redb` | 基于 redb 的持久状态和 `FactStore`。 |
| `nexus-actors` | 标准进程内 driver 和 Provider。 |
| `nexus-gateway` | external 协议适配器共享的 session 准入、流控、taint 和 audit 代码。 |
| `nexus-gateway-grpc` | 使用 `nexus-proto` 的 external Provider/Source gRPC 适配器。 |
| `nexus-gateway-websocket` | external Provider/Source WebSocket 适配器。 |
| `nexus-gateway-mcp` | 把选定 Nexus effect 暴露为 MCP tool 的服务端适配器。 |
| `nexus-proto` | Protobuf schema 和随仓库提供的 prost/tonic 绑定。 |
| `nexus-console` | Web 控制台管理动作的 gateway。 |
| `nexus-daemon` | 长期运行的宿主进程 `nexusd`。 |
| `nexus-sdk` | 嵌入和测试用便捷导出。 |
| `nexus-plan`, `nexus-sim` | 规划与仿真 crate。 |

## 环境要求

- Rust 1.95 或更新版本。
- 与稳定版工具链匹配的 Cargo。
- 不需要本地安装 `protoc`。`nexus-proto` 已包含随仓库提供的 prost/tonic Rust 绑定。

## 构建与测试

```sh
cargo fmt --all
cargo check --workspace
cargo test --workspace
```

构建守护进程：

```sh
cargo build -p nexus-daemon
```

## 运行 `nexusd`

创建本地配置：

```sh
cp nexus.toml.example nexus.toml
```

启动守护进程：

```sh
cargo run -p nexus-daemon -- up
```

`nexusd` 只启动宿主进程；运行时管理通过 Console WebSocket 执行。

`nexus.toml.example` 默认地址：

- 控制台监听地址：`127.0.0.1:9000`
- External gRPC gateway：`127.0.0.1:9444`
- External WebSocket gateway：`127.0.0.1:9200`

`nexus-daemon` 默认启用 `external-grpc` 和 `external-websocket`。可以用
`--no-default-features --features external-grpc` 或
`--no-default-features --features external-websocket` 只构建其中一种
transport。

首次启动时，如果状态中没有控制台 root 账号，也没有配置预置凭据，`nexusd` 会把一次性 root 密码打印到 stderr。

## 配置

`nexus.toml` 是引导配置。它控制存储、监听绑定地址、root 引导凭据、external gateway 限制、gateway 传输安全设置和控制台资源上限。

- `[server]`：控制台、external gRPC 和 external WebSocket 绑定地址。
- `[external_gateway.grpc]`：external gRPC 的 Provider/Source session 限制。
- `[external_gateway.grpc.transport_security]`：external gRPC 传输边界。
- `[external_gateway.websocket]`：external WebSocket 的 Provider/Source session 限制。
- `[external_gateway.websocket.transport]`：WebSocket frame、idle、first-frame 和连接数限制。
- `[external_gateway.websocket.transport_security]`：external WebSocket plain listener 传输边界。
- `[console.*]`：控制台 root 凭据、认证/会话限制、WebSocket 限制和传输安全。

运行时配置、Provider 设置、模型路由、组、绑定、外部程序安装、Provider projection、Source projection 和策略管理状态都属于 Nexus state，并通过 Console WebSocket 管理。

## 外部接口

详细接入说明见 [网关](docs/zh-CN/src/gateways.md)、[External Gateway](docs/zh-CN/src/external-gateway.md) 和[控制台协议](docs/zh-CN/src/console-protocol.md)。

### 控制台

`nexus-console` 是 Web 控制台管理动作的 gateway。HTTP 负责健康检查和认证；登录后，Console WebSocket 承载快照、配置读取/写入/CAS、运行时检查、订阅、trace/fact stream、外部程序生命周期动作、配对动作、登出和控制台用户/角色/会话管理。

### External Gateway

外部程序以 Provider 或 Source projection 接入。daemon 持有 session 准入、generation 检查、流控、去重、command idempotency 和入站污点标记。

External gRPC 通过 `[server].external_grpc_addr` 或 `NEXUS_EXTERNAL_GRPC_ADDR` 提供 Provider/Source session stream。

External WebSocket 通过 `[server].external_websocket_addr` 或 `NEXUS_EXTERNAL_WEBSOCKET_ADDR` 提供同一套 Provider/Source session frame。

控制状态使用这些前缀：

```text
state://kernel/external-installations/<installation_id>
state://kernel/external-projections/<installation_id>/<projection_id>
state://kernel/external-pairings/<pairing_id>
state://kernel/external-sessions/<installation_id>/<role>
state://kernel/external-credential-revocations/<installation_id>
```

### MCP

`nexus-gateway-mcp` 只在对应 effect resource 拥有显式 publish capability 时，把选定 Nexus effect 暴露为 MCP tool。MCP 调用会转换为标准能力约束操作。

## 路径与能力规则

资源路径格式：

```text
path://[cluster/]<scheme>/<segment>[/<segment>...]
```

示例：

```text
effect://inference/infer
state://memory/alice/thread
process://alice
```

能力字面量使用动词 scheme：

```text
perform://effect/inference/infer
read://state/memory/alice/thread
write://state/kernel/config
```

路径参数会被拒绝。选项应放进结构化值、显式资源段或策略/配置 state。

## 开发说明

- 解析、发现、策略源处理和 schema 工作应保持在控制路径。
- 数据路径只处理已编译 ID、句柄、driver plan、policy snapshot、operation、outcome 和 fact。
- 外部协议 crate 应保持为 gateway、console 或 kernel runtime API 的薄适配器。
- 协议变更应同时更新 proto、随仓库绑定、转换、测试、示例和公开文档。

## 许可证

MIT。见 [LICENSE](LICENSE)。
