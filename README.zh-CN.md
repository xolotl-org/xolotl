# Nexus

Nexus 是面向模型应用的能力运行时。它把模型推理、工具调用、记忆、状态和外部系统映射为 `effect://` 与 `state://` 资源。程序通过 `open()` 编译出的能力句柄访问这些资源；模型后端、工具进程和状态存储保留在资源绑定与驱动层。

Nexus 的范围是模型调用、工具执行、长期状态和外部协议之间的执行边界。模型训练、应用界面和业务逻辑由调用方或外部组件承担。推理、嵌入、重排和计划是效果资源；MCP、文件、终端、网络抓取等工具是效果资源；扩展以提供方或来源接入；程序入口最终落到执行图。所有访问都经过同一套 `Resource / Interface / Driver`、`open()` 句柄和能力检查。

英文默认文档：[README.md](README.md)

## 已实现范围

- 模型执行：`effect://inference/*` 支持推理、嵌入、重排和计划；路由器按模型能力、模态、组策略、重试和回退选择后端。
- 工具接入：MCP 工具、文件、终端、网络抓取、时间、事件、锁、blob、tensor、审批和压缩都作为 effect 资源注册。
- 记忆与上下文：记忆驱动结合状态后端、向量索引和重排器；上下文组装和压缩是独立 effect。
- 扩展系统：外部扩展通过安装声明和投影声明接入，提供方暴露远端 effect，来源写入状态流。
- 能力边界：`open()` 把资源路径、授权记录、策略和绑定编译为进程持有的句柄；派生进程只能获得衰减后的权限。
- 程序入口：Rust `DoNode`、计划文档和结构化 Protobuf `Program` 都会落到同一个执行图，由同一个执行器推进。

## 当前状态

这个仓库是 Nexus 能力运行时与网关的早期 Rust 工作区。当前实现强制这些公开兼容规则：

- 资源路径语法会拒绝 `@param` 后缀，例如
  `effect://memory/recall@scope=user`；
- gRPC `GatewayService.Submit` 接收结构化 Protobuf `Program`；
- 能力字面量使用动词形式，例如
  `perform://effect/inference/infer`；资源路径仍写作 `effect://...`。

## 文档

公开手册：

需要安装 mdBook 时运行：

```sh
cargo install mdbook
```

- 中文手册：直接阅读 [docs/zh-CN/src/README.md](docs/zh-CN/src/README.md)，
  或构建：

```sh
mdbook build docs/zh-CN
```

- 英文手册：直接阅读 [docs/src/README.md](docs/src/README.md)，或构建：

```sh
mdbook build docs
```

本地浏览器预览可运行 `mdbook serve docs/zh-CN` 或 `mdbook serve docs`。
中文手册在 `docs/zh-CN/book.toml` 中声明 `language = "zh-CN"`，并加载
`docs/zh-CN/theme/cjk.css` 处理中文字体与行高。

中文手册的统一译名见 [docs/zh-CN/src/glossary.md](docs/zh-CN/src/glossary.md)。Rust 类型名、Rust 包名、配置键、协议字段、命令和路径保持原文，方便回到代码中查找。

生成并检查 Rust API 文档：

```sh
RUSTDOCFLAGS='-W missing-docs' cargo doc --workspace --no-deps
```

然后在浏览器里打开 `target/doc/index.html`。各 Rust 包页面位于
`target/doc/<crate_name>/index.html`，Rust 包名里的连字符会转换成下划线；
例如 `nexus-sdk` 对应 `target/doc/nexus_sdk/index.html`。

## 架构

热路径保持很小：

```text
进程持有句柄，
对资源方法发起操作，
通过驱动计划执行，
遵守策略快照，
产出结果和事实记录。
```

这些中文术语分别对应代码中的 `Process`、`Handle`、`Resource.method`、`Operation`、`DriverPlan`、`PolicySnapshot`、`Outcome` 和 `Fact`。

运行时分成四个平面：

- 控制平面：注册表、命名、准入、策略编译、绑定解析和 `open()` 句柄编译。
- 数据平面：只围绕进程、句柄、操作、事实记录做固定成本执行。
- 扩展平面：外部提供方、来源、驱动和协议适配。
- 程序平面：可恢复的 `Do<A>` 程序和执行图。

控制平面负责解析和编译。数据平面只执行已经编译好的对象。

## 工作区

| Rust 包 | 职责 |
| --- | --- |
| `nexus-types` | 核心 ID、路径、值、能力、操作、审计类型。 |
| `nexus-graph` | 可恢复 `Do<A>` 程序中间表示和执行图编译器。 |
| `nexus-state` | 状态后端 trait（特征）与内存实现。 |
| `nexus-kernel` | 进程、句柄、注册表、策略、执行器、恢复、事实记录。 |
| `nexus-storage-redb` | 基于 redb 的持久状态和 `FactStore`。 |
| `nexus-actors` | 标准进程内驱动和提供方。 |
| `nexus-gateway` | 提交程序的共享网关抽象。 |
| `nexus-gateway-grpc` | 使用 `nexus-proto` 的 gRPC `GatewayService` 适配器。 |
| `nexus-gateway-websocket` | WebSocket 网关适配器。 |
| `nexus-gateway-mcp` | MCP 服务端网关适配器。 |
| `nexus-proto` | Protobuf 模式定义和手工随仓库提供的 prost/tonic 绑定。 |
| `nexus-console` | Web 控制台后端的管理域网关。HTTP 只负责引导和认证；登录后的管理主路径是控制台 WebSocket。 |
| `nexus-daemon` | 长期运行的宿主进程 `nexusd`。 |
| `nexus-sdk` | 嵌入和测试用便捷导出。 |
| `nexus-plan`, `nexus-sim` | 规划与仿真脚手架。 |

## 环境要求

- Rust 1.95 或更新版本。
- 与稳定版工具链匹配的 Cargo。
- 不需要本地安装 `protoc`。`nexus-proto` 已经带有随仓库提供的 prost/tonic Rust 绑定。

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

`nexusd` 负责启动宿主进程。运行时管理由控制台网关处理；守护进程子命令不承载管理功能。

`nexus.toml.example` 默认地址：

- 控制台监听地址：`127.0.0.1:9000`
- gRPC 网关：`127.0.0.1:9100`
- 程序 WebSocket 网关：`127.0.0.1:9200`

首次启动时，如果状态中没有控制台 root 账号，也没有配置预置凭据，`nexusd` 会把一次性 root 密码打印到 stderr。

## 配置

`nexus.toml` 是引导配置，控制存储、网关监听地址、root 引导凭据和有界的控制台资源限制：

- `[storage]`：`redb` 持久存储或内存存储。
- `[server]`：控制台、gRPC、WebSocket 绑定地址。
- `[console.root]`：可选的预置 root 凭据。
- `[console.auth]`：会话 TTL、会话数量和 Argon2 校验并发限制。
- `[console.ws]`：控制台 WebSocket 帧大小、连接数、空闲时间、速率、订阅数、结果大小和事件背压限制。

运行时配置、提供方设置、模型路由、组、绑定和策略管理的状态，都属于 Nexus 状态，通过控制台网关管理。
控制台认证和 WebSocket 配置属于部署容量参数。能力检查、二次确认门槛、Origin/Host 校验、按路径准入、动作注册表校验和敏感值脱敏始终由运行时路径执行。

## 外部接口

详细接入说明见手册：[网关](docs/zh-CN/src/gateways.md)、[程序网关](docs/zh-CN/src/program-gateways.md)
和[控制台协议](docs/zh-CN/src/console-protocol.md)。

### 控制台

`nexus-console` 是 Web 控制台的管理域网关。管理动作使用和其它运行时路径相同的授权、状态、CAS 和审计接口。管理动作调用运行时效果时，该效果是标准的、受能力约束的操作。

当前接口形态：

- HTTP：`GET /health`、`POST /api/auth/login`、
  `POST /api/auth/key/challenge`、`POST /api/auth/key/login`、
  `POST /api/auth/step-up`。
- 控制台 WebSocket：登录后的管理主路径，承载快照、配置读取/写入/CAS、运行时检查、订阅、跟踪/事实流、
  `ExtensionInstallation*` 生命周期动作、配对动作、登出、
  控制台用户/角色/会话管理。

登录后的管理功能运行在控制台 WebSocket 上；HTTP 保持为健康检查和认证入口。

### 扩展协议

扩展由一个 `ExtensionInstallationDef` 加一个或多个单角色
`ExtensionProjectionDef` 描述。安装声明是生命周期、传输、配对、凭据和共享配置单位。投影分为两类：提供方把 `effect://...` 能力暴露为远端绑定；来源把入站事件写入声明的状态流。

控制状态使用这些前缀：

```text
state://kernel/extension-installations/<installation_id>
state://kernel/extension-projections/<installation_id>/<projection_id>
state://kernel/extension-pairings/<pairing_id>
state://kernel/extension-sessions/<installation_id>/<role>
state://kernel/extension-revocations/<installation_id>
```

进程外扩展通过扩展 gRPC/WebSocket 协议连接：
`RoleSessionClientHello { installation_id, projection_id, ... }`、守护进程
裁定的 `SessionContext`、`RoleReady`、AEAD 保护的业务/控制帧，以及提供方
`Invoke` / 来源 `InboundEvent` 帧。配对输入使用 `installation_id`；
敏感值限制在一次性展示边界；操作输入、状态、事实记录和跟踪只接收脱敏元数据或引用。

### gRPC 和 Proto

主要的外部程序提交 API 是
`crates/nexus-proto/proto/nexus/v1/gateway.proto` 里的 `GatewayService`。

```proto
service GatewayService {
  rpc Submit(SubmitRequest) returns (SubmitResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
}
```

`SubmitRequest.program` 是结构化 Protobuf `Program`。

`nexus-proto` 是 Rust 网关和移动端 Kotlin/Swift 等生成客户端的传输协议模式定义源头。

### WebSocket

`nexus-gateway-websocket` 提供程序提交用的 WebSocket 网关，把 WebSocket
帧适配到共享网关抽象。它和上面的控制台 WebSocket 是不同通道，
并且和其它程序网关一样走请求进程、污点、策略、事实记录、句柄路径。

### MCP

`nexus-gateway-mcp` 以显式必需能力绑定作为工具发布前置条件。MCP 调用会翻译成普通网关提交。

## 路径和能力规则

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

能力字面量使用动词前缀：

```text
perform://effect/inference/infer
read://state/memory/alice/thread
write://state/kernel/config
```

路径参数会被拒绝。参数应放在结构化值、显式资源段或策略/配置状态中。

## 开发约束

- 解析、发现、策略源、模式定义处理留在控制平面。
- 数据平面只处理编译后的 ID、句柄、驱动计划、策略快照、操作、结果和事实记录。
- 外部协议 Rust 包应保持为 `nexus-gateway` 或内核扩展原语之上的薄适配层。
- 破坏性的运行时或协议变更需要同步更新 `.proto`、随仓库提供的绑定、转换逻辑、测试和文档。

## 许可证

MIT。见 [LICENSE](LICENSE)。
