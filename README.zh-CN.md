# Xolotl

> [!WARNING]
> Xolotl 还处于 v1 前阶段。运行时行为、配置路径、protobuf schema 和 gateway
> 协议都可能变化，暂不提供兼容性保证。

Xolotl 是可组合的 Rust AI 程序执行内核。默认 SDK 提供无需堆分配的 `no_std` 状态机；模型、工具、状态、存储和外部系统由可选宿主通过能力受控的资源接入。

调用方以 `Process` 运行。它打开 `effect://inference/infer` 或
`state://memory/alice/thread` 这样的 `Resource`，拿到属于该进程的
`Handle`。内核检查授权和策略，通过 `Driver` 或外部 Provider/Source session 分派请求，并记录
`Fact`，用于审计、重放和恢复。

需要 daemon 时使用 `xolotld`，它提供 Console、external gRPC 和 external WebSocket
监听器。需要嵌入另一个 Rust 程序时使用 `xolotl-sdk`。两种形态下，应用层仍然持有模型选择策略、用户界面和业务逻辑，并通过资源和操作调用 Xolotl。

英文默认文档：[README.md](README.md)

## 特性

- Resource 和进程持有的 Handle 是模型调用、工具、记忆、状态和外部系统的访问边界
- `open()` 在执行前编译授权、策略、绑定和驱动计划；操作热路径只处理 ID 和权限位图
- 子 Process 只获得衰减后的授权。命名长寿任务使用 `ActorSpec`，但仍然是 Process
- 外部程序通过 gRPC 或 WebSocket 以 Provider/Source projection 接入，并共用 gateway session 模型
- `xolotld` 和 `xolotl-sdk` 共用一个内核；宿主可以替换状态、事实记录、驱动、策略来源和模型后端
- Rust 和 JSON 程序共用编译器，可组合词法绑定、递归、循环、并行、竞争、错误恢复和结构化清理
- 最小内核使用调用方提供的定长存储并显式限制资源；Tokio、持久化、Provider 和网关由宿主按需选择
- 可选检查点保留完整执行状态和动态调用标识；结果不确定的非幂等效果需要核对后处理

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
RUSTDOCFLAGS='-D warnings -W missing-docs' cargo doc --workspace --all-features --no-deps --locked
```

Rustdoc 输出在 `target/doc/index.html`。

## 架构

一次操作的路径如下：

```text
Process
  owns Handle
  issues Operation on Resource.method
  through DriverPlan
  under PolicySnapshot
  producing Outcome and Fact
```

运行时分成四类代码路径：

- 控制路径：注册表、命名、准入、策略编译、绑定解析和 `open()` 句柄编译
- 数据路径：已编译方法的准入、祖先进程预算记账、驱动分派和 Fact 记录；祖先检查开销随委托深度变化
- 外部适配：Provider、Source、driver 和协议适配器
- 程序执行：portable 程序与现有 `Do<A>` / `ExecutionGraph` 入口共用宿主驱动的核心状态机

分层、feature 组合、程序 API、资源限制与恢复约定见[核心与可移植程序](docs/zh-CN/src/core-and-portable.md)。

## 工作区

| Rust 包 | 职责 |
| --- | --- |
| `xolotl-core` | 默认零依赖的 `no_std` 状态机、定长存储、链接、能力句柄和有界通道 |
| `xolotl-types` | 核心 ID、路径、值、能力、操作、审计类型和 external Provider/Source 数据 |
| `xolotl-graph` | portable Rust/JSON 编译器，以及 `Do<A>` 和执行图入口 |
| `xolotl-state` | 独立的 State / 对象能力、可选宿主装配和内存适配器 |
| `xolotl-value-codec` | 增量值事件、显式键工作区及可选 CBOR 编码 |
| `xolotl-value-object` | 结构化对象引用、具有所有权的读写与复制、经 EOF 校验的回执 |
| `xolotl-kernel` | 可移植执行与调用规则，以及可选托管进程、注册表、策略、恢复和事实记录 |
| `xolotl-storage-redb` | 基于 redb 的持久状态、`FactStore` 与可选检查点日志 |
| `xolotl-storage-fs` | 增量对象存储、具有所有权的暂存上传和原子发布 |
| `xolotl-standard` | 标准进程内 Provider 和 Source 实现 |
| `xolotl-gateway` | 按 profile 装配的应用准入和对象回执，以及独立的 external Provider/Source 会话 |
| `xolotl-gateway-grpc` | 使用 `xolotl-proto` 的应用与 external Provider/Source gRPC 适配器 |
| `xolotl-gateway-websocket` | external Provider/Source WebSocket 适配器 |
| `xolotl-gateway-mcp` | 把选定 Gateway publication 暴露为 MCP tool、resource、resource template 和 prompt 的服务端适配器 |
| `xolotl-proto` | Protobuf schema 和随仓库提供的 prost/tonic 绑定 |
| `xolotl-console-protocol` | Console 动作定义及类型化管理记录 |
| `xolotl-console` | Web 控制台管理动作的 gateway |
| `xolotl-daemon` | 长期运行的宿主进程 `xolotld` |
| `xolotl-sdk` | 最小嵌入式运行时门面和便捷导出 |
| `xolotl-plan`, `xolotl-sim` | 规划与仿真 crate |

`xolotl-standard` 使用 Cargo feature 选择要编译的模块。默认 `standard` feature 启用标准进程内实现。
嵌入式宿主可以用 `StandardConfig::with_modules` 安装更小的模块集合，也可以用
`StandardConfig::with_inference_backend` 提供模型 backend。Gateway 适配器共享 profile 和会话契约，
宿主负责安装监听器；结构化对象输出可独立启用，并要求显式披露策略。

`xolotl-sdk` 默认不启用 feature，仅导出无需 allocator 的 `xolotl_sdk::core`。
`program` 提供支持 `no_std + alloc` 的通用值和 portable 编译器。
`runtime` 增加协作式执行、调用准入、作用域记账和流端口，不要求 Tokio、`Send` 或装箱 Future。
启用 `host` 后提供 `Xolotl`、`XolotlBuilder` 和内存宿主；`plan`、
`standard`、`durable`、`multi-thread` 按需启用。宿主通过 `XolotlBuilder` 提供状态和事实记录后端。
`ActorSpec` 可通过 `xolotl-graph` 和 `xolotl-sdk` 使用；内核可以通过
`Bootstrap::spawn_actor_under` 把它启动为命名长寿 Process，SDK 也提供
`Xolotl::spawn_actor` 便捷入口。body 或终结器如果引用进程本地 `StepRef`，宿主应在启动时
通过 `Bootstrap::spawn_actor_under_with_steps` 或 `Xolotl::spawn_actor_with_steps`
传入对应函数。Actor 声明可以使用 `state://process/self/...`；启动时会在 lint 和执行前绑定为具体 Process id。

对象端口通过引用和分块 I/O 支持大数据；具体 Provider 是否增量处理取决于其实现。
流通过可配置的驻留窗口施加背压，窗口大小不限制累计流长度。
宿主通过 `StandardConfig::with_object_store` 安装对象适配器；State 的读取、写入、查询、历史和订阅能力可以分别安装。
daemon 在 State 数据库旁安装文件对象存储，可通过 `storage.object_path` 指定目录。

不同任务通过普通能力组合：

| 任务 | 组合方式 |
| --- | --- |
| Agent / RAG | 模型调用、显式检索表示、工具授权委派及流式结果 |
| 批处理 | 可复用的程序/缓冲区布局、有界活动并发及增量输出 |
| 音视频 | 分别准入的采集/回放调用、带时间戳的 Frame 引用及设备租约 |
| 多 Agent 工作流 | 子作用域、通道、词法清理及可恢复程序模块 |
| 训练与评测 | 外部任务提交/观察/取消方法及已提交的产物引用 |
| 仿真与边缘计算 | 注入时钟/完成事件、定长控制存储及可选 portable 值/运行时层 |

[`task_scenarios`](crates/xolotl-sdk/tests/task_scenarios.rs) 提供可执行的 RAG、媒体和外部任务组合。
模型、设备及服务采用模拟适配器，检索、执行、授权、流信用和文件对象使用实际实现；这些用例不测试硬件，
也不向单次调用增加实时双向输入参数。
[持久批处理工作流](crates/xolotl-sdk/tests/durable/workflow.rs) 将子任务授权、State 结果增量消费
和有界中断恢复组合起来；检查点经真实序列化后保存在跨宿主实例保留的测试内存中。
[`benchmarks/runtime`](benchmarks/runtime/README.md) 通过分开的计时和堆统计运行测量实际运行时路径。

## 构建与测试

需要 Rust 1.98.1 或更新版本，使用 edition 2024。`rust-toolchain.toml` 固定已验证的工具链，并包含 rustfmt、Clippy 和 Cortex-M 检查目标。
依赖版本统一在根 `Cargo.toml` 中管理；独立 portable 示例还维护自己的锁文件。

```sh
cargo fmt --all
cargo check --workspace
cargo test --workspace
cargo test --workspace --all-features
cargo run -p xolotl-sdk --features host --example portable
```

构建守护进程：

```sh
cargo build -p xolotl-daemon
```

## 运行 `xolotld`

创建本地配置：

```sh
cp xolotl.toml.example xolotl.toml
```

启动守护进程：

```sh
cargo run -p xolotl-daemon -- up
```

`xolotld` 只启动宿主进程；运行时管理通过 Console WebSocket 执行。

`xolotl.toml.example` 默认地址：

- 控制台监听地址：`127.0.0.1:9000`
- External gRPC gateway：`127.0.0.1:9444`
- External WebSocket gateway：`127.0.0.1:9200`

`xolotl-daemon` 默认启用 `external-grpc` 和 `external-websocket`。可以用
`--no-default-features --features external-grpc` 或
`--no-default-features --features external-websocket` 只构建其中一种
transport。

应用客户端可单独启用 `application-grpc` feature，使用认证发现、增量对象上传和
类型化提交。启用地址前先配置 State profile，见[应用网关](docs/zh-CN/src/application-gateway.md)。

首次启动时，如果状态中没有控制台 root 账号，也没有配置预置凭据，`xolotld` 会把一次性 root 密码打印到 stderr。

## 配置

`xolotl.toml` 是引导配置。它控制存储、监听绑定地址、root 引导凭据、external gateway 限制、gateway 传输安全设置和控制台资源上限。

- `[server]`：控制台、应用 gRPC、external gRPC 和 external WebSocket 绑定地址
- `[application_gateway]`：State profile 选择和应用传输窗口
- `[external_gateway.grpc]`：external gRPC 的 Provider/Source session 限制
- `[external_gateway.grpc.transport_security]`：external gRPC 传输边界
- `[external_gateway.websocket]`：external WebSocket 的 Provider/Source session 限制
- `[external_gateway.websocket.transport]`：WebSocket frame、idle、first-frame 和连接数限制
- `[external_gateway.websocket.transport_security]`：external WebSocket 明文监听器的传输边界
- `[console.*]`：控制台 root 凭据、认证/会话限制、WebSocket 限制和传输安全

运行时配置、Provider 设置、模型路由、组、绑定、外部程序安装、Provider projection、Source projection 和策略管理状态都属于 Xolotl state，并通过 Console WebSocket 管理。

## 外部接口

详细接入说明见 [网关](docs/zh-CN/src/gateways.md)、[External Gateway](docs/zh-CN/src/external-gateway.md) 和[控制台协议](docs/zh-CN/src/console-protocol.md)。

### 控制台

`xolotl-console` 是 Web 控制台管理动作的 gateway。HTTP 负责健康检查和认证；登录后，Console WebSocket 承载快照、配置读取/写入/CAS、运行时检查、订阅、trace/fact stream、外部程序生命周期动作、配对动作、登出和控制台用户/角色/会话管理。

### External Gateway

外部程序以 Provider 或 Source projection 接入。daemon 持有 session 准入、generation 检查、流控、去重、command idempotency 和入站污点标记。

External gRPC 通过 `[server].external_grpc_addr` 或 `XOLOTL_EXTERNAL_GRPC_ADDR` 提供 Provider/Source session stream。

External WebSocket 通过 `[server].external_websocket_addr` 或 `XOLOTL_EXTERNAL_WEBSOCKET_ADDR` 提供同一套 Provider/Source session frame。

控制状态使用这些前缀：

```text
state://kernel/external-installations/<installation_id>
state://kernel/external-pairings/<pairing_id>
state://kernel/external-sessions/<installation_id>/<role>
state://kernel/external-credential-revocations/<installation_id>
```

Provider/Source 投影嵌在每个 external installation 声明中。

### MCP

`xolotl-gateway-mcp` 把选定 Gateway publication 暴露为 MCP tool、resource、resource template 和 prompt。每个 publication 引用一个 Gateway surface；该 surface 必须有显式 publish capability，MCP 调用、资源读取和 prompt 请求都会转换为标准能力约束操作。adapter 优先协商 `2025-11-25`，保留已支持的已发布 MCP 协议修订，只在对应修订定义 completion 时声明 completion，并在返回原生 MCP content block 前进行校验。

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

路径参数会被拒绝。选项放进结构化值、显式资源段或策略/配置 state。

## 许可证

MIT。见 [LICENSE](LICENSE)。
