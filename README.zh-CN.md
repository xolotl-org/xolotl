# Xolotl

Xolotl 是可嵌入的 Rust 能力运行时，用于组合调用宿主授权工具、模型、数据及外部服务的程序。应用拥有自己的界面和业务政策；宿主选择资源、存储、调度和开放范围。

[English README](README.md)

> [!WARNING]
> Xolotl 尚未正式发布。当前自有协议与格式使用 v1；API、配置和格式可能直接变化，不保证旧版兼容。

## 特点

- **程序组合**：使用 Rust 图或可移植的 Rust／JSON 表达式，组合顺序执行、分支、循环、并行汇合、竞速及词法清理。可选 Plan 前端接受 YAML／JSON 工作流文档。
- **模块复用**：宿主安装具名续接函数，根据中间结果构造子程序。原生续接函数与准备好的可移植程序可组合在同一模块中，效果仍通过授权资源调用执行。
- **能力控制的资源**：为工具、模型、State 或外部服务安装 Driver；Kernel 检查 Process 授权与专属 Handle，并跟踪调用结果、来源及用量。
- **按需选择执行层**：使用无需堆分配的 `no_std` Core、`no_std` + `alloc` 可移植执行或托管运行时。准备好的程序共享不可变指令，各次执行保持独立状态，并可复用空缓冲。
- **可选远程接入**：开放应用或 Console 服务，连接外部 Provider／Source，或启用节点联邦。宿主选择开放的能力、路由与授权。

## 快速开始

仓库在 [rust-toolchain.toml](rust-toolchain.toml) 中固定 Rust 工具链。

### 嵌入 Rust 程序

运行托管执行示例：

```sh
cargo run -p xolotl-sdk --features memory --example portable
cargo run -p xolotl-sdk --features memory --example native_modules
```

[portable 示例](crates/xolotl-sdk/examples/portable.rs)组合有界循环与并行分支，将程序通过 JSON 往返转换，再使用共享指令和可复用缓冲运行两组输入。[模块示例](crates/xolotl-sdk/examples/native_modules.rs)将原生续接函数与准备好的可移植程序组合使用。

SDK 默认提供无需堆分配的 `no_std` Core。`program` 启用可移植编译，`runtime` 启用协作式执行，`host` 启用托管执行；`memory` 增加内存 State 适配器和快捷构造器。嵌入无需 daemon、监听器或 Console。feature 与宿主端口见[核心与可移植程序](docs/zh-CN/src/core-and-portable.md)。

自行提供 Driver 与调度器、不使用托管运行时的方式见 [`no_std` + `alloc` 示例](examples/portable-runtime/README.md)。

### 运行配置好的宿主

`xolotld` 装配带 Console 和外部网关的宿主。先复制示例配置：

```sh
cp xolotl.toml.example xolotl.toml
```

启动示例的 redb 配置前：

1. 准备两个独立、私有的原始 32 字节密钥文件，文件权限设为 `0600`：分别用于 Console 凭据和外部配对凭据。
2. 将 `console.credentials.active_key_file` 和 `external_credentials.key_file` 的示例路径替换为各自的绝对路径。密钥须与数据库备份一同妥善保管。
3. 非交互初始化 root 时，通过 `console.root.password_hash`、`console.root.password` 或 `console.root.pubkeys` 预置凭据。密钥文件要求和 root 认证设置见[配置](docs/zh-CN/src/configuration.md)。

然后启动宿主：

```sh
cargo run -p xolotl-daemon -- up
```

示例监听器使用本机回环地址。初始化空 Console 且未预置凭据时，daemon 仅在 stderr 是终端时展示随机初始 root 密码；登录后应修改密码。监听设置及认证细节见[配置](docs/zh-CN/src/configuration.md)和[Console 协议](docs/zh-CN/src/console-protocol.md)。

### 接入客户端或外部服务

- 应用客户端通过[应用网关](docs/zh-CN/src/application-gateway.md)访问 Profile 绑定的业务接口。daemon 的 gRPC 入口需要启用 `application-grpc` feature，并配置 Profile 与监听地址。
- Console 客户端通过 [Console](docs/zh-CN/src/console-protocol.md)进行管理及可选的资源执行。示例关闭运行时执行；启用后仍需显式开放范围、调用者权限及 level-2 MFA。
- 外部效果处理方与事件生产方以 [Provider 或 Source](docs/zh-CN/src/external-gateway.md)身份接入。
- MCP 客户端通过 [MCP 服务端适配器](docs/zh-CN/src/api-reference.md#mcp-发布)访问显式发布的 Gateway 业务接口，传输由宿主装配。

远程客户端使用已开放的协议，无需本地 Rust 绑定。Swift／Kotlin **进程内嵌入**需要语言绑定与移动生命周期集成，当前仓库尚未提供。可用传输与监听配置见[网关](docs/zh-CN/src/gateways.md)。

## 框架分工

| 组件 | 职责 |
| --- | --- |
| Core | 使用调用方提供的有界存储，推进程序控制流、取消与词法清理。 |
| Kernel | 管理 Process 权限与专属 Handle，授权资源调用并结算资源预算。 |
| Driver | 执行已准入的效果，返回结果、来源及用量。 |
| 宿主 | 安装资源、选择存储与调度，拥有任务生命周期及可选诊断。 |
| 服务与适配器 | 接纳客户端、开放选定能力，并在传输交接时检查当前交付权限。 |

执行属于本轮宿主生命周期。应用数据可独立持久保存，重开数据不会重新启动程序。程序成功时仍可能存在未决的外部效果：执行结果单独报告已知身份，不自动重发未知效果。局部容量限额不能单独约束宿主总内存。

取消是协作式的，不会回滚效果。词法清理随执行推进，丢弃 Future 无法完成异步清理。原生 Driver 和续接函数属于可信宿主代码，并非沙箱插件。

可选 Federation 连接已认证节点，按授权交付流、读取对象及调用远端资源，并保留业务请求／结果记录。宿主提供路由、授权及应用投影或合并规则。所有权与组合边界见[架构](docs/zh-CN/src/architecture.md)，资源及委派见[能力模型](docs/zh-CN/src/capability-model.md)。

## 文档

- [中文手册](docs/zh-CN/src/README.md) · [English manual](docs/src/README.md)：概念与按任务组织的指南。
- [架构](docs/zh-CN/src/architecture.md) · [安全政策](docs/zh-CN/src/security-and-boundaries.md)：框架职责与安全规则。
- [Rust API 参考](docs/zh-CN/src/api-reference.md)：公开合同、feature 选择及 rustdoc 命令。
- [网关](docs/zh-CN/src/gateways.md) · [Console 协议](docs/zh-CN/src/console-protocol.md)：应用、Provider/Source、管理与运行时入口。

## 开发

```sh
cargo check --workspace
cargo test --workspace
```

这些命令覆盖默认配置，可选 feature 需要额外验证。设计归属与验证流程见 [AGENTS.md](AGENTS.md)，feature 和文档命令见 [API 参考](docs/zh-CN/src/api-reference.md)。

## 许可证

MIT。见 [LICENSE](LICENSE)。
