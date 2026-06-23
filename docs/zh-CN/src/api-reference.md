# API 参考

Rustdoc 是工作区的公开 API 参考。

用缺失文档检查生成：

```sh
RUSTDOCFLAGS='-W missing-docs' cargo doc --workspace --no-deps
```

打开工作区首页：

```text
target/doc/index.html
```

单个 Rust 包页面位于：

```text
target/doc/<crate_name>/index.html
```

Cargo 会把 Rust 包名里的连字符转换为下划线。例如：

```text
xolotl-sdk      -> target/doc/xolotl_sdk/index.html
xolotl-kernel   -> target/doc/xolotl_kernel/index.html
xolotl-standard   -> target/doc/xolotl_standard/index.html
```

## 阅读顺序

嵌入运行时：

- `xolotl-sdk`
- `xolotl-graph`
- `xolotl-types`
- `xolotl-kernel`

`xolotl-sdk` 默认保持最小化。用 `XolotlBuilder` 接入宿主持有的状态和事实记录后端。
SDK 的 `standard` feature 提供标准进程内 Provider 安装 API。
使用 `ActorSpec` 和 `Xolotl::spawn_actor` 声明并启动命名长寿 Process。
Actor body 或终结器引用进程本地 `StepRef` 时，使用 `Xolotl::spawn_actor_with_steps`。
使用 `StandardConfig::with_modules` 选择实际安装的 standard 模块，使用
`StandardConfig::with_inference_backend` 接入标准模型类 effect 使用的宿主模型 backend。

协议适配器：

- `xolotl-gateway`
- `xolotl-proto`
- `xolotl-gateway-grpc`
- `xolotl-gateway-websocket`
- `xolotl-gateway-mcp`

External Provider/Source session 准入和 secure envelope helper 位于
`xolotl_gateway::external`。`xolotl-gateway` 根 API 用于 gateway profile、
session、submission、limit 和运行时状态。

标准提供方：

- `xolotl-standard`
- `xolotl-state`
- `xolotl-storage-redb`

## 文档质量检查

公开 API 文档在缺失文档警告提升为错误时构建：

```sh
RUSTDOCFLAGS='-W missing-docs' cargo doc --workspace --no-deps
```

文档测试也应保持可运行：

```sh
cargo test --doc --workspace
```
