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
andrias-sdk      -> target/doc/andrias_sdk/index.html
andrias-kernel   -> target/doc/andrias_kernel/index.html
andrias-standard   -> target/doc/andrias_standard/index.html
```

## 阅读顺序

嵌入运行时：

- `andrias-sdk`
- `andrias-graph`
- `andrias-types`
- `andrias-kernel`

`andrias-sdk` 默认保持最小化。用 `AndriasBuilder` 接入宿主持有的状态和事实记录后端。
SDK 的 `standard` feature 提供标准进程内 Provider 安装 API。
使用 `ActorSpec` 和 `Andrias::spawn_actor` 声明并启动命名长寿 Process。
Actor body 或终结器引用进程本地 `StepRef` 时，使用 `Andrias::spawn_actor_with_steps`。
使用 `StandardConfig::with_modules` 选择实际安装的 standard 模块，使用
`StandardConfig::with_inference_backend` 接入标准模型类 effect 使用的宿主模型 backend。

协议适配器：

- `andrias-gateway`
- `andrias-proto`
- `andrias-gateway-grpc`
- `andrias-gateway-websocket`
- `andrias-gateway-mcp`

External Provider/Source session 准入和 secure envelope helper 位于
`andrias_gateway::external`。`andrias-gateway` 根 API 用于 gateway profile、
session、submission、limit 和运行时状态。

标准提供方：

- `andrias-standard`
- `andrias-state`
- `andrias-storage-redb`

## 文档质量检查

公开 API 文档在缺失文档警告提升为错误时构建：

```sh
RUSTDOCFLAGS='-W missing-docs' cargo doc --workspace --no-deps
```

文档测试也应保持可运行：

```sh
cargo test --doc --workspace
```
