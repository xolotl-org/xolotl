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
nexus-sdk      -> target/doc/nexus_sdk/index.html
nexus-kernel   -> target/doc/nexus_kernel/index.html
nexus-standard   -> target/doc/nexus_standard/index.html
```

## 阅读顺序

嵌入运行时：

- `nexus-sdk`
- `nexus-graph`
- `nexus-types`
- `nexus-kernel`

`nexus-sdk` 默认保持最小化。用 `NexusBuilder` 接入宿主持有的状态和事实记录后端。
SDK 的 `standard` feature 提供标准进程内 Provider 安装 API。

协议适配器：

- `nexus-gateway`
- `nexus-proto`
- `nexus-gateway-grpc`
- `nexus-gateway-websocket`
- `nexus-gateway-mcp`

External Provider/Source session 准入和 secure envelope helper 位于
`nexus_gateway::external`。`nexus-gateway` 根 API 用于 gateway profile、
session、submission、limit 和运行时状态。

标准提供方：

- `nexus-standard`
- `nexus-state`
- `nexus-storage-redb`

## 文档质量检查

公开 API 文档在缺失文档警告提升为错误时构建：

```sh
RUSTDOCFLAGS='-W missing-docs' cargo doc --workspace --no-deps
```

文档测试也应保持可运行：

```sh
cargo test --doc --workspace
```
