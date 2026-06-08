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
nexus-actors   -> target/doc/nexus_actors/index.html
```

## 阅读顺序

嵌入运行时：

1. `nexus-sdk`
2. `nexus-graph`
3. `nexus-types`
4. `nexus-kernel`

协议适配器：

1. `nexus-gateway`
2. `nexus-proto`
3. `nexus-gateway-grpc`
4. `nexus-gateway-websocket`
5. `nexus-gateway-mcp`

标准提供方：

1. `nexus-actors`
2. `nexus-state`
3. `nexus-storage-redb`

## 文档质量检查

公开 API 文档应该能在缺失文档警告提升为错误时构建：

```sh
RUSTDOCFLAGS='-W missing-docs' cargo doc --workspace --no-deps
```

文档测试也应保持可运行：

```sh
cargo test --doc --workspace
```
