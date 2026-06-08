# API Reference

Rustdoc is the public API reference for the workspace.

Generate it with missing-doc checks enabled:

```sh
RUSTDOCFLAGS='-W missing-docs' cargo doc --workspace --no-deps
```

Open the workspace index:

```text
target/doc/index.html
```

Individual crate pages live under:

```text
target/doc/<crate_name>/index.html
```

Cargo converts hyphens to underscores in generated Rustdoc paths. For example:

```text
nexus-sdk      -> target/doc/nexus_sdk/index.html
nexus-kernel   -> target/doc/nexus_kernel/index.html
nexus-actors   -> target/doc/nexus_actors/index.html
```

## Reading Order

For embedding:

1. `nexus-sdk`
2. `nexus-graph`
3. `nexus-types`
4. `nexus-kernel`

For protocol adapters:

1. `nexus-gateway`
2. `nexus-proto`
3. `nexus-gateway-grpc`
4. `nexus-gateway-websocket`
5. `nexus-gateway-mcp`

For standard providers:

1. `nexus-actors`
2. `nexus-state`
3. `nexus-storage-redb`

## Doc Quality Checks

The current public API docs are expected to build without missing-doc warnings:

```sh
RUSTDOCFLAGS='-W missing-docs' cargo doc --workspace --no-deps
```

Doc tests should also stay runnable:

```sh
cargo test --doc --workspace
```
