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
nexus-standard   -> target/doc/nexus_standard/index.html
```

## Reading Order

For embedding:

- `nexus-sdk`
- `nexus-graph`
- `nexus-types`
- `nexus-kernel`

`nexus-sdk` is minimal by default. Use `NexusBuilder` to supply host-owned state
and fact backends. The SDK `standard` feature exposes the standard in-process
provider package installation API.
Use `ActorSpec` and `Nexus::spawn_actor` for named long-lived Process
declarations. Use `Nexus::spawn_actor_with_steps` when the actor body references
process-local `StepRef`s in the body or finalizers. Use
`StandardConfig::with_modules` to choose installed standard modules and
`StandardConfig::with_inference_backend` to supply the host model backend used
by standard model-backed effects.

For protocol adapters:

- `nexus-gateway`
- `nexus-proto`
- `nexus-gateway-grpc`
- `nexus-gateway-websocket`
- `nexus-gateway-mcp`

External Provider/Source session admission and secure envelope helpers are under
`nexus_gateway::external`. The `nexus-gateway` root API is for gateway profiles,
sessions, submissions, limits, and runtime status.

For standard providers:

- `nexus-standard`
- `nexus-state`
- `nexus-storage-redb`

## Doc Quality Checks

The current public API docs are expected to build without missing-doc warnings:

```sh
RUSTDOCFLAGS='-W missing-docs' cargo doc --workspace --no-deps
```

Run doc tests with:

```sh
cargo test --doc --workspace
```
