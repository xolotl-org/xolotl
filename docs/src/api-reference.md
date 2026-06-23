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
andrias-sdk      -> target/doc/andrias_sdk/index.html
andrias-kernel   -> target/doc/andrias_kernel/index.html
andrias-standard   -> target/doc/andrias_standard/index.html
```

## Reading Order

For embedding:

- `andrias-sdk`
- `andrias-graph`
- `andrias-types`
- `andrias-kernel`

`andrias-sdk` is minimal by default. Use `AndriasBuilder` to supply host-owned state
and fact backends. The SDK `standard` feature exposes the standard in-process
provider package installation API.
Use `ActorSpec` and `Andrias::spawn_actor` for named long-lived Process
declarations. Use `Andrias::spawn_actor_with_steps` when the actor body references
process-local `StepRef`s in the body or finalizers. Use
`StandardConfig::with_modules` to choose installed standard modules and
`StandardConfig::with_inference_backend` to supply the host model backend used
by standard model-backed effects.

For protocol adapters:

- `andrias-gateway`
- `andrias-proto`
- `andrias-gateway-grpc`
- `andrias-gateway-websocket`
- `andrias-gateway-mcp`

External Provider/Source session admission and secure envelope helpers are under
`andrias_gateway::external`. The `andrias-gateway` root API is for gateway profiles,
sessions, submissions, limits, and runtime status.

For standard providers:

- `andrias-standard`
- `andrias-state`
- `andrias-storage-redb`

## Doc Quality Checks

The current public API docs are expected to build without missing-doc warnings:

```sh
RUSTDOCFLAGS='-W missing-docs' cargo doc --workspace --no-deps
```

Run doc tests with:

```sh
cargo test --doc --workspace
```
