# Portable Runtime

This example runs a compiled `Program` through `LinkedExecution`, using the same
`Invocation`, `Scope`, billing, and provenance rules as the hosted runtime. Its
library is `no_std + alloc`; the executable only prints the library's result.

```sh
cargo run --manifest-path examples/portable-runtime/Cargo.toml --offline
cargo test --manifest-path examples/portable-runtime/Cargo.toml --offline
cargo check --manifest-path examples/portable-runtime/Cargo.toml --no-default-features --target thumbv7em-none-eabi --lib --offline
```

The embedding supplies three task/future slots, 32 shared frames, and eight
handle slots. Concrete `Ready` driver and recorder futures need no heap box.
Source compilation and variable-sized values use the allocator. Firmware must
supply its allocator, entry point, and executor; this is an embedding library,
not board firmware or a Cortex performance measurement.

Only local transforms and the fixed root identity are admitted. Scope changes,
external operations, waits, modules, and durable images require explicit host
adapters and are rejected here. `NoFacts` permits unrecorded deterministic work;
an effect cannot start without a working `FactRecorder`.

For asynchronous adapters, the owning embedding first calls `Scope::cancel`,
then `LinkedExecution::cancel`, and continues polling to finish structured
cleanup. Drop alone releases pending calls but cannot await cleanup. Account
adapters borrow scopes only during reserve/settle, never across suspension.
