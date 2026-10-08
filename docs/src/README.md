# Xolotl Manual

Xolotl is an embeddable, composable capability runtime designed for generality, performance, and memory efficiency. Applications own business policy; hosts choose resources, storage, scheduling, and exposure. This manual covers embedding, optional services, and host configuration.

Start with [Architecture](architecture.md), then choose an execution configuration in [Core And Portable Programs](core-and-portable.md). Hosted execution adds the [Runtime Model](runtime-model.md) and [Capability Model](capability-model.md). For a specific task, use these pages:

| Task | Page |
| --- | --- |
| Embed Xolotl in a Rust host or compose portable programs | [Core And Portable Programs](core-and-portable.md), [API Reference](api-reference.md) |
| Run and configure `xolotld` | [Configuration](configuration.md) |
| Call an application surface | [Application Gateway](application-gateway.md) |
| Manage the runtime through Console | [Console Protocol](console-protocol.md), [Runtime Calls and Submissions](console-runtime.md) |
| Connect an external Provider or Source | [External Gateway](external-gateway.md) |
| Connect independent nodes | [Federation configuration](configuration.md#federation-publisher), [FederationStore contract](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-federation/src/lib.rs) |
| Choose a listener or protocol | [Gateways](gateways.md) |
| Configure an HTTP model provider | [HTTP Inference Providers](http-inference-providers.md) |
| Check replay, state, or trust boundaries | [Programs And Replay](programs-and-replay.md), [State And Facts](state-and-facts.md), [Security And Boundaries](security-and-boundaries.md) |
