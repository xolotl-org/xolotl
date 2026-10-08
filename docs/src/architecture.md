# Architecture

Xolotl is an embeddable, composable capability runtime. Optimize for **generality, performance and memory efficiency**, subject to security and truthful effects and data commits. Applications own business policy; hosts choose resources, storage, scheduling and exposure.

```text
Local SDK                    Remote client
    |                             |
    |                       protocol adapter
    |                             |
    |                      service admission
    +--------------+--------------+
                   |
                   +-- program --> compiler --> Core --+
                   |                  request/completion|
                   +-- direct call --------------------+
                                                       v
                                    Kernel: Process / Handle / policy
                                                       | admitted Operation
                                                       v
                                    Driver -> outcome / provenance / usage

Host assembles ports, budgets and task lifecycles.
Data and service stores own their commits and retention.
```

Core advances control flow, cancellation and lexical cleanup. Kernel authorizes resource calls; Drivers perform effects. Services admit clients and expose selected capabilities; adapters handle transport. Trusted components exchange ordinary typed values. Protection belongs at actual trust boundaries; see [Security And Boundaries](security-and-boundaries.md).

## Layers and ownership

| Owner | Responsibility | Dependency direction |
| --- | --- | --- |
| `xolotl-types` | Values, provenance, identifiers and unresolved-operation evidence | Portable representations, independent of service policy |
| `xolotl-core` | Control flow and request/completion transitions | Generic values and caller-supplied storage; no domain crates |
| `xolotl-plan`, `xolotl-graph` | Bounded compilation into Core programs | Types and Core; execution belongs to the runtime |
| `xolotl-kernel` | Invocation, Process authority, Handles, live execution and host ports | Core and data contracts |
| `xolotl-state`, `xolotl-source` | Observations/history; external installation and stream evidence | Data contracts implemented by storage adapters |
| `xolotl-storage-*` | Transactions, indexes, retained accounting and backend recovery | Data and optional service-store contracts |
| Gateway, Console, Federation | Client admission, exposure, service records and delivery authority | Kernel/data ports; adapters consume service contracts |
| Protocol adapters | Framing, connection evidence, buffering and transport handoff | Service decisions remain in services |
| Standard, SDK, daemon | Resource implementations, embedding facade, host assembly and shutdown | Compose lower layers; rules remain with their owners |

Choose only the execution configuration needed:

| Need | Entry point | Host supplies |
| --- | --- | --- |
| Allocation-free control flow | Core; default SDK `core` | Machine storage and request/completion handling |
| Portable compilation | SDK `program` | Program input and compile limits |
| Cooperative execution | SDK `runtime` | Caller-owned storage, invocation and scheduling ports |
| Hosted execution | SDK `host` | Resources, authority, HostRuntime and selected backends |
| Remote access | Services and protocol adapters | Hosted runtime, client admission and exposure |

Core-only hosts handle effects themselves. Kernel's portable runtime and hosted configuration have different assembly requirements; `host` adds Tokio-backed integration. See [feature selection](core-and-portable.md#feature-selection).

## Invocation path

1. The host installs Resources and Interfaces and delegates a grant to a Process.
2. `open()` resolves the method and compiles a process-owned Handle with a frozen contract and Driver plan. Registry changes leave existing Handles unchanged.
3. A direct call or program request reaches the same dispatch boundary: Kernel checks ownership, liveness, method rights and current residual policy before calling the Driver.
4. The Driver returns outcome, provenance and usage. Kernel settles the budget and emits diagnostic Facts when selected.
5. Execution completes lexical cleanup; the owning service settles its request records. An adapter checks current disclosure authority at the final transport handoff.

These stages have separate verdicts: a completed effect, a settled service record and delivered bytes are different facts. Signal waits enter through authorized `subscribe` Operations. See [Runtime Model](runtime-model.md), [Capability Model](capability-model.md) and [Programs And Replay](programs-and-replay.md).

## Host composition

`KernelBuilder` selects ports, identity sources and limits and creates related runtime tables; `build()` starts no task or listener. `Bootstrap::from_kernel` establishes the root Process; `Xolotl::from_kernel` adds the SDK facade. Compiling a feature, installing a Resource and granting authority are separate host choices.

Clones of one Kernel share its tables and ports. Independent builders create independent runtime domains, even when they share a backend. Components must belong to the intended domain; hosts sharing an execution namespace also share its `ExecutionIdSource` and retain the issuing `IdentityDirectory` for persistent caller identities. Fact observation defaults off; the default execution ID source has a fresh in-memory namespace.

Hosts own installed effect runtimes and accepted tasks through cleanup. Shutdown closes admission, stops producers, joins owned tasks and drains accepted work before releasing storage. Interrupted or concurrent shutdown waiters must preserve that custody. See [assembly APIs](api-reference.md) and [live execution and persistence](core-and-portable.md#live-suspension-and-data-persistence).

## State, commits and evidence

| Information | Owner and meaning |
| --- | --- |
| Frames, Process/Handle tables, in-flight calls | One live host lifecycle; live suspension preserves running work |
| State, Source positions, objects, credentials | Their data owners; persistence preserves data, not ordinary execution |
| Service request records | Their service/store owner; acceptance, retry and reconciliation within the declared scope |
| Unresolved-operation evidence | Trusted local invocation identities; retained across handled errors and losing branches |
| Facts and traces | Optional observation, distinct from authority and commit evidence |

Each data owner commits independently. Separate logical domains may share a backend recovery boundary: an uncertain commit can require reopening that shared instance. Hosts follow the backend's rejection and release contract before reconciliation.

Cancellation before dispatch can prevent work. After an external effect starts, cancellation, transport loss or withheld output does not prove rollback. Successful program output does not erase unresolved effects. Remote verdicts remain peer claims, not trusted local operation identities.

Evidence lookup, cached-result delivery and execution are separate operations. Missing evidence proves neither non-commit nor safe replay. Retry scope includes its evidence owner's namespace and contract version; only the trusted host closes a range before reclaiming eligible evidence. Retained obligations survive configuration and feature changes.

State notifications are live observations, not a durable event log; Fact scans cannot resume programs. Detailed commit, retry and retention rules belong to the contracts below.

## Composition checks

At each asynchronous handoff or cross-owner call, establish:

1. **Authority:** which identity, contract and dependencies apply at dispatch or disclosure? Protected queued output retains its original authority and deadline through the final transport handoff.
2. **Custody:** who owns accepted work, unresolved effects and cleanup after cancellation or disconnection?
3. **Commit:** which domain is known, rejected or uncertain, and what evidence identifies it? A reply or queue acceptance does not prove peer receipt.
4. **Capacity:** what is charged before work, where is it retained, and how does its reservation transfer? Preparation, in-flight work and retained data have distinct costs.
5. **Release:** which observable event confirms resources are gone, including during failed cleanup or interrupted shutdown?

Charge capacity until actual release. Shared quotas must allow accepted work to finish incrementally; separate instance limits do not automatically form a host-wide budget. Encoded bytes, structural work and retained memory are different measures; none alone bounds RSS or native Driver allocations. Prefer removing work or reusing an owner over adding another registry, history or wrapper.

## External entry points

[Application Gateway](application-gateway.md) exposes profile-constrained business calls. [External Gateway](external-gateway.md) installs remote Providers and Sources. [Console](console-protocol.md) exposes selected management and runtime operations. Their admission policies differ; all delegated Operations retain Kernel checks. See [Gateways](gateways.md) for service and transport selection.

Optional Federation provides authenticated node Sessions, scoped stream catch-up, objects and remote calls. The host supplies routes, subject mapping, application projections and merge rules. A `path://<cluster>/...` name alone provides no connection or authority; Kernel Processes remain local. Federation commit verdicts and final-delivery checks belong to its service/transport contracts, not error text or local execution evidence.

Use the rule owner to continue a review:

| Detail | Primary contract / guide |
| --- | --- |
| Compilation, buffers, live scheduling and cancellation | [Core And Portable Programs](core-and-portable.md) |
| State/Fact ports and backend recovery | [State And Facts](state-and-facts.md) |
| Gateway evidence, result delivery and retry closure | [Application Gateway](application-gateway.md), [request-store contract](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-gateway/src/idempotency_store.rs) |
| Console acceptance, authentication and delivery | [Console Runtime](console-runtime.md), [Console Protocol](console-protocol.md) |
| Source decision time and read-only inspection | [Source contract](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-source/src/lib.rs) |
| Federation retention, snapshots, call clocks and disclosure | [Federation contracts](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-federation/src/lib.rs), [transport contract](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-federation-grpc/src/lib.rs), [configuration](configuration.md#federation-publisher) |
| Standard Driver guarantees and limits | [API Reference](api-reference.md), [Configuration](configuration.md) |

Read the owning public rustdoc before implementation and acceptance tests. Cross-layer decisions belong here; domain transitions, field lists and algorithm details belong with their owner.
