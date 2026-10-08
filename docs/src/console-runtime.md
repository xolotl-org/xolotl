# Console Runtime Calls and Submissions

Console calls installed Kernel resources through one service admission path. This page covers direct calls, portable programs, retained executions, modules and subscriptions. See [Console Protocol](console-protocol.md) for the service and [Console Actions and Streams](console-actions-and-streams.md) for action names.

## Session storage owner

Hosts explicitly inject `ConsoleConfig::session_store`; missing storage is rejected. Use `MemoryConsoleSessionStore` or the redb adapter's optional `console` feature. One immutable `ConsoleSessionPolicy` governs all instances sharing the store: defaults are 5 retained sessions per account and 10,000 per storage domain. Account capacity atomically replaces its oldest `(issued_at, SID)` row; that freed slot counts toward the global quota. Otherwise a full domain rejects admission without evicting unrelated accounts. Expired rows remain charged until deleted.

Session aggregates use private typed storage, not ordinary State or history. Rows are bounded to 256 KiB including SID; indexed expiry maintenance examines at most 16 rows and 256 KiB per call. Issuance does not scan all expired rows first, so an older live account session may be replaced while newer expired rows await maintenance. Listing and bulk revocation use bounded passes. Touch/rotation update expiry without changing issuance order or capacity. Unknown creation reconciles only the original fixed SID, verifier, authority and liveness; an absent read remains uncertain and never triggers a new SID or second eviction. Account mutations are a separate commit domain.

Embedded hosts drive `ConsoleSessionStore::maintain` explicitly. The daemon runs one bounded expiry batch per second while Console is enabled and skips missed ticks; sustained expiry faster than maintenance can retain capacity, so hosts must size policy and maintenance throughput together. All live handles of one redb owner use one policy; conflicting assembly is rejected. After the owner is closed and the database reopened, a changed policy is accepted only if retained domain and per-account counts fit. Changing limits never resets counters or evicts rows.

## Rust runtime requests

Embedded hosts pass an owned `RuntimeCode::Operation { operation }` or `RuntimeCode::Program(Program)` without a program JSON round trip. A `RuntimeRequest` carries input, budget, timeout, visibility scope, justification, TTL and an optional registry revision.

| Entry | Ownership |
| --- | --- |
| `ConsoleService::run_runtime` | Attached to this request. |
| `ConsoleService::submit_runtime` | Owned by the current Console host after acceptance. |
| `ConsoleService::subscribe_runtime` | Attached to this subscription and its delivery bounds. |

Adapters reserve capacity with `service.admit_call()` before reading or decoding an untrusted body, then consume the permit through `ConsoleCallAdmission::run_runtime` or `submit_runtime`. Dropping the permit releases capacity. Hosts using the direct methods enter the same admission path.

Rust and protocol requests share authentication, MFA, exposure, imported-method grants, input limits and Kernel policy. `source` is host-verified provenance, not authority. An independent submission can outlive its observer, but not the host lifecycle; it has no persistent-program option.

`ConsoleConfig.request_anchor` may retain an `Arc<RequestProcess<'static>>` created by `Bootstrap::request_under_owned`. Otherwise requests derive from the Bootstrap root. The anchor must belong to the same Kernel, be available at assembly and carry the necessary delegation ceiling. Requests cannot choose another parent or escape that ceiling. Shutdown cancels accepted jobs and retains failed cleanup custody for later retry.

## Host runtime and work scheduling

Console shares the Kernel's `HostRuntime` for clocks, deadlines and task spawning. Hosts can supply a custom runtime; a Tokio adapter is available.

`ConsoleConfig.blocking_spawner` defaults to the Kernel's blocking port for password hashing, identity reservation and synchronous storage work. An override must bound its own workers and queue. Accepted blocking work remains owned until it settles; cancellation of its waiter does not prove that a data write was rolled back.

## General Resource Calls and Portable Composition

Domain management actions preserve account, credential and CAS invariants. The runtime entry points invoke installed kernel resources, so adding a business resource does not require another Console action.

| Action | Input and result |
| --- | --- |
| `runtime.describe` | Public runtime limits, `supported_imports`, `execution_modes` with `enabled` and `accepting`, `atomic`, the caller-visible module catalog, and current `submission_retry_scope`. |
| `runtime.resource.describe` | Concrete `target`; current kernel Resource ID, descriptive `kind`, declared `addressing` (`exact` or `prefix`), and visible Interface/Method contracts. The registered prefix root is not disclosed. Advisory: residual policy still applies. |
| `runtime.operation.invoke` | `target`, `method`, optional `input`, `output`, `collect_limit`, `timeout_ms`. |
| `runtime.program.run` | Portable Program v1 JSON in the `source` string, optional lossless Console `input` and `timeout_ms`. |

Resource discovery, direct calls, portable Operations, and module operation declarations accept concrete local paths such as `effect://app/echo` and cluster-qualified paths such as `path://edge/effect/app/echo`. The host must install the target Resource and expose its method authority; the caller must hold a matching capability. For example, `perform://path://edge/effect/app/echo` covers that clustered target, while `perform://effect/app/echo` covers only the local one. The kernel then checks the request grant, anchor rights, and policy at open and invocation. A cluster qualifier names a resource namespace; it does not install a remote transport or imply access to another cluster.

Both execution actions require MFA level 2 and outer ActionCall `scope`, `justification` and `ttl_ms`. The service limits `scope` and `justification` to 1024 bytes each before recording them in an audit. Output defaults to `unary`; `sink_only` and `collect` with a positive `collect_limit` are supported. Success returns `value`, `taint`, `outcome` (done/short), a decimal `process_id` and hexadecimal `program_id`. The program ID identifies compiled content; each execution owns a separate process. `ActionResult.unresolved_operations` is separate from that value: a successful Race may cancel a losing effect after dispatch, and a recovered failure may have already committed an external effect. The field lists known IDs needing reconciliation; `identities_incomplete` means the host could not retain every ID. An absent field means no unresolved effect was observed, not proof that no external effect occurred.

After a host installs `effect://external/example/echo`, a program source can be:

```json
{
  "version": 1,
  "body": {
    "op": "sequence",
    "steps": [
      {"op": "invoke", "operation": {"target": "effect://external/example/echo", "method": "invoke"}},
      {"op": "transform", "operation": {"op": "length"}}
    ]
  }
}
```

With a string as the outer input, this returns its character count. Variables, named functions, branches, bounded loops, parallel/race, Catch and Finally use the same kernel compiler. Preserve native tagged Value constants in source JSON; converting them to ordinary JSON loses types such as bytes. Resolve methods by name and omit `method_id`.

Enable execution through `[console.runtime]` or `ConsoleRuntimeConfig`. It is disabled by default, with no exposed resources:

```toml
[console.runtime]
enabled = true
capabilities = ["perform://effect/external/example/**", "read://state/app/**"]
max_duration_ms = 30000
max_steps = 100000
max_collect_items = 256
max_request_grants = 4096
```

Exposure only narrows authority. The caller's grants and authority ceiling must also cover each target. Both exposure and account grants may select a stable method name with `#`, for example `perform://effect/external/example/echo#invoke`; a selector without `#` covers every method in its verb/path scope. An AsyncProcess call may separately require `spawn-with://effect/external/example/echo#invoke`. Discovery and admission compare these selectors with the installed method name and its declared authority class; a method-scoped selector does not authorize unrelated methods or methodless checks. The daemon's local Console root defaults cover management, external/proc effects and business-data reads; new effect namespaces are not automatically granted. Use `RootProvisioning.additional_grants` or `[console.root].additional_grants` to extend root and its delegation ceiling during initial trusted provisioning. This never rewrites an existing account on restart. Exposure accepts unconditional selectors; conditional user capabilities are never promoted to unconditional authority. Kernel residual policy remains in force.

For ordinary method and Acting imports, preflight checks structural coverage and rejects already expired `@until` grants. It retains each matching user predicate in the request Process; the kernel evaluates the actual operation or scope input and time at each use. Distinct grants on the same path are alternatives, while predicates within one grant all apply. Discovery remains advisory. A single target admits at most 1,024 distinct alternatives, and `max_request_grants` bounds the whole program (default 4,096; configuration maximum 16,384).

Kernel attenuates each request against every structurally and rights-covering anchor grant, preserving those parent grants as OR alternatives independently of registration order. It deduplicates equivalent derived grants and rejects admission before execution if the resulting Process would attach more than 16,384 grants.

For AsyncProcess, method candidates and `spawn-with` candidates are separate alternatives: (any method grant) AND (any propagation grant), evaluated against the same actual Operation input and clock. Console passes separate method-only and propagation-only request grants to Kernel, so a propagation predicate cannot add callable method rights. Retained execution candidates keep their original domain and predicate during periodic account checks.

After host child admission, Kernel rechecks the grant conditions before derivation without rerunning stateful host policy. Callable methods use the installed `MethodAuthority` independently of the Resource scheme; `act-as` targets registered `identity://...` identities and `spawn` targets process resources.

Each installed Method declares an `authority` category. Console reads it from the host's descriptor for discovery, admission and subscription delivery; callers cannot override it. Method names and purity do not select permissions. A method named `read` on an effect may require `perform`, and a State method named `load` may require `read`. Standard State `compare_set`, `append`, `write` and `delete` require `write`; `read` and `list` require `read`; unary `subscribe` requires `subscribe`. `perform` does not grant every method of a resource. For multi-interface resources, source grants select stable method names while open requests and Handles use one resource-wide bitmap; names and ids must be unambiguous.

At initial admission, the service compiles the program, admits all imports, delegates only imported method rights and explicitly declared identity delegation. It pre-opens operation handles under the requesting identity before any effect. Input-dependent and acting-identity policies still run for each Operation. Kernel/vault/Fact reserved paths require dedicated management actions. Rust, HTTP and WebSocket share these checks and execution admission. Submission workers have separate capacity from active calls.

`resource.type.*` describes management views; `runtime.resource.describe` describes methods of a concrete installed resource. Global kernel resource enumeration is not exposed; use host naming contracts or resource directory methods.

Limits cover source bytes, outer-input Value nodes, depth and inline bytes, instructions, imports, transitions, tasks, execution container memory, collection items and deadline. The same input limits apply to protocol calls and owned Rust requests before compilation or execution. An excess returns `ConsoleFailure.code = bad_request`; protobuf encodes this as `VALIDATION_FAILED`, and HTTP uses status 400. Defaults are 16,384 logical node occurrences, depth 128 and 4 MiB of logical inline bytes. Shared descendants count at each logical occurrence; keys, scalar storage and reference metadata count, while referenced Blob/Tensor/Frame contents do not. This charge is neither process RSS nor encoded frame size. Console cannot raise kernel ceilings; driver-produced Value payloads still need resource-specific budgets. For attached calls and subscriptions, the Kernel execution deadline is the earlier of `timeout_ms` and outer `ttl_ms`. An attached call may then wait up to `executions.cleanup_timeout_ms` for the Kernel's terminal decision and a separate bounded interval for process finalization; these waits grant no further program execution time. If Kernel reports `OutcomeUnknown`, a later process-finalization failure does not erase its known `operation_ids`. If the started evaluation fails to settle within the bounded wait, Console instead reports `OutcomeUnknown` with empty `operation_ids` and reason `settlement_timeout`. A subscription keeps its visibility `ttl_ms` as a strict delivery boundary. An accepted submission has its own fixed deadline, which can outlive the request TTL. Failure, cancellation, timeout or completion-audit failure may follow committed effects; there is no implicit transaction or retry deduplication. Dropping a call cancels its request and revokes handles while the host retains cleanup work; it does not promise to run the program's Finally after its Future is dropped.

Every runtime call, subscription and submission accepts an optional `budget` map. `[console.runtime.budget]` defines the host's per-execution ceiling using the same fields:

| Field | Meaning | Input |
| --- | --- | --- |
| `max_micro_usd` | Cumulative reserved and settled cost, in millionths of a US dollar. | Unsigned integer or decimal string, up to u64. |
| `max_inflight_ops` | Operations simultaneously holding reservations, including free calls. | Unsigned integer, up to u32. |
| `max_inference_tokens` | Cumulative token reservations and settled kernel token usage. | Unsigned integer or decimal string, up to u64. |

Each dimension is optional or null; it adds no restriction when absent. Zero is a real limit. Caller and host ceilings intersect per dimension. Every Operation also charges all ancestor accounts; a new submission does not reset its ancestors' spending. Children share their parent's account even after its body finishes. These are process-tree lifetime limits with no daily/monthly reset; account-wide billing requires separate host accounting.

For example, `budget: {"max_micro_usd": "1000000", "max_inflight_ops": 4}` sets a $1 budget for an execution tree and allows at most four in-flight Operations. It does not change interpreter task slots. Reservation estimates are checked before Driver dispatch; measured usage settles afterward and may exceed estimates. Token settlement follows the kernel's output-token counter (measured usage when provided, otherwise the billing estimate); this field is not a provider's generation limit. Use resource inputs for provider-specific limits.

Successful call outputs, subscription `started`/`finished` events, and submission metadata include `budget`: the admitted tree ceiling, with all three fields present. Monetary and token limits are exact decimal strings; unrestricted dimensions are null. This is not remaining quota: children report the shared source ceiling, and ancestor accounts or recovery configuration may be tighter. The descriptor definition is `execution_budget`.

Acting scopes accept concrete local `identity://...` identities. Both host exposure and user capabilities must cover `act-as://identity/...` for every imported identity, including untaken branches and transitive modules. Admission requests only `DELEGATE` and no callable methods for each identity. The kernel checks the anchor's rights ceiling and preserves expiry and predicates; predicates evaluate against the value entering each scope. Acting changes the identity recorded in Operations and Facts, without gaining the target identity's resource grants. Scope exit restores the previous identity. Subscription delivery revalidates identity authority as well as resource authority. `max_identities` (default 128, maximum 1024) bounds distinct imports.

Signal waits become unary `subscribe` Operations on their exact resource paths. Console checks host exposure, user grants, and the installed method's output mode before effects. The method's `MethodAuthority` determines the required grant: Standard State uses `subscribe://state/...`; a custom method may instead require `perform://effect/...`. Cluster-qualified paths use the corresponding `<verb>://path://<cluster>/...` selector. User grants may be conditional. At each Wait entry, the kernel checks Operation authority and residual policy against the value entering Wait. The installed method's result completes the wait.

Standard State subscribes before reading, returns a present value (including null), or awaits the next exact Set/Append. Delete keeps waiting and contributes provenance to the eventual result or error; lag and closure fail explicitly. Its signal method requires the backend's paired observation port, including on cluster-qualified paths. A long wait does not recheck revoked kernel authority when its method completes; Console subscriptions separately revalidate before delivering an event. Calls and subscriptions retain their deadlines and cancellation. Local reserved paths still require dedicated Console actions.

## Service-owned submissions and retained results

A submission retains its bounded body-result projection as soon as evaluation returns, before draining output logs. A later drain timeout or worker abandonment preserves that result and its cleanup evidence; `stop_cause` records the first nonempty stopping reason separately. Finalization reuses the retained projection rather than encoding the body again. A settlement-timeout result is synthesized only when no body conclusion was acquired.

For an attached stream whose body is already known, expiry while draining reports `Failure::Timeout` with the retained body and independent cleanup state. `settlement_timeout` is reserved for bounded waiting that ends before a body conclusion is acquired.

`runtime.operation.submit` and `runtime.program.submit` share the invoke/run input, MFA and visibility checks. Before executing any Operation, the service reserves capacity and returns metadata plus `ActionResult.execution.execution_id`. The three `runtime.describe.execution_modes` entries have `lifetime: "host"`; submission `accepting` also reports shutdown admission closure.

An accepted job survives a dropped response, observer disconnect, logout and session expiry. It retains no bearer or SID as execution authority. The original `timeout_ms` (or host `max_duration_ms`) fixes its execution deadline; `ttl_ms` bounds admission and immediate disclosure, not the accepted job. Calls and subscriptions use the earlier execution/visibility deadline. Without `submission_identity`, distinct submit calls remain nonidempotent fire-and-forget submissions; losing a response does not make repeating them safe.

Both submit actions optionally accept `submission_identity: {registry_instance, retry_epoch, nonce}` for explicit response-loss retry protection. Take the instance and epoch from `runtime.describe.submission_retry_scope` and retain a nonce before submitting. `retry_epoch` is a canonical unsigned u64 decimal **string** (`"0"` or digits without leading zeros), not an integer. The identity belongs to the immutable account instance, not a SID, and grants no authority. First guarded acceptance returns full job metadata plus `submission_evidence: "accepted"`. An existing retry of the same identity and request returns the original `ActionResult.execution` and only `{execution, submission_evidence}`, with evidence `accepted` or `retired`; it does not recompile, redispatch or choose a new deadline. Changed requests under that identity are rejected. Reference-only retries avoid a record-read expiry race; use `runtime.execution.get` or `runtime.execution.result` separately under their own contracts to retrieve the record. Submit output metadata fields are optional to allow these retries. After output or record retirement, `retired` preserves the original reference rather than creating a replacement job.

`runtime.submission.lookup` takes the same required identity and returns only `{evidence, execution}`: `unproven`, `preparing`, `accepted` or `retired`, with a null reference for the first two and the original reference for the latter two. It uses the ownership, MFA and visibility admission of `runtime.execution.get`, returns no payload or output, and has no dispatch or mutation side effect. `preparing` is not acceptance; `unproven` is not proof that no effect occurred or permission to replay.

`max_records` and `max_records_per_account` bound shared logical entries, including Preparing reservations and retired tombstones; a record and its alias count once, with no separate retry-history configuration. The trusted host can advance the expected epoch with `ConsoleService::close_submission_retry_epoch`; there is no client close action. Retained aliases in closed epochs remain queryable, but absent identities in those epochs cannot execute. Host restart changes the registry instance and rejects old-instance identities; it does not prove that old effects did not occur.

The stock daemon closes retry epochs using the monotonic `console.submission_retry_epoch_ms` cadence when runtime submissions are enabled; see [Configuration](configuration.md). It reuses the one-second Console session maintenance task and performs due closure before session-store I/O. A delayed tick closes one epoch and schedules from the actual close time, without catch-up generations. The interval is not a per-request TTL: actual closure rejects unknown old identities; retained original records still provide acceptance evidence. Result expiry and epoch closure remain independent, and closure does not release pending execution cleanup. Embedded hosts use `ConsoleService::submission_retry_scope` and the explicit close method to choose their own policy; a host that never closes ranges keeps tombstones charged and can exhaust new admission.

Execution account authority does not depend on the submission SID; a new session for the same account instance can observe old jobs. Disclosure validates the current request SID after the last relevant wait, including account and credential queries; ordinary idle renewal remains valid. Embedded hosts can synchronously call `ConsoleService::close_execution_admission(&self)` to close only independent submissions without cancelling accepted work or closing ordinary calls and observation. `shutdown_executions` reuses this step and still cancels jobs and awaits bounded finalization.

| Action | Behavior |
| --- | --- |
| `runtime.execution.get` | Read metadata without payload. |
| `runtime.execution.list` | List this account instance's metadata using bounded, opaque-cursor pages. |
| `runtime.execution.result` | Read `record`, lossless `output`, `retention_failure`, `unresolved_operations` and separate `finalization`. |
| `runtime.execution.output.read` | Page retained Stream events with `cursor`, `limit`, `max_bytes` and `wait_ms`. |
| `runtime.execution.cancel` | Request cooperative cancellation and return current metadata; requires MFA. |
| `runtime.execution.forget` | Remove a settled record, once cleanup and live-source receipt dependencies end. |

All six actions enforce immutable account-instance ownership. Recreating a username cannot inherit old jobs. Metadata and cancellation do not require continued resource grants; result and output reads recheck MFA, visibility, host exposure and all original operation/acting grants. Unavailable, expired and another account's records are indistinguishable. List budgets come from `console.queries`, and cursors bind the account and host instance.

Stream logs belong to executions, not submission connections. Pages return `entries`, `next_cursor`, `last_sequence`, `has_more` and `complete`; observers page independently and may wait up to 30 seconds. Authorization is repeated before delivery. Event and terminal retention have separate bounded capacity from the final result. `max_output_page_bytes` must fit a maximum event plus delivery metadata; a smaller requested page may require a larger `max_bytes`.

Workers check account identity, revocation/credential epochs and retained conditional grant candidates before effects and periodically while running. A confirmed revoke, missing covering grant or inability to establish current authority stops the job. `authority_poll_ms` controls check frequency; `authority_timeout_ms` bounds each check. Kernel still evaluates policy per Operation. Logout alone does not revoke accepted job authority.

Cancellation grants lexical Finally work a bounded opportunity under the original deadline and the method's `finalize_allowed` contract. Lifecycle cleanup has separate bounded attempts; failed cleanup is retried without rerunning the body. Capacity remains charged until the attempt exits and Kernel confirms cleanup. Expiry hides results but cannot release pending custody. Cancellation or deletion never rolls back completed effects.

Metadata separates `status` (running, cancelling, finalizing, finished), `outcome`, `result_status` and `cleanup_status`. Submission and child lifecycles use live execution records and Kernel cleanup reports, without additional lifecycle audit writes. Authentication and visibility security events have their own contracts. Oversized results may be omitted without changing a successful body outcome. Known unresolved identities remain independently available in `runtime.execution.result`, even when output is omitted. Unknown interruption stays unknown; diagnostic failure does not imply rollback. Children additionally identify their source execution and full operation ID. Timestamps use Unix milliseconds.

`finalization` has `status: "pending"`, `"available"` or `"omitted"`, a nullable `report` and nullable `retention_failure`. An available report includes lifecycle terminal status, ordered taint, sanitized indexed finalizer failures, and released/revoked handle counts. Body `outcome` remains independent of that lifecycle status. Unresolved body and finalizer identities are merged in the separately bounded `unresolved_operations` sidecar; report omission never proves that all effects are known. Console captures the projection before releasing cleanup custody, so the result remains queryable after Kernel automatically retires its Process. Later cleanup confirmation does not replay the body or extend result retention.

Metadata and retained Stream terminal entries also expose nullable `stop_cause`. Host-classified causes such as `output_limit`, `authority_revoked`, `shutdown` and `timed_out` remain observable without replacing a known successful body or its typed failure. Body `outcome` consistently classifies Done, Short, Cancelled failure, Timeout failure, other failures and missing output as `done`, `short`, `cancelled`, `timed_out`, `failed` and `interrupted`, respectively. Output-limit cancellation still drains in-flight ports and preserves unresolved effect identities. Reads reconcile already committed cleanup evidence for their target, and lists reconcile only their bounded candidate page, before reporting complete; they do not run cleanup I/O or expire records. Forget performs the same evidence handoff before releasing custody.

Attached calls and subscription failures can carry bounded `ConsoleFailure.runtime_completion` with `body`, `body_retention_failure` and separate `finalization`; lifecycle failures also include a safe `cleanup_failure`. Execution references and known unresolved identities remain independent. Trusted Rust hosts can inspect native-only `finalization_error.error`, which retains the typed `RequestFinishError` and its original cleanup ticket for retry. This custody is never serialized to clients. Failed encoding, delivery or revision reporting does not authorize replay or undo effects; delivery still requires current authorization and a transport frame large enough for the error.

```toml
[console.runtime.executions]
enabled = true                  # also requires console.runtime.enabled
max_concurrent = 32
max_concurrent_per_account = 8
max_records = 256
max_records_per_account = 64
max_authority_bytes = 32768
max_result_bytes = 262144
max_finalization_bytes = 65536
max_output_event_bytes = 16384
max_output_page_bytes = 131072
max_output_events = 1024
max_output_bytes_per_execution = 1048576
max_output_bytes_total = 33554432
retention_ms = 900000
cleanup_timeout_ms = 5000
authority_poll_ms = 1000
authority_timeout_ms = 1000
```

Every active or retained record reserves result, finalization and authority capacity before execution. Stream jobs also reserve their log slot. `max_finalization_bytes` bounds retained report JSON bytes independently of body result bytes; its default is 64 KiB and configuration above 4 MiB is rejected. The projection borrows typed failures for redaction, retains encoded bytes directly and decodes on observation. These byte charges do not bound the original report, transient conversion allocations, allocator capacity or process RSS. `ConsoleService::shutdown_executions` closes admission, cancels jobs, stops background cleanup and performs a bounded final pass; pending cleanup remains in custody for a later shutdown attempt. A shutdown timeout does not cancel an accepted blocking disposal job: its owner remains until the job actually ends, and cleanup cannot be confirmed earlier. All records and logs disappear with the host.

`max_authority_bytes` bounds each record's complete logical JSON representation of owner, operation authority, origin, retained candidate Capabilities and actual budget, including punctuation and escaping; shared candidates are charged in full per record. It is not an RSS limit. Root and child reservations accept equality and reject overflow before consuming a record or execution slot; children inherit the source's actual budget and candidates. Candidate retention continues to support current permission and revocation checks.

## Child processes in submissions

Independent submissions support `output: "async_process"`. The installed method must support it, and callers need both the method grant and `spawn-with` authority; attached calls/subscriptions cannot detach a child.

Before Driver dispatch, each child reserves its own account/global slot and inherits the account ceiling and original submission deadline. Its parent result contains an `ExecutionReference`. The child has independent result, cancellation and cleanup ownership; ending the parent does not cancel an independently owned child.

`source.operation_id` retains process, execution, invocation, position and explicit retry attempt. Repeating that exact live-source invocation returns its existing accepted reference rather than dispatching twice. A reservation awaiting Kernel confirmation is not an accepted receipt; distinct requests and explicit retries remain independent.

A finished child's receipt remains charged while its source is active. Expiry hides the result without losing the reference needed by the original invocation; `forget` rejects deletion until source and cleanup dependencies end. These receipts are in memory only. Unknown effects and failed cleanup keep their original identities and custody; cleanup retries do not replay the Driver.


## Host module composition

Rust hosts assemble `ConsoleModule::new(ModuleManifest, loader)` into `ConsoleModules::new` or combine independent catalogs with `ConsoleModules::compose`, then set `ConsoleConfig.modules`. The daemon uses an empty catalog; native loaders are installed by Rust host code. A remote portable `Module` contains only a name and optional argument, and receives the piped input through the kernel.

Each manifest declares a semantic 32-byte `revision`, concrete local or cluster-qualified Resource/method/output contracts in `operations`, concrete local Acting identities in `identities`, concrete local or cluster-qualified Signal resource paths in `signals`, and direct module dependencies in `modules`. Assembly rejects duplicate names, malformed contracts and missing dependencies.

`runtime.describe.modules` returns complete canonical manifests projected for the current caller and host exposure. A module is listed only when every declared operation method supports its output mode and is visible, every `Collect` bound fits the host limit, and every Acting identity, Signal subscription, and transitive module dependency is visible. An AsyncProcess operation also requires `spawn-with` on its target. The response does not trim individual manifests or reveal denied dependencies. Its `config` omits the host's concrete capability selectors.

The original installed manifests, including their complete content, participate in `registry_rev`; that revision does not track caller grants and cannot by itself validate a module-list cache across users or authority changes.

The module catalog describes installed structure; `execution_modes` reports which execution lifetimes are currently available. Discovery is a structural, advisory projection: the selected request lifecycle, program budgets, input-dependent residual policy, and current execution admission are checked separately at use.

Host assembly rejects a canonical manifest catalog whose complete JSON array exceeds 512 KiB after sorting and deduplication. This bounds catalog projection work but does not guarantee delivery under every transport frame configuration.

For `operations[].output`, `collect.limit` is the maximum item count the module may request. It must be positive. If it exceeds the host's `max_collect_items`, discovery hides the module and admission rejects use before allocating a process. An output mode unsupported by its installed method has the same behavior. Other output modes are declared exactly.

Canonicalization merges redundant smaller `Collect` bounds for the same resource and method; changing the effective bound changes `registry_rev`. Hosts must change the revision whenever loader semantics or captured configuration changes. Actions and subscriptions both accept a registry revision precondition, checked before resolving the action/stream name or starting any execution.

Admission traverses the full dependency graph, including cycles, and authorizes every transitive operation, signal and identity before any top-level effect. The traversal is bounded by `max_modules` (default 64), `max_operations`, `max_identities`, and `max_request_grants`. Each dynamically returned program uses the same exact source-byte ceiling and instruction/depth limits as direct programs. Rust programs, including module results, first pass structural validation and then bounded compact JSON encoding before compilation; escaped characters count at their encoded size. Protocol source is bounded at its actual JSON byte length before decoding. A rejected module starts none of its returned operations, without rolling back earlier enclosing-program effects. Before its first effect, operations must match the module's own declared target, method and output mode. A `Collect` request must have a `limit` between 1 and the declared maximum; module imports must be declared direct dependencies; Acting identities must appear in the module's own manifest, as must Signal paths. Signal operations count toward `max_operations`. Numeric method IDs are rejected. Kernel cumulative code/frame/step limits still bound recursive module calls. Unary calls and runtime subscriptions use the same loaders.

A loader is trusted, synchronous host code. It must be pure, total and bounded; I/O, clock access and randomness belong in returned Operations. Console checks the returned program, but cannot preempt a blocking native function or enforce the purity of a Rust closure. Client source cannot install native code. See the public host composition regression in `crates/xolotl-console/tests/http.rs`.

## Shared subscriptions and live execution

`ConsoleService::subscribe(bearer, source, StreamCall)` is the subscription entry point for embedded hosts and custom transports. WebSocket uses the same admission and source ownership. The returned `ConsoleSubscription` is an owned receiving edge: `recv()` returns one `ConsoleEvent`, a terminal `ConsoleFailure` once, or `None` after completion. Dropping it closes the source and requests cancellation; `close().await` also joins its execution worker. Cancelling a pending `recv()` retains any event already read but still awaiting authorization. `ConsoleSubscription::execution()` exposes an allocated runtime reference immediately; the WebSocket acknowledgement carries it too. A terminal `SubscriptionClosed.failure` retains the reference even before the first event.

If a State watch is invalidated by an uncertain commit, the subscription reports a terminal failure. The client must reread authoritative State and subscribe again; the old event stream cannot establish whether that write committed.

Every delivery checks the current session, MFA epoch, identity, effective grants and target authority. Changes to identity, grants or MFA close the subscription. This check is read-only: server output neither renews session idle time nor writes session State that could recursively trigger a watch. Client requests and explicit refresh remain session activity. Visibility expiration is checked before and after receiving; queued data cannot escape an expired subscription.

`[console.streams]` applies across Rust and all WebSocket connections:

| Setting | Default | Bounds | Meaning |
| --- | --- | --- | --- |
| `max_subscriptions_global` | 1024 | 1–65536 | Reserved subscription handles on this host. |
| `max_subscriptions_per_account` | 64 | 1–4096 | Reserved handles for one authenticated account instance. |
| `max_event_bytes` | 1048576 | 1024–4194304 | Canonical v1 event envelope size, including the largest stream ID. |

Limits are clamped at host assembly and exposed as `runtime.describe.subscription_limits`. They participate in `registry_rev`. Event admission also bounds recursive Value conversion. A subscription retains its reservation until it is closed, dropped or consumed to termination. A retained handle is not a detached job. Rust callers own any values they retain after receipt; source storage and transport buffers have separate budgets.

`runtime.operation.stream` has the same input fields as `runtime.operation.invoke`, but `output` defaults to `stream`. `runtime.program.stream` accepts the same portable v1 source and input as `runtime.program.run`; each operation selects its own output mode. Both use `StreamCall.scope`, `justification`, and `ttl_ms`, require MFA level 2, and perform the same complete import preflight as calls. A successful subscription starts execution: retrying a lost subscription acknowledgment can repeat effects. These streams do not support replay, reconnection to an existing execution or a resume cursor. Use retained Facts and process observations to investigate uncertainty.

`runtime.describe.execution_modes` identifies each contract by `(mode, lifetime)`:

| Mode | Lifetime | Owner | Output modes |
| --- | --- | --- | --- |
| `call` | `host` | `request` | `unary`, `collect`, `sink_only` |
| `subscription` | `host` | `subscription` | `unary`, `collect`, `sink_only`, `stream` |
| `submission` | `host` | `service` | `unary`, `collect`, `sink_only`, `stream`, `async_process` |

Each row includes `entries`, `enabled` and `accepting`. Disabled contracts remain visible; `enabled` reflects build support and host configuration, while `accepting` additionally reflects submission shutdown. Clients select a row by its pair of identifiers, not its position or a cross product of separate mode and lifetime lists. Its output modes still require installed method support, authority and the configured collection limits. Discovery reserves no capacity and is not a promise that a later request will be admitted. The action descriptor defines this row as `execution_mode`.

A streamed program can combine Unary, SinkOnly, bounded Collect and Stream operations, including parallel branches. Both call and subscription execution share `max_concurrent_calls`; subscriptions cannot evade the host's action capacity.

The runtime output router provides a separate kernel `StreamWindow` for each operation. `[console.runtime]` declares `max_output_streams` (default 16, maximum 256), `stream_window_chunks` (16, maximum 4096), and `stream_window_bytes` (262144, maximum 4194304); zero is invalid. Ports awaiting delivery still occupy capacity. Opening beyond that capacity fails the operation. Kernel byte credits use lossless tagged JSON including taint, independently of the protobuf event bound. Between the kernel ports and the caller, one queued projected event and one event being sent are retained, plus a bounded terminal slot. A slow reader backpressures execution; WebSocket additionally closes a subscription if its own queue fills.

The worker's deadline includes output delivery and process finalization, and is capped by `ttl_ms`. It releases execution capacity even if the reader stops polling. Drop, unsubscribe, expiry, delivery failure or failed authorization cancels unfinished attached work; cleanup follows `RequestProcess` ownership. Once the body returns, its terminal decision, provenance and unresolved identities are handed to Kernel before waiting on delivery. A later drain failure or delivery timeout retains the body for cleanup and bounded failure projection instead of replacing it with cancellation. Worker abandonment preserves the handed-off cleanup evidence; it cannot guarantee delivery to a closed receiver. Completed effects are not rolled back, and future cancellation cannot execute asynchronous Finally bodies.

The protobuf `ConsoleEvent.runtime` payload is a lossless Value with a `kind` discriminator. The stream descriptor supplies the four variant schemas:

| `kind` | Fields | Ordering |
| --- | --- | --- |
| `started` | `process_id`, `program_id`, `budget` | Before execution outputs. |
| `output` | `operation_id`, `value`, `taint` | Ordered within one operation; parallel operations may interleave. |
| `operation_finished` | `operation_id`, nullable sanitized `failure`, `taint`, `origin` | After that operation's chunks. Origin is `current_attempt` or `cached_outcome`; cached completion does not replay chunks. |
| `finished` | `process_id`, `program_id`, `budget`, `outcome`, `value`, nullable sanitized `failure`, `taint`, `unresolved_operations`, `finalization` | After all operation output ports drain and request finalization succeeds. Outcome is `done`, `short` or `failed`. |

Identifiers remain decimal strings or the kernel operation ID string, so clients need no unsafe JSON number conversion. The full terminal sidecar counts toward `max_event_bytes`; if the event exceeds that bound, the terminal error retains the sidecar. A transport frame must also be large enough to encode the error. Retained Stream terminal entries expose only the count and incompleteness summary; use `runtime.execution.result` for full IDs. Normal completion drains queued events before WebSocket emits `SubscriptionClosed`. Timeout, cancellation or transport loss can close before `finished`; in particular, expiry of the subscription visibility `ttl_ms` ends delivery even when a Kernel result with known `operation_ids` might arrive later. When the execution deadline is earlier than that TTL, a bounded settlement interval can still deliver a terminal result before visibility ends. An absent final event never proves that nothing happened.
