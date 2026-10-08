# API Reference

Rustdoc is the source of truth for public Rust signatures and trait contracts. Generate the workspace index with:

```sh
RUSTDOCFLAGS='-D warnings -W missing-docs' cargo doc --workspace --all-features --no-deps --locked
```

Open `target/doc/index.html`. Cargo replaces hyphens with underscores in crate paths, for example `target/doc/xolotl_sdk/index.html`.

## Choose a crate

| Need | Start with |
| --- | --- |
| Allocation-free control flow | `xolotl-core` |
| Embedded host facade and portable programs | `xolotl-sdk`, `xolotl-graph`, `xolotl-plan` |
| Resources, authority and invocation | `xolotl-types`, `xolotl-kernel` |
| State, objects and bundled implementations | `xolotl-state`, `xolotl-value-object`, `xolotl-standard`, `xolotl-storage-redb`, `xolotl-storage-fs` |
| Application and external services | `xolotl-gateway`, `xolotl-gateway-grpc`, `xolotl-gateway-websocket`, `xolotl-gateway-mcp` |
| Console and wire formats | `xolotl-console`, `xolotl-proto` |
| Optional node federation | `xolotl-federation`, `xolotl-federation-kernel`, `xolotl-federation-grpc`; `xolotl-storage-redb` for durable federation state |

The default SDK exports only `xolotl_sdk::core`. The `host` feature adds `KernelBuilder`, `Bootstrap`, `Xolotl` and hosted execution. The optional `memory` feature adds an in-memory State adapter and convenience constructors. `standard`, `plan` and protocol adapters are independent choices; see [Core And Portable Programs](core-and-portable.md#feature-selection).

Federation is optional and does not change local SDK calls. `FederationService` composes an authoritative `FederationStore` for publication, subscription, inbox and projection positions. `FederationKernelCallBridge` binds a prepared remote CallRef to one live local Kernel request. `FederationGrpcSubscriberClient` and `FederationGrpcPublisherServer` adapt those ports to an authenticated Session; `FederationGrpcObjectSource` binds a pinned client and exact `ObjectReceiveSpec` to `FederationObjectReceiver::fetch`. After content verification, an embedding host implements `FederationObjectReferenceStore` to durably publish and hold its exact application reference, then calls `bind_verified_object`; that function retains the host guard through the receive receipt's `Verified`→`Bound` CAS. A crash between the two commits is retried under the same transfer identity. The host still coordinates all its other references with object GC. See [Federation configuration](configuration.md#federation-publisher) for stock assembly and the [FederationStore contract](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-federation/src/lib.rs) for retention and recovery rules.

## Assemble and run

Federation hosts use `ServedCapability` to select the required group:
`server.connected_peer(peer, capability)` filters the bounded registry by the
authenticated served group, and `client.serves(capability)` checks a connected
peer's advertisement. This selection does not replace current operation
authorization. Daemon object reception clones the `PreparedPublisher` transport
runtime, so receiver connections share its admission, cancellation and drain
domain. Wire version and group values belong to [Federation configuration](configuration.md#federation-publisher).

`KernelBuilder::new(state)` takes the host-selected State backend; ordinary request cleanup needs no write port. Facts default to disabled; install a selected sink with `with_fact_sink`. The builder creates a fresh in-memory execution ID source independently of Facts. Persistent or shared execution namespaces must explicitly use `with_execution_ids`; an installed sink is bound to the chosen IDs. The builder also selects the caller identity port. `build()` returns a Kernel without starting a listener or task. `Bootstrap::from_kernel` initializes its root Process; `Xolotl::from_kernel` adds the SDK execution facade. `Xolotl::bootstrap()` exposes the same host's request and cleanup services. Install standard resources explicitly and delegate their methods to each request Process. `Kernel::identities()` registers concrete local `identity://...` paths in one shared namespace; persistent hosts install the same durable directory with `KernelBuilder::with_identity_directory` before admitting work. A retained `IdentityRef` is meaningful only in the directory that issued it; `process://...` addresses a process resource.

All SDK request helpers, including `run`, `run_with_steps`, `run_plan` and `run_plan_with_steps`, take an explicit caller `IdentityRef`; choose `IdentityRef::ROOT` only for a deliberate system request. The caller identity does not grant resources; the trusted host must authorize each resource allowlist before calling these helpers. Use `Xolotl::run_program` or `run_prepared` for portable programs. `PreparedProgram` shares immutable instructions across calls; each execution owns its mutable buffers. `run_prepared_with_buffers` reuses caller-provided empty containers. Inputs are `TaintedValue`; SDK results are `ExecutionCompletion { output, finalization }`. Access `output: ExecutionOutput` explicitly for its outcome, taint and bounded unresolved effect identities. `output.into_parts()` returns the lineage-bearing result together with those identities, so composition cannot silently discard reconciliation evidence. `finalization: Option<Arc<ProcessFinalizationReport>>` independently retains cleanup evidence; `None` means preparation rejection before Process admission. See [Core And Portable Programs](core-and-portable.md) for preparation, limits and the low-level `LinkedExecution` path.

If request finalization fails after evaluation, the helper returns `XolotlError::Finalization { process, output, source }`. The original output and its taint remain available; `source: RequestFinishError` retains the typed cause and original `cleanup` ticket. Keep that ticket and call `Bootstrap::resume_cleanup(&source.cleanup)` to retry the selected cleanup scope without replaying the body; `source.cleanup.finalization_report()` can observe a later committed report. `CleanupWaitExpired` means a caller's observation deadline elapsed, not cleanup completion or rollback. Admission failures use `XolotlError::Bootstrap` because no body output exists yet. Successful `RequestProcess::finish` returns the report `Arc` before releasing its pin; a retained report does not prevent automatic Process retirement.

`Bootstrap::request_under` creates an owned request scope. Its `RequestProcess` owns cancellation and finalization; `finish` commits terminal cleanup, while `detach` transfers that duty to the host. A dropped bare Executor future does not finalize its Process. `drain_cleanup` retries retained lifecycle work. See [Runtime Model](runtime-model.md#process).

Ordinary request cleanup works with a read-only or empty State port. Actor directory and asynchronous-result publication require their own business write capability; their commit failures preserve the original result and pending publication responsibility.

Standalone execution uses `Executor::new(process, identity, data_plane, registry)`; the identity is required and the host owns its lifecycle. This path can compose independent Registry and HandleTable instances. `Executor::from_process_table(...)` instead reads identity and lifecycle from a process admitted by `Bootstrap`; pass the associated Kernel-owned ProcessTable, HandleTable, Registry and host clock. It rejects a missing Process during execution. Both constructors return `Result` and reject partially bound or mixed Kernel runtime tables; neither grants rights. Trusted hosts composing an Executor or FactSink outside Kernel assembly install the issuing directory with `Executor::with_identity_registry` and `FactSink::with_identity_registry`, then open or bind the required Handles. A bare `IdentityRef` cannot prove its path in a different directory. `Executor::with_steps` selects an immutable host module for native continuations.

`HostDeadline` belongs to the `HostRuntime` clock that created it. Deadline setters, comparisons, remaining-time calculations and sleeps reject values from another clock domain with `ClockDomainError`; a runtime clone retains the same domain.

## Fact Observation

`FactStore::is_enabled()` defaults to `true` for installed implementations. The disabled sink rejects writes and checked reads as uninstalled, rather than returning an empty history. `record: true` remains fail-closed when no sink is installed. `Bootstrap::record_optional_gateway_audit` skips an uninstalled observation sink but propagates errors once installed; `record_gateway_audit` remains strict. Optional observations are not required business commit barriers.

`InMemoryFactStore::new()` and `with_capacity` use `FactRetentionLimits::default()`; `with_capacity` selects broadcast capacity, not retention capacity. `with_limits` selects explicit retention limits:

| Field | Default | Charged object |
| --- | --- | --- |
| `max_records` | 4,096 | Retained Fact records |
| `max_encoded_bytes` | 64 MiB | Aggregate encoded records |
| `max_record_bytes` | 1 MiB | One encoded record |

These are not RSS limits. Atomic capacity rejection leaves records, cursor and notifications unchanged; duplicate begin adds no charge, and completion charges the net encoded-size change. No automatic Fact retirement is provided. The [Fact rustdoc](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-kernel/src/fact.rs) owns storage and charging rules.

`RedbStore::fact_store_with_limits` applies the same budgets transactionally and retains usage across reopen. Adapters on one live database must select identical limits. When both derived retention counters are absent, installation reconstructs their charge once from actual retained rows; partial counters or a record-count mismatch reject installation. `fact_store()` uses the defaults above. The daemon opts into these budgets using `[storage.observations]`; without that section it still retains execution identities independently of observation storage.

## State

The redb current domain retains provenance for deleted values independently of history, including in `CurrentOnly` and after `Full` history trimming. Comparisons, pages and Source appends consume that current provenance. An absence page may contain no entries but still carry provenance, consumed bytes and a continuation cursor. `StateRead::read_tainted`, `StateBoundedRead::read_tainted_bounded` and the snapshot in `Backend::observe_signal` return `StateObservation { value: Option<Value>, taint: TaintSet }`, including provenance for absence. `Backend::observe_signal_current` rereads the same paired Signal domain. `read` and `read_bounded` explicitly discard provenance. Bounded redb observations limit individual current records; `RedbOptions::absence_limits` separately limits retained sourced-absence records and encodings with the same defaults as memory.

### In-Memory State

`InMemoryBackend::with_options(InMemoryOptions)` returns `StateResult<InMemoryBackend>`. Its options independently control reads, retention and capacity:

| Field | Default | Accounting and behavior |
| --- | --- | --- |
| `read_shards` | 1 | Nonzero; 1 uses an inline map. More shards add locks and resident memory for point reads of different keys; writes remain serialized and prefix reads capture a consistent snapshot |
| `history` | `MemoryHistory::Disabled` | No history capability by default; `Full` retains non-vault mutations until trimmed |
| `notification_capacity` | 256 | Nonzero; at most 1,048,576 events. A full pending queue rejects matching writes before commit; slow broadcast receivers can still lag |
| `source_stream_limit` | 4096 | Nonzero; at most 65,536 Source stream identities. At capacity, new identities are refused before their first commit; existing streams may advance |
| `absence_limits` | `Some(65_536)` records / `Some(64 MiB)` encoded bytes | Keys plus full sourced-absence encoding; `None` removes a dimension. Zero rejects new charge; lowered quotas permit non-growing usage, preserving evidence |

`InMemoryBackend::new()` uses defaults. `with_notification_capacity(NonZeroUsize)` also returns `StateResult<InMemoryBackend>` and leaves other options at their defaults. Unsupported capacities and shard reservation failures return errors. Disabling history does not bound live values or payloads; logical capacities are not allocation or host RSS limits. On the direct memory history port, disabled history only permits `read_at(path, 0)` for the current observation; other historical queries return `MissingCapability`.

Custom adapters implement provenance-preserving atomic mutations in `StateWrite::mutate`; `write_merge` and related helpers delegate to that port. See the [State mutation contract](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-state/src/write.rs) for shared transitions and commit contracts.

## Extend the host

Use `MethodSpec` and Resource/Interface declarations to expose a Driver; `MethodAuthority` declares the method's actual capability verb. Use `StandardConfig::with_modules` to select bundled implementations and `with_inference_backend` or `with_object_store` to supply host adapters. State, Fact, stream and object ports can be implemented independently. See [Capability Model](capability-model.md), [State And Facts](state-and-facts.md) and [Incremental Values](incremental-values.md).

The standard `effect://approval/{ask,check,respond}` broker stores one record per `dedup_key`, identifying one business approval. Use a distinct key for a different approval; deleting and recreating a record under the same key neither isolates pending responses nor starts a separate approval round. `ask` creates it once; duplicate asks retain the original fanout, quorum and deadline. Responses use full-record CAS: RequireAll merges concurrent votes, while AnyOne retains the first committed decision. Terminal decisions cannot be rewritten by late responses. Conflicts permit at most eight commit attempts; other storage failures, including commit uncertainty, are not retried automatically. Deadline checks use the Kernel's `HostRuntime` clock (`0` means no deadline; a pending record expires strictly after its deadline); request-supplied `now_millis` is rejected. `check` does not write expiration. Authorized brokers remain responsible for authenticating the human response: an approver label is not an identity credential. These records are not wired automatically into a Kernel policy approval registry, nor do they prove that an external action executed.

The standard `effect://time/{now,sleep,cron}` effects also use the installed Kernel's `HostRuntime`. `now` returns Unix milliseconds; `sleep` waits for a nonnegative duration on that host's monotonic clock, unaffected by wall-clock changes. Zero duration completes without a host wait. Dropping its future cancels only that wait through the host clock contract. `cron` computes a next timestamp, not a registered recurring schedule: use a positive `interval_ms`, or positive `every` with `unit` (`s`, `m`, `h`, `d`, default `s`); the two forms cannot be combined. Interval multiplication, next-timestamp addition and monotonic deadline construction reject unrepresentable results rather than panicking, wrapping or saturating. A custom timer does not make the entire host build Tokio-free or provide durable scheduling.

`StepModule` composes named native functions and portable loaders. Actors and ordinary requests attach their own module snapshots. `AsyncProcess` requires an explicit host custody implementation; see [Programs And Replay](programs-and-replay.md) and [Runtime Model](runtime-model.md#process).

## Terminal installation

Embedded hosts explicitly pass a shared `TerminalRuntime` to `StandardConfig::with_terminal_runtime`; installation without that owner fails. `TerminalRuntime::default()` admits at most 16 concurrent commands; `new(NonZeroUsize)` selects another finite bound. Exhaustion rejects before spawning rather than queueing. A slot charges one supervisor, its direct child and two bounded output buffers, not process RSS; output buffers default to 1 MiB each and permit at most 16 MiB each. One supervisor polls child exit and both pipes, retaining the slot through direct-child reaping. The full timeout covers pipe EOF as well as child exit, including inherited pipes held open by descendants.

Calls require the originating `DriverContext.operation_id` before admission.
Post-spawn timeout, I/O failure or close returns `OutcomeUnknown` with that
original identity, including when a program handles the failure. Reaping the
child releases custody, not evidence of external-effect rollback or permission
to replay. Policy, capacity and spawn rejection remain known pre-effect failures.

`close()` permanently closes admission and cancels accepted calls; `shutdown().await` also drains their cleanup. Keep the host executor alive until draining completes. Concurrent or cancelled shutdown waiters do not discard cleanup custody. Cancellation, timeout and close drop pipes and kill/reap the direct child, but do not track or kill descendants or roll back effects. Command authority and the custom-Driver boundary belong to [Security And Boundaries](security-and-boundaries.md#driver-boundaries).

## Execution ownership

SDK request helpers own request cleanup. Console [service-owned submissions](console-runtime.md#service-owned-submissions-and-retained-results) transfer execution to the live service and retain bounded results. Hosts select persistent backends for State, Source, objects, identities and application call records independently of program execution. See [live suspension and data persistence](core-and-portable.md#live-suspension-and-data-persistence).

## Streaming And Objects

`xolotl_kernel::stream::{StreamSink, StreamRouter}` are portable output ports. Their contracts require neither Tokio nor `Send`/`Sync`; host adapters install those bounds explicitly. `host::stream::channel(StreamWindow)` bounds accepted and borrowed chunks by count and encoded inline bytes, defaulting to 64 chunks and 256 KiB. These windows do not limit total stream traffic. Dropping a `StreamChunk` releases its credits; `into_value` transfers the value to the caller and releases the transport credits. The caller owns any further retention. `StreamEnd` follows outstanding chunks and carries input and final-result provenance. Each chunk retains its own provenance. A cached invocation reports `CompletionOrigin::CachedOutcome` on its completion; this does not change the origin of a program that executes using that invocation.

Streaming invocations require an explicit sink or router. The invocation owns its producer future; receiver closure and cancellation drop that future. State does not implicitly collect chunks. See [HTTP Inference Providers](http-inference-providers.md#incremental-http-data) for the bundled HTTP stream adapters and their response limits.

`xolotl_state::object::{ObjectRead, ObjectWrite, ObjectDelete}` provide independent portable capabilities. The host `ObjectStore` installs them with `with_read`, `with_write`, and `with_delete`. Supply it through `StandardConfig::with_object_store`; `FileObjectStore::into_object_store` installs the file adapter. Reads fill caller-owned buffers. Uploads acknowledge partial writes and publish a reference only after commit. Stateful uploads must attach their cleanup owner with `UploadId::with_lease`; the final owner drop releases abandoned staging or transfers cleanup to the adapter's reliable mechanism. `UploadId::stateless` is only for uploads without resources requiring cleanup. Cancelling `begin_upload` before it returns an id must also release its unclaimed staging. Explicit abort permits earlier cleanup; callers do not need to spawn an asynchronous abort task from `Drop`. Missing capabilities produce explicit errors.

`ObjectStore::write_all` advances through borrowed windows and partial writes, validates each acknowledgement, and returns the next offset. Its nonzero window does not limit cumulative upload size. It does not commit or abort; the upload owner handles failure, cancellation, and staging cleanup.

For `FileObjectStore`, dropping the final upload lease immediately revokes its identity and hands staging to one lazily started, bounded cleanup thread per owner. The thread starts on the first upload, not read-only use, and is independent of the caller future and Tokio runtime lifetime. Queued and running cleanup retain their upload slots until cleanup finishes; explicit abort waits for physical cleanup. `pending_uploads()` counts registered upload identities, not cleanup completion or available slots. A completed upload with a lost receipt retains its slot until the original owner retrieves the receipt with the same sealed request or abandons it. Limits and defaults are in [Configuration](configuration.md#runtime-configuration).

On Unix, a successful file-backend commit confirms synchronization of the content and metadata files, object directory, and `objects` parent directory. A post-rename sync failure can leave visible content without durable confirmation; retrying, including an identical publication, must complete synchronization. A delete retry must sync the parent even if the object is already absent. Reopening checks stored data, not physical power-loss survival; actual guarantees depend on the filesystem and deployment. Non-Unix directory sync is not implemented, so directory-entry power-loss durability is not promised. See the owning [object-storage contract](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-state/src/object.rs).

`ObjectWrite::commit_upload(upload, final_taint)` seals content and the union of initial/final sources before publication I/O. A live sealed retry requires the same sources; deduplication persists their union in canonical object metadata. `xolotl-value-object` adds explicit encoded references and incremental read/write/copy consumers. Standard's independent `value-objects` feature installs only the supplied ports. See [Incremental Values](incremental-values.md).

An embedded `GatewayRuntime` receives the same store through `with_object_store`. Its upload tickets and proofs remain in State, while content and provenance live in ObjectStore. See [Application Gateway](application-gateway.md#protocol) for ticket limits, provenance, single-use receipts and uncertain commits. `Gateway::begin_object_upload` accepts metadata-only `BeginObjectUploadRequest` and returns an owned `GatewayObjectUpload`, including through `dyn Gateway`. Its `write(&[u8])` borrows each input chunk and returns the cumulative accepted byte count. `commit(GatewayObjectKind)` constructs the canonical Blob, Tensor or Frame reference; shape and timestamps can be supplied at end-of-input without a caller-generated digest. No complete input buffer is retained by the upload. Once a write is polled, failure or cancellation closes the upload and releases its staging lease. An unpolled write leaves it intact; `abort` is an optional early cleanup operation. Live profile and expiry checks do not extend the ticket lifetime. The embedding remains responsible for delivering transport chunks and dropping idle or disconnected upload owners.

`effect://blob/write` accepts bytes or text and returns a `BlobRef`. `effect://blob/read` returns bytes for objects up to 1 MiB, the canonical `BlobRef` for larger unary reads, or bounded byte chunks in stream mode. `effect://blob/delete` deletes committed content through `ObjectDelete`. Both accept Blob, Tensor and Frame Values directly, as well as a hash string or `{hash}` map, and operate on the referenced bytes. `Value::backing_blob()` borrows the backing `BlobRef` from any of these three typed values. Fetch and filesystem reads offload large unary bodies incrementally, while stream mode emits bytes directly.

## Gateway Output

`Gateway::lookup_request` reads original request evidence using
`GatewayRequestLookup`; gRPC exposes the same summary-only operation as `LookupRequest`.
`Gateway::read_retained_request_result` reads the cached payload for adapter-owned
delivery; gRPC exposes explicit delivery as `DeliverRequestResult`, using
`LookupRequestRequest` and returning `SubmitResponse`. Configured externalization
can write objects and grants, but neither entry point reexecutes the program.
The native summary is `GatewayRequestSummary { accepted, result_class,
unresolved_operations }`, with `GatewayRequestResultClass::{Done, Short, Fail}`.
The retained read returns `GatewayRetainedRequestResult::{Available(Box<GatewaySubmitResult>),
Unproven, Reserved, Retired}`; only `Available` carries the original cached output
and provenance. A native read itself does not create transport exports.
See [Original Request Lookup](application-gateway.md#original-request-lookup)
for identity binding, evidence states and bounded delivery.

`Gateway::submit_output_stream(session, submission, StreamWindow)` requires `OutputMode::Stream`. The returned `GatewayOutputStream` exposes `accepted()` and `next().await` or `poll_next(cx)`. It shares admission and execution with ordinary `submit` and input-stream completion. Each `GatewayOutputEvent::Chunk` contains a `GatewayOutputChunk` that borrows a `TaintedValue` and retains both kernel window credits and Gateway capacity, even if the response is dropped. `into_value()` acknowledges the chunk and explicitly transfers further retention to the caller. Dropping a response cancels its remaining execution.

`GatewayOutputEvent::Complete` carries the same `GatewaySubmitResult` as ordinary `submit`: acceptance, `ExecutionOutput`, and request origin. It follows final validation, idempotency persistence and process cleanup. Normal completion waits for outstanding chunks. Cancellation or task expiry discards queued data and may report termination while previously borrowed chunks still hold capacity.

`SubmitResponse.terminal.completion` and streamed `Completed` share `SubmissionCompletion { outcome, origin, taint, unresolved_operations }`. Final outcome, taint and reconciliation state are required, including failures and replay; pristine is an explicit empty taint set. When the current session retains submit access to the original surface and the transport can deliver a terminal frame, an accepted request whose result settlement or encoding fails uses `SubmitResponse.terminal.indeterminate` or streamed `Indeterminate`, retaining bounded effect identities without claiming a program outcome. A lost connection cannot deliver this evidence. `Gateway::validate_submission_access` lets transports recheck the current session and submit binding before disclosing acceptance or reconciliation identities. Final schema rejection preserves result taint, and a rejected chunk contributes its taint even if the driver ignores the send error. A fresh Gateway program is `CompletionOrigin::CurrentAttempt`, including kernel cache hits. Only whole-request Gateway replay is `CachedOutcome`. Its dedicated request store preserves the complete outcome and taint in a bounded envelope, without State history or historical chunks; see [request storage](application-gateway.md). Taint and origin do not authorize object downloads.

The wire `OutputOutcome` preserves Done, Short or typed Fail independently of its inline/object representation. With `gateway-grpc/structured-output`, install an explicit `GatewayOutputExternalizer` on `ApplicationGrpcService` to externalize values exceeding inline budgets. `EncodedOutputObject` carries encoding, Blob, read grant and expiry; nested references receive no implicit grants. The original event retains capacity through encoding and policy waits, while the execution's cancellation and deadline remain polled. Acceptance metadata and source sets still need to fit the frame. See [Application Gateway](application-gateway.md).

## MCP Publications

A Gateway publication names a surface, the `mcp` protocol and one kind: `tool`, `resource`, `resource_template` or `prompt`. It reuses the surface's target, schema, principal binding and admission path. Discovery shows only publications visible to the authenticated principal; calls submit by surface ID. The referenced surface needs a `publish://...` capability covering its effect. An MCP client cannot supply raw effect paths, capabilities, acting identities or Operations.

The adapter negotiates MCP `2025-11-25` first and retains its other supported revisions in the handshake. It implements initialization, ping, tools, resources, resource templates, prompts and completion where the negotiated revision defines it. It does not advertise logging, resource subscriptions, list-change notifications or task execution. Publication properties hold MCP fields such as `icons`, `mimeType`, prompt `arguments` and static `completions`; Gateway still owns the surface contract.

`McpGateway::call_tool`, `read_resource` and `get_prompt` return the complete `GatewaySubmitResult`, including acceptance, outcome, taint, request origin and unresolved operations. Normal JSON-RPC results carry the same evidence in `_meta["xolotl/gateway"]`; the adapter owns this key even in native MCP results. It revalidates access to the submitted surface after execution. Revocation prevents evidence delivery but returns an unknown outcome, not proof that execution was rejected.

`McpGateway::with_output_limits(McpOutputLimits)` bounds one response's Value occurrences, depth, inline payload, projected JSON nodes and encoded message. The defaults are 65,536 occurrences, depth 32, 8 MiB inline payload, 65,536 JSON nodes and 16 MiB encoded output. These are transport admission limits, not a whole-task memory limit. Failure to render or fit an accepted result returns JSON-RPC `-32001` (`outcome unknown; reconcile before retrying`), retaining original acceptance and unresolved identities in `error.data` when they fit. Truncated identities set `identities_incomplete`; a minimal response may omit evidence or use a null request ID. It never grants retry authority or rolls back effects. Typed Rust results are not subject to these JSON limits.

Tool business failures remain complete `isError: true` results with host metadata. Resource and prompt business failures use JSON-RPC `-32003` with the full failure and metadata in `error.data`; if that response cannot fit, it becomes an unknown delivery outcome. Private Gateway diagnostics are not included in unknown responses. MCP provides no public reconciliation query or execution cancellation guarantee through notifications. See the [delivery design](application-gateway.md).

## Vector Search

Embedding producers and retrieval consumers share `Embedding` and `EmbeddingRepresentation`. The envelope carries `space_id`, `representation` and optional `embedding_model`. These are capability protocols over ordinary Values; the kernel introduces no model-specific control flow.

| Representation `kind` | Required fields |
| --- | --- |
| `dense` | `values`: one nonempty numeric list |
| `tensor` | `tensor`: a typed rank-one `TensorRef` |
| `sparse` | `dimensions`, sorted unique `indices`, and equally long `values` |
| `multi` | `vectors`: nonempty, equally dimensioned numeric rows |
| `multi_tensor` | `tensor`: a typed rank-two `TensorRef` |

`StandardConfig::with_retrieval(RetrievalConfig)` selects the consumer's object reader, I/O window and scalar work quantum. Tensor references require that explicit reader; even a one-byte window can decode every dtype. The built-in index admits finite `f32` values and computes scores in `f64`. Sparse dimensions and indices also accept decimal strings for full platform-width values. The index materializes admitted vectors; an I/O window does not bound index storage.

`effect://index/upsert` accepts the envelope plus `id`, optional `generation` and `metric`. A space fixes representation family, dimension and metric. Dense and sparse spaces support `cosine` (the default), `dot` and `negative_squared_euclidean`; multi-vector spaces require `mean_max_cosine`. For each query vector, `mean_max_cosine` takes the highest cosine over the document's vectors, then averages these maxima across query vectors. `delete` accepts `space_id`, `id` and an optional expected `generation`.

`effect://index/search` accepts `space_id`, `representation`, optional `metric`, `k` and `mode`. Omitting `metric` uses the space's declared metric. `k` defaults to `10` and must be nonnegative. With `k: 0`, search skips scoring but still validates the representation and preserves the space's sources.

| `mode` | Search behavior |
| --- | --- |
| Omitted or `"auto"` | Approximate candidates when ANN is available in a large dense cosine space; exact fallback otherwise, including while another query builds ANN. |
| `"exact"` | Scan every entry in the space, regardless of size, and select the top `k`. |

Other mode values are rejected. For example, this input requests exact search:

```json
{
  "space_id": "example/embedding-model",
  "representation": { "kind": "dense", "values": [0.25, -0.5, 1.0] },
  "k": 10,
  "mode": "exact"
}
```

Results contain up to `k` entries of `{id, sim}` plus a stored `generation` when present. Ordering is descending score, then ascending `id` among equal scores. `auto` can differ from `exact`. Searches retain immutable paged roots, release registry locks and yield at configured scalar-work and traversal intervals, including within a single very high-dimensional vector. This is cooperative scheduling without a hard real-time bound on one poll. Sources remain attached even to empty results or data-dependent validation failures.

Result selection retains `O(k)` entries, excluding query/storage payloads and ANN candidate discovery. ANN construction is lazy on an `auto` search above 4096 entries; shrinking to 2048 or fewer releases it. Construction is cancellable and publishes only if its captured space version remains current.

Memory records persist their representation and generation in State. Its index is a rebuildable projection. `store` and `commit` create an absent record by default; replacing or promoting one requires its `expected_generation`. Their result contains `{ id, path, indexed, generation }`. `indexed: false` means State accepted the record but a concurrent projection update prevented publication. Retrying the same OperationId and semantic request reuses the first committed representation, including when concurrent embedding calls produced different numeric results. After a newer generation replaces the record, an older operation conflicts instead of recreating its retired generation. Recall verifies each hit's generation before attaching its score to a record. Default `consistency: "indexed"` repairs observed stale hits; `"reconcile"` rebuilds from State first when `k > 0`. A zero-result recall skips rebuilding. `effect://memory/rebuild` explicitly repairs a namespace without calling the embedding model again. These are generation checks across independent systems, not a cross-system transactional snapshot. Memory scans use State pages and explicitly read an oversized row before continuing with the backend's cursor. The page window does not impose a maximum memory-record size; the selected resident representation still has its own cost.

Memory recall selects up to `8 * k` semantic candidates before applying kind filters and its final ranker. Its `mode: "exact"` describes that candidate search; it does not guarantee the global top `k` after filtering and reranking, and can return fewer than `k` eligible records. Consolidation admits at most 1024 records, 16 MiB of cumulative encoded records and 4 MiB of text by default, before writing summaries. `StandardConfig::with_memory_consolidation_limits` selects explicit nonzero limits. It precomputes borrowed word sets and yields every 1024 inspected tokens, preserving asymmetric seed-based clustering. Pairwise work remains quadratic within admitted limits; these limits are not an RSS or deadline guarantee. These policies are separate from the kernel's execution and stream windows.

`RetrievalConfig::with_repair_attempts(NonZeroUsize)` bounds Memory recall search rounds and projection attempts per rebuilt record, including the initial attempt; the default is eight. Exhaustion returns `Failure::HandlerError` with kind `memory_repair_exhausted` and all observed sources, not a partial ranking or a successful rebuild count. Cancellation stops further repair but does not undo committed records or projections. This bound limits contention amplification, not namespace size, vector memory or total call duration; the host still owns call deadlines. Memory preserves downstream structured failures, including the ranker's original kind and sources.

## Tensor Views

`TensorRef { blob, dtype, shape }` describes a view of committed object bytes. The blob hash identifies those bytes; different dtype or shape views can share the same blob. The complete reference carries the view through values and Gateway responses, without a tensor catalog lookup.

`effect://tensor/write` accepts an inline `data` list with optional `dtype` and `shape`, serializes bounded chunks, and returns a `TensorRef` after object commit. It requires `ObjectWrite` and performs no State writes. The default dtype is `f32`; the default shape is `[data.len()]`. Explicit `shape: []` denotes a scalar and requires one data element. A shape with a dimension of length zero denotes an empty tensor and requires an empty data list:

```json
{"data": [2.5], "shape": [], "dtype": "f64"}
```

```json
{"data": [], "shape": [0, 3], "dtype": "f32"}
```

Dimensions must be nonnegative integers, and the shape's element count must match the data length. Supported dtypes are `f16`, `bf16`, `f32`, `f64`, `i8`, `i16`, `i32`, `i64`, `u8`, and `bool`. Floating types accept integer or floating values, round to the selected precision, and support IEEE NaN and infinity. Integer types require integer values within the selected type's range. `bool` requires boolean values and encodes each as one byte, `0` or `1`. Multibyte elements use little-endian encoding.

The serializer reuses one buffer of at most 16 KiB; small tensors reserve only their encoded size. This bounds serialization storage, not the complete inline input list. Use Gateway object uploads for incremental byte input.

Pass the complete `TensorRef` or `FrameRef` value directly to the independently installed `effect://blob/read` or `effect://blob/delete` capability. Explicitly passing `TensorRef.blob` remains supported. These operations act on shared bytes; deleting content affects every view backed by that blob. For persistent names, explicitly store the complete `TensorRef` at an application-selected State path; removing that State entry does not delete the object.
