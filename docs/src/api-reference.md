# API Reference

Rustdoc is the public API reference for the workspace.

Generate it with missing-doc checks enabled:

```sh
RUSTDOCFLAGS='-D warnings -W missing-docs' cargo doc --workspace --all-features --no-deps --locked
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
xolotl-sdk      -> target/doc/xolotl_sdk/index.html
xolotl-kernel   -> target/doc/xolotl_kernel/index.html
xolotl-standard   -> target/doc/xolotl_standard/index.html
```

## Reading Order

For embedding:

- `xolotl-core`
- `xolotl-sdk`
- `xolotl-graph`
- `xolotl-types`
- `xolotl-kernel`

The default SDK exports only `xolotl_sdk::core`. Start with `ProgramImage`,
`Values` and `Execution` for allocator-free hosts. Enable `host` for `Program`,
`Expression`, `PreparedProgram`, `ExecutionConfig`, `ExecutionLayout`, `ExecutionBuffers` and `Xolotl::run_prepared`.
`ProgramImage::resource_requirements` performs allocation-free resource analysis;
`PreparedProgram::layout` reports execution container sizes under host ceilings.
`run_prepared_with_buffers` reuses caller-owned empty execution containers.

Prepared execution accepts `TaintedValue { value, taint }`. Portable
`LinkedExecution` and hosted Executor evaluation return
`ExecutionOutput { outcome, taint }`; SDK execution helpers return
`Result<ExecutionOutput, XolotlError>`. `ExecutionOutput::into_result` preserves
lineage as `Result<TaintedValue, TaintedFailure>`, and `TaintedFailure::into_value`
preserves it when a diagnostic becomes the next program's input. Call usage and
cache origin remain at invocation boundaries, outside `ExecutionOutput`.
`Executor::with_deadline(tokio::time::Instant)` stops execution at a monotonic
deadline while retaining known live provenance. This drops pending calls; process
finalization remains the request owner's responsibility.

`Execution::suspend` / `resume` transfer live storage through a validated handoff
without cloning values; optional hosted native expansion uses this to grow within
the configured byte budget.
Use `XolotlBuilder` to supply host-owned state and facts; `durable` additionally
exposes checkpoint contracts. The `standard` feature exposes provider installation.
`ExecutionIds` and `ExecutionIdSource` make the identity namespace independently
replaceable through `with_execution_ids` on Kernel, Executor or the SDK builder.
`OperationId::new(process, execution, invocation, position, attempt)` and its
`FromStr`/`Display` pair share one five-component format; `to_bytes` produces a
canonical 32-byte key. `retry` returns `None` on attempt exhaustion.
See [Core And Portable Programs](core-and-portable.md) for feature combinations
and the recovery contract.
Use `Bootstrap::request_under` for an owned request with precompiled grants.
`Bootstrap::request_under_owned` on `Arc<Bootstrap>` returns the same request
scope with shared host ownership for independent tasks and accepted input streams.
Both forms share cancellation and finalization; the borrowed form needs no
additional shared reference.
`RequestProcess::executor` creates its Executor; `finish(&ExecutionOutput)` commits
terminal cleanup while preserving the body's status provenance,
and `detach` explicitly transfers lifecycle responsibility. Ordinary SDK runs
use this scope automatically. `Bootstrap::drain_cleanup` and
`Xolotl::drain_cleanup` return a `ProcessCleanupReport` with completed tree counts
and retained failures after abandonment or interrupted finalization. Dropping
a bare Executor future does not finish its Process. Durable SDK execution
transfers ownership to recovery; it does not queue cancellation on drop.
`XolotlBuilder::with_process_capacity(NonZeroUsize)` limits retained process entries.
`ProcessTable::set_capacity` changes the shared limit; `len` includes terminal and
pending cleanup entries. `reap_finalized(limit)` explicitly removes eligible leaves
after completion, preserving parents with children and all persisted history.
Capacity failures are `BootstrapError::ProcessAdmission(ProcessAdmissionError::Capacity)`.
After the first actual reap, arbitrary historical snapshot import requires a new
Kernel. Recovery from current leased storage rows can keep advancing the backlog
in the same Kernel.

The first hosted checkpoint format retains provenance on values and failures,
sharing one Value table across all fields, active module code and bindings.
Program loaders require a `LoaderRevision`. Reattach their `StepModule` through
`Executor::with_steps` or `checkpoint_recovery()?.with_steps(module)`; recovery
validates the revisions and resumes the saved expanded image. Missing taint,
unknown formats, invalid module ranges and changed loader revisions are rejected.
The core's format is independent of hosted persistence.
`durable` also exports `CheckpointQuery`, `CheckpointInfo`, `DurableRecoveryConfig`
and `DurableRecovery`. Configure metadata page size, shared recovery concurrency and
explicit reap batches with `with_checkpoint_recovery_config`; bound encoded reads
and writes with `ExecutionConfig::max_checkpoint_bytes`. Reserve checkpoint process
IDs before fresh application admission, then create `checkpoint_recovery()` after
installing authority and advance it with `advance()`. `deferred` indicates capacity
pressure; `complete` ends the scan range while scheduled programs may still await
I/O. Store adapters implement bounded `scan`, `high_water`, `try_acquire`, and the
lease's bounded `load`, `commit` and durable `retire` operations.
`FactQuery`, `FactOrder` and `FactPage` define directional Fact reads with result,
candidate and encoded-byte budgets. Continue using `query.next_page(&page)`;
empty filtered pages can still have a continuation. Custom `FactStore` adapters
implement `scan` and indexed `lookup(FactLookup)`. Point queries filter the current
caller before spending their byte budget and return `FactLookupResult::{Found,
Missing, FilteredOut}`. `get_bounded` and unbounded `get` are unfiltered conveniences.
Automatic recovery uses these pages.
`Bootstrap::recover_all_with_limits(RecoveryLimits)` selects record and encoded-byte
budgets; defaults are 256 records and 1 MiB per page. The append bound fixes which
slots are scanned, but does not freeze concurrent outcome updates.
`InMemoryBackend::with_options(InMemoryOptions)` returns
`StateResult<InMemoryBackend>` and combines three independent construction choices:
`read_shards: NonZeroUsize` defaults to 1 for an inline map; larger counts reserve
padded shards for point reads. Writes remain serialized and prefix reads capture
one consistent snapshot. `history: MemoryHistory` defaults to `Full`, retaining
every mutation. `Disabled` stores no history or historical timestamps;
`read_range` and `read_at` with a nonzero timestamp return `Unsupported`, while
`read_at(path, 0)` reads the current value. `notification_capacity: NonZeroUsize`
defaults to 256 and accepts at most `InMemoryOptions::MAX_NOTIFICATION_CAPACITY`
(1,048,576 events). Full pending queues reject matching writes before commit,
and slow broadcast receivers can still lag.
`InMemoryBackend::new()` retains the default settings.
`with_notification_capacity(NonZeroUsize)` also returns
`StateResult<InMemoryBackend>` and keeps the other options at their defaults.
Unsupported capacities and shard reservation failures return errors. Disabling
history does not bound current values, payloads or the host's total memory.
Custom state adapters must implement atomic provenance-preserving `write_merge`
or retain the default `Unsupported` result.
Use `ActorSpec` and `Xolotl::spawn_actor` for named long-lived Process
declarations. Use `Xolotl::spawn_actor_with_steps` when the actor body references
process-local `StepRef`s in the body or finalizers. It accepts a shared `StepModule`;
assemble one with `single`, `new` or `compose`. Ordinary requests use
`run_with_steps` / `run_plan_with_steps`; standalone executors use `with_steps`.
`StepRef::new(name)` resolves against the executor's immutable module;
reusable graphs and nested Step functions do not
capture process ids. Plan compilation is `xolotl_plan::compile(&plan)`, exported
as `xolotl_sdk::compile_plan` by the `plan` feature. Use
`StandardConfig::with_modules` to choose installed standard modules and
`StandardConfig::with_inference_backend` to supply the host model backend used
by standard model-backed effects.

For protocol adapters:

- `xolotl-gateway`
- `xolotl-proto`
- `xolotl-gateway-grpc`
- `xolotl-gateway-websocket`
- `xolotl-gateway-mcp`

External Provider/Source session admission and secure envelope helpers are under
`xolotl_gateway::external`. The `xolotl-gateway` root API is for gateway profiles,
sessions, submissions, limits, and runtime status.

For standard providers:

- `xolotl-standard`
- `xolotl-state`
- `xolotl-storage-redb`
- `xolotl-storage-fs`

Providers can return a synchronous input hook from `Driver::input_admission`.
Opening a method freezes this optional function pointer into its dispatch entry.
The hook accepts without allocation or returns a boxed `InputRejection` carrying
the failure and the input safe to record. Method adapters forward the hook when
renaming a method; domain-specific field checks remain in the provider.

## Streaming And Objects

`xolotl_kernel::stream::{StreamSink, StreamRouter}` are portable output ports.
Their contracts require neither Tokio nor `Send`/`Sync`; host adapters install
those bounds explicitly. `host::stream::channel(StreamWindow)` bounds accepted
and borrowed chunks by count and encoded inline bytes, defaulting to 64 chunks
and 256 KiB. These windows do not limit total stream traffic. Dropping a
`StreamChunk` releases its credits; `into_value` transfers the value to the caller
and releases the transport credits. The caller owns any further retention.
`StreamEnd` follows outstanding chunks and carries input and final-result
provenance. Each chunk retains its own provenance. A cached invocation reports
`CompletionOrigin::CachedOutcome` on its completion; this does not change the
origin of a program that executes using that invocation.

Streaming invocations require an explicit sink or router. The invocation owns
its producer future; receiver closure and cancellation drop that future. State
does not implicitly collect chunks. HTTP inference uses incremental SSE decoding
and permits retry or fallback only before the first accepted output chunk.
Its byte admission validates UTF-8 and handles one initial BOM before the SSE
parser retains input. Incomplete UTF-8 keeps at most three bytes; malformed input
fails without accumulating a deferred invalid suffix. The request future owns
the response and buffers directly, without a parser worker or a separate queue.

HTTP generation and embedding requests pull JSON windows from shared input,
configuration and overrides under HTTP backpressure. Unary and SSE responses
share incremental JSON validation and dialect-specific projection; only selected
output is materialized. Ignored fields and repeated completion snapshots do not
build a complete response DOM. Malformed UTF-8, invalid suffixes and late provider
errors fail the response; SSE output is admitted only after its record validates.
`InferenceBackendDef::io_window_bytes` controls I/O windows, while
`response_limits` independently selects output-byte, node and nesting admission.
Default policy has no cumulative response-byte cap. Retained input, selected
output, nesting and HTTP library buffers still consume memory.
Non-success responses retain at most an 8 KiB diagnostic prefix and display at
most 512 redacted characters; they do not wait for EOF after reaching the prefix
limit. This byte bound is not an I/O timeout.

`xolotl_state::object::{ObjectRead, ObjectWrite, ObjectDelete}` provide independent
portable capabilities. The host `ObjectStore` installs them with `with_read`,
`with_write`, and `with_delete`. Supply it through
`StandardConfig::with_object_store`; `FileObjectStore::into_object_store` installs
the file adapter. Reads fill caller-owned buffers. Uploads acknowledge partial
writes and publish a reference only after commit. Stateful uploads must attach
their cleanup owner with `UploadId::with_lease`; the final owner drop releases
abandoned staging or transfers cleanup to the adapter's reliable mechanism.
`UploadId::stateless` is only for uploads without resources requiring cleanup.
Cancelling `begin_upload` before it returns an id must also release its unclaimed
staging. Explicit abort permits earlier cleanup; callers do not need to spawn an
asynchronous abort task from `Drop`. Missing capabilities produce explicit errors.

`ObjectStore::write_all` advances through borrowed windows and partial writes,
validates each acknowledgement, and returns the next offset. Its nonzero window
does not limit cumulative upload size. It does not commit or abort; the upload
owner handles failure, cancellation, and staging cleanup.

`ObjectWrite::commit_upload(upload, final_taint)` seals content and the union of
initial/final sources before publication I/O. A live sealed retry requires the
same sources; deduplication persists their union in canonical object metadata.
`xolotl-value-object` adds explicit encoded references and incremental
read/write/copy consumers. Standard's independent `value-objects` feature installs
only the supplied ports. See [Incremental Values](incremental-values.md).

An embedded `GatewayRuntime` receives the same store through `with_object_store`.
Its upload tickets and proofs remain in State, while content and provenance live
in ObjectStore. A ticket must be committed before it can authorize an object
reference. Receipts bind the profile name as well as the principal and surface.
Single-use receipts are consumed after Gateway admission, before a new execution
attempt is accepted; an admitted driver failure does not restore them.
`Gateway::begin_object_upload` accepts metadata-only `BeginObjectUploadRequest`
and returns an owned `GatewayObjectUpload`, including through `dyn Gateway`.
Its `write(&[u8])` borrows each input chunk and returns the cumulative accepted
byte count. `commit(GatewayObjectKind)` constructs the canonical Blob, Tensor
or Frame reference; shape and timestamps can be supplied at end-of-input without
a caller-generated digest. No complete input buffer is retained by the upload.
Once a write is polled, failure or cancellation closes the upload and releases
its staging lease. An unpolled write leaves it intact; `abort` is an optional
early cleanup operation. Live profile and expiry checks do not extend the ticket
lifetime. The embedding remains responsible for delivering transport chunks and
dropping idle or disconnected upload owners.

`effect://blob/write` accepts bytes or text and returns a `BlobRef`.
`effect://blob/read` returns bytes for objects up to 1 MiB, the canonical
`BlobRef` for larger unary reads, or bounded byte chunks in stream mode.
`effect://blob/delete` deletes committed content through `ObjectDelete`.
Both accept Blob, Tensor and Frame Values directly, as well
as a hash string or `{hash}` map, and operate on the referenced bytes.
`Value::backing_blob()` borrows the backing `BlobRef` from any of these three
typed values.
Fetch and filesystem reads offload large unary bodies incrementally, while
stream mode emits bytes directly.

## Gateway Output

`Gateway::submit_output_stream(session, submission, StreamWindow)` requires
`OutputMode::Stream`. The returned `GatewayOutputStream` exposes `accepted()`
and `next().await` or `poll_next(cx)`. It shares admission and execution with
ordinary `submit` and input-stream completion. Each `GatewayOutputEvent::Chunk`
contains a `GatewayOutputChunk` that borrows a `TaintedValue` and retains both
kernel window credits and Gateway capacity, even if the response is dropped.
`into_value()` acknowledges the chunk and explicitly transfers further retention
to the caller. Dropping a response cancels its remaining execution.

`GatewayOutputEvent::Complete` carries the same `GatewaySubmitResult` as ordinary
`submit`: acceptance, `ExecutionOutput`, and request origin. It follows final
validation, idempotency persistence and process cleanup. Normal completion waits
for outstanding chunks. Cancellation or task expiry discards queued data and may
report termination while previously borrowed chunks still hold capacity.

`SubmitResponse.completion` and streamed `Completed` share the protobuf
`SubmissionCompletion { outcome, origin, taint }`. Final outcome and taint are
required, including failures and replay; pristine is an explicit empty set.
Final schema rejection preserves result taint, and a rejected chunk contributes
its taint even if the driver ignores the send error. A fresh Gateway program is
`CompletionOrigin::CurrentAttempt`, including kernel cache hits. Only whole-request
Gateway replay is `CachedOutcome`. Its idempotency record preserves the complete
outcome and taint through State's required envelope, without historical chunks.
Taint and origin do not authorize object downloads.

The wire `OutputOutcome` preserves Done, Short or typed Fail independently of
its inline/object representation. With `gateway-grpc/structured-output`, install
an explicit `GatewayOutputExternalizer` on `ApplicationGrpcService` to externalize
values exceeding inline budgets. `EncodedOutputObject` carries encoding, Blob,
read grant and expiry; nested references receive no implicit grants. The original
event retains capacity through encoding and policy waits, while the execution's
cancellation and deadline remain polled. Acceptance metadata and source sets
still need to fit the frame. See [Application Gateway](application-gateway.md).

## Vector Search

Embedding producers and retrieval consumers share `Embedding` and
`EmbeddingRepresentation`. The envelope carries `space_id`, `representation`
and optional `embedding_model`. These are capability protocols over ordinary
Values; the kernel introduces no model-specific control flow.

| Representation `kind` | Required fields |
| --- | --- |
| `dense` | `values`: one nonempty numeric list |
| `tensor` | `tensor`: a typed rank-one `TensorRef` |
| `sparse` | `dimensions`, sorted unique `indices`, and equally long `values` |
| `multi` | `vectors`: nonempty, equally dimensioned numeric rows |
| `multi_tensor` | `tensor`: a typed rank-two `TensorRef` |

`StandardConfig::with_retrieval(RetrievalConfig)` selects the consumer's object
reader, I/O window and scalar work quantum. Tensor references require that
explicit reader; even a one-byte window can decode every dtype. The built-in
index admits finite `f32` values and computes scores in `f64`. Sparse dimensions
and indices also accept decimal strings for full platform-width values. The
index materializes admitted vectors; an I/O window does not bound index storage.

`effect://index/upsert` accepts the envelope plus `id`, optional `generation`
and `metric`. A space fixes representation family, dimension and metric. Dense
and sparse spaces support `cosine` (the default), `dot` and
`negative_squared_euclidean`; multi-vector spaces require `mean_max_cosine`.
For each query vector, `mean_max_cosine` takes the highest cosine over the
document's vectors, then averages these maxima across query vectors.
`delete` accepts `space_id`, `id` and an optional expected `generation`.

`effect://index/search` accepts `space_id`, `representation`, optional `metric`,
`k` and `mode`. Omitting `metric` uses the space's declared metric. `k` defaults
to `10` and must be nonnegative. With `k: 0`, search skips scoring but still
validates the representation and preserves the space's sources.

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

Results contain up to `k` entries of `{id, sim}` plus a stored `generation` when
present. Ordering is descending score, then ascending `id` among equal scores.
`auto` can differ from `exact`. Searches retain immutable paged roots, release
registry locks and yield at configured scalar-work and traversal intervals,
including within a single very high-dimensional vector. This is cooperative
scheduling without a hard real-time bound on one poll. Sources remain attached
even to empty results or data-dependent validation failures.

Result selection retains `O(k)` entries, excluding query/storage payloads and ANN
candidate discovery. ANN construction is lazy on an `auto` search above 4096
entries; shrinking to 2048 or fewer releases it. Construction is cancellable and
publishes only if its captured space version remains current.

Memory records persist their representation and generation in State. Its index
is a rebuildable projection. `store` and `commit` create an absent record by
default; replacing or promoting one requires its `expected_generation`.
Their result contains `{ id, path, indexed, generation }`. `indexed: false`
means State accepted the record but a concurrent projection update prevented
publication. Retrying the same OperationId and semantic request reuses the
first committed representation, including when concurrent embedding calls
produced different numeric results.
After a newer generation replaces the record, an older operation conflicts
instead of recreating its retired generation.
Recall verifies each hit's generation before attaching its score to a record.
Default `consistency: "indexed"` repairs observed stale hits; `"reconcile"`
rebuilds from State first when `k > 0`. A zero-result recall skips rebuilding.
`effect://memory/rebuild` explicitly repairs a
namespace without calling the embedding model again. These are generation
checks across independent systems, not a cross-system transactional snapshot.
Memory scans use State pages and explicitly read an oversized row before
continuing with the backend's cursor. The page window does not impose a maximum
memory-record size; the selected resident representation still has its own cost.

Memory recall selects up to `8 * k` semantic candidates before applying kind
filters and its final ranker. Its `mode: "exact"` describes that candidate search;
it does not guarantee the global top `k` after filtering and reranking, and can
return fewer than `k` eligible records. The built-in consolidation policy collects
the namespace and performs pairwise text comparisons in memory. Its storage scan
is paged, but the complete clustering operation is neither fixed-memory nor
cooperatively incremental. These policies are separate from the kernel's execution
and stream windows.

## Tensor Views

`TensorRef { blob, dtype, shape }` describes a view of committed object bytes.
The blob hash identifies those bytes; different dtype or shape views can share
the same blob. The complete reference carries the view through values and
Gateway responses, without a tensor catalog lookup.

`effect://tensor/write` accepts an inline `data` list with optional
`dtype` and `shape`, serializes bounded chunks, and returns a `TensorRef` after
object commit. It requires `ObjectWrite` and performs no State writes. The default
dtype is `f32`; the default shape is `[data.len()]`. Explicit `shape: []` denotes
a scalar and requires one data element. A shape with a dimension of length zero
denotes an empty tensor and requires an empty data list:

```json
{"data": [2.5], "shape": [], "dtype": "f64"}
```

```json
{"data": [], "shape": [0, 3], "dtype": "f32"}
```

Dimensions must be nonnegative integers, and the shape's element count must
match the data length. Supported dtypes are `f16`, `bf16`, `f32`, `f64`, `i8`,
`i16`, `i32`, `i64`, `u8`, and `bool`. Floating types accept integer or floating
values, round to the selected precision, and support IEEE NaN and infinity.
Integer types require integer values within the selected type's range. `bool`
requires boolean values and encodes each as one byte, `0` or `1`. Multibyte
elements use little-endian encoding.

The serializer reuses one buffer of at most 16 KiB; small tensors reserve only
their encoded size. This bounds serialization storage, not the complete inline
input list. Use Gateway object uploads for incremental byte input.

Pass the complete `TensorRef` or `FrameRef` value directly to the independently
installed `effect://blob/read` or `effect://blob/delete` capability. Explicitly
passing `TensorRef.blob` remains supported. These operations act on shared bytes;
deleting content affects every view backed by that blob. For persistent names,
explicitly store the complete `TensorRef` at an application-selected State path;
removing that State entry does not delete the object.

## Doc Quality Checks

The current public API docs are expected to build without missing-doc warnings:

```sh
RUSTDOCFLAGS='-W missing-docs' cargo doc --workspace --no-deps
```

Run doc tests with:

```sh
cargo test --doc --workspace
```
