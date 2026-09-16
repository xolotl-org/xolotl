# Application Gateway

The application gRPC listener exposes one profile-bound `GatewayRuntime`. Its
principals and surfaces are independent of external Provider/Source sessions.
The daemon gives Standard and this runtime clones of the same ObjectStore;
State holds authorization records and receipts, while the store owns content.

## Configuration

Build the optional listener independently:

```sh
cargo build -p xolotl-daemon --no-default-features --features application-grpc --locked
```

First start the daemon with persistent State and Console enabled, leaving the
application address absent. Use the authenticated Console `config.write_cas`
action to create `state://kernel/gateway/profiles/tasks`. Its input contains
`path`, the profile `value`, and `expected_version: null` for creation. Console
requires write authority and its normal MFA step-up. It assigns `version: 1`;
subsequent updates supply the observed `expected_version` and advance it.

The profile document owns credentials, identity mappings, surfaces, bindings,
registered authorities and Gateway admission limits. For example:

```json
{
  "profile_name": "tasks",
  "credentials": [{
    "credential_id": "worker-key",
    "principal_id": "worker",
    "verifier": {
      "kind": "bearer",
      "token_hash": "0000000000000000000000000000000000000000000000000000000000000000"
    }
  }],
  "identity_mappings": [{
    "principal_id": "worker",
    "identity_path": "process://application/worker"
  }],
  "surfaces": [{ "surface_id": "clock", "target": "effect://time/now" }],
  "principal_surface_bindings": [{
    "principal_id": "worker",
    "visible_surfaces": ["clock"],
    "submit_surfaces": ["clock"],
    "capability_ceiling": ["perform://effect/time/now"]
  }],
  "registered_hosts": ["127.0.0.1:9445"]
}
```

Replace the placeholder `token_hash` with the lowercase BLAKE3 digest of a
high-entropy bearer secret; do not store the raw secret in the profile. A client
certificate verifier uses `kind: "client_certificate"` and `der_sha256` instead.
Empty permission lists grant no access. Omitted limit fields use the Gateway
defaults advertised by authenticated discovery. Unknown document fields fail
admission. Profiles reference already registered effects; they do not install
providers. Remote Provider targets must be Ready before a profile using them
can be installed.

Then enable the listener and select the existing profile:

```toml
[server]
application_grpc_addr = "127.0.0.1:9445"

[application_gateway]
profile = "tasks"

[application_gateway.grpc]
max_frame_bytes = 65536
max_concurrent_uploads = 8
max_concurrent_output_responses = 8
output_window_chunks = 16
output_window_bytes = 262144
first_frame_timeout_ms = 15000
idle_timeout_ms = 30000
storage_timeout_ms = 120000

[application_gateway.grpc.transport_security]
mode = "local_trusted"
```

`XOLOTL_APPLICATION_GRPC_ADDR` supplies the address when the config field is
absent. With neither address, the daemon does not load the profile, construct an
application runtime, bind a socket or create its watcher. An enabled listener
fails startup for a missing, malformed or uncompilable profile. It does not
create a default principal or import a seed that can revive deleted authority.
An address supplied to a build without `application-grpc` is a configuration error.

The running listener watches the exact State record. Successful revisions swap
the compiled profile; invalid replacements retain the last good profile. A
deleted or missing record, a failed State reread, or a lost, closed or failed
subscription closes the listener and cancels its active RPCs. It does not
resubscribe or reopen automatically; after restoring valid State, restart the
daemon to recreate the listener. To revoke access while retaining a running
listener, write a higher-version closed profile with empty credentials and
bindings. Profile admission and runtime resource resolution remain separate
checks.

## Protocol

The vendored schema is `proto/xolotl/v1/application.proto` in `xolotl-proto`.
The service name is `xolotl.v1.application.ApplicationGateway`.

| RPC | Contract |
| --- | --- |
| `Describe` | Authenticated, redacted profile revision, visible surfaces, publications and limits. |
| `IssueUploadTicket` | A principal/surface-bound ticket with optional size, digest, media type and lifetime constraints. |
| `UploadObject` | Client stream `Begin -> Chunk* -> Finish -> clean HTTP input completion`, then one committed typed reference and receipt. |
| `DownloadObject` | Explicit read grant plus absolute range; server stream `Header -> Chunk* -> Completed`, then successful gRPC EOF. |
| `Submit` | Surface id, structural Value, optional receipt provenance and submit options; returns acceptance metadata and `SubmissionCompletion`. |
| `SubmitOutput` | The same typed input with explicit Stream mode; returns `Accepted -> Chunk* -> Completed` followed by successful gRPC EOF. |

Each RPC authenticates a single `authorization: Bearer <secret>` header or, in
mutual TLS mode, the listener-verified leaf certificate. Profile authority
matching uses HTTP/2 `:authority`. An independent `host` header cannot replace
it. Gateway checks session generation and authority in one profile snapshot,
so profile replacement cannot combine old hosts with newly issued sessions.
Forwarded authorities are accepted only from configured proxy peers. TLS
modes require actual tonic TLS connection evidence, and local mode requires a
verified loopback peer. TLS file settings follow the external gRPC listener's
transport-security configuration.

Upload `Begin` contains the ticket id, optional media type and submission token.
Each `Chunk` contains bytes. `Finish` selects Blob, Tensor (`dtype`, `shape`) or
Frame (`ts_nanos`, `kind`); the server computes digest and byte length. Pass the
returned `item` and `provenance` together to `Submit` for that ticket's surface.
Do not reconstruct a reference from guessed metadata or substitute another
principal's proof.

`DownloadObject` consumes `read_grant_id`, an absolute `offset`, and optional
`length`. Omission selects the rest of the granted range; zero selects an empty
range. The header supplies the frozen canonical backing BlobRef, selected range,
initial taint and fixed expiry. Each chunk carries its absolute offset, bytes and
current taint. Completion supplies `next_offset` and total `bytes_read`; range
completion can precede the object's physical EOF. Successful gRPC completion is
still required, including for empty ranges. Errors use gRPC status, independently
of AI execution outcomes or cache origin.

Trusted host code issues a grant through
`GatewayRuntime::issue_object_read_grant(session, IssueObjectReadGrantRequest)`
only after authorizing disclosure of the direct Blob, Tensor or Frame in
`object: TaintedValue`. The request selects a known profile `surface_id`, absolute
`offset`, optional `length` and optional `expires_in_ms`. Grant lifetime is bounded
by the profile's deadline window. There is no remotely callable grant issuer.
Knowing a hash, possessing an upload receipt, or receiving a tainted execution
result does not authorize disclosure. Application-specific output export
policies can call the trusted issuer; this service does not discover and export
references by recursively scanning ordinary results.

Object delegation is independent of discovery and submission permissions.
A live authenticated audience may receive a read grant while having only
directory visibility or no discovery/submission binding at all. Its submissions
still follow the ordinary capability and surface admission rules. The known
surface and target bind the delegation's scope without giving its audience
execution authority.

The immutable versioned State record binds profile name/revision, principal and
credential identities/generations, authentication kind, identity path, surface
target, exact object and permitted range. State's tainted envelope is the sole
persisted provenance authority. Trusted replicas or restarted runtimes can
consume the grant when those bindings and shared storage agree. Profile revision
changes invalidate it. Grant activity does not renew expiry. The trusted
`revoke_object_read_grant(session, grant_id)` API compare-deletes the record
without deleting content; expiration itself does not collect retained State
records. Storage retention remains a host policy.

`SubmitOutput` shares admission, receipt consumption, execution and cleanup with
`Submit`. Acceptance precedes execution. Each output chunk carries its typed
`item` and server-assigned `taint`; the latter records lineage and does not grant
object access. An optional surface `output_stream_schema` validates each whole
chunk before delivery. The existing `output_schema` independently validates the
final value. A failed chunk validation remains a request failure even if a driver
ignores the send error. Final-value rejection retains the rejected result's taint;
chunk rejection adds the rejected chunk's taint to the final failure. Other chunks
keep their own lineage independently of the final result.

Submission retains the selected surface identity through admission, quotas and
final schema validation. Several surfaces may expose the same effect with
different schemas without being confused by a target lookup. Accepted requests
use their frozen profile; later profile replacement applies to new admissions.
Replacing a profile alone does not cancel an accepted request. Explicit request
cancellation and listener shutdown retain their own lifecycle semantics.

`SubmitResponse.completion` and the `SubmitOutput` `Completed` event use the same
`SubmissionCompletion { outcome, origin, taint }`. The application contract requires
both `outcome` and `taint` on every completion, including failures and cached
results. Pristine lineage is an explicitly present empty `TaintSet`; missing taint
is invalid. In Rust, ordinary `submit` and `GatewayOutputEvent::Complete` return
the same `GatewaySubmitResult { accepted, output: ExecutionOutput, origin }`.
Completion follows idempotency persistence and process cleanup. The driver's
`StreamEnd` does not determine the final request result.

Origin describes the boundary reporting the result. An invocation cache hit has
`CompletionOrigin::CachedOutcome` on its `DriverOutput` and `StreamEnd`. A program
that runs in a new Gateway request still reports
`COMPLETION_ORIGIN_CURRENT_ATTEMPT`, including when its calls hit kernel caches.
Only whole-request Gateway replay reports `COMPLETION_ORIGIN_CACHED_OUTCOME`.
Both caches retain final outcomes and their taint without replaying historical
chunks. Gateway idempotency records use `gateway-idempotency-v1` and State's
required tainted envelope; unknown or malformed records are rejected.

Clients must also observe successful gRPC completion; disconnects and transport
encoding failures do not establish a completed request. Taint and cache origin
do not grant access to referenced objects.

## Resource Ownership

Each upload RPC owns one existing `GatewayObjectUpload` and one shared semaphore
permit. Excess uploads fail immediately. The adapter reads one protobuf frame,
borrows its bytes through storage writes, then reads the next frame. It retains
no cumulative payload buffer. Storage offers remain at most 16 KiB. The
configured protobuf frame includes envelope overhead, so a byte chunk must be
smaller than `max_frame_bytes`.

The frame and concurrency windows do not cap cumulative object size. Unknown
total lengths are accepted; declared ticket constraints and the current
`i64::MAX` receipt size representation still apply. First-frame, subsequent-frame
and storage wait windows are independently configurable and reject invalid
settings instead of silently clamping them. These waits do not extend absolute
ticket expiry or replace task admission deadlines.

Each download owns a `GatewayObjectDownload` over the existing optional object
reader. It opens no kernel process, producer task or reader registry. The
transport retains one byte window of at most `min(max_frame_bytes, 16 KiB)` and
splits it using the actual encoded protobuf size, including taint. Partial reads
are valid; invalid offsets, non-progress or inconsistent physical EOF close the
owner. Full object sizes and ranges use `u64`, without the upload receipt's
signed-size representation. An empty range reads no object bytes.

The owner verifies the grant's exact State value and provenance before and after
each storage read, and again at completion. Live session and expiry checks also
precede delivery of each frame. A failed or cancelled polled read closes the
owner; callers must not deliver buffer contents from an unsuccessful read.
Revocation prevents later authorized reads but cannot recall bytes already
acknowledged or buffered by the transport. Per-chunk taint combines opening and
grant sources with that read's sources, without accumulating historical chunk
taint. Separate reads do not pin an object against deletion; a deleted object
can interrupt a download. Republished content with the same hash denotes the
same bytes, with current read provenance still included.

An output response owns its execution future and one kernel channel. Transport
polling advances both; there is no detached producer or second output queue.
`output_window_chunks` and `output_window_bytes` bound accepted and borrowed
kernel chunks. The byte charge is the tagged JSON encoding of value and lineage,
not protobuf bytes or RSS. Kernel credits are held through bounded protobuf
conversion, after which tonic owns its copy. Total output can exceed these
windows without accumulating historical chunks. Codec and HTTP/2 buffers,
conversion of one chunk and the final result have additional retention costs.

`max_concurrent_output_responses` is shared by execution output and object download
responses, including slow clients and transport buffers. Its permit follows both the response body and
the encoded DATA bytes transferred to HTTP/2, without copying their payload.
It is released only after the last owner drops. Gateway admission and budget
leases similarly follow the response and any borrowed output chunks, without
retaining a cancelled execution process. Cancellation or deadline expiry revokes execution
authority; it does not release capacity still owned by a live response. A slow
HTTP/2 peer can prevent response polling, so logical cancellation alone does
not guarantee immediate destruction of a pending driver future. Listener
shutdown also closes connection I/O to reach these stalled responses.

The ingress captures `grpc-timeout` before decoding and retains its absolute
deadline through response completion. It also tightens the submitted task
deadline. Gateway converts the task deadline once to a monotonic instant shared
by execution and deadline sweeping. After execution and output validation, it
resolves cancellation or expiry and freezes the request result before persisting
the cache and cleaning up the process. These decisions preserve final taint.
An ordinary driver `Timeout` before the task deadline remains a driver failure.
After that completion decision, the task deadline does not rewrite the result or
discard queued output; the RPC deadline still applies to delivery. When response
polling resumes after RPC expiry, the body terminates with `DeadlineExceeded`.

Missing, reordered or trailing frames, a reset, an expired wait or shutdown
release the request owner. Publication requires both the final protocol marker
and actual successful HTTP body completion: tonic can translate HTTP/2 CANCEL
into an apparent stream EOF. Cancellation during commit or receipt CAS can
leave published content or an uncertain receipt result. Shared committed bytes
are never deleted to undo such uncertainty.

Shutdown also cancels requests still being decoded before their handler starts.
The daemon propagates its close signal through connection reads and writes, so
incomplete HTTP/2 prefaces and peers that stop reading cannot keep internal
tonic connection tasks alive after the listener is closed.

## Current Output Scope

`Submit` supports Unary and Collect. It explicitly rejects Stream, AsyncProcess
and SinkOnly because this RPC returns a completed response. Inline inputs,
collected outcomes, protobuf decoding and transport buffers have their own
memory costs. The frame limit also applies to responses; an oversized response
can fail after execution, so retries still need normal idempotency semantics.

Outgoing `Value` fields also use the shared protobuf codec's 30-level nesting
limit, counting each value's root as level one. This leaves room for envelope
messages within prost's default decoding recursion limit. It applies to results
and discovery schemas and metadata; exceeding it returns `ResourceExhausted`
even when the response fits the frame budget. Raising `max_frame_bytes` does not
raise this depth limit.

With the optional `xolotl-gateway-grpc/structured-output` feature, a host can
install `ApplicationGrpcService::with_output_externalizer`. The adapter first
tries bounded inline encoding. If the payload exceeds that frame or nesting
budget, it polls one owned Gateway externalizer configured with an explicit I/O
window, asynchronous key-store factory and disclosure policy. Publication and
canonical metadata inspection precede the policy decision and read-grant commit.
The policy sees the original output, authenticated audience, complete current
metadata and exact proposed expiry. No policy is installed automatically.

`OutputValue` and `OutputFailure` each select exactly one inline or object
representation; `OutputOutcome` independently preserves Done, Short and Fail.
Object delivery carries the explicit encoding, complete BlobRef, read-grant ID
and expiry. Failure objects contain the shared lossless externally tagged
Failure layout. Completion origin and provenance remain required, including
cached results. Externalization errors affect delivery without rewriting the
execution result or its cache. Nested references receive no grants.

`SubmitOutput` retains the original chunk's credits through encoding, policy and
bounded wire projection. The same execution owner continues to process request
cancellation and deadlines during a pending encoder. Cancellation abandons that
encoding before delivering the original interrupted request's final outcome.
There is no additional producer or output queue. Unary, stream and download
responses share the configured transport concurrency window through HTTP/2 DATA
ownership. The encoded document can exceed a frame and the inline depth limit;
its consumer validates incremental downloads through actual successful EOF.

Acceptance metadata, object descriptors and advertised provenance still have to
fit a response frame. Externalizing a payload does not remove those metadata
bounds, nor the memory required by an explicitly materializing consumer. The
CBOR profile encodes logical tree occurrences, so a heavily shared resident DAG
may expand substantially. No cumulative object or stream-byte cap is inferred
from the transport window.

`DownloadObject` serves bytes explicitly authorized by trusted host issuance;
the daemon does not yet install a general provider-result export policy.
Hosts select that disclosure policy when composing their service. Explicit
`value/read` or `ValueObjectReader` consumers reconstruct structured objects;
inference backends do not implicitly load references, and an upload receipt does
not confer Provider/Source or MCP authority.
