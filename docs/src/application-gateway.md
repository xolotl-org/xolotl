# Application Gateway

The application gRPC listener exposes one profile-bound `GatewayRuntime`. Its principals and surfaces are independent of external Provider/Source sessions. The daemon gives Standard and this runtime clones of the same ObjectStore; State holds authorization records and receipts, while the store owns content.

Each submission shares one current-profile authority context for resource dispatch and protected delivery. The Kernel's request-authorizer hook rechecks it on every resource call, including inherited children. Replacing a profile invalidates sessions issued by its previous revision: undispatched work is rejected, while already accepted effects retain their real outcome and reconciliation evidence. Delivery independently rechecks authority after its final await; withholding a response does not roll back an effect.

Submission response bodies retain the original session and surface and recheck
current authority before encoding and before handing each ready frame to the
transport. This includes cached results, structured output and indeterminate
fallbacks. Revocation withholds pending data and successful completion without
changing stored effects or evidence. Bytes already handed to the network cannot
be recalled; encoded buffers retain their capacity permit, not the authority
context, until the last retained slice is released.

## Configuration

Build the optional listener independently:

```sh
cargo build -p xolotl-daemon --no-default-features --features application-grpc --locked
```

First start the daemon with persistent State and Console enabled, leaving the application address absent. Use the authenticated Console `config.write_cas` action to create `state://kernel/gateway/profiles/tasks`. Its input contains `path`, the profile `value`, and `expected_version: null` for creation. Console requires write authority and its normal MFA step-up. It assigns `version: 1`; subsequent updates supply the observed `expected_version` and advance it.

The profile document owns credentials, identity mappings, surfaces, bindings, registered authorities and Gateway admission limits. For example:

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
    "identity_path": "identity://application/worker"
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

Replace the placeholder `token_hash` with the lowercase BLAKE3 digest of a bearer secret generated from at least 32 random bytes by the OS CSPRNG; do not store the raw secret in the profile. Length checks cannot establish entropy. A client certificate verifier uses `kind: "client_certificate"` and `der_sha384` (96 lowercase hex characters) instead. Empty permission lists grant no access. Omitted limit fields use the Gateway defaults advertised by authenticated discovery. Unknown document fields fail admission. Profiles reference already registered effects; they do not install providers. Remote Provider targets must be Ready before a profile using them can be installed.

Each `identity_path` must be a concrete local `identity://...` path. The Gateway registers active mappings in the Kernel's shared identity directory before publishing a profile, then reuses the assigned identity number for requests. A `process://...` path addresses a process resource and cannot identify a caller.

`limits.max_recent_cancellations` bounds the retained cancellation-record count in one Gateway registry (default 4096; zero disables it). It does not bound active requests, borrowed output, other runtime instances or total RSS; the active request remains resident while its response or borrowed chunks hold capacity. Profile replacement applies a smaller history limit immediately.

`limits.max_deadline_ms_from_now` bounds a supplied task deadline, including the server ceiling derived from `grpc-timeout` for `Submit` and `SubmitOutput`. With neither a client task deadline nor `grpc-timeout`, no task timer is created; admission, budget and connection limits still apply.

`GatewayRuntime::new` starts request and object maintenance through the Kernel's installed `HostRuntime`; construction fails if the host cannot schedule the required tasks. A host that owns its own scheduler can use `GatewayRuntime::new_manual` and call `maintain_once(&mut GatewayMaintenanceCursor)` repeatedly, including while requests are idle. Each call sweeps all currently due requests in the deadline index, then independently attempts at most one bounded page of tickets and one of read grants when the State ports are available. The request sweep has no per-call count limit, so a tick can take longer when many requests expire together. Keep the cursor with that runtime; a successful report indicates whether object scans were available, counts oversized rows and reports request-process cancellations that could not be confirmed. If either available scan fails, the call returns an error after attempting the other scan. Earlier conditional deletions stay committed, and each failed family's cursor restarts at its prefix on retry. Manual Gateway maintenance does not drain abandoned Kernel process cleanup. The host must also call `Bootstrap::drain_cleanup()` when cleaning up abandoned scopes and during controlled shutdown; that operation may wait for detached owners and should not be folded into every short maintenance tick. The daemon uses automatic maintenance.

`GatewayRuntime::status().maintenance` exposes independent `request_deadlines` and `object_records` progress. Each includes `state`, `observed_for`, `since_last_attempt`, `since_last_success`, `active_attempts` and `consecutive_failures`, all measured with the Kernel host's monotonic clock. A request pass succeeds only if every due process cancellation was confirmed; an object pass succeeds only if both ticket and read-grant scans succeed. `Active` means the host still owns the automatic future and its last successful pass is within the alert window. `Overdue` means no full success for at least one second for requests or 20 seconds for object records, measured from tracker creation until the first success. `Stopped` means the future exited or was aborted. `Manual` reports only calls to `maintain_once`; the host chooses the cadence, so no automatic overdue threshold is imposed. `Unavailable` for object records means State lacks a query or bounded conditional write port and the host owns retained-record cleanup. `active_attempts` counts overlapping passes; a cancelled pass releases its count and records a failure. `since_last_attempt` shows when the latest pass began. Profile authentication `readiness` is independent of maintenance status; operators should observe both.

Then enable the listener and select the existing profile:

```toml
[server]
application_grpc_addr = "127.0.0.1:9445"

[application_gateway]
profile = "tasks"

[application_gateway.request_storage]
max_records = 4096
max_bytes = 67108864
max_record_bytes = 1048576
retry_epoch_ms = 900000

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

`XOLOTL_APPLICATION_GRPC_ADDR` supplies the address when the config field is absent. With neither address, the daemon does not load the profile, construct an application runtime, bind a socket or create its watcher. An enabled listener fails startup for a missing, malformed or uncompilable profile. It does not create a default principal or import a seed that can revive deleted authority. An address supplied to a build without `application-grpc` is a configuration error.

The running listener watches the exact State record. Successful revisions swap the compiled profile; invalid replacements retain the last good profile. A deleted or missing record, a failed State reread, or a lost, closed or failed subscription closes the listener and cancels its active RPCs. It does not resubscribe or reopen automatically; after restoring valid State, restart the daemon to recreate the listener. To revoke access while retaining a running listener, write a higher-version closed profile with empty credentials and bindings. Profile admission and runtime resource resolution remain separate checks.

## Protocol

Gateway-local observations, including MCP discovery and authentication events, are optional when the host has not installed observation storage. Installed storage failures remain visible; required recording uses a separate strict API. Authorization, retry receipts and delivery checks do not depend on observation history.

Embedded callers can first construct a payload-free `GatewaySubmissionHead`, acquire a non-cloneable `GatewayPreparation` through the fail-fast `Gateway::prepare_submission(session, head, output_window)`, and transfer the payload and provenance through `submit_prepared` or `submit_output_stream_prepared`. The owner freezes its runtime, session, profile, submission head, output window, and original deadline. A foreign runtime or the wrong output entry point rejects it and releases its capacity. Preparation neither creates an acceptance identity nor reserves idempotency. Existing `submit`/`submit_output_stream` methods acquire preparation admission once as convenience entry points; they cannot bound Value construction already performed by their callers.

gRPC acquires shared admission after authentication and head validation, before protobuf payload conversion to Value. MCP authenticates and resolves the surface before acquiring admission and converting raw arguments to Value. Semantic hashing, idempotency CAS, input inspection, and object metadata reads share that admission; execution takes the existing guard without acquiring another slot. Folded input streams retain stream-open admission instead of reacquiring it at completion. Initial transport decoding, frame buffers, and caller-owned Values have separate memory costs; concurrency slots are not RSS limits. Dropping preparation releases local capacity, but cancellation or an uncertain CAS does not delete persistent pending evidence or prove that ticket consumption or external effects rolled back. See the [submission and object ingress design](application-gateway.md).

The vendored schema is `proto/xolotl/v1/application.proto` in `xolotl-proto`. The service name is `xolotl.v1.application.ApplicationGateway`.

| RPC | Contract |
| --- | --- |
| `Describe` | Authenticated, redacted profile revision, visible surfaces, publications and business limits; `max_frame_bytes` separately reports this adapter's actual transport frame limit. |
| `LookupRequest` | Read-only, bounded original-request evidence summary without result payload or export creation. |
| `DeliverRequestResult` | Explicit delivery of the retained original result, without business reexecution; may externalize objects and create read grants. |
| `IssueUploadTicket` | A principal/surface-bound, bounded object-set ticket with optional content, media type and lifetime constraints. |
| `UploadObject` | Client stream `Begin -> Chunk* -> Finish -> clean HTTP input completion`, then one committed typed reference and receipt. |
| `DownloadObject` | Explicit read grant plus absolute range; server stream `Header -> Chunk* -> Completed`, then successful gRPC EOF. |
| `Submit` | Surface id, structural Value, optional receipt provenance and submit options; returns acceptance metadata and `SubmissionCompletion`. |
| `SubmitOutput` | The same typed input with explicit Stream mode; returns `Accepted -> Chunk* -> Completed` followed by successful gRPC EOF. |

`Describe.max_frame_bytes` bounds an encoded protobuf envelope for this
transport, not HTTP/2 headers, gRPC framing, cumulative stream traffic, object
length or RSS. It is a transport fact, not a Gateway business-limit override.

Each RPC authenticates a single `authorization: Bearer <secret>` header or, in mutual TLS mode, the listener-verified leaf certificate. Profile authority matching uses HTTP/2 `:authority`. An independent `host` header cannot replace it. Gateway checks session generation and authority in one profile snapshot, so profile replacement cannot combine old hosts with newly issued sessions. Forwarded authorities are accepted only from configured proxy peers. TLS modes require actual tonic TLS connection evidence, and local mode requires a verified loopback peer. TLS file settings follow the external gRPC listener's transport-security configuration.

A trusted reverse proxy must remove client-supplied forwarding headers and overwrite each adopted `X-Forwarded-Proto`, `X-Forwarded-Host`, or `Forwarded` field with one value. Appending a chain, repeating a header or repeating an adopted `Forwarded` parameter is rejected; the Gateway cannot infer which entry the proxy actually observed. When a host-supplied `GrpcConnectionInfo` is present, its peer address is authoritative, including when that address is absent.

Upload `Begin` contains the ticket id, optional media type, submission token, and per-upload expected size and digest. The bundled object store and Gateway use lowercase SHA-384 digests (96 hexadecimal characters) for object content. Ticket-level expected size or digest requires `max_objects = 1`; a multi-object ticket uses per-upload expectations. Each `Chunk` contains bytes. `Finish` selects Blob, Tensor (`dtype`, `shape`) or Frame (`ts_nanos`, `kind`); the server computes digest and byte length.

Pass the returned `item` and `provenance` together to `Submit` for that ticket's surface. Do not reconstruct a reference from guessed metadata or substitute another principal's proof. One provenance names one ticket that can contain several committed Blob, Tensor, and Frame bindings. A structured input can combine or repeat its exact typed members. Changing Tensor dtype or shape, or Frame kind or timestamp, while keeping the same bytes is rejected before shared object metadata is read.

The ticket defaults to at most 16 distinct typed members, 1 GiB of distinct canonical backing bytes, and a 256 KiB encoded State row. The profile configures these independent limits within the implementation ceilings; an issue request can only tighten the profile limits. The record-size check reserves 4 KiB for the State key and provenance envelope, with the backend's bounded read and write as the final 256 KiB guard. Tickets also admit at most 32 media type patterns, 64 Tensor dimensions, and 16 KiB of inline receipt metadata. Ticket lookup and conditional updates require exact-path bounded State read and write capabilities with a 256 KiB encoded-record budget. A host must install both capabilities against the same current-value commit domain before it can issue tickets.

Different tickets cannot be combined in one submission: all typed members must belong to the one named ticket. A single-use submission must carry an `idempotency_key` or `submission_token`; Gateway binds that material to the complete content and consumes the entire ticket before Driver execution. An unknown consumption verdict stops execution and retains the pending replay reservation. A folded input stream establishes or replays this reservation only after its full payload is known. If an upload append verdict is unknown and its operation identity cannot be read back, the upload returns an indeterminate result; equal content uploaded elsewhere does not establish success for that attempt. See the [submission and object ingress design](application-gateway.md).

When State supports bounded queries and bounded conditional writes, automatic maintenance scans at most 16 ticket rows and 256 KiB every five host-clock seconds. It conditionally removes expired or consumed current rows, including after a restart. Manual maintenance advances one such page when its ticket scan succeeds. State returns preceding records as a partial page before reporting an oversized row; Gateway handles that page, then explicitly skips the rejected row on the next pass and reports it in `skipped_oversized`. It does not replay preceding rows or add a second scan budget. The examined count includes an oversized boundary inspected by the partial page. Oversized or malformed rows may remain; selecting redb `Full` also retains prior events, so this is not a total storage bound. A concurrent replacement above the ticket row budget is rejected before redb decodes it during a conditional update; its provenance is then unknown and the row remains for separate repair.

`DownloadObject` consumes `read_grant_id`, an absolute `offset`, and optional `length`. Omission selects the rest of the granted range; zero selects an empty range. The header supplies the frozen canonical backing BlobRef, selected range, initial taint and fixed expiry. Each chunk carries its absolute offset, bytes and current taint. Completion supplies `next_offset` and total `bytes_read`; range completion can precede the object's physical EOF. Successful gRPC completion is still required, including for empty ranges. Errors use gRPC status, independently of AI execution outcomes or cache origin.

Trusted host code issues a grant through `GatewayRuntime::issue_object_read_grant(session, IssueObjectReadGrantRequest)` only after authorizing disclosure of the direct Blob, Tensor or Frame in `object: TaintedValue`. The request selects a known profile `surface_id`, absolute `offset`, optional `length` and optional `expires_in_ms`. Grant lifetime is bounded by the profile's deadline window. Issuance requires exact-path bounded State read and conditional write capabilities; it checks the complete record with its taint against the 256 KiB maintenance page budget before the bounded commit. There is no remotely callable grant issuer. Knowing a hash, possessing an upload receipt, or receiving a tainted execution result does not authorize disclosure. Application-specific output export policies can call the trusted issuer; this service does not discover and export references by recursively scanning ordinary results.

Object delegation is independent of discovery and submission permissions. A live authenticated audience may receive a read grant while having only directory visibility or no discovery/submission binding at all. Its submissions still follow the ordinary capability and surface admission rules. The known surface and target bind the delegation's scope without giving its audience execution authority.

The immutable versioned State record binds profile name/revision, principal and credential identities/generations, authentication kind, identity path, surface target, exact object and permitted range. State's tainted envelope is the sole persisted provenance authority. Trusted replicas or restarted runtimes can consume the grant when those bindings and shared storage agree. Opening a grant and verifying it around each storage read use a 256 KiB bounded State point read; an oversized current record is rejected before use. Profile revision changes invalidate it. Grant activity does not renew expiry. The trusted `revoke_object_read_grant(session, grant_id)` API uses bounded conditional deletion without deleting content. With State query and bounded conditional write, Gateway maintenance also compare-deletes expired grants in pages of at most 16 rows and 256 KiB; invalid or oversized rows require separate repair. A host with bounded point read and conditional write but no query can still issue grants, while owning retained-record cleanup. Storage retention remains a host policy.

`SubmitOutput` shares admission, receipt consumption, execution and cleanup with `Submit`. Acceptance precedes execution. Each output chunk carries its typed `item` and server-assigned `taint`; the latter records lineage and does not grant object access. An optional surface `output_stream_schema` validates each whole chunk before delivery. The existing `output_schema` independently validates the final value. A failed chunk validation remains a request failure even if a driver ignores the send error. Final-value rejection retains the rejected result's taint; chunk rejection adds the rejected chunk's taint to the final failure. Other chunks keep their own lineage independently of the final result.

Submission retains the selected surface identity through admission, quotas and final schema validation. Several surfaces may expose the same effect with different schemas without being confused by a target lookup. Accepted requests use their frozen profile; later profile replacement applies to new admissions. Replacing a profile alone does not cancel an accepted request. Explicit request cancellation and listener shutdown retain their own lifecycle semantics.

`SubmitResponse` requires `accepted` and exactly one `terminal`: `completion` or `indeterminate`. `SubmitOutput` delivers `Accepted`, zero or more `Chunk` events, then either `Completed` or `Indeterminate`. Normal `completion` and `Completed` share `SubmissionCompletion { outcome, origin, taint, unresolved_operations }`. Successful, failed and cached completions all carry host-observed reconciliation state. `operation_ids` lists known opaque identities; `identities_incomplete` means some identities were omitted. Pristine lineage is an explicitly present empty `TaintSet`; missing taint is invalid. In Rust, ordinary `submit` and `GatewayOutputEvent::Complete` return the same `GatewaySubmitResult { accepted, output: ExecutionOutput, origin }`. Whole-request idempotency replay retains the reconciliation state. Completion follows idempotency persistence and process cleanup. The driver's `StreamEnd` does not determine the final request result.

Origin describes the boundary reporting the result. An invocation cache hit has `CompletionOrigin::CachedOutcome` on its `DriverOutput` and `StreamEnd`. A program that runs in a new Gateway request still reports `COMPLETION_ORIGIN_CURRENT_ATTEMPT`, including when its calls hit kernel caches. Only whole-request Gateway replay reports `COMPLETION_ORIGIN_CACHED_OUTCOME`. Both caches retain final outcomes and their taint without replaying historical chunks. Gateway idempotency records use `gateway-idempotency-v1` and the request store's required tainted envelope; unknown or malformed records are rejected. If result persistence, process cleanup or output delivery fails after execution, and the current session remains authorized to submit to the original surface and the connection can carry a terminal frame, `indeterminate` retains the original acceptance, a stable `reason_code` and bounded `unresolved_operations`. IDs omitted to fit the frame set `identities_incomplete`. It has no program outcome and does not authorize a retry. Unknown results before acceptance still use gRPC `FAILED_PRECONDITION` with `x-xolotl-error-code: outcome_unknown`.

Clients must also observe successful gRPC completion; a disconnect, lost response or frame too small for acceptance can prevent evidence delivery. `LookupRequest` reads retained request evidence without resubmitting the payload or executing work; it is not universal Driver reconciliation. An unsettled request still requires the host or external effect system to reconcile the original identity. Without retained idempotency material or a queryable external identity, clients cannot guarantee self-service resolution and must not retry under a fresh identity. Taint and cache origin do not grant access to referenced objects.

`GatewayRuntime::new` and `new_manual` require an explicit third argument, `Arc<dyn GatewayIdempotencyStore>`. Share the same store across runtimes that own the same request-evidence scope. An embedded memory host can choose `MemoryGatewayIdempotencyStore::default()` or `new(limits)`; a persistent host uses `RedbStore::gateway_idempotency_store(limits)` with the redb `gateway` feature. Request evidence is separate from ordinary State and execution state; it does not enter State history. The daemon uses its selected storage backend: one shared memory request store for `storage.kind = "memory"`, or the same redb database and tracked blocking admission owner for `"redb"`. Persistent startup never silently falls back to memory. Unsupported request-evidence layouts reject opening rather than replacing retained evidence with an empty ledger.

`application_gateway.request_storage` owns the daemon's request-store limits. Defaults come from `GatewayIdempotencyLimits`: 4096 retained identities, 64 MiB aggregate encoded key/row bytes plus pending result reservations, and 1 MiB per encoded row. All three limits must be nonzero, and aggregate capacity must fit one key plus its full result reservation. These are logical storage charges, not process RSS or a bound on caller-owned values. Reserve charges the full result capacity before execution; settlement releases unused bytes exactly once. Full stores still permit observation and replay of existing identities. Failed admission can release only its original pending reservation; cancellation, uncertain effects and unknown results do not authorize deletion. Oversized or conflicting settlements leave evidence and accounting unchanged.

There is no automatic retirement. A host can explicitly `retire` only a known committed result with no unresolved operations or incomplete identities. Retirement releases result bytes but retains the complete fingerprint, provenance and record count, so old material cannot execute again. Object-ticket maintenance does not remove request evidence. Persistent reopen preserves usage and requires the same limits; changing limits is not a silent capacity reset. Deleting pending or committed records can repeat effects, and changing the profile revision does not preserve deduplication for an earlier request. See the [retention contract](application-gateway.md).

## Retry Ranges

A retained `pending` row proves reservation without a settled result, not that
the execution is still running. Reopen does not restart the execution. Retrying
that identity cannot redispatch it; absence of a result does not prove that no
effect occurred.

Each authenticated surface advertises `request_scope`. A submission carrying an
`idempotency_key` or `submission_token` must retain that value in
`SubmitOptions.expected_request_scope`. Preparation compares it against the same
Profile snapshot used for admission, before payload conversion, reservation or
effects. A changed ledger, Profile, subject binding, target or schema rejects the
original scope. Discovery alone is not a submission precondition; preserve and
send the value, rather than refreshing it on retry. Scope is not authority.

The request store owns its evidence namespace. Shared memory adapters keep one
identity; a replacement memory store has a different one. Redb stores the
namespace with its v1 metadata and preserves it on reopen. Missing or invalid
metadata and unsupported formats reject opening; there is no synthetic identity or
automatic migration. A new ledger cannot resolve old effects. The namespace
does not detect rollback of the same database to an old backup. Profile versions
must continue to identify immutable declarations within one evidence domain.

`Describe.retry_epoch` reports the request store's current retry range. `SubmitOptions.retry_epoch` selects that range and defaults to zero; `idempotency_key` and `submission_token` retain their literal meaning and 256-byte limits. Changing the epoch creates a new request, not a retry. Clients must retain the original epoch when reconciling an unknown request instead of automatically advancing it into a newer range.

Only a trusted host calls `GatewayIdempotencyStore::close_retry_epoch(expected)`, atomically advancing the store-wide barrier and reclaiming eligible closed-range evidence. This is neither a TTL nor a profile revision or reset, and no client close RPC is provided. Pending and unknown work remains charged and observable; resubmitting its original identity can inspect or replay retained evidence but never redispatches its effects. Redb retains the barrier across reopen; memory storage does not provide restart-safe retries. Exact eligibility and uncertain-commit handling belong to the [request-store rustdoc](https://github.com/xolotl-org/xolotl/blob/main/crates/xolotl-gateway/src/idempotency_store.rs).

The stock application daemon closes retry epochs on its host monotonic clock. `application_gateway.request_storage.retry_epoch_ms` defaults to 900000 ms and accepts 1–86400000; invalid values reject rather than clamp. This store-wide cadence is independent of profile revisions, result retention and Console's separate registry. A delayed wake closes once, then schedules from confirmed completion. Size capacity and cadence together: admission can fill before closure, and unresolved work remains charged.

Maintenance shares the existing profile supervisor but runs concurrently with profile observation, so slow storage does not postpone revocation. Each store read or closure is bounded by `application_gateway.grpc.storage_timeout_ms`. Failure, timeout or uncertain commit stops the service and listener; accepted storage work retains its backend recovery contract. No automatic retry or rollback is implied. Embedding hosts choose their own closure policy.

## Original Request Lookup

The native `Gateway::lookup_request` and gRPC `LookupRequest` require the original
surface, `request_scope`, retry epoch and exactly one idempotency key or submission
token. For a submission containing both, use its idempotency key. Current session
and surface authorization still apply; a changed scope rejects the lookup rather
than searching another Profile or ledger. A closed epoch can retain queryable
evidence, but lookup never opens or advances an epoch.

A submission token alone does not opt every pure call into result retention;
lookup can report unproven evidence for such a call. An explicit idempotency key
selects request retention; required token-backed protection follows the existing
submission contract.

The response distinguishes `unproven` (no retained evidence, not proof of
non-execution), `reserved` (reservation, not proof of acceptance or liveness),
`settled` (original acceptance, Done/Short/Fail result class and bounded unresolved
operations, without result contents or error details), and `retired` (result unavailable, never permission
to rerun). It does not replay stream chunks. A corrupt record is an error, not
`unproven`. Oversized settled evidence returns a frame-budget error, not a
fabricated execution outcome or an unsettled verdict.

Lookup uses an exact read and no execution admission, Process, reservation,
settlement, audit write, object/grant write or scan. Storage timeout and response windows remain
bounded, and delivery rechecks current authority. Keep the original identity
after a lost response; generating a fresh key, scope or epoch is a new request.
Backend observation reads and decodes one record within `request_storage.max_record_bytes`;
a small wire summary does not imply payload-independent storage work or allocations.
Lookup validates metadata and required payload shape; delivery validates the full payload codec.

`DeliverRequestResult` uses the same original-request identity and current
session/surface authorization, but explicitly requests the retained payload.
It returns cached completion through the existing result-delivery path, with no
business execution or replay of historical chunks. With an installed structured
output externalizer, delivery may write objects and read grants; it is not a
pure observation. Encoding and final handoff recheck current delivery authority.
Unproven, Reserved and Retired return `FAILED_PRECONDITION`; they never authorize reexecution.
Oversized results require an installed externalizer. Delivery failure does not change settled evidence.
Result encoding
is selected by the installed adapter/externalizer, not a `requested_encoding`
submission option; that field has been removed.

## Resource Ownership

Object authorization cleanup removes the authorization Value, not necessarily the current State record. A non-pristine deletion retains sourced absence even in `CurrentOnly`; history trimming does not release it. Both memory and redb enforce configured sourced-absence record and encoded-byte quotas atomically, rejecting growth beyond those quotas without partially deleting the value. Hosts account for this current-domain retention separately from history and object content; expiry is not evidence that storage was reclaimed. These quotas are not allocator-byte or RSS limits. See [State And Facts](state-and-facts.md).

Gateway retains the request's cleanup pin until finalization custody is complete and a committed `ProcessFinalizationReport` is available. It merges finalizer taint and unresolved effects into the body output before caching or delivery, without replacing the body outcome with known typed finalizer failures. Missing reports, incomplete custody, and finalization errors remain indeterminate and retain pending idempotency; they never authorize reexecution. Report presence alone is not proof of completed cleanup. Folded-stream replay merges the current request's finalization evidence into delivery without rewriting the original cached result. The protocol projects the body and aggregate taint/unresolved effects, not the full runtime cleanup report.

Each upload RPC owns one existing `GatewayObjectUpload` and one shared semaphore permit. Excess uploads fail immediately. The adapter reads one protobuf frame, borrows its bytes through storage writes, then reads the next frame. It retains no cumulative payload buffer. Storage offers remain at most 16 KiB. The configured protobuf frame includes envelope overhead, so a byte chunk must be smaller than `max_frame_bytes`.

The frame and concurrency windows do not cap cumulative object size. Unknown total lengths are accepted; declared ticket constraints and the current `i64::MAX` receipt size representation still apply. First-frame, subsequent-frame and storage wait windows are independently configurable and reject invalid settings instead of silently clamping them. These waits do not extend absolute ticket expiry or replace task admission deadlines.

Each download owns a `GatewayObjectDownload` over the existing optional object reader. It opens no kernel process, producer task or reader registry. The transport retains one byte window of at most `min(max_frame_bytes, 16 KiB)` and splits it using the actual encoded protobuf size, including taint. Partial reads are valid; invalid offsets, non-progress or inconsistent physical EOF close the owner. Full object sizes and ranges use `u64`, without the upload receipt's signed-size representation. An empty range reads no object bytes.

The owner verifies the grant's exact State value and provenance before and after each storage read, and again at completion. Live session and expiry checks also precede delivery of each frame. A failed or cancelled polled read closes the owner; callers must not deliver buffer contents from an unsuccessful read. Revocation prevents later authorized reads but cannot recall bytes already acknowledged or buffered by the transport. Per-chunk taint combines opening and grant sources with that read's sources, without accumulating historical chunk taint. Separate reads do not pin an object against deletion; a deleted object can interrupt a download. Republished content with the same hash denotes the same bytes, with current read provenance still included.

An output response owns its execution future and one kernel channel. Transport polling advances both; there is no detached producer or second output queue. `output_window_chunks` and `output_window_bytes` bound accepted and borrowed kernel chunks. The byte charge is the tagged JSON encoding of value and lineage, not protobuf bytes or RSS. Kernel credits are held through bounded protobuf conversion, after which tonic owns its copy. Total output can exceed these windows without accumulating historical chunks. Codec and HTTP/2 buffers, conversion of one chunk and the final result have additional retention costs.

`max_concurrent_output_responses` is shared by execution output and object download responses, including slow clients and transport buffers. Its permit follows both the response body and the encoded DATA bytes transferred to HTTP/2, without copying their payload. It is released only after the last owner drops. Gateway admission and budget leases similarly follow the response and any borrowed output chunks, without retaining a cancelled execution process. Cancellation or deadline expiry revokes execution authority; it does not release capacity still owned by a live response. A slow HTTP/2 peer can prevent response polling, so logical cancellation alone does not guarantee immediate destruction of a pending driver future. Listener shutdown also closes connection I/O to reach these stalled responses.

After the last request lease drops, only a cancelled request can enter the registry's compact history. A matching principal, Gateway and trace root can repeat that cancellation for up to 60 seconds after the cancellation decision, measured by the Kernel's monotonic host clock. Oldest expirations leave first when the configured capacity fills, so a later repeat then returns false. Completed, failed and expired requests leave the registry with their final lease. Deadline sweeping indexes only active requests with an actual task deadline; it does not scan deadline-free requests or retained cancellations. The 60-second validity check and physical reclamation are separate: automatic maintenance or a later registry operation prunes expired history. A manually maintained runtime can keep expired tombstones until its next maintenance pass or registry operation, still within the configured count limit.

The ingress captures `grpc-timeout` before decoding and retains its transport deadline through response completion. For both `Submit` and `SubmitOutput`, it converts the remaining time at handoff into a deadline from the Gateway's host clock; Gateway combines that ceiling with the client's absolute task deadline in the same monotonic domain. Execution and deadline sweeping use the resulting deadline. After execution and output validation, Gateway resolves cancellation or expiry and freezes the body result, then finalizes the process and merges finalization taint and unresolved effects before persisting the complete idempotent result. These decisions preserve aggregate taint. An ordinary driver `Timeout` before the task deadline remains a driver failure. After that completion decision, the task deadline does not rewrite the result or discard queued output; the RPC deadline still applies to delivery. When response polling resumes after RPC expiry, the body terminates with `DeadlineExceeded`.

Missing, reordered or trailing frames, a reset, an expired wait or shutdown release the request owner. Publication requires both the final protocol marker and actual successful HTTP body completion: tonic can translate HTTP/2 CANCEL into an apparent stream EOF. Cancellation during commit or receipt CAS can leave published content or an uncertain receipt result. Shared committed bytes are never deleted to undo such uncertainty.

Shutdown also cancels requests still being decoded before their handler starts. The daemon propagates its close signal through connection reads and writes, so incomplete HTTP/2 prefaces and peers that stop reading cannot keep internal tonic connection tasks alive after the listener is closed.

The stock daemon owns the application service together with its other listeners and background tasks. After the Kernel is built, startup errors and shutdown-signal errors use the same asynchronous teardown as normal exit; the original error is returned only after teardown. Teardown closes application admission, uses the services' execution and transport shutdown, waits for owned background tasks, drains process cleanup, then waits for accepted work on the shared blocking spawner. Cancelling an application shutdown future does not discard pending task handles. Dropping the whole host scope requests task cancellation but does not substitute for asynchronous teardown or roll back committed external effects.

The daemon also observes the termination of required listeners and maintenance tasks. An unexpected successful return, service error, panic or external abort triggers the same teardown and a nonzero exit, rather than leaving the daemon running without a required service. Explicit deletion or confirmed absence of the application profile closes only this application service; a lost profile watch or failed profile read escalates to the host. Invalid profile updates retain the last accepted version. The daemon does not automatically restart tasks or replay accepted work. Termination observation does not detect a hung task or prove remote-service health.

## Current Output Scope

`Submit` supports Unary and Collect. It explicitly rejects Stream, AsyncProcess and SinkOnly because this RPC returns a completed response. Inline inputs, collected outcomes, protobuf decoding and transport buffers have their own memory costs. The frame limit also applies to responses; an oversized response can fail after execution, so retries still need normal idempotency semantics.

Outgoing `Value` fields also use the shared protobuf codec's 30-level nesting limit, counting each value's root as level one. This leaves room for envelope messages within prost's default decoding recursion limit. It applies to results and discovery schemas and metadata; exceeding it returns `ResourceExhausted` even when the response fits the frame budget. Raising `max_frame_bytes` does not raise this depth limit.

With the optional `xolotl-gateway-grpc/structured-output` feature, a host can install `ApplicationGrpcService::with_output_externalizer`. The adapter first tries bounded inline encoding. If the payload exceeds that frame or nesting budget, it polls one owned Gateway externalizer configured with an explicit I/O window, asynchronous key-store factory and disclosure policy. Publication and canonical metadata inspection precede the policy decision and read-grant commit. The policy sees the original output, authenticated audience, complete current metadata and exact proposed expiry. No policy is installed automatically.

`OutputValue` and `OutputFailure` each select exactly one inline or object representation; `OutputOutcome` independently preserves Done, Short and Fail. Object delivery carries the explicit encoding, complete BlobRef, read-grant ID and expiry. Failure objects contain the shared lossless externally tagged Failure layout. Completion origin and provenance remain required, including cached results. Externalization errors affect delivery without rewriting the execution result or its cache. Nested references receive no grants.

`SubmitOutput` retains the original chunk's credits through encoding, policy and bounded wire projection. The same execution owner continues to process request cancellation and deadlines during a pending encoder. Cancellation abandons that encoding before delivering the original interrupted request's final outcome. There is no additional producer or output queue. Unary, stream and download responses share the configured transport concurrency window through HTTP/2 DATA ownership. The encoded document can exceed a frame and the inline depth limit; its consumer validates incremental downloads through actual successful EOF.

Acceptance metadata, object descriptors and advertised provenance still have to fit a response frame. Externalizing a payload does not remove those metadata bounds, nor the memory required by an explicitly materializing consumer. The CBOR profile encodes logical tree occurrences, so a heavily shared resident DAG may expand substantially. No cumulative object or stream-byte cap is inferred from the transport window.

`DownloadObject` serves bytes explicitly authorized by trusted host issuance; the daemon does not yet install a general provider-result export policy. Hosts select that disclosure policy when composing their service. Explicit `value/read` or `ValueObjectReader` consumers reconstruct structured objects; inference backends do not implicitly load references, and an upload receipt does not confer Provider/Source or MCP authority.
