# Gateways

This page maps `xolotld` listener addresses to client protocols.

Application clients submit through profile-bound surfaces. External programs
that provide effects or events connect as Provider or Source projections;
gRPC and WebSocket implement that separate external session boundary.

## Entry Points

A listener starts when its `[server]` config field is set, or when the matching
environment variable is set. `xolotl-daemon` enables `external-grpc` and
`external-websocket` by default; either transport can be built alone with
`--no-default-features --features external-grpc` or `--no-default-features
--features external-websocket`.

| Entry point | Config field | Environment variable | Route or service | Encoding |
| --- | --- | --- | --- | --- |
| Console HTTP | `console_addr` | `XOLOTL_CONSOLE_ADDR` | `/health`, `/api/auth/*` | HTTP JSON |
| Console WebSocket | `console_addr` | `XOLOTL_CONSOLE_ADDR` | `/ws` | Binary protobuf `ConsoleFrame`, `protobuf+xolotl-console-v1` |
| Application gRPC | `application_grpc_addr` | `XOLOTL_APPLICATION_GRPC_ADDR` | `xolotl.v1.application.ApplicationGateway` | Protobuf |
| External gRPC | `external_grpc_addr` | `XOLOTL_EXTERNAL_GRPC_ADDR` | `xolotl.v1.external.ExternalService.Session` | Protobuf |
| External WebSocket | `external_websocket_addr` | `XOLOTL_EXTERNAL_WEBSOCKET_ADDR` | `/ws` | Binary protobuf frames |

Console WebSocket and external WebSocket both mount `/ws`. They are selected by
listener address and frame encoding:

- Console WebSocket uses `[server].console_addr` and binary protobuf console
  frames under the `xolotl-console-v1` subprotocol.
- External WebSocket uses `[server].external_websocket_addr` and binary
  Provider/Source session frames.

## Which Entry Point To Use

| Need | Entry point |
| --- | --- |
| Run management actions, inspect runtime state, manage users, manage sessions, subscribe to state or audit streams | Console Protocol |
| Discover permitted surfaces, upload typed objects and submit AI tasks as an application principal | [Application Gateway](application-gateway.md), optional `application-grpc` feature |
| Connect an external program that provides effect handlers | External gateway as Provider |
| Connect an external program that emits inbound events or receives outbound commands | External gateway as Source |
| Publish selected Gateway publications as MCP tools, resources, resource templates, and prompts | MCP |

## External Gateway

External gateway sessions are described in [External Gateway](external-gateway.md).
Provider and Source are the only external projection roles.

Use this entry point when a program runs outside the Xolotl process but should be
projected into the runtime as declared effects or declared event streams. The
daemon owns session admission, generation checks, binding selection, and
runtime limits; external programs do not self-declare authority.

## Embedded Object Access

The profile-driven `GatewayRuntime` installs object capabilities explicitly with
`with_object_store`. Pass clones of the same `ObjectStore` to the gateway and
`StandardConfig::with_object_store` so admitted references can be read by standard
providers. The default gateway has no object adapter; inline submissions do not
need one. State retains upload tickets and proofs, not object bytes.

An upload commits immutable content before publishing its ticket receipt with
CAS. The receipt binds the profile name, principal, surface, optional submission
token, digest and size. It does not pin the profile revision; the current session
and authority are checked again. Uncommitted tickets cannot authorize existing content. Admission checks
the receipt and canonical metadata, and propagates the object's provenance into
execution. A single-use proof is consumed after Gateway admission and before a
new execution attempt is accepted; an admitted driver failure does not restore it.
A failed receipt CAS never deletes shared committed content.

The kernel's request scope owns each admitted process while receipt consumption
or execution is pending, including across input-stream calls. Dropping an
unfinished submission or accepted stream cancels the process tree and revokes
its handles; asynchronous cleanup uses the shared host lifecycle mechanism.
Cancellation during a receipt CAS can leave its result uncertain and does not
restore a single-use receipt automatically.
Accepted input streams belong to the runtime that admitted them. Its clones
share that ownership; another runtime cannot complete or fail the stream.

Object input uses one incremental API. `begin_object_upload` takes ticket,
media-type and submission-token metadata and returns an owned upload. `write`
borrows each chunk; it splits storage offers into windows of at most 16 KiB and
handles partial acknowledgements without retaining earlier payloads. A caller
can supply smaller chunks. Total size can remain unknown; neither window size
nor chunk count imposes a cumulative object limit. Declared size and digest
constraints still apply, and the ticket representation supports sizes through
`i64::MAX`.

```rust,ignore
use xolotl_gateway::{BeginObjectUploadRequest, Gateway, GatewayObjectKind};

let mut upload = gateway.begin_object_upload(&session, BeginObjectUploadRequest {
    ticket_id: ticket.ticket_id().into(),
    media_type: Some("application/octet-stream".into()),
    submission_token: None,
}).await?;
upload.write(&first_chunk).await?;
upload.write(&next_chunk).await?;
let result = upload.commit(GatewayObjectKind::Blob).await?;
```

At end-of-input, `GatewayObjectKind::Tensor { dtype, shape }` or
`GatewayObjectKind::Frame { ts_nanos, kind }` adds interpretation without requiring
the caller to construct a hash or byte count. The upload computes its digest
incrementally and validates the final reference against committed metadata.

The upload holds the original store and live profile state itself. It does not
accept a second runtime at commit. A polled write that fails or is cancelled
abandons its staging lease and closes the upload, since storage may have accepted
an uncertain prefix. Dropping an unpolled write leaves the upload intact.
`abort` is optional; dropping the upload cleans staging through the adapter's
existing ownership contract. Ticket expiry never slides with activity; an idle
expired upload still needs its owner dropped or aborted to release staging.

The optional [Application Gateway](application-gateway.md) feeds this API from
incremental gRPC input and releases its owner on disconnect, timeout or shutdown.
Caller buffers, transport parsing, committed objects and State retention have
their own memory or storage costs.

## MCP

MCP server support is defined by Gateway publications. A publication names one
Gateway surface for the `mcp` protocol and declares one kind: `tool`,
`resource`, `resource_template`, or `prompt`. It does not repeat the effect
target, schema, or caller binding. Discovery returns only MCP publications whose
surface is visible to the authenticated principal. Tool calls, resource reads,
and prompt requests submit through the published surface id, so schema checks,
limits, policy, Handle ownership, Facts, taint, and audit stay on the shared
Gateway path.

Publishing requires the referenced surface to carry a `publish://...`
capability that covers the target effect. MCP clients never submit raw effect
paths, raw capabilities, acting identities, or raw Operations.

The MCP adapter negotiates `2025-11-25` first and keeps all supported published
MCP protocol revisions in the handshake. It implements initialize, ping, tool,
resource, resource template, prompt, and completion requests. It advertises
completion support only for protocol revisions that define it. It does not
advertise logging, resource subscriptions, list-change notifications, or task
execution.

MCP-specific fields stay in publication properties. `icons`, `mimeType`, `size`,
prompt `arguments`, and static `completions` are read by the MCP adapter.
Gateway still owns the surface target, schemas, bindings, limits, and audit
path. Tool results may return native MCP `content`, `structuredContent`,
`isError`, and `_meta`; content blocks are validated before they are sent.

`McpGateway::with_output_limits(McpOutputLimits)` selects response admission.
Defaults allow 65,536 logical Value occurrences, depth 32, 8 MiB of inline
payload, 65,536 projected JSON nodes and a 16 MiB encoded message. The JSON node
budget includes bytes expanded into numeric arrays and generated media fields;
the byte budget includes escaping and the final JSON-RPC envelope. Shared
descendants count at each occurrence. The ordinary JSON adapter supports Value
depths up to 64; deeper structures can use explicit encoded object references.
These transport budgets do not constrain kernel value depth or cumulative task
data. A result rejected during projection does not undo its completed effects.

## Console Protocol

Console HTTP is limited to health and authentication. Logged-in management uses
Console WebSocket with authorization, CAS, visibility gates, and audit records.

Console transport security is deployment configuration and is documented in
[Configuration](configuration.md). This page only identifies the console
protocol entry point.
