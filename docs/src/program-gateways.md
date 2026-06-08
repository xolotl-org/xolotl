# Program Gateways

Program gateways accept external work and run it through the shared
`nexus-gateway` contract. The submitted work becomes a `DoNode` program and is
executed as an attenuated request Process.

## Shared Semantics

`nexus-gateway` defines `Gateway` and `InProcessGateway`.

`InProcessGateway` currently validates a non-empty token that parses as an
identity path, for example `process://alice`. Hosts can restrict identities with
an allowlist, declare the capability ceiling for request Processes, and expose
resource handles per request.

All protocol adapters follow this sequence:

1. authenticate the client token;
2. map the token to a `RequestIdentity`;
3. spawn a request Process for that identity;
4. convert inbound frames to a `DoNode`;
5. evaluate the program with inbound taint;
6. return the `Outcome`.

Gateway audit records use adapter-specific event names such as `gateway_grpc`
and `gateway_ws`.

## gRPC

The gRPC API is defined in
`crates/nexus-proto/proto/nexus/v1/gateway.proto`:

```proto
service GatewayService {
  rpc Submit(SubmitRequest) returns (SubmitResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
}
```

`nexus-daemon` serves this API on `[server].grpc_addr` or `NEXUS_GRPC_ADDR`
when the `grpc` feature is enabled. The feature is enabled by default.

`SubmitRequest`:

| Field | Meaning |
| --- | --- |
| `auth_token` | Gateway auth token. The current in-process gateway parses it as a request identity path. |
| `program` | Structured protobuf `Program`; the root field is a `DoNode`. |

`Program.root` supports the `DoNode` variants defined in `gateway.proto`,
including `pure`, sequencing, fallback, parallel composition, `let`, `acting`,
`wait`, `fail`, and operation templates.

Integration sequence:

1. Connect to the configured gRPC listener.
2. Generate a client from `gateway.proto` and `common.proto`, or use the Rust
   bindings from `nexus-proto`.
3. Call `Health` and read `HealthResponse { ready, version }`.
4. Build `Program { root: DoNode }`.
5. Call `Submit` with `auth_token` and `program`.
6. Read `SubmitResponse.outcome`.

Error mapping:

| Condition | gRPC status |
| --- | --- |
| Authentication failure | `Unauthenticated` |
| Authenticated identity lacks gateway permission | `PermissionDenied` |
| Missing or unconvertible `program` | `InvalidArgument` |
| Request rejected by admission or kernel setup | `FailedPrecondition` |

## WebSocket

`nexus-gateway-websocket` exposes `/ws` on `[server].ws_addr` or
`NEXUS_WS_ADDR`. This channel uses WebSocket text frames containing JSON.

The client sends an auth frame first:

```json
{"type":"auth","token":"process://alice"}
```

The server returns the mapped identity:

```json
{"type":"authenticated","identity":"process://alice"}
```

The client can then submit programs:

```json
{"type":"submit","id":1,"program":{ "...":"DoNode serde JSON" }}
```

The result carries the same `id`:

```json
{"type":"result","id":1,"outcome":{ "...":"Outcome JSON" }}
```

Protocol, auth, and execution errors use:

```json
{"type":"error","message":"..."}
```

Program WebSocket accepts text frames only. Binary frames, malformed JSON, and
submissions before authentication return an error frame. The `program` field is
the serde representation of `nexus-graph::DoNode`; use gRPC for a stable
cross-language schema.

## MCP

`nexus-gateway-mcp` exposes selected Nexus effects as MCP tools. Each published
tool is tied to an explicit required capability. Calls are converted into normal
gateway submissions, so request identity, authorization, taint, execution, and
gateway audit handling stay on the same path as other program gateways.
