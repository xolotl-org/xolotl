# Gateways

This page is the ingress map for `nexusd`. Use it to choose the listener and
protocol for a client. Protocol details live on separate pages:

- [Program Gateways](program-gateways.md): external clients submit `Program` or
  `DoNode` work through gRPC, WebSocket, or MCP adapters.
- [Console Protocol](console-protocol.md): console clients authenticate and run
  management actions through HTTP auth and Console WebSocket.

## Entry Points

A channel starts when its `[server]` config field is set, or when the matching
environment variable is set. `nexus.toml.example` enables the three listeners
below. The gRPC listener is compiled by the `grpc` feature, which is enabled in
the default `nexus-daemon` build.

| Surface | Config field | Environment variable | Route or service | Encoding |
| --- | --- | --- | --- | --- |
| Console HTTP | `console_addr` | `NEXUS_CONSOLE_ADDR` | `/health`, `/api/auth/*` | HTTP JSON |
| Console WebSocket | `console_addr` | `NEXUS_CONSOLE_ADDR` | `/ws` | MessagePack, `msgpack+nexus-console-v1` |
| Program gRPC | `grpc_addr` | `NEXUS_GRPC_ADDR` | `nexus.v1.GatewayService` | Protobuf |
| Program WebSocket | `ws_addr` | `NEXUS_WS_ADDR` | `/ws` | Text JSON |

Console WebSocket and Program WebSocket both mount `/ws`. They are selected by
listener address and frame encoding:

- Console WebSocket uses `[server].console_addr` and binary MessagePack frames.
- Program WebSocket uses `[server].ws_addr` and text JSON frames.

## Which Surface To Use

| Need | Surface |
| --- | --- |
| Run management actions, inspect runtime state, manage users, manage sessions, subscribe to state or audit streams | Console Protocol |
| Submit structured programs from a cross-language client | Program gRPC |
| Submit JSON `DoNode` values from Rust-side tools or repository-local tests | Program WebSocket |
| Publish selected Nexus effects as MCP tools with explicit required capabilities | MCP gateway |

## Request Boundary

Program gateways use the shared `Gateway` trait:

1. validate the presented token;
2. map the token to a request identity such as `process://alice`;
3. create an attenuated request Process;
4. convert the protocol payload into a `DoNode` program;
5. run the program through the executor and return an `Outcome`.

The host declares the capabilities a request may reach and opens exposed
resource handles when it builds an `InProcessGateway`. Network adapters handle
transport, auth-frame parsing, structural conversion, and gateway audit tags.

Console Protocol uses `nexus-console`. HTTP is limited to health and
authentication. Logged-in management uses descriptor-named actions and streams
over Console WebSocket, with authorization, CAS, visibility gates, and audit
records handled by the same runtime surfaces used elsewhere.

## Extension Ingress

Extensions are declared as an installation plus one or more projections. A
Provider projection exposes effect handlers through remote bindings. A Source
projection emits inbound events into a declared state stream. Pairing,
credential generation, revocation floor, session context, and business frames
are represented as typed data in `nexus-types` and `nexus-proto`.

Secrets stay on the one-shot display edge. Operation input, state, Facts, and
traces receive only redacted metadata or references.
