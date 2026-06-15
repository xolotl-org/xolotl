# Gateways

This page maps `nexusd` listener addresses to client protocols.

External programs have one role model: they connect as Provider or Source
projections. gRPC and WebSocket are transport implementations for the same
external gateway.

## Entry Points

A listener starts when its `[server]` config field is set, or when the matching
environment variable is set. `nexus-daemon` enables `external-grpc` and
`external-websocket` by default; either transport can be built alone with
`--no-default-features --features external-grpc` or `--no-default-features
--features external-websocket`.

| Entry point | Config field | Environment variable | Route or service | Encoding |
| --- | --- | --- | --- | --- |
| Console HTTP | `console_addr` | `NEXUS_CONSOLE_ADDR` | `/health`, `/api/auth/*` | HTTP JSON |
| Console WebSocket | `console_addr` | `NEXUS_CONSOLE_ADDR` | `/ws` | MessagePack, `msgpack+nexus-console-v1` |
| External gRPC | `external_grpc_addr` | `NEXUS_EXTERNAL_GRPC_ADDR` | `nexus.v1.external.ExternalService.Session` | Protobuf |
| External WebSocket | `external_websocket_addr` | `NEXUS_EXTERNAL_WEBSOCKET_ADDR` | `/ws` | Binary protobuf frames |

Console WebSocket and external WebSocket both mount `/ws`. They are selected by
listener address and frame encoding:

- Console WebSocket uses `[server].console_addr` and MessagePack console
  frames.
- External WebSocket uses `[server].external_websocket_addr` and binary
  Provider/Source session frames.

## Which Entry Point To Use

| Need | Entry point |
| --- | --- |
| Run management actions, inspect runtime state, manage users, manage sessions, subscribe to state or audit streams | Console Protocol |
| Connect an external program that provides effect handlers | External gateway as Provider |
| Connect an external program that emits inbound events or receives outbound commands | External gateway as Source |
| Publish selected Nexus effects as MCP tools through explicit publish capabilities | MCP |

## External Gateway

External gateway sessions are described in [External Gateway](external-gateway.md).
Provider and Source are the only external projection roles.

The daemon owns session admission and authority:

1. the external program sends `RoleSessionClientHello`;
2. the daemon loads the installation, projection, pairing, and approved session
   state;
3. the daemon sends `SessionContext` with authoritative generations and limits;
4. the external program replies with `RoleReady`;
5. business frames flow only after the session is ready.

Provider readiness registers projected bindings for that ready session. Source
events are admitted only after generation checks, schema checks, dedupe,
capacity checks, rate checks, and policy checks pass.

## Console Protocol

Console HTTP is limited to health and authentication. Logged-in management uses
Console WebSocket with authorization, CAS, visibility gates, and audit records.

Console transport security is daemon-owned: `production_tls`,
`trusted_reverse_proxy`, `local_trusted`, and explicit unsafe modes are
configured in `[console.transport_security]`.
