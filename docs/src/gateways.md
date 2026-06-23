# Gateways

This page maps `xolotld` listener addresses to client protocols.

External programs have one role model: they connect as Provider or Source
projections. gRPC and WebSocket are transport implementations for the same
external gateway.

## Entry Points

A listener starts when its `[server]` config field is set, or when the matching
environment variable is set. `xolotl-daemon` enables `external-grpc` and
`external-websocket` by default; either transport can be built alone with
`--no-default-features --features external-grpc` or `--no-default-features
--features external-websocket`.

| Entry point | Config field | Environment variable | Route or service | Encoding |
| --- | --- | --- | --- | --- |
| Console HTTP | `console_addr` | `XOLOTL_CONSOLE_ADDR` | `/health`, `/api/auth/*` | HTTP JSON |
| Console WebSocket | `console_addr` | `XOLOTL_CONSOLE_ADDR` | `/ws` | MessagePack, `msgpack+xolotl-console-v1` |
| External gRPC | `external_grpc_addr` | `XOLOTL_EXTERNAL_GRPC_ADDR` | `xolotl.v1.external.ExternalService.Session` | Protobuf |
| External WebSocket | `external_websocket_addr` | `XOLOTL_EXTERNAL_WEBSOCKET_ADDR` | `/ws` | Binary protobuf frames |

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
| Publish selected Gateway publications as MCP tools, resources, resource templates, and prompts | MCP |

## External Gateway

External gateway sessions are described in [External Gateway](external-gateway.md).
Provider and Source are the only external projection roles.

Use this entry point when a program runs outside the Xolotl process but should be
projected into the runtime as declared effects or declared event streams. The
daemon owns session admission, generation checks, binding selection, and
runtime limits; external programs do not self-declare authority.

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

## Console Protocol

Console HTTP is limited to health and authentication. Logged-in management uses
Console WebSocket with authorization, CAS, visibility gates, and audit records.

Console transport security is deployment configuration and is documented in
[Configuration](configuration.md). This page only identifies the console
protocol entry point.
