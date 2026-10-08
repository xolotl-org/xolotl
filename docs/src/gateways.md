# Gateways

`xolotld` exposes separate application, management and external integration boundaries. A listener starts only when its `[server]` address or matching environment variable is set. The external gRPC and WebSocket transports are enabled by default in the daemon build; `application-grpc` is optional.

| Entry point | Address setting / environment | Route or service | Encoding |
| --- | --- | --- | --- |
| Console HTTP | `console_addr` / `XOLOTL_CONSOLE_ADDR` | `/api/console/v1`; see [routes](console-http-and-credentials.md#http-routes) | JSON authentication and credentials; protobuf `ConsoleFrame` at `/calls` |
| Console WebSocket | same | `/api/console/v1/ws` | Binary protobuf `ConsoleFrame`, subprotocol `xolotl-console-v1` |
| Application gRPC | `application_grpc_addr` / `XOLOTL_APPLICATION_GRPC_ADDR` | `xolotl.v1.application.ApplicationGateway` | Protobuf |
| External gRPC | `external_grpc_addr` / `XOLOTL_EXTERNAL_GRPC_ADDR` | `xolotl.v1.external.ExternalService.Session` | Protobuf |
| External WebSocket | `external_websocket_addr` / `XOLOTL_EXTERNAL_WEBSOCKET_ADDR` | `/ws` | Binary protobuf frames |

## Choose an entry point

| Caller | Use |
| --- | --- |
| Administrator or Console client | [Console Protocol](console-protocol.md): authentication, management actions, runtime calls and subscriptions. |
| Application principal | [Application Gateway](application-gateway.md): profile-bound surfaces, submissions and typed object transfer. |
| External effect handler | [External Gateway](external-gateway.md) as a Provider. |
| External event producer or command consumer | [External Gateway](external-gateway.md) as a Source. |
| MCP client | A host-published [MCP surface](api-reference.md#mcp-publications). |

External Providers and Sources connect as declared projections. They do not self-install resources or choose their authority. Application Gateway object uploads use an explicitly installed `ObjectStore`; their tickets and references are covered in [Application Gateway](application-gateway.md#protocol). Listener security and limits are configured in [Configuration](configuration.md).
