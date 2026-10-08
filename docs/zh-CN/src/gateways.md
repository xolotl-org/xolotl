# 网关

本页列出 `xolotld` 的监听器和客户端协议。嵌入式宿主可以分别安装服务、选择传输，自行挂载 HTTP 路径；下表路径是 daemon 的默认挂载位置。

## 接入口

`[server]` 中的地址或对应环境变量决定是否启动监听器。构建时还须包含对应 feature；`xolotl-daemon` 默认启用 `external-grpc` 和 `external-websocket`，可以用 `--no-default-features --features external-grpc` 等方式单独选择。

| 接口 | 配置字段 / 环境变量 | 默认路径或服务 | 编码 |
| --- | --- | --- | --- |
| Console HTTP | `console_addr` / `XOLOTL_CONSOLE_ADDR` | `/api/console/v1` | 认证和凭据使用 JSON；`/calls` 使用 protobuf `ConsoleFrame` |
| Console WebSocket | 同上 | `/api/console/v1/ws` | 二进制 protobuf `ConsoleFrame`；子协议 `xolotl-console-v1` |
| 应用 gRPC | `application_grpc_addr` / `XOLOTL_APPLICATION_GRPC_ADDR` | `xolotl.v1.application.ApplicationGateway` | Protobuf |
| External gRPC | `external_grpc_addr` / `XOLOTL_EXTERNAL_GRPC_ADDR` | `xolotl.v1.external.ExternalService.Session` | Protobuf |
| External WebSocket | `external_websocket_addr` / `XOLOTL_EXTERNAL_WEBSOCKET_ADDR` | `/ws` | 二进制 protobuf frame |

监听地址和传输安全配置见[配置](configuration.md)。Console 的相对路由及 HTTP 组合方式见[控制台协议](console-http-and-credentials.md#http-路由)。

## 选择接口

| 需求 | 接口 |
| --- | --- |
| 管理账户和运行时、调用宿主开放的资源、订阅状态或审计流 | [Console](console-protocol.md) |
| 按 profile 发现并提交应用 surface，上传或下载类型化对象 | [应用网关](application-gateway.md) |
| 接入进程外 effect handler 或事件流 | [External Gateway](external-gateway.md) 的 Provider 或 Source session |
| 将应用 surface 发布为 MCP tool、resource、resource template 或 prompt | MCP；发布与适配器契约见 [API 参考](api-reference.md#mcp-发布) |

应用网关和 External Gateway 分别准入。前者由 profile 选择 principal、surface 和授权范围；后者使用已安装的 Provider/Source projection 及已批准的 session。MCP publication 引用现有应用 surface，调用仍经过该 surface 的准入和执行路径。
