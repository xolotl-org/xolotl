# 网关

本页说明 `nexusd` 的监听地址和客户端协议。

外部程序只有一套角色模型：以 Provider 或 Source projection 接入。gRPC 和 WebSocket 是同一个 external gateway 的两种传输实现。

## 接入口

当 `[server]` 中的配置字段存在，或对应环境变量存在时，`nexusd` 会启动该通道。gRPC 监听需要 `grpc` feature；默认 `nexus-daemon` 构建已启用。

| 接口 | 配置字段 | 环境变量 | 路径或服务 | 编码 |
| --- | --- | --- | --- | --- |
| 控制台 HTTP | `console_addr` | `NEXUS_CONSOLE_ADDR` | `/health`、`/api/auth/*` | HTTP JSON |
| 控制台 WebSocket | `console_addr` | `NEXUS_CONSOLE_ADDR` | `/ws` | MessagePack，`msgpack+nexus-console-v1` |
| External gRPC | `external_grpc_addr` | `NEXUS_EXTERNAL_GRPC_ADDR` | `nexus.v1.external.ExternalService.Session` | Protobuf |
| External WebSocket | `external_websocket_addr` | `NEXUS_EXTERNAL_WEBSOCKET_ADDR` | `/ws` | 二进制 protobuf frame |

控制台 WebSocket 和 external WebSocket 都挂在 `/ws`，通过监听地址和帧编码区分：

- 控制台 WebSocket 使用 `[server].console_addr` 和 MessagePack 控制台帧。
- External WebSocket 使用 `[server].external_websocket_addr` 和二进制 Provider/Source session frame。

## 如何选择接口

| 需求 | 接口 |
| --- | --- |
| 执行管理动作、检查运行时状态、管理用户、管理会话、订阅状态或审计流 | 控制台协议 |
| 连接提供 effect handler 的外部程序 | External gateway Provider |
| 连接发送入站事件或接收 outbound command 的外部程序 | External gateway Source |
| 通过显式 publish capability 把选定 Nexus effect 暴露为 MCP tool | MCP |

## External Gateway

External gateway session 见 [External Gateway](external-gateway.md)。Provider 和 Source 是唯一的外部 projection role。

daemon 负责 session 准入和裁定：

1. 外部程序发送 `RoleSessionClientHello`；
2. daemon 读取 installation、projection、pairing 和已批准 session state；
3. daemon 发送带权威 generation 和限制的 `SessionContext`；
4. 外部程序回复 `RoleReady`；
5. session ready 后才允许业务 frame 流动。

Provider ready 后会为该 ready session 注册投影 binding。Source event 只有通过 generation、schema、dedupe、capacity、rate 和 policy 检查后才会准入。

## 控制台协议

控制台 HTTP 只负责健康检查和认证。登录后的管理功能通过 Console WebSocket 执行，带授权、CAS、可见性门槛和审计记录。

控制台传输安全由 daemon 持有：`production_tls`、`trusted_reverse_proxy`、`local_trusted` 和显式 unsafe mode 通过 `[console.transport_security]` 配置。
